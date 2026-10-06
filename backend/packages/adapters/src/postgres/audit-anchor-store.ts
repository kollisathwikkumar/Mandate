import type { Pool, PoolClient } from 'pg';
import type { AuditAnchorCheckpointRecord, AuditAnchorRepository, AuditAnchorSnapshot } from '../../../ports/src/audit-anchor.js';

interface OrganizationRow { readonly organization_id: string; }
interface EventHeadRow { readonly sequence: string; readonly event_hash: string; }
interface AnchorRow {
  readonly organization_id: string;
  readonly checkpoint_sequence: string;
  readonly event_hash: string;
  readonly previous_checkpoint_hash: string | null;
  readonly checkpoint_hash: string;
  readonly object_key: string;
  readonly object_version_id: string;
  readonly key_id: string;
  readonly key_fingerprint: string;
  readonly signature: string;
  readonly retained_until: Date;
}

const ADVISORY_LOCK_SEED = 754331;

function mapAnchor(row: AnchorRow): AuditAnchorCheckpointRecord {
  return {
    organizationId: row.organization_id,
    checkpointSequence: row.checkpoint_sequence,
    eventHash: row.event_hash.trim(),
    previousCheckpointHash: row.previous_checkpoint_hash?.trim() ?? null,
    checkpointHash: row.checkpoint_hash.trim(),
    objectKey: row.object_key,
    objectVersionId: row.object_version_id,
    keyId: row.key_id,
    keyFingerprint: row.key_fingerprint.trim(),
    signature: row.signature,
    retainedUntil: row.retained_until.toISOString(),
  };
}

async function latestAnchor(client: PoolClient, organizationId: string): Promise<AuditAnchorCheckpointRecord | null> {
  const result = await client.query<AnchorRow>(
    `SELECT c.organization_id, c.checkpoint_sequence::text, c.event_hash, c.previous_checkpoint_hash, c.checkpoint_hash,
       c.object_key, c.object_version_id, c.key_id, c.key_fingerprint, c.signature, c.retained_until
     FROM audit_anchor_checkpoints AS c WHERE c.organization_id = $1 ORDER BY c.checkpoint_sequence DESC LIMIT 1`,
    [organizationId],
  );
  const row = result.rows[0];
  return row === undefined ? null : mapAnchor(row);
}

async function sourceHead(client: PoolClient, organizationId: string): Promise<{ sequence: string; eventHash: string } | null> {
  const result = await client.query<EventHeadRow>(
    'SELECT e.sequence::text, e.event_hash FROM audit_events AS e WHERE e.organization_id = $1 ORDER BY e.sequence DESC LIMIT 1',
    [organizationId],
  );
  const row = result.rows[0];
  return row === undefined ? null : { sequence: row.sequence, eventHash: row.event_hash.trim() };
}

function validateCheckpoint(record: AuditAnchorCheckpointRecord, snapshot: AuditAnchorSnapshot): void {
  if (record.organizationId !== snapshot.organizationId || snapshot.sourceHead === null
    || record.checkpointSequence !== snapshot.sourceHead.sequence || record.eventHash !== snapshot.sourceHead.eventHash
    || record.previousCheckpointHash !== (snapshot.previousAnchor?.checkpointHash ?? null)
    || !/^[0-9a-f]{64}$/.test(record.checkpointHash)
    || !/^0x[0-9a-f]{64}$/.test(record.eventHash)
    || (record.previousCheckpointHash !== null && !/^[0-9a-f]{64}$/.test(record.previousCheckpointHash))
    || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(record.keyId)
    || !/^[0-9a-f]{64}$/.test(record.keyFingerprint)
    || record.objectKey.trim() === '' || record.objectVersionId.trim() === '' || record.signature.trim() === ''
    || !Number.isFinite(Date.parse(record.retainedUntil))) {
    throw new Error('Audit anchor checkpoint is invalid for the locked PostgreSQL snapshot');
  }
  if (snapshot.previousAnchor !== null && BigInt(record.checkpointSequence) <= BigInt(snapshot.previousAnchor.checkpointSequence)) {
    throw new Error('Audit anchor checkpoint sequence did not advance');
  }
}

export class AuditAnchorStore implements AuditAnchorRepository {
  public constructor(private readonly pool: Pool) {}

  public async getCandidateOrganizationIds(limit: number): Promise<readonly string[]> {
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 500) throw new Error('Audit anchor candidate limit must be between 1 and 500');
    const result = await this.pool.query<OrganizationRow>(
      `SELECT e.organization_id
       FROM audit_events e
       LEFT JOIN LATERAL (
         SELECT checkpoint_sequence FROM audit_anchor_checkpoints c
         WHERE c.organization_id = e.organization_id ORDER BY checkpoint_sequence DESC LIMIT 1
       ) c ON true
       WHERE e.sequence > COALESCE(c.checkpoint_sequence, 0)
       GROUP BY e.organization_id
       ORDER BY MIN(e.sequence), e.organization_id
       LIMIT $1`,
      [limit],
    );
    return result.rows.map((row) => row.organization_id);
  }

  public async anchorLatest(
    organizationId: string,
    createCheckpoint: (snapshot: AuditAnchorSnapshot) => Promise<AuditAnchorCheckpointRecord | null>,
  ): Promise<boolean> {
    const client = await this.pool.connect();
    let locked = false;
    try {
      await client.query('SELECT pg_advisory_lock(hashtextextended($1, $2::bigint))', [organizationId, ADVISORY_LOCK_SEED]);
      locked = true;
      const previousAnchor = await latestAnchor(client, organizationId);
      const head = await sourceHead(client, organizationId);
      const snapshot: AuditAnchorSnapshot = { organizationId, previousAnchor, sourceHead: head };
      const record = await createCheckpoint(snapshot);
      if (record === null) return false;
      validateCheckpoint(record, snapshot);

      await client.query('BEGIN');
      try {
        await client.query(
          `INSERT INTO audit_anchor_checkpoints
             (organization_id, checkpoint_sequence, event_hash, previous_checkpoint_hash, checkpoint_hash,
              object_key, object_version_id, key_id, key_fingerprint, signature, retained_until)
           VALUES ($1,$2::bigint,$3,$4,$5,$6,$7,$8,$9,$10,$11::timestamptz)`,
          [record.organizationId, record.checkpointSequence, record.eventHash, record.previousCheckpointHash,
            record.checkpointHash, record.objectKey, record.objectVersionId, record.keyId,
            record.keyFingerprint, record.signature, record.retainedUntil],
        );
        await client.query('COMMIT');
      } catch (error: unknown) {
        await client.query('ROLLBACK');
        throw error;
      }
      return true;
    } finally {
      if (locked) {
        try { await client.query('SELECT pg_advisory_unlock(hashtextextended($1, $2::bigint))', [organizationId, ADVISORY_LOCK_SEED]); }
        finally { client.release(); }
      } else {
        client.release();
      }
    }
  }
}
