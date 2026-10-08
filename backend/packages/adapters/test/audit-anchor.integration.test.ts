import { generateKeyPairSync } from 'node:crypto';
import { Pool, Client } from 'pg';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { AuditAnchorService } from '../../application/src/audit-anchor-service.js';
import { Ed25519AuditExportSigner } from '../../application/src/audit-export-service.js';
import { AuditAnchorStore } from '../src/postgres/audit-anchor-store.js';
import { migrate } from '../src/postgres/migrate.js';
import type { AuditAnchorRepository, AuditAnchorStorage, AuditAnchorStorageResult } from '../../ports/src/audit-anchor.js';

const connectionString = process.env.DATABASE_URL;
const signingPair = generateKeyPairSync('ed25519');
const signer = new Ed25519AuditExportSigner('postgres-anchor-test-v1', signingPair.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString());

class MemoryImmutableStorage implements AuditAnchorStorage {
  public readonly writes = new Map<string, string>();
  public readonly versions = new Map<string, string>();

  public async putImmutable(key: string, body: string, _retentionDays: number): Promise<AuditAnchorStorageResult> {
    const existing = this.writes.get(key);
    if (existing !== undefined && existing !== body) throw new Error('immutable object key has different bytes');
    this.writes.set(key, body);
    const versionId = this.versions.get(key) ?? `version-${this.versions.size + 1}`;
    this.versions.set(key, versionId);
    return { versionId, retainedUntil: '2027-10-06T00:00:00.000Z' };
  }
}

describe.skipIf(connectionString === undefined)('Audit anchor/PostgreSQL integration', () => {
  let pool: Pool;
  let organizationId: string;

  beforeAll(async () => {
    if (connectionString === undefined) throw new Error('DATABASE_URL is required');
    pool = new Pool({ connectionString });
    const migrationClient = new Client({ connectionString });
    await migrationClient.connect();
    await migrate(migrationClient);
    await migrationClient.end();
  });

  afterAll(async () => {
    await pool?.end();
  });

  it('serializes concurrent anchor workers and chains subsequent independent checkpoints', async () => {
    organizationId = `anchor-${Date.now()}-${Math.random().toString(16).slice(2)}`;
    await pool.query('INSERT INTO organizations (id, display_name) VALUES ($1, $2)', [organizationId, 'Audit Anchor Integration']);
    const firstHash = `0x${'a'.repeat(64)}`;
    const secondHash = `0x${'b'.repeat(64)}`;
    await pool.query(
      `INSERT INTO audit_events (organization_id, actor_type, actor_id, event_type, subject_type, subject_id, correlation_id, payload, event_hash)
       VALUES ($1, 'TEST', 'anchor-test', 'A', 'TEST', 'first', 'anchor-first', '{}'::jsonb, $2)`,
      [organizationId, firstHash],
    );
    await pool.query(
      `INSERT INTO audit_events (organization_id, actor_type, actor_id, event_type, subject_type, subject_id, correlation_id, payload, previous_hash, event_hash)
       VALUES ($1, 'TEST', 'anchor-test', 'B', 'TEST', 'second', 'anchor-second', '{}'::jsonb, $2, $3)`,
      [organizationId, firstHash, secondHash],
    );

    const repository = new AuditAnchorStore(pool);
    const scopedRepository: AuditAnchorRepository = {
      async getCandidateOrganizationIds(_limit) {
        // Keep this concurrency test independent of unrelated organizations and
        // the global candidate batch limit in a database reused across runs.
        return [organizationId];
      },
      anchorLatest: (id, createCheckpoint) => repository.anchorLatest(id, createCheckpoint),
    };
    const storage = new MemoryImmutableStorage();
    const workerA = new AuditAnchorService(scopedRepository, storage, signer, 25, 365);
    const workerB = new AuditAnchorService(scopedRepository, storage, signer, 25, 365);
    const results = await Promise.all([workerA.runBatch(), workerB.runBatch()]);
    expect(results.reduce((count, result) => count + result.anchored, 0)).toBe(1);
    expect(results.reduce((count, result) => count + result.failed, 0)).toBe(0);
    expect(storage.writes.size).toBe(1);
    const firstAnchor = await pool.query<{ checkpoint_sequence: string; event_hash: string; checkpoint_hash: string }>(
      'SELECT checkpoint_sequence::text, event_hash, checkpoint_hash FROM audit_anchor_checkpoints WHERE organization_id = $1',
      [organizationId],
    );
    expect(firstAnchor.rows).toHaveLength(1);
    expect(firstAnchor.rows[0]?.event_hash.trim()).toBe(secondHash);

    const thirdHash = `0x${'c'.repeat(64)}`;
    await pool.query(
      `INSERT INTO audit_events (organization_id, actor_type, actor_id, event_type, subject_type, subject_id, correlation_id, payload, previous_hash, event_hash)
       VALUES ($1, 'TEST', 'anchor-test', 'C', 'TEST', 'third', 'anchor-third', '{}'::jsonb, $2, $3)`,
      [organizationId, secondHash, thirdHash],
    );
    await expect(workerA.runBatch()).resolves.toMatchObject({ anchored: 1, failed: 0 });
    const allAnchors = await pool.query<{ checkpoint_sequence: string; event_hash: string; previous_checkpoint_hash: string | null }>(
      `SELECT checkpoint_sequence::text, event_hash, previous_checkpoint_hash FROM audit_anchor_checkpoints
       WHERE organization_id = $1 ORDER BY checkpoint_sequence`,
      [organizationId],
    );
    expect(allAnchors.rows).toHaveLength(2);
    expect(allAnchors.rows[1]?.event_hash.trim()).toBe(thirdHash);
    expect(allAnchors.rows[1]?.previous_checkpoint_hash).toBe(firstAnchor.rows[0]?.checkpoint_hash);
    await expect(repository.getCandidateOrganizationIds(500)).resolves.not.toContain(organizationId);
  });

  it('rejects edits and deletions of checkpoint metadata in PostgreSQL', async () => {
    const checkpoint = await pool.query<{ organization_id: string; checkpoint_sequence: string }>(
      'SELECT organization_id, checkpoint_sequence::text FROM audit_anchor_checkpoints WHERE organization_id = $1 ORDER BY anchored_at DESC LIMIT 1',
      [organizationId],
    );
    const row = checkpoint.rows[0];
    if (row === undefined) throw new Error('the anchor integration test did not create a checkpoint');
    await expect(pool.query(
      'UPDATE audit_anchor_checkpoints SET event_hash = $1 WHERE organization_id = $2 AND checkpoint_sequence = $3',
      [`0x${'d'.repeat(64)}`, row.organization_id, row.checkpoint_sequence],
    )).rejects.toThrow('audit_anchor_checkpoints is append-only');
    await expect(pool.query(
      'DELETE FROM audit_anchor_checkpoints WHERE organization_id = $1 AND checkpoint_sequence = $2',
      [row.organization_id, row.checkpoint_sequence],
    )).rejects.toThrow('audit_anchor_checkpoints is append-only');
    await expect(pool.query('TRUNCATE audit_anchor_checkpoints')).rejects.toThrow('audit_anchor_checkpoints is append-only');
    await expect(pool.query('TRUNCATE audit_events')).rejects.toThrow('audit_events is append-only');
  });
});
