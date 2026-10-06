import { createHash, randomUUID } from 'node:crypto';
import type { Pool } from 'pg';

export interface CreatedOrganization {
  readonly organizationId: string;
  readonly displayName: string;
  readonly role: 'OWNER';
  readonly createdAt: string;
}
interface IdempotencyRow { readonly request_hash: string; readonly response_json: CreatedOrganization; }

export class OrganizationOnboardingConflictError extends Error {
  public constructor() { super('IDEMPOTENCY_CONFLICT'); this.name = 'OrganizationOnboardingConflictError'; }
}
const digest = (value: string): string => `0x${createHash('sha256').update(value, 'utf8').digest('hex')}`;

export class OrganizationOnboardingStore {
  public constructor(private readonly pool: Pool) {}

  public async create(input: { principalId: string; displayName: string; idempotencyKey: string; requestHash: string }): Promise<{ readonly kind: 'CREATED' | 'REPLAY'; readonly organization: CreatedOrganization }> {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1, 0))', [`org.create|${input.principalId}|${input.idempotencyKey}`]);
      await client.query('DELETE FROM organization_creation_idempotency WHERE principal_id = $1 AND idempotency_key = $2 AND expires_at <= now()', [input.principalId, input.idempotencyKey]);
      const prior = await client.query<IdempotencyRow>(
        'SELECT request_hash, response_json FROM organization_creation_idempotency WHERE principal_id = $1 AND idempotency_key = $2',
        [input.principalId, input.idempotencyKey],
      );
      const existing = prior.rows[0];
      if (existing !== undefined) {
        if (existing.request_hash.trim() !== input.requestHash) throw new OrganizationOnboardingConflictError();
        await client.query('COMMIT');
        return { kind: 'REPLAY', organization: existing.response_json };
      }

      const organizationId = `org_${randomUUID()}`;
      const inserted = await client.query<{ created_at: Date }>(
        'INSERT INTO organizations (id, display_name) VALUES ($1, $2) RETURNING created_at',
        [organizationId, input.displayName],
      );
      const createdAt = inserted.rows[0]?.created_at;
      if (createdAt === undefined) throw new Error('Organization creation returned no row');
      await client.query('INSERT INTO members (organization_id, subject, role) VALUES ($1, $2, \'OWNER\')', [organizationId, input.principalId]);
      const organization: CreatedOrganization = { organizationId, displayName: input.displayName, role: 'OWNER', createdAt: createdAt.toISOString() };
      const payload = JSON.stringify({ displayName: input.displayName });
      const eventHash = digest(`${organizationId}|${input.principalId}|ORG_CREATED|${payload}`);
      await client.query(`INSERT INTO audit_events (organization_id, actor_type, actor_id, event_type, subject_type, subject_id, correlation_id, payload, previous_hash, event_hash)
        VALUES ($1, 'HUMAN', $2, 'ORG_CREATED', 'ORGANIZATION', $1, $3, $4::jsonb, NULL, $5)`,
      [organizationId, input.principalId, input.idempotencyKey, payload, eventHash]);
      await client.query(`INSERT INTO outbox_events (organization_id, aggregate_type, aggregate_id, event_type, payload)
        VALUES ($1, 'ORGANIZATION', $1, 'ORG_CREATED', $2::jsonb)`, [organizationId, payload]);
      await client.query(`INSERT INTO organization_creation_idempotency (principal_id, idempotency_key, request_hash, organization_id, response_json)
        VALUES ($1, $2, $3, $4, $5::jsonb)`, [input.principalId, input.idempotencyKey, input.requestHash, organizationId, JSON.stringify(organization)]);
      await client.query('COMMIT');
      return { kind: 'CREATED', organization };
    } catch (error: unknown) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  }
}
