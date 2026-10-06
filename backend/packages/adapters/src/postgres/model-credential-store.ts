import { createHash } from 'node:crypto';
import type { Pool, PoolClient } from 'pg';
import type { ModelCredentialRecord, ModelCredentialRepository, ModelCredentialState, ModelCredentialSummary, ModelCredentialWriteInput, ModelCredentialWriteOutcome, ModelProvider } from '../../../ports/src/model-credential-repository.js';
import { RepositoryAccessError } from '../../../ports/src/repository-errors.js';

interface CredentialRow {
  readonly provider: ModelProvider;
  readonly secret_reference: string;
  readonly masked_suffix: string;
  readonly state: ModelCredentialState;
  readonly created_at: Date;
  readonly rotated_at: Date | null;
  readonly verified_at: Date | null;
  readonly disabled_at: Date | null;
}
interface IdempotencyRow { readonly request_hash: string; readonly response_json: ModelCredentialSummary; }
const mapSummary = (row: CredentialRow): ModelCredentialSummary => ({
  provider: row.provider, maskedSuffix: row.masked_suffix, state: row.state,
  createdAt: row.created_at.toISOString(), rotatedAt: row.rotated_at?.toISOString() ?? null,
  verifiedAt: row.verified_at?.toISOString() ?? null, disabledAt: row.disabled_at?.toISOString() ?? null,
});
const mapRecord = (row: CredentialRow): ModelCredentialRecord => ({ ...mapSummary(row), secretReference: row.secret_reference });
const digest = (value: string): string => `0x${createHash('sha256').update(value, 'utf8').digest('hex')}`;

async function requireAdministrator(client: PoolClient, organizationId: string, principalId: string): Promise<void> {
  const result = await client.query<{ role: string }>('SELECT role FROM members WHERE organization_id = $1 AND subject = $2 FOR UPDATE', [organizationId, principalId]);
  const role = result.rows[0]?.role;
  if (role === undefined) throw new RepositoryAccessError(404);
  if (role !== 'OWNER' && role !== 'ADMIN') throw new RepositoryAccessError(403);
}

export class ModelCredentialStore implements ModelCredentialRepository {
  public constructor(private readonly pool: Pool) {}

  public async getHumanRole(organizationId: string, subject: string): Promise<string | null> {
    const result = await this.pool.query<{ role: string }>('SELECT role FROM members WHERE organization_id = $1 AND subject = $2', [organizationId, subject]);
    return result.rows[0]?.role ?? null;
  }

  public async listCredentials(organizationId: string): Promise<readonly ModelCredentialSummary[]> {
    const result = await this.pool.query<CredentialRow>(`SELECT provider, secret_reference, masked_suffix, state, created_at, rotated_at, verified_at, disabled_at
      FROM model_provider_credentials WHERE organization_id = $1 ORDER BY provider`, [organizationId]);
    return result.rows.map(mapSummary);
  }

  public async getCredential(organizationId: string, provider: ModelProvider): Promise<ModelCredentialRecord | null> {
    const result = await this.pool.query<CredentialRow>(`SELECT provider, secret_reference, masked_suffix, state, created_at, rotated_at, verified_at, disabled_at
      FROM model_provider_credentials WHERE organization_id = $1 AND provider = $2`, [organizationId, provider]);
    const row = result.rows[0];
    return row === undefined ? null : mapRecord(row);
  }

  public async writeCredential(input: ModelCredentialWriteInput): Promise<ModelCredentialWriteOutcome> {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      await requireAdministrator(client, input.organizationId, input.principalId);
      const lockKey = `${input.organizationId}|${input.principalId}|model-provider.write|${input.idempotencyKey}`;
      await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1, 0))', [lockKey]);
      await client.query(`DELETE FROM command_idempotency WHERE organization_id = $1 AND principal_id = $2 AND scope = 'model-provider.write' AND idempotency_key = $3 AND expires_at <= now()`, [input.organizationId, input.principalId, input.idempotencyKey]);
      const prior = await client.query<IdempotencyRow>(`SELECT request_hash, response_json FROM command_idempotency
        WHERE organization_id = $1 AND principal_id = $2 AND scope = 'model-provider.write' AND idempotency_key = $3 AND expires_at > now()`, [input.organizationId, input.principalId, input.idempotencyKey]);
      const old = prior.rows[0];
      if (old !== undefined) {
        if (old.request_hash.trim() !== input.requestHash) throw new Error('IDEMPOTENCY_CONFLICT');
        const replay = await client.query<CredentialRow>(`SELECT provider, secret_reference, masked_suffix, state, created_at, rotated_at, verified_at, disabled_at FROM model_provider_credentials WHERE organization_id = $1 AND provider = $2`, [input.organizationId, input.provider]);
        const row = replay.rows[0];
        if (row === undefined) throw new Error('Idempotent model credential no longer exists');
        await client.query('COMMIT');
        return { kind: 'REPLAY', credential: mapSummary(row) };
      }
      const priorCredential = await client.query<CredentialRow>(`SELECT provider, secret_reference, masked_suffix, state, created_at, rotated_at, verified_at, disabled_at FROM model_provider_credentials WHERE organization_id = $1 AND provider = $2 FOR UPDATE`, [input.organizationId, input.provider]);
      const replacedSecretReference = priorCredential.rows[0]?.secret_reference ?? null;
      const result = await client.query<CredentialRow>(`INSERT INTO model_provider_credentials (organization_id, provider, secret_reference, masked_suffix, created_by, state, rotated_at, disabled_at, verified_at)
        VALUES ($1, $2, $3, $4, $5, 'ACTIVE', CASE WHEN EXISTS (SELECT 1 FROM model_provider_credentials WHERE organization_id = $1 AND provider = $2) THEN now() ELSE NULL END, NULL, NULL)
        ON CONFLICT (organization_id, provider) DO UPDATE SET secret_reference = EXCLUDED.secret_reference, masked_suffix = EXCLUDED.masked_suffix, created_by = EXCLUDED.created_by, state = 'ACTIVE', rotated_at = now(), disabled_at = NULL, verified_at = NULL
        RETURNING provider, secret_reference, masked_suffix, state, created_at, rotated_at, verified_at, disabled_at`, [input.organizationId, input.provider, input.secretReference, input.maskedSuffix, input.principalId]);
      const row = result.rows[0];
      if (row === undefined) throw new Error('Model credential insert returned no row');
      const summary = mapSummary(row);
      const responseJson = JSON.stringify(summary);
      await client.query(`INSERT INTO command_idempotency (organization_id, principal_id, scope, idempotency_key, request_hash, response_json)
        VALUES ($1, $2, 'model-provider.write', $3, $4, $5::jsonb)`, [input.organizationId, input.principalId, input.idempotencyKey, input.requestHash, responseJson]);
      const eventPayload = JSON.stringify({ provider: input.provider, maskedSuffix: input.maskedSuffix });
      await client.query('SELECT id FROM organizations WHERE id = $1 FOR UPDATE', [input.organizationId]);
      const lastAuditEvent = await client.query<{ event_hash: string }>('SELECT event_hash FROM audit_events WHERE organization_id = $1 ORDER BY sequence DESC LIMIT 1', [input.organizationId]);
      const previousHash = lastAuditEvent.rows[0]?.event_hash.trim() ?? null;
      const eventHash = digest(`${previousHash ?? ''}|${input.organizationId}|${input.principalId}|MODEL_PROVIDER_CREDENTIAL_WRITTEN|${eventPayload}`);
      await client.query(`INSERT INTO audit_events (organization_id, actor_type, actor_id, event_type, subject_type, subject_id, correlation_id, payload, previous_hash, event_hash)
        VALUES ($1, 'HUMAN', $2, 'MODEL_PROVIDER_CREDENTIAL_WRITTEN', 'MODEL_PROVIDER', $3, $4, $5::jsonb, $6, $7)`, [input.organizationId, input.principalId, input.provider, input.idempotencyKey, eventPayload, previousHash, eventHash]);
      await client.query(`INSERT INTO outbox_events (organization_id, aggregate_type, aggregate_id, event_type, payload) VALUES ($1, 'MODEL_PROVIDER', $2, 'MODEL_PROVIDER_CREDENTIAL_WRITTEN', $3::jsonb)`, [input.organizationId, input.provider, eventPayload]);
      await client.query('COMMIT');
      return { kind: 'CREATED', credential: summary, replacedSecretReference };
    } catch (error: unknown) {
      await client.query('ROLLBACK');
      throw error;
    } finally { client.release(); }
  }

  public async updateCredentialState(organizationId: string, principalId: string, provider: ModelProvider, state: ModelCredentialState): Promise<ModelCredentialRecord | null> {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN'); await requireAdministrator(client, organizationId, principalId);
      const result = await client.query<CredentialRow>(`UPDATE model_provider_credentials SET state = $3, disabled_at = CASE WHEN $3 = 'DISABLED' THEN now() ELSE NULL END WHERE organization_id = $1 AND provider = $2 RETURNING provider, secret_reference, masked_suffix, state, created_at, rotated_at, verified_at, disabled_at`, [organizationId, provider, state]);
      await client.query('COMMIT'); const row = result.rows[0]; return row === undefined ? null : mapRecord(row);
    } catch (error: unknown) { await client.query('ROLLBACK'); throw error; } finally { client.release(); }
  }

  public async deleteCredential(organizationId: string, principalId: string, provider: ModelProvider): Promise<ModelCredentialRecord | null> {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN'); await requireAdministrator(client, organizationId, principalId);
      const result = await client.query<CredentialRow>(`DELETE FROM model_provider_credentials WHERE organization_id = $1 AND provider = $2 RETURNING provider, secret_reference, masked_suffix, state, created_at, rotated_at, verified_at, disabled_at`, [organizationId, provider]);
      await client.query('COMMIT'); const row = result.rows[0]; return row === undefined ? null : mapRecord(row);
    } catch (error: unknown) { await client.query('ROLLBACK'); throw error; } finally { client.release(); }
  }

  public async markVerified(organizationId: string, provider: ModelProvider, state: ModelCredentialState): Promise<void> {
    await this.pool.query(`UPDATE model_provider_credentials SET verified_at = CASE WHEN $3 = 'ACTIVE' THEN now() ELSE verified_at END, state = $3 WHERE organization_id = $1 AND provider = $2`, [organizationId, provider, state]);
  }
}
