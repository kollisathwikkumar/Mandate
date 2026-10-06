import { createHash } from 'node:crypto';
import type { Pool, PoolClient } from 'pg';
import { z } from 'zod';
import { RepositoryAccessError } from '../../../ports/src/repository-errors.js';
import { WEBHOOK_EVENT_TYPES, type WebhookDeliverySummary, type WebhookEndpointRepository, type WebhookEndpointSummary, type WebhookEventType, type WebhookRemovalOutcome, type WebhookSecretRotationOutcome } from '../../../ports/src/webhook.js';

interface EndpointRow {
  readonly id: string;
  readonly url: string;
  readonly event_types: string[];
  readonly enabled: boolean;
  readonly created_at: Date;
  readonly updated_at: Date;
  readonly signing_secret_ref: string | null;
  readonly previous_signing_secret_ref?: string | null;
  readonly deleted_at?: Date | null;
}

interface ExistingIdempotencyRow {
  readonly request_hash: string;
  readonly response_json: unknown;
}

interface RoleRow { readonly role: string; }
interface SecretReferenceRow {
  readonly signing_secret_ref: string | null;
  readonly previous_signing_secret_ref?: string | null;
  readonly deleted_at: Date | null;
}

const EndpointSummarySchema = z.object({
  id: z.string().uuid(), url: z.string(), eventTypes: z.array(z.enum(WEBHOOK_EVENT_TYPES)),
  enabled: z.boolean(), createdAt: z.string().datetime(), updatedAt: z.string().datetime(),
}).strict();

const toSummary = (row: EndpointRow): WebhookEndpointSummary => EndpointSummarySchema.parse({
  id: row.id, url: row.url, eventTypes: row.event_types,
  enabled: row.enabled, createdAt: row.created_at.toISOString(), updatedAt: row.updated_at.toISOString(),
});

const digest = (value: string): string => `0x${createHash('sha256').update(value, 'utf8').digest('hex')}`;

export class WebhookConflictError extends Error {
  public constructor(public readonly code: 'IDEMPOTENCY_CONFLICT' | 'RESOURCE_CONFLICT') {
    super(code === 'IDEMPOTENCY_CONFLICT' ? 'Webhook idempotency key conflicts with a prior request' : 'Webhook endpoint state conflicts with the request');
    this.name = 'WebhookConflictError';
  }
}

async function requireAdministrator(client: PoolClient, organizationId: string, principalId: string): Promise<void> {
  const result = await client.query<RoleRow>(
    'SELECT role FROM members WHERE organization_id = $1 AND subject = $2 FOR UPDATE', [organizationId, principalId],
  );
  const role = result.rows[0]?.role;
  if (role === undefined) throw new RepositoryAccessError(404);
  if (role !== 'OWNER' && role !== 'ADMIN') throw new RepositoryAccessError(403);
}

async function lockIdempotency(client: PoolClient, input: {
  readonly organizationId: string; readonly principalId: string; readonly idempotencyKey: string; readonly scope: string;
}): Promise<void> {
  await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1, 0))', [
    `${input.organizationId}|${input.principalId}|${input.scope}|${input.idempotencyKey}`,
  ]);
  await client.query(
    'DELETE FROM command_idempotency WHERE organization_id = $1 AND principal_id = $2 AND scope = $3 AND idempotency_key = $4 AND expires_at <= now()',
    [input.organizationId, input.principalId, input.scope, input.idempotencyKey],
  );
}

async function findIdempotency(client: PoolClient, input: {
  readonly organizationId: string; readonly principalId: string; readonly idempotencyKey: string; readonly scope: string;
}): Promise<ExistingIdempotencyRow | null> {
  const result = await client.query<ExistingIdempotencyRow>(
    `SELECT request_hash, response_json FROM command_idempotency
     WHERE organization_id = $1 AND principal_id = $2 AND scope = $3 AND idempotency_key = $4 AND expires_at > now()`,
    [input.organizationId, input.principalId, input.scope, input.idempotencyKey],
  );
  return result.rows[0] ?? null;
}

async function saveIdempotency(client: PoolClient, input: {
  readonly organizationId: string; readonly principalId: string; readonly idempotencyKey: string;
  readonly scope: string; readonly requestHash: string; readonly response: unknown;
}): Promise<void> {
  await client.query(
    `INSERT INTO command_idempotency (organization_id, principal_id, scope, idempotency_key, request_hash, response_json)
     VALUES ($1, $2, $3, $4, $5, $6::jsonb)`,
    [input.organizationId, input.principalId, input.scope, input.idempotencyKey, input.requestHash, JSON.stringify(input.response)],
  );
}

async function auditAndOutbox(client: PoolClient, input: {
  readonly organizationId: string; readonly principalId: string; readonly correlationId: string;
  readonly eventType: 'WEBHOOK_ENDPOINT_CREATED' | 'WEBHOOK_ENDPOINT_UPDATED' | 'WEBHOOK_ENDPOINT_DELETED';
  readonly endpointId: string; readonly payload: Readonly<Record<string, string | boolean | readonly string[]>>;
}): Promise<void> {
  await client.query('SELECT id FROM organizations WHERE id = $1 FOR UPDATE', [input.organizationId]);
  const previous = await client.query<{ event_hash: string }>(
    'SELECT event_hash FROM audit_events WHERE organization_id = $1 ORDER BY sequence DESC LIMIT 1', [input.organizationId],
  );
  const previousHash = previous.rows[0]?.event_hash.trim() ?? null;
  const payloadText = JSON.stringify(input.payload);
  const eventHash = digest(`${previousHash ?? ''}|${input.organizationId}|${input.principalId}|${input.eventType}|${payloadText}`);
  await client.query(
    `INSERT INTO audit_events (organization_id, actor_type, actor_id, event_type, subject_type, subject_id, correlation_id, payload, previous_hash, event_hash)
     VALUES ($1, 'HUMAN', $2, $3, 'WEBHOOK_ENDPOINT', $4, $5, $6::jsonb, $7, $8)`,
    [input.organizationId, input.principalId, input.eventType, input.endpointId, input.correlationId, payloadText, previousHash, eventHash],
  );
  await client.query(
    `INSERT INTO outbox_events (organization_id, aggregate_type, aggregate_id, event_type, payload)
     VALUES ($1, 'WEBHOOK_ENDPOINT', $2, $3, $4::jsonb)`,
    [input.organizationId, input.endpointId, input.eventType, payloadText],
  );
}

async function begin(client: PoolClient): Promise<void> { await client.query('BEGIN'); }
async function commit(client: PoolClient): Promise<void> { await client.query('COMMIT'); }
async function rollback(client: PoolClient): Promise<void> { await client.query('ROLLBACK'); }

export class WebhookEndpointStore implements WebhookEndpointRepository {
  public constructor(private readonly pool: Pool) {}

  public async getHumanRole(organizationId: string, subject: string): Promise<string | null> {
    const result = await this.pool.query<RoleRow>('SELECT role FROM members WHERE organization_id = $1 AND subject = $2', [organizationId, subject]);
    return result.rows[0]?.role ?? null;
  }

  public async list(organizationId: string, principalId: string): Promise<readonly WebhookEndpointSummary[]> {
    const result = await this.pool.query<EndpointRow>(
      `SELECT endpoint.id::text, endpoint.url, endpoint.event_types, endpoint.enabled, endpoint.created_at, endpoint.updated_at,
              endpoint.signing_secret_ref
       FROM webhook_endpoints endpoint
       WHERE endpoint.organization_id = $1 AND endpoint.deleted_at IS NULL
         AND EXISTS (SELECT 1 FROM members member WHERE member.organization_id = endpoint.organization_id
           AND member.subject = $2 AND member.role IN ('OWNER', 'ADMIN'))
       ORDER BY endpoint.created_at, endpoint.id`,
      [organizationId, principalId],
    );
    return result.rows.map(toSummary);
  }

  public async create(input: {
    readonly organizationId: string; readonly principalId: string; readonly endpointId: string;
    readonly idempotencyKey: string; readonly requestHash: string; readonly url: string;
    readonly eventTypes: readonly WebhookEventType[]; readonly secretReference: string;
  }): Promise<{ readonly kind: 'CREATED' | 'REPLAY'; readonly endpoint: WebhookEndpointSummary }> {
    const client = await this.pool.connect();
    try {
      await begin(client);
      await requireAdministrator(client, input.organizationId, input.principalId);
      const scope = 'webhook.create';
      await lockIdempotency(client, { ...input, scope });
      const prior = await findIdempotency(client, { ...input, scope });
      if (prior !== null) {
        if (prior.request_hash.trim() !== input.requestHash) throw new WebhookConflictError('IDEMPOTENCY_CONFLICT');
        const previousSummary = EndpointSummarySchema.parse(prior.response_json);
        const current = await client.query<EndpointRow>(
          `SELECT id::text, url, event_types, enabled, created_at, updated_at, signing_secret_ref
           FROM webhook_endpoints WHERE organization_id = $1 AND id = $2 AND deleted_at IS NULL`,
          [input.organizationId, previousSummary.id],
        );
        const row = current.rows[0];
        if (row === undefined) throw new WebhookConflictError('RESOURCE_CONFLICT');
        await commit(client);
        return { kind: 'REPLAY', endpoint: toSummary(row) };
      }
      const inserted = await client.query<EndpointRow>(
        `INSERT INTO webhook_endpoints (id, organization_id, url, signing_secret_ref, event_types, enabled)
         VALUES ($1, $2, $3, $4, $5, true)
         RETURNING id::text, url, event_types, enabled, created_at, updated_at, signing_secret_ref`,
        [input.endpointId, input.organizationId, input.url, input.secretReference, input.eventTypes],
      );
      const row = inserted.rows[0];
      if (row === undefined) throw new Error('Webhook endpoint insert returned no row');
      const endpoint = toSummary(row);
      await saveIdempotency(client, { ...input, scope, response: endpoint });
      const hostname = new URL(input.url).hostname;
      await auditAndOutbox(client, {
        organizationId: input.organizationId, principalId: input.principalId, correlationId: input.idempotencyKey,
        eventType: 'WEBHOOK_ENDPOINT_CREATED', endpointId: endpoint.id,
        payload: { endpointId: endpoint.id, host: hostname, eventTypes: endpoint.eventTypes, enabled: true },
      });
      await commit(client);
      return { kind: 'CREATED', endpoint };
    } catch (error: unknown) {
      await rollback(client);
      throw error;
    } finally { client.release(); }
  }

  public async rotateSecret(input: {
    readonly organizationId: string; readonly principalId: string; readonly endpointId: string;
    readonly idempotencyKey: string; readonly requestHash: string; readonly secretReference: string;
  }): Promise<WebhookSecretRotationOutcome> {
    const client = await this.pool.connect();
    try {
      await begin(client);
      await requireAdministrator(client, input.organizationId, input.principalId);
      const scope = `webhook.rotate.${input.endpointId}`;
      await lockIdempotency(client, { ...input, scope });
      const prior = await findIdempotency(client, { ...input, scope });
      if (prior !== null) {
        if (prior.request_hash.trim() !== input.requestHash) throw new WebhookConflictError('IDEMPOTENCY_CONFLICT');
        const pending = await client.query<SecretReferenceRow>(
          `SELECT signing_secret_ref, previous_signing_secret_ref, deleted_at FROM webhook_endpoints
           WHERE organization_id = $1 AND id = $2`, [input.organizationId, input.endpointId],
        );
        if (pending.rows[0] === undefined) throw new RepositoryAccessError(404);
        await commit(client);
        return { kind: 'REPLAY', priorSecretReference: pending.rows[0].previous_signing_secret_ref ?? null };
      }
      const locked = await client.query<SecretReferenceRow>(
        `SELECT signing_secret_ref, previous_signing_secret_ref, deleted_at FROM webhook_endpoints
         WHERE organization_id = $1 AND id = $2 FOR UPDATE`, [input.organizationId, input.endpointId],
      );
      const current = locked.rows[0];
      if (current === undefined || current.deleted_at !== null) throw new RepositoryAccessError(404);
      if (current.previous_signing_secret_ref !== null && current.previous_signing_secret_ref !== undefined) throw new WebhookConflictError('RESOURCE_CONFLICT');
      const updated = await client.query<SecretReferenceRow>(
        `UPDATE webhook_endpoints SET previous_signing_secret_ref = signing_secret_ref, signing_secret_ref = $3, updated_at = now()
         WHERE organization_id = $1 AND id = $2 AND deleted_at IS NULL
         RETURNING signing_secret_ref, previous_signing_secret_ref, deleted_at`,
        [input.organizationId, input.endpointId, input.secretReference],
      );
      const row = updated.rows[0];
      if (row === undefined) throw new RepositoryAccessError(404);
      const priorSecretReference = current.signing_secret_ref;
      await saveIdempotency(client, { ...input, scope, response: { rotated: true } });
      await auditAndOutbox(client, {
        organizationId: input.organizationId, principalId: input.principalId, correlationId: input.idempotencyKey,
        eventType: 'WEBHOOK_ENDPOINT_UPDATED', endpointId: input.endpointId,
        payload: { endpointId: input.endpointId, signingSecretRotated: true },
      });
      await commit(client);
      return { kind: 'ROTATED', priorSecretReference: priorSecretReference ?? null };
    } catch (error: unknown) {
      await rollback(client);
      throw error;
    } finally { client.release(); }
  }

  public async setEnabled(input: {
    readonly organizationId: string; readonly principalId: string; readonly endpointId: string;
    readonly idempotencyKey: string; readonly requestHash: string; readonly enabled: boolean;
  }): Promise<{ readonly kind: 'UPDATED' | 'REPLAY'; readonly endpoint: WebhookEndpointSummary }> {
    const client = await this.pool.connect();
    try {
      await begin(client);
      await requireAdministrator(client, input.organizationId, input.principalId);
      const scope = `webhook.enabled.${input.endpointId}`;
      await lockIdempotency(client, { ...input, scope });
      const prior = await findIdempotency(client, { ...input, scope });
      if (prior !== null) {
        if (prior.request_hash.trim() !== input.requestHash) throw new WebhookConflictError('IDEMPOTENCY_CONFLICT');
        const stored = EndpointSummarySchema.parse(prior.response_json);
        const current = await client.query<EndpointRow>(
          `SELECT id::text, url, event_types, enabled, created_at, updated_at, signing_secret_ref
           FROM webhook_endpoints WHERE organization_id = $1 AND id = $2 AND deleted_at IS NULL`,
          [input.organizationId, stored.id],
        );
        const row = current.rows[0];
        if (row === undefined) throw new RepositoryAccessError(404);
        await commit(client);
        return { kind: 'REPLAY', endpoint: toSummary(row) };
      }
      const update = await client.query<EndpointRow>(
        `UPDATE webhook_endpoints SET enabled = $3, updated_at = now()
         WHERE organization_id = $1 AND id = $2 AND deleted_at IS NULL
         RETURNING id::text, url, event_types, enabled, created_at, updated_at, signing_secret_ref`,
        [input.organizationId, input.endpointId, input.enabled],
      );
      const row = update.rows[0];
      if (row === undefined) throw new RepositoryAccessError(404);
      const endpoint = toSummary(row);
      await saveIdempotency(client, { ...input, scope, response: endpoint });
      await auditAndOutbox(client, {
        organizationId: input.organizationId, principalId: input.principalId, correlationId: input.idempotencyKey,
        eventType: 'WEBHOOK_ENDPOINT_UPDATED', endpointId: input.endpointId,
        payload: { endpointId: input.endpointId, enabled: input.enabled },
      });
      await commit(client);
      return { kind: 'UPDATED', endpoint };
    } catch (error: unknown) {
      await rollback(client);
      throw error;
    } finally { client.release(); }
  }

  public async disableAndRemove(input: {
    readonly organizationId: string; readonly principalId: string; readonly endpointId: string;
    readonly idempotencyKey: string; readonly requestHash: string;
  }): Promise<WebhookRemovalOutcome> {
    const client = await this.pool.connect();
    try {
      await begin(client);
      await requireAdministrator(client, input.organizationId, input.principalId);
      const scope = `webhook.delete.${input.endpointId}`;
      await lockIdempotency(client, { ...input, scope });
      const prior = await findIdempotency(client, { ...input, scope });
      if (prior !== null && prior.request_hash.trim() !== input.requestHash) throw new WebhookConflictError('IDEMPOTENCY_CONFLICT');
      const locked = await client.query<SecretReferenceRow>(
        `SELECT signing_secret_ref, deleted_at FROM webhook_endpoints WHERE organization_id = $1 AND id = $2 FOR UPDATE`,
        [input.organizationId, input.endpointId],
      );
      const row = locked.rows[0];
      if (row === undefined) throw new RepositoryAccessError(404);
      if (prior === null) {
        await client.query(
          `UPDATE webhook_endpoints SET enabled = false, deleted_at = COALESCE(deleted_at, now()), updated_at = now()
           WHERE organization_id = $1 AND id = $2`, [input.organizationId, input.endpointId],
        );
        await saveIdempotency(client, { ...input, scope, response: { removed: true } });
        if (row.deleted_at === null) {
          await auditAndOutbox(client, {
            organizationId: input.organizationId, principalId: input.principalId, correlationId: input.idempotencyKey,
            eventType: 'WEBHOOK_ENDPOINT_DELETED', endpointId: input.endpointId,
            payload: { endpointId: input.endpointId, enabled: false },
          });
        }
      }
      await commit(client);
      return { kind: prior === null ? 'REMOVED' : 'REPLAY', secretReference: row.signing_secret_ref };
    } catch (error: unknown) {
      await rollback(client);
      throw error;
    } finally { client.release(); }
  }

  public async clearSecretReference(input: { readonly organizationId: string; readonly endpointId: string; readonly secretReference: string }): Promise<void> {
    await this.pool.query(
      `UPDATE webhook_endpoints SET signing_secret_ref = NULL, updated_at = now()
       WHERE organization_id = $1 AND id = $2 AND deleted_at IS NOT NULL AND signing_secret_ref = $3`,
      [input.organizationId, input.endpointId, input.secretReference],
    );
  }

  public async clearPriorSecretReference(input: { readonly organizationId: string; readonly endpointId: string; readonly secretReference: string }): Promise<void> {
    await this.pool.query(
      `UPDATE webhook_endpoints SET previous_signing_secret_ref = NULL, updated_at = now()
       WHERE organization_id = $1 AND id = $2 AND previous_signing_secret_ref = $3`,
      [input.organizationId, input.endpointId, input.secretReference],
    );
  }

  public async listDeliveries(input: { readonly organizationId: string; readonly principalId: string; readonly endpointId: string; readonly limit: number }): Promise<readonly WebhookDeliverySummary[]> {
    const endpoint = await this.pool.query(
      `SELECT 1 FROM webhook_endpoints endpoint
       WHERE endpoint.organization_id = $1 AND endpoint.id = $2
         AND EXISTS (SELECT 1 FROM members member WHERE member.organization_id = endpoint.organization_id
           AND member.subject = $3 AND member.role IN ('OWNER', 'ADMIN'))`,
      [input.organizationId, input.endpointId, input.principalId],
    );
    if (endpoint.rowCount === 0) throw new RepositoryAccessError(404);
    const result = await this.pool.query<{
      id: string; endpoint_id: string; event_type: string; status: 'PENDING' | 'DELIVERED' | 'FAILED';
      attempts: number; available_at: Date; delivered_at: Date | null; last_error_code: string | null;
    }>(
      `SELECT delivery.id::text, delivery.endpoint_id::text, event.event_type, delivery.status, delivery.attempts,
              delivery.available_at, delivery.delivered_at, delivery.last_error_code
       FROM webhook_deliveries delivery
       JOIN outbox_events event ON event.organization_id = delivery.organization_id AND event.id = delivery.outbox_event_id
       WHERE delivery.organization_id = $1 AND delivery.endpoint_id = $2
         AND EXISTS (SELECT 1 FROM members member WHERE member.organization_id = delivery.organization_id
           AND member.subject = $4 AND member.role IN ('OWNER', 'ADMIN'))
       ORDER BY delivery.created_at DESC, delivery.id DESC LIMIT $3`,
      [input.organizationId, input.endpointId, input.limit, input.principalId],
    );
    return result.rows.map((row) => ({
      id: row.id, endpointId: row.endpoint_id, eventType: row.event_type, status: row.status, attempts: row.attempts,
      availableAt: row.available_at.toISOString(), deliveredAt: row.delivered_at?.toISOString() ?? null, lastErrorCode: row.last_error_code,
    }));
  }
}
