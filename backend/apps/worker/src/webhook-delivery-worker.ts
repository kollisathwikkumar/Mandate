import { createHmac } from 'node:crypto';
import type { Pool, PoolClient } from 'pg';
import type { WebhookSecretStore, WebhookTransport } from '../../../packages/ports/src/webhook.js';

interface ClaimedDelivery {
  readonly id: string;
  readonly organization_id: string;
  readonly endpoint_id: string;
  readonly outbox_event_id: string;
  readonly endpoint_url: string;
  readonly signing_secret_ref: string;
  readonly event_type: string;
  readonly aggregate_type: string;
  readonly aggregate_id: string;
  readonly payload: unknown;
  readonly created_at: Date;
  readonly attempts: number;
}

export interface WebhookDeliveryBatchResult {
  readonly claimed: number;
  readonly delivered: number;
  readonly retried: number;
  readonly failed: number;
}

const MAX_ATTEMPTS = 12;
const MAX_BATCH_SIZE = 50;
const REDACTED_FIELD = /(?:secret|password|token|credential|signature|calldata|private.?key|mnemonic|seed|api.?key|raw.?prompt)/i;

function sanitizeWebhookValue(value: unknown, depth = 0): unknown {
  if (depth > 8) return '[TRUNCATED]';
  if (typeof value === 'string') return value.length > 2048 ? `${value.slice(0, 2048)}[TRUNCATED]` : value;
  if (typeof value === 'number' || typeof value === 'boolean' || value === null) return value;
  if (Array.isArray(value)) return value.slice(0, 100).map((entry) => sanitizeWebhookValue(entry, depth + 1));
  if (typeof value !== 'object') return null;
  const result: Record<string, unknown> = {};
  for (const [key, entry] of Object.entries(value)) {
    if (!REDACTED_FIELD.test(key)) result[key] = sanitizeWebhookValue(entry, depth + 1);
  }
  return result;
}

function payloadObject(value: unknown): Record<string, unknown> {
  const sanitized = sanitizeWebhookValue(value);
  if (typeof sanitized !== 'object' || sanitized === null || Array.isArray(sanitized)) return {};
  return sanitized as Record<string, unknown>;
}

async function claim(client: PoolClient, batchSize: number, organizationId?: string): Promise<readonly ClaimedDelivery[]> {
  await client.query(
    `UPDATE webhook_deliveries AS delivery
     SET status = 'FAILED', locked_at = NULL, last_error_code = 'ENDPOINT_DISABLED', updated_at = now()
     FROM webhook_endpoints AS endpoint
     WHERE delivery.organization_id = endpoint.organization_id AND delivery.endpoint_id = endpoint.id
       AND delivery.status = 'PENDING' AND ($1::text IS NULL OR delivery.organization_id = $1)
       AND (endpoint.enabled = false OR endpoint.deleted_at IS NOT NULL
         OR endpoint.signing_secret_ref IS NULL)`,
    [organizationId ?? null],
  );
  const result = await client.query<ClaimedDelivery>(
    `WITH ready AS (
       SELECT delivery.id
       FROM webhook_deliveries AS delivery
       JOIN webhook_endpoints AS endpoint
         ON endpoint.organization_id = delivery.organization_id AND endpoint.id = delivery.endpoint_id
       WHERE delivery.status = 'PENDING' AND delivery.available_at <= now()
         AND ($2::text IS NULL OR delivery.organization_id = $2)
         AND (delivery.locked_at IS NULL OR delivery.locked_at < now() - interval '60 seconds')
         AND endpoint.enabled = true AND endpoint.deleted_at IS NULL AND endpoint.signing_secret_ref IS NOT NULL
       ORDER BY delivery.available_at, delivery.created_at
       FOR UPDATE OF delivery SKIP LOCKED
       LIMIT $1
     )
     UPDATE webhook_deliveries AS delivery
     SET locked_at = now(), attempts = delivery.attempts + 1, updated_at = now()
     FROM ready, webhook_endpoints AS endpoint, outbox_events AS event
     WHERE delivery.id = ready.id AND endpoint.organization_id = delivery.organization_id
       AND endpoint.id = delivery.endpoint_id AND event.organization_id = delivery.organization_id
       AND event.id = delivery.outbox_event_id
     RETURNING delivery.id::text, delivery.organization_id, delivery.endpoint_id::text,
       delivery.outbox_event_id::text, endpoint.url AS endpoint_url, endpoint.signing_secret_ref,
       event.event_type, event.aggregate_type, event.aggregate_id, event.payload, event.created_at,
       delivery.attempts`,
    [batchSize, organizationId ?? null],
  );
  return result.rows;
}

async function markDelivered(pool: Pool, deliveryId: string): Promise<void> {
  await pool.query(
    `UPDATE webhook_deliveries SET status = 'DELIVERED', delivered_at = now(), locked_at = NULL,
       last_error_code = NULL, updated_at = now()
     WHERE id = $1 AND status = 'PENDING' AND locked_at IS NOT NULL`,
    [deliveryId],
  );
}

async function markFailure(pool: Pool, delivery: ClaimedDelivery, errorCode: string): Promise<'RETRIED' | 'FAILED'> {
  const final = delivery.attempts >= MAX_ATTEMPTS;
  const delaySeconds = Math.min(3600, 2 ** Math.min(delivery.attempts, 10));
  await pool.query(
    `UPDATE webhook_deliveries SET status = $2, locked_at = NULL,
       available_at = CASE WHEN $2 = 'PENDING' THEN now() + ($3 * interval '1 second') ELSE available_at END,
       last_error_code = $4, updated_at = now()
     WHERE id = $1 AND status = 'PENDING' AND locked_at IS NOT NULL`,
    [delivery.id, final ? 'FAILED' : 'PENDING', delaySeconds, errorCode],
  );
  return final ? 'FAILED' : 'RETRIED';
}

export class WebhookDeliveryWorker {
  public constructor(
    private readonly pool: Pool,
    private readonly secrets: WebhookSecretStore,
    private readonly transport: WebhookTransport,
  ) {}

  public async runBatch(batchSize = 25, organizationId?: string): Promise<WebhookDeliveryBatchResult> {
    if (!Number.isInteger(batchSize) || batchSize < 1 || batchSize > MAX_BATCH_SIZE) {
      throw new RangeError(`batchSize must be an integer from 1 to ${MAX_BATCH_SIZE}`);
    }
    const client = await this.pool.connect();
    let deliveries: readonly ClaimedDelivery[];
    try {
      await client.query('BEGIN');
      deliveries = await claim(client, batchSize, organizationId);
      await client.query('COMMIT');
    } catch (error: unknown) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }

    let delivered = 0;
    let retried = 0;
    let failed = 0;
    for (const delivery of deliveries) {
      try {
        const secret = await this.secrets.get(delivery.signing_secret_ref);
        if (Buffer.byteLength(secret, 'utf8') < 32 || Buffer.byteLength(secret, 'utf8') > 256) {
          throw new Error('WEBHOOK_SECRET_INVALID');
        }
        const timestampSeconds = Math.floor(Date.now() / 1000);
        const body = JSON.stringify({
          id: delivery.outbox_event_id,
          deliveryId: delivery.id,
          organizationId: delivery.organization_id,
          eventType: delivery.event_type,
          aggregateType: delivery.aggregate_type,
          aggregateId: delivery.aggregate_id,
          createdAt: delivery.created_at.toISOString(),
          data: payloadObject(delivery.payload),
        });
        const signature = `sha256=${createHmac('sha256', secret).update(`${timestampSeconds}.${body}`, 'utf8').digest('hex')}`;
        const statusCode = await this.transport.send({
          url: delivery.endpoint_url,
          deliveryId: delivery.id,
          eventType: delivery.event_type,
          timestampSeconds,
          body,
          signature,
        });
        if (statusCode >= 200 && statusCode < 300) {
          await markDelivered(this.pool, delivery.id);
          delivered += 1;
        } else {
          const outcome = await markFailure(this.pool, delivery, statusCode >= 300 && statusCode < 400 ? 'REDIRECT_REJECTED' : 'HTTP_DELIVERY_FAILED');
          if (outcome === 'RETRIED') retried += 1; else failed += 1;
        }
      } catch (error: unknown) {
        const errorCode = error instanceof Error && error.message === 'WEBHOOK_SECRET_INVALID'
          ? 'SECRET_INVALID'
          : error instanceof Error && error.message.startsWith('WEBHOOK_URL_')
            ? 'DESTINATION_REJECTED'
            : 'DELIVERY_FAILED';
        const outcome = await markFailure(this.pool, delivery, errorCode);
        if (outcome === 'RETRIED') retried += 1; else failed += 1;
      }
    }
    return { claimed: deliveries.length, delivered, retried, failed };
  }
}
