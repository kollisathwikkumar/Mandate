import { createHmac, randomUUID } from 'node:crypto';
import { Client, Pool } from 'pg';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { migrate } from '../../../packages/adapters/src/postgres/migrate.js';
import type { WebhookSecretStore, WebhookTransport } from '../../../packages/ports/src/webhook.js';
import { OutboxWorker } from '../src/outbox-worker.js';
import { WebhookDeliveryWorker } from '../src/webhook-delivery-worker.js';

const connectionString = process.env.DATABASE_URL;
const testSecret = 'test-webhook-signing-secret-that-is-at-least-32-bytes';

describe.skipIf(connectionString === undefined)('signed webhook delivery (PostgreSQL integration)', () => {
  let pool: Pool;
  beforeAll(async () => {
    pool = new Pool({ connectionString });
    const client = new Client({ connectionString });
    await client.connect();
    await migrate(client);
    await client.end();
  });
  afterAll(async () => pool?.end());

  it('projects matching outbox events, signs the exact body, and marks one delivery complete', async () => {
    const organizationId = `webhook-${randomUUID()}`;
    const eventId = randomUUID();
    const endpointId = randomUUID();
    const seen: Parameters<WebhookTransport['send']>[0][] = [];
    await pool.query('INSERT INTO organizations (id, display_name) VALUES ($1, $2)', [organizationId, 'Webhook integration']);
    await pool.query(
      `INSERT INTO webhook_endpoints (id, organization_id, url, signing_secret_ref, event_types)
       VALUES ($1, $2, 'https://hooks.example.test/mandate', 'secret-ref', ARRAY['ACTION_BLOCKED'])`,
      [endpointId, organizationId],
    );
    await pool.query(
      `INSERT INTO outbox_events (id, organization_id, aggregate_type, aggregate_id, event_type, payload)
       VALUES ($1, $2, 'ACTION', 'action-1', 'ACTION_BLOCKED', '{"reason":"TARGET_DENIED","apiKey":"never-send-this"}'::jsonb)`,
      [eventId, organizationId],
    );
    await new OutboxWorker(pool).runBatch(25, organizationId);
    const secretStore: WebhookSecretStore = {
      async put() { return 'unused'; }, async get() { return testSecret; }, async delete() {},
    };
    const transport: WebhookTransport = { async send(input) { seen.push(input); return 204; } };
    const worker = new WebhookDeliveryWorker(pool, secretStore, transport);
    await expect(worker.runBatch(25, organizationId)).resolves.toEqual({ claimed: 1, delivered: 1, retried: 0, failed: 0 });
    expect(seen).toHaveLength(1);
    const delivered = seen[0];
    expect(delivered?.url).toBe('https://hooks.example.test/mandate');
    expect(delivered?.eventType).toBe('ACTION_BLOCKED');
    expect(delivered?.signature).toMatch(/^sha256=[0-9a-f]{64}$/);
    expect(delivered?.signature).toBe(`sha256=${createHmac('sha256', testSecret).update(`${delivered?.timestampSeconds}.${delivered?.body}`).digest('hex')}`);
    const payload = JSON.parse(delivered?.body ?? '{}') as Record<string, unknown>;
    expect(payload).toMatchObject({ id: eventId, organizationId, eventType: 'ACTION_BLOCKED', aggregateType: 'ACTION', aggregateId: 'action-1', data: { reason: 'TARGET_DENIED' } });
    expect(delivered?.body).not.toContain('never-send-this');
    const row = await pool.query<{ status: string; attempts: number; delivered_at: Date | null }>(
      'SELECT status, attempts, delivered_at FROM webhook_deliveries WHERE organization_id = $1 AND endpoint_id = $2 AND outbox_event_id = $3',
      [organizationId, endpointId, eventId],
    );
    expect(row.rows).toEqual([expect.objectContaining({ status: 'DELIVERED', attempts: 1, delivered_at: expect.any(Date) })]);
    await worker.runBatch(25, organizationId);
    expect(seen).toHaveLength(1);
  });

  it('does not enqueue unmatched events and records failed deliveries for disabled endpoints', async () => {
    const organizationId = `webhook-disabled-${randomUUID()}`;
    const eventId = randomUUID();
    const endpointId = randomUUID();
    await pool.query('INSERT INTO organizations (id, display_name) VALUES ($1, $2)', [organizationId, 'Webhook disabled integration']);
    await pool.query(
      `INSERT INTO webhook_endpoints (id, organization_id, url, signing_secret_ref, event_types, enabled)
       VALUES ($1, $2, 'https://hooks.example.test/mandate', 'secret-ref', ARRAY['ACTION_RECONCILED'], false)`,
      [endpointId, organizationId],
    );
    await pool.query(
      `INSERT INTO outbox_events (id, organization_id, aggregate_type, aggregate_id, event_type, payload)
       VALUES ($1, $2, 'ACTION', 'action-2', 'ACTION_BLOCKED', '{}'::jsonb)`,
      [eventId, organizationId],
    );
    await new OutboxWorker(pool).runBatch(25, organizationId);
    const pending = await pool.query('SELECT id FROM webhook_deliveries WHERE organization_id = $1', [organizationId]);
    expect(pending.rowCount).toBe(0);
  });

  it('backs off transient failures and stops after the bounded attempt count', async () => {
    const organizationId = `webhook-retry-${randomUUID()}`;
    const eventId = randomUUID();
    const endpointId = randomUUID();
    await pool.query('INSERT INTO organizations (id, display_name) VALUES ($1, $2)', [organizationId, 'Webhook retry integration']);
    await pool.query(
      `INSERT INTO webhook_endpoints (id, organization_id, url, signing_secret_ref, event_types)
       VALUES ($1, $2, 'https://hooks.example.test/mandate', 'secret-ref', ARRAY['ACTION_BLOCKED'])`,
      [endpointId, organizationId],
    );
    await pool.query(
      `INSERT INTO outbox_events (id, organization_id, aggregate_type, aggregate_id, event_type, payload)
       VALUES ($1, $2, 'ACTION', 'action-retry', 'ACTION_BLOCKED', '{}'::jsonb)`,
      [eventId, organizationId],
    );
    await new OutboxWorker(pool).runBatch(25, organizationId);
    const secretStore: WebhookSecretStore = {
      async put() { return 'unused'; }, async get() { return testSecret; }, async delete() {},
    };
    const failingTransport: WebhookTransport = { async send() { return 503; } };
    const worker = new WebhookDeliveryWorker(pool, secretStore, failingTransport);
    await expect(worker.runBatch(25, organizationId)).resolves.toEqual({ claimed: 1, delivered: 0, retried: 1, failed: 0 });
    const scheduled = await pool.query<{ status: string; attempts: number; available_at: Date; last_error_code: string }>(
      'SELECT status, attempts, available_at, last_error_code FROM webhook_deliveries WHERE organization_id = $1 AND endpoint_id = $2 AND outbox_event_id = $3',
      [organizationId, endpointId, eventId],
    );
    expect(scheduled.rows[0]).toMatchObject({ status: 'PENDING', attempts: 1, last_error_code: 'HTTP_DELIVERY_FAILED' });
    expect(scheduled.rows[0]?.available_at.getTime()).toBeGreaterThan(Date.now());
    await pool.query('UPDATE webhook_deliveries SET attempts = 11, available_at = now() WHERE organization_id = $1 AND endpoint_id = $2 AND outbox_event_id = $3', [organizationId, endpointId, eventId]);
    await expect(worker.runBatch(25, organizationId)).resolves.toEqual({ claimed: 1, delivered: 0, retried: 0, failed: 1 });
    const terminal = await pool.query<{ status: string; attempts: number; last_error_code: string }>(
      'SELECT status, attempts, last_error_code FROM webhook_deliveries WHERE organization_id = $1 AND endpoint_id = $2 AND outbox_event_id = $3',
      [organizationId, endpointId, eventId],
    );
    expect(terminal.rows[0]).toEqual({ status: 'FAILED', attempts: 12, last_error_code: 'HTTP_DELIVERY_FAILED' });
  });
});
