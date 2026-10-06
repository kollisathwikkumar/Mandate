import { randomUUID } from 'node:crypto';
import { Client, Pool } from 'pg';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { migrate } from '../../../packages/adapters/src/postgres/migrate.js';
import { OutboxWorker } from '../src/outbox-worker.js';

const connectionString = process.env.DATABASE_URL;

describe.skipIf(connectionString === undefined)('PostgreSQL outbox worker (integration)', () => {
  let pool: Pool;

  beforeAll(async () => {
    pool = new Pool({ connectionString });
    const client = new Client({ connectionString });
    await client.connect();
    await migrate(client);
    await client.end();
  });

  afterAll(async () => pool?.end());

  it('projects a claimed outbox event to one durable alert and marks it delivered exactly once', async () => {
    const organizationId = `worker-${randomUUID()}`;
    const eventId = randomUUID();
    const unknownEventId = randomUUID();
    const protectionEventId = randomUUID();
    const revocationEventId = randomUUID();
    const authorizationEventId = randomUUID();
    const executionEventId = randomUUID();
    const reconciledEventId = randomUUID();
    const replacedEventId = randomUUID();
    const droppedEventId = randomUUID();
    const deepReorgEventId = randomUUID();
    await pool.query('INSERT INTO organizations (id, display_name) VALUES ($1, $2)', [organizationId, 'Worker integration']);
    await pool.query(
      `INSERT INTO outbox_events (id, organization_id, aggregate_type, aggregate_id, event_type, payload)
       VALUES ($1, $2, 'ACTION', 'worker-action', 'ACTION_BLOCKED', '{"reason":"TARGET_DENIED"}'::jsonb)`,
      [eventId, organizationId],
    );
    await pool.query(
      `INSERT INTO outbox_events (id, organization_id, aggregate_type, aggregate_id, event_type, payload)
       VALUES ($1, $2, 'CUSTOM', 'custom-event', 'CUSTOM_EVENT', '{"apiKey":"sk-test-secret"}'::jsonb)`,
      [unknownEventId, organizationId],
    );
    await pool.query(
      `INSERT INTO outbox_events (id, organization_id, aggregate_type, aggregate_id, event_type, payload)
       VALUES ($1, $2, 'ACCOUNT', 'protected-account', 'ACCOUNT_PROTECTION_PAUSED', '{"reasonCode":"SAFE_GUARD_CHANGED"}'::jsonb)`,
      [protectionEventId, organizationId],
    );
    await pool.query(
      `INSERT INTO outbox_events (id, organization_id, aggregate_type, aggregate_id, event_type, payload)
       VALUES ($1, $2, 'POLICY', 'revoked-policy', 'POLICY_REVOKED', '{"policyEpoch":"7"}'::jsonb)`,
      [revocationEventId, organizationId],
    );
    await pool.query(
      `INSERT INTO outbox_events (id, organization_id, aggregate_type, aggregate_id, event_type, payload)
       VALUES ($1, $2, 'ACTION', 'authorized-action', 'ACTION_AUTHORIZED', '{"actionHash":"0xabc"}'::jsonb)`,
      [authorizationEventId, organizationId],
    );
    await pool.query(
      `INSERT INTO outbox_events (id, organization_id, aggregate_type, aggregate_id, event_type, payload)
       VALUES ($1, $2, 'ACTION', 'submitted-action', 'ACTION_SUBMITTED', '{"transactionHash":"0xabc"}'::jsonb)`,
      [executionEventId, organizationId],
    );
    await pool.query(
      `INSERT INTO outbox_events (id, organization_id, aggregate_type, aggregate_id, event_type, payload)
       VALUES ($1, $2, 'ACTION', 'reconciled-action', 'ACTION_RECONCILED', '{"transactionHash":"0xabc"}'::jsonb)`,
      [reconciledEventId, organizationId],
    );
    await pool.query(
      `INSERT INTO outbox_events (id, organization_id, aggregate_type, aggregate_id, event_type, payload)
       VALUES ($1, $2, 'ACTION', 'replaced-action', 'ACTION_TRANSACTION_REPLACED', '{"transactionHash":"0xabc"}'::jsonb)`,
      [replacedEventId, organizationId],
    );
    await pool.query(
      `INSERT INTO outbox_events (id, organization_id, aggregate_type, aggregate_id, event_type, payload)
       VALUES ($1, $2, 'ACTION', 'dropped-action', 'ACTION_DROPPED', '{"transactionHash":"0xabc"}'::jsonb)`,
      [droppedEventId, organizationId],
    );
    await pool.query(
      `INSERT INTO outbox_events (id, organization_id, aggregate_type, aggregate_id, event_type, payload)
       VALUES ($1, $2, 'ACTION', 'reorged-action', 'ACTION_DEEP_REORG_DETECTED', '{"transactionHash":"0xabc"}'::jsonb)`,
      [deepReorgEventId, organizationId],
    );

    const worker = new OutboxWorker(pool);
    const concurrentResults = await Promise.all([worker.runBatch(1, organizationId), new OutboxWorker(pool).runBatch(1, organizationId)]);
    expect(concurrentResults.reduce((sum, result) => sum + result.delivered, 0)).toBe(2);
    const allFixtureEvents = [eventId, unknownEventId, protectionEventId, revocationEventId, authorizationEventId, executionEventId, reconciledEventId, replacedEventId, droppedEventId, deepReorgEventId];
    let allDelivered = false;
    for (let attempt = 0; attempt < 250 && !allDelivered; attempt += 1) {
      await worker.runBatch(10, organizationId);
      const status = await pool.query<{ delivered: boolean }>(
        'SELECT bool_and(delivered_at IS NOT NULL) AS delivered FROM outbox_events WHERE id = ANY($1::uuid[])',
        [allFixtureEvents],
      );
      allDelivered = status.rows[0]?.delivered === true;
    }
    expect(allDelivered).toBe(true);
    const stored = await pool.query<{ event_type: string; title: string; delivered_at: Date | null; attempts: number }>(
      `SELECT n.event_type, n.title, o.delivered_at, o.attempts FROM outbox_events o
       JOIN alert_notifications n ON n.outbox_event_id = o.id WHERE o.id = $1`,
      [eventId],
    );
    expect(stored.rows).toHaveLength(1);
    expect(stored.rows[0]?.event_type).toBe('ACTION_BLOCKED');
    expect(stored.rows[0]?.title).toBe('Action blocked');
    expect(stored.rows[0]?.delivered_at).toBeInstanceOf(Date);
    expect(stored.rows[0]?.attempts).toBe(1);
    const genericAlert = await pool.query<{ event_type: string; title: string; aggregate_id: string }>(
      'SELECT event_type, title, aggregate_id FROM alert_notifications WHERE outbox_event_id = $1',
      [unknownEventId],
    );
    expect(genericAlert.rows[0]).toEqual({ event_type: 'ORGANIZATION_ACTIVITY', title: 'Organization activity', aggregate_id: unknownEventId });

    await worker.runBatch(100, organizationId);
    const notificationCount = await pool.query<{ count: string }>(
      'SELECT count(*)::text AS count FROM alert_notifications WHERE outbox_event_id = $1',
      [eventId],
    );
    expect(notificationCount.rows[0]?.count).toBe('1');
    const replayAttempts = await pool.query<{ attempts: number }>('SELECT attempts FROM outbox_events WHERE id = $1', [eventId]);
    expect(replayAttempts.rows[0]?.attempts).toBe(1);
    const noSecretProjection = await pool.query<{ has_secret: boolean }>(
      `SELECT (title || event_type || aggregate_id) LIKE '%sk-test-secret%' AS has_secret
       FROM alert_notifications WHERE outbox_event_id = $1`,
      [unknownEventId],
    );
    expect(noSecretProjection.rows[0]?.has_secret).toBe(false);
    const protectionAlert = await pool.query<{ event_type: string; title: string; aggregate_id: string }>(
      'SELECT event_type, title, aggregate_id FROM alert_notifications WHERE outbox_event_id = $1', [protectionEventId],
    );
    expect(protectionAlert.rows).toEqual([{ event_type: 'ACCOUNT_PROTECTION_PAUSED', title: 'Account protection paused', aggregate_id: 'protected-account' }]);
    const revocationAlert = await pool.query<{ event_type: string; title: string; aggregate_id: string }>(
      'SELECT event_type, title, aggregate_id FROM alert_notifications WHERE outbox_event_id = $1', [revocationEventId],
    );
    expect(revocationAlert.rows).toEqual([{ event_type: 'POLICY_REVOKED', title: 'Policy revoked', aggregate_id: 'revoked-policy' }]);
    const authorizationAlert = await pool.query<{ event_type: string; title: string; aggregate_id: string }>(
      'SELECT event_type, title, aggregate_id FROM alert_notifications WHERE outbox_event_id = $1', [authorizationEventId],
    );
    expect(authorizationAlert.rows).toEqual([{ event_type: 'ACTION_AUTHORIZED', title: 'Action authorized', aggregate_id: 'authorized-action' }]);
    const executionAlert = await pool.query<{ event_type: string; title: string; aggregate_id: string }>(
      'SELECT event_type, title, aggregate_id FROM alert_notifications WHERE outbox_event_id = $1', [executionEventId],
    );
    expect(executionAlert.rows).toEqual([{ event_type: 'ACTION_SUBMITTED', title: 'Action submitted', aggregate_id: 'submitted-action' }]);
    const reconciledAlert = await pool.query<{ event_type: string; title: string; aggregate_id: string }>(
      'SELECT event_type, title, aggregate_id FROM alert_notifications WHERE outbox_event_id = $1', [reconciledEventId],
    );
    expect(reconciledAlert.rows).toEqual([{ event_type: 'ACTION_RECONCILED', title: 'Action settled', aggregate_id: 'reconciled-action' }]);
    const replacedAlert = await pool.query<{ event_type: string; title: string; aggregate_id: string }>(
      'SELECT event_type, title, aggregate_id FROM alert_notifications WHERE outbox_event_id = $1', [replacedEventId],
    );
    expect(replacedAlert.rows).toEqual([{ event_type: 'ACTION_TRANSACTION_REPLACED', title: 'Action transaction replaced', aggregate_id: 'replaced-action' }]);
    const droppedAlert = await pool.query<{ event_type: string; title: string; aggregate_id: string }>(
      'SELECT event_type, title, aggregate_id FROM alert_notifications WHERE outbox_event_id = $1', [droppedEventId],
    );
    expect(droppedAlert.rows).toEqual([{ event_type: 'ACTION_DROPPED', title: 'Action dropped', aggregate_id: 'dropped-action' }]);
    const deepReorgAlert = await pool.query<{ event_type: string; title: string; aggregate_id: string }>(
      'SELECT event_type, title, aggregate_id FROM alert_notifications WHERE outbox_event_id = $1', [deepReorgEventId],
    );
    expect(deepReorgAlert.rows).toEqual([{ event_type: 'ACTION_DEEP_REORG_DETECTED', title: 'Finalized execution reorganized', aggregate_id: 'reorged-action' }]);
  });
});
