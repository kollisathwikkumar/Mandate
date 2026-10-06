import type { Pool, PoolClient } from 'pg';

interface ClaimedEvent {
  readonly id: string;
  readonly organization_id: string;
  readonly aggregate_id: string;
  readonly event_type: string;
  readonly attempts: number;
}

export interface OutboxBatchResult {
  readonly claimed: number;
  readonly delivered: number;
  readonly failed: number;
}

interface AlertProjection {
  readonly eventType: string;
  readonly title: string;
  readonly exposeAggregateId: boolean;
}

const ALERT_TYPES: Readonly<Record<string, AlertProjection>> = {
  ACTION_BLOCKED: { eventType: 'ACTION_BLOCKED', title: 'Action blocked', exposeAggregateId: true },
  ACTION_HELD: { eventType: 'ACTION_HELD', title: 'Approval requested', exposeAggregateId: true },
  ACTION_RESERVED: { eventType: 'ACTION_RESERVED', title: 'Action reserved', exposeAggregateId: true },
  ACTION_AUTHORIZED: { eventType: 'ACTION_AUTHORIZED', title: 'Action authorized', exposeAggregateId: true },
  ACTION_SUBMITTED: { eventType: 'ACTION_SUBMITTED', title: 'Action submitted', exposeAggregateId: true },
  ACTION_RECONCILED: { eventType: 'ACTION_RECONCILED', title: 'Action settled', exposeAggregateId: true },
  ACTION_DROPPED: { eventType: 'ACTION_DROPPED', title: 'Action dropped', exposeAggregateId: true },
  ACTION_DEEP_REORG_DETECTED: { eventType: 'ACTION_DEEP_REORG_DETECTED', title: 'Finalized execution reorganized', exposeAggregateId: true },
  ACTION_REVERTED: { eventType: 'ACTION_REVERTED', title: 'Action reverted', exposeAggregateId: true },
  ACTION_RECEIPT_REORGED: { eventType: 'ACTION_RECEIPT_REORGED', title: 'Action receipt reorganized', exposeAggregateId: true },
  ACTION_RECEIPT_TENTATIVE: { eventType: 'ACTION_RECEIPT_TENTATIVE', title: 'Action receipt pending finality', exposeAggregateId: true },
  ACTION_TRANSACTION_REPLACED: { eventType: 'ACTION_TRANSACTION_REPLACED', title: 'Action transaction replaced', exposeAggregateId: true },
  ACTION_APPROVED: { eventType: 'ACTION_APPROVED', title: 'Action approved', exposeAggregateId: true },
  ACTION_DENIED: { eventType: 'ACTION_DENIED', title: 'Action denied', exposeAggregateId: true },
  ACTION_EXPIRED: { eventType: 'ACTION_EXPIRED', title: 'Action expired', exposeAggregateId: true },
  POLICY_DRAFT_CREATED: { eventType: 'POLICY_DRAFT_CREATED', title: 'Policy draft created', exposeAggregateId: true },
  POLICY_REVISION_CREATED: { eventType: 'POLICY_REVISION_CREATED', title: 'Policy revision created', exposeAggregateId: true },
  POLICY_ACTIVATION_PLAN_CREATED: { eventType: 'POLICY_ACTIVATION_PLAN_CREATED', title: 'Policy activation awaiting owner execution', exposeAggregateId: true },
  POLICY_ACTIVATED: { eventType: 'POLICY_ACTIVATED', title: 'Policy activated', exposeAggregateId: true },
  POLICY_REVOCATION_PLAN_CREATED: { eventType: 'POLICY_REVOCATION_PLAN_CREATED', title: 'Policy revocation awaiting owner execution', exposeAggregateId: true },
  POLICY_REVOKED: { eventType: 'POLICY_REVOKED', title: 'Policy revoked', exposeAggregateId: true },
  AGENT_REGISTERED: { eventType: 'AGENT_REGISTERED', title: 'Agent registered', exposeAggregateId: true },
  ACCOUNT_PROTECTION_PAUSED: { eventType: 'ACCOUNT_PROTECTION_PAUSED', title: 'Account protection paused', exposeAggregateId: true },
};

function projectAlert(eventType: string): AlertProjection {
  return ALERT_TYPES[eventType] ?? { eventType: 'ORGANIZATION_ACTIVITY', title: 'Organization activity', exposeAggregateId: false };
}

async function claim(client: PoolClient, batchSize: number, organizationId?: string): Promise<readonly ClaimedEvent[]> {
  const result = await client.query<ClaimedEvent>(
    `WITH ready AS (
       SELECT id FROM outbox_events
       WHERE delivered_at IS NULL AND available_at <= now() AND ($2::text IS NULL OR organization_id = $2)
         AND (locked_at IS NULL OR locked_at < now() - interval '60 seconds')
       ORDER BY available_at, created_at
       FOR UPDATE SKIP LOCKED
       LIMIT $1
     )
     UPDATE outbox_events event
     SET locked_at = now(), attempts = event.attempts + 1
     FROM ready
     WHERE event.id = ready.id
     RETURNING event.id::text, event.organization_id, event.aggregate_id, event.event_type, event.attempts`,
    [batchSize, organizationId ?? null],
  );
  return result.rows;
}

async function projectAndComplete(pool: Pool, event: ClaimedEvent): Promise<void> {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const projection = projectAlert(event.event_type);
    await client.query(
      `INSERT INTO alert_notifications (organization_id, outbox_event_id, event_type, title, aggregate_id)
       VALUES ($1, $2, $3, $4, $5) ON CONFLICT (outbox_event_id) DO NOTHING`,
      [event.organization_id, event.id, projection.eventType, projection.title, projection.exposeAggregateId ? event.aggregate_id : event.id],
    );
    await client.query(
      `INSERT INTO webhook_deliveries (organization_id, endpoint_id, outbox_event_id)
       SELECT $1, endpoint.id, $2
       FROM webhook_endpoints AS endpoint
       WHERE endpoint.organization_id = $1 AND endpoint.enabled = true
         AND endpoint.deleted_at IS NULL AND endpoint.signing_secret_ref IS NOT NULL
         AND endpoint.event_types @> ARRAY[$3]::text[]
       ON CONFLICT (endpoint_id, outbox_event_id) DO NOTHING`,
      [event.organization_id, event.id, event.event_type],
    );
    await client.query(
      `UPDATE outbox_events SET delivered_at = now(), locked_at = NULL, last_error_code = NULL
       WHERE id = $1 AND delivered_at IS NULL AND locked_at IS NOT NULL`,
      [event.id],
    );
    await client.query('COMMIT');
  } catch (error: unknown) {
    await client.query('ROLLBACK');
    throw error;
  } finally {
    client.release();
  }
}

async function releaseForRetry(pool: Pool, event: ClaimedEvent): Promise<void> {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const delaySeconds = Math.min(3600, 2 ** Math.min(event.attempts, 10));
    await client.query(
      `UPDATE outbox_events SET locked_at = NULL, available_at = now() + ($2 * interval '1 second'),
         last_error_code = 'ALERT_PROJECTION_FAILED'
       WHERE id = $1 AND delivered_at IS NULL`,
      [event.id, delaySeconds],
    );
    await client.query('COMMIT');
  } catch (error: unknown) {
    await client.query('ROLLBACK');
    throw error;
  } finally {
    client.release();
  }
}

export class OutboxWorker {
  public constructor(private readonly pool: Pool) {}

  public async runBatch(batchSize = 25, organizationId?: string): Promise<OutboxBatchResult> {
    if (!Number.isInteger(batchSize) || batchSize < 1 || batchSize > 100) throw new RangeError('batchSize must be an integer from 1 to 100');
    const claimClient = await this.pool.connect();
    let events: readonly ClaimedEvent[];
    try {
      await claimClient.query('BEGIN');
      events = await claim(claimClient, batchSize, organizationId);
      await claimClient.query('COMMIT');
    } catch (error: unknown) {
      await claimClient.query('ROLLBACK');
      throw error;
    } finally {
      claimClient.release();
    }

    let delivered = 0;
    let failed = 0;
    for (const event of events) {
      try {
        await projectAndComplete(this.pool, event);
        delivered += 1;
      } catch {
        await releaseForRetry(this.pool, event);
        failed += 1;
      }
    }
    return { claimed: events.length, delivered, failed };
  }
}
