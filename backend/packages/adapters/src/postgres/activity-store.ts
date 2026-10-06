import type { Pool } from 'pg';
import { ActionIntentSchema, type ActionIntent } from '../../../policy/src/schema.js';
import type { ActionState } from '../../../domain/src/action-state.js';
import { ACTION_STATES } from '../../../domain/src/action-state.js';
import { POLICY_REASON_CODES, type PolicyReasonCode, type PolicyVerdict } from '../../../domain/src/reason-code.js';
import type { JsonObject } from '../../../domain/src/json-value.js';
import type { ActivityRepository, ActionDetailRecord, AlertRecord, AuditEventRecord, ReceiptRecord, ReservationRecord } from '../../../ports/src/activity-repository.js';

interface RoleRow { readonly role: string; }
interface ActionRow {
  readonly action_id: string;
  readonly policy_id: string;
  readonly policy_revision: number;
  readonly request_hash: string;
  readonly state: string;
  readonly verdict: string | null;
  readonly reason_code: string | null;
  readonly action_json: JsonObject;
  readonly created_at: Date;
  readonly updated_at: Date;
  readonly reservation_state: ReservationRecord['state'] | null;
  readonly reservation_amount: string | null;
  readonly lease_expires_at: Date | null;
}
interface AuditRow {
  readonly sequence: string;
  readonly event_type: string;
  readonly actor_type: string;
  readonly actor_id: string;
  readonly subject_type: string;
  readonly subject_id: string;
  readonly correlation_id: string;
  readonly payload: JsonObject;
  readonly previous_hash: string | null;
  readonly event_hash: string;
  readonly created_at: Date;
}
interface ReceiptRow {
  readonly id: string;
  readonly action_id: string;
  readonly chain_id: string;
  readonly transaction_hash: string;
  readonly block_number: string;
  readonly block_hash: string;
  readonly status: ReceiptRecord['status'];
  readonly receipt_json: JsonObject;
  readonly observed_at: Date;
}
interface AlertRow {
  readonly id: string;
  readonly event_type: string;
  readonly title: string;
  readonly aggregate_id: string;
  readonly created_at: Date;
}

const POLICY_VERDICTS = ['ALLOW', 'BLOCK', 'HOLD'] as const;

function mapAudit(row: AuditRow): AuditEventRecord {
  return {
    sequence: row.sequence,
    eventType: row.event_type,
    actorType: row.actor_type,
    actorId: row.actor_id,
    subjectType: row.subject_type,
    subjectId: row.subject_id,
    correlationId: row.correlation_id,
    payload: row.payload,
    previousHash: row.previous_hash?.trim() ?? null,
    eventHash: row.event_hash.trim(),
    createdAt: row.created_at.toISOString(),
  };
}

export class ActivityStore implements ActivityRepository {
  public constructor(private readonly pool: Pool) {}

  public async getHumanRole(organizationId: string, subject: string): Promise<string | null> {
    const result = await this.pool.query<RoleRow>(
      'SELECT role FROM members WHERE organization_id = $1 AND subject = $2',
      [organizationId, subject],
    );
    return result.rows[0]?.role ?? null;
  }

  public async getAction(organizationId: string, actionId: string, agentId: string | null): Promise<ActionDetailRecord | null> {
    const params: (string | null)[] = [organizationId, actionId, agentId];
    const result = await this.pool.query<ActionRow>(
      `SELECT a.id AS action_id, a.policy_id, a.policy_revision, a.request_hash, a.state, a.verdict, a.reason_code,
        a.action_json, a.created_at, a.updated_at, r.state AS reservation_state, r.amount::text AS reservation_amount, r.lease_expires_at
       FROM action_requests a LEFT JOIN reservations r ON r.organization_id = a.organization_id AND r.action_id = a.id
       WHERE a.organization_id = $1 AND a.id = $2 AND ($3::text IS NULL OR a.action_json->>'agentId' = $3)`,
      params,
    );
    const row = result.rows[0];
    if (row === undefined) return null;
    const eventResult = await this.pool.query<AuditRow>(
      `SELECT sequence::text, event_type, actor_type, actor_id, subject_type, subject_id, correlation_id, payload,
        previous_hash, event_hash, created_at FROM audit_events
       WHERE organization_id = $1 AND subject_type = 'ACTION' AND subject_id = $2 ORDER BY sequence`,
      [organizationId, actionId],
    );
    const state = ACTION_STATES.find((candidate): candidate is ActionState => candidate === row.state);
    if (state === undefined) throw new Error('Stored action state is invalid');
    const verdict = row.verdict === null ? null : POLICY_VERDICTS.find((candidate): candidate is PolicyVerdict => candidate === row.verdict) ?? null;
    if (row.verdict !== null && verdict === null) throw new Error('Stored action verdict is invalid');
    const reason = row.reason_code === null ? null : POLICY_REASON_CODES.find((code): code is PolicyReasonCode => code === row.reason_code) ?? null;
    if (row.reason_code !== null && reason === null) throw new Error('Stored action reason code is invalid');
    const reservation: ReservationRecord | null = row.reservation_state === null || row.reservation_amount === null || row.lease_expires_at === null
      ? null
      : { state: row.reservation_state, amount: row.reservation_amount, leaseExpiresAt: row.lease_expires_at.toISOString() };
    return {
      actionId: row.action_id,
      policyId: row.policy_id,
      policyRevision: row.policy_revision,
      actionHash: row.request_hash.trim(),
      state,
      verdict,
      reason,
      action: ActionIntentSchema.parse(row.action_json),
      createdAt: row.created_at.toISOString(),
      updatedAt: row.updated_at.toISOString(),
      reservation,
      events: eventResult.rows.map(mapAudit),
    };
  }

  public async listAuditEvents(organizationId: string, agentId: string | null, limit: number, beforeSequence: string | null): Promise<readonly AuditEventRecord[]> {
    const result = await this.pool.query<AuditRow>(
      `SELECT e.sequence::text, e.event_type, e.actor_type, e.actor_id, e.subject_type, e.subject_id, e.correlation_id,
        e.payload, e.previous_hash, e.event_hash, e.created_at FROM audit_events e
       WHERE e.organization_id = $1
         AND ($2::text IS NULL OR (e.subject_type = 'ACTION' AND EXISTS (
           SELECT 1 FROM action_requests a WHERE a.organization_id = e.organization_id AND a.id = e.subject_id AND a.action_json->>'agentId' = $2
         )))
         AND ($3::bigint IS NULL OR e.sequence < $3::bigint)
       ORDER BY e.sequence DESC LIMIT $4`,
      [organizationId, agentId, beforeSequence, limit],
    );
    return result.rows.map(mapAudit);
  }

  public async listReceipts(organizationId: string, agentId: string | null, limit: number): Promise<readonly ReceiptRecord[]> {
    const result = await this.pool.query<ReceiptRow>(
      `SELECT r.id::text, r.action_id, r.chain_id::text, r.transaction_hash, r.block_number::text, r.block_hash, r.status, r.receipt_json, r.observed_at
       FROM receipts r JOIN action_requests a ON a.organization_id = r.organization_id AND a.id = r.action_id
       WHERE r.organization_id = $1 AND ($2::text IS NULL OR a.action_json->>'agentId' = $2)
       ORDER BY r.observed_at DESC, r.id DESC LIMIT $3`,
      [organizationId, agentId, limit],
    );
    return result.rows.map((row) => {
      const chainId = Number(row.chain_id);
      if (!Number.isSafeInteger(chainId) || chainId <= 0) throw new Error('Stored receipt chain ID is outside the supported integer range');
      return {
        id: row.id,
        actionId: row.action_id,
        chainId,
        transactionHash: row.transaction_hash.trim(),
        blockNumber: row.block_number,
        blockHash: row.block_hash.trim(),
        status: row.status,
        receipt: row.receipt_json,
        observedAt: row.observed_at.toISOString(),
      };
    });
  }

  public async listAlerts(organizationId: string, limit: number): Promise<readonly AlertRecord[]> {
    const result = await this.pool.query<AlertRow>(
      `SELECT id::text, event_type, title, aggregate_id, created_at FROM alert_notifications
       WHERE organization_id = $1 ORDER BY created_at DESC, id DESC LIMIT $2`,
      [organizationId, limit],
    );
    return result.rows.map((row) => ({
      id: row.id,
      eventType: row.event_type,
      title: row.title,
      aggregateId: row.aggregate_id,
      createdAt: row.created_at.toISOString(),
    }));
  }
}
