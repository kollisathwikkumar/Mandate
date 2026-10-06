import { createHash } from 'node:crypto';
import type { Pool, PoolClient } from 'pg';
import { canTransitionAction, type ActionState } from '../../../domain/src/action-state.js';
import { RepositoryAccessError } from '../../../ports/src/repository-errors.js';
import type { ApprovalInput, ApprovalOutcome, ApprovalRepository, ApprovalResult } from '../../../ports/src/approval-repository.js';
import { ActionConflictError } from './action-store.js';

interface IdempotencyRow { readonly request_hash: string; readonly response_json: unknown; }
interface PendingActionRow {
  readonly request_hash: string;
  readonly state: ActionState;
  readonly action_json: { readonly expiresAt?: number };
  readonly created_by: string;
  readonly lease_expires_at: Date | null;
}

function sha256(value: string): string { return createHash('sha256').update(value, 'utf8').digest('hex'); }

async function audit(client: PoolClient, input: ApprovalInput, eventType: string, state: string): Promise<void> {
  await client.query('SELECT id FROM organizations WHERE id = $1 FOR UPDATE', [input.organizationId]);
  const previous = await client.query<{ event_hash: string }>(
    'SELECT event_hash FROM audit_events WHERE organization_id = $1 ORDER BY sequence DESC LIMIT 1',
    [input.organizationId],
  );
  const previousHash = previous.rows[0]?.event_hash.trim() ?? null;
  const payload = { actionId: input.actionId, actionHash: input.actionHash, state, outcome: input.outcome };
  const payloadText = JSON.stringify(payload);
  const eventHash = `0x${sha256(`${previousHash ?? ''}|${input.organizationId}|${input.approverSubject}|${eventType}|${payloadText}`)}`;
  await client.query(
    `INSERT INTO audit_events (organization_id, actor_type, actor_id, event_type, subject_type, subject_id, correlation_id, payload, previous_hash, event_hash)
     VALUES ($1, 'HUMAN', $2, $3, 'ACTION', $4, $5, $6::jsonb, $7, $8)`,
    [input.organizationId, input.approverSubject, eventType, input.actionId, input.idempotencyKey, payloadText, previousHash, eventHash],
  );
}

async function decideInTransaction(client: PoolClient, input: ApprovalInput): Promise<ApprovalOutcome> {
  const member = await client.query<{ role: string }>(
    'SELECT role FROM members WHERE organization_id = $1 AND subject = $2 FOR UPDATE',
    [input.organizationId, input.approverSubject],
  );
  const role = member.rows[0]?.role;
  if (role === undefined) throw new RepositoryAccessError(404);
  if (!['OWNER', 'ADMIN', 'APPROVER'].includes(role)) throw new RepositoryAccessError(403);

  await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1, 0))', [
    `${input.organizationId}|${input.approverSubject}|approval.decide|${input.idempotencyKey}`,
  ]);
  await client.query(
    `DELETE FROM command_idempotency WHERE organization_id = $1 AND principal_id = $2
       AND scope = 'approval.decide' AND idempotency_key = $3 AND expires_at <= now()`,
    [input.organizationId, input.approverSubject, input.idempotencyKey],
  );
  const requestHash = `0x${sha256(`${input.actionId}|${input.actionHash}|${input.outcome}`)}`;
  const replay = await client.query<IdempotencyRow>(
    `SELECT request_hash, response_json FROM command_idempotency
     WHERE organization_id = $1 AND principal_id = $2 AND scope = 'approval.decide' AND idempotency_key = $3 AND expires_at > now()`,
    [input.organizationId, input.approverSubject, input.idempotencyKey],
  );
  const existing = replay.rows[0];
  if (existing !== undefined) {
    if (existing.request_hash.trim() !== requestHash) throw new ActionConflictError('Idempotency key was used for a different approval', 'IDEMPOTENCY_CONFLICT');
    return { kind: 'REPLAY', approval: existing.response_json as ApprovalResult };
  }

  const action = await client.query<PendingActionRow>(
    `SELECT a.request_hash, a.state, a.action_json, r.created_by, v.lease_expires_at
     FROM action_requests a
     JOIN policy_revisions r ON r.organization_id = a.organization_id AND r.policy_id = a.policy_id AND r.revision = a.policy_revision
     LEFT JOIN reservations v ON v.organization_id = a.organization_id AND v.action_id = a.id
     WHERE a.organization_id = $1 AND a.id = $2 FOR UPDATE OF a`,
    [input.organizationId, input.actionId],
  );
  const row = action.rows[0];
  if (row === undefined) throw new RepositoryAccessError(404);
  if (row.request_hash.trim() !== input.actionHash) throw new ActionConflictError('Approval must bind the exact action hash');
  if (row.state !== 'HELD') throw new ActionConflictError('Only a pending held action can receive an approval');
  if (row.created_by === input.approverSubject) throw new RepositoryAccessError(403);
  const expiresAt = row.action_json.expiresAt;
  const expired = typeof expiresAt !== 'number' || expiresAt <= Math.floor(Date.now() / 1000)
    || row.lease_expires_at === null || row.lease_expires_at.getTime() <= Date.now();
  if (expired) {
    if (!canTransitionAction('HELD', 'EXPIRED')) throw new Error('Action expiry transition invariant failed');
    const result: ApprovalResult = { actionId: input.actionId, state: 'EXPIRED', verdict: 'BLOCK', reason: 'ACTION_EXPIRED', actionHash: input.actionHash };
    await client.query("UPDATE action_requests SET state = 'EXPIRED', verdict = 'BLOCK', reason_code = 'ACTION_EXPIRED', updated_at = now() WHERE organization_id = $1 AND id = $2", [input.organizationId, input.actionId]);
    await client.query("UPDATE reservations SET state = 'EXPIRED', updated_at = now() WHERE organization_id = $1 AND action_id = $2 AND state = 'ACTIVE'", [input.organizationId, input.actionId]);
    await audit(client, input, 'ACTION_EXPIRED', 'EXPIRED');
    await client.query(
      `INSERT INTO outbox_events (organization_id, aggregate_type, aggregate_id, event_type, payload)
       VALUES ($1, 'ACTION', $2, 'ACTION_EXPIRED', $3::jsonb)`,
      [input.organizationId, input.actionId, JSON.stringify(result)],
    );
    await client.query(
      `INSERT INTO command_idempotency (organization_id, principal_id, scope, idempotency_key, request_hash, response_json)
       VALUES ($1, $2, 'approval.decide', $3, $4, $5::jsonb)`,
      [input.organizationId, input.approverSubject, input.idempotencyKey, requestHash, JSON.stringify(result)],
    );
    return { kind: 'CREATED', approval: result };
  }

  const nextState: ApprovalResult['state'] = input.outcome === 'APPROVED' ? 'RESERVED' : 'DENIED';
  const verdict: ApprovalResult['verdict'] = input.outcome === 'APPROVED' ? 'ALLOW' : 'BLOCK';
  const reason: ApprovalResult['reason'] = input.outcome === 'APPROVED' ? 'HUMAN_APPROVED' : 'APPROVAL_DENIED';
  await client.query(
    `INSERT INTO approvals (organization_id, action_id, action_hash, approver_subject, outcome, expires_at)
     VALUES ($1, $2, $3, $4, $5, to_timestamp($6))`,
    [input.organizationId, input.actionId, input.actionHash, input.approverSubject, input.outcome, expiresAt],
  );
  if (input.outcome === 'APPROVED') {
    if (!canTransitionAction('HELD', 'APPROVED') || !canTransitionAction('APPROVED', 'RESERVED')) throw new Error('Approval action transition invariant failed');
    await client.query("UPDATE action_requests SET state = 'APPROVED', updated_at = now() WHERE organization_id = $1 AND id = $2", [input.organizationId, input.actionId]);
    await audit(client, input, 'ACTION_APPROVED', 'APPROVED');
    await client.query("UPDATE action_requests SET state = 'RESERVED', verdict = 'ALLOW', reason_code = 'HUMAN_APPROVED', updated_at = now() WHERE organization_id = $1 AND id = $2", [input.organizationId, input.actionId]);
    await audit(client, input, 'ACTION_RESERVED', 'RESERVED');
  } else {
    if (!canTransitionAction('HELD', 'DENIED')) throw new Error('Approval action transition invariant failed');
    await client.query("UPDATE action_requests SET state = 'DENIED', verdict = 'BLOCK', reason_code = 'APPROVAL_DENIED', updated_at = now() WHERE organization_id = $1 AND id = $2", [input.organizationId, input.actionId]);
    await client.query("UPDATE reservations SET state = 'RELEASED', updated_at = now() WHERE organization_id = $1 AND action_id = $2 AND state = 'ACTIVE'", [input.organizationId, input.actionId]);
    await audit(client, input, 'ACTION_DENIED', 'DENIED');
  }
  const result: ApprovalResult = { actionId: input.actionId, state: nextState, verdict, reason, actionHash: input.actionHash };
  await client.query(
    `INSERT INTO outbox_events (organization_id, aggregate_type, aggregate_id, event_type, payload)
     VALUES ($1, 'ACTION', $2, $3, $4::jsonb)`,
    [input.organizationId, input.actionId, `ACTION_${nextState}`, JSON.stringify(result)],
  );
  await client.query(
    `INSERT INTO command_idempotency (organization_id, principal_id, scope, idempotency_key, request_hash, response_json)
     VALUES ($1, $2, 'approval.decide', $3, $4, $5::jsonb)`,
    [input.organizationId, input.approverSubject, input.idempotencyKey, requestHash, JSON.stringify(result)],
  );
  return { kind: 'CREATED', approval: result };
}

export class ApprovalStore implements ApprovalRepository {
  public constructor(private readonly pool: Pool) {}

  public async approveAction(input: ApprovalInput): Promise<ApprovalOutcome> {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      const result = await decideInTransaction(client, input);
      await client.query('COMMIT');
      return result;
    } catch (error: unknown) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  }
}
