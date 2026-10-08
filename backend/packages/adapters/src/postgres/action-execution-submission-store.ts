import { createHash } from 'node:crypto';
import type { Pool, PoolClient } from 'pg';
import { canTransitionAction } from '../../../domain/src/action-state.js';
import { RepositoryAccessError } from '../../../ports/src/repository-errors.js';
import {
  ActionExecutionSubmissionConflictError,
  type ActionExecutionSubmissionIdentity,
  type ActionExecutionSubmissionRepository,
  type ActionExecutionSubmissionResult,
  type CompleteActionExecutionSubmissionOutcome,
  type ReserveActionExecutionSubmissionOutcome,
} from '../../../ports/src/action-execution-submission-repository.js';

interface LockedExecutionRow {
  readonly action_state: string;
  readonly authorization_status: string;
  readonly authorization_expires_at: Date;
  readonly attempt_state: string;
  readonly attempt_transaction_hash: string | null;
  readonly eligible: boolean;
}
interface ExistingSubmissionRow {
  readonly action_id: string;
  readonly idempotency_key: string;
  readonly request_hash: string;
  readonly transaction_hash: string;
  readonly status: 'PENDING' | 'SUBMITTED';
}

function sha256(value: string): string { return createHash('sha256').update(value, 'utf8').digest('hex'); }
function requestHash(input: ActionExecutionSubmissionIdentity): string {
  return `0x${sha256(`${input.actionId}|${input.transactionHash.toLowerCase()}`)}`;
}
function uniqueViolation(error: unknown): boolean {
  return typeof error === 'object' && error !== null && 'code' in error && error.code === '23505';
}
function conflict(message: string, code: 'RESOURCE_CONFLICT' | 'IDEMPOTENCY_CONFLICT' = 'RESOURCE_CONFLICT'): never {
  throw new ActionExecutionSubmissionConflictError(message, code);
}
function result(actionId: string, transactionHash: string): ActionExecutionSubmissionResult {
  return { actionId, state: 'SUBMITTED', transactionHash: transactionHash.toLowerCase() };
}

function eligibleForBroadcast(context: LockedExecutionRow): boolean {
  return context.action_state === 'AUTHORIZED' && context.authorization_status === 'ACTIVE'
    && context.authorization_expires_at.getTime() > Date.now() && context.attempt_state === 'AUTHORIZED'
    && context.attempt_transaction_hash === null && context.eligible;
}

const lockedContextQuery = `
  SELECT ar.state AS action_state, authz.status AS authorization_status, authz.expires_at AS authorization_expires_at,
         attempt.state AS attempt_state, attempt.transaction_hash AS attempt_transaction_hash,
         (p.state = 'ACTIVE' AND p.current_revision = ar.policy_revision
           AND revision.revision_hash = authz.policy_revision_hash
           AND account.status = 'ACTIVE' AND lower(btrim(account.address)) = lower(ar.action_json->>'account')
           AND account.chain_id = (ar.action_json->>'chainId')::bigint
           AND EXISTS (SELECT 1 FROM policy_grants grant_row WHERE grant_row.organization_id = p.organization_id
             AND grant_row.policy_id = p.id AND grant_row.policy_revision = p.current_revision
             AND grant_row.account_id = p.account_id AND grant_row.adapter = account.adapter AND grant_row.state = 'ACTIVE')
           AND EXISTS (SELECT 1 FROM reservations reservation WHERE reservation.organization_id = ar.organization_id
             AND reservation.action_id = ar.id AND reservation.state = 'ACTIVE' AND reservation.lease_expires_at > now())
         ) AS eligible
  FROM action_requests ar
  JOIN policies p ON p.organization_id = ar.organization_id AND p.id = ar.policy_id
  JOIN policy_revisions revision ON revision.organization_id = ar.organization_id
    AND revision.policy_id = ar.policy_id AND revision.revision = ar.policy_revision
  JOIN accounts account ON account.organization_id = p.organization_id AND account.id = p.account_id
  JOIN agents agent ON agent.organization_id = ar.organization_id AND agent.id = ar.action_json->>'agentId'
  JOIN agent_credentials credential ON credential.organization_id = agent.organization_id AND credential.agent_id = agent.id
  JOIN action_authorizations authz ON authz.organization_id = ar.organization_id AND authz.action_id = ar.id
  JOIN execution_attempts attempt ON attempt.organization_id = ar.organization_id AND attempt.action_id = ar.id AND attempt.attempt_number = 1
  WHERE ar.organization_id = $1 AND ar.id = $2 AND ar.action_json->>'agentId' = $3
    AND ar.action_json->>'agentKeyVersion' = $4::text AND agent.status = 'ACTIVE' AND agent.key_version::text = $4::text
    AND credential.id = $5 AND credential.key_version::text = $4::text AND credential.revoked_at IS NULL
    AND (credential.expires_at IS NULL OR credential.expires_at > now())
  FOR UPDATE OF ar, p, account, agent, credential, authz, attempt`;

async function lockContext(client: PoolClient, input: ActionExecutionSubmissionIdentity): Promise<LockedExecutionRow> {
  const locked = await client.query<LockedExecutionRow>(lockedContextQuery, [
    input.organizationId, input.actionId, input.agentId, input.agentKeyVersion, input.credentialId,
  ]);
  const row = locked.rows[0];
  if (row === undefined) throw new RepositoryAccessError(404);
  return row;
}

async function findExisting(client: PoolClient, input: ActionExecutionSubmissionIdentity): Promise<ExistingSubmissionRow | null> {
  const byAction = await client.query<ExistingSubmissionRow>(
    `SELECT action_id, idempotency_key, request_hash, transaction_hash, status
     FROM action_execution_submissions WHERE organization_id = $1 AND action_id = $2 FOR UPDATE`,
    [input.organizationId, input.actionId],
  );
  const actionRow = byAction.rows[0];
  if (actionRow !== undefined) return actionRow;
  const byKey = await client.query<ExistingSubmissionRow>(
    `SELECT action_id, idempotency_key, request_hash, transaction_hash, status
     FROM action_execution_submissions WHERE organization_id = $1 AND agent_id = $2 AND idempotency_key = $3 FOR UPDATE`,
    [input.organizationId, input.agentId, input.idempotencyKey],
  );
  return byKey.rows[0] ?? null;
}

async function reserveWithinTransaction(client: PoolClient, input: ActionExecutionSubmissionIdentity): Promise<ReserveActionExecutionSubmissionOutcome> {
  if (!/^0x[0-9a-f]{40}$/.test(input.outerSender) || !Number.isSafeInteger(input.outerNonce) || input.outerNonce < 0) {
    return conflict('Signed transaction sender or nonce metadata is invalid');
  }
  await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1, 0))', [
    `${input.organizationId}|${input.agentId}|action.execute|${input.idempotencyKey}`,
  ]);
  const context = await lockContext(client, input);
  const existing = await findExisting(client, input);
  const hash = requestHash(input);
  if (existing !== null) {
    if (existing.action_id !== input.actionId || existing.idempotency_key !== input.idempotencyKey || existing.request_hash.trim() !== hash) {
      return conflict('Action or idempotency key already has a different signed transaction', 'IDEMPOTENCY_CONFLICT');
    }
    if (existing.status === 'SUBMITTED') return { kind: 'REPLAY', result: result(input.actionId, existing.transaction_hash.trim()) };
    if (!eligibleForBroadcast(context)) {
      return conflict('Action authorization, policy grant, account, reservation, or execution attempt is no longer eligible');
    }
    return { kind: 'BROADCAST', transactionHash: existing.transaction_hash.trim() };
  }
  if (!eligibleForBroadcast(context)) {
    return conflict('Action authorization, policy grant, account, reservation, or execution attempt is no longer eligible');
  }
  await client.query(
    `INSERT INTO action_execution_submissions
       (organization_id, action_id, agent_id, idempotency_key, request_hash, transaction_hash, outer_sender, outer_nonce, status)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'PENDING')`,
    [input.organizationId, input.actionId, input.agentId, input.idempotencyKey, hash, input.transactionHash.toLowerCase(), input.outerSender, input.outerNonce],
  );
  return { kind: 'BROADCAST', transactionHash: input.transactionHash.toLowerCase() };
}

async function appendSubmittedAudit(client: PoolClient, input: ActionExecutionSubmissionIdentity): Promise<void> {
  await client.query('SELECT id FROM organizations WHERE id = $1 FOR UPDATE', [input.organizationId]);
  const previous = await client.query<{ event_hash: string }>(
    'SELECT event_hash FROM audit_events WHERE organization_id = $1 ORDER BY sequence DESC LIMIT 1', [input.organizationId],
  );
  const previousHash = previous.rows[0]?.event_hash.trim() ?? null;
  const payload = { actionId: input.actionId, transactionHash: input.transactionHash.toLowerCase() };
  const payloadText = JSON.stringify(payload);
  const eventHash = `0x${sha256(`${previousHash ?? ''}|${input.organizationId}|${input.agentId}|ACTION_SUBMITTED|${payloadText}`)}`;
  await client.query(
    `INSERT INTO audit_events (organization_id, actor_type, actor_id, event_type, subject_type, subject_id, correlation_id, payload, previous_hash, event_hash)
     VALUES ($1, 'AGENT', $2, 'ACTION_SUBMITTED', 'ACTION', $3, $4, $5::jsonb, $6, $7)`,
    [input.organizationId, input.agentId, input.actionId, input.idempotencyKey, payloadText, previousHash, eventHash],
  );
}

async function completeWithinTransaction(client: PoolClient, input: ActionExecutionSubmissionIdentity): Promise<CompleteActionExecutionSubmissionOutcome> {
  await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1, 0))', [
    `${input.organizationId}|${input.agentId}|action.execute|${input.idempotencyKey}`,
  ]);
  const context = await lockContext(client, input);
  const existing = await findExisting(client, input);
  if (existing === null || existing.action_id !== input.actionId || existing.idempotency_key !== input.idempotencyKey
    || existing.transaction_hash.trim().toLowerCase() !== input.transactionHash.toLowerCase()) {
    return conflict('Signed transaction submission record does not match the broadcast transaction');
  }
  if (existing.status === 'SUBMITTED') return { kind: 'REPLAY', result: result(input.actionId, input.transactionHash) };
  if (context.action_state !== 'AUTHORIZED' || context.authorization_status !== 'ACTIVE'
    || context.attempt_state !== 'AUTHORIZED' || !canTransitionAction('AUTHORIZED', 'SUBMITTED')) {
    return conflict('Action execution state changed before submission could be committed');
  }
  await client.query(
    `UPDATE action_execution_submissions SET status = 'SUBMITTED', submitted_at = now(), updated_at = now()
     WHERE organization_id = $1 AND action_id = $2 AND status = 'PENDING'`, [input.organizationId, input.actionId],
  );
  await client.query(
    `UPDATE execution_attempts SET transaction_hash = $3, state = 'SUBMITTED', updated_at = now()
     WHERE organization_id = $1 AND action_id = $2 AND attempt_number = 1 AND state = 'AUTHORIZED'`,
    [input.organizationId, input.actionId, input.transactionHash.toLowerCase()],
  );
  await client.query(
    `UPDATE action_authorizations SET status = 'CONSUMED', updated_at = now()
     WHERE organization_id = $1 AND action_id = $2 AND status = 'ACTIVE'`, [input.organizationId, input.actionId],
  );
  await client.query(
    `UPDATE action_requests SET state = 'SUBMITTED', updated_at = now()
     WHERE organization_id = $1 AND id = $2 AND state = 'AUTHORIZED'`, [input.organizationId, input.actionId],
  );
  await appendSubmittedAudit(client, input);
  await client.query(
    `INSERT INTO outbox_events (organization_id, aggregate_type, aggregate_id, event_type, payload)
     VALUES ($1, 'ACTION', $2, 'ACTION_SUBMITTED', $3::jsonb)`,
    [input.organizationId, input.actionId, JSON.stringify({ actionId: input.actionId, transactionHash: input.transactionHash.toLowerCase() })],
  );
  return { kind: 'CREATED', result: result(input.actionId, input.transactionHash) };
}

async function inTransaction<T>(pool: Pool, operation: (client: PoolClient) => Promise<T>): Promise<T> {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const value = await operation(client);
    await client.query('COMMIT');
    return value;
  } catch (error: unknown) {
    await client.query('ROLLBACK');
    if (uniqueViolation(error)) return conflict('Action or idempotency key already has an execution submission', 'IDEMPOTENCY_CONFLICT');
    throw error;
  } finally { client.release(); }
}

export class ActionExecutionSubmissionStore implements ActionExecutionSubmissionRepository {
  public constructor(private readonly pool: Pool) {}
  public reserveSubmission(input: ActionExecutionSubmissionIdentity): Promise<ReserveActionExecutionSubmissionOutcome> {
    return inTransaction(this.pool, (client) => reserveWithinTransaction(client, input));
  }
  public completeSubmission(input: ActionExecutionSubmissionIdentity): Promise<CompleteActionExecutionSubmissionOutcome> {
    return inTransaction(this.pool, (client) => completeWithinTransaction(client, input));
  }
}
