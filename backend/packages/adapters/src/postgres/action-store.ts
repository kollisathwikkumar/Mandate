import { createHash } from 'node:crypto';
import type { Pool, PoolClient } from 'pg';
import { z } from 'zod';
import { canTransitionAction, type ActionState } from '../../../domain/src/action-state.js';
import { POLICY_REASON_CODES, type PolicyDecision, type PolicyReasonCode } from '../../../domain/src/reason-code.js';
import { RepositoryAccessError } from '../../../ports/src/repository-errors.js';
import type { ActionRepository, ActionSubmissionInput, ActionSubmissionOutcome, ActionSubmissionResult } from '../../../ports/src/action-repository.js';
import { evaluateAction, type PolicyState } from '../../../policy/src/evaluate.js';
import { ActionIntentSchema, PolicyRevisionSchema, type PolicyRevision } from '../../../policy/src/schema.js';

const ActionSubmissionResultSchema = z.object({
  actionId: z.string(),
  state: z.enum(['BLOCKED', 'HELD', 'RESERVED']),
  verdict: z.enum(['BLOCK', 'HOLD', 'ALLOW']),
  reason: z.enum(POLICY_REASON_CODES),
  policyRevisionHash: z.string().regex(/^0x[0-9a-f]{64}$/),
  reservationExpiresAt: z.string().datetime().nullable(),
}).strict();

interface ExistingIdempotencyRow {
  readonly request_hash: string;
  readonly response_json: unknown;
}

interface CurrentPolicyRow {
  readonly account_id: string;
  readonly state: 'DRAFT' | 'ACTIVE' | 'REVOKED' | 'EXPIRED';
  readonly current_revision: number;
  readonly revision_hash: string;
  readonly canonical_json: unknown;
  readonly account_status: 'ACTIVE' | 'PAUSED' | 'UNSUPPORTED';
  readonly account_adapter: string;
  readonly grant_active: boolean;
}

interface AgentCredentialRow {
  readonly credential_id: string;
  readonly credential_key_version: number;
  readonly agent_status: 'ACTIVE' | 'REVOKED';
  readonly agent_key_version: number;
}

interface BudgetRow {
  readonly spent: string;
  readonly reserved: string;
  readonly action_count: string;
}

interface NonceRow {
  readonly next_nonce: string;
}

function sha256(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('hex');
}

function uniqueViolation(error: unknown): boolean {
  return typeof error === 'object' && error !== null && 'code' in error && error.code === '23505';
}

function getPolicyState(state: CurrentPolicyRow['state']): PolicyState {
  switch (state) {
    case 'ACTIVE': return 'active';
    case 'DRAFT': return 'draft';
    case 'REVOKED': return 'revoked';
    case 'EXPIRED': return 'expired';
  }
}

async function verifyCredential(client: PoolClient, input: ActionSubmissionInput): Promise<void> {
  const result = await client.query<AgentCredentialRow>(
    `SELECT c.id AS credential_id, c.key_version AS credential_key_version,
            a.status AS agent_status, a.key_version AS agent_key_version
     FROM agent_credentials c
     JOIN agents a ON a.organization_id = c.organization_id AND a.id = c.agent_id
     WHERE c.id = $1 AND c.organization_id = $2 AND c.agent_id = $3
       AND c.revoked_at IS NULL AND (c.expires_at IS NULL OR c.expires_at > now())
     FOR UPDATE OF c, a`,
    [input.credentialId, input.organizationId, input.agentId],
  );
  const row = result.rows[0];
  if (row === undefined || row.agent_status !== 'ACTIVE' || row.credential_key_version !== input.agentKeyVersion || row.agent_key_version !== input.agentKeyVersion) {
    throw new RepositoryAccessError(403);
  }
}

async function findReplay(client: PoolClient, input: ActionSubmissionInput): Promise<ActionSubmissionOutcome | null> {
  const result = await client.query<ExistingIdempotencyRow>(
    `SELECT request_hash, response_json FROM command_idempotency
     WHERE organization_id = $1 AND principal_id = $2 AND scope = 'action.submit'
       AND idempotency_key = $3 AND expires_at > now()`,
    [input.organizationId, input.agentId, input.idempotencyKey],
  );
  const previous = result.rows[0];
  if (previous === undefined) return null;
  const requestHash = `0x${sha256(JSON.stringify(input.action))}`;
  if (previous.request_hash.trim() !== requestHash) throw new ActionConflictError('Idempotency key was already used for a different action', 'IDEMPOTENCY_CONFLICT');
  return { kind: 'REPLAY', action: ActionSubmissionResultSchema.parse(previous.response_json) };
}

async function lockPolicy(client: PoolClient, input: ActionSubmissionInput): Promise<{ readonly row: CurrentPolicyRow; readonly policy: PolicyRevision }> {
  const result = await client.query<CurrentPolicyRow>(
    `SELECT p.account_id, p.state, p.current_revision, r.revision_hash, r.canonical_json,
            a.status AS account_status, a.adapter AS account_adapter,
            EXISTS (
              SELECT 1 FROM policy_grants g
              WHERE g.organization_id = p.organization_id AND g.policy_id = p.id
                AND g.policy_revision = p.current_revision AND g.account_id = p.account_id
                AND g.adapter = a.adapter AND g.state = 'ACTIVE'
            ) AS grant_active
     FROM policies p
     JOIN policy_revisions r ON r.organization_id = p.organization_id AND r.policy_id = p.id AND r.revision = p.current_revision
     JOIN accounts a ON a.organization_id = p.organization_id AND a.id = p.account_id
     WHERE p.organization_id = $1 AND p.id = $2
     FOR UPDATE OF p, a`,
    [input.organizationId, input.action.policyId],
  );
  const row = result.rows[0];
  if (row === undefined) throw new RepositoryAccessError(404);
  return { row, policy: PolicyRevisionSchema.parse(row.canonical_json) };
}

async function getExpectedNonce(client: PoolClient, input: ActionSubmissionInput, policy: PolicyRevision): Promise<number> {
  await client.query(
    `INSERT INTO action_nonce_counters (organization_id, policy_id, agent_id, agent_key_version, nonce_epoch, next_nonce)
     VALUES ($1, $2, $3, $4, $5, 0) ON CONFLICT DO NOTHING`,
    [input.organizationId, policy.policyId, input.agentId, input.agentKeyVersion, policy.nonceEpoch],
  );
  const result = await client.query<NonceRow>(
    `SELECT next_nonce::text AS next_nonce FROM action_nonce_counters
     WHERE organization_id = $1 AND policy_id = $2 AND agent_id = $3 AND agent_key_version = $4 AND nonce_epoch = $5
     FOR UPDATE`,
    [input.organizationId, policy.policyId, input.agentId, input.agentKeyVersion, policy.nonceEpoch],
  );
  const nextNonce = Number(result.rows[0]?.next_nonce);
  if (!Number.isSafeInteger(nextNonce) || nextNonce < 0) return -1;
  return nextNonce;
}

async function getBudget(client: PoolClient, input: ActionSubmissionInput, policy: PolicyRevision, now: number): Promise<BudgetRow> {
  const result = await client.query<BudgetRow>(
    `SELECT
       COALESCE(sum(r.amount) FILTER (WHERE r.state = 'CONSUMED'), 0)::text AS spent,
       COALESCE(sum(r.amount) FILTER (WHERE r.state = 'ACTIVE' AND r.lease_expires_at > to_timestamp($3)), 0)::text AS reserved,
       count(*) FILTER (WHERE r.state = 'CONSUMED' OR (r.state = 'ACTIVE' AND r.lease_expires_at > to_timestamp($3)))::text AS action_count
     FROM reservations r
     JOIN action_requests a ON a.organization_id = r.organization_id AND a.id = r.action_id
     WHERE r.organization_id = $1 AND a.policy_id = $2
       AND r.created_at >= to_timestamp($3 - $4)`,
    [input.organizationId, policy.policyId, now, policy.limits.windowSeconds],
  );
  const row = result.rows[0];
  return row ?? { spent: '0', reserved: '0', action_count: '0' };
}

async function writeAuditEvent(
  client: PoolClient,
  input: ActionSubmissionInput,
  eventType: string,
  payload: Readonly<Record<string, string | number | null>>,
): Promise<void> {
  const previous = await client.query<{ event_hash: string }>(
    'SELECT event_hash FROM audit_events WHERE organization_id = $1 ORDER BY sequence DESC LIMIT 1',
    [input.organizationId],
  );
  const previousHash = previous.rows[0]?.event_hash.trim() ?? null;
  const payloadText = JSON.stringify(payload);
  const eventHash = `0x${sha256(`${previousHash ?? ''}|${input.organizationId}|${input.agentId}|${eventType}|${payloadText}`)}`;
  await client.query(
    `INSERT INTO audit_events (organization_id, actor_type, actor_id, event_type, subject_type, subject_id, correlation_id, payload, previous_hash, event_hash)
     VALUES ($1, 'AGENT', $2, $3, 'ACTION', $4, $5, $6::jsonb, $7, $8)`,
    [input.organizationId, input.agentId, eventType, input.action.actionId, input.idempotencyKey, payloadText, previousHash, eventHash],
  );
}

async function transition(
  client: PoolClient,
  input: ActionSubmissionInput,
  from: ActionState,
  to: ActionState,
  verdict: PolicyDecision['verdict'] | null,
  reason: PolicyReasonCode | null,
  revisionHash: string,
): Promise<void> {
  if (!canTransitionAction(from, to)) throw new Error(`Invalid action transition ${from} -> ${to}`);
  await client.query(
    `UPDATE action_requests SET state = $1, verdict = COALESCE($2, verdict), reason_code = COALESCE($3, reason_code), updated_at = now()
     WHERE organization_id = $4 AND id = $5`,
    [to, verdict, reason, input.organizationId, input.action.actionId],
  );
  await writeAuditEvent(client, input, `ACTION_${to}`, {
    actionId: input.action.actionId,
    state: to,
    policyRevisionHash: revisionHash,
    verdict,
    reasonCode: reason,
  });
}

async function insertAction(client: PoolClient, input: ActionSubmissionInput, revision: PolicyRevision): Promise<void> {
  const actionHash = `0x${sha256(JSON.stringify(input.action))}`;
  await client.query(
    `INSERT INTO action_requests (organization_id, id, policy_id, policy_revision, idempotency_key, request_hash, action_json, state)
     VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, 'RECEIVED')`,
    [input.organizationId, input.action.actionId, revision.policyId, revision.revision, input.idempotencyKey, actionHash, JSON.stringify(input.action)],
  );
}

async function persistDecision(
  client: PoolClient,
  input: ActionSubmissionInput,
  policy: PolicyRevision,
  policyHash: string,
  decision: PolicyDecision,
): Promise<ActionSubmissionResult> {
  await insertAction(client, input, policy);
  await writeAuditEvent(client, input, 'ACTION_RECEIVED', { actionId: input.action.actionId, policyRevisionHash: policyHash, verdict: null, reasonCode: null });
  await transition(client, input, 'RECEIVED', 'VALIDATED', null, null, policyHash);
  await transition(client, input, 'VALIDATED', 'QUOTED', null, null, policyHash);
  await transition(client, input, 'QUOTED', 'EVALUATED', decision.verdict, decision.reason, policyHash);
  await client.query(
    `INSERT INTO decisions (organization_id, action_id, policy_revision_hash, verdict, reason_code)
     VALUES ($1, $2, $3, $4, $5)`,
    [input.organizationId, input.action.actionId, policyHash, decision.verdict, decision.reason],
  );

  let state: ActionSubmissionResult['state'];
  let reservationExpiresAt: string | null = null;
  if (decision.verdict === 'BLOCK') {
    await transition(client, input, 'EVALUATED', 'BLOCKED', decision.verdict, decision.reason, policyHash);
    state = 'BLOCKED';
  } else {
    const finalState = decision.verdict === 'HOLD' ? 'HELD' : 'ALLOWED';
    await transition(client, input, 'EVALUATED', finalState, decision.verdict, decision.reason, policyHash);
    if (finalState === 'ALLOWED') await transition(client, input, 'ALLOWED', 'RESERVED', decision.verdict, decision.reason, policyHash);
    const expiresAt = new Date(input.action.expiresAt * 1000);
    reservationExpiresAt = expiresAt.toISOString();
    await client.query(
      `INSERT INTO reservations (organization_id, action_id, amount, state, lease_expires_at)
       VALUES ($1, $2, $3::numeric, 'ACTIVE', $4)`,
      [input.organizationId, input.action.actionId, input.action.amount, expiresAt.toISOString()],
    );
    await client.query(
      `UPDATE action_nonce_counters SET next_nonce = next_nonce + 1, updated_at = now()
       WHERE organization_id = $1 AND policy_id = $2 AND agent_id = $3 AND agent_key_version = $4 AND nonce_epoch = $5`,
      [input.organizationId, policy.policyId, input.agentId, input.agentKeyVersion, policy.nonceEpoch],
    );
    state = decision.verdict === 'HOLD' ? 'HELD' : 'RESERVED';
  }

  const result: ActionSubmissionResult = {
    actionId: input.action.actionId,
    state,
    verdict: decision.verdict,
    reason: decision.reason,
    policyRevisionHash: policyHash,
    reservationExpiresAt,
  };
  await client.query(
    `INSERT INTO outbox_events (organization_id, aggregate_type, aggregate_id, event_type, payload)
     VALUES ($1, 'ACTION', $2, $3, $4::jsonb)`,
    [input.organizationId, input.action.actionId, `ACTION_${state}`, JSON.stringify(result)],
  );
  await client.query(
    `INSERT INTO command_idempotency (organization_id, principal_id, scope, idempotency_key, request_hash, response_json)
     VALUES ($1, $2, 'action.submit', $3, $4, $5::jsonb)`,
    [input.organizationId, input.agentId, input.idempotencyKey, `0x${sha256(JSON.stringify(input.action))}`, JSON.stringify(result)],
  );
  return result;
}

async function submitWithinTransaction(client: PoolClient, input: ActionSubmissionInput): Promise<ActionSubmissionOutcome> {
  await verifyCredential(client, input);
  const lockKey = `${input.organizationId}|${input.agentId}|action.submit|${input.idempotencyKey}`;
  await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1, 0))', [lockKey]);
  await client.query(
    `DELETE FROM command_idempotency WHERE organization_id = $1 AND principal_id = $2 AND scope = 'action.submit'
       AND idempotency_key = $3 AND expires_at <= now()`,
    [input.organizationId, input.agentId, input.idempotencyKey],
  );
  const replay = await findReplay(client, input);
  if (replay !== null) return replay;

  const { row, policy } = await lockPolicy(client, input);
  await client.query('SELECT id FROM organizations WHERE id = $1 FOR UPDATE', [input.organizationId]);
  const now = Math.floor(Date.now() / 1000);
  let expectedNonce = 0;
  if (input.action.nonceEpoch === policy.nonceEpoch) expectedNonce = await getExpectedNonce(client, input, policy);
  const budget = await getBudget(client, input, policy, now);
  const count = Number(budget.action_count);
  const currentRevisionHash = row.revision_hash.trim();
  let decision: PolicyDecision = evaluateAction({
    policy,
    policyState: getPolicyState(row.state),
    now,
    action: ActionIntentSchema.parse(input.action),
    expectedNonce,
    spentInWindow: budget.spent,
    reservedInWindow: budget.reserved,
    actionsInWindow: Number.isSafeInteger(count) ? count : -1,
  });
  if (!['POLICY_REVOKED', 'POLICY_EXPIRED', 'POLICY_INACTIVE', 'POLICY_NOT_YET_VALID'].includes(decision.reason)) {
    if (row.account_status !== 'ACTIVE' || row.account_adapter !== policy.adapter) {
      decision = { verdict: 'BLOCK', reason: 'ADAPTER_UNSUPPORTED' };
    } else if (!row.grant_active) {
      decision = { verdict: 'BLOCK', reason: 'GRANT_INACTIVE' };
    }
  }
  const result = await persistDecision(client, input, policy, currentRevisionHash, decision);
  return { kind: 'CREATED', action: result };
}

export class ActionConflictError extends Error {
  public constructor(message: string, public readonly code: 'RESOURCE_CONFLICT' | 'IDEMPOTENCY_CONFLICT' = 'RESOURCE_CONFLICT') {
    super(message);
    this.name = 'ActionConflictError';
  }
}

export class ActionStore implements ActionRepository {
  public constructor(private readonly pool: Pool) {}

  public async submitAction(input: ActionSubmissionInput): Promise<ActionSubmissionOutcome> {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      const result = await submitWithinTransaction(client, input);
      await client.query('COMMIT');
      return result;
    } catch (error: unknown) {
      await client.query('ROLLBACK');
      if (uniqueViolation(error)) throw new ActionConflictError('Action identifier or idempotency key conflicts with an existing request');
      throw error;
    } finally {
      client.release();
    }
  }
}
