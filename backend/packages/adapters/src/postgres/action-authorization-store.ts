import { createHash } from 'node:crypto';
import type { Pool, PoolClient } from 'pg';
import { z } from 'zod';
import { ACTION_STATES, canTransitionAction, type ActionState } from '../../../domain/src/action-state.js';
import { RepositoryAccessError } from '../../../ports/src/repository-errors.js';
import type {
  ActionAuthorizationContext,
  ActionAuthorizationInput,
  ActionAuthorizationOutcome,
  ActionAuthorizationRepository,
  ActionAuthorizationResult,
} from '../../../ports/src/action-authorization-repository.js';
import { ActionIntentSchema, PolicyRevisionSchema } from '../../../policy/src/schema.js';
import { hashPolicyRevision } from '../../../policy/src/canonical.js';
import { ActionAuthorizationConflictError as ActionAuthorizationConflict } from '../../../ports/src/action-authorization-repository.js';
import { ActionExecutionAuthorizationError, parseActionExecutionAuthorization, type ActionExecutionAuthorization } from '../../../chain/src/action-execution-authorization.js';

interface AuthorizationContextRow {
  readonly action_state: string;
  readonly action_json: unknown;
  readonly policy_state: 'DRAFT' | 'ACTIVE' | 'REVOKED' | 'EXPIRED';
  readonly current_revision: number;
  readonly revision_hash: string;
  readonly canonical_json: unknown;
  readonly account_address: string;
  readonly account_chain_id: string;
  readonly account_status: 'PAUSED' | 'ACTIVE' | 'UNSUPPORTED';
  readonly guard_address: string | null;
  readonly module_address: string | null;
  readonly grant_active: boolean;
  readonly reservation_expires_at: Date | null;
  readonly existing_idempotency_key: string | null;
  readonly existing_authorization_status: 'ACTIVE' | 'CONSUMED' | 'EXPIRED' | 'SUPERSEDED' | null;
  readonly existing_authorization_json: unknown;
}

interface IdempotencyRow { readonly request_hash: string; readonly response_json: unknown; }

const storedResultSchema = z.object({
  actionId: z.string(), state: z.literal('AUTHORIZED'), authorization: z.json(),
}).strict();

function sha256(value: string): string { return createHash('sha256').update(value, 'utf8').digest('hex'); }
function uniqueViolation(error: unknown): boolean {
  return typeof error === 'object' && error !== null && 'code' in error && error.code === '23505';
}

const contextQuery = `
  SELECT ar.state AS action_state, ar.action_json,
         p.state AS policy_state, p.current_revision,
         r.revision_hash, r.canonical_json,
         lower(btrim(a.address)) AS account_address, a.chain_id::text AS account_chain_id, a.status AS account_status,
         lower(btrim(a.guard_address)) AS guard_address, lower(btrim(a.module_address)) AS module_address,
         EXISTS (
           SELECT 1 FROM policy_grants g
           WHERE g.organization_id = p.organization_id AND g.policy_id = p.id
             AND g.policy_revision = p.current_revision AND g.account_id = p.account_id
             AND g.adapter = a.adapter AND g.state = 'ACTIVE'
         ) AS grant_active,
         reservation.lease_expires_at AS reservation_expires_at,
         existing_auth.idempotency_key AS existing_idempotency_key,
         existing_auth.status AS existing_authorization_status,
         existing_auth.authorization_json AS existing_authorization_json
  FROM action_requests ar
  JOIN policies p ON p.organization_id = ar.organization_id AND p.id = ar.policy_id
  JOIN policy_revisions r ON r.organization_id = ar.organization_id AND r.policy_id = ar.policy_id AND r.revision = ar.policy_revision
  JOIN accounts a ON a.organization_id = p.organization_id AND a.id = p.account_id
  JOIN agents agent ON agent.organization_id = ar.organization_id AND agent.id = ar.action_json->>'agentId'
  JOIN agent_credentials credential ON credential.organization_id = agent.organization_id AND credential.agent_id = agent.id
  LEFT JOIN reservations reservation ON reservation.organization_id = ar.organization_id AND reservation.action_id = ar.id
  LEFT JOIN action_authorizations existing_auth ON existing_auth.organization_id = ar.organization_id AND existing_auth.action_id = ar.id
  WHERE ar.organization_id = $1 AND ar.id = $2
    AND ar.action_json->>'agentId' = $3 AND ar.action_json->>'agentKeyVersion' = $4::text
    AND agent.status = 'ACTIVE' AND agent.key_version::text = $4::text
    AND credential.id = $5 AND credential.key_version::text = $4::text
    AND credential.revoked_at IS NULL AND (credential.expires_at IS NULL OR credential.expires_at > now())`;

function conflict(message: string, code: 'RESOURCE_CONFLICT' | 'IDEMPOTENCY_CONFLICT' = 'RESOURCE_CONFLICT'): never {
  throw new ActionAuthorizationConflict(message, code);
}

function parseStoredAuthorization(value: unknown): ActionExecutionAuthorization {
  try { return parseActionExecutionAuthorization(value); }
  catch (error: unknown) {
    if (error instanceof ActionExecutionAuthorizationError) return conflict('Stored action authorization failed its integrity checks');
    throw error;
  }
}

function contextFromRow(row: AuthorizationContextRow): ActionAuthorizationContext {
  const state = row.action_state;
  if (!ACTION_STATES.includes(state as ActionState)) return conflict('Stored action state is invalid');
  const action = ActionIntentSchema.parse(row.action_json);
  const policy = PolicyRevisionSchema.parse(row.canonical_json);
  const revisionHash = row.revision_hash.trim().toLowerCase();
  if (hashPolicyRevision(policy) !== revisionHash || policy.policyId !== action.policyId
    || Number(row.account_chain_id) !== policy.chainId) {
    return conflict('Stored action policy revision integrity check failed');
  }
  let existingAuthorization: ActionAuthorizationContext['existingAuthorization'] = null;
  if (row.existing_idempotency_key !== null) {
    if (row.existing_authorization_status === null) return conflict('Stored authorization state is missing');
    existingAuthorization = {
      idempotencyKey: row.existing_idempotency_key,
      status: row.existing_authorization_status,
      authorization: parseStoredAuthorization(row.existing_authorization_json),
    };
  }
  if (row.guard_address === null || row.module_address === null) return conflict('Account enforcement enrollment is missing');
  return {
    actionState: state as ActionState, action, policy, currentRevision: row.current_revision,
    currentRevisionHash: revisionHash, policyState: row.policy_state, accountAddress: row.account_address,
    accountChainId: Number(row.account_chain_id), accountStatus: row.account_status,
    guardAddress: row.guard_address, moduleAddress: row.module_address, grantActive: row.grant_active,
    reservationExpiresAt: row.reservation_expires_at?.toISOString() ?? null, existingAuthorization,
  };
}

async function loadContext(pool: Pool, input: {
  readonly organizationId: string; readonly agentId: string; readonly agentKeyVersion: number;
  readonly credentialId: string; readonly actionId: string;
}): Promise<ActionAuthorizationContext> {
  const result = await pool.query<AuthorizationContextRow>(contextQuery, [
    input.organizationId, input.actionId, input.agentId, input.agentKeyVersion, input.credentialId,
  ]);
  const row = result.rows[0];
  if (row === undefined) throw new RepositoryAccessError(404);
  return contextFromRow(row);
}

function validateEligible(input: ActionAuthorizationInput, context: ActionAuthorizationContext): ActionExecutionAuthorization {
  const authorization = parseStoredAuthorization(input.authorization);
  if (context.actionState !== 'RESERVED' || context.policyState !== 'ACTIVE'
    || context.currentRevision !== context.action.policyRevision
    || context.currentRevisionHash !== context.action.policyRevisionHash
    || context.accountStatus !== 'ACTIVE' || context.accountAddress !== context.action.account
    || context.accountChainId !== context.action.chainId || !context.grantActive
    || context.reservationExpiresAt === null || new Date(context.reservationExpiresAt).getTime() <= Date.now()
    || context.guardAddress !== authorization.guardAddress || context.moduleAddress !== authorization.moduleAddress
    || context.accountAddress !== authorization.safeAddress || context.policy.agentAddress !== authorization.agentAddress
    || context.policy.agentKeyVersion !== input.agentKeyVersion
    || authorization.actionId !== input.actionId || authorization.chainId !== context.action.chainId
    || authorization.policyRevisionHash !== context.currentRevisionHash
    || authorization.deadline > context.action.expiresAt
    || authorization.deadline > Math.floor(new Date(context.reservationExpiresAt).getTime() / 1000)
    || authorization.deadline <= Math.floor(Date.now() / 1000)) {
    return conflict('Action, policy, account, reservation, or exact authorization has changed');
  }
  return authorization;
}

async function writeAudit(client: PoolClient, input: ActionAuthorizationInput, authorizationId: string, plan: ActionExecutionAuthorization): Promise<void> {
  await client.query('SELECT id FROM organizations WHERE id = $1 FOR UPDATE', [input.organizationId]);
  const previous = await client.query<{ event_hash: string }>(
    'SELECT event_hash FROM audit_events WHERE organization_id = $1 ORDER BY sequence DESC LIMIT 1', [input.organizationId],
  );
  const previousHash = previous.rows[0]?.event_hash.trim() ?? null;
  const payload = {
    actionId: input.actionId, authorizationId, actionHash: plan.actionHash, actionDigest: plan.actionDigest,
    policyRevisionHash: plan.policyRevisionHash, executionNonce: plan.executionNonce, deadline: plan.deadline,
    snapshotBlockNumber: plan.snapshotBlockNumber, snapshotBlockHash: plan.snapshotBlockHash,
  };
  const payloadText = JSON.stringify(payload);
  const eventHash = `0x${sha256(`${previousHash ?? ''}|${input.organizationId}|${input.agentId}|ACTION_AUTHORIZED|${payloadText}`)}`;
  await client.query(
    `INSERT INTO audit_events (organization_id, actor_type, actor_id, event_type, subject_type, subject_id, correlation_id, payload, previous_hash, event_hash)
     VALUES ($1, 'AGENT', $2, 'ACTION_AUTHORIZED', 'ACTION', $3, $4, $5::jsonb, $6, $7)`,
    [input.organizationId, input.agentId, input.actionId, input.idempotencyKey, payloadText, previousHash, eventHash],
  );
}

async function saveWithinTransaction(client: PoolClient, input: ActionAuthorizationInput): Promise<ActionAuthorizationOutcome> {
  await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1, 0))', [
    `${input.organizationId}|${input.agentId}|action.authorize|${input.idempotencyKey}`,
  ]);
  await client.query(
    `DELETE FROM command_idempotency WHERE organization_id = $1 AND principal_id = $2
       AND scope = 'action.authorize' AND idempotency_key = $3 AND expires_at <= now()`,
    [input.organizationId, input.agentId, input.idempotencyKey],
  );
  const requestHash = `0x${sha256(JSON.stringify({ actionId: input.actionId }))}`;
  const replay = await client.query<IdempotencyRow>(
    `SELECT request_hash, response_json FROM command_idempotency
     WHERE organization_id = $1 AND principal_id = $2 AND scope = 'action.authorize'
       AND idempotency_key = $3 AND expires_at > now()`,
    [input.organizationId, input.agentId, input.idempotencyKey],
  );
  const previous = replay.rows[0];
  if (previous !== undefined) {
    if (previous.request_hash.trim() !== requestHash) return conflict('Idempotency key was used for a different action', 'IDEMPOTENCY_CONFLICT');
    const saved = storedResultSchema.parse(previous.response_json);
    if (saved.actionId !== input.actionId) return conflict('Stored action authorization replay has a different action identifier');
    const authorization = parseStoredAuthorization(saved.authorization);
    return { kind: 'REPLAY', result: { actionId: saved.actionId, state: 'AUTHORIZED', authorization } };
  }

  const locked = await client.query<AuthorizationContextRow>(`${contextQuery} FOR UPDATE OF ar, p, a, agent, credential`, [
    input.organizationId, input.actionId, input.agentId, input.agentKeyVersion, input.credentialId,
  ]);
  const row = locked.rows[0];
  if (row === undefined) throw new RepositoryAccessError(404);
  const context = contextFromRow(row);
  if (context.existingAuthorization !== null) {
    if (context.existingAuthorization.idempotencyKey !== input.idempotencyKey) return conflict('Action already has an authorization under a different idempotency key', 'IDEMPOTENCY_CONFLICT');
    if (context.existingAuthorization.status !== 'ACTIVE') return conflict('Action authorization is no longer active');
    return { kind: 'REPLAY', result: { actionId: input.actionId, state: 'AUTHORIZED', authorization: context.existingAuthorization.authorization } };
  }
  const plan = validateEligible(input, context);
  if (!canTransitionAction(context.actionState, 'AUTHORIZED')) return conflict('Action is not in a state that can be authorized');

  const inserted = await client.query<{ id: string }>(
    `INSERT INTO action_authorizations
      (organization_id, action_id, idempotency_key, request_hash, action_hash, policy_revision_hash, chain_id,
       snapshot_block_number, snapshot_block_hash, execution_nonce, status, authorization_json, expires_at)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::numeric, 'ACTIVE', $11::jsonb, to_timestamp($12))
     RETURNING id`,
    [input.organizationId, input.actionId, input.idempotencyKey, requestHash, plan.actionHash, plan.policyRevisionHash,
      plan.chainId, plan.snapshotBlockNumber, plan.snapshotBlockHash, plan.executionNonce, JSON.stringify(plan), plan.deadline],
  );
  const authorizationId = inserted.rows[0]?.id;
  if (authorizationId === undefined) throw new Error('Action authorization insert returned no identifier');
  await client.query(
    `INSERT INTO execution_attempts (organization_id, action_id, attempt_number, chain_id, state)
     VALUES ($1, $2, 1, $3, 'AUTHORIZED')`,
    [input.organizationId, input.actionId, plan.chainId],
  );
  await client.query(
    `UPDATE action_requests SET state = 'AUTHORIZED', updated_at = now()
     WHERE organization_id = $1 AND id = $2 AND state = 'RESERVED'`,
    [input.organizationId, input.actionId],
  );
  await writeAudit(client, input, authorizationId, plan);
  const result: ActionAuthorizationResult = { actionId: input.actionId, state: 'AUTHORIZED', authorization: plan };
  const eventPayload = {
    actionId: plan.actionId, actionHash: plan.actionHash, actionDigest: plan.actionDigest,
    policyRevisionHash: plan.policyRevisionHash, executionNonce: plan.executionNonce,
    deadline: plan.deadline, snapshotBlockNumber: plan.snapshotBlockNumber, snapshotBlockHash: plan.snapshotBlockHash,
  };
  await client.query(
    `INSERT INTO outbox_events (organization_id, aggregate_type, aggregate_id, event_type, payload)
     VALUES ($1, 'ACTION', $2, 'ACTION_AUTHORIZED', $3::jsonb)`,
    [input.organizationId, input.actionId, JSON.stringify(eventPayload)],
  );
  await client.query(
    `INSERT INTO command_idempotency (organization_id, principal_id, scope, idempotency_key, request_hash, response_json)
     VALUES ($1, $2, 'action.authorize', $3, $4, $5::jsonb)`,
    [input.organizationId, input.agentId, input.idempotencyKey, requestHash, JSON.stringify(result)],
  );
  return { kind: 'CREATED', result };
}

export class ActionAuthorizationStore implements ActionAuthorizationRepository {
  public constructor(private readonly pool: Pool) {}

  public async getAuthorizationContext(input: {
    readonly organizationId: string; readonly agentId: string; readonly agentKeyVersion: number;
    readonly credentialId: string; readonly actionId: string;
  }): Promise<ActionAuthorizationContext> {
    return loadContext(this.pool, input);
  }

  public async saveAuthorization(input: ActionAuthorizationInput): Promise<ActionAuthorizationOutcome> {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      const outcome = await saveWithinTransaction(client, input);
      await client.query('COMMIT');
      return outcome;
    } catch (error: unknown) {
      await client.query('ROLLBACK');
      if (uniqueViolation(error)) return conflict('Action authorization or execution attempt already exists');
      throw error;
    } finally {
      client.release();
    }
  }
}
