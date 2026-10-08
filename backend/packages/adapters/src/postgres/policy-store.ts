import { createHash } from 'node:crypto';
import type { Pool, PoolClient } from 'pg';
import { z } from 'zod';
import { canonicalizePolicyRevision, hashPolicyRevision } from '../../../policy/src/canonical.js';
import { PolicyRevisionSchema, type PolicyRevision } from '../../../policy/src/schema.js';
import { ActionIntentSchema, type ActionIntent } from '../../../policy/src/schema.js';
import { evaluateAction, type PolicyState } from '../../../policy/src/evaluate.js';
import type { PolicyListItem, PolicyRepository, PolicySimulationResult, PolicyWriteInput, PolicyWriteOutcome, PolicyWriteResult } from '../../../ports/src/policy-repository.js';
import { RepositoryAccessError } from '../../../ports/src/repository-errors.js';

const PolicyWriteResultSchema = z.object({
  policyId: z.string(),
  revision: z.number().int().positive(),
  state: z.literal('DRAFT'),
  revisionHash: z.string().regex(/^0x[0-9a-f]{64}$/),
}).strict();

interface IdempotencyRow {
  readonly request_hash: string;
  readonly response_json: unknown;
}

interface AgentAccountLink {
  readonly account_id: string;
  readonly account_adapter: string;
  readonly account_status: 'ACTIVE' | 'PAUSED' | 'UNSUPPORTED';
  readonly agent_status: 'ACTIVE' | 'REVOKED';
  readonly agent_key_version: number;
}

interface PolicyRow {
  readonly id: string;
  readonly account_id: string;
  readonly current_revision: number;
  readonly state: 'DRAFT' | 'ACTIVE' | 'REVOKED' | 'EXPIRED';
  readonly revision_hash: string;
  readonly created_at: Date;
}

interface SimulationRow {
  readonly state: 'DRAFT' | 'ACTIVE' | 'REVOKED' | 'EXPIRED';
  readonly revision_hash: string;
  readonly canonical_json: unknown;
  readonly account_status: 'ACTIVE' | 'PAUSED' | 'UNSUPPORTED';
  readonly account_adapter: string;
  readonly grant_active: boolean;
}

interface SimulationBudgetRow {
  readonly spent: string;
  readonly reserved: string;
  readonly action_count: string;
}

interface SimulationNonceRow { readonly next_nonce: string; }

function policyState(state: SimulationRow['state']): PolicyState {
  switch (state) {
    case 'ACTIVE': return 'active';
    case 'DRAFT': return 'draft';
    case 'REVOKED': return 'revoked';
    case 'EXPIRED': return 'expired';
  }
}

async function simulateInPostgres(pool: Pool, organizationId: string, policyId: string, inputAction: ActionIntent): Promise<PolicySimulationResult> {
  const action = ActionIntentSchema.parse(inputAction);
  const policyResult = await pool.query<SimulationRow>(
    `SELECT p.state, r.revision_hash, r.canonical_json, a.status AS account_status, a.adapter AS account_adapter,
       EXISTS (SELECT 1 FROM policy_grants g WHERE g.organization_id = p.organization_id AND g.policy_id = p.id
         AND g.policy_revision = p.current_revision AND g.account_id = p.account_id AND g.adapter = a.adapter AND g.state = 'ACTIVE') AS grant_active
     FROM policies p JOIN policy_revisions r ON r.organization_id = p.organization_id AND r.policy_id = p.id AND r.revision = p.current_revision
     JOIN accounts a ON a.organization_id = p.organization_id AND a.id = p.account_id
     WHERE p.organization_id = $1 AND p.id = $2`,
    [organizationId, policyId],
  );
  const row = policyResult.rows[0];
  if (row === undefined) throw new RepositoryAccessError(404);
  const policy = PolicyRevisionSchema.parse(row.canonical_json);
  const now = Math.floor(Date.now() / 1000);
  const nonceResult = await pool.query<SimulationNonceRow>(
    `SELECT next_nonce::text AS next_nonce FROM action_nonce_counters
     WHERE organization_id = $1 AND policy_id = $2 AND agent_id = $3 AND agent_key_version = $4 AND nonce_epoch = $5`,
    [organizationId, policy.policyId, policy.agentId, policy.agentKeyVersion, policy.nonceEpoch],
  );
  const nonceValue = nonceResult.rows[0]?.next_nonce;
  const expectedNonce = nonceValue === undefined ? 0 : Number(nonceValue);
  const windowStart = now - policy.limits.windowSeconds;
  const budgetResult = await pool.query<SimulationBudgetRow>(
    `SELECT COALESCE(sum(r.amount) FILTER (WHERE r.state = 'CONSUMED'), 0)::text AS spent,
       COALESCE(sum(r.amount) FILTER (WHERE r.state = 'ACTIVE' AND r.lease_expires_at > to_timestamp($3)), 0)::text AS reserved,
       count(*) FILTER (WHERE r.state = 'CONSUMED' OR (r.state = 'ACTIVE' AND r.lease_expires_at > to_timestamp($3)))::text AS action_count
     FROM reservations r JOIN action_requests a ON a.organization_id = r.organization_id AND a.id = r.action_id
     WHERE r.organization_id = $1 AND a.policy_id = $2 AND r.created_at >= to_timestamp($4)`,
    [organizationId, policy.policyId, now, windowStart],
  );
  const budget = budgetResult.rows[0];
  const decision = evaluateAction({
    policy,
    policyState: policyState(row.state),
    now,
    action,
    expectedNonce: Number.isSafeInteger(expectedNonce) && expectedNonce >= 0 ? expectedNonce : -1,
    spentInWindow: budget?.spent ?? null,
    reservedInWindow: budget?.reserved ?? null,
    actionsInWindow: budget === undefined ? null : Number(budget.action_count),
  });
  if (['POLICY_REVOKED', 'POLICY_EXPIRED', 'POLICY_INACTIVE', 'POLICY_NOT_YET_VALID'].includes(decision.reason)) {
    return { ...decision, policyRevisionHash: row.revision_hash.trim() };
  }
  if (row.account_status !== 'ACTIVE' || row.account_adapter !== policy.adapter) {
    return { verdict: 'BLOCK', reason: 'ADAPTER_UNSUPPORTED', policyRevisionHash: row.revision_hash.trim() };
  }
  if (!row.grant_active) return { verdict: 'BLOCK', reason: 'GRANT_INACTIVE', policyRevisionHash: row.revision_hash.trim() };
  return { ...decision, policyRevisionHash: row.revision_hash.trim() };
}

function sha256(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('hex');
}

function isUniqueViolation(error: unknown): boolean {
  return typeof error === 'object' && error !== null && 'code' in error && error.code === '23505';
}

async function authorizeMember(client: PoolClient, input: PolicyWriteInput): Promise<void> {
  const result = await client.query<{ role: string }>(
    'SELECT role FROM members WHERE organization_id = $1 AND subject = $2 FOR UPDATE',
    [input.organizationId, input.principalId],
  );
  const role = result.rows[0]?.role;
  if (role === undefined) throw new RepositoryAccessError(404);
  if (role !== 'OWNER' && role !== 'ADMIN') throw new RepositoryAccessError(403);
}

async function replayIdempotency(client: PoolClient, input: PolicyWriteInput, scope: 'policy.create' | 'policy.revise'): Promise<PolicyWriteOutcome | null> {
  const result = await client.query<IdempotencyRow>(
    `SELECT request_hash, response_json FROM command_idempotency
     WHERE organization_id = $1 AND principal_id = $2 AND scope = $3 AND idempotency_key = $4 AND expires_at > now()`,
    [input.organizationId, input.principalId, scope, input.idempotencyKey],
  );
  const row = result.rows[0];
  if (row === undefined) return null;
  const requestHash = hashPolicyRevision(input.revision);
  if (row.request_hash.trim() !== requestHash) throw new PolicyConflictError('Idempotency key was already used for a different policy revision', 'IDEMPOTENCY_CONFLICT');
  return { kind: 'REPLAY', policy: PolicyWriteResultSchema.parse(row.response_json) };
}

async function resolveAccountAndAgent(client: PoolClient, input: PolicyWriteInput): Promise<AgentAccountLink> {
  const result = await client.query<AgentAccountLink>(
    `SELECT a.id AS account_id, a.adapter AS account_adapter, a.status AS account_status,
            g.status AS agent_status, g.key_version AS agent_key_version
     FROM accounts a
     JOIN agents g ON g.organization_id = a.organization_id
     WHERE a.organization_id = $1 AND a.chain_id = $2 AND lower(btrim(a.address)) = $3
       AND g.id = $4`,
    [input.organizationId, input.revision.chainId, input.revision.account, input.revision.agentId],
  );
  const link = result.rows[0];
  if (link === undefined) throw new RepositoryAccessError(404);
  if (link.agent_status !== 'ACTIVE' || link.agent_key_version !== input.revision.agentKeyVersion) {
    throw new PolicyConflictError('Policy revision does not match the active agent key version');
  }
  if (link.account_status !== 'ACTIVE' || link.account_adapter !== input.revision.adapter) {
    throw new PolicyConflictError('Policy adapter is not active for the linked account');
  }
  return link;
}

async function writeAuditAndOutbox(
  client: PoolClient,
  input: PolicyWriteInput,
  policy: PolicyWriteResult,
  eventType: 'POLICY_DRAFT_CREATED' | 'POLICY_REVISION_CREATED',
): Promise<void> {
  await client.query('SELECT id FROM organizations WHERE id = $1 FOR UPDATE', [input.organizationId]);
  const lastEvent = await client.query<{ event_hash: string }>(
    'SELECT event_hash FROM audit_events WHERE organization_id = $1 ORDER BY sequence DESC LIMIT 1',
    [input.organizationId],
  );
  const previousHash = lastEvent.rows[0]?.event_hash.trim() ?? null;
  const payload = { policyId: policy.policyId, revision: policy.revision, revisionHash: policy.revisionHash };
  const eventHash = `0x${sha256(`${previousHash ?? ''}|${input.organizationId}|${input.principalId}|${eventType}|${JSON.stringify(payload)}`)}`;
  await client.query(
    `INSERT INTO audit_events (organization_id, actor_type, actor_id, event_type, subject_type, subject_id, correlation_id, payload, previous_hash, event_hash)
     VALUES ($1, 'HUMAN', $2, $3, 'POLICY', $4, $5, $6::jsonb, $7, $8)`,
    [input.organizationId, input.principalId, eventType, policy.policyId, input.idempotencyKey, JSON.stringify(payload), previousHash, eventHash],
  );
  await client.query(
    `INSERT INTO outbox_events (organization_id, aggregate_type, aggregate_id, event_type, payload)
     VALUES ($1, 'POLICY', $2, $3, $4::jsonb)`,
    [input.organizationId, policy.policyId, eventType, JSON.stringify(payload)],
  );
}

async function saveRevision(client: PoolClient, input: PolicyWriteInput, accountId: string, policyStatus: 'DRAFT' | 'EXISTING'): Promise<PolicyWriteResult> {
  const revision = PolicyRevisionSchema.parse(input.revision);
  const canonicalRevision = canonicalizePolicyRevision(revision);
  const revisionHash = hashPolicyRevision(revision);

  if (policyStatus === 'DRAFT') {
    await client.query(
      `INSERT INTO policies (organization_id, id, account_id, current_revision, state)
       VALUES ($1, $2, $3, $4, 'DRAFT')`,
      [input.organizationId, revision.policyId, accountId, revision.revision],
    );
  }
  await client.query(
    `INSERT INTO policy_revisions (organization_id, policy_id, revision, schema_version, canonical_json, revision_hash, created_by, valid_after, expires_at)
     VALUES ($1, $2, $3, $4, $5::jsonb, $6, $7, to_timestamp($8), to_timestamp($9))`,
    [input.organizationId, revision.policyId, revision.revision, revision.schemaVersion, canonicalRevision, revisionHash, input.principalId, revision.validAfter, revision.expiresAt],
  );
  if (policyStatus === 'EXISTING') {
    await client.query(
      `UPDATE policies SET current_revision = $1, state = 'DRAFT', updated_at = now()
       WHERE organization_id = $2 AND id = $3`,
      [revision.revision, input.organizationId, revision.policyId],
    );
  }
  return { policyId: revision.policyId, revision: revision.revision, state: 'DRAFT', revisionHash };
}

async function createPolicyInTransaction(client: PoolClient, input: PolicyWriteInput, isRevision: boolean): Promise<PolicyWriteOutcome> {
  await authorizeMember(client, input);
  const scope = isRevision ? 'policy.revise' : 'policy.create';
  const lockKey = `${input.organizationId}|${input.principalId}|${scope}|${input.idempotencyKey}`;
  await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1, 0))', [lockKey]);
  await client.query(
    `DELETE FROM command_idempotency WHERE organization_id = $1 AND principal_id = $2 AND scope = $3 AND idempotency_key = $4 AND expires_at <= now()`,
    [input.organizationId, input.principalId, scope, input.idempotencyKey],
  );
  const replay = await replayIdempotency(client, input, scope);
  if (replay !== null) return replay;

  const link = await resolveAccountAndAgent(client, input);
  const revision = PolicyRevisionSchema.parse(input.revision);
  let eventType: 'POLICY_DRAFT_CREATED' | 'POLICY_REVISION_CREATED';

  if (!isRevision) {
    if (revision.revision !== 1) throw new PolicyConflictError('A new policy must begin at revision 1');
    eventType = 'POLICY_DRAFT_CREATED';
  } else {
    const current = await client.query<PolicyRow>(
      `SELECT p.id, p.account_id, p.current_revision, p.state, r.revision_hash, r.created_at
       FROM policies p JOIN policy_revisions r
         ON r.organization_id = p.organization_id AND r.policy_id = p.id AND r.revision = p.current_revision
       WHERE p.organization_id = $1 AND p.id = $2 FOR UPDATE OF p`,
      [input.organizationId, revision.policyId],
    );
    const row = current.rows[0];
    if (row === undefined) throw new RepositoryAccessError(404);
    if (row.state === 'REVOKED' || row.state === 'EXPIRED') throw new PolicyConflictError('A revoked or expired policy cannot receive a new revision');
    if (revision.revision !== row.current_revision + 1) throw new PolicyConflictError('Policy revision number must increment by exactly one');
    if (link.account_id !== row.account_id) throw new RepositoryAccessError(404);
    const previousRevision = PolicyRevisionSchema.parse(
      (await client.query<{ canonical_json: unknown }>(
        'SELECT canonical_json FROM policy_revisions WHERE organization_id = $1 AND policy_id = $2 AND revision = $3',
        [input.organizationId, revision.policyId, row.current_revision],
      )).rows[0]?.canonical_json,
    );
    if (revision.nonceEpoch < previousRevision.nonceEpoch) throw new PolicyConflictError('Policy nonce epoch cannot move backwards');
    eventType = 'POLICY_REVISION_CREATED';
  }

  const policy = await saveRevision(client, input, link.account_id, isRevision ? 'EXISTING' : 'DRAFT');
  await client.query(
    `INSERT INTO command_idempotency (organization_id, principal_id, scope, idempotency_key, request_hash, response_json)
     VALUES ($1, $2, $3, $4, $5, $6::jsonb)`,
    [input.organizationId, input.principalId, scope, input.idempotencyKey, hashPolicyRevision(revision), JSON.stringify(policy)],
  );
  await writeAuditAndOutbox(client, input, policy, eventType);
  return { kind: 'CREATED', policy };
}

export class PolicyConflictError extends Error {
  public constructor(message: string, public readonly code: 'RESOURCE_CONFLICT' | 'IDEMPOTENCY_CONFLICT' = 'RESOURCE_CONFLICT') {
    super(message);
    this.name = 'PolicyConflictError';
  }
}

export class PolicyStore implements PolicyRepository {
  public constructor(private readonly pool: Pool) {}

  public async getHumanRole(organizationId: string, subject: string): Promise<string | null> {
    const result = await this.pool.query<{ role: string }>(
      'SELECT role FROM members WHERE organization_id = $1 AND subject = $2',
      [organizationId, subject],
    );
    return result.rows[0]?.role ?? null;
  }

  public async listPolicies(organizationId: string): Promise<readonly PolicyListItem[]> {
    const result = await this.pool.query<PolicyRow>(
      `SELECT p.id, p.account_id, p.current_revision, p.state, r.revision_hash, r.created_at
       FROM policies p JOIN policy_revisions r
         ON r.organization_id = p.organization_id AND r.policy_id = p.id AND r.revision = p.current_revision
       WHERE p.organization_id = $1 ORDER BY p.created_at, p.id`,
      [organizationId],
    );
    return result.rows.map((row) => ({
      id: row.id,
      accountId: row.account_id,
      currentRevision: row.current_revision,
      state: row.state,
      revisionHash: row.revision_hash.trim(),
      createdAt: row.created_at.toISOString(),
    }));
  }

  public async getRevision(organizationId: string, policyId: string, revision: number): Promise<PolicyRevision | null> {
    const result = await this.pool.query<{ canonical_json: unknown }>(
      'SELECT canonical_json FROM policy_revisions WHERE organization_id = $1 AND policy_id = $2 AND revision = $3',
      [organizationId, policyId, revision],
    );
    const canonical = result.rows[0]?.canonical_json;
    return canonical === undefined ? null : PolicyRevisionSchema.parse(canonical);
  }

  public async simulateAction(organizationId: string, policyId: string, action: ActionIntent): Promise<PolicySimulationResult> {
    return simulateInPostgres(this.pool, organizationId, policyId, action);
  }

  public async createDraft(input: PolicyWriteInput): Promise<PolicyWriteOutcome> {
    return this.transaction(input, false);
  }

  public async createRevision(input: PolicyWriteInput): Promise<PolicyWriteOutcome> {
    return this.transaction(input, true);
  }

  private async transaction(input: PolicyWriteInput, isRevision: boolean): Promise<PolicyWriteOutcome> {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      const result = await createPolicyInTransaction(client, input, isRevision);
      await client.query('COMMIT');
      return result;
    } catch (error: unknown) {
      await client.query('ROLLBACK');
      if (isUniqueViolation(error)) throw new PolicyConflictError('Policy or revision identifier already exists');
      throw error;
    } finally {
      client.release();
    }
  }
}
