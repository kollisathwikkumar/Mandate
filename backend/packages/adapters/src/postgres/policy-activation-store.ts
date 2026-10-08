import { createHash, randomUUID } from 'node:crypto';
import type { Pool, PoolClient } from 'pg';
import { PolicyRevisionSchema } from '../../../policy/src/schema.js';
import { hashPolicyRevision } from '../../../policy/src/canonical.js';
import type {
  FinalizePolicyActivationInput,
  FinalizePolicyActivationOutcome,
  PolicyActivationRecord,
  PolicyActivationRepository,
  PolicyActivationSource,
  SavePolicyActivationPlanInput,
  SavedPolicyActivationPlan,
} from '../../../ports/src/policy-activation-repository.js';
import type { SafePolicyActivationPlan } from '../../../chain/src/safe-policy-activation-plan.js';
import type { FinalizedPolicyActivation } from '../../../ports/src/policy-activation-finalizer.js';
import { RepositoryAccessError } from '../../../ports/src/repository-errors.js';
import { PolicyConflictError } from './policy-store.js';

interface ActivationSourceRow {
  readonly policy_id: string;
  readonly current_revision: number;
  readonly policy_state: 'DRAFT' | 'ACTIVE' | 'REVOKED' | 'EXPIRED';
  readonly revision_hash: string;
  readonly canonical_json: unknown;
  readonly account_id: string;
  readonly account_status: 'PAUSED' | 'ACTIVE' | 'UNSUPPORTED';
  readonly account_address: string;
  readonly chain_id: string;
  readonly guard_address: string | null;
  readonly module_address: string | null;
  readonly verified_at: Date | null;
}

interface IdempotencyRow { readonly request_hash: string; readonly response_json: unknown; }
interface ExistingPlanRow { readonly id: string; readonly plan_json: unknown; }
interface ActivationRecordRow extends ActivationSourceRow {
  readonly plan_id: string;
  readonly plan_state: PolicyActivationRecord['planState'];
  readonly plan_json: unknown;
}

function sha256(value: string): string { return createHash('sha256').update(value, 'utf8').digest('hex'); }
function normalizeAddress(value: string | null): string | null { return value?.trim().toLowerCase() ?? null; }
function isUniqueViolation(error: unknown): boolean {
  return typeof error === 'object' && error !== null && 'code' in error && error.code === '23505';
}

function sourceFromRow(row: ActivationSourceRow): PolicyActivationSource {
  const revision = PolicyRevisionSchema.parse(row.canonical_json);
  const revisionHash = row.revision_hash.trim().toLowerCase();
  if (hashPolicyRevision(revision) !== revisionHash || revision.chainId !== Number(row.chain_id)) {
    throw new PolicyConflictError('Stored canonical policy hash does not match its immutable revision record');
  }
  return {
    policyId: row.policy_id,
    currentRevision: row.current_revision,
    state: row.policy_state,
    revisionHash,
    revision,
    accountId: row.account_id,
    accountStatus: row.account_status,
    accountAddress: row.account_address.trim().toLowerCase(),
    guardAddress: normalizeAddress(row.guard_address),
    moduleAddress: normalizeAddress(row.module_address),
    verifiedAt: row.verified_at?.toISOString() ?? null,
  };
}

function planFromUnknown(value: unknown): SafePolicyActivationPlan {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) throw new Error('Persisted activation plan is malformed');
  return value as SafePolicyActivationPlan;
}

function assertPlanMatchesSource(source: PolicyActivationSource, plan: SafePolicyActivationPlan): void {
  const purposes = plan.calls.map(({ purpose }) => purpose);
  if (plan.chainId !== source.revision.chainId || plan.safeAddress !== source.accountAddress
    || plan.guardAddress !== source.guardAddress || plan.moduleAddress !== source.moduleAddress
    || plan.agentAddress !== source.revision.agentAddress || plan.agentKeyVersion !== source.revision.agentKeyVersion
    || plan.revisionHash.toLowerCase() !== source.revisionHash
    || plan.expectedPolicyEpoch !== String(source.revision.nonceEpoch)
    || plan.resultingPolicyEpoch !== String(source.revision.nonceEpoch + 1)
    || plan.compiledConfiguration.revisionHash.toLowerCase() !== source.revisionHash
    || plan.compiledConfiguration.nextEpoch !== plan.resultingPolicyEpoch
    || purposes.at(-1) !== 'CONFIGURE_POLICY' || purposes.filter((purpose) => purpose === 'CONFIGURE_POLICY').length !== 1
    || purposes.some((purpose, index) => purpose === 'REGISTER_AGENT' && index !== 0)
    || plan.calls.length < 1 || plan.calls.length > 2
    || plan.calls.some(({ safeTxHash, nonce, data }) => !/^0x[0-9a-f]{64}$/.test(safeTxHash)
      || !/^\d+$/.test(nonce) || !/^0x[0-9a-fA-F]+$/.test(data))) {
    throw new PolicyConflictError('Persisted activation plan no longer matches the canonical policy/account');
  }
}

function validateFinalizedEvidence(plan: SafePolicyActivationPlan, finalized: FinalizedPolicyActivation, planId: string, revisionHash: string): void {
  if (finalized.planId !== planId || finalized.revisionHash.toLowerCase() !== revisionHash.toLowerCase()
    || finalized.policyEpoch !== plan.resultingPolicyEpoch || finalized.receipts.length !== plan.calls.length
    || !/^\d+$/.test(finalized.finalizedBlockNumber)) throw new PolicyConflictError('Finalized activation evidence does not match the stored plan');
  const seenTransactionHashes = new Set<string>();
  let previousBlock = -1;
  let previousIndex = -1;
  for (let index = 0; index < plan.calls.length; index += 1) {
    const expected = plan.calls[index];
    const receipt = finalized.receipts[index];
    if (expected === undefined || receipt === undefined || receipt.status !== 'FINAL'
      || receipt.safeTxHash.toLowerCase() !== expected.safeTxHash.toLowerCase()
      || !/^0x[0-9a-f]{64}$/.test(receipt.transactionHash) || !/^0x[0-9a-f]{64}$/.test(receipt.blockHash)
      || !/^\d+$/.test(receipt.blockNumber) || !Number.isSafeInteger(Number(receipt.blockNumber))
      || Number(receipt.blockNumber) > Number(finalized.finalizedBlockNumber)
      || !Number.isSafeInteger(receipt.transactionIndex) || receipt.transactionIndex < 0
      || !Number.isSafeInteger(receipt.confirmations) || receipt.confirmations < 1) {
      throw new PolicyConflictError('Activation receipt evidence is incomplete or out of order');
    }
    if (seenTransactionHashes.has(receipt.transactionHash) || Number(receipt.blockNumber) < previousBlock
      || (Number(receipt.blockNumber) === previousBlock && receipt.transactionIndex <= previousIndex)) {
      throw new PolicyConflictError('Activation receipt evidence is duplicated or out of order');
    }
    seenTransactionHashes.add(receipt.transactionHash);
    previousBlock = Number(receipt.blockNumber);
    previousIndex = receipt.transactionIndex;
  }
}

async function authorizeOwner(client: PoolClient, organizationId: string, principalId: string): Promise<void> {
  const result = await client.query<{ role: string }>(
    'SELECT role FROM members WHERE organization_id = $1 AND subject = $2 FOR UPDATE', [organizationId, principalId],
  );
  const role = result.rows[0]?.role;
  if (role === undefined) throw new RepositoryAccessError(404);
  if (role !== 'OWNER') throw new RepositoryAccessError(403);
}

async function writeActivationAudit(client: PoolClient, input: SavePolicyActivationPlanInput, planId: string): Promise<void> {
  await client.query('SELECT id FROM organizations WHERE id = $1 FOR UPDATE', [input.organizationId]);
  const lastEvent = await client.query<{ event_hash: string }>(
    'SELECT event_hash FROM audit_events WHERE organization_id = $1 ORDER BY sequence DESC LIMIT 1', [input.organizationId],
  );
  const previousHash = lastEvent.rows[0]?.event_hash.trim() ?? null;
  const payload = { policyId: input.policyId, revisionHash: input.revisionHash, activationPlanId: planId, state: 'AWAITING_SAFE_OWNER_SIGNATURES' };
  const payloadText = JSON.stringify(payload);
  const eventHash = `0x${sha256(`${previousHash ?? ''}|${input.organizationId}|${input.principalId}|POLICY_ACTIVATION_PLAN_CREATED|${payloadText}`)}`;
  await client.query(
    `INSERT INTO audit_events (organization_id, actor_type, actor_id, event_type, subject_type, subject_id, correlation_id, payload, previous_hash, event_hash)
     VALUES ($1, 'HUMAN', $2, 'POLICY_ACTIVATION_PLAN_CREATED', 'POLICY', $3, $4, $5::jsonb, $6, $7)`,
    [input.organizationId, input.principalId, input.policyId, input.idempotencyKey, payloadText, previousHash, eventHash],
  );
  await client.query(
    `INSERT INTO outbox_events (organization_id, aggregate_type, aggregate_id, event_type, payload)
     VALUES ($1, 'POLICY', $2, 'POLICY_ACTIVATION_PLAN_CREATED', $3::jsonb)`,
    [input.organizationId, input.policyId, payloadText],
  );
}

export class PolicyActivationStore implements PolicyActivationRepository {
  public constructor(private readonly pool: Pool) {}

  public async getHumanRole(organizationId: string, subject: string): Promise<string | null> {
    const result = await this.pool.query<{ role: string }>(
      'SELECT role FROM members WHERE organization_id = $1 AND subject = $2', [organizationId, subject],
    );
    return result.rows[0]?.role ?? null;
  }

  public async getActivationSource(organizationId: string, policyId: string): Promise<PolicyActivationSource | null> {
    const result = await this.pool.query<ActivationSourceRow>(
      `SELECT p.id AS policy_id, p.current_revision, p.state AS policy_state, r.revision_hash, r.canonical_json,
              a.id AS account_id, a.status AS account_status, btrim(a.address) AS account_address, a.chain_id::text,
              a.guard_address, a.module_address, a.verified_at
       FROM policies p
       JOIN policy_revisions r ON r.organization_id = p.organization_id AND r.policy_id = p.id AND r.revision = p.current_revision
       JOIN accounts a ON a.organization_id = p.organization_id AND a.id = p.account_id
       WHERE p.organization_id = $1 AND p.id = $2`,
      [organizationId, policyId],
    );
    const row = result.rows[0];
    return row === undefined ? null : sourceFromRow(row);
  }

  public async getActivationRecord(organizationId: string, policyId: string, planId: string): Promise<PolicyActivationRecord | null> {
    const result = await this.pool.query<ActivationRecordRow>(
      `SELECT p.id AS policy_id, p.current_revision, p.state AS policy_state, r.revision_hash, r.canonical_json,
              a.id AS account_id, a.status AS account_status, btrim(a.address) AS account_address, a.chain_id::text,
              a.guard_address, a.module_address, a.verified_at, ap.id::text AS plan_id, ap.state AS plan_state, ap.plan_json
       FROM policy_activation_plans ap
       JOIN policies p ON p.organization_id = ap.organization_id AND p.id = ap.policy_id
       JOIN policy_revisions r ON r.organization_id = ap.organization_id AND r.policy_id = ap.policy_id AND r.revision = ap.policy_revision
       JOIN accounts a ON a.organization_id = p.organization_id AND a.id = p.account_id
       WHERE ap.organization_id = $1 AND ap.policy_id = $2 AND ap.id = $3`,
      [organizationId, policyId, planId],
    );
    const row = result.rows[0];
    if (row === undefined) return null;
    const source = sourceFromRow(row);
    const plan = planFromUnknown(row.plan_json);
    assertPlanMatchesSource(source, plan);
    return { planId: row.plan_id, planState: row.plan_state, source, plan };
  }

  public async saveActivationPlan(input: SavePolicyActivationPlanInput): Promise<SavedPolicyActivationPlan> {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      await authorizeOwner(client, input.organizationId, input.principalId);
      const scope = 'policy.activate.plan';
      const lockKey = `${input.organizationId}|${input.principalId}|${scope}|${input.idempotencyKey}`;
      await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1, 0))', [lockKey]);
      await client.query(
        `DELETE FROM command_idempotency WHERE organization_id = $1 AND principal_id = $2 AND scope = $3 AND idempotency_key = $4 AND expires_at <= now()`,
        [input.organizationId, input.principalId, scope, input.idempotencyKey],
      );
      const requestHash = `0x${sha256(`${input.policyId}|${input.revisionHash}`)}`;
      const previous = await client.query<IdempotencyRow>(
        `SELECT request_hash, response_json FROM command_idempotency
         WHERE organization_id = $1 AND principal_id = $2 AND scope = $3 AND idempotency_key = $4 AND expires_at > now()`,
        [input.organizationId, input.principalId, scope, input.idempotencyKey],
      );
      const idempotency = previous.rows[0];
      if (idempotency !== undefined) {
        if (idempotency.request_hash.trim() !== requestHash) throw new PolicyConflictError('Idempotency key was already used for a different activation plan', 'IDEMPOTENCY_CONFLICT');
        const saved = idempotency.response_json as { readonly planId?: unknown; readonly plan?: unknown };
        if (typeof saved.planId !== 'string') throw new Error('Persisted idempotency response is malformed');
        const replay = { kind: 'REPLAY' as const, planId: saved.planId, plan: planFromUnknown(saved.plan) };
        await client.query('COMMIT');
        return replay;
      }

      const selected = await client.query<ActivationSourceRow>(
        `SELECT p.id AS policy_id, p.current_revision, p.state AS policy_state, r.revision_hash, r.canonical_json,
                a.id AS account_id, a.status AS account_status, btrim(a.address) AS account_address, a.chain_id::text,
                a.guard_address, a.module_address, a.verified_at
         FROM policies p JOIN policy_revisions r ON r.organization_id = p.organization_id AND r.policy_id = p.id AND r.revision = p.current_revision
         JOIN accounts a ON a.organization_id = p.organization_id AND a.id = p.account_id
         WHERE p.organization_id = $1 AND p.id = $2 FOR UPDATE OF p, a`,
        [input.organizationId, input.policyId],
      );
      const row = selected.rows[0];
      if (row === undefined) throw new RepositoryAccessError(404);
      const source = sourceFromRow(row);
      if (source.state !== 'DRAFT' || source.revisionHash !== input.revisionHash || source.currentRevision !== source.revision.revision) {
        throw new PolicyConflictError('Policy revision changed or is not a draft');
      }
      if (source.accountStatus !== 'ACTIVE' || source.guardAddress === null || source.moduleAddress === null || source.verifiedAt === null) {
        throw new PolicyConflictError('Verified active Safe enrollment is required before activation planning');
      }
      if (input.plan.revisionHash !== source.revisionHash || input.plan.safeAddress !== source.accountAddress
        || input.plan.guardAddress !== source.guardAddress || input.plan.moduleAddress !== source.moduleAddress) {
        throw new PolicyConflictError('Activation plan does not match the current stored policy and account');
      }
      const existing = await client.query<ExistingPlanRow>(
        `SELECT id, plan_json FROM policy_activation_plans
         WHERE organization_id = $1 AND policy_id = $2 AND policy_revision = $3`,
        [input.organizationId, input.policyId, source.currentRevision],
      );
      if (existing.rows[0] !== undefined) throw new PolicyConflictError('This policy revision already has an activation plan');

      const planId = randomUUID();
      const planJson = JSON.stringify(input.plan);
      await client.query(
        `INSERT INTO policy_activation_plans (id, organization_id, policy_id, policy_revision, revision_hash, created_by, state, plan_json)
         VALUES ($1, $2, $3, $4, $5, $6, 'AWAITING_SAFE_OWNER_SIGNATURES', $7::jsonb)`,
        [planId, input.organizationId, input.policyId, source.currentRevision, input.revisionHash, input.principalId, planJson],
      );
      await client.query(
        `INSERT INTO policy_grants (organization_id, policy_id, policy_revision, account_id, adapter, grant_reference, state)
         VALUES ($1, $2, $3, $4, 'evm-smart-account', $5, 'PENDING')`,
        [input.organizationId, input.policyId, source.currentRevision, source.accountId, planId],
      );
      const response = { planId, plan: input.plan };
      await client.query(
        `INSERT INTO command_idempotency (organization_id, principal_id, scope, idempotency_key, request_hash, response_json)
         VALUES ($1, $2, $3, $4, $5, $6::jsonb)`,
        [input.organizationId, input.principalId, scope, input.idempotencyKey, requestHash, JSON.stringify(response)],
      );
      await writeActivationAudit(client, input, planId);
      await client.query('COMMIT');
      return { kind: 'CREATED', ...response };
    } catch (error: unknown) {
      await client.query('ROLLBACK');
      if (isUniqueViolation(error)) throw new PolicyConflictError('Activation plan identifier, idempotency key, or receipt hash already exists');
      throw error;
    } finally {
      client.release();
    }
  }

  public async finalizeActivation(input: FinalizePolicyActivationInput): Promise<FinalizePolicyActivationOutcome> {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      await authorizeOwner(client, input.organizationId, input.principalId);
      const scope = 'policy.activate.finalize';
      const lockKey = `${input.organizationId}|${input.principalId}|${scope}|${input.idempotencyKey}`;
      await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1, 0))', [lockKey]);
      await client.query(
        `DELETE FROM command_idempotency WHERE organization_id = $1 AND principal_id = $2 AND scope = $3 AND idempotency_key = $4 AND expires_at <= now()`,
        [input.organizationId, input.principalId, scope, input.idempotencyKey],
      );
      const previous = await client.query<IdempotencyRow>(
        `SELECT request_hash, response_json FROM command_idempotency
         WHERE organization_id = $1 AND principal_id = $2 AND scope = $3 AND idempotency_key = $4 AND expires_at > now()`,
        [input.organizationId, input.principalId, scope, input.idempotencyKey],
      );
      const requestHash = `0x${sha256(`${input.policyId}|${input.planId}|${JSON.stringify(input.finalized.receipts.map(({ transactionHash }) => transactionHash.toLowerCase()))}`)}`;
      const prior = previous.rows[0];
      if (prior !== undefined) {
        if (prior.request_hash.trim() !== requestHash) throw new PolicyConflictError('Idempotency key was already used for different activation receipts', 'IDEMPOTENCY_CONFLICT');
        const result = prior.response_json as FinalizePolicyActivationOutcome['result'];
        await client.query('COMMIT');
        return { kind: 'REPLAY', result };
      }

      const selected = await client.query<ActivationRecordRow>(
        `SELECT p.id AS policy_id, p.current_revision, p.state AS policy_state, r.revision_hash, r.canonical_json,
                a.id AS account_id, a.status AS account_status, btrim(a.address) AS account_address, a.chain_id::text,
                a.guard_address, a.module_address, a.verified_at, ap.id::text AS plan_id, ap.state AS plan_state, ap.plan_json
         FROM policy_activation_plans ap
         JOIN policies p ON p.organization_id = ap.organization_id AND p.id = ap.policy_id
         JOIN policy_revisions r ON r.organization_id = ap.organization_id AND r.policy_id = ap.policy_id AND r.revision = ap.policy_revision
         JOIN accounts a ON a.organization_id = p.organization_id AND a.id = p.account_id
         WHERE ap.organization_id = $1 AND ap.policy_id = $2 AND ap.id = $3
         FOR UPDATE OF ap, p, a`,
        [input.organizationId, input.policyId, input.planId],
      );
      const row = selected.rows[0];
      if (row === undefined) throw new RepositoryAccessError(404);
      const source = sourceFromRow(row);
      const plan = planFromUnknown(row.plan_json);
      assertPlanMatchesSource(source, plan);
      if (row.plan_state !== 'AWAITING_SAFE_OWNER_SIGNATURES' || source.state !== 'DRAFT'
        || source.currentRevision !== source.revision.revision || source.revisionHash !== plan.revisionHash.toLowerCase()) {
        throw new PolicyConflictError('Activation plan or policy is no longer pending');
      }
      validateFinalizedEvidence(plan, input.finalized, input.planId, source.revisionHash);
      const grants = await client.query<{ id: string }>(
        `UPDATE policy_grants SET state = 'ACTIVE', granted_at = now()
         WHERE organization_id = $1 AND policy_id = $2 AND policy_revision = $3 AND account_id = $4
           AND grant_reference = $5 AND state = 'PENDING' RETURNING id::text`,
        [input.organizationId, input.policyId, source.currentRevision, source.accountId, input.planId],
      );
      if (grants.rowCount !== 1) throw new PolicyConflictError('Pending policy grant was not found for this activation plan');
      const activatedPolicy = await client.query(
        `UPDATE policies SET state = 'ACTIVE', updated_at = now()
         WHERE organization_id = $1 AND id = $2 AND current_revision = $3 AND state = 'DRAFT'`,
        [input.organizationId, input.policyId, source.currentRevision],
      );
      if (activatedPolicy.rowCount !== 1) throw new PolicyConflictError('Policy revision changed while activation was being finalized');
      const confirmedPlan = await client.query(
        `UPDATE policy_activation_plans SET state = 'CONFIRMED', finalized_block_number = $1,
           finalized_receipts = $2::jsonb, confirmed_at = now(), updated_at = now()
         WHERE id = $3 AND organization_id = $4 AND state = 'AWAITING_SAFE_OWNER_SIGNATURES'`,
        [input.finalized.finalizedBlockNumber, JSON.stringify(input.finalized), input.planId, input.organizationId],
      );
      if (confirmedPlan.rowCount !== 1) throw new PolicyConflictError('Activation plan changed while finalization was being recorded');
      const receipts = input.finalized.receipts;
      for (const receipt of receipts) {
        await client.query(
          `INSERT INTO policy_activation_receipts
           (plan_id, chain_id, safe_tx_hash, transaction_hash, block_number, block_hash, transaction_index, confirmations, status)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'FINAL')`,
          [input.planId, source.revision.chainId, receipt.safeTxHash, receipt.transactionHash, receipt.blockNumber, receipt.blockHash, receipt.transactionIndex, receipt.confirmations],
        );
      }
      const result = {
        planId: input.planId, policyId: input.policyId, policyRevision: source.currentRevision,
        revisionHash: source.revisionHash, policyState: 'ACTIVE' as const, grantState: 'ACTIVE' as const,
        finalized: input.finalized,
      };
      await client.query(
        `INSERT INTO command_idempotency (organization_id, principal_id, scope, idempotency_key, request_hash, response_json)
         VALUES ($1, $2, $3, $4, $5, $6::jsonb)`,
        [input.organizationId, input.principalId, scope, input.idempotencyKey, requestHash, JSON.stringify(result)],
      );
      await client.query('SELECT id FROM organizations WHERE id = $1 FOR UPDATE', [input.organizationId]);
      const lastEvent = await client.query<{ event_hash: string }>(
        'SELECT event_hash FROM audit_events WHERE organization_id = $1 ORDER BY sequence DESC LIMIT 1', [input.organizationId],
      );
      const previousHash = lastEvent.rows[0]?.event_hash.trim() ?? null;
      const payload = { policyId: input.policyId, policyRevision: source.currentRevision, revisionHash: source.revisionHash, activationPlanId: input.planId, finalizedBlockNumber: input.finalized.finalizedBlockNumber, transactionHashes: receipts.map(({ transactionHash }) => transactionHash) };
      const payloadText = JSON.stringify(payload);
      const eventHash = `0x${sha256(`${previousHash ?? ''}|${input.organizationId}|${input.principalId}|POLICY_ACTIVATED|${payloadText}`)}`;
      await client.query(
        `INSERT INTO audit_events (organization_id, actor_type, actor_id, event_type, subject_type, subject_id, correlation_id, payload, previous_hash, event_hash)
         VALUES ($1, 'HUMAN', $2, 'POLICY_ACTIVATED', 'POLICY', $3, $4, $5::jsonb, $6, $7)`,
        [input.organizationId, input.principalId, input.policyId, input.idempotencyKey, payloadText, previousHash, eventHash],
      );
      await client.query(
        `INSERT INTO outbox_events (organization_id, aggregate_type, aggregate_id, event_type, payload)
         VALUES ($1, 'POLICY', $2, 'POLICY_ACTIVATED', $3::jsonb)`,
        [input.organizationId, input.policyId, payloadText],
      );
      await client.query('COMMIT');
      return { kind: 'FINALIZED', result };
    } catch (error: unknown) {
      await client.query('ROLLBACK');
      if (isUniqueViolation(error)) throw new PolicyConflictError('Activation transaction receipt hash or idempotency key already exists');
      throw error;
    } finally {
      client.release();
    }
  }
}
