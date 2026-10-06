import { createHash, randomUUID } from 'node:crypto';
import type { Pool, PoolClient } from 'pg';
import { z } from 'zod';
import { Interface, TypedDataEncoder, ZeroAddress } from 'ethers';
import { PolicyRevisionSchema } from '../../../policy/src/schema.js';
import { hashPolicyRevision } from '../../../policy/src/canonical.js';
import type {
  FinalizePolicyRevocationInput, FinalizePolicyRevocationOutcome, PolicyRevocationRecord,
  PolicyRevocationRepository, SavePolicyRevocationPlanInput, SavedPolicyRevocationPlan,
} from '../../../ports/src/policy-revocation-repository.js';
import type { PolicyActivationSource } from '../../../ports/src/policy-activation-repository.js';
import type { SafePolicyRevocationPlan } from '../../../chain/src/safe-policy-revocation-plan.js';
import { safeTransactionTypes } from '../../../chain/src/safe-policy-activation-plan.js';
import type { FinalizedPolicyRevocation } from '../../../ports/src/policy-revocation-finalizer.js';
import { RepositoryAccessError } from '../../../ports/src/repository-errors.js';
import { PolicyConflictError } from './policy-store.js';

interface SourceRow {
  readonly policy_id: string;
  readonly current_revision: number;
  readonly policy_state: PolicyActivationSource['state'];
  readonly revision_hash: string;
  readonly canonical_json: unknown;
  readonly account_id: string;
  readonly account_status: PolicyActivationSource['accountStatus'];
  readonly account_address: string;
  readonly chain_id: string;
  readonly guard_address: string | null;
  readonly module_address: string | null;
  readonly verified_at: Date | null;
}
interface RevocationRow extends SourceRow {
  readonly plan_id: string;
  readonly plan_state: PolicyRevocationRecord['planState'];
  readonly plan_json: unknown;
}
interface IdempotencyRow { readonly request_hash: string; readonly response_json: unknown; }

const AddressSchema = z.string().regex(/^0x[0-9a-f]{40}$/);
const HashSchema = z.string().regex(/^0x[0-9a-f]{64}$/);
const DecimalSchema = z.string().regex(/^(0|[1-9][0-9]*)$/);
const RevocationInterface = new Interface(['function revokePolicy()']);
const SafePayloadSchema = z.object({
  domain: z.object({ chainId: z.number().int().positive(), verifyingContract: AddressSchema }).strict(),
  types: z.object({ SafeTx: z.array(z.object({ name: z.string(), type: z.string() }).strict()).length(10) }).strict(),
  primaryType: z.literal('SafeTx'),
  message: z.object({
    to: AddressSchema, value: DecimalSchema, data: z.string().regex(/^0x[0-9a-fA-F]+$/),
    operation: z.literal(0), safeTxGas: DecimalSchema, baseGas: DecimalSchema, gasPrice: DecimalSchema,
    gasToken: AddressSchema, refundReceiver: AddressSchema, nonce: DecimalSchema,
  }).strict(),
}).strict();
const SafePolicyRevocationPlanSchema = z.object({
  chainId: z.number().int().positive(), safeAddress: AddressSchema, guardAddress: AddressSchema, moduleAddress: AddressSchema, agentAddress: AddressSchema,
  revisionHash: HashSchema, expectedPolicyEpoch: DecimalSchema, resultingPolicyEpoch: DecimalSchema,
  ownerAddresses: z.array(AddressSchema).min(1).max(100), ownerThreshold: z.number().int().positive(),
  call: z.object({ to: AddressSchema, data: z.string().regex(/^0x[0-9a-fA-F]+$/), nonce: DecimalSchema,
    safeTxHash: HashSchema, signingPayload: SafePayloadSchema }).strict(),
  status: z.literal('AWAITING_SAFE_OWNER_SIGNATURES'),
}).strict();

function sha256(value: string): string { return createHash('sha256').update(value, 'utf8').digest('hex'); }
function isUniqueViolation(error: unknown): boolean {
  return typeof error === 'object' && error !== null && 'code' in error && error.code === '23505';
}
function normalizeAddress(value: string | null): string | null { return value?.trim().toLowerCase() ?? null; }

function sourceFromRow(row: SourceRow): PolicyActivationSource {
  const revision = PolicyRevisionSchema.parse(row.canonical_json);
  const revisionHash = row.revision_hash.trim().toLowerCase();
  if (hashPolicyRevision(revision) !== revisionHash || revision.chainId !== Number(row.chain_id)) {
    throw new PolicyConflictError('Stored canonical policy hash does not match its immutable revision record');
  }
  return {
    policyId: row.policy_id, currentRevision: row.current_revision, state: row.policy_state,
    revisionHash, revision, accountId: row.account_id, accountStatus: row.account_status,
    accountAddress: row.account_address.trim().toLowerCase(), guardAddress: normalizeAddress(row.guard_address),
    moduleAddress: normalizeAddress(row.module_address), verifiedAt: row.verified_at?.toISOString() ?? null,
  };
}

function planFromUnknown(value: unknown): SafePolicyRevocationPlan {
  const plan = SafePolicyRevocationPlanSchema.parse(value);
  const expectedTypes = JSON.stringify(safeTransactionTypes);
  const payload = plan.call.signingPayload;
  const recomputedSafeTxHash = TypedDataEncoder.hash(payload.domain, safeTransactionTypes, payload.message);
  const expectedData = RevocationInterface.encodeFunctionData('revokePolicy');
  if (plan.call.to !== plan.guardAddress || plan.call.nonce !== payload.message.nonce
    || plan.call.to !== payload.message.to || plan.call.data !== expectedData || plan.call.data.toLowerCase() !== payload.message.data.toLowerCase()
    || payload.message.value !== '0' || payload.message.operation !== 0 || payload.message.safeTxGas !== '0'
    || payload.message.baseGas !== '0' || payload.message.gasPrice !== '0'
    || payload.message.gasToken.toLowerCase() !== ZeroAddress.toLowerCase()
    || payload.message.refundReceiver.toLowerCase() !== ZeroAddress.toLowerCase()
    || payload.domain.chainId !== plan.chainId || payload.domain.verifyingContract !== plan.safeAddress
    || JSON.stringify(payload.types) !== expectedTypes
    || recomputedSafeTxHash.toLowerCase() !== plan.call.safeTxHash.toLowerCase()
    || plan.ownerThreshold > plan.ownerAddresses.length
    || BigInt(plan.resultingPolicyEpoch) !== BigInt(plan.expectedPolicyEpoch) + 1n) {
    throw new PolicyConflictError('Stored policy revocation plan is malformed or no longer canonical');
  }
  return plan;
}

function assertPlanMatchesSource(source: PolicyActivationSource, plan: SafePolicyRevocationPlan, requireActive = true): void {
  if ((requireActive && source.state !== 'ACTIVE') || (!requireActive && source.state !== 'ACTIVE' && source.state !== 'REVOKED')
    || plan.chainId !== source.revision.chainId || plan.safeAddress !== source.accountAddress
    || plan.guardAddress !== source.guardAddress || plan.moduleAddress !== source.moduleAddress
    || plan.agentAddress !== source.revision.agentAddress
    || plan.revisionHash !== source.revisionHash || plan.expectedPolicyEpoch !== String(source.revision.nonceEpoch + 1)) {
    throw new PolicyConflictError('Policy revocation plan no longer matches the active policy/account');
  }
}

function validateFinalizedEvidence(plan: SafePolicyRevocationPlan, finalized: FinalizedPolicyRevocation, planId: string): void {
  const receipt = finalized.receipt;
  if (finalized.planId !== planId || finalized.revisionHash !== plan.revisionHash
    || finalized.previousPolicyEpoch !== plan.expectedPolicyEpoch || finalized.policyEpoch !== plan.resultingPolicyEpoch
    || !/^(0|[1-9][0-9]*)$/.test(finalized.finalizedBlockNumber)
    || receipt.status !== 'FINAL' || receipt.safeTxHash !== plan.call.safeTxHash
    || !/^0x[0-9a-f]{64}$/.test(receipt.transactionHash) || !/^0x[0-9a-f]{64}$/.test(receipt.blockHash)
    || !/^(0|[1-9][0-9]*)$/.test(receipt.blockNumber)
    || !Number.isSafeInteger(Number(receipt.blockNumber)) || Number(receipt.blockNumber) > Number(finalized.finalizedBlockNumber)
    || !Number.isSafeInteger(receipt.transactionIndex) || receipt.transactionIndex < 0
    || !Number.isSafeInteger(receipt.confirmations) || receipt.confirmations < 1) {
    throw new PolicyConflictError('Finalized revocation evidence does not match the stored plan');
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

async function loadSource(poolOrClient: Pool | PoolClient, organizationId: string, policyId: string, lock = false): Promise<SourceRow | undefined> {
  const result = await poolOrClient.query<SourceRow>(
    `SELECT p.id AS policy_id, p.current_revision, p.state AS policy_state, r.revision_hash, r.canonical_json,
            a.id AS account_id, a.status AS account_status, btrim(a.address) AS account_address, a.chain_id::text,
            a.guard_address, a.module_address, a.verified_at
     FROM policies p
     JOIN policy_revisions r ON r.organization_id = p.organization_id AND r.policy_id = p.id AND r.revision = p.current_revision
     JOIN accounts a ON a.organization_id = p.organization_id AND a.id = p.account_id
     WHERE p.organization_id = $1 AND p.id = $2${lock ? ' FOR UPDATE OF p, a' : ''}`,
    [organizationId, policyId],
  );
  return result.rows[0];
}

async function writeAuditAndOutbox(
  client: PoolClient, organizationId: string, principalId: string, policyId: string,
  idempotencyKey: string, eventType: 'POLICY_REVOCATION_PLAN_CREATED' | 'POLICY_REVOKED', payload: Readonly<Record<string, unknown>>,
): Promise<void> {
  await client.query('SELECT id FROM organizations WHERE id = $1 FOR UPDATE', [organizationId]);
  const lastEvent = await client.query<{ event_hash: string }>(
    'SELECT event_hash FROM audit_events WHERE organization_id = $1 ORDER BY sequence DESC LIMIT 1', [organizationId],
  );
  const previousHash = lastEvent.rows[0]?.event_hash.trim() ?? null;
  const payloadText = JSON.stringify(payload);
  const eventHash = `0x${sha256(`${previousHash ?? ''}|${organizationId}|${principalId}|${eventType}|${payloadText}`)}`;
  await client.query(
    `INSERT INTO audit_events (organization_id, actor_type, actor_id, event_type, subject_type, subject_id, correlation_id, payload, previous_hash, event_hash)
     VALUES ($1, 'HUMAN', $2, $3, 'POLICY', $4, $5, $6::jsonb, $7, $8)`,
    [organizationId, principalId, eventType, policyId, idempotencyKey, payloadText, previousHash, eventHash],
  );
  await client.query(
    `INSERT INTO outbox_events (organization_id, aggregate_type, aggregate_id, event_type, payload)
     VALUES ($1, 'POLICY', $2, $3, $4::jsonb)`, [organizationId, policyId, eventType, payloadText],
  );
}

export class PolicyRevocationStore implements PolicyRevocationRepository {
  public constructor(private readonly pool: Pool) {}

  public async getHumanRole(organizationId: string, subject: string): Promise<string | null> {
    const result = await this.pool.query<{ role: string }>(
      'SELECT role FROM members WHERE organization_id = $1 AND subject = $2', [organizationId, subject],
    );
    return result.rows[0]?.role ?? null;
  }

  public async getRevocationSource(organizationId: string, policyId: string): Promise<PolicyActivationSource | null> {
    const row = await loadSource(this.pool, organizationId, policyId);
    return row === undefined ? null : sourceFromRow(row);
  }

  public async saveRevocationPlan(input: SavePolicyRevocationPlanInput): Promise<SavedPolicyRevocationPlan> {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      await authorizeOwner(client, input.organizationId, input.principalId);
      const scope = 'policy.revoke.plan';
      const lockKey = `${input.organizationId}|${input.principalId}|${scope}|${input.idempotencyKey}`;
      await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1, 0))', [lockKey]);
      await client.query(
        'DELETE FROM command_idempotency WHERE organization_id = $1 AND principal_id = $2 AND scope = $3 AND idempotency_key = $4 AND expires_at <= now()',
        [input.organizationId, input.principalId, scope, input.idempotencyKey],
      );
      const requestHash = `0x${sha256(`${input.policyId}|${input.revisionHash}|${input.plan.call.safeTxHash}`)}`;
      const previous = await client.query<IdempotencyRow>(
        `SELECT request_hash, response_json FROM command_idempotency
         WHERE organization_id = $1 AND principal_id = $2 AND scope = $3 AND idempotency_key = $4 AND expires_at > now()`,
        [input.organizationId, input.principalId, scope, input.idempotencyKey],
      );
      const prior = previous.rows[0];
      if (prior !== undefined) {
        if (prior.request_hash.trim() !== requestHash) throw new PolicyConflictError('Idempotency key was already used for a different revocation plan', 'IDEMPOTENCY_CONFLICT');
        const saved = prior.response_json as { readonly planId?: unknown; readonly plan?: unknown };
        if (typeof saved.planId !== 'string') throw new Error('Persisted idempotency response is malformed');
        const replay = { kind: 'REPLAY' as const, planId: saved.planId, plan: planFromUnknown(saved.plan) };
        await client.query('COMMIT');
        return replay;
      }
      const sourceRow = await loadSource(client, input.organizationId, input.policyId, true);
      if (sourceRow === undefined) throw new RepositoryAccessError(404);
      const source = sourceFromRow(sourceRow);
      if (source.state !== 'ACTIVE' || source.accountStatus !== 'ACTIVE' || source.guardAddress === null || source.moduleAddress === null
        || source.verifiedAt === null || source.revisionHash !== input.revisionHash) {
        throw new PolicyConflictError('A verified active policy and account are required before revocation planning');
      }
      const plan = planFromUnknown(input.plan);
      assertPlanMatchesSource(source, plan);
      const activeGrant = await client.query<{ id: string }>(
        `SELECT id::text FROM policy_grants WHERE organization_id = $1 AND policy_id = $2 AND policy_revision = $3
           AND account_id = $4 AND adapter = $5 AND state = 'ACTIVE' FOR UPDATE`,
        [input.organizationId, input.policyId, source.currentRevision, source.accountId, source.revision.adapter],
      );
      if (activeGrant.rowCount !== 1) throw new PolicyConflictError('Active policy grant was not found for this policy revision');
      const planId = randomUUID();
      const planJson = JSON.stringify(plan);
      await client.query(
        `INSERT INTO policy_revocation_plans (id, organization_id, policy_id, policy_revision, revision_hash, created_by, state, plan_json)
         VALUES ($1, $2, $3, $4, $5, $6, 'AWAITING_SAFE_OWNER_SIGNATURES', $7::jsonb)`,
        [planId, input.organizationId, input.policyId, source.currentRevision, input.revisionHash, input.principalId, planJson],
      );
      const response = { planId, plan };
      await client.query(
        `INSERT INTO command_idempotency (organization_id, principal_id, scope, idempotency_key, request_hash, response_json)
         VALUES ($1, $2, $3, $4, $5, $6::jsonb)`,
        [input.organizationId, input.principalId, scope, input.idempotencyKey, requestHash, JSON.stringify(response)],
      );
      await writeAuditAndOutbox(client, input.organizationId, input.principalId, input.policyId, input.idempotencyKey,
        'POLICY_REVOCATION_PLAN_CREATED', { policyId: input.policyId, revisionHash: input.revisionHash, revocationPlanId: planId, state: plan.status });
      await client.query('COMMIT');
      return { kind: 'CREATED', ...response };
    } catch (error: unknown) {
      await client.query('ROLLBACK');
      if (isUniqueViolation(error)) throw new PolicyConflictError('A revocation plan, idempotency key, or receipt already exists');
      throw error;
    } finally { client.release(); }
  }

  public async getRevocationRecord(organizationId: string, policyId: string, planId: string): Promise<PolicyRevocationRecord | null> {
    const result = await this.pool.query<RevocationRow>(
      `SELECT p.id AS policy_id, p.current_revision, p.state AS policy_state, r.revision_hash, r.canonical_json,
              a.id AS account_id, a.status AS account_status, btrim(a.address) AS account_address, a.chain_id::text,
              a.guard_address, a.module_address, a.verified_at, rp.id::text AS plan_id, rp.state AS plan_state, rp.plan_json
       FROM policy_revocation_plans rp
       JOIN policies p ON p.organization_id = rp.organization_id AND p.id = rp.policy_id
       JOIN policy_revisions r ON r.organization_id = rp.organization_id AND r.policy_id = rp.policy_id AND r.revision = rp.policy_revision
       JOIN accounts a ON a.organization_id = p.organization_id AND a.id = p.account_id
       WHERE rp.organization_id = $1 AND rp.policy_id = $2 AND rp.id = $3`, [organizationId, policyId, planId],
    );
    const row = result.rows[0];
    if (row === undefined) return null;
    const source = sourceFromRow(row);
    const plan = planFromUnknown(row.plan_json);
    assertPlanMatchesSource(source, plan, row.plan_state === 'AWAITING_SAFE_OWNER_SIGNATURES');
    return { planId: row.plan_id, planState: row.plan_state, source, plan };
  }

  public async finalizeRevocation(input: FinalizePolicyRevocationInput): Promise<FinalizePolicyRevocationOutcome> {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      await authorizeOwner(client, input.organizationId, input.principalId);
      const scope = 'policy.revoke.finalize';
      const lockKey = `${input.organizationId}|${input.principalId}|${scope}|${input.idempotencyKey}`;
      await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1, 0))', [lockKey]);
      await client.query(
        'DELETE FROM command_idempotency WHERE organization_id = $1 AND principal_id = $2 AND scope = $3 AND idempotency_key = $4 AND expires_at <= now()',
        [input.organizationId, input.principalId, scope, input.idempotencyKey],
      );
      const requestHash = `0x${sha256(`${input.policyId}|${input.planId}|${input.finalized.receipt.transactionHash.toLowerCase()}`)}`;
      const previous = await client.query<IdempotencyRow>(
        `SELECT request_hash, response_json FROM command_idempotency
         WHERE organization_id = $1 AND principal_id = $2 AND scope = $3 AND idempotency_key = $4 AND expires_at > now()`,
        [input.organizationId, input.principalId, scope, input.idempotencyKey],
      );
      const prior = previous.rows[0];
      if (prior !== undefined) {
        if (prior.request_hash.trim() !== requestHash) throw new PolicyConflictError('Idempotency key was already used for different revocation evidence', 'IDEMPOTENCY_CONFLICT');
        const result = prior.response_json as FinalizePolicyRevocationOutcome['result'];
        await client.query('COMMIT');
        return { kind: 'REPLAY', result };
      }
      const selected = await client.query<RevocationRow>(
        `SELECT p.id AS policy_id, p.current_revision, p.state AS policy_state, r.revision_hash, r.canonical_json,
                a.id AS account_id, a.status AS account_status, btrim(a.address) AS account_address, a.chain_id::text,
                a.guard_address, a.module_address, a.verified_at, rp.id::text AS plan_id, rp.state AS plan_state, rp.plan_json
         FROM policy_revocation_plans rp
         JOIN policies p ON p.organization_id = rp.organization_id AND p.id = rp.policy_id
         JOIN policy_revisions r ON r.organization_id = rp.organization_id AND r.policy_id = rp.policy_id AND r.revision = rp.policy_revision
         JOIN accounts a ON a.organization_id = p.organization_id AND a.id = p.account_id
         WHERE rp.organization_id = $1 AND rp.policy_id = $2 AND rp.id = $3
         FOR UPDATE OF rp, p, a`, [input.organizationId, input.policyId, input.planId],
      );
      const row = selected.rows[0];
      if (row === undefined) throw new RepositoryAccessError(404);
      const source = sourceFromRow(row);
      const plan = planFromUnknown(row.plan_json);
      assertPlanMatchesSource(source, plan);
      if (row.plan_state !== 'AWAITING_SAFE_OWNER_SIGNATURES' || source.state !== 'ACTIVE'
        || source.currentRevision !== source.revision.revision) throw new PolicyConflictError('Revocation plan or policy is no longer pending');
      validateFinalizedEvidence(plan, input.finalized, input.planId);
      const grant = await client.query<{ id: string }>(
        `UPDATE policy_grants SET state = 'REVOKED', revoked_at = now()
         WHERE organization_id = $1 AND policy_id = $2 AND policy_revision = $3 AND account_id = $4
           AND adapter = $5 AND state = 'ACTIVE' RETURNING id::text`,
        [input.organizationId, input.policyId, source.currentRevision, source.accountId, source.revision.adapter],
      );
      if (grant.rowCount !== 1) throw new PolicyConflictError('Active policy grant changed while revocation was being finalized');
      const policy = await client.query(
        `UPDATE policies SET state = 'REVOKED', updated_at = now()
         WHERE organization_id = $1 AND id = $2 AND current_revision = $3 AND state = 'ACTIVE'`,
        [input.organizationId, input.policyId, source.currentRevision],
      );
      if (policy.rowCount !== 1) throw new PolicyConflictError('Active policy changed while revocation was being finalized');
      const confirmed = await client.query(
        `UPDATE policy_revocation_plans SET state = 'CONFIRMED', finalized_block_number = $1,
           finalized_receipt = $2::jsonb, confirmed_at = now(), updated_at = now()
         WHERE id = $3 AND organization_id = $4 AND state = 'AWAITING_SAFE_OWNER_SIGNATURES'`,
        [input.finalized.finalizedBlockNumber, JSON.stringify(input.finalized.receipt), input.planId, input.organizationId],
      );
      if (confirmed.rowCount !== 1) throw new PolicyConflictError('Revocation plan changed while finalization was being recorded');
      const receipt = input.finalized.receipt;
      await client.query(
        `INSERT INTO policy_revocation_receipts
         (plan_id, chain_id, safe_tx_hash, transaction_hash, block_number, block_hash, transaction_index, confirmations, status)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'FINAL')`,
        [input.planId, source.revision.chainId, receipt.safeTxHash, receipt.transactionHash, receipt.blockNumber,
          receipt.blockHash, receipt.transactionIndex, receipt.confirmations],
      );
      const result = {
        planId: input.planId, policyId: input.policyId, policyRevision: source.currentRevision,
        revisionHash: source.revisionHash, previousPolicyEpoch: input.finalized.previousPolicyEpoch,
        policyEpoch: input.finalized.policyEpoch, policyState: 'REVOKED' as const, grantState: 'REVOKED' as const,
        finalized: input.finalized,
      };
      await client.query(
        `INSERT INTO command_idempotency (organization_id, principal_id, scope, idempotency_key, request_hash, response_json)
         VALUES ($1, $2, $3, $4, $5, $6::jsonb)`,
        [input.organizationId, input.principalId, scope, input.idempotencyKey, requestHash, JSON.stringify(result)],
      );
      await writeAuditAndOutbox(client, input.organizationId, input.principalId, input.policyId, input.idempotencyKey,
        'POLICY_REVOKED', { policyId: input.policyId, policyRevision: source.currentRevision, revisionHash: source.revisionHash,
          revocationPlanId: input.planId, policyEpoch: input.finalized.policyEpoch,
          finalizedBlockNumber: input.finalized.finalizedBlockNumber, transactionHash: receipt.transactionHash });
      await client.query('COMMIT');
      return { kind: 'FINALIZED', result };
    } catch (error: unknown) {
      await client.query('ROLLBACK');
      if (isUniqueViolation(error)) throw new PolicyConflictError('Revocation transaction receipt or idempotency key already exists');
      throw error;
    } finally { client.release(); }
  }
}
