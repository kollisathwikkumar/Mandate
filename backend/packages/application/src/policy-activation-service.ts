import type { Principal } from '../../domain/src/principal.js';
import type { AccountEnrollmentVerifier } from '../../ports/src/account-enrollment-verifier.js';
import type { FinalizePolicyActivationOutcome, PolicyActivationRepository, SavedPolicyActivationPlan } from '../../ports/src/policy-activation-repository.js';
import type { SafePolicyActivationReader } from '../../ports/src/safe-policy-activation-reader.js';
import type { PolicyActivationFinalizer } from '../../ports/src/policy-activation-finalizer.js';
import { PolicyActivationFinalizationError } from '../../ports/src/policy-activation-finalizer.js';
import { buildSafePolicyActivationPlan } from '../../chain/src/safe-policy-activation-plan.js';
import { ApplicationAccessError } from './agent-service.js';
import { RepositoryAccessError } from '../../ports/src/repository-errors.js';

export class PolicyActivationConflictError extends Error {
  public constructor(message: string) {
    super(message);
    this.name = 'PolicyActivationConflictError';
  }
}

export class PolicyActivationApplicationService {
  public constructor(
    private readonly repository: PolicyActivationRepository,
    private readonly enrollmentVerifier: AccountEnrollmentVerifier,
    private readonly chainReader: SafePolicyActivationReader,
    private readonly finalizer: PolicyActivationFinalizer,
    private readonly confirmationsByChain: Readonly<Record<number, number>>,
  ) {}

  public async prepare(
    principal: Principal,
    organizationId: string,
    policyId: string,
    idempotencyKey: string,
  ): Promise<SavedPolicyActivationPlan> {
    if (principal.type !== 'HUMAN') throw new ApplicationAccessError(403, 'FORBIDDEN');
    try {
      const role = await this.repository.getHumanRole(organizationId, principal.subject);
      if (role === null) throw new ApplicationAccessError(404, 'RESOURCE_NOT_FOUND');
      if (role !== 'OWNER') throw new ApplicationAccessError(403, 'FORBIDDEN');
      const source = await this.repository.getActivationSource(organizationId, policyId);
      if (source === null) throw new ApplicationAccessError(404, 'RESOURCE_NOT_FOUND');
      if (source.revision.organizationId !== organizationId) throw new ApplicationAccessError(404, 'RESOURCE_NOT_FOUND');
      if (source.state !== 'DRAFT') throw new PolicyActivationConflictError('Only a draft policy can be prepared for activation');
      if (source.accountStatus !== 'ACTIVE' || source.guardAddress === null || source.moduleAddress === null || source.verifiedAt === null) {
        throw new PolicyActivationConflictError('Verified active Safe enrollment is required before activation planning');
      }
      const proof = await this.enrollmentVerifier.verify({ chainId: source.revision.chainId, address: source.accountAddress });
      if (proof.safeAddress.toLowerCase() !== source.accountAddress
        || proof.guardAddress.toLowerCase() !== source.guardAddress
        || proof.moduleAddress.toLowerCase() !== source.moduleAddress) {
        throw new PolicyActivationConflictError('Current on-chain enrollment does not match the registered Safe');
      }
      const state = await this.chainReader.readState({
        chainId: source.revision.chainId,
        safeAddress: source.accountAddress,
        guardAddress: source.guardAddress,
        moduleAddress: source.moduleAddress,
        agentAddress: source.revision.agentAddress,
      });
      if (state.safeAddress.toLowerCase() !== source.accountAddress || state.guardAddress.toLowerCase() !== source.guardAddress
        || state.moduleAddress.toLowerCase() !== source.moduleAddress || state.chainId !== source.revision.chainId) {
        throw new PolicyActivationConflictError('Current Safe state does not match the verified enrollment');
      }
      const plan = buildSafePolicyActivationPlan(source.revision, state);
      return await this.repository.saveActivationPlan({
        organizationId, principalId: principal.subject, idempotencyKey, policyId,
        revisionHash: source.revisionHash, plan,
      });
    } catch (error: unknown) {
      if (error instanceof RepositoryAccessError) throw new ApplicationAccessError(error.statusCode, error.statusCode === 403 ? 'FORBIDDEN' : 'RESOURCE_NOT_FOUND');
      throw error;
    }
  }

  public async finalize(
    principal: Principal,
    organizationId: string,
    policyId: string,
    planId: string,
    idempotencyKey: string,
    transactionHashes: readonly string[],
  ): Promise<FinalizePolicyActivationOutcome> {
    if (principal.type !== 'HUMAN') throw new ApplicationAccessError(403, 'FORBIDDEN');
    try {
      const role = await this.repository.getHumanRole(organizationId, principal.subject);
      if (role === null) throw new ApplicationAccessError(404, 'RESOURCE_NOT_FOUND');
      if (role !== 'OWNER') throw new ApplicationAccessError(403, 'FORBIDDEN');
      const record = await this.repository.getActivationRecord(organizationId, policyId, planId);
      if (record === null) throw new ApplicationAccessError(404, 'RESOURCE_NOT_FOUND');
      if (record.planState === 'FAILED' || record.planState === 'SUPERSEDED') {
        throw new PolicyActivationConflictError('Activation plan is no longer finalizable');
      }
      const { source, plan } = record;
      const proof = await this.enrollmentVerifier.verify({ chainId: source.revision.chainId, address: source.accountAddress });
      if (proof.safeAddress.toLowerCase() !== source.accountAddress || proof.guardAddress.toLowerCase() !== source.guardAddress
        || proof.moduleAddress.toLowerCase() !== source.moduleAddress) {
        throw new PolicyActivationConflictError('Current on-chain enrollment does not match the stored activation plan');
      }
      const confirmations = this.confirmationsByChain[source.revision.chainId];
      if (confirmations === undefined) throw new PolicyActivationFinalizationError('UNSUPPORTED_CHAIN');
      const finalized = await this.finalizer.verifyFinalizedActivation({
        planId, plan, transactionHashes, minimumConfirmations: confirmations,
      });
      if (finalized.planId !== planId || finalized.revisionHash.toLowerCase() !== plan.revisionHash.toLowerCase()
        || finalized.policyEpoch !== plan.resultingPolicyEpoch) {
        throw new PolicyActivationConflictError('Finalized chain evidence does not match the stored activation plan');
      }
      return await this.repository.finalizeActivation({
        organizationId, principalId: principal.subject, idempotencyKey, policyId, planId, finalized,
      });
    } catch (error: unknown) {
      if (error instanceof RepositoryAccessError) throw new ApplicationAccessError(error.statusCode, error.statusCode === 403 ? 'FORBIDDEN' : 'RESOURCE_NOT_FOUND');
      throw error;
    }
  }
}
