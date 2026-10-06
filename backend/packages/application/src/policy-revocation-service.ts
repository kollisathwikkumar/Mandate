import type { Principal } from '../../domain/src/principal.js';
import type { AccountEnrollmentVerifier } from '../../ports/src/account-enrollment-verifier.js';
import type { SafePolicyActivationReader } from '../../ports/src/safe-policy-activation-reader.js';
import type { FinalizePolicyRevocationOutcome, PolicyRevocationRepository, SavedPolicyRevocationPlan } from '../../ports/src/policy-revocation-repository.js';
import type { PolicyRevocationFinalizer } from '../../ports/src/policy-revocation-finalizer.js';
import { PolicyRevocationFinalizationError } from '../../ports/src/policy-revocation-finalizer.js';
import { buildSafePolicyRevocationPlan } from '../../chain/src/safe-policy-revocation-plan.js';
import { ApplicationAccessError } from './agent-service.js';
import { RepositoryAccessError } from '../../ports/src/repository-errors.js';

export class PolicyRevocationConflictError extends Error {
  public constructor(message: string) {
    super(message);
    this.name = 'PolicyRevocationConflictError';
  }
}

export class PolicyRevocationApplicationService {
  public constructor(
    private readonly repository: PolicyRevocationRepository,
    private readonly enrollmentVerifier: AccountEnrollmentVerifier,
    private readonly chainReader: SafePolicyActivationReader,
    private readonly finalizer: PolicyRevocationFinalizer,
    private readonly confirmationsByChain: Readonly<Record<number, number>>,
  ) {}

  public async prepare(
    principal: Principal,
    organizationId: string,
    policyId: string,
    idempotencyKey: string,
  ): Promise<SavedPolicyRevocationPlan> {
    if (principal.type !== 'HUMAN') throw new ApplicationAccessError(403, 'FORBIDDEN');
    try {
      const role = await this.repository.getHumanRole(organizationId, principal.subject);
      if (role === null) throw new ApplicationAccessError(404, 'RESOURCE_NOT_FOUND');
      if (role !== 'OWNER') throw new ApplicationAccessError(403, 'FORBIDDEN');
      const source = await this.repository.getRevocationSource(organizationId, policyId);
      if (source === null) throw new ApplicationAccessError(404, 'RESOURCE_NOT_FOUND');
      if (source.state !== 'ACTIVE') throw new PolicyRevocationConflictError('Only an active policy can be revoked');
      if (source.accountStatus !== 'ACTIVE' || source.guardAddress === null || source.moduleAddress === null || source.verifiedAt === null) {
        throw new PolicyRevocationConflictError('Verified active Safe enrollment is required before revocation planning');
      }
      const proof = await this.enrollmentVerifier.verify({ chainId: source.revision.chainId, address: source.accountAddress });
      if (proof.safeAddress.toLowerCase() !== source.accountAddress || proof.guardAddress.toLowerCase() !== source.guardAddress
        || proof.moduleAddress.toLowerCase() !== source.moduleAddress) {
        throw new PolicyRevocationConflictError('Current on-chain enrollment does not match the registered Safe');
      }
      const state = await this.chainReader.readState({
        chainId: source.revision.chainId, safeAddress: source.accountAddress,
        guardAddress: source.guardAddress, moduleAddress: source.moduleAddress,
        agentAddress: source.revision.agentAddress,
      });
      if (state.safeAddress.toLowerCase() !== source.accountAddress || state.guardAddress.toLowerCase() !== source.guardAddress
        || state.moduleAddress.toLowerCase() !== source.moduleAddress || state.chainId !== source.revision.chainId
        || state.policyRevisionHash.toLowerCase() !== source.revisionHash
        || state.policyEpoch !== BigInt(source.revision.nonceEpoch + 1)) {
        throw new PolicyRevocationConflictError('Current Safe state does not match the active policy revision');
      }
      const plan = buildSafePolicyRevocationPlan(state, source.revision.agentAddress);
      return await this.repository.saveRevocationPlan({
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
    transactionHash: string,
  ): Promise<FinalizePolicyRevocationOutcome> {
    if (principal.type !== 'HUMAN') throw new ApplicationAccessError(403, 'FORBIDDEN');
    try {
      const role = await this.repository.getHumanRole(organizationId, principal.subject);
      if (role === null) throw new ApplicationAccessError(404, 'RESOURCE_NOT_FOUND');
      if (role !== 'OWNER') throw new ApplicationAccessError(403, 'FORBIDDEN');
      const record = await this.repository.getRevocationRecord(organizationId, policyId, planId);
      if (record === null) throw new ApplicationAccessError(404, 'RESOURCE_NOT_FOUND');
      if (record.planState === 'SUPERSEDED') throw new PolicyRevocationConflictError('Revocation plan is no longer finalizable');
      const { source, plan } = record;
      const expectedPolicyState = record.planState === 'CONFIRMED' ? 'REVOKED' : 'ACTIVE';
      if (source.state !== expectedPolicyState || source.currentRevision !== source.revision.revision
        || source.revisionHash !== plan.revisionHash.toLowerCase()) {
        throw new PolicyRevocationConflictError('Active policy revision no longer matches the stored revocation plan');
      }
      const proof = await this.enrollmentVerifier.verify({ chainId: source.revision.chainId, address: source.accountAddress });
      if (proof.safeAddress.toLowerCase() !== source.accountAddress || proof.guardAddress.toLowerCase() !== source.guardAddress
        || proof.moduleAddress.toLowerCase() !== source.moduleAddress) {
        throw new PolicyRevocationConflictError('Current on-chain enrollment does not match the stored revocation plan');
      }
      const confirmations = this.confirmationsByChain[source.revision.chainId];
      if (confirmations === undefined) throw new PolicyRevocationFinalizationError('UNSUPPORTED_CHAIN');
      const finalized = await this.finalizer.verifyFinalizedRevocation({ planId, plan, transactionHash, minimumConfirmations: confirmations });
      if (finalized.planId !== planId || finalized.revisionHash.toLowerCase() !== plan.revisionHash.toLowerCase()
        || finalized.previousPolicyEpoch !== plan.expectedPolicyEpoch || finalized.policyEpoch !== plan.resultingPolicyEpoch) {
        throw new PolicyRevocationConflictError('Finalized chain evidence does not match the stored revocation plan');
      }
      return await this.repository.finalizeRevocation({
        organizationId, principalId: principal.subject, idempotencyKey, policyId, planId, finalized,
      });
    } catch (error: unknown) {
      if (error instanceof RepositoryAccessError) throw new ApplicationAccessError(error.statusCode, error.statusCode === 403 ? 'FORBIDDEN' : 'RESOURCE_NOT_FOUND');
      throw error;
    }
  }
}
