import type { PolicyRevision } from '../../policy/src/schema.js';
import type { SafePolicyActivationPlan } from '../../chain/src/safe-policy-activation-plan.js';
import type { FinalizedPolicyActivation } from './policy-activation-finalizer.js';

export interface PolicyActivationSource {
  readonly policyId: string;
  readonly currentRevision: number;
  readonly state: 'DRAFT' | 'ACTIVE' | 'REVOKED' | 'EXPIRED';
  readonly revisionHash: string;
  readonly revision: PolicyRevision;
  readonly accountId: string;
  readonly accountStatus: 'PAUSED' | 'ACTIVE' | 'UNSUPPORTED';
  readonly accountAddress: string;
  readonly guardAddress: string | null;
  readonly moduleAddress: string | null;
  readonly verifiedAt: string | null;
}

export interface SavePolicyActivationPlanInput {
  readonly organizationId: string;
  readonly principalId: string;
  readonly idempotencyKey: string;
  readonly policyId: string;
  readonly revisionHash: string;
  readonly plan: SafePolicyActivationPlan;
}

export interface PolicyActivationRecord {
  readonly planId: string;
  readonly planState: 'AWAITING_SAFE_OWNER_SIGNATURES' | 'SUBMITTED' | 'CONFIRMED' | 'FAILED' | 'SUPERSEDED';
  readonly source: PolicyActivationSource;
  readonly plan: SafePolicyActivationPlan;
}

export interface FinalizePolicyActivationInput {
  readonly organizationId: string;
  readonly principalId: string;
  readonly idempotencyKey: string;
  readonly policyId: string;
  readonly planId: string;
  readonly finalized: FinalizedPolicyActivation;
}

export interface FinalizedPolicyActivationResult {
  readonly planId: string;
  readonly policyId: string;
  readonly policyRevision: number;
  readonly revisionHash: string;
  readonly policyState: 'ACTIVE';
  readonly grantState: 'ACTIVE';
  readonly finalized: FinalizedPolicyActivation;
}

export type FinalizePolicyActivationOutcome =
  | { readonly kind: 'FINALIZED'; readonly result: FinalizedPolicyActivationResult }
  | { readonly kind: 'REPLAY'; readonly result: FinalizedPolicyActivationResult };

export type SavedPolicyActivationPlan =
  | { readonly kind: 'CREATED'; readonly planId: string; readonly plan: SafePolicyActivationPlan }
  | { readonly kind: 'REPLAY'; readonly planId: string; readonly plan: SafePolicyActivationPlan };

export interface PolicyActivationRepository {
  getHumanRole(organizationId: string, subject: string): Promise<string | null>;
  getActivationSource(organizationId: string, policyId: string): Promise<PolicyActivationSource | null>;
  saveActivationPlan(input: SavePolicyActivationPlanInput): Promise<SavedPolicyActivationPlan>;
  getActivationRecord(organizationId: string, policyId: string, planId: string): Promise<PolicyActivationRecord | null>;
  finalizeActivation(input: FinalizePolicyActivationInput): Promise<FinalizePolicyActivationOutcome>;
}
