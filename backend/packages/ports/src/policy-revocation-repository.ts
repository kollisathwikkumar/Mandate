import type { SafePolicyRevocationPlan } from '../../chain/src/safe-policy-revocation-plan.js';
import type { FinalizedPolicyRevocation } from './policy-revocation-finalizer.js';
import type { PolicyActivationSource } from './policy-activation-repository.js';

export interface PolicyRevocationRecord {
  readonly planId: string;
  readonly planState: 'AWAITING_SAFE_OWNER_SIGNATURES' | 'CONFIRMED' | 'SUPERSEDED';
  readonly source: PolicyActivationSource;
  readonly plan: SafePolicyRevocationPlan;
}

export interface SavePolicyRevocationPlanInput {
  readonly organizationId: string;
  readonly principalId: string;
  readonly idempotencyKey: string;
  readonly policyId: string;
  readonly revisionHash: string;
  readonly plan: SafePolicyRevocationPlan;
}

export interface SavedPolicyRevocationPlan {
  readonly kind: 'CREATED' | 'REPLAY';
  readonly planId: string;
  readonly plan: SafePolicyRevocationPlan;
}

export interface FinalizePolicyRevocationInput {
  readonly organizationId: string;
  readonly principalId: string;
  readonly idempotencyKey: string;
  readonly policyId: string;
  readonly planId: string;
  readonly finalized: FinalizedPolicyRevocation;
}

export interface FinalizedPolicyRevocationResult {
  readonly planId: string;
  readonly policyId: string;
  readonly policyRevision: number;
  readonly revisionHash: string;
  readonly previousPolicyEpoch: string;
  readonly policyEpoch: string;
  readonly policyState: 'REVOKED';
  readonly grantState: 'REVOKED';
  readonly finalized: FinalizedPolicyRevocation;
}

export type FinalizePolicyRevocationOutcome =
  | { readonly kind: 'FINALIZED'; readonly result: FinalizedPolicyRevocationResult }
  | { readonly kind: 'REPLAY'; readonly result: FinalizedPolicyRevocationResult };

export interface PolicyRevocationRepository {
  getHumanRole(organizationId: string, subject: string): Promise<string | null>;
  getRevocationSource(organizationId: string, policyId: string): Promise<PolicyActivationSource | null>;
  saveRevocationPlan(input: SavePolicyRevocationPlanInput): Promise<SavedPolicyRevocationPlan>;
  getRevocationRecord(organizationId: string, policyId: string, planId: string): Promise<PolicyRevocationRecord | null>;
  finalizeRevocation(input: FinalizePolicyRevocationInput): Promise<FinalizePolicyRevocationOutcome>;
}
