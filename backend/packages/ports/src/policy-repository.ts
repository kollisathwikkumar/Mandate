import type { PolicyRevision } from '../../policy/src/schema.js';
import type { ActionIntent } from '../../policy/src/schema.js';
import type { PolicyReasonCode, PolicyVerdict } from '../../domain/src/reason-code.js';

export interface PolicyWriteInput {
  readonly organizationId: string;
  readonly principalId: string;
  readonly idempotencyKey: string;
  readonly revision: PolicyRevision;
}

export interface PolicyWriteResult {
  readonly policyId: string;
  readonly revision: number;
  readonly state: 'DRAFT';
  readonly revisionHash: string;
}

export type PolicyWriteOutcome =
  | { readonly kind: 'CREATED'; readonly policy: PolicyWriteResult }
  | { readonly kind: 'REPLAY'; readonly policy: PolicyWriteResult };

export interface PolicyListItem {
  readonly id: string;
  readonly accountId: string;
  readonly currentRevision: number;
  readonly state: 'DRAFT' | 'ACTIVE' | 'REVOKED' | 'EXPIRED';
  readonly revisionHash: string;
  readonly createdAt: string;
}

export interface PolicyRepository {
  getHumanRole(organizationId: string, subject: string): Promise<string | null>;
  listPolicies(organizationId: string): Promise<readonly PolicyListItem[]>;
  simulateAction(organizationId: string, policyId: string, action: ActionIntent): Promise<PolicySimulationResult>;
  createDraft(input: PolicyWriteInput): Promise<PolicyWriteOutcome>;
  createRevision(input: PolicyWriteInput): Promise<PolicyWriteOutcome>;
}

export interface PolicySimulationResult {
  readonly verdict: PolicyVerdict;
  readonly reason: PolicyReasonCode;
  readonly policyRevisionHash: string;
}
