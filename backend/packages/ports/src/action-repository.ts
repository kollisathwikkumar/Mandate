import type { ActionIntent } from '../../policy/src/schema.js';
import type { PolicyReasonCode } from '../../domain/src/reason-code.js';

export interface ActionSubmissionInput {
  readonly organizationId: string;
  readonly agentId: string;
  readonly agentKeyVersion: number;
  readonly credentialId: string;
  readonly idempotencyKey: string;
  readonly action: ActionIntent;
}

export interface ActionSubmissionResult {
  readonly actionId: string;
  readonly state: 'BLOCKED' | 'HELD' | 'RESERVED';
  readonly verdict: 'BLOCK' | 'HOLD' | 'ALLOW';
  readonly reason: PolicyReasonCode;
  readonly policyRevisionHash: string;
  readonly reservationExpiresAt: string | null;
}

export type ActionSubmissionOutcome =
  | { readonly kind: 'CREATED'; readonly action: ActionSubmissionResult }
  | { readonly kind: 'REPLAY'; readonly action: ActionSubmissionResult };

export interface ActionRepository {
  submitAction(input: ActionSubmissionInput): Promise<ActionSubmissionOutcome>;
}
