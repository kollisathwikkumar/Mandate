import type { ActionExecutionAuthorization } from '../../chain/src/action-execution-authorization.js';
import type { ActionIntent, PolicyRevision } from '../../policy/src/schema.js';
import type { ActionState } from '../../domain/src/action-state.js';

export class ActionAuthorizationConflictError extends Error {
  public constructor(message: string, public readonly code: 'RESOURCE_CONFLICT' | 'IDEMPOTENCY_CONFLICT' = 'RESOURCE_CONFLICT') {
    super(message);
    this.name = 'ActionAuthorizationConflictError';
  }
}

export interface StoredActionAuthorization {
  readonly idempotencyKey: string;
  readonly status: 'ACTIVE' | 'CONSUMED' | 'EXPIRED' | 'SUPERSEDED';
  readonly authorization: ActionExecutionAuthorization;
}

export interface ActionAuthorizationContext {
  readonly actionState: ActionState;
  readonly action: ActionIntent;
  readonly policy: PolicyRevision;
  readonly currentRevision: number;
  readonly currentRevisionHash: string;
  readonly policyState: 'DRAFT' | 'ACTIVE' | 'REVOKED' | 'EXPIRED';
  readonly accountAddress: string;
  readonly accountChainId: number;
  readonly accountStatus: 'PAUSED' | 'ACTIVE' | 'UNSUPPORTED';
  readonly guardAddress: string;
  readonly moduleAddress: string;
  readonly grantActive: boolean;
  readonly reservationExpiresAt: string | null;
  readonly existingAuthorization: StoredActionAuthorization | null;
}

export interface ActionAuthorizationInput {
  readonly organizationId: string;
  readonly agentId: string;
  readonly agentKeyVersion: number;
  readonly credentialId: string;
  readonly actionId: string;
  readonly idempotencyKey: string;
  readonly authorization: ActionExecutionAuthorization;
}

export interface ActionAuthorizationResult {
  readonly actionId: string;
  readonly state: 'AUTHORIZED';
  readonly authorization: ActionExecutionAuthorization;
}

export type ActionAuthorizationOutcome =
  | { readonly kind: 'CREATED'; readonly result: ActionAuthorizationResult }
  | { readonly kind: 'REPLAY'; readonly result: ActionAuthorizationResult };

export interface ActionAuthorizationRepository {
  getAuthorizationContext(input: {
    readonly organizationId: string;
    readonly agentId: string;
    readonly agentKeyVersion: number;
    readonly credentialId: string;
    readonly actionId: string;
  }): Promise<ActionAuthorizationContext>;
  saveAuthorization(input: ActionAuthorizationInput): Promise<ActionAuthorizationOutcome>;
}
