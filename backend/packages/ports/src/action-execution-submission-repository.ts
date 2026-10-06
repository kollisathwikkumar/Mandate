export class ActionExecutionSubmissionConflictError extends Error {
  public constructor(message: string, public readonly code: 'RESOURCE_CONFLICT' | 'IDEMPOTENCY_CONFLICT' = 'RESOURCE_CONFLICT') {
    super(message);
    this.name = 'ActionExecutionSubmissionConflictError';
  }
}

export interface ActionExecutionSubmissionIdentity {
  readonly organizationId: string;
  readonly agentId: string;
  readonly agentKeyVersion: number;
  readonly credentialId: string;
  readonly actionId: string;
  readonly idempotencyKey: string;
  readonly transactionHash: string;
  readonly outerSender: string;
  readonly outerNonce: number;
}

export interface ActionExecutionSubmissionResult {
  readonly actionId: string;
  readonly state: 'SUBMITTED';
  readonly transactionHash: string;
}

export type ReserveActionExecutionSubmissionOutcome =
  | { readonly kind: 'BROADCAST'; readonly transactionHash: string }
  | { readonly kind: 'REPLAY'; readonly result: ActionExecutionSubmissionResult };

export type CompleteActionExecutionSubmissionOutcome =
  | { readonly kind: 'CREATED'; readonly result: ActionExecutionSubmissionResult }
  | { readonly kind: 'REPLAY'; readonly result: ActionExecutionSubmissionResult };

export interface ActionExecutionSubmissionRepository {
  reserveSubmission(input: ActionExecutionSubmissionIdentity): Promise<ReserveActionExecutionSubmissionOutcome>;
  completeSubmission(input: ActionExecutionSubmissionIdentity): Promise<CompleteActionExecutionSubmissionOutcome>;
}
