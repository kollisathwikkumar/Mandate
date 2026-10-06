export interface ApprovalInput {
  readonly organizationId: string;
  readonly actionId: string;
  readonly approverSubject: string;
  readonly idempotencyKey: string;
  readonly actionHash: string;
  readonly outcome: 'APPROVED' | 'DENIED';
}

export interface ApprovalResult {
  readonly actionId: string;
  readonly state: 'RESERVED' | 'DENIED' | 'EXPIRED';
  readonly verdict: 'ALLOW' | 'BLOCK';
  readonly reason: 'HUMAN_APPROVED' | 'APPROVAL_DENIED' | 'ACTION_EXPIRED';
  readonly actionHash: string;
}

export type ApprovalOutcome =
  | { readonly kind: 'CREATED'; readonly approval: ApprovalResult }
  | { readonly kind: 'REPLAY'; readonly approval: ApprovalResult };

export interface ApprovalRepository {
  approveAction(input: ApprovalInput): Promise<ApprovalOutcome>;
}
