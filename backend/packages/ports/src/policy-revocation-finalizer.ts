import type { SafePolicyRevocationPlan } from '../../chain/src/safe-policy-revocation-plan.js';

export type PolicyRevocationFinalizationErrorCode =
  | 'UNSUPPORTED_CHAIN'
  | 'RPC_UNAVAILABLE'
  | 'INVALID_CONFIRMATION_CONFIGURATION'
  | 'RECEIPT_NOT_FOUND'
  | 'TRANSACTION_FAILED'
  | 'SAFE_EXECUTION_NOT_FOUND'
  | 'NOT_FINALIZED'
  | 'POLICY_STATE_MISMATCH';

export class PolicyRevocationFinalizationError extends Error {
  public constructor(public readonly code: PolicyRevocationFinalizationErrorCode) {
    super(code);
    this.name = 'PolicyRevocationFinalizationError';
  }
}

export interface FinalizedPolicyRevocationReceipt {
  readonly safeTxHash: string;
  readonly transactionHash: string;
  readonly blockNumber: string;
  readonly blockHash: string;
  readonly transactionIndex: number;
  readonly confirmations: number;
  readonly status: 'FINAL';
}

export interface FinalizedPolicyRevocation {
  readonly planId: string;
  readonly revisionHash: string;
  readonly previousPolicyEpoch: string;
  readonly policyEpoch: string;
  readonly finalizedBlockNumber: string;
  readonly receipt: FinalizedPolicyRevocationReceipt;
}

export interface PolicyRevocationFinalizer {
  verifyFinalizedRevocation(input: {
    readonly planId: string;
    readonly plan: SafePolicyRevocationPlan;
    readonly transactionHash: string;
    readonly minimumConfirmations: number;
  }): Promise<FinalizedPolicyRevocation>;
}
