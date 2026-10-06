export class ActionTransactionSubmissionError extends Error {
  public constructor(public readonly code: 'UNSUPPORTED_CHAIN' | 'RPC_UNAVAILABLE' | 'CHAIN_ID_MISMATCH' | 'INVALID_TRANSACTION') {
    super(code);
    this.name = 'ActionTransactionSubmissionError';
  }
}

export interface ActionTransactionSubmissionResult {
  readonly transactionHash: string;
}

export interface ActionTransactionSubmitter {
  submitRawTransaction(input: { readonly chainId: number; readonly rawTransaction: string }): Promise<ActionTransactionSubmissionResult>;
}
