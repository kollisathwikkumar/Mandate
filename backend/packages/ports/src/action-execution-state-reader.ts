export interface ActionExecutionState {
  readonly safeAddress: string;
  readonly guardAddress: string;
  readonly moduleAddress: string;
  readonly chainId: number;
  readonly timestampSeconds: number;
  readonly policyEpoch: bigint;
  readonly policyEnabled: boolean;
  readonly policyRevisionHash: string;
  readonly agentKeyVersion: bigint;
  readonly agentActive: boolean;
  readonly moduleNonce: bigint;
  readonly blockNumber: number;
  readonly blockHash: string;
}

export interface ActionExecutionStateReader {
  readState(input: {
    readonly chainId: number;
    readonly safeAddress: string;
    readonly guardAddress: string;
    readonly moduleAddress: string;
    readonly agentAddress: string;
  }): Promise<ActionExecutionState>;
}
