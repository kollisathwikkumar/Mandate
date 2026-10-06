export interface SafePolicyActivationState {
  readonly safeAddress: string;
  readonly guardAddress: string;
  readonly moduleAddress: string;
  readonly chainId: number;
  readonly timestampSeconds: number;
  readonly safeNonce: bigint;
  readonly safeOwners: readonly string[];
  readonly safeThreshold: bigint;
  readonly policyEpoch: bigint;
  readonly policyEnabled: boolean;
  readonly policyRevisionHash: string;
  readonly agentKeyVersion: bigint;
  readonly agentActive: boolean;
}

export interface SafePolicyActivationReader {
  readState(input: {
    readonly chainId: number;
    readonly safeAddress: string;
    readonly guardAddress: string;
    readonly moduleAddress: string;
    readonly agentAddress: string;
  }): Promise<SafePolicyActivationState>;
}
