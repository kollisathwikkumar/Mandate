import { Interface, TypedDataEncoder, ZeroAddress } from 'ethers';
import { compileEvmSafePolicy } from './evm-safe-policy-compiler.js';
import type { PolicyRevision } from '../../policy/src/schema.js';
import type { SafePolicyActivationState } from '../../ports/src/safe-policy-activation-reader.js';

export const safeTransactionTypes = { SafeTx: [
  { name: 'to', type: 'address' }, { name: 'value', type: 'uint256' }, { name: 'data', type: 'bytes' },
  { name: 'operation', type: 'uint8' }, { name: 'safeTxGas', type: 'uint256' }, { name: 'baseGas', type: 'uint256' },
  { name: 'gasPrice', type: 'uint256' }, { name: 'gasToken', type: 'address' },
  { name: 'refundReceiver', type: 'address' }, { name: 'nonce', type: 'uint256' },
] };

const moduleInterface = new Interface(['function setAgent(address agent,uint64 keyVersion,bool active)']);

export type SafePolicyActivationErrorCode = 'STALE_POLICY_EPOCH' | 'AGENT_KEY_VERSION_AHEAD' | 'POLICY_NOT_ACTIVE' | 'POLICY_EPOCH_EXHAUSTED';

export class SafePolicyActivationError extends Error {
  public constructor(public readonly code: SafePolicyActivationErrorCode) {
    super(code);
    this.name = 'SafePolicyActivationError';
  }
}

export interface SafeTransactionSigningPayload {
  readonly domain: { readonly chainId: number; readonly verifyingContract: string };
  readonly types: typeof safeTransactionTypes;
  readonly primaryType: 'SafeTx';
  readonly message: {
    readonly to: string;
    readonly value: string;
    readonly data: string;
    readonly operation: number;
    readonly safeTxGas: string;
    readonly baseGas: string;
    readonly gasPrice: string;
    readonly gasToken: string;
    readonly refundReceiver: string;
    readonly nonce: string;
  };
}

export interface SafePolicyActivationCall {
  readonly purpose: 'REGISTER_AGENT' | 'CONFIGURE_POLICY';
  readonly to: string;
  readonly data: string;
  readonly nonce: string;
  readonly safeTxHash: string;
  readonly signingPayload: SafeTransactionSigningPayload;
}

export interface SafePolicyActivationPlan {
  readonly chainId: number;
  readonly safeAddress: string;
  readonly guardAddress: string;
  readonly moduleAddress: string;
  readonly agentAddress: string;
  readonly agentKeyVersion: number;
  readonly ownerAddresses: readonly string[];
  readonly ownerThreshold: number;
  readonly revisionHash: string;
  readonly expectedPolicyEpoch: string;
  readonly resultingPolicyEpoch: string;
  readonly compiledConfiguration: {
    readonly revisionHash: string;
    readonly nextEpoch: string;
    readonly policyValidUntil: string;
    readonly windowDuration: number;
    readonly actionCountLimit: number;
    readonly assets: readonly string[];
    readonly perActionLimits: readonly string[];
    readonly perWindowLimits: readonly string[];
    readonly approvalThresholds: readonly string[];
    readonly approvalRequired: readonly boolean[];
    readonly recipients: readonly string[];
  };
  readonly calls: readonly SafePolicyActivationCall[];
  readonly status: 'AWAITING_SAFE_OWNER_SIGNATURES';
}

/** Creates exact owner-signed Safe calls; planning never submits a transaction or activates a DB grant. */
export function buildSafePolicyActivationPlan(revision: PolicyRevision, state: SafePolicyActivationState): SafePolicyActivationPlan {
  if (BigInt(revision.chainId) !== BigInt(state.chainId)
    || revision.account.toLowerCase() !== state.safeAddress.toLowerCase()) {
    throw new RangeError('Policy account does not match the verified Safe');
  }
  if (state.safeOwners.length === 0 || state.safeThreshold < 1n || state.safeThreshold > BigInt(state.safeOwners.length)) {
    throw new RangeError('Safe owner threshold is invalid');
  }
  if (BigInt(revision.nonceEpoch) !== state.policyEpoch) throw new SafePolicyActivationError('STALE_POLICY_EPOCH');
  if (state.agentKeyVersion > BigInt(revision.agentKeyVersion)) throw new SafePolicyActivationError('AGENT_KEY_VERSION_AHEAD');

  const compiled = compileEvmSafePolicy(revision, state.timestampSeconds);
  const calls: Omit<SafePolicyActivationCall, 'nonce' | 'safeTxHash' | 'signingPayload'>[] = [];
  if (!state.agentActive || state.agentKeyVersion !== BigInt(revision.agentKeyVersion)) {
    calls.push({
      purpose: 'REGISTER_AGENT',
      to: state.moduleAddress.toLowerCase(),
      data: moduleInterface.encodeFunctionData('setAgent', [revision.agentAddress, revision.agentKeyVersion, true]),
    });
  }
  calls.push({
    purpose: 'CONFIGURE_POLICY',
    to: state.guardAddress.toLowerCase(),
    data: compiled.configurePolicyCalldata,
  });

  const signedCalls = calls.map((call, index): SafePolicyActivationCall => {
    const nonce = state.safeNonce + BigInt(index);
    const message = {
      to: call.to,
      value: '0',
      data: call.data,
      operation: 0,
      safeTxGas: '0',
      baseGas: '0',
      gasPrice: '0',
      gasToken: ZeroAddress,
      refundReceiver: ZeroAddress,
      nonce: nonce.toString(),
    };
    const domain = { chainId: state.chainId, verifyingContract: state.safeAddress.toLowerCase() };
    const safeTxHash = TypedDataEncoder.hash(domain, safeTransactionTypes, message);
    return { ...call, nonce: nonce.toString(), safeTxHash, signingPayload: { domain, types: safeTransactionTypes, primaryType: 'SafeTx', message } };
  });

  return {
    chainId: state.chainId,
    safeAddress: state.safeAddress.toLowerCase(),
    guardAddress: state.guardAddress.toLowerCase(),
    moduleAddress: state.moduleAddress.toLowerCase(),
    agentAddress: revision.agentAddress,
    agentKeyVersion: revision.agentKeyVersion,
    ownerAddresses: state.safeOwners.map((owner) => owner.toLowerCase()),
    ownerThreshold: Number(state.safeThreshold),
    revisionHash: compiled.revisionHash,
    expectedPolicyEpoch: state.policyEpoch.toString(),
    resultingPolicyEpoch: compiled.configuration.nextEpoch.toString(),
    compiledConfiguration: {
      revisionHash: compiled.configuration.revisionHash,
      nextEpoch: compiled.configuration.nextEpoch.toString(),
      policyValidUntil: compiled.configuration.policyValidUntil.toString(),
      windowDuration: compiled.configuration.windowDuration,
      actionCountLimit: compiled.configuration.actionCountLimit,
      assets: compiled.configuration.assets,
      perActionLimits: compiled.configuration.perActionLimits.map(String),
      perWindowLimits: compiled.configuration.perWindowLimits.map(String),
      approvalThresholds: compiled.configuration.approvalThresholds.map(String),
      approvalRequired: compiled.configuration.approvalRequired,
      recipients: compiled.configuration.recipients,
    },
    calls: signedCalls,
    status: 'AWAITING_SAFE_OWNER_SIGNATURES',
  };
}
