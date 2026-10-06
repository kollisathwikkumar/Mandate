import { Interface, TypedDataEncoder, ZeroAddress } from 'ethers';
import type { SafePolicyActivationState } from '../../ports/src/safe-policy-activation-reader.js';
import { SafePolicyActivationError, safeTransactionTypes, type SafeTransactionSigningPayload } from './safe-policy-activation-plan.js';

const guardInterface = new Interface(['function revokePolicy()']);
const UINT64_MAX = (1n << 64n) - 1n;

export interface SafePolicyRevocationPlan {
  readonly chainId: number;
  readonly safeAddress: string;
  readonly guardAddress: string;
  readonly moduleAddress: string;
  readonly agentAddress: string;
  readonly revisionHash: string;
  readonly expectedPolicyEpoch: string;
  readonly resultingPolicyEpoch: string;
  readonly ownerAddresses: readonly string[];
  readonly ownerThreshold: number;
  readonly call: {
    readonly to: string;
    readonly data: string;
    readonly nonce: string;
    readonly safeTxHash: string;
    readonly signingPayload: SafeTransactionSigningPayload;
  };
  readonly status: 'AWAITING_SAFE_OWNER_SIGNATURES';
}

/** Produces the one owner-Safe call that disables the on-chain policy and advances its replay epoch. */
export function buildSafePolicyRevocationPlan(state: SafePolicyActivationState, agentAddress: string): SafePolicyRevocationPlan {
  if (!state.policyEnabled || !/^0x[0-9a-f]{64}$/.test(state.policyRevisionHash)
    || state.policyRevisionHash === `0x${'0'.repeat(64)}`) {
    throw new SafePolicyActivationError('POLICY_NOT_ACTIVE');
  }
  if (state.policyEpoch >= UINT64_MAX) throw new SafePolicyActivationError('POLICY_EPOCH_EXHAUSTED');
  if (state.safeOwners.length === 0 || state.safeThreshold < 1n || state.safeThreshold > BigInt(state.safeOwners.length)) {
    throw new RangeError('Safe owner threshold is invalid');
  }
  const to = state.guardAddress.toLowerCase();
  const data = guardInterface.encodeFunctionData('revokePolicy');
  const message = {
    to,
    value: '0',
    data,
    operation: 0,
    safeTxGas: '0',
    baseGas: '0',
    gasPrice: '0',
    gasToken: ZeroAddress,
    refundReceiver: ZeroAddress,
    nonce: state.safeNonce.toString(),
  };
  const domain = { chainId: state.chainId, verifyingContract: state.safeAddress.toLowerCase() };
  const safeTxHash = TypedDataEncoder.hash(domain, safeTransactionTypes, message);
  return {
    chainId: state.chainId,
    safeAddress: state.safeAddress.toLowerCase(),
    guardAddress: state.guardAddress.toLowerCase(),
    moduleAddress: state.moduleAddress.toLowerCase(),
    agentAddress: agentAddress.toLowerCase(),
    revisionHash: state.policyRevisionHash.toLowerCase(),
    expectedPolicyEpoch: state.policyEpoch.toString(),
    resultingPolicyEpoch: (state.policyEpoch + 1n).toString(),
    ownerAddresses: state.safeOwners.map((owner) => owner.toLowerCase()),
    ownerThreshold: Number(state.safeThreshold),
    call: { to, data, nonce: state.safeNonce.toString(), safeTxHash, signingPayload: { domain, types: safeTransactionTypes, primaryType: 'SafeTx', message } },
    status: 'AWAITING_SAFE_OWNER_SIGNATURES',
  };
}
