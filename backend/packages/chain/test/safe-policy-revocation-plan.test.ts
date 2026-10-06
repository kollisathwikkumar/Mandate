import { Interface, TypedDataEncoder } from 'ethers';
import { describe, expect, it } from 'vitest';
import { SafePolicyActivationError } from '../src/safe-policy-activation-plan.js';
import { buildSafePolicyRevocationPlan } from '../src/safe-policy-revocation-plan.js';

const state = {
  safeAddress: `0x${'1'.repeat(40)}`,
  guardAddress: `0x${'2'.repeat(40)}`,
  moduleAddress: `0x${'3'.repeat(40)}`,
  chainId: 10143,
  timestampSeconds: 1_800_000_000,
  safeNonce: 88n,
  safeOwners: [`0x${'4'.repeat(40)}`, `0x${'5'.repeat(40)}`],
  safeThreshold: 2n,
  policyEpoch: 6n,
  policyEnabled: true,
  policyRevisionHash: `0x${'a'.repeat(64)}`,
  agentKeyVersion: 4n,
  agentActive: true,
} as const;
const agentAddress = `0x${'6'.repeat(40)}`;

describe('Safe policy revocation planner', () => {
  it('builds a single exact owner-threshold SafeTx that increments the active policy epoch', () => {
    const plan = buildSafePolicyRevocationPlan(state, agentAddress);
    const safeInterface = new Interface(['function revokePolicy()']);
    const call = plan.call;
    expect(plan).toMatchObject({
      chainId: state.chainId,
      safeAddress: state.safeAddress,
      guardAddress: state.guardAddress,
      revisionHash: state.policyRevisionHash,
      agentAddress,
      expectedPolicyEpoch: '6',
      resultingPolicyEpoch: '7',
      ownerAddresses: state.safeOwners,
      ownerThreshold: 2,
      status: 'AWAITING_SAFE_OWNER_SIGNATURES',
    });
    expect(call.to).toBe(state.guardAddress);
    expect(call.nonce).toBe('88');
    expect(safeInterface.decodeFunctionData('revokePolicy', call.data).length).toBe(0);
    expect(call.signingPayload.message.data).toBe(call.data);
    expect(call.safeTxHash).toBe(TypedDataEncoder.hash(call.signingPayload.domain, call.signingPayload.types, call.signingPayload.message));
  });

  it('rejects inactive policy state and epoch overflow instead of planning revocation', () => {
    expect(() => buildSafePolicyRevocationPlan({ ...state, policyEnabled: false }, agentAddress))
      .toThrowError(expect.objectContaining({ code: 'POLICY_NOT_ACTIVE' } satisfies Partial<SafePolicyActivationError>));
    expect(() => buildSafePolicyRevocationPlan({ ...state, policyEpoch: (1n << 64n) - 1n }, agentAddress))
      .toThrowError(expect.objectContaining({ code: 'POLICY_EPOCH_EXHAUSTED' } satisfies Partial<SafePolicyActivationError>));
  });

  it.each([
    ['malformed revision hash', { policyRevisionHash: 'not-a-hash' }],
    ['zero revision hash', { policyRevisionHash: `0x${'0'.repeat(64)}` }],
  ] as const)('rejects a %s', (_name, overrides) => {
    expect(() => buildSafePolicyRevocationPlan({ ...state, ...overrides }, agentAddress))
      .toThrowError(expect.objectContaining({ code: 'POLICY_NOT_ACTIVE' } satisfies Partial<SafePolicyActivationError>));
  });

  it.each([
    ['an empty owner set', { safeOwners: [] as readonly string[] }],
    ['a zero threshold', { safeThreshold: 0n }],
    ['a threshold above the owner count', { safeThreshold: 3n }],
  ] as const)('rejects %s', (_name, overrides) => {
    expect(() => buildSafePolicyRevocationPlan({ ...state, ...overrides }, agentAddress)).toThrow('Safe owner threshold is invalid');
  });
});
