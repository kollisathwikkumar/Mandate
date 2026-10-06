import { Interface } from 'ethers';
import { describe, expect, it } from 'vitest';
import { hashPolicyRevision } from '../../policy/src/canonical.js';
import { EvmPolicyCompileError, compileEvmSafePolicy } from '../src/evm-safe-policy-compiler.js';
import { SafePolicyActivationError, buildSafePolicyActivationPlan } from '../src/safe-policy-activation-plan.js';

const account = `0x${'1'.repeat(40)}`;
const token = `0x${'2'.repeat(40)}`;
const recipient = `0x${'3'.repeat(40)}`;

function policy(overrides: Record<string, unknown> = {}): ReturnType<typeof basePolicy> {
  return { ...basePolicy(), ...overrides } as ReturnType<typeof basePolicy>;
}

function basePolicy() {
  return {
    schemaVersion: 1 as const,
    policyId: 'treasury-policy',
    revision: 1,
    organizationId: 'org-1',
    owner: account,
    account,
    agentId: 'agent-1',
    agentAddress: `0x${'4'.repeat(40)}`,
    agentKeyVersion: 1,
    chainId: 10143,
    adapter: 'evm-smart-account' as const,
    target: token,
    selectors: ['0xa9059cbb'],
    asset: token,
    recipients: [recipient],
    limits: { perAction: '100', cumulative: '1000', windowSeconds: 60, approvalThreshold: '80', maxActions: 5 },
    validAfter: 100,
    expiresAt: 200,
    nonceEpoch: 0,
  };
}

describe('EVM Safe policy compiler', () => {
  it('compiles canonical ERC-20 policy fields into the contract ABI and exact revision hash', () => {
    const revision = policy();
    const compiled = compileEvmSafePolicy(revision, 100);
    expect(compiled.revisionHash).toBe(hashPolicyRevision(revision));
    expect(compiled.configuration).toEqual({
      revisionHash: hashPolicyRevision(revision), nextEpoch: 1n, policyValidUntil: 200n,
      windowDuration: 60, actionCountLimit: 5, assets: [token], perActionLimits: [100n],
      perWindowLimits: [1000n], approvalThresholds: [80n], approvalRequired: [true], recipients: [recipient],
    });
    const contractInterface = new Interface([
      'function configurePolicy((bytes32 revisionHash,uint64 nextEpoch,uint64 policyValidUntil,uint32 windowDuration,uint32 actionCountLimit,address[] assets,uint256[] perActionLimits,uint256[] perWindowLimits,uint256[] approvalThresholds,bool[] approvalRequired,address[] recipients) config)',
    ]);
    const decoded = contractInterface.decodeFunctionData('configurePolicy', compiled.configurePolicyCalldata);
    expect(decoded[0].revisionHash).toBe(hashPolicyRevision(revision));
    expect(decoded[0].assets).toEqual([token]);
    expect(decoded[0].perActionLimits).toEqual([100n]);
  });

  it('compiles native transfers only when the fixed target is allowlisted and marked with the empty-data selector', () => {
    const compiled = compileEvmSafePolicy(policy({
      target: recipient,
      asset: `0x${'0'.repeat(40)}`,
      selectors: ['0x00000000'],
      limits: { perAction: '1', cumulative: '10', windowSeconds: 30, maxActions: 3 },
    }), 100);
    expect(compiled.configuration.assets).toEqual([`0x${'0'.repeat(40)}`]);
    expect(compiled.configuration.approvalRequired).toEqual([false]);
    expect(compiled.configuration.approvalThresholds).toEqual([0n]);
  });

  it.each([
    ['future activation', { validAfter: 101 }, 100, 'POLICY_NOT_YET_VALID'],
    ['expired policy', { validAfter: 0, expiresAt: 99 }, 100, 'POLICY_EXPIRED'],
    ['unbound token target', { target: account }, 100, 'UNSUPPORTED_TARGET_OR_SELECTOR'],
    ['unsupported selector', { selectors: ['0x095ea7b3'] }, 100, 'UNSUPPORTED_TARGET_OR_SELECTOR'],
    ['unrepresentable window', { limits: { perAction: '1', cumulative: '2', windowSeconds: 0x1_0000_0000 } }, 100, 'UNSUPPORTED_LIMIT'],
    ['window lower than action cap', { limits: { perAction: '5', cumulative: '4', windowSeconds: 60 } }, 100, 'UNSUPPORTED_LIMIT'],
  ] as const)('denies %s rather than emitting a weaker on-chain rule', (_name, overrides, now, code) => {
    expect(() => compileEvmSafePolicy(policy(overrides), now)).toThrowError(expect.objectContaining({ code } satisfies Partial<EvmPolicyCompileError>));
  });

  it('exposes stable typed compiler errors', () => {
    try {
      compileEvmSafePolicy(policy({ validAfter: 101 }), 100);
      throw new Error('expected compiler failure');
    } catch (error: unknown) {
      expect(error).toBeInstanceOf(EvmPolicyCompileError);
      expect(error).toMatchObject({ code: 'POLICY_NOT_YET_VALID' });
    }
  });
});

describe('Safe policy activation transaction planner', () => {
  const state = {
    safeAddress: account,
    guardAddress: `0x${'5'.repeat(40)}`,
    moduleAddress: `0x${'6'.repeat(40)}`,
    chainId: 10143,
    timestampSeconds: 100,
    safeNonce: 21n,
    safeOwners: [`0x${'7'.repeat(40)}`],
    safeThreshold: 1n,
    policyEpoch: 0n,
    policyEnabled: false,
    policyRevisionHash: `0x${'0'.repeat(64)}`,
    agentKeyVersion: 0n,
    agentActive: false,
  } as const;

  it('returns sequential nonce-bound owner SafeTx payloads and registers a missing agent first', () => {
    const plan = buildSafePolicyActivationPlan(policy(), state);
    expect(plan.ownerThreshold).toBe(1);
    expect(plan.ownerAddresses).toEqual(state.safeOwners);
    expect(plan.calls.map(({ purpose, nonce }) => [purpose, nonce])).toEqual([
      ['REGISTER_AGENT', '21'], ['CONFIGURE_POLICY', '22'],
    ]);
    expect(plan.calls[0]?.signingPayload.message.to).toBe(state.moduleAddress);
    expect(plan.calls[1]?.signingPayload.message.to).toBe(state.guardAddress);
    expect(plan.status).toBe('AWAITING_SAFE_OWNER_SIGNATURES');
  });

  it('skips agent registration when the current on-chain key is already active and matches', () => {
    const plan = buildSafePolicyActivationPlan(policy(), { ...state, agentKeyVersion: 1n, agentActive: true });
    expect(plan.calls.map(({ purpose }) => purpose)).toEqual(['CONFIGURE_POLICY']);
    expect(plan.calls[0]?.nonce).toBe('21');
  });

  it('rejects a stale policy epoch and a higher on-chain agent key version', () => {
    expect(() => buildSafePolicyActivationPlan(policy(), { ...state, policyEpoch: 1n }))
      .toThrowError(expect.objectContaining({ code: 'STALE_POLICY_EPOCH' } satisfies Partial<SafePolicyActivationError>));
    expect(() => buildSafePolicyActivationPlan(policy(), { ...state, agentKeyVersion: 2n }))
      .toThrowError(expect.objectContaining({ code: 'AGENT_KEY_VERSION_AHEAD' } satisfies Partial<SafePolicyActivationError>));
  });
});
