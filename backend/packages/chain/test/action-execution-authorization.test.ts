import { AbiCoder, Interface, TypedDataEncoder, Wallet, ZeroAddress, keccak256, verifyTypedData } from 'ethers';
import { describe, expect, it } from 'vitest';
import { buildActionExecutionAuthorization, encodeAuthorizedModuleExecution, parseActionExecutionAuthorization, validateSignedActionExecutionTransaction, verifyActionExecutionSignature } from '../src/action-execution-authorization.js';
import type { ActionIntent, PolicyRevision } from '../../policy/src/schema.js';
import { hashPolicyRevision } from '../../policy/src/canonical.js';

const safe = `0x${'1'.repeat(40)}`;
const guard = `0x${'2'.repeat(40)}`;
const module = `0x${'3'.repeat(40)}`;
const agent = `0x${'4'.repeat(40)}`;
const token = `0x${'5'.repeat(40)}`;
const recipient = `0x${'6'.repeat(40)}`;

const policy: PolicyRevision = {
  schemaVersion: 1, policyId: 'policy-a', revision: 1, organizationId: 'org-a', owner: safe, account: safe,
  agentId: 'agent-a', agentAddress: agent, agentKeyVersion: 2, chainId: 10143, adapter: 'evm-smart-account',
  target: token, selectors: ['0xa9059cbb'], asset: token, recipients: [recipient],
  limits: { perAction: '10000', cumulative: '50000', windowSeconds: 3600 },
  validAfter: 1_700_000_000, expiresAt: 1_900_000_000, nonceEpoch: 6,
};
const action: ActionIntent = {
  actionId: 'action-a', idempotencyKey: 'idem-a', policyId: 'policy-a', policyRevision: 1,
  policyRevisionHash: '', organizationId: 'org-a', account: safe, agentId: 'agent-a', agentKeyVersion: 2,
  chainId: 10143, target: token, selector: '0xa9059cbb', asset: token, recipient, amount: '1234', nonce: 8,
  nonceEpoch: 6, expiresAt: 1_800_000_500,
};
const state = {
  safeAddress: safe, guardAddress: guard, moduleAddress: module, chainId: 10143, timestampSeconds: 1_800_000_000,
  policyEpoch: 7n, policyEnabled: true, policyRevisionHash: '', agentKeyVersion: 2n, agentActive: true,
  moduleNonce: 9n, blockNumber: 100, blockHash: `0x${'b'.repeat(64)}`,
};

describe('exact action execution authorization', () => {
  const canonicalHash = hashPolicyRevision(policy);
  const currentAction = { ...action, policyRevisionHash: canonicalHash };
  const currentState = { ...state, policyRevisionHash: canonicalHash };

  it('builds EIP-712 authorization over the exact ERC-20 call and current on-chain nonce', () => {
    const plan = buildActionExecutionAuthorization({ action: currentAction, policy, state: currentState });
    expect(parseActionExecutionAuthorization(plan)).toEqual(plan);
    expect(plan).toMatchObject({
      actionId: 'action-a', chainId: 10143, safeAddress: safe, guardAddress: guard, moduleAddress: module,
      agentAddress: agent, policyRevisionHash: canonicalHash, policyEpoch: '7', keyVersion: 2,
      executionNonce: '9', deadline: 1_800_000_500, to: token, value: '0',
    });
    expect(plan.data).toBe(new Interface(['function transfer(address,uint256)']).encodeFunctionData('transfer', [recipient, 1234n]));
    expect(plan.signingPayload.message.dataHash).toBe(keccak256(plan.data));
    expect(plan.actionDigest).toBe(TypedDataEncoder.hash(plan.signingPayload.domain, plan.signingPayload.types, plan.signingPayload.message));
    expect(plan.actionHash).toBe(keccak256(AbiCoder.defaultAbiCoder().encode(
      ['address', 'uint256', 'uint64', 'address', 'uint64', 'address', 'uint256', 'bytes32', 'uint256', 'uint256'],
      [safe, 10143, 7, agent, 2, token, 0, keccak256(plan.data), 9, 1_800_000_500],
    )));
    const encoded = encodeAuthorizedModuleExecution(plan, `0x${'ab'.repeat(65)}`);
    expect(new Interface(['function execute(address,uint256,bytes,uint256,uint64,uint256,bytes)']).decodeFunctionData('execute', encoded))
      .toEqual([token, 0n, plan.data, 1_800_000_500n, 2n, 9n, `0x${'ab'.repeat(65)}`]);
  });

  it.each([
    ['malformed schema', (plan: ReturnType<typeof buildActionExecutionAuthorization>) => ({ ...plan, actionId: '' })],
    ['altered digest', (plan: ReturnType<typeof buildActionExecutionAuthorization>) => ({ ...plan, actionDigest: `0x${'0'.repeat(64)}` })],
    ['altered action hash', (plan: ReturnType<typeof buildActionExecutionAuthorization>) => ({ ...plan, actionHash: `0x${'0'.repeat(64)}` })],
    ['altered exact call', (plan: ReturnType<typeof buildActionExecutionAuthorization>) => ({ ...plan, value: '1' })],
    ['altered snapshot chain', (plan: ReturnType<typeof buildActionExecutionAuthorization>) => ({ ...plan, snapshotBlockHash: 'not-a-hash' })],
    ['out-of-range typed integer', (plan: ReturnType<typeof buildActionExecutionAuthorization>) => ({
      ...plan, signingPayload: { ...plan.signingPayload, message: { ...plan.signingPayload.message, policyEpoch: '18446744073709551616' } },
    })],
    ['noncanonical EIP-712 types', (plan: ReturnType<typeof buildActionExecutionAuthorization>) => {
      const types = { MandateAction: [...plan.signingPayload.types.MandateAction].reverse() };
      return {
        ...plan,
        signingPayload: { ...plan.signingPayload, types },
        actionDigest: TypedDataEncoder.hash(plan.signingPayload.domain, types, plan.signingPayload.message),
      } as unknown as ReturnType<typeof buildActionExecutionAuthorization>;
    }],
  ])('rejects a stored plan with %s', (_name, alter) => {
    const plan = buildActionExecutionAuthorization({ action: currentAction, policy, state: currentState });
    expect(() => parseActionExecutionAuthorization(alter(plan)))
      .toThrowError(expect.objectContaining({ code: 'INVALID_INPUT' }));
  });

  it('maps the native-asset policy to an exact value transfer with empty calldata', () => {
    const nativePolicy: PolicyRevision = { ...policy, target: recipient, selectors: ['0x00000000'], asset: ZeroAddress, recipients: [recipient] };
    const nativeAction: ActionIntent = { ...action, target: recipient, selector: '0x00000000', asset: ZeroAddress };
    const nativeHash = hashPolicyRevision(nativePolicy);
    const plan = buildActionExecutionAuthorization({ action: { ...nativeAction, policyRevisionHash: nativeHash }, policy: nativePolicy, state: { ...state, policyRevisionHash: nativeHash } });
    expect(plan).toMatchObject({ to: recipient, value: '1234', data: '0x' });
  });

  it.each([
    ['disabled policy', { policyEnabled: false }],
    ['wrong revision hash', { policyRevisionHash: `0x${'b'.repeat(64)}` }],
    ['wrong epoch', { policyEpoch: 8n }],
    ['inactive agent', { agentActive: false }],
    ['wrong key version', { agentKeyVersion: 3n }],
  ] as const)('rejects %s', (_name, override) => {
    expect(() => buildActionExecutionAuthorization({ action: currentAction, policy, state: { ...currentState, ...override } }))
      .toThrowError(expect.objectContaining({ code: 'CHAIN_POLICY_MISMATCH' }));
  });

  it('rejects a request that does not exactly match the typed policy scope', () => {
    expect(() => buildActionExecutionAuthorization({ action: { ...currentAction, recipient: safe }, policy, state: currentState }))
      .toThrowError(expect.objectContaining({ code: 'ACTION_POLICY_MISMATCH' }));
  });

  it('rejects an action selector omitted from the signed policy', () => {
    expect(() => buildActionExecutionAuthorization({ action: { ...currentAction, selector: '0x12345678' }, policy, state: currentState }))
      .toThrowError(expect.objectContaining({ code: 'ACTION_POLICY_MISMATCH' }));
  });

  it('rejects execution before the policy validity window begins', () => {
    const futurePolicy = { ...policy, validAfter: 1_800_000_001 };
    const futureHash = hashPolicyRevision(futurePolicy);
    expect(() => buildActionExecutionAuthorization({ action: { ...currentAction, policyRevisionHash: futureHash }, policy: futurePolicy, state: { ...currentState, policyRevisionHash: futureHash } }))
      .toThrowError(expect.objectContaining({ code: 'CHAIN_POLICY_MISMATCH' }));
  });

  it('rejects chain state for a different Safe account', () => {
    expect(() => buildActionExecutionAuthorization({ action: currentAction, policy, state: { ...currentState, safeAddress: recipient } }))
      .toThrowError(expect.objectContaining({ code: 'CHAIN_POLICY_MISMATCH' }));
  });

  it('rejects malformed intent before deriving an authorization', () => {
    expect(() => buildActionExecutionAuthorization({ action: { ...currentAction, amount: 'not-a-uint' }, policy, state: currentState }))
      .toThrowError(expect.objectContaining({ code: 'INVALID_INPUT' }));
  });

  it('rejects a policy whose native-transfer target does not equal its recipient', () => {
    const unsupportedPolicy = { ...policy, asset: ZeroAddress };
    const unsupportedHash = hashPolicyRevision(unsupportedPolicy);
    expect(() => buildActionExecutionAuthorization({
      action: { ...currentAction, asset: ZeroAddress, policyRevisionHash: unsupportedHash },
      policy: unsupportedPolicy, state: { ...currentState, policyRevisionHash: unsupportedHash },
    })).toThrowError(expect.objectContaining({ code: 'UNSUPPORTED_ACTION' }));
  });

  it('rejects an ERC-20 policy that routes calls to an asset other than the token contract', () => {
    const unsupportedPolicy = { ...policy, target: recipient };
    const unsupportedHash = hashPolicyRevision(unsupportedPolicy);
    expect(() => buildActionExecutionAuthorization({
      action: { ...currentAction, target: recipient, policyRevisionHash: unsupportedHash },
      policy: unsupportedPolicy, state: { ...currentState, policyRevisionHash: unsupportedHash },
    })).toThrowError(expect.objectContaining({ code: 'UNSUPPORTED_ACTION' }));
  });

  it('uses the policy expiry when it is earlier than the action expiry', () => {
    const expires = { ...policy, expiresAt: 1_800_000_400 };
    const expiresHash = hashPolicyRevision(expires);
    const plan = buildActionExecutionAuthorization({
      action: { ...currentAction, policyRevisionHash: expiresHash, expiresAt: 1_800_000_500 },
      policy: expires,
      state: { ...currentState, policyRevisionHash: expiresHash },
    });
    expect(plan.deadline).toBe(expires.expiresAt);
  });

  it('rejects an expired policy even when the action has a later expiry', () => {
    const expiredPolicy = { ...policy, expiresAt: 1_800_000_000 };
    const expiredHash = hashPolicyRevision(expiredPolicy);
    expect(() => buildActionExecutionAuthorization({
      action: { ...currentAction, policyRevisionHash: expiredHash, expiresAt: 1_800_000_500 },
      policy: expiredPolicy,
      state: { ...currentState, policyRevisionHash: expiredHash },
    })).toThrowError(expect.objectContaining({ code: 'ACTION_EXPIRED' }));
  });

  it('accepts only a 65-byte ECDSA signature when encoding the module transaction', () => {
    const plan = buildActionExecutionAuthorization({ action: currentAction, policy, state: currentState });
    expect(() => encodeAuthorizedModuleExecution(plan, '0x1234'))
      .toThrowError(expect.objectContaining({ code: 'INVALID_INPUT' }));
  });

  it('round-trips an agent EIP-712 signature against the derived exact-action payload', async () => {
    const signer = new Wallet(`0x${'1'.repeat(64)}`);
    const signerPolicy = { ...policy, agentAddress: signer.address.toLowerCase() };
    const signerHash = hashPolicyRevision(signerPolicy);
    const plan = buildActionExecutionAuthorization({
      action: { ...currentAction, policyRevisionHash: signerHash },
      policy: signerPolicy,
      state: { ...currentState, policyRevisionHash: signerHash },
    });
    const signature = await signer.signTypedData(plan.signingPayload.domain, plan.signingPayload.types, plan.signingPayload.message);
    expect(verifyTypedData(plan.signingPayload.domain, plan.signingPayload.types, plan.signingPayload.message, signature))
      .toBe(signer.address);
    expect(verifyActionExecutionSignature(plan, signature)).toBe(encodeAuthorizedModuleExecution(plan, signature));
    expect(verifyActionExecutionSignature(plan, signature)).toMatch(/^0x[0-9a-f]+$/i);
  });

  it('rejects a valid EIP-712 signature from a different agent', async () => {
    const signer = new Wallet(`0x${'1'.repeat(64)}`);
    const wrongSigner = new Wallet(`0x${'2'.repeat(64)}`);
    const signerPolicy = { ...policy, agentAddress: signer.address.toLowerCase() };
    const signerHash = hashPolicyRevision(signerPolicy);
    const plan = buildActionExecutionAuthorization({
      action: { ...currentAction, policyRevisionHash: signerHash }, policy: signerPolicy,
      state: { ...currentState, policyRevisionHash: signerHash },
    });
    const signature = await wrongSigner.signTypedData(plan.signingPayload.domain, plan.signingPayload.types, plan.signingPayload.message);
    expect(() => verifyActionExecutionSignature(plan, signature))
      .toThrowError(expect.objectContaining({ code: 'INVALID_SIGNATURE' }));
  });

  it('accepts only an agent-signed EVM transaction to the exact authorized module call', async () => {
    const signer = new Wallet(`0x${'1'.repeat(64)}`);
    const signerPolicy = { ...policy, agentAddress: signer.address.toLowerCase() };
    const signerHash = hashPolicyRevision(signerPolicy);
    const plan = buildActionExecutionAuthorization({
      action: { ...currentAction, policyRevisionHash: signerHash }, policy: signerPolicy,
      state: { ...currentState, policyRevisionHash: signerHash },
    });
    const signature = await signer.signTypedData(plan.signingPayload.domain, plan.signingPayload.types, plan.signingPayload.message);
    const data = verifyActionExecutionSignature(plan, signature);
    const rawTransaction = await signer.signTransaction({ chainId: plan.chainId, nonce: 0, gasLimit: 150_000, gasPrice: 1_000_000_000n, to: module, value: 0, data });
    expect(validateSignedActionExecutionTransaction(plan, signature, rawTransaction)).toMatchObject({
      transactionHash: keccak256(rawTransaction), from: signer.address.toLowerCase(), to: module,
    });
  });

  it('rejects a correctly signed transaction that changes the module call', async () => {
    const signer = new Wallet(`0x${'1'.repeat(64)}`);
    const signerPolicy = { ...policy, agentAddress: signer.address.toLowerCase() };
    const signerHash = hashPolicyRevision(signerPolicy);
    const plan = buildActionExecutionAuthorization({
      action: { ...currentAction, policyRevisionHash: signerHash }, policy: signerPolicy,
      state: { ...currentState, policyRevisionHash: signerHash },
    });
    const signature = await signer.signTypedData(plan.signingPayload.domain, plan.signingPayload.types, plan.signingPayload.message);
    const rawTransaction = await signer.signTransaction({ chainId: plan.chainId, nonce: 0, gasLimit: 150_000, gasPrice: 1_000_000_000n, to: recipient, value: 0, data: '0x' });
    expect(() => validateSignedActionExecutionTransaction(plan, signature, rawTransaction))
      .toThrowError(expect.objectContaining({ code: 'INVALID_TRANSACTION' }));
  });

  it.each(['malformed raw transaction', 'malformed EVM serialization', 'wrong sender', 'wrong chain', 'nonzero outer value'] as const)(
    'rejects a signed transaction with %s', async (failure) => {
      const signer = new Wallet(`0x${'1'.repeat(64)}`);
      const otherSigner = new Wallet(`0x${'2'.repeat(64)}`);
      const signerPolicy = { ...policy, agentAddress: signer.address.toLowerCase() };
      const signerHash = hashPolicyRevision(signerPolicy);
      const plan = buildActionExecutionAuthorization({
        action: { ...currentAction, policyRevisionHash: signerHash }, policy: signerPolicy,
        state: { ...currentState, policyRevisionHash: signerHash },
      });
      const signature = await signer.signTypedData(plan.signingPayload.domain, plan.signingPayload.types, plan.signingPayload.message);
      const callData = verifyActionExecutionSignature(plan, signature);
      const raw = failure === 'malformed raw transaction' ? 'nope' : failure === 'malformed EVM serialization' ? '0x02' : await (failure === 'wrong sender' ? otherSigner : signer).signTransaction({
        chainId: failure === 'wrong chain' ? 1 : plan.chainId,
        nonce: 0, gasLimit: 150_000, gasPrice: 1_000_000_000n, to: module,
        value: failure === 'nonzero outer value' ? 1 : 0, data: callData,
      });
      expect(() => validateSignedActionExecutionTransaction(plan, signature, raw))
        .toThrowError(expect.objectContaining({ code: 'INVALID_TRANSACTION' }));
    },
  );

  it.each([
    ['wrong length', '0x1234'],
    ['zero r scalar', `0x${'0'.repeat(64)}${'1'.repeat(64)}1b`],
    ['high-s malleable scalar', `0x${'1'.repeat(64)}${'f'.repeat(64)}1b`],
    ['invalid recovery id', `0x${'1'.repeat(64)}${'1'.repeat(64)}00`],
    ['unrecoverable curve point', `0x${'f'.repeat(64)}${'1'.repeat(64)}1b`],
  ])('rejects a signature with %s', (_name, signature) => {
    const signer = new Wallet(`0x${'1'.repeat(64)}`);
    const signerPolicy = { ...policy, agentAddress: signer.address.toLowerCase() };
    const signerHash = hashPolicyRevision(signerPolicy);
    const plan = buildActionExecutionAuthorization({
      action: { ...currentAction, policyRevisionHash: signerHash }, policy: signerPolicy,
      state: { ...currentState, policyRevisionHash: signerHash },
    });
    expect(() => verifyActionExecutionSignature(plan, signature))
      .toThrowError(expect.objectContaining({ code: 'INVALID_SIGNATURE' }));
  });
});
