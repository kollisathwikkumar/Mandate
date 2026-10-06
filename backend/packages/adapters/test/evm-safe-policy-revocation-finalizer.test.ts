import { describe, expect, it } from 'vitest';
import { EvmSafePolicyRevocationFinalizer } from '../src/chain/evm-safe-policy-revocation-finalizer.js';
import { PolicyRevocationFinalizationError } from '../../ports/src/policy-revocation-finalizer.js';
import { buildSafePolicyRevocationPlan } from '../../chain/src/safe-policy-revocation-plan.js';

const plan = buildSafePolicyRevocationPlan({
  safeAddress: `0x${'1'.repeat(40)}`, guardAddress: `0x${'2'.repeat(40)}`, moduleAddress: `0x${'3'.repeat(40)}`,
  chainId: 10143, timestampSeconds: 1_800_000_000, safeNonce: 4n, safeOwners: [`0x${'4'.repeat(40)}`], safeThreshold: 1n,
  policyEpoch: 1n, policyEnabled: true, policyRevisionHash: `0x${'a'.repeat(64)}`, agentKeyVersion: 1n, agentActive: true,
}, `0x${'5'.repeat(40)}`);
const txHash = `0x${'6'.repeat(64)}`;

describe('EVM Safe policy revocation finalizer configuration', () => {
  it('rejects malformed transaction hashes before RPC work', async () => {
    const finalizer = new EvmSafePolicyRevocationFinalizer({ 10143: 'http://127.0.0.1:8545' }, { 10143: 1 });
    await expect(finalizer.verifyFinalizedRevocation({ planId: 'plan', plan, transactionHash: 'bad', minimumConfirmations: 1 }))
      .rejects.toMatchObject({ code: 'SAFE_EXECUTION_NOT_FOUND' } satisfies Partial<PolicyRevocationFinalizationError>);
  });

  it('requires a configured positive finality depth for the plan chain', async () => {
    const finalizer = new EvmSafePolicyRevocationFinalizer({ 10143: 'http://127.0.0.1:8545' }, { 10143: 2 });
    await expect(finalizer.verifyFinalizedRevocation({ planId: 'plan', plan, transactionHash: txHash, minimumConfirmations: 1 }))
      .rejects.toMatchObject({ code: 'INVALID_CONFIRMATION_CONFIGURATION' } satisfies Partial<PolicyRevocationFinalizationError>);
    await expect(finalizer.verifyFinalizedRevocation({ planId: 'plan', plan, transactionHash: txHash, minimumConfirmations: 0 }))
      .rejects.toMatchObject({ code: 'INVALID_CONFIRMATION_CONFIGURATION' } satisfies Partial<PolicyRevocationFinalizationError>);
  });

  it('fails closed for unsupported chains and non-TLS remote RPC configuration', async () => {
    const unsupported = new EvmSafePolicyRevocationFinalizer({}, { 10143: 1 });
    await expect(unsupported.verifyFinalizedRevocation({ planId: 'plan', plan, transactionHash: txHash, minimumConfirmations: 1 }))
      .rejects.toMatchObject({ code: 'UNSUPPORTED_CHAIN' } satisfies Partial<PolicyRevocationFinalizationError>);
    const insecure = new EvmSafePolicyRevocationFinalizer({ 10143: 'http://rpc.example.invalid' }, { 10143: 1 });
    await expect(insecure.verifyFinalizedRevocation({ planId: 'plan', plan, transactionHash: txHash, minimumConfirmations: 1 }))
      .rejects.toMatchObject({ code: 'RPC_UNAVAILABLE' } satisfies Partial<PolicyRevocationFinalizationError>);
  });
});
