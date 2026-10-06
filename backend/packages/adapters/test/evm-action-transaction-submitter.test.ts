import { Wallet } from 'ethers';
import { describe, expect, it } from 'vitest';
import { EvmActionTransactionSubmitter } from '../src/chain/evm-action-transaction-submitter.js';

const wallet = new Wallet(`0x${'1'.repeat(64)}`);
const rawTransaction = (chainId = 10143) => wallet.signTransaction({
  chainId, nonce: 0, gasLimit: 21_000, gasPrice: 1_000_000_000n,
  to: `0x${'2'.repeat(40)}`, value: 1n,
});

describe('EVM action transaction submitter', () => {
  it('fails closed for unconfigured chains', async () => {
    await expect(new EvmActionTransactionSubmitter({}).submitRawTransaction({ chainId: 10143, rawTransaction: '0x01' }))
      .rejects.toMatchObject({ code: 'INVALID_TRANSACTION' });
    await expect(new EvmActionTransactionSubmitter({}).submitRawTransaction({ chainId: 1, rawTransaction: await rawTransaction(1) }))
      .rejects.toMatchObject({ code: 'UNSUPPORTED_CHAIN' });
  });

  it.each(['http://rpc.example.test', 'https://user:password@rpc.example.test'])('rejects unsafe RPC URL %s', async (url) => {
    await expect(new EvmActionTransactionSubmitter({ 10143: url }).submitRawTransaction({
      chainId: 10143, rawTransaction: await rawTransaction(),
    })).rejects.toMatchObject({ code: 'RPC_UNAVAILABLE' });
  });

  it('rejects malformed, unsigned, wrong-chain and oversized transactions before RPC access', async () => {
    const submitter = new EvmActionTransactionSubmitter({ 10143: 'https://rpc.example.test' });
    await expect(submitter.submitRawTransaction({ chainId: 10143, rawTransaction: 'not-hex' }))
      .rejects.toMatchObject({ code: 'INVALID_TRANSACTION' });
    await expect(submitter.submitRawTransaction({ chainId: 10143, rawTransaction: '0x01' }))
      .rejects.toMatchObject({ code: 'INVALID_TRANSACTION' });
    const wrongChain = await wallet.signTransaction({
      chainId: 1, nonce: 0, gasLimit: 21_000, gasPrice: 1_000_000_000n,
      to: `0x${'2'.repeat(40)}`, value: 1n,
    });
    await expect(submitter.submitRawTransaction({ chainId: 10143, rawTransaction: wrongChain }))
      .rejects.toMatchObject({ code: 'INVALID_TRANSACTION' });
    await expect(submitter.submitRawTransaction({ chainId: 10143, rawTransaction: `0x${'11'.repeat(131073)}` }))
      .rejects.toMatchObject({ code: 'INVALID_TRANSACTION' });
  });
});
