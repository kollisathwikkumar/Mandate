import { describe, expect, it } from 'vitest';
import { EvmActionExecutionStateReader } from '../src/chain/evm-action-execution-state-reader.js';

const input = {
  chainId: 10143,
  safeAddress: `0x${'1'.repeat(40)}`,
  guardAddress: `0x${'2'.repeat(40)}`,
  moduleAddress: `0x${'3'.repeat(40)}`,
  agentAddress: `0x${'4'.repeat(40)}`,
};

describe('EVM action execution state reader', () => {
  it('fails closed when no RPC is configured for the requested chain', async () => {
    await expect(new EvmActionExecutionStateReader({}).readState(input))
      .rejects.toMatchObject({ code: 'UNSUPPORTED_CHAIN' });
  });

  it('rejects remote cleartext RPC endpoints before connecting', async () => {
    await expect(new EvmActionExecutionStateReader({ 10143: 'http://rpc.example.test' }).readState(input))
      .rejects.toMatchObject({ code: 'RPC_UNAVAILABLE' });
  });

  it('rejects malformed adapter addresses before connecting', async () => {
    await expect(new EvmActionExecutionStateReader({ 10143: 'https://rpc.example.test' }).readState({ ...input, guardAddress: 'bad-address' }))
      .rejects.toMatchObject({ code: 'CHAIN_STATE_MISMATCH' });
  });
});
