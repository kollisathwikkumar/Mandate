import { describe, expect, it } from 'vitest';
import type { EvmBlock, EvmIndexerRpc, EvmLog } from '../src/evm-rpc.js';
import { FailoverEvmIndexerRpc } from '../src/evm-rpc.js';

class ConfigurableRpc implements EvmIndexerRpc {
  public chainIdCalls = 0;
  public latestBlockCalls = 0;
  public blockCalls = 0;
  public logCalls = 0;
  public constructor(private readonly configuredChainId: number | Error, private readonly latest: number | Error = 42) {}
  public async chainId(): Promise<number> {
    this.chainIdCalls += 1;
    if (this.configuredChainId instanceof Error) throw this.configuredChainId;
    return this.configuredChainId;
  }
  public async latestBlock(): Promise<number> {
    this.latestBlockCalls += 1;
    if (this.latest instanceof Error) throw this.latest;
    return this.latest;
  }
  public async block(number: number): Promise<EvmBlock> {
    this.blockCalls += 1;
    return { number, hash: `block-${number}`, parentHash: `block-${number - 1}` };
  }
  public async logs(): Promise<readonly EvmLog[]> { this.logCalls += 1; return []; }
}

describe('EVM indexer RPC failover', () => {
  it('requires at least one endpoint and a positive expected chain ID', () => {
    expect(() => new FailoverEvmIndexerRpc([], 10143)).toThrow('At least one indexer RPC endpoint is required');
    expect(() => new FailoverEvmIndexerRpc([new ConfigurableRpc(10143)], 0)).toThrow('expectedChainId');
  });

  it('fails over from an unavailable primary and sticks to the working endpoint', async () => {
    const primary = new ConfigurableRpc(new Error('offline'));
    const backup = new ConfigurableRpc(10143, 99);
    const rpc = new FailoverEvmIndexerRpc([primary, backup], 10143);

    await expect(rpc.latestBlock()).resolves.toBe(99);
    await expect(rpc.block(98)).resolves.toEqual({ number: 98, hash: 'block-98', parentHash: 'block-97' });
    await expect(rpc.logs(96, 98, ['0x0000000000000000000000000000000000000001'])).resolves.toEqual([]);
    expect(primary.latestBlockCalls + primary.blockCalls + primary.logCalls).toBe(0);
    expect(backup.chainIdCalls).toBe(1);
    expect(backup.latestBlockCalls).toBe(1);
    expect(backup.blockCalls).toBe(1);
    expect(backup.logCalls).toBe(1);
  });

  it('skips an endpoint on the wrong chain before invoking its RPC method', async () => {
    const wrongChain = new ConfigurableRpc(1, 500);
    const correctChain = new ConfigurableRpc(10143, 101);
    const rpc = new FailoverEvmIndexerRpc([wrongChain, correctChain], 10143);

    await expect(rpc.latestBlock()).resolves.toBe(101);
    expect(wrongChain.latestBlockCalls).toBe(0);
    expect(correctChain.latestBlockCalls).toBe(1);
    await expect(rpc.chainId()).resolves.toBe(10143);
  });

  it('fails over when a chain-matched endpoint returns a failed method result', async () => {
    const failed = new ConfigurableRpc(10143, new Error('provider body must stay private'));
    const backup = new ConfigurableRpc(10143, 101);
    const rpc = new FailoverEvmIndexerRpc([failed, backup], 10143);

    await expect(rpc.latestBlock()).resolves.toBe(101);
    expect(failed.latestBlockCalls).toBe(1);
    expect(backup.latestBlockCalls).toBe(1);
  });

  it('fails closed without exposing endpoint errors when every endpoint is unavailable or misconfigured', async () => {
    const unavailable = new ConfigurableRpc(new Error('private provider error details'));
    const wrongChain = new ConfigurableRpc(1);
    const rpc = new FailoverEvmIndexerRpc([unavailable, wrongChain], 10143);

    await expect(rpc.latestBlock()).rejects.toThrow('All configured RPC endpoints failed or returned an unexpected chain ID');
    await expect(rpc.latestBlock()).rejects.not.toThrow('private provider error details');
    expect(wrongChain.latestBlockCalls).toBe(0);
  });
});
