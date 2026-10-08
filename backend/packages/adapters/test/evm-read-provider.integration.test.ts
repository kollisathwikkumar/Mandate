import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import type { AbstractProvider } from 'ethers';
import { describe, expect, it } from 'vitest';
import { createEvmReadProvider } from '../src/chain/evm-read-provider.js';

interface RpcRequest { readonly id: number; readonly method: string; }
type RpcValue = { readonly result: string } | { readonly error: { readonly code: number; readonly message: string } };
type RpcResponder = (method: string) => RpcValue;

async function startRpcServer(respond: RpcResponder): Promise<{ readonly url: string; readonly close: () => Promise<void> }> {
  const server = createServer((request: IncomingMessage, response: ServerResponse) => {
    const chunks: Buffer[] = [];
    request.on('data', (chunk: Buffer | string) => chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)));
    request.on('end', () => {
      const payload = JSON.parse(Buffer.concat(chunks).toString('utf8')) as RpcRequest;
      response.writeHead(200, { 'content-type': 'application/json' });
      response.end(JSON.stringify({ jsonrpc: '2.0', id: payload.id, ...respond(payload.method) }));
    });
  });
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  const address = server.address();
  if (address === null || typeof address === 'string') throw new Error('Could not bind local test RPC');
  return {
    url: `http://127.0.0.1:${address.port}/rpc`,
    close: async () => new Promise<void>((resolve, reject) => server.close((error) => error === undefined ? resolve() : reject(error))),
  };
}

async function destroyProvider(provider: AbstractProvider): Promise<void> { await provider.destroy(); }

const chainIdResult: RpcValue = { result: '0x279f' };
const blockResult: RpcValue = { result: '0x2a' };
const rpcError: RpcValue = { error: { code: -32000, message: 'temporarily unavailable' } };

describe('EVM read provider fallback (local JSON-RPC integration)', () => {
  it('rejects remote cleartext and duplicate endpoints before opening providers', async () => {
    await expect(createEvmReadProvider(10143, ['http://rpc.example.com'])).rejects.toThrow('RPC_UNAVAILABLE');
    await expect(createEvmReadProvider(10143, ['https://rpc.example.com', 'https://rpc.example.com/']))
      .rejects.toThrow('RPC_UNAVAILABLE');
  });

  it('validates each endpoint chain and switches to a backup after the primary read fails', async () => {
    let primaryBalanceCalls = 0;
    const primary = await startRpcServer((method) => {
      if (method === 'eth_chainId') return chainIdResult;
      if (method === 'eth_getBalance') {
        primaryBalanceCalls += 1;
        return rpcError;
      }
      if (method === 'eth_blockNumber') return blockResult;
      return rpcError;
    });
    let backupBalanceCalls = 0;
    const backup = await startRpcServer((method) => {
      if (method === 'eth_chainId') return chainIdResult;
      if (method === 'eth_getBalance') {
        backupBalanceCalls += 1;
        return { result: '0x2a' };
      }
      if (method === 'eth_blockNumber') return blockResult;
      return rpcError;
    });
    let provider: AbstractProvider | undefined;
    try {
      provider = await createEvmReadProvider(10143, [primary.url, backup.url]);
      await expect(provider.getBalance('0x0000000000000000000000000000000000000001')).resolves.toBe(42n);
      expect(primaryBalanceCalls).toBeGreaterThanOrEqual(1);
      expect(backupBalanceCalls).toBeGreaterThanOrEqual(1);
    } finally {
      if (provider !== undefined) await destroyProvider(provider);
      await primary.close();
      await backup.close();
    }
  });

  it('skips mismatched-chain endpoints and reports chain mismatch when no endpoint agrees', async () => {
    const wrongChain = await startRpcServer((method) => method === 'eth_chainId' ? { result: '0x1' } : rpcError);
    const correctChain = await startRpcServer((method) => method === 'eth_chainId' ? chainIdResult : blockResult);
    let provider: AbstractProvider | undefined;
    try {
      provider = await createEvmReadProvider(10143, [wrongChain.url, correctChain.url]);
      await expect(provider.getBlockNumber()).resolves.toBe(42);
      await destroyProvider(provider);
      provider = undefined;
      await expect(createEvmReadProvider(10143, [wrongChain.url])).rejects.toThrow('CHAIN_MISMATCH');
    } finally {
      if (provider !== undefined) await destroyProvider(provider);
      await wrongChain.close();
      await correctChain.close();
    }
  });
});
