import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { describe, expect, it } from 'vitest';
import { FailoverEvmIndexerRpc, HttpEvmIndexerRpc } from '../src/evm-rpc.js';

interface RpcRequest { readonly id: number; readonly method: string; }

function handleRpc(request: IncomingMessage, response: ServerResponse): void {
  const chunks: Buffer[] = [];
  request.on('data', (chunk: Buffer | string) => chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)));
  request.on('end', () => {
    const payload = JSON.parse(Buffer.concat(chunks).toString('utf8')) as RpcRequest;
    const result = payload.method === 'eth_chainId' ? '0x279f' : payload.method === 'eth_blockNumber' ? '0x63' : null;
    response.writeHead(200, { 'content-type': 'application/json' });
    response.end(JSON.stringify({ jsonrpc: '2.0', id: payload.id, result }));
  });
}

describe('HTTP EVM indexer RPC failover integration', () => {
  it('falls back from a refused loopback connection to an HTTP JSON-RPC endpoint', async () => {
    const server = createServer(handleRpc);
    await new Promise<void>((resolve, reject) => {
      server.once('error', reject);
      server.listen(0, '127.0.0.1', resolve);
    });
    const address = server.address();
    if (address === null || typeof address === 'string') throw new Error('Could not bind test RPC server');

    try {
      const rpc = new FailoverEvmIndexerRpc([
        new HttpEvmIndexerRpc('http://127.0.0.1:1', 500),
        new HttpEvmIndexerRpc(`http://127.0.0.1:${address.port}/rpc`, 1000),
      ], 10143);
      await expect(rpc.chainId()).resolves.toBe(10143);
      await expect(rpc.latestBlock()).resolves.toBe(99);
    } finally {
      await new Promise<void>((resolve, reject) => server.close((error) => error === undefined ? resolve() : reject(error)));
    }
  });
});
