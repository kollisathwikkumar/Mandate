import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { Wallet, keccak256 } from 'ethers';
import { afterEach, describe, expect, it } from 'vitest';
import { EvmActionTransactionSubmitter } from '../src/chain/evm-action-transaction-submitter.js';

interface RpcRequest { readonly id: number; readonly method: string; readonly params: readonly unknown[]; }
type RpcReply = { readonly result: unknown } | { readonly error: { readonly code: number; readonly message: string } };
type RpcHandler = (request: RpcRequest) => { readonly status?: number; readonly reply?: RpcReply };
const wallet = new Wallet(`0x${'1'.repeat(64)}`);
const raw = async (): Promise<string> => wallet.signTransaction({ chainId: 10143, nonce: 0, gasLimit: 21_000,
  gasPrice: 1_000_000_000n, to: `0x${'2'.repeat(40)}`, value: 1n });
const servers: Array<() => Promise<void>> = [];

async function startRpc(handler: RpcHandler): Promise<string> {
  const server = createServer((request: IncomingMessage, response: ServerResponse) => {
    const chunks: Buffer[] = [];
    request.on('data', (chunk: Buffer | string) => chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)));
    request.on('end', () => {
      const message = JSON.parse(Buffer.concat(chunks).toString('utf8')) as RpcRequest;
      const result = handler(message);
      response.writeHead(result.status ?? 200, { 'content-type': 'application/json' });
      response.end(result.reply === undefined ? '' : JSON.stringify({ jsonrpc: '2.0', id: message.id, ...result.reply }));
    });
  });
  await new Promise<void>((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
  const address = server.address();
  if (address === null || typeof address === 'string') throw new Error('Local JSON-RPC server did not bind');
  servers.push(() => new Promise<void>((resolve, reject) => server.close((error) => error === undefined ? resolve() : reject(error))));
  return `http://127.0.0.1:${address.port}/rpc`;
}

afterEach(async () => { await Promise.all(servers.splice(0).map((close) => close())); });

describe('EVM broadcaster ordered failover (local JSON-RPC integration)', () => {
  it('retries only the identical signed bytes after an ambiguous primary response', async () => {
    const signed = await raw();
    const expectedHash = keccak256(signed).toLowerCase();
    const observed: string[] = [];
    const primary = await startRpc(({ method, params }) => {
      if (method === 'eth_chainId') return { reply: { result: '0x279f' } };
      if (method === 'eth_sendRawTransaction') {
        observed.push(String(params[0]));
        return { status: 503 };
      }
      return { reply: { result: null } };
    });
    const backup = await startRpc(({ method, params }) => {
      if (method === 'eth_chainId') return { reply: { result: '0x279f' } };
      if (method === 'eth_sendRawTransaction') {
        observed.push(String(params[0]));
        return { reply: { result: expectedHash } };
      }
      return { reply: { result: null } };
    });
    const submitter = new EvmActionTransactionSubmitter({ 10143: primary }, { 10143: [backup] });
    await expect(submitter.submitRawTransaction({ chainId: 10143, rawTransaction: signed })).resolves.toEqual({ transactionHash: expectedHash });
    expect(observed).toEqual([signed, signed]);
    expect(observed.every((candidate) => keccak256(candidate).toLowerCase() === expectedHash)).toBe(true);
  });

  it('skips wrong-chain backups and returns chain mismatch only when all endpoints mismatch', async () => {
    let wrongSends = 0;
    const wrong = await startRpc(({ method }) => {
      if (method === 'eth_chainId') return { reply: { result: '0x1' } };
      if (method === 'eth_sendRawTransaction') wrongSends += 1;
      return { reply: { result: null } };
    });
    const signed = await raw();
    const expectedHash = keccak256(signed).toLowerCase();
    const good = await startRpc(({ method }) => method === 'eth_chainId'
      ? { reply: { result: '0x279f' } } : { reply: { result: expectedHash } });
    await expect(new EvmActionTransactionSubmitter({ 10143: wrong }, { 10143: [good] })
      .submitRawTransaction({ chainId: 10143, rawTransaction: signed })).resolves.toEqual({ transactionHash: expectedHash });
    expect(wrongSends).toBe(0);
    await expect(new EvmActionTransactionSubmitter({ 10143: wrong })
      .submitRawTransaction({ chainId: 10143, rawTransaction: signed })).rejects.toMatchObject({ code: 'CHAIN_ID_MISMATCH' });
  });

  it('confirms an already-known fallback by matching the transaction receipt hash', async () => {
    const signed = await raw();
    const expectedHash = keccak256(signed).toLowerCase();
    let transactionLookups = 0;
    let receiptLookups = 0;
    const known = await startRpc(({ method }) => {
      if (method === 'eth_chainId') return { reply: { result: '0x279f' } };
      if (method === 'eth_sendRawTransaction') return { reply: { error: { code: -32000, message: 'already known' } } };
      if (method === 'eth_getTransactionByHash') { transactionLookups += 1; return { reply: { result: null } }; }
      if (method === 'eth_getTransactionReceipt') {
        receiptLookups += 1;
        return { reply: { result: { transactionHash: expectedHash } } };
      }
      return { reply: { result: null } };
    });
    await expect(new EvmActionTransactionSubmitter({ 10143: 'http://127.0.0.1:1' }, { 10143: [known] })
      .submitRawTransaction({ chainId: 10143, rawTransaction: signed })).resolves.toEqual({ transactionHash: expectedHash });
    expect(transactionLookups).toBe(1);
    expect(receiptLookups).toBe(1);
  });

  it('keeps the failure typed when every verified endpoint rejects the exact transaction', async () => {
    let sends = 0;
    const unavailable = () => startRpc(({ method }) => {
      if (method === 'eth_chainId') return { reply: { result: '0x279f' } };
      if (method === 'eth_sendRawTransaction') sends += 1;
      return { status: 503 };
    });
    const primary = await unavailable();
    const backup = await unavailable();
    await expect(new EvmActionTransactionSubmitter({ 10143: primary }, { 10143: [backup] })
      .submitRawTransaction({ chainId: 10143, rawTransaction: await raw() })).rejects.toMatchObject({ code: 'RPC_UNAVAILABLE' });
    expect(sends).toBe(2);
  });
});
