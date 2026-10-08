import { afterEach, describe, expect, it, vi } from 'vitest';
import { EvmAccountEnrollmentVerifier } from '../src/chain/evm-account-enrollment-verifier.js';

const safeAddress = '0x00000000000000000000000000000000000000a1';
const singletonAddress = '0x00000000000000000000000000000000000000b2';
const guardAddress = '0x00000000000000000000000000000000000000c3';
const moduleAddress = '0x00000000000000000000000000000000000000d4';
const blockHash = `0x${'12'.repeat(32)}`;
const word = (address: string): string => `0x${address.slice(2).padStart(64, '0')}`;

function mockRpc(blockNumber = '0x9'): typeof fetch {
  return vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
    const request = JSON.parse(String(init?.body ?? '{}')) as { id: number; method: string; params: unknown[] };
    let result: unknown;
    if (request.method === 'eth_chainId') result = '0x279f';
    else if (request.method === 'eth_blockNumber') result = blockNumber;
    else if (request.method === 'eth_getBlockByNumber') result = { hash: blockHash };
    else if (request.method === 'eth_getCode') result = '0x6000';
    else if (request.method === 'eth_getStorageAt') {
      const slot = String(request.params[1]);
      result = slot === '0x0' ? word(singletonAddress) : word(guardAddress);
    } else if (request.method === 'eth_call') {
      const transaction = request.params[0] as { to: string; data: string };
      const data = transaction.data.toLowerCase();
      if (data.startsWith('0xa619486e')) result = word(singletonAddress);
      else if (data.startsWith('0x186f0354')) result = word(safeAddress);
      else if (data.startsWith('0x7c0a8378')) result = word(moduleAddress);
      else if (data.startsWith('0xc5305f76')) result = word(`0x${'0'.repeat(63)}1`);
      else if (data.startsWith('0x7ceab3b1')) result = word(guardAddress);
      else if (data.startsWith('0x2d9ad53d')) result = word(`0x${'0'.repeat(63)}1`);
      else throw new Error(`Unexpected eth_call selector ${data.slice(0, 10)}`);
    } else throw new Error(`Unexpected RPC method ${request.method}`);

    return new Response(JSON.stringify({ jsonrpc: '2.0', id: request.id, result }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    });
  }) as typeof fetch;
}

afterEach(() => vi.unstubAllGlobals());

describe('EvmAccountEnrollmentVerifier JSON-RPC quantities', () => {
  it('accepts an odd-length hexadecimal block height and returns the verified enrollment proof', async () => {
    vi.stubGlobal('fetch', mockRpc());
    const verifier = new EvmAccountEnrollmentVerifier(
      { 10143: 'http://127.0.0.1:8545' },
      { 10143: singletonAddress },
    );

    await expect(verifier.verify({ chainId: 10143, address: safeAddress })).resolves.toEqual({
      safeAddress,
      guardAddress,
      moduleAddress,
    });
  });

  it('classifies a non-canonical JSON-RPC quantity as an unavailable RPC response', async () => {
    vi.stubGlobal('fetch', mockRpc('0x09'));
    const verifier = new EvmAccountEnrollmentVerifier(
      { 10143: 'http://127.0.0.1:8545' },
      { 10143: singletonAddress },
    );

    await expect(verifier.verify({ chainId: 10143, address: safeAddress })).rejects.toMatchObject({
      code: 'RPC_UNAVAILABLE',
    });
  });
});
