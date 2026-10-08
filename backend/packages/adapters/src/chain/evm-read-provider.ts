import { AbstractProvider, JsonRpcProvider, Network } from 'ethers';
import type { PerformActionRequest } from 'ethers';
import { z } from 'zod';

const MAX_ENDPOINTS = 4;
const PROBE_TIMEOUT_MS = 3000;

const quantitySchema = z.string().regex(/^0x(?:0|[1-9a-fA-F][0-9a-fA-F]*)$/);
const successfulProbeSchema = z.object({ jsonrpc: z.literal('2.0'), id: z.literal(1), result: quantitySchema }).strict();
const failedProbeSchema = z.object({
  jsonrpc: z.literal('2.0'), id: z.literal(1), error: z.object({ code: z.number().int(), message: z.string() }).strict(),
}).strict();
const probeResponseSchema = z.union([successfulProbeSchema, failedProbeSchema]);

class SequentialEvmReadProvider extends AbstractProvider {
  public constructor(private readonly endpoints: readonly JsonRpcProvider[], private readonly chainId: number) {
    super(chainId, { cacheTimeout: -1 });
  }

  public async _detectNetwork(): Promise<Network> { return Network.from(this.chainId); }

  public async _perform<T = unknown>(request: PerformActionRequest): Promise<T> {
    if (request.method === 'broadcastTransaction') throw new Error('RPC_UNAVAILABLE');
    let emptyResult: T | undefined;
    for (const endpoint of this.endpoints) {
      try {
        const result = await endpoint._perform(request) as T;
        if (isMissingReadResult(request.method, result)) {
          emptyResult = result;
          continue;
        }
        return result;
      } catch {
        // Provider errors are endpoint-local; keep trying without exposing URLs or error bodies.
      }
    }
    if (emptyResult !== undefined) return emptyResult;
    throw new Error('RPC_UNAVAILABLE');
  }

  public override destroy(): void {
    for (const endpoint of this.endpoints) endpoint.destroy();
    super.destroy();
  }
}

function isMissingReadResult(method: string, result: unknown): boolean {
  if (result === null) return method === 'getBlock' || method === 'getTransaction' || method === 'getTransactionReceipt' || method === 'getTransactionResult';
  return method === 'getLogs' && Array.isArray(result) && result.length === 0;
}

interface ProbeResult {
  readonly endpoint: string;
  readonly status: 'ready' | 'mismatch' | 'unavailable';
}

function normalizeEndpoint(endpoint: string): string {
  let parsed: URL;
  try { parsed = new URL(endpoint); } catch { throw new Error('RPC_UNAVAILABLE'); }
  const hostname = parsed.hostname.toLowerCase().replace(/^\[|\]$/g, '');
  const loopback = hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '::1';
  if ((parsed.protocol !== 'https:' && !(parsed.protocol === 'http:' && loopback))
    || parsed.username !== '' || parsed.password !== '' || parsed.hash !== '') throw new Error('RPC_UNAVAILABLE');
  return parsed.toString();
}

async function probeEndpoint(endpoint: string, chainId: number): Promise<ProbeResult> {
  try {
    const response = await fetch(endpoint, {
      method: 'POST',
      redirect: 'error',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'eth_chainId', params: [] }),
      signal: AbortSignal.timeout(PROBE_TIMEOUT_MS),
    });
    if (!response.ok) return { endpoint, status: 'unavailable' };
    const payload = probeResponseSchema.safeParse(await response.json());
    if (!payload.success || !('result' in payload.data)) return { endpoint, status: 'unavailable' };
    return BigInt(payload.data.result) === BigInt(chainId)
      ? { endpoint, status: 'ready' }
      : { endpoint, status: 'mismatch' };
  } catch {
    return { endpoint, status: 'unavailable' };
  }
}

/** Creates a chain-verified ethers read provider with sequential, error-aware endpoint failover. */
export async function createEvmReadProvider(chainId: number, configuredEndpoints: readonly string[]): Promise<AbstractProvider> {
  if (!Number.isSafeInteger(chainId) || chainId < 1) throw new Error('INVALID_INPUT');
  if (configuredEndpoints.length === 0 || configuredEndpoints.length > MAX_ENDPOINTS) throw new Error('RPC_UNAVAILABLE');
  const endpoints = configuredEndpoints.map(normalizeEndpoint);
  if (new Set(endpoints).size !== endpoints.length) throw new Error('RPC_UNAVAILABLE');
  const probeResults = await Promise.all(endpoints.map((endpoint) => probeEndpoint(endpoint, chainId)));
  const readyEndpoints = probeResults.filter(({ status }) => status === 'ready').map(({ endpoint }) => endpoint);
  if (readyEndpoints.length === 0) {
    if (probeResults.every(({ status }) => status === 'mismatch')) throw new Error('CHAIN_MISMATCH');
    throw new Error('RPC_UNAVAILABLE');
  }

  const providers = readyEndpoints.map((endpoint) => new JsonRpcProvider(endpoint, chainId, { staticNetwork: true }));
  return new SequentialEvmReadProvider(providers, chainId);
}
