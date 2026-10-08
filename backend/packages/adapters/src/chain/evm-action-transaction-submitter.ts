import { Transaction, keccak256 } from 'ethers';
import { z } from 'zod';
import { ActionTransactionSubmissionError, type ActionTransactionSubmitter } from '../../../ports/src/action-transaction-submitter.js';

const MAX_TRANSACTION_HEX_LENGTH = 262146;
const MAX_ENDPOINTS = 4;
const RPC_TIMEOUT_MS = 5000;
const RPC_RESPONSE_LIMIT_BYTES = 65536;
const hashSchema = z.string().regex(/^0x[0-9a-fA-F]{64}$/);
const quantitySchema = z.string().regex(/^0x(?:0|[1-9a-fA-F][0-9a-fA-F]*)$/);
const errorResponseSchema = z.object({
  jsonrpc: z.literal('2.0'), id: z.literal(1), error: z.object({ code: z.number().int(), message: z.string() }).passthrough(),
}).passthrough();
const chainIdResponseSchema = z.object({ jsonrpc: z.literal('2.0'), id: z.literal(1), result: quantitySchema }).passthrough();
const transactionHashResponseSchema = z.object({ jsonrpc: z.literal('2.0'), id: z.literal(1), result: hashSchema }).passthrough();
const knownTransactionResponseSchema = z.object({
  jsonrpc: z.literal('2.0'), id: z.literal(1), result: z.union([z.null(), z.object({ hash: hashSchema }).passthrough()]),
}).passthrough();
const knownReceiptResponseSchema = z.object({
  jsonrpc: z.literal('2.0'), id: z.literal(1), result: z.union([z.null(), z.object({ transactionHash: hashSchema }).passthrough()]),
}).passthrough();

type EndpointResult = 'accepted' | 'mismatch' | 'unavailable';

function normalizeEndpoint(endpoint: string): string {
  let parsed: URL;
  try { parsed = new URL(endpoint); } catch { throw new ActionTransactionSubmissionError('RPC_UNAVAILABLE'); }
  const hostname = parsed.hostname.toLowerCase().replace(/^\[|\]$/g, '');
  const local = hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '::1';
  if ((parsed.protocol !== 'https:' && !(parsed.protocol === 'http:' && local))
    || parsed.username !== '' || parsed.password !== '' || parsed.hash !== '') {
    throw new ActionTransactionSubmissionError('RPC_UNAVAILABLE');
  }
  return parsed.toString();
}

async function requestRpc(endpoint: string, method: string, params: readonly string[]): Promise<unknown> {
  const response = await fetch(endpoint, {
    method: 'POST',
    redirect: 'error',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
    signal: AbortSignal.timeout(RPC_TIMEOUT_MS),
  });
  if (!response.ok) throw new Error('RPC_UNAVAILABLE');
  const declaredLength = Number(response.headers.get('content-length') ?? '0');
  if (Number.isFinite(declaredLength) && declaredLength > RPC_RESPONSE_LIMIT_BYTES) throw new Error('RPC_UNAVAILABLE');
  const body = await response.text();
  if (Buffer.byteLength(body, 'utf8') > RPC_RESPONSE_LIMIT_BYTES) throw new Error('RPC_UNAVAILABLE');
  try { return JSON.parse(body) as unknown; } catch { throw new Error('RPC_UNAVAILABLE'); }
}

async function isKnown(endpoint: string, transactionHash: string): Promise<boolean> {
  try {
    const transactionPayload = await requestRpc(endpoint, 'eth_getTransactionByHash', [transactionHash]);
    const transaction = knownTransactionResponseSchema.safeParse(transactionPayload);
    if (transaction.success && transaction.data.result !== null
      && transaction.data.result.hash.toLowerCase() === transactionHash) return true;
    const receiptPayload = await requestRpc(endpoint, 'eth_getTransactionReceipt', [transactionHash]);
    const receipt = knownReceiptResponseSchema.safeParse(receiptPayload);
    return receipt.success && receipt.data.result !== null
      && receipt.data.result.transactionHash.toLowerCase() === transactionHash;
  } catch {
    return false;
  }
}

async function submitToEndpoint(endpoint: string, chainId: number, rawTransaction: string, transactionHash: string): Promise<EndpointResult> {
  let chainPayload: unknown;
  try { chainPayload = await requestRpc(endpoint, 'eth_chainId', []); } catch { return 'unavailable'; }
  const chainResponse = chainIdResponseSchema.safeParse(chainPayload);
  if (!chainResponse.success) return 'unavailable';
  if (BigInt(chainResponse.data.result) !== BigInt(chainId)) return 'mismatch';

  try {
    const payload = await requestRpc(endpoint, 'eth_sendRawTransaction', [rawTransaction]);
    const accepted = transactionHashResponseSchema.safeParse(payload);
    if (accepted.success && accepted.data.result.toLowerCase() === transactionHash) return 'accepted';
    if (errorResponseSchema.safeParse(payload).success && await isKnown(endpoint, transactionHash)) return 'accepted';
    return 'unavailable';
  } catch {
    return await isKnown(endpoint, transactionHash) ? 'accepted' : 'unavailable';
  }
}

/** Broadcasts only caller-signed bytes; fallback retries keep the exact same transaction hash. */
export class EvmActionTransactionSubmitter implements ActionTransactionSubmitter {
  public constructor(
    private readonly rpcUrls: Readonly<Record<number, string>>,
    private readonly fallbackUrls: Readonly<Record<number, readonly string[]>> = {},
  ) {}

  public async submitRawTransaction(input: { readonly chainId: number; readonly rawTransaction: string }): Promise<{ readonly transactionHash: string }> {
    if (!Number.isSafeInteger(input.chainId) || input.chainId <= 0 || typeof input.rawTransaction !== 'string'
      || input.rawTransaction.length > MAX_TRANSACTION_HEX_LENGTH || !/^0x(?:[0-9a-fA-F]{2})+$/.test(input.rawTransaction)) {
      throw new ActionTransactionSubmissionError('INVALID_TRANSACTION');
    }
    let transaction: Transaction;
    try { transaction = Transaction.from(input.rawTransaction); }
    catch { throw new ActionTransactionSubmissionError('INVALID_TRANSACTION'); }
    if (transaction.hash === null || transaction.from === null || transaction.chainId !== BigInt(input.chainId)
      || transaction.to === null || transaction.gasLimit <= 0n) {
      throw new ActionTransactionSubmissionError('INVALID_TRANSACTION');
    }
    const expectedHash = keccak256(input.rawTransaction).toLowerCase();
    if (transaction.hash.toLowerCase() !== expectedHash) throw new ActionTransactionSubmissionError('INVALID_TRANSACTION');
    const configuredPrimary = this.rpcUrls[input.chainId];
    if (configuredPrimary === undefined) throw new ActionTransactionSubmissionError('UNSUPPORTED_CHAIN');
    const configured = [configuredPrimary, ...(this.fallbackUrls[input.chainId] ?? [])];
    if (configured.length > MAX_ENDPOINTS) throw new ActionTransactionSubmissionError('RPC_UNAVAILABLE');
    const endpoints = configured.map(normalizeEndpoint);
    if (new Set(endpoints).size !== endpoints.length) throw new ActionTransactionSubmissionError('RPC_UNAVAILABLE');

    let chainMismatches = 0;
    for (const endpoint of endpoints) {
      const result = await submitToEndpoint(endpoint, input.chainId, input.rawTransaction, expectedHash);
      if (result === 'accepted') return { transactionHash: expectedHash };
      if (result === 'mismatch') chainMismatches += 1;
    }
    if (chainMismatches === endpoints.length) throw new ActionTransactionSubmissionError('CHAIN_ID_MISMATCH');
    throw new ActionTransactionSubmissionError('RPC_UNAVAILABLE');
  }
}
