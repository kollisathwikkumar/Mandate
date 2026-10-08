import { isAddress } from 'ethers';
import { createEvmReadProvider } from './evm-read-provider.js';
import type { JsonObject } from '../../../domain/src/json-value.js';
import type { ExecutionReceiptObservation, ExecutionReceiptReader } from '../../../ports/src/execution-reconciliation.js';

function rpcUrl(chainId: number, urls: Readonly<Record<number, string>>): string {
  const configured = urls[chainId];
  if (configured === undefined) throw new Error('RPC_UNAVAILABLE');
  let parsed: URL;
  try { parsed = new URL(configured); } catch { throw new Error('RPC_UNAVAILABLE'); }
  const loopback = ['localhost', '127.0.0.1', '[::1]'].includes(parsed.hostname);
  if ((parsed.protocol !== 'https:' && !(parsed.protocol === 'http:' && loopback)) || parsed.username !== '' || parsed.password !== '') {
    throw new Error('RPC_UNAVAILABLE');
  }
  return parsed.toString();
}

/** Reads a receipt, its containing canonical block, and the chain head from the configured EVM RPC. */
export class EvmExecutionReceiptReader implements ExecutionReceiptReader {
  public constructor(
    private readonly urls: Readonly<Record<number, string>>,
    private readonly fallbackUrls: Readonly<Record<number, readonly string[]>> = {},
  ) {}

  private async provider(chainId: number) {
    const primary = rpcUrl(chainId, this.urls);
    return createEvmReadProvider(chainId, [primary, ...(this.fallbackUrls[chainId] ?? [])]);
  }

  public async observe(input: { readonly chainId: number; readonly transactionHash: string; readonly requiredConfirmations: number }): Promise<ExecutionReceiptObservation | null> {
    if (!Number.isSafeInteger(input.chainId) || input.chainId < 1 || !Number.isSafeInteger(input.requiredConfirmations)
      || input.requiredConfirmations < 1 || !/^0x[0-9a-fA-F]{64}$/.test(input.transactionHash)) throw new Error('INVALID_INPUT');
    const provider = await this.provider(input.chainId);
    try {
      const network = await provider.getNetwork();
      if (network.chainId !== BigInt(input.chainId)) throw new Error('CHAIN_MISMATCH');
      const receipt = await provider.getTransactionReceipt(input.transactionHash);
      if (receipt === null) return null;
      if (receipt.hash.toLowerCase() !== input.transactionHash.toLowerCase() || receipt.status === null) throw new Error('INVALID_RECEIPT');
      const [head, block] = await Promise.all([provider.getBlockNumber(), provider.getBlock(receipt.blockNumber)]);
      if (block === null || block.hash === null) throw new Error('RPC_UNAVAILABLE');
      if (block.hash.toLowerCase() !== receipt.blockHash.toLowerCase()) return null;
      const confirmedBlock = await provider.getBlock(receipt.blockNumber);
      if (confirmedBlock === null || confirmedBlock.hash === null) throw new Error('RPC_UNAVAILABLE');
      if (confirmedBlock.hash.toLowerCase() !== receipt.blockHash.toLowerCase()) return null;
      const confirmations = Math.max(0, head - receipt.blockNumber + 1);
      const status: ExecutionReceiptObservation['status'] = confirmations >= input.requiredConfirmations ? 'FINAL' : 'TENTATIVE';
      const receiptJson: JsonObject = {
        transactionHash: receipt.hash.toLowerCase(),
        status: receipt.status === 1 ? 'SUCCESS' : 'REVERTED',
        blockNumber: receipt.blockNumber,
        blockHash: receipt.blockHash.toLowerCase(),
        transactionIndex: receipt.index,
        confirmations,
        from: receipt.from.toLowerCase(),
        to: receipt.to?.toLowerCase() ?? null,
        gasUsed: receipt.gasUsed.toString(),
        effectiveGasPrice: receipt.gasPrice?.toString() ?? null,
      };
      return {
        transactionHash: receipt.hash.toLowerCase(), blockNumber: receipt.blockNumber,
        blockHash: receipt.blockHash.toLowerCase(), status,
        executionResult: receipt.status === 1 ? 'SUCCESS' : 'REVERTED', confirmations, receipt: receiptJson,
      };
    } finally {
      await provider.destroy();
    }
  }

  /** Reads sender nonce at a database-indexed finalized block and verifies its hash first. */
  public async getSenderNonceAtCheckpoint(input: {
    readonly chainId: number; readonly sender: string; readonly blockNumber: number; readonly blockHash: string;
  }): Promise<{ readonly senderNonce: number; readonly timestampSeconds: number }> {
    if (!Number.isSafeInteger(input.chainId) || input.chainId < 1 || !Number.isSafeInteger(input.blockNumber) || input.blockNumber < 0
      || !isAddress(input.sender) || !/^0x[0-9a-f]{64}$/.test(input.blockHash)) throw new Error('INVALID_INPUT');
    const provider = await this.provider(input.chainId);
    try {
      const network = await provider.getNetwork();
      if (network.chainId !== BigInt(input.chainId)) throw new Error('CHAIN_MISMATCH');
      const block = await provider.getBlock(input.blockNumber);
      if (block === null || block.hash === null || block.hash.toLowerCase() !== input.blockHash) throw new Error('CHECKPOINT_NOT_CANONICAL');
      const senderNonce = await provider.getTransactionCount(input.sender, input.blockNumber);
      if (!Number.isSafeInteger(senderNonce) || senderNonce < 0) throw new Error('UNSUPPORTED_NONCE');
      const canonicalBlock = await provider.getBlock(input.blockNumber);
      if (canonicalBlock === null || canonicalBlock.hash === null || canonicalBlock.hash.toLowerCase() !== input.blockHash) {
        throw new Error('CHECKPOINT_NOT_CANONICAL');
      }
      return { senderNonce, timestampSeconds: block.timestamp };
    } finally {
      await provider.destroy();
    }
  }

  /** Checks the current canonical block at a previously finalized receipt height. */
  public async getCanonicalBlockAtFinality(input: { readonly chainId: number; readonly blockNumber: number }): Promise<{ readonly blockHash: string; readonly confirmations: number } | null> {
    if (!Number.isSafeInteger(input.chainId) || input.chainId < 1 || !Number.isSafeInteger(input.blockNumber) || input.blockNumber < 0) {
      throw new Error('INVALID_INPUT');
    }
    const provider = await this.provider(input.chainId);
    try {
      const network = await provider.getNetwork();
      if (network.chainId !== BigInt(input.chainId)) throw new Error('CHAIN_MISMATCH');
      const [head, block] = await Promise.all([provider.getBlockNumber(), provider.getBlock(input.blockNumber)]);
      if (block === null || block.hash === null) return null;
      const canonical = await provider.getBlock(input.blockNumber);
      if (canonical === null || canonical.hash === null || canonical.hash.toLowerCase() !== block.hash.toLowerCase()) return null;
      return { blockHash: block.hash.toLowerCase(), confirmations: Math.max(0, head - input.blockNumber + 1) };
    } finally {
      await provider.destroy();
    }
  }
}
