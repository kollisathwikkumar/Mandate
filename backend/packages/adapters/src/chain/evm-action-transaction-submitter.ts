import { JsonRpcProvider, Transaction, keccak256 } from 'ethers';
import { ActionTransactionSubmissionError, type ActionTransactionSubmitter } from '../../../ports/src/action-transaction-submitter.js';

function endpointFor(chainId: number, rpcUrls: Readonly<Record<number, string>>): string {
  const configured = rpcUrls[chainId];
  if (configured === undefined) throw new ActionTransactionSubmissionError('UNSUPPORTED_CHAIN');
  let endpoint: URL;
  try { endpoint = new URL(configured); }
  catch { throw new ActionTransactionSubmissionError('RPC_UNAVAILABLE'); }
  const local = ['localhost', '127.0.0.1', '[::1]'].includes(endpoint.hostname);
  if ((endpoint.protocol !== 'https:' && !(endpoint.protocol === 'http:' && local))
    || endpoint.username !== '' || endpoint.password !== '') {
    throw new ActionTransactionSubmissionError('RPC_UNAVAILABLE');
  }
  return endpoint.toString();
}

/** Broadcasts only a caller-signed EVM transaction; the adapter never holds or creates a signer. */
export class EvmActionTransactionSubmitter implements ActionTransactionSubmitter {
  public constructor(private readonly rpcUrls: Readonly<Record<number, string>>) {}

  public async submitRawTransaction(input: { readonly chainId: number; readonly rawTransaction: string }): Promise<{ readonly transactionHash: string }> {
    if (!Number.isSafeInteger(input.chainId) || input.chainId <= 0 || typeof input.rawTransaction !== 'string'
      || input.rawTransaction.length > 262146 || !/^0x(?:[0-9a-fA-F]{2})+$/.test(input.rawTransaction)) {
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
    const endpoint = endpointFor(input.chainId, this.rpcUrls);
    const provider = new JsonRpcProvider(endpoint, input.chainId, { staticNetwork: true });
    try {
      const network = await provider.getNetwork();
      if (network.chainId !== BigInt(input.chainId)) throw new ActionTransactionSubmissionError('CHAIN_ID_MISMATCH');
      try {
        const response = await provider.broadcastTransaction(input.rawTransaction);
        if (response.hash.toLowerCase() !== expectedHash) throw new ActionTransactionSubmissionError('RPC_UNAVAILABLE');
      } catch (error: unknown) {
        if (error instanceof ActionTransactionSubmissionError) throw error;
        const message = error instanceof Error ? error.message.toLowerCase() : '';
        if (message.includes('already known') || message.includes('known transaction') || message.includes('already imported') || message.includes('nonce too low')) {
          const [knownTransaction, knownReceipt] = await Promise.all([
            provider.getTransaction(expectedHash), provider.getTransactionReceipt(expectedHash),
          ]);
          if (knownTransaction !== null || knownReceipt !== null) return { transactionHash: expectedHash };
        }
        throw new ActionTransactionSubmissionError('RPC_UNAVAILABLE');
      }
      return { transactionHash: expectedHash };
    } catch (error: unknown) {
      if (error instanceof ActionTransactionSubmissionError) throw error;
      throw new ActionTransactionSubmissionError('RPC_UNAVAILABLE');
    } finally {
      await provider.destroy();
    }
  }
}
