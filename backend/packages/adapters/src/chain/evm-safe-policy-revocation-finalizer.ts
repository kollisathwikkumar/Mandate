import { Interface, JsonRpcProvider } from 'ethers';
import type { PolicyRevocationFinalizer, FinalizedPolicyRevocation } from '../../../ports/src/policy-revocation-finalizer.js';
import { PolicyRevocationFinalizationError } from '../../../ports/src/policy-revocation-finalizer.js';
import type { SafePolicyRevocationPlan } from '../../../chain/src/safe-policy-revocation-plan.js';
import { EvmSafePolicyActivationReader } from './evm-safe-policy-activation-reader.js';

const safeInterface = new Interface(['event ExecutionSuccess(bytes32 indexed txHash,uint256 payment)']);
const safeEventTopic = safeInterface.getEvent('ExecutionSuccess')?.topicHash;
const hashSchema = /^0x[0-9a-fA-F]{64}$/;

function rpcUrl(chainId: number, rpcUrls: Readonly<Record<number, string>>): string {
  const raw = rpcUrls[chainId];
  if (raw === undefined) throw new PolicyRevocationFinalizationError('UNSUPPORTED_CHAIN');
  let parsed: URL;
  try { parsed = new URL(raw); } catch { throw new PolicyRevocationFinalizationError('RPC_UNAVAILABLE'); }
  const local = ['localhost', '127.0.0.1', '[::1]'].includes(parsed.hostname);
  if ((parsed.protocol !== 'https:' && !(parsed.protocol === 'http:' && local)) || parsed.username !== '' || parsed.password !== '') {
    throw new PolicyRevocationFinalizationError('RPC_UNAVAILABLE');
  }
  return parsed.toString();
}

/** Proves one finalized direct Safe execution and the resulting disabled guard epoch. */
export class EvmSafePolicyRevocationFinalizer implements PolicyRevocationFinalizer {
  public constructor(
    private readonly rpcUrls: Readonly<Record<number, string>>,
    private readonly confirmationsByChain: Readonly<Record<number, number>>,
  ) {}

  public async verifyFinalizedRevocation(input: {
    readonly planId: string;
    readonly plan: SafePolicyRevocationPlan;
    readonly transactionHash: string;
    readonly minimumConfirmations: number;
  }): Promise<FinalizedPolicyRevocation> {
    const { plan, transactionHash } = input;
    if (!hashSchema.test(transactionHash)) throw new PolicyRevocationFinalizationError('SAFE_EXECUTION_NOT_FOUND');
    if (!Number.isSafeInteger(input.minimumConfirmations) || input.minimumConfirmations < 1 || input.minimumConfirmations > 10000
      || this.confirmationsByChain[plan.chainId] !== input.minimumConfirmations) {
      throw new PolicyRevocationFinalizationError('INVALID_CONFIRMATION_CONFIGURATION');
    }
    const endpoint = rpcUrl(plan.chainId, this.rpcUrls);
    const provider = new JsonRpcProvider(endpoint, plan.chainId, { staticNetwork: true });
    try {
      const network = await provider.getNetwork();
      if (network.chainId !== BigInt(plan.chainId)) throw new PolicyRevocationFinalizationError('POLICY_STATE_MISMATCH');
      const latestBlock = await provider.getBlockNumber();
      const receipt = await provider.getTransactionReceipt(transactionHash);
      if (receipt === null) throw new PolicyRevocationFinalizationError('RECEIPT_NOT_FOUND');
      if (receipt.hash.toLowerCase() !== transactionHash.toLowerCase() || receipt.status !== 1
        || receipt.to?.toLowerCase() !== plan.safeAddress.toLowerCase()) {
        throw new PolicyRevocationFinalizationError('TRANSACTION_FAILED');
      }
      const matchingEvents = receipt.logs.filter((log) => log.address.toLowerCase() === plan.safeAddress.toLowerCase()
        && log.topics[0]?.toLowerCase() === safeEventTopic?.toLowerCase())
        .map((log) => safeInterface.parseLog({ topics: [...log.topics], data: log.data }))
        .filter((log) => log !== null && String(log.args[0]).toLowerCase() === plan.call.safeTxHash.toLowerCase());
      if (matchingEvents.length !== 1) throw new PolicyRevocationFinalizationError('SAFE_EXECUTION_NOT_FOUND');
      const confirmations = latestBlock - receipt.blockNumber + 1;
      if (confirmations < input.minimumConfirmations) throw new PolicyRevocationFinalizationError('NOT_FINALIZED');
      const canonicalBlock = await provider.getBlock(receipt.blockNumber);
      if (canonicalBlock === null || canonicalBlock.hash === null || canonicalBlock.hash.toLowerCase() !== receipt.blockHash.toLowerCase()) {
        throw new PolicyRevocationFinalizationError('NOT_FINALIZED');
      }
      const finalizedBlockNumber = latestBlock - input.minimumConfirmations + 1;
      if (finalizedBlockNumber < 0 || receipt.blockNumber > finalizedBlockNumber) throw new PolicyRevocationFinalizationError('NOT_FINALIZED');
      const state = await new EvmSafePolicyActivationReader(this.rpcUrls).readState({
        chainId: plan.chainId, safeAddress: plan.safeAddress, guardAddress: plan.guardAddress,
        moduleAddress: plan.moduleAddress, agentAddress: plan.agentAddress,
      });
      if (state.policyEnabled || state.policyRevisionHash !== plan.revisionHash.toLowerCase()
        || state.policyEpoch.toString() !== plan.resultingPolicyEpoch) {
        throw new PolicyRevocationFinalizationError('POLICY_STATE_MISMATCH');
      }
      return {
        planId: input.planId,
        revisionHash: plan.revisionHash,
        previousPolicyEpoch: plan.expectedPolicyEpoch,
        policyEpoch: plan.resultingPolicyEpoch,
        finalizedBlockNumber: String(finalizedBlockNumber),
        receipt: {
          safeTxHash: plan.call.safeTxHash.toLowerCase(), transactionHash: receipt.hash.toLowerCase(),
          blockNumber: String(receipt.blockNumber), blockHash: receipt.blockHash.toLowerCase(),
          transactionIndex: receipt.index, confirmations, status: 'FINAL',
        },
      };
    } catch (error: unknown) {
      if (error instanceof PolicyRevocationFinalizationError) throw error;
      throw new PolicyRevocationFinalizationError('RPC_UNAVAILABLE');
    } finally {
      await provider.destroy();
    }
  }
}
