import { Interface, JsonRpcProvider } from 'ethers';
import { PolicyActivationFinalizationError, type PolicyActivationFinalizer, type FinalizedPolicyActivation } from '../../../ports/src/policy-activation-finalizer.js';
import type { SafePolicyActivationPlan } from '../../../chain/src/safe-policy-activation-plan.js';
import { EvmSafePolicyActivationReader } from './evm-safe-policy-activation-reader.js';

const safeInterface = new Interface(['event ExecutionSuccess(bytes32 indexed txHash,uint256 payment)']);
const safeEventTopic = safeInterface.getEvent('ExecutionSuccess')?.topicHash;
const guardAbi = [
  'function policyEpoch() view returns (uint64)',
  'function policyEnabled() view returns (bool)',
  'function policyRevisionHash() view returns (bytes32)',
];
const moduleAbi = ['function agents(address agent) view returns (uint64 version,bool active)'];
const hashSchema = /^0x[0-9a-fA-F]{64}$/;

function rpcUrl(chainId: number, rpcUrls: Readonly<Record<number, string>>): string {
  const raw = rpcUrls[chainId];
  if (raw === undefined) throw new PolicyActivationFinalizationError('UNSUPPORTED_CHAIN');
  let parsed: URL;
  try { parsed = new URL(raw); } catch { throw new PolicyActivationFinalizationError('RPC_UNAVAILABLE'); }
  const local = ['localhost', '127.0.0.1', '[::1]'].includes(parsed.hostname);
  if ((parsed.protocol !== 'https:' && !(parsed.protocol === 'http:' && local)) || parsed.username !== '' || parsed.password !== '') {
    throw new PolicyActivationFinalizationError('RPC_UNAVAILABLE');
  }
  return parsed.toString();
}

function validatePlanHashes(plan: SafePolicyActivationPlan, transactionHashes: readonly string[]): void {
  if (transactionHashes.length !== plan.calls.length || transactionHashes.length === 0
    || transactionHashes.some((value) => !hashSchema.test(value))
    || new Set(transactionHashes.map((value) => value.toLowerCase())).size !== transactionHashes.length) {
    throw new PolicyActivationFinalizationError('SAFE_EXECUTION_NOT_FOUND');
  }
}

/** Confirms Safe owner execution events and the resulting guard/module state at chain finality. */
export class EvmSafePolicyActivationFinalizer implements PolicyActivationFinalizer {
  public constructor(
    private readonly rpcUrls: Readonly<Record<number, string>>,
    private readonly confirmationsByChain: Readonly<Record<number, number>>,
  ) {}

  public async verifyFinalizedActivation(input: {
    readonly planId: string;
    readonly plan: SafePolicyActivationPlan;
    readonly transactionHashes: readonly string[];
    readonly minimumConfirmations: number;
  }): Promise<FinalizedPolicyActivation> {
    const { plan } = input;
    validatePlanHashes(plan, input.transactionHashes);
    if (!Number.isSafeInteger(input.minimumConfirmations) || input.minimumConfirmations < 1 || input.minimumConfirmations > 10000
      || this.confirmationsByChain[plan.chainId] !== input.minimumConfirmations) {
      throw new PolicyActivationFinalizationError('INVALID_CONFIRMATION_CONFIGURATION');
    }
    const endpoint = rpcUrl(plan.chainId, this.rpcUrls);
    const provider = new JsonRpcProvider(endpoint, plan.chainId, { staticNetwork: true });
    try {
      const network = await provider.getNetwork();
      if (network.chainId !== BigInt(plan.chainId)) throw new PolicyActivationFinalizationError('POLICY_STATE_MISMATCH');
      const latestBlock = await provider.getBlockNumber();
      const receipts = [];
      let priorBlock = -1;
      let priorTransactionIndex = -1;
      for (let index = 0; index < plan.calls.length; index += 1) {
        const expectedCall = plan.calls[index];
        const transactionHash = input.transactionHashes[index];
        if (expectedCall === undefined || transactionHash === undefined) throw new PolicyActivationFinalizationError('SAFE_EXECUTION_NOT_FOUND');
        const receipt = await provider.getTransactionReceipt(transactionHash);
        if (receipt === null) throw new PolicyActivationFinalizationError('RECEIPT_NOT_FOUND');
        if (receipt.status !== 1 || receipt.to?.toLowerCase() !== plan.safeAddress.toLowerCase()) {
          throw new PolicyActivationFinalizationError('TRANSACTION_FAILED');
        }
        const matchingEvents = receipt.logs.filter((log) => log.address.toLowerCase() === plan.safeAddress.toLowerCase()
          && log.topics[0]?.toLowerCase() === safeEventTopic?.toLowerCase())
          .map((log) => safeInterface.parseLog({ topics: [...log.topics], data: log.data }))
          .filter((log) => log !== null && String(log.args[0]).toLowerCase() === expectedCall.safeTxHash.toLowerCase());
        if (matchingEvents.length !== 1) throw new PolicyActivationFinalizationError('SAFE_EXECUTION_NOT_FOUND');
        const confirmations = latestBlock - receipt.blockNumber + 1;
        if (confirmations < input.minimumConfirmations) throw new PolicyActivationFinalizationError('NOT_FINALIZED');
        const canonicalBlock = await provider.getBlock(receipt.blockNumber);
        if (canonicalBlock === null || canonicalBlock.hash === null || canonicalBlock.hash.toLowerCase() !== receipt.blockHash.toLowerCase()) {
          throw new PolicyActivationFinalizationError('NOT_FINALIZED');
        }
        if (receipt.blockNumber < priorBlock || (receipt.blockNumber === priorBlock && receipt.index <= priorTransactionIndex)) {
          throw new PolicyActivationFinalizationError('SAFE_EXECUTION_NOT_FOUND');
        }
        priorBlock = receipt.blockNumber;
        priorTransactionIndex = receipt.index;
        receipts.push({
          safeTxHash: expectedCall.safeTxHash.toLowerCase(),
          transactionHash: receipt.hash.toLowerCase(),
          blockNumber: String(receipt.blockNumber),
          blockHash: receipt.blockHash.toLowerCase(),
          transactionIndex: receipt.index,
          confirmations,
          status: 'FINAL' as const,
        });
      }

      const state = await new EvmSafePolicyActivationReader(this.rpcUrls).readState({
        chainId: plan.chainId,
        safeAddress: plan.safeAddress,
        guardAddress: plan.guardAddress,
        moduleAddress: plan.moduleAddress,
        agentAddress: plan.agentAddress,
      });
      if (!state.policyEnabled || state.policyRevisionHash !== plan.revisionHash.toLowerCase()
        || state.policyEpoch.toString() !== plan.resultingPolicyEpoch
        || state.agentKeyVersion !== BigInt(plan.agentKeyVersion) || !state.agentActive) {
        throw new PolicyActivationFinalizationError('POLICY_STATE_MISMATCH');
      }
      const finalizedBlockNumber = latestBlock - input.minimumConfirmations + 1;
      if (finalizedBlockNumber < 0 || receipts.some(({ blockNumber }) => Number(blockNumber) > finalizedBlockNumber)) {
        throw new PolicyActivationFinalizationError('NOT_FINALIZED');
      }
      return {
        planId: input.planId,
        revisionHash: plan.revisionHash,
        policyEpoch: plan.resultingPolicyEpoch,
        finalizedBlockNumber: String(finalizedBlockNumber),
        receipts,
      };
    } catch (error: unknown) {
      if (error instanceof PolicyActivationFinalizationError) throw error;
      throw new PolicyActivationFinalizationError('RPC_UNAVAILABLE');
    } finally {
      await provider.destroy();
    }
  }
}
