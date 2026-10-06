import type {
  ExecutionReceiptReader,
  ExecutionReconciliationRepository,
  ExecutionReconciliationResult,
  PendingExecutionReceipt,
} from '../../ports/src/execution-reconciliation.js';

export class ExecutionReconciliationService {
  public constructor(
    private readonly repository: ExecutionReconciliationRepository,
    private readonly reader: ExecutionReceiptReader,
    private readonly confirmationDepths: Readonly<Record<number, number>>,
  ) {}

  public async runBatch(limit = 25): Promise<ExecutionReconciliationResult> {
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 100) throw new RangeError('limit must be an integer from 1 to 100');
    const pending = await this.repository.listPending(limit);
    const counts = { checked: 0, tentative: 0, finalized: 0, dropped: 0, deepReorged: 0, reorged: 0, unchanged: 0, failed: 0 };
    for (const item of pending) {
      counts.checked += 1;
      try {
        let observedTransactionHash = item.transactionHash;
        let observation = await this.observe(item, observedTransactionHash);
        let canonicalExecution: string | null = null;
        if (observation === null) {
          canonicalExecution = await this.repository.findCanonicalExecution(item);
          if (canonicalExecution !== null) {
            observedTransactionHash = canonicalExecution;
            observation = await this.observe(item, observedTransactionHash);
          }
        }
        if (observation === null && canonicalExecution === null && item.outerSender !== null && item.outerNonce !== null) {
          const checkpoint = await this.repository.getDropCheckpoint(item);
          if (checkpoint !== null) {
            const senderState = await this.reader.getSenderNonceAtCheckpoint({
              chainId: item.chainId, sender: item.outerSender, blockNumber: checkpoint.blockNumber, blockHash: checkpoint.blockHash,
            });
            if (senderState.senderNonce > item.outerNonce && senderState.timestampSeconds > item.authorizationDeadline) {
              const dropped = await this.repository.markDropped({
                pending: item, checkpoint, senderNonce: senderState.senderNonce,
                checkpointTimestampSeconds: senderState.timestampSeconds,
              });
              if (dropped) { counts.dropped += 1; continue; }
            }
          }
        }
        const result = await this.repository.recordObservation({ pending: item, observation });
        if (result === 'TENTATIVE') counts.tentative += 1;
        else if (result === 'FINALIZED') counts.finalized += 1;
        else if (result === 'REORGED') counts.reorged += 1;
        else counts.unchanged += 1;
      } catch {
        counts.failed += 1;
      }
    }
    const finalized = await this.repository.listFinalizedReceipts(limit);
    for (const candidate of finalized) {
      counts.checked += 1;
      try {
        const requiredConfirmations = this.confirmationDepths[candidate.pending.chainId];
        if (requiredConfirmations === undefined) throw new Error('No finality depth is configured for the transaction chain');
        const canonical = await this.reader.getCanonicalBlockAtFinality({
          chainId: candidate.pending.chainId, blockNumber: candidate.blockNumber,
        });
        if (canonical !== null && canonical.confirmations >= requiredConfirmations
          && canonical.blockHash !== candidate.blockHash.toLowerCase()) {
          if (await this.repository.markDeepReorg({ candidate, canonicalBlockHash: canonical.blockHash })) counts.deepReorged += 1;
          else {
            await this.repository.markFinalizedReceiptChecked(candidate);
            counts.unchanged += 1;
          }
        } else {
          await this.repository.markFinalizedReceiptChecked(candidate);
          counts.unchanged += 1;
        }
      } catch {
        await this.repository.markFinalizedReceiptChecked(candidate).catch(() => undefined);
        counts.failed += 1;
      }
    }
    return counts;
  }

  private async observe(item: PendingExecutionReceipt, transactionHash: string) {
    const requiredConfirmations = this.confirmationDepths[item.chainId];
    if (requiredConfirmations === undefined) throw new Error('No finality depth is configured for the transaction chain');
    return this.reader.observe({ chainId: item.chainId, transactionHash, requiredConfirmations });
  }
}
