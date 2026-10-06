import { describe, expect, it, vi } from 'vitest';
import { ExecutionReconciliationService } from '../src/execution-reconciliation-service.js';
import type { ExecutionReconciliationRepository, ExecutionReceiptReader, PendingExecutionReceipt } from '../../ports/src/execution-reconciliation.js';

const pending: PendingExecutionReceipt = {
  organizationId: 'org-a', actionId: 'action-a', chainId: 31337,
  transactionHash: `0x${'a'.repeat(64)}`,
  moduleAddress: `0x${'b'.repeat(40)}`, agentAddress: `0x${'c'.repeat(40)}`,
  keyVersion: '1', executionNonce: '7', actionHash: `0x${'d'.repeat(64)}`,
  snapshotBlockNumber: 100, authorizationDeadline: 2_000_000_000,
  outerSender: null, outerNonce: null,
};

describe('ExecutionReconciliationService', () => {
  it('marks an unobserved execution dropped only after finalized sender-nonce consumption and authorization expiry', async () => {
    const eligible: PendingExecutionReceipt = { ...pending, outerSender: `0x${'9'.repeat(40)}`, outerNonce: 4 };
    const checkpoint = { blockNumber: 200, blockHash: `0x${'8'.repeat(64)}` };
    const reader: ExecutionReceiptReader = {
      observe: vi.fn().mockResolvedValue(null),
      getSenderNonceAtCheckpoint: vi.fn().mockResolvedValue({ senderNonce: 5, timestampSeconds: eligible.authorizationDeadline + 1 }),
      getCanonicalBlockAtFinality: vi.fn(),
    };
    const repository: ExecutionReconciliationRepository = {
      listPending: vi.fn().mockResolvedValue([eligible]), findCanonicalExecution: vi.fn().mockResolvedValue(null),
      getDropCheckpoint: vi.fn().mockResolvedValue(checkpoint), markDropped: vi.fn().mockResolvedValue(true),
      listFinalizedReceipts: vi.fn().mockResolvedValue([]), markDeepReorg: vi.fn(), markFinalizedReceiptChecked: vi.fn(),
      recordObservation: vi.fn(),
    };
    const service = new ExecutionReconciliationService(repository, reader, { 31337: 12 });
    await expect(service.runBatch()).resolves.toEqual({ checked: 1, tentative: 0, finalized: 0, dropped: 1, deepReorged: 0, reorged: 0, unchanged: 0, failed: 0 });
    expect(reader.getSenderNonceAtCheckpoint).toHaveBeenCalledWith({ chainId: eligible.chainId, sender: eligible.outerSender,
      blockNumber: checkpoint.blockNumber, blockHash: checkpoint.blockHash });
    expect(repository.markDropped).toHaveBeenCalledWith({ pending: eligible, checkpoint, senderNonce: 5,
      checkpointTimestampSeconds: eligible.authorizationDeadline + 1 });
    expect(repository.recordObservation).not.toHaveBeenCalled();
  });

  it('keeps an unobserved transaction pending until its authorization deadline has passed at the checkpoint', async () => {
    const eligible: PendingExecutionReceipt = { ...pending, outerSender: `0x${'9'.repeat(40)}`, outerNonce: 4 };
    const reader: ExecutionReceiptReader = {
      observe: vi.fn().mockResolvedValue(null),
      getSenderNonceAtCheckpoint: vi.fn().mockResolvedValue({ senderNonce: 5, timestampSeconds: eligible.authorizationDeadline }),
      getCanonicalBlockAtFinality: vi.fn(),
    };
    const repository: ExecutionReconciliationRepository = {
      listPending: vi.fn().mockResolvedValue([eligible]), findCanonicalExecution: vi.fn().mockResolvedValue(null),
      getDropCheckpoint: vi.fn().mockResolvedValue({ blockNumber: 200, blockHash: `0x${'8'.repeat(64)}` }),
      markDropped: vi.fn(), recordObservation: vi.fn().mockResolvedValue('UNCHANGED'),
      listFinalizedReceipts: vi.fn().mockResolvedValue([]), markDeepReorg: vi.fn(), markFinalizedReceiptChecked: vi.fn(),
    };
    const service = new ExecutionReconciliationService(repository, reader, { 31337: 12 });
    await expect(service.runBatch()).resolves.toMatchObject({ dropped: 0, unchanged: 1, failed: 0 });
    expect(repository.markDropped).not.toHaveBeenCalled();
    expect(repository.recordObservation).toHaveBeenCalledWith({ pending: eligible, observation: null });
  });

  it('uses the chain-specific finality depth and records a tentative receipt', async () => {
    const reader: ExecutionReceiptReader = { observe: vi.fn().mockResolvedValue(null), getSenderNonceAtCheckpoint: vi.fn(), getCanonicalBlockAtFinality: vi.fn() };
    const repository: ExecutionReconciliationRepository = {
      listPending: vi.fn().mockResolvedValue([pending]),
      findCanonicalExecution: vi.fn().mockResolvedValue(null),
      getDropCheckpoint: vi.fn().mockResolvedValue(null), markDropped: vi.fn(),
      listFinalizedReceipts: vi.fn().mockResolvedValue([]), markDeepReorg: vi.fn(), markFinalizedReceiptChecked: vi.fn(),
      recordObservation: vi.fn().mockResolvedValue('UNCHANGED'),
    };
    const service = new ExecutionReconciliationService(repository, reader, { 31337: 12 });
    await expect(service.runBatch(10)).resolves.toEqual({ checked: 1, tentative: 0, finalized: 0, dropped: 0, deepReorged: 0, reorged: 0, unchanged: 1, failed: 0 });
    expect(reader.observe).toHaveBeenCalledWith({ chainId: 31337, transactionHash: pending.transactionHash, requiredConfirmations: 12 });
    expect(repository.recordObservation).toHaveBeenCalledWith({ pending, observation: null });
  });

  it('fails closed for a chain without a configured confirmation depth and continues the batch', async () => {
    const reader: ExecutionReceiptReader = { observe: vi.fn(), getSenderNonceAtCheckpoint: vi.fn(), getCanonicalBlockAtFinality: vi.fn() };
    const repository: ExecutionReconciliationRepository = {
      listPending: vi.fn().mockResolvedValue([pending]),
      findCanonicalExecution: vi.fn(),
      getDropCheckpoint: vi.fn(), markDropped: vi.fn(),
      listFinalizedReceipts: vi.fn().mockResolvedValue([]), markDeepReorg: vi.fn(), markFinalizedReceiptChecked: vi.fn(),
      recordObservation: vi.fn(),
    };
    const service = new ExecutionReconciliationService(repository, reader, {});
    await expect(service.runBatch()).resolves.toEqual({ checked: 1, tentative: 0, finalized: 0, dropped: 0, deepReorged: 0, reorged: 0, unchanged: 0, failed: 1 });
    expect(reader.observe).not.toHaveBeenCalled();
    expect(repository.recordObservation).not.toHaveBeenCalled();
  });

  it('rejects invalid polling batch sizes', async () => {
    const service = new ExecutionReconciliationService(
      { listPending: vi.fn(), findCanonicalExecution: vi.fn(), getDropCheckpoint: vi.fn(), markDropped: vi.fn(),
        listFinalizedReceipts: vi.fn(), markDeepReorg: vi.fn(), markFinalizedReceiptChecked: vi.fn(), recordObservation: vi.fn() },
      { observe: vi.fn(), getSenderNonceAtCheckpoint: vi.fn(), getCanonicalBlockAtFinality: vi.fn() }, {},
    );
    await expect(service.runBatch(101)).rejects.toThrow('limit must be an integer from 1 to 100');
  });

  it('reconciles the canonical transaction that emitted the exact authorized module event', async () => {
    const replacementHash = `0x${'e'.repeat(64)}`;
    const observation = {
      transactionHash: replacementHash, blockNumber: 500, blockHash: `0x${'f'.repeat(64)}`,
      status: 'FINAL' as const, executionResult: 'SUCCESS' as const, confirmations: 12,
      receipt: { status: 'SUCCESS' },
    };
    const reader: ExecutionReceiptReader = { observe: vi.fn().mockResolvedValueOnce(null).mockResolvedValueOnce(observation), getSenderNonceAtCheckpoint: vi.fn(), getCanonicalBlockAtFinality: vi.fn() };
    const repository: ExecutionReconciliationRepository = {
      listPending: vi.fn().mockResolvedValue([pending]),
      findCanonicalExecution: vi.fn().mockResolvedValue(replacementHash),
      getDropCheckpoint: vi.fn(), markDropped: vi.fn(),
      listFinalizedReceipts: vi.fn().mockResolvedValue([]), markDeepReorg: vi.fn(), markFinalizedReceiptChecked: vi.fn(),
      recordObservation: vi.fn().mockResolvedValue('FINALIZED'),
    };
    const service = new ExecutionReconciliationService(repository, reader, { 31337: 12 });
    await expect(service.runBatch()).resolves.toMatchObject({ checked: 1, finalized: 1, failed: 0 });
    expect(reader.observe).toHaveBeenNthCalledWith(1, { chainId: 31337, transactionHash: pending.transactionHash, requiredConfirmations: 12 });
    expect(reader.observe).toHaveBeenNthCalledWith(2, { chainId: 31337, transactionHash: replacementHash, requiredConfirmations: 12 });
    expect(repository.recordObservation).toHaveBeenCalledWith({ pending, observation });
  });

  it('compensates a previously finalized receipt only after the replacement canonical block meets finality', async () => {
    const candidate = { pending, blockNumber: 500, blockHash: `0x${'f'.repeat(64)}` };
    const canonicalBlockHash = `0x${'e'.repeat(64)}`;
    const reader: ExecutionReceiptReader = {
      observe: vi.fn(), getSenderNonceAtCheckpoint: vi.fn(),
      getCanonicalBlockAtFinality: vi.fn().mockResolvedValue({ blockHash: canonicalBlockHash, confirmations: 12 }),
    };
    const repository: ExecutionReconciliationRepository = {
      listPending: vi.fn().mockResolvedValue([]), findCanonicalExecution: vi.fn(), getDropCheckpoint: vi.fn(), markDropped: vi.fn(),
      listFinalizedReceipts: vi.fn().mockResolvedValue([candidate]), markDeepReorg: vi.fn().mockResolvedValue(true),
      markFinalizedReceiptChecked: vi.fn(), recordObservation: vi.fn(),
    };
    const service = new ExecutionReconciliationService(repository, reader, { 31337: 12 });
    await expect(service.runBatch()).resolves.toEqual({ checked: 1, tentative: 0, finalized: 0, dropped: 0,
      deepReorged: 1, reorged: 0, unchanged: 0, failed: 0 });
    expect(repository.markDeepReorg).toHaveBeenCalledWith({ candidate, canonicalBlockHash });
    expect(repository.markFinalizedReceiptChecked).not.toHaveBeenCalled();
  });

  it('does not compensate a deep reorg before the replacement block reaches configured finality', async () => {
    const candidate = { pending, blockNumber: 500, blockHash: `0x${'f'.repeat(64)}` };
    const reader: ExecutionReceiptReader = {
      observe: vi.fn(), getSenderNonceAtCheckpoint: vi.fn(),
      getCanonicalBlockAtFinality: vi.fn().mockResolvedValue({ blockHash: `0x${'e'.repeat(64)}`, confirmations: 11 }),
    };
    const repository: ExecutionReconciliationRepository = {
      listPending: vi.fn().mockResolvedValue([]), findCanonicalExecution: vi.fn(), getDropCheckpoint: vi.fn(), markDropped: vi.fn(),
      listFinalizedReceipts: vi.fn().mockResolvedValue([candidate]), markDeepReorg: vi.fn(),
      markFinalizedReceiptChecked: vi.fn(), recordObservation: vi.fn(),
    };
    const service = new ExecutionReconciliationService(repository, reader, { 31337: 12 });
    await expect(service.runBatch()).resolves.toMatchObject({ deepReorged: 0, unchanged: 1, failed: 0 });
    expect(repository.markDeepReorg).not.toHaveBeenCalled();
    expect(repository.markFinalizedReceiptChecked).toHaveBeenCalledWith(candidate);
  });
});
