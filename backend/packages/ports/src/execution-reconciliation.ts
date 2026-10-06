import type { JsonObject } from '../../domain/src/json-value.js';

export interface PendingExecutionReceipt {
  readonly organizationId: string;
  readonly actionId: string;
  readonly chainId: number;
  readonly transactionHash: string;
  readonly moduleAddress: string;
  readonly agentAddress: string;
  readonly keyVersion: string;
  readonly executionNonce: string;
  readonly actionHash: string;
  readonly snapshotBlockNumber: number;
  readonly authorizationDeadline: number;
  readonly outerSender: string | null;
  readonly outerNonce: number | null;
}

export interface FinalizedDropCheckpoint {
  readonly blockNumber: number;
  readonly blockHash: string;
}

export interface FinalizedSenderNonce {
  readonly senderNonce: number;
  readonly timestampSeconds: number;
}

export interface FinalizedReceiptCandidate {
  readonly pending: PendingExecutionReceipt;
  readonly blockNumber: number;
  readonly blockHash: string;
}

export interface CanonicalBlockCheckpoint {
  readonly blockHash: string;
  readonly confirmations: number;
}

export interface ExecutionReceiptObservation {
  readonly transactionHash: string;
  readonly blockNumber: number;
  readonly blockHash: string;
  readonly status: 'TENTATIVE' | 'FINAL';
  readonly executionResult: 'SUCCESS' | 'REVERTED';
  readonly confirmations: number;
  readonly receipt: JsonObject;
}

export interface ExecutionReceiptReader {
  observe(input: { readonly chainId: number; readonly transactionHash: string; readonly requiredConfirmations: number }): Promise<ExecutionReceiptObservation | null>;
  getSenderNonceAtCheckpoint(input: {
    readonly chainId: number; readonly sender: string; readonly blockNumber: number; readonly blockHash: string;
  }): Promise<FinalizedSenderNonce>;
  getCanonicalBlockAtFinality(input: { readonly chainId: number; readonly blockNumber: number }): Promise<CanonicalBlockCheckpoint | null>;
}

export interface ExecutionReconciliationRepository {
  listPending(limit: number): Promise<readonly PendingExecutionReceipt[]>;
  findCanonicalExecution(pending: PendingExecutionReceipt): Promise<string | null>;
  getDropCheckpoint(pending: PendingExecutionReceipt): Promise<FinalizedDropCheckpoint | null>;
  markDropped(input: {
    readonly pending: PendingExecutionReceipt;
    readonly checkpoint: FinalizedDropCheckpoint;
    readonly senderNonce: number;
    readonly checkpointTimestampSeconds: number;
  }): Promise<boolean>;
  listFinalizedReceipts(limit: number): Promise<readonly FinalizedReceiptCandidate[]>;
  markDeepReorg(input: { readonly candidate: FinalizedReceiptCandidate; readonly canonicalBlockHash: string }): Promise<boolean>;
  markFinalizedReceiptChecked(candidate: FinalizedReceiptCandidate): Promise<void>;
  recordObservation(input: {
    readonly pending: PendingExecutionReceipt;
    readonly observation: ExecutionReceiptObservation | null;
  }): Promise<'TENTATIVE' | 'FINALIZED' | 'REORGED' | 'UNCHANGED'>;
}

export interface ExecutionReconciliationResult {
  readonly checked: number;
  readonly tentative: number;
  readonly finalized: number;
  readonly dropped: number;
  readonly deepReorged: number;
  readonly reorged: number;
  readonly unchanged: number;
  readonly failed: number;
}
