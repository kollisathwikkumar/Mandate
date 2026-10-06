import { createHash } from 'node:crypto';
import type { Pool, PoolClient } from 'pg';
import type {
  ExecutionReconciliationRepository,
  ExecutionReceiptObservation,
  FinalizedReceiptCandidate,
  PendingExecutionReceipt,
} from '../../../ports/src/execution-reconciliation.js';

interface PendingRow {
  readonly organization_id: string; readonly action_id: string; readonly chain_id: string; readonly transaction_hash: string;
  readonly module_address: string; readonly agent_address: string; readonly key_version: string;
  readonly execution_nonce: string; readonly action_hash: string;
  readonly snapshot_block_number: string; readonly authorization_deadline: string;
  readonly outer_sender: string | null; readonly outer_nonce: string | null;
}
interface FinalizedReceiptRow extends PendingRow { readonly block_number: string; readonly block_hash: string; }
interface LockedRow { readonly action_state: string; readonly attempt_state: string; readonly chain_id: string; readonly transaction_hash: string | null; }
interface DroppedContextRow {
  readonly action_state: string; readonly attempt_state: string; readonly transaction_hash: string;
  readonly authorization_deadline: string; readonly snapshot_block_number: string;
  readonly outer_sender: string | null; readonly outer_nonce: string | null;
  readonly reservation_state: string; readonly module_address: string;
}
interface DeepReorgContextRow {
  readonly account_id: string; readonly account_status: string; readonly action_state: string; readonly attempt_state: string;
  readonly transaction_hash: string; readonly receipt_status: string; readonly receipt_block_number: string;
  readonly receipt_block_hash: string; readonly reservation_state: string;
}

function hash(value: string): string { return `0x${createHash('sha256').update(value, 'utf8').digest('hex')}`; }

function parsePending(row: PendingRow): PendingExecutionReceipt {
  const chainId = Number(row.chain_id);
  if (!Number.isSafeInteger(chainId) || chainId < 1) throw new Error('Stored execution chain ID is invalid');
  const pending = {
    organizationId: row.organization_id, actionId: row.action_id, chainId, transactionHash: row.transaction_hash.trim(),
    moduleAddress: row.module_address.toLowerCase(), agentAddress: row.agent_address.toLowerCase(),
    keyVersion: row.key_version, executionNonce: row.execution_nonce, actionHash: row.action_hash.toLowerCase(),
    snapshotBlockNumber: Number(row.snapshot_block_number), authorizationDeadline: Number(row.authorization_deadline),
    outerSender: row.outer_sender?.trim().toLowerCase() ?? null,
    outerNonce: row.outer_nonce === null ? null : Number(row.outer_nonce),
  };
  if (!/^0x[0-9a-f]{64}$/.test(pending.transactionHash) || !/^0x[0-9a-f]{40}$/.test(pending.moduleAddress)
    || !/^0x[0-9a-f]{40}$/.test(pending.agentAddress) || !/^\d+$/.test(pending.keyVersion)
    || !/^\d+$/.test(pending.executionNonce) || !/^0x[0-9a-f]{64}$/.test(pending.actionHash)) {
    throw new Error('Stored execution authorization is invalid');
  }
  if (!Number.isSafeInteger(pending.snapshotBlockNumber) || pending.snapshotBlockNumber < 0
    || !Number.isSafeInteger(pending.authorizationDeadline) || pending.authorizationDeadline < 1
    || (pending.outerSender !== null && !/^0x[0-9a-f]{40}$/.test(pending.outerSender))
    || (pending.outerNonce !== null && (!Number.isSafeInteger(pending.outerNonce) || pending.outerNonce < 0))
    || ((pending.outerSender === null) !== (pending.outerNonce === null))) throw new Error('Stored execution drop metadata is invalid');
  return pending;
}

async function appendEvent(client: PoolClient, input: {
  readonly organizationId: string; readonly actionId: string; readonly eventType: string;
  readonly subjectType?: string; readonly subjectId?: string; readonly aggregateType?: string; readonly aggregateId?: string;
  readonly payload: Readonly<Record<string, string | number>>;
}): Promise<void> {
  await client.query('SELECT id FROM organizations WHERE id = $1 FOR UPDATE', [input.organizationId]);
  const prior = await client.query<{ event_hash: string }>(
    'SELECT event_hash FROM audit_events WHERE organization_id = $1 ORDER BY sequence DESC LIMIT 1', [input.organizationId],
  );
  const previousHash = prior.rows[0]?.event_hash.trim() ?? null;
  const payloadText = JSON.stringify(input.payload);
  const eventHash = hash(`${previousHash ?? ''}|${input.organizationId}|system:execution-reconciler|${input.eventType}|${payloadText}`);
  await client.query(
    `INSERT INTO audit_events (organization_id, actor_type, actor_id, event_type, subject_type, subject_id, correlation_id, payload, previous_hash, event_hash)
     VALUES ($1, 'SYSTEM', 'execution-reconciler', $2, $3, $4, $5, $6::jsonb, $7, $8)`,
    [input.organizationId, input.eventType, input.subjectType ?? 'ACTION', input.subjectId ?? input.actionId,
      input.actionId, payloadText, previousHash, eventHash],
  );
  await client.query(
    `INSERT INTO outbox_events (organization_id, aggregate_type, aggregate_id, event_type, payload)
     VALUES ($1, $2, $3, $4, $5::jsonb)`,
    [input.organizationId, input.aggregateType ?? 'ACTION', input.aggregateId ?? input.actionId, input.eventType, payloadText],
  );
}

async function inTransaction<T>(pool: Pool, action: (client: PoolClient) => Promise<T>): Promise<T> {
  const client = await pool.connect();
  try { await client.query('BEGIN'); const result = await action(client); await client.query('COMMIT'); return result; }
  catch (error: unknown) { await client.query('ROLLBACK'); throw error; }
  finally { client.release(); }
}

export class ExecutionReconciliationStore implements ExecutionReconciliationRepository {
  public constructor(private readonly pool: Pool) {}

  public async listPending(limit: number): Promise<readonly PendingExecutionReceipt[]> {
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 100) throw new RangeError('limit must be an integer from 1 to 100');
    const result = await this.pool.query<PendingRow>(
      `SELECT attempt.organization_id, attempt.action_id, attempt.chain_id::text, attempt.transaction_hash
              , btrim(authz.authorization_json->>'moduleAddress') AS module_address
              , btrim(authz.authorization_json->>'agentAddress') AS agent_address
              , authz.authorization_json->>'keyVersion' AS key_version
              , authz.authorization_json->>'executionNonce' AS execution_nonce
              , btrim(authz.action_hash) AS action_hash
              , authz.snapshot_block_number::text AS snapshot_block_number
              , authz.authorization_json->>'deadline' AS authorization_deadline
              , submission.outer_sender AS outer_sender
              , submission.outer_nonce::text AS outer_nonce
       FROM execution_attempts attempt
       JOIN action_authorizations authz ON authz.organization_id = attempt.organization_id AND authz.action_id = attempt.action_id
       LEFT JOIN action_execution_submissions submission ON submission.organization_id = attempt.organization_id AND submission.action_id = attempt.action_id
       WHERE attempt.state = 'SUBMITTED' AND attempt.transaction_hash IS NOT NULL
       ORDER BY attempt.updated_at, attempt.organization_id, attempt.action_id LIMIT $1`, [limit],
    );
    return result.rows.map(parsePending);
  }

  public async listFinalizedReceipts(limit: number): Promise<readonly FinalizedReceiptCandidate[]> {
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 100) throw new RangeError('limit must be an integer from 1 to 100');
    const result = await this.pool.query<FinalizedReceiptRow>(
      `SELECT attempt.organization_id, attempt.action_id, attempt.chain_id::text, btrim(receipt.transaction_hash) AS transaction_hash,
              btrim(authz.authorization_json->>'moduleAddress') AS module_address,
              btrim(authz.authorization_json->>'agentAddress') AS agent_address,
              authz.authorization_json->>'keyVersion' AS key_version,
              authz.authorization_json->>'executionNonce' AS execution_nonce,
              btrim(authz.action_hash) AS action_hash, authz.snapshot_block_number::text AS snapshot_block_number,
              authz.authorization_json->>'deadline' AS authorization_deadline,
              submission.outer_sender, submission.outer_nonce::text AS outer_nonce,
              receipt.block_number::text AS block_number, btrim(receipt.block_hash) AS block_hash
       FROM receipts receipt
       JOIN execution_attempts attempt ON attempt.organization_id = receipt.organization_id AND attempt.action_id = receipt.action_id
       JOIN action_requests action ON action.organization_id = receipt.organization_id AND action.id = receipt.action_id
       JOIN action_authorizations authz ON authz.organization_id = receipt.organization_id AND authz.action_id = receipt.action_id
       LEFT JOIN action_execution_submissions submission ON submission.organization_id = receipt.organization_id AND submission.action_id = receipt.action_id
       JOIN indexer_cursors cursor ON cursor.chain_id = receipt.chain_id AND cursor.indexed_from_block <= receipt.block_number
         AND cursor.finalized_block >= receipt.block_number
       WHERE receipt.status = 'FINAL' AND action.state = 'RECONCILED' AND attempt.state IN ('CONFIRMED', 'REVERTED')
         AND (receipt.deep_reorg_checked_at IS NULL OR receipt.deep_reorg_checked_at <= now() - interval '1 minute')
       ORDER BY receipt.deep_reorg_checked_at NULLS FIRST, receipt.block_number, receipt.organization_id, receipt.action_id LIMIT $1`, [limit],
    );
    return result.rows.map((row) => {
      const blockNumber = Number(row.block_number);
      if (!Number.isSafeInteger(blockNumber) || blockNumber < 0 || !/^0x[0-9a-f]{64}$/.test(row.block_hash.toLowerCase())) {
        throw new Error('Stored finalized receipt checkpoint is invalid');
      }
      return { pending: parsePending(row), blockNumber, blockHash: row.block_hash.toLowerCase() };
    });
  }

  public async findCanonicalExecution(pending: PendingExecutionReceipt): Promise<string | null> {
    const agentTopic = `0x${pending.agentAddress.slice(2).padStart(64, '0')}`;
    const keyVersionTopic = `0x${BigInt(pending.keyVersion).toString(16).padStart(64, '0')}`;
    const nonceTopic = `0x${BigInt(pending.executionNonce).toString(16).padStart(64, '0')}`;
    const result = await this.pool.query<{ transaction_hash: string }>(
      `SELECT log.transaction_hash
       FROM indexed_chain_logs log
       JOIN indexer_blocks block ON block.chain_id = log.chain_id AND block.block_number = log.block_number
         AND lower(btrim(block.block_hash)) = lower(log.block_hash)
       WHERE log.chain_id = $1 AND lower(btrim(log.address)) = $2
         AND log.topics[1] = $3 AND log.topics[2] = $4 AND log.topics[3] = $5 AND log.topics[4] = $6
         AND lower(log.data) = $7
       ORDER BY log.block_number DESC, log.transaction_index DESC LIMIT 1`,
      [pending.chainId, pending.moduleAddress, '0xf8ac4b4e81cac0a2fb7dc0f50ae0205789de4f0a13336381c20e5cd71016f24b',
        agentTopic, keyVersionTopic, nonceTopic, pending.actionHash],
    );
    const hash = result.rows[0]?.transaction_hash.trim().toLowerCase();
    return hash !== undefined && /^0x[0-9a-f]{64}$/.test(hash) ? hash : null;
  }

  public async getDropCheckpoint(pending: PendingExecutionReceipt): Promise<{ readonly blockNumber: number; readonly blockHash: string } | null> {
    if (pending.outerSender === null || pending.outerNonce === null) return null;
    const result = await this.pool.query<{ block_number: string; block_hash: string }>(
      `SELECT cursor.finalized_block::text AS block_number, btrim(block.block_hash) AS block_hash
       FROM indexer_cursors cursor
       JOIN indexer_blocks block ON block.chain_id = cursor.chain_id AND block.block_number = cursor.finalized_block
         AND lower(btrim(block.block_hash)) = lower(btrim(cursor.block_hash))
       JOIN action_authorizations authz ON authz.organization_id = $2 AND authz.action_id = $3
       JOIN action_requests action ON action.organization_id = authz.organization_id AND action.id = authz.action_id
       JOIN policies policy ON policy.organization_id = action.organization_id AND policy.id = action.policy_id
       JOIN accounts account ON account.organization_id = policy.organization_id AND account.id = policy.account_id
       WHERE cursor.chain_id = $1 AND cursor.indexed_from_block IS NOT NULL
         AND cursor.indexed_from_block <= authz.snapshot_block_number
         AND cursor.finalized_block >= authz.snapshot_block_number
         AND lower(btrim(account.module_address)) = $4
       ORDER BY cursor.finalized_block DESC LIMIT 1`,
      [pending.chainId, pending.organizationId, pending.actionId, pending.moduleAddress],
    );
    const row = result.rows[0];
    if (row === undefined) return null;
    const blockNumber = Number(row.block_number);
    if (!Number.isSafeInteger(blockNumber) || blockNumber < pending.snapshotBlockNumber || !/^0x[0-9a-f]{64}$/.test(row.block_hash.toLowerCase())) return null;
    return { blockNumber, blockHash: row.block_hash.toLowerCase() };
  }

  public markDropped(input: {
    readonly pending: PendingExecutionReceipt;
    readonly checkpoint: { readonly blockNumber: number; readonly blockHash: string };
    readonly senderNonce: number;
    readonly checkpointTimestampSeconds: number;
  }): Promise<boolean> {
    return inTransaction(this.pool, async (client) => {
      const { pending, checkpoint } = input;
      if (pending.outerSender === null || pending.outerNonce === null || !Number.isSafeInteger(input.senderNonce)
        || input.senderNonce <= pending.outerNonce || !Number.isSafeInteger(input.checkpointTimestampSeconds)
        || input.checkpointTimestampSeconds <= pending.authorizationDeadline || !/^0x[0-9a-f]{64}$/.test(checkpoint.blockHash)
        || !Number.isSafeInteger(checkpoint.blockNumber) || checkpoint.blockNumber < pending.snapshotBlockNumber) return false;
      await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1, 0))', [
        `${pending.organizationId}|${pending.actionId}|receipt.reconcile|${pending.transactionHash.toLowerCase()}`,
      ]);
      const locked = await client.query<DroppedContextRow>(
        `SELECT action.state AS action_state, attempt.state AS attempt_state, btrim(attempt.transaction_hash) AS transaction_hash,
                authz.authorization_json->>'deadline' AS authorization_deadline, authz.snapshot_block_number::text AS snapshot_block_number,
                submission.outer_sender AS outer_sender, submission.outer_nonce::text AS outer_nonce,
                reservation.state AS reservation_state, btrim(account.module_address) AS module_address
         FROM action_requests action
         JOIN execution_attempts attempt ON attempt.organization_id = action.organization_id AND attempt.action_id = action.id
         JOIN action_authorizations authz ON authz.organization_id = action.organization_id AND authz.action_id = action.id
         JOIN action_execution_submissions submission ON submission.organization_id = action.organization_id AND submission.action_id = action.id
         JOIN reservations reservation ON reservation.organization_id = action.organization_id AND reservation.action_id = action.id
         JOIN policies policy ON policy.organization_id = action.organization_id AND policy.id = action.policy_id
         JOIN accounts account ON account.organization_id = policy.organization_id AND account.id = policy.account_id
         WHERE action.organization_id = $1 AND action.id = $2 AND attempt.chain_id = $3
         FOR UPDATE OF action, attempt, authz, submission, reservation, account`,
        [pending.organizationId, pending.actionId, pending.chainId],
      );
      const row = locked.rows[0];
      if (row === undefined || row.action_state !== 'SUBMITTED' || row.attempt_state !== 'SUBMITTED'
        || row.transaction_hash.toLowerCase() !== pending.transactionHash.toLowerCase()
        || row.outer_sender?.trim().toLowerCase() !== pending.outerSender
        || Number(row.outer_nonce) !== pending.outerNonce || Number(row.authorization_deadline) !== pending.authorizationDeadline
        || Number(row.snapshot_block_number) !== pending.snapshotBlockNumber || row.reservation_state !== 'ACTIVE'
        || row.module_address.toLowerCase() !== pending.moduleAddress) return false;

      const coverage = await client.query<{ indexed_from_block: string | null; finalized_block: string; block_hash: string }>(
        `SELECT cursor.indexed_from_block::text, cursor.finalized_block::text, btrim(block.block_hash) AS block_hash
         FROM indexer_cursors cursor JOIN indexer_blocks block
           ON block.chain_id = cursor.chain_id AND block.block_number = $2
         WHERE cursor.chain_id = $1 AND cursor.finalized_block >= $2
           AND lower(btrim(block.block_hash)) = $3
           AND lower(btrim(block.block_hash)) = lower(btrim(cursor.block_hash))
         FOR SHARE OF cursor, block`,
        [pending.chainId, checkpoint.blockNumber, checkpoint.blockHash],
      );
      const indexed = coverage.rows[0];
      if (indexed === undefined || indexed.indexed_from_block === null
        || Number(indexed.indexed_from_block) > pending.snapshotBlockNumber
        || Number(indexed.finalized_block) < checkpoint.blockNumber
        || indexed.block_hash.trim().toLowerCase() !== checkpoint.blockHash) return false;

      const agentTopic = `0x${pending.agentAddress.slice(2).padStart(64, '0')}`;
      const keyVersionTopic = `0x${BigInt(pending.keyVersion).toString(16).padStart(64, '0')}`;
      const nonceTopic = `0x${BigInt(pending.executionNonce).toString(16).padStart(64, '0')}`;
      const event = await client.query(
        `SELECT 1 FROM indexed_chain_logs log
         WHERE log.chain_id = $1 AND log.block_number <= $2 AND lower(btrim(log.address)) = $3
           AND log.topics[1] = $4 AND log.topics[2] = $5 AND log.topics[3] = $6 AND log.topics[4] = $7
           AND lower(log.data) = $8 LIMIT 1`,
        [pending.chainId, checkpoint.blockNumber, pending.moduleAddress,
          '0xf8ac4b4e81cac0a2fb7dc0f50ae0205789de4f0a13336381c20e5cd71016f24b',
          agentTopic, keyVersionTopic, nonceTopic, pending.actionHash],
      );
      if ((event.rowCount ?? 0) > 0) return false;

      const attempt = await client.query(
        `UPDATE execution_attempts SET state = 'DROPPED', updated_at = now()
         WHERE organization_id = $1 AND action_id = $2 AND state = 'SUBMITTED'`, [pending.organizationId, pending.actionId],
      );
      const dropped = await client.query(
        `UPDATE action_requests SET state = 'DROPPED', updated_at = now()
         WHERE organization_id = $1 AND id = $2 AND state = 'SUBMITTED'`, [pending.organizationId, pending.actionId],
      );
      const reconciled = await client.query(
        `UPDATE action_requests SET state = 'RECONCILED', updated_at = now()
         WHERE organization_id = $1 AND id = $2 AND state = 'DROPPED'`, [pending.organizationId, pending.actionId],
      );
      const reservation = await client.query(
        `UPDATE reservations SET state = 'RELEASED', updated_at = now()
         WHERE organization_id = $1 AND action_id = $2 AND state = 'ACTIVE'`, [pending.organizationId, pending.actionId],
      );
      if ([attempt, dropped, reconciled, reservation].some((result) => (result.rowCount ?? 0) !== 1)) {
        throw new Error('Dropped execution did not settle all lifecycle rows exactly once');
      }
      await appendEvent(client, { organizationId: pending.organizationId, actionId: pending.actionId, eventType: 'ACTION_DROPPED',
        payload: { actionId: pending.actionId, transactionHash: pending.transactionHash.toLowerCase(),
          senderNonce: input.senderNonce, blockNumber: checkpoint.blockNumber, blockHash: checkpoint.blockHash } });
      return true;
    });
  }

  public async markFinalizedReceiptChecked(candidate: FinalizedReceiptCandidate): Promise<void> {
    await this.pool.query(
      `UPDATE receipts SET deep_reorg_checked_at = now()
       WHERE organization_id = $1 AND action_id = $2 AND chain_id = $3 AND transaction_hash = $4
         AND block_number = $5 AND lower(btrim(block_hash)) = $6 AND status = 'FINAL'`,
      [candidate.pending.organizationId, candidate.pending.actionId, candidate.pending.chainId,
        candidate.pending.transactionHash.toLowerCase(), candidate.blockNumber, candidate.blockHash.toLowerCase()],
    );
  }

  public markDeepReorg(input: { readonly candidate: FinalizedReceiptCandidate; readonly canonicalBlockHash: string }): Promise<boolean> {
    return inTransaction(this.pool, async (client) => {
      const { candidate, canonicalBlockHash } = input;
      const { pending } = candidate;
      if (!/^0x[0-9a-f]{64}$/.test(candidate.blockHash) || !/^0x[0-9a-f]{64}$/.test(canonicalBlockHash)
        || canonicalBlockHash === candidate.blockHash || !Number.isSafeInteger(candidate.blockNumber) || candidate.blockNumber < 0) return false;
      await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1, 0))', [
        `${pending.organizationId}|${pending.actionId}|receipt.reconcile|${pending.transactionHash.toLowerCase()}`,
      ]);
      const locked = await client.query<DeepReorgContextRow>(
        `SELECT account.id AS account_id, account.status AS account_status, action.state AS action_state, attempt.state AS attempt_state,
                btrim(receipt.transaction_hash) AS transaction_hash, receipt.status AS receipt_status,
                receipt.block_number::text AS receipt_block_number, lower(btrim(receipt.block_hash)) AS receipt_block_hash,
                reservation.state AS reservation_state
         FROM action_requests action
         JOIN execution_attempts attempt ON attempt.organization_id = action.organization_id AND attempt.action_id = action.id
         JOIN receipts receipt ON receipt.organization_id = action.organization_id AND receipt.action_id = action.id AND receipt.chain_id = attempt.chain_id
         JOIN reservations reservation ON reservation.organization_id = action.organization_id AND reservation.action_id = action.id
         JOIN policies policy ON policy.organization_id = action.organization_id AND policy.id = action.policy_id
         JOIN accounts account ON account.organization_id = policy.organization_id AND account.id = policy.account_id
         WHERE action.organization_id = $1 AND action.id = $2 AND attempt.chain_id = $3
           AND receipt.transaction_hash = $4
         FOR UPDATE OF action, attempt, receipt, reservation, account`,
        [pending.organizationId, pending.actionId, pending.chainId, pending.transactionHash.toLowerCase()],
      );
      const row = locked.rows[0];
      if (row === undefined || row.action_state !== 'RECONCILED' || !['CONFIRMED', 'REVERTED'].includes(row.attempt_state)
        || row.receipt_status !== 'FINAL' || Number(row.receipt_block_number) !== candidate.blockNumber
        || row.receipt_block_hash !== candidate.blockHash || row.reservation_state !== (row.attempt_state === 'CONFIRMED' ? 'CONSUMED' : 'RELEASED')) {
        return false;
      }
      const canonical = await client.query<{ indexed_from_block: string | null; finalized_block: string; block_hash: string }>(
        `SELECT cursor.indexed_from_block::text, cursor.finalized_block::text, lower(btrim(block.block_hash)) AS block_hash
         FROM indexer_cursors cursor JOIN indexer_blocks block ON block.chain_id = cursor.chain_id AND block.block_number = $2
         WHERE cursor.chain_id = $1 AND cursor.finalized_block >= $2 AND cursor.indexed_from_block <= $2
           AND lower(btrim(block.block_hash)) = $3
         FOR SHARE OF cursor, block`,
        [pending.chainId, candidate.blockNumber, canonicalBlockHash],
      );
      const canonicalRow = canonical.rows[0];
      if (canonicalRow === undefined || Number(canonicalRow.finalized_block) < candidate.blockNumber
        || canonicalRow.block_hash !== canonicalBlockHash) return false;

      const receipt = await client.query(
        `UPDATE receipts SET status = 'REORGED', deep_reorg_checked_at = now(), observed_at = now()
         WHERE organization_id = $1 AND action_id = $2 AND chain_id = $3 AND transaction_hash = $4 AND status = 'FINAL'`,
        [pending.organizationId, pending.actionId, pending.chainId, pending.transactionHash.toLowerCase()],
      );
      const attempt = await client.query(
        `UPDATE execution_attempts SET state = 'REORGED', updated_at = now()
         WHERE organization_id = $1 AND action_id = $2 AND chain_id = $3 AND state IN ('CONFIRMED', 'REVERTED')`,
        [pending.organizationId, pending.actionId, pending.chainId],
      );
      const action = await client.query(
        `UPDATE action_requests SET state = 'REORGED', updated_at = now()
         WHERE organization_id = $1 AND id = $2 AND state = 'RECONCILED'`, [pending.organizationId, pending.actionId],
      );
      const reservation = await client.query(
        `UPDATE reservations SET state = 'ACTIVE', updated_at = now()
         WHERE organization_id = $1 AND action_id = $2 AND state IN ('CONSUMED', 'RELEASED')`,
        [pending.organizationId, pending.actionId],
      );
      if ([receipt, attempt, action, reservation].some((result) => (result.rowCount ?? 0) !== 1)) {
        throw new Error('Deep-reorg compensation did not update every lifecycle row exactly once');
      }
      await appendEvent(client, { organizationId: pending.organizationId, actionId: pending.actionId,
        eventType: 'ACTION_DEEP_REORG_DETECTED', payload: { actionId: pending.actionId,
          transactionHash: pending.transactionHash.toLowerCase(), blockNumber: candidate.blockNumber,
          previousBlockHash: candidate.blockHash, canonicalBlockHash } });
      if (row.account_status === 'ACTIVE') {
        const paused = await client.query(
          `UPDATE accounts SET status = 'PAUSED' WHERE organization_id = $1 AND id = $2 AND status = 'ACTIVE'`,
          [pending.organizationId, row.account_id],
        );
        if ((paused.rowCount ?? 0) !== 1) throw new Error('Affected account was not paused during deep-reorg compensation');
        await appendEvent(client, { organizationId: pending.organizationId, actionId: pending.actionId,
          eventType: 'ACCOUNT_PROTECTION_PAUSED', subjectType: 'ACCOUNT', subjectId: row.account_id,
          aggregateType: 'ACCOUNT', aggregateId: row.account_id,
          payload: { accountId: row.account_id, actionId: pending.actionId, reasonCode: 'FINALIZED_RECEIPT_REORGED',
            blockNumber: candidate.blockNumber, previousBlockHash: candidate.blockHash, canonicalBlockHash } });
      }
      return true;
    });
  }

  public recordObservation(input: {
    readonly pending: PendingExecutionReceipt;
    readonly observation: ExecutionReceiptObservation | null;
  }): Promise<'TENTATIVE' | 'FINALIZED' | 'REORGED' | 'UNCHANGED'> {
    return inTransaction(this.pool, async (client) => {
      await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1, 0))', [
        `${input.pending.organizationId}|${input.pending.actionId}|receipt.reconcile|${input.pending.transactionHash.toLowerCase()}`,
      ]);
      const locked = await client.query<LockedRow>(
        `SELECT action.state AS action_state, attempt.state AS attempt_state,
                attempt.chain_id::text, attempt.transaction_hash
         FROM action_requests action JOIN execution_attempts attempt
           ON attempt.organization_id = action.organization_id AND attempt.action_id = action.id
         WHERE action.organization_id = $1 AND action.id = $2 AND attempt.chain_id = $3
         FOR UPDATE OF action, attempt`,
        [input.pending.organizationId, input.pending.actionId, input.pending.chainId],
      );
      const row = locked.rows[0];
      if (row === undefined || row.transaction_hash?.trim().toLowerCase() !== input.pending.transactionHash.toLowerCase()) return 'UNCHANGED';
      if (row.attempt_state !== 'SUBMITTED' || row.action_state !== 'SUBMITTED') return 'UNCHANGED';

      if (input.observation === null) {
        const changed = await client.query(
          `UPDATE receipts SET status = 'REORGED', observed_at = now()
           WHERE organization_id = $1 AND action_id = $2 AND chain_id = $3 AND transaction_hash = $4 AND status = 'TENTATIVE'`,
          [input.pending.organizationId, input.pending.actionId, input.pending.chainId, input.pending.transactionHash.toLowerCase()],
        );
        if ((changed.rowCount ?? 0) > 0) {
          await appendEvent(client, { organizationId: input.pending.organizationId, actionId: input.pending.actionId,
            eventType: 'ACTION_RECEIPT_REORGED', payload: { actionId: input.pending.actionId, transactionHash: input.pending.transactionHash.toLowerCase() } });
          return 'REORGED';
        }
        return 'UNCHANGED';
      }

      const observation = input.observation;
      if (!/^0x[0-9a-f]{64}$/.test(observation.transactionHash)
        || !/^0x[0-9a-f]{64}$/.test(observation.blockHash) || !Number.isSafeInteger(observation.blockNumber) || observation.blockNumber < 0
        || !Number.isSafeInteger(observation.confirmations) || observation.confirmations < 1) throw new Error('Receipt observation is malformed or does not match the submitted transaction');
      if (observation.transactionHash !== input.pending.transactionHash.toLowerCase()
        && await this.findCanonicalExecution(input.pending) !== observation.transactionHash) {
        throw new Error('Replacement receipt is not proven by a canonical indexed AgentActionExecuted event');
      }
      if (observation.transactionHash !== input.pending.transactionHash.toLowerCase() && observation.executionResult !== 'SUCCESS') {
        throw new Error('Canonical AgentActionExecuted replacement must have a successful transaction receipt');
      }

      const priorReceipt = await client.query<{ status: string; block_hash: string }>(
        'SELECT status, block_hash FROM receipts WHERE chain_id = $1 AND transaction_hash = $2 FOR UPDATE',
        [input.pending.chainId, observation.transactionHash],
      );
      const prior = priorReceipt.rows[0];
      const receiptChanged = prior === undefined || prior.status === 'REORGED' || prior.block_hash.trim().toLowerCase() !== observation.blockHash;
      const receipt = await client.query<{ id: string }>(
        `INSERT INTO receipts (organization_id, action_id, chain_id, transaction_hash, block_number, block_hash, status, receipt_json)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb)
         ON CONFLICT (chain_id, transaction_hash) DO UPDATE
           SET block_number = EXCLUDED.block_number, block_hash = EXCLUDED.block_hash, status = EXCLUDED.status,
               receipt_json = EXCLUDED.receipt_json, observed_at = now()
           WHERE receipts.organization_id = EXCLUDED.organization_id AND receipts.action_id = EXCLUDED.action_id
         RETURNING id::text`,
        [input.pending.organizationId, input.pending.actionId, input.pending.chainId, observation.transactionHash,
          observation.blockNumber, observation.blockHash, observation.status, JSON.stringify(observation.receipt)],
      );
      if (receipt.rows[0] === undefined) throw new Error('Receipt hash is already associated with a different action');
      if (observation.status === 'TENTATIVE') {
        if (receiptChanged) await appendEvent(client, { organizationId: input.pending.organizationId, actionId: input.pending.actionId,
          eventType: 'ACTION_RECEIPT_TENTATIVE', payload: { actionId: input.pending.actionId,
            transactionHash: observation.transactionHash, blockNumber: observation.blockNumber, blockHash: observation.blockHash,
            confirmations: observation.confirmations } });
        return 'TENTATIVE';
      }

      const outcome = observation.executionResult === 'SUCCESS' ? 'CONFIRMED' : 'REVERTED';
      const transitioned = await client.query(
        `UPDATE execution_attempts SET transaction_hash = $5, state = $4, updated_at = now()
         WHERE organization_id = $1 AND action_id = $2 AND chain_id = $3 AND state = 'SUBMITTED'`,
        [input.pending.organizationId, input.pending.actionId, input.pending.chainId, outcome, observation.transactionHash],
      );
      if ((transitioned.rowCount ?? 0) !== 1) throw new Error('Execution attempt did not transition from SUBMITTED exactly once');
      const transitionedAction = await client.query(`UPDATE action_requests SET state = $3, updated_at = now() WHERE organization_id = $1 AND id = $2 AND state = 'SUBMITTED'`,
        [input.pending.organizationId, input.pending.actionId, outcome]);
      if ((transitionedAction.rowCount ?? 0) !== 1) throw new Error('Action did not transition from SUBMITTED exactly once');
      const reconciledAction = await client.query(`UPDATE action_requests SET state = 'RECONCILED', updated_at = now() WHERE organization_id = $1 AND id = $2 AND state = $3`,
        [input.pending.organizationId, input.pending.actionId, outcome]);
      if ((reconciledAction.rowCount ?? 0) !== 1) throw new Error('Action did not transition to RECONCILED exactly once');
      const reservationState = observation.executionResult === 'SUCCESS' ? 'CONSUMED' : 'RELEASED';
      const updatedReservation = await client.query(
        `UPDATE reservations SET state = $3, updated_at = now() WHERE organization_id = $1 AND action_id = $2 AND state = 'ACTIVE'`,
        [input.pending.organizationId, input.pending.actionId, reservationState],
      );
      if ((updatedReservation.rowCount ?? 0) !== 1) throw new Error('Active reservation did not settle exactly once');
      const eventType = observation.executionResult === 'SUCCESS' ? 'ACTION_RECONCILED' : 'ACTION_REVERTED';
      if (observation.transactionHash !== input.pending.transactionHash.toLowerCase()) {
        await appendEvent(client, { organizationId: input.pending.organizationId, actionId: input.pending.actionId,
          eventType: 'ACTION_TRANSACTION_REPLACED', payload: { actionId: input.pending.actionId,
            submittedTransactionHash: input.pending.transactionHash.toLowerCase(), transactionHash: observation.transactionHash } });
      }
      await appendEvent(client, { organizationId: input.pending.organizationId, actionId: input.pending.actionId, eventType,
        payload: { actionId: input.pending.actionId, transactionHash: observation.transactionHash, blockNumber: observation.blockNumber,
          blockHash: observation.blockHash, confirmations: observation.confirmations, reservationState } });
      return 'FINALIZED';
    });
  }
}
