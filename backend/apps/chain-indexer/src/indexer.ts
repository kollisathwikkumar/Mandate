import { createHash } from 'node:crypto';
import type { Pool, PoolClient } from 'pg';
import type { EvmBlock, EvmIndexerRpc, EvmLog } from './evm-rpc.js';

interface CursorRow {
  readonly next_block: string;
  readonly finalized_block: string;
  readonly block_hash: string | null;
  readonly indexed_from_block: string | null;
}

export interface IndexerOptions {
  readonly chainId: number;
  readonly startBlock: number;
  readonly confirmations: number;
  readonly maxBlockRange: number;
}

export interface IndexerBatchResult {
  readonly chainId: number;
  readonly fromBlock: number | null;
  readonly toBlock: number | null;
  readonly indexedBlocks: number;
  readonly indexedLogs: number;
  readonly rolledBackBlocks: number;
  readonly finalizedBlock: number;
}

export const SAFE_CHANGED_GUARD_TOPIC = '0x1151116914515bc0891ff9047a6cb32cf902546f83066499bcf8ba33d2353fa2';
export const SAFE_DISABLED_MODULE_TOPIC = '0xaab4fa2b463f581b2b32cb3b7e3b704b9ce37cc209b5fb4d77e593ace4054276';
export const MANDATE_POLICY_REVOKED_TOPIC = '0x37d52e3c06b5247c58aa8438cf9ae079c88d08a0294c5e10f3d183a7988b7d41';
export const MANDATE_MODULE_CONFIGURED_TOPIC = '0x467b7feea7979d383d43a1bf41124e41c7954adb27bb9258320e8d9926ecad19';

interface ProtectedAccountRow {
  readonly organization_id: string;
  readonly id: string;
  readonly address: string;
  readonly guard_address: string;
  readonly module_address: string;
}

function integer(value: string, label: string): number {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 0) throw new Error(`Invalid stored ${label}`);
  return parsed;
}

function validate(options: IndexerOptions): void {
  if (!Number.isSafeInteger(options.chainId) || options.chainId < 1) throw new RangeError('chainId must be a positive safe integer');
  if (!Number.isSafeInteger(options.startBlock) || options.startBlock < 1) throw new RangeError('startBlock must be a positive safe integer');
  if (!Number.isSafeInteger(options.confirmations) || options.confirmations < 1 || options.confirmations > 10000) throw new RangeError('confirmations must be from 1 to 10000');
  if (!Number.isSafeInteger(options.maxBlockRange) || options.maxBlockRange < 1 || options.maxBlockRange > 2000) throw new RangeError('maxBlockRange must be from 1 to 2000');
}

function uniqueAddresses(rows: readonly { readonly address: string; readonly guard_address: string | null; readonly module_address: string | null }[]): string[] {
  return [...new Set(rows.flatMap((row) => [row.address, row.guard_address, row.module_address]
    .filter((address): address is string => address !== null)
    .map((address) => address.trim().toLowerCase())))].sort();
}

function assertLogsMatchBlocks(logs: readonly EvmLog[], blocks: ReadonlyMap<number, EvmBlock>, fromBlock: number, toBlock: number): void {
  for (const log of logs) {
    const block = blocks.get(log.blockNumber);
    if (log.blockNumber < fromBlock || log.blockNumber > toBlock || block === undefined || log.blockHash !== block.hash) {
      throw new Error('RPC log does not match the canonical scanned block');
    }
  }
}

function addressTopic(address: string): string {
  return `0x${'0'.repeat(24)}${address.trim().toLowerCase().slice(2)}`;
}

function protectionFailure(log: EvmLog, account: ProtectedAccountRow): 'SAFE_GUARD_CHANGED' | 'SAFE_MODULE_DISABLED' | 'POLICY_REVOKED' | 'AGENT_MODULE_CHANGED' | null {
  const emitter = log.address.toLowerCase();
  const safe = account.address.trim().toLowerCase();
  const guard = account.guard_address.trim().toLowerCase();
  const module = account.module_address.trim().toLowerCase();
  const topic = log.topics[0]?.toLowerCase();
  if (emitter === safe && topic === SAFE_CHANGED_GUARD_TOPIC && log.topics[1]?.toLowerCase() !== addressTopic(guard)) return 'SAFE_GUARD_CHANGED';
  if (emitter === safe && topic === SAFE_DISABLED_MODULE_TOPIC && log.topics[1]?.toLowerCase() === addressTopic(module)) return 'SAFE_MODULE_DISABLED';
  if (emitter === guard && topic === MANDATE_POLICY_REVOKED_TOPIC) return 'POLICY_REVOKED';
  if (emitter === guard && topic === MANDATE_MODULE_CONFIGURED_TOPIC && log.topics[1]?.toLowerCase() !== addressTopic(module)) return 'AGENT_MODULE_CHANGED';
  return null;
}

async function recordProtectionPause(
  client: PoolClient,
  account: ProtectedAccountRow,
  chainId: number,
  log: EvmLog,
  reasonCode: NonNullable<ReturnType<typeof protectionFailure>>,
): Promise<boolean> {
  const updated = await client.query(
    `UPDATE accounts SET status = 'PAUSED'
     WHERE organization_id = $1 AND id = $2 AND status = 'ACTIVE'`,
    [account.organization_id, account.id],
  );
  if (updated.rowCount !== 1) return false;
  await client.query('SELECT id FROM organizations WHERE id = $1 FOR UPDATE', [account.organization_id]);
  const previous = await client.query<{ event_hash: string }>(
    'SELECT event_hash FROM audit_events WHERE organization_id = $1 ORDER BY sequence DESC LIMIT 1',
    [account.organization_id],
  );
  const previousHash = previous.rows[0]?.event_hash.trim() ?? null;
  const actorId = `chain-indexer:${chainId}`;
  const payload = {
    accountId: account.id, chainId, status: 'PAUSED', reasonCode,
    blockNumber: log.blockNumber, blockHash: log.blockHash, transactionHash: log.transactionHash,
  };
  const payloadText = JSON.stringify(payload);
  const digest = createHash('sha256')
    .update(`${previousHash ?? ''}|${account.organization_id}|${actorId}|ACCOUNT_PROTECTION_PAUSED|${payloadText}`, 'utf8').digest('hex');
  const eventHash = `0x${digest}`;
  await client.query(
    `INSERT INTO audit_events (organization_id, actor_type, actor_id, event_type, subject_type, subject_id, correlation_id, payload, previous_hash, event_hash)
     VALUES ($1, 'SYSTEM', $2, 'ACCOUNT_PROTECTION_PAUSED', 'ACCOUNT', $3, $4, $5::jsonb, $6, $7)`,
    [account.organization_id, actorId, account.id, log.transactionHash, payloadText, previousHash, eventHash],
  );
  await client.query(
    `INSERT INTO outbox_events (organization_id, aggregate_type, aggregate_id, event_type, payload)
     VALUES ($1, 'ACCOUNT', $2, 'ACCOUNT_PROTECTION_PAUSED', $3::jsonb)`,
    [account.organization_id, account.id, payloadText],
  );
  return true;
}

async function applyProtectionLogs(client: PoolClient, chainId: number, logs: readonly EvmLog[]): Promise<void> {
  if (logs.length === 0) return;
  const result = await client.query<ProtectedAccountRow>(
    `SELECT organization_id, id, btrim(address) AS address, btrim(guard_address) AS guard_address,
            btrim(module_address) AS module_address FROM accounts
     WHERE chain_id = $1 AND status = 'ACTIVE' AND guard_address IS NOT NULL AND module_address IS NOT NULL`,
    [chainId],
  );
  for (const log of logs) {
    for (const account of result.rows) {
      const reasonCode = protectionFailure(log, account);
      if (reasonCode !== null) await recordProtectionPause(client, account, chainId, log, reasonCode);
    }
  }
}

export class FinalizedEvmIndexer {
  public constructor(private readonly pool: Pool, private readonly rpc: EvmIndexerRpc, private readonly options: IndexerOptions) {
    validate(options);
  }

  public async runBatch(): Promise<IndexerBatchResult> {
    const { chainId, startBlock, confirmations, maxBlockRange } = this.options;
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      await client.query('SELECT pg_advisory_xact_lock($1::bigint)', [chainId]);
      const actualChain = await this.rpc.chainId();
      if (actualChain !== chainId) throw new Error('Configured chain ID does not match RPC');

      await client.query(
        `INSERT INTO indexer_cursors (chain_id, next_block, finalized_block, block_hash, indexed_from_block)
         VALUES ($1, $2, $3, NULL, $4) ON CONFLICT (chain_id) DO NOTHING`,
        [chainId, startBlock, Math.max(0, startBlock - 1), startBlock],
      );
      const cursorResult = await client.query<CursorRow>(
        'SELECT next_block::text, finalized_block::text, block_hash, indexed_from_block::text FROM indexer_cursors WHERE chain_id = $1 FOR UPDATE',
        [chainId],
      );
      const cursor = cursorResult.rows[0];
      if (cursor === undefined) throw new Error('Indexer cursor was not initialized');
      if (cursor.indexed_from_block !== null && integer(cursor.indexed_from_block, 'indexed start block') !== startBlock) {
        throw new Error('Configured indexer start block differs from the persisted coverage boundary');
      }
      let nextBlock = integer(cursor.next_block, 'next block');
      let finalizedBlock = integer(cursor.finalized_block, 'finalized block');
      let blockHash = cursor.block_hash?.trim().toLowerCase() ?? null;
      if (nextBlock < startBlock) throw new Error('Stored cursor precedes configured start block');
      let rolledBackBlocks = 0;

      // A persisted tip is rechecked before every batch. On mismatch, find the common
      // ancestor and cascade-delete that fork's logs before rescanning canonical blocks.
      if (nextBlock > startBlock && blockHash !== null) {
        const tip = await this.rpc.block(nextBlock - 1);
        if (tip.hash !== blockHash) {
          let ancestor = startBlock - 1;
          let ancestorHash: string | null = null;
          for (let candidate = nextBlock - 2; candidate >= startBlock; candidate -= 1) {
            const saved = await client.query<{ block_hash: string }>(
              'SELECT block_hash FROM indexer_blocks WHERE chain_id = $1 AND block_number = $2',
              [chainId, candidate],
            );
            const canonical = await this.rpc.block(candidate);
            if (saved.rows[0]?.block_hash.trim().toLowerCase() === canonical.hash) {
              ancestor = candidate;
              ancestorHash = canonical.hash;
              break;
            }
          }
          const removed = await client.query(
            'DELETE FROM indexer_blocks WHERE chain_id = $1 AND block_number > $2',
            [chainId, ancestor],
          );
          rolledBackBlocks = removed.rowCount ?? 0;
          nextBlock = ancestor + 1;
          finalizedBlock = Math.min(finalizedBlock, ancestor);
          blockHash = ancestorHash;
          await client.query(
            'UPDATE indexer_cursors SET next_block = $2, finalized_block = $3, block_hash = $4, updated_at = now() WHERE chain_id = $1',
            [chainId, nextBlock, finalizedBlock, blockHash],
          );
        }
      }

      const latest = await this.rpc.latestBlock();
      const target = latest - confirmations;
      if (target < nextBlock) {
        await client.query('COMMIT');
        return { chainId, fromBlock: null, toBlock: null, indexedBlocks: 0, indexedLogs: 0, rolledBackBlocks, finalizedBlock };
      }
      const fromBlock = nextBlock;
      const toBlock = Math.min(target, fromBlock + maxBlockRange - 1);
      const blockRows: EvmBlock[] = [];
      for (let number = fromBlock; number <= toBlock; number += 1) blockRows.push(await this.rpc.block(number));
      for (let index = 1; index < blockRows.length; index += 1) {
        if (blockRows[index]?.parentHash !== blockRows[index - 1]?.hash) throw new Error('RPC returned a discontinuous block range');
      }
      if (blockHash !== null && blockRows[0]?.parentHash !== blockHash) throw new Error('RPC range does not extend the persisted canonical tip');
      const addressesResult = await client.query<{ address: string; guard_address: string | null; module_address: string | null }>(
        `SELECT address, guard_address, module_address FROM accounts WHERE chain_id = $1
         AND (guard_address IS NOT NULL OR module_address IS NOT NULL)`,
        [chainId],
      );
      const addresses = uniqueAddresses(addressesResult.rows);
      const logs = await this.rpc.logs(fromBlock, toBlock, addresses);
      const blocksByNumber = new Map(blockRows.map((block) => [block.number, block]));
      assertLogsMatchBlocks(logs, blocksByNumber, fromBlock, toBlock);

      // Re-read the scanned tip immediately before commit to detect a moving RPC view.
      const canonicalTip = await this.rpc.block(toBlock);
      if (canonicalTip.hash !== blockRows.at(-1)?.hash) throw new Error('Chain changed while indexer batch was being read');
      for (const block of blockRows) {
        await client.query(
          `INSERT INTO indexer_blocks (chain_id, block_number, block_hash, parent_hash)
           VALUES ($1, $2, $3, $4)`,
          [chainId, block.number, block.hash, block.parentHash],
        );
      }
      for (const log of logs) {
        await client.query(
          `INSERT INTO indexed_chain_logs
           (chain_id, block_number, block_hash, transaction_hash, transaction_index, log_index, address, topics, data)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
          [chainId, log.blockNumber, log.blockHash, log.transactionHash, log.transactionIndex, log.logIndex, log.address, [...log.topics], log.data],
        );
      }
      await applyProtectionLogs(client, chainId, logs);
      const newTip = blockRows.at(-1);
      if (newTip === undefined) throw new Error('Indexer batch has no block headers');
      nextBlock = toBlock + 1;
      finalizedBlock = toBlock;
      blockHash = newTip.hash;
      await client.query(
        `UPDATE indexer_cursors SET next_block = $2, finalized_block = $3, block_hash = $4, updated_at = now()
         WHERE chain_id = $1`,
        [chainId, nextBlock, finalizedBlock, blockHash],
      );
      await client.query('COMMIT');
      return { chainId, fromBlock, toBlock, indexedBlocks: blockRows.length, indexedLogs: logs.length, rolledBackBlocks, finalizedBlock };
    } catch (error: unknown) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  }
}
