import { randomUUID } from 'node:crypto';
import { Client, Pool } from 'pg';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { migrate } from '../../../packages/adapters/src/postgres/migrate.js';
import type { EvmBlock, EvmIndexerRpc, EvmLog } from '../src/evm-rpc.js';
import { FinalizedEvmIndexer, SAFE_CHANGED_GUARD_TOPIC } from '../src/indexer.js';

const connectionString = process.env.DATABASE_URL;
const hash = (label: string): string => `0x${Buffer.from(label).toString('hex').padStart(64, '0').slice(-64)}`;
const address = (digit: string): string => `0x${digit.repeat(40)}`;

class FakeRpc implements EvmIndexerRpc {
  public forked = false;
  public readonly chain = 1_000_000 + Math.floor(Math.random() * 1_000_000_000);
  public async chainId(): Promise<number> { return this.chain; }
  public async latestBlock(): Promise<number> { return 10; }
  public async block(number: number): Promise<EvmBlock> {
    const variant = this.forked && number >= 7 ? 'fork-' : 'base-';
    return {
      number,
      hash: hash(`${variant}${number}`),
      parentHash: number === 0 ? hash('genesis-parent') : hash(`${this.forked && number - 1 >= 7 ? 'fork-' : 'base-'}${number - 1}`),
    };
  }
  public async logs(fromBlock: number, toBlock: number, addresses: readonly string[]): Promise<readonly EvmLog[]> {
    const target = address('a');
    if (this.forked || !addresses.includes(target) || fromBlock > 7 || toBlock < 7) return [];
    return [
      {
        blockNumber: 6,
        blockHash: (await this.block(6)).hash,
        transactionHash: hash('expected-guard'),
        transactionIndex: 0,
        logIndex: 0,
        address: target,
        topics: [SAFE_CHANGED_GUARD_TOPIC, `0x${'0'.repeat(24)}${'b'.repeat(40)}`],
        data: '0x',
      },
      {
        blockNumber: 7,
        blockHash: (await this.block(7)).hash,
        transactionHash: hash('old-log'),
        transactionIndex: 0,
        logIndex: 0,
        address: target,
        topics: [SAFE_CHANGED_GUARD_TOPIC, `0x${'0'.repeat(64)}`],
        data: '0x',
      },
    ];
  }
}

describe.skipIf(connectionString === undefined)('finalized EVM chain indexer (PostgreSQL integration)', () => {
  let pool: Pool;
  beforeAll(async () => {
    pool = new Pool({ connectionString });
    const client = new Client({ connectionString });
    await client.connect();
    await migrate(client);
    await client.end();
  });
  afterAll(async () => pool?.end());

  it('indexes only finalized blocks, persists logs atomically, and rolls back forked rows to a common ancestor', async () => {
    const rpc = new FakeRpc();
    const indexer = new FinalizedEvmIndexer(pool, rpc, { chainId: rpc.chain, startBlock: 1, confirmations: 2, maxBlockRange: 20 });
    const organizationId = `indexer-${randomUUID()}`;
    const safeAddress = address('a');
    await pool.query('DELETE FROM indexer_cursors WHERE chain_id = $1', [rpc.chain]);
    await pool.query('DELETE FROM indexer_blocks WHERE chain_id = $1', [rpc.chain]);
    await pool.query('INSERT INTO organizations (id, display_name) VALUES ($1, $2)', [organizationId, 'Indexer integration']);
    await pool.query(
      `INSERT INTO accounts (organization_id, id, chain_id, address, adapter, status, guard_address, module_address, verified_at)
       VALUES ($1, 'indexer-safe', $2, $3, 'SAFE_EVM', 'ACTIVE', $4, $5, now())`,
      [organizationId, rpc.chain, safeAddress, address('b'), address('c')],
    );

    const first = await indexer.runBatch();
    expect(first).toMatchObject({ fromBlock: 1, toBlock: 8, indexedBlocks: 8, indexedLogs: 2, rolledBackBlocks: 0, finalizedBlock: 8 });
    const paused = await pool.query<{ status: string }>('SELECT status FROM accounts WHERE organization_id = $1 AND id = $2', [organizationId, 'indexer-safe']);
    expect(paused.rows[0]?.status).toBe('PAUSED');
    const incident = await pool.query<{ event_type: string; payload: { reasonCode: string; blockNumber: number } }>(
      'SELECT event_type, payload FROM audit_events WHERE organization_id = $1', [organizationId],
    );
    expect(incident.rows).toEqual([{ event_type: 'ACCOUNT_PROTECTION_PAUSED', payload: expect.objectContaining({ reasonCode: 'SAFE_GUARD_CHANGED', blockNumber: 7 }) }]);
    const notice = await pool.query<{ event_type: string; aggregate_id: string }>(
      'SELECT event_type, aggregate_id FROM outbox_events WHERE organization_id = $1', [organizationId],
    );
    expect(notice.rows).toEqual([{ event_type: 'ACCOUNT_PROTECTION_PAUSED', aggregate_id: 'indexer-safe' }]);
    const cursor = await pool.query<{ next_block: string; finalized_block: string; indexed_from_block: string }>(
      'SELECT next_block::text, finalized_block::text, indexed_from_block::text FROM indexer_cursors WHERE chain_id = $1', [rpc.chain],
    );
    expect(cursor.rows[0]).toEqual({ next_block: '9', finalized_block: '8', indexed_from_block: '1' });

    rpc.forked = true;
    const second = await indexer.runBatch();
    expect(second).toMatchObject({ fromBlock: 7, toBlock: 8, indexedBlocks: 2, indexedLogs: 0, rolledBackBlocks: 2, finalizedBlock: 8 });
    const stored = await pool.query<{ block_number: string; block_hash: string; transaction_hash: string }>(
      'SELECT block_number::text, block_hash, transaction_hash FROM indexed_chain_logs WHERE chain_id = $1', [rpc.chain],
    );
    expect(stored.rows).toEqual([{ block_number: '6', block_hash: hash('base-6'), transaction_hash: hash('expected-guard') }]);
    const stillPaused = await pool.query<{ status: string }>('SELECT status FROM accounts WHERE organization_id = $1 AND id = $2', [organizationId, 'indexer-safe']);
    expect(stillPaused.rows[0]?.status).toBe('PAUSED');
    const blocks = await pool.query<{ count: string }>('SELECT count(*)::text AS count FROM indexer_blocks WHERE chain_id = $1', [rpc.chain]);
    expect(blocks.rows[0]?.count).toBe('8');

    await pool.query('DELETE FROM indexer_cursors WHERE chain_id = $1', [rpc.chain]);
    await pool.query('DELETE FROM indexer_blocks WHERE chain_id = $1', [rpc.chain]);
  });

  it('fails closed when the configured chain ID disagrees with the RPC', async () => {
    const rpc = new FakeRpc();
    const wrongChainIndexer = new FinalizedEvmIndexer(pool, rpc, { chainId: rpc.chain + 1, startBlock: 1, confirmations: 2, maxBlockRange: 10 });
    await expect(wrongChainIndexer.runBatch()).rejects.toThrow('Configured chain ID does not match RPC');
  });
});
