import { Pool } from 'pg';
import { HttpEvmIndexerRpc } from './evm-rpc.js';
import { FinalizedEvmIndexer } from './indexer.js';

function parseStringMap(value: string | undefined, name: string): Readonly<Record<number, string>> {
  if (value === undefined || value.trim() === '') return {};
  let parsed: unknown;
  try { parsed = JSON.parse(value) as unknown; } catch { throw new Error(`${name} must be a JSON object keyed by decimal chain ID`); }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) throw new Error(`${name} must be a JSON object keyed by decimal chain ID`);
  const result: Record<number, string> = {};
  for (const [key, entry] of Object.entries(parsed)) {
    const chainId = Number(key);
    if (!Number.isSafeInteger(chainId) || chainId < 1 || String(chainId) !== key || typeof entry !== 'string' || entry.trim() === '') {
      throw new Error(`${name} contains an invalid chain ID or value`);
    }
    result[chainId] = entry;
  }
  return result;
}

function parseStartBlocks(value: string | undefined): Readonly<Record<number, number>> {
  if (value === undefined || value.trim() === '') return {};
  let parsed: unknown;
  try { parsed = JSON.parse(value) as unknown; } catch { throw new Error('MANDATE_INDEXER_START_BLOCKS must be a JSON object keyed by decimal chain ID'); }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) throw new Error('MANDATE_INDEXER_START_BLOCKS must be a JSON object keyed by decimal chain ID');
  const result: Record<number, number> = {};
  for (const [key, entry] of Object.entries(parsed)) {
    const chainId = Number(key);
    const startBlock = typeof entry === 'number' ? entry : Number(entry);
    if (!Number.isSafeInteger(chainId) || chainId < 1 || String(chainId) !== key || !Number.isSafeInteger(startBlock) || startBlock < 1) {
      throw new Error('MANDATE_INDEXER_START_BLOCKS contains an invalid chain ID or positive start block');
    }
    result[chainId] = startBlock;
  }
  return result;
}

const databaseUrl = process.env.DATABASE_URL;
const pollMs = Number(process.env.MANDATE_INDEXER_POLL_MS ?? '3000');
const confirmations = Number(process.env.MANDATE_INDEXER_CONFIRMATIONS ?? '12');
const maxBlockRange = Number(process.env.MANDATE_INDEXER_MAX_BLOCK_RANGE ?? '100');
const rpcUrls = parseStringMap(process.env.MANDATE_EVM_RPC_URLS, 'MANDATE_EVM_RPC_URLS');
const starts = parseStartBlocks(process.env.MANDATE_INDEXER_START_BLOCKS);

if (databaseUrl === undefined) throw new Error('DATABASE_URL is required');
if (!Number.isSafeInteger(pollMs) || pollMs < 250 || pollMs > 60000) throw new Error('MANDATE_INDEXER_POLL_MS must be from 250 to 60000');
if (!Number.isSafeInteger(confirmations) || confirmations < 1 || confirmations > 10000) throw new Error('MANDATE_INDEXER_CONFIRMATIONS must be from 1 to 10000');
if (!Number.isSafeInteger(maxBlockRange) || maxBlockRange < 1 || maxBlockRange > 2000) throw new Error('MANDATE_INDEXER_MAX_BLOCK_RANGE must be from 1 to 2000');
if (Object.keys(rpcUrls).length === 0) throw new Error('At least one MANDATE_EVM_RPC_URLS entry is required');
for (const chainId of Object.keys(rpcUrls).map(Number)) {
  if (starts[chainId] === undefined) throw new Error(`MANDATE_INDEXER_START_BLOCKS must include chain ${chainId}`);
}

const pool = new Pool({ connectionString: databaseUrl, max: 5, application_name: 'mandate-chain-indexer' });
const indexers = Object.entries(rpcUrls).map(([chainId, url]) => new FinalizedEvmIndexer(
  pool,
  new HttpEvmIndexerRpc(url),
  { chainId: Number(chainId), startBlock: starts[Number(chainId)] ?? 1, confirmations, maxBlockRange },
));
let stopping = false;
process.once('SIGINT', () => { stopping = true; });
process.once('SIGTERM', () => { stopping = true; });

try {
  while (!stopping) {
    let worked = false;
    for (const indexer of indexers) {
      if (stopping) break;
      try {
        const result = await indexer.runBatch();
        if (result.indexedBlocks > 0 || result.rolledBackBlocks > 0) {
          process.stdout.write(`${JSON.stringify({ component: 'chain-indexer', ...result })}\n`);
          worked = true;
        }
      } catch {
        process.stderr.write(`${JSON.stringify({ component: 'chain-indexer', event: 'batch_failed' })}\n`);
      }
    }
    if (!worked && !stopping) await new Promise<void>((resolve) => setTimeout(resolve, pollMs));
  }
} finally {
  await pool.end();
}
