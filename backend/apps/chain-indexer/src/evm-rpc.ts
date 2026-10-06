export interface EvmBlock {
  readonly number: number;
  readonly hash: string;
  readonly parentHash: string;
}

export interface EvmLog {
  readonly blockNumber: number;
  readonly blockHash: string;
  readonly transactionHash: string;
  readonly transactionIndex: number;
  readonly logIndex: number;
  readonly address: string;
  readonly topics: readonly string[];
  readonly data: string;
}

export interface EvmIndexerRpc {
  chainId(): Promise<number>;
  latestBlock(): Promise<number>;
  block(number: number): Promise<EvmBlock>;
  logs(fromBlock: number, toBlock: number, addresses: readonly string[]): Promise<readonly EvmLog[]>;
}

const HASH = /^0x[0-9a-fA-F]{64}$/;
const ADDRESS = /^0x[0-9a-fA-F]{40}$/;
const DATA = /^0x(?:[0-9a-fA-F]{2})*$/;

function quantity(value: unknown, label: string): number {
  if (typeof value !== 'string' || !/^0x(?:0|[1-9a-fA-F][0-9a-fA-F]*)$/.test(value)) throw new Error(`Invalid ${label} from RPC`);
  const parsed = Number(BigInt(value));
  if (!Number.isSafeInteger(parsed) || parsed < 0) throw new Error(`Unsupported ${label} from RPC`);
  return parsed;
}

function object(value: unknown, label: string): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) throw new Error(`Invalid ${label} from RPC`);
  return value as Record<string, unknown>;
}

function validHash(value: unknown, label: string): string {
  if (typeof value !== 'string' || !HASH.test(value)) throw new Error(`Invalid ${label} from RPC`);
  return value.toLowerCase();
}

function parseBlock(value: unknown, expectedNumber: number): EvmBlock {
  const block = object(value, 'block');
  const number = quantity(block['number'], 'block number');
  if (number !== expectedNumber) throw new Error('RPC returned the wrong block number');
  return {
    number,
    hash: validHash(block['hash'], 'block hash'),
    parentHash: validHash(block['parentHash'], 'parent hash'),
  };
}

function parseLog(value: unknown): EvmLog {
  const log = object(value, 'log');
  const address = log['address'];
  const topics = log['topics'];
  const data = log['data'];
  const transactionIndex = quantity(log['transactionIndex'], 'transaction index');
  const logIndex = quantity(log['logIndex'], 'log index');
  if (typeof address !== 'string' || !ADDRESS.test(address) || !Array.isArray(topics)
    || !topics.every((topic: unknown) => typeof topic === 'string' && HASH.test(topic))
    || typeof data !== 'string' || !DATA.test(data)) throw new Error('Invalid log fields from RPC');
  return {
    blockNumber: quantity(log['blockNumber'], 'log block number'),
    blockHash: validHash(log['blockHash'], 'log block hash'),
    transactionHash: validHash(log['transactionHash'], 'transaction hash'),
    transactionIndex,
    logIndex,
    address: address.toLowerCase(),
    topics: topics.map((topic: string) => topic.toLowerCase()),
    data: data.toLowerCase(),
  };
}

/** Minimal JSON-RPC adapter. Endpoints are operator configuration, never request input. */
export class HttpEvmIndexerRpc implements EvmIndexerRpc {
  private requestId = 0;

  public async chainId(): Promise<number> {
    return quantity(await this.call('eth_chainId', []), 'chain ID');
  }

  public constructor(private readonly endpoint: string, private readonly timeoutMs = 8000) {
    const url = new URL(endpoint);
    const local = url.hostname === 'localhost' || url.hostname === '127.0.0.1' || url.hostname === '::1';
    if (url.protocol !== 'https:' && !(url.protocol === 'http:' && local)) throw new Error('Indexer RPC must use HTTPS or loopback HTTP');
    if (url.username !== '' || url.password !== '' || url.hash !== '') throw new Error('Indexer RPC URL contains unsupported components');
    if (!Number.isInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 60000) throw new RangeError('timeoutMs must be from 100 to 60000');
  }

  private async call(method: string, params: readonly unknown[]): Promise<unknown> {
    const id = ++this.requestId;
    const response = await fetch(this.endpoint, {
      method: 'POST',
      redirect: 'error',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id, method, params }),
      signal: AbortSignal.timeout(this.timeoutMs),
    });
    if (!response.ok) throw new Error(`RPC HTTP ${response.status}`);
    const payload = object(await response.json(), 'JSON-RPC response');
    if (payload['id'] !== id || payload['jsonrpc'] !== '2.0' || payload['error'] !== undefined) throw new Error('RPC call failed');
    return payload['result'];
  }

  public async latestBlock(): Promise<number> {
    return quantity(await this.call('eth_blockNumber', []), 'latest block');
  }

  public async block(number: number): Promise<EvmBlock> {
    const result = await this.call('eth_getBlockByNumber', [`0x${number.toString(16)}`, false]);
    if (result === null) throw new Error(`RPC block ${number} is unavailable`);
    return parseBlock(result, number);
  }

  public async logs(fromBlock: number, toBlock: number, addresses: readonly string[]): Promise<readonly EvmLog[]> {
    if (addresses.length === 0) return [];
    const result = await this.call('eth_getLogs', [{
      fromBlock: `0x${fromBlock.toString(16)}`,
      toBlock: `0x${toBlock.toString(16)}`,
      address: [...new Set(addresses.map((address) => address.toLowerCase()))],
    }]);
    if (!Array.isArray(result)) throw new Error('Invalid logs result from RPC');
    return result.map(parseLog);
  }
}
