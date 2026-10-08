import type { AccountEnrollmentProof, AccountEnrollmentRequest, AccountEnrollmentVerifier } from '../../../ports/src/account-enrollment-verifier.js';

export type ChainVerificationErrorCode = 'UNSUPPORTED_CHAIN' | 'RPC_UNAVAILABLE' | 'CHAIN_ID_MISMATCH' | 'CHAIN_STATE_CHANGED' | 'ACCOUNT_NOT_ENROLLED';

export class ChainVerificationError extends Error {
  public constructor(public readonly code: ChainVerificationErrorCode) {
    super(code);
    this.name = 'ChainVerificationError';
  }
}

interface JsonRpcSuccess { readonly jsonrpc: '2.0'; readonly id: number; readonly result: unknown; }
interface JsonRpcFailure { readonly jsonrpc: '2.0'; readonly id: number; readonly error: { readonly code: number; readonly message: string; }; }
type JsonRpcResponse = JsonRpcSuccess | JsonRpcFailure;

const SAFE_TX_GUARD_SLOT = '0x4a204f620c8c5ccdca3fd54d003badd85ba500436a431f0cbda4f558c93c34c8';
const SAFE_MODULE_GUARD_SLOT = '0xb104e0b93118902c651344349b610029d694cfdec91c589c91ebafbcd0289947';
const SAFE_SINGLETON_SLOT = '0x0';
const SAFE_GETTER = '0x186f0354';
const SAFE_MASTER_COPY_GETTER = '0xa619486e';
const GUARD_MODULE_GETTER = '0x7c0a8378';
const GUARD_FULLY_INSTALLED = '0xc5305f76';
const MODULE_GUARD_GETTER = '0x7ceab3b1';
const SAFE_MODULE_ENABLED = '0x2d9ad53d';
const ZERO_ADDRESS = `0x${'0'.repeat(40)}`;
const RPC_TIMEOUT_MS = 5000;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function rpcUrlFor(chainId: number, urls: Readonly<Record<number, string>>): URL {
  const configured = urls[chainId];
  if (configured === undefined) throw new ChainVerificationError('UNSUPPORTED_CHAIN');
  let url: URL;
  try { url = new URL(configured); } catch { throw new ChainVerificationError('RPC_UNAVAILABLE'); }
  const loopback = ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname);
  if ((url.protocol !== 'https:' && !(url.protocol === 'http:' && loopback)) || url.username !== '' || url.password !== '') {
    throw new ChainVerificationError('RPC_UNAVAILABLE');
  }
  return url;
}

function parseHex(value: unknown, expectedBytes?: number): string {
  if (typeof value !== 'string' || !/^0x(?:[0-9a-fA-F]{2})*$/.test(value)) throw new ChainVerificationError('ACCOUNT_NOT_ENROLLED');
  if (expectedBytes !== undefined && value.length !== 2 + expectedBytes * 2) throw new ChainVerificationError('ACCOUNT_NOT_ENROLLED');
  return value.toLowerCase();
}

function parseQuantity(value: unknown): string {
  if (typeof value !== 'string' || !/^0x(?:0|[1-9a-fA-F][0-9a-fA-F]*)$/.test(value)) {
    throw new ChainVerificationError('RPC_UNAVAILABLE');
  }
  return value.toLowerCase();
}

function addressFromWord(value: unknown): string {
  const word = parseHex(value, 32);
  const address = `0x${word.slice(-40)}`;
  if (address === ZERO_ADDRESS) throw new ChainVerificationError('ACCOUNT_NOT_ENROLLED');
  return address;
}

function sameAddress(left: string, right: string): boolean { return left.toLowerCase() === right.toLowerCase(); }

export class EvmAccountEnrollmentVerifier implements AccountEnrollmentVerifier {
  private nextRequestId = 0;

  public constructor(
    private readonly rpcUrls: Readonly<Record<number, string>>,
    private readonly trustedSafeSingletons: Readonly<Record<number, string>>,
  ) {}

  public async verify(request: AccountEnrollmentRequest): Promise<AccountEnrollmentProof> {
    const safeAddress = request.address.toLowerCase();
    if (!/^0x[0-9a-f]{40}$/.test(safeAddress) || safeAddress === ZERO_ADDRESS || !Number.isSafeInteger(request.chainId) || request.chainId < 1) {
      throw new ChainVerificationError('ACCOUNT_NOT_ENROLLED');
    }
    const url = rpcUrlFor(request.chainId, this.rpcUrls);
    const trustedSingleton = this.trustedSafeSingletons[request.chainId]?.toLowerCase();
    if (trustedSingleton === undefined || !/^0x[0-9a-f]{40}$/.test(trustedSingleton) || trustedSingleton === ZERO_ADDRESS) {
      throw new ChainVerificationError('UNSUPPORTED_CHAIN');
    }
    const onChainIdHex = await this.callRpc(url, 'eth_chainId', []);
    const onChainId = BigInt(parseQuantity(onChainIdHex));
    if (onChainId !== BigInt(request.chainId)) throw new ChainVerificationError('CHAIN_ID_MISMATCH');
    const blockTag = parseQuantity(await this.callRpc(url, 'eth_blockNumber', []));
    const blockHash = this.blockHash(await this.callRpc(url, 'eth_getBlockByNumber', [blockTag, false]));
    await this.requireCode(url, safeAddress, blockTag);
    const [singletonSlot, masterCopyWord] = await Promise.all([
      this.callRpc(url, 'eth_getStorageAt', [safeAddress, SAFE_SINGLETON_SLOT, blockTag]),
      this.callContract(url, safeAddress, SAFE_MASTER_COPY_GETTER, blockTag),
    ]);
    const singletonAddress = addressFromWord(singletonSlot);
    if (!sameAddress(singletonAddress, trustedSingleton) || !sameAddress(addressFromWord(masterCopyWord), trustedSingleton)) {
      throw new ChainVerificationError('ACCOUNT_NOT_ENROLLED');
    }
    await this.requireCode(url, trustedSingleton, blockTag);

    const [transactionGuardWord, moduleGuardWord] = await Promise.all([
      this.callRpc(url, 'eth_getStorageAt', [safeAddress, SAFE_TX_GUARD_SLOT, blockTag]),
      this.callRpc(url, 'eth_getStorageAt', [safeAddress, SAFE_MODULE_GUARD_SLOT, blockTag]),
    ]);
    const guardAddress = addressFromWord(transactionGuardWord);
    const moduleGuardAddress = addressFromWord(moduleGuardWord);
    if (!sameAddress(guardAddress, moduleGuardAddress)) throw new ChainVerificationError('ACCOUNT_NOT_ENROLLED');
    await this.requireCode(url, guardAddress, blockTag);

    const [guardSafeWord, moduleAddressWord, installedWord] = await Promise.all([
      this.callContract(url, guardAddress, SAFE_GETTER, blockTag),
      this.callContract(url, guardAddress, GUARD_MODULE_GETTER, blockTag),
      this.callContract(url, guardAddress, GUARD_FULLY_INSTALLED, blockTag),
    ]);
    if (!sameAddress(addressFromWord(guardSafeWord), safeAddress) || parseHex(installedWord, 32) !== `0x${'0'.repeat(63)}1`) {
      throw new ChainVerificationError('ACCOUNT_NOT_ENROLLED');
    }
    const agentModuleAddress = addressFromWord(moduleAddressWord);
    await this.requireCode(url, agentModuleAddress, blockTag);

    const [moduleSafeWord, moduleGuardAddressWord, moduleEnabledWord] = await Promise.all([
      this.callContract(url, agentModuleAddress, SAFE_GETTER, blockTag),
      this.callContract(url, agentModuleAddress, MODULE_GUARD_GETTER, blockTag),
      this.callContract(url, safeAddress, `${SAFE_MODULE_ENABLED}${agentModuleAddress.slice(2).padStart(64, '0')}`, blockTag),
    ]);
    if (!sameAddress(addressFromWord(moduleSafeWord), safeAddress)
      || !sameAddress(addressFromWord(moduleGuardAddressWord), guardAddress)
      || parseHex(moduleEnabledWord, 32) !== `0x${'0'.repeat(63)}1`) {
      throw new ChainVerificationError('ACCOUNT_NOT_ENROLLED');
    }
    const finalBlockHash = this.blockHash(await this.callRpc(url, 'eth_getBlockByNumber', [blockTag, false]));
    if (finalBlockHash !== blockHash) throw new ChainVerificationError('CHAIN_STATE_CHANGED');
    return { safeAddress, guardAddress, moduleAddress: agentModuleAddress };
  }

  private async requireCode(url: URL, address: string, blockTag: string): Promise<void> {
    const code = parseHex(await this.callRpc(url, 'eth_getCode', [address, blockTag]));
    if (code === '0x') throw new ChainVerificationError('ACCOUNT_NOT_ENROLLED');
  }

  private async callContract(url: URL, to: string, data: string, blockTag: string): Promise<string> {
    return parseHex(await this.callRpc(url, 'eth_call', [{ to, data }, blockTag]), 32);
  }

  private blockHash(value: unknown): string {
    if (!isRecord(value)) throw new ChainVerificationError('RPC_UNAVAILABLE');
    return parseHex(value.hash, 32);
  }

  private async callRpc(url: URL, method: string, params: readonly unknown[]): Promise<unknown> {
    const id = ++this.nextRequestId;
    let response: Response;
    try {
      response = await fetch(url, {
        method: 'POST', redirect: 'error', signal: AbortSignal.timeout(RPC_TIMEOUT_MS),
        headers: { 'content-type': 'application/json', accept: 'application/json' },
        body: JSON.stringify({ jsonrpc: '2.0', id, method, params }),
      });
    } catch {
      throw new ChainVerificationError('RPC_UNAVAILABLE');
    }
    if (!response.ok) throw new ChainVerificationError('RPC_UNAVAILABLE');
    let body: unknown;
    try { body = await response.json() as unknown; } catch { throw new ChainVerificationError('RPC_UNAVAILABLE'); }
    if (!isRecord(body) || body.jsonrpc !== '2.0' || body.id !== id) throw new ChainVerificationError('RPC_UNAVAILABLE');
    const parsed = body as unknown as JsonRpcResponse;
    if ('error' in parsed) throw new ChainVerificationError('ACCOUNT_NOT_ENROLLED');
    if (!('result' in parsed)) throw new ChainVerificationError('RPC_UNAVAILABLE');
    return parsed.result;
  }
}
