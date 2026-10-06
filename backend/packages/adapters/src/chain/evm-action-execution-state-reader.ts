import { Contract, JsonRpcProvider, isAddress } from 'ethers';
import type { ActionExecutionState, ActionExecutionStateReader } from '../../../ports/src/action-execution-state-reader.js';

export type ActionExecutionChainReadErrorCode = 'UNSUPPORTED_CHAIN' | 'RPC_UNAVAILABLE' | 'CHAIN_STATE_MISMATCH';

export class ActionExecutionChainReadError extends Error {
  public constructor(public readonly code: ActionExecutionChainReadErrorCode) {
    super(code);
    this.name = 'ActionExecutionChainReadError';
  }
}

const safeAbi = ['function isModuleEnabled(address module) view returns (bool)'];
const guardAbi = [
  'function safe() view returns (address)',
  'function agentModule() view returns (address)',
  'function policyEpoch() view returns (uint64)',
  'function policyEnabled() view returns (bool)',
  'function policyRevisionHash() view returns (bytes32)',
  'function isFullyInstalled() view returns (bool)',
];
const moduleAbi = [
  'function safe() view returns (address)',
  'function guard() view returns (address)',
  'function agents(address agent) view returns (uint64 version,bool active)',
  'function nextNonce(address agent) view returns (uint256)',
];

function normalizeAddress(value: string): string {
  if (!isAddress(value)) throw new ActionExecutionChainReadError('CHAIN_STATE_MISMATCH');
  return value.toLowerCase();
}

function rpcUrl(chainId: number, urls: Readonly<Record<number, string>>): string {
  const configured = urls[chainId];
  if (configured === undefined) throw new ActionExecutionChainReadError('UNSUPPORTED_CHAIN');
  let parsed: URL;
  try { parsed = new URL(configured); } catch { throw new ActionExecutionChainReadError('RPC_UNAVAILABLE'); }
  const loopback = ['localhost', '127.0.0.1', '[::1]'].includes(parsed.hostname);
  if ((parsed.protocol !== 'https:' && !(parsed.protocol === 'http:' && loopback)) || parsed.username !== '' || parsed.password !== '') {
    throw new ActionExecutionChainReadError('RPC_UNAVAILABLE');
  }
  return parsed.toString();
}

/** Reads all authorization facts at one numbered block and confirms its hash after the reads. */
export class EvmActionExecutionStateReader implements ActionExecutionStateReader {
  public constructor(private readonly urls: Readonly<Record<number, string>>) {}

  public async readState(input: {
    readonly chainId: number;
    readonly safeAddress: string;
    readonly guardAddress: string;
    readonly moduleAddress: string;
    readonly agentAddress: string;
  }): Promise<ActionExecutionState> {
    const safeAddress = normalizeAddress(input.safeAddress);
    const guardAddress = normalizeAddress(input.guardAddress);
    const moduleAddress = normalizeAddress(input.moduleAddress);
    const agentAddress = normalizeAddress(input.agentAddress);
    const provider = new JsonRpcProvider(rpcUrl(input.chainId, this.urls), input.chainId, { staticNetwork: true });
    try {
      const [network, block] = await Promise.all([provider.getNetwork(), provider.getBlock('latest')]);
      if (network.chainId !== BigInt(input.chainId) || block === null) throw new ActionExecutionChainReadError('CHAIN_STATE_MISMATCH');
      const [safeCode, guardCode, moduleCode] = await Promise.all([
        provider.getCode(safeAddress, block.number),
        provider.getCode(guardAddress, block.number),
        provider.getCode(moduleAddress, block.number),
      ]);
      if (safeCode === '0x' || guardCode === '0x' || moduleCode === '0x') throw new ActionExecutionChainReadError('CHAIN_STATE_MISMATCH');

      const safe = new Contract(safeAddress, safeAbi, provider);
      const guard = new Contract(guardAddress, guardAbi, provider);
      const module = new Contract(moduleAddress, moduleAbi, provider);
      const [moduleEnabled, guardSafe, guardModule, policyEpoch, policyEnabled, policyRevisionHash, fullyInstalled,
        moduleSafe, moduleGuard, agentKey, moduleNonce] = await Promise.all([
        safe.getFunction('isModuleEnabled')(moduleAddress, { blockTag: block.number }) as Promise<boolean>,
        guard.getFunction('safe')({ blockTag: block.number }) as Promise<string>,
        guard.getFunction('agentModule')({ blockTag: block.number }) as Promise<string>,
        guard.getFunction('policyEpoch')({ blockTag: block.number }) as Promise<bigint>,
        guard.getFunction('policyEnabled')({ blockTag: block.number }) as Promise<boolean>,
        guard.getFunction('policyRevisionHash')({ blockTag: block.number }) as Promise<string>,
        guard.getFunction('isFullyInstalled')({ blockTag: block.number }) as Promise<boolean>,
        module.getFunction('safe')({ blockTag: block.number }) as Promise<string>,
        module.getFunction('guard')({ blockTag: block.number }) as Promise<string>,
        module.getFunction('agents')(agentAddress, { blockTag: block.number }) as Promise<readonly [bigint, boolean]>,
        module.getFunction('nextNonce')(agentAddress, { blockTag: block.number }) as Promise<bigint>,
      ]);
      if (!moduleEnabled || !fullyInstalled || normalizeAddress(guardSafe) !== safeAddress
        || normalizeAddress(guardModule) !== moduleAddress || normalizeAddress(moduleSafe) !== safeAddress
        || normalizeAddress(moduleGuard) !== guardAddress) {
        throw new ActionExecutionChainReadError('CHAIN_STATE_MISMATCH');
      }
      const confirmedBlock = await provider.getBlock(block.number);
      if (confirmedBlock === null || block.hash === null || confirmedBlock.hash === null
        || confirmedBlock.hash.toLowerCase() !== block.hash.toLowerCase()) {
        throw new ActionExecutionChainReadError('CHAIN_STATE_MISMATCH');
      }
      const [agentKeyVersion, agentActive] = agentKey;
      return {
        safeAddress, guardAddress, moduleAddress, chainId: input.chainId, timestampSeconds: block.timestamp,
        policyEpoch, policyEnabled, policyRevisionHash: policyRevisionHash.toLowerCase(), agentKeyVersion, agentActive,
        moduleNonce, blockNumber: block.number, blockHash: block.hash.toLowerCase(),
      };
    } catch (error: unknown) {
      if (error instanceof ActionExecutionChainReadError) throw error;
      throw new ActionExecutionChainReadError('RPC_UNAVAILABLE');
    } finally {
      await provider.destroy();
    }
  }
}
