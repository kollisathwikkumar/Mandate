import { Contract, JsonRpcProvider, isAddress } from 'ethers';
import type { SafePolicyActivationReader, SafePolicyActivationState } from '../../../ports/src/safe-policy-activation-reader.js';

export type PolicyActivationChainErrorCode = 'UNSUPPORTED_CHAIN' | 'RPC_UNAVAILABLE' | 'CHAIN_STATE_MISMATCH';

export class PolicyActivationChainError extends Error {
  public constructor(public readonly code: PolicyActivationChainErrorCode) {
    super(code);
    this.name = 'PolicyActivationChainError';
  }
}

const safeAbi = [
  'function nonce() view returns (uint256)',
  'function isModuleEnabled(address module) view returns (bool)',
  'function getOwners() view returns (address[])',
  'function getThreshold() view returns (uint256)',
];
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
];

function normalizeAddress(value: string): string {
  if (!isAddress(value)) throw new PolicyActivationChainError('CHAIN_STATE_MISMATCH');
  return value.toLowerCase();
}

function getRpcUrl(chainId: number, rpcUrls: Readonly<Record<number, string>>): string {
  const raw = rpcUrls[chainId];
  if (raw === undefined) throw new PolicyActivationChainError('UNSUPPORTED_CHAIN');
  let url: URL;
  try { url = new URL(raw); } catch { throw new PolicyActivationChainError('RPC_UNAVAILABLE'); }
  const loopback = ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname);
  if ((url.protocol !== 'https:' && !(url.protocol === 'http:' && loopback)) || url.username !== '' || url.password !== '') {
    throw new PolicyActivationChainError('RPC_UNAVAILABLE');
  }
  return url.toString();
}

/** Reads the latest canonical Safe/guard/module state used to construct owner SafeTx plans. */
export class EvmSafePolicyActivationReader implements SafePolicyActivationReader {
  public constructor(private readonly rpcUrls: Readonly<Record<number, string>>) {}

  public async readState(input: {
    readonly chainId: number;
    readonly safeAddress: string;
    readonly guardAddress: string;
    readonly moduleAddress: string;
    readonly agentAddress: string;
  }): Promise<SafePolicyActivationState> {
    const safeAddress = normalizeAddress(input.safeAddress);
    const guardAddress = normalizeAddress(input.guardAddress);
    const moduleAddress = normalizeAddress(input.moduleAddress);
    const agentAddress = normalizeAddress(input.agentAddress);
    const provider = new JsonRpcProvider(getRpcUrl(input.chainId, this.rpcUrls), input.chainId, { staticNetwork: true });
    try {
      const network = await provider.getNetwork();
      const block = await provider.getBlock('latest');
      if (network.chainId !== BigInt(input.chainId) || block === null) throw new PolicyActivationChainError('CHAIN_STATE_MISMATCH');
      const [codeSafe, codeGuard, codeModule] = await Promise.all([
        provider.getCode(safeAddress, block.number), provider.getCode(guardAddress, block.number), provider.getCode(moduleAddress, block.number),
      ]);
      if (codeSafe === '0x' || codeGuard === '0x' || codeModule === '0x') throw new PolicyActivationChainError('CHAIN_STATE_MISMATCH');
      const safe = new Contract(safeAddress, safeAbi, provider);
      const guard = new Contract(guardAddress, guardAbi, provider);
      const module = new Contract(moduleAddress, moduleAbi, provider);
      const [nonce, safeEnabled, owners, threshold, guardSafe, guardModule, policyEpoch, policyEnabled, policyRevisionHash, installed, moduleSafe, moduleGuard, agentKey] = await Promise.all([
        safe.getFunction('nonce')({ blockTag: block.number }) as Promise<bigint>,
        safe.getFunction('isModuleEnabled')(moduleAddress, { blockTag: block.number }) as Promise<boolean>,
        safe.getFunction('getOwners')({ blockTag: block.number }) as Promise<readonly string[]>,
        safe.getFunction('getThreshold')({ blockTag: block.number }) as Promise<bigint>,
        guard.getFunction('safe')({ blockTag: block.number }) as Promise<string>,
        guard.getFunction('agentModule')({ blockTag: block.number }) as Promise<string>,
        guard.getFunction('policyEpoch')({ blockTag: block.number }) as Promise<bigint>,
        guard.getFunction('policyEnabled')({ blockTag: block.number }) as Promise<boolean>,
        guard.getFunction('policyRevisionHash')({ blockTag: block.number }) as Promise<string>,
        guard.getFunction('isFullyInstalled')({ blockTag: block.number }) as Promise<boolean>,
        module.getFunction('safe')({ blockTag: block.number }) as Promise<string>,
        module.getFunction('guard')({ blockTag: block.number }) as Promise<string>,
        module.getFunction('agents')(agentAddress, { blockTag: block.number }) as Promise<readonly [bigint, boolean]>,
      ]);
      if (!safeEnabled || !installed || owners.length === 0 || threshold < 1n || threshold > BigInt(owners.length)
        || normalizeAddress(guardSafe) !== safeAddress || normalizeAddress(guardModule) !== moduleAddress
        || normalizeAddress(moduleSafe) !== safeAddress || normalizeAddress(moduleGuard) !== guardAddress) {
        throw new PolicyActivationChainError('CHAIN_STATE_MISMATCH');
      }
      const confirmedBlock = await provider.getBlock(block.number);
      if (confirmedBlock === null || confirmedBlock.hash !== block.hash) throw new PolicyActivationChainError('CHAIN_STATE_MISMATCH');
      const [agentKeyVersion, agentActive] = agentKey;
      return {
        safeAddress, guardAddress, moduleAddress, chainId: input.chainId,
        timestampSeconds: block.timestamp, safeNonce: nonce, safeOwners: owners.map(normalizeAddress), safeThreshold: threshold,
        policyEpoch, policyEnabled, policyRevisionHash: policyRevisionHash.toLowerCase(),
        agentKeyVersion, agentActive,
      };
    } catch (error: unknown) {
      if (error instanceof PolicyActivationChainError) throw error;
      throw new PolicyActivationChainError('RPC_UNAVAILABLE');
    } finally {
      await provider.destroy();
    }
  }
}
