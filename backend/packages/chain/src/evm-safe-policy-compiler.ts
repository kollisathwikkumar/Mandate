import { Interface } from 'ethers';
import { hashPolicyRevision } from '../../policy/src/canonical.js';
import { PolicyRevisionSchema, type PolicyRevision } from '../../policy/src/schema.js';

const ZERO_ADDRESS = `0x${'0'.repeat(40)}`;
const ERC20_TRANSFER = '0xa9059cbb';
const NATIVE_TRANSFER_MARKER = '0x00000000';
const UINT32_MAX = 0xffff_ffff;
const UINT64_MAX = (1n << 64n) - 1n;

const guardInterface = new Interface([
  'function configurePolicy((bytes32 revisionHash,uint64 nextEpoch,uint64 policyValidUntil,uint32 windowDuration,uint32 actionCountLimit,address[] assets,uint256[] perActionLimits,uint256[] perWindowLimits,uint256[] approvalThresholds,bool[] approvalRequired,address[] recipients) config)',
]);

export type EvmPolicyCompileErrorCode =
  | 'POLICY_NOT_YET_VALID'
  | 'POLICY_EXPIRED'
  | 'UNSUPPORTED_TARGET_OR_SELECTOR'
  | 'UNSUPPORTED_LIMIT'
  | 'INVALID_EPOCH';

export class EvmPolicyCompileError extends Error {
  public constructor(public readonly code: EvmPolicyCompileErrorCode) {
    super(code);
    this.name = 'EvmPolicyCompileError';
  }
}

export interface EvmSafePolicyConfiguration {
  readonly revisionHash: string;
  readonly nextEpoch: bigint;
  readonly policyValidUntil: bigint;
  readonly windowDuration: number;
  readonly actionCountLimit: number;
  readonly assets: readonly string[];
  readonly perActionLimits: readonly bigint[];
  readonly perWindowLimits: readonly bigint[];
  readonly approvalThresholds: readonly bigint[];
  readonly approvalRequired: readonly boolean[];
  readonly recipients: readonly string[];
}

export interface CompiledEvmSafePolicy {
  readonly revisionHash: string;
  readonly configuration: EvmSafePolicyConfiguration;
  readonly configurePolicyCalldata: string;
}

/** Compiles only rule semantics that the current Safe guard enforces byte-for-byte. */
export function compileEvmSafePolicy(revisionInput: PolicyRevision, chainTimestampSeconds: number): CompiledEvmSafePolicy {
  const revision = PolicyRevisionSchema.parse(revisionInput);
  if (!Number.isSafeInteger(chainTimestampSeconds) || chainTimestampSeconds < 0) throw new RangeError('chainTimestampSeconds must be a nonnegative safe integer');
  if (revision.validAfter > chainTimestampSeconds) throw new EvmPolicyCompileError('POLICY_NOT_YET_VALID');
  if (revision.expiresAt <= chainTimestampSeconds) throw new EvmPolicyCompileError('POLICY_EXPIRED');
  if (BigInt(revision.expiresAt) > UINT64_MAX || BigInt(revision.nonceEpoch) + 1n > UINT64_MAX) throw new EvmPolicyCompileError('INVALID_EPOCH');
  if (revision.limits.windowSeconds > UINT32_MAX || (revision.limits.maxActions !== undefined && revision.limits.maxActions > UINT32_MAX)) {
    throw new EvmPolicyCompileError('UNSUPPORTED_LIMIT');
  }

  const native = revision.asset === ZERO_ADDRESS;
  const supportedNative = native && revision.selectors.length === 1
    && revision.selectors[0] === NATIVE_TRANSFER_MARKER && revision.recipients.includes(revision.target);
  const supportedErc20 = !native && revision.target === revision.asset
    && revision.selectors.length === 1 && revision.selectors[0] === ERC20_TRANSFER;
  if (!supportedNative && !supportedErc20) throw new EvmPolicyCompileError('UNSUPPORTED_TARGET_OR_SELECTOR');

  const perActionLimit = BigInt(revision.limits.perAction);
  const perWindowLimit = BigInt(revision.limits.cumulative);
  const approvalThreshold = revision.limits.approvalThreshold === undefined ? 0n : BigInt(revision.limits.approvalThreshold);
  if (perActionLimit <= 0n || perWindowLimit < perActionLimit || approvalThreshold > perActionLimit) {
    throw new EvmPolicyCompileError('UNSUPPORTED_LIMIT');
  }

  const configuration: EvmSafePolicyConfiguration = {
    revisionHash: hashPolicyRevision(revision),
    nextEpoch: BigInt(revision.nonceEpoch) + 1n,
    policyValidUntil: BigInt(revision.expiresAt),
    windowDuration: revision.limits.windowSeconds,
    actionCountLimit: revision.limits.maxActions ?? UINT32_MAX,
    assets: [revision.asset],
    perActionLimits: [perActionLimit],
    perWindowLimits: [perWindowLimit],
    approvalThresholds: [approvalThreshold],
    approvalRequired: [revision.limits.approvalThreshold !== undefined],
    recipients: [...revision.recipients],
  };
  const configurePolicyCalldata = guardInterface.encodeFunctionData('configurePolicy', [configuration]);
  return { revisionHash: configuration.revisionHash, configuration, configurePolicyCalldata };
}
