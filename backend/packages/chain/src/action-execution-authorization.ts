import { AbiCoder, Interface, Transaction, TypedDataEncoder, ZeroAddress, isAddress, keccak256, verifyTypedData } from 'ethers';
import { z } from 'zod';
import { hashPolicyRevision } from '../../policy/src/canonical.js';
import { ActionIntentSchema, PolicyRevisionSchema, type ActionIntent, type PolicyRevision } from '../../policy/src/schema.js';

export const mandateActionTypes = { MandateAction: [
  { name: 'safe', type: 'address' }, { name: 'chainId', type: 'uint256' }, { name: 'module', type: 'address' },
  { name: 'policyEpoch', type: 'uint64' }, { name: 'agent', type: 'address' }, { name: 'keyVersion', type: 'uint64' },
  { name: 'to', type: 'address' }, { name: 'value', type: 'uint256' }, { name: 'dataHash', type: 'bytes32' },
  { name: 'nonce', type: 'uint256' }, { name: 'deadline', type: 'uint256' },
] };

const moduleInterface = new Interface(['function execute(address to,uint256 value,bytes data,uint256 deadline,uint64 keyVersion,uint256 nonce,bytes signature)']);
const erc20Interface = new Interface(['function transfer(address recipient,uint256 amount)']);
const ERC20_TRANSFER_SELECTOR = '0xa9059cbb';
const NATIVE_TRANSFER_SELECTOR = '0x00000000';
const actionHashCoder = AbiCoder.defaultAbiCoder();
const SECP256K1_HALF_ORDER = 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0n;
const typedDataFieldSchema = z.object({ name: z.string(), type: z.string() }).strict();
const actionMessageSchema = z.object({
  safe: z.string().regex(/^0x[0-9a-f]{40}$/), chainId: z.number().int().positive().safe(), module: z.string().regex(/^0x[0-9a-f]{40}$/),
  policyEpoch: z.string().regex(/^\d+$/), agent: z.string().regex(/^0x[0-9a-f]{40}$/), keyVersion: z.string().regex(/^\d+$/),
  to: z.string().regex(/^0x[0-9a-f]{40}$/), value: z.string().regex(/^\d+$/), dataHash: z.string().regex(/^0x[0-9a-f]{64}$/),
  nonce: z.string().regex(/^\d+$/), deadline: z.string().regex(/^\d+$/),
}).strict();
const actionAuthorizationSchema = z.object({
  actionId: z.string().min(1), actionHash: z.string().regex(/^0x[0-9a-f]{64}$/), chainId: z.number().int().positive().safe(),
  snapshotBlockNumber: z.number().int().nonnegative().safe(), snapshotBlockHash: z.string().regex(/^0x[0-9a-f]{64}$/),
  safeAddress: z.string().regex(/^0x[0-9a-f]{40}$/), guardAddress: z.string().regex(/^0x[0-9a-f]{40}$/),
  moduleAddress: z.string().regex(/^0x[0-9a-f]{40}$/), agentAddress: z.string().regex(/^0x[0-9a-f]{40}$/),
  policyRevisionHash: z.string().regex(/^0x[0-9a-f]{64}$/), policyEpoch: z.string().regex(/^\d+$/),
  keyVersion: z.number().int().positive().safe(), executionNonce: z.string().regex(/^\d+$/), deadline: z.number().int().positive().safe(),
  to: z.string().regex(/^0x[0-9a-f]{40}$/), value: z.string().regex(/^\d+$/), data: z.string().regex(/^0x(?:[0-9a-fA-F]{2})*$/),
  actionDigest: z.string().regex(/^0x[0-9a-f]{64}$/),
  signingPayload: z.object({
    domain: z.object({ name: z.literal('MandateAgentModule'), version: z.literal('1'), chainId: z.number().int().positive().safe(), verifyingContract: z.string().regex(/^0x[0-9a-f]{40}$/) }).strict(),
    types: z.object({ MandateAction: z.array(typedDataFieldSchema).length(11) }).strict(),
    primaryType: z.literal('MandateAction'), message: actionMessageSchema,
  }).strict(),
}).strict();

export type ActionExecutionAuthorizationErrorCode = 'INVALID_INPUT' | 'INVALID_SIGNATURE' | 'INVALID_TRANSACTION' | 'ACTION_POLICY_MISMATCH' | 'CHAIN_POLICY_MISMATCH' | 'ACTION_EXPIRED' | 'UNSUPPORTED_ACTION';

export class ActionExecutionAuthorizationError extends Error {
  public constructor(public readonly code: ActionExecutionAuthorizationErrorCode) {
    super(code);
    this.name = 'ActionExecutionAuthorizationError';
  }
}

export interface ActionExecutionChainState {
  readonly safeAddress: string;
  readonly guardAddress: string;
  readonly moduleAddress: string;
  readonly chainId: number;
  readonly timestampSeconds: number;
  readonly policyEpoch: bigint;
  readonly policyEnabled: boolean;
  readonly policyRevisionHash: string;
  readonly agentKeyVersion: bigint;
  readonly agentActive: boolean;
  readonly moduleNonce: bigint;
  readonly blockNumber: number;
  readonly blockHash: string;
}

interface MandateActionMessage {
  readonly safe: string;
  readonly chainId: number;
  readonly module: string;
  readonly policyEpoch: string;
  readonly agent: string;
  readonly keyVersion: string;
  readonly to: string;
  readonly value: string;
  readonly dataHash: string;
  readonly nonce: string;
  readonly deadline: string;
}

export interface ActionExecutionAuthorization {
  readonly actionId: string;
  readonly actionHash: string;
  readonly chainId: number;
  readonly snapshotBlockNumber: number;
  readonly snapshotBlockHash: string;
  readonly safeAddress: string;
  readonly guardAddress: string;
  readonly moduleAddress: string;
  readonly agentAddress: string;
  readonly policyRevisionHash: string;
  readonly policyEpoch: string;
  readonly keyVersion: number;
  readonly executionNonce: string;
  readonly deadline: number;
  readonly to: string;
  readonly value: string;
  readonly data: string;
  readonly actionDigest: string;
  readonly signingPayload: {
    readonly domain: { readonly name: 'MandateAgentModule'; readonly version: '1'; readonly chainId: number; readonly verifyingContract: string };
    readonly types: typeof mandateActionTypes;
    readonly primaryType: 'MandateAction';
    readonly message: MandateActionMessage;
  };
}

export function parseActionExecutionAuthorization(value: unknown): ActionExecutionAuthorization {
  let plan: ActionExecutionAuthorization;
  try {
    plan = actionAuthorizationSchema.parse(value);
  } catch {
    return fail('INVALID_INPUT');
  }
  if (JSON.stringify(plan.signingPayload.types) !== JSON.stringify(mandateActionTypes)) return fail('INVALID_INPUT');
  const { message } = plan.signingPayload;
  let expectedActionHash: string;
  let digest: string;
  try {
    expectedActionHash = keccak256(actionHashCoder.encode(
      ['address', 'uint256', 'uint64', 'address', 'uint64', 'address', 'uint256', 'bytes32', 'uint256', 'uint256'],
      [message.safe, message.chainId, message.policyEpoch, message.agent, message.keyVersion, message.to, message.value,
        message.dataHash, message.nonce, message.deadline],
    ));
    digest = TypedDataEncoder.hash(plan.signingPayload.domain, plan.signingPayload.types, message);
  } catch {
    return fail('INVALID_INPUT');
  }
  if (plan.actionId.length === 0 || plan.chainId !== message.chainId || plan.chainId !== plan.signingPayload.domain.chainId
    || plan.safeAddress !== message.safe || plan.moduleAddress !== message.module
    || plan.signingPayload.domain.verifyingContract !== message.module || plan.agentAddress !== message.agent
    || plan.policyEpoch !== message.policyEpoch || String(plan.keyVersion) !== message.keyVersion
    || String(plan.executionNonce) !== message.nonce || String(plan.deadline) !== message.deadline
    || plan.to !== message.to || plan.value !== message.value || keccak256(plan.data) !== message.dataHash
    || plan.actionHash !== expectedActionHash || plan.actionDigest !== digest) {
    return fail('INVALID_INPUT');
  }
  return plan;
}

function fail(code: ActionExecutionAuthorizationErrorCode): never {
  throw new ActionExecutionAuthorizationError(code);
}

/** Builds only the current contract's native/ERC-20 transfer authorization subset. */
export function buildActionExecutionAuthorization(input: {
  readonly action: ActionIntent;
  readonly policy: PolicyRevision;
  readonly state: ActionExecutionChainState;
}): ActionExecutionAuthorization {
  let action: ActionIntent;
  let policy: PolicyRevision;
  try {
    action = ActionIntentSchema.parse(input.action);
    policy = PolicyRevisionSchema.parse(input.policy);
  } catch {
    return fail('INVALID_INPUT');
  }
  const { state } = input;
  const revisionHash = hashPolicyRevision(policy);
  const scoped = action.organizationId === policy.organizationId
    && action.policyId === policy.policyId
    && action.policyRevision === policy.revision
    && action.policyRevisionHash === revisionHash
    && action.account === policy.account
    && action.agentId === policy.agentId
    && action.agentKeyVersion === policy.agentKeyVersion
    && action.chainId === policy.chainId
    && action.nonceEpoch === policy.nonceEpoch
    && action.target === policy.target
    && action.asset === policy.asset
    && policy.selectors.includes(action.selector)
    && policy.recipients.includes(action.recipient)
    && BigInt(action.amount) <= BigInt(policy.limits.perAction);
  if (!scoped) return fail('ACTION_POLICY_MISMATCH');
  if (action.expiresAt <= state.timestampSeconds || policy.expiresAt <= state.timestampSeconds) return fail('ACTION_EXPIRED');

  const validChainState = state.chainId === policy.chainId
    && isAddress(state.safeAddress)
    && isAddress(state.guardAddress)
    && isAddress(state.moduleAddress)
    && state.safeAddress.toLowerCase() === policy.account
    && state.policyEnabled
    && state.policyRevisionHash.toLowerCase() === revisionHash
    && state.policyEpoch === BigInt(policy.nonceEpoch) + 1n
    && state.agentActive
    && state.agentKeyVersion === BigInt(policy.agentKeyVersion)
    && state.moduleNonce >= 0n
    && Number.isSafeInteger(state.timestampSeconds)
    && Number.isSafeInteger(state.blockNumber)
    && state.blockNumber >= 0
    && /^0x[0-9a-f]{64}$/i.test(state.blockHash)
    && state.timestampSeconds >= policy.validAfter;
  if (!validChainState) return fail('CHAIN_POLICY_MISMATCH');

  let to: string;
  let value: bigint;
  let data: string;
  if (policy.asset === ZeroAddress) {
    if (action.selector !== NATIVE_TRANSFER_SELECTOR || action.target !== action.recipient) return fail('UNSUPPORTED_ACTION');
    to = action.recipient;
    value = BigInt(action.amount);
    data = '0x';
  } else {
    if (policy.target !== policy.asset || action.selector !== ERC20_TRANSFER_SELECTOR) return fail('UNSUPPORTED_ACTION');
    to = policy.asset;
    value = 0n;
    data = erc20Interface.encodeFunctionData('transfer', [action.recipient, BigInt(action.amount)]);
  }

  const deadline = Math.min(action.expiresAt, policy.expiresAt);
  const message: MandateActionMessage = {
    safe: state.safeAddress.toLowerCase(), chainId: state.chainId, module: state.moduleAddress.toLowerCase(),
    policyEpoch: state.policyEpoch.toString(), agent: policy.agentAddress, keyVersion: String(policy.agentKeyVersion),
    to, value: value.toString(), dataHash: keccak256(data), nonce: state.moduleNonce.toString(), deadline: String(deadline),
  };
  const signingPayload: ActionExecutionAuthorization['signingPayload'] = {
    domain: { name: 'MandateAgentModule', version: '1', chainId: state.chainId, verifyingContract: state.moduleAddress.toLowerCase() },
    types: mandateActionTypes,
    primaryType: 'MandateAction',
    message,
  };
  const actionHash = keccak256(actionHashCoder.encode(
    ['address', 'uint256', 'uint64', 'address', 'uint64', 'address', 'uint256', 'bytes32', 'uint256', 'uint256'],
    [message.safe, message.chainId, message.policyEpoch, message.agent, message.keyVersion, message.to, message.value,
      message.dataHash, message.nonce, message.deadline],
  ));
  return {
    actionId: action.actionId,
    actionHash,
    chainId: state.chainId,
    snapshotBlockNumber: state.blockNumber,
    snapshotBlockHash: state.blockHash.toLowerCase(),
    safeAddress: state.safeAddress.toLowerCase(),
    guardAddress: state.guardAddress.toLowerCase(),
    moduleAddress: state.moduleAddress.toLowerCase(),
    agentAddress: policy.agentAddress,
    policyRevisionHash: revisionHash,
    policyEpoch: state.policyEpoch.toString(),
    keyVersion: policy.agentKeyVersion,
    executionNonce: state.moduleNonce.toString(),
    deadline,
    to,
    value: value.toString(),
    data,
    actionDigest: TypedDataEncoder.hash(signingPayload.domain, signingPayload.types, signingPayload.message),
    signingPayload,
  };
}

/** Encodes the module transaction only after the agent signs the returned typed payload. */
export function encodeAuthorizedModuleExecution(plan: ActionExecutionAuthorization, signature: string): string {
  if (!/^0x(?:[0-9a-fA-F]{2}){65}$/.test(signature)) return fail('INVALID_INPUT');
  return moduleInterface.encodeFunctionData('execute', [
    plan.to, BigInt(plan.value), plan.data, BigInt(plan.deadline), BigInt(plan.keyVersion), BigInt(plan.executionNonce), signature,
  ]);
}

/** Verifies the enrolled agent's exact EIP-712 signature and returns only its bound module call. */
export function verifyActionExecutionSignature(value: unknown, signature: string): string {
  const plan = parseActionExecutionAuthorization(value);
  if (!/^0x(?:[0-9a-fA-F]{2}){65}$/.test(signature)) return fail('INVALID_SIGNATURE');
  const r = BigInt(`0x${signature.slice(2, 66)}`);
  const s = BigInt(`0x${signature.slice(66, 130)}`);
  const v = Number.parseInt(signature.slice(130, 132), 16);
  if (r === 0n || s === 0n || s > SECP256K1_HALF_ORDER || (v !== 27 && v !== 28)) return fail('INVALID_SIGNATURE');
  let signer: string;
  try {
    signer = verifyTypedData(plan.signingPayload.domain, plan.signingPayload.types, plan.signingPayload.message, signature);
  } catch {
    return fail('INVALID_SIGNATURE');
  }
  if (signer.toLowerCase() !== plan.agentAddress.toLowerCase()) return fail('INVALID_SIGNATURE');
  return encodeAuthorizedModuleExecution(plan, signature);
}

/** Validates a user-signed outer EVM transaction; no private key or server-side signer is used. */
export function validateSignedActionExecutionTransaction(
  value: unknown,
  agentSignature: string,
  rawTransaction: string,
): { readonly transactionHash: string; readonly from: string; readonly to: string; readonly nonce: number } {
  const plan = parseActionExecutionAuthorization(value);
  const expectedCall = verifyActionExecutionSignature(plan, agentSignature);
  if (typeof rawTransaction !== 'string' || rawTransaction.length > 262146
    || !/^0x(?:[0-9a-fA-F]{2})+$/.test(rawTransaction)) return fail('INVALID_TRANSACTION');
  let transaction: Transaction;
  try { transaction = Transaction.from(rawTransaction); }
  catch { return fail('INVALID_TRANSACTION'); }
  if (transaction.hash === null || transaction.from === null || transaction.to === null
    || transaction.from.toLowerCase() !== plan.agentAddress.toLowerCase()
    || transaction.to.toLowerCase() !== plan.moduleAddress.toLowerCase()
    || transaction.chainId !== BigInt(plan.chainId) || transaction.value !== 0n
    || transaction.data.toLowerCase() !== expectedCall.toLowerCase()
    || !Number.isSafeInteger(transaction.nonce) || transaction.nonce < 0 || transaction.gasLimit <= 0n) {
    return fail('INVALID_TRANSACTION');
  }
  return {
    transactionHash: transaction.hash.toLowerCase(), from: transaction.from.toLowerCase(),
    to: transaction.to.toLowerCase(), nonce: transaction.nonce,
  };
}
