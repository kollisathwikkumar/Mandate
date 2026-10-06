import type { PolicyDecision } from '../../domain/src/reason-code.js';
import { parseUint256 } from '../../domain/src/uint256.js';
import { hashPolicyRevision } from './canonical.js';
import type { ActionIntent, PolicyRevision } from './schema.js';

export type PolicyState = 'active' | 'draft' | 'revoked' | 'expired';

export interface EvaluationInput {
  readonly policy: PolicyRevision;
  readonly policyState: PolicyState;
  readonly now: number;
  readonly action: ActionIntent;
  readonly expectedNonce: number;
  readonly spentInWindow: string | null;
  readonly reservedInWindow: string | null;
  readonly actionsInWindow: number | null;
}

function block(reason: PolicyDecision['reason']): PolicyDecision {
  return { verdict: 'BLOCK', reason };
}

export function evaluateAction(input: EvaluationInput): PolicyDecision {
  const { policy, action } = input;

  if (input.policyState === 'revoked') {
    return block('POLICY_REVOKED');
  }
  if (input.policyState === 'expired') {
    return block('POLICY_EXPIRED');
  }
  if (input.policyState !== 'active') {
    return block('POLICY_INACTIVE');
  }
  if (action.policyId !== policy.policyId) {
    return block('POLICY_ID_MISMATCH');
  }
  if (action.policyRevision !== policy.revision) {
    return block('POLICY_REVISION_MISMATCH');
  }
  if (action.policyRevisionHash !== hashPolicyRevision(policy)) {
    return block('POLICY_REVISION_HASH_MISMATCH');
  }
  if (input.now < policy.validAfter) {
    return block('POLICY_NOT_YET_VALID');
  }
  if (input.now >= policy.expiresAt) {
    return block('POLICY_EXPIRED');
  }
  if (action.expiresAt <= input.now) {
    return block('ACTION_EXPIRED');
  }
  if (action.nonce !== input.expectedNonce || action.nonceEpoch !== policy.nonceEpoch) {
    return block('NONCE_INVALID');
  }
  if (action.organizationId !== policy.organizationId) {
    return block('ORG_MISMATCH');
  }
  if (action.account !== policy.account) {
    return block('ACCOUNT_MISMATCH');
  }
  if (action.agentId !== policy.agentId) {
    return block('AGENT_MISMATCH');
  }
  if (action.agentKeyVersion !== policy.agentKeyVersion) {
    return block('AGENT_KEY_VERSION_MISMATCH');
  }
  if (action.chainId !== policy.chainId) {
    return block('CHAIN_MISMATCH');
  }
  if (action.target !== policy.target) {
    return block('TARGET_DENIED');
  }
  if (!policy.selectors.includes(action.selector)) {
    return block('SELECTOR_DENIED');
  }
  if (action.asset !== policy.asset) {
    return block('ASSET_DENIED');
  }
  if (!policy.recipients.includes(action.recipient)) {
    return block('RECIPIENT_DENIED');
  }

  const amount = parseUint256(action.amount, false);
  if (amount === null) {
    return block('ACTION_AMOUNT_INVALID');
  }
  const perActionLimit = BigInt(policy.limits.perAction);
  if (amount > perActionLimit) {
    return block('ACTION_LIMIT_EXCEEDED');
  }

  if (input.spentInWindow === null || input.reservedInWindow === null || input.actionsInWindow === null) {
    return block('BUDGET_UNAVAILABLE');
  }
  if (!Number.isSafeInteger(input.actionsInWindow) || input.actionsInWindow < 0) {
    return block('BUDGET_UNAVAILABLE');
  }
  const spent = parseUint256(input.spentInWindow, true);
  const reserved = parseUint256(input.reservedInWindow, true);
  if (spent === null || reserved === null) {
    return block('BUDGET_UNAVAILABLE');
  }

  if (policy.limits.maxActions !== undefined && input.actionsInWindow >= policy.limits.maxActions) {
    return block('ACTION_COUNT_LIMIT_EXCEEDED');
  }
  if (spent + reserved + amount > BigInt(policy.limits.cumulative)) {
    return block('CUMULATIVE_LIMIT_EXCEEDED');
  }
  if (policy.limits.approvalThreshold !== undefined && amount > BigInt(policy.limits.approvalThreshold)) {
    return { verdict: 'HOLD', reason: 'APPROVAL_REQUIRED' };
  }
  return { verdict: 'ALLOW', reason: 'POLICY_PASS' };
}
