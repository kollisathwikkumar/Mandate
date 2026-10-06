import { describe, expect, it } from 'vitest';
import { ActionIntentSchema, PolicyRevisionSchema, canonicalizePolicyRevision, evaluateAction, hashPolicyRevision, type EvaluationInput, type PolicyRevision } from '../src/index.js';

interface BlockCase {
  readonly label: string;
  readonly reason: string;
  readonly update: (input: EvaluationInput) => EvaluationInput;
}

const withAction = (input: EvaluationInput, changes: Partial<EvaluationInput['action']>): EvaluationInput => ({
  ...input,
  action: { ...input.action, ...changes },
});

const basePolicyInput = {
  schemaVersion: 1,
  policyId: 'policy-1',
  revision: 1,
  organizationId: 'org-1',
  owner: '0x6666666666666666666666666666666666666666',
  account: '0x1111111111111111111111111111111111111111',
  agentId: 'agent-1',
  agentAddress: '0x5555555555555555555555555555555555555555',
  agentKeyVersion: 1,
  chainId: 10143,
  adapter: 'evm-smart-account',
  target: '0x3333333333333333333333333333333333333333',
  selectors: ['0xa9059cbb'],
  asset: '0x3333333333333333333333333333333333333333',
  recipients: ['0x4444444444444444444444444444444444444444'],
  limits: {
    perAction: '1000',
    cumulative: '5000',
    windowSeconds: 86400,
    approvalThreshold: '800',
    maxActions: 10,
  },
  validAfter: 1_800_000_000,
  expiresAt: 1_900_000_000,
  nonceEpoch: 0,
} as const;

const validEvaluationInput = (policy: PolicyRevision): EvaluationInput => ({
  policy,
  policyState: 'active',
  now: 1_850_000_000,
  action: {
    actionId: 'action-1',
    idempotencyKey: 'intent-1',
    policyId: policy.policyId,
    policyRevision: policy.revision,
    policyRevisionHash: hashPolicyRevision(policy),
    organizationId: 'org-1',
    account: '0x1111111111111111111111111111111111111111',
    agentId: 'agent-1',
    agentKeyVersion: 1,
    chainId: 10143,
    target: '0x3333333333333333333333333333333333333333',
    selector: '0xa9059cbb',
    asset: '0x3333333333333333333333333333333333333333',
    recipient: '0x4444444444444444444444444444444444444444',
    amount: '500',
    nonce: 7,
    nonceEpoch: 0,
    expiresAt: 1_850_000_300,
  },
  expectedNonce: 7,
  spentInWindow: '1000',
  reservedInWindow: '500',
  actionsInWindow: 2,
});

const policy = (): PolicyRevision => PolicyRevisionSchema.parse(basePolicyInput);

describe('PolicyRevisionSchema', () => {
  it('normalizes EVM addresses and selectors before canonical comparison', () => {
    const parsed = PolicyRevisionSchema.parse({
      ...basePolicyInput,
      account: '0x111111111111111111111111111111111111111A',
      selectors: ['0xA9059CBB'],
      recipients: ['0x444444444444444444444444444444444444444A'],
    });

    expect(parsed.account).toBe('0x111111111111111111111111111111111111111a');
    expect(parsed.selectors).toEqual(['0xa9059cbb']);
    expect(parsed.recipients).toEqual(['0x444444444444444444444444444444444444444a']);
  });

  it('rejects unsupported fields rather than silently ignoring policy terms', () => {
    const result = PolicyRevisionSchema.safeParse({ ...basePolicyInput, arbitraryCall: true });
    expect(result.success).toBe(false);
  });

  it('rejects malformed addresses, duplicate selectors and invalid validity windows', () => {
    expect(PolicyRevisionSchema.safeParse({ ...basePolicyInput, account: 'not-an-address' }).success).toBe(false);
    expect(PolicyRevisionSchema.safeParse({ ...basePolicyInput, selectors: ['0xa9059cbb', '0xA9059CBB'] }).success).toBe(false);
    expect(PolicyRevisionSchema.safeParse({ ...basePolicyInput, expiresAt: basePolicyInput.validAfter }).success).toBe(false);
  });

  it('requires positive integer base-unit amounts and bounded counters', () => {
    expect(PolicyRevisionSchema.safeParse({
      ...basePolicyInput,
      limits: { ...basePolicyInput.limits, perAction: '1.5' },
    }).success).toBe(false);
    expect(PolicyRevisionSchema.safeParse({
      ...basePolicyInput,
      limits: { ...basePolicyInput.limits, windowSeconds: 0 },
    }).success).toBe(false);
  });

  it('produces the same canonical bytes and hash regardless of input key or allowlist order', () => {
    const first = PolicyRevisionSchema.parse({
      ...basePolicyInput,
      selectors: ['0xa9059cbb', '0x23b872dd'],
      recipients: [
        '0x4444444444444444444444444444444444444444',
        '0x5555555555555555555555555555555555555555',
      ],
    });
    const second = PolicyRevisionSchema.parse({
      ...basePolicyInput,
      selectors: ['0x23B872DD', '0xA9059CBB'],
      recipients: [
        '0x5555555555555555555555555555555555555555',
        '0x4444444444444444444444444444444444444444',
      ],
    });

    expect(canonicalizePolicyRevision(first)).toBe(canonicalizePolicyRevision(second));
    expect(hashPolicyRevision(first)).toBe(hashPolicyRevision(second));
    expect(hashPolicyRevision(first)).toMatch(/^0x[0-9a-f]{64}$/);
  });
});

describe('ActionIntentSchema', () => {
  it('requires stable action and idempotency identifiers and rejects unknown fields', () => {
    const action = validEvaluationInput(policy()).action;
    expect(ActionIntentSchema.parse(action)).toEqual(action);
    expect(ActionIntentSchema.safeParse({ ...action, idempotencyKey: undefined }).success).toBe(false);
    expect(ActionIntentSchema.safeParse({ ...action, arbitraryCall: true }).success).toBe(false);
  });
});

describe('evaluateAction', () => {
  it('allows an action inside every configured bound', () => {
    expect(evaluateAction(validEvaluationInput(policy()))).toEqual({ verdict: 'ALLOW', reason: 'POLICY_PASS' });
  });

  const blockCases: BlockCase[] = [
    { label: 'revoked policy', reason: 'POLICY_REVOKED', update: (input) => ({ ...input, policyState: 'revoked' }) },
    { label: 'inactive policy', reason: 'POLICY_INACTIVE', update: (input) => ({ ...input, policyState: 'draft' }) },
    { label: 'expired policy state', reason: 'POLICY_EXPIRED', update: (input) => ({ ...input, policyState: 'expired' }) },
    { label: 'policy not yet valid', reason: 'POLICY_NOT_YET_VALID', update: (input) => ({ ...input, now: 1_799_999_999 }) },
    { label: 'expired policy', reason: 'POLICY_EXPIRED', update: (input) => ({ ...input, now: 1_900_000_000 }) },
    { label: 'action expired', reason: 'ACTION_EXPIRED', update: (input) => withAction(input, { expiresAt: 1_849_999_999 }) },
    { label: 'wrong policy id', reason: 'POLICY_ID_MISMATCH', update: (input) => withAction(input, { policyId: 'other-policy' }) },
    { label: 'wrong policy revision', reason: 'POLICY_REVISION_MISMATCH', update: (input) => withAction(input, { policyRevision: 2 }) },
    { label: 'wrong policy revision hash', reason: 'POLICY_REVISION_HASH_MISMATCH', update: (input) => withAction(input, { policyRevisionHash: `0x${'f'.repeat(64)}` }) },
    { label: 'wrong organization', reason: 'ORG_MISMATCH', update: (input) => withAction(input, { organizationId: 'org-other' }) },
    { label: 'wrong account', reason: 'ACCOUNT_MISMATCH', update: (input) => withAction(input, { account: '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' }) },
    { label: 'wrong agent', reason: 'AGENT_MISMATCH', update: (input) => withAction(input, { agentId: 'agent-other' }) },
    { label: 'rotated agent key', reason: 'AGENT_KEY_VERSION_MISMATCH', update: (input) => withAction(input, { agentKeyVersion: 2 }) },
    { label: 'wrong chain', reason: 'CHAIN_MISMATCH', update: (input) => withAction(input, { chainId: 1 }) },
    { label: 'wrong target', reason: 'TARGET_DENIED', update: (input) => withAction(input, { target: '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' }) },
    { label: 'wrong selector', reason: 'SELECTOR_DENIED', update: (input) => withAction(input, { selector: '0xdeadbeef' }) },
    { label: 'wrong asset', reason: 'ASSET_DENIED', update: (input) => withAction(input, { asset: '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' }) },
    { label: 'wrong recipient', reason: 'RECIPIENT_DENIED', update: (input) => withAction(input, { recipient: '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' }) },
    { label: 'per-action limit exceeded', reason: 'ACTION_LIMIT_EXCEEDED', update: (input) => withAction(input, { amount: '1001' }) },
    {
      label: 'cumulative limit exceeded',
      reason: 'CUMULATIVE_LIMIT_EXCEEDED',
      update: (input) => ({ ...withAction(input, { amount: '1' }), spentInWindow: '4500' }),
    },
    { label: 'action-count limit exceeded', reason: 'ACTION_COUNT_LIMIT_EXCEEDED', update: (input) => ({ ...input, actionsInWindow: 10 }) },
    { label: 'nonce replay or gap', reason: 'NONCE_INVALID', update: (input) => ({ ...input, expectedNonce: 8 }) },
    { label: 'nonce epoch mismatch', reason: 'NONCE_INVALID', update: (input) => withAction(input, { nonceEpoch: 1 }) },
  ];

  it.each(blockCases)('blocks $label', ({ update, reason }) => {
    const input = validEvaluationInput(policy());
    expect(evaluateAction(update(input))).toEqual({ verdict: 'BLOCK', reason });
  });

  it('holds actions that exceed the human approval threshold', () => {
    const input = validEvaluationInput(policy());
    input.action.amount = '801';
    expect(evaluateAction(input)).toEqual({ verdict: 'HOLD', reason: 'APPROVAL_REQUIRED' });
  });

  it('allows an action exactly at the approval threshold', () => {
    const input = validEvaluationInput(policy());
    input.action.amount = '800';
    expect(evaluateAction(input)).toEqual({ verdict: 'ALLOW', reason: 'POLICY_PASS' });
  });

  it('blocks unavailable budget measurements instead of treating them as zero', () => {
    const input = validEvaluationInput(policy());
    expect(evaluateAction({ ...input, spentInWindow: null })).toEqual({ verdict: 'BLOCK', reason: 'BUDGET_UNAVAILABLE' });
  });

  it('blocks malformed budget counters and action counts', () => {
    const input = validEvaluationInput(policy());
    expect(evaluateAction({ ...input, spentInWindow: 'not-an-integer' })).toEqual({ verdict: 'BLOCK', reason: 'BUDGET_UNAVAILABLE' });
    expect(evaluateAction({ ...input, actionsInWindow: -1 })).toEqual({ verdict: 'BLOCK', reason: 'BUDGET_UNAVAILABLE' });
  });

  it('blocks malformed action amounts with a stable reason', () => {
    const input = validEvaluationInput(policy());
    input.action.amount = '01';
    expect(evaluateAction(input)).toEqual({ verdict: 'BLOCK', reason: 'ACTION_AMOUNT_INVALID' });
    input.action.amount = '0';
    expect(evaluateAction(input)).toEqual({ verdict: 'BLOCK', reason: 'ACTION_AMOUNT_INVALID' });
    input.action.amount = '1'.repeat(79);
    expect(evaluateAction(input)).toEqual({ verdict: 'BLOCK', reason: 'ACTION_AMOUNT_INVALID' });
  });

  it('allows policies that do not configure optional action-count or approval thresholds', () => {
    const optionalLimitsPolicy = PolicyRevisionSchema.parse({
      ...basePolicyInput,
      limits: {
        perAction: '1000',
        cumulative: '5000',
        windowSeconds: 86400,
      },
    });
    expect(evaluateAction(validEvaluationInput(optionalLimitsPolicy))).toEqual({ verdict: 'ALLOW', reason: 'POLICY_PASS' });
  });
});
