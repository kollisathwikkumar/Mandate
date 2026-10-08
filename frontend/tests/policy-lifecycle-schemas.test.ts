import { describe, expect, it } from 'vitest';
import { PolicyActivationFinalizedSchema, PolicyRevocationFinalizedSchema, PolicySignaturePlanSchema } from '../src/api/schemas';

const planId = '00000000-0000-4000-8000-000000000001';
const revisionHash = `0x${'a'.repeat(64)}`;

describe('Safe policy lifecycle API contracts', () => {
  it('accepts an owner-signature plan but not an active state before finalization', () => {
    expect(PolicySignaturePlanSchema.parse({ planId, state: 'AWAITING_SAFE_OWNER_SIGNATURES', plan: { safeTx: { to: '0x1' } } }).planId).toBe(planId);
    expect(PolicySignaturePlanSchema.safeParse({ planId, state: 'ACTIVE', plan: {} }).success).toBe(false);
  });

  it('requires the backend to report both policy and grant active on activation', () => {
    const result = { planId, policyId: 'policy-1', policyRevision: 2, revisionHash, policyState: 'ACTIVE', grantState: 'ACTIVE', finalized: {} };
    expect(PolicyActivationFinalizedSchema.parse(result).policyState).toBe('ACTIVE');
    expect(PolicyActivationFinalizedSchema.safeParse({ ...result, grantState: 'REVOKED' }).success).toBe(false);
  });

  it('requires the backend to report both policy and grant revoked on revocation', () => {
    const result = { planId, policyId: 'policy-1', policyRevision: 2, revisionHash, previousPolicyEpoch: '1', policyEpoch: '2', policyState: 'REVOKED', grantState: 'REVOKED', finalized: {} };
    expect(PolicyRevocationFinalizedSchema.parse(result).grantState).toBe('REVOKED');
    expect(PolicyRevocationFinalizedSchema.safeParse({ ...result, policyState: 'ACTIVE' }).success).toBe(false);
  });
});
