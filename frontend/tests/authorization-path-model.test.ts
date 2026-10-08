import { describe, expect, it } from 'vitest';
import { buildAuthorizationPath } from '../src/app/authorizationPathModel';

describe('buildAuthorizationPath', () => {
  it('distinguishes active agent, policy and verified account readiness from final evidence', () => {
    const path = buildAuthorizationPath({
      agents: [{ status: 'ACTIVE' }, { status: 'REVOKED' }],
      policies: [{ state: 'ACTIVE' }, { state: 'DRAFT' }],
      accounts: [{ status: 'ACTIVE', verifiedAt: '2026-10-07T00:00:00.000Z' }, { status: 'ACTIVE', verifiedAt: null }],
      receipts: [{ status: 'FINAL' }, { status: 'TENTATIVE' }],
    });

    expect(path.map(({ count, status }) => [count, status])).toEqual([
      [1, 'ready'], [1, 'ready'], [1, 'ready'], [1, 'evidence'],
    ]);
    expect(path[1]?.note).toContain('Matching rules still apply');
    expect(path[3]?.note).toContain('latest 5');
  });

  it('keeps execution prerequisites blocked when no active policy or verified account exists', () => {
    const path = buildAuthorizationPath({
      agents: [],
      policies: [{ state: 'DRAFT' }, { state: 'REVOKED' }, { state: 'EXPIRED' }],
      accounts: [{ status: 'ACTIVE', verifiedAt: null }, { status: 'UNSUPPORTED', verifiedAt: '2026-10-07T00:00:00.000Z' }],
      receipts: [],
    });

    expect(path.map(({ count, status }) => [count, status])).toEqual([
      [0, 'attention'], [0, 'attention'], [0, 'attention'], [0, 'pending'],
    ]);
    expect(path[1]?.note).toContain('Actions remain blocked');
    expect(path[2]?.note).toContain('supported account');
  });

  it('reports zero evidence independently of authorization readiness', () => {
    const path = buildAuthorizationPath({ agents: [{ status: 'ACTIVE' }], policies: [{ state: 'ACTIVE' }], accounts: [{ status: 'ACTIVE', verifiedAt: '2026-10-07T00:00:00.000Z' }], receipts: [{ status: 'REORGED' }, { status: 'TENTATIVE' }] });
    expect(path[0]?.status).toBe('ready');
    expect(path[1]?.status).toBe('ready');
    expect(path[2]?.status).toBe('ready');
    expect(path[3]?.count).toBe(0);
    expect(path[3]?.note).toContain('No final receipts');
  });

  it('uses plural receipt copy and excludes paused accounts even if previously verified', () => {
    const path = buildAuthorizationPath({ agents: [], policies: [], accounts: [{ status: 'PAUSED', verifiedAt: '2026-10-07T00:00:00.000Z' }], receipts: [{ status: 'FINAL' }, { status: 'FINAL' }, { status: 'TENTATIVE' }] });
    expect(path[2]?.count).toBe(0);
    expect(path[3]?.note).toContain('2 final receipts');
  });
});
