import { describe, expect, it } from 'vitest';
import { AgentListSchema, AlertsSchema, PolicyListSchema, ReceiptsSchema } from '../src/api/schemas';
import { buildOverviewMetrics } from '../src/app/overviewMetrics';

const ready = {
  agents: { data: AgentListSchema.parse({ agents: [{ id: 'agent-a', displayName: 'Agent A', status: 'ACTIVE', keyVersion: 1, createdAt: '2026-10-07' }] }), loading: false, error: null },
  policies: { data: PolicyListSchema.parse({ policies: [{ id: 'policy-a', accountId: 'account-a', currentRevision: 1, state: 'DRAFT', revisionHash: '0xhash', createdAt: '2026-10-07' }] }), loading: false, error: null },
  receipts: { data: ReceiptsSchema.parse({ receipts: [{ id: 'receipt-a', actionId: 'action-a', chainId: 10143, transactionHash: '0xhash', blockNumber: '1', blockHash: '0xblock', status: 'TENTATIVE', observedAt: '2026-10-07' }] }), loading: false, error: null },
  alerts: { data: AlertsSchema.parse({ alerts: [{ id: 'alert-a', eventType: 'ORGANIZATION_ACTIVITY', title: 'Activity', aggregateId: 'org-a', createdAt: '2026-10-07' }] }), loading: false, error: null },
};

describe('overview metrics', () => {
  it('labels limited receipt/alert lists as recent records rather than final evidence or open alerts', () => {
    const metrics = buildOverviewMetrics(ready);
    expect(metrics.map((metric) => metric.value)).toEqual([1, 1, 1, 1]);
    expect(metrics[1]?.note).toBe('0 active');
    expect(metrics[2]?.note).toBe('Latest 5 receipt records');
    expect(metrics[3]?.label).toBe('Recent signals');
    expect(metrics[3]?.note).toBe('Latest 5 alert records');
    expect(metrics.map((metric) => metric.href)).toEqual(['/app/agents', '/app/policies', '/app/activity', '/app/activity']);
  });

  it('keeps pending receipts and alerts as unknown even after agents and policies have loaded', () => {
    const metrics = buildOverviewMetrics({ ...ready, receipts: { data: null, loading: true, error: null }, alerts: { data: null, loading: true, error: null } });
    expect(metrics.map((metric) => metric.value)).toEqual([1, 1, '—', '—']);
    expect(metrics[2]?.note).toBe('Loading live data');
    expect(metrics[3]?.note).toBe('Loading live data');
  });

  it('never presents an API error or stale data as zero or a successful count', () => {
    const metrics = buildOverviewMetrics({
      agents: { ...ready.agents, error: 'request failed' },
      policies: { ...ready.policies, error: 'request failed' },
      receipts: { ...ready.receipts, error: 'request failed' },
      alerts: { ...ready.alerts, error: 'request failed' },
    });
    expect(metrics.map((metric) => metric.value)).toEqual(['Unavailable', 'Unavailable', 'Unavailable', 'Unavailable']);
    expect(metrics.every((metric) => metric.note === 'API request failed')).toBe(true);
  });

  it('keeps the initial not-yet-requested state unknown', () => {
    const pending = { data: null, loading: false, error: null };
    const metrics = buildOverviewMetrics({ agents: pending, policies: pending, receipts: pending, alerts: pending });
    expect(metrics.map((metric) => metric.value)).toEqual(['—', '—', '—', '—']);
    expect(metrics.every((metric) => metric.note === 'Awaiting API data')).toBe(true);
  });

  it('reports genuine empty successful lists as zero', () => {
    const metrics = buildOverviewMetrics({ agents: { data: { agents: [] }, loading: false, error: null }, policies: { data: { policies: [] }, loading: false, error: null }, receipts: { data: { receipts: [] }, loading: false, error: null }, alerts: { data: { alerts: [] }, loading: false, error: null } });
    expect(metrics.map((metric) => metric.value)).toEqual([0, 0, 0, 0]);
  });

  it('hides the previous list during a new tenant request', () => {
    const metrics = buildOverviewMetrics({ ...ready, agents: { ...ready.agents, loading: true } });
    expect(metrics[0]?.value).toBe('—');
  });

  it('counts active policies without counting drafts as active', () => {
    const existing = ready.policies.data.policies[0];
    if (existing === undefined) throw new Error('Policy test fixture is missing');
    const metrics = buildOverviewMetrics({ ...ready, policies: { data: { policies: [existing, { ...existing, id: 'active-policy', state: 'ACTIVE' }] }, loading: false, error: null } });
    expect(metrics[1]?.value).toBe(2);
    expect(metrics[1]?.note).toBe('1 active');
  });
});
