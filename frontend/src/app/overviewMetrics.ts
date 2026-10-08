import type { AgentList, Alerts, PolicyList, Receipts } from '../api/schemas';

interface MetricRequest<T> {
  readonly data: T | null;
  readonly loading: boolean;
  readonly error: string | null;
}
interface OverviewMetricsInput {
  readonly agents: MetricRequest<AgentList>;
  readonly policies: MetricRequest<PolicyList>;
  readonly receipts: MetricRequest<Receipts>;
  readonly alerts: MetricRequest<Alerts>;
}
export interface OverviewMetric {
  readonly label: string;
  readonly value: number | '—' | 'Unavailable';
  readonly note: string;
  readonly href: string;
}

function metric<T>(request: MetricRequest<T>, label: string, href: string, count: (data: T) => number, note: (data: T) => string): OverviewMetric {
  if (request.error !== null) return { label, href, value: 'Unavailable', note: 'API request failed' };
  if (request.loading) return { label, href, value: '—', note: 'Loading live data' };
  if (request.data === null) return { label, href, value: '—', note: 'Awaiting API data' };
  return { label, href, value: count(request.data), note: note(request.data) };
}

export function buildOverviewMetrics(input: OverviewMetricsInput): readonly OverviewMetric[] {
  return [
    metric(input.agents, 'Registered agents', '/app/agents', (data) => data.agents.length, () => 'Identity records'),
    metric(input.policies, 'Policies', '/app/policies', (data) => data.policies.length, (data) => `${data.policies.filter((policy) => policy.state === 'ACTIVE').length} active`),
    metric(input.receipts, 'Recent receipts', '/app/activity', (data) => data.receipts.length, () => 'Latest 5 receipt records'),
    metric(input.alerts, 'Recent signals', '/app/activity', (data) => data.alerts.length, () => 'Latest 5 alert records'),
  ];
}
