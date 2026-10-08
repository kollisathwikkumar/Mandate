export type RouteAudience = 'public' | 'auth' | 'app';

export interface RouteDefinition {
  readonly id: string;
  readonly path: string;
  readonly title: string;
  readonly audience: RouteAudience;
  readonly description: string;
}

export interface MatchedRoute {
  readonly definition: RouteDefinition;
  readonly params: Readonly<Record<string, string>>;
}

export const ROUTE_MANIFEST = [
  { id: 'home', path: '/', title: 'Overview', audience: 'public', description: 'The Mandate authorization control plane.' },
  { id: 'how-it-works', path: '/how-it-works', title: 'How it works', audience: 'public', description: 'From policy to enforced execution and evidence.' },
  { id: 'security', path: '/security', title: 'Security', audience: 'public', description: 'Boundaries, safeguards, and evidence.' },
  { id: 'integrations', path: '/integrations', title: 'Integrations', audience: 'public', description: 'Supported adapters and interfaces.' },
  { id: 'developers', path: '/developers', title: 'Developers', audience: 'public', description: 'REST, SDK, MCP, and CLI documentation.' },
  { id: 'login', path: '/login', title: 'Sign in', audience: 'auth', description: 'Sign in through your organization identity provider.' },
  { id: 'overview', path: '/app/overview', title: 'Overview', audience: 'app', description: 'Organization activity and control status.' },
  { id: 'agents', path: '/app/agents', title: 'Agents', audience: 'app', description: 'Registered agent identities.' },
  { id: 'agent-detail', path: '/app/agents/:agentId', title: 'Agent detail', audience: 'app', description: 'Agent identity and lifecycle.' },
  { id: 'policies', path: '/app/policies', title: 'Policies', audience: 'app', description: 'Versioned authorization policies.' },
  { id: 'policy-create', path: '/app/policies/new', title: 'New policy', audience: 'app', description: 'Create a draft policy revision.' },
  { id: 'policy-detail', path: '/app/policies/:policyId', title: 'Policy detail', audience: 'app', description: 'Review immutable policy revision state.' },
  { id: 'policy-edit', path: '/app/policies/:policyId/edit', title: 'Edit revision', audience: 'app', description: 'Create the next immutable revision.' },
  { id: 'policy-simulate', path: '/app/policies/:policyId/simulate', title: 'Simulate policy', audience: 'app', description: 'Read-only preflight for a proposed action.' },
  { id: 'approvals', path: '/app/approvals', title: 'Approvals', audience: 'app', description: 'Review exact held action requests.' },
  { id: 'activity', path: '/app/activity', title: 'Activity', audience: 'app', description: 'Tenant-scoped decisions and execution evidence.' },
  { id: 'activity-detail', path: '/app/activity/:actionId', title: 'Action timeline', audience: 'app', description: 'Trace a specific action and receipt.' },
  { id: 'team', path: '/app/settings/team', title: 'Team', audience: 'app', description: 'Organization members and invitations.' },
  { id: 'accounts', path: '/app/settings/accounts', title: 'Accounts', audience: 'app', description: 'Linked smart accounts and adapter status.' },
  { id: 'integrations-settings', path: '/app/settings/integrations', title: 'Integrations', audience: 'app', description: 'Provider credentials and network connections.' },
] as const satisfies readonly RouteDefinition[];

const compilePath = (path: string): RegExp => {
  const segments = path.split('/').filter(Boolean);
  if (segments.length === 0) return /^\/$/;
  const source = segments.map((segment) => segment.startsWith(':') ? '([^/]+)' : segment.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('/');
  return new RegExp(`^/${source}/?$`);
};

export const matchRoute = (pathname: string): MatchedRoute | undefined => {
  for (const definition of ROUTE_MANIFEST) {
    const names = definition.path.split('/').filter(Boolean).filter((segment) => segment.startsWith(':')).map((segment) => segment.slice(1));
    const match = compilePath(definition.path).exec(pathname);
    if (match === null) continue;
    const captures = match.slice(1);
    const params: Record<string, string> = {};
    for (const [index, name] of names.entries()) {
      const value = captures[index];
      if (value === undefined) continue;
      try {
        const decoded = decodeURIComponent(value);
        if (!/^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$/.test(decoded)) return undefined;
        params[name] = decoded;
      } catch {
        return undefined;
      }
    }
    return { definition, params };
  }
  return undefined;
};
