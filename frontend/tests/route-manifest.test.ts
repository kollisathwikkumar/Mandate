import { describe, expect, it } from 'vitest';
import { ROUTE_MANIFEST, matchRoute } from '../src/app/routeManifest';

describe('Mandate page route manifest', () => {
  it('defines the 20 architecture page templates', () => {
    expect(ROUTE_MANIFEST).toHaveLength(20);
    expect(ROUTE_MANIFEST.map(({ path }) => path)).toEqual([
      '/', '/how-it-works', '/security', '/integrations', '/developers', '/login',
      '/app/overview', '/app/agents', '/app/agents/:agentId', '/app/policies',
      '/app/policies/new', '/app/policies/:policyId', '/app/policies/:policyId/edit',
      '/app/policies/:policyId/simulate', '/app/approvals', '/app/activity',
      '/app/activity/:actionId', '/app/settings/team', '/app/settings/accounts',
      '/app/settings/integrations',
    ]);
  });

  it('matches detail pages ahead of their collection routes', () => {
    expect(matchRoute('/app/agents/agent-7')?.definition.id).toBe('agent-detail');
    expect(matchRoute('/app/policies/new')?.definition.id).toBe('policy-create');
    expect(matchRoute('/app/policies/pol-7/simulate')?.definition.id).toBe('policy-simulate');
    expect(matchRoute('/app/activity/action-9')?.definition.id).toBe('activity-detail');
  });

  it('rejects unknown or malformed routes rather than silently falling back', () => {
    expect(matchRoute('/app/policies/not-a-real-page/unknown')).toBeUndefined();
    expect(matchRoute('/app/unknown')).toBeUndefined();
  });
});

it.each(['/app/agents/%2F', '/app/agents/%5c', '/app/agents/..', '/app/agents/%00', `/app/agents/${'a'.repeat(129)}`, '/app/agents/%ZZ'])('rejects malformed opaque IDs: %s', (path) => {
  expect(matchRoute(path)).toBeUndefined();
});
