import { describe, expect, it } from 'vitest';
import { MandateApiError, MandateClient } from '../src/client.js';

const validAction = {
  actionId: 'action-1', idempotencyKey: 'request-1', policyId: 'policy-1', policyRevision: 1,
  policyRevisionHash: `0x${'a'.repeat(64)}`, organizationId: 'org-other', account: `0x${'1'.repeat(40)}`,
  agentId: 'agent-1', agentKeyVersion: 1, chainId: 10143, target: `0x${'2'.repeat(40)}`,
  selector: '0x12345678', asset: `0x${'3'.repeat(40)}`, recipient: `0x${'4'.repeat(40)}`,
  amount: '1', nonce: 0, nonceEpoch: 0, expiresAt: 1_900_000_000,
};

describe('Mandate SDK REST client', () => {
  it('records owner-initiated deep-reorg reservation decisions through the API', async () => {
    const calls: Array<{ url: string; method: string; body: string | null; key: string | null }> = [];
    const fetcher: typeof fetch = async (input, init) => {
      const url = String(input);
      calls.push({ url, method: init?.method ?? 'GET', body: typeof init?.body === 'string' ? init.body : null,
        key: new Headers(init?.headers).get('idempotency-key') });
      const payload = url.endsWith('/api/v1/me')
        ? { principal: { type: 'HUMAN', subject: 'owner' }, organizations: [{ organizationId: 'org-1', role: 'OWNER' }] }
        : { actionId: 'action-7', actionState: 'REORGED', reservationState: 'RELEASED' };
      return new Response(JSON.stringify(payload), { status: url.endsWith('/api/v1/me') ? 200 : 201 });
    };
    const client = await MandateClient.connect({ apiUrl: 'https://mandate.example', token: 'a'.repeat(32), fetcher });
    await expect(client.resolveDeepReorg('action-7', 'RELEASED', 'No settlement in independent records.', 'resolution-1', `0x${'a'.repeat(64)}`))
      .resolves.toMatchObject({ actionState: 'REORGED', reservationState: 'RELEASED' });
    expect(calls[1]).toEqual({
      url: 'https://mandate.example/api/v1/orgs/org-1/actions/action-7/reorg-resolution', method: 'POST',
      body: JSON.stringify({ disposition: 'RELEASED', reason: 'No settlement in independent records.', evidenceHash: `0x${'a'.repeat(64)}` }),
      key: 'resolution-1',
    });
  });

  it('supports human onboarding with no organization and selects a newly created tenant', async () => {
    const requests: Array<{ url: string; method: string; body: string | null; idempotencyKey: string | null }> = [];
    let onboarded = false;
    const fetcher: typeof fetch = async (input, init) => {
      const url = String(input);
      const method = init?.method ?? 'GET';
      const body = typeof init?.body === 'string' ? init.body : null;
      const idempotencyKey = new Headers(init?.headers).get('idempotency-key');
      requests.push({ url, method, body, idempotencyKey });
      if (url.endsWith('/api/v1/me')) return new Response(JSON.stringify({
        principal: { type: 'HUMAN', subject: 'new-human' },
        organizations: onboarded ? [{ organizationId: 'org-new', role: 'OWNER' }] : [],
      }), { status: 200 });
      if (url.endsWith('/api/v1/orgs')) {
        onboarded = true;
        return new Response(JSON.stringify({ organization: {
          organizationId: 'org-new', displayName: 'New organization', role: 'OWNER', createdAt: '2026-10-06T00:00:00.000Z',
        } }), { status: 201 });
      }
      return new Response(JSON.stringify({ policies: [] }), { status: 200 });
    };
    const client = await MandateClient.connect({ apiUrl: 'https://mandate.example', token: 'a'.repeat(32), fetcher });
    expect(client.context).toEqual({ organizationId: null, principalType: 'HUMAN' });
    const created = await client.createOrganization('New organization', 'onboard-1');
    expect(created).toMatchObject({ organization: { organizationId: 'org-new' } });
    const selected = await client.selectOrganization('org-new');
    expect(selected.context).toEqual({ organizationId: 'org-new', principalType: 'HUMAN' });
    expect(await selected.listPolicies()).toEqual({ policies: [] });
    expect(requests.map(({ url, method, idempotencyKey }) => ({ url, method, idempotencyKey }))).toEqual([
      { url: 'https://mandate.example/api/v1/me', method: 'GET', idempotencyKey: null },
      { url: 'https://mandate.example/api/v1/orgs', method: 'POST', idempotencyKey: 'onboard-1' },
      { url: 'https://mandate.example/api/v1/me', method: 'GET', idempotencyKey: null },
      { url: 'https://mandate.example/api/v1/orgs/org-new/policies', method: 'GET', idempotencyKey: null },
    ]);
    expect(requests[1]?.body).toBe(JSON.stringify({ displayName: 'New organization' }));
  });

  it('supports account enrollment and model-provider credential operations without exposing secrets in errors', async () => {
    const requests: Array<{ url: string; method: string; body: string | null }> = [];
    const fetcher: typeof fetch = async (input, init) => {
      const url = String(input);
      const body = typeof init?.body === 'string' ? init.body : null;
      requests.push({ url, method: init?.method ?? 'GET', body });
      if (url.endsWith('/api/v1/me')) return new Response(JSON.stringify({
        principal: { type: 'HUMAN', subject: 'owner' }, organizations: [{ organizationId: 'org-1', role: 'OWNER' }],
      }), { status: 200 });
      if (url.endsWith('/accounts')) return new Response(JSON.stringify({ accounts: [] }), { status: 200 });
      if (url.endsWith('/integrations/model-providers/DEEPSEEK') && init?.method === 'PUT') return new Response(JSON.stringify({ provider: 'DEEPSEEK', maskedSuffix: 'abcd' }), { status: 201 });
      if (url.endsWith('/integrations/model-providers')) return new Response(JSON.stringify({ credentials: [] }), { status: 200 });
      return new Response(null, { status: 204 });
    };
    const client = await MandateClient.connect({ apiUrl: 'https://mandate.example', token: 'a'.repeat(32), fetcher });
    expect(await client.listAccounts()).toEqual({ accounts: [] });
    expect(await client.setModelProviderCredential('DEEPSEEK', 's'.repeat(32), 'provider-1')).toMatchObject({ provider: 'DEEPSEEK' });
    expect(await client.deleteModelProviderCredential('DEEPSEEK')).toBeNull();
    expect(requests).toEqual([
      { url: 'https://mandate.example/api/v1/me', method: 'GET', body: null },
      { url: 'https://mandate.example/api/v1/orgs/org-1/accounts', method: 'GET', body: null },
      { url: 'https://mandate.example/api/v1/orgs/org-1/integrations/model-providers/DEEPSEEK', method: 'PUT', body: JSON.stringify({ apiKey: 's'.repeat(32) }) },
      { url: 'https://mandate.example/api/v1/orgs/org-1/integrations/model-providers/DEEPSEEK', method: 'DELETE', body: null },
    ]);
  });

  it('supports audit pagination with a validated opaque sequence cursor', async () => {
    const urls: string[] = [];
    const fetcher: typeof fetch = async (input) => {
      const url = String(input);
      urls.push(url);
      const payload = url.endsWith('/api/v1/me')
        ? { principal: { type: 'HUMAN', subject: 'owner' }, organizations: [{ organizationId: 'org-1', role: 'OWNER' }] }
        : { events: [] };
      return new Response(JSON.stringify(payload), { status: 200 });
    };
    const client = await MandateClient.connect({ apiUrl: 'https://mandate.example', token: 'a'.repeat(32), fetcher });
    await client.getAuditEvents(20, '9001');
    await expect(client.getAuditEvents(20, '0')).rejects.toThrow();
    expect(urls).toEqual([
      'https://mandate.example/api/v1/me',
      'https://mandate.example/api/v1/orgs/org-1/audit-events?limit=20&beforeSequence=9001',
    ]);
  });

  it('requests signed audit exports only for humans with bounded pagination', async () => {
    const urls: string[] = [];
    const fetcher: typeof fetch = async (input) => {
      const url = String(input);
      urls.push(url);
      const payload = url.endsWith('/api/v1/me')
        ? { principal: { type: 'HUMAN', subject: 'owner' }, organizations: [{ organizationId: 'org-1', role: 'OWNER' }] }
        : { algorithm: 'Ed25519', events: [] };
      return new Response(JSON.stringify(payload), { status: 200 });
    };
    const client = await MandateClient.connect({ apiUrl: 'https://mandate.example', token: 'a'.repeat(32), fetcher });
    await client.getSignedAuditExport(10_000, '9001');
    await expect(client.getSignedAuditExport(10_001)).rejects.toThrow('between 1 and 10000');
    expect(urls).toEqual([
      'https://mandate.example/api/v1/me',
      'https://mandate.example/api/v1/orgs/org-1/audit-exports?limit=10000&beforeSequence=9001',
    ]);
  });

  it('does not expose the signed-audit-export operation to an agent identity', async () => {
    const fetcher: typeof fetch = async () => new Response(JSON.stringify({
      principal: { type: 'AGENT', organizationId: 'org-agent', agentId: 'agent-1', keyVersion: 1 },
    }), { status: 200 });
    const client = await MandateClient.connect({ apiUrl: 'https://mandate.example', token: 'a'.repeat(32), fetcher });
    await expect(client.getSignedAuditExport()).rejects.toThrow('requires a human principal');
  });

  it('resolves a single tenant and sends authenticated calls to the canonical API route', async () => {
    const requests: Array<{ url: string; authorization: string | null }> = [];
    const fetcher: typeof fetch = async (input, init) => {
      const url = String(input);
      const authorization = new Headers(init?.headers).get('authorization');
      requests.push({ url, authorization });
      const payload = url.endsWith('/api/v1/me')
        ? { principal: { type: 'HUMAN', subject: 'human-1' }, organizations: [{ organizationId: 'org-1', role: 'OWNER' }] }
        : { policies: [] };
      return new Response(JSON.stringify(payload), { status: 200, headers: { 'content-type': 'application/json' } });
    };
    const client = await MandateClient.connect({ apiUrl: 'https://mandate.example/api', token: 'a'.repeat(32), fetcher });
    expect(client.context).toEqual({ organizationId: 'org-1', principalType: 'HUMAN' });
    expect(await client.listPolicies()).toEqual({ policies: [] });
    expect(requests).toEqual([
      { url: 'https://mandate.example/api/v1/me', authorization: `Bearer ${'a'.repeat(32)}` },
      { url: 'https://mandate.example/api/v1/orgs/org-1/policies', authorization: `Bearer ${'a'.repeat(32)}` },
    ]);
  });

  it('requires HTTPS outside loopback and rejects malformed tokens', async () => {
    const fetcher: typeof fetch = async () => new Response('{}', { status: 200 });
    await expect(MandateClient.connect({ apiUrl: 'http://public.example', token: 'a'.repeat(32), fetcher })).rejects.toThrow('must be HTTPS');
    await expect(MandateClient.connect({ apiUrl: 'http://127.0.0.1:3000', token: 'short', fetcher })).rejects.toThrow('MANDATE_API_TOKEN is invalid');
    await expect(MandateClient.connect({ apiUrl: 'https://user:pass@mandate.example', token: 'a'.repeat(32), fetcher })).rejects.toThrow('without credentials');
  });

  it('binds agent credentials to their API-derived organization and rejects ambiguous human context', async () => {
    const agentFetcher: typeof fetch = async () => new Response(JSON.stringify({
      principal: { type: 'AGENT', organizationId: 'org-agent', agentId: 'agent-1', keyVersion: 2 },
    }), { status: 200 });
    const agent = await MandateClient.connect({ apiUrl: 'https://mandate.example', token: 'd'.repeat(32), fetcher: agentFetcher });
    expect(agent.context).toEqual({ organizationId: 'org-agent', principalType: 'AGENT' });
    await expect(MandateClient.connect({ apiUrl: 'https://mandate.example', token: 'd'.repeat(32), organizationId: 'org-other', fetcher: agentFetcher }))
      .rejects.toThrow('does not match the authenticated agent organization');

    const humanFetcher: typeof fetch = async () => new Response(JSON.stringify({
      principal: { type: 'HUMAN', subject: 'human-1' },
      organizations: [{ organizationId: 'org-1', role: 'OWNER' }, { organizationId: 'org-2', role: 'ADMIN' }],
    }), { status: 200 });
    await expect(MandateClient.connect({ apiUrl: 'https://mandate.example', token: 'e'.repeat(32), fetcher: humanFetcher }))
      .rejects.toThrow('MANDATE_ORGANIZATION_ID is required');
  });

  it('rejects a cross-organization action before sending a REST request', async () => {
    let requestCount = 0;
    const fetcher: typeof fetch = async (input) => {
      requestCount += 1;
      return String(input).endsWith('/api/v1/me')
        ? new Response(JSON.stringify({ principal: { type: 'HUMAN', subject: 'human-1' }, organizations: [{ organizationId: 'org-1', role: 'OWNER' }] }), { status: 200 })
        : new Response(JSON.stringify({ verdict: 'BLOCK' }), { status: 200 });
    };
    const client = await MandateClient.connect({ apiUrl: 'https://mandate.example', token: 'f'.repeat(32), fetcher });
    await expect(client.simulateAction(validAction)).rejects.toThrow('Action organization does not match');
    expect(requestCount).toBe(1);
  });

  it('surfaces typed API error code, request ID, and retry delay without response-body leakage', async () => {
    const fetcher: typeof fetch = async (input) => String(input).endsWith('/api/v1/me')
      ? new Response(JSON.stringify({ principal: { type: 'HUMAN', subject: 'human-1' }, organizations: [{ organizationId: 'org-1', role: 'OWNER' }] }), { status: 200 })
      : new Response(JSON.stringify({ error: { code: 'RATE_LIMITED', message: 'Request limit exceeded', requestId: 'req-8' } }), {
        status: 429, headers: { 'content-type': 'application/json', 'retry-after': '17' },
      });
    const client = await MandateClient.connect({
      apiUrl: 'https://mandate.example', token: 'b'.repeat(32), organizationId: 'org-1', fetcher,
    });
    await expect(client.listPolicies()).rejects.toMatchObject({
      name: 'MandateApiError', code: 'RATE_LIMITED', statusCode: 429, requestId: 'req-8', retryAfterSeconds: 17,
    } satisfies Partial<MandateApiError>);
    await expect(client.listPolicies()).rejects.toThrow('Request limit exceeded');
  });

  it('does not include malformed server response bodies in thrown errors', async () => {
    const fetcher: typeof fetch = async (input) => String(input).endsWith('/api/v1/me')
      ? new Response(JSON.stringify({ principal: { type: 'HUMAN', subject: 'human-1' }, organizations: [{ organizationId: 'org-1', role: 'OWNER' }] }), { status: 200 })
      : new Response('must-not-appear-in-error', { status: 502 });
    const client = await MandateClient.connect({ apiUrl: 'https://mandate.example', token: 'c'.repeat(32), organizationId: 'org-1', fetcher });
    await expect(client.listPolicies()).rejects.toMatchObject({ name: 'MandateApiError', code: 'INVALID_RESPONSE', statusCode: 502 });
  });
});
