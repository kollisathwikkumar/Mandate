import { describe, expect, it } from 'vitest';
import { Client } from '@modelcontextprotocol/client';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/client';
import { createHostedMcpFetchHandler, parseHostedMcpConfiguration, type HostedMcpConfiguration } from '../src/hosted.js';

const configuration: HostedMcpConfiguration = {
  apiUrl: 'http://127.0.0.1:3000/api',
  resourceUrl: 'https://mcp.example.com/mcp',
  issuer: 'https://identity.example.com',
  organizationId: null,
  allowedOrigins: ['https://client.example.com'],
};
const validToken = `e30.${Buffer.from(JSON.stringify({ sub: 'human-1', aud: 'https://mcp.example.com/mcp', exp: Math.floor(Date.now() / 1000) + 300 })).toString('base64url')}.signature`;
const wrongResourceToken = `e30.${Buffer.from(JSON.stringify({ sub: 'human-1', aud: 'mandate-api', exp: Math.floor(Date.now() / 1000) + 300 })).toString('base64url')}.signature`;

function apiFetcher(acceptedToken = validToken, requests: string[] = []): typeof fetch {
  return async (input, init) => {
    const url = new URL(String(input));
    const token = new Headers(init?.headers).get('authorization');
    requests.push(`${url.pathname}:${token ?? 'missing'}`);
    if (token !== `Bearer ${acceptedToken}`) {
      return new Response(JSON.stringify({ error: { code: 'UNAUTHENTICATED', message: 'Unauthenticated', requestId: 'test' } }), {
        status: 401, headers: { 'content-type': 'application/json' },
      });
    }
    const payload = url.pathname.endsWith('/api/v1/me')
      ? { principal: { type: 'HUMAN', subject: 'human-1' }, organizations: [{ organizationId: 'org-1', role: 'OWNER' }] }
      : { policies: [] };
    return new Response(JSON.stringify(payload), { status: 200, headers: { 'content-type': 'application/json' } });
  };
}

describe('hosted MCP HTTP authorization', () => {
  it('requires canonical HTTPS deployment URLs and a configured OIDC issuer', () => {
    expect(parseHostedMcpConfiguration({
      MANDATE_API_URL: 'http://127.0.0.1:3000/api',
      MANDATE_MCP_RESOURCE_URL: 'https://mcp.example.com/mcp',
      MANDATE_JWT_ISSUER: 'https://identity.example.com',
      MANDATE_MCP_ALLOWED_ORIGINS: 'https://client.example.com',
    })).toEqual(configuration);
    expect(() => parseHostedMcpConfiguration({
      MANDATE_API_URL: 'http://public.example.com/api',
      MANDATE_MCP_RESOURCE_URL: 'https://mcp.example.com/mcp',
      MANDATE_JWT_ISSUER: 'https://identity.example.com',
    })).toThrow('MANDATE_API_URL must use HTTPS');
    expect(() => parseHostedMcpConfiguration({
      MANDATE_API_URL: 'https://api.example.com',
      MANDATE_MCP_RESOURCE_URL: 'http://mcp.example.com/mcp',
      MANDATE_JWT_ISSUER: 'https://identity.example.com',
    })).toThrow('MANDATE_MCP_RESOURCE_URL must use HTTPS');
    expect(() => parseHostedMcpConfiguration({
      MANDATE_API_URL: 'https://api.example.com',
      MANDATE_MCP_RESOURCE_URL: 'https://mcp.example.com/mcp',
      MANDATE_JWT_ISSUER: 'https://identity.example.com',
      MANDATE_MCP_ALLOWED_ORIGINS: 'http://untrusted.example',
    })).toThrow('MANDATE_MCP_ALLOWED_ORIGINS must contain canonical HTTPS origins');
  });

  it('publishes resource metadata that points clients to the configured authorization server', async () => {
    const handler = createHostedMcpFetchHandler(configuration, apiFetcher());
    const response = await handler(new Request('https://mcp.example.com/.well-known/oauth-protected-resource/mcp'));
    expect(response.status).toBe(200);
    expect(await response.json()).toMatchObject({
      resource: 'https://mcp.example.com/mcp',
      authorization_servers: ['https://identity.example.com'],
      bearer_methods_supported: ['header'],
    });
  });

  it('rejects missing and invalid bearer tokens with a metadata discovery challenge', async () => {
    const handler = createHostedMcpFetchHandler(configuration, apiFetcher());
    const missing = await handler(new Request('https://mcp.example.com/mcp', { method: 'POST', headers: { host: 'mcp.example.com' } }));
    expect(missing.status).toBe(401);
    expect(missing.headers.get('www-authenticate')).toContain('resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource/mcp"');

    const invalid = await handler(new Request('https://mcp.example.com/mcp', {
      method: 'POST', headers: { host: 'mcp.example.com', authorization: `Bearer ${'x'.repeat(32)}`, accept: 'application/json, text/event-stream', 'content-type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'test', version: '1' } } }),
    }));
    expect(invalid.status).toBe(401);
  });

  it('authenticates each HTTP exchange before exposing tenant-bound MCP tools', async () => {
    const requests: string[] = [];
    const handler = createHostedMcpFetchHandler(configuration, apiFetcher(validToken, requests));
    const client = new Client({ name: 'hosted-mcp-test', version: '1.0.0' });
    const transport = new StreamableHTTPClientTransport(new URL(configuration.resourceUrl), {
      authProvider: { async token() { return validToken; } },
      fetch: async (input, init) => {
        const headers = new Headers(init?.headers);
        headers.set('host', 'mcp.example.com');
        return handler(new Request(input, { ...init, headers }));
      },
    });
    try {
      await client.connect(transport);
      const tools = await client.listTools();
      expect(tools.tools.map((tool) => tool.name)).toContain('mandate_policy_list');
      const listed = await client.callTool({ name: 'mandate_policy_list', arguments: {} });
      expect(listed.content).toMatchObject([{ type: 'text', text: '{"policies":[]}' }]);
      expect(requests).toContain('/api/v1/orgs/org-1/policies:Bearer ' + validToken);
      expect(requests.filter((request) => request.startsWith('/api/v1/me:')).length).toBeGreaterThanOrEqual(3);
    } finally {
      await client.close();
    }
  });

  it('rejects a JWT accepted by the API when its audience is not this MCP resource', async () => {
    const handler = createHostedMcpFetchHandler(configuration, apiFetcher(wrongResourceToken));
    const response = await handler(new Request('https://mcp.example.com/mcp', {
      method: 'POST',
      headers: { host: 'mcp.example.com', authorization: `Bearer ${wrongResourceToken}`, accept: 'application/json, text/event-stream', 'content-type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'test', version: '1' } } }),
    }));
    expect(response.status).toBe(401);
    expect(response.headers.get('www-authenticate')).toContain('error="invalid_token"');
  });

  it('rejects untrusted browser origins and hosts before API access', async () => {
    const requests: string[] = [];
    const handler = createHostedMcpFetchHandler(configuration, apiFetcher('m'.repeat(32), requests));
    const response = await handler(new Request('https://mcp.example.com/mcp', {
      method: 'POST', headers: { host: 'mcp.example.com', origin: 'https://attacker.example', authorization: `Bearer ${'m'.repeat(32)}` },
    }));
    expect(response.status).toBe(403);
    expect(requests).toEqual([]);
  });

  it('answers preflight only for configured origins and applies CORS to challenge responses', async () => {
    const handler = createHostedMcpFetchHandler(configuration, apiFetcher());
    const preflight = await handler(new Request('https://mcp.example.com/mcp', {
      method: 'OPTIONS', headers: {
        host: 'mcp.example.com', origin: 'https://client.example.com',
        'access-control-request-method': 'POST', 'access-control-request-headers': 'authorization, content-type',
      },
    }));
    expect(preflight.status).toBe(204);
    expect(preflight.headers.get('access-control-allow-origin')).toBe('https://client.example.com');
    expect(preflight.headers.get('access-control-allow-methods')).toContain('POST');

    const challenged = await handler(new Request('https://mcp.example.com/mcp', {
      method: 'POST', headers: { host: 'mcp.example.com', origin: 'https://client.example.com' },
    }));
    expect(challenged.status).toBe(401);
    expect(challenged.headers.get('access-control-allow-origin')).toBe('https://client.example.com');
    expect(challenged.headers.get('www-authenticate')).toContain('resource_metadata=');
  });
});
