import { Client } from '@modelcontextprotocol/client';
import { InMemoryTransport, type McpServer } from '@modelcontextprotocol/server';
import { afterEach, describe, expect, it } from 'vitest';
import type { ActionIntent } from '../../../packages/policy/src/schema.js';
import { createMandateMcpServer, MandateRestMcpClient, resolveOrganizationContext, type MandateMcpApi } from '../src/server.js';

const servers: McpServer[] = [];
const clients: Client[] = [];
afterEach(async () => {
  await Promise.all(clients.splice(0).map(async (client) => client.close()));
  await Promise.all(servers.splice(0).map(async (server) => server.close()));
});

describe('Mandate MCP server', () => {
  it('does not advertise policy read or simulation authority to an agent principal', async () => {
    const calls: string[] = [];
    const api: MandateMcpApi = {
      context: { organizationId: 'org-1', principalType: 'AGENT' },
      async listPolicies() { calls.push('list'); return []; },
      async getPolicy() { calls.push('get'); return null; },
      async simulateAction() { calls.push('simulate'); return { verdict: 'ALLOW' }; },
      async requestAction() { calls.push('request'); return { actionId: 'a' }; },
      async getAction() { return null; },
      async getReceipt() { return null; },
    };
    const server = createMandateMcpServer(api);
    servers.push(server);
    const client = new Client({ name: 'mcp-agent-boundary', version: '1.0.0' });
    clients.push(client);
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    await server.connect(serverTransport);
    await client.connect(clientTransport);
    for (const [name, args] of [
      ['mandate_policy_list', {}],
      ['mandate_policy_get', { policyId: 'policy-1' }],
    ] as const) {
      const result = await client.callTool({ name, arguments: args });
      expect(result.isError).toBe(true);
      expect(result.content).toMatchObject([{ type: 'text', text: 'HUMAN_PRINCIPAL_REQUIRED' }]);
    }
    expect(calls).toEqual([]);
  });

  it('keeps policy reads available to a human while rejecting human action submission', async () => {
    const calls: string[] = [];
    const api: MandateMcpApi = {
      context: { organizationId: 'org-1', principalType: 'HUMAN' },
      async listPolicies() { calls.push('list'); return [{ id: 'policy-1' }]; },
      async getPolicy(id) { calls.push('get'); return { id }; },
      async simulateAction() { calls.push('simulate'); return { verdict: 'BLOCK' }; },
      async requestAction() { calls.push('request'); return {}; },
      async getAction() { return null; },
      async getReceipt() { return null; },
    };
    const server = createMandateMcpServer(api);
    servers.push(server);
    const client = new Client({ name: 'mcp-human-boundary', version: '1.0.0' });
    clients.push(client);
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    await server.connect(serverTransport);
    await client.connect(clientTransport);
    expect((await client.callTool({ name: 'mandate_policy_list', arguments: {} })).isError).not.toBe(true);
    expect((await client.callTool({ name: 'mandate_policy_get', arguments: { policyId: 'policy-1' } })).isError).not.toBe(true);
    const action = {
      actionId: 'action-1', idempotencyKey: 'mcp-human-idem-1', policyId: 'policy-1', policyRevision: 1,
      policyRevisionHash: `0x${'a'.repeat(64)}`, account: `0x${'1'.repeat(40)}`,
      agentId: 'agent-1', agentKeyVersion: 1, chainId: 10143,
      target: `0x${'2'.repeat(40)}`, selector: '0x12345678', asset: `0x${'3'.repeat(40)}`,
      recipient: `0x${'4'.repeat(40)}`, amount: '1', nonce: 0, nonceEpoch: 0, expiresAt: 1_900_000_000,
    };
    const request = await client.callTool({ name: 'mandate_action_request', arguments: action });
    expect(request.isError).toBe(true);
    expect(request.content).toMatchObject([{ type: 'text', text: 'AGENT_PRINCIPAL_REQUIRED' }]);
    expect(calls).toEqual(['list', 'get']);
  });
  it('registers tenant-bound tools and exposes list/get/simulate/request/receipt capabilities through MCP', async () => {
    const calls: string[] = [];
    const observed: { simulatedAction: ActionIntent | null } = { simulatedAction: null };
    const api: MandateMcpApi = {
      context: { organizationId: 'org-1', principalType: 'AGENT' },
      async listPolicies() { calls.push('listPolicies'); return [{ id: 'policy-1', state: 'ACTIVE' }]; },
      async getPolicy(id) { calls.push(`getPolicy:${id}`); return { id, state: 'ACTIVE' }; },
      async simulateAction(action) { observed.simulatedAction = action; calls.push('simulateAction'); return { verdict: 'ALLOW' }; },
      async requestAction(_action) { calls.push('requestAction'); return { actionId: 'action-1', state: 'RESERVED' }; },
      async getAction(id) { calls.push(`getAction:${id}`); return { actionId: id, state: 'RECONCILED' }; },
      async getReceipt(id) { calls.push(`getReceipt:${id}`); return { actionId: id, status: 'FINAL' }; },
    };
    const server = createMandateMcpServer(api);
    servers.push(server);
    const client = new Client({ name: 'mandate-mcp-test', version: '1.0.0' });
    clients.push(client);
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    await server.connect(serverTransport);
    await client.connect(clientTransport);
    const listed = await client.listTools();
    expect(listed.tools.map((tool) => tool.name)).toEqual([
      'mandate_policy_list', 'mandate_policy_get', 'mandate_action_simulate',
      'mandate_action_request', 'mandate_action_get', 'mandate_receipt_get',
    ]);
    expect(listed.tools.find((tool) => tool.name === 'mandate_policy_list')?.inputSchema).not.toHaveProperty('properties.orgId');
    const result = await client.callTool({ name: 'mandate_policy_get', arguments: { policyId: 'policy-1' } });
    expect(result.isError).toBe(true);
    expect(calls).not.toContain('getPolicy:policy-1');
    const action = {
      actionId: 'action-1', idempotencyKey: 'mcp-action-idem-1', policyId: 'policy-1', policyRevision: 1,
      policyRevisionHash: `0x${'a'.repeat(64)}`, 
      account: `0x${'1'.repeat(40)}`, agentId: 'agent-1', agentKeyVersion: 1, chainId: 10143,
      target: `0x${'2'.repeat(40)}`, selector: '0x12345678', asset: `0x${'3'.repeat(40)}`,
      recipient: `0x${'4'.repeat(40)}`, amount: '1', nonce: 0, nonceEpoch: 0, expiresAt: 1_900_000_000,
    };
    const simulation = await client.callTool({ name: 'mandate_action_simulate', arguments: action });
    expect(simulation.isError).toBe(true);
    expect(observed.simulatedAction).toBeNull();
    const request = await client.callTool({ name: 'mandate_action_request', arguments: action });
    expect(request.content).toMatchObject([{ type: 'text', text: '{"actionId":"action-1","state":"RESERVED"}' }]);
    expect(calls).toContain('requestAction');
    const receipt = await client.callTool({ name: 'mandate_receipt_get', arguments: { id: 'action-1' } });
    expect(receipt.content).toMatchObject([{ type: 'text', text: '{"actionId":"action-1","status":"FINAL"}' }]);
  });

  it('validates configured identity context and pins REST calls to it', async () => {
    const requests: Array<{ url: string; authorization: string | null }> = [];
    const fetcher: typeof fetch = async (input, init) => {
      const url = String(input);
      const headers = new Headers(init?.headers);
      requests.push({ url, authorization: headers.get('authorization') });
      const payload = url.endsWith('/api/v1/me')
        ? { principal: { type: 'HUMAN', subject: 'human-1' }, organizations: [{ organizationId: 'org-1', role: 'OWNER' }] }
        : { policies: [] };
      return new Response(JSON.stringify(payload), { status: 200, headers: { 'content-type': 'application/json' } });
    };
    const api = await MandateRestMcpClient.connect('https://mandate.example/api', 'a'.repeat(32), null, fetcher);
    expect(api.context).toEqual({ organizationId: 'org-1', principalType: 'HUMAN' });
    await api.listPolicies();
    expect(requests.map((request) => request.url)).toEqual([
      'https://mandate.example/api/v1/me', 'https://mandate.example/api/v1/orgs/org-1/policies',
    ]);
    expect(requests.every((request) => request.authorization === `Bearer ${'a'.repeat(32)}`)).toBe(true);
    await expect(MandateRestMcpClient.connect('http://public.example/api', 'a'.repeat(32), 'org-1', fetcher)).rejects.toThrow('must be HTTPS');
  });

  it('resolves a single organization from the authenticated identity and rejects ambiguous or ungranted selection', () => {
    expect(resolveOrganizationContext({
      principal: { type: 'HUMAN', subject: 'human-1' },
      organizations: [{ organizationId: 'org-1', role: 'OWNER' }],
    }, null)).toEqual({ organizationId: 'org-1', principalType: 'HUMAN' });
    expect(() => resolveOrganizationContext({
      principal: { type: 'HUMAN', subject: 'human-1' },
      organizations: [{ organizationId: 'org-1', role: 'OWNER' }, { organizationId: 'org-2', role: 'ADMIN' }],
    }, null)).toThrow('MANDATE_ORGANIZATION_ID is required');
    expect(() => resolveOrganizationContext({
      principal: { type: 'HUMAN', subject: 'human-1' },
      organizations: [{ organizationId: 'org-1', role: 'OWNER' }],
    }, 'org-2')).toThrow('not present in the authenticated identity');
  });
});
