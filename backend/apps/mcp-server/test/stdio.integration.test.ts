import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { fileURLToPath } from 'node:url';
import { Client } from '@modelcontextprotocol/client';
import { StdioClientTransport } from '@modelcontextprotocol/client/stdio';
import { afterEach, describe, expect, it } from 'vitest';

let apiServer: Server | null = null;
let mcpClient: Client | null = null;

afterEach(async () => {
  if (mcpClient !== null) { await mcpClient.close(); mcpClient = null; }
  if (apiServer !== null) {
    await new Promise<void>((resolve, reject) => apiServer?.close((error) => error === undefined ? resolve() : reject(error)));
    apiServer = null;
  }
});

function send(response: ServerResponse, status: number, body: Readonly<Record<string, unknown>>): void {
  response.writeHead(status, { 'content-type': 'application/json' });
  response.end(JSON.stringify(body));
}

function handleApiRequest(request: IncomingMessage, response: ServerResponse, calls: string[]): void {
  calls.push(`${request.method ?? 'GET'} ${request.url ?? '/'}`);
  if (request.headers.authorization !== `Bearer ${'m'.repeat(32)}`) { send(response, 401, { error: { code: 'UNAUTHENTICATED', message: 'No', requestId: 'test' } }); return; }
  if (request.url === '/api/v1/me') {
    send(response, 200, { principal: { type: 'HUMAN', subject: 'human-1' }, organizations: [{ organizationId: 'org-1', role: 'OWNER' }] }); return;
  }
  if (request.url === '/api/v1/orgs/org-1/policies') { send(response, 200, { policies: [{ id: 'policy-1', state: 'ACTIVE' }] }); return; }
  send(response, 404, { error: { code: 'RESOURCE_NOT_FOUND', message: 'Not found', requestId: 'test' } });
}

describe('Mandate MCP stdio process', () => {
  it('starts as a real MCP subprocess, derives tenant context from /me, and speaks clean JSON-RPC on stdout', async () => {
    const calls: string[] = [];
    apiServer = createServer((request, response) => handleApiRequest(request, response, calls));
    await new Promise<void>((resolve, reject) => {
      apiServer?.once('error', reject);
      apiServer?.listen(0, '127.0.0.1', resolve);
    });
    const address = apiServer.address();
    if (address === null || typeof address === 'string') throw new Error('Test API server did not bind');
    const command = new Client({ name: 'mandate-stdio-test', version: '1.0.0' });
    mcpClient = command;
    const script = fileURLToPath(new URL('../src/main.ts', import.meta.url));
    const transport = new StdioClientTransport({
      command: process.execPath,
      args: ['--import', 'tsx', script],
      cwd: process.cwd(),
      env: { PATH: process.env.PATH ?? '', MANDATE_API_URL: `http://127.0.0.1:${address.port}`, MANDATE_API_TOKEN: 'm'.repeat(32) },
      stderr: 'pipe',
    });
    await command.connect(transport);
    const tools = await command.listTools();
    expect(tools.tools.map((tool) => tool.name)).toContain('mandate_policy_list');
    const result = await command.callTool({ name: 'mandate_policy_list', arguments: {} });
    expect(result.content).toMatchObject([{ type: 'text', text: '{"policies":[{"id":"policy-1","state":"ACTIVE"}]}' }]);
    const mutation = await command.callTool({ name: 'mandate_action_request', arguments: {} });
    expect(mutation.isError).toBe(true);
    expect(calls).toEqual(['GET /api/v1/me', 'GET /api/v1/orgs/org-1/policies']);
  });
});
