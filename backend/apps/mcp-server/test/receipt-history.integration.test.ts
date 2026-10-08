import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { Client as PgClient, Pool } from 'pg';
import { Client as McpClient } from '@modelcontextprotocol/client';
import { InMemoryTransport } from '@modelcontextprotocol/server';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createApiServer } from '../../api/src/app.js';
import { createMandateMcpServer, MandateRestMcpClient } from '../src/server.js';
import { migrate } from '../../../packages/adapters/src/postgres/migrate.js';
import { ActivityApplicationService } from '../../../packages/application/src/activity-service.js';
import { ActivityStore } from '../../../packages/adapters/src/postgres/activity-store.js';

const connectionString = process.env.DATABASE_URL;
describe.skipIf(!connectionString)('MCP receipt history through REST/application/PostgreSQL', () => {
  const pool = new Pool({ connectionString });
  const organizationId = `receipt-${randomUUID()}`;
  const otherOrganization = `receipt-${randomUUID()}`;
  const token = `mnd_agent_${randomBytes(32).toString('hex')}`;
  const otherToken = `mnd_agent_${randomBytes(32).toString('hex')}`;
  let server: Awaited<ReturnType<typeof createApiServer>>;
  let api: MandateRestMcpClient;
  let origin: string;
  let expectedHash: string;

  beforeAll(async () => {
    const client = new PgClient({ connectionString });
    await client.connect();
    try { await migrate(client); } finally { await client.end(); }
    for (const org of [organizationId, otherOrganization]) {
      const tx = await pool.connect();
      try {
        await tx.query('BEGIN');
        await tx.query('INSERT INTO organizations (id, display_name) VALUES ($1, $2)', [org, 'Receipt history fixture']);
        await tx.query("INSERT INTO members (organization_id, subject, role) VALUES ($1, 'viewer', 'VIEWER')", [org]);
        await tx.query("INSERT INTO accounts (organization_id, id, chain_id, address, adapter, status) VALUES ($1, 'account', 10143, $2, 'evm-smart-account', 'PAUSED')", [org, `0x${randomBytes(20).toString('hex')}`]);
        await tx.query("INSERT INTO policies (organization_id, id, account_id, current_revision, state) VALUES ($1, 'policy', 'account', 1, 'DRAFT')", [org]);
        await tx.query("INSERT INTO policy_revisions (organization_id, policy_id, revision, schema_version, canonical_json, revision_hash, created_by, valid_after, expires_at) VALUES ($1, 'policy', 1, 1, '{}'::jsonb, $2, 'owner', now(), now() + interval '1 day')", [org, `0x${randomBytes(32).toString('hex')}`]);
        for (const agent of ['reader', 'another-agent']) {
          await tx.query("INSERT INTO agents (organization_id, id, display_name, status, key_version) VALUES ($1, $2, $2, 'ACTIVE', 1)", [org, agent]);
        }
        await tx.query('COMMIT');
      } catch (error) { await tx.query('ROLLBACK'); throw error; } finally { tx.release(); }
    }
    for (const [agent, secret] of [['reader', token], ['another-agent', otherToken]] as const) {
      await pool.query("INSERT INTO agent_credentials (organization_id, agent_id, key_version, secret_hash, created_by) VALUES ($1, $2, 1, $3, 'owner')", [organizationId, agent, createHash('sha256').update(secret).digest('hex')]);
    }
    for (const org of [organizationId, otherOrganization]) {
      for (let index = 0; index < (org === organizationId ? 103 : 1); index += 1) {
        const actionId = `action-${index}`;
        const actionHash = `0x${randomBytes(32).toString('hex')}`;
        const hash = `0x${randomBytes(32).toString('hex')}`;
        if (org === organizationId && index === 0) expectedHash = hash;
        await pool.query("INSERT INTO action_requests (organization_id, id, policy_id, policy_revision, idempotency_key, request_hash, action_json, state) VALUES ($1, $2, 'policy', 1, $2, $3, $4::jsonb, 'RECONCILED')", [org, actionId, actionHash, JSON.stringify({ agentId: index === 102 ? 'another-agent' : 'reader' })]);
        await pool.query("INSERT INTO receipts (organization_id, action_id, chain_id, transaction_hash, block_number, block_hash, status, receipt_json, observed_at) VALUES ($1, $2, 10143, $3, $4::bigint, $5, 'FINAL', '{}'::jsonb, now() - interval '1 day' + ($4::bigint * interval '1 second'))", [org, actionId, hash, index, `0x${randomBytes(32).toString('hex')}`]);
      }
    }
    server = await createApiServer({ pool, jwksUrl: 'http://127.0.0.1:1/jwks', issuer: 'https://test.invalid', audience: 'mandate', rateLimit: { maxRequests: 2000, windowSeconds: 60 } });
    await server.listen({ host: '127.0.0.1', port: 0 });
    const address = server.server.address();
    if (address === null || typeof address === 'string') throw new Error('API did not bind');
    origin = `http://127.0.0.1:${address.port}`;
    api = await MandateRestMcpClient.connect(origin, token, organizationId);
  });
  afterAll(async () => { await server?.close(); await pool.end(); });

  it('finds an action receipt older than the newest 100 through the real MCP tool', async () => {
    const recent = await server.inject({ url: `/api/v1/orgs/${organizationId}/receipts?limit=100`, headers: { authorization: `Bearer ${token}` } });
    expect(recent.statusCode).toBe(200);
    expect(recent.body).not.toContain('"action-0"');
    const mcp = createMandateMcpServer(api);
    const client = new McpClient({ name: 'receipt-history-test', version: '1.0.0' });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    await mcp.connect(serverTransport);
    await client.connect(clientTransport);
    try {
      const result = await client.callTool({ name: 'mandate_receipt_get', arguments: { id: 'action-0' } });
      expect(result.isError).not.toBe(true);
      expect(result.content).toMatchObject([{ type: 'text', text: expect.stringContaining(expectedHash) }]);
    } finally { await client.close(); await mcp.close(); }
  });
  it('filters before the limit while retaining receipt finality evidence', async () => {
    const response = await server.inject({ url: `/api/v1/orgs/${organizationId}/receipts?limit=1&actionId=action-0`, headers: { authorization: `Bearer ${token}` } });
    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({ receipts: [{ actionId: 'action-0', status: 'FINAL', transactionHash: expectedHash }] });
  });
  it('keeps missing and another agent’s action indistinguishable', async () => {
    expect(await api.getReceipt('missing-action')).toBeNull();
    expect(await api.getReceipt('action-102')).toBeNull();
    const other = await MandateRestMcpClient.connect(origin, otherToken, organizationId);
    expect(await other.getReceipt('action-0')).toBeNull();
    expect(await other.getReceipt('action-102')).toMatchObject({ actionId: 'action-102' });
  });
  it('preserves tenant hiding even when the same action identifier exists elsewhere', async () => {
    const response = await server.inject({ url: `/api/v1/orgs/${otherOrganization}/receipts?actionId=action-0`, headers: { authorization: `Bearer ${token}` } });
    expect(response.statusCode).toBe(404);
    expect(response.body).not.toContain(expectedHash);
  });
  it.each(['', '../action-0', 'a'.repeat(129), 'action-0&limit=100'])('rejects malformed actionId %s', async (id) => {
    const response = await server.inject({ url: `/api/v1/orgs/${organizationId}/receipts?actionId=${encodeURIComponent(id)}`, headers: { authorization: `Bearer ${token}` } });
    expect(response.statusCode).toBe(400);
  });
  it('requires authentication before a filtered receipt can be read', async () => {
    const response = await server.inject(`/api/v1/orgs/${organizationId}/receipts?actionId=action-0`);
    expect(response.statusCode).toBe(401);
  });
  it('keeps human membership authorization in the shared service', async () => {
    const service = new ActivityApplicationService(new ActivityStore(pool));
    await expect(service.listReceipts({ type: 'HUMAN', subject: 'nonmember' }, organizationId, 1)).rejects.toMatchObject({ statusCode: 404 });
    expect(await service.listReceipts({ type: 'HUMAN', subject: 'viewer' }, organizationId, 1)).toHaveLength(1);
  });
});
