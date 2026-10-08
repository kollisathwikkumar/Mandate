import { Pool } from 'pg';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { FastifyInstance } from 'fastify';
import { createApiServer } from '../src/app.js';

const identity = { jwksUrl: 'http://127.0.0.1:1/jwks', issuer: 'https://test.invalid', audience: 'mandate', logger: false } as const;

describe('dependency outage HTTP boundary', () => {
  const pool = new Pool({ connectionString: 'postgresql://test:test@127.0.0.1:1/test', connectionTimeoutMillis: 100 });
  let app: FastifyInstance;
  beforeAll(async () => {
    app = await createApiServer({ pool, ...identity });
    app.get('/__test/unexpected', async () => { throw new Error('private SQL detail /internal/path'); });
    app.get('/__test/connection', async () => { await pool.query('SELECT 1'); return { ok: true }; });
    app.get('/__test/upstream', async () => { throw Object.assign(new Error('private upstream response'), { statusCode: 502 }); });
  });
  afterAll(async () => { await app.close(); await pool.end(); });
  it('fails closed with typed 503 when shared rate-limit storage is unavailable', async () => {
    const response = await app.inject({ method: 'GET', url: '/api/v1/me' });
    expect(response.statusCode).toBe(503);
    expect(response.json()).toMatchObject({ error: { code: 'DEPENDENCY_UNAVAILABLE' } });
    expect(response.body).not.toMatch(/ECONNREFUSED|postgres|127\.0\.0\.1|stack/i);
  });
  it('keeps liveness up while readiness reports dependency failure', async () => {
    expect((await app.inject('/health/live')).statusCode).toBe(200);
    expect((await app.inject('/health/ready')).statusCode).toBe(503);
  });
  it('classifies an unexpected failure as internal without exposing details', async () => {
    const response = await app.inject('/__test/unexpected');
    expect(response.statusCode).toBe(500);
    expect(response.json()).toMatchObject({ error: { code: 'INTERNAL_ERROR', requestId: expect.any(String) } });
    expect(response.body).not.toMatch(/private SQL|internal\/path|stack/i);
  });
  it('distinguishes connection outage from upstream gateway failure without exposing details', async () => {
    for (const [path, status] of [['/__test/connection', 503], ['/__test/upstream', 502]] as const) {
      const response = await app.inject(path);
      expect(response.statusCode).toBe(status);
      expect(response.json()).toMatchObject({ error: { code: 'DEPENDENCY_UNAVAILABLE', requestId: expect.any(String) } });
      expect(response.body).not.toMatch(/private|database URL|upstream response|stack/i);
    }
  });
});

describe.skipIf(!process.env.DATABASE_URL)('request parser HTTP boundary with real PostgreSQL', () => {
  const pool = new Pool({ connectionString: process.env.DATABASE_URL });
  let app: FastifyInstance;
  beforeAll(async () => { app = await createApiServer({ pool, ...identity }); });
  afterAll(async () => { await app.close(); await pool.end(); });
  it.each([
    [413, 'application/json', JSON.stringify({ payload: 'x'.repeat(300_001) })],
    [415, 'application/xml', '<request/>'],
    [400, 'application/json', '{invalid'],
  ] as const)('preserves client HTTP %s instead of turning it into a 500', async (status, contentType, payload) => {
    const response = await app.inject({ method: 'POST', url: '/api/v1/orgs', headers: { 'content-type': contentType }, payload });
    expect(response.statusCode).toBe(status);
    expect(response.json()).toMatchObject({ error: { code: 'INVALID_REQUEST' } });
    expect(response.body).not.toContain(payload);
  });
  it.each(['/api/v1/no-such-route', '/mcp/no-such-route', '/auth/no-such-route'])('never returns an HTML shell for %s', async (url) => {
    const response = await app.inject(url);
    expect(response.statusCode).toBe(404);
    expect(response.headers['content-type']).toContain('application/json');
  });
});
