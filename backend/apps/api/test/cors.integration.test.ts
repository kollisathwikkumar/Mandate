import { Pool } from 'pg';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { FastifyInstance } from 'fastify';
import { createApiServer } from '../src/app.js';

describe('API browser-origin policy', () => {
  const pool = new Pool({ connectionString: 'postgresql://mandate:mandate@127.0.0.1:1/mandate', connectionTimeoutMillis: 100 });
  let app: FastifyInstance;

  beforeAll(async () => {
    app = await createApiServer({
      pool,
      jwksUrl: 'http://127.0.0.1:1/.well-known/jwks.json',
      issuer: 'https://identity.example.test/',
      audience: 'mandate-api-test',
      corsAllowedOrigins: ['https://console.example.test'],
      logger: false,
    });
    await app.ready();
  });

  afterAll(async () => {
    await app?.close();
    await pool.end();
  });

  it('answers valid preflight with a precise origin and supported headers without credentials', async () => {
    const response = await app.inject({
      method: 'OPTIONS',
      url: '/api/v1/orgs/acme/agents',
      headers: {
        origin: 'https://console.example.test',
        'access-control-request-method': 'POST',
        'access-control-request-headers': 'authorization,content-type,idempotency-key',
      },
    });
    expect(response.statusCode).toBe(204);
    expect(response.headers['access-control-allow-origin']).toBe('https://console.example.test');
    expect(response.headers['access-control-allow-methods']).toContain('POST');
    expect(response.headers['access-control-allow-headers']).toContain('Idempotency-Key');
    expect(response.headers['access-control-allow-credentials']).toBeUndefined();
  });

  it('rejects a disallowed origin and preflight attempts to use unsupported headers', async () => {
    const blockedOrigin = await app.inject({
      method: 'GET',
      url: '/api/v1/me',
      headers: { origin: 'https://attacker.example.test' },
    });
    expect(blockedOrigin.statusCode).toBe(403);
    expect(blockedOrigin.json()).toMatchObject({ error: { code: 'FORBIDDEN' } });

    const blockedHeader = await app.inject({
      method: 'OPTIONS',
      url: '/api/v1/me',
      headers: {
        origin: 'https://console.example.test',
        'access-control-request-method': 'GET',
        'access-control-request-headers': 'authorization,x-unlisted-header',
      },
    });
    expect(blockedHeader.statusCode).toBe(403);

    const blockedMethod = await app.inject({
      method: 'OPTIONS',
      url: '/api/v1/me',
      headers: {
        origin: 'https://console.example.test',
        'access-control-request-method': 'TRACE',
        'access-control-request-headers': 'authorization',
      },
    });
    expect(blockedMethod.statusCode).toBe(403);
  });

  it('rejects malformed direct allowlist entries at server construction', async () => {
    await expect(createApiServer({
      pool,
      jwksUrl: 'http://127.0.0.1:1/.well-known/jwks.json',
      issuer: 'https://identity.example.test/',
      audience: 'mandate-api-test',
      corsAllowedOrigins: ['https://console.example.test,https://unexpected.example.test'],
      logger: false,
    })).rejects.toThrow('Each configured CORS origin must be exactly one canonical origin');
  });
});
