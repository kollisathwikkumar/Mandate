import { randomUUID } from 'node:crypto';
import { createServer, type Server } from 'node:http';
import { exportJWK, generateKeyPair, SignJWT, type CryptoKey, type JWK } from 'jose';
import { Client, Pool } from 'pg';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createApiServer } from '../../../apps/api/src/app.js';
import { migrate } from '../../adapters/src/postgres/migrate.js';
import { MandateClient } from '../src/client.js';

const connectionString = process.env.DATABASE_URL;
const issuer = 'https://identity.mandate.test';
const audience = 'mandate-api';

describe.skipIf(connectionString === undefined)('Mandate SDK against the local API and PostgreSQL', () => {
  let pool: Pool;
  let jwksServer: Server;
  let api: Awaited<ReturnType<typeof createApiServer>>;
  let ownerToken: string;
  let ownerSubject: string;
  let organizationId: string;
  let onboardingToken: string;
  let onboardingSubject: string;

  beforeAll(async () => {
    if (connectionString === undefined) throw new Error('DATABASE_URL is required');
    pool = new Pool({ connectionString });
    const migrationClient = new Client({ connectionString });
    await migrationClient.connect();
    await migrate(migrationClient);
    await migrationClient.end();

    const keyPair = await generateKeyPair('RS256');
    const privateKey: CryptoKey = keyPair.privateKey;
    const publicJwk: JWK = { ...await exportJWK(keyPair.publicKey), kid: 'sdk-integration-key', alg: 'RS256', use: 'sig' };
    jwksServer = createServer((_request, response) => {
      response.writeHead(200, { 'content-type': 'application/json', 'cache-control': 'public, max-age=60' });
      response.end(JSON.stringify({ keys: [publicJwk] }));
    });
    await new Promise<void>((resolve, reject) => {
      jwksServer.once('error', reject);
      jwksServer.listen(0, '127.0.0.1', resolve);
    });
    const jwksAddress = jwksServer.address();
    if (jwksAddress === null || typeof jwksAddress === 'string') throw new Error('SDK JWKS test server did not bind');
    const jwksUrl = `http://127.0.0.1:${jwksAddress.port}/jwks`;

    organizationId = `sdk-${randomUUID()}`;
    await pool.query('INSERT INTO organizations (id, display_name) VALUES ($1, $2)', [organizationId, 'SDK Integration']);
    ownerSubject = `sdk-owner-${randomUUID()}`;
    await pool.query('INSERT INTO members (organization_id, subject, role) VALUES ($1, $2, $3)', [organizationId, ownerSubject, 'OWNER']);
    ownerToken = await new SignJWT({})
      .setProtectedHeader({ alg: 'RS256', kid: 'sdk-integration-key' })
      .setIssuer(issuer).setAudience(audience).setSubject(ownerSubject).setIssuedAt().setExpirationTime('5m').sign(privateKey);
    onboardingSubject = `sdk-onboarding-${randomUUID()}`;
    onboardingToken = await new SignJWT({})
      .setProtectedHeader({ alg: 'RS256', kid: 'sdk-integration-key' })
      .setIssuer(issuer).setAudience(audience).setSubject(onboardingSubject).setIssuedAt().setExpirationTime('5m').sign(privateKey);
    api = await createApiServer({ pool, jwksUrl, issuer, audience, logger: false, rateLimitHmacKey: 'sdk-integration-rate-limit-hmac-key-32-bytes' });
    await api.listen({ host: '127.0.0.1', port: 0 });
  });

  afterAll(async () => {
    await api?.close();
    if (organizationId !== undefined) await pool?.query('DELETE FROM organizations WHERE id = $1', [organizationId]);
    await pool?.end();
    if (jwksServer?.listening) await new Promise<void>((resolve, reject) => jwksServer.close((error) => error === undefined ? resolve() : reject(error)));
  });

  it('discovers authenticated tenant context and invokes the same tenant-scoped API services', async () => {
    const address = api.server.address();
    if (address === null || typeof address === 'string') throw new Error('Mandate API did not bind a TCP port');
    const client = await MandateClient.connect({ apiUrl: `http://127.0.0.1:${address.port}`, token: ownerToken });
    expect(client.context).toEqual({ organizationId, principalType: 'HUMAN' });
    expect(await client.listPolicies()).toMatchObject({ policies: [] });
    expect(await client.listAgents()).toMatchObject({ agents: [] });
  });

  it('fails signed audit exports closed when no server-side signing key is configured', async () => {
    const address = api.server.address();
    if (address === null || typeof address === 'string') throw new Error('Mandate API did not bind a TCP port');
    const client = await MandateClient.connect({ apiUrl: `http://127.0.0.1:${address.port}`, token: ownerToken });
    await expect(client.getSignedAuditExport()).rejects.toMatchObject({ code: 'DEPENDENCY_UNAVAILABLE', statusCode: 503 });
  });

  it('onboards a human without an organization through the real API and PostgreSQL', async () => {
    const address = api.server.address();
    if (address === null || typeof address === 'string') throw new Error('Mandate API did not bind a TCP port');
    const client = await MandateClient.connect({ apiUrl: `http://127.0.0.1:${address.port}`, token: onboardingToken });
    expect(client.context).toEqual({ organizationId: null, principalType: 'HUMAN' });
    const result = await client.createOrganization('SDK Onboarding Integration', `sdk-onboard-${randomUUID()}`);
    if (result === null || typeof result !== 'object' || Array.isArray(result)) throw new Error('Organization creation returned an invalid response');
    const organization = result.organization;
    if (organization === null || typeof organization !== 'object' || Array.isArray(organization)) throw new Error('Organization creation returned an invalid response');
    const newOrganizationId = organization.organizationId;
    if (typeof newOrganizationId !== 'string') throw new Error('Organization creation response omitted its identifier');
    const selected = await client.selectOrganization(newOrganizationId);
    expect(selected.context).toEqual({ organizationId: newOrganizationId, principalType: 'HUMAN' });
    expect(await selected.listPolicies()).toMatchObject({ policies: [] });
    const membership = await pool.query<{ role: string }>('SELECT role FROM members WHERE organization_id = $1 AND subject = $2', [newOrganizationId, onboardingSubject]);
    expect(membership.rows).toHaveLength(1);
    expect(membership.rows[0]?.role).toBe('OWNER');
  });
});
