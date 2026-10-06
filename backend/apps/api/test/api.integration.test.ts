import { createHmac, generateKeyPairSync, randomUUID } from 'node:crypto';
import { createServer, type Server } from 'node:http';
import { exportJWK, generateKeyPair, SignJWT, type CryptoKey, type JWK } from 'jose';
import { Interface, Wallet, keccak256 } from 'ethers';
import { Client, Pool } from 'pg';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createApiServer } from '../src/app.js';
import { migrate } from '../../../packages/adapters/src/postgres/migrate.js';
import type { ModelProvider } from '../../../packages/ports/src/model-credential-repository.js';
import type { ActionExecutionAuthorization } from '../../../packages/chain/src/action-execution-authorization.js';
import { ActionTransactionSubmissionError } from '../../../packages/ports/src/action-transaction-submitter.js';
import { ExecutionReconciliationStore } from '../../../packages/adapters/src/postgres/execution-reconciliation-store.js';
import { Ed25519AuditExportSigner, verifyAuditExport, type SignedAuditExport } from '../../../packages/application/src/audit-export-service.js';
import { AesGcmInvitationTokenCipher } from '../../../packages/adapters/src/crypto/aes-gcm-invitation-token-cipher.js';

const connectionString = process.env.DATABASE_URL;
const issuer = 'https://identity.mandate.test';
const audience = 'mandate-api';
const mcpResource = 'https://mcp.mandate.test/mcp';
const actionAgentWallet = new Wallet(`0x${'59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d'}`);
const actionExecutionInterface = new Interface(['function execute(address to,uint256 value,bytes data,uint256 deadline,uint64 keyVersion,uint256 nonce,bytes signature)']);
const auditSigningKeyPair = generateKeyPairSync('ed25519');
const auditExportSigner = new Ed25519AuditExportSigner('api-integration-key-v1', auditSigningKeyPair.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString());

describe.skipIf(connectionString === undefined)('REST API/PostgreSQL integration', () => {
  let pool: Pool;
  let app: Awaited<ReturnType<typeof createApiServer>>;
  let ownerToken: string;
  let organizationId: string;
  let policyAccountAddress: string;
  let jwksServer: Server;
  let signingKey: CryptoKey;
  let jwksUrl: string;
  let observedPolicyEnabled = false;
  let observedPolicyRevisionHash = `0x${'0'.repeat(64)}`;
  let observedPolicyEpoch = 0n;
  const modelSecrets = new Map<string, string>();
  const webhookSecrets = new Map<string, string>();
  let failNextWebhookDelete = false;
  let lastTestedKey: string | null = null;
  const submittedRawTransactions: string[] = [];
  let failNextTransactionSubmission = false;

  beforeAll(async () => {
    pool = new Pool({ connectionString });
    const keyPair = await generateKeyPair('RS256');
    signingKey = keyPair.privateKey;
    const publicJwk: JWK = { ...await exportJWK(keyPair.publicKey), kid: 'integration-key', alg: 'RS256', use: 'sig' };
    jwksServer = createServer((_request, response) => {
      response.writeHead(200, { 'content-type': 'application/json', 'cache-control': 'public, max-age=60' });
      response.end(JSON.stringify({ keys: [publicJwk] }));
    });
    await new Promise<void>((resolve, reject) => {
      jwksServer.once('error', reject);
      jwksServer.listen(0, '127.0.0.1', resolve);
    });
    const address = jwksServer.address();
    if (address === null || typeof address === 'string') throw new Error('JWKS test server did not bind a TCP port');
    jwksUrl = `http://127.0.0.1:${address.port}/jwks`;
    const migrationClient = new Client({ connectionString });
    await migrationClient.connect();
    await migrate(migrationClient);
    await migrationClient.end();
    organizationId = `api-${randomUUID()}`;
    policyAccountAddress = `0x${randomUUID().replaceAll('-', '')}${'1'.repeat(8)}`;
    await pool.query('INSERT INTO organizations (id, display_name) VALUES ($1, $2)', [organizationId, 'API Integration']);
    await pool.query('INSERT INTO members (organization_id, subject, role) VALUES ($1, $2, $3)', [organizationId, 'owner-subject', 'OWNER']);
    await pool.query(
      `INSERT INTO accounts (organization_id, id, chain_id, address, adapter, status, guard_address, module_address, verified_at)
       VALUES ($1, 'policy-account', 10143, $2, 'evm-smart-account', 'ACTIVE', $3, $4, now())`,
      [organizationId, policyAccountAddress, `0x${'4'.repeat(40)}`, `0x${'5'.repeat(40)}`],
    );
    await pool.query(
      `INSERT INTO agents (organization_id, id, display_name, status, key_version)
       VALUES ($1, 'policy-agent', 'Policy Agent', 'ACTIVE', 1)`,
      [organizationId],
    );
    ownerToken = await new SignJWT({})
      .setProtectedHeader({ alg: 'RS256', kid: 'integration-key' })
      .setIssuer(issuer)
      .setAudience(audience)
      .setSubject('owner-subject')
      .setIssuedAt()
      .setExpirationTime('5m')
      .sign(signingKey);
    app = await createApiServer({
      pool, jwksUrl, issuer, audience: [audience, mcpResource], logger: false, rateLimit: { maxRequests: 2000, windowSeconds: 60 },
      auditExportSigner,
      modelSecretStore: {
        async put(orgId: string, provider: ModelProvider, value: string): Promise<string> {
          const reference = `fake://${orgId}/${provider}/${randomUUID()}`;
          modelSecrets.set(reference, value);
          return reference;
        },
        async get(reference: string): Promise<string> {
          const value = modelSecrets.get(reference);
          if (value === undefined) throw new Error('fake secret not found');
          return value;
        },
        async delete(reference: string): Promise<void> { modelSecrets.delete(reference); },
      },
      webhookSecretStore: {
        async put(orgId: string, endpointId: string, secret: string): Promise<string> {
          const reference = `fake-webhook://${orgId}/${endpointId}/${randomUUID()}`;
          webhookSecrets.set(reference, secret);
          return reference;
        },
        async get(reference: string): Promise<string> {
          const value = webhookSecrets.get(reference);
          if (value === undefined) throw new Error('fake webhook secret not found');
          return value;
        },
        async delete(reference: string): Promise<void> {
          if (failNextWebhookDelete) { failNextWebhookDelete = false; throw new Error('secret cleanup transient failure'); }
          webhookSecrets.delete(reference);
        },
      },
      webhookUrlValidator: {
        async validate(url: string): Promise<void> {
          if (url.includes('private')) throw new Error('WEBHOOK_URL_PRIVATE_ADDRESS');
        },
      },
      modelProviderTester: {
        async test(_provider: ModelProvider, apiKey: string) { lastTestedKey = apiKey; return { ok: true, reason: null }; },
      },
      accountEnrollmentVerifier: {
        async verify({ chainId, address }) {
          if (chainId !== 10143) throw new Error('unexpected test chain');
          if (address.toLowerCase() === policyAccountAddress.toLowerCase()) {
            return { safeAddress: address.toLowerCase(), guardAddress: `0x${'4'.repeat(40)}`, moduleAddress: `0x${'5'.repeat(40)}` };
          }
          return { safeAddress: address.toLowerCase(), guardAddress: `0x${'8'.repeat(40)}`, moduleAddress: `0x${'9'.repeat(40)}` };
        },
      },
      policyActivationReader: {
        async readState({ chainId, safeAddress, guardAddress, moduleAddress }) {
          return {
            chainId, safeAddress, guardAddress, moduleAddress, timestampSeconds: Math.floor(Date.now() / 1000),
            safeNonce: 7n, safeOwners: [`0x${'b'.repeat(40)}`], safeThreshold: 1n,
            policyEpoch: observedPolicyEpoch, policyEnabled: observedPolicyEnabled, policyRevisionHash: observedPolicyRevisionHash,
            agentKeyVersion: 0n, agentActive: false,
          };
        },
      },
      actionExecutionStateReader: {
        async readState({ chainId, safeAddress, guardAddress, moduleAddress }) {
          return {
            safeAddress, guardAddress, moduleAddress, chainId, timestampSeconds: Math.floor(Date.now() / 1000),
            policyEpoch: observedPolicyEpoch, policyEnabled: observedPolicyEnabled,
            policyRevisionHash: observedPolicyRevisionHash, agentKeyVersion: 1n, agentActive: true,
            moduleNonce: 0n, blockNumber: 101, blockHash: `0x${'c'.repeat(64)}`,
          };
        },
      },
      actionTransactionSubmitter: {
        async submitRawTransaction({ chainId, rawTransaction }) {
          if (chainId !== 10143) throw new Error('unexpected test chain');
          submittedRawTransactions.push(rawTransaction);
          if (failNextTransactionSubmission) {
            failNextTransactionSubmission = false;
            throw new ActionTransactionSubmissionError('RPC_UNAVAILABLE');
          }
          return { transactionHash: keccak256(rawTransaction).toLowerCase() };
        },
      },
      chainConfirmations: { 10143: 1 },
      policyActivationFinalizer: {
        async verifyFinalizedActivation({ planId, plan, transactionHashes, minimumConfirmations }) {
          observedPolicyEnabled = true;
          observedPolicyRevisionHash = plan.revisionHash;
          observedPolicyEpoch = BigInt(plan.resultingPolicyEpoch);
          return {
            planId, revisionHash: plan.revisionHash, policyEpoch: plan.resultingPolicyEpoch,
            finalizedBlockNumber: '50',
            receipts: plan.calls.map((call, index) => ({
              safeTxHash: call.safeTxHash,
              transactionHash: transactionHashes[index] ?? `0x${String(index + 1).padStart(64, '0')}`,
              blockNumber: String(48 + index), blockHash: `0x${String(index + 1).padStart(64, '0')}`,
              transactionIndex: index, confirmations: minimumConfirmations, status: 'FINAL' as const,
            })),
          };
        },
      },
      policyRevocationFinalizer: {
        async verifyFinalizedRevocation({ planId, plan, transactionHash, minimumConfirmations }) {
          observedPolicyEnabled = false;
          observedPolicyEpoch = BigInt(plan.resultingPolicyEpoch);
          return {
            planId, revisionHash: plan.revisionHash,
            previousPolicyEpoch: plan.expectedPolicyEpoch,
            policyEpoch: plan.resultingPolicyEpoch,
            finalizedBlockNumber: '60',
            receipt: {
              safeTxHash: plan.call.safeTxHash, transactionHash,
              blockNumber: '59', blockHash: `0x${'c'.repeat(64)}`, transactionIndex: 0,
              confirmations: minimumConfirmations, status: 'FINAL' as const,
            },
          };
        },
      },
    });
  });

  afterAll(async () => {
    await app?.close();
    await pool?.end();
    if (jwksServer?.listening) await new Promise<void>((resolve, reject) => jwksServer.close((error) => error === undefined ? resolve() : reject(error)));
  });

  it('rejects missing bearer credentials and serves liveness without auth', async () => {
    const live = await app.inject({ method: 'GET', url: '/health/live' });
    const openApi = await app.inject({ method: 'GET', url: '/api/v1/openapi.json' });
    const unauthorized = await app.inject({ method: 'GET', url: '/api/v1/me' });
    expect(live.statusCode).toBe(200);
    expect(live.headers['x-request-id']).toBeTruthy();
    expect(openApi.statusCode).toBe(200);
    expect(openApi.json<{ paths: Record<string, unknown> }>().paths).toHaveProperty('/api/v1/orgs/{orgId}/actions/{actionId}/execute');
    expect(live.json()).toEqual({ status: 'live' });
    const specification = await app.inject({ method: 'GET', url: '/api/v1/openapi.json' });
    expect(specification.statusCode).toBe(200);
    expect(specification.json()).toMatchObject({
      openapi: '3.1.0',
      paths: { '/api/v1/orgs/{orgId}/agents': { get: { operationId: 'listOrganizationAgents' }, post: { operationId: 'registerOrganizationAgent' } } },
    });
    expect(specification.json<{ info: { description: string } }>().info.description).toContain('429 RATE_LIMITED');
    expect(specification.json<{ paths: Record<string, unknown> }>().paths).toHaveProperty('/api/v1/orgs/{orgId}/policies/{policyId}/revisions');
    expect(specification.json<{ paths: Record<string, unknown> }>().paths).toHaveProperty('/api/v1/orgs/{orgId}/policies/{policyId}/activate');
    expect(specification.json<{ paths: Record<string, unknown> }>().paths).toHaveProperty('/api/v1/orgs/{orgId}/policies/{policyId}/activate/finalize');
    expect(specification.json<{ paths: Record<string, unknown> }>().paths).toHaveProperty('/api/v1/orgs/{orgId}/policies/{policyId}/revoke');
    expect(specification.json<{ paths: Record<string, unknown> }>().paths).toHaveProperty('/api/v1/orgs/{orgId}/policies/{policyId}/revoke/finalize');
    expect(specification.json<{ paths: Record<string, unknown> }>().paths).toHaveProperty('/api/v1/orgs/{orgId}/accounts');
    expect(specification.json<{ paths: Record<string, unknown> }>().paths).toHaveProperty('/api/v1/orgs/{orgId}/accounts/{accountId}/verify');
    expect(specification.json<{ paths: Record<string, unknown> }>().paths).toHaveProperty('/api/v1/orgs/{orgId}/actions');
    expect(specification.json<{ paths: Record<string, unknown> }>().paths).toHaveProperty('/api/v1/orgs/{orgId}/actions/{actionId}/approval');
    expect(specification.json<{ paths: Record<string, unknown> }>().paths).toHaveProperty('/api/v1/orgs/{orgId}/actions/{actionId}/reorg-resolution');
    expect(specification.json<{ paths: Record<string, unknown> }>().paths).toHaveProperty('/api/v1/orgs/{orgId}/policies/{policyId}/simulate');
    expect(specification.json<{ paths: Record<string, unknown> }>().paths).toHaveProperty('/api/v1/orgs/{orgId}/actions/{actionId}');
    expect(specification.json<{ paths: Record<string, unknown> }>().paths).toHaveProperty('/api/v1/orgs/{orgId}/audit-events');
    expect(specification.json<{ paths: Record<string, unknown> }>().paths).toHaveProperty('/api/v1/orgs/{orgId}/audit-exports');
    expect(specification.json<{ paths: Record<string, unknown> }>().paths).toHaveProperty('/api/v1/orgs/{orgId}/receipts');
    expect(specification.json<{ paths: Record<string, unknown> }>().paths).toHaveProperty('/api/v1/orgs/{orgId}/alerts');
    expect(specification.json<{ paths: Record<string, unknown> }>().paths).toHaveProperty('/api/v1/orgs/{orgId}/integrations/model-providers');
    expect(specification.json<{ paths: Record<string, unknown> }>().paths).toHaveProperty('/api/v1/orgs/{orgId}/members');
    expect(specification.json<{ paths: Record<string, unknown> }>().paths).toHaveProperty('/api/v1/orgs/{orgId}/members/{subject}');
    expect(specification.json<{ paths: Record<string, unknown> }>().paths).toHaveProperty('/api/v1/orgs/{orgId}/webhooks');
    expect(specification.json<{ paths: Record<string, unknown> }>().paths).toHaveProperty('/api/v1/orgs/{orgId}/webhooks/{endpointId}/rotate-secret');
    expect(specification.json<{ paths: Record<string, unknown> }>().paths).toHaveProperty('/api/v1/orgs/{orgId}/webhooks/{endpointId}/deliveries');
    expect(unauthorized.statusCode).toBe(401);
    expect(unauthorized.json()).toMatchObject({ error: { code: 'UNAUTHENTICATED' } });
    const unknownRoute = await app.inject({ method: 'GET', url: '/api/v1/not-a-route' });
    expect(unknownRoute.statusCode).toBe(404);
    expect(unknownRoute.json()).toMatchObject({ error: { code: 'RESOURCE_NOT_FOUND' } });
  });

  it('resolves a deep-reorg reservation only for an owner while preserving reorg evidence and account pause', async () => {
    const suffix = randomUUID();
    const recoveryOrganizationId = `recovery-${suffix}`;
    const accountId = `recovery-account-${suffix}`;
    const policyId = `recovery-policy-${suffix}`;
    const actionId = `recovery-action-${suffix}`;
    const chainId = 10143;
    const digest = (label: string): string => `0x${createHmac('sha256', 'recovery-fixture').update(`${suffix}:${label}`).digest('hex')}`;
    const previousBlockHash = digest('old');
    const canonicalBlockHash = digest('canonical');
    const transactionHash = digest('transaction');
    const requestHash = digest('request');
    const revisionHash = digest('revision');
    const accountAddress = `0x${randomUUID().replaceAll('-', '')}${'2'.repeat(8)}`;
    const ownerSubject = 'owner-subject';
    const viewerSubject = `viewer-${suffix}`;
    await pool.query('INSERT INTO organizations (id, display_name) VALUES ($1, $2)', [recoveryOrganizationId, 'Reorg Recovery API Test']);
    await pool.query('INSERT INTO members (organization_id, subject, role) VALUES ($1, $2, \'OWNER\')', [recoveryOrganizationId, ownerSubject]);
    await pool.query('INSERT INTO members (organization_id, subject, role) VALUES ($1, $2, \'VIEWER\')', [recoveryOrganizationId, viewerSubject]);
    await pool.query(
      `INSERT INTO accounts (organization_id, id, chain_id, address, adapter, status, guard_address, module_address, verified_at)
       VALUES ($1, $2, $3, $4, 'evm-smart-account', 'PAUSED', $5, $6, now())`,
      [recoveryOrganizationId, accountId, chainId, accountAddress, `0x${'a'.repeat(40)}`, `0x${'b'.repeat(40)}`],
    );
    await pool.query('BEGIN');
    try {
      await pool.query('INSERT INTO policies (organization_id, id, account_id, current_revision, state) VALUES ($1, $2, $3, 1, \'ACTIVE\')',
        [recoveryOrganizationId, policyId, accountId]);
      await pool.query(
        `INSERT INTO policy_revisions (organization_id, policy_id, revision, schema_version, canonical_json, revision_hash, created_by, valid_after, expires_at)
         VALUES ($1, $2, 1, 1, '{}'::jsonb, $3, $4, now() - interval '1 hour', now() + interval '1 day')`,
        [recoveryOrganizationId, policyId, revisionHash, ownerSubject],
      );
      await pool.query('COMMIT');
    } catch (error: unknown) { await pool.query('ROLLBACK'); throw error; }
    await pool.query(
      `INSERT INTO action_requests (organization_id, id, policy_id, policy_revision, idempotency_key, request_hash, action_json, state, verdict, reason_code)
       VALUES ($1, $2, $3, 1, $4, $5, '{}'::jsonb, 'REORGED', 'ALLOW', 'ALLOW')`,
      [recoveryOrganizationId, actionId, policyId, `recovery-${suffix}`, requestHash],
    );
    await pool.query('INSERT INTO reservations (organization_id, action_id, amount, state, lease_expires_at) VALUES ($1, $2, 1, \'ACTIVE\', now() + interval \'1 day\')',
      [recoveryOrganizationId, actionId]);
    await pool.query(
      `INSERT INTO execution_attempts (organization_id, action_id, attempt_number, chain_id, transaction_hash, state)
       VALUES ($1, $2, 1, $3, $4, 'REORGED')`, [recoveryOrganizationId, actionId, chainId, transactionHash],
    );
    await pool.query(
      `INSERT INTO receipts (organization_id, action_id, chain_id, transaction_hash, block_number, block_hash, status, receipt_json)
       VALUES ($1, $2, $3, $4, 77, $5, 'REORGED', '{}'::jsonb)`, [recoveryOrganizationId, actionId, chainId, transactionHash, previousBlockHash],
    );
    await pool.query(
      `INSERT INTO audit_events (organization_id, actor_type, actor_id, event_type, subject_type, subject_id, correlation_id, payload, event_hash)
       VALUES ($1, 'SYSTEM', 'execution-reconciler', 'ACTION_DEEP_REORG_DETECTED', 'ACTION', $2, $3,
         $4::jsonb, $5)`,
      [recoveryOrganizationId, actionId, actionId, JSON.stringify({ blockNumber: 77, previousBlockHash, canonicalBlockHash }), digest('incident-audit')],
    );
    const viewerToken = await new SignJWT({})
      .setProtectedHeader({ alg: 'RS256', kid: 'integration-key' }).setIssuer(issuer).setAudience(audience)
      .setSubject(viewerSubject).setIssuedAt().setExpirationTime('5m').sign(signingKey);
    const url = `/api/v1/orgs/${recoveryOrganizationId}/actions/${actionId}/reorg-resolution`;
    const payload = { disposition: 'RELEASED', reason: 'Reconciliation confirms no settlement occurred.', evidenceHash: digest('evidence') };
    const headers = { authorization: `Bearer ${ownerToken}`, 'idempotency-key': `resolve-${suffix}` };
    const prematureVerification = await app.inject({ method: 'POST',
      url: `/api/v1/orgs/${recoveryOrganizationId}/accounts/${accountId}/verify`,
      headers: { authorization: `Bearer ${ownerToken}`, 'idempotency-key': `premature-verify-${suffix}` } });
    expect(prematureVerification.statusCode).toBe(409);
    const invalid = await app.inject({ method: 'POST', url, headers, payload: { ...payload, reason: ' ' } });
    expect(invalid.statusCode).toBe(400);
    const viewer = await app.inject({ method: 'POST', url, headers: { authorization: `Bearer ${viewerToken}`, 'idempotency-key': `viewer-${suffix}` }, payload });
    expect(viewer.statusCode).toBe(403);
    const created = await app.inject({ method: 'POST', url, headers, payload });
    expect(created.statusCode).toBe(201);
    expect(created.json()).not.toHaveProperty('kind');
    expect(created.json()).toMatchObject({ actionId, actionState: 'REORGED', reservationState: 'RELEASED', disposition: 'RELEASED',
      evidenceHash: payload.evidenceHash, incident: { blockNumber: 77, previousBlockHash, canonicalBlockHash } });
    const replay = await app.inject({ method: 'POST', url, headers, payload });
    expect(replay.statusCode).toBe(200);
    expect(replay.json()).toMatchObject({ actionId, actionState: 'REORGED', reservationState: 'RELEASED', replayed: true });
    const conflicting = await app.inject({ method: 'POST', url,
      headers: { ...headers, 'idempotency-key': `resolve-conflict-${suffix}` },
      payload: { ...payload, disposition: 'CONSUMED' } });
    expect(conflicting.statusCode).toBe(409);
    await expect(pool.query('UPDATE execution_reorg_resolutions SET disposition = \'CONSUMED\' WHERE organization_id = $1 AND action_id = $2',
      [recoveryOrganizationId, actionId])).rejects.toThrow('execution_reorg_resolutions is append-only');
    const state = await pool.query<{ action_state: string; attempt_state: string; receipt_status: string; reservation_state: string; account_status: string; resolutions: string }>(
      `SELECT action.state AS action_state, attempt.state AS attempt_state, receipt.status AS receipt_status,
         reservation.state AS reservation_state, account.status AS account_status,
         (SELECT count(*)::text FROM execution_reorg_resolutions WHERE organization_id = $1 AND action_id = $2) AS resolutions
       FROM action_requests action JOIN execution_attempts attempt ON attempt.organization_id = action.organization_id AND attempt.action_id = action.id
       JOIN receipts receipt ON receipt.organization_id = action.organization_id AND receipt.action_id = action.id
       JOIN reservations reservation ON reservation.organization_id = action.organization_id AND reservation.action_id = action.id
       JOIN policies policy ON policy.organization_id = action.organization_id AND policy.id = action.policy_id
       JOIN accounts account ON account.organization_id = policy.organization_id AND account.id = policy.account_id
       WHERE action.organization_id = $1 AND action.id = $2`, [recoveryOrganizationId, actionId],
    );
    expect(state.rows[0]).toEqual({ action_state: 'REORGED', attempt_state: 'REORGED', receipt_status: 'REORGED', reservation_state: 'RELEASED', account_status: 'PAUSED', resolutions: '1' });
    const reverified = await app.inject({ method: 'POST',
      url: `/api/v1/orgs/${recoveryOrganizationId}/accounts/${accountId}/verify`,
      headers: { authorization: `Bearer ${ownerToken}`, 'idempotency-key': `verify-after-resolution-${suffix}` } });
    expect(reverified.statusCode).toBe(200);
    expect(reverified.json()).toMatchObject({ account: { id: accountId, status: 'ACTIVE' } });
  });

  it('validates an OIDC-compatible JWT and resolves /me from its subject', async () => {
    const response = await app.inject({ method: 'GET', url: '/api/v1/me', headers: { authorization: `Bearer ${ownerToken}` } });
    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({ principal: { type: 'HUMAN', subject: 'owner-subject' } });
  });

  it('registers accounts as paused until chain guard verification and lists them tenant-scoped', async () => {
    const address = `0x${randomUUID().replaceAll('-', '')}${'2'.repeat(8)}`;
    const headers = { authorization: `Bearer ${ownerToken}`, 'idempotency-key': 'account-registration-v1' };
    const payload = { id: 'safe-pending', chainId: 10143, address, adapter: 'evm-smart-account' };
    const created = await app.inject({ method: 'POST', url: `/api/v1/orgs/${organizationId}/accounts`, headers, payload });
    expect(created.statusCode).toBe(201);
    expect(created.json()).toMatchObject({ account: { ...payload, address: address.toLowerCase(), status: 'PAUSED' } });
    const replay = await app.inject({ method: 'POST', url: `/api/v1/orgs/${organizationId}/accounts`, headers, payload });
    expect(replay.statusCode).toBe(200);
    expect(replay.json()).toMatchObject({ account: { id: payload.id, status: 'PAUSED' }, replayed: true });
    const listed = await app.inject({ method: 'GET', url: `/api/v1/orgs/${organizationId}/accounts`, headers: { authorization: `Bearer ${ownerToken}` } });
    expect(listed.statusCode).toBe(200);
    expect(listed.json<{ accounts: readonly { id: string; status: string }[] }>().accounts).toContainEqual(expect.objectContaining({ id: payload.id, status: 'PAUSED' }));
    const persisted = await pool.query<{ status: string; count: string }>(
      `SELECT status, (SELECT count(*)::text FROM accounts WHERE organization_id = $1 AND id = $2) AS count
       FROM accounts WHERE organization_id = $1 AND id = $2`, [organizationId, payload.id],
    );
    expect(persisted.rows[0]).toEqual({ status: 'PAUSED', count: '1' });
    const durableEvents = await pool.query<{ audit_count: string; outbox_count: string }>(
      `SELECT (SELECT count(*)::text FROM audit_events WHERE organization_id = $1 AND event_type = 'ACCOUNT_REGISTERED' AND subject_id = $2) AS audit_count,
              (SELECT count(*)::text FROM outbox_events WHERE organization_id = $1 AND event_type = 'ACCOUNT_REGISTERED' AND aggregate_id = $2) AS outbox_count`,
      [organizationId, payload.id],
    );
    expect(durableEvents.rows[0]).toEqual({ audit_count: '1', outbox_count: '1' });

    const verified = await app.inject({
      method: 'POST', url: `/api/v1/orgs/${organizationId}/accounts/${payload.id}/verify`,
      headers: { authorization: `Bearer ${ownerToken}`, 'idempotency-key': 'account-verify-v1' },
    });
    expect(verified.statusCode).toBe(200);
    expect(verified.json()).toMatchObject({ account: { id: payload.id, status: 'ACTIVE', guardAddress: `0x${'8'.repeat(40)}`, moduleAddress: `0x${'9'.repeat(40)}` } });
    const verifyReplay = await app.inject({
      method: 'POST', url: `/api/v1/orgs/${organizationId}/accounts/${payload.id}/verify`,
      headers: { authorization: `Bearer ${ownerToken}`, 'idempotency-key': 'account-verify-v1' },
    });
    expect(verifyReplay.statusCode).toBe(200);
    expect(verifyReplay.json()).toMatchObject({ replayed: true, account: { status: 'ACTIVE' } });
    const verifiedRow = await pool.query<{ status: string; guard_address: string; module_address: string; verified_at: Date | null }>(
      'SELECT status, btrim(guard_address) AS guard_address, btrim(module_address) AS module_address, verified_at FROM accounts WHERE organization_id = $1 AND id = $2',
      [organizationId, payload.id],
    );
    expect(verifiedRow.rows[0]).toMatchObject({ status: 'ACTIVE', guard_address: `0x${'8'.repeat(40)}`, module_address: `0x${'9'.repeat(40)}` });
    expect(verifiedRow.rows[0]?.verified_at).toBeInstanceOf(Date);
    const verificationEvents = await pool.query<{ audit_count: string; outbox_count: string }>(
      `SELECT (SELECT count(*)::text FROM audit_events WHERE organization_id = $1 AND event_type = 'ACCOUNT_ENROLLMENT_VERIFIED' AND subject_id = $2) AS audit_count,
              (SELECT count(*)::text FROM outbox_events WHERE organization_id = $1 AND event_type = 'ACCOUNT_ENROLLMENT_VERIFIED' AND aggregate_id = $2) AS outbox_count`,
      [organizationId, payload.id],
    );
    expect(verificationEvents.rows[0]).toEqual({ audit_count: '1', outbox_count: '1' });

    const conflict = await app.inject({
      method: 'POST', url: `/api/v1/orgs/${organizationId}/accounts`, headers,
      payload: { ...payload, id: 'different-account' },
    });
    expect(conflict.statusCode).toBe(409);
    expect(conflict.json()).toMatchObject({ error: { code: 'IDEMPOTENCY_CONFLICT' } });
    const invalid = await app.inject({
      method: 'POST', url: `/api/v1/orgs/${organizationId}/accounts`,
      headers: { authorization: `Bearer ${ownerToken}`, 'idempotency-key': 'account-invalid-v1' },
      payload: { ...payload, id: 'bad-account', address: 'not-an-address' },
    });
    expect(invalid.statusCode).toBe(400);

    await pool.query('INSERT INTO members (organization_id, subject, role) VALUES ($1, $2, $3)', [organizationId, 'account-viewer', 'VIEWER']);
    const viewerToken = await new SignJWT({})
      .setProtectedHeader({ alg: 'RS256', kid: 'integration-key' })
      .setIssuer(issuer).setAudience(audience).setSubject('account-viewer').setIssuedAt().setExpirationTime('5m').sign(signingKey);
    const forbidden = await app.inject({
      method: 'POST', url: `/api/v1/orgs/${organizationId}/accounts`,
      headers: { authorization: `Bearer ${viewerToken}`, 'idempotency-key': 'account-viewer-v1' },
      payload: { ...payload, id: 'viewer-account', address: `0x${'3'.repeat(40)}` },
    });
    expect(forbidden.statusCode).toBe(403);
    const forbiddenVerify = await app.inject({
      method: 'POST', url: `/api/v1/orgs/${organizationId}/accounts/${payload.id}/verify`,
      headers: { authorization: `Bearer ${viewerToken}`, 'idempotency-key': 'account-viewer-verify-v1' },
    });
    expect(forbiddenVerify.statusCode).toBe(403);
  });

  it('rejects expired and wrong-audience ID tokens', async () => {
    const expired = await new SignJWT({})
      .setProtectedHeader({ alg: 'RS256', kid: 'integration-key' })
      .setIssuer(issuer)
      .setAudience(audience)
      .setSubject('owner-subject')
      .setIssuedAt()
      .setExpirationTime(Math.floor(Date.now() / 1000) - 1)
      .sign(signingKey);
    const wrongAudience = await new SignJWT({})
      .setProtectedHeader({ alg: 'RS256', kid: 'integration-key' })
      .setIssuer(issuer)
      .setAudience('another-api')
      .setSubject('owner-subject')
      .setIssuedAt()
      .setExpirationTime('5m')
      .sign(signingKey);
    for (const token of [expired, wrongAudience]) {
      const response = await app.inject({ method: 'GET', url: '/api/v1/me', headers: { authorization: `Bearer ${token}` } });
      expect(response.statusCode).toBe(401);
      expect(response.json()).toMatchObject({ error: { code: 'UNAUTHENTICATED' } });
    }
  });

  it('accepts only explicitly configured MCP resource audiences for REST identity calls', async () => {
    const mcpToken = await new SignJWT({})
      .setProtectedHeader({ alg: 'RS256', kid: 'integration-key' })
      .setIssuer(issuer)
      .setAudience(mcpResource)
      .setSubject('owner-subject')
      .setIssuedAt()
      .setExpirationTime('5m')
      .sign(signingKey);
    const accepted = await app.inject({ method: 'GET', url: '/api/v1/me', headers: { authorization: `Bearer ${mcpToken}` } });
    expect(accepted.statusCode).toBe(200);
    expect(accepted.json()).toMatchObject({ principal: { type: 'HUMAN', subject: 'owner-subject' } });
  });

  it('manages organization members with role gates, idempotency, and a last-owner invariant', async () => {
    const baseUrl = `/api/v1/orgs/${organizationId}/members`;
    const listed = await app.inject({ method: 'GET', url: baseUrl, headers: { authorization: `Bearer ${ownerToken}` } });
    expect(listed.statusCode).toBe(200);
    expect(listed.json<{ members: Array<{ subject: string; role: string }> }>().members).toContainEqual(expect.objectContaining({ subject: 'owner-subject', role: 'OWNER' }));

    const first = await app.inject({ method: 'PUT', url: `${baseUrl}/member-viewer`, headers: { authorization: `Bearer ${ownerToken}`, 'idempotency-key': 'member-viewer-add-v1' }, payload: { role: 'VIEWER' } });
    expect(first.statusCode).toBe(201);
    expect(first.json()).toMatchObject({ member: { subject: 'member-viewer', role: 'VIEWER' } });
    const replay = await app.inject({ method: 'PUT', url: `${baseUrl}/member-viewer`, headers: { authorization: `Bearer ${ownerToken}`, 'idempotency-key': 'member-viewer-add-v1' }, payload: { role: 'VIEWER' } });
    expect(replay.statusCode).toBe(200);
    expect(replay.json()).toMatchObject({ member: { subject: 'member-viewer', role: 'VIEWER' }, replayed: true });
    const changedReplay = await app.inject({ method: 'PUT', url: `${baseUrl}/member-viewer`, headers: { authorization: `Bearer ${ownerToken}`, 'idempotency-key': 'member-viewer-add-v1' }, payload: { role: 'APPROVER' } });
    expect(changedReplay.statusCode).toBe(409);

    const admin = await app.inject({ method: 'PUT', url: `${baseUrl}/member-admin`, headers: { authorization: `Bearer ${ownerToken}`, 'idempotency-key': 'member-admin-add-v1' }, payload: { role: 'ADMIN' } });
    expect(admin.statusCode).toBe(201);
    const adminToken = await new SignJWT({}).setProtectedHeader({ alg: 'RS256', kid: 'integration-key' }).setIssuer(issuer).setAudience(audience).setSubject('member-admin').setIssuedAt().setExpirationTime('5m').sign(signingKey);
    const adminOwnerGrant = await app.inject({ method: 'PUT', url: `${baseUrl}/new-owner`, headers: { authorization: `Bearer ${adminToken}`, 'idempotency-key': 'member-admin-owner-v1' }, payload: { role: 'OWNER' } });
    expect(adminOwnerGrant.statusCode).toBe(403);
    const adminRemoveOwner = await app.inject({ method: 'DELETE', url: `${baseUrl}/owner-subject`, headers: { authorization: `Bearer ${adminToken}`, 'idempotency-key': 'member-admin-remove-owner-v1' } });
    expect(adminRemoveOwner.statusCode).toBe(403);
    const adminDemoteOwner = await app.inject({ method: 'PUT', url: `${baseUrl}/owner-subject`, headers: { authorization: `Bearer ${adminToken}`, 'idempotency-key': 'member-admin-demote-owner-v1' }, payload: { role: 'ADMIN' } });
    expect(adminDemoteOwner.statusCode).toBe(403);
    const viewerToken = await new SignJWT({}).setProtectedHeader({ alg: 'RS256', kid: 'integration-key' }).setIssuer(issuer).setAudience(audience).setSubject('member-viewer').setIssuedAt().setExpirationTime('5m').sign(signingKey);
    const viewerMutation = await app.inject({ method: 'PUT', url: `${baseUrl}/member-next`, headers: { authorization: `Bearer ${viewerToken}`, 'idempotency-key': 'member-viewer-mutation-v1' }, payload: { role: 'VIEWER' } });
    expect(viewerMutation.statusCode).toBe(403);

    const promote = await app.inject({ method: 'PUT', url: `${baseUrl}/member-admin`, headers: { authorization: `Bearer ${ownerToken}`, 'idempotency-key': 'member-owner-promote-v1' }, payload: { role: 'OWNER' } });
    expect(promote.statusCode).toBe(200);
    const transfer = await app.inject({ method: 'PUT', url: `${baseUrl}/owner-subject`, headers: { authorization: `Bearer ${ownerToken}`, 'idempotency-key': 'member-owner-transfer-v1' }, payload: { role: 'ADMIN' } });
    expect(transfer.statusCode).toBe(200);
    const removeLastOwner = await app.inject({ method: 'DELETE', url: `${baseUrl}/member-admin`, headers: { authorization: `Bearer ${adminToken}`, 'idempotency-key': 'member-owner-last-owner-v1' } });
    expect(removeLastOwner.statusCode).toBe(409);
    const demoteLastOwner = await app.inject({ method: 'PUT', url: `${baseUrl}/member-admin`, headers: { authorization: `Bearer ${adminToken}`, 'idempotency-key': 'member-owner-demote-v1' }, payload: { role: 'ADMIN' } });
    expect(demoteLastOwner.statusCode).toBe(409);
    const removed = await app.inject({ method: 'DELETE', url: `${baseUrl}/member-viewer`, headers: { authorization: `Bearer ${ownerToken}`, 'idempotency-key': 'member-viewer-remove-v1' } });
    expect(removed.statusCode).toBe(204);
    const history = await pool.query<{ event_type: string }>(`SELECT event_type FROM audit_events WHERE organization_id = $1 AND subject_type = 'ORG_MEMBER' AND subject_id = 'member-viewer' ORDER BY sequence`, [organizationId]);
    expect(history.rows.map((row) => row.event_type)).toEqual(['ORG_MEMBER_ADDED', 'ORG_MEMBER_REMOVED']);
    const restoreFixtureOwner = await app.inject({ method: 'PUT', url: `${baseUrl}/owner-subject`, headers: { authorization: `Bearer ${adminToken}`, 'idempotency-key': 'member-test-restore-owner' }, payload: { role: 'OWNER' } });
    expect(restoreFixtureOwner.statusCode).toBe(200);
  });

  it('serializes concurrent owner removals so an organization always retains an owner', async () => {
    const isolatedOrganization = `membership-race-${randomUUID()}`;
    await pool.query('INSERT INTO organizations (id, display_name) VALUES ($1, $2)', [isolatedOrganization, 'Membership race']);
    await pool.query(`INSERT INTO members (organization_id, subject, role) VALUES ($1, $2, 'OWNER'), ($1, $3, 'OWNER')`, [isolatedOrganization, 'owner-subject', 'second-owner']);
    const secondOwnerToken = await new SignJWT({}).setProtectedHeader({ alg: 'RS256', kid: 'integration-key' }).setIssuer(issuer).setAudience(audience).setSubject('second-owner').setIssuedAt().setExpirationTime('5m').sign(signingKey);
    const baseUrl = `/api/v1/orgs/${isolatedOrganization}/members`;
    const removals = await Promise.all([
      app.inject({ method: 'DELETE', url: `${baseUrl}/second-owner`, headers: { authorization: `Bearer ${ownerToken}`, 'idempotency-key': 'race-remove-second-owner' } }),
      app.inject({ method: 'DELETE', url: `${baseUrl}/owner-subject`, headers: { authorization: `Bearer ${secondOwnerToken}`, 'idempotency-key': 'race-remove-first-owner' } }),
    ]);
    expect(removals.map((response) => response.statusCode).sort()).toEqual([204, 404]);
    const owners = await pool.query<{ count: string }>("SELECT count(*)::text AS count FROM members WHERE organization_id = $1 AND role = 'OWNER'", [isolatedOrganization]);
    expect(owners.rows[0]?.count).toBe('1');
  });

  it('lists only masked model-provider integration metadata', async () => {
    const response = await app.inject({
      method: 'GET',
      url: `/api/v1/orgs/${organizationId}/integrations/model-providers`,
      headers: { authorization: `Bearer ${ownerToken}` },
    });
    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({ credentials: [] });
  });

  it('lists signed webhook endpoints only for an authorized organization administrator', async () => {
    const response = await app.inject({
      method: 'GET',
      url: `/api/v1/orgs/${organizationId}/webhooks`,
      headers: { authorization: `Bearer ${ownerToken}` },
    });
    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({ endpoints: [] });
  });

  it('creates, lists, rotates, toggles, inspects, and deletes a signed webhook endpoint without returning stored secrets', async () => {
    const baseUrl = `/api/v1/orgs/${organizationId}/webhooks`;
    const payload = { url: 'https://hooks.example.test/mandate', eventTypes: ['ACTION_BLOCKED', 'POLICY_REVOKED'] };
    const firstHeaders = { authorization: `Bearer ${ownerToken}`, 'idempotency-key': 'webhook-create-v1' };
    const first = await app.inject({ method: 'POST', url: baseUrl, headers: firstHeaders, payload });
    expect(first.statusCode).toBe(201);
    const firstResponse = first.json<{ endpoint: { id: string; enabled: boolean; eventTypes: string[] }; signingSecret: string; shownOnce: boolean }>();
    expect(firstResponse).toMatchObject({ endpoint: { enabled: true, eventTypes: ['ACTION_BLOCKED', 'POLICY_REVOKED'] }, shownOnce: true });
    expect(firstResponse.signingSecret).toMatch(/^[A-Za-z0-9_-]{43}$/);
    const endpointId = firstResponse.endpoint.id;
    const replay = await app.inject({ method: 'POST', url: baseUrl, headers: firstHeaders, payload });
    expect(replay.statusCode).toBe(200);
    expect(replay.json()).toMatchObject({ endpoint: { id: endpointId }, replayed: true });
    expect(replay.body).not.toContain(firstResponse.signingSecret);
    expect(webhookSecrets.size).toBe(1);

    const conflict = await app.inject({ method: 'POST', url: baseUrl, headers: firstHeaders, payload: { ...payload, url: 'https://other.example.test/hook' } });
    expect(conflict.statusCode).toBe(409);
    const unsafe = await app.inject({ method: 'POST', url: baseUrl, headers: { authorization: `Bearer ${ownerToken}`, 'idempotency-key': 'webhook-unsafe' }, payload: { ...payload, url: 'https://private.example.test/hook' } });
    expect(unsafe.statusCode).toBe(400);
    expect(webhookSecrets.size).toBe(1);

    await pool.query('INSERT INTO members (organization_id, subject, role) VALUES ($1, $2, $3)', [organizationId, 'webhook-viewer', 'VIEWER']);
    const viewerToken = await new SignJWT({}).setProtectedHeader({ alg: 'RS256', kid: 'integration-key' }).setIssuer(issuer).setAudience(audience).setSubject('webhook-viewer').setIssuedAt().setExpirationTime('5m').sign(signingKey);
    const viewer = await app.inject({ method: 'GET', url: baseUrl, headers: { authorization: `Bearer ${viewerToken}` } });
    expect(viewer.statusCode).toBe(403);
    const viewerCreate = await app.inject({ method: 'POST', url: baseUrl, headers: { authorization: `Bearer ${viewerToken}`, 'idempotency-key': 'webhook-viewer-create' }, payload });
    expect(viewerCreate.statusCode).toBe(403);
    const viewerHistory = await app.inject({ method: 'GET', url: `${baseUrl}/${endpointId}/deliveries`, headers: { authorization: `Bearer ${viewerToken}` } });
    expect(viewerHistory.statusCode).toBe(403);
    expect(webhookSecrets.size).toBe(1);

    failNextWebhookDelete = true;
    const rotated = await app.inject({ method: 'POST', url: `${baseUrl}/${endpointId}/rotate-secret`, headers: { authorization: `Bearer ${ownerToken}`, 'idempotency-key': 'webhook-rotate-v1' } });
    expect(rotated.statusCode).toBe(200);
    const rotatedSecret = rotated.json<{ signingSecret: string; shownOnce: boolean; cleanupPending: boolean }>().signingSecret;
    expect(rotatedSecret).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(rotated.json()).toMatchObject({ shownOnce: true, cleanupPending: true });
    expect(rotatedSecret).not.toBe(firstResponse.signingSecret);
    expect(webhookSecrets.size).toBe(2);
    const rotationState = await pool.query<{ previous_signing_secret_ref: string | null; signing_secret_ref: string | null }>(
      'SELECT previous_signing_secret_ref, signing_secret_ref FROM webhook_endpoints WHERE organization_id = $1 AND id = $2', [organizationId, endpointId],
    );
    expect(rotationState.rows[0]?.previous_signing_secret_ref).not.toBeNull();
    expect(rotationState.rows[0]?.signing_secret_ref).not.toBeNull();
    const rotationReplay = await app.inject({ method: 'POST', url: `${baseUrl}/${endpointId}/rotate-secret`, headers: { authorization: `Bearer ${ownerToken}`, 'idempotency-key': 'webhook-rotate-v1' } });
    expect(rotationReplay.statusCode).toBe(200);
    expect(rotationReplay.json()).toMatchObject({ endpointId, replayed: true });
    expect(rotationReplay.body).not.toContain(rotatedSecret);
    expect(webhookSecrets.size).toBe(1);
    const cleanupState = await pool.query<{ previous_signing_secret_ref: string | null }>(
      'SELECT previous_signing_secret_ref FROM webhook_endpoints WHERE organization_id = $1 AND id = $2', [organizationId, endpointId],
    );
    expect(cleanupState.rows[0]?.previous_signing_secret_ref).toBeNull();

    const disabled = await app.inject({ method: 'PATCH', url: `${baseUrl}/${endpointId}`, headers: { authorization: `Bearer ${ownerToken}`, 'idempotency-key': 'webhook-disable-v1' }, payload: { enabled: false } });
    expect(disabled.statusCode).toBe(200);
    expect(disabled.json()).toMatchObject({ endpoint: { id: endpointId, enabled: false } });
    const disabledReplay = await app.inject({ method: 'PATCH', url: `${baseUrl}/${endpointId}`, headers: { authorization: `Bearer ${ownerToken}`, 'idempotency-key': 'webhook-disable-v1' }, payload: { enabled: false } });
    expect(disabledReplay.json()).toMatchObject({ endpoint: { id: endpointId, enabled: false }, replayed: true });
    const enabledConflict = await app.inject({ method: 'PATCH', url: `${baseUrl}/${endpointId}`, headers: { authorization: `Bearer ${ownerToken}`, 'idempotency-key': 'webhook-disable-v1' }, payload: { enabled: true } });
    expect(enabledConflict.statusCode).toBe(409);
    const enabled = await app.inject({ method: 'PATCH', url: `${baseUrl}/${endpointId}`, headers: { authorization: `Bearer ${ownerToken}`, 'idempotency-key': 'webhook-enable-v1' }, payload: { enabled: true } });
    expect(enabled.json()).toMatchObject({ endpoint: { id: endpointId, enabled: true } });

    const outboxId = randomUUID();
    const deliveryId = randomUUID();
    await pool.query(`INSERT INTO outbox_events (id, organization_id, aggregate_type, aggregate_id, event_type, payload) VALUES ($1, $2, 'ACTION', 'hook-action', 'ACTION_BLOCKED', '{}'::jsonb)`, [outboxId, organizationId]);
    await pool.query(`INSERT INTO webhook_deliveries (id, organization_id, endpoint_id, outbox_event_id) VALUES ($1, $2, $3, $4)`, [deliveryId, organizationId, endpointId, outboxId]);
    const history = await app.inject({ method: 'GET', url: `${baseUrl}/${endpointId}/deliveries?limit=10`, headers: { authorization: `Bearer ${ownerToken}` } });
    expect(history.statusCode).toBe(200);
    expect(history.json()).toMatchObject({ deliveries: [{ id: deliveryId, endpointId, eventType: 'ACTION_BLOCKED', status: 'PENDING' }] });

    const deleted = await app.inject({ method: 'DELETE', url: `${baseUrl}/${endpointId}`, headers: { authorization: `Bearer ${ownerToken}`, 'idempotency-key': 'webhook-delete-v1' } });
    expect(deleted.statusCode).toBe(204);
    expect(webhookSecrets.size).toBe(0);
    const deleteReplay = await app.inject({ method: 'DELETE', url: `${baseUrl}/${endpointId}`, headers: { authorization: `Bearer ${ownerToken}`, 'idempotency-key': 'webhook-delete-v1' } });
    expect(deleteReplay.statusCode).toBe(204);
    expect((await app.inject({ method: 'GET', url: baseUrl, headers: { authorization: `Bearer ${ownerToken}` } })).json()).toEqual({ endpoints: [] });
    const preservedHistory = await app.inject({ method: 'GET', url: `${baseUrl}/${endpointId}/deliveries`, headers: { authorization: `Bearer ${ownerToken}` } });
    expect(preservedHistory.json()).toMatchObject({ deliveries: [{ id: deliveryId, status: 'PENDING' }] });
    const audit = await pool.query<{ event_type: string }>(
      `SELECT DISTINCT event_type FROM audit_events WHERE organization_id = $1 AND subject_type = 'WEBHOOK_ENDPOINT' AND subject_id = $2 ORDER BY event_type`,
      [organizationId, endpointId],
    );
    expect(audit.rows.map((row) => row.event_type)).toEqual(['WEBHOOK_ENDPOINT_CREATED', 'WEBHOOK_ENDPOINT_DELETED', 'WEBHOOK_ENDPOINT_UPDATED']);
    const storedSecrets = await pool.query<{ db_text: string; audit_text: string; idem_text: string }>(
      `SELECT to_jsonb(endpoint)::text AS db_text,
              (SELECT string_agg(payload::text, '') FROM audit_events WHERE organization_id = $1 AND subject_type = 'WEBHOOK_ENDPOINT' AND subject_id = $2::text) AS audit_text,
              (SELECT string_agg(response_json::text, '') FROM command_idempotency WHERE organization_id = $1 AND scope LIKE 'webhook.%') AS idem_text
       FROM webhook_endpoints endpoint WHERE endpoint.organization_id = $1 AND endpoint.id::text = $2`,
      [organizationId, endpointId],
    );
    for (const content of [storedSecrets.rows[0]?.db_text, storedSecrets.rows[0]?.audit_text, storedSecrets.rows[0]?.idem_text]) {
      expect(content ?? '').not.toContain(firstResponse.signingSecret);
      expect(content ?? '').not.toContain(rotatedSecret);
    }
  });

  it('stores, rotates, tests, disables, and deletes provider keys without exposing them in API or PostgreSQL metadata', async () => {
    const headers = { authorization: `Bearer ${ownerToken}`, 'idempotency-key': 'model-key-write-v1' };
    const firstKey = 'test-model-provider-key-0001';
    const first = await app.inject({ method: 'PUT', url: `/api/v1/orgs/${organizationId}/integrations/model-providers/DEEPSEEK`, headers, payload: { apiKey: firstKey } });
    expect(first.statusCode).toBe(201);
    expect(first.body).not.toContain(firstKey);
    expect(first.json()).toMatchObject({ credential: { provider: 'DEEPSEEK', maskedSuffix: '0001', state: 'ACTIVE' } });
    const persisted = await pool.query<{ secret_reference: string; response_json: string; row_text: string }>(
      `SELECT c.secret_reference, i.response_json::text AS response_json, to_jsonb(c)::text AS row_text
       FROM model_provider_credentials c JOIN command_idempotency i ON i.organization_id = c.organization_id AND i.principal_id = c.created_by
         AND i.scope = 'model-provider.write' AND i.idempotency_key = $2
       WHERE c.organization_id = $1 AND c.provider = 'DEEPSEEK'`, [organizationId, headers['idempotency-key']],
    );
    expect(persisted.rows[0]?.secret_reference).not.toContain(firstKey);
    expect(persisted.rows[0]?.response_json).not.toContain(firstKey);
    expect(persisted.rows[0]?.row_text).not.toContain(firstKey);

    const test = await app.inject({ method: 'POST', url: `/api/v1/orgs/${organizationId}/integrations/model-providers/DEEPSEEK/test`, headers: { authorization: `Bearer ${ownerToken}` } });
    expect(test.statusCode).toBe(200);
    expect(test.json()).toMatchObject({ ok: true, credential: { provider: 'DEEPSEEK', state: 'ACTIVE' } });
    expect(lastTestedKey).toBe(firstKey);

    const rotatedKey = 'test-model-provider-key-0002';
    const rotated = await app.inject({ method: 'PUT', url: `/api/v1/orgs/${organizationId}/integrations/model-providers/DEEPSEEK`, headers: { authorization: `Bearer ${ownerToken}`, 'idempotency-key': 'model-key-write-v2' }, payload: { apiKey: rotatedKey } });
    expect(rotated.statusCode).toBe(201);
    expect(rotated.body).not.toContain(rotatedKey);
    expect(modelSecrets.size).toBe(1);
    expect((await app.inject({ method: 'POST', url: `/api/v1/orgs/${organizationId}/integrations/model-providers/DEEPSEEK/disable`, headers: { authorization: `Bearer ${ownerToken}` } })).json()).toMatchObject({ credential: { state: 'DISABLED' } });
    const deleted = await app.inject({ method: 'DELETE', url: `/api/v1/orgs/${organizationId}/integrations/model-providers/DEEPSEEK`, headers: { authorization: `Bearer ${ownerToken}` } });
    expect(deleted.statusCode).toBe(204);
    expect(modelSecrets.size).toBe(0);
    expect((await app.inject({ method: 'GET', url: `/api/v1/orgs/${organizationId}/integrations/model-providers`, headers: { authorization: `Bearer ${ownerToken}` } })).json()).toEqual({ credentials: [] });
  });

  it('creates an agent once, returns its API token once, then authenticates it', async () => {
    const body = { id: 'treasury-bot', displayName: 'Treasury Bot' };
    const headers = { authorization: `Bearer ${ownerToken}`, 'idempotency-key': 'register-treasury-bot' };
    const first = await app.inject({ method: 'POST', url: `/api/v1/orgs/${organizationId}/agents`, headers, payload: body });
    expect(first.statusCode).toBe(201);
    expect(first.json()).toMatchObject({ agent: { id: body.id, status: 'ACTIVE', keyVersion: 1 }, credential: { token: expect.any(String) } });
    const token = first.json<{ agent: { id: string }; credential: { token: string } }>().credential.token;
    const persisted = await pool.query<{ secret_hash: string; response_text: string; outbox_count: string; audit_count: string }>(
      `SELECT c.secret_hash, i.response_json::text AS response_text,
              (SELECT count(*)::text FROM outbox_events WHERE organization_id = $1 AND aggregate_id = $2) AS outbox_count,
              (SELECT count(*)::text FROM audit_events WHERE organization_id = $1 AND subject_id = $2) AS audit_count
       FROM agent_credentials c JOIN command_idempotency i
         ON i.organization_id = c.organization_id AND i.principal_id = c.created_by AND i.scope = 'agent.register' AND i.idempotency_key = $3
       WHERE c.organization_id = $1 AND c.agent_id = $2`,
      [organizationId, body.id, headers['idempotency-key']],
    );
    expect(persisted.rows[0]?.secret_hash).not.toBe(token);
    expect(persisted.rows[0]?.response_text).not.toContain(token);
    expect(persisted.rows[0]?.outbox_count).toBe('1');
    expect(persisted.rows[0]?.audit_count).toBe('1');
    const replay = await app.inject({ method: 'POST', url: `/api/v1/orgs/${organizationId}/agents`, headers, payload: body });
    expect(replay.statusCode).toBe(200);
    expect(replay.json()).toMatchObject({ agent: { id: body.id } });
    expect(replay.json()).not.toHaveProperty('credential');
    const mismatchedReplay = await app.inject({
      method: 'POST',
      url: `/api/v1/orgs/${organizationId}/agents`,
      headers,
      payload: { ...body, displayName: 'Changed Body' },
    });
    expect(mismatchedReplay.statusCode).toBe(409);
    expect(mismatchedReplay.json()).toMatchObject({ error: { code: 'IDEMPOTENCY_CONFLICT' } });

    const list = await app.inject({ method: 'GET', url: `/api/v1/orgs/${organizationId}/agents`, headers: { authorization: `Bearer ${ownerToken}` } });
    expect(list.statusCode).toBe(200);
    const agents = list.json<{ agents: readonly { id: string; displayName: string }[] }>().agents;
    expect(agents.some((agent) => agent.id === body.id && agent.displayName === body.displayName)).toBe(true);
    const agentMe = await app.inject({ method: 'GET', url: '/api/v1/me', headers: { authorization: `Bearer ${token}` } });
    expect(agentMe.statusCode).toBe(200);
    expect(agentMe.json()).toMatchObject({ principal: { type: 'AGENT', organizationId, agentId: body.id, keyVersion: 1 } });
    await pool.query('UPDATE agents SET key_version = 2 WHERE organization_id = $1 AND id = $2', [organizationId, body.id]);
    const staleCredential = await app.inject({ method: 'GET', url: '/api/v1/me', headers: { authorization: `Bearer ${token}` } });
    expect(staleCredential.statusCode).toBe(401);
    await pool.query('UPDATE agents SET key_version = 1 WHERE organization_id = $1 AND id = $2', [organizationId, body.id]);
  });

  it('does not reveal cross-tenant agents to a human without membership', async () => {
    const otherOrganization = `other-${randomUUID()}`;
    await pool.query('INSERT INTO organizations (id, display_name) VALUES ($1, $2)', [otherOrganization, 'Other tenant']);
    const response = await app.inject({ method: 'GET', url: `/api/v1/orgs/${otherOrganization}/agents`, headers: { authorization: `Bearer ${ownerToken}` } });
    expect(response.statusCode).toBe(404);
    expect(response.json()).toMatchObject({ error: { code: 'RESOURCE_NOT_FOUND' } });
    const policyResponse = await app.inject({ method: 'GET', url: `/api/v1/orgs/${otherOrganization}/policies`, headers: { authorization: `Bearer ${ownerToken}` } });
    expect(policyResponse.statusCode).toBe(404);
  });

  it('denies an authenticated viewer from registering agents', async () => {
    await pool.query('INSERT INTO members (organization_id, subject, role) VALUES ($1, $2, $3)', [organizationId, 'viewer-subject', 'VIEWER']);
    const viewerToken = await new SignJWT({})
      .setProtectedHeader({ alg: 'RS256', kid: 'integration-key' })
      .setIssuer(issuer)
      .setAudience(audience)
      .setSubject('viewer-subject')
      .setIssuedAt()
      .setExpirationTime('5m')
      .sign(signingKey);
    const response = await app.inject({
      method: 'POST',
      url: `/api/v1/orgs/${organizationId}/agents`,
      headers: { authorization: `Bearer ${viewerToken}`, 'idempotency-key': 'viewer-attempt' },
      payload: { id: 'viewer-created-agent', displayName: 'Should not exist' },
    });
    expect(response.statusCode).toBe(403);
    expect(response.json()).toMatchObject({ error: { code: 'FORBIDDEN' } });
  });

  it('serializes concurrent duplicate registrations into one creation and one replay', async () => {
    const body = { id: 'concurrent-agent', displayName: 'Concurrent Agent' };
    const headers = { authorization: `Bearer ${ownerToken}`, 'idempotency-key': 'same-concurrent-key' };
    const responses = await Promise.all([
      app.inject({ method: 'POST', url: `/api/v1/orgs/${organizationId}/agents`, headers, payload: body }),
      app.inject({ method: 'POST', url: `/api/v1/orgs/${organizationId}/agents`, headers, payload: body }),
    ]);
    expect(responses.map((response) => response.statusCode).sort()).toEqual([200, 201]);
    expect(responses.filter((response) => response.json<{ credential?: { token: string } }>().credential !== undefined)).toHaveLength(1);
    const created = await pool.query<{ count: string }>(
      'SELECT count(*)::text AS count FROM agents WHERE organization_id = $1 AND id = $2',
      [organizationId, body.id],
    );
    expect(created.rows[0]?.count).toBe('1');
  });

  it('creates a hashed draft policy, lists it, and records the next immutable revision', async () => {
    const now = Math.floor(Date.now() / 1000);
    const actionAgentResponse = await app.inject({
      method: 'POST',
      url: `/api/v1/orgs/${organizationId}/agents`,
      headers: { authorization: `Bearer ${ownerToken}`, 'idempotency-key': 'register-action-agent' },
      payload: { id: 'action-agent', displayName: 'Action Agent' },
    });
    expect(actionAgentResponse.statusCode).toBe(201);
    const actionAgentToken = actionAgentResponse.json<{ credential: { token: string } }>().credential.token;
    const revisionOne = {
      schemaVersion: 1,
      policyId: 'treasury-policy',
      revision: 1,
      organizationId,
      owner: '0x9999999999999999999999999999999999999999',
      account: policyAccountAddress,
      agentId: 'action-agent',
      agentAddress: actionAgentWallet.address.toLowerCase(),
      agentKeyVersion: 1,
      chainId: 10143,
      adapter: 'evm-smart-account',
      target: '0x3333333333333333333333333333333333333333',
      selectors: ['0xa9059cbb'],
      asset: '0x3333333333333333333333333333333333333333',
      recipients: ['0x4444444444444444444444444444444444444444'],
      limits: { perAction: '1000', cumulative: '5000', windowSeconds: 3600, approvalThreshold: '800', maxActions: 10 },
      validAfter: now,
      expiresAt: now + 3600,
      nonceEpoch: 0,
    };
    const headers = { authorization: `Bearer ${ownerToken}`, 'idempotency-key': 'create-treasury-policy' };
    const created = await app.inject({ method: 'POST', url: `/api/v1/orgs/${organizationId}/policies`, headers, payload: revisionOne });
    expect(created.statusCode).toBe(201);
    expect(created.json()).toMatchObject({ policyId: 'treasury-policy', revision: 1, state: 'DRAFT' });
    const revisionOneHash = created.json<{ revisionHash: string }>().revisionHash;
    expect(revisionOneHash).toMatch(/^0x[0-9a-f]{64}$/);

    const replay = await app.inject({ method: 'POST', url: `/api/v1/orgs/${organizationId}/policies`, headers, payload: revisionOne });
    expect(replay.statusCode).toBe(200);
    expect(replay.json()).toMatchObject({ policyId: 'treasury-policy', revisionHash: revisionOneHash, replayed: true });

    const listed = await app.inject({ method: 'GET', url: `/api/v1/orgs/${organizationId}/policies`, headers: { authorization: `Bearer ${ownerToken}` } });
    expect(listed.statusCode).toBe(200);
    expect(listed.json()).toMatchObject({ policies: [{ id: 'treasury-policy', currentRevision: 1, state: 'DRAFT', revisionHash: revisionOneHash }] });

    const revisionTwo = { ...revisionOne, revision: 2, limits: { ...revisionOne.limits, cumulative: '6000' } };
    const next = await app.inject({
      method: 'POST',
      url: `/api/v1/orgs/${organizationId}/policies/treasury-policy/revisions`,
      headers: { authorization: `Bearer ${ownerToken}`, 'idempotency-key': 'create-treasury-policy-revision-2' },
      payload: revisionTwo,
    });
    expect(next.statusCode).toBe(201);
    expect(next.json()).toMatchObject({ policyId: 'treasury-policy', revision: 2, state: 'DRAFT' });
    expect(next.json<{ revisionHash: string }>().revisionHash).not.toBe(revisionOneHash);

    const revisionRows = await pool.query<{ revision: number }>(
      'SELECT revision FROM policy_revisions WHERE organization_id = $1 AND policy_id = $2 ORDER BY revision',
      [organizationId, 'treasury-policy'],
    );
    expect(revisionRows.rows.map(({ revision }) => revision)).toEqual([1, 2]);

    const repeatedRevision = await app.inject({
      method: 'POST',
      url: `/api/v1/orgs/${organizationId}/policies/treasury-policy/revisions`,
      headers: { authorization: `Bearer ${ownerToken}`, 'idempotency-key': 'policy-revision-gap' },
      payload: { ...revisionTwo, revision: 2, limits: { ...revisionTwo.limits, cumulative: '6100' } },
    });
    expect(repeatedRevision.statusCode).toBe(409);
    expect(repeatedRevision.json()).toMatchObject({ error: { code: 'RESOURCE_CONFLICT' } });

    const activationHeaders = { authorization: `Bearer ${ownerToken}`, 'idempotency-key': 'prepare-policy-activation' };
    const activation = await app.inject({
      method: 'POST', url: `/api/v1/orgs/${organizationId}/policies/treasury-policy/activate`, headers: activationHeaders,
    });
    expect(activation.statusCode).toBe(201);
    const activationBody = activation.json<{ planId: string; state: string; plan: { calls: readonly { purpose: string; nonce: string; safeTxHash: string }[] } }>();
    expect(activationBody.state).toBe('AWAITING_SAFE_OWNER_SIGNATURES');
    expect(activationBody.plan.calls.map(({ purpose, nonce }) => [purpose, nonce])).toEqual([
      ['REGISTER_AGENT', '7'], ['CONFIGURE_POLICY', '8'],
    ]);
    expect(activationBody.plan.calls.every(({ safeTxHash }) => /^0x[0-9a-f]{64}$/.test(safeTxHash))).toBe(true);
    const pendingGrant = await pool.query<{ state: string }>(
      'SELECT state FROM policy_grants WHERE organization_id = $1 AND policy_id = $2 AND policy_revision = 2',
      [organizationId, 'treasury-policy'],
    );
    expect(pendingGrant.rows[0]?.state).toBe('PENDING');
    const activationReplay = await app.inject({
      method: 'POST', url: `/api/v1/orgs/${organizationId}/policies/treasury-policy/activate`, headers: activationHeaders,
    });
    expect(activationReplay.statusCode).toBe(200);
    expect(activationReplay.json()).toMatchObject({ planId: activationBody.planId, replayed: true, plan: activationBody.plan });

    const activationTxHashes = [randomUUID().replaceAll('-', '').repeat(2), randomUUID().replaceAll('-', '').repeat(2)].map((hash) => `0x${hash}`);
    const finalizedActivation = await app.inject({
      method: 'POST',
      url: `/api/v1/orgs/${organizationId}/policies/treasury-policy/activate/finalize`,
      headers: { authorization: `Bearer ${ownerToken}`, 'idempotency-key': 'finalize-policy-activation-1' },
      payload: { planId: activationBody.planId, transactionHashes: activationTxHashes },
    });
    expect(finalizedActivation.statusCode).toBe(200);
    expect(finalizedActivation.json()).toMatchObject({
      planId: activationBody.planId, policyId: 'treasury-policy', policyRevision: 2,
      revisionHash: next.json<{ revisionHash: string }>().revisionHash, policyState: 'ACTIVE', grantState: 'ACTIVE',
    });
    const finalizedDb = await pool.query<{ policy_state: string; grant_state: string; plan_state: string; receipt_count: string }>(
      `SELECT p.state AS policy_state, g.state AS grant_state, ap.state AS plan_state,
              (SELECT count(*)::text FROM policy_activation_receipts ar WHERE ar.plan_id = ap.id) AS receipt_count
       FROM policies p JOIN policy_grants g ON g.organization_id = p.organization_id AND g.policy_id = p.id
       JOIN policy_activation_plans ap ON ap.organization_id = p.organization_id AND ap.policy_id = p.id
       WHERE p.organization_id = $1 AND p.id = 'treasury-policy' AND ap.id = $2`,
      [organizationId, activationBody.planId],
    );
    expect(finalizedDb.rows[0]).toEqual({ policy_state: 'ACTIVE', grant_state: 'ACTIVE', plan_state: 'CONFIRMED', receipt_count: '2' });
    const finalizationReplay = await app.inject({
      method: 'POST',
      url: `/api/v1/orgs/${organizationId}/policies/treasury-policy/activate/finalize`,
      headers: { authorization: `Bearer ${ownerToken}`, 'idempotency-key': 'finalize-policy-activation-1' },
      payload: { planId: activationBody.planId, transactionHashes: activationTxHashes },
    });
    expect(finalizationReplay.statusCode).toBe(200);
    expect(finalizationReplay.json()).toMatchObject({ planId: activationBody.planId, replayed: true, policyState: 'ACTIVE' });

    await pool.query('INSERT INTO members (organization_id, subject, role) VALUES ($1, $2, $3)', [organizationId, 'policy-viewer', 'VIEWER']);
    const viewerToken = await new SignJWT({})
      .setProtectedHeader({ alg: 'RS256', kid: 'integration-key' })
      .setIssuer(issuer)
      .setAudience(audience)
      .setSubject('policy-viewer')
      .setIssuedAt()
      .setExpirationTime('5m')
      .sign(signingKey);
    const viewerCreate = await app.inject({
      method: 'POST',
      url: `/api/v1/orgs/${organizationId}/policies`,
      headers: { authorization: `Bearer ${viewerToken}`, 'idempotency-key': 'viewer-policy-attempt' },
      payload: revisionOne,
    });
    expect(viewerCreate.statusCode).toBe(403);
    expect(viewerCreate.json()).toMatchObject({ error: { code: 'FORBIDDEN' } });
    const viewerActivation = await app.inject({
      method: 'POST', url: `/api/v1/orgs/${organizationId}/policies/treasury-policy/activate`,
      headers: { authorization: `Bearer ${viewerToken}`, 'idempotency-key': 'viewer-policy-activation-attempt' },
    });
    expect(viewerActivation.statusCode).toBe(403);
    expect(viewerActivation.json()).toMatchObject({ error: { code: 'FORBIDDEN' } });

    const revisionTwoHash = next.json<{ revisionHash: string }>().revisionHash;
    const actionHeaders = { authorization: `Bearer ${actionAgentToken}`, 'idempotency-key': 'action-submit-1' };
    const actionBody = {
      actionId: 'transfer-1',
      idempotencyKey: actionHeaders['idempotency-key'],
      policyId: 'treasury-policy',
      policyRevision: 2,
      policyRevisionHash: revisionTwoHash,
      organizationId,
      account: policyAccountAddress,
      agentId: 'action-agent',
      agentKeyVersion: 1,
      chainId: 10143,
      target: revisionOne.target,
      selector: '0xa9059cbb',
      asset: revisionOne.asset,
      recipient: revisionOne.recipients[0],
      amount: '100',
      nonce: 0,
      nonceEpoch: 0,
      expiresAt: now + 600,
    };
    await pool.query("UPDATE policy_grants SET state = 'PENDING', granted_at = NULL WHERE organization_id = $1 AND policy_id = 'treasury-policy'", [organizationId]);
    const missingGrantSimulation = await app.inject({
      method: 'POST',
      url: `/api/v1/orgs/${organizationId}/policies/treasury-policy/simulate`,
      headers: { authorization: `Bearer ${ownerToken}` },
      payload: actionBody,
    });
    expect(missingGrantSimulation.statusCode).toBe(200);
    expect(missingGrantSimulation.json()).toMatchObject({ verdict: 'BLOCK', reason: 'GRANT_INACTIVE' });
    await pool.query("UPDATE policy_grants SET state = 'ACTIVE', granted_at = now() WHERE organization_id = $1 AND policy_id = 'treasury-policy'", [organizationId]);
    const simulationBaseline = await pool.query<{ action_count: string; reservation_count: string; audit_count: string }>(
      `SELECT (SELECT count(*)::text FROM action_requests WHERE organization_id = $1) AS action_count,
       (SELECT count(*)::text FROM reservations WHERE organization_id = $1) AS reservation_count,
       (SELECT count(*)::text FROM audit_events WHERE organization_id = $1) AS audit_count`,
      [organizationId],
    );
    const simulation = await app.inject({
      method: 'POST',
      url: `/api/v1/orgs/${organizationId}/policies/treasury-policy/simulate`,
      headers: { authorization: `Bearer ${ownerToken}` },
      payload: actionBody,
    });
    expect(simulation.statusCode).toBe(200);
    expect(simulation.json()).toEqual({ verdict: 'ALLOW', reason: 'POLICY_PASS', policyRevisionHash: revisionTwoHash });
    const simulationSideEffects = await pool.query<{ action_count: string; reservation_count: string; audit_count: string }>(
      `SELECT (SELECT count(*)::text FROM action_requests WHERE organization_id = $1) AS action_count,
       (SELECT count(*)::text FROM reservations WHERE organization_id = $1) AS reservation_count,
       (SELECT count(*)::text FROM audit_events WHERE organization_id = $1) AS audit_count`,
      [organizationId],
    );
    expect(simulationSideEffects.rows[0]).toEqual(simulationBaseline.rows[0]);
    const actionResponse = await app.inject({
      method: 'POST',
      url: `/api/v1/orgs/${organizationId}/actions`,
      headers: actionHeaders,
      payload: actionBody,
    });
    expect(actionResponse.statusCode).toBe(201);
    expect(actionResponse.json()).toMatchObject({
      actionId: 'transfer-1', state: 'RESERVED', verdict: 'ALLOW', reason: 'POLICY_PASS', policyRevisionHash: revisionTwoHash,
    });
    const actionDetail = await app.inject({
      method: 'GET',
      url: `/api/v1/orgs/${organizationId}/actions/transfer-1`,
      headers: { authorization: `Bearer ${actionAgentToken}` },
    });
    expect(actionDetail.statusCode).toBe(200);
    expect(actionDetail.json()).toMatchObject({ actionId: 'transfer-1', state: 'RESERVED', actionHash: expect.stringMatching(/^0x[0-9a-f]{64}$/) });
    const unrelatedAgent = await app.inject({
      method: 'POST',
      url: `/api/v1/orgs/${organizationId}/agents`,
      headers: { authorization: `Bearer ${ownerToken}`, 'idempotency-key': 'register-unrelated-reader' },
      payload: { id: 'unrelated-reader', displayName: 'Unrelated Reader' },
    });
    expect(unrelatedAgent.statusCode).toBe(201);
    const unrelatedAgentToken = unrelatedAgent.json<{ credential: { token: string } }>().credential.token;
    const hiddenAction = await app.inject({
      method: 'GET',
      url: `/api/v1/orgs/${organizationId}/actions/transfer-1`,
      headers: { authorization: `Bearer ${unrelatedAgentToken}` },
    });
    expect(hiddenAction.statusCode).toBe(404);
    const auditFeed = await app.inject({
      method: 'GET',
      url: `/api/v1/orgs/${organizationId}/audit-events?limit=50`,
      headers: { authorization: `Bearer ${ownerToken}` },
    });
    expect(auditFeed.statusCode).toBe(200);
    expect(auditFeed.json<{ events: readonly { subjectId: string; eventType: string }[] }>().events.some((event) => event.subjectId === 'transfer-1' && event.eventType === 'ACTION_RESERVED')).toBe(true);
    const signedAuditExport = await app.inject({
      method: 'GET',
      url: `/api/v1/orgs/${organizationId}/audit-exports?limit=50`,
      headers: { authorization: `Bearer ${ownerToken}` },
    });
    expect(signedAuditExport.statusCode).toBe(200);
    const signedExportBody = signedAuditExport.json<SignedAuditExport>();
    expect(signedExportBody.payload.events.some((event) => event.subjectId === 'transfer-1' && event.eventType === 'ACTION_RESERVED')).toBe(true);
    expect(verifyAuditExport(signedExportBody, signedExportBody.keyFingerprint)).toEqual({ valid: true, reason: null });
    const agentAuditExport = await app.inject({
      method: 'GET',
      url: `/api/v1/orgs/${organizationId}/audit-exports?limit=50`,
      headers: { authorization: `Bearer ${actionAgentToken}` },
    });
    expect(agentAuditExport.statusCode).toBe(403);
    const receiptList = await app.inject({
      method: 'GET',
      url: `/api/v1/orgs/${organizationId}/receipts`,
      headers: { authorization: `Bearer ${ownerToken}` },
    });
    expect(receiptList.statusCode).toBe(200);
    expect(receiptList.json()).toEqual({ receipts: [] });
    const transactionHash = `0x${randomUUID().replaceAll('-', '').repeat(2)}`;
    const blockHash = `0x${randomUUID().replaceAll('-', '').repeat(2)}`;
    await pool.query(
      `INSERT INTO receipts (organization_id, action_id, chain_id, transaction_hash, block_number, block_hash, status, receipt_json)
       VALUES ($1, 'transfer-1', 10143, $2, 123, $3, 'FINAL', '{"status":"success"}'::jsonb)`,
      [organizationId, transactionHash, blockHash],
    );
    const populatedReceipts = await app.inject({
      method: 'GET',
      url: `/api/v1/orgs/${organizationId}/receipts?limit=10`,
      headers: { authorization: `Bearer ${actionAgentToken}` },
    });
    expect(populatedReceipts.statusCode).toBe(200);
    expect(populatedReceipts.json()).toMatchObject({ receipts: [{ actionId: 'transfer-1', chainId: 10143, transactionHash, blockNumber: '123', blockHash, status: 'FINAL', receipt: { status: 'success' } }] });
    const alertEventId = randomUUID();
    await pool.query(
      `INSERT INTO outbox_events (id, organization_id, aggregate_type, aggregate_id, event_type, payload)
       VALUES ($1, $2, 'ACTION', 'transfer-1', 'ACTION_BLOCKED', '{}'::jsonb)`,
      [alertEventId, organizationId],
    );
    await pool.query(
      `INSERT INTO alert_notifications (organization_id, outbox_event_id, event_type, title, aggregate_id)
       VALUES ($1, $2, 'ACTION_BLOCKED', 'Action blocked', 'transfer-1')`,
      [organizationId, alertEventId],
    );
    const alerts = await app.inject({
      method: 'GET', url: `/api/v1/orgs/${organizationId}/alerts?limit=10`,
      headers: { authorization: `Bearer ${ownerToken}` },
    });
    expect(alerts.statusCode).toBe(200);
    expect(alerts.json()).toMatchObject({ alerts: [{ eventType: 'ACTION_BLOCKED', title: 'Action blocked', aggregateId: 'transfer-1' }] });
    const replayedAction = await app.inject({
      method: 'POST',
      url: `/api/v1/orgs/${organizationId}/actions`,
      headers: actionHeaders,
      payload: actionBody,
    });
    expect(replayedAction.statusCode).toBe(200);
    expect(replayedAction.json()).toMatchObject({ actionId: 'transfer-1', state: 'RESERVED', replayed: true });
    const persistedAction = await pool.query<{ state: string; reservation_count: string; decision_count: string; outbox_count: string }>(
      `SELECT a.state,
       (SELECT count(*)::text FROM reservations r WHERE r.organization_id = a.organization_id AND r.action_id = a.id) AS reservation_count,
       (SELECT count(*)::text FROM decisions d WHERE d.organization_id = a.organization_id AND d.action_id = a.id) AS decision_count,
       (SELECT count(*)::text FROM outbox_events o WHERE o.organization_id = a.organization_id AND o.aggregate_id = a.id AND o.event_type = 'ACTION_RESERVED') AS outbox_count
       FROM action_requests a WHERE a.organization_id = $1 AND a.id = 'transfer-1'`,
      [organizationId],
    );
    expect(persistedAction.rows[0]).toEqual({ state: 'RESERVED', reservation_count: '1', decision_count: '1', outbox_count: '1' });

    const staleNonceResponse = await app.inject({
      method: 'POST',
      url: `/api/v1/orgs/${organizationId}/actions`,
      headers: { authorization: `Bearer ${actionAgentToken}`, 'idempotency-key': 'action-submit-stale-nonce' },
      payload: { ...actionBody, actionId: 'transfer-stale-nonce', idempotencyKey: 'action-submit-stale-nonce' },
    });
    expect(staleNonceResponse.statusCode).toBe(201);
    expect(staleNonceResponse.json()).toMatchObject({ state: 'BLOCKED', verdict: 'BLOCK', reason: 'NONCE_INVALID' });
    const nonceCounts = await pool.query<{ active_reservations: string; next_nonce: string }>(
      `SELECT (SELECT count(*)::text FROM reservations WHERE organization_id = $1 AND state = 'ACTIVE') AS active_reservations,
       (SELECT next_nonce::text FROM action_nonce_counters WHERE organization_id = $1 AND policy_id = 'treasury-policy' AND agent_id = 'action-agent' AND nonce_epoch = 0) AS next_nonce`,
      [organizationId],
    );
    expect(nonceCounts.rows[0]).toEqual({ active_reservations: '1', next_nonce: '1' });

    const authorizeHeaders = { authorization: `Bearer ${actionAgentToken}`, 'idempotency-key': 'authorize-transfer-1' };
    const unrelatedAuthorization = await app.inject({
      method: 'POST',
      url: `/api/v1/orgs/${organizationId}/actions/transfer-1/authorize`,
      headers: { authorization: `Bearer ${unrelatedAgentToken}`, 'idempotency-key': 'unrelated-authorize-transfer' },
    });
    expect(unrelatedAuthorization.statusCode).toBe(404);
    const concurrentAuthorizations = await Promise.all([
      app.inject({ method: 'POST', url: `/api/v1/orgs/${organizationId}/actions/transfer-1/authorize`, headers: authorizeHeaders }),
      app.inject({ method: 'POST', url: `/api/v1/orgs/${organizationId}/actions/transfer-1/authorize`, headers: authorizeHeaders }),
    ]);
    expect(concurrentAuthorizations.map((response) => response.statusCode).sort()).toEqual([200, 201]);
    const authorization = concurrentAuthorizations.find((response) => response.statusCode === 201);
    expect(authorization).toBeDefined();
    if (authorization === undefined) throw new Error('Concurrent authorization did not produce a creation response');
    expect(authorization.statusCode).toBe(201);
    const authorizationBody = authorization.json<{ actionId: string; state: string; authorization: ActionExecutionAuthorization }>();
    expect(authorizationBody).toMatchObject({
      actionId: 'transfer-1', state: 'AUTHORIZED',
      authorization: { executionNonce: '0', signingPayload: { domain: { verifyingContract: `0x${'5'.repeat(40)}` } } },
    });
    expect(authorizationBody.authorization.actionDigest).toMatch(/^0x[0-9a-f]{64}$/);
    expect(authorizationBody.authorization.actionHash).toMatch(/^0x[0-9a-f]{64}$/);
    const authorizationReplay = await app.inject({
      method: 'POST',
      url: `/api/v1/orgs/${organizationId}/actions/transfer-1/authorize`,
      headers: authorizeHeaders,
    });
    expect(authorizationReplay.statusCode).toBe(200);
    expect(authorizationReplay.json()).toMatchObject({ ...authorizationBody, replayed: true });
    const changedAuthorizationKey = await app.inject({
      method: 'POST',
      url: `/api/v1/orgs/${organizationId}/actions/transfer-1/authorize`,
      headers: { authorization: `Bearer ${actionAgentToken}`, 'idempotency-key': 'authorize-transfer-different-key' },
    });
    expect(changedAuthorizationKey.statusCode).toBe(409);
    const ownerCannotAuthorize = await app.inject({
      method: 'POST',
      url: `/api/v1/orgs/${organizationId}/actions/transfer-1/authorize`,
      headers: { authorization: `Bearer ${ownerToken}`, 'idempotency-key': 'owner-cannot-authorize' },
    });
    expect(ownerCannotAuthorize.statusCode).toBe(403);
    const authorizationRows = await pool.query<{ action_state: string; attempt_state: string; authorization_state: string; action_hash: string; snapshot_block_number: string; snapshot_block_hash: string; signature_saved: boolean; audit_count: string; outbox_count: string }>(
      `SELECT a.state AS action_state, e.state AS attempt_state, x.status AS authorization_state,
         btrim(x.action_hash) AS action_hash, x.snapshot_block_number::text AS snapshot_block_number,
         btrim(x.snapshot_block_hash) AS snapshot_block_hash, x.authorization_json ? 'signature' AS signature_saved,
         (SELECT count(*)::text FROM audit_events v WHERE v.organization_id = a.organization_id AND v.subject_id = a.id AND v.event_type = 'ACTION_AUTHORIZED') AS audit_count,
         (SELECT count(*)::text FROM outbox_events o WHERE o.organization_id = a.organization_id AND o.aggregate_id = a.id AND o.event_type = 'ACTION_AUTHORIZED') AS outbox_count
       FROM action_requests a JOIN execution_attempts e ON e.organization_id = a.organization_id AND e.action_id = a.id
       JOIN action_authorizations x ON x.organization_id = a.organization_id AND x.action_id = a.id
       WHERE a.organization_id = $1 AND a.id = 'transfer-1'`, [organizationId],
    );
    expect(authorizationRows.rows[0]).toEqual({
      action_state: 'AUTHORIZED', attempt_state: 'AUTHORIZED', authorization_state: 'ACTIVE',
      action_hash: authorizationBody.authorization.actionHash, snapshot_block_number: '101', snapshot_block_hash: `0x${'c'.repeat(64)}`,
      signature_saved: false, audit_count: '1', outbox_count: '1',
    });

    const plan = authorizationBody.authorization;
    const agentSignature = await actionAgentWallet.signTypedData(plan.signingPayload.domain, plan.signingPayload.types, plan.signingPayload.message);
    const moduleCall = actionExecutionInterface.encodeFunctionData('execute', [
      plan.to, BigInt(plan.value), plan.data, plan.deadline, plan.keyVersion, BigInt(plan.executionNonce), agentSignature,
    ]);
    const signedTransaction = await actionAgentWallet.signTransaction({
      chainId: plan.chainId, nonce: 0, gasLimit: 150_000, gasPrice: 1_000_000_000n,
      to: plan.moduleAddress, value: 0n, data: moduleCall,
    });
    const executeHeaders = { authorization: `Bearer ${actionAgentToken}`, 'idempotency-key': 'execute-transfer-1' };
    const executeUrl = `/api/v1/orgs/${organizationId}/actions/transfer-1/execute`;
    failNextTransactionSubmission = true;
    const uncertainSubmission = await app.inject({
      method: 'POST', url: executeUrl, headers: executeHeaders,
      payload: { signature: agentSignature, rawTransaction: signedTransaction },
    });
    expect(uncertainSubmission.statusCode).toBe(503);
    expect(submittedRawTransactions).toEqual([signedTransaction]);
    const pendingSubmission = await pool.query<{ status: string; transaction_hash: string }>(
      'SELECT status, btrim(transaction_hash) AS transaction_hash FROM action_execution_submissions WHERE organization_id = $1 AND action_id = $2',
      [organizationId, 'transfer-1'],
    );
    expect(pendingSubmission.rows[0]).toEqual({ status: 'PENDING', transaction_hash: keccak256(signedTransaction).toLowerCase() });
    const concurrentExecutions = await Promise.all([
      app.inject({ method: 'POST', url: executeUrl, headers: executeHeaders, payload: { signature: agentSignature, rawTransaction: signedTransaction } }),
      app.inject({ method: 'POST', url: executeUrl, headers: executeHeaders, payload: { signature: agentSignature, rawTransaction: signedTransaction } }),
    ]);
    expect(concurrentExecutions.map((response) => response.statusCode).sort()).toEqual([200, 201]);
    const executeResponse = concurrentExecutions.find((response) => response.statusCode === 201);
    expect(executeResponse).toBeDefined();
    if (executeResponse === undefined) throw new Error('Concurrent action execution did not produce a creation response');
    expect(executeResponse.statusCode).toBe(201);
    const executed = executeResponse.json<{ actionId: string; state: string; transactionHash: string }>();
    expect(executed).toEqual({ actionId: 'transfer-1', state: 'SUBMITTED', transactionHash: keccak256(signedTransaction).toLowerCase() });
    expect(submittedRawTransactions.length).toBeGreaterThanOrEqual(2);
    expect(submittedRawTransactions.length).toBeLessThanOrEqual(3);
    expect(submittedRawTransactions.every((transaction) => transaction === signedTransaction)).toBe(true);
    const executionReplay = await app.inject({
      method: 'POST', url: executeUrl, headers: executeHeaders,
      payload: { signature: agentSignature, rawTransaction: signedTransaction },
    });
    expect(executionReplay.statusCode).toBe(200);
    expect(executionReplay.json()).toMatchObject({ ...executed, replayed: true });
    expect(submittedRawTransactions.length).toBeGreaterThanOrEqual(2);
    expect(submittedRawTransactions.every((transaction) => transaction === signedTransaction)).toBe(true);
    const changedRawTransaction = await actionAgentWallet.signTransaction({
      chainId: plan.chainId, nonce: 1, gasLimit: 150_000, gasPrice: 1_000_000_000n,
      to: plan.moduleAddress, value: 0n, data: moduleCall,
    });
    const conflictingExecution = await app.inject({
      method: 'POST', url: executeUrl,
      headers: { authorization: `Bearer ${actionAgentToken}`, 'idempotency-key': 'execute-transfer-different-raw-tx' },
      payload: { signature: agentSignature, rawTransaction: changedRawTransaction },
    });
    expect(conflictingExecution.statusCode).toBe(409);
    expect(submittedRawTransactions.every((transaction) => transaction === signedTransaction)).toBe(true);
    const executionRows = await pool.query<{ action_state: string; attempt_state: string; transaction_hash: string; authorization_state: string; submission_state: string; audit_count: string; outbox_count: string }>(
      `SELECT a.state AS action_state, e.state AS attempt_state, btrim(e.transaction_hash) AS transaction_hash,
         x.status AS authorization_state, s.status AS submission_state,
         (SELECT count(*)::text FROM audit_events v WHERE v.organization_id = a.organization_id AND v.subject_id = a.id AND v.event_type = 'ACTION_SUBMITTED') AS audit_count,
         (SELECT count(*)::text FROM outbox_events o WHERE o.organization_id = a.organization_id AND o.aggregate_id = a.id AND o.event_type = 'ACTION_SUBMITTED') AS outbox_count
       FROM action_requests a JOIN execution_attempts e ON e.organization_id = a.organization_id AND e.action_id = a.id
       JOIN action_authorizations x ON x.organization_id = a.organization_id AND x.action_id = a.id
       JOIN action_execution_submissions s ON s.organization_id = a.organization_id AND s.action_id = a.id
       WHERE a.organization_id = $1 AND a.id = 'transfer-1'`, [organizationId],
    );
    expect(executionRows.rows[0]).toEqual({
      action_state: 'SUBMITTED', attempt_state: 'SUBMITTED', transaction_hash: executed.transactionHash,
      authorization_state: 'CONSUMED', submission_state: 'SUBMITTED', audit_count: '1', outbox_count: '1',
    });
    const reconciliation = new ExecutionReconciliationStore(pool);
    const pendingExecution = {
      organizationId, actionId: 'transfer-1', chainId: plan.chainId, transactionHash: executed.transactionHash,
      moduleAddress: plan.moduleAddress, agentAddress: plan.agentAddress, keyVersion: String(plan.keyVersion),
      executionNonce: plan.executionNonce, actionHash: plan.actionHash,
      snapshotBlockNumber: plan.snapshotBlockNumber, authorizationDeadline: plan.deadline,
      outerSender: null, outerNonce: null,
    };
    const tentativeReceipt = {
      transactionHash: executed.transactionHash, blockNumber: 120, blockHash: `0x${'d'.repeat(64)}`,
      status: 'TENTATIVE' as const, executionResult: 'SUCCESS' as const, confirmations: 1,
      receipt: { status: 'SUCCESS', gasUsed: '42000' },
    };
    await expect(reconciliation.recordObservation({ pending: pendingExecution, observation: tentativeReceipt })).resolves.toBe('TENTATIVE');
    await expect(reconciliation.recordObservation({ pending: pendingExecution, observation: null })).resolves.toBe('REORGED');
    const replacementHash = `0x${randomUUID().replaceAll('-', '')}${'e'.repeat(32)}`;
    const replacementBlock = 1_000_000_000 + Math.floor(Math.random() * 100_000);
    const replacementBlockHash = `0x${randomUUID().replaceAll('-', '')}${'f'.repeat(32)}`;
    await pool.query(
      `INSERT INTO indexer_blocks (chain_id, block_number, block_hash, parent_hash) VALUES ($1, $2, $3, $4)`,
      [plan.chainId, replacementBlock, replacementBlockHash, `0x${'a'.repeat(64)}`],
    );
    const indexedEventTopics = [
      '0xf8ac4b4e81cac0a2fb7dc0f50ae0205789de4f0a13336381c20e5cd71016f24b',
      `0x${plan.agentAddress.slice(2).padStart(64, '0')}`,
      `0x${BigInt(plan.keyVersion).toString(16).padStart(64, '0')}`,
      `0x${BigInt(plan.executionNonce).toString(16).padStart(64, '0')}`,
    ];
    await pool.query(
      `INSERT INTO indexed_chain_logs (chain_id, block_number, block_hash, transaction_hash, transaction_index, log_index, address, topics, data)
       VALUES ($1, $2, $3, $4, 0, 0, $5, $6, $7)`,
      [plan.chainId, replacementBlock, replacementBlockHash, replacementHash, plan.moduleAddress, indexedEventTopics, plan.actionHash],
    );
    await expect(reconciliation.findCanonicalExecution(pendingExecution)).resolves.toBe(replacementHash);
    await expect(reconciliation.recordObservation({ pending: pendingExecution, observation: {
      ...tentativeReceipt, transactionHash: replacementHash, blockNumber: replacementBlock,
      blockHash: replacementBlockHash, status: 'FINAL', confirmations: 12,
      receipt: { ...tentativeReceipt.receipt, transactionHash: replacementHash, blockNumber: replacementBlock, blockHash: replacementBlockHash },
    } })).resolves.toBe('FINALIZED');
    const reconciledState = await pool.query<{ action_state: string; attempt_state: string; attempt_transaction_hash: string; reservation_state: string; receipt_status: string; final_audit_count: string; reorg_audit_count: string; replacement_audit_count: string }>(
      `SELECT a.state AS action_state, e.state AS attempt_state, btrim(e.transaction_hash) AS attempt_transaction_hash,
         r.state AS reservation_state, receipt.status AS receipt_status,
         (SELECT count(*)::text FROM audit_events v WHERE v.organization_id = a.organization_id AND v.subject_id = a.id AND v.event_type = 'ACTION_RECONCILED') AS final_audit_count,
         (SELECT count(*)::text FROM audit_events v WHERE v.organization_id = a.organization_id AND v.subject_id = a.id AND v.event_type = 'ACTION_RECEIPT_REORGED') AS reorg_audit_count,
         (SELECT count(*)::text FROM audit_events v WHERE v.organization_id = a.organization_id AND v.subject_id = a.id AND v.event_type = 'ACTION_TRANSACTION_REPLACED') AS replacement_audit_count
       FROM action_requests a JOIN execution_attempts e ON e.organization_id = a.organization_id AND e.action_id = a.id
       JOIN reservations r ON r.organization_id = a.organization_id AND r.action_id = a.id
       JOIN receipts receipt ON receipt.organization_id = a.organization_id AND receipt.action_id = a.id
       WHERE a.organization_id = $1 AND a.id = 'transfer-1' AND receipt.status = 'FINAL'`, [organizationId],
    );
    expect(reconciledState.rows[0]).toEqual({ action_state: 'RECONCILED', attempt_state: 'CONFIRMED', attempt_transaction_hash: replacementHash,
      reservation_state: 'CONSUMED', receipt_status: 'FINAL', final_audit_count: '1', reorg_audit_count: '1', replacement_audit_count: '1' });
    await expect(reconciliation.recordObservation({ pending: pendingExecution, observation: {
      ...tentativeReceipt, status: 'FINAL', confirmations: 12,
    } })).resolves.toBe('UNCHANGED');
    const ownerCannotExecute = await app.inject({
      method: 'POST', url: executeUrl,
      headers: { authorization: `Bearer ${ownerToken}`, 'idempotency-key': 'owner-execute' },
      payload: { signature: agentSignature, rawTransaction: signedTransaction },
    });
    expect(ownerCannotExecute.statusCode).toBe(403);
    const invalidSignature = await new Wallet(`0x${'1'.repeat(64)}`).signTypedData(
      plan.signingPayload.domain, plan.signingPayload.types, { ...plan.signingPayload.message, value: '1' },
    );
    const rejectedSignature = await app.inject({
      method: 'POST', url: executeUrl,
      headers: { authorization: `Bearer ${actionAgentToken}`, 'idempotency-key': 'invalid-execution-signature' },
      payload: { signature: invalidSignature, rawTransaction: signedTransaction },
    });
    expect(rejectedSignature.statusCode).toBe(400);

    const heldAction = {
      ...actionBody,
      actionId: 'transfer-needs-approval',
      idempotencyKey: 'action-submit-held',
      amount: '900',
      nonce: 1,
    };
    const heldResponse = await app.inject({
      method: 'POST',
      url: `/api/v1/orgs/${organizationId}/actions`,
      headers: { authorization: `Bearer ${actionAgentToken}`, 'idempotency-key': heldAction.idempotencyKey },
      payload: heldAction,
    });
    expect(heldResponse.statusCode).toBe(201);
    expect(heldResponse.json()).toMatchObject({ state: 'HELD', verdict: 'HOLD', reason: 'APPROVAL_REQUIRED' });
    const heldActionData = await pool.query<{ request_hash: string }>(
      'SELECT request_hash FROM action_requests WHERE organization_id = $1 AND id = $2',
      [organizationId, heldAction.actionId],
    );
    const actionHash = heldActionData.rows[0]?.request_hash.trim();
    expect(actionHash).toMatch(/^0x[0-9a-f]{64}$/);
    const authorApproval = await app.inject({
      method: 'POST',
      url: `/api/v1/orgs/${organizationId}/actions/${heldAction.actionId}/approval`,
      headers: { authorization: `Bearer ${ownerToken}`, 'idempotency-key': 'author-cannot-approve' },
      payload: { outcome: 'APPROVED', actionHash },
    });
    expect(authorApproval.statusCode).toBe(403);
    await pool.query('INSERT INTO members (organization_id, subject, role) VALUES ($1, $2, \'APPROVER\')', [organizationId, 'independent-approver']);
    const approverToken = await new SignJWT({})
      .setProtectedHeader({ alg: 'RS256', kid: 'integration-key' })
      .setIssuer(issuer)
      .setAudience(audience)
      .setSubject('independent-approver')
      .setIssuedAt()
      .setExpirationTime('5m')
      .sign(signingKey);
    const mismatchedHashApproval = await app.inject({
      method: 'POST',
      url: `/api/v1/orgs/${organizationId}/actions/${heldAction.actionId}/approval`,
      headers: { authorization: `Bearer ${approverToken}`, 'idempotency-key': 'wrong-action-hash' },
      payload: { outcome: 'APPROVED', actionHash: `0x${'f'.repeat(64)}` },
    });
    expect(mismatchedHashApproval.statusCode).toBe(409);
    const approvalResponse = await app.inject({
      method: 'POST',
      url: `/api/v1/orgs/${organizationId}/actions/${heldAction.actionId}/approval`,
      headers: { authorization: `Bearer ${approverToken}`, 'idempotency-key': 'approve-held-action' },
      payload: { outcome: 'APPROVED', actionHash },
    });
    expect(approvalResponse.statusCode).toBe(201);
    expect(approvalResponse.json()).toMatchObject({
      actionId: heldAction.actionId, state: 'RESERVED', verdict: 'ALLOW', reason: 'HUMAN_APPROVED', actionHash,
    });
    const approvalReplay = await app.inject({
      method: 'POST',
      url: `/api/v1/orgs/${organizationId}/actions/${heldAction.actionId}/approval`,
      headers: { authorization: `Bearer ${approverToken}`, 'idempotency-key': 'approve-held-action' },
      payload: { outcome: 'APPROVED', actionHash },
    });
    expect(approvalReplay.statusCode).toBe(200);
    expect(approvalReplay.json()).toMatchObject({ actionId: heldAction.actionId, state: 'RESERVED', replayed: true });

    const deniedHeldAction = {
      ...heldAction,
      actionId: 'transfer-denied',
      idempotencyKey: 'action-submit-denied',
      nonce: 2,
    };
    const deniedHeldResponse = await app.inject({
      method: 'POST',
      url: `/api/v1/orgs/${organizationId}/actions`,
      headers: { authorization: `Bearer ${actionAgentToken}`, 'idempotency-key': deniedHeldAction.idempotencyKey },
      payload: deniedHeldAction,
    });
    expect(deniedHeldResponse.statusCode).toBe(201);
    expect(deniedHeldResponse.json()).toMatchObject({ state: 'HELD', verdict: 'HOLD' });
    const deniedHashResult = await pool.query<{ request_hash: string }>(
      'SELECT request_hash FROM action_requests WHERE organization_id = $1 AND id = $2',
      [organizationId, deniedHeldAction.actionId],
    );
    const deniedHash = deniedHashResult.rows[0]?.request_hash.trim();
    expect(deniedHash).toMatch(/^0x[0-9a-f]{64}$/);
    const deniedApproval = await app.inject({
      method: 'POST',
      url: `/api/v1/orgs/${organizationId}/actions/${deniedHeldAction.actionId}/approval`,
      headers: { authorization: `Bearer ${approverToken}`, 'idempotency-key': 'deny-held-action' },
      payload: { outcome: 'DENIED', actionHash: deniedHash },
    });
    expect(deniedApproval.statusCode).toBe(201);
    expect(deniedApproval.json()).toMatchObject({ actionId: deniedHeldAction.actionId, state: 'DENIED', verdict: 'BLOCK', reason: 'APPROVAL_DENIED' });
    const deniedReservation = await pool.query<{ state: string }>(
      'SELECT state FROM reservations WHERE organization_id = $1 AND action_id = $2',
      [organizationId, deniedHeldAction.actionId],
    );
    expect(deniedReservation.rows[0]?.state).toBe('RELEASED');

    const expiringAction = {
      ...heldAction,
      actionId: 'transfer-expiring',
      idempotencyKey: 'action-submit-expiring',
      nonce: 3,
    };
    const expiringHeld = await app.inject({
      method: 'POST',
      url: `/api/v1/orgs/${organizationId}/actions`,
      headers: { authorization: `Bearer ${actionAgentToken}`, 'idempotency-key': expiringAction.idempotencyKey },
      payload: expiringAction,
    });
    expect(expiringHeld.statusCode).toBe(201);
    const expiringHashResult = await pool.query<{ request_hash: string }>(
      'SELECT request_hash FROM action_requests WHERE organization_id = $1 AND id = $2',
      [organizationId, expiringAction.actionId],
    );
    const expiringHash = expiringHashResult.rows[0]?.request_hash.trim();
    expect(expiringHash).toMatch(/^0x[0-9a-f]{64}$/);
    await pool.query("UPDATE reservations SET lease_expires_at = now() - interval '1 second' WHERE organization_id = $1 AND action_id = $2", [organizationId, expiringAction.actionId]);
    const expirationResult = await app.inject({
      method: 'POST',
      url: `/api/v1/orgs/${organizationId}/actions/${expiringAction.actionId}/approval`,
      headers: { authorization: `Bearer ${approverToken}`, 'idempotency-key': 'expire-held-action' },
      payload: { outcome: 'APPROVED', actionHash: expiringHash },
    });
    expect(expirationResult.statusCode).toBe(201);
    expect(expirationResult.json()).toMatchObject({ actionId: expiringAction.actionId, state: 'EXPIRED', verdict: 'BLOCK', reason: 'ACTION_EXPIRED' });
    const expiryStates = await pool.query<{ state: string; reservation_state: string }>(
      `SELECT a.state, r.state AS reservation_state FROM action_requests a JOIN reservations r
       ON r.organization_id = a.organization_id AND r.action_id = a.id WHERE a.organization_id = $1 AND a.id = $2`,
      [organizationId, expiringAction.actionId],
    );
    expect(expiryStates.rows[0]).toEqual({ state: 'EXPIRED', reservation_state: 'EXPIRED' });

    await pool.query("UPDATE accounts SET status = 'PAUSED' WHERE organization_id = $1 AND id = 'policy-account'", [organizationId]);
    const pausedAccountAction = await app.inject({
      method: 'POST',
      url: `/api/v1/orgs/${organizationId}/actions`,
      headers: { authorization: `Bearer ${actionAgentToken}`, 'idempotency-key': 'paused-account-action' },
      payload: { ...actionBody, actionId: 'transfer-paused-account', idempotencyKey: 'paused-account-action' },
    });
    expect(pausedAccountAction.statusCode).toBe(201);
    expect(pausedAccountAction.json()).toMatchObject({ state: 'BLOCKED', verdict: 'BLOCK', reason: 'ADAPTER_UNSUPPORTED' });
    await pool.query("UPDATE accounts SET status = 'ACTIVE' WHERE organization_id = $1 AND id = 'policy-account'", [organizationId]);

    const revocationPlan = await app.inject({
      method: 'POST', url: `/api/v1/orgs/${organizationId}/policies/treasury-policy/revoke`,
      headers: { authorization: `Bearer ${ownerToken}`, 'idempotency-key': 'prepare-policy-revocation-1' },
    });
    expect(revocationPlan.statusCode).toBe(201);
    const revokePlanBody = revocationPlan.json<{ planId: string; state: string; plan: { expectedPolicyEpoch: string; resultingPolicyEpoch: string; call: { safeTxHash: string } } }>();
    expect(revokePlanBody).toMatchObject({ state: 'AWAITING_SAFE_OWNER_SIGNATURES', plan: { expectedPolicyEpoch: '1', resultingPolicyEpoch: '2' } });
    expect(revokePlanBody.plan.call.safeTxHash).toMatch(/^0x[0-9a-f]{64}$/);
    const revocationReplay = await app.inject({
      method: 'POST', url: `/api/v1/orgs/${organizationId}/policies/treasury-policy/revoke`,
      headers: { authorization: `Bearer ${ownerToken}`, 'idempotency-key': 'prepare-policy-revocation-1' },
    });
    expect(revocationReplay.statusCode).toBe(200);
    expect(revocationReplay.json()).toMatchObject({ planId: revokePlanBody.planId, replayed: true, plan: revokePlanBody.plan });
    const viewerRevocation = await app.inject({
      method: 'POST', url: `/api/v1/orgs/${organizationId}/policies/treasury-policy/revoke`,
      headers: { authorization: `Bearer ${viewerToken}`, 'idempotency-key': 'viewer-policy-revocation' },
    });
    expect(viewerRevocation.statusCode).toBe(403);
    const stillActive = await pool.query<{ policy_state: string; grant_state: string }>(
      `SELECT p.state AS policy_state, g.state AS grant_state FROM policies p JOIN policy_grants g
         ON g.organization_id = p.organization_id AND g.policy_id = p.id AND g.policy_revision = p.current_revision
       WHERE p.organization_id = $1 AND p.id = 'treasury-policy'`, [organizationId],
    );
    expect(stillActive.rows[0]).toEqual({ policy_state: 'ACTIVE', grant_state: 'ACTIVE' });
    const revocationTransactionHash = `0x${randomUUID().replaceAll('-', '').repeat(2)}`;
    const finalizedRevocation = await app.inject({
      method: 'POST', url: `/api/v1/orgs/${organizationId}/policies/treasury-policy/revoke/finalize`,
      headers: { authorization: `Bearer ${ownerToken}`, 'idempotency-key': 'finalize-policy-revocation-1' },
      payload: { planId: revokePlanBody.planId, transactionHash: revocationTransactionHash },
    });
    expect(finalizedRevocation.statusCode).toBe(200);
    expect(finalizedRevocation.json()).toMatchObject({
      planId: revokePlanBody.planId, policyId: 'treasury-policy', policyState: 'REVOKED', grantState: 'REVOKED',
      previousPolicyEpoch: '1', policyEpoch: '2',
    });
    const revokedDb = await pool.query<{ policy_state: string; grant_state: string; plan_state: string; receipt_count: string }>(
      `SELECT p.state AS policy_state, g.state AS grant_state, rp.state AS plan_state,
              (SELECT count(*)::text FROM policy_revocation_receipts rr WHERE rr.plan_id = rp.id) AS receipt_count
       FROM policies p JOIN policy_grants g ON g.organization_id = p.organization_id AND g.policy_id = p.id
       JOIN policy_revocation_plans rp ON rp.organization_id = p.organization_id AND rp.policy_id = p.id
       WHERE p.organization_id = $1 AND p.id = 'treasury-policy' AND rp.id = $2`, [organizationId, revokePlanBody.planId],
    );
    expect(revokedDb.rows[0]).toEqual({ policy_state: 'REVOKED', grant_state: 'REVOKED', plan_state: 'CONFIRMED', receipt_count: '1' });
    const revocationFinalizationReplay = await app.inject({
      method: 'POST', url: `/api/v1/orgs/${organizationId}/policies/treasury-policy/revoke/finalize`,
      headers: { authorization: `Bearer ${ownerToken}`, 'idempotency-key': 'finalize-policy-revocation-1' },
      payload: { planId: revokePlanBody.planId, transactionHash: revocationTransactionHash },
    });
    expect(revocationFinalizationReplay.statusCode).toBe(200);
    expect(revocationFinalizationReplay.json()).toMatchObject({ planId: revokePlanBody.planId, replayed: true, policyState: 'REVOKED' });
    const differentReceiptReplay = await app.inject({
      method: 'POST', url: `/api/v1/orgs/${organizationId}/policies/treasury-policy/revoke/finalize`,
      headers: { authorization: `Bearer ${ownerToken}`, 'idempotency-key': 'finalize-policy-revocation-1' },
      payload: { planId: revokePlanBody.planId, transactionHash: `0x${'e'.repeat(64)}` },
    });
    expect(differentReceiptReplay.statusCode).toBe(409);
    const revokedSimulation = await app.inject({
      method: 'POST', url: `/api/v1/orgs/${organizationId}/policies/treasury-policy/simulate`,
      headers: { authorization: `Bearer ${ownerToken}` }, payload: actionBody,
    });
    expect(revokedSimulation.statusCode).toBe(200);
    expect(revokedSimulation.json()).toMatchObject({ verdict: 'BLOCK', reason: 'POLICY_REVOKED' });
    const revocationEvents = await pool.query<{ audit_count: string; outbox_count: string }>(
      `SELECT (SELECT count(*)::text FROM audit_events WHERE organization_id = $1 AND event_type = 'POLICY_REVOKED' AND subject_id = 'treasury-policy') AS audit_count,
              (SELECT count(*)::text FROM outbox_events WHERE organization_id = $1 AND event_type = 'POLICY_REVOKED' AND aggregate_id = 'treasury-policy') AS outbox_count`,
      [organizationId],
    );
    expect(revocationEvents.rows[0]).toEqual({ audit_count: '1', outbox_count: '1' });

  });

  it('creates an organization with an initial owner and replays creation idempotently', async () => {
    const createKey = `create-org-onboarding-${randomUUID()}`;
    const unauthenticated = await app.inject({ method: 'POST', url: '/api/v1/orgs', payload: { displayName: 'Unauthorized' } });
    expect(unauthenticated.statusCode).toBe(401);
    const missingKey = await app.inject({ method: 'POST', url: '/api/v1/orgs', headers: { authorization: `Bearer ${ownerToken}` }, payload: { displayName: 'Missing key' } });
    expect(missingKey.statusCode).toBe(400);
    const create = await app.inject({
      method: 'POST', url: '/api/v1/orgs',
      headers: { authorization: `Bearer ${ownerToken}`, 'idempotency-key': createKey },
      payload: { displayName: 'New Treasury Team' },
    });
    expect(create.statusCode).toBe(201);
    const created = create.json<{ organization: { organizationId: string; displayName: string; role: string } }>();
    expect(created.organization).toMatchObject({ displayName: 'New Treasury Team', role: 'OWNER' });
    const membership = await pool.query<{ role: string; display_name: string }>(
      `SELECT m.role, o.display_name FROM members m JOIN organizations o ON o.id = m.organization_id WHERE m.organization_id = $1 AND m.subject = 'owner-subject'`,
      [created.organization.organizationId],
    );
    expect(membership.rows).toEqual([{ role: 'OWNER', display_name: 'New Treasury Team' }]);

    const replay = await app.inject({
      method: 'POST', url: '/api/v1/orgs',
      headers: { authorization: `Bearer ${ownerToken}`, 'idempotency-key': createKey },
      payload: { displayName: 'New Treasury Team' },
    });
    expect(replay.statusCode).toBe(200);
    expect(replay.json()).toMatchObject({ organization: created.organization, replayed: true });

    const conflict = await app.inject({
      method: 'POST', url: '/api/v1/orgs',
      headers: { authorization: `Bearer ${ownerToken}`, 'idempotency-key': createKey },
      payload: { displayName: 'Different Team' },
    });
    expect(conflict.statusCode).toBe(409);
    const counts = await pool.query<{ organizations: string; members: string; audit: string }>(
      `SELECT (SELECT count(*)::text FROM organizations WHERE id = $1) AS organizations,
              (SELECT count(*)::text FROM members WHERE organization_id = $1) AS members,
              (SELECT count(*)::text FROM audit_events WHERE organization_id = $1 AND event_type = 'ORG_CREATED') AS audit`,
      [created.organization.organizationId],
    );
    expect(counts.rows[0]).toEqual({ organizations: '1', members: '1', audit: '1' });

    const registeredAgent = await app.inject({
      method: 'POST', url: `/api/v1/orgs/${organizationId}/agents`,
      headers: { authorization: `Bearer ${ownerToken}`, 'idempotency-key': `org-create-agent-denial-${randomUUID()}` },
      payload: { id: 'org-create-agent-denial', displayName: 'Org Create Agent' },
    });
    const agentToken = registeredAgent.json<{ credential: { token: string } }>().credential.token;
    const agentCreate = await app.inject({
      method: 'POST', url: '/api/v1/orgs',
      headers: { authorization: `Bearer ${agentToken}`, 'idempotency-key': 'org-create-agent-denial' },
      payload: { displayName: 'Agent Must Not Create' },
    });
    expect(agentCreate.statusCode).toBe(403);
  });

  it('serializes concurrent organization-creation retries into one organization and one replay', async () => {
    const createKey = `concurrent-org-create-${randomUUID()}`;
    const request = () => app.inject({
      method: 'POST', url: '/api/v1/orgs',
      headers: { authorization: `Bearer ${ownerToken}`, 'idempotency-key': createKey },
      payload: { displayName: 'Concurrent Treasury Group' },
    });
    const [left, right] = await Promise.all([request(), request()]);
    expect([left.statusCode, right.statusCode].sort()).toEqual([200, 201]);
    const responses = [left, right].map((response) => response.json<{ organization: { organizationId: string }; replayed?: true }>()).sort((a, b) => Number(Boolean(a.replayed)) - Number(Boolean(b.replayed)));
    expect(responses[0]?.organization.organizationId).toBe(responses[1]?.organization.organizationId);
    expect(responses[0]?.replayed).toBeUndefined();
    expect(responses[1]?.replayed).toBe(true);
    const rows = await pool.query<{ organization_count: string; owner_count: string }>(
      `SELECT (SELECT count(*)::text FROM organizations WHERE id = $1) AS organization_count,
              (SELECT count(*)::text FROM members WHERE organization_id = $1 AND role = 'OWNER') AS owner_count`,
      [responses[0]?.organization.organizationId],
    );
    expect(rows.rows[0]).toEqual({ organization_count: '1', owner_count: '1' });
  });

  it('invites a verified email identity and accepts the invitation once', async () => {
    const key = `invite-member-${randomUUID()}`;
    const invitationResponse = await app.inject({
      method: 'POST', url: `/api/v1/orgs/${organizationId}/invitations`,
      headers: { authorization: `Bearer ${ownerToken}`, 'idempotency-key': key },
      payload: { email: 'new.member@example.test', role: 'APPROVER' },
    });
    expect(invitationResponse.statusCode).toBe(201);
    const created = invitationResponse.json<{ invitation: { id: string; role: string; state: string }; invitationToken: string; shownOnce: true }>();
    expect(created.invitation).toMatchObject({ role: 'APPROVER', state: 'PENDING' });
    expect(created.invitationToken).toMatch(/^[A-Za-z0-9_-]{40,}$/);
    expect(created.shownOnce).toBe(true);
    const persisted = await pool.query<{ token_hash: string; response_text: string }>(
      'SELECT token_hash, response_json::text AS response_text FROM organization_invitations WHERE id = $1', [created.invitation.id],
    );
    expect(persisted.rows[0]?.token_hash).not.toBe(created.invitationToken);
    expect(persisted.rows[0]?.response_text).not.toContain(created.invitationToken);
    expect(persisted.rows[0]?.response_text).not.toContain('new.member@example.test');

    const replay = await app.inject({
      method: 'POST', url: `/api/v1/orgs/${organizationId}/invitations`,
      headers: { authorization: `Bearer ${ownerToken}`, 'idempotency-key': key },
      payload: { email: 'new.member@example.test', role: 'APPROVER' },
    });
    expect(replay.statusCode).toBe(200);
    expect(replay.json()).toMatchObject({ invitation: created.invitation, replayed: true });
    expect(replay.json()).not.toHaveProperty('invitationToken');

    const unverified = await new SignJWT({ email: 'new.member@example.test', email_verified: false })
      .setProtectedHeader({ alg: 'RS256', kid: 'integration-key' }).setIssuer(issuer).setAudience(audience)
      .setSubject('new-member-subject').setIssuedAt().setExpirationTime('5m').sign(signingKey);
    const unverifiedAttempt = await app.inject({
      method: 'POST', url: '/api/v1/invitations/accept',
      headers: { authorization: `Bearer ${unverified}` }, payload: { token: created.invitationToken },
    });
    expect(unverifiedAttempt.statusCode).toBe(403);

    await pool.query("INSERT INTO members (organization_id, subject, role) VALUES ($1, 'invitation-admin-subject', 'ADMIN')", [organizationId]);
    const adminToken = await new SignJWT({ email: 'admin@example.test', email_verified: true })
      .setProtectedHeader({ alg: 'RS256', kid: 'integration-key' }).setIssuer(issuer).setAudience(audience)
      .setSubject('invitation-admin-subject').setIssuedAt().setExpirationTime('5m').sign(signingKey);
    const ownerRoleInvite = await app.inject({
      method: 'POST', url: `/api/v1/orgs/${organizationId}/invitations`,
      headers: { authorization: `Bearer ${adminToken}`, 'idempotency-key': `admin-owner-invite-${randomUUID()}` },
      payload: { email: 'new.owner@example.test', role: 'OWNER' },
    });
    expect(ownerRoleInvite.statusCode).toBe(403);

    const mismatchedEmailToken = await new SignJWT({ email: 'other@example.test', email_verified: true })
      .setProtectedHeader({ alg: 'RS256', kid: 'integration-key' }).setIssuer(issuer).setAudience(audience)
      .setSubject('wrong-email-subject').setIssuedAt().setExpirationTime('5m').sign(signingKey);
    const mismatchedEmail = await app.inject({
      method: 'POST', url: '/api/v1/invitations/accept',
      headers: { authorization: `Bearer ${mismatchedEmailToken}` }, payload: { token: created.invitationToken },
    });
    expect(mismatchedEmail.statusCode).toBe(404);

    const inviteeToken = await new SignJWT({ email: 'new.member@example.test', email_verified: true })
      .setProtectedHeader({ alg: 'RS256', kid: 'integration-key' }).setIssuer(issuer).setAudience(audience)
      .setSubject('new-member-subject').setIssuedAt().setExpirationTime('5m').sign(signingKey);
    const accepted = await app.inject({
      method: 'POST', url: '/api/v1/invitations/accept',
      headers: { authorization: `Bearer ${inviteeToken}` }, payload: { token: created.invitationToken },
    });
    expect(accepted.statusCode).toBe(200);
    expect(accepted.json()).toMatchObject({ organizationId, role: 'APPROVER', accepted: true });
    const profile = await app.inject({ method: 'GET', url: '/api/v1/me', headers: { authorization: `Bearer ${inviteeToken}` } });
    expect(profile.json()).not.toHaveProperty('principal.verifiedEmail');
    const replayAccept = await app.inject({
      method: 'POST', url: '/api/v1/invitations/accept',
      headers: { authorization: `Bearer ${inviteeToken}` }, payload: { token: created.invitationToken },
    });
    expect(replayAccept.statusCode).toBe(200);
    expect(replayAccept.json()).toMatchObject({ organizationId, role: 'APPROVER', replayed: true });

    const expiredInvite = await app.inject({
      method: 'POST', url: `/api/v1/orgs/${organizationId}/invitations`,
      headers: { authorization: `Bearer ${ownerToken}`, 'idempotency-key': `expired-invite-${randomUUID()}` },
      payload: { email: 'expired.member@example.test', role: 'VIEWER' },
    });
    const expired = expiredInvite.json<{ invitation: { id: string }; invitationToken: string }>();
    await pool.query("UPDATE organization_invitations SET expires_at = now() - interval '1 minute' WHERE id = $1", [expired.invitation.id]);
    const expiredToken = await new SignJWT({ email: 'expired.member@example.test', email_verified: true })
      .setProtectedHeader({ alg: 'RS256', kid: 'integration-key' }).setIssuer(issuer).setAudience(audience)
      .setSubject('expired-member-subject').setIssuedAt().setExpirationTime('5m').sign(signingKey);
    const expiredAcceptance = await app.inject({
      method: 'POST', url: '/api/v1/invitations/accept',
      headers: { authorization: `Bearer ${expiredToken}` }, payload: { token: expired.invitationToken },
    });
    expect(expiredAcceptance.statusCode).toBe(409);
    const expirationEvents = await pool.query<{ state: string; audit_count: string; outbox_count: string }>(
      `SELECT state,
              (SELECT count(*)::text FROM audit_events WHERE organization_id = $1 AND event_type = 'ORG_INVITATION_EXPIRED' AND subject_id = $2) AS audit_count,
              (SELECT count(*)::text FROM outbox_events WHERE organization_id = $1 AND event_type = 'ORG_INVITATION_EXPIRED' AND aggregate_id = $2) AS outbox_count
       FROM organization_invitations WHERE id = $3`, [organizationId, expired.invitation.id, expired.invitation.id],
    );
    expect(expirationEvents.rows[0]).toEqual({ state: 'EXPIRED', audit_count: '1', outbox_count: '1' });
  });

  it('queues encrypted mail delivery when the invitation cipher is configured', async () => {
    const emailApp = await createApiServer({
      pool, jwksUrl, issuer, audience, logger: false,
      invitationTokenCipher: new AesGcmInvitationTokenCipher('22'.repeat(32)),
    });
    try {
      const response = await emailApp.inject({
        method: 'POST',
        url: `/api/v1/orgs/${organizationId}/invitations`,
        headers: { authorization: `Bearer ${ownerToken}`, 'idempotency-key': `mail-${randomUUID()}` },
        payload: { email: 'mail-recipient@example.com', role: 'VIEWER' },
      });
      expect(response.statusCode).toBe(201);
      const result = response.json<{ invitation: { id: string }; invitationToken: string; emailDeliveryQueued: true }>();
      expect(result.emailDeliveryQueued).toBe(true);
      const queued = await pool.query<{ token_ciphertext: string }>(
        'SELECT token_ciphertext FROM invitation_email_deliveries WHERE invitation_id = $1', [result.invitation.id],
      );
      expect(queued.rows[0]?.token_ciphertext).not.toContain(result.invitationToken);
    } finally {
      await emailApp.close();
    }
  });

  it('lists and revokes organization invitations idempotently', async () => {
    const invite = await app.inject({
      method: 'POST', url: `/api/v1/orgs/${organizationId}/invitations`,
      headers: { authorization: `Bearer ${ownerToken}`, 'idempotency-key': `revoke-invite-create-${randomUUID()}` },
      payload: { email: 'revoke.member@example.test', role: 'VIEWER' },
    });
    const created = invite.json<{ invitation: { id: string; state: string }; invitationToken: string }>();
    const list = await app.inject({ method: 'GET', url: `/api/v1/orgs/${organizationId}/invitations`, headers: { authorization: `Bearer ${ownerToken}` } });
    expect(list.statusCode).toBe(200);
    expect(list.json<{ invitations: readonly { id: string; state: string }[] }>().invitations).toContainEqual(expect.objectContaining({ id: created.invitation.id, state: 'PENDING' }));

    const revokeKey = `revoke-invite-${randomUUID()}`;
    const revoked = await app.inject({
      method: 'DELETE', url: `/api/v1/orgs/${organizationId}/invitations/${created.invitation.id}`,
      headers: { authorization: `Bearer ${ownerToken}`, 'idempotency-key': revokeKey },
    });
    expect(revoked.statusCode).toBe(204);
    const replay = await app.inject({
      method: 'DELETE', url: `/api/v1/orgs/${organizationId}/invitations/${created.invitation.id}`,
      headers: { authorization: `Bearer ${ownerToken}`, 'idempotency-key': revokeKey },
    });
    expect(replay.statusCode).toBe(204);
    const updated = await app.inject({ method: 'GET', url: `/api/v1/orgs/${organizationId}/invitations`, headers: { authorization: `Bearer ${ownerToken}` } });
    expect(updated.json<{ invitations: readonly { id: string; state: string }[] }>().invitations).toContainEqual(expect.objectContaining({ id: created.invitation.id, state: 'REVOKED' }));
    const token = await new SignJWT({ email: 'revoke.member@example.test', email_verified: true })
      .setProtectedHeader({ alg: 'RS256', kid: 'integration-key' }).setIssuer(issuer).setAudience(audience)
      .setSubject('revoked-member-subject').setIssuedAt().setExpirationTime('5m').sign(signingKey);
    const accept = await app.inject({ method: 'POST', url: '/api/v1/invitations/accept', headers: { authorization: `Bearer ${token}` }, payload: { token: created.invitationToken } });
    expect(accept.statusCode).toBe(409);
    const counts = await pool.query<{ audit_count: string; outbox_count: string }>(
      `SELECT (SELECT count(*)::text FROM audit_events WHERE organization_id = $1 AND event_type = 'ORG_INVITATION_REVOKED' AND subject_id = $2) AS audit_count,
              (SELECT count(*)::text FROM outbox_events WHERE organization_id = $1 AND event_type = 'ORG_INVITATION_REVOKED' AND aggregate_id = $2) AS outbox_count`,
      [organizationId, created.invitation.id],
    );
    expect(counts.rows[0]).toEqual({ audit_count: '1', outbox_count: '1' });
  });

  it('enforces an atomic shared PostgreSQL request window and returns Retry-After on exhaustion', async () => {
    const sourceIp = `2001:db8::${randomUUID().slice(0, 8)}`;
    const rateLimitHmacKey = 'integration-rate-limit-hmac-key-32-bytes';
    const subjectHash = createHmac('sha256', rateLimitHmacKey).update(`ip:${sourceIp}`, 'utf8').digest('hex');
    const originalNodeEnv = process.env.NODE_ENV;
    const originalHmacKey = process.env.MANDATE_RATE_LIMIT_HMAC_KEY;
    process.env.NODE_ENV = 'production';
    delete process.env.MANDATE_RATE_LIMIT_HMAC_KEY;
    try {
      await expect(createApiServer({ pool, jwksUrl, issuer, audience, logger: false }))
        .rejects.toThrow('MANDATE_RATE_LIMIT_HMAC_KEY is required in production');
    } finally {
      if (originalNodeEnv === undefined) delete process.env.NODE_ENV; else process.env.NODE_ENV = originalNodeEnv;
      if (originalHmacKey === undefined) delete process.env.MANDATE_RATE_LIMIT_HMAC_KEY; else process.env.MANDATE_RATE_LIMIT_HMAC_KEY = originalHmacKey;
    }
    await expect(createApiServer({ pool, jwksUrl, issuer, audience, logger: false, rateLimitHmacKey: 'short' }))
      .rejects.toThrow('MANDATE_RATE_LIMIT_HMAC_KEY must contain at least 32 UTF-8 bytes');
    const limitedApp = await createApiServer({ pool, jwksUrl, issuer, audience, logger: false, rateLimit: { maxRequests: 2, windowSeconds: 1 }, rateLimitHmacKey });
    try {
      const responses = await Promise.all(Array.from({ length: 5 }, () => limitedApp.inject({
        method: 'GET', url: '/api/v1/me', remoteAddress: sourceIp, headers: { 'x-forwarded-for': randomUUID() },
      })));
      expect(responses.map((response) => response.statusCode).sort((a, b) => a - b)).toEqual([401, 401, 429, 429, 429]);
      const limited = responses.find((response) => response.statusCode === 429);
      expect(limited?.headers['retry-after']).toMatch(/^[1-9][0-9]*$/);
      expect(limited?.headers['ratelimit-limit']).toBe('2');
      expect(limited?.json()).toMatchObject({ error: { code: 'RATE_LIMITED' } });
      await new Promise((resolve) => setTimeout(resolve, 1100));
      const nextWindow = await limitedApp.inject({ method: 'GET', url: '/api/v1/me', remoteAddress: sourceIp });
      expect(nextWindow.statusCode).toBe(401);
      const stored = await pool.query<{ request_count: number; subject_hash: string }>(
        'SELECT request_count, subject_hash FROM api_rate_limit_windows WHERE subject_hash = $1 ORDER BY window_start', [subjectHash],
      );
      expect(stored.rows).toHaveLength(2);
      expect(stored.rows[0]).toMatchObject({ request_count: 3, subject_hash: subjectHash });
      expect(stored.rows[1]).toMatchObject({ request_count: 1, subject_hash: subjectHash });
      expect(stored.rows[0]?.subject_hash).not.toContain(sourceIp);
    } finally {
      await pool.query('DELETE FROM api_rate_limit_windows WHERE subject_hash = $1', [subjectHash]);
      await limitedApp.close();
    }
  });
});
