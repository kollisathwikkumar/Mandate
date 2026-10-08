import { randomUUID } from 'node:crypto';
import { Pool } from 'pg';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { ModelCredentialStore } from '../src/postgres/model-credential-store.js';

describe.skipIf(!process.env.DATABASE_URL)('provider verification concurrency boundary', () => {
  const pool = new Pool({ connectionString: process.env.DATABASE_URL });
  const store = new ModelCredentialStore(pool);
  const organization = `verify-${randomUUID()}`;
  beforeAll(async () => {
    await pool.query('INSERT INTO organizations (id, display_name) VALUES ($1, $2)', [organization, 'verification race']);
    await pool.query("INSERT INTO members (organization_id, subject, role) VALUES ($1, 'owner', 'OWNER')", [organization]);
    await store.writeCredential({ organizationId: organization, principalId: 'owner', idempotencyKey: 'create', requestHash: `0x${'a'.repeat(64)}`, provider: 'OPENAI', secretReference: 'test/reference/one', maskedSuffix: 'test' });
  });
  afterAll(async () => { await pool.end(); });
  it('does not let an in-flight verification reactivate a disabled credential', async () => {
    await store.updateCredentialState(organization, 'owner', 'OPENAI', 'DISABLED');
    expect(await store.markVerified(organization, 'owner', 'OPENAI', 'test/reference/one', 'ACTIVE')).toBeNull();
    expect((await store.getCredential(organization, 'OPENAI'))?.state).toBe('DISABLED');
  });
  it('does not stamp a rotated secret with a result for its predecessor', async () => {
    await store.writeCredential({ organizationId: organization, principalId: 'owner', idempotencyKey: 'rotate', requestHash: `0x${'b'.repeat(64)}`, provider: 'OPENAI', secretReference: 'test/reference/two', maskedSuffix: 'two2' });
    expect(await store.markVerified(organization, 'owner', 'OPENAI', 'test/reference/one', 'ACTIVE')).toBeNull();
    expect((await store.getCredential(organization, 'OPENAI'))?.verifiedAt).toBeNull();
    expect(await store.markVerified(organization, 'owner', 'OPENAI', 'test/reference/two', 'ACTIVE')).toMatchObject({ state: 'ACTIVE' });
    expect(await store.markVerified(organization, 'owner', 'OPENAI', 'test/reference/two', 'ERROR')).toMatchObject({ state: 'ERROR' });
  });
  it('rechecks administrator membership at the write boundary', async () => {
    await pool.query("UPDATE members SET role = 'VIEWER' WHERE organization_id = $1", [organization]);
    await expect(store.markVerified(organization, 'owner', 'OPENAI', 'test/reference/two', 'ACTIVE')).rejects.toMatchObject({ statusCode: 403 });
    await expect(store.markVerified(organization, 'nonmember', 'OPENAI', 'test/reference/two', 'ACTIVE')).rejects.toMatchObject({ statusCode: 404 });
    expect((await store.getCredential(organization, 'OPENAI'))?.state).toBe('ERROR');
  });
});
