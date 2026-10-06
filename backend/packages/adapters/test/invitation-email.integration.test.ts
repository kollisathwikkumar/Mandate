import { createCipheriv, randomBytes, randomUUID } from 'node:crypto';
import { Pool, Client } from 'pg';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { OrganizationInvitationStore } from '../src/postgres/organization-invitation-store.js';
import { AesGcmInvitationTokenCipher } from '../src/crypto/aes-gcm-invitation-token-cipher.js';
import { InvitationEmailDeliveryWorker } from '../../../apps/worker/src/invitation-email-worker.js';
import type { InvitationEmailMessage, InvitationEmailTransport } from '../../ports/src/invitation-email.js';
import { migrate } from '../src/postgres/migrate.js';

const connectionString = process.env.DATABASE_URL;
const cipher = new AesGcmInvitationTokenCipher('11'.repeat(32));

class CaptureTransport implements InvitationEmailTransport {
  public readonly sent: InvitationEmailMessage[] = [];
  public failures = 0;
  public async send(message: InvitationEmailMessage): Promise<void> {
    if (this.failures > 0) {
      this.failures -= 1;
      throw new Error('provider detail must not escape');
    }
    this.sent.push(message);
  }
}

describe.skipIf(connectionString === undefined)('invitation email delivery/PostgreSQL integration', () => {
  let pool: Pool;
  beforeAll(async () => {
    if (connectionString === undefined) throw new Error('DATABASE_URL is required');
    pool = new Pool({ connectionString });
    const client = new Client({ connectionString });
    await client.connect();
    await migrate(client);
    await client.end();
    // Keep repeated runs on a reused integration database deterministic: only this
    // suite's pending queue records are cancelled, never unrelated organizations.
    await pool.query(`UPDATE invitation_email_deliveries
      SET status = 'CANCELLED', token_ciphertext = NULL, locked_at = NULL, updated_at = now()
      WHERE status = 'PENDING' AND invitation_id IN (
        SELECT id FROM organization_invitations WHERE organization_id LIKE 'invite-email-%'
      )`);
  });
  afterAll(async () => { await pool?.end(); });

  async function createInvitation() {
    const organizationId = `invite-email-${randomUUID()}`;
    const principalId = `owner-${randomUUID()}`;
    await pool.query('INSERT INTO organizations (id, display_name) VALUES ($1, $2)', [organizationId, 'Northstar Operations']);
    await pool.query("INSERT INTO members (organization_id, subject, role) VALUES ($1, $2, 'OWNER')", [organizationId, principalId]);
    const store = new OrganizationInvitationStore(pool, cipher);
    const result = await store.create({ organizationId, principalId, email: 'operator@example.com', role: 'ADMIN', idempotencyKey: randomUUID(), requestHash: `0x${'a'.repeat(64)}` });
    if (result.token === null) throw new Error('a new invitation must return its one-time token');
    // Sort this fixture ahead of unrelated pending jobs in a reused test database.
    await pool.query("UPDATE invitation_email_deliveries SET available_at = '1970-01-01T00:00:00Z' WHERE invitation_id = $1", [result.invitation.id]);
    return { store, result, organizationId, principalId };
  }

  it('queues only authenticated ciphertext and sends a one-time fragment link, then erases ciphertext', async () => {
    const { result } = await createInvitation();
    const queued = await pool.query<{ token_ciphertext: string; status: string }>(
      'SELECT token_ciphertext, status FROM invitation_email_deliveries WHERE invitation_id = $1', [result.invitation.id],
    );
    expect(queued.rows[0]?.status).toBe('PENDING');
    expect(queued.rows[0]?.token_ciphertext).not.toContain(result.token);
    expect(cipher.decrypt(queued.rows[0]?.token_ciphertext ?? '', result.invitation.organizationId, result.invitation.id)).toBe(result.token);
    const noPlaintext = await pool.query<{ invitation: string; outbox: string }>(
      `SELECT invitation.response_json::text AS invitation, event.payload::text AS outbox
       FROM organization_invitations invitation JOIN outbox_events event
         ON event.aggregate_id = invitation.id::text AND event.event_type = 'ORG_INVITATION_CREATED'
       WHERE invitation.id = $1`, [result.invitation.id],
    );
    expect(noPlaintext.rows[0]?.invitation).not.toContain(result.token);
    expect(noPlaintext.rows[0]?.outbox).not.toContain(result.token);

    const transport = new CaptureTransport();
    const worker = new InvitationEmailDeliveryWorker(pool, cipher, transport, {
      from: 'mandate@example.com', acceptUrl: 'https://console.example.com/invitations/accept',
    });
    await expect(worker.runBatch(1)).resolves.toEqual({ claimed: 1, sent: 1, retried: 0, failed: 0 });
    expect(transport.sent[0]).toMatchObject({ to: 'operator@example.com', from: 'mandate@example.com' });
    expect(transport.sent[0]?.text).toContain(`#token=${result.token}`);
    expect(transport.sent[0]?.text).toContain('ADMIN');
    const delivered = await pool.query<{ token_ciphertext: string | null; status: string; sent_at: Date | null }>(
      'SELECT token_ciphertext, status, sent_at FROM invitation_email_deliveries WHERE invitation_id = $1', [result.invitation.id],
    );
    expect(delivered.rows[0]).toMatchObject({ token_ciphertext: null, status: 'DELIVERED' });
    expect(delivered.rows[0]?.sent_at).toBeInstanceOf(Date);
  });

  it('retries provider errors with bounded state and erases queued ciphertext when an invite is revoked', async () => {
    const { result } = await createInvitation();
    const transport = new CaptureTransport();
    transport.failures = 1;
    const worker = new InvitationEmailDeliveryWorker(pool, cipher, transport, {
      from: 'mandate@example.com', acceptUrl: 'https://console.example.com/invitations/accept',
    });
    await expect(worker.runBatch(1)).resolves.toEqual({ claimed: 1, sent: 0, retried: 1, failed: 0 });
    await pool.query("UPDATE invitation_email_deliveries SET available_at = '1970-01-01T00:00:00Z' WHERE invitation_id = $1", [result.invitation.id]);
    await expect(worker.runBatch(1)).resolves.toEqual({ claimed: 1, sent: 1, retried: 0, failed: 0 });

    const pending = await createInvitation();
    await pending.store.revoke({ organizationId: pending.organizationId, principalId: pending.principalId, invitationId: pending.result.invitation.id, idempotencyKey: randomUUID(), requestHash: `0x${'b'.repeat(64)}` });
    const cancelled = await pool.query<{ token_ciphertext: string | null; status: string }>(
      'SELECT token_ciphertext, status FROM invitation_email_deliveries WHERE invitation_id = $1', [pending.result.invitation.id],
    );
    expect(cancelled.rows[0]).toEqual({ token_ciphertext: null, status: 'CANCELLED' });

    const acceptedInvite = await createInvitation();
    await acceptedInvite.store.accept({ token: acceptedInvite.result.token ?? '', principalId: `invitee-${randomUUID()}`, verifiedEmail: 'operator@example.com' });
    const acceptedDelivery = await pool.query<{ token_ciphertext: string | null; status: string }>(
      'SELECT token_ciphertext, status FROM invitation_email_deliveries WHERE invitation_id = $1', [acceptedInvite.result.invitation.id],
    );
    expect(acceptedDelivery.rows[0]).toEqual({ token_ciphertext: null, status: 'CANCELLED' });

    const exhausted = await createInvitation();
    await pool.query('UPDATE invitation_email_deliveries SET attempts = 11 WHERE invitation_id = $1', [exhausted.result.invitation.id]);
    const terminalTransport = new CaptureTransport();
    terminalTransport.failures = 1;
    const terminalWorker = new InvitationEmailDeliveryWorker(pool, cipher, terminalTransport, {
      from: 'mandate@example.com', acceptUrl: 'https://console.example.com/invitations/accept',
    });
    await expect(terminalWorker.runBatch(1)).resolves.toEqual({ claimed: 1, sent: 0, retried: 0, failed: 1 });
    const terminalDelivery = await pool.query<{ token_ciphertext: string | null; status: string; attempts: number }>(
      'SELECT token_ciphertext, status, attempts FROM invitation_email_deliveries WHERE invitation_id = $1', [exhausted.result.invitation.id],
    );
    expect(terminalDelivery.rows[0]).toEqual({ token_ciphertext: null, status: 'FAILED', attempts: 12 });
  });

  it('binds AES-GCM ciphertext to both organization and invitation identifiers', () => {
    const token = 'a'.repeat(43);
    const encrypted = cipher.encrypt(token, 'org-one', 'inv-one');
    expect(encrypted).not.toContain(token);
    expect(cipher.decrypt(encrypted, 'org-one', 'inv-one')).toBe(token);
    expect(() => cipher.decrypt(encrypted, 'org-two', 'inv-one')).toThrow();
    expect(() => cipher.decrypt('malformed', 'org-one', 'inv-one')).toThrow();
    const iv = randomBytes(12);
    const forgedPayload = createCipheriv('aes-256-gcm', Buffer.from('11'.repeat(32), 'hex'), iv);
    forgedPayload.setAAD(Buffer.from(JSON.stringify(['org-one', 'inv-one']), 'utf8'));
    const invalidPlaintext = Buffer.concat([forgedPayload.update('not-a-valid-token', 'utf8'), forgedPayload.final()]);
    const forgedCiphertext = `v1.${iv.toString('base64url')}.${forgedPayload.getAuthTag().toString('base64url')}.${invalidPlaintext.toString('base64url')}`;
    expect(() => cipher.decrypt(forgedCiphertext, 'org-one', 'inv-one')).toThrow('token is invalid');
    expect(() => cipher.encrypt('not-a-token', 'org-one', 'inv-one')).toThrow('token format');
    expect(() => cipher.encrypt(token, '', 'inv-one')).toThrow('context');
    expect(() => new AesGcmInvitationTokenCipher('not-hex')).toThrow('32 bytes');
  });
});
