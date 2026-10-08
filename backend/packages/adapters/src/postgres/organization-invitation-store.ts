import { createHash, randomBytes } from 'node:crypto';
import type { Pool, PoolClient } from 'pg';
import type { OrganizationRole } from '../../../domain/src/principal.js';
import { RepositoryAccessError } from '../../../ports/src/repository-errors.js';
import type { InvitationTokenCipher } from '../../../ports/src/invitation-email.js';

export type InvitationState = 'PENDING' | 'ACCEPTED' | 'REVOKED' | 'EXPIRED';
export interface OrganizationInvitationSummary {
  readonly id: string;
  readonly organizationId: string;
  readonly role: OrganizationRole;
  readonly state: InvitationState;
  readonly expiresAt: string;
  readonly createdAt: string;
}
interface InvitationRow {
  readonly id: string; readonly organization_id: string; readonly email: string; readonly role: OrganizationRole;
  readonly state: InvitationState; readonly expires_at: Date; readonly created_at: Date;
  readonly accepted_by: string | null; readonly response_json?: OrganizationInvitationSummary;
}
interface ReplayRow { readonly request_hash: string; readonly response_json: OrganizationInvitationSummary; }
export class OrganizationInvitationConflictError extends Error {
  public constructor(public readonly code: 'IDEMPOTENCY_CONFLICT' | 'OWNER_ROLE_REQUIRED' | 'INVITATION_EXPIRED' | 'INVITATION_CLOSED' | 'ALREADY_MEMBER') {
    super(code); this.name = 'OrganizationInvitationConflictError';
  }
}
const digest = (value: string): string => `0x${createHash('sha256').update(value, 'utf8').digest('hex')}`;
const summary = (row: InvitationRow): OrganizationInvitationSummary => ({
  id: row.id, organizationId: row.organization_id, role: row.role, state: row.state,
  expiresAt: row.expires_at.toISOString(), createdAt: row.created_at.toISOString(),
});

async function appendEvent(client: PoolClient, input: { orgId: string; actor: string; id: string; event: 'ORG_INVITATION_CREATED' | 'ORG_INVITATION_ACCEPTED' | 'ORG_INVITATION_EXPIRED' | 'ORG_INVITATION_REVOKED' }): Promise<void> {
  const payload = JSON.stringify({ invitationId: input.id });
  const previous = await client.query<{ event_hash: string }>('SELECT event_hash FROM audit_events WHERE organization_id = $1 ORDER BY sequence DESC LIMIT 1', [input.orgId]);
  const previousHash = previous.rows[0]?.event_hash.trim() ?? null;
  const eventHash = digest(`${previousHash ?? ''}|${input.orgId}|${input.actor}|${input.event}|${payload}`);
  await client.query(`INSERT INTO audit_events (organization_id, actor_type, actor_id, event_type, subject_type, subject_id, correlation_id, payload, previous_hash, event_hash)
    VALUES ($1, 'HUMAN', $2, $3, 'ORG_INVITATION', $4, $4, $5::jsonb, $6, $7)`, [input.orgId, input.actor, input.event, input.id, payload, previousHash, eventHash]);
  await client.query('INSERT INTO outbox_events (organization_id, aggregate_type, aggregate_id, event_type, payload) VALUES ($1, \'ORG_INVITATION\', $2, $3, $4::jsonb)', [input.orgId, input.id, input.event, payload]);
}

async function lockIdempotency(client: PoolClient, organizationId: string, principalId: string, key: string, scope: string): Promise<ReplayRow | null> {
  await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1, 0))', [`${organizationId}|${principalId}|${scope}|${key}`]);
  await client.query('DELETE FROM command_idempotency WHERE organization_id = $1 AND principal_id = $2 AND scope = $3 AND idempotency_key = $4 AND expires_at <= now()', [organizationId, principalId, scope, key]);
  const result = await client.query<ReplayRow>('SELECT request_hash, response_json FROM command_idempotency WHERE organization_id = $1 AND principal_id = $2 AND scope = $3 AND idempotency_key = $4 AND expires_at > now()', [organizationId, principalId, scope, key]);
  return result.rows[0] ?? null;
}

async function saveIdempotency(client: PoolClient, input: { organizationId: string; principalId: string; key: string; scope: string; requestHash: string; response: unknown }): Promise<void> {
  await client.query('INSERT INTO command_idempotency (organization_id, principal_id, scope, idempotency_key, request_hash, response_json) VALUES ($1, $2, $3, $4, $5, $6::jsonb)', [input.organizationId, input.principalId, input.scope, input.key, input.requestHash, JSON.stringify(input.response)]);
}

export class OrganizationInvitationStore {
  public constructor(private readonly pool: Pool, private readonly tokenCipher?: InvitationTokenCipher) {}

  public async list(input: { organizationId: string; principalId: string }): Promise<readonly OrganizationInvitationSummary[]> {
    const organization = await this.pool.query('SELECT id FROM organizations WHERE id = $1', [input.organizationId]);
    if (organization.rowCount === 0) throw new RepositoryAccessError(404);
    const member = await this.pool.query<{ role: OrganizationRole }>('SELECT role FROM members WHERE organization_id = $1 AND subject = $2', [input.organizationId, input.principalId]);
    const role = member.rows[0]?.role;
    if (role === undefined) throw new RepositoryAccessError(404);
    if (role !== 'OWNER' && role !== 'ADMIN') throw new RepositoryAccessError(403);
    const result = await this.pool.query<InvitationRow>(`SELECT id::text, organization_id, email, role, state, expires_at, created_at, accepted_by
      FROM organization_invitations WHERE organization_id = $1 ORDER BY created_at DESC, id DESC LIMIT 100`, [input.organizationId]);
    return result.rows.map(summary);
  }

  public async revoke(input: { organizationId: string; principalId: string; invitationId: string; idempotencyKey: string; requestHash: string }): Promise<'REVOKED' | 'REPLAY'> {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      const organization = await client.query('SELECT id FROM organizations WHERE id = $1 FOR UPDATE', [input.organizationId]);
      if (organization.rowCount === 0) throw new RepositoryAccessError(404);
      const member = await client.query<{ role: OrganizationRole }>('SELECT role FROM members WHERE organization_id = $1 AND subject = $2 FOR UPDATE', [input.organizationId, input.principalId]);
      const role = member.rows[0]?.role;
      if (role === undefined) throw new RepositoryAccessError(404);
      if (role !== 'OWNER' && role !== 'ADMIN') throw new RepositoryAccessError(403);
      const scope = `org.invitation.revoke.${input.invitationId}`;
      const prior = await lockIdempotency(client, input.organizationId, input.principalId, input.idempotencyKey, scope);
      if (prior !== null) {
        if (prior.request_hash.trim() !== input.requestHash) throw new OrganizationInvitationConflictError('IDEMPOTENCY_CONFLICT');
        await client.query('COMMIT'); return 'REPLAY';
      }
      const selected = await client.query<InvitationRow>(`SELECT id::text, organization_id, email, role, state, expires_at, created_at, accepted_by
        FROM organization_invitations WHERE organization_id = $1 AND id = $2 FOR UPDATE`, [input.organizationId, input.invitationId]);
      const invitation = selected.rows[0];
      if (invitation === undefined) throw new RepositoryAccessError(404);
      if (invitation.state !== 'PENDING') throw new OrganizationInvitationConflictError('INVITATION_CLOSED');
      await client.query("UPDATE organization_invitations SET state = 'REVOKED' WHERE organization_id = $1 AND id = $2", [input.organizationId, input.invitationId]);
      await client.query(`UPDATE invitation_email_deliveries SET status = 'CANCELLED', token_ciphertext = NULL, locked_at = NULL, updated_at = now()
        WHERE invitation_id = $1 AND status = 'PENDING'`, [input.invitationId]);
      await saveIdempotency(client, { organizationId: input.organizationId, principalId: input.principalId, key: input.idempotencyKey, scope, requestHash: input.requestHash, response: { revoked: true } });
      await appendEvent(client, { orgId: input.organizationId, actor: input.principalId, id: input.invitationId, event: 'ORG_INVITATION_REVOKED' });
      await client.query('COMMIT'); return 'REVOKED';
    } catch (error: unknown) { await client.query('ROLLBACK'); throw error; }
    finally { client.release(); }
  }

  public async create(input: { organizationId: string; principalId: string; email: string; role: OrganizationRole; idempotencyKey: string; requestHash: string }): Promise<{ readonly kind: 'CREATED' | 'REPLAY'; readonly invitation: OrganizationInvitationSummary; readonly token: string | null }> {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      const organization = await client.query('SELECT id FROM organizations WHERE id = $1 FOR UPDATE', [input.organizationId]);
      if (organization.rowCount === 0) throw new RepositoryAccessError(404);
      const actor = await client.query<{ role: OrganizationRole }>('SELECT role FROM members WHERE organization_id = $1 AND subject = $2 FOR UPDATE', [input.organizationId, input.principalId]);
      const actorRole = actor.rows[0]?.role;
      if (actorRole === undefined) throw new RepositoryAccessError(404);
      if (actorRole !== 'OWNER' && actorRole !== 'ADMIN') throw new RepositoryAccessError(403);
      if (input.role === 'OWNER' && actorRole !== 'OWNER') throw new OrganizationInvitationConflictError('OWNER_ROLE_REQUIRED');
      await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1, 0))', [`${input.organizationId}|${input.principalId}|org.invite|${input.idempotencyKey}`]);
      const existing = await client.query<ReplayRow>(`SELECT request_hash, response_json FROM organization_invitations
        WHERE organization_id = $1 AND created_by = $2 AND idempotency_key = $3`, [input.organizationId, input.principalId, input.idempotencyKey]);
      const prior = existing.rows[0];
      if (prior !== undefined) {
        if (prior.request_hash.trim() !== input.requestHash) throw new OrganizationInvitationConflictError('IDEMPOTENCY_CONFLICT');
        await client.query('COMMIT');
        return { kind: 'REPLAY', invitation: prior.response_json, token: null };
      }
      const token = randomBytes(32).toString('base64url');
      const tokenHash = digest(token);
      const inserted = await client.query<InvitationRow>(`INSERT INTO organization_invitations
        (organization_id, email, role, token_hash, created_by, idempotency_key, request_hash, response_json)
        VALUES ($1, $2, $3, $4, $5, $6, $7, '{}'::jsonb) RETURNING id, organization_id, email, role, state, expires_at, created_at, accepted_by`,
      [input.organizationId, input.email, input.role, tokenHash, input.principalId, input.idempotencyKey, input.requestHash]);
      const row = inserted.rows[0];
      if (row === undefined) throw new Error('Invitation creation returned no row');
      const invitation = summary(row);
      await client.query('UPDATE organization_invitations SET response_json = $2::jsonb WHERE id = $1', [row.id, JSON.stringify(invitation)]);
      if (this.tokenCipher !== undefined) {
        const tokenCiphertext = this.tokenCipher.encrypt(token, input.organizationId, row.id);
        await client.query('INSERT INTO invitation_email_deliveries (invitation_id, token_ciphertext) VALUES ($1, $2)', [row.id, tokenCiphertext]);
      }
      await appendEvent(client, { orgId: input.organizationId, actor: input.principalId, id: row.id, event: 'ORG_INVITATION_CREATED' });
      await client.query('COMMIT');
      return { kind: 'CREATED', invitation, token };
    } catch (error: unknown) {
      await client.query('ROLLBACK'); throw error;
    } finally { client.release(); }
  }

  public async accept(input: { token: string; principalId: string; verifiedEmail: string }): Promise<{ readonly kind: 'ACCEPTED' | 'REPLAY'; readonly organizationId: string; readonly role: OrganizationRole }> {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      const tokenHash = digest(input.token);
      const invitationResult = await client.query<InvitationRow>(`SELECT id, organization_id, email, role, state, expires_at, created_at, accepted_by
        FROM organization_invitations WHERE token_hash = $1 FOR UPDATE`, [tokenHash]);
      const invitation = invitationResult.rows[0];
      if (invitation === undefined || invitation.email !== input.verifiedEmail) throw new RepositoryAccessError(404);
      if (invitation.state === 'ACCEPTED' && invitation.accepted_by === input.principalId) {
        await client.query('COMMIT'); return { kind: 'REPLAY', organizationId: invitation.organization_id, role: invitation.role };
      }
      if (invitation.state !== 'PENDING') throw new OrganizationInvitationConflictError('INVITATION_CLOSED');
      if (invitation.expires_at.getTime() <= Date.now()) {
        await client.query("UPDATE organization_invitations SET state = 'EXPIRED' WHERE id = $1", [invitation.id]);
        await client.query(`UPDATE invitation_email_deliveries SET status = 'CANCELLED', token_ciphertext = NULL, locked_at = NULL, updated_at = now()
          WHERE invitation_id = $1 AND status = 'PENDING'`, [invitation.id]);
        await appendEvent(client, { orgId: invitation.organization_id, actor: input.principalId, id: invitation.id, event: 'ORG_INVITATION_EXPIRED' });
        await client.query('COMMIT');
        throw new OrganizationInvitationConflictError('INVITATION_EXPIRED');
      }
      const priorMember = await client.query('SELECT 1 FROM members WHERE organization_id = $1 AND subject = $2 FOR UPDATE', [invitation.organization_id, input.principalId]);
      if (priorMember.rowCount !== 0) throw new OrganizationInvitationConflictError('ALREADY_MEMBER');
      await client.query('INSERT INTO members (organization_id, subject, role) VALUES ($1, $2, $3)', [invitation.organization_id, input.principalId, invitation.role]);
      await client.query("UPDATE organization_invitations SET state = 'ACCEPTED', accepted_by = $2, accepted_at = now() WHERE id = $1", [invitation.id, input.principalId]);
      await client.query(`UPDATE invitation_email_deliveries SET status = 'CANCELLED', token_ciphertext = NULL, locked_at = NULL, updated_at = now()
        WHERE invitation_id = $1 AND status = 'PENDING'`, [invitation.id]);
      await appendEvent(client, { orgId: invitation.organization_id, actor: input.principalId, id: invitation.id, event: 'ORG_INVITATION_ACCEPTED' });
      await client.query('COMMIT');
      return { kind: 'ACCEPTED', organizationId: invitation.organization_id, role: invitation.role };
    } catch (error: unknown) {
      if (error instanceof OrganizationInvitationConflictError && error.code === 'INVITATION_EXPIRED') throw error;
      await client.query('ROLLBACK'); throw error;
    } finally { client.release(); }
  }
}
