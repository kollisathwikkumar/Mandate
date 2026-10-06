import { createHash } from 'node:crypto';
import type { Pool, PoolClient } from 'pg';
import { RepositoryAccessError } from '../../../ports/src/repository-errors.js';
import type { OrganizationRole } from '../../../domain/src/principal.js';
import type { OrganizationMemberSummary, OrganizationMembershipRepository } from '../../../ports/src/organization-membership.js';

interface MemberRow { readonly subject: string; readonly role: OrganizationRole; readonly created_at: Date; }
interface IdempotencyRow { readonly request_hash: string; readonly response_json: OrganizationMemberSummary; }

export class OrganizationMembershipConflictError extends Error {
  public constructor(public readonly code: 'IDEMPOTENCY_CONFLICT' | 'LAST_OWNER' | 'OWNER_ROLE_REQUIRED' | 'MEMBER_NOT_FOUND') {
    super(code); this.name = 'OrganizationMembershipConflictError';
  }
}

const digest = (value: string): string => `0x${createHash('sha256').update(value, 'utf8').digest('hex')}`;
const summary = (row: MemberRow): OrganizationMemberSummary => ({ subject: row.subject, role: row.role, createdAt: row.created_at.toISOString() });

async function requireOrgAndAdmin(client: PoolClient, orgId: string, principalId: string): Promise<OrganizationRole> {
  const org = await client.query('SELECT id FROM organizations WHERE id = $1 FOR UPDATE', [orgId]);
  if (org.rowCount === 0) throw new RepositoryAccessError(404);
  const member = await client.query<{ role: OrganizationRole }>('SELECT role FROM members WHERE organization_id = $1 AND subject = $2 FOR UPDATE', [orgId, principalId]);
  const role = member.rows[0]?.role;
  if (role === undefined) throw new RepositoryAccessError(404);
  if (role !== 'OWNER' && role !== 'ADMIN') throw new RepositoryAccessError(403);
  return role;
}

async function lockIdempotency(client: PoolClient, orgId: string, actor: string, key: string, scope: string): Promise<IdempotencyRow | null> {
  await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1, 0))', [`${orgId}|${actor}|${scope}|${key}`]);
  await client.query('DELETE FROM command_idempotency WHERE organization_id = $1 AND principal_id = $2 AND scope = $3 AND idempotency_key = $4 AND expires_at <= now()', [orgId, actor, scope, key]);
  const result = await client.query<IdempotencyRow>('SELECT request_hash, response_json FROM command_idempotency WHERE organization_id = $1 AND principal_id = $2 AND scope = $3 AND idempotency_key = $4 AND expires_at > now()', [orgId, actor, scope, key]);
  return result.rows[0] ?? null;
}

async function saveIdempotency(client: PoolClient, input: { orgId: string; actor: string; key: string; scope: string; requestHash: string; response: unknown }): Promise<void> {
  await client.query('INSERT INTO command_idempotency (organization_id, principal_id, scope, idempotency_key, request_hash, response_json) VALUES ($1, $2, $3, $4, $5, $6::jsonb)', [input.orgId, input.actor, input.scope, input.key, input.requestHash, JSON.stringify(input.response)]);
}

async function appendMutation(client: PoolClient, input: { orgId: string; actor: string; subject: string; key: string; event: 'ORG_MEMBER_ADDED' | 'ORG_MEMBER_ROLE_CHANGED' | 'ORG_MEMBER_REMOVED'; role?: OrganizationRole }): Promise<void> {
  const payload = JSON.stringify({ subject: input.subject, ...(input.role === undefined ? {} : { role: input.role }) });
  const previous = await client.query<{ event_hash: string }>('SELECT event_hash FROM audit_events WHERE organization_id = $1 ORDER BY sequence DESC LIMIT 1', [input.orgId]);
  const previousHash = previous.rows[0]?.event_hash.trim() ?? null;
  const eventHash = digest(`${previousHash ?? ''}|${input.orgId}|${input.actor}|${input.event}|${payload}`);
  await client.query(`INSERT INTO audit_events (organization_id, actor_type, actor_id, event_type, subject_type, subject_id, correlation_id, payload, previous_hash, event_hash)
    VALUES ($1, 'HUMAN', $2, $3, 'ORG_MEMBER', $4, $5, $6::jsonb, $7, $8)`, [input.orgId, input.actor, input.event, input.subject, input.key, payload, previousHash, eventHash]);
  await client.query(`INSERT INTO outbox_events (organization_id, aggregate_type, aggregate_id, event_type, payload) VALUES ($1, 'ORG_MEMBER', $2, $3, $4::jsonb)`, [input.orgId, input.subject, input.event, payload]);
}

export class OrganizationMembershipStore implements OrganizationMembershipRepository {
  public constructor(private readonly pool: Pool) {}

  public async getHumanRole(organizationId: string, subject: string): Promise<OrganizationRole | null> {
    const result = await this.pool.query<{ role: OrganizationRole }>('SELECT role FROM members WHERE organization_id = $1 AND subject = $2', [organizationId, subject]);
    return result.rows[0]?.role ?? null;
  }

  public async listMembers(organizationId: string, principalId: string): Promise<readonly OrganizationMemberSummary[]> {
    const result = await this.pool.query<MemberRow>(`SELECT subject, role, created_at FROM members member WHERE organization_id = $1 AND EXISTS (SELECT 1 FROM members requester WHERE requester.organization_id = member.organization_id AND requester.subject = $2) ORDER BY created_at, subject`, [organizationId, principalId]);
    if (result.rowCount === 0) throw new RepositoryAccessError(404);
    return result.rows.map(summary);
  }

  public async setMemberRole(input: { organizationId: string; principalId: string; subject: string; role: OrganizationRole; idempotencyKey: string; requestHash: string }): Promise<{ kind: 'CREATED' | 'UPDATED' | 'REPLAY'; member: OrganizationMemberSummary }> {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      const actorRole = await requireOrgAndAdmin(client, input.organizationId, input.principalId);
      if (input.role === 'OWNER' && actorRole !== 'OWNER') throw new OrganizationMembershipConflictError('OWNER_ROLE_REQUIRED');
      const scope = `org.member.role.${input.subject}`;
      const prior = await lockIdempotency(client, input.organizationId, input.principalId, input.idempotencyKey, scope);
      if (prior !== null) {
        if (prior.request_hash.trim() !== input.requestHash) throw new OrganizationMembershipConflictError('IDEMPOTENCY_CONFLICT');
        const replay = await client.query<MemberRow>('SELECT subject, role, created_at FROM members WHERE organization_id = $1 AND subject = $2', [input.organizationId, input.subject]);
        const row = replay.rows[0];
        if (row === undefined) throw new OrganizationMembershipConflictError('MEMBER_NOT_FOUND');
        await client.query('COMMIT');
        return { kind: 'REPLAY', member: summary(row) };
      }
      const current = await client.query<MemberRow>('SELECT subject, role, created_at FROM members WHERE organization_id = $1 AND subject = $2 FOR UPDATE', [input.organizationId, input.subject]);
      const old = current.rows[0];
      if (old?.role === 'OWNER' && input.role !== 'OWNER') {
        if (actorRole !== 'OWNER') throw new OrganizationMembershipConflictError('OWNER_ROLE_REQUIRED');
        const owners = await client.query<{ count: string }>("SELECT count(*)::text AS count FROM members WHERE organization_id = $1 AND role = 'OWNER'", [input.organizationId]);
        if (Number(owners.rows[0]?.count ?? '0') <= 1) throw new OrganizationMembershipConflictError('LAST_OWNER');
      }
      const result = await client.query<MemberRow>(`INSERT INTO members (organization_id, subject, role) VALUES ($1, $2, $3)
        ON CONFLICT (organization_id, subject) DO UPDATE SET role = EXCLUDED.role RETURNING subject, role, created_at`, [input.organizationId, input.subject, input.role]);
      const row = result.rows[0];
      if (row === undefined) throw new Error('Membership write returned no row');
      const member = summary(row);
      await saveIdempotency(client, { orgId: input.organizationId, actor: input.principalId, key: input.idempotencyKey, scope, requestHash: input.requestHash, response: member });
      if (old === undefined || old.role !== input.role) await appendMutation(client, { orgId: input.organizationId, actor: input.principalId, subject: input.subject, key: input.idempotencyKey, event: old === undefined ? 'ORG_MEMBER_ADDED' : 'ORG_MEMBER_ROLE_CHANGED', role: input.role });
      await client.query('COMMIT');
      return { kind: old === undefined ? 'CREATED' : 'UPDATED', member };
    } catch (error: unknown) { await client.query('ROLLBACK'); throw error; }
    finally { client.release(); }
  }

  public async removeMember(input: { organizationId: string; principalId: string; subject: string; idempotencyKey: string; requestHash: string }): Promise<'REMOVED' | 'REPLAY'> {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      const actorRole = await requireOrgAndAdmin(client, input.organizationId, input.principalId);
      const scope = `org.member.remove.${input.subject}`;
      const prior = await lockIdempotency(client, input.organizationId, input.principalId, input.idempotencyKey, scope);
      if (prior !== null) {
        if (prior.request_hash.trim() !== input.requestHash) throw new OrganizationMembershipConflictError('IDEMPOTENCY_CONFLICT');
        await client.query('COMMIT'); return 'REPLAY';
      }
      const current = await client.query<MemberRow>('SELECT subject, role, created_at FROM members WHERE organization_id = $1 AND subject = $2 FOR UPDATE', [input.organizationId, input.subject]);
      const member = current.rows[0];
      if (member === undefined) throw new RepositoryAccessError(404);
      if (member.role === 'OWNER' && actorRole !== 'OWNER') throw new OrganizationMembershipConflictError('OWNER_ROLE_REQUIRED');
      if (member.role === 'OWNER') {
        const owners = await client.query<{ count: string }>("SELECT count(*)::text AS count FROM members WHERE organization_id = $1 AND role = 'OWNER'", [input.organizationId]);
        if (Number(owners.rows[0]?.count ?? '0') <= 1) throw new OrganizationMembershipConflictError('LAST_OWNER');
      }
      await client.query('DELETE FROM members WHERE organization_id = $1 AND subject = $2', [input.organizationId, input.subject]);
      await saveIdempotency(client, { orgId: input.organizationId, actor: input.principalId, key: input.idempotencyKey, scope, requestHash: input.requestHash, response: { removed: true } });
      await appendMutation(client, { orgId: input.organizationId, actor: input.principalId, subject: input.subject, key: input.idempotencyKey, event: 'ORG_MEMBER_REMOVED' });
      await client.query('COMMIT'); return 'REMOVED';
    } catch (error: unknown) { await client.query('ROLLBACK'); throw error; }
    finally { client.release(); }
  }
}
