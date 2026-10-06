import { createHash, randomBytes } from 'node:crypto';
import type { Pool, PoolClient } from 'pg';
import { z } from 'zod';
import type { AgentCredentialIdentity, AgentListItem, AgentRegistrationInput, AgentRegistrationResult, AgentRepository, AgentSummary } from '../../../ports/src/agent-repository.js';
import { RepositoryAccessError } from '../../../ports/src/repository-errors.js';

const AgentSummarySchema = z.object({
  id: z.string(),
  displayName: z.string(),
  status: z.literal('ACTIVE'),
  keyVersion: z.number().int().positive(),
  createdAt: z.string(),
}).strict();
const OrganizationRoleSchema = z.enum(['OWNER', 'ADMIN', 'APPROVER', 'VIEWER']);

interface ExistingIdempotencyRow {
  readonly request_hash: string;
  readonly response_json: unknown;
}

interface AgentRow {
  readonly id: string;
  readonly display_name: string;
  readonly status: 'ACTIVE' | 'REVOKED';
  readonly key_version: number;
  readonly created_at: Date;
}

function sha256(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('hex');
}

function uniqueViolation(error: unknown): boolean {
  return typeof error === 'object' && error !== null && 'code' in error && error.code === '23505';
}

async function getAgentByIdempotency(client: PoolClient, input: AgentRegistrationInput): Promise<AgentRegistrationResult | null> {
  const previous = await client.query<ExistingIdempotencyRow>(
    `SELECT request_hash, response_json FROM command_idempotency
     WHERE organization_id = $1 AND principal_id = $2 AND scope = 'agent.register' AND idempotency_key = $3 AND expires_at > now()`,
    [input.organizationId, input.principalId, input.idempotencyKey],
  );
  const row = previous.rows[0];
  if (row === undefined) return null;

  const requestHash = `0x${sha256(JSON.stringify(input.request))}`;
  if (row.request_hash.trim() !== requestHash) {
    throw new AgentConflictError('Idempotency key was already used for a different request', 'IDEMPOTENCY_CONFLICT');
  }
  return { kind: 'REPLAY', agent: AgentSummarySchema.parse(row.response_json) };
}

async function writeAuditAndOutbox(client: PoolClient, input: AgentRegistrationInput, agent: AgentSummary): Promise<void> {
  await client.query('SELECT id FROM organizations WHERE id = $1 FOR UPDATE', [input.organizationId]);
  const lastEvent = await client.query<{ event_hash: string }>(
    'SELECT event_hash FROM audit_events WHERE organization_id = $1 ORDER BY sequence DESC LIMIT 1',
    [input.organizationId],
  );
  const previousHash = lastEvent.rows[0]?.event_hash.trim() ?? null;
  const payload = { agentId: agent.id, keyVersion: agent.keyVersion };
  const eventHash = `0x${sha256(`${previousHash ?? ''}|${input.organizationId}|${input.principalId}|AGENT_CREATED|${JSON.stringify(payload)}`)}`;
  await client.query(
    `INSERT INTO audit_events (organization_id, actor_type, actor_id, event_type, subject_type, subject_id, correlation_id, payload, previous_hash, event_hash)
     VALUES ($1, 'HUMAN', $2, 'AGENT_CREATED', 'AGENT', $3, $4, $5::jsonb, $6, $7)`,
    [input.organizationId, input.principalId, agent.id, input.idempotencyKey, JSON.stringify(payload), previousHash, eventHash],
  );
  await client.query(
    `INSERT INTO outbox_events (organization_id, aggregate_type, aggregate_id, event_type, payload)
     VALUES ($1, 'AGENT', $2, 'AGENT_CREATED', $3::jsonb)`,
    [input.organizationId, agent.id, JSON.stringify(payload)],
  );
}

async function registerInTransaction(client: PoolClient, input: AgentRegistrationInput): Promise<AgentRegistrationResult> {
  const membership = await client.query<{ role: string }>(
    'SELECT role FROM members WHERE organization_id = $1 AND subject = $2 FOR UPDATE',
    [input.organizationId, input.principalId],
  );
  const role = membership.rows[0]?.role;
  if (role === undefined) throw new RepositoryAccessError(404);
  if (role !== 'OWNER' && role !== 'ADMIN') throw new RepositoryAccessError(403);

  const lockKey = `${input.organizationId}|${input.principalId}|agent.register|${input.idempotencyKey}`;
  await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1, 0))', [lockKey]);
  await client.query(
    `DELETE FROM command_idempotency WHERE organization_id = $1 AND principal_id = $2 AND scope = 'agent.register' AND idempotency_key = $3 AND expires_at <= now()`,
    [input.organizationId, input.principalId, input.idempotencyKey],
  );

  const replay = await getAgentByIdempotency(client, input);
  if (replay !== null) return replay;

  const token = `mnd_agent_${randomBytes(32).toString('base64url')}`;
  const keyVersion = 1;
  const insert = await client.query<AgentRow>(
    `INSERT INTO agents (organization_id, id, display_name, status, key_version)
     VALUES ($1, $2, $3, 'ACTIVE', $4)
     RETURNING id, display_name, status, key_version, created_at`,
    [input.organizationId, input.request.id, input.request.displayName, keyVersion],
  );
  const row = insert.rows[0];
  if (row === undefined) throw new Error('agent insert returned no row');
  const agent = AgentSummarySchema.parse({
    id: row.id,
    displayName: row.display_name,
    status: row.status,
    keyVersion: row.key_version,
    createdAt: row.created_at.toISOString(),
  });

  await client.query(
    `INSERT INTO agent_credentials (organization_id, agent_id, key_version, secret_hash, created_by)
     VALUES ($1, $2, $3, $4, $5)`,
    [input.organizationId, agent.id, keyVersion, sha256(token), input.principalId],
  );
  await client.query(
    `INSERT INTO command_idempotency (organization_id, principal_id, scope, idempotency_key, request_hash, response_json)
     VALUES ($1, $2, 'agent.register', $3, $4, $5::jsonb)`,
    [input.organizationId, input.principalId, input.idempotencyKey, `0x${sha256(JSON.stringify(input.request))}`, JSON.stringify(agent)],
  );
  await writeAuditAndOutbox(client, input, agent);
  return { kind: 'CREATED', agent, token };
}

export class AgentStore implements AgentRepository {
  public constructor(private readonly pool: Pool) {}

  public async getHumanRole(organizationId: string, subject: string): Promise<'OWNER' | 'ADMIN' | 'APPROVER' | 'VIEWER' | null> {
    const result = await this.pool.query<{ role: string }>(
      'SELECT role FROM members WHERE organization_id = $1 AND subject = $2',
      [organizationId, subject],
    );
    const role = result.rows[0]?.role;
    return role === undefined ? null : OrganizationRoleSchema.parse(role);
  }

  public async getHumanOrganizations(subject: string): Promise<readonly { readonly organizationId: string; readonly role: 'OWNER' | 'ADMIN' | 'APPROVER' | 'VIEWER' }[]> {
    const result = await this.pool.query<{ organization_id: string; role: string }>(
      'SELECT organization_id, role FROM members WHERE subject = $1 ORDER BY organization_id',
      [subject],
    );
    return result.rows.map(({ organization_id, role }) => ({ organizationId: organization_id, role: OrganizationRoleSchema.parse(role) }));
  }

  public async listAgents(organizationId: string): Promise<readonly AgentListItem[]> {
    const result = await this.pool.query<AgentRow>(
      `SELECT id, display_name, status, key_version, created_at FROM agents
       WHERE organization_id = $1 ORDER BY created_at, id`,
      [organizationId],
    );
    return result.rows.map((row) => ({
      id: row.id,
      displayName: row.display_name,
      status: row.status,
      keyVersion: row.key_version,
      createdAt: row.created_at.toISOString(),
    }));
  }

  public async registerAgent(input: AgentRegistrationInput): Promise<AgentRegistrationResult> {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      const result = await registerInTransaction(client, input);
      await client.query('COMMIT');
      return result;
    } catch (error: unknown) {
      await client.query('ROLLBACK');
      if (uniqueViolation(error)) throw new AgentConflictError();
      throw error;
    } finally {
      client.release();
    }
  }

  public async findAgentByCredentialHash(secretHash: string): Promise<AgentCredentialIdentity | null> {
    const result = await this.pool.query<{ credential_id: string; organization_id: string; agent_id: string; key_version: number; agent_status: 'ACTIVE' | 'REVOKED' }>(
      `SELECT c.id AS credential_id, c.organization_id, c.agent_id, c.key_version, a.status AS agent_status
       FROM agent_credentials c
       JOIN agents a ON a.organization_id = c.organization_id AND a.id = c.agent_id
       WHERE c.secret_hash = $1 AND c.key_version = a.key_version AND c.revoked_at IS NULL
         AND (c.expires_at IS NULL OR c.expires_at > now())`,
      [secretHash],
    );
    const row = result.rows[0];
    return row?.agent_status === 'ACTIVE'
      ? { organizationId: row.organization_id, agentId: row.agent_id, keyVersion: row.key_version, credentialId: row.credential_id }
      : null;
  }
}

export class AgentConflictError extends Error {
  public constructor(
    message = 'Agent registration conflicts with an existing resource',
    public readonly code: 'IDEMPOTENCY_CONFLICT' | 'RESOURCE_CONFLICT' = 'RESOURCE_CONFLICT',
  ) {
    super(message);
    this.name = 'AgentConflictError';
  }
}
