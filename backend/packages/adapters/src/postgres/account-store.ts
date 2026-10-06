import { createHash } from 'node:crypto';
import type { Pool, PoolClient } from 'pg';
import { z } from 'zod';
import type { AccountActivationInput, AccountActivationOutcome, AccountRepository, AccountRegistrationInput, AccountRegistrationOutcome, AccountSummary } from '../../../ports/src/account-repository.js';
import { RepositoryAccessError } from '../../../ports/src/repository-errors.js';

const AccountSummarySchema = z.object({
  id: z.string(), chainId: z.number().int().positive().safe(), address: z.string().regex(/^0x[0-9a-f]{40}$/),
  adapter: z.literal('evm-smart-account'), status: z.enum(['PAUSED', 'ACTIVE', 'UNSUPPORTED']), createdAt: z.string().datetime(),
  guardAddress: z.string().regex(/^0x[0-9a-f]{40}$/).nullable().default(null),
  moduleAddress: z.string().regex(/^0x[0-9a-f]{40}$/).nullable().default(null),
  verifiedAt: z.string().datetime().nullable().default(null),
}).strict();
const AccountEnrollmentProofSchema = z.object({
  safeAddress: z.string().regex(/^0x[0-9a-f]{40}$/),
  guardAddress: z.string().regex(/^0x[0-9a-f]{40}$/),
  moduleAddress: z.string().regex(/^0x[0-9a-f]{40}$/),
}).strict();

interface AccountRow { readonly id: string; readonly chain_id: string; readonly address: string; readonly adapter: string; readonly status: 'PAUSED' | 'ACTIVE' | 'UNSUPPORTED'; readonly created_at: Date; readonly guard_address: string | null; readonly module_address: string | null; readonly verified_at: Date | null; }
interface IdempotencyRow { readonly request_hash: string; readonly response_json: unknown; }

function sha256(value: string): string { return createHash('sha256').update(value, 'utf8').digest('hex'); }

function accountSummary(row: AccountRow): AccountSummary {
  const chainId = Number(row.chain_id);
  return AccountSummarySchema.parse({
    id: row.id, chainId, address: row.address.trim().toLowerCase(), adapter: row.adapter,
    status: row.status, createdAt: row.created_at.toISOString(),
    guardAddress: row.guard_address?.trim().toLowerCase() ?? null,
    moduleAddress: row.module_address?.trim().toLowerCase() ?? null,
    verifiedAt: row.verified_at?.toISOString() ?? null,
  });
}

function uniqueViolation(error: unknown): boolean {
  return typeof error === 'object' && error !== null && 'code' in error && error.code === '23505';
}

export class AccountConflictError extends Error {
  public constructor(message: string, public readonly code: 'RESOURCE_CONFLICT' | 'IDEMPOTENCY_CONFLICT' = 'RESOURCE_CONFLICT') {
    super(message);
    this.name = 'AccountConflictError';
  }
}

async function authorizeAccountMember(client: PoolClient, input: Pick<AccountRegistrationInput, 'organizationId' | 'principalId'>): Promise<void> {
  const result = await client.query<{ role: string }>(
    'SELECT role FROM members WHERE organization_id = $1 AND subject = $2 FOR UPDATE',
    [input.organizationId, input.principalId],
  );
  const role = result.rows[0]?.role;
  if (role === undefined) throw new RepositoryAccessError(404);
  if (role !== 'OWNER' && role !== 'ADMIN') throw new RepositoryAccessError(403);
}

async function replayRegistration(client: PoolClient, input: AccountRegistrationInput): Promise<AccountRegistrationOutcome | null> {
  const previous = await client.query<IdempotencyRow>(
    `SELECT request_hash, response_json FROM command_idempotency
     WHERE organization_id = $1 AND principal_id = $2 AND scope = 'account.register' AND idempotency_key = $3 AND expires_at > now()`,
    [input.organizationId, input.principalId, input.idempotencyKey],
  );
  const row = previous.rows[0];
  if (row === undefined) return null;
  const requestHash = `0x${sha256(JSON.stringify(input.request))}`;
  if (row.request_hash.trim() !== requestHash) throw new AccountConflictError('Idempotency key was already used for a different account request', 'IDEMPOTENCY_CONFLICT');
  return { kind: 'REPLAY', account: AccountSummarySchema.parse(row.response_json) };
}

async function writeAuditAndOutbox(client: PoolClient, input: AccountRegistrationInput, account: AccountSummary): Promise<void> {
  await client.query('SELECT id FROM organizations WHERE id = $1 FOR UPDATE', [input.organizationId]);
  const lastEvent = await client.query<{ event_hash: string }>(
    'SELECT event_hash FROM audit_events WHERE organization_id = $1 ORDER BY sequence DESC LIMIT 1',
    [input.organizationId],
  );
  const previousHash = lastEvent.rows[0]?.event_hash.trim() ?? null;
  const payload = { accountId: account.id, chainId: account.chainId, address: account.address, adapter: account.adapter, status: account.status };
  const payloadText = JSON.stringify(payload);
  const eventHash = `0x${sha256(`${previousHash ?? ''}|${input.organizationId}|${input.principalId}|ACCOUNT_REGISTERED|${payloadText}`)}`;
  await client.query(
    `INSERT INTO audit_events (organization_id, actor_type, actor_id, event_type, subject_type, subject_id, correlation_id, payload, previous_hash, event_hash)
     VALUES ($1, 'HUMAN', $2, 'ACCOUNT_REGISTERED', 'ACCOUNT', $3, $4, $5::jsonb, $6, $7)`,
    [input.organizationId, input.principalId, account.id, input.idempotencyKey, payloadText, previousHash, eventHash],
  );
  await client.query(
    `INSERT INTO outbox_events (organization_id, aggregate_type, aggregate_id, event_type, payload)
     VALUES ($1, 'ACCOUNT', $2, 'ACCOUNT_REGISTERED', $3::jsonb)`,
    [input.organizationId, account.id, payloadText],
  );
}

async function replayActivation(client: PoolClient, input: AccountActivationInput): Promise<AccountActivationOutcome | null> {
  const previous = await client.query<IdempotencyRow>(
    `SELECT request_hash, response_json FROM command_idempotency
     WHERE organization_id = $1 AND principal_id = $2 AND scope = 'account.verify' AND idempotency_key = $3 AND expires_at > now()`,
    [input.organizationId, input.principalId, input.idempotencyKey],
  );
  const row = previous.rows[0];
  if (row === undefined) return null;
  const requestHash = `0x${sha256(JSON.stringify({ accountId: input.accountId, proof: input.proof }))}`;
  if (row.request_hash.trim() !== requestHash) throw new AccountConflictError('Idempotency key was already used for a different verification request', 'IDEMPOTENCY_CONFLICT');
  return { kind: 'REPLAY', account: AccountSummarySchema.parse(row.response_json) };
}

async function writeEnrollmentAuditAndOutbox(client: PoolClient, input: AccountActivationInput, account: AccountSummary): Promise<void> {
  await client.query('SELECT id FROM organizations WHERE id = $1 FOR UPDATE', [input.organizationId]);
  const lastEvent = await client.query<{ event_hash: string }>(
    'SELECT event_hash FROM audit_events WHERE organization_id = $1 ORDER BY sequence DESC LIMIT 1', [input.organizationId],
  );
  const previousHash = lastEvent.rows[0]?.event_hash.trim() ?? null;
  const payload = {
    accountId: account.id, chainId: account.chainId, address: account.address,
    guardAddress: account.guardAddress, moduleAddress: account.moduleAddress, verifiedAt: account.verifiedAt,
  };
  const payloadText = JSON.stringify(payload);
  const eventHash = `0x${sha256(`${previousHash ?? ''}|${input.organizationId}|${input.principalId}|ACCOUNT_ENROLLMENT_VERIFIED|${payloadText}`)}`;
  await client.query(
    `INSERT INTO audit_events (organization_id, actor_type, actor_id, event_type, subject_type, subject_id, correlation_id, payload, previous_hash, event_hash)
     VALUES ($1, 'HUMAN', $2, 'ACCOUNT_ENROLLMENT_VERIFIED', 'ACCOUNT', $3, $4, $5::jsonb, $6, $7)`,
    [input.organizationId, input.principalId, account.id, input.idempotencyKey, payloadText, previousHash, eventHash],
  );
  await client.query(
    `INSERT INTO outbox_events (organization_id, aggregate_type, aggregate_id, event_type, payload)
     VALUES ($1, 'ACCOUNT', $2, 'ACCOUNT_ENROLLMENT_VERIFIED', $3::jsonb)`,
    [input.organizationId, account.id, payloadText],
  );
}

async function activateInTransaction(client: PoolClient, input: AccountActivationInput): Promise<AccountActivationOutcome> {
  const proof = AccountEnrollmentProofSchema.parse(input.proof);
  await authorizeAccountMember(client, input);
  await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1, 0))', [
    `${input.organizationId}|${input.accountId}|account.lifecycle`,
  ]);
  const lockKey = `${input.organizationId}|${input.principalId}|account.verify|${input.idempotencyKey}`;
  await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1, 0))', [lockKey]);
  await client.query(
    `DELETE FROM command_idempotency
     WHERE organization_id = $1 AND principal_id = $2 AND scope = 'account.verify' AND idempotency_key = $3 AND expires_at <= now()`,
    [input.organizationId, input.principalId, input.idempotencyKey],
  );
  const current = await client.query<AccountRow>(
    `SELECT id, chain_id::text, btrim(address) AS address, adapter, status, created_at, guard_address, module_address, verified_at
     FROM accounts WHERE organization_id = $1 AND id = $2 FOR UPDATE`,
    [input.organizationId, input.accountId],
  );
  const row = current.rows[0];
  if (row === undefined) throw new RepositoryAccessError(404);
  const unresolvedReorg = await client.query<{ action_id: string }>(
    `SELECT action.id AS action_id
     FROM action_requests action
     JOIN policies policy ON policy.organization_id = action.organization_id AND policy.id = action.policy_id
     JOIN reservations reservation ON reservation.organization_id = action.organization_id AND reservation.action_id = action.id
     LEFT JOIN execution_reorg_resolutions resolution ON resolution.organization_id = action.organization_id AND resolution.action_id = action.id
     WHERE action.organization_id = $1 AND policy.account_id = $2 AND action.state = 'REORGED'
       AND reservation.state = 'ACTIVE' AND resolution.action_id IS NULL
     LIMIT 1`,
    [input.organizationId, input.accountId],
  );
  if (unresolvedReorg.rows[0] !== undefined) {
    throw new AccountConflictError('Deep-reorg reservations must receive an explicit owner disposition before account re-verification');
  }
  const replay = await replayActivation(client, input);
  if (replay !== null) {
    if (row.status !== 'ACTIVE') throw new AccountConflictError('Account is not active; submit a fresh verification request after resolving pending holds');
    return replay;
  }
  if (row.status === 'UNSUPPORTED' || row.address.trim().toLowerCase() !== proof.safeAddress
      || proof.guardAddress === `0x${'0'.repeat(40)}` || proof.moduleAddress === `0x${'0'.repeat(40)}`) {
    throw new AccountConflictError('On-chain account verification does not match the registered account');
  }
  const updated = await client.query<AccountRow>(
    `UPDATE accounts SET status = 'ACTIVE', guard_address = $1, module_address = $2, verified_at = now()
     WHERE organization_id = $3 AND id = $4
     RETURNING id, chain_id::text, btrim(address) AS address, adapter, status, created_at, guard_address, module_address, verified_at`,
    [proof.guardAddress, proof.moduleAddress, input.organizationId, input.accountId],
  );
  const updatedRow = updated.rows[0];
  if (updatedRow === undefined) throw new Error('account enrollment update returned no row');
  const account = accountSummary(updatedRow);
  await client.query(
    `INSERT INTO command_idempotency (organization_id, principal_id, scope, idempotency_key, request_hash, response_json)
     VALUES ($1, $2, 'account.verify', $3, $4, $5::jsonb)`,
    [input.organizationId, input.principalId, input.idempotencyKey, `0x${sha256(JSON.stringify({ accountId: input.accountId, proof }))}`, JSON.stringify(account)],
  );
  await writeEnrollmentAuditAndOutbox(client, input, account);
  return { kind: 'ACTIVATED', account };
}

async function registerInTransaction(client: PoolClient, input: AccountRegistrationInput): Promise<AccountRegistrationOutcome> {
  await authorizeAccountMember(client, input);
  const lockKey = `${input.organizationId}|${input.principalId}|account.register|${input.idempotencyKey}`;
  await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1, 0))', [lockKey]);
  await client.query(
    `DELETE FROM command_idempotency
     WHERE organization_id = $1 AND principal_id = $2 AND scope = 'account.register' AND idempotency_key = $3 AND expires_at <= now()`,
    [input.organizationId, input.principalId, input.idempotencyKey],
  );
  const replay = await replayRegistration(client, input);
  if (replay !== null) return replay;

  const result = await client.query<AccountRow>(
    `INSERT INTO accounts (organization_id, id, chain_id, address, adapter, status)
     VALUES ($1, $2, $3, $4, $5, 'PAUSED')
     RETURNING id, chain_id::text, btrim(address) AS address, adapter, status, created_at, guard_address, module_address, verified_at`,
    [input.organizationId, input.request.id, input.request.chainId, input.request.address, input.request.adapter],
  );
  const row = result.rows[0];
  if (row === undefined) throw new Error('account insert returned no row');
  const account = accountSummary(row);
  await client.query(
    `INSERT INTO command_idempotency (organization_id, principal_id, scope, idempotency_key, request_hash, response_json)
     VALUES ($1, $2, 'account.register', $3, $4, $5::jsonb)`,
    [input.organizationId, input.principalId, input.idempotencyKey, `0x${sha256(JSON.stringify(input.request))}`, JSON.stringify(account)],
  );
  await writeAuditAndOutbox(client, input, account);
  return { kind: 'CREATED', account };
}

export class AccountStore implements AccountRepository {
  public constructor(private readonly pool: Pool) {}

  public async getHumanRole(organizationId: string, subject: string): Promise<'OWNER' | 'ADMIN' | 'APPROVER' | 'VIEWER' | null> {
    const result = await this.pool.query<{ role: string }>(
      'SELECT role FROM members WHERE organization_id = $1 AND subject = $2', [organizationId, subject],
    );
    const role = result.rows[0]?.role;
    return role === 'OWNER' || role === 'ADMIN' || role === 'APPROVER' || role === 'VIEWER' ? role : null;
  }

  public async listAccounts(organizationId: string): Promise<readonly AccountSummary[]> {
    const result = await this.pool.query<AccountRow>(
      `SELECT id, chain_id::text, btrim(address) AS address, adapter, status, created_at, guard_address, module_address, verified_at
       FROM accounts WHERE organization_id = $1 ORDER BY created_at, id`,
      [organizationId],
    );
    return result.rows.map(accountSummary);
  }

  public async getAccount(organizationId: string, accountId: string): Promise<AccountSummary | null> {
    const result = await this.pool.query<AccountRow>(
      `SELECT id, chain_id::text, btrim(address) AS address, adapter, status, created_at, guard_address, module_address, verified_at
       FROM accounts WHERE organization_id = $1 AND id = $2`, [organizationId, accountId],
    );
    const row = result.rows[0];
    return row === undefined ? null : accountSummary(row);
  }

  public async registerAccount(input: AccountRegistrationInput): Promise<AccountRegistrationOutcome> {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      const outcome = await registerInTransaction(client, input);
      await client.query('COMMIT');
      return outcome;
    } catch (error: unknown) {
      await client.query('ROLLBACK');
      if (uniqueViolation(error)) throw new AccountConflictError('Account identifier or address is already registered');
      throw error;
    } finally {
      client.release();
    }
  }

  public async activateAccount(input: AccountActivationInput): Promise<AccountActivationOutcome> {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      const outcome = await activateInTransaction(client, input);
      await client.query('COMMIT');
      return outcome;
    } catch (error: unknown) {
      await client.query('ROLLBACK');
      if (uniqueViolation(error)) throw new AccountConflictError('Account verification conflicts with an existing request');
      throw error;
    } finally {
      client.release();
    }
  }
}
