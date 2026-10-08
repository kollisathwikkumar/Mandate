import { createHash } from 'node:crypto';
import type { Pool, PoolClient } from 'pg';
import { RepositoryAccessError } from '../../../ports/src/repository-errors.js';
import type {
  ExecutionReorgResolutionRepository,
  ExecutionReorgResolutionResult,
  ResolveExecutionReorgInput,
} from '../../../ports/src/execution-reorg-resolution.js';

interface IncidentRow { readonly payload: unknown; }
interface ResolutionRow {
  readonly actor_subject: string; readonly disposition: 'CONSUMED' | 'RELEASED'; readonly reason: string;
  readonly evidence_hash: string | null; readonly block_number: string; readonly previous_block_hash: string;
  readonly canonical_block_hash: string; readonly idempotency_key: string; readonly request_hash: string; readonly resolved_at: Date;
}
interface ActionContextRow {
  readonly action_state: string; readonly attempt_state: string; readonly receipt_status: string;
  readonly reservation_state: string; readonly account_status: string;
}

export class ExecutionReorgResolutionConflictError extends Error {
  public readonly statusCode = 409;
  public readonly code = 'RESOURCE_CONFLICT';
  public constructor(message: string) { super(message); this.name = 'ExecutionReorgResolutionConflictError'; }
}

function sha256(value: string): string { return `0x${createHash('sha256').update(value, 'utf8').digest('hex')}`; }

function resolutionFromRow(input: ResolveExecutionReorgInput, row: ResolutionRow, kind: 'CREATED' | 'REPLAY'): ExecutionReorgResolutionResult {
  const blockNumber = Number(row.block_number);
  if (!Number.isSafeInteger(blockNumber) || blockNumber < 0) throw new Error('Stored deep-reorg block number is invalid');
  return {
    kind, actionId: input.actionId, actionState: 'REORGED', reservationState: row.disposition,
    disposition: row.disposition, reason: row.reason, evidenceHash: row.evidence_hash?.trim() ?? null,
    actorSubject: row.actor_subject, resolvedAt: row.resolved_at.toISOString(),
    incident: { blockNumber, previousBlockHash: row.previous_block_hash.trim(), canonicalBlockHash: row.canonical_block_hash.trim() },
  };
}

async function appendAudit(client: PoolClient, input: ResolveExecutionReorgInput, payloadText: string): Promise<void> {
  await client.query('SELECT id FROM organizations WHERE id = $1 FOR UPDATE', [input.organizationId]);
  const previous = await client.query<{ event_hash: string }>(
    'SELECT event_hash FROM audit_events WHERE organization_id = $1 ORDER BY sequence DESC LIMIT 1', [input.organizationId],
  );
  const previousHash = previous.rows[0]?.event_hash.trim() ?? null;
  const eventType = 'ACTION_DEEP_REORG_RESOLVED';
  const eventHash = sha256(`${previousHash ?? ''}|${input.organizationId}|${input.actorSubject}|${eventType}|${payloadText}`);
  await client.query(
    `INSERT INTO audit_events (organization_id, actor_type, actor_id, event_type, subject_type, subject_id, correlation_id, payload, previous_hash, event_hash)
     VALUES ($1, 'HUMAN', $2, $3, 'ACTION', $4, $5, $6::jsonb, $7, $8)`,
    [input.organizationId, input.actorSubject, eventType, input.actionId, input.idempotencyKey, payloadText, previousHash, eventHash],
  );
  await client.query(
    `INSERT INTO outbox_events (organization_id, aggregate_type, aggregate_id, event_type, payload)
     VALUES ($1, 'ACTION', $2, $3, $4::jsonb)`,
    [input.organizationId, input.actionId, eventType, payloadText],
  );
}

export class ExecutionReorgResolutionStore implements ExecutionReorgResolutionRepository {
  public constructor(private readonly pool: Pool) {}

  public async resolveDeepReorg(input: ResolveExecutionReorgInput): Promise<ExecutionReorgResolutionResult> {
    const reason = input.reason.trim();
    const evidenceHash = input.evidenceHash?.toLowerCase() ?? null;
    // oxlint-disable-next-line no-control-regex -- Control-character rejection is intentional.
    if (reason.length < 1 || reason.length > 1000 || /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(reason)
      || (evidenceHash !== null && !/^0x[0-9a-f]{64}$/.test(evidenceHash))) throw new TypeError('Deep-reorg resolution input is invalid');
    if (input.disposition !== 'CONSUMED' && input.disposition !== 'RELEASED') throw new TypeError('Deep-reorg disposition is invalid');
    const normalized: ResolveExecutionReorgInput = { ...input, reason, evidenceHash };
    const requestHash = sha256(JSON.stringify([normalized.actionId, normalized.disposition, normalized.reason, normalized.evidenceHash]));
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      const membership = await client.query<{ role: string }>(
        'SELECT role FROM members WHERE organization_id = $1 AND subject = $2 FOR UPDATE',
        [normalized.organizationId, normalized.actorSubject],
      );
      const role = membership.rows[0]?.role;
      if (role === undefined) throw new RepositoryAccessError(404);
      if (role !== 'OWNER') throw new RepositoryAccessError(403);
      const accountResult = await client.query<{ account_id: string }>(
        `SELECT policy.account_id
         FROM action_requests action JOIN policies policy
           ON policy.organization_id = action.organization_id AND policy.id = action.policy_id
         WHERE action.organization_id = $1 AND action.id = $2`,
        [normalized.organizationId, normalized.actionId],
      );
      const accountId = accountResult.rows[0]?.account_id;
      if (accountId === undefined) throw new RepositoryAccessError(404);
      await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1, 0))', [
        `${normalized.organizationId}|${accountId}|account.lifecycle`,
      ]);
      await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1, 0))', [
        `${normalized.organizationId}|${normalized.actionId}|execution.reorg.resolve.action`,
      ]);
      await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1, 0))', [
        `${normalized.organizationId}|${normalized.actorSubject}|execution.reorg.resolve|${normalized.idempotencyKey}`,
      ]);
      const idempotency = await client.query<{ request_hash: string }>(
        `SELECT request_hash FROM command_idempotency
         WHERE organization_id = $1 AND principal_id = $2 AND scope = 'execution.reorg.resolve' AND idempotency_key = $3`,
        [normalized.organizationId, normalized.actorSubject, normalized.idempotencyKey],
      );
      if (idempotency.rows[0] !== undefined && idempotency.rows[0].request_hash.trim() !== requestHash) {
        throw new ExecutionReorgResolutionConflictError('Idempotency key was used for a different deep-reorg resolution');
      }
      const prior = await client.query<ResolutionRow>(
        `SELECT actor_subject, disposition, reason, evidence_hash, block_number::text, previous_block_hash,
                canonical_block_hash, idempotency_key, request_hash, resolved_at
         FROM execution_reorg_resolutions WHERE organization_id = $1 AND action_id = $2 FOR UPDATE`,
        [normalized.organizationId, normalized.actionId],
      );
      const existing = prior.rows[0];
      if (existing !== undefined) {
        if (existing.actor_subject !== normalized.actorSubject || existing.idempotency_key !== normalized.idempotencyKey
          || existing.request_hash.trim() !== requestHash) {
          throw new ExecutionReorgResolutionConflictError('This deep-reorg action already has a different durable resolution');
        }
        await client.query('COMMIT');
        return resolutionFromRow(normalized, existing, 'REPLAY');
      }

      const context = await client.query<ActionContextRow>(
        `SELECT action.state AS action_state, attempt.state AS attempt_state, receipt.status AS receipt_status,
                reservation.state AS reservation_state, account.status AS account_status
         FROM action_requests action
         JOIN execution_attempts attempt ON attempt.organization_id = action.organization_id AND attempt.action_id = action.id
         JOIN receipts receipt ON receipt.organization_id = action.organization_id AND receipt.action_id = action.id
         JOIN reservations reservation ON reservation.organization_id = action.organization_id AND reservation.action_id = action.id
         JOIN policies policy ON policy.organization_id = action.organization_id AND policy.id = action.policy_id
         JOIN accounts account ON account.organization_id = policy.organization_id AND account.id = policy.account_id
         WHERE action.organization_id = $1 AND action.id = $2
         FOR UPDATE OF action, attempt, receipt, reservation, account`,
        [normalized.organizationId, normalized.actionId],
      );
      const state = context.rows[0];
      if (state === undefined) throw new RepositoryAccessError(404);
      if (state.action_state !== 'REORGED' || state.attempt_state !== 'REORGED' || state.receipt_status !== 'REORGED'
        || state.reservation_state !== 'ACTIVE' || state.account_status !== 'PAUSED') {
        throw new ExecutionReorgResolutionConflictError('Action is not in the unresolved deep-reorg state');
      }
      const incidentResult = await client.query<IncidentRow>(
        `SELECT payload FROM audit_events WHERE organization_id = $1 AND subject_type = 'ACTION' AND subject_id = $2
           AND event_type = 'ACTION_DEEP_REORG_DETECTED' ORDER BY sequence DESC LIMIT 1`,
        [normalized.organizationId, normalized.actionId],
      );
      const incident = incidentResult.rows[0]?.payload as { blockNumber?: unknown; previousBlockHash?: unknown; canonicalBlockHash?: unknown } | undefined;
      const blockNumber = incident?.blockNumber;
      const previousBlockHash = incident?.previousBlockHash;
      const canonicalBlockHash = incident?.canonicalBlockHash;
      if (typeof blockNumber !== 'number' || !Number.isSafeInteger(blockNumber) || blockNumber < 0
        || typeof previousBlockHash !== 'string' || !/^0x[0-9a-f]{64}$/.test(previousBlockHash)
        || typeof canonicalBlockHash !== 'string' || !/^0x[0-9a-f]{64}$/.test(canonicalBlockHash)
        || previousBlockHash === canonicalBlockHash) throw new ExecutionReorgResolutionConflictError('Deep-reorg incident evidence is missing or invalid');

      const inserted = await client.query<ResolutionRow>(
        `INSERT INTO execution_reorg_resolutions
          (organization_id, action_id, actor_subject, disposition, reason, evidence_hash, block_number,
           previous_block_hash, canonical_block_hash, idempotency_key, request_hash)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
         RETURNING actor_subject, disposition, reason, evidence_hash, block_number::text, previous_block_hash,
                   canonical_block_hash, idempotency_key, request_hash, resolved_at`,
        [normalized.organizationId, normalized.actionId, normalized.actorSubject, normalized.disposition, normalized.reason,
          normalized.evidenceHash, blockNumber, previousBlockHash, canonicalBlockHash, normalized.idempotencyKey, requestHash],
      );
      const row = inserted.rows[0];
      if (row === undefined) throw new Error('Deep-reorg resolution was not persisted');
      await client.query(
        `UPDATE reservations SET state = $3, updated_at = now()
         WHERE organization_id = $1 AND action_id = $2 AND state = 'ACTIVE'`,
        [normalized.organizationId, normalized.actionId, normalized.disposition],
      );
      const result = resolutionFromRow(normalized, row, 'CREATED');
      const payloadText = JSON.stringify({ actionId: result.actionId, actionState: result.actionState,
        reservationState: result.reservationState, disposition: result.disposition, reason: result.reason,
        evidenceHash: result.evidenceHash, actorSubject: result.actorSubject, resolvedAt: result.resolvedAt, incident: result.incident });
      await appendAudit(client, normalized, payloadText);
      await client.query(
        `INSERT INTO command_idempotency (organization_id, principal_id, scope, idempotency_key, request_hash, response_json, expires_at)
         VALUES ($1, $2, 'execution.reorg.resolve', $3, $4, $5::jsonb, 'infinity')
         ON CONFLICT (organization_id, principal_id, scope, idempotency_key) DO NOTHING`,
        [normalized.organizationId, normalized.actorSubject, normalized.idempotencyKey, requestHash, JSON.stringify(result)],
      );
      await client.query('COMMIT');
      return result;
    } catch (error: unknown) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  }
}
