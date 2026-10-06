import { createHash, randomUUID } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { Pool } from 'pg';
import { ExecutionReconciliationStore } from '../src/postgres/execution-reconciliation-store.js';
import { migrate } from '../src/postgres/migrate.js';

const connectionString = process.env.DATABASE_URL;

describe.skipIf(connectionString === undefined)('PostgreSQL dropped execution evidence (integration)', () => {
  let pool: Pool;
  beforeAll(async () => {
    if (connectionString === undefined) throw new Error('DATABASE_URL is required');
    pool = new Pool({ connectionString });
    const client = await pool.connect();
    try { await migrate(client); } finally { client.release(); }
  });
  afterAll(async () => { await pool?.end(); });

  it('atomically drops an expired, nonce-consumed submission with complete finalized coverage', async () => {
    const suffix = randomUUID();
    const organizationId = `drop-${suffix}`; const actionId = `action-${suffix}`;
    const accountId = `account-${suffix}`; const policyId = `policy-${suffix}`; const agentId = `agent-${suffix}`;
    const digest = (label: string): string => `0x${createHash('sha256').update(`${suffix}:${label}`).digest('hex')}`;
    const address = (label: string): string => digest(label).slice(0, 42);
    const chainId = 1_500_000_000 + Math.floor(Math.random() * 500_000_000); const moduleAddress = address('module'); const accountAddress = address('account');
    const guardAddress = address('guard'); const agentAddress = address('agent'); const outerSender = address('sender');
    const originalHash = digest('tx'); const actionHash = digest('action');
    const checkpointHash = digest('block'); const revisionHash = digest('revision');
    const requestHash = digest('request'); const blockNumber = 200; const snapshotBlockNumber = 100; const deadline = 1_000;
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      await client.query('INSERT INTO organizations (id, display_name) VALUES ($1, $2)', [organizationId, 'Drop Evidence Integration']);
      await client.query(`INSERT INTO accounts (organization_id, id, chain_id, address, adapter, status, guard_address, module_address, verified_at)
        VALUES ($1, $2, $3, $4, 'evm-smart-account', 'PAUSED', $5, $6, now())`,
      [organizationId, accountId, chainId, accountAddress, guardAddress, moduleAddress]);
      await client.query(`INSERT INTO policies (organization_id, id, account_id, current_revision, state) VALUES ($1, $2, $3, 1, 'ACTIVE')`,
        [organizationId, policyId, accountId]);
      await client.query(`INSERT INTO policy_revisions (organization_id, policy_id, revision, schema_version, canonical_json, revision_hash, created_by, valid_after, expires_at)
        VALUES ($1, $2, 1, 1, '{}'::jsonb, $3, 'test-owner', now() - interval '1 hour', now() + interval '1 day')`, [organizationId, policyId, revisionHash]);
      await client.query(`INSERT INTO agents (organization_id, id, display_name, status, key_version) VALUES ($1, $2, 'Drop Test Agent', 'ACTIVE', 1)`,
        [organizationId, agentId]);
      await client.query(`INSERT INTO action_requests (organization_id, id, policy_id, policy_revision, idempotency_key, request_hash, action_json, state, verdict, reason_code)
        VALUES ($1, $2, $3, 1, $4, $5, '{}'::jsonb, 'SUBMITTED', 'ALLOW', 'ALLOW')`,
        [organizationId, actionId, policyId, `idem-${suffix}`, requestHash]);
      await client.query(`INSERT INTO reservations (organization_id, action_id, amount, state, lease_expires_at) VALUES ($1, $2, 1, 'ACTIVE', now() + interval '1 day')`,
        [organizationId, actionId]);
      await client.query(`INSERT INTO execution_attempts (organization_id, action_id, attempt_number, chain_id, transaction_hash, state)
        VALUES ($1, $2, 1, $3, $4, 'SUBMITTED')`, [organizationId, actionId, chainId, originalHash]);
      await client.query(`INSERT INTO action_authorizations (organization_id, action_id, idempotency_key, request_hash, action_hash,
        policy_revision_hash, chain_id, snapshot_block_number, snapshot_block_hash, execution_nonce, status, authorization_json, expires_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 7, 'CONSUMED', $10::jsonb, to_timestamp($11))`,
      [organizationId, actionId, `auth-${suffix}`, requestHash, actionHash, revisionHash, chainId, snapshotBlockNumber, checkpointHash,
        JSON.stringify({ moduleAddress, agentAddress, keyVersion: '1', executionNonce: '7', actionHash, deadline }), deadline]);
      await client.query(`INSERT INTO action_execution_submissions (organization_id, action_id, agent_id, idempotency_key, request_hash,
        transaction_hash, status, submitted_at, outer_sender, outer_nonce)
        VALUES ($1, $2, $3, $4, $5, $6, 'SUBMITTED', now(), $7, 4)`,
      [organizationId, actionId, agentId, `submit-${suffix}`, requestHash, originalHash, outerSender]);
      await client.query(`INSERT INTO indexer_cursors (chain_id, next_block, finalized_block, block_hash, indexed_from_block) VALUES ($1, $2, $3, $4, 1)`,
        [chainId, blockNumber + 1, blockNumber, checkpointHash]);
      await client.query('INSERT INTO indexer_blocks (chain_id, block_number, block_hash, parent_hash) VALUES ($1, $2, $3, $4)',
        [chainId, blockNumber, checkpointHash, `0x${'b'.repeat(64)}`]);
      await client.query('COMMIT');
    } catch (error: unknown) { await client.query('ROLLBACK'); throw error; } finally { client.release(); }

    const store = new ExecutionReconciliationStore(pool);
    const selected = (await store.listPending(100)).find((item) => item.actionId === actionId);
    expect(selected).toMatchObject({ organizationId, actionId, outerSender, outerNonce: 4, snapshotBlockNumber, authorizationDeadline: deadline });
    if (selected === undefined) throw new Error('New submitted action was not selected for reconciliation');
    const checkpoint = await store.getDropCheckpoint(selected);
    expect(checkpoint).toEqual({ blockNumber, blockHash: checkpointHash });
    await pool.query('UPDATE indexer_cursors SET indexed_from_block = $2 WHERE chain_id = $1', [chainId, snapshotBlockNumber + 1]);
    await expect(store.getDropCheckpoint(selected)).resolves.toBeNull();
    await pool.query('UPDATE indexer_cursors SET indexed_from_block = 1 WHERE chain_id = $1', [chainId]);
    const eventBlockHash = digest('event-block');
    await pool.query('INSERT INTO indexer_blocks (chain_id, block_number, block_hash, parent_hash) VALUES ($1, 150, $2, $3)',
      [chainId, eventBlockHash, checkpointHash]);
    await pool.query(`INSERT INTO indexed_chain_logs (chain_id, block_number, block_hash, transaction_hash, transaction_index, log_index, address, topics, data)
      VALUES ($1, 150, $2, $3, 0, 0, $4, $5, $6)`,
    [chainId, eventBlockHash, digest('replacement-tx'), moduleAddress,
      ['0xf8ac4b4e81cac0a2fb7dc0f50ae0205789de4f0a13336381c20e5cd71016f24b',
        `0x${agentAddress.slice(2).padStart(64, '0')}`, `0x${BigInt(1).toString(16).padStart(64, '0')}`,
        `0x${BigInt(7).toString(16).padStart(64, '0')}`], actionHash]);
    await expect(store.markDropped({ pending: selected, checkpoint: checkpoint!, senderNonce: 5, checkpointTimestampSeconds: deadline + 1 })).resolves.toBe(false);
    await pool.query('DELETE FROM indexer_blocks WHERE chain_id = $1 AND block_number = 150', [chainId]);
    await expect(store.markDropped({ pending: selected, checkpoint: checkpoint!, senderNonce: 5, checkpointTimestampSeconds: deadline + 1 })).resolves.toBe(true);
    await expect(store.markDropped({ pending: selected, checkpoint: checkpoint!, senderNonce: 5, checkpointTimestampSeconds: deadline + 1 })).resolves.toBe(false);
    const result = await pool.query<{ action_state: string; attempt_state: string; reservation_state: string; event_count: string; outbox_count: string }>(
      `SELECT action.state AS action_state, attempt.state AS attempt_state, reservation.state AS reservation_state,
        (SELECT count(*)::text FROM audit_events WHERE organization_id = $1 AND subject_id = $2 AND event_type = 'ACTION_DROPPED') AS event_count,
        (SELECT count(*)::text FROM outbox_events WHERE organization_id = $1 AND aggregate_id = $2 AND event_type = 'ACTION_DROPPED') AS outbox_count
       FROM action_requests action JOIN execution_attempts attempt ON attempt.organization_id = action.organization_id AND attempt.action_id = action.id
       JOIN reservations reservation ON reservation.organization_id = action.organization_id AND reservation.action_id = action.id
       WHERE action.organization_id = $1 AND action.id = $2`, [organizationId, actionId]);
    expect(result.rows[0]).toEqual({ action_state: 'RECONCILED', attempt_state: 'DROPPED', reservation_state: 'RELEASED', event_count: '1', outbox_count: '1' });
  });

  it('restores the reservation hold, pauses the account, and records one incident when a finalized receipt block is replaced', async () => {
    const suffix = randomUUID();
    const digest = (label: string): string => `0x${createHash('sha256').update(`${suffix}:${label}`).digest('hex')}`;
    const address = (label: string): string => digest(label).slice(0, 42);
    const organizationId = `deep-reorg-${suffix}`; const actionId = `action-${suffix}`;
    const accountId = `account-${suffix}`; const policyId = `policy-${suffix}`; const agentId = `agent-${suffix}`;
    const chainId = 1_500_000_000 + Math.floor(Math.random() * 500_000_000);
    const moduleAddress = address('module'); const accountAddress = address('account'); const guardAddress = address('guard');
    const agentAddress = address('agent'); const txHash = digest('tx'); const actionHash = digest('action');
    const oldReceiptHash = digest('old-block'); const newCanonicalHash = digest('new-block'); const tipHash = digest('tip');
    const revisionHash = digest('revision'); const requestHash = digest('request'); const blockNumber = 500;
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      await client.query('INSERT INTO organizations (id, display_name) VALUES ($1, $2)', [organizationId, 'Deep Reorg Integration']);
      await client.query(`INSERT INTO accounts (organization_id, id, chain_id, address, adapter, status, guard_address, module_address, verified_at)
        VALUES ($1, $2, $3, $4, 'evm-smart-account', 'ACTIVE', $5, $6, now())`,
      [organizationId, accountId, chainId, accountAddress, guardAddress, moduleAddress]);
      await client.query(`INSERT INTO policies (organization_id, id, account_id, current_revision, state) VALUES ($1, $2, $3, 1, 'ACTIVE')`,
        [organizationId, policyId, accountId]);
      await client.query(`INSERT INTO policy_revisions (organization_id, policy_id, revision, schema_version, canonical_json, revision_hash, created_by, valid_after, expires_at)
        VALUES ($1, $2, 1, 1, '{}'::jsonb, $3, 'test-owner', now() - interval '1 hour', now() + interval '1 day')`, [organizationId, policyId, revisionHash]);
      await client.query(`INSERT INTO agents (organization_id, id, display_name, status, key_version) VALUES ($1, $2, 'Reorg Test Agent', 'ACTIVE', 1)`,
        [organizationId, agentId]);
      await client.query(`INSERT INTO action_requests (organization_id, id, policy_id, policy_revision, idempotency_key, request_hash, action_json, state, verdict, reason_code)
        VALUES ($1, $2, $3, 1, $4, $5, '{}'::jsonb, 'RECONCILED', 'ALLOW', 'ALLOW')`,
        [organizationId, actionId, policyId, `idem-${suffix}`, requestHash]);
      await client.query(`INSERT INTO reservations (organization_id, action_id, amount, state, lease_expires_at) VALUES ($1, $2, 1, 'CONSUMED', now() + interval '1 day')`,
        [organizationId, actionId]);
      await client.query(`INSERT INTO execution_attempts (organization_id, action_id, attempt_number, chain_id, transaction_hash, state)
        VALUES ($1, $2, 1, $3, $4, 'CONFIRMED')`, [organizationId, actionId, chainId, txHash]);
      await client.query(`INSERT INTO action_authorizations (organization_id, action_id, idempotency_key, request_hash, action_hash,
        policy_revision_hash, chain_id, snapshot_block_number, snapshot_block_hash, execution_nonce, status, authorization_json, expires_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, 100, $8, 7, 'CONSUMED', $9::jsonb, now() + interval '1 day')`,
      [organizationId, actionId, `auth-${suffix}`, requestHash, actionHash, revisionHash, chainId, oldReceiptHash,
        JSON.stringify({ moduleAddress, agentAddress, keyVersion: '1', executionNonce: '7', actionHash, deadline: 9_000 })]);
      await client.query(`INSERT INTO action_execution_submissions (organization_id, action_id, agent_id, idempotency_key, request_hash,
        transaction_hash, status, submitted_at, outer_sender, outer_nonce)
        VALUES ($1, $2, $3, $4, $5, $6, 'SUBMITTED', now(), $7, 4)`,
      [organizationId, actionId, agentId, `submit-${suffix}`, requestHash, txHash, address('sender')]);
      await client.query(`INSERT INTO receipts (organization_id, action_id, chain_id, transaction_hash, block_number, block_hash, status, receipt_json)
        VALUES ($1, $2, $3, $4, $5, $6, 'FINAL', '{"status":"SUCCESS"}'::jsonb)`,
      [organizationId, actionId, chainId, txHash, blockNumber, oldReceiptHash]);
      await client.query(`INSERT INTO indexer_cursors (chain_id, next_block, finalized_block, block_hash, indexed_from_block)
        VALUES ($1, 601, 600, $2, 1)`, [chainId, tipHash]);
      await client.query('INSERT INTO indexer_blocks (chain_id, block_number, block_hash, parent_hash) VALUES ($1, $2, $3, $4)',
        [chainId, blockNumber, newCanonicalHash, digest('parent')]);
      await client.query('INSERT INTO indexer_blocks (chain_id, block_number, block_hash, parent_hash) VALUES ($1, 600, $2, $3)',
        [chainId, tipHash, digest('parent-tip')]);
      await client.query('COMMIT');
    } catch (error: unknown) { await client.query('ROLLBACK'); throw error; } finally { client.release(); }

    const store = new ExecutionReconciliationStore(pool);
    const candidate = (await store.listFinalizedReceipts(100)).find((item) => item.pending.actionId === actionId);
    expect(candidate).toMatchObject({ blockNumber, blockHash: oldReceiptHash, pending: { organizationId, actionId, transactionHash: txHash } });
    if (candidate === undefined) throw new Error('Finalized receipt was not selected for deep-reorg monitoring');
    await expect(store.markDeepReorg({ candidate, canonicalBlockHash: digest('not-indexed-canonical') })).resolves.toBe(false);
    await expect(store.markDeepReorg({ candidate, canonicalBlockHash: newCanonicalHash })).resolves.toBe(true);
    await expect(store.markDeepReorg({ candidate, canonicalBlockHash: newCanonicalHash })).resolves.toBe(false);
    const state = await pool.query<{ action_state: string; attempt_state: string; receipt_status: string; reservation_state: string; account_status: string; incident_count: string; pause_count: string }>(
      `SELECT action.state AS action_state, attempt.state AS attempt_state, receipt.status AS receipt_status,
        reservation.state AS reservation_state, account.status AS account_status,
        (SELECT count(*)::text FROM audit_events WHERE organization_id = $1 AND subject_id = $2 AND event_type = 'ACTION_DEEP_REORG_DETECTED') AS incident_count,
        (SELECT count(*)::text FROM audit_events WHERE organization_id = $1 AND subject_id = $3 AND event_type = 'ACCOUNT_PROTECTION_PAUSED') AS pause_count
       FROM action_requests action JOIN execution_attempts attempt ON attempt.organization_id = action.organization_id AND attempt.action_id = action.id
       JOIN receipts receipt ON receipt.organization_id = action.organization_id AND receipt.action_id = action.id
       JOIN reservations reservation ON reservation.organization_id = action.organization_id AND reservation.action_id = action.id
       JOIN policies policy ON policy.organization_id = action.organization_id AND policy.id = action.policy_id
       JOIN accounts account ON account.organization_id = policy.organization_id AND account.id = policy.account_id
       WHERE action.organization_id = $1 AND action.id = $2`, [organizationId, actionId, accountId]);
    expect(state.rows[0]).toEqual({ action_state: 'REORGED', attempt_state: 'REORGED', receipt_status: 'REORGED',
      reservation_state: 'ACTIVE', account_status: 'PAUSED', incident_count: '1', pause_count: '1' });

    await pool.query("INSERT INTO members (organization_id, subject, role) VALUES ($1, 'owner-recovery', 'OWNER')", [organizationId]);
    await pool.query("INSERT INTO members (organization_id, subject, role) VALUES ($1, 'non-owner', 'VIEWER')", [organizationId]);
    const { ExecutionReorgResolutionStore } = await import('../src/postgres/execution-reorg-resolution-store.js');
    const recovery = new ExecutionReorgResolutionStore(pool);
    const resolution = {
      organizationId, actionId, actorSubject: 'owner-recovery', idempotencyKey: `resolve-${suffix}`,
      disposition: 'RELEASED' as const, reason: 'Independent treasury records confirm no transfer settled.', evidenceHash: digest('evidence'),
    };
    await expect(recovery.resolveDeepReorg({ ...resolution, actorSubject: 'non-owner' })).rejects.toMatchObject({ statusCode: 403 });
    const competingResolution = { ...resolution, idempotencyKey: `resolve-competing-${suffix}` };
    const race = await Promise.allSettled([recovery.resolveDeepReorg(resolution), recovery.resolveDeepReorg(competingResolution)]);
    expect(race.filter((result) => result.status === 'fulfilled')).toHaveLength(1);
    expect(race.filter((result) => result.status === 'rejected')).toHaveLength(1);
    const winnerIndex = race[0]?.status === 'fulfilled' ? 0 : 1;
    const winningInput = winnerIndex === 0 ? resolution : competingResolution;
    const winningResult = race[winnerIndex];
    if (winningResult?.status !== 'fulfilled') throw new Error('Concurrent deep-reorg resolution did not persist');
    expect(winningResult.value).toMatchObject({
      kind: 'CREATED', actionId, actionState: 'REORGED', reservationState: 'RELEASED', disposition: 'RELEASED',
      actorSubject: 'owner-recovery', evidenceHash: digest('evidence'),
      incident: { blockNumber, previousBlockHash: oldReceiptHash, canonicalBlockHash: newCanonicalHash },
    });
    await expect(recovery.resolveDeepReorg(winningInput)).resolves.toMatchObject({ kind: 'REPLAY', reservationState: 'RELEASED' });
    await expect(recovery.resolveDeepReorg({ ...resolution, idempotencyKey: `resolve-other-${suffix}`, disposition: 'CONSUMED' }))
      .rejects.toMatchObject({ statusCode: 409 });
    const resolved = await pool.query<{ action_state: string; attempt_state: string; receipt_status: string; reservation_state: string; account_status: string; resolutions: string; event_count: string }>(
      `SELECT action.state AS action_state, attempt.state AS attempt_state, receipt.status AS receipt_status,
        reservation.state AS reservation_state, account.status AS account_status,
        (SELECT count(*)::text FROM execution_reorg_resolutions WHERE organization_id = $1 AND action_id = $2) AS resolutions,
        (SELECT count(*)::text FROM audit_events WHERE organization_id = $1 AND subject_id = $2 AND event_type = 'ACTION_DEEP_REORG_RESOLVED') AS event_count
       FROM action_requests action JOIN execution_attempts attempt ON attempt.organization_id = action.organization_id AND attempt.action_id = action.id
       JOIN receipts receipt ON receipt.organization_id = action.organization_id AND receipt.action_id = action.id
       JOIN reservations reservation ON reservation.organization_id = action.organization_id AND reservation.action_id = action.id
       JOIN policies policy ON policy.organization_id = action.organization_id AND policy.id = action.policy_id
       JOIN accounts account ON account.organization_id = policy.organization_id AND account.id = policy.account_id
       WHERE action.organization_id = $1 AND action.id = $2`, [organizationId, actionId]);
    expect(resolved.rows[0]).toEqual({ action_state: 'REORGED', attempt_state: 'REORGED', receipt_status: 'REORGED',
      reservation_state: 'RELEASED', account_status: 'PAUSED', resolutions: '1', event_count: '1' });
  });
});
