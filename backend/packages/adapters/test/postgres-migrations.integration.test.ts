import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { randomUUID } from 'node:crypto';
import { Client } from 'pg';
import { migrate } from '../src/postgres/migrate.js';

const connectionString = process.env.DATABASE_URL;

describe.skipIf(connectionString === undefined)('PostgreSQL migrations (integration)', () => {
  let client: Client;

  beforeAll(async () => {
    client = new Client({ connectionString });
    await client.connect();
  });

  afterAll(async () => {
    await client.end();
  });

  it('applies the schema and safely records repeated migration runs', async () => {
    const firstRun = await migrate(client);
    const secondRun = await migrate(client);
    expect(firstRun.every((id) => ['001_initial.sql', '002_api_identity.sql', '003_idempotency_scope.sql', '004_action_nonce_counters.sql', '005_alert_notifications.sql', '006_model_credential_state.sql', '007_verified_account_enrollment.sql', '008_finalized_chain_indexer.sql', '009_policy_activation_plans.sql', '010_policy_activation_finalization.sql', '011_policy_revocation_plans.sql', '012_action_authorizations.sql', '013_action_execution_submissions.sql', '014_execution_reconciliation.sql', '015_execution_drop_evidence.sql', '016_deep_reorg_compensation.sql', '017_signed_webhooks.sql', '018_webhook_rotation_recovery.sql', '019_organization_onboarding.sql', '020_organization_invitations.sql', '021_api_rate_limits.sql', '022_execution_reorg_resolutions.sql', '023_audit_anchor_checkpoints.sql', '024_invitation_email_deliveries.sql'].includes(id))).toBe(true);
    expect(secondRun).toEqual([]);

    const tables = await client.query<{ table_name: string }>(
      "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' AND table_name IN ('organizations', 'accounts', 'policies', 'policy_revisions', 'policy_grants', 'policy_activation_plans', 'policy_activation_receipts', 'policy_revocation_plans', 'policy_revocation_receipts', 'model_provider_credentials', 'action_requests', 'action_authorizations', 'action_execution_submissions', 'agent_credentials', 'command_idempotency', 'action_nonce_counters', 'alert_notifications', 'reservations', 'outbox_events', 'webhook_endpoints', 'webhook_deliveries', 'audit_events', 'schema_migrations', 'indexer_blocks', 'indexed_chain_logs', 'api_rate_limit_windows', 'execution_reorg_resolutions', 'audit_anchor_checkpoints', 'invitation_email_deliveries') ORDER BY table_name",
    );

    expect(tables.rows.map(({ table_name }) => table_name)).toEqual([
      'accounts',
      'action_authorizations',
      'action_execution_submissions',
      'action_nonce_counters',
      'action_requests',
      'agent_credentials',
      'alert_notifications',
      'api_rate_limit_windows',
      'audit_anchor_checkpoints',
      'audit_events',
      'command_idempotency',
      'execution_reorg_resolutions',
      'indexed_chain_logs',
      'indexer_blocks',
      'invitation_email_deliveries',
      'model_provider_credentials',
      'organizations',
      'outbox_events',
      'policies',
      'policy_activation_plans',
      'policy_activation_receipts',
      'policy_grants',
      'policy_revisions',
      'policy_revocation_plans',
      'policy_revocation_receipts',
      'reservations',
      'schema_migrations',
      'webhook_deliveries',
      'webhook_endpoints',
    ]);
  });

  it('stores model credentials by secret-manager reference rather than raw API key', async () => {
    const columns = await client.query<{ column_name: string }>(
      "SELECT column_name FROM information_schema.columns WHERE table_name = 'model_provider_credentials' ORDER BY ordinal_position",
    );
    const columnNames = columns.rows.map(({ column_name }) => column_name);
    expect(columnNames).toContain('secret_reference');
    expect(columnNames).toContain('masked_suffix');
    expect(columnNames).not.toContain('api_key');
    expect(columnNames).not.toContain('raw_secret');
  });

  it('tracks pending webhook signing-secret cleanup without storing secret values', async () => {
    const columns = await client.query<{ column_name: string }>(
      "SELECT column_name FROM information_schema.columns WHERE table_name = 'webhook_endpoints' ORDER BY ordinal_position",
    );
    const names = columns.rows.map(({ column_name }) => column_name);
    expect(names).toContain('signing_secret_ref');
    expect(names).toContain('previous_signing_secret_ref');
    expect(names).not.toContain('signing_secret');
    expect(names).not.toContain('raw_secret');
  });

  it('stores signed outer transaction nonce evidence and explicit indexer coverage boundaries', async () => {
    const submissionColumns = await client.query<{ column_name: string }>(
      "SELECT column_name FROM information_schema.columns WHERE table_name = 'action_execution_submissions'",
    );
    expect(submissionColumns.rows.map(({ column_name }) => column_name)).toContain('outer_sender');
    expect(submissionColumns.rows.map(({ column_name }) => column_name)).toContain('outer_nonce');
    const cursorColumns = await client.query<{ column_name: string }>(
      "SELECT column_name FROM information_schema.columns WHERE table_name = 'indexer_cursors'",
    );
    expect(cursorColumns.rows.map(({ column_name }) => column_name)).toContain('indexed_from_block');
  });

  it('supports explicit deep-reorg state and periodically scheduled canonical receipt checks', async () => {
    const actionStates = await client.query<{ definition: string }>(
      `SELECT pg_get_constraintdef(oid) AS definition FROM pg_constraint WHERE conrelid = 'action_requests'::regclass AND conname = 'action_requests_state_check'`,
    );
    expect(actionStates.rows[0]?.definition).toContain('REORGED');
    const receiptColumns = await client.query<{ column_name: string }>(
      "SELECT column_name FROM information_schema.columns WHERE table_name = 'receipts'",
    );
    expect(receiptColumns.rows.map(({ column_name }) => column_name)).toContain('deep_reorg_checked_at');
  });

  it('requires verified guard and module metadata before an account can be active', async () => {
    const organizationId = `enrollment-${randomUUID()}`;
    await client.query('INSERT INTO organizations (id, display_name) VALUES ($1, $2)', [organizationId, 'Enrollment Constraint Test']);
    await expect(client.query(
      `INSERT INTO accounts (organization_id, id, chain_id, address, adapter, status)
       VALUES ($1, 'unverified', 10143, $2, 'evm-smart-account', 'ACTIVE')`,
      [organizationId, `0x${randomUUID().replaceAll('-', '')}${'a'.repeat(8)}`],
    )).rejects.toThrow('accounts_active_requires_verified_enrollment');
    await expect(client.query(
      `INSERT INTO accounts (organization_id, id, chain_id, address, adapter, status)
       VALUES ($1, 'pending', 10143, $2, 'evm-smart-account', 'PAUSED')`,
      [organizationId, `0x${randomUUID().replaceAll('-', '')}${'b'.repeat(8)}`],
    )).resolves.toMatchObject({ rowCount: 1 });
  });

  it('stores agent credentials as digests rather than bearer tokens', async () => {
    const columns = await client.query<{ column_name: string }>(
      "SELECT column_name FROM information_schema.columns WHERE table_name = 'agent_credentials' ORDER BY ordinal_position",
    );
    const columnNames = columns.rows.map(({ column_name }) => column_name);
    expect(columnNames).toContain('secret_hash');
    expect(columnNames).not.toContain('token');
    expect(columnNames).not.toContain('raw_secret');
  });

  it('persists exact action authorization without storing an agent signature or raw transaction', async () => {
    const columns = await client.query<{ column_name: string }>(
      "SELECT column_name FROM information_schema.columns WHERE table_name = 'action_authorizations' ORDER BY ordinal_position",
    );
    const columnNames = columns.rows.map(({ column_name }) => column_name);
    expect(columnNames).toContain('authorization_json');
    expect(columnNames).toContain('action_hash');
    expect(columnNames).toContain('snapshot_block_hash');
    expect(columnNames).not.toContain('signature');
    expect(columnNames).not.toContain('raw_transaction');
    const submissionColumns = await client.query<{ column_name: string }>(
      "SELECT column_name FROM information_schema.columns WHERE table_name = 'action_execution_submissions' ORDER BY ordinal_position",
    );
    const submissionColumnNames = submissionColumns.rows.map(({ column_name }) => column_name);
    expect(submissionColumnNames).toContain('transaction_hash');
    expect(submissionColumnNames).not.toContain('signature');
    expect(submissionColumnNames).not.toContain('raw_transaction');
  });

  it('rejects edits to an already-created policy revision', async () => {
    const organizationId = `revision-${randomUUID()}`;
    const accountId = 'account-fixture';
    const policyId = 'policy-fixture';
    await client.query('INSERT INTO organizations (id, display_name) VALUES ($1, $2)', [organizationId, 'Revision Integration Test']);
    await client.query(
      `INSERT INTO accounts (organization_id, id, chain_id, address, adapter, status, guard_address, module_address, verified_at)
       VALUES ($1, $2, 10143, $3, 'evm-smart-account', 'ACTIVE', $4, $5, now())`,
      [organizationId, accountId, `0x${randomUUID().replaceAll('-', '')}${'d'.repeat(8)}`, `0x${'6'.repeat(40)}`, `0x${'7'.repeat(40)}`],
    );
    await client.query('BEGIN');
    try {
      await client.query(
        'INSERT INTO policies (organization_id, id, account_id, current_revision, state) VALUES ($1, $2, $3, 1, $4)',
        [organizationId, policyId, accountId, 'DRAFT'],
      );
      await client.query(
        `INSERT INTO policy_revisions (organization_id, policy_id, revision, schema_version, canonical_json, revision_hash, created_by, valid_after, expires_at)
         VALUES ($1, $2, 1, 1, '{}'::jsonb, $3, 'owner-fixture', now(), now() + interval '1 hour')`,
        [organizationId, policyId, `0x${randomUUID().replaceAll('-', '').padEnd(64, 'a')}`],
      );
      await client.query('COMMIT');
    } catch (error: unknown) {
      await client.query('ROLLBACK');
      throw error;
    }
    await expect(
      client.query('UPDATE policy_revisions SET created_by = $1 WHERE organization_id = $2 AND policy_id = $3 AND revision = 1', ['tampered', organizationId, policyId]),
    ).rejects.toThrow('policy_revisions is append-only');
  });

  it('rejects audit-event mutation in PostgreSQL', async () => {
    const organizationId = `integration-${randomUUID()}`;
    await client.query('INSERT INTO organizations (id, display_name) VALUES ($1, $2)', [organizationId, 'Integration Test']);
    const inserted = await client.query<{ id: string }>(
      `INSERT INTO audit_events (organization_id, actor_type, actor_id, event_type, subject_type, subject_id, correlation_id, payload, event_hash)
       VALUES ($1, 'TEST', 'fixture', 'TEST_CREATED', 'TEST', 'fixture', $2, '{}'::jsonb, $3) RETURNING id`,
      [organizationId, randomUUID(), `0x${'a'.repeat(64)}`],
    );
    const eventId = inserted.rows[0]?.id;
    expect(eventId).toBeDefined();
    await expect(client.query('UPDATE audit_events SET event_type = $1 WHERE id = $2', ['TAMPERED', eventId])).rejects.toThrow('audit_events is append-only');
    await expect(client.query('DELETE FROM audit_events WHERE id = $1', [eventId])).rejects.toThrow('audit_events is append-only');
  });
});
