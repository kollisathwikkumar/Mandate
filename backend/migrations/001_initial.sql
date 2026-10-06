CREATE TABLE organizations (
  id text PRIMARY KEY,
  display_name text NOT NULL CHECK (length(display_name) BETWEEN 1 AND 160),
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE members (
  organization_id text NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  subject text NOT NULL,
  role text NOT NULL CHECK (role IN ('OWNER', 'ADMIN', 'APPROVER', 'VIEWER')),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id, subject)
);

CREATE TABLE agents (
  organization_id text NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  id text NOT NULL,
  display_name text NOT NULL,
  status text NOT NULL CHECK (status IN ('ACTIVE', 'REVOKED')),
  key_version integer NOT NULL CHECK (key_version > 0),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id, id)
);

CREATE TABLE accounts (
  organization_id text NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  id text NOT NULL,
  chain_id bigint NOT NULL CHECK (chain_id > 0),
  address char(42) NOT NULL,
  adapter text NOT NULL,
  status text NOT NULL CHECK (status IN ('ACTIVE', 'PAUSED', 'UNSUPPORTED')),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id, id),
  UNIQUE (chain_id, address)
);

CREATE TABLE policies (
  organization_id text NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  id text NOT NULL,
  account_id text NOT NULL,
  current_revision integer NOT NULL CHECK (current_revision > 0),
  state text NOT NULL CHECK (state IN ('DRAFT', 'ACTIVE', 'REVOKED', 'EXPIRED')),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id, id),
  FOREIGN KEY (organization_id, account_id) REFERENCES accounts(organization_id, id)
);

CREATE TABLE policy_revisions (
  organization_id text NOT NULL,
  policy_id text NOT NULL,
  revision integer NOT NULL CHECK (revision > 0),
  schema_version integer NOT NULL,
  canonical_json jsonb NOT NULL,
  revision_hash char(66) NOT NULL UNIQUE,
  created_by text NOT NULL,
  valid_after timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id, policy_id, revision),
  FOREIGN KEY (organization_id, policy_id) REFERENCES policies(organization_id, id),
  CHECK (expires_at > valid_after)
);

CREATE TABLE policy_grants (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id text NOT NULL,
  policy_id text NOT NULL,
  policy_revision integer NOT NULL,
  account_id text NOT NULL,
  adapter text NOT NULL,
  grant_reference text NOT NULL,
  state text NOT NULL CHECK (state IN ('PENDING', 'ACTIVE', 'REVOKED', 'FAILED')),
  granted_at timestamptz,
  revoked_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (organization_id, policy_id, policy_revision) REFERENCES policy_revisions(organization_id, policy_id, revision),
  FOREIGN KEY (organization_id, account_id) REFERENCES accounts(organization_id, id),
  CHECK ((state <> 'ACTIVE') OR granted_at IS NOT NULL)
);

CREATE TABLE model_provider_credentials (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id text NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  provider text NOT NULL CHECK (provider IN ('DEEPSEEK', 'OPENAI', 'ANTHROPIC', 'OTHER')),
  secret_reference text NOT NULL,
  masked_suffix text NOT NULL CHECK (length(masked_suffix) <= 8),
  created_by text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  rotated_at timestamptz,
  disabled_at timestamptz,
  UNIQUE (organization_id, provider)
);

ALTER TABLE policies ADD CONSTRAINT policies_current_revision_fk
  FOREIGN KEY (organization_id, id, current_revision)
  REFERENCES policy_revisions(organization_id, policy_id, revision)
  DEFERRABLE INITIALLY DEFERRED;

CREATE TABLE approvals (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id text NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  action_id text NOT NULL,
  action_hash char(66) NOT NULL,
  approver_subject text NOT NULL,
  outcome text NOT NULL CHECK (outcome IN ('APPROVED', 'DENIED')),
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (organization_id, action_id, approver_subject)
);

CREATE TABLE action_requests (
  organization_id text NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  id text NOT NULL,
  policy_id text NOT NULL,
  policy_revision integer NOT NULL,
  idempotency_key text NOT NULL,
  request_hash char(66) NOT NULL,
  action_json jsonb NOT NULL,
  state text NOT NULL CHECK (state IN ('RECEIVED','VALIDATED','QUOTED','EVALUATED','BLOCKED','HELD','APPROVED','DENIED','EXPIRED','ALLOWED','RESERVED','AUTHORIZED','SUBMITTED','CONFIRMED','REVERTED','DROPPED','RECONCILED')),
  verdict text CHECK (verdict IN ('ALLOW', 'BLOCK', 'HOLD')),
  reason_code text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id, id),
  UNIQUE (organization_id, idempotency_key),
  FOREIGN KEY (organization_id, policy_id, policy_revision) REFERENCES policy_revisions(organization_id, policy_id, revision)
);

CREATE TABLE decisions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id text NOT NULL,
  action_id text NOT NULL,
  policy_revision_hash char(66) NOT NULL,
  verdict text NOT NULL CHECK (verdict IN ('ALLOW', 'BLOCK', 'HOLD')),
  reason_code text NOT NULL,
  evaluated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (organization_id, action_id),
  FOREIGN KEY (organization_id, action_id) REFERENCES action_requests(organization_id, id)
);

ALTER TABLE approvals ADD CONSTRAINT approvals_action_fk
  FOREIGN KEY (organization_id, action_id) REFERENCES action_requests(organization_id, id);

CREATE TABLE reservations (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id text NOT NULL,
  action_id text NOT NULL,
  amount numeric(78,0) NOT NULL CHECK (amount > 0),
  state text NOT NULL CHECK (state IN ('ACTIVE', 'CONSUMED', 'RELEASED', 'EXPIRED')),
  lease_expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (organization_id, action_id),
  FOREIGN KEY (organization_id, action_id) REFERENCES action_requests(organization_id, id)
);

CREATE TABLE execution_attempts (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id text NOT NULL,
  action_id text NOT NULL,
  attempt_number integer NOT NULL CHECK (attempt_number > 0),
  chain_id bigint NOT NULL CHECK (chain_id > 0),
  transaction_hash char(66),
  state text NOT NULL CHECK (state IN ('AUTHORIZED','SUBMITTED','CONFIRMED','REVERTED','DROPPED','REORGED')),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (organization_id, action_id, attempt_number),
  FOREIGN KEY (organization_id, action_id) REFERENCES action_requests(organization_id, id)
);

CREATE TABLE receipts (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id text NOT NULL,
  action_id text NOT NULL,
  chain_id bigint NOT NULL CHECK (chain_id > 0),
  transaction_hash char(66) NOT NULL,
  block_number bigint NOT NULL CHECK (block_number >= 0),
  block_hash char(66) NOT NULL,
  status text NOT NULL CHECK (status IN ('TENTATIVE','FINAL','REORGED')),
  receipt_json jsonb NOT NULL,
  observed_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (chain_id, transaction_hash),
  FOREIGN KEY (organization_id, action_id) REFERENCES action_requests(organization_id, id)
);

CREATE TABLE audit_events (
  sequence bigserial PRIMARY KEY,
  id uuid NOT NULL DEFAULT gen_random_uuid() UNIQUE,
  organization_id text NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  actor_type text NOT NULL,
  actor_id text NOT NULL,
  event_type text NOT NULL,
  subject_type text NOT NULL,
  subject_id text NOT NULL,
  correlation_id text NOT NULL,
  payload jsonb NOT NULL,
  previous_hash char(66),
  event_hash char(66) NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE outbox_events (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id text NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  aggregate_type text NOT NULL,
  aggregate_id text NOT NULL,
  event_type text NOT NULL,
  payload jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  available_at timestamptz NOT NULL DEFAULT now(),
  attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
  locked_at timestamptz,
  delivered_at timestamptz,
  last_error_code text
);
CREATE INDEX outbox_events_ready_idx ON outbox_events (available_at, created_at) WHERE delivered_at IS NULL;

CREATE TABLE webhook_endpoints (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id text NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  url text NOT NULL,
  signing_secret_ref text NOT NULL,
  event_types text[] NOT NULL,
  enabled boolean NOT NULL DEFAULT true,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE indexer_cursors (
  chain_id bigint PRIMARY KEY CHECK (chain_id > 0),
  next_block bigint NOT NULL CHECK (next_block >= 0),
  finalized_block bigint NOT NULL CHECK (finalized_block >= 0),
  block_hash char(66),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CHECK (finalized_block <= next_block)
);

CREATE FUNCTION reject_immutable_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION '% is append-only', TG_TABLE_NAME;
END;
$$;
CREATE TRIGGER audit_events_no_update BEFORE UPDATE OR DELETE ON audit_events
  FOR EACH ROW EXECUTE FUNCTION reject_immutable_mutation();
CREATE TRIGGER policy_revisions_no_update BEFORE UPDATE OR DELETE ON policy_revisions
  FOR EACH ROW EXECUTE FUNCTION reject_immutable_mutation();
