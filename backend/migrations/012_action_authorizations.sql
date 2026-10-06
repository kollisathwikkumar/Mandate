CREATE TABLE action_authorizations (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id text NOT NULL,
  action_id text NOT NULL,
  idempotency_key text NOT NULL CHECK (length(idempotency_key) BETWEEN 1 AND 200),
  request_hash char(66) NOT NULL CHECK (request_hash ~ '^0x[0-9a-f]{64}$'),
  action_hash char(66) NOT NULL CHECK (action_hash ~ '^0x[0-9a-f]{64}$'),
  policy_revision_hash char(66) NOT NULL CHECK (policy_revision_hash ~ '^0x[0-9a-f]{64}$'),
  chain_id bigint NOT NULL CHECK (chain_id > 0),
  snapshot_block_number bigint NOT NULL CHECK (snapshot_block_number >= 0),
  snapshot_block_hash char(66) NOT NULL CHECK (snapshot_block_hash ~ '^0x[0-9a-f]{64}$'),
  execution_nonce numeric(78, 0) NOT NULL CHECK (execution_nonce >= 0),
  status text NOT NULL CHECK (status IN ('ACTIVE', 'CONSUMED', 'EXPIRED', 'SUPERSEDED')),
  authorization_json jsonb NOT NULL,
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (organization_id, action_id),
  FOREIGN KEY (organization_id, action_id) REFERENCES action_requests(organization_id, id)
);

CREATE INDEX action_authorizations_active_idx
  ON action_authorizations (status, expires_at)
  WHERE status = 'ACTIVE';
