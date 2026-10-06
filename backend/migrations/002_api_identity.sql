CREATE TABLE agent_credentials (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id text NOT NULL,
  agent_id text NOT NULL,
  key_version integer NOT NULL CHECK (key_version > 0),
  secret_hash char(64) NOT NULL UNIQUE,
  created_by text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz,
  revoked_at timestamptz,
  FOREIGN KEY (organization_id, agent_id) REFERENCES agents(organization_id, id),
  UNIQUE (organization_id, agent_id, key_version)
);

CREATE TABLE command_idempotency (
  organization_id text NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  principal_id text NOT NULL,
  idempotency_key text NOT NULL CHECK (length(idempotency_key) BETWEEN 1 AND 200),
  request_hash char(66) NOT NULL,
  response_json jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL DEFAULT now() + interval '24 hours',
  PRIMARY KEY (organization_id, principal_id, idempotency_key),
  CHECK (request_hash ~ '^0x[0-9a-f]{64}$')
);

CREATE INDEX agent_credentials_active_idx ON agent_credentials (secret_hash) WHERE revoked_at IS NULL;
CREATE INDEX command_idempotency_expiry_idx ON command_idempotency (expires_at);
