CREATE TABLE organization_creation_idempotency (
  principal_id text NOT NULL,
  idempotency_key text NOT NULL,
  request_hash char(66) NOT NULL,
  organization_id text NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  response_json jsonb NOT NULL,
  expires_at timestamptz NOT NULL DEFAULT (now() + interval '24 hours'),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (principal_id, idempotency_key)
);
CREATE INDEX organization_creation_idempotency_expiry_idx ON organization_creation_idempotency (expires_at);
