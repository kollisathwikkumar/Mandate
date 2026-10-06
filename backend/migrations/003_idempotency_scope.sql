ALTER TABLE command_idempotency ADD COLUMN scope text NOT NULL DEFAULT 'legacy';
ALTER TABLE command_idempotency DROP CONSTRAINT command_idempotency_pkey;
ALTER TABLE command_idempotency ADD CONSTRAINT command_idempotency_pkey
  PRIMARY KEY (organization_id, principal_id, scope, idempotency_key);
ALTER TABLE command_idempotency ADD CONSTRAINT command_idempotency_scope_length
  CHECK (length(scope) BETWEEN 1 AND 128);
