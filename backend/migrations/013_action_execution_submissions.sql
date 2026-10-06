CREATE TABLE action_execution_submissions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id text NOT NULL,
  action_id text NOT NULL,
  agent_id text NOT NULL,
  idempotency_key text NOT NULL CHECK (length(idempotency_key) BETWEEN 1 AND 200),
  request_hash char(66) NOT NULL CHECK (request_hash ~ '^0x[0-9a-f]{64}$'),
  transaction_hash char(66) NOT NULL CHECK (transaction_hash ~ '^0x[0-9a-f]{64}$'),
  status text NOT NULL CHECK (status IN ('PENDING', 'SUBMITTED')),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  submitted_at timestamptz,
  UNIQUE (organization_id, action_id),
  UNIQUE (organization_id, agent_id, idempotency_key),
  FOREIGN KEY (organization_id, action_id) REFERENCES action_requests(organization_id, id),
  FOREIGN KEY (organization_id, agent_id) REFERENCES agents(organization_id, id),
  CHECK ((status = 'PENDING' AND submitted_at IS NULL) OR (status = 'SUBMITTED' AND submitted_at IS NOT NULL))
);

CREATE INDEX action_execution_submissions_pending_idx
  ON action_execution_submissions (updated_at)
  WHERE status = 'PENDING';
