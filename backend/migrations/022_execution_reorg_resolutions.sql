CREATE TABLE execution_reorg_resolutions (
  organization_id text NOT NULL,
  action_id text NOT NULL,
  actor_subject text NOT NULL,
  disposition text NOT NULL CHECK (disposition IN ('CONSUMED', 'RELEASED')),
  reason text NOT NULL CHECK (length(btrim(reason)) BETWEEN 1 AND 1000),
  evidence_hash char(66) CHECK (evidence_hash IS NULL OR evidence_hash ~ '^0x[0-9a-f]{64}$'),
  block_number bigint NOT NULL CHECK (block_number >= 0),
  previous_block_hash char(66) NOT NULL CHECK (previous_block_hash ~ '^0x[0-9a-f]{64}$'),
  canonical_block_hash char(66) NOT NULL CHECK (canonical_block_hash ~ '^0x[0-9a-f]{64}$'),
  idempotency_key text NOT NULL CHECK (length(idempotency_key) BETWEEN 1 AND 200),
  request_hash char(66) NOT NULL CHECK (request_hash ~ '^0x[0-9a-f]{64}$'),
  resolved_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id, action_id),
  UNIQUE (organization_id, actor_subject, idempotency_key),
  FOREIGN KEY (organization_id, action_id) REFERENCES action_requests(organization_id, id)
);

CREATE TRIGGER execution_reorg_resolutions_no_update
  BEFORE UPDATE OR DELETE ON execution_reorg_resolutions
  FOR EACH ROW EXECUTE FUNCTION reject_immutable_mutation();

CREATE INDEX execution_reorg_resolutions_actor_idx
  ON execution_reorg_resolutions (organization_id, actor_subject, resolved_at DESC);
