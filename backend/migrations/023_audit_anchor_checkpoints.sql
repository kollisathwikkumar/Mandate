CREATE TABLE audit_anchor_checkpoints (
  organization_id text NOT NULL,
  checkpoint_sequence bigint NOT NULL CHECK (checkpoint_sequence > 0),
  event_hash char(66) NOT NULL CHECK (event_hash ~ '^0x[0-9a-f]{64}$'),
  previous_checkpoint_hash char(64) CHECK (previous_checkpoint_hash IS NULL OR previous_checkpoint_hash ~ '^[0-9a-f]{64}$'),
  checkpoint_hash char(64) NOT NULL CHECK (checkpoint_hash ~ '^[0-9a-f]{64}$'),
  object_key text NOT NULL,
  object_version_id text NOT NULL,
  key_id text NOT NULL,
  key_fingerprint char(64) NOT NULL CHECK (key_fingerprint ~ '^[0-9a-f]{64}$'),
  signature text NOT NULL,
  retained_until timestamptz NOT NULL,
  anchored_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id, checkpoint_sequence),
  UNIQUE (object_key, object_version_id)
);
CREATE INDEX audit_anchor_checkpoints_latest_idx
  ON audit_anchor_checkpoints (organization_id, checkpoint_sequence DESC);

CREATE TRIGGER audit_anchor_checkpoints_no_update BEFORE UPDATE OR DELETE ON audit_anchor_checkpoints
  FOR EACH ROW EXECUTE FUNCTION reject_immutable_mutation();

CREATE FUNCTION reject_immutable_truncate() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION '% is append-only', TG_TABLE_NAME;
END;
$$;

CREATE TRIGGER audit_events_no_truncate BEFORE TRUNCATE ON audit_events
  FOR EACH STATEMENT EXECUTE FUNCTION reject_immutable_truncate();
CREATE TRIGGER audit_anchor_checkpoints_no_truncate BEFORE TRUNCATE ON audit_anchor_checkpoints
  FOR EACH STATEMENT EXECUTE FUNCTION reject_immutable_truncate();
