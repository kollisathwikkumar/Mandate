ALTER TABLE action_execution_submissions
  ADD COLUMN outer_sender char(42),
  ADD COLUMN outer_nonce bigint,
  ADD CONSTRAINT action_execution_submission_outer_tx_pair_chk
    CHECK ((outer_sender IS NULL AND outer_nonce IS NULL)
      OR (outer_sender ~ '^0x[0-9a-f]{40}$' AND outer_nonce IS NOT NULL AND outer_nonce >= 0));

CREATE INDEX action_execution_submission_outer_nonce_idx
  ON action_execution_submissions (organization_id, outer_sender, outer_nonce)
  WHERE outer_sender IS NOT NULL AND outer_nonce IS NOT NULL;

ALTER TABLE indexer_cursors
  ADD COLUMN indexed_from_block bigint,
  ADD CONSTRAINT indexer_cursors_indexed_from_block_chk
    CHECK (indexed_from_block IS NULL OR indexed_from_block >= 1);
