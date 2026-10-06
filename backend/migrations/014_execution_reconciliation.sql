CREATE INDEX execution_attempts_submitted_reconciliation_idx
  ON execution_attempts (updated_at, chain_id)
  WHERE state = 'SUBMITTED' AND transaction_hash IS NOT NULL;

CREATE INDEX receipts_action_status_idx
  ON receipts (organization_id, action_id, status, observed_at DESC);
