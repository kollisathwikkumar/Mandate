ALTER TABLE action_requests DROP CONSTRAINT action_requests_state_check;
ALTER TABLE action_requests ADD CONSTRAINT action_requests_state_check
  CHECK (state IN ('RECEIVED','VALIDATED','QUOTED','EVALUATED','BLOCKED','HELD','APPROVED','DENIED','EXPIRED',
    'ALLOWED','RESERVED','AUTHORIZED','SUBMITTED','CONFIRMED','REVERTED','DROPPED','REORGED','RECONCILED'));

ALTER TABLE receipts ADD COLUMN deep_reorg_checked_at timestamptz;

CREATE INDEX receipts_deep_reorg_scan_idx
  ON receipts (deep_reorg_checked_at NULLS FIRST, block_number)
  WHERE status = 'FINAL';
