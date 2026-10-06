ALTER TABLE policy_activation_plans
  ADD COLUMN finalized_block_number bigint CHECK (finalized_block_number IS NULL OR finalized_block_number >= 0),
  ADD COLUMN finalized_receipts jsonb,
  ADD COLUMN confirmed_at timestamptz,
  ADD CONSTRAINT policy_activation_confirmed_evidence_check CHECK (
    (state = 'CONFIRMED' AND finalized_block_number IS NOT NULL AND finalized_receipts IS NOT NULL AND confirmed_at IS NOT NULL)
    OR (state <> 'CONFIRMED' AND finalized_block_number IS NULL AND finalized_receipts IS NULL AND confirmed_at IS NULL)
  );

CREATE TABLE policy_activation_receipts (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  plan_id uuid NOT NULL REFERENCES policy_activation_plans(id),
  chain_id bigint NOT NULL CHECK (chain_id > 0),
  safe_tx_hash char(66) NOT NULL,
  transaction_hash char(66) NOT NULL,
  block_number bigint NOT NULL CHECK (block_number >= 0),
  block_hash char(66) NOT NULL,
  transaction_index integer NOT NULL CHECK (transaction_index >= 0),
  confirmations integer NOT NULL CHECK (confirmations > 0),
  status text NOT NULL CHECK (status = 'FINAL'),
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (plan_id, safe_tx_hash),
  UNIQUE (chain_id, transaction_hash)
);

CREATE INDEX policy_activation_receipts_plan_idx
  ON policy_activation_receipts (plan_id, block_number, transaction_index);
