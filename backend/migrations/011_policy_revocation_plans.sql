CREATE TABLE policy_revocation_plans (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id text NOT NULL,
  policy_id text NOT NULL,
  policy_revision integer NOT NULL CHECK (policy_revision > 0),
  revision_hash char(66) NOT NULL,
  created_by text NOT NULL,
  state text NOT NULL CHECK (state IN ('AWAITING_SAFE_OWNER_SIGNATURES', 'CONFIRMED', 'SUPERSEDED')),
  plan_json jsonb NOT NULL,
  finalized_block_number bigint CHECK (finalized_block_number IS NULL OR finalized_block_number >= 0),
  finalized_receipt jsonb,
  confirmed_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (organization_id, policy_id, policy_revision),
  FOREIGN KEY (organization_id, policy_id, policy_revision)
    REFERENCES policy_revisions(organization_id, policy_id, revision),
  CHECK (
    (state = 'CONFIRMED' AND finalized_block_number IS NOT NULL AND finalized_receipt IS NOT NULL AND confirmed_at IS NOT NULL)
    OR (state <> 'CONFIRMED' AND finalized_block_number IS NULL AND finalized_receipt IS NULL AND confirmed_at IS NULL)
  )
);

CREATE INDEX policy_revocation_plans_state_idx
  ON policy_revocation_plans (state, created_at);

CREATE TABLE policy_revocation_receipts (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  plan_id uuid NOT NULL REFERENCES policy_revocation_plans(id),
  chain_id bigint NOT NULL CHECK (chain_id > 0),
  safe_tx_hash char(66) NOT NULL,
  transaction_hash char(66) NOT NULL,
  block_number bigint NOT NULL CHECK (block_number >= 0),
  block_hash char(66) NOT NULL,
  transaction_index integer NOT NULL CHECK (transaction_index >= 0),
  confirmations integer NOT NULL CHECK (confirmations > 0),
  status text NOT NULL CHECK (status = 'FINAL'),
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (plan_id),
  UNIQUE (chain_id, transaction_hash)
);
