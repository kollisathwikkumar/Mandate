CREATE TABLE policy_activation_plans (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id text NOT NULL,
  policy_id text NOT NULL,
  policy_revision integer NOT NULL CHECK (policy_revision > 0),
  revision_hash char(66) NOT NULL,
  created_by text NOT NULL,
  state text NOT NULL CHECK (state IN ('AWAITING_SAFE_OWNER_SIGNATURES', 'SUBMITTED', 'CONFIRMED', 'FAILED', 'SUPERSEDED')),
  plan_json jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (organization_id, policy_id, policy_revision),
  FOREIGN KEY (organization_id, policy_id, policy_revision)
    REFERENCES policy_revisions(organization_id, policy_id, revision)
);

CREATE UNIQUE INDEX policy_grants_one_pending_revision_idx
  ON policy_grants (organization_id, policy_id, policy_revision)
  WHERE state = 'PENDING';

CREATE INDEX policy_activation_plans_state_idx
  ON policy_activation_plans (state, created_at);
