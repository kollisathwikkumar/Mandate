CREATE TABLE action_nonce_counters (
  organization_id text NOT NULL,
  policy_id text NOT NULL,
  agent_id text NOT NULL,
  agent_key_version integer NOT NULL CHECK (agent_key_version > 0),
  nonce_epoch integer NOT NULL CHECK (nonce_epoch >= 0),
  next_nonce bigint NOT NULL CHECK (next_nonce >= 0),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id, policy_id, agent_id, agent_key_version, nonce_epoch),
  FOREIGN KEY (organization_id, policy_id) REFERENCES policies(organization_id, id),
  FOREIGN KEY (organization_id, agent_id) REFERENCES agents(organization_id, id)
);
