CREATE TABLE organization_invitations (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id text NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  email text NOT NULL CHECK (email = lower(email) AND length(email) BETWEEN 3 AND 254),
  role text NOT NULL CHECK (role IN ('OWNER', 'ADMIN', 'APPROVER', 'VIEWER')),
  token_hash char(66) NOT NULL UNIQUE,
  created_by text NOT NULL,
  idempotency_key text NOT NULL,
  request_hash char(66) NOT NULL,
  response_json jsonb NOT NULL,
  state text NOT NULL DEFAULT 'PENDING' CHECK (state IN ('PENDING', 'ACCEPTED', 'REVOKED', 'EXPIRED')),
  expires_at timestamptz NOT NULL DEFAULT (now() + interval '7 days'),
  accepted_by text,
  accepted_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (organization_id, created_by, idempotency_key),
  CHECK ((state = 'ACCEPTED') = (accepted_by IS NOT NULL AND accepted_at IS NOT NULL))
);
CREATE INDEX organization_invitations_pending_idx ON organization_invitations (organization_id, created_at DESC) WHERE state = 'PENDING';
