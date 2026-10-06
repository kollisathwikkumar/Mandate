CREATE TABLE invitation_email_deliveries (
  invitation_id uuid PRIMARY KEY REFERENCES organization_invitations(id) ON DELETE CASCADE,
  status text NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'DELIVERED', 'FAILED', 'CANCELLED')),
  token_ciphertext text,
  attempts integer NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 12),
  available_at timestamptz NOT NULL DEFAULT now(),
  locked_at timestamptz,
  sent_at timestamptz,
  last_error_code text CHECK (last_error_code IS NULL OR last_error_code IN ('EMAIL_DELIVERY_FAILED')),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CHECK ((status = 'PENDING') = (token_ciphertext IS NOT NULL)),
  CHECK ((status = 'DELIVERED') = (sent_at IS NOT NULL))
);

CREATE INDEX invitation_email_deliveries_ready_idx
  ON invitation_email_deliveries (available_at, created_at)
  WHERE status = 'PENDING';
