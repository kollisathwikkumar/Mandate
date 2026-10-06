ALTER TABLE model_provider_credentials
  ADD COLUMN state text NOT NULL DEFAULT 'ACTIVE' CHECK (state IN ('ACTIVE', 'DISABLED', 'ERROR')),
  ADD COLUMN verified_at timestamptz;
