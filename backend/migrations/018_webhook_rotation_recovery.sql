ALTER TABLE webhook_endpoints
  ADD COLUMN previous_signing_secret_ref text;

COMMENT ON COLUMN webhook_endpoints.previous_signing_secret_ref IS
  'Secret-manager reference awaiting cleanup after rotation; never used for signing or returned by the API.';
