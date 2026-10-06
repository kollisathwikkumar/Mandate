CREATE TABLE api_rate_limit_windows (
  subject_hash text NOT NULL CHECK (subject_hash ~ '^[0-9a-f]{64}$'),
  window_start timestamptz NOT NULL,
  request_count integer NOT NULL CHECK (request_count > 0),
  PRIMARY KEY (subject_hash, window_start)
);

CREATE INDEX api_rate_limit_windows_expiry_idx
  ON api_rate_limit_windows (window_start);
