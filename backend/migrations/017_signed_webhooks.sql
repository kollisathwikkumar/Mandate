ALTER TABLE webhook_endpoints
  ALTER COLUMN signing_secret_ref DROP NOT NULL,
  ADD COLUMN updated_at timestamptz NOT NULL DEFAULT now(),
  ADD COLUMN deleted_at timestamptz,
  ADD CONSTRAINT webhook_endpoints_event_types_nonempty_chk CHECK (cardinality(event_types) BETWEEN 1 AND 30),
  ADD CONSTRAINT webhook_endpoints_org_id_uq UNIQUE (organization_id, id);

ALTER TABLE outbox_events ADD CONSTRAINT outbox_events_org_id_uq UNIQUE (organization_id, id);

CREATE TABLE webhook_deliveries (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id text NOT NULL,
  endpoint_id uuid NOT NULL,
  outbox_event_id uuid NOT NULL,
  status text NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'DELIVERED', 'FAILED')),
  attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
  available_at timestamptz NOT NULL DEFAULT now(),
  locked_at timestamptz,
  delivered_at timestamptz,
  last_error_code text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (endpoint_id, outbox_event_id),
  FOREIGN KEY (organization_id, endpoint_id) REFERENCES webhook_endpoints(organization_id, id),
  FOREIGN KEY (organization_id, outbox_event_id) REFERENCES outbox_events(organization_id, id),
  CHECK ((status = 'DELIVERED' AND delivered_at IS NOT NULL AND locked_at IS NULL)
      OR (status <> 'DELIVERED' AND delivered_at IS NULL))
);

CREATE INDEX webhook_deliveries_ready_idx
  ON webhook_deliveries (available_at, created_at)
  WHERE status = 'PENDING';

CREATE INDEX webhook_deliveries_endpoint_idx
  ON webhook_deliveries (organization_id, endpoint_id, created_at DESC);
