CREATE TABLE alert_notifications (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id text NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  outbox_event_id uuid NOT NULL UNIQUE REFERENCES outbox_events(id) ON DELETE CASCADE,
  event_type text NOT NULL,
  title text NOT NULL,
  aggregate_id text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX alert_notifications_org_created_idx
  ON alert_notifications (organization_id, created_at DESC, id DESC);
