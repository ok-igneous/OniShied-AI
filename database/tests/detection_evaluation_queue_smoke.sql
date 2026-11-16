-- Run as database administrator after migration 016 and runtime grants.
-- Verifies durable queue idempotency and tenant isolation.
BEGIN;
SET LOCAL ROLE onishield_app;
SELECT set_config('app.tenant_id', 'queue-tenant-a', true);

INSERT INTO onishield.security_events
  (tenant_id, connector_id, event_id, schema_version, event_type,
   observed_at, ingested_at, severity_hint, event_json, payload_sha256)
VALUES
  ('queue-tenant-a', 'queue-connector', 'queue-event-a', '1.0',
   'synthetic.test', NOW(), NOW(), 'unknown', '{}'::jsonb, repeat('a', 64));

INSERT INTO onishield.detection_evaluation_jobs
  (tenant_id, connector_id, event_id)
VALUES ('queue-tenant-a', 'queue-connector', 'queue-event-a')
ON CONFLICT (tenant_id, connector_id, event_id) DO NOTHING;

INSERT INTO onishield.detection_evaluation_jobs
  (tenant_id, connector_id, event_id)
VALUES ('queue-tenant-a', 'queue-connector', 'queue-event-a')
ON CONFLICT (tenant_id, connector_id, event_id) DO NOTHING;

DO $$
DECLARE row_count INTEGER;
BEGIN
  SELECT count(*) INTO row_count FROM onishield.detection_evaluation_jobs;
  IF row_count <> 1 THEN
    RAISE EXCEPTION 'Detection queue enqueue is not idempotent';
  END IF;
END $$;

SELECT set_config('app.tenant_id', 'queue-tenant-b', true);
DO $$
DECLARE row_count INTEGER;
BEGIN
  SELECT count(*) INTO row_count FROM onishield.detection_evaluation_jobs;
  IF row_count <> 0 THEN
    RAISE EXCEPTION 'Detection queue RLS failed: cross-tenant row visible';
  END IF;
END $$;
ROLLBACK;
