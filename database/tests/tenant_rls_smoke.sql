-- Run against a disposable lab database after migrations and runtime grants.
-- Execute as a database administrator who may SET ROLE onishield_app.
-- This test rolls back all inserted rows.
BEGIN;
SET LOCAL ROLE onishield_app;
SELECT set_config('app.tenant_id', 'rls-tenant-a', true);

INSERT INTO onishield.security_events
  (tenant_id, connector_id, event_id, schema_version, event_type,
   observed_at, ingested_at, severity_hint, event_json, payload_sha256)
VALUES
  ('rls-tenant-a', 'rls-smoke-connector', 'rls-smoke-event-a',
   '0.1.0', 'identity.authentication.failure', NOW(), NOW(), 'low',
   '{"test":"tenant-isolation"}'::jsonb, repeat('a', 64));

SELECT set_config('app.tenant_id', 'rls-tenant-b', true);

DO $$
DECLARE
  visible_rows INTEGER;
BEGIN
  SELECT count(*) INTO visible_rows
    FROM onishield.security_events
   WHERE event_id = 'rls-smoke-event-a';

  IF visible_rows <> 0 THEN
    RAISE EXCEPTION 'Tenant isolation failed: tenant B can read tenant A data';
  END IF;

  BEGIN
    INSERT INTO onishield.security_events
      (tenant_id, connector_id, event_id, schema_version, event_type,
       observed_at, ingested_at, severity_hint, event_json, payload_sha256)
    VALUES
      ('rls-tenant-a', 'rls-smoke-connector', 'rls-smoke-event-b',
       '0.1.0', 'identity.authentication.failure', NOW(), NOW(), 'low',
       '{"test":"cross-tenant-write"}'::jsonb, repeat('b', 64));

    RAISE EXCEPTION 'Tenant isolation failed: tenant B inserted tenant A data';
  EXCEPTION
    WHEN insufficient_privilege THEN
      NULL;
  END;
END
$$;

ROLLBACK;
