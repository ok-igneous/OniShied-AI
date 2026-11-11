ALTER TABLE onishield.security_events
  ADD COLUMN IF NOT EXISTS payload_sha256 TEXT;

ALTER TABLE onishield.security_events
  ADD CONSTRAINT security_events_payload_sha256_format
  CHECK (payload_sha256 IS NULL OR payload_sha256 ~ '^[a-f0-9]{64}$');

ALTER TABLE onishield.security_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE onishield.security_events FORCE ROW LEVEL SECURITY;

CREATE POLICY security_events_tenant_isolation
  ON onishield.security_events
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
