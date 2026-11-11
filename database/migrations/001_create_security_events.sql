CREATE SCHEMA IF NOT EXISTS onishield;

CREATE TABLE IF NOT EXISTS onishield.security_events (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  connector_id TEXT NOT NULL,
  event_id TEXT NOT NULL,
  schema_version TEXT NOT NULL,
  event_type TEXT NOT NULL,
  observed_at TIMESTAMPTZ NOT NULL,
  ingested_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  severity_hint TEXT NOT NULL DEFAULT 'unknown'
    CHECK (severity_hint IN ('unknown', 'info', 'low', 'medium', 'high', 'critical')),
  event_json JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT security_events_idempotency_key
    UNIQUE (tenant_id, connector_id, event_id)
);

CREATE INDEX IF NOT EXISTS security_events_tenant_observed_idx
  ON onishield.security_events (tenant_id, observed_at DESC);

CREATE INDEX IF NOT EXISTS security_events_tenant_type_idx
  ON onishield.security_events (tenant_id, event_type);
