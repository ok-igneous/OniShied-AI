-- Durable, tenant-scoped detection work. Queue insertion must share the
-- transaction that accepts the canonical event.
BEGIN;

CREATE TABLE onishield.detection_evaluation_jobs (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  connector_id TEXT NOT NULL,
  event_id TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending'
    CHECK (status IN ('pending', 'processing', 'completed', 'dead_letter')),
  attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
  available_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  locked_at TIMESTAMPTZ,
  last_error_code TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  completed_at TIMESTAMPTZ,
  CONSTRAINT detection_evaluation_jobs_event_fk
    FOREIGN KEY (tenant_id, connector_id, event_id)
    REFERENCES onishield.security_events (tenant_id, connector_id, event_id)
    ON DELETE CASCADE,
  CONSTRAINT detection_evaluation_jobs_event_unique
    UNIQUE (tenant_id, connector_id, event_id),
  CONSTRAINT detection_evaluation_jobs_lease_state
    CHECK ((status = 'processing') = (locked_at IS NOT NULL))
);

CREATE INDEX detection_evaluation_jobs_claim_idx
  ON onishield.detection_evaluation_jobs (tenant_id, available_at, id)
  WHERE status IN ('pending', 'processing');

ALTER TABLE onishield.detection_evaluation_jobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE onishield.detection_evaluation_jobs FORCE ROW LEVEL SECURITY;

CREATE POLICY detection_evaluation_jobs_tenant_isolation
  ON onishield.detection_evaluation_jobs
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

GRANT SELECT, INSERT, UPDATE ON onishield.detection_evaluation_jobs TO onishield_app;
GRANT USAGE, SELECT ON SEQUENCE
  onishield.detection_evaluation_jobs_id_seq TO onishield_app;

COMMIT;
