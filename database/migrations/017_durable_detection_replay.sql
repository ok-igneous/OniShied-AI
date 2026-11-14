-- Durable tenant-scoped detection work. Event persistence and enqueue happen in one transaction.
BEGIN;

CREATE TABLE onishield.detection_replay_jobs (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  connector_id TEXT NOT NULL,
  event_id TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending'
    CHECK (status IN ('pending', 'processing', 'completed', 'dead_letter')),
  attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
  available_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  lease_until TIMESTAMPTZ,
  lease_token UUID,
  last_error TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  completed_at TIMESTAMPTZ,
  CONSTRAINT detection_replay_jobs_event_unique
    UNIQUE (tenant_id, connector_id, event_id),
  CONSTRAINT detection_replay_jobs_event_fk
    FOREIGN KEY (tenant_id, connector_id, event_id)
    REFERENCES onishield.security_events (tenant_id, connector_id, event_id),
  CONSTRAINT detection_replay_jobs_lease_consistency CHECK (
    (status = 'processing' AND lease_until IS NOT NULL AND lease_token IS NOT NULL)
    OR (status <> 'processing' AND lease_until IS NULL AND lease_token IS NULL)
  )
);

CREATE INDEX detection_replay_jobs_claim_idx
  ON onishield.detection_replay_jobs (tenant_id, available_at, id)
  WHERE status IN ('pending', 'processing');

CREATE INDEX detection_replay_jobs_completed_idx
  ON onishield.detection_replay_jobs (tenant_id, completed_at DESC)
  WHERE status = 'completed';

GRANT SELECT, INSERT, UPDATE ON onishield.detection_replay_jobs TO onishield_app;
GRANT USAGE, SELECT ON SEQUENCE onishield.detection_replay_jobs_id_seq TO onishield_app;

-- FORCE RLS also applies to the table owner. Temporarily remove FORCE from
-- the source table inside this transaction so the migration owner can seed
-- jobs for historical rows. Restore FORCE before committing the migration.
ALTER TABLE onishield.security_events NO FORCE ROW LEVEL SECURITY;
INSERT INTO onishield.detection_replay_jobs (tenant_id, connector_id, event_id)
SELECT tenant_id, connector_id, event_id
FROM onishield.security_events
ON CONFLICT (tenant_id, connector_id, event_id) DO NOTHING;
ALTER TABLE onishield.security_events FORCE ROW LEVEL SECURITY;

ALTER TABLE onishield.detection_replay_jobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE onishield.detection_replay_jobs FORCE ROW LEVEL SECURITY;
CREATE POLICY detection_replay_jobs_tenant_isolation
  ON onishield.detection_replay_jobs
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

COMMIT;
