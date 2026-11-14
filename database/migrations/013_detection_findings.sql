CREATE TABLE onishield.detection_findings (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  finding_id TEXT NOT NULL,
  rule_id TEXT NOT NULL CHECK (rule_id IN ('AUTH_FAILURE_BURST', 'AUTH_FAILURE_THEN_SUCCESS')),
  rule_version TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('open', 'suppressed', 'resolved')),
  title TEXT NOT NULL,
  explanation TEXT NOT NULL,
  severity TEXT NOT NULL CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical')),
  confidence TEXT NOT NULL CHECK (confidence IN ('low', 'medium', 'high')),
  first_seen_at TIMESTAMPTZ NOT NULL,
  last_seen_at TIMESTAMPTZ NOT NULL,
  evidence_event_ids JSONB NOT NULL CHECK (jsonb_typeof(evidence_event_ids) = 'array'),
  grouping_key_hash TEXT NOT NULL CHECK (grouping_key_hash ~ '^[a-f0-9]{64}$'),
  matched_conditions JSONB NOT NULL CHECK (jsonb_typeof(matched_conditions) = 'array'),
  known_limitations JSONB NOT NULL CHECK (jsonb_typeof(known_limitations) = 'array'),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT detection_findings_tenant_finding_unique UNIQUE (tenant_id, finding_id),
  CONSTRAINT detection_findings_time_order CHECK (last_seen_at >= first_seen_at)
);

CREATE INDEX detection_findings_tenant_recent_idx
  ON onishield.detection_findings (tenant_id, last_seen_at DESC);

CREATE INDEX detection_findings_tenant_status_idx
  ON onishield.detection_findings (tenant_id, status, last_seen_at DESC);

ALTER TABLE onishield.detection_findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE onishield.detection_findings FORCE ROW LEVEL SECURITY;

CREATE POLICY detection_findings_tenant_isolation
  ON onishield.detection_findings
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
