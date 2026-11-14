-- Stable finding episode anchors and append-only, exact event evidence.
-- Existing findings retain their IDs; the earliest structured evidence ref is
-- recorded as the legacy anchor. New IDs are derived from the rule trigger event.
BEGIN;

ALTER TABLE onishield.detection_findings
  ADD COLUMN episode_anchor_connector_id TEXT,
  ADD COLUMN episode_anchor_event_id TEXT;

UPDATE onishield.detection_findings AS f
SET episode_anchor_connector_id = f.evidence_event_refs->0->>'connector_id',
    episode_anchor_event_id = f.evidence_event_refs->0->>'event_id'
WHERE jsonb_array_length(f.evidence_event_refs) > 0;

DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM onishield.detection_findings
    WHERE episode_anchor_connector_id IS NULL OR episode_anchor_event_id IS NULL
  ) THEN
    RAISE EXCEPTION 'Cannot assign stable episode anchor to a finding without structured evidence';
  END IF;
END;
$$;

ALTER TABLE onishield.detection_findings
  ALTER COLUMN episode_anchor_connector_id SET NOT NULL,
  ALTER COLUMN episode_anchor_event_id SET NOT NULL,
  ADD CONSTRAINT detection_findings_anchor_event_fk
    FOREIGN KEY (tenant_id, episode_anchor_connector_id, episode_anchor_event_id)
    REFERENCES onishield.security_events (tenant_id, connector_id, event_id);

CREATE INDEX detection_findings_episode_anchor_idx
  ON onishield.detection_findings
    (tenant_id, rule_id, rule_version, grouping_key_hash,
     episode_anchor_connector_id, episode_anchor_event_id);

CREATE TABLE onishield.detection_finding_evidence (
  tenant_id TEXT NOT NULL,
  finding_id TEXT NOT NULL,
  connector_id TEXT NOT NULL,
  event_id TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT detection_finding_evidence_pk
    PRIMARY KEY (tenant_id, finding_id, connector_id, event_id),
  CONSTRAINT detection_finding_evidence_finding_fk
    FOREIGN KEY (tenant_id, finding_id)
    REFERENCES onishield.detection_findings (tenant_id, finding_id),
  CONSTRAINT detection_finding_evidence_event_fk
    FOREIGN KEY (tenant_id, connector_id, event_id)
    REFERENCES onishield.security_events (tenant_id, connector_id, event_id)
);

INSERT INTO onishield.detection_finding_evidence
  (tenant_id, finding_id, connector_id, event_id)
SELECT f.tenant_id, f.finding_id,
       evidence.value->>'connector_id', evidence.value->>'event_id'
FROM onishield.detection_findings AS f
CROSS JOIN LATERAL jsonb_array_elements(f.evidence_event_refs) AS evidence(value)
ON CONFLICT (tenant_id, finding_id, connector_id, event_id) DO NOTHING;

CREATE INDEX detection_finding_evidence_event_idx
  ON onishield.detection_finding_evidence
    (tenant_id, connector_id, event_id);

ALTER TABLE onishield.detection_finding_evidence ENABLE ROW LEVEL SECURITY;
ALTER TABLE onishield.detection_finding_evidence FORCE ROW LEVEL SECURITY;

CREATE POLICY detection_finding_evidence_tenant_isolation
  ON onishield.detection_finding_evidence
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

GRANT SELECT, INSERT ON onishield.detection_finding_evidence TO onishield_app;
GRANT UPDATE ON onishield.detection_findings TO onishield_app;

COMMIT;
