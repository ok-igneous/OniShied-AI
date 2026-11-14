-- Link exact threat-indicator matches to the exact event evidence in a finding.
-- This is contextual enrichment only; it never authorizes a response.
BEGIN;

ALTER TABLE onishield.detection_findings
  ADD COLUMN evidence_event_refs JSONB NOT NULL DEFAULT '[]'::jsonb
  CHECK (jsonb_typeof(evidence_event_refs) = 'array');

-- Backfill structured references from the legacy connector:event string only
-- when each reference maps to exactly one canonical stored event.
DO $
BEGIN
  IF EXISTS (
    SELECT 1
    FROM onishield.detection_findings AS f
    CROSS JOIN LATERAL jsonb_array_elements_text(f.evidence_event_ids) AS ref(value)
    WHERE (
      SELECT COUNT(*)
      FROM onishield.security_events AS e
      WHERE e.tenant_id = f.tenant_id
        AND e.connector_id || ':' || e.event_id = ref.value
    ) <> 1
  ) THEN
    RAISE EXCEPTION
      'Cannot backfill structured finding evidence: one or more legacy references are ambiguous or missing';
  END IF;
END;
$;

UPDATE onishield.detection_findings AS f
SET evidence_event_refs = COALESCE((
  SELECT jsonb_agg(jsonb_build_object(
    'connector_id', e.connector_id,
    'event_id', e.event_id
  ) ORDER BY e.observed_at, e.connector_id, e.event_id)
  FROM jsonb_array_elements_text(f.evidence_event_ids) AS ref(value)
  JOIN onishield.security_events AS e
    ON e.tenant_id = f.tenant_id
   AND e.connector_id || ':' || e.event_id = ref.value
), '[]'::jsonb);

ALTER TABLE onishield.threat_indicator_matches
  ADD CONSTRAINT threat_matches_tenant_event_id_unique
  UNIQUE (tenant_id, connector_id, event_id, id);

CREATE TABLE onishield.detection_finding_threat_matches (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  finding_id TEXT NOT NULL,
  connector_id TEXT NOT NULL,
  event_id TEXT NOT NULL,
  threat_match_id BIGINT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT finding_threat_match_finding_fk
    FOREIGN KEY (tenant_id, finding_id)
    REFERENCES onishield.detection_findings (tenant_id, finding_id),
  CONSTRAINT finding_threat_match_exact_evidence_fk
    FOREIGN KEY (tenant_id, connector_id, event_id, threat_match_id)
    REFERENCES onishield.threat_indicator_matches
      (tenant_id, connector_id, event_id, id),
  CONSTRAINT finding_threat_match_unique
    UNIQUE (tenant_id, finding_id, threat_match_id)
);

CREATE INDEX detection_finding_threat_matches_lookup_idx
  ON onishield.detection_finding_threat_matches
    (tenant_id, finding_id, created_at DESC);

ALTER TABLE onishield.detection_finding_threat_matches ENABLE ROW LEVEL SECURITY;
ALTER TABLE onishield.detection_finding_threat_matches FORCE ROW LEVEL SECURITY;

CREATE POLICY detection_finding_threat_matches_tenant_isolation
  ON onishield.detection_finding_threat_matches
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

GRANT SELECT, INSERT ON onishield.detection_finding_threat_matches TO onishield_app;
GRANT USAGE, SELECT ON SEQUENCE
  onishield.detection_finding_threat_matches_id_seq TO onishield_app;

COMMIT;
