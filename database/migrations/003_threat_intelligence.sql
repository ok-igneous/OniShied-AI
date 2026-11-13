-- Tenant-scoped threat intelligence storage for the synthetic lab.
-- Global/platform intelligence is deliberately not represented in this migration.
-- Runtime access is tenant-bound by app.tenant_id and cannot update or delete records.

CREATE TABLE onishield.threat_intelligence_sources (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  source_key TEXT NOT NULL,
  display_name TEXT NOT NULL,
  source_kind TEXT NOT NULL CHECK (source_kind IN ('manual', 'synthetic')),
  license_ref TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, source_key)
);

CREATE TABLE onishield.threat_indicators (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  indicator_key TEXT NOT NULL,
  version INTEGER NOT NULL CHECK (version > 0),
  indicator_type TEXT NOT NULL CHECK (
    indicator_type IN ('ipv4', 'ipv6', 'domain', 'url', 'file_hash_sha256', 'email_address')
  ),
  value_normalized TEXT NOT NULL CHECK (
    length(value_normalized) BETWEEN 1 AND 2048
  ),
  source_id BIGINT NOT NULL,
  source_record_ref TEXT NOT NULL,
  first_seen_at TIMESTAMPTZ,
  collected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  valid_from TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at TIMESTAMPTZ,
  confidence SMALLINT NOT NULL CHECK (confidence BETWEEN 0 AND 100),
  confidence_rubric_version TEXT NOT NULL,
  assessed_by TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending'
    CHECK (status IN ('pending', 'active', 'expired', 'revoked', 'rejected')),
  tlp TEXT NOT NULL CHECK (tlp IN ('clear', 'green', 'amber', 'red')),
  content_digest TEXT CHECK (content_digest IS NULL OR content_digest ~ '^[a-f0-9]{64}$'),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT threat_indicators_source_same_tenant
    FOREIGN KEY (tenant_id, source_id)
    REFERENCES onishield.threat_intelligence_sources (tenant_id, id),
  UNIQUE (tenant_id, indicator_key, version),
  UNIQUE (tenant_id, id, version),
  CHECK (expires_at IS NULL OR expires_at > valid_from)
);

CREATE INDEX threat_indicators_match_lookup_idx
  ON onishield.threat_indicators
    (tenant_id, indicator_type, value_normalized, status, valid_from, expires_at);

CREATE INDEX threat_indicators_expiry_idx
  ON onishield.threat_indicators (tenant_id, expires_at)
  WHERE status = 'active' AND expires_at IS NOT NULL;

CREATE TABLE onishield.threat_indicator_matches (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  event_id TEXT NOT NULL,
  indicator_id BIGINT NOT NULL,
  indicator_version INTEGER NOT NULL,
  matched_field_path TEXT NOT NULL CHECK (length(matched_field_path) BETWEEN 1 AND 512),
  matcher_version TEXT NOT NULL,
  matched_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT threat_matches_indicator_same_tenant
    FOREIGN KEY (tenant_id, indicator_id, indicator_version)
    REFERENCES onishield.threat_indicators (tenant_id, id, version),
  UNIQUE (
    tenant_id, event_id, indicator_id, indicator_version,
    matched_field_path, matcher_version
  )
);

CREATE INDEX threat_indicator_matches_event_idx
  ON onishield.threat_indicator_matches (tenant_id, event_id, matched_at DESC);

ALTER TABLE onishield.threat_intelligence_sources ENABLE ROW LEVEL SECURITY;
ALTER TABLE onishield.threat_intelligence_sources FORCE ROW LEVEL SECURITY;
CREATE POLICY threat_sources_tenant_isolation
  ON onishield.threat_intelligence_sources
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

ALTER TABLE onishield.threat_indicators ENABLE ROW LEVEL SECURITY;
ALTER TABLE onishield.threat_indicators FORCE ROW LEVEL SECURITY;
CREATE POLICY threat_indicators_tenant_isolation
  ON onishield.threat_indicators
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (
    tenant_id = current_setting('app.tenant_id', true)
    AND status = 'pending'
  );

ALTER TABLE onishield.threat_indicator_matches ENABLE ROW LEVEL SECURITY;
ALTER TABLE onishield.threat_indicator_matches FORCE ROW LEVEL SECURITY;
CREATE POLICY threat_matches_tenant_isolation
  ON onishield.threat_indicator_matches
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

-- The runtime role can read sources, submit pending indicators, and record matches.
-- It cannot update, activate, revoke, or delete intelligence. Those operations
-- require a separately designed reviewer role and audited workflow.
GRANT SELECT ON onishield.threat_intelligence_sources TO onishield_app;
GRANT SELECT, INSERT ON onishield.threat_indicators TO onishield_app;
GRANT SELECT, INSERT ON onishield.threat_indicator_matches TO onishield_app;
GRANT USAGE, SELECT ON SEQUENCE
  onishield.threat_intelligence_sources_id_seq,
  onishield.threat_indicators_id_seq,
  onishield.threat_indicator_matches_id_seq
TO onishield_app;
