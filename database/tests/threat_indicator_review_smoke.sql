-- The legacy shared DB reviewer role must not perform approvals.
-- Authenticated operator reviews are tested in operator_auth_security_smoke.sql.
BEGIN;
SELECT set_config('app.tenant_id', 'review-tenant-a', true);
SET LOCAL ROLE onishield_owner;

INSERT INTO onishield.threat_intelligence_sources
  (tenant_id, source_key, display_name, source_kind, license_ref)
VALUES ('review-tenant-a', 'review-source', 'Review test source', 'synthetic', 'internal-test');

INSERT INTO onishield.threat_indicators
  (tenant_id, indicator_key, version, indicator_type, value_normalized,
   source_id, source_record_ref, confidence, confidence_rubric_version,
   assessed_by, status, tlp)
SELECT tenant_id, 'review-indicator', 1, 'domain', 'malware.test',
       id, 'review-fixture', 90, 'test-v1', 'fixture-author', 'pending', 'green'
FROM onishield.threat_intelligence_sources WHERE source_key = 'review-source';

SET LOCAL ROLE onishield_app;
DO $$
BEGIN
  BEGIN
    UPDATE onishield.threat_indicators SET status = 'active'
    WHERE indicator_key = 'review-indicator';
    RAISE EXCEPTION 'Runtime unexpectedly activated an indicator';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
END
$$;

SET LOCAL ROLE onishield_reviewer;
DO $$
BEGIN
  BEGIN
    UPDATE onishield.threat_indicators SET status = 'active'
    WHERE indicator_key = 'review-indicator';
    RAISE EXCEPTION 'Legacy shared reviewer role unexpectedly activated an indicator';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
END
$$;

SET LOCAL ROLE onishield_owner;
DO $$
DECLARE visible_count INTEGER; audit_count INTEGER;
BEGIN
  SELECT count(*) INTO visible_count
    FROM onishield.threat_indicators WHERE indicator_key = 'review-indicator';
  IF visible_count <> 1 THEN
    RAISE EXCEPTION 'Owner cannot see the seeded tenant indicator';
  END IF;
  SELECT count(*) INTO audit_count
    FROM onishield.threat_indicator_status_audit
   WHERE indicator_id=(SELECT id FROM onishield.threat_indicators
                       WHERE indicator_key='review-indicator');
  IF audit_count <> 0 THEN
    RAISE EXCEPTION 'A denied shared-role update unexpectedly wrote an audit row';
  END IF;
END
$$;

ROLLBACK;
