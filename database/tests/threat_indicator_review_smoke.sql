-- Verify reviewer authorization, legal transitions, audit integrity and tenant RLS.
-- Executed in CI as postgres; SET LOCAL ROLE exercises the granted principals.
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
  BEGIN
    UPDATE onishield.threat_indicators SET status = 'rejected'
    WHERE indicator_key = 'review-indicator';
    RAISE EXCEPTION 'Runtime unexpectedly rejected an indicator';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
END
$$;

SET LOCAL ROLE onishield_reviewer;
SELECT set_config('app.threat_review_reason', 'Validated synthetic source and provenance.', true);
UPDATE onishield.threat_indicators SET status = 'active'
WHERE indicator_key = 'review-indicator';

DO $$
DECLARE audit_count INTEGER;
BEGIN
  SELECT count(*) INTO audit_count
  FROM onishield.threat_indicator_status_audit
  WHERE indicator_id = (
    SELECT id FROM onishield.threat_indicators WHERE indicator_key = 'review-indicator'
  );
  IF audit_count <> 1 THEN
    RAISE EXCEPTION 'Approval did not create exactly one audit row';
  END IF;
END
$$;

-- Reviewer cannot rewrite evidence fields, and illegal transitions are rejected.
DO $$
BEGIN
  BEGIN
    UPDATE onishield.threat_indicators SET value_normalized = 'changed.test'
    WHERE indicator_key = 'review-indicator';
    RAISE EXCEPTION 'Reviewer unexpectedly changed immutable indicator data';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;

  BEGIN
    UPDATE onishield.threat_indicators SET status = 'pending'
    WHERE indicator_key = 'review-indicator';
    RAISE EXCEPTION 'Illegal active-to-pending transition was accepted';
  EXCEPTION WHEN raise_exception THEN
    IF SQLERRM = 'Illegal active-to-pending transition was accepted' THEN RAISE; END IF;
  END;
END
$$;

-- Reviewer cannot mutate or delete audit history.
DO $$
BEGIN
  BEGIN
    DELETE FROM onishield.threat_indicator_status_audit;
    RAISE EXCEPTION 'Reviewer unexpectedly deleted audit history';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
END
$$;

-- Cross-tenant reviewer cannot read or change tenant A indicators.
SELECT set_config('app.tenant_id', 'review-tenant-b', true);
DO $$
DECLARE visible_count INTEGER;
BEGIN
  SELECT count(*) INTO visible_count FROM onishield.threat_indicators
  WHERE indicator_key = 'review-indicator';
  IF visible_count <> 0 THEN
    RAISE EXCEPTION 'Cross-tenant reviewer can see tenant A indicator';
  END IF;
END
$$;
ROLLBACK;
