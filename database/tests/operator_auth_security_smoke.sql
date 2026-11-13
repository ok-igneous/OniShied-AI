-- Verify durable login throttling and audit attribution to a real operator session.
BEGIN;
SELECT set_config('app.tenant_id','auth-review-tenant',true);
SET LOCAL ROLE onishield_owner;

INSERT INTO onishield.threat_intelligence_sources
  (tenant_id,source_key,display_name,source_kind,license_ref)
VALUES ('auth-review-tenant','auth-review-source','Auth review source','synthetic','internal-test');

INSERT INTO onishield.threat_indicators
  (tenant_id,indicator_key,version,indicator_type,value_normalized,source_id,
   source_record_ref,confidence,confidence_rubric_version,assessed_by,status,tlp)
SELECT tenant_id,'auth-review-indicator',1,'domain','review-malware.test',id,
       'auth-review-fixture',90,'test-v1','fixture','pending','green'
FROM onishield.threat_intelligence_sources
WHERE source_key='auth-review-source';

INSERT INTO onishield.operators(id,email,password_hash,display_name,status)
VALUES ('10000000-0000-4000-8000-000000000001','reviewer@example.test',
        'test-only-not-a-real-password-hash','Test Reviewer','active');

INSERT INTO onishield.operator_memberships(tenant_id,operator_id,role,status)
VALUES ('auth-review-tenant','10000000-0000-4000-8000-000000000001','reviewer','active');

INSERT INTO onishield.operator_sessions
  (tenant_id,operator_id,membership_id,token_hash,expires_at)
SELECT 'auth-review-tenant',o.id,m.id,
       repeat('a',64),NOW()+INTERVAL '1 hour'
FROM onishield.operators o
JOIN onishield.operator_memberships m ON m.operator_id=o.id
WHERE o.email='reviewer@example.test';

SET LOCAL ROLE onishield_auth;
DO $$
DECLARE attempt INTEGER; permitted BOOLEAN;
BEGIN
  FOR attempt IN 1..5 LOOP
    SELECT allowed INTO permitted
      FROM onishield.consume_operator_login_limit(repeat('b',64),5,900,900);
    IF NOT permitted THEN RAISE EXCEPTION 'Login throttle blocked before the fifth attempt'; END IF;
  END LOOP;
  SELECT allowed INTO permitted
    FROM onishield.consume_operator_login_limit(repeat('b',64),5,900,900);
  IF permitted THEN RAISE EXCEPTION 'Login throttle did not block the sixth attempt'; END IF;
  PERFORM onishield.reset_operator_login_limit(repeat('b',64));

  PERFORM * FROM onishield.review_threat_indicator(
    repeat('a',64),
    (SELECT id FROM onishield.threat_indicators WHERE indicator_key='auth-review-indicator'),
    'active',
    'Verified synthetic source provenance.'
  );
END
$$;

SET LOCAL ROLE onishield_owner;
DO $$
DECLARE actor UUID; approved_count INTEGER;
BEGIN
  SELECT actor_operator_id INTO actor
    FROM onishield.threat_indicator_status_audit
   WHERE indicator_id=(SELECT id FROM onishield.threat_indicators
                       WHERE indicator_key='auth-review-indicator');
  SELECT count(*) INTO approved_count
    FROM onishield.threat_indicator_status_audit
   WHERE indicator_id=(SELECT id FROM onishield.threat_indicators
                       WHERE indicator_key='auth-review-indicator')
     AND old_status='pending' AND new_status='active';
  IF actor IS DISTINCT FROM '10000000-0000-4000-8000-000000000001'::UUID
     OR approved_count <> 1 THEN
    RAISE EXCEPTION 'Review audit did not preserve authenticated operator identity';
  END IF;
END
$$;
ROLLBACK;
