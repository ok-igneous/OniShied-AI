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

SELECT set_config('app.test_indicator_id',
  (SELECT id::TEXT FROM onishield.threat_indicators WHERE indicator_key='auth-review-indicator'), true);

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

INSERT INTO onishield.operators(id,email,password_hash,display_name,status)
VALUES ('10000000-0000-4000-8000-000000000002','viewer@example.test',
        'test-only-not-a-real-password-hash','Test Viewer','active');
INSERT INTO onishield.operator_memberships(tenant_id,operator_id,role,status)
VALUES ('auth-review-tenant','10000000-0000-4000-8000-000000000002','viewer','active');
INSERT INTO onishield.operator_sessions
  (tenant_id,operator_id,membership_id,token_hash,expires_at)
SELECT 'auth-review-tenant',o.id,m.id,
       repeat('d',64),NOW()+INTERVAL '1 hour'
FROM onishield.operators o
JOIN onishield.operator_memberships m ON m.operator_id=o.id
WHERE o.email='viewer@example.test';

-- Seed a second session for the reviewer so same-operator revocation can be checked.
INSERT INTO onishield.operator_sessions
  (tenant_id,operator_id,membership_id,token_hash,expires_at)
SELECT 'auth-review-tenant',o.id,m.id,repeat('f',64),NOW()+INTERVAL '1 hour'
FROM onishield.operators o
JOIN onishield.operator_memberships m ON m.operator_id=o.id
WHERE o.email='reviewer@example.test';

SET LOCAL ROLE onishield_auth;
DO $$
DECLARE attempt INTEGER; permitted BOOLEAN;
BEGIN
  IF has_table_privilege(current_user,'onishield.operators','SELECT')
     OR has_table_privilege(current_user,'onishield.operator_sessions','SELECT')
     OR has_table_privilege(current_user,'onishield.operator_memberships','SELECT') THEN
    RAISE EXCEPTION 'Auth service role unexpectedly has direct identity-table access';
  END IF;

  FOR attempt IN 1..5 LOOP
    SELECT allowed INTO permitted
      FROM onishield.consume_operator_login_limit(repeat('b',64),5,900,900);
    IF NOT permitted THEN RAISE EXCEPTION 'Login throttle blocked before the fifth attempt'; END IF;
  END LOOP;
  SELECT allowed INTO permitted
    FROM onishield.consume_operator_login_limit(repeat('b',64),5,900,900);
  IF permitted THEN RAISE EXCEPTION 'Login throttle did not block the sixth attempt'; END IF;
  PERFORM onishield.reset_operator_login_limit(repeat('b',64));

  BEGIN
    PERFORM * FROM onishield.review_threat_indicator(
      repeat('a',64), current_setting('app.test_indicator_id')::BIGINT,
      'active', 'Must require fresh password reauthentication.'
    );
    RAISE EXCEPTION 'Review accepted without step-up authentication';
  EXCEPTION WHEN raise_exception THEN
    IF SQLERRM = 'Review accepted without step-up authentication' THEN RAISE; END IF;
    IF SQLERRM <> 'Step-up authentication required' THEN RAISE; END IF;
  END;

  IF NOT onishield.mark_operator_session_step_up(repeat('a',64)) THEN
    RAISE EXCEPTION 'Valid operator session could not complete step-up';
  END IF;

  PERFORM * FROM onishield.review_threat_indicator(
    repeat('a',64),
    current_setting('app.test_indicator_id')::BIGINT,
    'active',
    'Verified synthetic source provenance.'
  );

  BEGIN
    PERFORM * FROM onishield.review_threat_indicator(
      repeat('c',64), current_setting('app.test_indicator_id')::BIGINT,
      'revoked', 'Invalid session must never review.'
    );
    RAISE EXCEPTION 'Review accepted an invalid session';
  EXCEPTION WHEN raise_exception THEN
    IF SQLERRM = 'Review accepted an invalid session' THEN RAISE; END IF;
  END;

  BEGIN
    PERFORM * FROM onishield.review_threat_indicator(
      repeat('d',64), current_setting('app.test_indicator_id')::BIGINT,
      'revoked', 'Viewer role must not review indicators.'
    );
    RAISE EXCEPTION 'Review accepted a viewer session';
  EXCEPTION WHEN raise_exception THEN
    IF SQLERRM = 'Review accepted a viewer session' THEN RAISE; END IF;
  END;
    -- Session inventory exposes only metadata and is scoped to the authenticated operator.
  IF (SELECT count(*) FROM onishield.list_operator_sessions(repeat('a',64))) <> 2 THEN
    RAISE EXCEPTION 'Session inventory did not return only the review operator sessions';
  END IF;

  IF NOT onishield.revoke_operator_session_by_id(
    repeat('a',64),
    (SELECT id FROM onishield.operator_sessions WHERE token_hash=repeat('f',64))
  ) THEN
    RAISE EXCEPTION 'Could not revoke another session belonging to the same operator';
  END IF;

  IF onishield.revoke_operator_session_by_id(
    repeat('a',64),
    (SELECT id FROM onishield.operator_sessions WHERE token_hash=repeat('a',64))
  ) THEN
    RAISE EXCEPTION 'Session management must not revoke the current session';
  END IF;

  PERFORM * FROM onishield.rotate_operator_session(
    repeat('a',64), repeat('e',64), NOW()+INTERVAL '8 hours'
  );
  IF EXISTS (SELECT 1 FROM onishield.resolve_operator_session(repeat('a',64))) THEN
    RAISE EXCEPTION 'Rotation did not invalidate the old session';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM onishield.resolve_operator_session(repeat('e',64))) THEN
    RAISE EXCEPTION 'Rotation did not create a valid replacement session';
  END IF;

END
$$;

SET LOCAL ROLE onishield_owner;
DO $$
DECLARE actor UUID; approved_count INTEGER;
BEGIN
  SELECT actor_operator_id INTO actor
    FROM onishield.threat_indicator_status_audit
   WHERE indicator_id=current_setting('app.test_indicator_id')::BIGINT;
  SELECT count(*) INTO approved_count
    FROM onishield.threat_indicator_status_audit
   WHERE indicator_id=current_setting('app.test_indicator_id')::BIGINT
     AND old_status='pending' AND new_status='active';
  IF actor IS DISTINCT FROM '10000000-0000-4000-8000-000000000001'::UUID
     OR approved_count <> 1 THEN
    RAISE EXCEPTION 'Review audit did not preserve authenticated operator identity';
  END IF;
END
$$;
ROLLBACK;
