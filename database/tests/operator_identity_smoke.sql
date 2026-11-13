-- Run as database administrator against the disposable migrated lab DB.
BEGIN;
SET LOCAL ROLE onishield_owner;
INSERT INTO onishield.operators (id, email, password_hash, display_name, status)
VALUES ('00000000-0000-4000-8000-000000000001',
        'operator-a@example.test', 'scrypt$test-placeholder', 'Synthetic Operator', 'active');
INSERT INTO onishield.operator_memberships (tenant_id, operator_id, role, status)
VALUES ('identity-tenant-a', '00000000-0000-4000-8000-000000000001', 'security_analyst', 'active');

SET LOCAL ROLE onishield_app;
SELECT set_config('app.tenant_id', 'identity-tenant-a', true);
DO $$
DECLARE
  membership_count INTEGER;
BEGIN
  SELECT count(*) INTO membership_count
    FROM onishield.operator_memberships
   WHERE operator_id = '00000000-0000-4000-8000-000000000001';
  IF membership_count <> 1 THEN
    RAISE EXCEPTION 'Active tenant membership is not visible in its tenant';
  END IF;

  BEGIN
    PERFORM password_hash FROM onishield.operators
     WHERE email = 'operator-a@example.test';
    RAISE EXCEPTION 'Runtime unexpectedly read operator password hashes';
  EXCEPTION WHEN insufficient_privilege THEN
    NULL;
  END;

  BEGIN
    PERFORM token_hash FROM onishield.operator_sessions;
    RAISE EXCEPTION 'Runtime unexpectedly read operator session digests';
  EXCEPTION WHEN insufficient_privilege THEN
    NULL;
  END;

  BEGIN
    UPDATE onishield.operator_memberships SET role = 'owner'
     WHERE tenant_id = 'identity-tenant-a';
    RAISE EXCEPTION 'Runtime unexpectedly modified operator membership';
  EXCEPTION WHEN insufficient_privilege THEN
    NULL;
  END;
END
$$;

SELECT set_config('app.tenant_id', 'identity-tenant-b', true);
DO $$
DECLARE
  membership_count INTEGER;
BEGIN
  SELECT count(*) INTO membership_count
    FROM onishield.operator_memberships
   WHERE operator_id = '00000000-0000-4000-8000-000000000001';
  IF membership_count <> 0 THEN
    RAISE EXCEPTION 'Operator membership crossed tenant boundary';
  END IF;
END
$$;
RESET ROLE;
SET LOCAL ROLE onishield_auth;
DO $
DECLARE
  credential_count INTEGER;
  session_count INTEGER;
  v_membership_id BIGINT;
  digest TEXT := repeat('a', 64);
BEGIN
  SELECT count(*) INTO credential_count
    FROM onishield.lookup_operator_credentials('operator-a@example.test');
  IF credential_count <> 1 THEN
    RAISE EXCEPTION 'Dedicated auth role cannot resolve credentials';
  END IF;
  BEGIN
    PERFORM password_hash FROM onishield.operators
     WHERE email = 'operator-a@example.test';
    RAISE EXCEPTION 'Auth role unexpectedly has direct operator-table access';
  EXCEPTION WHEN insufficient_privilege THEN
    NULL;
  END;
  BEGIN
    PERFORM token_hash FROM onishield.operator_sessions;
    RAISE EXCEPTION 'Auth role unexpectedly has direct session-table access';
  EXCEPTION WHEN insufficient_privilege THEN
    NULL;
  END;
  SELECT membership_id INTO v_membership_id
    FROM onishield.lookup_operator_membership(
      '00000000-0000-4000-8000-000000000001', 'identity-tenant-a'
    );
  PERFORM * FROM onishield.create_operator_session(
    digest, 'identity-tenant-a', '00000000-0000-4000-8000-000000000001',
    v_membership_id, NOW() + INTERVAL '1 hour'
  );
  SELECT count(*) INTO session_count FROM onishield.resolve_operator_session(digest);
  IF session_count <> 1 THEN RAISE EXCEPTION 'Session did not resolve'; END IF;
  PERFORM onishield.revoke_operator_session(digest);
  SELECT count(*) INTO session_count FROM onishield.resolve_operator_session(digest);
  IF session_count <> 0 THEN RAISE EXCEPTION 'Revoked session still resolves'; END IF;
END
$;
ROLLBACK;
