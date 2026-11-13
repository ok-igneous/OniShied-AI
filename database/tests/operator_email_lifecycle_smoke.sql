-- Exercise one-use invitation, email verification, password reset and session revocation.
BEGIN;

SET LOCAL ROLE onishield_owner;
INSERT INTO onishield.operators(id,email,password_hash,display_name,status,email_verified_at)
VALUES(
 '10000000-0000-4000-8000-000000000001','inviter@example.test',
 'scrypt$16384$8$1$00112233445566778899aabbccddeeff$' || repeat('a',128),
 'Test Inviter','active',NOW()
);
INSERT INTO onishield.operator_memberships(tenant_id,operator_id,role,status)
VALUES('email-test-tenant','10000000-0000-4000-8000-000000000001','owner','active');
INSERT INTO onishield.operator_sessions(tenant_id,operator_id,membership_id,token_hash,expires_at)
SELECT 'email-test-tenant','10000000-0000-4000-8000-000000000001',id,repeat('a',64),NOW()+INTERVAL '1 hour'
FROM onishield.operator_memberships
WHERE tenant_id='email-test-tenant'
  AND operator_id='10000000-0000-4000-8000-000000000001';

SET LOCAL ROLE onishield_auth;
DO $$
DECLARE invited RECORD;
  accepted RECORD;
  verified BOOLEAN;
  reset BOOLEAN;
  invite_hash TEXT:=repeat('b',64);
  verify_hash TEXT:=repeat('c',64);
  reset_hash TEXT:=repeat('d',64);
  password_hash TEXT:='scrypt$16384$8$1$00112233445566778899aabbccddeeff$' || repeat('e',128);
BEGIN
  SELECT * INTO invited FROM onishield.create_operator_invitation(
    repeat('a',64),'new-operator@example.test','New Operator','security_analyst',
    invite_hash,NOW()+INTERVAL '1 hour'
  );
  IF invited.action_id IS NULL THEN RAISE EXCEPTION 'Invitation was not created'; END IF;

  SELECT * INTO accepted FROM onishield.accept_operator_invitation(invite_hash,password_hash);
  IF accepted.email IS DISTINCT FROM 'new-operator@example.test'
    OR accepted.role IS DISTINCT FROM 'security_analyst' THEN
    RAISE EXCEPTION 'Invitation acceptance failed';
  END IF;
  PERFORM * FROM onishield.create_operator_session(
    repeat('e',64),accepted.tenant_id,accepted.operator_id,accepted.membership_id,
    NOW()+INTERVAL '1 hour'
  );
  BEGIN
    PERFORM * FROM onishield.accept_operator_invitation(invite_hash,password_hash);
    RAISE EXCEPTION 'Invitation token was reusable';
  EXCEPTION WHEN raise_exception THEN
    IF SQLERRM='Invitation token was reusable' THEN RAISE; END IF;
  END;

  IF NOT EXISTS(SELECT 1 FROM onishield.request_operator_password_reset(
    'new-operator@example.test',reset_hash,NOW()+INTERVAL '20 minutes')
  ) THEN RAISE EXCEPTION 'Password reset was not issued'; END IF;
  SELECT onishield.consume_operator_password_reset(reset_hash,password_hash) INTO reset;
  IF reset IS DISTINCT FROM TRUE THEN RAISE EXCEPTION 'Password reset was not consumed'; END IF;
  SELECT onishield.consume_operator_password_reset(reset_hash,password_hash) INTO reset;
  IF reset IS DISTINCT FROM FALSE THEN RAISE EXCEPTION 'Password reset token was reusable'; END IF;
  IF EXISTS(SELECT 1 FROM onishield.resolve_operator_session(repeat('e',64))) THEN
    RAISE EXCEPTION 'Password reset did not revoke existing sessions';
  END IF;
END;
$$;

SET LOCAL ROLE onishield_owner;
INSERT INTO onishield.operators(id,email,password_hash,display_name,status)
VALUES(
 '10000000-0000-4000-8000-000000000002','unverified@example.test',
 'scrypt$16384$8$1$00112233445566778899aabbccddeeff$' || repeat('f',128),
 'Unverified Operator','active'
);
SET LOCAL ROLE onishield_auth;
DO $$
DECLARE verified BOOLEAN;
  verification RECORD;
BEGIN
  SELECT * INTO verification FROM onishield.request_operator_email_verification(
    'unverified@example.test',repeat('f',64),NOW()+INTERVAL '20 minutes'
  );
  IF verification.action_id IS NULL THEN RAISE EXCEPTION 'Verification action was not issued'; END IF;
  SELECT onishield.consume_operator_email_verification(repeat('f',64)) INTO verified;
  IF verified IS DISTINCT FROM TRUE THEN RAISE EXCEPTION 'Email verification failed'; END IF;
  SELECT onishield.consume_operator_email_verification(repeat('f',64)) INTO verified;
  IF verified IS DISTINCT FROM FALSE THEN RAISE EXCEPTION 'Verification token was reusable'; END IF;
  IF NOT EXISTS(SELECT 1 FROM onishield.lookup_operator_credentials('unverified@example.test')
    WHERE email_verified IS TRUE) THEN RAISE EXCEPTION 'Verified status was not persisted'; END IF;
END;
$$;

ROLLBACK;
