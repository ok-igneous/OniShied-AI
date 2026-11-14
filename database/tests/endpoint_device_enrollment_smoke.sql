-- Run after migrations 001-022 in a disposable database as onishield_owner.
BEGIN;
INSERT INTO onishield.operators(email,password_hash,display_name,status)
VALUES ('endpoint-enrollment-smoke@example.invalid','test-only-not-a-real-password-hash','Endpoint Smoke', 'active');
INSERT INTO onishield.operator_memberships(tenant_id,operator_id,role,status)
SELECT 'endpoint-enrollment-smoke',id,'owner','active'
FROM onishield.operators WHERE email='endpoint-enrollment-smoke@example.invalid';

INSERT INTO onishield.operator_sessions(
  tenant_id,operator_id,membership_id,token_hash,expires_at,step_up_at
)
SELECT m.tenant_id,m.operator_id,m.id,repeat('a',64),NOW()+INTERVAL '1 hour',NOW()
FROM onishield.operator_memberships m
JOIN onishield.operators o ON o.id=m.operator_id
WHERE o.email='endpoint-enrollment-smoke@example.invalid';

SELECT * FROM onishield.create_endpoint_enrollment_token(
  repeat('a',64),repeat('b',64),'Smoke Linux Host','linux'
);

CREATE TEMP TABLE endpoint_enrollment_smoke_agent AS
SELECT * FROM onishield.claim_endpoint_enrollment(
  repeat('b',64),repeat('c',64),'smoke-host','0.1.0','linux'
);

DO $$
BEGIN
  IF (SELECT count(*) FROM onishield.endpoint_agents
      WHERE tenant_id='endpoint-enrollment-smoke'
        AND credential_hash=repeat('c',64) AND status='active') <> 1 THEN
    RAISE EXCEPTION 'enrolled endpoint or credential verifier missing';
  END IF;
  BEGIN
    PERFORM * FROM onishield.claim_endpoint_enrollment(
      repeat('b',64),repeat('d',64),'second-claim','0.1.0','linux'
    );
    RAISE EXCEPTION 'one-time enrollment token was reused';
  EXCEPTION WHEN OTHERS THEN
    IF SQLERRM='one-time enrollment token was reused' THEN RAISE; END IF;
  END;
END $$;

SELECT onishield.revoke_endpoint_agent(
  repeat('a',64),(SELECT agent_id FROM endpoint_enrollment_smoke_agent),'Smoke test revocation'
);

DO $$
BEGIN
  IF (SELECT status FROM onishield.endpoint_agents
      WHERE id=(SELECT agent_id FROM endpoint_enrollment_smoke_agent)) <> 'revoked' THEN
    RAISE EXCEPTION 'endpoint revocation did not persist';
  END IF;
END $$;
ROLLBACK;
