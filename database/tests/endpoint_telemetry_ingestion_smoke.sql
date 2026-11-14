-- Run after migrations 001-023 in a disposable database as onishield_owner.
BEGIN;
INSERT INTO onishield.operators(email,password_hash,display_name,status)
VALUES ('endpoint-telemetry-smoke@example.invalid','test-only-not-a-real-password-hash','Endpoint Telemetry Smoke','active');
INSERT INTO onishield.operator_memberships(tenant_id,operator_id,role,status)
SELECT 'endpoint-telemetry-smoke',id,'owner','active'
FROM onishield.operators WHERE email='endpoint-telemetry-smoke@example.invalid';
INSERT INTO onishield.operator_sessions(
  tenant_id,operator_id,membership_id,token_hash,expires_at,step_up_at
)
SELECT m.tenant_id,m.operator_id,m.id,repeat('a',64),NOW()+INTERVAL '1 hour',NOW()
FROM onishield.operator_memberships m
JOIN onishield.operators o ON o.id=m.operator_id
WHERE o.email='endpoint-telemetry-smoke@example.invalid';
SELECT * FROM onishield.create_endpoint_enrollment_token(
  repeat('a',64),repeat('b',64),'Telemetry Smoke Host','linux'
);
CREATE TEMP TABLE telemetry_smoke_agent AS
SELECT * FROM onishield.claim_endpoint_enrollment(
  repeat('b',64),repeat('c',64),'telemetry-host','0.1.0','linux'
);
CREATE TEMP TABLE telemetry_smoke_payload AS
SELECT jsonb_build_object(
  'agent_id',agent_id,'event_id','b3a2c4d6-2222-4222-8222-222222222222',
  'sequence',1,'boot_id','b3a2c4d6-3333-4333-8333-333333333333',
  'observed_at',NOW(),'collected_at',NOW(),'agent_version','0.1.0',
  'platform','linux','kind','heartbeat',
  'data',jsonb_build_object('os_version','6.8','hostname','telemetry-host',
    'capabilities',jsonb_build_array(),'clock_skew_ms',0)
) AS event
FROM telemetry_smoke_agent;
DO $$
DECLARE first_result RECORD; retry_result RECORD;
BEGIN
  SELECT * INTO first_result FROM onishield.ingest_endpoint_telemetry(
    repeat('c',64),(SELECT jsonb_build_array(event) FROM telemetry_smoke_payload)
  );
  IF first_result.accepted_count<>1 OR first_result.duplicate_count<>0 THEN
    RAISE EXCEPTION 'first telemetry batch was not accepted exactly once';
  END IF;
  SELECT * INTO retry_result FROM onishield.ingest_endpoint_telemetry(
    repeat('c',64),(SELECT jsonb_build_array(event) FROM telemetry_smoke_payload)
  );
  IF retry_result.accepted_count<>0 OR retry_result.duplicate_count<>1 THEN
    RAISE EXCEPTION 'exact telemetry retry was not idempotent';
  END IF;
  BEGIN
    PERFORM * FROM onishield.ingest_endpoint_telemetry(
      repeat('c',64),(SELECT jsonb_build_array(event || jsonb_build_object('sequence',2)) FROM telemetry_smoke_payload)
    );
    RAISE EXCEPTION 'event ID reuse with a new sequence was accepted';
  EXCEPTION WHEN OTHERS THEN
    IF SQLERRM='event ID reuse with a new sequence was accepted' THEN RAISE; END IF;
  END;
  BEGIN
    PERFORM * FROM onishield.ingest_endpoint_telemetry(
      repeat('c',64),(SELECT jsonb_build_array(event || jsonb_build_object('agent_id','b3a2c4d6-9999-4999-8999-999999999999')) FROM telemetry_smoke_payload)
    );
    RAISE EXCEPTION 'cross-agent event was accepted';
  EXCEPTION WHEN OTHERS THEN
    IF SQLERRM='cross-agent event was accepted' THEN RAISE; END IF;
  END;
END $$;
SELECT onishield.revoke_endpoint_agent(
  repeat('a',64),(SELECT agent_id FROM telemetry_smoke_agent),'Smoke test revocation'
);
DO $$
BEGIN
  BEGIN
    PERFORM * FROM onishield.ingest_endpoint_telemetry(
      repeat('c',64),(SELECT jsonb_build_array(event) FROM telemetry_smoke_payload)
    );
    RAISE EXCEPTION 'revoked credential was accepted';
  EXCEPTION WHEN OTHERS THEN
    IF SQLERRM='revoked credential was accepted' THEN RAISE; END IF;
  END;
END $$;
ROLLBACK;
