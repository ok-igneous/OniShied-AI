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
    'capabilities',jsonb_build_array('authentication'),'clock_skew_ms',0)
) AS event
FROM telemetry_smoke_agent
UNION ALL
SELECT jsonb_build_object(
  'agent_id',agent_id,'event_id','b3a2c4d6-4444-4444-8444-444444444444',
  'sequence',2,'boot_id','b3a2c4d6-3333-4333-8333-333333333333',
  'observed_at',NOW(),'collected_at',NOW(),'agent_version','0.1.0',
  'platform','linux','kind','authentication',
  'data',jsonb_build_object('result','failure','mechanism','remote',
    'principal_ref',repeat('d',64),'source_address','192.0.2.10')
) AS event
FROM telemetry_smoke_agent;

DO $telemetry_smoke$
DECLARE first_result RECORD; retry_result RECORD; normalized_count INTEGER;
BEGIN
  SELECT * INTO first_result FROM onishield.ingest_endpoint_telemetry(
    repeat('c',64),(SELECT jsonb_agg(event ORDER BY event->>'sequence') FROM telemetry_smoke_payload)
  );
  IF first_result.accepted_count<>2 OR first_result.duplicate_count<>0
     OR jsonb_array_length(first_result.canonical_events)<>2 THEN
    RAISE EXCEPTION 'first telemetry batch was not accepted and normalized exactly twice';
  END IF;
  SELECT count(*) INTO normalized_count
    FROM onishield.security_events
   WHERE tenant_id='endpoint-telemetry-smoke'
     AND connector_id='endpoint:' || (SELECT agent_id::TEXT FROM telemetry_smoke_agent);
  IF normalized_count<>2 THEN RAISE EXCEPTION 'canonical security events were not persisted'; END IF;
  IF NOT EXISTS (
    SELECT 1 FROM onishield.security_events
     WHERE tenant_id='endpoint-telemetry-smoke'
       AND event_type='identity.authentication.failure'
  ) THEN RAISE EXCEPTION 'authentication telemetry did not map to canonical auth failure'; END IF;
  IF (SELECT count(*) FROM onishield.detection_replay_jobs
       WHERE tenant_id='endpoint-telemetry-smoke')<>2 THEN
    RAISE EXCEPTION 'canonical events were not queued for detection replay';
  END IF;

  UPDATE onishield.detection_replay_jobs SET status='dead_letter',
    last_error='smoke_test_dead_letter'
   WHERE tenant_id='endpoint-telemetry-smoke';
  SELECT * INTO retry_result FROM onishield.ingest_endpoint_telemetry(
    repeat('c',64),(SELECT jsonb_agg(event ORDER BY event->>'sequence') FROM telemetry_smoke_payload)
  );
  IF retry_result.accepted_count<>0 OR retry_result.duplicate_count<>2
     OR jsonb_array_length(retry_result.canonical_events)<>2 THEN
    RAISE EXCEPTION 'exact telemetry retry did not safely requeue dead-lettered detection';
  END IF;
  IF (SELECT count(*) FROM onishield.detection_replay_jobs
       WHERE tenant_id='endpoint-telemetry-smoke' AND status='pending')<>2 THEN
    RAISE EXCEPTION 'dead-lettered detection jobs were not reset to pending';
  END IF;
  BEGIN
    PERFORM * FROM onishield.ingest_endpoint_telemetry(
      repeat('c',64),(SELECT jsonb_build_array(event || jsonb_build_object('sequence',3))
                       FROM telemetry_smoke_payload WHERE event->>'kind'='heartbeat')
    );
    RAISE EXCEPTION 'event ID reuse with a new sequence was accepted';
  EXCEPTION WHEN OTHERS THEN
    IF SQLERRM='event ID reuse with a new sequence was accepted' THEN RAISE; END IF;
  END;
  BEGIN
    PERFORM * FROM onishield.ingest_endpoint_telemetry(
      repeat('c',64),(SELECT jsonb_build_array(event || jsonb_build_object(
        'agent_id','b3a2c4d6-9999-4999-8999-999999999999'))
        FROM telemetry_smoke_payload WHERE event->>'kind'='heartbeat')
    );
    RAISE EXCEPTION 'cross-agent event was accepted';
  EXCEPTION WHEN OTHERS THEN
    IF SQLERRM='cross-agent event was accepted' THEN RAISE; END IF;
  END;
  BEGIN
    PERFORM * FROM onishield.ingest_endpoint_telemetry(
      repeat('c',64),(SELECT jsonb_build_array(event || jsonb_build_object('agent_version','9.9.9'))
        FROM telemetry_smoke_payload WHERE event->>'kind'='heartbeat')
    );
    RAISE EXCEPTION 'unregistered agent version was accepted';
  EXCEPTION WHEN OTHERS THEN
    IF SQLERRM='unregistered agent version was accepted' THEN RAISE; END IF;
  END;
  BEGIN
    PERFORM * FROM onishield.ingest_endpoint_telemetry(
      repeat('c',64),(SELECT jsonb_build_array(event || jsonb_build_object('platform',NULL))
        FROM telemetry_smoke_payload WHERE event->>'kind'='heartbeat')
    );
    RAISE EXCEPTION 'null platform was accepted';
  EXCEPTION WHEN OTHERS THEN
    IF SQLERRM='null platform was accepted' THEN RAISE; END IF;
  END;
  BEGIN
    PERFORM * FROM onishield.ingest_endpoint_telemetry(
      repeat('c',64),(SELECT jsonb_build_array(event - 'agent_id')
        FROM telemetry_smoke_payload WHERE event->>'kind'='heartbeat')
    );
    RAISE EXCEPTION 'missing agent identity was accepted';
  EXCEPTION WHEN OTHERS THEN
    IF SQLERRM='missing agent identity was accepted' THEN RAISE; END IF;
  END;
  BEGIN
    PERFORM * FROM onishield.ingest_endpoint_telemetry(
      repeat('c',64),(SELECT jsonb_build_array(event || jsonb_build_object('sequence',1.5))
        FROM telemetry_smoke_payload WHERE event->>'kind'='heartbeat')
    );
    RAISE EXCEPTION 'fractional sequence was accepted';
  EXCEPTION WHEN OTHERS THEN
    IF SQLERRM='fractional sequence was accepted' THEN RAISE; END IF;
  END;
  BEGIN
    PERFORM * FROM onishield.ingest_endpoint_telemetry(
      repeat('c',64),(SELECT jsonb_build_array(event || jsonb_build_object('observed_at','not-a-timestamp'))
        FROM telemetry_smoke_payload WHERE event->>'kind'='heartbeat')
    );
    RAISE EXCEPTION 'malformed timestamp was accepted';
  EXCEPTION WHEN OTHERS THEN
    IF SQLERRM='malformed timestamp was accepted' THEN RAISE; END IF;
  END;
  BEGIN
    PERFORM * FROM onishield.ingest_endpoint_telemetry(
      repeat('c',64),(SELECT jsonb_build_array(event || jsonb_build_object(
        'collected_at',(event->>'observed_at')::TIMESTAMPTZ-INTERVAL '6 minutes'))
        FROM telemetry_smoke_payload WHERE event->>'kind'='heartbeat')
    );
    RAISE EXCEPTION 'collection time outside allowed skew was accepted';
  EXCEPTION WHEN OTHERS THEN
    IF SQLERRM='collection time outside allowed skew was accepted' THEN RAISE; END IF;
  END;
END $telemetry_smoke$;

SELECT onishield.revoke_endpoint_agent(
  repeat('a',64),(SELECT agent_id FROM telemetry_smoke_agent),'Smoke test revocation'
);
DO $$
BEGIN
  BEGIN
    PERFORM * FROM onishield.ingest_endpoint_telemetry(
      repeat('c',64),(SELECT jsonb_agg(event) FROM telemetry_smoke_payload)
    );
    RAISE EXCEPTION 'revoked credential was accepted';
  EXCEPTION WHEN OTHERS THEN
    IF SQLERRM='revoked credential was accepted' THEN RAISE; END IF;
  END;
END $$;
ROLLBACK;
