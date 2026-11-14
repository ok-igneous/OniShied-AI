BEGIN;

-- Credential-authenticated endpoint telemetry and canonical security-event bridge.
CREATE TABLE onishield.endpoint_telemetry_events (
  tenant_id TEXT NOT NULL,
  agent_id UUID NOT NULL,
  boot_id UUID NOT NULL,
  sequence BIGINT NOT NULL CHECK (sequence > 0),
  event_id UUID NOT NULL,
  event_kind TEXT NOT NULL CHECK (event_kind IN (
    'heartbeat','process_start','authentication','network_connection','file_integrity','service_change'
  )),
  observed_at TIMESTAMPTZ NOT NULL,
  collected_at TIMESTAMPTZ NOT NULL,
  event_json JSONB NOT NULL CHECK (jsonb_typeof(event_json)='object'),
  received_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (tenant_id,agent_id,boot_id,sequence),
  UNIQUE (tenant_id,agent_id,event_id),
  FOREIGN KEY (tenant_id,agent_id)
    REFERENCES onishield.endpoint_agents(tenant_id,id)
);
CREATE INDEX endpoint_telemetry_recent_idx
  ON onishield.endpoint_telemetry_events(tenant_id,agent_id,observed_at DESC);
ALTER TABLE onishield.endpoint_telemetry_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE onishield.endpoint_telemetry_events FORCE ROW LEVEL SECURITY;
CREATE POLICY endpoint_telemetry_tenant_scope ON onishield.endpoint_telemetry_events
  USING (tenant_id=current_setting('app.tenant_id',true))
  WITH CHECK (tenant_id=current_setting('app.tenant_id',true));
CREATE POLICY endpoint_telemetry_owner_all ON onishield.endpoint_telemetry_events
  TO onishield_owner USING (true) WITH CHECK (true);
REVOKE ALL ON onishield.endpoint_telemetry_events FROM PUBLIC,onishield_app,onishield_auth;

CREATE FUNCTION onishield.ingest_endpoint_telemetry(
  p_credential_hash TEXT,p_events JSONB
) RETURNS TABLE(
  accepted_count INTEGER,duplicate_count INTEGER,agent_id UUID,
  tenant_id TEXT,canonical_events JSONB
)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,onishield AS $$
DECLARE
  trusted RECORD;
  item JSONB;
  inserted_count INTEGER := 0;
  duplicates INTEGER := 0;
  event_agent UUID;
  event_boot UUID;
  event_id_value UUID;
  event_sequence BIGINT;
  event_observed_at TIMESTAMPTZ;
  event_collected_at TIMESTAMPTZ;
  existing_event JSONB;
  existing_id UUID;
  was_inserted BOOLEAN;
  normalized_event JSONB;
  stored_event JSONB;
  normalized_type TEXT;
  normalized_events JSONB := '[]'::JSONB;
  connector_identity TEXT;
BEGIN
  IF p_credential_hash IS NULL OR p_credential_hash !~ '^[a-f0-9]{64}$'
     OR jsonb_typeof(p_events) IS DISTINCT FROM 'array' THEN
    RAISE EXCEPTION 'Invalid endpoint telemetry batch';
  END IF;
  IF jsonb_array_length(p_events) NOT BETWEEN 1 AND 100 THEN
    RAISE EXCEPTION 'Invalid endpoint telemetry batch';
  END IF;

  SELECT a.id,a.tenant_id,a.platform,a.status,a.hostname,a.agent_version
    INTO trusted
    FROM onishield.endpoint_agents a
   WHERE a.credential_hash=p_credential_hash
   FOR UPDATE;
  IF NOT FOUND OR trusted.status <> 'active' THEN
    RAISE EXCEPTION 'Unauthorized endpoint credential';
  END IF;
  PERFORM set_config('app.tenant_id',trusted.tenant_id,true);
  connector_identity := 'endpoint:' || trusted.id::TEXT;

  FOR item IN SELECT value FROM jsonb_array_elements(p_events) LOOP
    IF jsonb_typeof(item) IS DISTINCT FROM 'object'
       OR jsonb_typeof(item->'data') IS DISTINCT FROM 'object'
       OR jsonb_typeof(item->'agent_id') IS DISTINCT FROM 'string'
       OR jsonb_typeof(item->'boot_id') IS DISTINCT FROM 'string'
       OR jsonb_typeof(item->'event_id') IS DISTINCT FROM 'string'
       OR jsonb_typeof(item->'sequence') IS DISTINCT FROM 'number'
       OR jsonb_typeof(item->'platform') IS DISTINCT FROM 'string'
       OR jsonb_typeof(item->'agent_version') IS DISTINCT FROM 'string'
       OR jsonb_typeof(item->'kind') IS DISTINCT FROM 'string'
       OR jsonb_typeof(item->'observed_at') IS DISTINCT FROM 'string'
       OR jsonb_typeof(item->'collected_at') IS DISTINCT FROM 'string'
       OR CASE
            WHEN jsonb_typeof(item->'sequence')='number' THEN
              (item->>'sequence')::NUMERIC <= 0
              OR (item->>'sequence')::NUMERIC <> trunc((item->>'sequence')::NUMERIC)
              OR (item->>'sequence')::NUMERIC > 9007199254740991
            ELSE true
          END
       OR item->>'kind' NOT IN (
         'heartbeat','process_start','authentication','network_connection','file_integrity','service_change'
       ) THEN
      RAISE EXCEPTION 'Invalid endpoint event shape';
    END IF;

    BEGIN
      event_agent := (item->>'agent_id')::UUID;
      event_boot := (item->>'boot_id')::UUID;
      event_id_value := (item->>'event_id')::UUID;
      event_sequence := (item->>'sequence')::BIGINT;
      event_observed_at := (item->>'observed_at')::TIMESTAMPTZ;
      event_collected_at := (item->>'collected_at')::TIMESTAMPTZ;
    EXCEPTION WHEN OTHERS THEN
      RAISE EXCEPTION 'Invalid endpoint event identity or timestamp';
    END;

    IF event_agent IS DISTINCT FROM trusted.id
       OR item->>'platform' IS DISTINCT FROM trusted.platform
       OR item->>'agent_version' IS DISTINCT FROM trusted.agent_version
       OR event_sequence <= 0
       OR event_observed_at > NOW()+INTERVAL '5 minutes'
       OR event_collected_at > NOW()+INTERVAL '5 minutes'
       OR event_collected_at < event_observed_at-INTERVAL '5 minutes'
       OR (item->>'kind'='heartbeat'
           AND item->'data'->>'hostname' IS DISTINCT FROM trusted.hostname) THEN
      RAISE EXCEPTION 'Endpoint event identity, version, hostname, platform, or timestamp mismatch';
    END IF;

    INSERT INTO onishield.endpoint_telemetry_events(
      tenant_id,agent_id,boot_id,sequence,event_id,event_kind,
      observed_at,collected_at,event_json
    ) VALUES (
      trusted.tenant_id,trusted.id,event_boot,event_sequence,event_id_value,item->>'kind',
      event_observed_at,event_collected_at,item
    ) ON CONFLICT DO NOTHING;
    was_inserted := FOUND;

    normalized_type := CASE item->>'kind'
      WHEN 'heartbeat' THEN 'endpoint.agent.heartbeat'
      WHEN 'process_start' THEN 'endpoint.process.start'
      WHEN 'authentication' THEN
        CASE item->'data'->>'result'
          WHEN 'failure' THEN 'identity.authentication.failure'
          WHEN 'success' THEN 'identity.authentication.success'
          ELSE 'endpoint.authentication.unknown'
        END
      WHEN 'network_connection' THEN 'endpoint.network.connection'
      WHEN 'file_integrity' THEN 'endpoint.file.integrity'
      WHEN 'service_change' THEN 'endpoint.service.change'
    END;

    IF was_inserted THEN
      inserted_count := inserted_count + 1;
      normalized_event := jsonb_build_object(
        'schema_version','0.1.0',
        'event_id',event_id_value::TEXT,
        'tenant_id',trusted.tenant_id,
        'source',jsonb_build_object(
          'connector_id',connector_identity,
          'kind','endpoint_agent',
          'version',item->>'agent_version',
          'host_ref',left(trusted.hostname,128)
        ),
        'event_type',normalized_type,
        'observed_at',event_observed_at,
        'ingested_at',NOW(),
        'severity_hint','unknown',
        'provenance',jsonb_build_object(
          'record_ref',event_id_value::TEXT,
          'collection_method','agent'
        ),
        'data',(item->'data') || jsonb_build_object(
          'endpoint_agent_id',trusted.id::TEXT,
          'boot_id',event_boot::TEXT,
          'sequence',event_sequence,
          'agent_event_kind',item->>'kind'
        )
      );

      INSERT INTO onishield.security_events(
        tenant_id,connector_id,event_id,schema_version,event_type,
        observed_at,ingested_at,severity_hint,event_json
      ) VALUES (
        trusted.tenant_id,connector_identity,event_id_value::TEXT,'0.1.0',
        normalized_type,event_observed_at,NOW(),'unknown',normalized_event
      ) ON CONFLICT (tenant_id,connector_id,event_id) DO NOTHING;

      SELECT e.event_json INTO stored_event
        FROM onishield.security_events e
       WHERE e.tenant_id=trusted.tenant_id
         AND e.connector_id=connector_identity
         AND e.event_id=event_id_value::TEXT;
      IF NOT FOUND OR stored_event IS DISTINCT FROM normalized_event THEN
        RAISE EXCEPTION 'Endpoint canonical event identity conflict';
      END IF;

      INSERT INTO onishield.detection_replay_jobs(tenant_id,connector_id,event_id)
      VALUES (trusted.tenant_id,connector_identity,event_id_value::TEXT)
      ON CONFLICT (tenant_id,connector_id,event_id) DO NOTHING;
      normalized_events := normalized_events || jsonb_build_array(normalized_event);
    ELSE
      SELECT e.event_json,e.event_id INTO existing_event,existing_id
        FROM onishield.endpoint_telemetry_events e
       WHERE e.tenant_id=trusted.tenant_id AND e.agent_id=trusted.id
         AND e.boot_id=event_boot AND e.sequence=event_sequence;
      IF NOT FOUND OR existing_id <> event_id_value OR existing_event <> item THEN
        RAISE EXCEPTION 'Endpoint sequence replay conflict';
      END IF;

      INSERT INTO onishield.detection_replay_jobs(tenant_id,connector_id,event_id)
      VALUES (trusted.tenant_id,connector_identity,event_id_value::TEXT)
      ON CONFLICT (tenant_id,connector_id,event_id) DO UPDATE
        SET status='pending',attempts=0,available_at=NOW(),lease_until=NULL,
            lease_token=NULL,last_error=NULL,updated_at=NOW()
        WHERE onishield.detection_replay_jobs.status='dead_letter';

      SELECT e.event_json INTO normalized_event
        FROM onishield.security_events e
       WHERE e.tenant_id=trusted.tenant_id
         AND e.connector_id=connector_identity AND e.event_id=event_id_value::TEXT;
      IF FOUND AND EXISTS (
        SELECT 1 FROM onishield.detection_replay_jobs j
         WHERE j.tenant_id=trusted.tenant_id
           AND j.connector_id=connector_identity
           AND j.event_id=event_id_value::TEXT AND j.status='pending'
      ) THEN
        normalized_events := normalized_events || jsonb_build_array(normalized_event);
      END IF;
      duplicates := duplicates + 1;
    END IF;
  END LOOP;

  UPDATE onishield.endpoint_agents AS current_agent
     SET last_seen_at=GREATEST(COALESCE(current_agent.last_seen_at,'-infinity'::TIMESTAMPTZ),NOW())
   WHERE current_agent.tenant_id=trusted.tenant_id AND current_agent.id=trusted.id;
  RETURN QUERY SELECT inserted_count,duplicates,trusted.id,trusted.tenant_id,normalized_events;
END; $$;
REVOKE ALL ON FUNCTION onishield.ingest_endpoint_telemetry(TEXT,JSONB) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION onishield.ingest_endpoint_telemetry(TEXT,JSONB) TO onishield_auth;

COMMIT;

            THEN (item->>'sequence')::NUMERIC > 9007199254740991
            ELSE TRUE
          END
       OR item->>'kind' NOT IN (
         'heartbeat','process_start','authentication','network_connection','file_integrity','service_change'
       ) THEN
      RAISE EXCEPTION 'Invalid endpoint event shape';
    END IF;

    BEGIN
      event_agent := (item->>'agent_id')::UUID;
      event_boot := (item->>'boot_id')::UUID;
      event_id_value := (item->>'event_id')::UUID;
      event_sequence := (item->>'sequence')::BIGINT;
      event_observed_at := (item->>'observed_at')::TIMESTAMPTZ;
      event_collected_at := (item->>'collected_at')::TIMESTAMPTZ;
    EXCEPTION WHEN OTHERS THEN
      RAISE EXCEPTION 'Invalid endpoint event identity or timestamp';
    END;

    IF event_agent IS DISTINCT FROM trusted.id
       OR item->>'platform' IS DISTINCT FROM trusted.platform
       OR item->>'agent_version' IS DISTINCT FROM trusted.agent_version
       OR event_sequence <= 0
       OR event_observed_at > NOW()+INTERVAL '5 minutes'
       OR event_collected_at > NOW()+INTERVAL '5 minutes'
       OR event_collected_at < event_observed_at-INTERVAL '5 minutes'
       OR (item->>'kind'='heartbeat'
           AND item->'data'->>'hostname' IS DISTINCT FROM trusted.hostname) THEN
      RAISE EXCEPTION 'Endpoint event identity, version, hostname, platform, or timestamp mismatch';
    END IF;

    INSERT INTO onishield.endpoint_telemetry_events(
      tenant_id,agent_id,boot_id,sequence,event_id,event_kind,
      observed_at,collected_at,event_json
    ) VALUES (
      trusted.tenant_id,trusted.id,event_boot,event_sequence,event_id_value,item->>'kind',
      event_observed_at,event_collected_at,item
    ) ON CONFLICT DO NOTHING;
    was_inserted := FOUND;

    normalized_type := CASE item->>'kind'
      WHEN 'heartbeat' THEN 'endpoint.agent.heartbeat'
      WHEN 'process_start' THEN 'endpoint.process.start'
      WHEN 'authentication' THEN
        CASE item->'data'->>'result'
          WHEN 'failure' THEN 'identity.authentication.failure'
          WHEN 'success' THEN 'identity.authentication.success'
          ELSE 'endpoint.authentication.unknown'
        END
      WHEN 'network_connection' THEN 'endpoint.network.connection'
      WHEN 'file_integrity' THEN 'endpoint.file.integrity'
      WHEN 'service_change' THEN 'endpoint.service.change'
    END;

    IF was_inserted THEN
      inserted_count := inserted_count + 1;
      normalized_event := jsonb_build_object(
        'schema_version','0.1.0',
        'event_id',event_id_value::TEXT,
        'tenant_id',trusted.tenant_id,
        'source',jsonb_build_object(
          'connector_id',connector_identity,
          'kind','endpoint_agent',
          'version',item->>'agent_version',
          'host_ref',left(trusted.hostname,128)
        ),
        'event_type',normalized_type,
        'observed_at',event_observed_at,
        'ingested_at',NOW(),
        'severity_hint','unknown',
        'provenance',jsonb_build_object(
          'record_ref',event_id_value::TEXT,
          'collection_method','agent'
        ),
        'data',(item->'data') || jsonb_build_object(
          'endpoint_agent_id',trusted.id::TEXT,
          'boot_id',event_boot::TEXT,
          'sequence',event_sequence,
          'agent_event_kind',item->>'kind'
        )
      );

      INSERT INTO onishield.security_events(
        tenant_id,connector_id,event_id,schema_version,event_type,
        observed_at,ingested_at,severity_hint,event_json
      ) VALUES (
        trusted.tenant_id,connector_identity,event_id_value::TEXT,'0.1.0',
        normalized_type,event_observed_at,NOW(),'unknown',normalized_event
      ) ON CONFLICT (tenant_id,connector_id,event_id) DO NOTHING;

      SELECT e.event_json INTO stored_event
        FROM onishield.security_events e
       WHERE e.tenant_id=trusted.tenant_id
         AND e.connector_id=connector_identity
         AND e.event_id=event_id_value::TEXT;
      IF NOT FOUND OR stored_event IS DISTINCT FROM normalized_event THEN
        RAISE EXCEPTION 'Endpoint canonical event identity conflict';
      END IF;

      INSERT INTO onishield.detection_replay_jobs(tenant_id,connector_id,event_id)
      VALUES (trusted.tenant_id,connector_identity,event_id_value::TEXT)
      ON CONFLICT (tenant_id,connector_id,event_id) DO NOTHING;
      normalized_events := normalized_events || jsonb_build_array(normalized_event);
    ELSE
      SELECT e.event_json,e.event_id INTO existing_event,existing_id
        FROM onishield.endpoint_telemetry_events e
       WHERE e.tenant_id=trusted.tenant_id AND e.agent_id=trusted.id
         AND e.boot_id=event_boot AND e.sequence=event_sequence;
      IF NOT FOUND OR existing_id <> event_id_value OR existing_event <> item THEN
        RAISE EXCEPTION 'Endpoint sequence replay conflict';
      END IF;

      INSERT INTO onishield.detection_replay_jobs(tenant_id,connector_id,event_id)
      VALUES (trusted.tenant_id,connector_identity,event_id_value::TEXT)
      ON CONFLICT (tenant_id,connector_id,event_id) DO UPDATE
        SET status='pending',attempts=0,available_at=NOW(),lease_until=NULL,
            lease_token=NULL,last_error=NULL,updated_at=NOW()
        WHERE onishield.detection_replay_jobs.status='dead_letter';

      SELECT e.event_json INTO normalized_event
        FROM onishield.security_events e
       WHERE e.tenant_id=trusted.tenant_id
         AND e.connector_id=connector_identity AND e.event_id=event_id_value::TEXT;
      IF FOUND AND EXISTS (
        SELECT 1 FROM onishield.detection_replay_jobs j
         WHERE j.tenant_id=trusted.tenant_id
           AND j.connector_id=connector_identity
           AND j.event_id=event_id_value::TEXT AND j.status='pending'
      ) THEN
        normalized_events := normalized_events || jsonb_build_array(normalized_event);
      END IF;
      duplicates := duplicates + 1;
    END IF;
  END LOOP;

  UPDATE onishield.endpoint_agents AS current_agent
     SET last_seen_at=GREATEST(COALESCE(current_agent.last_seen_at,'-infinity'::TIMESTAMPTZ),NOW())
   WHERE current_agent.tenant_id=trusted.tenant_id AND current_agent.id=trusted.id;
  RETURN QUERY SELECT inserted_count,duplicates,trusted.id,trusted.tenant_id,normalized_events;
END; $$;
REVOKE ALL ON FUNCTION onishield.ingest_endpoint_telemetry(TEXT,JSONB) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION onishield.ingest_endpoint_telemetry(TEXT,JSONB) TO onishield_auth;

COMMIT;
