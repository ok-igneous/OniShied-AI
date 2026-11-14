import assert from "node:assert/strict";
import test from "node:test";
import { endpointTelemetryBatchSchema } from "./endpoint-telemetry.js";

const base = {
  agent_id:"b3a2c4d6-1111-4111-8111-111111111111",
  event_id:"b3a2c4d6-2222-4222-8222-222222222222",
  sequence:1,
  boot_id:"b3a2c4d6-3333-4333-8333-333333333333",
  observed_at:"2026-11-14T10:00:00.000Z",
  collected_at:"2026-11-14T10:00:01.000Z",
  agent_version:"0.1.0",platform:"linux" as const
};

test("accepts a bounded heartbeat batch",()=>{
  const result=endpointTelemetryBatchSchema.safeParse({events:[{
    ...base,kind:"heartbeat",
    data:{os_version:"6.8",hostname:"workstation-01",capabilities:[],clock_skew_ms:0}
  }]});
  assert.equal(result.success,true);
});

test("rejects event batches with unknown tenant or credential fields",()=>{
  const result=endpointTelemetryBatchSchema.safeParse({tenant_id:"attacker-tenant",events:[{
    ...base,kind:"heartbeat",
    data:{os_version:"6.8",hostname:"workstation-01",capabilities:[],clock_skew_ms:0}
  }]});
  assert.equal(result.success,false);
});

test("rejects invalid IP and malformed timestamps",()=>{
  const result=endpointTelemetryBatchSchema.safeParse({events:[{
    ...base,observed_at:"not-a-date",kind:"network_connection",
    data:{protocol:"tcp",direction:"outbound",local_port:5000,remote_port:443,remote_address:"not-an-ip"}
  }]});
  assert.equal(result.success,false);
});

import { evaluateDetections } from "./detection-engine.js";
import { securityEventSchema } from "./security-event.js";

test("endpoint-normalized authentication failures enter deterministic detection",()=>{
  const events=Array.from({length:8},(_,index)=>({
    schema_version:"0.1.0" as const,
    event_id:`endpoint-event-${index+1}`,
    tenant_id:"tenant-a",
    source:{
      connector_id:"endpoint:b3a2c4d6-1111-4111-8111-111111111111",
      kind:"endpoint_agent",
      version:"0.1.0",
      host_ref:"workstation-01"
    },
    event_type:"identity.authentication.failure",
    observed_at:new Date(Date.parse("2026-11-14T10:00:00.000Z")+index*30000).toISOString(),
    severity_hint:"unknown" as const,
    provenance:{record_ref:`endpoint-event-${index+1}`,collection_method:"agent" as const},
    data:{
      result:"failure",
      mechanism:"remote",
      principal_ref:"d".repeat(64),
      source_address:"192.0.2.10",
      endpoint_agent_id:"b3a2c4d6-1111-4111-8111-111111111111",
      boot_id:"b3a2c4d6-3333-4333-8333-333333333333",
      sequence:index+1,
      agent_event_kind:"authentication"
    }
  }));
  for(const event of events) assert.equal(securityEventSchema.safeParse(event).success,true);
  const findings=evaluateDetections(events);
  assert.equal(findings.length,1);
  assert.equal(findings[0]?.rule_id,"AUTH_FAILURE_BURST");
  assert.equal(findings[0]?.evidence_event_refs.length,8);
});
