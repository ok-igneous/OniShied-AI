import assert from "node:assert/strict";
import test from "node:test";
import { endpointTelemetryBatchSchema, endpointTelemetryEventSchema } from "./endpoint-telemetry.js";
const base = {
  agent_id:"b3a2c4d6-1111-4111-8111-111111111111",
  event_id:"b3a2c4d6-2222-4222-8222-222222222222", sequence:1,
  boot_id:"b3a2c4d6-3333-4333-8333-333333333333",
  observed_at:"2026-11-14T10:00:00.000Z", collected_at:"2026-11-14T10:00:01.000Z",
  agent_version:"0.1.0", platform:"linux" as const
};
const ref="a".repeat(64), digest="b".repeat(64);
test("accepts bounded process metadata",()=>{
  const result=endpointTelemetryEventSchema.safeParse({...base,kind:"process_start",
    data:{process_id:101,parent_process_id:1,image_path_ref:ref,image_sha256:digest,signer_status:"valid"}});
  assert.equal(result.success,true);
});
test("rejects raw command lines and unknown process fields",()=>{
  const result=endpointTelemetryEventSchema.safeParse({...base,kind:"process_start",
    data:{process_id:101,image_path_ref:ref,command_line:"sensitive arguments",signer_status:"unknown"}});
  assert.equal(result.success,false);
});
test("requires pseudonymous principal references",()=>{
  const valid=endpointTelemetryEventSchema.safeParse({...base,kind:"authentication",
    data:{result:"failure",mechanism:"remote",principal_ref:ref,source_address:"192.0.2.10"}});
  const raw=endpointTelemetryEventSchema.safeParse({...base,kind:"authentication",
    data:{result:"failure",mechanism:"remote",username:"alice"}});
  assert.equal(valid.success,true); assert.equal(raw.success,false);
});
test("rejects duplicate per-agent sequence numbers in a batch",()=>{
  const event={...base,kind:"heartbeat",data:{os_version:"6.8",hostname:"workstation-01",capabilities:["process_start"],clock_skew_ms:0}};
  const result=endpointTelemetryBatchSchema.safeParse({events:[event,{...event,event_id:"b3a2c4d6-4444-4444-8444-444444444444"}]});
  assert.equal(result.success,false);
});
test("rejects batches above the event-count bound",()=>{
  const event={...base,kind:"heartbeat",data:{os_version:"6.8",hostname:"workstation-01",capabilities:[],clock_skew_ms:0}};
  const result=endpointTelemetryBatchSchema.safeParse({events:Array.from({length:101},(_,index)=>({...event,
    event_id:`b3a2c4d6-4444-4444-8444-${String(index).padStart(12,"0")}`,sequence:index+1}))});
  assert.equal(result.success,false);
});
test("rejects deletion events with a current file digest",()=>{
  const result=endpointTelemetryEventSchema.safeParse({...base,kind:"file_integrity",
    data:{action:"deleted",path_ref:ref,current_sha256:digest,monitored_scope:"startup"}});
  assert.equal(result.success,false);
});
