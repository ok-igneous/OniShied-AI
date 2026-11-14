import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import Fastify from "fastify";
import test from "node:test";
import { registerEndpointTelemetryRoutes } from "./endpoint-telemetry-routes.js";

const token = "A".repeat(43);
const heartbeat = {
  agent_id:"b3a2c4d6-1111-4111-8111-111111111111",
  event_id:"b3a2c4d6-2222-4222-8222-222222222222",
  sequence:1,
  boot_id:"b3a2c4d6-3333-4333-8333-333333333333",
  observed_at:"2026-11-14T10:00:00.000Z",
  collected_at:"2026-11-14T10:00:01.000Z",
  agent_version:"0.1.0",
  platform:"linux",
  kind:"heartbeat",
  data:{os_version:"6.8",hostname:"workstation-01",capabilities:[],clock_skew_ms:0}
};

async function makeApp(query: (...args: any[]) => Promise<any>) {
  const app=Fastify({logger:false});
  registerEndpointTelemetryRoutes(app,{query} as never);
  await app.ready();
  return app;
}

test("endpoint route rejects missing device credentials before database access",async()=>{
  let calls=0;
  const app=await makeApp(async()=>{calls+=1;return {rows:[]};});
  const response=await app.inject({method:"POST",url:"/v1/endpoints/telemetry",payload:{events:[heartbeat]}});
  assert.equal(response.statusCode,401);
  assert.equal(calls,0);
  await app.close();
});

test("endpoint route rejects invalid event payload before database access",async()=>{
  let calls=0;
  const app=await makeApp(async()=>{calls+=1;return {rows:[]};});
  const response=await app.inject({
    method:"POST",url:"/v1/endpoints/telemetry",
    headers:{authorization:`Bearer ${token}`},
    payload:{events:[{...heartbeat,data:{...heartbeat.data,unexpected_secret:"must-not-pass"}}]}
  });
  assert.equal(response.statusCode,400);
  assert.equal(calls,0);
  await app.close();
});

test("endpoint route hashes the bearer secret and returns accepted status",async()=>{
  let receivedHash="";
  const app=await makeApp(async(_sql:string,params:unknown[])=>{
    receivedHash=String(params[0]);
    return {rows:[{
      accepted_count:1,duplicate_count:0,
      agent_id:heartbeat.agent_id,tenant_id:"tenant-a",canonical_events:[]
    }]};
  });
  const response=await app.inject({
    method:"POST",url:"/v1/endpoints/telemetry",
    headers:{authorization:`Bearer ${token}`},payload:{events:[heartbeat]}
  });
  assert.equal(response.statusCode,202);
  assert.equal(receivedHash,createHash("sha256").update(token).digest("hex"));
  assert.equal(response.json().detection_status,"evaluated");
  assert.equal(response.headers["cache-control"],"no-store");
  await app.close();
});

test("endpoint route fails closed when the ingestion database is unavailable",async()=>{
  const app=await makeApp(async()=>{throw new Error("database unavailable");});
  const response=await app.inject({
    method:"POST",url:"/v1/endpoints/telemetry",
    headers:{authorization:`Bearer ${token}`},payload:{events:[heartbeat]}
  });
  assert.equal(response.statusCode,503);
  assert.equal(response.json().error,"endpoint_telemetry_unavailable");
  await app.close();
});
