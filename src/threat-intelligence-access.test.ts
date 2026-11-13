import assert from "node:assert/strict";
import test from "node:test";
import {
  evaluateIndicatorDisclosure,
  type TrustedDisclosureContext
} from "./threat-intelligence-access.js";

const baseContext: TrustedDisclosureContext = {
  tenantId: "tenant-a",
  actorId: "operator-1",
  purpose: "investigation",
  recipientScope: "tenant",
  recipientId: "tenant-a"
};

test("TLP:CLEAR remains inside the tenant boundary", () => {
  assert.equal(evaluateIndicatorDisclosure(
    { tenantId: "tenant-a", tlp: "clear" }, baseContext
  ).allowed, true);
  assert.equal(evaluateIndicatorDisclosure(
    { tenantId: "tenant-b", tlp: "clear" }, baseContext
  ).reason, "tenant_boundary");
});

test("TLP:GREEN requires the exact authorized community", () => {
  const indicator = {
    tenantId: "tenant-a", tlp: "green" as const, communityId: "community-1"
  };
  const context = {
    ...baseContext,
    recipientScope: "community" as const,
    recipientId: "community-1",
    communityId: "community-1"
  };
  assert.equal(evaluateIndicatorDisclosure(indicator, context).allowed, true);
  assert.equal(evaluateIndicatorDisclosure(indicator, {
    ...context, recipientId: "community-2"
  }).allowed, false);
  assert.equal(evaluateIndicatorDisclosure(indicator, baseContext).allowed, false);
});

test("TLP:AMBER requires the exact organization", () => {
  const indicator = {
    tenantId: "tenant-a", tlp: "amber" as const, organizationId: "org-1"
  };
  const context = {
    ...baseContext,
    recipientScope: "organization" as const,
    recipientId: "org-1",
    organizationId: "org-1"
  };
  assert.equal(evaluateIndicatorDisclosure(indicator, context).allowed, true);
  assert.equal(evaluateIndicatorDisclosure(indicator, {
    ...context, organizationId: "org-2", recipientId: "org-2"
  }).allowed, false);
});

test("TLP:RED requires an explicitly named recipient", () => {
  const indicator = {
    tenantId: "tenant-a", tlp: "red" as const,
    namedRecipientIds: ["operator-1"]
  };
  const namedContext = {
    ...baseContext,
    recipientScope: "named" as const,
    recipientId: "operator-1"
  };
  assert.equal(evaluateIndicatorDisclosure(indicator, namedContext).allowed, true);
  assert.equal(evaluateIndicatorDisclosure(indicator, {
    ...namedContext, recipientId: "operator-2"
  }).allowed, false);
});

test("missing identity and recipient context fails closed", () => {
  assert.equal(evaluateIndicatorDisclosure(
    { tenantId: "tenant-a", tlp: "red", namedRecipientIds: ["operator-1"] },
    { ...baseContext, actorId: "", recipientScope: "named" }
  ).reason, "invalid_context");
});
