import type { TrafficLightProtocol } from "./threat-intelligence.js";

export type TlpRecipientScope = "tenant" | "community" | "organization" | "named";

export interface TrustedDisclosureContext {
  /** Values must come from authenticated server-side identity and authorization. */
  tenantId: string;
  actorId: string;
  purpose: "investigation" | "incident_response" | "reporting";
  recipientScope: TlpRecipientScope;
  recipientId: string;
  communityId?: string;
  organizationId?: string;
}

export interface IndicatorDisclosureMetadata {
  tenantId: string;
  tlp: TrafficLightProtocol;
  communityId?: string;
  organizationId?: string;
  namedRecipientIds?: readonly string[];
}

export type DisclosureDecision =
  | { allowed: true; reason: "tlp_scope_satisfied" }
  | { allowed: false; reason: "invalid_context" | "tenant_boundary" | "tlp_scope_denied" };

/**
 * Evaluates disclosure only. It does not authenticate the caller or grant
 * access to the underlying record. Call only after tenant-scoped authorization.
 */
export function evaluateIndicatorDisclosure(
  indicator: IndicatorDisclosureMetadata,
  context: TrustedDisclosureContext
): DisclosureDecision {
  if (
    !indicator.tenantId ||
    !context.tenantId ||
    !context.actorId ||
    !context.recipientId ||
    !context.purpose
  ) {
    return { allowed: false, reason: "invalid_context" };
  }

  // TLP never overrides OniShield's tenant isolation, including TLP:CLEAR.
  if (indicator.tenantId !== context.tenantId) {
    return { allowed: false, reason: "tenant_boundary" };
  }

  switch (indicator.tlp) {
    case "clear":
      return { allowed: true, reason: "tlp_scope_satisfied" };
    case "green":
      return context.recipientScope === "community" &&
        Boolean(context.communityId) &&
        context.recipientId === context.communityId &&
        indicator.communityId === context.communityId
        ? { allowed: true, reason: "tlp_scope_satisfied" }
        : { allowed: false, reason: "tlp_scope_denied" };
    case "amber":
      return context.recipientScope === "organization" &&
        Boolean(context.organizationId) &&
        context.recipientId === context.organizationId &&
        indicator.organizationId === context.organizationId
        ? { allowed: true, reason: "tlp_scope_satisfied" }
        : { allowed: false, reason: "tlp_scope_denied" };
    case "red":
      return context.recipientScope === "named" &&
        indicator.namedRecipientIds?.includes(context.recipientId) === true
        ? { allowed: true, reason: "tlp_scope_satisfied" }
        : { allowed: false, reason: "tlp_scope_denied" };
    default: {
      const exhaustive: never = indicator.tlp;
      return exhaustive;
    }
  }
}

export function assertIndicatorDisclosure(
  indicator: IndicatorDisclosureMetadata,
  context: TrustedDisclosureContext
): void {
  const decision = evaluateIndicatorDisclosure(indicator, context);
  if (!decision.allowed) {
    throw new Error(`Threat intelligence disclosure denied: ${decision.reason}`);
  }
}
