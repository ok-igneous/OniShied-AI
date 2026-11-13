import type { OperatorPrincipal } from "./operator-auth-service.js";

export type OperatorAction = "tenant:read" | "events:read" | "investigation:read" | "threat-intelligence:read" | "threat-intelligence:submit" | "threat-intelligence:review" | "operators:manage" | "response:approve";

const permissions: Record<string, readonly OperatorAction[]> = {
  owner: ["tenant:read","events:read","investigation:read","threat-intelligence:read","threat-intelligence:submit","threat-intelligence:review","operators:manage","response:approve"],
  admin: ["tenant:read","events:read","investigation:read","threat-intelligence:read","threat-intelligence:submit","threat-intelligence:review","operators:manage"],
  security_analyst: ["tenant:read","events:read","investigation:read","threat-intelligence:read","threat-intelligence:submit"],
  reviewer: ["tenant:read","threat-intelligence:read","threat-intelligence:review"],
  viewer: ["tenant:read","events:read","investigation:read","threat-intelligence:read"]
};

export function canPerformOperatorAction(principal: Pick<OperatorPrincipal,"role">, action: OperatorAction): boolean {
  return permissions[principal.role]?.includes(action) ?? false;
}

export function assertOperatorAction(principal: Pick<OperatorPrincipal,"role">, action: OperatorAction): void {
  if (!canPerformOperatorAction(principal, action)) throw new Error("forbidden");
}
