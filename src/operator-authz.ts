export type OperatorRole = "owner" | "admin" | "security_analyst" | "reviewer" | "viewer";
export type OperatorAction =
  | "tenant:admin"
  | "operator:admin"
  | "event:read"
  | "detection:read"
  | "detection:triage"
  | "investigation:read"
  | "threat-intelligence:read"
  | "threat-intelligence:review"
  | "response:approve";

const ROLE_ACTIONS: Readonly<Record<OperatorRole, ReadonlySet<OperatorAction>>> = {
  owner: new Set(["tenant:admin", "operator:admin", "event:read", "detection:read", "detection:triage", "investigation:read", "threat-intelligence:read", "threat-intelligence:review", "response:approve"]),
  admin: new Set(["tenant:admin", "operator:admin", "event:read", "detection:read", "detection:triage", "investigation:read", "threat-intelligence:read", "threat-intelligence:review"]),
  security_analyst: new Set(["event:read", "detection:read", "detection:triage", "investigation:read", "threat-intelligence:read"]),
  reviewer: new Set(["event:read", "detection:read", "investigation:read", "threat-intelligence:read", "threat-intelligence:review"]),
  viewer: new Set(["event:read", "detection:read", "threat-intelligence:read"])
};

export function canOperatorPerform(role: string, action: string): boolean {
  if (!Object.hasOwn(ROLE_ACTIONS, role) || !Object.hasOwn(ROLE_ACTIONS.owner, action)) return false;
  return ROLE_ACTIONS[role as OperatorRole].has(action as OperatorAction);
}

export function assertOperatorPermission(role: string, action: string): void {
  if (!canOperatorPerform(role, action)) throw new Error("forbidden");
}
