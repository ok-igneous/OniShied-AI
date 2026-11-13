# Configurable Autopilot — Technical Contract

**Status:** Normative design contract; not implemented.  
**Initial deployment:** Synthetic, isolated lab only.  
**Default state:** Disabled.  
**Authority:** Policy-bounded execution only; AI never grants itself permission.

## 1. Product behavior

Autopilot lets an authorized organization explicitly enable bounded automation and configure the maximum risk it accepts. Configuration is tenant-scoped, versioned, auditable, and enforced by deterministic server-side policy before every action.

The user-facing controls must include:
- A clear master enable/disable switch (default OFF).
- An autonomy mode and maximum permitted risk tier.
- Per-action allow/deny settings from a server-owned action catalogue.
- Scope restrictions (approved assets, groups, environments, and time windows).
- Approval requirements, notification preferences, and emergency pause.
- A visible explanation of what can run automatically and what still requires approval.

A UI setting is not an authorization boundary. The policy service and executor must enforce the same configuration server-side.

## 2. Autonomy modes

| Mode | Behavior |
|---|---|
| Off | No response action executes. Detection and investigation may continue. |
| Observe | Simulate proposed actions, record policy decisions, execute nothing. |
| Low-risk autopilot | Execute only explicitly enabled Tier 0 and individually approved Tier 1 actions. |
| Guarded autopilot | Execute the same allowlisted low-risk actions; queue Tier 2 actions for human approval. Tier 3 remains prohibited. |

The organization may select a lower ceiling at any time. It cannot raise the system's hard safety ceiling or convert a prohibited action into an allowed action.

## 3. Risk tiers and hard boundaries

Risk is determined by impact, blast radius, reversibility, asset criticality, and confidence in target identity—not by model confidence alone.

- **Tier 0 — Observe:** read-only collection, enrichment, investigation, and alerting.
- **Tier 1 — Low impact / reversible:** narrowly scoped, reversible actions such as adding a temporary local alert label or applying a short-lived, pre-approved containment rule in a disposable lab.
- **Tier 2 — Disruptive:** disabling accounts, isolating business-critical devices, blocking production network ranges, or interrupting services. Human approval is mandatory.
- **Tier 3 — Destructive / irreversible:** wiping devices, deleting data, destructive remediation, broad isolation, or irreversible configuration changes. Excluded from initial Autopilot; no AI or tenant setting can enable them.

Initial product release must not ship a general-purpose command execution tool. Response adapters expose narrow typed actions, not shell access or arbitrary scripts.

## 4. Authorization decision

Every proposed action must pass all checks, in this order:

1. Authenticate the initiating service and derive tenant, actor, and target scope from trusted server-side context.
2. Confirm the organization has explicitly enabled the applicable mode.
3. Load the latest active policy version; reject missing, expired, or stale policy.
4. Confirm the action exists in the server-owned allowlist and is enabled for this tenant.
5. Verify the target is enrolled, authorized, in scope, and uniquely identified.
6. Recalculate risk using deterministic rules and asset criticality.
7. Verify evidence freshness, minimum evidence requirements, and preconditions.
8. Enforce approval requirements independently of AI output.
9. Enforce per-tenant rate, concurrency, blast-radius, and time-window limits.
10. Create an immutable execution intent and audit record before dispatch.
11. Execute with a narrowly scoped credential, idempotency key, timeout, and cancellation handling.
12. Verify the resulting state; record success, partial success, failure, and rollback status.

Any failed, unavailable, ambiguous, or timed-out policy check fails closed: no execution.

## 5. Evidence and AI boundaries

- AI may recommend an action but cannot select or raise its own permissions.
- Model confidence never substitutes for evidence, target identity, policy, or approval.
- A detection or threat-indicator match alone is insufficient authorization.
- Prompt-injected event content cannot alter policy, scope, or tool permissions.
- If evidence is stale, contradictory, incomplete, or target identity is ambiguous, require human review or do nothing.
- The action executor accepts a validated typed intent, never a free-form model-generated command.

## 6. Policy configuration and change control

Store tenant policy with: policy ID/version, tenant ID, enabled flag, mode, maximum risk tier, per-action decisions, approved target scopes, asset exclusions, time windows, rate/concurrency limits, minimum evidence rules, approval rules, effective/expiry timestamps, creator, approver where required, and change reason.

Policy changes require an authenticated authorized operator, step-up authentication for privileged changes, schema validation, and append-only audit. A policy update must invalidate cached policy before new execution. Existing in-flight actions must re-check cancellation and current policy at safe checkpoints.

Only authorized owner/admin roles may enable Autopilot or change its ceiling. A delegated security operator may pause it if granted explicit permission. Enabling Autopilot must require an explicit confirmation that summarizes the actions and targets covered.

## 7. Emergency controls and failure handling

- Provide tenant-level pause and platform-wide emergency kill switch.
- Pause blocks new actions immediately; in-flight action handling follows each adapter's safe cancellation contract.
- Credential revocation must prevent subsequent dispatch.
- Policy service, database, audit sink, connector, or verification outage means no new action.
- Queue retries must be bounded and idempotent; never blindly repeat an action with uncertain outcome.
- Rollback is attempted only when a tested, safe compensating action exists. Report when rollback is unavailable or incomplete.
- Notify operators of execution, denial, failure, pause, and policy changes.

## 8. Audit requirements

Record proposed action, triggering finding and evidence IDs, tenant, target identity, calculated risk and rationale, policy ID/version, autonomy mode, allow/deny decision and reason, approver identity and approval timestamp, execution identity, idempotency key, dispatch/result timestamps, outcome, verification evidence, rollback outcome, and adapter version.

Ordinary runtime roles must not update or delete audit history. Audit integrity and retention must be independently tested.

## 9. Test matrix and release gates

Test at minimum:
- Default OFF; disabled and Observe modes never execute.
- Tenant A policy cannot affect tenant B.
- Tier 2 always blocks without a valid approval, even in Guarded mode.
- Tier 3 is rejected regardless of tenant settings or model output.
- Unlisted actions, stale policy, ambiguous targets, stale evidence, and missing asset context fail closed.
- Concurrent policy disable/pause prevents later dispatch.
- Duplicate requests are idempotent; timeout with unknown outcome does not trigger blind replay.
- Rate, concurrency, target scope, and blast-radius limits are enforced.
- Audit records exist for allowed, denied, failed, cancelled, and rolled-back actions.
- Emergency pause and credential revocation are tested during in-flight operations.

Release sequence:
1. Policy simulator and dry-run audit only.
2. Lab-only reversible action adapter.
3. Independent security review and failure-injection tests.
4. Explicit tenant opt-in after clear configuration UX and audit visibility.
5. Production action adapters only after restore, rollback, monitoring, and incident-response gates pass.

No production Autopilot claim is permitted until these gates pass.
