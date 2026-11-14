import test from "node:test";
import assert from "node:assert/strict";
import {
  investigationAnalysisInputSchema,
  investigationEvidenceDigest,
  validateInvestigationReport
} from "./investigation-analysis.js";

const input = investigationAnalysisInputSchema.parse({
  case: {
    id: "11111111-1111-4111-8111-111111111111",
    title: "Authentication anomaly",
    status: "open",
    priority: "high",
    created_at: "2026-11-14T00:00:00.000Z",
    updated_at: "2026-11-14T00:00:00.000Z"
  },
  findings: [{
    finding_id: "a".repeat(64),
    rule_id: "AUTH_FAILURE_BURST",
    rule_version: "1.0.0",
    title: "Authentication failure burst",
    explanation: "Repeated failed authentication attempts were observed.",
    severity: "high",
    confidence: "high",
    first_seen_at: "2026-11-14T00:00:00.000Z",
    last_seen_at: "2026-11-14T00:04:00.000Z",
    matched_conditions: ["threshold_met"],
    known_limitations: [],
    threat_match_total_count: 0,
    threat_matches_truncated: false,
    evidence_total_count: 1,
    evidence_truncated: false,
    threat_matches: [],
    evidence: [{
      connector_id: "connector-a",
      event_id: "event-1",
      observed_at: "2026-11-14T00:01:00.000Z",
      event_type: "identity.authentication.failure"
    }]
  }]
});

const report = {
  summary: "Repeated authentication failures were observed for this case.",
  summary_evidence_refs: [{ connector_id: "connector-a", event_id: "event-1" }],
  timeline: [{
    observed_at: "2026-11-14T00:01:00.000Z",
    event_ref: { connector_id: "connector-a", event_id: "event-1" },
    description: "A failed authentication event was recorded."
  }],
  hypotheses: [{
    statement: "The activity may indicate attempted credential guessing.",
    supporting_refs: [{ connector_id: "connector-a", event_id: "event-1" }],
    contradicting_refs: [],
    confidence: "low" as const
  }],
  recommendations: [{
    action: "Review the affected account's recent authentication activity.",
    rationale: "The observed failures warrant human review.",
    evidence_refs: [{ connector_id: "connector-a", event_id: "event-1" }],
    human_approval_required: true as const
  }],
  limitations: ["The supplied evidence does not establish a successful compromise."]
};

test("accepts reports whose citations and timeline timestamps match canonical evidence", () => {
  assert.doesNotThrow(() => validateInvestigationReport(report, input));
});

test("rejects event references that do not exist in the evidence manifest", () => {
  const invalid = {
    ...report,
    summary_evidence_refs: [{ connector_id: "other-connector", event_id: "invented-event" }]
  };
  assert.throws(
    () => validateInvestigationReport(invalid, input),
    /ungrounded_evidence_reference/
  );
});

test("rejects timeline timestamps that differ from canonical event time", () => {
  const invalid = {
    ...report,
    timeline: [{
      ...report.timeline[0],
      observed_at: "2026-11-14T00:02:00.000Z"
    }]
  };
  assert.throws(
    () => validateInvestigationReport(invalid, input),
    /ungrounded_timeline_timestamp/
  );
});

test("evidence digest is stable for equivalent object key order", () => {
  const reordered = {
    findings: input.findings,
    case: input.case
  };
  assert.equal(investigationEvidenceDigest(input), investigationEvidenceDigest(
    investigationAnalysisInputSchema.parse(reordered)
  ));
});
