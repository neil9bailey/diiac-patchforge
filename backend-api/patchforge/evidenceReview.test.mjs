import assert from "node:assert/strict";
import test from "node:test";
import {
  SUPPORTED_FINDING_EVIDENCE_CLASSES,
  assertEvidenceEventPersisted,
  compileFindingEvidenceItems,
  createFindingEvidenceRecord,
  createFindingEvidenceReopenEvent,
  createFindingEvidenceReviewEvent,
  projectFindingEvidenceRecord,
  replayFindingEvidenceEvents,
  rolesForEvidenceClass,
  reviewFindingEvidenceRecord
} from "./evidenceReview.js";

const vulnerability = {
  vulnerability_id: "CVE-2026-EVIDENCE-001",
  canonical_id: "CVE-2026-EVIDENCE-001",
  content_hash: "finding-revision-a"
};

test("finding evidence is server-owned, immutable, finding-scoped, and cannot issue final approval", () => {
  const record = createFindingEvidenceRecord({
    tenantId: "tenant-a",
    vulnerability,
    body: {
      evidence_class: "patch_feasibility",
      summary: "Validated in the pre-production service ring.",
      evidence: { test_run_id: "test-42", outcome: "passed" }
    }
  });
  assert.equal(record.server_owned, true);
  assert.equal(record.immutable, true);
  assert.equal(record.finding_revision_hash, "finding-revision-a");
  assert.equal(record.review_state, "pending_review");
  assert.equal(record.final_approval_issued, false);

  const reviewed = reviewFindingEvidenceRecord({
    record,
    vulnerability,
    body: { decision: "accept", expected_content_hash: record.content_hash, rationale: "Evidence checked." },
    principal: { oid: "service-owner-1", roles: ["PatchForge.ServiceOwner"] }
  });
  assert.equal(reviewed.review.server_verified, true);
  assert.equal(reviewed.final_approval_issued, false);
  const compiled = compileFindingEvidenceItems(vulnerability, [reviewed]);
  assert.equal(compiled[0].evidence_state, "accepted_positive_evidence");
  assert.equal(compiled[0].server_verified_review, true);
});

test("finding evidence review fails closed for wrong revision, hash, or reviewer role", () => {
  const record = createFindingEvidenceRecord({
    tenantId: "tenant-a",
    vulnerability,
    body: { evidence_class: "risk_acceptance", summary: "Temporary exception.", evidence: { owner: "risk-owner" } }
  });
  assert.throws(() => reviewFindingEvidenceRecord({
    record,
    vulnerability,
    body: { decision: "accept", expected_content_hash: "wrong" },
    principal: { oid: "risk-owner-1", roles: ["PatchForge.RiskOwner"] }
  }), { code: "evidence_revision_mismatch" });
  assert.throws(() => reviewFindingEvidenceRecord({
    record,
    vulnerability,
    body: { decision: "accept", expected_content_hash: record.content_hash },
    principal: { oid: "security-1", roles: ["PatchForge.SecurityLead"] }
  }), { code: "evidence_reviewer_role_required" });
  assert.throws(() => reviewFindingEvidenceRecord({
    record,
    vulnerability: { ...vulnerability, content_hash: "finding-revision-b" },
    body: { decision: "accept", expected_content_hash: record.content_hash },
    principal: { oid: "risk-owner-1", roles: ["PatchForge.RiskOwner"] }
  }), { code: "finding_revision_changed" });
  assert.equal(compileFindingEvidenceItems({ ...vulnerability, content_hash: "finding-revision-b" }, [record])[0].evidence_state, "stale");
});

test("finding evidence rejects unsupported classes and raw secret fields", () => {
  assert.throws(() => createFindingEvidenceRecord({
    tenantId: "tenant-a",
    vulnerability,
    body: { evidence_class: "untrusted_claim", summary: "Unsupported." }
  }), { code: "unsupported_evidence_class" });
  assert.throws(() => createFindingEvidenceRecord({
    tenantId: "tenant-a",
    vulnerability,
    body: { evidence_class: "test_evidence", summary: "Contains secret.", evidence: { api_key: "do-not-store" } }
  }), { code: "raw_secret_not_allowed" });
});

test("accepted evidence expires fail-closed and can no longer satisfy a gate", () => {
  const record = createFindingEvidenceRecord({
    tenantId: "tenant-a",
    vulnerability,
    now: "2026-07-12T09:00:00Z",
    body: {
      evidence_class: "patch_availability",
      summary: "Vendor patch availability confirmed.",
      expires_at: "2026-07-13T10:00:00+01:00"
    }
  });
  assert.equal(record.expires_at, "2026-07-13T09:00:00.000Z");
  assert.equal(record.expiry_source, "server_validated_submission");
  const event = createFindingEvidenceReviewEvent({
    record,
    vulnerability,
    now: "2026-07-12T10:00:00Z",
    body: { decision: "accept", expected_content_hash: record.content_hash },
    principal: { oid: "security-1", roles: ["PatchForge.SecurityLead"] }
  });
  const current = compileFindingEvidenceItems(vulnerability, [record], [event], { now: "2026-07-13T08:59:59Z" })[0];
  assert.equal(current.evidence_state, "accepted_positive_evidence");
  assert.equal(current.server_verified_review, true);

  const expired = compileFindingEvidenceItems(vulnerability, [record], [event], { now: "2026-07-13T09:00:00Z" })[0];
  assert.equal(expired.review_state, "expired");
  assert.equal(expired.evidence_state, "stale");
  assert.equal(expired.expired, true);
  assert.equal(expired.server_verified_review, false);
  assert.equal(expired.final_approval_issued, false);

  assert.throws(() => createFindingEvidenceRecord({
    tenantId: "tenant-a",
    vulnerability,
    now: "2026-07-12T09:00:00Z",
    body: { evidence_class: "patch_availability", summary: "Bad expiry.", expires_at: "2026-07-13 09:00:00" }
  }), { code: "evidence_expiry_invalid" });
  assert.throws(() => createFindingEvidenceRecord({
    tenantId: "tenant-a",
    vulnerability,
    now: "2026-07-12T09:00:00Z",
    body: { evidence_class: "patch_availability", summary: "Past expiry.", expires_at: "2026-07-12T08:59:59Z" }
  }), { code: "evidence_expiry_must_be_future" });
});

test("role-scoped reopen is append-only and immediately removes accepted gate evidence", () => {
  const record = createFindingEvidenceRecord({
    tenantId: "tenant-a",
    vulnerability,
    body: { evidence_class: "test_evidence", summary: "Test evidence." },
    now: "2026-07-12T09:00:00Z"
  });
  const principal = { oid: "service-owner-1", upn: "owner@diiac.io", roles: ["PatchForge.ServiceOwner"] };
  const review = createFindingEvidenceReviewEvent({
    record,
    vulnerability,
    body: { decision: "accept", expected_content_hash: record.content_hash },
    principal,
    now: "2026-07-12T10:00:00Z"
  });
  const reopen = createFindingEvidenceReopenEvent({
    record,
    vulnerability,
    events: [review],
    body: {
      expected_content_hash: record.content_hash,
      expected_event_hash: review.event_hash,
      rationale: "Test environment changed; evidence must be repeated."
    },
    principal,
    now: "2026-07-12T11:00:00Z"
  });
  assert.equal(reopen.previous_event_hash, review.event_hash);
  assert.equal(reopen.final_approval_issued, false);
  const projection = projectFindingEvidenceRecord({ record, vulnerability, events: [review, reopen], now: "2026-07-12T11:00:01Z" });
  assert.equal(projection.review_state, "reopened");
  assert.equal(projection.evidence_state, "referenced");
  assert.equal(projection.final_approval_issued, false);
  assert.equal(compileFindingEvidenceItems(vulnerability, [record], [review, reopen])[0].server_verified_review, false);

  const rereview = createFindingEvidenceReviewEvent({
    record,
    vulnerability,
    events: [review, reopen],
    body: { decision: "accept", expected_content_hash: record.content_hash, expected_event_hash: reopen.event_hash },
    principal,
    now: "2026-07-12T12:00:00Z"
  });
  assert.equal(replayFindingEvidenceEvents({ record, vulnerability, events: [review, reopen, rereview] }).replay_verified, true);
  assert.equal(compileFindingEvidenceItems(vulnerability, [record], [review, reopen, rereview])[0].server_verified_review, true);
  assert.throws(() => createFindingEvidenceReopenEvent({
    record,
    vulnerability,
    events: [review, reopen],
    body: { expected_content_hash: record.content_hash, expected_event_hash: reopen.event_hash, rationale: "Duplicate reopen." },
    principal
  }), { code: "evidence_reopen_conflict" });
});

test("event conflicts, cross-finding actions, changed revisions, and tampered replay fail closed", () => {
  const record = createFindingEvidenceRecord({
    tenantId: "tenant-a",
    vulnerability,
    body: { evidence_class: "vulnerability_identity", summary: "Identity evidence." },
    now: "2026-07-12T09:00:00Z"
  });
  const principal = { oid: "security-1", roles: ["PatchForge.SecurityLead"] };
  const accepted = createFindingEvidenceReviewEvent({
    record,
    vulnerability,
    body: { decision: "accept", expected_content_hash: record.content_hash },
    principal,
    now: "2026-07-12T10:00:00Z"
  });
  const rejected = createFindingEvidenceReviewEvent({
    record,
    vulnerability,
    body: { decision: "reject", expected_content_hash: record.content_hash },
    principal,
    now: "2026-07-12T10:00:01Z"
  });
  assert.equal(accepted.evidence_event_id, rejected.evidence_event_id);
  assert.throws(() => assertEvidenceEventPersisted(rejected, { record: accepted, created: false }), { code: "evidence_event_conflict" });
  assert.throws(() => createFindingEvidenceReopenEvent({
    record,
    vulnerability,
    events: [accepted],
    body: { expected_content_hash: record.content_hash, expected_event_hash: "stale", rationale: "Refresh." },
    principal
  }), { code: "evidence_event_conflict" });
  assert.throws(() => createFindingEvidenceReviewEvent({
    record,
    vulnerability: { ...vulnerability, vulnerability_id: "CVE-2026-OTHER" },
    body: { decision: "accept", expected_content_hash: record.content_hash },
    principal
  }), { code: "finding_evidence_scope_mismatch" });
  assert.throws(() => createFindingEvidenceReopenEvent({
    record,
    vulnerability: { ...vulnerability, content_hash: "finding-revision-b" },
    events: [accepted],
    body: { expected_content_hash: record.content_hash, expected_event_hash: accepted.event_hash, rationale: "Finding changed." },
    principal
  }), { code: "finding_revision_changed" });

  const crossFindingEvent = { ...accepted, vulnerability_id: "CVE-2026-OTHER" };
  const replay = replayFindingEvidenceEvents({ record, vulnerability, events: [crossFindingEvent] });
  assert.equal(replay.replay_verified, false);
  assert.ok(replay.failures.includes("event_scope_mismatch"));
  assert.equal(compileFindingEvidenceItems(vulnerability, [record], [crossFindingEvent])[0].evidence_state, "stale");

  const expiryTampered = { ...record, expires_at: "2099-01-01T00:00:00.000Z" };
  assert.equal(replayFindingEvidenceEvents({ record: expiryTampered, vulnerability, events: [] }).replay_verified, false);
});

test("every supported evidence class has a deterministic accountable reviewer policy", () => {
  for (const evidenceClass of SUPPORTED_FINDING_EVIDENCE_CLASSES) {
    const record = createFindingEvidenceRecord({
      tenantId: "tenant-a",
      vulnerability,
      body: { evidence_class: evidenceClass, summary: `${evidenceClass} evidence.` },
      now: "2026-07-12T09:00:00Z"
    });
    const roles = rolesForEvidenceClass(evidenceClass);
    assert.ok(roles.size > 0, evidenceClass);
    const event = createFindingEvidenceReviewEvent({
      record,
      vulnerability,
      body: { decision: "accept", expected_content_hash: record.content_hash },
      principal: { oid: `reviewer-${evidenceClass}`, roles: [[...roles][0]] },
      now: "2026-07-12T10:00:00Z"
    });
    assert.equal(event.event_type, "review", evidenceClass);
    assert.equal(event.final_approval_issued, false, evidenceClass);
  }
});
