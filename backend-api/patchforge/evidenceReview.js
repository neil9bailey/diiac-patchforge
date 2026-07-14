import { createHash, randomUUID } from "node:crypto";

export const SUPPORTED_FINDING_EVIDENCE_CLASSES = Object.freeze([
  "vulnerability_identity",
  "affected_asset_scope",
  "affected_service_scope",
  "exploitability_signal",
  "threat_intelligence_context",
  "business_service_impact",
  "patch_availability",
  "patch_feasibility",
  "test_evidence",
  "rollback_plan",
  "compensating_controls",
  "change_window",
  "customer_impact",
  "risk_acceptance",
  "human_review_signoff",
  "known_exploitation_or_urgency",
  "known_exploited_review",
  "owner",
  "expiry_date",
  "rationale",
  "post_patch_validation",
  "safety_impact",
  "maintenance_window",
  "vendor_support"
]);

const SUPPORTED_CLASS_SET = new Set(SUPPORTED_FINDING_EVIDENCE_CLASSES);
const GENERAL_REVIEW_ROLES = new Set(["PatchForge.SecurityLead", "PatchForge.Admin"]);
const SERVICE_REVIEW_ROLES = new Set(["PatchForge.ServiceOwner", "PatchForge.SecurityLead", "PatchForge.Admin"]);
const RISK_REVIEW_ROLES = new Set(["PatchForge.RiskOwner", "PatchForge.Admin"]);
const FINAL_SIGNOFF_ROLES = new Set(["PatchForge.CABApprover", "PatchForge.Admin"]);
const SERVICE_EVIDENCE_CLASSES = new Set([
  "affected_asset_scope",
  "affected_service_scope",
  "business_service_impact",
  "patch_feasibility",
  "test_evidence",
  "rollback_plan",
  "change_window",
  "customer_impact",
  "post_patch_validation",
  "maintenance_window",
  "vendor_support"
]);
const RISK_EVIDENCE_CLASSES = new Set([
  "risk_acceptance",
  "compensating_controls",
  "owner",
  "expiry_date",
  "rationale"
]);
const SECRET_KEY_PATTERN = /(?:password|passwd|secret|token|api[_-]?key|client[_-]?secret|private[_-]?key|credential)/i;
const TIMEZONE_SUFFIX = /(?:z|[+-]\d{2}:\d{2})$/i;

export function createFindingEvidenceRecord({ tenantId, vulnerability, body = {}, lineage = {}, now = new Date().toISOString() }) {
  assertPersistedFinding(vulnerability);
  const evidenceClass = String(body.evidence_class || "").trim();
  if (!SUPPORTED_CLASS_SET.has(evidenceClass)) {
    const error = evidenceError("unsupported_evidence_class", `Unsupported finding evidence class: ${evidenceClass || "not provided"}.`, 400);
    error.allowedEvidenceClasses = SUPPORTED_FINDING_EVIDENCE_CLASSES;
    throw error;
  }
  const evidencePayload = body.evidence && typeof body.evidence === "object"
    ? body.evidence
    : body.payload && typeof body.payload === "object"
      ? body.payload
      : {};
  assertNoRawSecrets(evidencePayload);
  const summary = String(body.summary || evidencePayload.summary || "").trim();
  if (!summary) {
    throw evidenceError("evidence_summary_required", "A concise evidence summary is required.", 400);
  }
  const serverNow = serverTimestamp(now);
  const expiresAt = normalizeExpiry(body.expires_at ?? body.valid_until, serverNow);
  const findingRevisionHash = currentFindingHash(vulnerability);
  const evidenceId = `finding-evidence-${randomUUID()}`;
  const submittedSourceType = String(body.source_type || "human_evidence_submission");
  const immutablePayload = submissionPayload({
    tenant_id: String(tenantId),
    evidence_id: evidenceId,
    vulnerability_id: String(vulnerability.vulnerability_id),
    canonical_id: String(vulnerability.canonical_id || vulnerability.vulnerability_id),
    evidence_class: evidenceClass,
    summary,
    evidence: evidencePayload,
    source_refs: stringList(body.source_refs || body.evidence_refs),
    submitted_source_type: submittedSourceType,
    finding_revision_hash: findingRevisionHash,
    expires_at: expiresAt
  });
  return {
    ...immutablePayload,
    source_class: "human_evidence_submission",
    content_hash: hashCanonical(immutablePayload),
    immutable: true,
    server_owned: true,
    expiry_source: expiresAt ? "server_validated_submission" : null,
    review_state: "pending_review",
    evidence_state: "referenced",
    review: null,
    final_approval_issued: false,
    submitted_at: serverNow,
    created_at: serverNow,
    ...safeLineage(lineage)
  };
}

export function createFindingEvidenceReviewEvent({ record, vulnerability, events = [], body = {}, principal = null, lineage = {}, now = new Date().toISOString() }) {
  const serverNow = serverTimestamp(now);
  const replay = replayFindingEvidenceEvents({ record, vulnerability, events, now: serverNow });
  assertReviewableRecord(record, vulnerability, body, principal, replay);
  if (!replay.replay_verified) {
    throw evidenceError("evidence_event_replay_failed", "Evidence review history failed integrity replay and cannot be extended.", 409);
  }
  if (replay.current_state !== "pending_review" && replay.current_state !== "reopened") {
    throw evidenceError("evidence_review_conflict", `Evidence is already ${replay.current_state}; reopen it before recording another review.`, 409);
  }
  if (isExpired(record.expires_at, serverNow)) {
    throw evidenceError("evidence_expired", "Expired evidence cannot be accepted or rejected as current evidence. Submit a refreshed evidence record.", 409);
  }
  assertExpectedEventHash(body, replay.latest_event_hash);
  const decision = String(body.decision || body.review_state || "").toLowerCase();
  if (!["accept", "accepted", "reviewed", "reject", "rejected"].includes(decision)) {
    throw evidenceError("evidence_review_decision_required", "Evidence review decision must be accept or reject.", 400);
  }
  const accepted = ["accept", "accepted", "reviewed"].includes(decision);
  return buildEvidenceEvent({
    record,
    vulnerability,
    eventType: "review",
    decision: accepted ? "accepted" : "rejected",
    rationale: String(body.rationale || body.notes || "").trim(),
    principal,
    lineage,
    previousEventHash: replay.latest_event_hash,
    now: serverNow
  });
}

export function createFindingEvidenceReopenEvent({ record, vulnerability, events = [], body = {}, principal = null, lineage = {}, now = new Date().toISOString() }) {
  const serverNow = serverTimestamp(now);
  const replay = replayFindingEvidenceEvents({ record, vulnerability, events, now: serverNow });
  assertReviewableRecord(record, vulnerability, body, principal, replay);
  if (!replay.replay_verified) {
    throw evidenceError("evidence_event_replay_failed", "Evidence review history failed integrity replay and cannot be extended.", 409);
  }
  if (!["reviewed", "rejected", "expired"].includes(replay.current_state)) {
    throw evidenceError("evidence_reopen_conflict", `Evidence in state ${replay.current_state} cannot be reopened.`, 409);
  }
  if (replay.latest_event?.event_type === "reopen") {
    throw evidenceError("evidence_reopen_conflict", "Evidence is already reopened. Submit refreshed evidence when the immutable record has expired.", 409);
  }
  assertExpectedEventHash(body, replay.latest_event_hash);
  const rationale = String(body.rationale || body.reason || "").trim();
  if (!rationale) {
    throw evidenceError("evidence_reopen_rationale_required", "Reopening evidence requires an auditable rationale.", 400);
  }
  return buildEvidenceEvent({
    record,
    vulnerability,
    eventType: "reopen",
    decision: "reopened",
    rationale,
    principal,
    lineage,
    previousEventHash: replay.latest_event_hash,
    now: serverNow
  });
}

// Backward-compatible pure projection helper. API persistence uses append-only events.
export function reviewFindingEvidenceRecord({ record, vulnerability, body = {}, principal = null, lineage = {}, now = new Date().toISOString() }) {
  const event = createFindingEvidenceReviewEvent({ record, vulnerability, events: [], body, principal, lineage, now });
  return projectFindingEvidenceRecord({ record, vulnerability, events: [event], now });
}

export function replayFindingEvidenceEvents({ record, vulnerability, events = [], now = new Date().toISOString() }) {
  const serverNow = serverTimestamp(now);
  const relevant = (Array.isArray(events) ? events : []).filter((event) => event?.evidence_id === record?.evidence_id);
  const failures = [];
  if (!record?.server_owned || !record?.immutable || !record?.evidence_id) failures.push("submission_not_server_owned_immutable");
  if (record?.submitted_source_type && hashCanonical(submissionPayload(record)) !== record.content_hash) failures.push("submission_content_hash_mismatch");
  const remaining = [...relevant];
  const chain = [];
  let previousEventHash = null;
  while (remaining.length) {
    const matches = remaining.filter((event) => normalizeOptionalHash(event.previous_event_hash) === normalizeOptionalHash(previousEventHash));
    if (matches.length !== 1) {
      failures.push(matches.length > 1 ? "event_chain_fork" : "event_chain_orphan");
      break;
    }
    const event = matches[0];
    remaining.splice(remaining.indexOf(event), 1);
    if (!event.server_owned || !event.immutable) failures.push("event_not_server_owned_immutable");
    if (!sameId(event.tenant_id, record.tenant_id)
      || !sameId(event.vulnerability_id, record.vulnerability_id)
      || !sameId(event.canonical_id, record.canonical_id)) failures.push("event_scope_mismatch");
    if (event.evidence_content_hash !== record.content_hash) failures.push("event_content_hash_mismatch");
    if (event.finding_revision_hash !== record.finding_revision_hash) failures.push("event_finding_revision_mismatch");
    if (event.evidence_class !== record.evidence_class) failures.push("event_evidence_class_mismatch");
    if ((event.expires_at || null) !== (record.expires_at || null)) failures.push("event_expiry_mismatch");
    if (event.evidence_event_id !== evidenceEventId(record, previousEventHash)) failures.push("event_id_mismatch");
    if (!event.actor_oid && !event.actor_upn) failures.push("event_actor_missing");
    if (!(event.actor_roles || []).some((role) => rolesForEvidenceClass(record.evidence_class).has(role))) failures.push("event_actor_role_invalid");
    if (!isValidEventTransition(event)) failures.push("event_transition_invalid");
    if (event.event_hash !== hashCanonical(eventPayload(event))) failures.push("event_hash_mismatch");
    chain.push(event);
    previousEventHash = event.event_hash;
  }
  if (remaining.length) failures.push("event_chain_incomplete");
  const latest = chain.at(-1) || null;
  const currentRevision = record?.finding_revision_hash === currentFindingHash(vulnerability || {});
  if (!currentRevision) failures.push("finding_revision_changed");
  const expired = isExpired(record?.expires_at, serverNow);
  let currentState = "pending_review";
  if (latest?.event_type === "review") currentState = latest.decision === "accepted" ? "reviewed" : "rejected";
  if (latest?.event_type === "reopen") currentState = "reopened";
  if (expired) currentState = "expired";
  if (failures.length) currentState = currentRevision ? "invalidated" : "stale";
  return {
    replay_verified: failures.length === 0,
    failures: [...new Set(failures)],
    events: chain,
    event_count: chain.length,
    latest_event: latest,
    latest_event_hash: latest?.event_hash || null,
    current_state: currentState,
    current_revision: currentRevision,
    expired,
    expires_at: record?.expires_at || null,
    evaluated_at: serverNow
  };
}

export function projectFindingEvidenceRecord({ record, vulnerability, events = [], now = new Date().toISOString() }) {
  const replay = replayFindingEvidenceEvents({ record, vulnerability, events, now });
  const latest = replay.latest_event;
  const accepted = replay.replay_verified && replay.current_state === "reviewed" && latest?.decision === "accepted";
  const rejected = replay.replay_verified && replay.current_state === "rejected";
  const review = latest?.event_type === "review" ? {
    decision: latest.decision,
    reviewer_oid: latest.actor_oid,
    reviewer_upn: latest.actor_upn,
    reviewer_roles: latest.actor_roles,
    reviewed_content_hash: latest.evidence_content_hash,
    finding_revision_hash: latest.finding_revision_hash,
    rationale: latest.rationale,
    reviewed_at: latest.created_at,
    server_verified: replay.replay_verified
  } : null;
  return {
    ...record,
    review_state: replay.current_state === "expired" ? "expired" : rejected ? "rejected" : accepted ? "reviewed" : replay.current_state,
    evidence_state: replay.current_state === "expired" || replay.current_state === "stale" || replay.current_state === "invalidated"
      ? "stale"
      : rejected ? "rejected" : accepted ? "accepted_positive_evidence" : "referenced",
    review,
    reviewed_by: review?.reviewer_upn || review?.reviewer_oid || null,
    reviewed_at: review?.reviewed_at || null,
    latest_event_hash: replay.latest_event_hash,
    event_count: replay.event_count,
    replay_verified: replay.replay_verified,
    replay_failures: replay.failures,
    expired: replay.expired,
    expiry_evaluated_at: replay.evaluated_at,
    final_approval_issued: false
  };
}

export function compileFindingEvidenceItems(vulnerability, records = [], events = [], options = {}) {
  const vulnerabilityIds = new Set([
    vulnerability?.vulnerability_id,
    vulnerability?.canonical_id
  ].filter(Boolean).map(normalizeId));
  return (Array.isArray(records) ? records : [])
    .filter((record) => record?.server_owned === true)
    .filter((record) => vulnerabilityIds.has(normalizeId(record.vulnerability_id)) || vulnerabilityIds.has(normalizeId(record.canonical_id)))
    .map((record) => {
      const recordEvents = (Array.isArray(events) ? events : []).filter((event) => event?.evidence_id === record.evidence_id);
      if (!recordEvents.length && record.review?.server_verified === true) {
        return compileLegacyRecord(vulnerability, record, options.now);
      }
      const projection = projectFindingEvidenceRecord({ record, vulnerability, events: recordEvents, now: options.now });
      const accepted = projection.replay_verified
        && projection.review_state === "reviewed"
        && projection.evidence_state === "accepted_positive_evidence"
        && projection.expired !== true;
      return {
        evidence_ref: record.evidence_id,
        evidence_class: record.evidence_class,
        source_class: record.source_class || "human_evidence_submission",
        review_state: projection.review_state,
        evidence_state: projection.evidence_state,
        summary: record.summary,
        content_hash: record.content_hash,
        finding_revision_hash: record.finding_revision_hash,
        expires_at: record.expires_at || null,
        expired: projection.expired,
        latest_event_hash: projection.latest_event_hash,
        evidence_event_count: projection.event_count,
        replay_verified: projection.replay_verified,
        replay_failures: projection.replay_failures,
        server_owned: true,
        server_verified_review: accepted,
        immutable: true,
        advisory_only: false,
        final_approval_issued: false
      };
    });
}

export function rolesForEvidenceClass(evidenceClass) {
  if (evidenceClass === "human_review_signoff") return FINAL_SIGNOFF_ROLES;
  if (RISK_EVIDENCE_CLASSES.has(evidenceClass)) return RISK_REVIEW_ROLES;
  if (SERVICE_EVIDENCE_CLASSES.has(evidenceClass)) return SERVICE_REVIEW_ROLES;
  return GENERAL_REVIEW_ROLES;
}

export function assertEvidenceEventPersisted(proposed, persisted) {
  if (!persisted?.record) {
    throw evidenceError("evidence_event_persistence_failed", "Evidence event was not persisted.", 500);
  }
  if (persisted.record.event_hash !== proposed.event_hash) {
    throw evidenceError("evidence_event_conflict", "Another review action changed this evidence state first. Refresh and retry against the latest event hash.", 409);
  }
  return persisted.record;
}

function buildEvidenceEvent({ record, vulnerability, eventType, decision, rationale, principal, lineage, previousEventHash, now }) {
  const roles = [...new Set((principal?.roles || []).map(String))].sort();
  const eventId = evidenceEventId(record, previousEventHash);
  const event = {
    tenant_id: record.tenant_id,
    evidence_event_id: eventId,
    evidence_id: record.evidence_id,
    vulnerability_id: record.vulnerability_id,
    canonical_id: record.canonical_id,
    evidence_class: record.evidence_class,
    evidence_content_hash: record.content_hash,
    finding_revision_hash: currentFindingHash(vulnerability),
    previous_event_hash: previousEventHash || null,
    event_type: eventType,
    decision,
    rationale,
    ...safeLineage(lineage),
    actor_oid: principal?.oid || null,
    actor_upn: principal?.upn || null,
    actor_roles: roles,
    expires_at: record.expires_at || null,
    server_owned: true,
    immutable: true,
    final_approval_issued: false,
    created_at: now
  };
  event.event_hash = hashCanonical(eventPayload(event));
  return event;
}

function assertReviewableRecord(record, vulnerability, body, principal, replay) {
  if (!record?.server_owned || !record?.immutable || !record?.evidence_id) {
    throw evidenceError("finding_evidence_not_found", "The server-owned immutable evidence record was not found.", 404);
  }
  if (!sameId(record.vulnerability_id, vulnerability?.vulnerability_id)) {
    throw evidenceError("finding_evidence_scope_mismatch", "Evidence can only be actioned against its exact finding.", 409);
  }
  const findingHash = currentFindingHash(vulnerability);
  if (record.finding_revision_hash !== findingHash || replay?.current_revision === false) {
    throw evidenceError("finding_revision_changed", "The finding changed after this evidence was submitted. Submit new evidence against the current revision.", 409);
  }
  const expectedHash = String(body.expected_content_hash || "");
  if (!expectedHash || expectedHash !== record.content_hash) {
    throw evidenceError("evidence_revision_mismatch", "The action requires the exact immutable evidence content hash.", 409);
  }
  const roles = new Set((principal?.roles || []).map(String));
  const actorId = principal?.oid || principal?.upn || null;
  if (!actorId) {
    throw evidenceError("authenticated_reviewer_required", "An authenticated reviewer principal is required.", 403);
  }
  const allowedRoles = rolesForEvidenceClass(record.evidence_class);
  if (![...roles].some((role) => allowedRoles.has(role))) {
    throw evidenceError("evidence_reviewer_role_required", `The reviewer is not authorized for ${record.evidence_class}.`, 403);
  }
}

function assertExpectedEventHash(body, latestEventHash) {
  const supplied = body.expected_event_hash ?? body.expected_latest_event_hash ?? null;
  if (latestEventHash && supplied !== latestEventHash) {
    throw evidenceError("evidence_event_conflict", "The evidence event history changed. Refresh and retry with the latest event hash.", 409);
  }
  if (!latestEventHash && supplied) {
    throw evidenceError("evidence_event_conflict", "No prior evidence event exists for the supplied event hash.", 409);
  }
}

function compileLegacyRecord(vulnerability, record, now) {
  const findingRevisionHash = currentFindingHash(vulnerability || {});
  const currentRevision = record.finding_revision_hash === findingRevisionHash;
  const expired = isExpired(record.expires_at, now);
  const serverReviewed = record.review?.server_verified === true
    && record.review?.reviewed_content_hash === record.content_hash
    && record.review?.finding_revision_hash === findingRevisionHash;
  const accepted = currentRevision && !expired && serverReviewed && record.review_state === "reviewed" && record.evidence_state === "accepted_positive_evidence";
  const rejected = record.review_state === "rejected" || record.evidence_state === "rejected";
  return {
    evidence_ref: record.evidence_id,
    evidence_class: record.evidence_class,
    source_class: record.source_class || "human_evidence_submission",
    review_state: expired ? "expired" : rejected ? "rejected" : accepted ? "reviewed" : currentRevision ? "pending_review" : "invalidated",
    evidence_state: expired || !currentRevision ? "stale" : rejected ? "rejected" : accepted ? "accepted_positive_evidence" : "referenced",
    summary: record.summary,
    content_hash: record.content_hash,
    finding_revision_hash: record.finding_revision_hash,
    expires_at: record.expires_at || null,
    expired,
    server_owned: true,
    server_verified_review: accepted,
    immutable: true,
    advisory_only: false,
    final_approval_issued: false,
    replay_verified: false,
    replay_failures: ["legacy_mutable_review_projection"]
  };
}

function submissionPayload(record) {
  return {
    tenant_id: String(record.tenant_id),
    evidence_id: String(record.evidence_id),
    vulnerability_id: String(record.vulnerability_id),
    canonical_id: String(record.canonical_id || record.vulnerability_id),
    evidence_class: String(record.evidence_class),
    summary: String(record.summary),
    evidence: record.evidence && typeof record.evidence === "object" ? record.evidence : {},
    source_refs: stringList(record.source_refs),
    submitted_source_type: String(record.submitted_source_type || "human_evidence_submission"),
    finding_revision_hash: String(record.finding_revision_hash),
    ...(record.expires_at ? { expires_at: String(record.expires_at) } : {})
  };
}

function eventPayload(event) {
  return {
    tenant_id: event.tenant_id,
    evidence_event_id: event.evidence_event_id,
    evidence_id: event.evidence_id,
    vulnerability_id: event.vulnerability_id,
    canonical_id: event.canonical_id,
    evidence_class: event.evidence_class,
    evidence_content_hash: event.evidence_content_hash,
    finding_revision_hash: event.finding_revision_hash,
    previous_event_hash: event.previous_event_hash || null,
    event_type: event.event_type,
    decision: event.decision,
    rationale: event.rationale,
    actor_oid: event.actor_oid || null,
    actor_upn: event.actor_upn || null,
    actor_roles: Array.isArray(event.actor_roles) ? event.actor_roles.map(String).sort() : [],
    actor_tenant_id: event.actor_tenant_id || null,
    effective_tenant_id: event.effective_tenant_id || null,
    requested_tenant_id: event.requested_tenant_id || null,
    tenant_id_source: event.tenant_id_source || null,
    tenant_override_ignored: Boolean(event.tenant_override_ignored),
    expires_at: event.expires_at || null,
    server_owned: true,
    immutable: true,
    final_approval_issued: false,
    created_at: event.created_at
  };
}

function evidenceEventId(record, previousEventHash) {
  return `finding-evidence-event-${hashCanonical({
    tenant_id: record.tenant_id,
    evidence_id: record.evidence_id,
    previous_event_hash: previousEventHash || "root"
  }).slice(0, 32)}`;
}

function isValidEventTransition(event) {
  return (event.event_type === "review" && ["accepted", "rejected"].includes(event.decision))
    || (event.event_type === "reopen" && event.decision === "reopened" && Boolean(String(event.rationale || "").trim()));
}

function normalizeExpiry(value, now) {
  if (value === undefined || value === null || value === "") return null;
  const text = String(value).trim();
  if (!TIMEZONE_SUFFIX.test(text)) {
    throw evidenceError("evidence_expiry_invalid", "Evidence expiry must be an ISO-8601 timestamp with an explicit timezone.", 400);
  }
  const timestamp = Date.parse(text);
  if (!Number.isFinite(timestamp)) {
    throw evidenceError("evidence_expiry_invalid", "Evidence expiry is not a valid timestamp.", 400);
  }
  if (timestamp <= Date.parse(now)) {
    throw evidenceError("evidence_expiry_must_be_future", "Evidence expiry must be later than the server submission time.", 400);
  }
  return new Date(timestamp).toISOString();
}

function isExpired(expiresAt, now = new Date().toISOString()) {
  if (!expiresAt) return false;
  const expiry = Date.parse(expiresAt);
  const observed = Date.parse(now || new Date().toISOString());
  return !Number.isFinite(expiry) || !Number.isFinite(observed) || observed >= expiry;
}

function currentFindingHash(vulnerability) {
  return String(vulnerability?.content_hash || hashCanonical(vulnerability || {}));
}

function assertPersistedFinding(vulnerability) {
  if (!vulnerability?.vulnerability_id) {
    throw evidenceError("vulnerability_not_found", "A persisted finding is required before evidence can be submitted.", 404);
  }
}

function serverTimestamp(value) {
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed)) throw evidenceError("server_timestamp_invalid", "Server evidence timestamp is invalid.", 500);
  return new Date(parsed).toISOString();
}

function safeLineage(lineage = {}) {
  return {
    actor_oid: lineage.actor_oid || null,
    actor_upn: lineage.actor_upn || null,
    actor_roles: Array.isArray(lineage.actor_roles) ? lineage.actor_roles.map(String).sort() : [],
    actor_tenant_id: lineage.actor_tenant_id || null,
    effective_tenant_id: lineage.effective_tenant_id || null,
    requested_tenant_id: lineage.requested_tenant_id || null,
    tenant_id_source: lineage.tenant_id_source || null,
    tenant_override_ignored: Boolean(lineage.tenant_override_ignored)
  };
}

function assertNoRawSecrets(value, path = []) {
  if (!value || typeof value !== "object") return;
  for (const [key, nested] of Object.entries(value)) {
    const currentPath = [...path, key];
    if (SECRET_KEY_PATTERN.test(key) && nested !== null && nested !== "") {
      throw evidenceError("raw_secret_not_allowed", `Raw secret field is not allowed in finding evidence: ${currentPath.join(".")}.`, 400);
    }
    if (nested && typeof nested === "object") assertNoRawSecrets(nested, currentPath);
  }
}

function hashCanonical(value) {
  return createHash("sha256").update(canonicalJson(value)).digest("hex");
}

function canonicalJson(value) {
  return JSON.stringify(sortValue(value));
}

function sortValue(value) {
  if (Array.isArray(value)) return value.map(sortValue);
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value).sort(([left], [right]) => left.localeCompare(right)).map(([key, nested]) => [key, sortValue(nested)]));
  }
  return value;
}

function stringList(value) {
  return [...new Set((Array.isArray(value) ? value : value ? [value] : []).map(String).map((item) => item.trim()).filter(Boolean))];
}

function sameId(left, right) {
  return Boolean(normalizeId(left) && normalizeId(left) === normalizeId(right));
}

function normalizeId(value) {
  return String(value || "").trim().toLowerCase();
}

function normalizeOptionalHash(value) {
  return value ? String(value) : null;
}

function evidenceError(code, message, statusCode) {
  return Object.assign(new Error(message), { code, statusCode, publicError: code, publicMessage: message });
}
