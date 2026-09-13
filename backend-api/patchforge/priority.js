import { createHash, randomUUID } from "node:crypto";
import { parseSecurityBoolean, parseSecurityBooleanAny } from "./securityBooleans.js";

const WORKFLOW_REVIEW_STATES = new Set(["triage", "ciso_review_required"]);
export const ACTION_PACK_ISSUANCE_GUIDANCE = Object.freeze({
  error: "action_pack_issuance_unavailable",
  message: "Auxiliary action-pack issuance has been retired. Generate a runtime-signed decision pack using the existing decision-pack workflow.",
  decision_pack_endpoint: "/api/patchforge/decision-packs/generate",
  decision_pack_method: "POST",
  verified: false,
  signature_ok: false,
  final_approval_issued: false
});

const POSTURES = [
  ["Emergency action recommended", 80],
  ["Priority patch candidate", 62],
  ["Scheduled remediation", 42],
  ["Mitigate and monitor", 28],
  ["Exception review required", 0],
  ["Insufficient evidence", 0]
];

export function buildPriorityIndex(input = {}) {
  input = normalizeDecisionFlags(input);
  const missing = requiredMissing(input, ["cve_id", "asset_id"]);
  const evidenceConfidence = number(input.evidence_confidence, 0.5);
  if (missing.length || evidenceConfidence < 0.25) {
    return priorityResult(input, 0, "Insufficient evidence", [`Missing required evidence: ${missing.join(", ") || "evidence confidence"}.`]);
  }

  const reasons = [];
  let score = 0;
  add(input.confirmed_asset_match, 16, "confirmed asset match");
  add(input.kev, 18, "CISA KEV");
  add(number(input.epss_probability) >= 0.5 || number(input.epss_percentile) >= 0.9, 12, "high EPSS");
  add(number(input.cvss_score) >= 9, 14, "critical CVSS");
  add(number(input.cvss_score) >= 7 && number(input.cvss_score) < 9, 8, "high CVSS");
  add(input.active_exploitation || input.exploit_signal, 15, "active exploitation signal");
  add(parseSecurityBoolean(input.ransomware_association)
    || (typeof input.ransomware_association === "string" && input.ransomware_association.trim().toLowerCase() === "known"), 10, "ransomware association");
  add(input.internet_exposed, 10, "internet exposed asset");
  add(String(input.asset_criticality || "").toLowerCase() === "critical", 9, "critical asset");
  add(input.sla_pressure, 6, "SLA pressure");
  add(input.patch_available, 8, "patch available");
  add(input.patch_maturity === "mature" || input.patch_maturity === "vendor_supported", 5, "mature/vendor-supported fix");
  reduce(input.workaround_available || input.compensating_controls, 8, "workaround or compensating controls");
  reduce(input.operational_risk === "low", 3, "low operational risk");

  const operationalRiskHigh = String(input.operational_risk || "").toLowerCase() === "high";
  const patchMaturityLow = ["low", "unknown", "new"].includes(String(input.patch_maturity || "").toLowerCase());
  const normalized = Math.max(0, Math.min(100, Math.round(score * Math.max(0.3, evidenceConfidence))));
  if (operationalRiskHigh && patchMaturityLow && normalized >= 45) {
    return priorityResult(input, normalized, "Exception review required", [...reasons, "High operational risk and immature patch require exception review."]);
  }
  if (input.workaround_available && !input.patch_available && normalized < 62) {
    return priorityResult(input, normalized, "Mitigate and monitor", reasons);
  }
  const posture = POSTURES.find(([, threshold]) => normalized >= threshold)?.[0] || "Scheduled remediation";
  return priorityResult(input, normalized, posture, reasons);

  function add(condition, points, reason) {
    if (condition) {
      score += points;
      reasons.push(`+${points}: ${reason}`);
    }
  }
  function reduce(condition, points, reason) {
    if (condition) {
      score -= points;
      reasons.push(`-${points}: ${reason}`);
    }
  }
}

export function comparePatchActions(input = {}) {
  input = normalizeDecisionFlags(input);
  const options = [
    actionOption("direct_patch", input, 88, 42, "Apply the vendor-supported fixed version through normal or emergency change."),
    actionOption("hotfix", input, 78, 55, "Use a vendor hotfix when the full patch cannot be adopted in the available window."),
    actionOption("major_upgrade", input, 84, 75, "Move to the supported major branch when fixed versions require platform uplift."),
    actionOption("workaround", input, 45, 30, "Apply a documented mitigation while patch evidence or window is completed."),
    actionOption("compensating_controls", input, 38, 28, "Reduce exposure through layered controls and monitoring with owner and expiry."),
    actionOption("defer_with_exception", input, 5, 65, "Defer only with accountable risk owner, CISO review, rationale, expiry, and evidence.")
  ];
  const selected = selectCandidate(options, input);
  return {
    id: input.id || `patch-compare-${Date.now()}-${randomUUID().slice(0, 8)}`,
    customer_id: input.customer_id || null,
    asset_id: input.asset_id || null,
    cve_id: input.cve_id || input.cve || null,
    options,
    selected_candidate: selected.action_type,
    comparison_summary: `${humanize(selected.action_type)} is the governed candidate. Human change approval remains required and PatchForge will not approve or deploy production changes.`,
    evidence_refs: list(input.evidence_refs),
    unresolved_gaps: selected.unresolved_gaps,
    ciso_approval_required: selected.ciso_approval_required,
    human_change_approval_required: true,
    no_autonomous_production_approval: true,
    created_at: new Date().toISOString()
  };
}

export function createWorkflowItem(input = {}) {
  const reviewRequired = parseSecurityBooleanAny(input.ciso_approval_required, input.ciso_review_required, input.exception_requested)
    || /critical|emergency|exception|accepted_risk/i.test(String(input.recommended_action || ""));
  const status = workflowReviewState(input.status ?? (reviewRequired ? "ciso_review_required" : "triage"));
  return {
    tenant_id: input.tenant_id,
    id: `action-${randomUUID()}`,
    customer_id: input.customer_id || null,
    asset_id: input.asset_id || null,
    cve_id: input.cve_id || input.vulnerability_id || null,
    recommended_action: input.recommended_action || "complete_evidence_review",
    status,
    owner: input.owner || "unassigned",
    sla: input.sla || input.sla_due_at || null,
    exception_requested: parseSecurityBoolean(input.exception_requested),
    ciso_review_required: reviewRequired || status === "ciso_review_required",
    evidence_refs: list(input.evidence_refs),
    audit_trail: [{
      event: "workflow_item_created",
      status,
      actor: input.actor_upn || "system",
      ...workflowLineage(input),
      at: new Date().toISOString()
    }],
    ...workflowLineage(input),
    final_approval_issued: false,
    human_review_required: true,
    no_autonomous_production_approval: true,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString()
  };
}

export function transitionWorkflowItem(item = {}, input = {}) {
  const status = workflowReviewState(input.status ?? item.status ?? "triage");
  const next = {
    ...item,
    status,
    owner: input.owner || item.owner || "unassigned",
    sla: input.sla || input.sla_due_at || item.sla || null,
    ciso_review_required: parseSecurityBooleanAny(item.ciso_review_required, input.ciso_review_required, input.ciso_approval_required)
      || status === "ciso_review_required",
    ...workflowLineage(input),
    final_approval_issued: false,
    human_review_required: true,
    no_autonomous_production_approval: true,
    updated_at: new Date().toISOString()
  };
  next.audit_trail = [
    ...(Array.isArray(item.audit_trail) ? item.audit_trail : []),
    {
      event: "workflow_status_transitioned",
      from: item.status || null,
      to: status,
      actor: input.actor_upn || "system",
      ...workflowLineage(input),
      at: next.updated_at
    }
  ];
  return next;
}

export function buildSignedActionPack() {
  const error = new Error(ACTION_PACK_ISSUANCE_GUIDANCE.message);
  error.statusCode = 410;
  error.publicError = ACTION_PACK_ISSUANCE_GUIDANCE.error;
  error.publicMessage = ACTION_PACK_ISSUANCE_GUIDANCE.message;
  throw error;
}

export function verifySignedActionPack(pack = {}) {
  const expected = sha256({ payload: pack.payload, source_hashes: pack.source_hashes || [] });
  const integrityOk = pack.pack_hash === expected && pack.signature === `test-digest:${expected}`;
  return {
    verified: false,
    integrity_ok: integrityOk,
    method: "legacy_test_digest_integrity_only",
    reason: "Auxiliary test digests do not authenticate a signer. Use runtime-signed decision packs for verified evidence.",
    pack_hash: pack.pack_hash || null,
    expected_hash: expected,
    signature_ok: false,
    replayable: false,
    production_key_management_required: true
  };
}

function workflowReviewState(value) {
  if (typeof value !== "string" || !WORKFLOW_REVIEW_STATES.has(value)) {
    const error = new Error("Workflow status must be triage or ciso_review_required. Final decisions require a separate evidence-bound human approval workflow.");
    error.statusCode = 400;
    error.publicError = "unsupported_workflow_status";
    error.publicMessage = error.message;
    throw error;
  }
  return value;
}

function workflowLineage(input) {
  return {
    actor_oid: input.actor_oid || null,
    actor_upn: input.actor_upn || null,
    actor_roles: Array.isArray(input.actor_roles) ? input.actor_roles : [],
    actor_tenant_id: input.actor_tenant_id || null,
    effective_tenant_id: input.effective_tenant_id || input.tenant_id || null
  };
}

function normalizeDecisionFlags(input) {
  const normalized = { ...input };
  for (const field of ["confirmed_asset_match", "kev", "active_exploitation", "exploit_signal", "internet_exposed", "sla_pressure", "patch_available", "workaround_available", "compensating_controls", "production_impacting", "defer", "accepted_risk"]) {
    normalized[field] = parseSecurityBoolean(input[field]);
  }
  normalized.kev = parseSecurityBooleanAny(input.kev, input.known_exploited, input.cisa_kev);
  return normalized;
}

function actionOption(actionType, input, riskReductionBase, operationalRiskBase, recommendation) {
  const hasEvidence = list(input.evidence_refs).length > 0;
  const severe = String(input.severity || "").toLowerCase() === "critical" || input.kev || input.active_exploitation;
  const exception = actionType === "defer_with_exception";
  const productionImpacting = !["workaround", "compensating_controls"].includes(actionType) || Boolean(input.production_impacting);
  return {
    id: `${actionType}-${shortHash(input)}`,
    action_type: actionType,
    recommended_action: recommendation,
    patch_url: actionType === "direct_patch" ? input.patch_url || null : null,
    hotfix_url: actionType === "hotfix" ? input.hotfix_url || null : null,
    workaround: ["workaround", "compensating_controls"].includes(actionType) ? input.workaround || "Documented mitigation evidence required." : null,
    risk_reduction: Math.max(0, Math.min(100, riskReductionBase + (input.kev ? 6 : 0) + (hasEvidence ? 4 : -8))),
    operational_risk: Math.max(0, Math.min(100, operationalRiskBase + (input.operational_risk === "high" ? 12 : 0))),
    service_impact: productionImpacting ? "production-impacting change review required" : "control-only review required",
    rollback_risk: actionType === "major_upgrade" ? "high" : actionType === "direct_patch" ? "medium" : "low_to_medium",
    change_window_suitability: actionType === "hotfix" ? "short_window_candidate" : actionType === "major_upgrade" ? "planned_window_required" : "standard_window_required",
    ciso_approval_required: Boolean(severe || exception || actionType === "defer_with_exception"),
    human_change_approval_required: true,
    no_autonomous_production_approval: true,
    evidence_refs: list(input.evidence_refs),
    unresolved_gaps: hasEvidence ? [] : ["Reviewed source, test, rollback, and service-impact evidence required."]
  };
}

function selectCandidate(options, input) {
  if (input.defer || input.accepted_risk) {
    return options.find((option) => option.action_type === "defer_with_exception");
  }
  if (!input.patch_available && input.workaround_available) {
    return options.find((option) => option.action_type === "workaround");
  }
  return [...options].sort((a, b) => (b.risk_reduction - b.operational_risk / 2) - (a.risk_reduction - a.operational_risk / 2))[0];
}

function priorityResult(input, score, posture, reasons) {
  return {
    id: input.id || `priority-${input.cve_id || input.cve || "unknown"}-${input.asset_id || "asset"}`,
    cve_id: input.cve_id || input.cve || null,
    asset_id: input.asset_id || null,
    priority_score: Math.max(0, Math.min(100, score)),
    posture,
    explainability: reasons,
    thresholds: {
      emergency_action_recommended: 80,
      priority_patch_candidate: 62,
      scheduled_remediation: 42,
      mitigate_and_monitor: 28,
      insufficient_evidence_confidence_below: 0.25
    },
    deterministic: true,
    final_approval_issued: false,
    human_review_required: true,
    no_autonomous_production_approval: true
  };
}

function requiredMissing(input, fields) {
  return fields.filter((field) => input[field] === undefined || input[field] === null || input[field] === "");
}

function number(value, fallback = 0) {
  const numeric = Number(value);
  return Number.isFinite(numeric) ? numeric : fallback;
}

function list(...values) {
  return values.flatMap((value) => {
    if (Array.isArray(value)) return value.flatMap((item) => list(item));
    if (value === undefined || value === null || value === "") return [];
    return String(value).split(",").map((item) => item.trim()).filter(Boolean);
  });
}

function shortHash(value) {
  return sha256(value).slice(0, 8);
}

function sha256(value) {
  return createHash("sha256").update(JSON.stringify(value)).digest("hex");
}

function humanize(value) {
  return String(value || "").replace(/[_-]+/g, " ").replace(/\b\w/g, (letter) => letter.toUpperCase());
}
