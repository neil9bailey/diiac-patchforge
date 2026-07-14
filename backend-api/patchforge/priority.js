import { createHash, randomUUID } from "node:crypto";

const POSTURES = [
  ["Emergency action recommended", 80],
  ["Priority patch candidate", 62],
  ["Scheduled remediation", 42],
  ["Mitigate and monitor", 28],
  ["Exception review required", 0],
  ["Insufficient evidence", 0]
];

export function buildPriorityIndex(input = {}) {
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
  add(input.ransomware_association === true || String(input.ransomware_association).toLowerCase() === "known", 10, "ransomware association");
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
  const status = input.status || (input.ciso_approval_required ? "ciso_review_required" : "triage");
  return {
    tenant_id: input.tenant_id,
    id: input.id || `action-${Date.now()}-${randomUUID().slice(0, 8)}`,
    customer_id: input.customer_id || null,
    asset_id: input.asset_id || null,
    cve_id: input.cve_id || input.vulnerability_id || null,
    recommended_action: input.recommended_action || "complete_evidence_review",
    status,
    owner: input.owner || "unassigned",
    sla: input.sla || input.sla_due_at || null,
    exception_requested: Boolean(input.exception_requested),
    ciso_review_required: Boolean(input.ciso_review_required || /critical|emergency|exception|accepted_risk/i.test(String(input.status || input.recommended_action || ""))),
    evidence_refs: list(input.evidence_refs),
    audit_trail: [{
      event: "workflow_item_created",
      status,
      actor: input.actor_upn || "system",
      at: new Date().toISOString()
    }],
    no_autonomous_production_approval: true,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString()
  };
}

export function transitionWorkflowItem(item = {}, input = {}) {
  const status = input.status || item.status || "triage";
  const next = {
    ...item,
    status,
    owner: input.owner || item.owner || "unassigned",
    sla: input.sla || input.sla_due_at || item.sla || null,
    ciso_review_required: Boolean(item.ciso_review_required || input.ciso_review_required || /ciso|accepted_risk|exception/i.test(status)),
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
      at: next.updated_at
    }
  ];
  return next;
}

export function buildSignedActionPack(input = {}) {
  const payload = {
    customer_id: input.customer_id || null,
    report_type: input.report_type || "CAB Patch Decision Report",
    action: input.action || input.recommended_action || "human_review_required",
    evidence_refs: list(input.evidence_refs),
    generated_at: new Date().toISOString(),
    final_approval_issued: false,
    no_exploit_content: true,
    no_raw_secrets: true
  };
  const sourceHashes = list(input.source_hashes, input.source_hash).filter(Boolean);
  const packHash = sha256({ payload, source_hashes: sourceHashes });
  return {
    id: input.id || `sap-${Date.now()}-${randomUUID().slice(0, 8)}`,
    customer_id: payload.customer_id,
    report_type: payload.report_type,
    payload,
    evidence_refs: payload.evidence_refs,
    source_hashes: sourceHashes,
    pack_hash: packHash,
    signature: `test-digest:${packHash}`,
    verifier_result: {
      verified: true,
      method: "deterministic_test_digest",
      production_key_management_required: true
    },
    replay_metadata: {
      deterministic_payload_hash: packHash,
      replayable: true,
      human_reviewable: true
    },
    created_at: payload.generated_at
  };
}

export function verifySignedActionPack(pack = {}) {
  const expected = sha256({ payload: pack.payload, source_hashes: pack.source_hashes || [] });
  const verified = pack.pack_hash === expected && pack.signature === `test-digest:${expected}`;
  return {
    verified,
    pack_hash: pack.pack_hash || null,
    expected_hash: expected,
    signature_ok: verified,
    replayable: Boolean(pack.replay_metadata?.replayable),
    production_key_management_required: String(pack.signature || "").startsWith("test-digest:")
  };
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
