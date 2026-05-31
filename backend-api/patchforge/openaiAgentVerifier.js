import { createHash } from "node:crypto";

const REQUIRED_TRUE_FLAGS = ["advisory_only", "human_review_required"];
const REQUIRED_FALSE_FLAGS = ["can_close_hard_gates", "can_approve", "can_patch", "can_accept_risk", "final_approval_issued"];

const BLOCKED_PATTERNS = [
  { code: "exploit_instructions", pattern: /\b(exploit steps|procedural exploit|weaponize|payload|reverse shell|metasploit|msfconsole)\b/i },
  { code: "procedural_exploitation_steps", pattern: /\b(step\s+\d+[:.)].{0,80}(exploit|bypass|gain access)|run\s+.+\bexploit\b)\b/i },
  { code: "patch_deployment", pattern: /\b(deploy|install|apply|push)\s+(?:the\s+)?(?:security\s+)?patch\b/i },
  { code: "production_mutation", pattern: /\b(change production|mutate production|modify production|restart production)\b/i },
  { code: "cab_approval", pattern: /\b(cab\s+approved|approve(?:s|d)?\s+cab|cab\s+can\s+approve|approved for cab)\b/i },
  { code: "risk_acceptance", pattern: /\b(risk\s+accepted|accept(?:s|ed)?\s+risk|approve\s+risk\s+acceptance)\b/i },
  { code: "hard_gate_closure", pattern: /\b(close(?:s|d)?\s+(?:the\s+)?(?:evidence\s+)?gate|hard\s+gate\s+closed|closure\s+approved)\b/i },
  { code: "source_free_truth", pattern: /\bconfirmed\s+(?:affected|remediated|not affected|not vulnerable)\b(?![^.]{0,120}\breviewed evidence\b)/i }
];

export function canonicalAgentOutput(value) {
  const normalized = baseAgentOutput(value);
  const withoutHash = { ...normalized };
  delete withoutHash.output_hash;
  return stableStringify(withoutHash);
}

export function hashAgentOutput(value) {
  return createHash("sha256").update(canonicalAgentOutput(value)).digest("hex");
}

export function normalizeAgentOutput(value = {}) {
  const output = baseAgentOutput(value);
  output.output_hash = String(value.output_hash || hashAgentOutput(output));
  return output;
}

function baseAgentOutput(value = {}) {
  const now = new Date().toISOString();
  return {
    agent_name: String(value.agent_name || "PatchForge Agent"),
    advisory_only: value.advisory_only === undefined ? true : Boolean(value.advisory_only),
    can_close_hard_gates: Boolean(value.can_close_hard_gates),
    can_approve: Boolean(value.can_approve),
    can_patch: Boolean(value.can_patch),
    can_accept_risk: Boolean(value.can_accept_risk),
    final_approval_issued: Boolean(value.final_approval_issued),
    human_review_required: value.human_review_required === undefined ? true : Boolean(value.human_review_required),
    evidence_used: listRecords(value.evidence_used),
    evidence_missing: listRecords(value.evidence_missing),
    source_bound_warnings: listStrings(value.source_bound_warnings),
    recommended_next_action: String(value.recommended_next_action || "Attach reviewed evidence and request accountable human review."),
    decision_not_allowed_yet: String(value.decision_not_allowed_yet || "PatchForge cannot issue final approval, risk acceptance, closure, or not-applicable status without reviewed evidence and named human approval."),
    created_at: String(value.created_at || now)
  };
}

export function verifyAgentOutput(value = {}, context = {}) {
  const output = normalizeAgentOutput(value);
  const failures = [];

  for (const flag of REQUIRED_TRUE_FLAGS) {
    if (output[flag] !== true) {
      failures.push({ code: `${flag}_required_true`, message: `${flag} must be true.` });
    }
  }
  for (const flag of REQUIRED_FALSE_FLAGS) {
    if (output[flag] !== false) {
      failures.push({ code: `${flag}_required_false`, message: `${flag} must be false.` });
    }
  }

  const text = JSON.stringify(output);
  for (const rule of BLOCKED_PATTERNS) {
    if (rule.pattern.test(text)) {
      failures.push({ code: rule.code, message: `Agent output matched blocked governance pattern: ${rule.code}.` });
    }
  }

  if (unsafeNotVulnerableClaim(text, context)) {
    failures.push({
      code: "not_vulnerable_without_reviewed_evidence",
      message: "\"safe\" or \"not vulnerable\" claims require reviewed exposure and applicability evidence."
    });
  }
  if (unsafeCustomerAssuranceClaim(text, context)) {
    failures.push({
      code: "customer_assurance_without_reviewed_evidence",
      message: "Customer assurance requires reviewed customer exposure and applicability evidence."
    });
  }

  const ok = failures.length === 0;
  return {
    ok,
    verifier_status: ok ? "passed" : "blocked",
    failures,
    output: ok ? output : null,
    blocked_output: ok ? null : {
      ...output,
      trusted_guidance: false,
      blocked: true,
      verification_failures: failures
    },
    fallback: ok ? null : blockedFallback(failures[0]?.code || "verification_failed", output.agent_name)
  };
}

export function blockedFallback(reason = "verification_failed", agentName = "PatchForge Agent") {
  const output = normalizeAgentOutput({
    agent_name: agentName,
    evidence_used: [],
    evidence_missing: [{ evidence_type: "governance_verification", state: reason }],
    source_bound_warnings: ["PatchForge could not use this agent response because it failed governance verification."],
    recommended_next_action: "Use the deterministic PatchForge answer, attach reviewed evidence, and request accountable human review.",
    decision_not_allowed_yet: "PatchForge cannot issue final approval, risk acceptance, closure, or not-applicable status without reviewed evidence and named human approval."
  });
  return {
    ...output,
    fallback_reason: reason,
    message: "PatchForge could not use this agent response because it failed governance verification."
  };
}

function unsafeNotVulnerableClaim(text, context) {
  if (context.reviewed_exposure_evidence === true && context.reviewed_applicability_evidence === true) {
    return false;
  }
  const sentences = text.split(/[.!?]\s+/);
  return sentences.some((sentence) =>
    /\b(safe|not vulnerable|not affected)\b/i.test(sentence)
    && !/\b(cannot|do not|must not|not allowed|without reviewed evidence|cannot mark|cannot claim)\b/i.test(sentence)
  );
}

function unsafeCustomerAssuranceClaim(text, context) {
  if (context.reviewed_customer_assurance_evidence === true) {
    return false;
  }
  const sentences = text.split(/[.!?]\s+/);
  return sentences.some((sentence) =>
    /\b(customer assurance|assurance can be issued|customer is remediated|customer exposure is confirmed)\b/i.test(sentence)
    && !/\b(cannot|do not|must not|not allowed|without reviewed evidence|not yet|requires reviewed)\b/i.test(sentence)
  );
}

function listStrings(value) {
  if (Array.isArray(value)) {
    return value.map((item) => String(item)).filter(Boolean);
  }
  if (value === undefined || value === null || value === "") {
    return [];
  }
  return [String(value)];
}

function listRecords(value) {
  if (!Array.isArray(value)) {
    return [];
  }
  return value.map((item) => item && typeof item === "object" ? item : { value: String(item) });
}

function stableStringify(value) {
  if (Array.isArray(value)) {
    return `[${value.map(stableStringify).join(",")}]`;
  }
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}
