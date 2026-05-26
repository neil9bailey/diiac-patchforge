import { createHash } from "node:crypto";

const TOOL_SUMMARIES = {
  research_cve: "Summarises source-bound vulnerability identity and advisory context.",
  assess_exploit_risk: "Assesses exploitation likelihood at a governance level without procedural content.",
  map_affected_assets: "Maps affected assets from provided inventory context.",
  suggest_compensating_controls: "Suggests governance-safe compensating controls for review.",
  assess_patch_feasibility: "Assesses patch feasibility, change constraints, and rollback readiness.",
  summarise_vendor_advisory: "Summarises vendor advisory information with source references.",
  assess_ot_patch_constraints: "Assesses OT safety, vendor, and maintenance-window constraints.",
  build_patch_decision_context: "Builds an advisory draft context for deterministic governance compilation."
};

const BLOCKED_INPUT_PATTERNS = [
  /exploit\s+code/i,
  /exploit\s+steps/i,
  /weaponi[sz]e/i,
  /payload/i,
  /reverse\s+shell/i,
  /deploy\s+patch/i,
  /install\s+patch/i,
  /mutate\s+production/i,
  /risk\s+accept\s+automatically/i
];

export const SRA_TOOLS = Object.keys(TOOL_SUMMARIES);

export function runSraTool(toolName, input = {}) {
  if (!SRA_TOOLS.includes(toolName)) {
    throw new Error(`Unknown SRA tool: ${toolName}`);
  }

  assertBoundarySafe(input);
  const inputHash = hashJson(input);
  const sourceRefs = Array.isArray(input.source_refs) ? input.source_refs : [];
  const vulnerabilityId = input.vulnerability_id || input.cve || "unscoped-vulnerability";
  const output = {
    tool_name: toolName,
    vulnerability_id: vulnerabilityId,
    advisory_only: true,
    source_bound: true,
    review_state: "pending_review",
    can_close_evidence_gates_alone: false,
    can_risk_accept: false,
    no_exploit_content: true,
    no_deployment_action: true,
    source_refs: sourceRefs,
    findings: buildFindings(toolName, input),
    contradictions: [],
    confidence: sourceRefs.length > 0 ? "medium" : "low"
  };

  return {
    ...output,
    input_hash: inputHash,
    output_hash: hashJson(output)
  };
}

export function researchCve(input) {
  return runSraTool("research_cve", input);
}

export function assessExploitRisk(input) {
  return runSraTool("assess_exploit_risk", input);
}

export function mapAffectedAssets(input) {
  return runSraTool("map_affected_assets", input);
}

export function suggestCompensatingControls(input) {
  return runSraTool("suggest_compensating_controls", input);
}

export function assessPatchFeasibility(input) {
  return runSraTool("assess_patch_feasibility", input);
}

export function summariseVendorAdvisory(input) {
  return runSraTool("summarise_vendor_advisory", input);
}

export function assessOtPatchConstraints(input) {
  return runSraTool("assess_ot_patch_constraints", input);
}

export function buildPatchDecisionContext(input) {
  return runSraTool("build_patch_decision_context", input);
}

function buildFindings(toolName, input) {
  const service = input.service_name || input.service_id || "affected service";
  const asset = input.asset_name || input.asset_id || "affected asset";
  const vulnerability = input.vulnerability_id || input.cve || "the vulnerability";

  switch (toolName) {
    case "research_cve":
      return [
        `${vulnerability} requires source review before it can support a governed decision.`,
        "Scanner and advisory sources remain evidence inputs, not accepted truth by default."
      ];
    case "assess_exploit_risk":
      return [
        `${vulnerability} should be prioritised using known exploitation signals, service exposure, and business impact.`,
        "This assessment contains no procedural exploitation detail."
      ];
    case "map_affected_assets":
      return [
        `${asset} should be linked to reviewed inventory evidence before asset scope is accepted.`,
        "Unreviewed scanner matches should remain source-bound."
      ];
    case "suggest_compensating_controls":
      return [
        "Consider time-bound network, identity, monitoring, and operational controls for human review.",
        "Controls do not replace patch governance or accountable approval."
      ];
    case "assess_patch_feasibility":
      return [
        `${service} requires change-window, test, rollback, and customer-impact evidence.`,
        "Patch feasibility is advisory until reviewed by the service owner or change authority."
      ];
    case "summarise_vendor_advisory":
      return [
        "Vendor advisory summary should be checked against attached source references.",
        "Superseded advisories must not remain accepted positive evidence."
      ];
    case "assess_ot_patch_constraints":
      return [
        "OT patch governance requires safety impact, maintenance-window, vendor-support, and rollback evidence.",
        "Operational continuity constraints require accountable human review."
      ];
    case "build_patch_decision_context":
      return [
        "Draft context should be compiled by the deterministic runtime before pack generation.",
        "Final approval remains false until an explicit human approval event exists."
      ];
    default:
      return [TOOL_SUMMARIES[toolName]];
  }
}

function assertBoundarySafe(input) {
  const text = JSON.stringify(input);
  const blocked = BLOCKED_INPUT_PATTERNS.find((pattern) => pattern.test(text));
  if (blocked) {
    throw new Error("SRA boundary violation: request contains prohibited procedural or deployment-oriented content.");
  }
}

function hashJson(value) {
  return createHash("sha256").update(JSON.stringify(value, Object.keys(value).sort())).digest("hex");
}

