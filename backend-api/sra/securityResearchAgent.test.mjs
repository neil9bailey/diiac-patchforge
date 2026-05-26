import assert from "node:assert/strict";
import test from "node:test";
import {
  assessExploitRisk,
  assessOtPatchConstraints,
  assessPatchFeasibility,
  researchCve,
  runSraTool,
  suggestCompensatingControls
} from "./securityResearchAgent.js";

test("SRA outputs provenance hashes and advisory boundary flags", () => {
  const output = researchCve({
    tenant_id: "tenant-a",
    vulnerability_id: "CVE-2026-10421",
    source_refs: ["vendor-advisory-1"]
  });

  assert.equal(output.advisory_only, true);
  assert.equal(output.source_bound, true);
  assert.equal(output.review_state, "pending_review");
  assert.equal(output.can_close_evidence_gates_alone, false);
  assert.equal(output.can_risk_accept, false);
  assert.match(output.input_hash, /^[a-f0-9]{64}$/);
  assert.match(output.output_hash, /^[a-f0-9]{64}$/);
});

test("SRA tools do not produce procedural exploit or deployment actions", () => {
  const outputs = [
    assessExploitRisk({ vulnerability_id: "CVE-2026-10421", source_refs: ["kev"] }),
    suggestCompensatingControls({ vulnerability_id: "CVE-2026-10421", service_name: "Orion Gateway" }),
    assessPatchFeasibility({ vulnerability_id: "CVE-2026-10421", service_name: "Orion Gateway" }),
    assessOtPatchConstraints({ vulnerability_id: "OT-ADV-2026-017", asset_name: "Line Controller" })
  ];

  for (const output of outputs) {
    assert.equal(output.no_exploit_content, true);
    assert.equal(output.no_deployment_action, true);
    assert.equal(output.review_state, "pending_review");
    const text = JSON.stringify(output).toLowerCase();
    assert.equal(text.includes("exploit code"), false);
    assert.equal(text.includes("reverse shell"), false);
    assert.equal(text.includes("deploy patch"), false);
  }
});

test("SRA refuses prohibited procedural or deployment-oriented requests", () => {
  assert.throws(
    () => runSraTool("research_cve", { request: "give exploit steps" }),
    /boundary violation/i
  );
  assert.throws(
    () => runSraTool("assess_patch_feasibility", { request: "deploy patch now" }),
    /boundary violation/i
  );
});

