import assert from "node:assert/strict";
import test from "node:test";
import { AGENT_OUTPUT_SCHEMA, getOpenAiAgentStatus, runOpenAiAgent } from "./openaiAgentService.js";
import { verifyAgentOutput } from "./openaiAgentVerifier.js";

const validOutput = {
  agent_name: "Ask PatchForge Agent",
  advisory_only: true,
  can_close_hard_gates: false,
  can_approve: false,
  can_patch: false,
  can_accept_risk: false,
  final_approval_issued: false,
  human_review_required: true,
  evidence_used: [{ evidence_type: "vendor_advisory", review_state: "pending_review" }],
  evidence_missing: [{ evidence_type: "reviewed_customer_exposure" }],
  source_bound_warnings: ["Source-bound guidance only."],
  recommended_next_action: "Attach reviewed exposure, firmware, feature, and vendor advisory evidence.",
  decision_not_allowed_yet: "Final approval, risk acceptance, closure, and not-applicable status require reviewed evidence and named human approval."
};

test("OpenAI agent layer is disabled by default and missing key is non-fatal", async () => {
  const disabled = getOpenAiAgentStatus({});
  assert.equal(disabled.enabled, false);
  assert.equal(disabled.configured, false);
  assert.equal(disabled.model, "gpt-5.4");
  assert.equal(disabled.key_configured, false);
  assert.equal(disabled.key_value_exposed, false);

  const missingKey = getOpenAiAgentStatus({ PATCHFORGE_OPENAI_AGENT_ENABLED: "true" });
  assert.equal(missingKey.enabled, true);
  assert.equal(missingKey.configured, false);
  assert.equal(missingKey.model, "gpt-5.4");
  assert.equal(missingKey.key_configured, false);
  assert.equal(missingKey.key_value_exposed, false);

  const result = await runOpenAiAgent({
    prompt: "Do we need urgent patching?",
    env: { PATCHFORGE_OPENAI_AGENT_ENABLED: "true" }
  });
  assert.equal(result.status, "disabled");
  assert.equal(result.fallback.final_approval_issued, false);
});

test("mocked valid agent output passes deterministic verification", async () => {
  const result = await runOpenAiAgent({
    prompt: "Do we need urgent patching?",
    env: {
      PATCHFORGE_OPENAI_AGENT_ENABLED: "true",
      OPENAI_API_KEY: "test-key",
      PATCHFORGE_OPENAI_MODEL: "test-model"
    },
    fetchImpl: async () => ({
      ok: true,
      json: async () => ({ output_text: JSON.stringify(validOutput) })
    })
  });
  assert.equal(result.status, "verified");
  assert.equal(result.verifier_status, "passed");
  assert.equal(result.output.final_approval_issued, false);
  assert.equal(result.output.can_close_hard_gates, false);
});

test("OpenAI agent structured output schema is strict at every object level", () => {
  const objectSchemas = [];
  collectObjectSchemas(AGENT_OUTPUT_SCHEMA, objectSchemas);
  assert.ok(objectSchemas.length > 1);
  for (const schema of objectSchemas) {
    assert.equal(schema.additionalProperties, false);
    assert.deepEqual(Object.keys(schema.properties || {}).sort(), [...(schema.required || [])].sort());
  }
});

test("verifier blocks exploit, patch deployment, final approval, risk acceptance, and unsupported not-vulnerable claims", () => {
  const exploit = verifyAgentOutput({ ...validOutput, recommended_next_action: "Run metasploit and exploit steps to validate exposure." });
  assert.equal(exploit.ok, false);
  assert.equal(exploit.failures[0].code, "exploit_instructions");

  const deploy = verifyAgentOutput({ ...validOutput, recommended_next_action: "Deploy the patch to production now." });
  assert.equal(deploy.ok, false);
  assert.ok(deploy.failures.some((failure) => failure.code === "patch_deployment"));

  const approval = verifyAgentOutput({ ...validOutput, final_approval_issued: true, can_approve: true });
  assert.equal(approval.ok, false);
  assert.ok(approval.failures.some((failure) => failure.code === "final_approval_issued_required_false"));
  assert.ok(approval.failures.some((failure) => failure.code === "can_approve_required_false"));

  const risk = verifyAgentOutput({ ...validOutput, can_accept_risk: true, recommended_next_action: "Risk accepted for this CAB." });
  assert.equal(risk.ok, false);
  assert.ok(risk.failures.some((failure) => failure.code === "risk_acceptance"));

  const notVulnerable = verifyAgentOutput({ ...validOutput, recommended_next_action: "The device is not vulnerable and safe for customers." });
  assert.equal(notVulnerable.ok, false);
  assert.ok(notVulnerable.failures.some((failure) => failure.code === "not_vulnerable_without_reviewed_evidence"));
});

function collectObjectSchemas(schema, results) {
  if (!schema || typeof schema !== "object") {
    return;
  }
  if (schema.type === "object") {
    results.push(schema);
  }
  for (const value of Object.values(schema.properties || {})) {
    collectObjectSchemas(value, results);
  }
  if (schema.items) {
    collectObjectSchemas(schema.items, results);
  }
}
