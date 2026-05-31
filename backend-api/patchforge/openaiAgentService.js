import { createHash } from "node:crypto";
import { blockedFallback, verifyAgentOutput } from "./openaiAgentVerifier.js";

export const OPENAI_AGENT_NAMES = {
  ask: "Ask PatchForge Agent",
  "config-applicability": "Config Applicability Agent",
  "evidence-gaps": "Evidence Gap Agent",
  "source-intelligence": "Source Intelligence Agent",
  "report-critic": "Report Critic Agent",
  "approval-readiness": "Approval Readiness Agent",
  "vendorlens": "VendorLens Agent"
};

const DEFAULT_MODEL = "gpt-4o-mini";
const DEFAULT_TIMEOUT_MS = 15000;
const DEFAULT_MAX_OUTPUT_TOKENS = 1000;

export const AGENT_OUTPUT_SCHEMA = {
  type: "object",
  additionalProperties: false,
  required: [
    "agent_name",
    "advisory_only",
    "can_close_hard_gates",
    "can_approve",
    "can_patch",
    "can_accept_risk",
    "final_approval_issued",
    "human_review_required",
    "evidence_used",
    "evidence_missing",
    "source_bound_warnings",
    "recommended_next_action",
    "decision_not_allowed_yet"
  ],
  properties: {
    agent_name: { type: "string" },
    advisory_only: { type: "boolean" },
    can_close_hard_gates: { type: "boolean" },
    can_approve: { type: "boolean" },
    can_patch: { type: "boolean" },
    can_accept_risk: { type: "boolean" },
    final_approval_issued: { type: "boolean" },
    human_review_required: { type: "boolean" },
    evidence_used: { type: "array", items: { type: "object", additionalProperties: true } },
    evidence_missing: { type: "array", items: { type: "object", additionalProperties: true } },
    source_bound_warnings: { type: "array", items: { type: "string" } },
    recommended_next_action: { type: "string" },
    decision_not_allowed_yet: { type: "string" }
  }
};

export function getOpenAiAgentStatus(env = process.env) {
  const enabled = String(env.PATCHFORGE_OPENAI_AGENT_ENABLED || "false").toLowerCase() === "true";
  const configured = enabled && Boolean(env.OPENAI_API_KEY);
  return {
    enabled,
    configured,
    provider: "openai",
    model: env.PATCHFORGE_OPENAI_MODEL || DEFAULT_MODEL,
    timeout_ms: numberFromEnv(env.PATCHFORGE_OPENAI_TIMEOUT_MS, DEFAULT_TIMEOUT_MS),
    max_output_tokens: numberFromEnv(env.PATCHFORGE_OPENAI_MAX_OUTPUT_TOKENS, DEFAULT_MAX_OUTPUT_TOKENS),
    agent_names: OPENAI_AGENT_NAMES,
    verifier_required: true,
    advisory_only: true,
    final_approval_issued: false,
    can_close_hard_gates: false,
    can_approve: false,
    can_patch: false,
    can_accept_risk: false,
    key_configured: Boolean(env.OPENAI_API_KEY),
    key_value_exposed: false
  };
}

export async function runOpenAiAgent({
  agentName = OPENAI_AGENT_NAMES.ask,
  prompt = "",
  evidence = {},
  tenantId = null,
  env = process.env,
  fetchImpl = globalThis.fetch
} = {}) {
  const status = getOpenAiAgentStatus(env);
  const createdAt = new Date().toISOString();
  const promptHash = hashText(prompt);

  if (!status.enabled) {
    return agentResult({
      tenantId,
      status,
      agentName,
      promptHash,
      createdAt,
      state: "disabled",
      fallbackReason: "openai_agent_disabled"
    });
  }
  if (!status.configured) {
    return agentResult({
      tenantId,
      status,
      agentName,
      promptHash,
      createdAt,
      state: "disabled",
      fallbackReason: "openai_api_key_missing"
    });
  }
  if (typeof fetchImpl !== "function") {
    return agentResult({
      tenantId,
      status,
      agentName,
      promptHash,
      createdAt,
      state: "blocked",
      fallbackReason: "fetch_unavailable"
    });
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), status.timeout_ms);
  try {
    const response = await fetchImpl("https://api.openai.com/v1/responses", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${env.OPENAI_API_KEY}`
      },
      body: JSON.stringify({
        model: status.model,
        input: [
          {
            role: "system",
            content: agentSystemPrompt(agentName)
          },
          {
            role: "user",
            content: JSON.stringify({
              agent_name: agentName,
              prompt,
              evidence,
              required_boundary: {
                advisory_only: true,
                can_close_hard_gates: false,
                can_approve: false,
                can_patch: false,
                can_accept_risk: false,
                final_approval_issued: false,
                human_review_required: true
              }
            })
          }
        ],
        max_output_tokens: status.max_output_tokens,
        text: {
          format: {
            type: "json_schema",
            name: "patchforge_agent_guidance",
            strict: true,
            schema: AGENT_OUTPUT_SCHEMA
          }
        }
      }),
      signal: controller.signal
    });
    const body = await response.json().catch(() => ({}));
    if (!response.ok) {
      return agentResult({
        tenantId,
        status,
        agentName,
        promptHash,
        createdAt,
        state: "blocked",
        fallbackReason: `openai_http_${response.status}`,
        providerState: sanitizeProviderState(body)
      });
    }

    const parsed = extractStructuredOutput(body);
    const verification = verifyAgentOutput({
      ...parsed,
      agent_name: parsed.agent_name || agentName,
      created_at: parsed.created_at || createdAt
    }, evidence);
    return {
      tenant_id: tenantId,
      snapshot_id: `agent-${createdAt.replace(/[^0-9]/g, "")}-${promptHash.slice(0, 10)}`,
      agent_name: agentName,
      status: verification.ok ? "verified" : "blocked",
      provider: "openai",
      model: status.model,
      prompt_hash: promptHash,
      output: verification.output,
      blocked_output: verification.blocked_output,
      fallback: verification.fallback,
      verifier_status: verification.verifier_status,
      verification_failures: verification.failures,
      created_at: createdAt,
      advisory_only: true,
      final_approval_issued: false,
      can_close_hard_gates: false,
      can_approve: false,
      can_patch: false,
      can_accept_risk: false
    };
  } catch (error) {
    return agentResult({
      tenantId,
      status,
      agentName,
      promptHash,
      createdAt,
      state: "blocked",
      fallbackReason: error.name === "AbortError" ? "openai_timeout" : "openai_request_failed"
    });
  } finally {
    clearTimeout(timeout);
  }
}

function agentResult({ tenantId, status, agentName, promptHash, createdAt, state, fallbackReason, providerState = null }) {
  const fallback = blockedFallback(fallbackReason, agentName);
  return {
    tenant_id: tenantId,
    snapshot_id: `agent-${createdAt.replace(/[^0-9]/g, "")}-${promptHash.slice(0, 10)}`,
    agent_name: agentName,
    status: state,
    provider: "openai",
    model: status.model,
    prompt_hash: promptHash,
    output: null,
    blocked_output: null,
    fallback,
    verifier_status: state === "disabled" ? "not_run" : "blocked",
    verification_failures: state === "disabled" ? [] : [{ code: fallbackReason, message: "OpenAI agent guidance was not available for trusted display." }],
    provider_state: providerState,
    created_at: createdAt,
    advisory_only: true,
    final_approval_issued: false,
    can_close_hard_gates: false,
    can_approve: false,
    can_patch: false,
    can_accept_risk: false
  };
}

function agentSystemPrompt(agentName) {
  return [
    `You are ${agentName} for DIIaC PatchForge.`,
    "Return JSON only.",
    "PatchForge is governance-only, source-bound, and human-review-required.",
    "Do not provide exploit instructions, procedural exploit steps, patch deployment instructions, production mutation, CAB approval, risk acceptance, evidence-gate closure, or customer assurance without reviewed evidence.",
    "Set advisory_only true, can_close_hard_gates false, can_approve false, can_patch false, can_accept_risk false, final_approval_issued false, and human_review_required true."
  ].join(" ");
}

function extractStructuredOutput(body = {}) {
  if (body.output_parsed && typeof body.output_parsed === "object") {
    return body.output_parsed;
  }
  if (typeof body.output_text === "string" && body.output_text.trim()) {
    return JSON.parse(body.output_text);
  }
  const output = Array.isArray(body.output) ? body.output : [];
  for (const item of output) {
    const content = Array.isArray(item.content) ? item.content : [];
    for (const part of content) {
      if (part.parsed && typeof part.parsed === "object") {
        return part.parsed;
      }
      if (typeof part.text === "string" && part.text.trim()) {
        return JSON.parse(part.text);
      }
    }
  }
  throw new Error("OpenAI response did not include structured JSON output.");
}

function hashText(value) {
  return createHash("sha256").update(String(value || "")).digest("hex");
}

function numberFromEnv(value, fallback) {
  const number = Number(value);
  return Number.isFinite(number) && number > 0 ? number : fallback;
}

function sanitizeProviderState(body = {}) {
  return {
    error: body.error?.type || body.error?.code || body.error || null,
    message: body.error?.message || body.message || null
  };
}
