# PatchForge Native Agent Layer

PF-AZ11 adds an optional OpenAI-native agent layer for customer-demo maturity. It is disabled by default and is never required for production readiness, report export, signed-pack generation, or deterministic Ask PatchForge responses.

## Configuration

- `PATCHFORGE_OPENAI_AGENT_ENABLED=false` by default.
- `PATCHFORGE_OPENAI_MODEL` selects the OpenAI model when enabled.
- `PATCHFORGE_OPENAI_TIMEOUT_MS` bounds agent latency.
- `PATCHFORGE_OPENAI_MAX_OUTPUT_TOKENS` bounds response size.
- `OPENAI_API_KEY` must come from Azure Key Vault or environment configuration. No key is stored in the repository.

## Agent Types

- VendorLens Agent
- Config Applicability Agent
- Evidence Gap Agent
- Source Intelligence Agent
- Report Critic Agent
- Approval Readiness Agent
- Ask PatchForge Agent

All output is structured JSON and must pass `openaiAgentVerifier.js` before display, storage, report inclusion, or pack inclusion.

## Boundary

Agent output is advisory-only. It cannot close hard gates, approve CAB, deploy patches, accept risk, issue final approval, or provide customer assurance without reviewed evidence. If verification fails, PatchForge stores the blocked output as untrusted and shows the deterministic fallback message.
