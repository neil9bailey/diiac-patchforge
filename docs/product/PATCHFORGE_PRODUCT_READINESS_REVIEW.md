# PatchForge Product Readiness Review

Date: 2026-06-10

## Purpose

This review frames PatchForge as advisory governance software for customer demonstrations and for integration with DIIaC IT Service / Enterprise Build workflows.

PatchForge remains source-bound, human-review-required, and production-mutation-free. It does not scan environments, generate exploit steps, deploy patches, approve CAB decisions, accept risk, close evidence gates, or issue final approval autonomously.

This document is product-readiness evidence, not release authorization. G4 real end-user UAT and G6 human release signoff are still required before claiming a production release is accepted.

## Current Readiness Capability

- Seven-area operating model: Security Action Center, Vendors & Exploits Register, Customer Operational Assets, Patch / Hotfix Compare, Ask PatchForge, Reports, and Admin.
- Microsoft Entra app-role enforcement on protected API routes.
- Runtime readiness evidence reports the active tenant storage mode in the live readiness path.
- Source-bound public intelligence, customer asset matching, patch/hotfix comparison, signed packs, and DOCX/PDF report exports.
- Ask PatchForge deterministic advisory answers with explicit evidence gaps, recommended next action, decision limits, human-review requirement, and final approval false.
- Optional OpenAI-native agent layer behind runtime configuration, structured JSON output, deterministic verifier, and deterministic fallback.
- Admin health, configuration save, signing trust visibility, and typed purge preview/confirmation controls.

## Readiness Improvement Slice

The 2026-06-10 production-demo slice improves clarity without changing the approved architecture:

- Ask PatchForge now distinguishes the displayed deterministic answer from optional verified AI assistance.
- Optional AI assistance is shown as runtime-gated and verifier-required; disabled or missing-key states do not look like product failure.
- Admin capability entries are static status cards instead of inert buttons.
- Out-of-scope or unsafe controls are labelled as blocked, runtime-only, guarded, planned, or human-only.
- DIIaC IT Service / Enterprise Build is represented as a harness-ready governance module, not as a hidden or implied integration.

## AI-Assisted Answer Boundary

OpenAI assistance may help phrase advisory guidance only after:

- `PATCHFORGE_OPENAI_AGENT_ENABLED=true` is set in runtime configuration.
- `OPENAI_API_KEY` is supplied from approved secret handling such as Azure Key Vault or deployment environment.
- Agent output passes `openaiAgentVerifier.js`.
- The deterministic PatchForge response remains available and authoritative as fallback.

Only approved, source-bound, minimized context should be sent to external AI providers. Do not send secrets, raw customer uploads, raw configuration files, raw logs, credentials, or customer assurance claims unless the tenant has explicitly approved that data flow and the data has been reviewed and redacted.

Verified AI output still cannot approve, patch, accept risk, close gates, or provide customer assurance without reviewed evidence and named human approval.

## DIIaC IT Service / Enterprise Build Harness

PatchForge can be positioned beside DIIaC IT Service / Enterprise Build as a governance module:

- consumes reviewed service, asset, advisory, and source-feed records
- maps customer estate exposure and applicability
- explains operational posture and evidence gaps
- prepares signed packs and report outputs
- preserves accountable human approval and audit lineage

Integration should remain API/event oriented. PatchForge should not become the system that mutates production infrastructure or service state.

## Remaining Readiness Work

- Run real signed-in PatchForge.Admin UAT through the seven-area flow.
- Validate optional OpenAI assistance in a configured non-production environment before enabling it for customer demonstrations.
- Add integration documentation for IT Service / Enterprise Build handoff payloads and expected source-bound records.
- Continue replacing any remaining inert UI affordances with either real protected actions or static status surfaces.
