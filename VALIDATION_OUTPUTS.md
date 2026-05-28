# PF-AZ9A VendorLens Report Proof Validation Outputs

## PF-AZ9A Local Validation

Date: 2026-05-28

Status: PASS. PF-AZ9A is deployed to Azure and validated through the live UI/API as a signed-in PatchForge Admin user.

Scope:

- Clarify release naming so VendorLens is `PF-AZ9-VENDORLENS` and the earlier operational-health release is `PF-AZ9-OPS`.
- Replace ambiguous manifest wording with reused-resource fields.
- Stamp every DOCX/PDF report with current renderer and image metadata.
- Prove current reports are not stale and include VendorLens sections.

Local validation:

- `node --check backend-api/server.js`: PASS
- `node --check backend-api/auth.js`: PASS
- `node --check backend-api/patchforge/reports.js`: PASS
- `node --check backend-api/patchforge/configApplicability.js`: PASS
- `node --check backend-api/patchforge/vendorLens.js`: PASS
- `node --check backend-api/patchforge/scheduler.js`: PASS
- `node --check backend-api/sra/securityResearchAgent.js`: PASS
- `npm --prefix backend-api test`: PASS, 29 tests
- `npm --prefix Frontend test`: PASS, 11 tests
- `npm --prefix Frontend run build`: PASS
- `python -m pytest -q --basetemp .pytest_tmp`: PASS, 26 tests
- `powershell -NoProfile -ExecutionPolicy Bypass -File scripts/validate_iac.ps1`: PASS
- `az bicep build --file infra/bicep/main.bicep`: PASS
- Docker frontend, bridge/API, and runtime build smoke: PASS
- Local current-report proof from signed pack `PF-20260527-2d9f160a`: PASS
- Local DOCX render attempt: NOT AVAILABLE because the local DOCX-to-PDF converter executable is missing

Azure rollout:

- GitHub push: PASS, commit `1a98433`
- Image tag: `pfaz9a-20260528-1a98433`
- ACR image push: PASS for frontend, bridge/API, runtime, SRA, worker, and scheduler
- ACR tag verification: PASS for all six repositories
- Azure what-if: captured; targeted image-only rollout used to avoid broad infrastructure drift
- Targeted Container Apps update: PASS
- Active revisions:
  - UI: `ca-patchforge-ui-prod--0000017`
  - Bridge/API: `ca-patchforge-bridge-prod--0000016`
  - Runtime: `ca-patchforge-runtime-prod--0000015`
  - SRA: `ca-patchforge-sra-prod--0000014`
  - Worker: `ca-patchforge-worker-prod--0000014`
  - Scheduler: `ca-patchforge-scheduler-prod--0000014`

Live validation:

- UI HTTP 200: PASS
- API health HTTP 200: PASS
- API readiness HTTP 200 with `storage=postgresql`, `auth_required=true`, and `tenant_required=true`: PASS
- Protected vulnerability route unauthenticated HTTP 401: PASS
- Browser/MSAL sign-in as `n.bailey@diiac.io`: PASS
- Displayed role `PatchForge.Admin`: PASS
- VendorLens UI opened and rendered: PASS
- Fresh signed pack generated: `PF-20260528-9a653d50`
- Pack verification: PASS, `verified=true`, `manifest_ok=true`, `signature_ok=true`
- Key Vault signing smoke: PASS, `azure_key_vault`
- PostgreSQL readiness and live write path: PASS
- Customer Patch Governance Pack DOCX/PDF export: PASS
- Board Vulnerability Remediation Summary DOCX/PDF export: PASS
- CAB Patch Decision Report DOCX/PDF export: PASS
- Live report version stamping: PASS
- VendorLens report sections: PASS
- Final approval remained false: PASS

PF-AZ9A evidence path:

`docs/release/evidence/2026-05-28-patchforge-pfaz9a-vendorlens-report-proof/`

Important boundary note: PF-AZ9A does not add scanning, exploit generation, procedural exploit steps, patch deployment, production mutation from the UI, autonomous evidence-gate closure, autonomous CAB approval, or autonomous risk acceptance.

# PF-AZ10 UI, VendorLens Catalogue, and CISO Patch Comparison Validation Outputs

## PF-AZ10 Local Validation

Date: 2026-05-27

Status: PASS. PF-AZ10 is deployed to Azure and validated through the live UI/API as a signed-in PatchForge Admin user.

Scope:

- Fix UI wrapping and content overflow in finding cards, context banners, hero panels, status lines, and VendorLens panels.
- Add pagination to growing content areas including findings, vulnerability queue, assets/services, source feeds/runs, vendor lists, VendorLens advisories/assets/gaps, decision packs, reports, Admin health checks, and Admin sections.
- Add clickable VendorLens reference catalogue with source details and per-vendor refresh action.
- Refresh NVD catalogue records without requiring a single CVE input.
- Handle NVD public API rate limits as governed `completed_with_warnings` or `rate_limited` feed-run states instead of a broken UI workflow.
- Add CISO patch-version comparison workflow and report artefact.

Local validation:

- `node --check backend-api/server.js`: PASS
- `node --check backend-api/auth.js`: PASS
- `node --check backend-api/patchforge/reports.js`: PASS
- `node --check backend-api/patchforge/scheduler.js`: PASS
- `node --check backend-api/patchforge/configApplicability.js`: PASS
- `node --check backend-api/patchforge/vendorLens.js`: PASS
- `node --check backend-api/sra/securityResearchAgent.js`: PASS
- `npm --prefix backend-api test`: PASS, 29 tests
- `npm --prefix Frontend test`: PASS, 11 tests
- `npm --prefix Frontend run build`: PASS
- `python -m pytest -q --basetemp .pytest_tmp`: PASS, 26 tests
- `powershell -NoProfile -ExecutionPolicy Bypass -File scripts/validate_iac.ps1`: PASS
- `az bicep build --file infra/bicep/main.bicep`: PASS

Azure rollout:

- GitHub push: PASS, latest commit `513fea2`
- Image tag: `pfaz10-20260527-513fea2`
- ACR image push: PASS for frontend, bridge/API, runtime, SRA, worker, and scheduler
- ACR tag verification: PASS for all six repositories
- Bicep what-if: captured; targeted image-only rollout used to avoid broad infrastructure drift
- Container Apps image update: PASS
- Active revisions:
  - UI: `ca-patchforge-ui-prod--0000016`
  - Bridge/API: `ca-patchforge-bridge-prod--0000015`
  - Runtime: `ca-patchforge-runtime-prod--0000014`
  - SRA: `ca-patchforge-sra-prod--0000013`
  - Worker: `ca-patchforge-worker-prod--0000013`
  - Scheduler: `ca-patchforge-scheduler-prod--0000013`

Live validation:

- UI HTTP 200: PASS
- API health HTTP 200: PASS
- API readiness HTTP 200 with `storage=postgresql`, `auth_required=true`, and `tenant_required=true`: PASS
- Protected vulnerability and VendorLens routes unauthenticated HTTP 401: PASS
- Browser/MSAL sign-in as `n.bailey@diiac.io`: PASS
- Displayed role `PatchForge.Admin`: PASS
- Action Center and Finding Detail visual overflow checks: PASS
- VendorLens reference catalogue loads: PASS, 17 vendors
- VendorLens active advisories: PASS, 730 source-bound records
- NVD catalogue refresh: PASS, governed `completed_with_warnings` state observed when the public NVD API rate limit was reached
- Patch Compare pagination: PASS, `1-10 of 730 comparison advisories`
- App console-breaking errors: PASS; only a Microsoft login favicon 404 was observed

PF-AZ10 evidence path:

`docs/release/evidence/2026-05-27-patchforge-pfaz10-ui-vendorlens-ciso-compare/`

Important boundary note: PF-AZ10 does not add scanning, exploit generation, procedural exploit steps, patch deployment, production mutation from the UI, autonomous CAB approval, or autonomous risk acceptance.

# PF-AZ9-VENDORLENS Validation Outputs

## PF-AZ9-VENDORLENS Local Validation

Date: 2026-05-27

Status: PASS. PF-AZ9-VENDORLENS is deployed to Azure and validated through the live UI/API as a signed-in PatchForge Admin user.

Scope:

- Add VendorLens Network Vendor Intelligence and Config-Aware Patch Advisor.
- Add source-bound network/security vendor catalogue and advisory ingest foundations.
- Add customer network asset, model, firmware, feature, exposure, and review-state records.
- Add config applicability engine and Ask PatchForge SRA/AIP chat.
- Add VendorLens UI and Admin: Vendor Sources controls.
- Add signed-pack artefacts and DOCX/PDF report sections for network vendor applicability.

Local validation:

- `node --check backend-api/server.js`: PASS
- `node --check backend-api/auth.js`: PASS
- `node --check backend-api/patchforge/reports.js`: PASS
- `node --check backend-api/patchforge/scheduler.js`: PASS
- `node --check backend-api/patchforge/configApplicability.js`: PASS
- `node --check backend-api/sra/securityResearchAgent.js`: PASS
- `npm --prefix backend-api test`: PASS, 27 tests
- `npm --prefix Frontend test`: PASS, 11 tests
- `npm --prefix Frontend run build`: PASS
- `python -m pytest -q --basetemp .pytest_tmp`: PASS, 26 tests
- `powershell -NoProfile -ExecutionPolicy Bypass -File scripts/validate_iac.ps1`: PASS
- `az bicep build --file infra/bicep/main.bicep`: PASS
- `docker build -f Frontend/Dockerfile -t diiac/patchforge-frontend:pfaz9-local Frontend`: PASS
- `docker build -f backend-api/Dockerfile -t diiac/patchforge-bridge:pfaz9-local backend-api`: PASS
- `docker build -f runtime/Dockerfile -t diiac/patchforge-runtime:pfaz9-local .`: PASS

Document quality gate:

- Customer Patch Governance Pack DOCX/PDF generated with VendorLens sections: PASS
- Board Vulnerability Remediation Summary DOCX/PDF generated with VendorLens sections: PASS
- CAB Patch Decision Report DOCX/PDF generated with VendorLens sections: PASS
- DOCX structural wording checks: PASS
- DOCX-to-PNG render: NOT AVAILABLE locally because LibreOffice/soffice is unavailable on PATH
- QA evidence: `docs/release/evidence/2026-05-27-patchforge-pfaz9-vendorlens/local-reports/`

Important boundary note: PF-AZ9-VENDORLENS does not add scanning, exploit generation, procedural exploit steps, patch deployment, production mutation from the UI, autonomous CAB approval, or autonomous risk acceptance.

Azure rollout:

- GitHub push: PASS, commit `e8a0de2`
- Image tag: `pfaz9-20260527-e8a0de2`
- ACR image push: PASS for frontend, bridge/API, runtime, SRA, worker, and scheduler
- ACR tag verification: PASS for all six repositories
- Bicep what-if: captured; not applied because it included broader drift/noise than the image rollout required
- Targeted image-only Container Apps update: PASS
- Active revisions:
  - UI: `ca-patchforge-ui-prod--0000013`
  - Bridge/API: `ca-patchforge-bridge-prod--0000012`
  - Runtime: `ca-patchforge-runtime-prod--0000011`
  - SRA: `ca-patchforge-sra-prod--0000010`
  - Worker: `ca-patchforge-worker-prod--0000010`
  - Scheduler: `ca-patchforge-scheduler-prod--0000010`

Live validation:

- UI HTTP 200: PASS
- API health HTTP 200: PASS
- API readiness HTTP 200 with `storage=postgresql`, `auth_required=true`, and `tenant_required=true`: PASS
- Protected VendorLens route unauthenticated HTTP 401: PASS
- Browser/MSAL sign-in as `n.bailey@diiac.io`: PASS
- Displayed role `PatchForge.Admin`: PASS
- VendorLens catalogue loaded: PASS, 17 tracked vendors
- Customer network asset create workflow: PASS
- Source-bound vendor advisory ingest workflow: PASS
- Config applicability assessment: PASS, `requires_review` with `urgent_scope_confirmation_required`
- Ask PatchForge chat: PASS, advisory-only with short answer, governed posture, evidence used, evidence missing, and final approval false
- Signed pack generated: `PF-20260527-2d9f160a`
- Pack verification: PASS, `verified=true`, `manifest_ok=true`, `signature_ok=true`
- Key Vault signing smoke: PASS, `azure_key_vault`, `pf-pack-signing-prod`
- PostgreSQL readiness and live write path: PASS
- Board DOCX/PDF report export: PASS
- DOCX structural QA for VendorLens report sections and final-approval boundary: PASS
- PF-AZ9-VENDORLENS live validation records removed from production PostgreSQL after evidence capture: PASS

PF-AZ9-VENDORLENS evidence path:

`docs/release/evidence/2026-05-27-patchforge-pfaz9-vendorlens/`

# PF-AZ8A Validation Outputs

## PF-AZ8A Local Validation

Date: 2026-05-27

Status: PASS. PF-AZ8A is deployed to Azure and validated through the live UI/API as a signed-in PatchForge Admin user.

Scope:

- Replace risky autonomous-analysis wording with safer automated-governance wording.
- Improve customer-facing posture for known-exploited public-source records with unconfirmed exposure.
- Add KEV/EPSS interpretation and source-bound vendor/threat intelligence wording.
- Make evidence gaps specific enough for customer, CAB, and board decisions.
- Add customer-specific assurance, impact, communication, shareable-position, and not-yet-claimable report sections.
- Add decision-option status, reason, required evidence, and approval fields.
- Add persistent UI context banner and simple next-action cards.

Local validation:

- `node --check backend-api/server.js`: PASS
- `node --check backend-api/auth.js`: PASS
- `node --check backend-api/patchforge/reports.js`: PASS
- `node --check backend-api/patchforge/scheduler.js`: PASS
- `node --check backend-api/sra/securityResearchAgent.js`: PASS
- `npm --prefix backend-api test`: PASS, 25 tests
- `npm --prefix Frontend test`: PASS, 10 tests
- `npm --prefix Frontend run build`: PASS
- `python -m pytest -q --basetemp .pytest_tmp`: PASS, 25 tests
- `powershell -NoProfile -ExecutionPolicy Bypass -File scripts/validate_iac.ps1`: PASS
- `az bicep build --file infra/bicep/main.bicep`: PASS
- `docker build -f Frontend/Dockerfile -t diiac/patchforge-frontend:pfaz8a-local Frontend`: PASS
- `docker build -f backend-api/Dockerfile -t diiac/patchforge-bridge:pfaz8a-local backend-api`: PASS
- `docker build -f runtime/Dockerfile -t diiac/patchforge-runtime:pfaz8a-local .`: PASS

Document quality gate:

- Customer Patch Governance Pack DOCX generated from PF-AZ8A report context: PASS
- Board Vulnerability Remediation Summary DOCX generated from PF-AZ8A report context: PASS
- CAB Patch Decision Report DOCX generated from PF-AZ8A report context: PASS
- Matching PDF artefacts generated and rendered to page PNGs: PASS
- DOCX structural checks: PASS
- Microsoft Word open checks: PASS
- Required wording and boundary checks: PASS
- QA evidence: `docs/release/evidence/2026-05-27-patchforge-pfaz8a-report-specificity/local-report-qa/`

Important boundary note: PF-AZ8A does not add scanning, exploit generation, procedural exploit steps, patch deployment, production mutation from the UI, autonomous CAB approval, or autonomous risk acceptance.

Azure rollout:

- GitHub push: PASS, commit `4f3bbe8`
- Image tag: `pfaz8a-20260527-4f3bbe8`
- ACR image push: PASS for frontend, bridge/API, runtime, SRA, worker, and scheduler
- ACR tag verification: PASS for all six repositories
- Bicep what-if: captured; not applied because it included broader drift/noise than the image rollout required
- Targeted image-only Container Apps update: PASS
- Active revisions:
  - UI: `ca-patchforge-ui-prod--0000012`
  - Bridge/API: `ca-patchforge-bridge-prod--0000011`
  - Runtime: `ca-patchforge-runtime-prod--0000010`
  - SRA: `ca-patchforge-sra-prod--0000009`
  - Worker: `ca-patchforge-worker-prod--0000009`
  - Scheduler: `ca-patchforge-scheduler-prod--0000009`

Live validation:

- UI HTTP 200: PASS
- API health HTTP 200: PASS
- API readiness HTTP 200 with `storage=postgresql`, `auth_required=true`, and `tenant_required=true`: PASS
- Protected vulnerability route unauthenticated HTTP 401: PASS
- Browser/MSAL sign-in as `n.bailey@diiac.io`: PASS
- Displayed role `PatchForge.Admin`: PASS
- Context banner for `CVE-2026-48172`: PASS
- Safer automation wording visible: PASS
- Old autonomous-analysis heading absent: PASS
- Human approval notice visible: PASS
- Fresh signed pack generated after PF-AZ8A rollout: `PF-20260527-934d6e60`
- Pack verification: PASS, `verified=true`, `manifest_ok=true`, `signature_ok=true`
- Key Vault signing smoke: PASS, `pf-pack-signing-prod`, ES256, `azure_key_vault`
- Final approval remained false: PASS
- Customer Patch Governance Pack DOCX/PDF export: PASS
- Board Vulnerability Remediation Summary DOCX/PDF export: PASS
- CAB Patch Decision Report DOCX/PDF export: PASS
- DOCX wording checks and PDF render QA: PASS
- PostgreSQL readiness: PASS

PF-AZ8A evidence path:

`docs/release/evidence/2026-05-27-patchforge-pfaz8a-report-specificity/`

# PF-AZ9-OPS Validation Outputs

## PF-AZ9-OPS Operational Health Enablement

Date: 2026-05-27

Status: PASS. PF-AZ9-OPS is deployed to Azure and validated through the live Admin UI/API.

Scope:

- Enable MCP agent intake health as governed.
- Enable public source feeds health as ready.
- Enable worker health as ready.
- Enable scheduler health as ready.
- Preserve source-feed and agent-intake defaults during Admin config saves.
- Show health mode detail in the Admin UI.

Local validation:

- `node --check backend-api/server.js`: PASS
- `node --check backend-api/patchforge/storage.js`: PASS
- `npm --prefix backend-api test`: PASS, 25 tests
- `npm --prefix Frontend test`: PASS, 10 tests
- `npm --prefix Frontend run build`: PASS
- `python -m pytest -q --basetemp .pytest_tmp`: PASS, 25 tests
- `powershell -NoProfile -ExecutionPolicy Bypass -File scripts/validate_iac.ps1`: PASS
- `az bicep build --file infra/bicep/main.bicep`: PASS
- `git diff --check`: PASS

Azure rollout:

- GitHub push: PASS, commit `c494375`
- Image tag: `pfaz9-20260527-c494375`
- ACR tag verification: PASS for frontend, bridge/API, runtime, SRA, worker, and scheduler images
- Targeted Container Apps update: PASS
- Active revisions:
  - UI: `ca-patchforge-ui-prod--0000011`
  - Bridge/API: `ca-patchforge-bridge-prod--0000010`
  - Runtime: `ca-patchforge-runtime-prod--0000009`
  - SRA: `ca-patchforge-sra-prod--0000008`
  - Worker: `ca-patchforge-worker-prod--0000008`
  - Scheduler: `ca-patchforge-scheduler-prod--0000008`

Live validation:

- UI HTTP 200: PASS
- API readiness HTTP 200 with `storage=postgresql`, `auth_required=true`, and `tenant_required=true`: PASS
- Protected Admin health unauthenticated HTTP 401: PASS
- Browser/MSAL session as `n.bailey@diiac.io`: PASS
- Displayed role `PatchForge.Admin`: PASS
- MCP agent intake: PASS, `governed`
- Public source feeds: PASS, `ready`
- Worker health: PASS, `ready`
- Scheduler health: PASS, `ready`

PF-AZ9-OPS evidence path:

`docs/release/evidence/2026-05-27-patchforge-pfaz9-operational-health-enablement/`

# PF-AZ8 Validation Outputs

## PF-AZ8 Local Validation

Date: 2026-05-27

Status: PASS. PF-AZ8 is deployed to Azure and validated through the live UI/API.

Scope:

- Guided Action Center, Finding Detail, Review & Approve, and Reports & Packs workflow.
- Human-readable finding intelligence API.
- Decision-grade DOCX/PDF board and CAB reports.
- Signed-pack support for `finding_intelligence_snapshot.json`.

Local validation:

- `node --check backend-api/server.js`: PASS
- `node --check backend-api/patchforge/intelligence.js`: PASS
- `node --check backend-api/patchforge/reports.js`: PASS
- `npm --prefix backend-api test`: PASS, 25 tests
- `npm --prefix Frontend test`: PASS, 10 tests
- `python -m pytest -q --basetemp .pytest_tmp`: PASS, 25 tests
- `npm --prefix Frontend run build`: PASS
- `powershell -NoProfile -ExecutionPolicy Bypass -File scripts/validate_iac.ps1`: PASS
- `az bicep build --file infra/bicep/main.bicep`: PASS
- `docker build -f Frontend/Dockerfile -t diiac/patchforge-frontend:pfaz8-local Frontend`: PASS
- `docker build -f backend-api/Dockerfile -t diiac/patchforge-bridge:pfaz8-local backend-api`: PASS
- `docker build -f runtime/Dockerfile -t diiac/patchforge-runtime:pfaz8-local .`: PASS
- `git diff --check`: PASS

Document quality gate:

- Local board DOCX generated from signed-pack context: PASS
- Local board PDF generated from same context: PASS
- Local CAB DOCX generated from signed-pack context: PASS
- Local CAB PDF generated from same context: PASS
- Microsoft Word-rendered DOCX pages inspected as PNGs: PASS
- No clipping, overlap, broken tables, missing text, unreadable wrapping, or orphan note page observed.
- QA evidence: `docs/release/evidence/2026-05-27-patchforge-pfaz8-guided-intelligence-workflow/report-qa/`

Important boundary note: PF-AZ8 does not add scanning, exploit generation, procedural exploit steps, patch deployment, production mutation from the UI, autonomous CAB approval, or autonomous risk acceptance.

Azure rollout:

- GitHub push: PASS, commit `cc708fd`
- Image tag: `pfaz8-20260527-cc708fd`
- ACR build/push: PASS for frontend, bridge/API, runtime, SRA, worker, and scheduler images
- ACR tag verification: PASS for all six repositories
- Bicep what-if: captured; not applied because it included broader drift/noise than the image rollout required
- Targeted image-only Container Apps update: PASS
- Active revisions:
  - UI: `ca-patchforge-ui-prod--0000010`
  - Bridge/API: `ca-patchforge-bridge-prod--0000009`
  - Runtime: `ca-patchforge-runtime-prod--0000008`
  - SRA: `ca-patchforge-sra-prod--0000007`
  - Worker: `ca-patchforge-worker-prod--0000007`
  - Scheduler: `ca-patchforge-scheduler-prod--0000007`

Live validation:

- UI HTTP 200: PASS
- API health HTTP 200: PASS
- API readiness HTTP 200 with `storage=postgresql`, `auth_required=true`, and `tenant_required=true`: PASS
- Protected vulnerability route unauthenticated HTTP 401: PASS
- Browser/MSAL sign-in as `n.bailey@diiac.io`: PASS
- Displayed role `PatchForge.Admin`: PASS
- Simplified guided navigation smoke across Action Center, Finding Detail, Review & Approve, Reports & Packs, Guide, and Admin: PASS
- Real public-source record validated: `CVE-2026-48172`
- Finding Detail plain-English intelligence: PASS
- Exploitability intelligence boundary: PASS, no exploit code, payloads, or procedural exploitation steps shown
- Review & Approve automated governance analysis summary: PASS
- SRA advisory: PASS, advisory-only
- Fresh signed pack generated after PF-AZ8 rollout: `PF-20260527-9fc7f010`
- Pack verification: PASS, `verified=true`, `manifest_ok=true`, `signature_ok=true`
- Key Vault signing smoke: PASS through live pack export with `signing_provider=azure_key_vault`
- Final approval remained false: PASS
- Protected DOCX report generation from live signed pack: PASS
- Protected PDF report generation from live signed pack: PASS
- Admin health route: PASS, database, storage, Key Vault, signing trust, bridge, runtime, and frontend health visible
- PostgreSQL readiness: PASS

PF-AZ8 evidence path:

`docs/release/evidence/2026-05-27-patchforge-pfaz8-guided-intelligence-workflow/`

# PF-AZ6 / PF-AZ7 Validation Outputs

## PF-AZ7 Live Validation

Date: 2026-05-27

PF-AZ7 is deployed to Azure and validated through the live UI as a signed-in PatchForge Admin user.

Scope:

- Professional DOCX and PDF board-pack generation from signed decision packs.
- Protected report catalogue and report download APIs.
- UI Reports page and Decision Pack DOCX/PDF export actions.
- Scheduler mode for recurring live CISA KEV and FIRST EPSS refresh.
- Scheduler source lineage, advisory-only controls, and no scanner/no deployment boundaries.

Local validation:

- `node --check backend-api/server.js`: PASS
- `node --check backend-api/auth.js`: PASS
- `node --check backend-api/patchforge/reports.js`: PASS
- `node --check backend-api/patchforge/scheduler.js`: PASS
- `node --check backend-api/sra/securityResearchAgent.js`: PASS
- `node --test backend-api/patchforge-api.test.mjs`: PASS, 20 tests
- `npm --prefix backend-api test`: PASS, 24 tests
- `npm test`: PASS, 24 backend/SRA tests
- `python -m pytest -q --basetemp .pytest_tmp`: PASS, 25 tests
- `npm --prefix Frontend test`: PASS, 13 tests
- `npm --prefix Frontend run build`: PASS
- `powershell -NoProfile -ExecutionPolicy Bypass -File scripts/validate_iac.ps1`: PASS
- `az bicep build --file infra/bicep/main.bicep`: PASS
- `docker build -f Frontend/Dockerfile -t diiac/patchforge-frontend:pfaz7-local Frontend`: PASS
- `docker build -f backend-api/Dockerfile -t diiac/patchforge-bridge:pfaz7-local backend-api`: PASS
- `docker build -f runtime/Dockerfile -t diiac/patchforge-runtime:pfaz7-local .`: PASS

Document quality gate:

- Local DOCX board pack generated from real public-source CVE context: PASS
- Local PDF board pack generated from the same signed-pack context: PASS
- Microsoft Word-rendered DOCX pages inspected as PNGs: PASS
- No clipping, overlap, broken tables, missing text, or unreadable wrapping observed.
- QA evidence: `docs/release/evidence/2026-05-27-patchforge-pfaz7-operational-demo/doc-qa/docx-pdf-visual-qa.json`

Azure rollout:

- GitHub push: PASS, commit `71643ce4123bed543c9b0b55c39347b4775946d1`
- Image tag: `pfaz7-20260527-71643ce`
- ACR build/push: PASS for frontend, bridge/API, runtime, SRA, worker, and scheduler images
- ACR tag verification: PASS for all six repositories
- Bicep what-if: captured; not applied because it included broader drift/noise than the image rollout required
- Targeted image-only Container Apps update: PASS
- Scheduler min/max replicas: PASS, one active replica
- Active revisions:
  - UI: `ca-patchforge-ui-prod--0000009`
  - Bridge/API: `ca-patchforge-bridge-prod--0000008`
  - Runtime: `ca-patchforge-runtime-prod--0000007`
  - SRA: `ca-patchforge-sra-prod--0000006`
  - Worker: `ca-patchforge-worker-prod--0000006`
  - Scheduler: `ca-patchforge-scheduler-prod--0000006`

Live validation:

- UI HTTP 200: PASS
- API health HTTP 200: PASS
- API readiness HTTP 200 with `storage=postgresql` and `auth_required=true`: PASS
- Protected vulnerability route unauthenticated HTTP 401: PASS
- Protected reports route unauthenticated HTTP 401: PASS
- Browser/MSAL sign-in as `n.bailey@diiac.io`: PASS
- Displayed role `PatchForge.Admin`: PASS
- Full navigation smoke across Command Center, Guide, Vulnerability Queue, Asset & Service Exposure, Decision Workbench, Emergency Patch, Risk Acceptances, Compensating Controls, SRA Research, Evidence Catalogue, Decision Packs, Reports, Source Feeds, Vendor & Threat Landscape, and Admin: PASS
- Scheduler run completed at 2026-05-27T00:29:31Z: PASS
- Real public-source record validated: `CVE-2026-48172`
- SRA advisory for `CVE-2026-48172`: PASS, advisory-only/source-bound/pending-review
- Bayesian advisory for `CVE-2026-48172`: PASS, advisory-only
- Fresh signed pack generated after PF-AZ7 rollout: `PF-20260527-54588be9`
- Pack verification: PASS, `manifest_ok=true`, `signature_ok=true`, `source_pack_immutable=true`
- Key Vault signing smoke: PASS through live pack export with `signing_provider=azure_key_vault`
- Final approval remained false: PASS
- DOCX report download from live UI/API: PASS
- PDF report download from live UI/API: PASS
- Fresh DOCX/PDF visual QA: PASS
- PostgreSQL readiness and protected list/export paths: PASS

PF-AZ7 evidence path:

`docs/release/evidence/2026-05-27-patchforge-pfaz7-operational-demo/`

Important boundary note: PF-AZ7 does not add scanning, exploit generation, procedural exploit steps, patch deployment, production mutation from the UI, autonomous CAB approval, or autonomous risk acceptance.

Date: 2026-05-26

This file records PF-AZ6 validation commands and rollout evidence. It will be updated again after Azure deployment and live UI validation.

## PF-AZ6 Scope

- Live CISA KEV public source feed refresh.
- Live FIRST EPSS public source feed enrichment.
- Source-feed run ledger.
- UI Source Feeds page bound to protected live APIs.
- Source-bound, pending-review, advisory-only controls for public intelligence.

## Pre-Flight

- Git remote: `https://github.com/neil9bailey/diiac-patchforge.git`
- Branch: `main`
- Azure tenant: `67f8be6c-07da-4a7c-bb0a-d6bcb38cd6da`
- Resource group: `rg-diiac-patchforge-prod`

## Local Validation

- `node --check backend-api/server.js`: PASS
- `node --check backend-api/auth.js`: PASS
- `node --check backend-api/sra/securityResearchAgent.js`: PASS
- `python -m pytest -q --basetemp .pytest_tmp`: PASS, 25 tests
- `npm --prefix backend-api test`: PASS, 22 tests
- `npm test`: PASS, 22 backend/SRA tests
- `npm --prefix Frontend test`: PASS, 12 tests
- `npm --prefix Frontend run build`: PASS
- `powershell -NoProfile -ExecutionPolicy Bypass -File scripts/validate_iac.ps1`: PASS
- `az bicep build --file infra/bicep/main.bicep`: PASS
- `docker build -f Frontend/Dockerfile -t diiac/patchforge-frontend:pfaz6-local Frontend`: PASS
- `docker build -f backend-api/Dockerfile -t diiac/patchforge-bridge:pfaz6-local backend-api`: PASS
- `docker build -f runtime/Dockerfile -t diiac/patchforge-runtime:pfaz6-local .`: PASS
- Local signed pack verification: not rerun in the PF-AZ6 pre-Azure gate; runtime signing path is unchanged from PF-AZ5 and live pack verification will be rerun after Azure rollout.

PF-AZ6 Azure rollout status: PASS.

## Azure Rollout

- Git push: PASS, commit `473b055005cb2bb212e47f46aaf4e660faeb7d3a`
- Image tag: `pfaz6-20260526-473b055`
- ACR build/push: PASS for frontend, bridge/API, runtime, SRA, worker, and scheduler images
- ACR tag verification: PASS for all six repositories
- Full Bicep what-if: captured; not applied because it included broader drift/noise than the image rollout required
- Targeted image-only Container Apps update: PASS
- Active revisions:
  - UI: `ca-patchforge-ui-prod--0000008`
  - Bridge/API: `ca-patchforge-bridge-prod--0000007`
  - Runtime: `ca-patchforge-runtime-prod--0000006`
  - SRA: `ca-patchforge-sra-prod--0000005`
  - Worker: `ca-patchforge-worker-prod--0000005`
  - Scheduler: `ca-patchforge-scheduler-prod--0000005`

## Live Validation

- UI HTTP 200: PASS
- API health HTTP 200: PASS
- API readiness HTTP 200 with `storage=postgresql` and `auth_required=true`: PASS
- Protected vulnerability route unauthenticated HTTP 401: PASS
- Protected source-feed route unauthenticated HTTP 401: PASS
- Browser/MSAL sign-in as `n.bailey@diiac.io`: PASS
- Displayed role `PatchForge.Admin`: PASS
- CISA KEV feed refresh: PASS, 1603 records seen, 5 ingested
- FIRST EPSS feed refresh: PASS, `CVE-2026-48172` enriched
- Real CISA records observed in queue: `CVE-2026-48172`, `CVE-2026-9082`, `CVE-2025-34291`, `CVE-2026-34926`, `CVE-2008-4250`
- Bayesian Patch Risk advisory on `CVE-2026-48172`: PASS
- Signed decision pack generated and exported: `PF-20260526-8312f908`
- Pack verification: PASS
- Key Vault signing smoke: PASS through live pack export with `signing_provider=azure_key_vault`
- PostgreSQL readiness: PASS
- Production no-demo-data cleanup: PASS, old PF-AZ5 synthetic validation record `CVE-2026-PF-DEMO-001` and linked records removed
- Temporary PostgreSQL firewall rule cleanup: PASS, only `AllowAzureServices` remained after validation
- Final approval remained false: PASS

Evidence path:

`docs/release/evidence/2026-05-26-patchforge-pfaz6-live-source-intelligence/`

## PF-AZ5 Historical Validation

- Git push: PASS, commit `8a145e849a2c57fed3bc00440f2f2f8b29585f72`
- Image tag: `pfaz5-20260526-8a145e8`
- ACR build/push: PASS for frontend, bridge/API, runtime, SRA, worker, and scheduler images
- Full Bicep what-if: captured; not applied because it included broader drift/noise than the image rollout required
- Targeted image-only Container Apps update: PASS
- Active revisions:
  - UI: `ca-patchforge-ui-prod--0000007`
  - Bridge/API: `ca-patchforge-bridge-prod--0000006`
  - Runtime: `ca-patchforge-runtime-prod--0000005`
  - SRA: `ca-patchforge-sra-prod--0000004`
  - Worker: `ca-patchforge-worker-prod--0000004`
  - Scheduler: `ca-patchforge-scheduler-prod--0000004`

## Live Validation

- UI HTTP 200: PASS
- API health HTTP 200: PASS
- API readiness HTTP 200 with `storage=postgresql` and `auth_required=true`: PASS
- Protected route unauthenticated HTTP 401: PASS
- Browser/MSAL sign-in as `n.bailey@diiac.io`: PASS
- Displayed role `PatchForge.Admin`: PASS
- UI ingest of `CVE-2026-PF-DEMO-001`: PASS
- SRA exploit-risk advisory source-bound/advisory-only: PASS
- Bayesian Patch Risk advisory-only: PASS
- Signed decision pack generated and exported: `PF-20260526-e90d3a02`
- Pack verification: PASS
- Key Vault ES256 signing smoke: PASS
- Final approval remained false with readiness blocked pending evidence/human gates: PASS

Evidence path:

`docs/release/evidence/2026-05-26-patchforge-pfaz5-intelligence-rollout/`

Note: Azure CLI token acquisition for the custom PatchForge API was blocked by AADSTS65001 interactive consent for the Azure CLI client, so the authenticated workflow was validated through the deployed browser/MSAL path.
