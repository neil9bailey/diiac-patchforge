# PF-AZ6 / PF-AZ7 Validation Outputs

## PF-AZ7 Local Candidate Validation

Date: 2026-05-27

PF-AZ7 is locally validated and pending GitHub push, Azure image rollout, live API smoke, signed-in browser validation, and live DOCX/PDF download visual QA.

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

Azure rollout status:

- GitHub push: pending
- Image tag: pending
- Azure update: pending
- Live API smoke: pending
- Live browser/MSAL validation: pending
- Live DOCX/PDF report download and visual QA: pending

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
