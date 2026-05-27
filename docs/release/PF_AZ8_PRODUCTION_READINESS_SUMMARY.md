# PF-AZ8 Production Readiness Summary

Date: 2026-05-27

Status: PASS. PF-AZ8 is deployed to Azure and validated through the live UI/API.

PF-AZ8 responds to customer-demo feedback that the product needed to feel less like a technical queue and more like an intelligent decision workflow.

## Added

- Guided user workflow:
  - Action Center
  - Finding Detail
  - Review & Approve
  - Reports & Packs
- Human-readable finding intelligence API:
  - `GET /api/patchforge/action-center`
  - `GET /api/patchforge/vulnerabilities/:id/intelligence`
  - `POST /api/patchforge/vulnerabilities/:id/analyse`
- Automated governance analysis wording and behaviour for normalisation, source binding, exploitability interpretation, evidence gaps, recommended posture, and next actions.
- Signed-pack artefact support for `finding_intelligence_snapshot.json`.
- Decision-grade DOCX/PDF reports with:
  - executive decision summary
  - plain-English vulnerability explanation
  - exploitability intelligence without exploit instructions
  - affected product/service/asset scope
  - recommended governance posture
  - decision options matrix
  - evidence confidence and gaps
  - human decisions still required
  - source-pack/current-state separation
  - signed artefact appendix

## Local Validation

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
- Local DOCX/PDF report QA: PASS

Report QA evidence:

- `docs/release/evidence/2026-05-27-patchforge-pfaz8-guided-intelligence-workflow/report-qa/`

## Azure Rollout

- GitHub push: PASS, commit `cc708fd`
- Image tag: `pfaz8-20260527-cc708fd`
- ACR build/push: PASS for frontend, bridge/API, runtime, SRA, worker, and scheduler images
- ACR tag verification: PASS
- What-if: captured under release evidence; full template apply was not used because the what-if included broader drift/noise than the image-only rollout required
- Targeted Container Apps image update: PASS

Active revisions:

- UI: `ca-patchforge-ui-prod--0000010`
- Bridge/API: `ca-patchforge-bridge-prod--0000009`
- Runtime: `ca-patchforge-runtime-prod--0000008`
- SRA: `ca-patchforge-sra-prod--0000007`
- Worker: `ca-patchforge-worker-prod--0000007`
- Scheduler: `ca-patchforge-scheduler-prod--0000007`

## Live Validation

- UI HTTP 200: PASS
- API health HTTP 200: PASS
- API readiness HTTP 200 with `storage=postgresql`, `auth_required=true`, and `tenant_required=true`: PASS
- Protected route unauthenticated HTTP 401: PASS
- Signed-in browser validation as `n.bailey@diiac.io`: PASS
- Displayed role `PatchForge.Admin`: PASS
- Action Center live API binding: PASS
- Finding Detail plain-English intelligence for `CVE-2026-48172`: PASS
- Review & Approve human-gated workflow: PASS
- SRA advisory-only workflow: PASS
- Signed decision pack generated: `PF-20260527-9fc7f010`
- Pack verification: PASS
- Key Vault signing provider: `azure_key_vault`
- Final approval issued: `false`
- Protected DOCX report generation: PASS
- Protected PDF report generation: PASS
- Admin health page: PASS
- Guide page: PASS
- PostgreSQL readiness: PASS

Live evidence:

- `docs/release/evidence/2026-05-27-patchforge-pfaz8-guided-intelligence-workflow/live-ui/`

## Boundary

PF-AZ8 does not add vulnerability scanning, exploit generation, procedural exploit steps, patch deployment, production mutation from UI, autonomous CAB approval, or autonomous risk acceptance.

PatchForge performs automated governance analysis and recommendation drafting only. Accountable human review remains required for approval, closure, and risk acceptance.
