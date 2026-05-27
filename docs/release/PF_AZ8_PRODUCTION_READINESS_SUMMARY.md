# PF-AZ8 Production Readiness Summary

Date: 2026-05-27

Status before Azure rollout: local validation passed; Azure image build, deployment, and live browser validation pending.

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
- Autonomous analysis wording and behaviour for normalisation, source binding, exploitability interpretation, evidence gaps, recommended posture, and next actions.
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

## Boundary

PF-AZ8 does not add vulnerability scanning, exploit generation, procedural exploit steps, patch deployment, production mutation from UI, autonomous CAB approval, or autonomous risk acceptance.

PatchForge performs autonomous analysis and recommendation drafting only. Accountable human review remains required for approval, closure, and risk acceptance.
