# PatchForge Validation Plan

## Scope

This plan validates the local 14-area improvement candidate before any GitHub/Azure release claim. It does not replace signed-in production UAT, exact-byte/visual report proof, cleanup evidence, or customer collector acceptance.

## Validation Gates

1. Product boundary documents repeat the no-scanner, no-exploit, no-patch-deployment, no-production-mutation, and no-autonomous-approval/risk-acceptance/closure boundary.
2. Domain schemas and server-owned finding evidence/review/expiry/reopen tests pass.
3. External source SSRF/DNS/redirect/size/time tests and optional-AI trust-boundary tests pass.
4. Backend API, runtime governance, exact-byte artifact, ZIP/report, scheduler/worker, SRA, and collector tests pass.
5. Frontend unit, production build, bundle budget, Playwright role/responsive journey, and axe accessibility checks pass.
6. Windows collector PowerShell lifecycle and package verification pass; unsigned output is labelled development-only.
7. Python/Node dependency audits and repository/container/IaC/secret/security scans pass at the configured release severity.
8. Azure IaC builds and the production what-if contains no unexplained destructive or topology changes.
9. A clean source commit produces attributable artifacts, SBOMs, attestations, immutable image digests, and a protected production approval artifact.
10. Signed-in production UAT proves role boundaries through the six-area UI.
11. Fresh production ZIP/DOCX/PDF exact bytes verify and DOCX/PDF visual review passes.
12. Prefixed UAT records are previewed, removed with typed confirmation, proved absent, and remain represented in audit evidence.
13. All six Container Apps are healthy/latest-ready, receive intended traffic, and report matching release metadata.
14. No demo seed data is shipped; demonstrations use explicitly identified operator-supplied or prefixed temporary records only.

## Commands

```powershell
python -m pytest -q --basetemp .pytest_tmp
npm test
npm run api:check
npm run collector:test
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/test_patchforge_collector_windows_lifecycle.ps1
npm --prefix Frontend test
npm --prefix Frontend run build
npm --prefix Frontend run test:e2e
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/validate_iac.ps1
```

Run the dependency/security/provenance jobs through the pinned GitHub workflows in `.github/workflows/ci.yml` and `.github/workflows/security.yml`. Retain the reports, SBOMs, and attestations with the release evidence.

## Azure Gate

Do not run deployment create/apply commands until the exact commit/tag/baseline/context has a successful protected production approval artifact, the what-if is approved, local rollback images exist, and the guarded publisher preflight passes. Stop on any command failure, digest/signature mismatch, unexpected what-if change, unhealthy revision, or readiness/metadata disagreement.

See [PatchForge 14-Area Improvement Closure Matrix](PATCHFORGE_14_AREA_IMPROVEMENT_CLOSURE_2026-07-14.md) for the per-area operator and closure evidence.
