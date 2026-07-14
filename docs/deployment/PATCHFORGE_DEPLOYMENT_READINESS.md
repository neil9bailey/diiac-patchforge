# PatchForge Deployment Readiness

## Purpose

Track PatchForge deployment readiness, live Azure bootstrap state, and remaining cutover gates.

## Current Image Release Gate — 2026-07-14

The approved image-only rollout for source commit `f51802d3544260259c252e6be88d6e7bae596868`, image tag `pfaz-enterprise-20260714d-f51802d`, baseline `PF-AZ-ENTERPRISE-AUTOMATION-20260714D`, and report context `patchforge-report-context.pfaz-enterprise-20260714d.v1` completed successfully. GitHub approval run `29345354677` was verified, the provenance manifest verified under ES256 with SHA-256 `d9c8f265aaab5c7d10549f1730620a9681bb0b13ff10c8b870973f52c07b9615`, and all six Container Apps reached healthy revisions with the approved image digests. Public UI, health, readiness, and protected-route smoke checks passed, and the temporary direct signing-key role assignment was absent after release.

This is **not full production acceptance**. Signed-in `PatchForge.Admin` health UAT passed all 13 checks against live `f51802d`, but the DOCX report journey failed closed with `signature_cryptographic_verification_failed`. The closeout branch locally fixes the Azure `KeyType.ec` / `KeyCurveName.p_256` label mismatch by strictly normalizing recognized values to `EC` / `P-256` before full ES256 verification; negative cases remain fail-closed. It also implements/tests ingestion navigation, verified ZIP export, and exact-ID cleanup. None of these fixes is deployed or live-accepted, and broader role UAT remains required.

The publisher changed images only. Live remains six apps at `minReplicas=0`, with no probes and July 11 metadata. The latest What-If has 43 resources: 0 destructive, 7 modify, 20 no-change, 3 ignore, 13 unsupported; 0 image changes, 0 environment removals, metadata convergence on six apps, +12 probes, and one intentional scheduler `min0→1` change because its timer is in-process. Full Bicep was not applied and needs new exact approval.

See the [14-Area Improvement Closure Matrix](../validation/PATCHFORGE_14_AREA_IMPROVEMENT_CLOSURE_2026-07-14.md), [Current Release](../../CURRENT_RELEASE.md), and [sanitized release evidence](../release/evidence/2026-07-14-patchforge-enterprise-image-rollout/README.md). The historical bootstrap details below describe already-established platform resources.

## Current Gate

PatchForge Azure bootstrap is live in a dedicated production resource group. The identity, production signing key, PostgreSQL resource, DNS custom-domain, API RBAC, PostgreSQL storage, and runtime Key Vault signing gates are completed.

PatchForge is not yet ready for full production acceptance. The remaining release gates are:

- deploy the strict report-verification normalization fix and prove fresh live DOCX, ZIP, and signed-pack artifacts without weakening fail-closed checks;
- deploy the closeout navigation, verified-ZIP, and exact-ID cleanup changes under an exact approval, then complete their signed-in production proof and representative role journeys;
- resolve or explicitly approve the 13 unsupported What-If resources, then apply the reviewed metadata/probe changes under a separate exact approval;
- complete trusted collector signing, clean customer-machine installation and lifecycle UAT, and representative customer acceptance; and
- close legal/licensing actions, including the repository root licence position.

Private-networking design for PostgreSQL and storage remains a separate production-hardening decision.

Known non-secret tenant planning values are recorded in `docs/deployment/PATCHFORGE_DIIAC_TENANT_REFERENCE.md`:

- tenant ID: `67f8be6c-07da-4a7c-bb0a-d6bcb38cd6da`
- subscription ID: `9ae9da49-de67-443b-af55-ce9db33ed8f4`
- region: `uksouth`

## Required Validation Before Deployment

Run:

```powershell
python -m pytest -q --basetemp .pytest_tmp
npm test
npm --prefix backend-api test
npm run collector:test
npm --prefix Frontend test
npm --prefix Frontend run build
npm --prefix Frontend run test:e2e
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/validate_iac.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/test_patchforge_collector_windows_lifecycle.ps1
```

Optional container smoke:

```powershell
docker build -t diiac/patchforge-frontend:local Frontend
docker build -t diiac/patchforge-bridge:local backend-api
docker build -f runtime/Dockerfile -t diiac/patchforge-runtime:local .
```

Local compose:

```powershell
docker compose up --build
```

Local dev without Docker:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/start_local_dev.ps1
```

## Deployment Boundary

The Azure bootstrap deployment gate was opened by user instruction on 2026-05-26.

Allowed without a new approval:

- local tests
- local builds
- local Docker builds
- Bicep build
- Azure read-only inspection
- Azure what-if

Requires a matching protected production approval artifact plus accountable user approval:

- additional resource creation outside the current PatchForge gate plan
- role assignment mutation outside the existing IaC baseline
- Key Vault mutation
- DNS changes
- Container Apps revision deployment

Production publishing must use `scripts/publish_patchforge_production.ps1` with the successful GitHub approval run ID. Preview/default mode is non-mutating; `-Execute` is permitted only when its commit/tag/baseline/context inputs match the verified attested approval artifact and all script preconditions pass.

## Live Azure URLs

- UI: `https://ca-patchforge-ui-prod.lemonpebble-11b2e331.uksouth.azurecontainerapps.io/`
- Bridge health: `https://ca-patchforge-bridge-prod.lemonpebble-11b2e331.uksouth.azurecontainerapps.io/health`
- Bridge readiness: `https://ca-patchforge-bridge-prod.lemonpebble-11b2e331.uksouth.azurecontainerapps.io/readiness`

Live custom-domain URLs:

- UI: `https://patchforge.diiac.io/`
- API health: `https://api.patchforge.diiac.io/health`
- API readiness: `https://api.patchforge.diiac.io/readiness`

## Live Identity And Data Gates

- API app ID: `ec30b0eb-cfc4-48cc-a5f2-2a1345d96736`
- UI app ID: `c4dfca53-14a5-4688-817d-6c6c7dd47407`
- PostgreSQL server: `psql-diiac-patchforge-prod.postgres.database.azure.com`
- PostgreSQL database: `patchforge_prod`
- Key Vault signing key: `pf-pack-signing-prod`
- Gate evidence: `docs/release/evidence/2026-05-26-patchforge-gates/`
- DNS cutover evidence: `docs/release/evidence/2026-05-26-patchforge-dns-cutover/`
- Production hardening evidence: `docs/release/evidence/2026-05-26-patchforge-production-hardening/`
- Historical PF-AZ4 image tag: `pfaz4-20260526`
- Current approved image tag: `pfaz-enterprise-20260714d-f51802d`

HTTP smoke after gates:

- UI: 200
- Bridge health: 200
- Bridge readiness: 200

HTTPS smoke after DNS cutover:

- Custom-domain UI: 200
- Custom-domain API health: 200
- Custom-domain API readiness: 200

PF-AZ4 smoke:

- Custom-domain UI: 200
- Custom-domain API health: 200
- Custom-domain API readiness: 200 with `storage=postgresql` and `auth_required=true`
- Unauthenticated protected API request: 401 expected

## Local URLs

When using `scripts/start_local_dev.ps1`:

- frontend: `http://127.0.0.1:5173`
- API: `http://127.0.0.1:8080`

When using Docker Compose:

- frontend: `http://127.0.0.1:5173`
- API: `http://127.0.0.1:8080`
- runtime health: `http://127.0.0.1:8081/health`
