# PatchForge Deployment Readiness

## Purpose

Track PatchForge deployment readiness, live Azure bootstrap state, and remaining cutover gates.

## Current Candidate Gate — 2026-07-14

The 14-area improvement implementation is a local candidate, not a claimed Azure release. Follow the [14-Area Improvement Closure Matrix](../validation/PATCHFORGE_14_AREA_IMPROVEMENT_CLOSURE_2026-07-14.md) before any rollout. In particular:

- Areas 1-3 (signed-in production UAT, fresh report/artifact proof, and UAT cleanup) remain pending.
- Area 14 (clean Git/GitHub state, required checks, approval attestation, guarded Azure rollout, and live readback) remains pending.
- A Bicep what-if must contain no unexplained replacement, deletion, database, storage, identity, or network changes.
- The exact commit, tag, product baseline, and report context must match the protected production approval artifact.
- All six rollback images must be preserved locally before production mutation.
- Stop on any failed/ambiguous native command, digest/signature mismatch, unhealthy revision, readiness failure, or metadata disagreement.

The historical bootstrap details below describe already-established platform resources. They do not authorize or evidence the current candidate rollout.

## Current Gate

PatchForge Azure bootstrap is live in a dedicated production resource group. The identity, production signing key, PostgreSQL resource, DNS custom-domain, API RBAC, PostgreSQL storage, and runtime Key Vault signing gates are completed.

PatchForge is not yet ready for full production cutover until the user confirms:

- UI sign-in flow and client-side role UX
- private networking design for PostgreSQL and storage

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
- Deployed image tag: `pfaz4-20260526`

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
