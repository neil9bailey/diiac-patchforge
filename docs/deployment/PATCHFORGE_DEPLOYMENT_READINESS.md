# PatchForge Deployment Readiness

## Purpose

Track PatchForge deployment readiness, live Azure bootstrap state, and remaining cutover gates.

## Current Gate

PatchForge Azure bootstrap is live in a dedicated production resource group.

PatchForge is not yet ready for full production cutover until the user confirms:

- Entra app registration and role assignment plan
- Key Vault signing strategy
- DNS ownership and cutover plan
- PostgreSQL/database deployment plan
- custom domain and TLS binding plan

Known non-secret tenant planning values are recorded in `docs/deployment/PATCHFORGE_DIIAC_TENANT_REFERENCE.md`:

- tenant ID: `67f8be6c-07da-4a7c-bb0a-d6bcb38cd6da`
- subscription ID: `9ae9da49-de67-443b-af55-ce9db33ed8f4`
- region: `uksouth`

## Required Validation Before Deployment

Run:

```powershell
python -m pytest -q --basetemp .pytest_tmp
npm test
npm --prefix Frontend test
npm --prefix Frontend run build
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/validate_iac.ps1
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

Requires fresh user approval:

- additional resource creation
- role assignment mutation outside the existing IaC baseline
- Key Vault mutation
- DNS changes
- production signing key creation
- Container Apps revision deployment

## Live Azure URLs

- UI: `https://ca-patchforge-ui-prod.lemonpebble-11b2e331.uksouth.azurecontainerapps.io/`
- Bridge health: `https://ca-patchforge-bridge-prod.lemonpebble-11b2e331.uksouth.azurecontainerapps.io/health`
- Bridge readiness: `https://ca-patchforge-bridge-prod.lemonpebble-11b2e331.uksouth.azurecontainerapps.io/readiness`

## Local URLs

When using `scripts/start_local_dev.ps1`:

- frontend: `http://127.0.0.1:5173`
- API: `http://127.0.0.1:8080`

When using Docker Compose:

- frontend: `http://127.0.0.1:5173`
- API: `http://127.0.0.1:8080`
- runtime health: `http://127.0.0.1:8081/health`
