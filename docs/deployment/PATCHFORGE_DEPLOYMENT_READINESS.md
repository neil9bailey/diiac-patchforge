# PatchForge Deployment Readiness

## Purpose

PF-E11 prepares DIIaC™ PatchForge for controlled deployment without creating or mutating Azure resources.

## Current Gate

PatchForge is ready for deployment planning, container build smoke checks, CI validation, and Azure what-if preparation.

PatchForge is not yet ready for live production deployment until the user confirms:

- Azure tenant ID
- Azure subscription ID
- target Azure region
- production/non-production rollout order
- Entra app registration and role assignment plan
- Key Vault signing strategy
- DNS ownership and cutover plan

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

Do not run Azure deployment create/apply commands until the deployment gate is explicitly opened.

Allowed before approval:

- local tests
- local builds
- local Docker builds
- Bicep build
- Azure what-if after tenant/subscription confirmation

Not allowed before approval:

- resource creation
- role assignment mutation
- Key Vault mutation
- DNS changes
- production signing key creation
- Container Apps revision deployment

## Local URLs

When using `scripts/start_local_dev.ps1`:

- frontend: `http://127.0.0.1:5173`
- API: `http://127.0.0.1:8080`

When using Docker Compose:

- frontend: `http://127.0.0.1:5173`
- API: `http://127.0.0.1:8080`
- runtime health: `http://127.0.0.1:8081/health`
