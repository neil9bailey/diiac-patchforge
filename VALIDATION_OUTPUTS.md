# PF-AZ5 Validation Outputs

Date: 2026-05-26

This file records PF-AZ5 validation commands and live rollout evidence. It is updated again after Azure deployment and live UI validation.

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
- `npm --prefix backend-api test`: PASS, 20 tests
- `npm test`: PASS, 20 backend/SRA tests
- `npm --prefix Frontend test`: PASS, 11 tests
- `npm --prefix Frontend run build`: PASS
- `powershell -NoProfile -ExecutionPolicy Bypass -File scripts/validate_iac.ps1`: PASS
- `az bicep build --file infra/bicep/main.bicep`: PASS
- `docker build -f Frontend/Dockerfile -t diiac/patchforge-frontend:local Frontend`: PASS
- `docker build -f backend-api/Dockerfile -t diiac/patchforge-bridge:local backend-api`: PASS
- `docker build -f runtime/Dockerfile -t diiac/patchforge-runtime:local .`: PASS
- Local signed pack verification: PASS
- Local signed pack path: `F:\code\diiac\patchforge\artifacts\pfaz5-validation-pack`

## Azure Rollout

Pending final image build, push, deployment update, and live validation.
