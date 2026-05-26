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
