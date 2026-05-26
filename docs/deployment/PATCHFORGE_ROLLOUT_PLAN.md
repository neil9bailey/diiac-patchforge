# PatchForge Rollout Plan

## Phase 0: Local Baseline

Status: complete through PF-E10.

Includes:

- docs and working memory
- schemas and evidence models
- backend API
- runtime and local signed packs
- frontend/admin shell
- SRA advisory layer
- Decision Control Center foundations
- reports, demos, validation

## Phase 1: CI/CD Hardening

PF-E11 adds:

- GitHub Actions CI
- Dockerfiles
- local orchestration
- deployment readiness docs

## Phase 2: Azure What-If

Run only after tenant/subscription/region confirmation.

Expected command:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/plan_azure_deployment.ps1 `
  -SubscriptionId <subscription-id> `
  -TenantId <tenant-id> `
  -RunWhatIf
```

## Phase 3: Non-Production Deployment

Recommended before production:

- deploy non-production resource group
- validate health endpoints
- validate signed pack storage
- validate Entra role claims
- validate Key Vault access
- validate logging

## Phase 4: Production Deployment

Production deployment requires explicit approval.

## Phase 5: DNS Cutover

Update DNS only after production ingress and TLS are validated.

