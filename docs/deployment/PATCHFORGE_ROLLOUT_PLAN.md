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

Status: complete for production bootstrap on 2026-05-26.

Executed against:

- tenant ID `67f8be6c-07da-4a7c-bb0a-d6bcb38cd6da`
- subscription ID `9ae9da49-de67-443b-af55-ce9db33ed8f4`
- region `uksouth`
- resource group `rg-diiac-patchforge-prod`

## Phase 3: Non-Production Deployment

Recommended before production:

- deploy non-production resource group
- validate health endpoints
- validate signed pack storage
- validate Entra role claims
- validate Key Vault access
- validate logging

## Phase 4: Production Deployment

Status: bootstrap complete on 2026-05-26.

Created:

- dedicated resource group
- managed identities
- ACR
- Storage containers
- Key Vault
- Log Analytics
- Container Apps environment
- UI, bridge, runtime, SRA, worker, and scheduler apps

Still pending:

- production PostgreSQL
- Entra app registration and role enforcement hardening
- production signing key creation
- custom domains and TLS binding
- DNS cutover

## Phase 5: DNS Cutover

Update DNS only after custom domain binding and TLS are validated.
