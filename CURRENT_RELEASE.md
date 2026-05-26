# Current Release

## DIIaC™ PatchForge PF-AZ1

Release state: Azure bootstrap live

Date: 2026-05-26

## Scope

PF-AZ1 deploys the first dedicated PatchForge Azure bootstrap into the DIIaC tenant using a new PatchForge resource group.

Included:

- repository skeleton
- product positioning document
- product boundary document
- implementation programme
- master working brief
- intended use
- claims matrix
- boundary matrix
- architecture
- Azure architecture
- security model
- epic backlog
- Bicep modules for resource group, managed identities, monitoring, ACR, storage, Key Vault, PostgreSQL placeholder, and Container Apps
- two-pass Container Apps deployment switch so ACR can be created and populated before app revisions are deployed
- ACR bootstrap SKU set to `Basic` with optional registry policies removed after Azure rejected the original policy/SKU combination
- production Bicep parameter placeholders
- IaC validation script
- Azure deployment planning script
- image build/push planning script
- vulnerability, source, asset, service, exploitability, threat context, patch availability, feasibility, controls, readiness, risk acceptance, decision, outcome, SRA, and pack manifest schemas
- evidence models for IT, emergency patch, risk acceptance, service transition, and OT patch governance
- contract tests for schema loading, required fields, SRA advisory-only state, final approval defaults, and hard gate controls
- Node Backend API with health, readiness, vulnerability, asset, service, exposure, and dashboard metrics endpoints
- local JSON storage abstraction under customer-config/demo/patchforge
- API tests for tenant isolation, review events, rejected evidence exclusion, metrics, and boundary endpoints
- deterministic governance runtime
- evidence register and evidence model evaluation
- policy pack evaluation and readiness calculation
- patch decision context construction
- local signed decision pack generation and verification
- runtime tests for rejected evidence, SRA/scanner hard-gate limits, emergency approval blockers, pack verification, and boundary rejection
- React/Vite PatchForge UI
- Command Center
- Vulnerability Queue
- Asset & Service Exposure
- Decision Workbench
- Emergency Patch
- Risk Acceptances
- Compensating Controls
- SRA Research
- Evidence Catalogue
- Decision Packs
- Admin route
- frontend tests and production build
- local admin config file
- admin config read/write API
- read-only admin health API
- secret masking after save
- UI health panels and configuration controls
- SRA advisory tool layer
- SRA API routes
- source-bound output hashes
- pending-review default
- no exploit or deployment action flags
- SRA boundary tests
- immutable source pack model
- current-state overlay model
- DCC event ledger
- evidence blocker resolution
- human approval recording
- risk acceptance expiry checks
- post-patch validation event handling
- DCC tests
- report renderer for CAB, board, customer, risk acceptance, and OT reports
- demo runbook
- demo scenario seeds
- validation plan
- readiness summary
- report and demo tests
- GitHub Actions CI
- deployment readiness docs
- Azure access checklist
- DIIaC tenant and Azure subscription reference captured from IT Services repo
- DNS cutover checklist
- Entra RBAC checklist
- production signing strategy
- rollout plan
- Dockerfiles for frontend, backend/API, and runtime
- runtime health server
- Docker Compose local orchestration
- local dev startup script
- release baseline manifest
- document control register
- Azure resource group `rg-diiac-patchforge-prod`
- ACR `acrdiiacpatchforgeprod.azurecr.io`
- ACA environment `acae-diiac-patchforge-prod`
- live UI, bridge, runtime, SRA, worker, and scheduler Container Apps
- live Key Vault, Storage, Log Analytics, and managed identities
- bootstrap images pushed to ACR
- HTTP smoke evidence for public UI, bridge health, and bridge readiness

Excluded:

- DNS cutover
- custom domain binding
- production PostgreSQL creation
- production signing key creation
- Entra app registration automation
- vulnerability scanning
- exploit generation
- patch deployment
- SIEM, SOAR, ITSM, CMDB, EDR, XDR, or OT engineering replacement functionality

## Runtime State

PatchForge bootstrap services are live in Azure Container Apps.

Public endpoints:

- UI: `https://ca-patchforge-ui-prod.lemonpebble-11b2e331.uksouth.azurecontainerapps.io/`
- Bridge health: `https://ca-patchforge-bridge-prod.lemonpebble-11b2e331.uksouth.azurecontainerapps.io/health`
- Bridge readiness: `https://ca-patchforge-bridge-prod.lemonpebble-11b2e331.uksouth.azurecontainerapps.io/readiness`

Internal endpoints:

- Runtime: `ca-patchforge-runtime-prod.internal.lemonpebble-11b2e331.uksouth.azurecontainerapps.io`
- SRA: `ca-patchforge-sra-prod.internal.lemonpebble-11b2e331.uksouth.azurecontainerapps.io`
- Worker: `ca-patchforge-worker-prod.internal.lemonpebble-11b2e331.uksouth.azurecontainerapps.io`
- Scheduler: `ca-patchforge-scheduler-prod.internal.lemonpebble-11b2e331.uksouth.azurecontainerapps.io`

## Deployment State

Deployment performed on 2026-05-26.

Target:

- Tenant ID: `67f8be6c-07da-4a7c-bb0a-d6bcb38cd6da`
- Subscription ID: `9ae9da49-de67-443b-af55-ce9db33ed8f4`
- Region: `uksouth`
- Resource group: `rg-diiac-patchforge-prod`

Deployment evidence:

- `docs/release/evidence/2026-05-26-patchforge-azure-bootstrap/`

## Trust State

Signed pack generation is implemented locally with a development/test signature path. Azure Key Vault is deployed, but production signing keys have not yet been created or bound.
