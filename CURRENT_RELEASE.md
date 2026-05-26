# Current Release

## DIIaC PatchForge PF-AZ5

Release state: PF-AZ5 intelligence hardening implementation in progress, with Azure rollout and live UI validation still to be evidenced for this increment

Date: 2026-05-26

## Scope

PF-AZ5 extends the current dedicated PatchForge Azure production state in the DIIaC tenant using the PatchForge resource group.

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
- local JSON storage abstraction under customer-config/default/patchforge
- API tests for tenant isolation, review events, rejected evidence exclusion, metrics, and boundary endpoints
- deterministic governance runtime
- evidence register and evidence model evaluation
- policy pack evaluation and readiness calculation
- patch decision context construction
- local signed decision pack generation and verification
- runtime tests for rejected evidence, SRA/scanner hard-gate limits, emergency approval blockers, pack verification, and boundary rejection
- React/Vite PatchForge UI with Microsoft Entra sign-in
- live protected API client
- no static vulnerability queue or seeded product data
- Command Center
- Vulnerability Queue
- real record ingest form
- Asset & Service Exposure
- Decision Workbench
- runtime signed decision-pack generation from ingested records
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
- customer demonstration runbook for real operator-supplied data only
- validation plan
- readiness summary
- report and no-seed validation tests
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
- Entra app registrations for `DIIaC PatchForge API` and `DIIaC PatchForge UI`
- PatchForge app roles and initial group assignments
- DIIaC admin group membership evidence for `n.bailey@diiac.io` and `nbailey@diiac.io`
- production Key Vault signing key `pf-pack-signing-prod`
- ES256 Key Vault signing smoke verification
- Azure Database for PostgreSQL Flexible Server `psql-diiac-patchforge-prod`
- PostgreSQL database `patchforge_prod`
- custom domains `patchforge.diiac.io` and `api.patchforge.diiac.io`
- Azure Container Apps managed certificates for both PatchForge custom domains
- HTTPS smoke evidence for custom-domain UI, bridge health, and bridge readiness
- Bridge/API Entra bearer-token enforcement for protected PatchForge API routes
- PostgreSQL storage adapter for PatchForge records, admin config, and audit events
- Bridge/API production deployment using PostgreSQL storage
- Bridge/API managed identity retrieval of the existing PostgreSQL password secret from Key Vault
- Runtime Azure Key Vault ES256 signing integration
- live runtime Key Vault signing smoke against `pf-pack-signing-prod`
- Bicep-managed custom-domain certificate bindings to prevent future deployment drift
- image tag `pfaz5-20260526` deployed to all PatchForge Container Apps
- image tag `pfaz5-agent-20260526` deployed to UI, bridge/API, and runtime for the Guide and agent-intelligence increment
- bridge-to-runtime internal Container Apps service discovery using the runtime app name
- decision-pack archive API
- Guide page for agent-led, human-approved PatchForge operation
- protected agent-finding intake API for MCP, Mythos, AGI-agent, and SRA advisory sources
- evidence model controls preventing agent findings from closing hard gates alone
- no demo seed pack or synthetic scenario data shipped
- live PF-AZ5 release evidence in `docs/release/evidence/2026-05-26-patchforge-live-product/`
- production auth fail-closed guard in application code
- production tenant context derived from verified Entra token/configured tenant mapping
- actor and tenant lineage on write actions
- Bayesian Patch Risk Inference as advisory-only governance intelligence
- vendor and threat landscape intelligence with source-bound review states
- live API-bound UI surfaces for metrics, vulnerabilities, assets, services, admin health/config, SRA, Bayesian, and vendor intelligence
- Microsoft Entra role UX in the frontend, including admin-control visibility gates
- board-grade report sections for signed pack metadata, Bayesian advisory, vendor/threat context, source-pack/current-state separation, blockers, and boundary controls
- signed decision-pack support for Bayesian, prior usage, prior proposal, vendor, threat landscape, and SRA artefacts

Excluded:

- seeded demo data
- synthetic vulnerability data
- vulnerability scanning
- exploit generation
- patch deployment
- SIEM, SOAR, ITSM, CMDB, EDR, XDR, or OT engineering replacement functionality
- unreviewed AI or agent source truth claims

PF-AZ5 Azure deployment, image tag, active revisions, and live browser validation evidence are recorded after the rollout is applied and verified.

## Runtime State

PatchForge bootstrap services are live in Azure Container Apps.

Public endpoints:

- UI custom domain: `https://patchforge.diiac.io/`
- API health custom domain: `https://api.patchforge.diiac.io/health`
- API readiness custom domain: `https://api.patchforge.diiac.io/readiness`
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
- `docs/release/evidence/2026-05-26-patchforge-gates/`
- `docs/release/evidence/2026-05-26-patchforge-dns-cutover/`
- `docs/release/evidence/2026-05-26-patchforge-production-hardening/`
- `docs/release/evidence/2026-05-26-patchforge-live-product/`

Latest PF-AZ5 agent-intelligence revisions:

- UI: `ca-patchforge-ui-prod--0000006`
- Bridge/API: `ca-patchforge-bridge-prod--0000005`
- Runtime: `ca-patchforge-runtime-prod--0000004`
- Image tag: `pfaz5-agent-20260526`

## Trust State

Signed pack generation supports both local development/test signatures and Azure Key Vault ES256 production signatures.

Azure Key Vault production signing key `pf-pack-signing-prod` exists and the runtime Key Vault signing path passed a live sign/verify smoke test.

## Identity State

PatchForge dedicated Entra app registrations exist in tenant `67f8be6c-07da-4a7c-bb0a-d6bcb38cd6da`:

- API app ID: `ec30b0eb-cfc4-48cc-a5f2-2a1345d96736`
- UI app ID: `c4dfca53-14a5-4688-817d-6c6c7dd47407`

App roles are present for reader, triage analyst, security lead, service owner, CAB approver, risk owner, admin, and auditor.

The requested users `n.bailey@diiac.io` and `nbailey@diiac.io` were checked against all DIIaC admin groups discovered in the tenant and were already present.

## Database State

PostgreSQL is live:

- Server: `psql-diiac-patchforge-prod.postgres.database.azure.com`
- Database: `patchforge_prod`
- Version: PostgreSQL 16
- State: Ready

The bridge is deployed with PostgreSQL storage enabled and retrieves the existing PostgreSQL password secret from Key Vault by managed identity.

## DNS State

`patchforge.diiac.io` and `api.patchforge.diiac.io` are live and bound to Azure Container Apps with managed certificates.

Live custom-domain endpoints:

- UI: `https://patchforge.diiac.io/`
- API health: `https://api.patchforge.diiac.io/health`
- API readiness: `https://api.patchforge.diiac.io/readiness`

## API Security State

Protected PatchForge API routes require Microsoft Entra bearer tokens when `PATCHFORGE_AUTH_REQUIRED=true`.

Unauthenticated protected API requests return 401 with the required PatchForge roles. The public health and readiness endpoints remain available for platform monitoring.
