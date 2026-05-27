# Current Release

## DIIaC PatchForge PF-AZ8

Release state: PF-AZ8 is deployed to Azure and live validated through the production UI/API as a signed-in PatchForge Admin user.

Date: 2026-05-27

PF-AZ8 adds a guided intelligence workflow and decision-grade DOCX/PDF reports that respond to customer-demo feedback.

PF-AZ8 image tag:

- `pfaz8-20260527-cc708fd`

PF-AZ8 commit:

- `cc708fd`

PF-AZ8 evidence path:

- `docs/release/evidence/2026-05-27-patchforge-pfaz8-guided-intelligence-workflow/`

PF-AZ8 adds:

- Action Center, Finding Detail, Review & Approve, and Reports & Packs workflow
- human-readable finding intelligence API
- autonomous analysis summary with human approval still required
- exploitability intelligence without exploit code or procedural steps
- decision options matrix and evidence gaps in the UI and reports
- signed-pack artefact support for `finding_intelligence_snapshot.json`
- improved DOCX/PDF board and CAB reports with Word-rendered visual QA

PF-AZ8 does not add seeded demo data, synthetic vulnerability data, scanning, exploit generation, procedural exploit steps, patch deployment, production mutation from the UI, autonomous CAB approval, or autonomous risk acceptance.

## DIIaC PatchForge PF-AZ7

Release state: PF-AZ7 was the previous live operational customer-demo baseline.

Date: 2026-05-27

PF-AZ8 is now the currently deployed Azure baseline.

## PF-AZ7 Operational Demo Increment

Date: 2026-05-27

PF-AZ7 is deployed and live validated.

PF-AZ7 adds:

- professional DOCX/PDF board and governance report generation from signed decision packs
- protected report catalogue and report download APIs
- UI Reports page and Decision Pack DOCX/PDF export actions
- scheduler-backed live CISA KEV and FIRST EPSS refresh
- scheduler source lineage, advisory-only controls, and no scanner/no deployment boundaries
- local Word-rendered DOCX visual QA evidence for customer-facing board-pack formatting

PF-AZ7 does not add seeded demo data, synthetic vulnerability data, scanning, exploit generation, procedural exploit steps, patch deployment, production mutation from the UI, autonomous CAB approval, or autonomous risk acceptance.

PF-AZ7 live evidence path:

- `docs/release/evidence/2026-05-27-patchforge-pfaz7-operational-demo/`

## Scope

PF-AZ7 extends the current dedicated PatchForge Azure production state in the DIIaC tenant using the PatchForge resource group.

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
- live public source intelligence feed API for CISA Known Exploited Vulnerabilities
- live public source intelligence feed API for FIRST EPSS enrichment
- source-feed run ledger with source-bound, pending-review, advisory-only controls
- source-feed schemas for feed manifests and feed runs
- source-feed UI page bound to live protected API calls
- Command Center and utility rail source-feed status
- backend and frontend tests for public source intelligence
- protected DOCX/PDF report catalogue and download APIs
- professional DOCX/PDF board reports generated from signed decision packs
- Reports page and Decision Pack DOCX/PDF export actions
- scheduler-backed live CISA KEV and FIRST EPSS refresh
- live PF-AZ7 signed pack `PF-20260527-54588be9`
- live DOCX/PDF visual QA evidence for board-grade output

Excluded:

- seeded demo data
- synthetic vulnerability data
- vulnerability scanning
- exploit generation
- patch deployment
- SIEM, SOAR, ITSM, CMDB, EDR, XDR, or OT engineering replacement functionality
- unreviewed AI or agent source truth claims

PF-AZ5 Azure deployment, image tag, active revisions, and live browser validation evidence are recorded under `docs/release/evidence/2026-05-26-patchforge-pfaz5-intelligence-rollout/`.

PF-AZ6 Azure rollout and live browser validation evidence is recorded under `docs/release/evidence/2026-05-26-patchforge-pfaz6-live-source-intelligence/`.

PF-AZ7 Azure rollout, scheduler validation, live browser validation, fresh signed pack verification, and DOCX/PDF visual QA evidence is recorded under `docs/release/evidence/2026-05-27-patchforge-pfaz7-operational-demo/`.

PF-AZ8 Azure rollout, guided workflow validation, signed-in browser validation, signed pack verification, DOCX/PDF live protected report checks, Key Vault signing smoke, and PostgreSQL readiness evidence is recorded under `docs/release/evidence/2026-05-27-patchforge-pfaz8-guided-intelligence-workflow/`.

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

Latest deployment performed on 2026-05-27.

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
- `docs/release/evidence/2026-05-26-patchforge-pfaz5-intelligence-rollout/`
- `docs/release/evidence/2026-05-26-patchforge-pfaz6-live-source-intelligence/`
- `docs/release/evidence/2026-05-27-patchforge-pfaz7-operational-demo/`
- `docs/release/evidence/2026-05-27-patchforge-pfaz8-guided-intelligence-workflow/`

Latest PF-AZ8 guided intelligence revisions:

- UI: `ca-patchforge-ui-prod--0000010`
- Bridge/API: `ca-patchforge-bridge-prod--0000009`
- Runtime: `ca-patchforge-runtime-prod--0000008`
- SRA: `ca-patchforge-sra-prod--0000007`
- Worker: `ca-patchforge-worker-prod--0000007`
- Scheduler: `ca-patchforge-scheduler-prod--0000007`
- Image tag: `pfaz8-20260527-cc708fd`

## PF-AZ8 Live Validation

Live UI validation result: PASS

Live API validation result: PASS

Validated user workflow:

- signed in at `https://patchforge.diiac.io` as `n.bailey@diiac.io`
- confirmed displayed role `PatchForge.Admin`
- confirmed live API readiness with PostgreSQL storage and Entra auth required
- confirmed protected API routes return 401 without a bearer token
- loaded the simplified Action Center from live protected APIs
- opened Finding Detail for `CVE-2026-48172` and confirmed plain-English vulnerability explanation, affected scope, exploitability intelligence, and decision options
- confirmed exploit code, exploit payloads, and procedural exploitation steps are not provided
- opened Review & Approve and confirmed autonomous analysis completed while human approval remained required
- ran SRA advisory and confirmed advisory-only output
- generated fresh signed pack `PF-20260527-9fc7f010`
- verified the exported pack reports `verified=true`, `manifest_ok=true`, `signature_ok=true`, `signing_provider=azure_key_vault`, and `final_approval_issued=false`
- confirmed the signed pack includes `finding_intelligence_snapshot.json`, Bayesian, SRA, vendor, and threat-landscape artefacts
- generated live protected DOCX and PDF reports from the signed pack
- opened Admin and confirmed database, storage, Key Vault, signing trust, bridge, runtime, and frontend health
- opened the Guide page for the minimal-input, agent-led workflow

Live evidence path:

- `docs/release/evidence/2026-05-27-patchforge-pfaz8-guided-intelligence-workflow/live-ui/`

## PF-AZ7 Live Validation

Live UI validation result: PASS

Live API validation result: PASS

Validated user workflow:

- signed in at `https://patchforge.diiac.io` as `n.bailey@diiac.io`
- confirmed displayed role `PatchForge.Admin`
- confirmed live API readiness with PostgreSQL storage and Entra auth required
- confirmed protected API routes return 401 without a bearer token
- navigated all main product pages including Reports and Vendor & Threat Landscape
- confirmed scheduler-backed CISA KEV/FIRST EPSS refresh completed as `patchforge-scheduler@diiac.io`
- ran SRA advisory for real public-source record `CVE-2026-48172`
- confirmed SRA output is advisory-only, source-bound, pending review, and cannot close hard gates
- ran Bayesian advisory for `CVE-2026-48172`
- generated fresh signed pack `PF-20260527-54588be9`
- verified the exported pack reports `verified=true`, `manifest_ok=true`, `signature_ok=true`, `signing_provider=azure_key_vault`, and `source_pack_immutable=true`
- confirmed `final_approval_issued=false`
- downloaded live DOCX and PDF board reports from the UI/API
- rendered and inspected the live DOCX and PDF outputs with no clipping, overlap, broken tables, missing text, or unreadable wrapping observed

Live evidence path:

- `docs/release/evidence/2026-05-27-patchforge-pfaz7-operational-demo/live-ui/`

## PF-AZ6 Live Validation

Live UI validation result: PASS

Live API validation result: PASS

Validated user workflow:

- signed in at `https://patchforge.diiac.io` as `n.bailey@diiac.io`
- confirmed displayed role `PatchForge.Admin`
- refreshed the live CISA Known Exploited Vulnerabilities public feed
- ingested five real CISA KEV records as source-bound pending-review intelligence
- confirmed real CVEs including `CVE-2026-48172` appeared in Vulnerability Queue
- refreshed FIRST EPSS for `CVE-2026-48172`
- confirmed FIRST EPSS enrichment remained source-bound and unable to close hard gates alone
- ran Bayesian Patch Risk advisory on `CVE-2026-48172`
- generated signed pack `PF-20260526-8312f908`
- verified the exported pack reports `verified=true`, `signing_provider=azure_key_vault`, and `source_pack_immutable=true`
- confirmed `final_approval_issued=false`
- removed the earlier PF-AZ5 synthetic validation record `CVE-2026-PF-DEMO-001`, its linked source records, signed pack, and audit references from production PostgreSQL
- confirmed no production record still references `CVE-2026-PF-DEMO-001`
- confirmed the temporary PostgreSQL firewall rule used for cleanup was deleted

Live evidence path:

- `docs/release/evidence/2026-05-26-patchforge-pfaz6-live-source-intelligence/live-ui/`

## PF-AZ5 Live Validation

Live UI validation result: PASS

Live API validation result: PASS

Validated user workflow:

- signed in at `https://patchforge.diiac.io` as `n.bailey@diiac.io`
- confirmed displayed role `PatchForge.Admin`
- ingested `CVE-2026-PF-DEMO-001` through the deployed UI
- confirmed the Vulnerability Queue rendered the live record as Critical, known exploited, internet exposed, Orion Gateway, and patch available
- ran SRA exploit-risk advisory and confirmed advisory-only/source-bound state
- ran Bayesian Patch Risk advisory and confirmed it cannot close hard gates or approve risk
- generated and exported signed pack `PF-20260526-e90d3a02`
- verified the exported pack reports `verified=true`, `manifest_ok=true`, and `signature_ok=true`
- confirmed `final_approval_issued=false` with readiness blocked pending evidence/human gates

Live evidence path:

- `docs/release/evidence/2026-05-26-patchforge-pfaz5-intelligence-rollout/live-ui/`

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
