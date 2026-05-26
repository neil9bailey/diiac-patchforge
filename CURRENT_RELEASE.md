# Current Release

## DIIaC™ PatchForge PF-E11

Release state: deployment readiness and CI/CD hardening complete

Date: 2026-05-26

## Scope

PF-E11 prepares PatchForge for controlled deployment through CI, containerization, local orchestration, and deployment readiness documentation.

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

Excluded:

- Azure deployment
- live cloud resource creation
- vulnerability scanning
- exploit generation
- patch deployment
- SIEM, SOAR, ITSM, CMDB, EDR, XDR, or OT engineering replacement functionality

## Runtime State

No runtime services exist in this baseline.

## Deployment State

No deployment has been performed.

## Trust State

Signed pack generation is implemented locally with a development/test signature path. Production signing trust is planned for Azure Key Vault-backed deployment.
