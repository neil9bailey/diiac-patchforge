# PatchForge Epic Backlog

## PF-E0: Repository Bootstrap

Status: complete

Purpose: create the dedicated PatchForge repository and baseline.

Acceptance:

- repository skeleton exists
- product boundary is clear
- no deployment performed
- no exploit or patch-deployment capability created

## PF-E1: Product Identity And Architecture

Status: complete

Purpose: define PatchForge as a dedicated product/add-on with controlled claims, clear boundaries, architecture, security model, and implementation backlog.

Acceptance:

- product docs exist
- boundary is clear and repeated
- no certification or autonomous patching claims
- architecture is dedicated to PatchForge

## PF-E2: Azure IaC Baseline

Status: complete

Purpose: create dedicated Azure infrastructure-as-code for PatchForge without deployment.

Deliverables:

- Bicep modules
- production parameter placeholders
- validation script
- deployment planning script
- image build/push planning script

Rules:

- no live Azure deployment
- no secrets in templates
- use managed identities
- runtime and SRA internal only

## PF-E3: Schemas And Evidence Models

Status: complete

Purpose: define PatchForge domain schemas and evidence models.

Deliverables:

- vulnerability and source schemas
- affected asset/service schemas
- exploitability, patch availability, feasibility, controls, change readiness, risk acceptance schemas
- SRA manifest and trace schemas
- decision pack manifest schema
- evidence models
- schema tests

## PF-E4: Backend API And Storage

Status: complete

Purpose: add tenant-isolated Patch Intelligence storage and API foundations.

Deliverables:

- health/readiness endpoints
- vulnerability ingest/list/detail/review APIs
- asset/service ingest/list APIs
- service exposure API
- dashboard metrics API
- local JSON storage abstraction
- API tests

Rules:

- source-bound by default
- review state defaults pending
- rejected evidence excluded from positive evidence
- no exploit or patch deployment endpoints

## PF-E5: Runtime Governance And Signed Packs

Status: complete

Purpose: add deterministic governance runtime and signed decision packs.

Deliverables:

- governance runtime
- evidence register
- policy/evidence model evaluation
- readiness calculation
- pack builder
- local verifier
- pack artefact tests

Rules:

- final approval false unless explicit approval exists
- no deployment action
- no exploit content
- source pack immutable

## PF-E6: Dedicated Frontend Shell

Status: complete

Purpose: build the enterprise PatchForge UI shell.

Deliverables:

- React/Vite frontend
- command centre
- vulnerability queue
- asset/service exposure
- decision workbench
- emergency patch
- risk acceptances
- controls
- SRA research
- evidence catalogue
- decision packs
- admin route
- tests and build

## PF-E7: Full Admin UI

Status: complete

Purpose: add enterprise-grade configuration surfaces.

Deliverables:

- general settings
- tenant configuration
- Entra ID/RBAC
- SRA configuration
- KRA/DIIaC IT integration
- scanner integrations
- source feeds
- evidence models
- policy packs
- decision state rules
- risk acceptance rules
- SLA/ageing rules
- signing and trust
- Key Vault, storage, database, telemetry
- health checks, audit logs, export settings, backup/restore, retention, feature flags

Rules:

- dangerous actions require confirmation
- no live Azure mutation in this phase
- secrets masked
- health checks read-only

## PF-E8: SRA MCP Advisory Layer

Status: complete

Purpose: add advisory Security Research Agent and MCP/agent-intelligence tooling inside governance controls.

Deliverables:

- SRA service
- advisory research functions
- source-bound outputs
- MCP, Mythos, and AGI-agent finding intake
- provenance and hashes
- SRA APIs
- tests

Rules:

- advisory only
- pending review
- no exploit instructions
- no deployment action
- cannot close hard gates alone
- cannot risk accept
- human review and approval remains mandatory

## PF-E9: Decision Workbench And DCC

Status: complete

Purpose: add decision creation, compile, approvals, evidence resolution, risk acceptance, and current-state overlay.

Deliverables:

- decision workbench flows
- evidence checklist
- deterministic compile
- signed pack export
- DCC event ledger
- risk acceptance expiry
- post-patch validation

Rules:

- signed source pack immutable
- current state event-ledger driven
- source and current state separated
- no autonomous approval

## PF-E10: Reports and Validation Pack

Status: complete

Purpose: add buyer-grade reports, demo runbooks, validation documents, and demo evidence.

Deliverables:

- CAB Patch Decision Report
- Board Vulnerability Remediation Summary
- Customer Patch Governance Pack
- Risk Acceptance Report
- OT Patch Deferral Report
- real-data customer demonstration runbook
- validation plan
- readiness summary

Rules:

- no exploit instructions
- no autonomous patch approval
- signed pack verifies
- no seeded or synthetic product data is shipped

## PF-E11: Deployment Readiness And CI/CD Hardening

Status: complete

Purpose: prepare PatchForge for controlled deployment without creating or mutating Azure resources.

Deliverables:

- GitHub Actions CI
- Dockerfiles for frontend, backend/API, and runtime
- local dev orchestration
- Azure access checklist
- DNS cutover checklist
- Entra RBAC checklist
- signing strategy
- rollout plan

Rules:

- no live Azure deployment
- no DNS changes
- no secrets in repository
- Azure what-if only after tenant and subscription confirmation
