# PatchForge Implementation Programme

## Programme Objective

Build DIIaC™ PatchForge as a dedicated DIIaC add-on product for governed vulnerability, patch, protection, and remediation decisions.

The programme starts with the governance cage first, then adds automation and advisory research inside that boundary.

## Build Sequence

| Epic | Name | Purpose |
| --- | --- | --- |
| PF-E0 | Repository bootstrap | Create the dedicated PatchForge repo, baseline documents, and skeleton. |
| PF-E1 | Product identity and architecture | Define intended use, claims, boundaries, architecture, and backlog. |
| PF-E2 | Azure IaC baseline | Create dedicated Azure infrastructure-as-code without deployment. |
| PF-E3 | Schemas and evidence models | Define domain schemas and evidence models. |
| PF-E4 | Backend API and storage | Add tenant-isolated Patch Intelligence storage and API foundations. |
| PF-E5 | Runtime governance and signed packs | Add deterministic runtime, evidence scoring, and signed decision packs. |
| PF-E6 | Dedicated frontend shell | Build the enterprise PatchForge command-centre UI. |
| PF-E7 | Full Admin UI | Add enterprise configuration and health surfaces. |
| PF-E8 | SRA MCP advisory agent | Add source-bound advisory research inside the governance boundary. |
| PF-E9 | Decision Workbench and DCC | Add decision compilation, evidence resolution, approvals, and current-state overlay. |
| PF-E10 | Reports, demos, validation pack | Add CAB, board, customer, risk acceptance, OT reports, demos, and validation evidence. |

## First MVP Scope

The first working MVP should include PF-E0 through PF-E6:

- PatchForge shell
- vulnerability queue
- manual vulnerability ingest
- affected asset and service records
- deterministic patch governance decision
- signed patch pack
- basic admin
- demo seed data

The MVP excludes live scanner ingestion, SRA automation, autonomous approval, and patch deployment.

## Core Product Surfaces

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
- Reports
- Admin

## Governance Rules

- Scanner output starts source-bound and is not accepted truth by default.
- SRA output starts pending review and advisory only.
- Rejected sources cannot close positive evidence gates.
- Final approval is false by default.
- Risk acceptance requires owner, expiry, and rationale.
- OT patch governance requires safety, maintenance-window, and vendor-support evidence.
- No exploit-generation, patch-deployment, or production-mutation capability is in scope.

## Azure Direction

PatchForge should be Azure-hosted, infrastructure-as-code governed, Entra ID protected, tenant-aware, signed-pack enabled, evidence-ledger driven, containerised, independently deployable, and integrable with DIIaC™ IT Enterprise / IT Services.

Planned resource families:

- Azure Container Apps
- Azure Container Registry
- Azure Key Vault
- Azure Storage
- PostgreSQL or Azure SQL
- Azure Monitor and Log Analytics
- Managed identities
- Entra ID app roles

## Current Status

PF-E0 baseline is the first repository state. No Azure deployment has been performed.
