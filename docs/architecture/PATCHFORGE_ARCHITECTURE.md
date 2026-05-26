# PatchForge Architecture

## Overview

DIIaC™ PatchForge is a dedicated product architecture for vulnerability, patch, protection, and remediation governance. It is built around source-bound evidence, deterministic governance runtime behaviour, human approval, signed packs, and optional integration with DIIaC™ IT Enterprise / IT Services.

## Logical Architecture

```text
Users
  |
  v
PatchForge Frontend
  |
  v
Bridge/API
  |---------------------\
  v                      v
Runtime Governance       SRA Advisory Service
  |                      |
  v                      v
Evidence + Decision      SRA Traces
State Store              |
  |                      |
  v                      v
Signed Pack Builder <----/
  |
  v
Decision Packs, Reports, Replay Certificates
```

## Components

### Frontend

The frontend provides the dedicated PatchForge UI:

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

### Bridge/API

The Bridge/API owns:

- authentication and role-aware request handling
- tenant scoping
- route orchestration
- vulnerability and asset/service APIs
- admin configuration APIs
- export orchestration
- SRA request mediation
- health and readiness endpoints

### Runtime Governance Service

The runtime owns deterministic governance logic:

- decision classification
- evidence register construction
- evidence model evaluation
- policy pack evaluation
- readiness calculation
- pack manifest construction
- local verification support

The runtime must not deploy patches or mutate production systems.

### SRA Advisory Service

The SRA service is advisory only. It may help research CVEs, summarise advisories, assess exploitability context, map affected assets, suggest compensating controls, and assess OT patch constraints.

SRA output is source-bound, hash-tracked, pending review by default, and unable to close hard evidence gates alone.

### Ingest Worker

The ingest worker handles asynchronous import from scanner exports, vendor advisories, manual uploads, service catalogues, asset inventories, and future integrations.

Imported records remain source-bound until reviewed.

### Scheduler

The scheduler handles:

- refresh jobs
- queue ageing
- SLA clock checks
- risk acceptance expiry checks
- evidence expiry checks
- scheduled report preparation

### Export Worker

The export worker handles large reports, signed exports, board packs, customer assurance packs, replay certificates, and audit slices.

## Data Stores

### Transactional State

Use PostgreSQL or Azure SQL for production state:

- tenants
- users_shadow
- vulnerabilities
- vulnerability_sources
- affected_assets
- affected_services
- exploitability_assessments
- patch_availability
- patch_feasibility
- compensating_controls
- risk_acceptances
- patch_decisions
- decision_events
- sra_calls
- evidence_bindings
- decision_packs
- audit_events
- admin_config

### Object Storage

Use object storage for raw/source artefacts and signed packs:

- raw vulnerability sources
- SRA traces
- evidence artefacts
- decision packs
- signed exports
- replay certificates
- audit slices
- logs slices
- import batches

## Integration Boundaries

PatchForge may integrate with:

- DIIaC™ IT Enterprise / IT Services
- scanners
- ITSM
- CMDB/service catalogue
- SIEM/SOAR
- EDR/XDR
- vendor advisory feeds
- KEV/EPSS style threat signals

Integrations supply evidence and context. They do not make PatchForge a scanner, deployment system, SIEM/SOAR, ITSM, CMDB, EDR/XDR, or OT engineering tool.

