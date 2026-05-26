# PatchForge Master Working Brief

## Executive Judgement

DIIaC™ PatchForge should be built as a dedicated product and add-on to DIIaC™ IT Enterprise / IT Services, not as another feature tab inside the existing IT Services build.

The DIIaC IT Services build is mature enough to support PatchForge as a sibling/add-on product. PatchForge's commercial wedge is strong because AI and automated tooling are accelerating vulnerability discovery, while organisations still need governed decisions about what to do next: patch, mitigate, defer, risk accept, block go-live, or escalate to emergency change.

PatchForge should own the missing layer: governed, evidence-bound, human-reviewable patch and protection decisions for IT and OT assets.

## Agent-Led Human-Approved Direction

PatchForge should minimise manual human input. MCP agents, SRA, Mythos, scanner connectors, advisory feeds, and other AGI-agent sources should perform research, correlation, contradiction detection, source mapping, and draft decision-context work wherever possible.

The human role is accountable review and approval: accept or reject sources, confirm service impact, own risk rationale, approve CAB/security decisions, and sign off final posture.

Agent findings are source-bound advisory inputs. They can prioritise and enrich decisions, but they cannot close hard evidence gates alone, accept risk, approve CAB decisions, deploy patches, mutate production systems, or claim source truth without review.

## Product Identity

Product name: DIIaC™ PatchForge

Product line: dedicated DIIaC™ add-on for vulnerability, patch, protection, and remediation governance.

Public description:

DIIaC™ PatchForge turns vulnerability intelligence, patch signals, exploitability context, asset and service exposure, compensating controls, and human approval into governed, signed patch-decision artefacts.

## What PatchForge Is

PatchForge is:

- a vulnerability and patch governance intelligence layer
- a patch decision-control centre
- a source-bound vulnerability evidence catalogue
- an SRA-assisted research and triage environment
- a CAB, service-owner, and security-lead decision workbench
- a signed patch-governance pack generator
- a proactive protection and exposure-control dashboard
- an add-on to DIIaC™ IT Enterprise / IT Services

## What PatchForge Is Not

PatchForge is not:

- a vulnerability scanner
- an exploit-generation system
- a patch deployment tool
- a SIEM/SOAR replacement
- an ITSM replacement
- a CMDB replacement
- an EDR/XDR replacement
- an OT engineering tool
- an autonomous CAB
- an autonomous risk-acceptance system

This boundary belongs in product docs, UI footer/help surfaces, report templates, decision packs, and admin configuration.

## Dedicated Product Rationale

The existing DIIaC IT Services product is broad across cyber, cloud, supplier, service transition, incident review, public-sector bids, and AI Output Assurance.

PatchForge is focused:

```text
vulnerability -> asset/service impact -> exploitability -> patch feasibility -> decision -> evidence -> approval -> outcome feedback
```

That focus justifies:

- dedicated URL: `patchforge.diiac.io`
- dedicated repo: `neil9bailey/diiac-patchforge`
- dedicated Azure resources
- dedicated UI
- dedicated admin centre
- dedicated policy packs
- dedicated evidence models
- dedicated SRA agent
- optional integration with DIIaC™ IT Services

## Strategic Value

For MSPs, PatchForge supports managed patch-governance services, customer-facing monthly assurance packs, audit-ready patch evidence, controlled emergency patch governance, better public-sector bids, and service-transition readiness for customer-facing systems.

For enterprise IT, PatchForge helps reduce patch-decision delay, prioritise based on business service impact, align remediation with CAB and governance expectations, preserve evidence for applied/deferred/mitigated/risk-accepted decisions, identify overdue risk acceptances, and connect security urgency to service-operational reality.

For OT and critical infrastructure, PatchForge can bridge cyber urgency with safety impact, maintenance windows, vendor support, unsupported systems, operational continuity, site constraints, compensating controls, rollback limitations, and incident response posture.

## Architecture Direction

PatchForge should be:

- Azure-hosted
- infrastructure-as-code governed
- Entra ID protected
- tenant-aware
- signed-pack enabled
- evidence-ledger driven
- containerised
- independently deployable
- integrable with DIIaC IT Services
- secure by default
- audit-ready

Initial Azure resource direction:

- resource group: `rg-diiac-patchforge-prod`
- ACR: `acrdiiacpatchforgeprod`
- Container Apps environment: `acae-diiac-patchforge-prod`
- Log Analytics: `law-diiac-patchforge-prod`
- storage account: `stdiiacpatchforgeprod01`
- Key Vault: `kv-diiac-patchforge-prod`
- managed identity: `id-diiac-patchforge-prod`
- database: `patchforge_prod` on PostgreSQL Flexible Server or Azure SQL

Container Apps:

- `ca-patchforge-ui-prod`
- `ca-patchforge-bridge-prod`
- `ca-patchforge-runtime-prod`
- `ca-patchforge-sra-prod`
- `ca-patchforge-worker-prod`
- `ca-patchforge-scheduler-prod`

Ingress posture:

- UI public ingress
- bridge/API public or private by parameter and protected by Entra/RBAC
- runtime internal only
- SRA and worker endpoints internal only

Future hardening:

- Front Door + WAF
- private endpoints
- VNET integrated Container Apps environment
- private database access
- private storage endpoints

## UI Direction

PatchForge should feel like a security operations and governance command centre, while still belonging to the DIIaC design language.

Design qualities:

- dark enterprise command-centre shell
- clear vulnerability queue
- restrained red/amber/green status language
- current decision state always visible
- evidence gaps prominent
- human approval state prominent
- SRA output clearly advisory
- no exploit-oriented language
- no autonomous patching language
- clean board/CAB export actions

Top-level navigation:

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

## Core Governance Rules

- Scanner output starts source-bound and is not accepted truth by default.
- SRA output starts pending review and advisory only.
- Rejected sources cannot be used as positive evidence.
- Final approval is false by default.
- Risk acceptance requires owner, expiry, and rationale.
- OT patch governance requires safety, maintenance-window, and vendor-support evidence.
- Signed source packs are immutable.
- Current state is event-ledger driven and separate from source state.
- Patch close requires validation evidence.
- No autonomous approval.

## First MVP

The first MVP should include PF-E0 through PF-E6:

- PatchForge shell
- vulnerability queue
- manual vulnerability ingest
- affected asset and service records
- deterministic patch governance decision
- signed patch pack
- basic admin
- no seeded or synthetic product data

The MVP excludes live scanner ingestion and SRA automation.

## Operational Rule For This Repo

Always keep local and remote synced after completed milestones. Do not deploy Azure resources until explicitly instructed. When Azure access or DNS changes become necessary, notify the user with the exact resource or record required.
