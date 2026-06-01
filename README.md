# DIIaC™ PatchForge

DIIaC™ PatchForge is a dedicated vulnerability, patch, protection, and remediation governance product for DIIaC™ IT Enterprise / IT Services.

PatchForge turns vulnerability intelligence, patch signals, exploitability context, affected asset and service exposure, compensating controls, and human approval into governed, signed patch-decision artefacts.

## Purpose

PatchForge is the decision-control layer between vulnerability discovery and remediation action. It helps service owners, security leads, CAB participants, MSPs, and enterprise governance teams decide whether to patch, mitigate, defer, risk accept, block go-live, or close verified based on evidence-bound records.

## Product Boundary

PatchForge is not:

- a vulnerability scanner
- an exploit-generation system
- a patch deployment tool
- a SIEM or SOAR replacement
- an ITSM replacement
- a CMDB replacement
- an EDR or XDR replacement
- an OT engineering tool
- an autonomous CAB
- an autonomous risk-acceptance system

PatchForge does not scan environments, exploit vulnerabilities, deploy patches, mutate production systems, or autonomously approve risk. All SRA-style research output is advisory, source-bound, and subject to human review before it can support a governed decision.

## Target Hosting

- Primary URL: `https://patchforge.diiac.io`
- Optional API URL: `https://api.patchforge.diiac.io`
- Identity: `diiac.io` Microsoft Entra ID tenant
- Hosting model: Azure Container Apps
- Trust services: Azure Key Vault, managed identities, signed decision packs
- State services: PostgreSQL or Azure SQL, Azure Storage
- Governance: infrastructure as code, evidence ledger, audit logs, policy packs, replayable signed exports

## Current Product Scope

This repository now contains the PF-AZ11-CUSTOMER-DEMO-MATURITY production product line for PatchForge:

- product identity
- product boundary
- implementation programme and release control
- Azure Container Apps infrastructure as code
- Entra-protected backend API
- PostgreSQL-backed tenant storage
- deterministic runtime governance and signed decision packs
- Azure Key Vault production signing path
- Microsoft Entra sign-in and token-backed frontend API use
- Security Action Center for source-bound CVEs, vendor advisories, KEV/EPSS signals, customer match counts, and governance posture
- Customer Operational Assets for customer devices/assets, services, config evidence, exposure matches, and Patch Compare
- Ask PatchForge advisory workflow for vendor, device, feature, patch, and evidence questions
- Reports consolidation for customer, board, CAB, technical appendix, signed pack, and verification outputs
- deterministic search index across vulnerabilities, vendor advisories, vendor profiles, customer assets, applicability assessments, and source-feed records
- vendor intelligence and config-aware patch advisor capabilities surfaced inside the simplified workflows
- customer network asset, model, firmware, feature, and exposure evidence records
- Ask PatchForge advisory chat with human accountability
- source-bound SRA and agent finding intake
- simplified Security Action Center, Vendors & Exploits Register, Customer Operational Assets, Patch / Hotfix Compare, Ask PatchForge, Reports, and Admin navigation
- human-readable finding intelligence API
- decision-grade DOCX/PDF board and CAB reports
- signed-pack finding intelligence snapshots
- board-grade validation evidence
- an operational user guide for day-to-day security, service-owner, CAB, and customer-assurance use

No scanner, exploit, or patch-deployment capability is created. PatchForge remains a governance and assurance product only.

## Operational User Guide

Start with [PatchForge Operational User Guide](docs/operations/PATCHFORGE_OPERATIONAL_USER_GUIDE.md) when helping end users understand how to use PatchForge correctly in day-to-day operations. It covers the Security Action Center, Vendors & Exploits Register, Customer Operational Assets, Patch / Hotfix Compare, Ask PatchForge, Reports, evidence discipline, human approval boundaries, and credibility checks before customer or board reporting.

## Canonical Rebuild Blueprint

The catalogue-first rebuild is governed by the [PatchForge Intelligence Rebuild Blueprint](docs/product/PATCHFORGE_INTELLIGENCE_REBUILD_BLUEPRINT.md). Implementation work after PF0 must remain aligned to this blueprint: Security Action Center first, Vendors & Exploits Register next, Customer Operational Assets, Patch / Hotfix Compare, Ask PatchForge, user-driven Reports, and Admin as System & Data Health.

## Local Validation

```powershell
python -m pytest -q --basetemp .pytest_tmp
npm test
npm --prefix Frontend test
npm --prefix Frontend run build
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/validate_iac.ps1
```

## Local Run

Without Docker:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/start_local_dev.ps1
```

With Docker:

```powershell
docker compose up --build
```

Local URLs:

- Frontend: `http://127.0.0.1:5173`
- API: `http://127.0.0.1:8080`
- Runtime health, Docker Compose: `http://127.0.0.1:8081/health`

## Deployment Gate

Azure deployment uses the dedicated `rg-diiac-patchforge-prod` resource group in the `diiac.io` tenant. Run a plan/what-if before applying changes, preserve custom domains and managed certificates, and do not disable `PATCHFORGE_AUTH_REQUIRED` in production.

## Repository Layout

```text
patchforge/
├── README.md
├── CURRENT_RELEASE.md
├── DOCUMENT_CONTROL.md
├── RELEASE_BASELINE_MANIFEST.json
├── docs/
├── contracts/
├── backend-api/
├── runtime/
├── Frontend/
├── infra/
├── scripts/
├── tests/
├── customer-config/
└── artifacts/
```

## Remote

```text
neil9bailey/diiac-patchforge
```
