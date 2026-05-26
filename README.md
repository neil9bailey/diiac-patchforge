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

This repository now contains the PF-AZ5 production-demo product line for PatchForge:

- product identity
- product boundary
- implementation programme and release control
- Azure Container Apps infrastructure as code
- Entra-protected backend API
- PostgreSQL-backed tenant storage
- deterministic runtime governance and signed decision packs
- Azure Key Vault production signing path
- Microsoft Entra sign-in and token-backed frontend API use
- Bayesian patch-risk advisory inference
- vendor and threat landscape intelligence
- source-bound SRA and agent finding intake
- board-grade reports and validation evidence

No scanner, exploit, or patch-deployment capability is created. PatchForge remains a governance and assurance product only.

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
