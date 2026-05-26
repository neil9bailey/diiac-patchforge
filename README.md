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

## Initial Repository Scope

This repository starts with the PF-E0 baseline only:

- product identity
- product boundary
- implementation programme
- release control placeholders
- skeleton directories for backend, runtime, frontend, contracts, infrastructure, scripts, tests, customer configuration, and artefacts

No Azure resources are deployed by this baseline. No scanner, exploit, or patch-deployment capability is created.

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

## Remote Target

Planned GitHub repository:

```text
neil9bailey/diiac-patchforge
```
