# Codex Working Memory: DIIaC™ PatchForge

This file is the persistent local working memory for the PatchForge build. Use it with the product docs and epic tracker before making implementation decisions.

## Mission

Build DIIaC™ PatchForge as a dedicated product and add-on to DIIaC™ IT Enterprise / IT Services.

PatchForge owns the missing governance layer between vulnerability discovery and action:

```text
vulnerability intelligence -> asset/service impact -> exploitability -> patch feasibility -> governed decision -> evidence -> approval -> outcome feedback
```

Core message:

```text
AI-speed vulnerability discovery needs governance-speed remediation control.
PatchForge delivers the signed, evidence-bound decision layer between discovery and action.
```

## Product Boundary

PatchForge is not a scanner, exploit-generation system, patch-deployment tool, SIEM/SOAR replacement, ITSM replacement, CMDB replacement, EDR/XDR replacement, OT engineering tool, autonomous CAB, or autonomous risk-acceptance system.

Do not create:

- exploit instructions
- exploit generation
- patch deployment
- production mutation
- autonomous CAB approval
- autonomous risk acceptance
- claims that PatchForge certifies safety, security, or compliance by itself

SRA output is advisory only, source-bound, pending review by default, and unable to close hard gates alone.

## Product Shape

- Product: DIIaC™ PatchForge
- Target URL: `https://patchforge.diiac.io`
- Optional API URL: `https://api.patchforge.diiac.io`
- Remote repo: `neil9bailey/diiac-patchforge`
- Local repo: `F:\code\diiac\patchforge`
- Hosting direction: Azure Container Apps, Key Vault, Storage, PostgreSQL or Azure SQL, managed identities, Entra ID app roles, Log Analytics / Azure Monitor

PatchForge is a dedicated product shell, not a tab inside the current IT Services app. It may share DIIaC governance patterns: signed packs, Merkle-style integrity, replay, trust registry, Entra RBAC, evidence states, and Decision Control Center patterns.

## Sync Discipline

Keep local and remote in sync:

1. Pull with `git pull --ff-only` before starting a new epic or major change.
2. Commit each completed epic or coherent milestone.
3. Push to `origin/main` after each commit.
4. Keep `git status --short --branch` clean before final handoff unless a deliberate in-progress state is reported.

## Azure and DNS Gates

Do not deploy Azure resources without explicit user instruction.

Tell the user before:

- Azure authentication or subscription access is required
- Azure resource creation or mutation is needed
- Key Vault, managed identity, database, storage, or Container Apps access must be granted
- DNS records need to be changed for `patchforge.diiac.io`, `api.patchforge.diiac.io`, or any admin host

IaC and deployment planning files can be created locally without Azure access.

## Build Order

Build the governance cage first:

1. PF-E0 repository bootstrap
2. PF-E1 product identity and architecture
3. PF-E2 Azure IaC baseline
4. PF-E3 schemas and evidence models
5. PF-E4 backend API and storage
6. PF-E5 runtime governance and signed packs
7. PF-E6 dedicated frontend shell
8. PF-E7 admin UI
9. PF-E8 SRA advisory layer
10. PF-E9 Decision Workbench and DCC
11. PF-E10 reports, demos, validation pack

Do not build SRA first. SRA must live inside the governance boundary.

