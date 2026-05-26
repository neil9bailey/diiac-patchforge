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

Known non-secret DIIaC tenant reference:

- Domain: `diiac.io`
- Entra tenant ID: `67f8be6c-07da-4a7c-bb0a-d6bcb38cd6da`
- Azure subscription ID: `9ae9da49-de67-443b-af55-ce9db33ed8f4`
- Azure subscription name: `Azure subscription 1`
- Primary region: `uksouth`
- Tenant reference doc: `docs/deployment/PATCHFORGE_DIIAC_TENANT_REFERENCE.md`

PatchForge should keep dedicated resources in the same tenant/subscription unless the user directs otherwise. Do not reuse IT Services resource names, Key Vaults, or app registrations by default.

Azure bootstrap live state as of 2026-05-26:

- Resource group: `rg-diiac-patchforge-prod`
- ACR: `acrdiiacpatchforgeprod.azurecr.io`
- ACA environment: `acae-diiac-patchforge-prod`
- ACA default domain: `lemonpebble-11b2e331.uksouth.azurecontainerapps.io`
- UI URL: `https://ca-patchforge-ui-prod.lemonpebble-11b2e331.uksouth.azurecontainerapps.io/`
- Bridge health URL: `https://ca-patchforge-bridge-prod.lemonpebble-11b2e331.uksouth.azurecontainerapps.io/health`
- Evidence: `docs/release/evidence/2026-05-26-patchforge-azure-bootstrap/`

PatchForge gate state as of 2026-05-26:

- Entra API app: `DIIaC PatchForge API`, app ID `ec30b0eb-cfc4-48cc-a5f2-2a1345d96736`
- Entra UI app: `DIIaC PatchForge UI`, app ID `c4dfca53-14a5-4688-817d-6c6c7dd47407`
- PatchForge API identifier URI: `api://ec30b0eb-cfc4-48cc-a5f2-2a1345d96736`
- Production signing key: `https://kv-diiac-patchforge-prod.vault.azure.net/keys/pf-pack-signing-prod/2e348fdeaaaf448ebba206130ef86b52`
- PostgreSQL server: `psql-diiac-patchforge-prod.postgres.database.azure.com`
- PostgreSQL database: `patchforge_prod`
- Admin membership evidence: `docs/release/evidence/2026-05-26-patchforge-gates/admin-group-membership.json`
- Gate evidence: `docs/release/evidence/2026-05-26-patchforge-gates/`

`n.bailey@diiac.io` and `nbailey@diiac.io` are confirmed as members of all DIIaC admin groups discovered in the tenant:

- `DIIAC-ITServices-Admins`
- `DIIAC-Pharma-Admins`

DNS is live for `patchforge.diiac.io` and `api.patchforge.diiac.io`. The `diiac.io` DNS zone is hosted at Porkbun, not Azure DNS.

Custom-domain live state:

- UI: `https://patchforge.diiac.io/`
- API health: `https://api.patchforge.diiac.io/health`
- API readiness: `https://api.patchforge.diiac.io/readiness`
- UI certificate: `mc-acae-diiac-pat-patchforge-diiac-9158`
- API certificate: `mc-acae-diiac-pat-api-patchforge-d-1628`
- DNS cutover evidence: `docs/release/evidence/2026-05-26-patchforge-dns-cutover/`

Production hardening state as of PF-AZ4 on 2026-05-26:

- Deployed image tag: `pfaz4-20260526`
- Bridge/API storage mode: `postgresql`
- Bridge/API auth mode: `PATCHFORGE_AUTH_REQUIRED=true`
- PostgreSQL password source: existing Key Vault secret `patchforge-postgres-admin-password`
- PostgreSQL firewall rule: `AllowAzureServices` (`0.0.0.0` to `0.0.0.0`) for initial Container Apps connectivity
- Runtime signing mode: Azure Key Vault ES256 supported
- Runtime signing key name: `pf-pack-signing-prod`
- Runtime Key Vault signing smoke: verified true
- Custom domains are now represented in Bicep using existing managed certificate names
- Production hardening evidence: `docs/release/evidence/2026-05-26-patchforge-production-hardening/`

PF-AZ5 direction from the user: no demo data, no seeded data, and no synthetic vulnerability records. Customer demonstrations must run from real operator-supplied tenant records ingested through the protected UI/API.

PF-AZ5 agent-intelligence direction from the user: PatchForge should be agent-led and human-approved. MCP agents, SRA, Mythos, scanners, advisory feeds, and other AGI-agent sources should minimise human typing by researching, correlating, source-mapping, and drafting context. Human users review, approve, reject, own risk, and sign off. Agent findings are source-bound, advisory, pending review, and cannot close hard gates or accept risk alone.

Reference: `docs/architecture/PATCHFORGE_MCP_AGENT_INTELLIGENCE.md`.

PF-AZ5 live state:

- Deployed image tag: `pfaz5-20260526`
- UI is an Entra-protected live workflow, not a static vulnerability queue.
- API CORS allows `https://patchforge.diiac.io`.
- Bridge calls runtime by Container Apps app name: `http://ca-patchforge-runtime-prod`.
- Protected API data requires Entra bearer tokens with PatchForge app roles.
- Live smoke evidence: `docs/release/evidence/2026-05-26-patchforge-live-product/`
- Protected agent-finding intake path: `POST /api/patchforge/agent-findings/ingest`
- Agent source classes: `mcp_agent_finding`, `mythos_finding`, `agi_agent_finding`, `sra_trace`

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
11. PF-E10 reports and validation pack

Do not build SRA first. SRA must live inside the governance boundary. Do not add seed/demo data unless the user explicitly reverses the no-demo-data instruction.
