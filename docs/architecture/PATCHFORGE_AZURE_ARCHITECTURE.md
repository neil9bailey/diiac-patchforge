# PatchForge Azure Architecture

## Objective

Host DIIaC™ PatchForge on dedicated Azure resources with infrastructure-as-code governance, Entra ID protection, managed identities, signed-pack support, durable evidence storage, and independent deployability.

## Microsoft Reference Basis

This architecture is aligned with Microsoft guidance for Azure Container Apps security, managed identities, Key Vault references, Entra authentication, and Azure RBAC:

- Azure Container Apps security overview: `https://learn.microsoft.com/azure/container-apps/security`
- Managed identities in Azure Container Apps: `https://learn.microsoft.com/azure/container-apps/managed-identity`
- Manage secrets in Azure Container Apps: `https://learn.microsoft.com/azure/container-apps/manage-secrets`
- Secure Azure Container Apps deployments: `https://learn.microsoft.com/azure/container-apps/secure-deployment`

## Resource Blueprint

### Resource Groups

Initial production build:

- `rg-diiac-patchforge-prod`

Future separation:

- `rg-diiac-patchforge-prod`
- `rg-diiac-patchforge-nonprod`
- `rg-diiac-shared-identity`
- `rg-diiac-shared-monitoring`

### DNS

- `patchforge.diiac.io` -> frontend
- `api.patchforge.diiac.io` -> bridge/API, optional
- `admin.patchforge.diiac.io` -> optional admin host or route

DNS records must not be changed without explicit user coordination.

### Container Registry

- `acrdiiacpatchforgeprod`

Images:

- `diiac/patchforge-frontend`
- `diiac/patchforge-bridge`
- `diiac/patchforge-runtime`
- `diiac/patchforge-sra-agent`
- `diiac/patchforge-ingest-worker`
- `diiac/patchforge-scheduler`

### Container Apps Environment

- environment: `acae-diiac-patchforge-prod`
- Log Analytics: `law-diiac-patchforge-prod`

Container apps:

- `ca-patchforge-ui-prod`
- `ca-patchforge-bridge-prod`
- `ca-patchforge-runtime-prod`
- `ca-patchforge-sra-prod`
- `ca-patchforge-worker-prod`
- `ca-patchforge-scheduler-prod`

### Storage

Storage account:

- `stdiiacpatchforgeprod01`

Containers:

- `raw-vulnerability-sources`
- `sra-traces`
- `evidence-artifacts`
- `decision-packs`
- `signed-exports`
- `replay-certificates`
- `audit-slices`
- `logs-slices`
- `import-batches`

### Database

Recommended production database:

- Azure Database for PostgreSQL Flexible Server
- database: `patchforge_prod`

Azure SQL remains an acceptable Microsoft-native alternative.

### Key Vault

Key Vault:

- `kv-diiac-patchforge-prod`

Stores:

- signing key references
- scanner integration secrets
- SRA provider credentials
- storage fallback secrets
- database connection references
- webhook signing secrets
- export signing metadata

No secrets should be committed to this repository.

### Managed Identities

Use user-assigned managed identities where pre-authorisation or sharing is useful:

- `id-patchforge-ui-prod`
- `id-patchforge-bridge-prod`
- `id-patchforge-runtime-prod`
- `id-patchforge-sra-prod`
- `id-patchforge-worker-prod`

Least privilege access:

| Identity | Access |
| --- | --- |
| UI | No direct Key Vault or database access. |
| Bridge | Database read/write, limited storage, Key Vault secret read where required. |
| Runtime | Signing key access, pack storage, database read/write. |
| SRA | SRA config and source storage, no signing key unless separately justified. |
| Workers | Queue, storage, and database access by job scope. |

## Network and Ingress Model

Initial production-grade model:

- public UI ingress
- bridge/API ingress protected by Entra/RBAC
- internal runtime ingress
- internal SRA and worker endpoints
- storage and database restricted through identity and network controls where feasible

Future hardened model:

- Azure Front Door and WAF
- VNET-integrated Container Apps environment
- private endpoints
- private database access
- private storage endpoints

## Deployment Gate

PF-E2 creates IaC only. Do not run live Azure deployments until the user confirms:

- Azure tenant and subscription
- target region
- DNS ownership and record plan
- Key Vault and signing strategy
- production vs non-production environment sequence

