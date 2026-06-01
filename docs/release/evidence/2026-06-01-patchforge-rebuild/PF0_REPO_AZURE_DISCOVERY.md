# PF0 Repo And Azure Discovery

PF0 timestamp: 2026-06-01T02:06:05+01:00

## Repository Identity

- Confirmed local repo path: `F:\code\diiac\patchforge`
- Git top level: `F:/code/diiac/patchforge`
- Current branch at discovery: `main`
- Work branch created after restore point: `codex/patchforge-rebuild-20260601`
- HEAD short SHA at discovery: `a4384cc`
- Authoritative remote from `git remote -v`:
  - fetch: `https://github.com/neil9bailey/diiac-patchforge.git`
  - push: `https://github.com/neil9bailey/diiac-patchforge.git`
- Repo documentation references checked agree with `neil9bailey/diiac-patchforge`.
- No documentation inspected identified `neil9bailey/DIIaC-v1.7.0-Production-Ready-Code-Check-UI` as the authoritative PatchForge remote.
- The repository is not the prohibited Pharma repository.

## Starting Working Tree

`git status --short --branch` before PF0 evidence creation:

```text
## main...origin/main
 M README.md
?? docs/operations/PATCHFORGE_OPERATIONAL_USER_GUIDE.md
```

These changes existed before the rebuild work. They were inspected for context and left intact.

Observed README change:

- Current product scope updated from `PF-AZ10-SIMPLIFIED-EXPERIENCE` to `PF-AZ11-CUSTOMER-DEMO-MATURITY`.
- Operational user guide link added.

Observed untracked file:

- `docs/operations/PATCHFORGE_OPERATIONAL_USER_GUIDE.md`

## Docs Inspected

- `README.md`
- `CURRENT_RELEASE.md`
- `DOCUMENT_CONTROL.md`
- `docs/product/PATCHFORGE_PRODUCT_POSITIONING.md`
- `docs/product/PATCHFORGE_MASTER_WORKING_BRIEF.md`
- `docs/architecture/PATCHFORGE_ARCHITECTURE.md`
- `docs/architecture/PATCHFORGE_AZURE_ARCHITECTURE.md`
- `docs/architecture/PATCHFORGE_SECURITY_MODEL.md`
- `docs/deployment/PATCHFORGE_AZURE_ACCESS_CHECKLIST.md`
- `docs/deployment/PATCHFORGE_DEPLOYMENT_READINESS.md`
- `docs/deployment/PATCHFORGE_DIIAC_TENANT_REFERENCE.md`
- `docs/deployment/PATCHFORGE_DNS_CUTOVER_CHECKLIST.md`
- `docs/deployment/PATCHFORGE_ENTRA_RBAC_CHECKLIST.md`
- `docs/deployment/PATCHFORGE_ROLLOUT_PLAN.md`
- `docs/deployment/PATCHFORGE_SIGNING_STRATEGY.md`
- `docs/release/PF_AZ10_RELEASE_BASELINE_MANIFEST.json`
- `docs/release/PF_AZ10_PRODUCTION_READINESS_SUMMARY.md`
- `package.json`
- `pyproject.toml`
- `Frontend/package.json`

`docs/README.md` and `backend-ui-bridge/package.json` were not present.

## Azure Files Inspected

- `infra/parameters/prod.bicepparam`
- `infra/bicep/main.bicep`
- `infra/bicep/container-apps.bicep`
- `infra/bicep/container-registry.bicep`
- `infra/bicep/identity.bicep`
- `infra/bicep/keyvault.bicep`
- `infra/bicep/monitoring.bicep`
- `infra/bicep/postgres-or-sql.bicep`
- `infra/bicep/storage.bicep`
- `scripts/build_push_images.ps1`
- `scripts/plan_azure_deployment.ps1`
- `scripts/deploy_azure_bootstrap.ps1`
- `scripts/validate_iac.ps1`
- `docs/release/evidence/2026-05-30-patchforge-pfaz10-simplified-experience/`
- `docs/release/evidence/2026-05-27-patchforge-pfaz10-ui-vendorlens-ciso-compare/`
- `docs/release/evidence/2026-05-26-patchforge-production-hardening/`

`live_verification.json` was not present.

## Azure Configuration Summary

- Azure tenant/domain references: `diiac.io`
- Entra tenant ID: `67f8be6c-07da-4a7c-bb0a-d6bcb38cd6da`
- Azure subscription ID: `9ae9da49-de67-443b-af55-ce9db33ed8f4`
- Azure subscription name reference: `Azure subscription 1`
- Region: `uksouth`
- Resource group: `rg-diiac-patchforge-prod`
- Hosting model: Azure Container Apps, with dedicated ACR, Key Vault, Storage, PostgreSQL, Log Analytics, and user-assigned managed identities
- Container Apps environment: `acae-diiac-patchforge-prod`
- ACR: `acrdiiacpatchforgeprod` / `acrdiiacpatchforgeprod.azurecr.io`
- Storage account: `stdiiacpatchforgeprod01`
- Key Vault: `kv-diiac-patchforge-prod`
- PostgreSQL server: `psql-diiac-patchforge-prod.postgres.database.azure.com`
- PostgreSQL database: `patchforge_prod`
- Managed identities:
  - `id-patchforge-ui-prod`
  - `id-patchforge-bridge-prod`
  - `id-patchforge-runtime-prod`
  - `id-patchforge-sra-prod`
  - `id-patchforge-worker-prod`
- Runtime app: `ca-patchforge-runtime-prod`
- Bridge/API app: `ca-patchforge-bridge-prod`
- Frontend app: `ca-patchforge-ui-prod`
- SRA/agent service: `ca-patchforge-sra-prod`
- Worker service: `ca-patchforge-worker-prod`
- Scheduler service: `ca-patchforge-scheduler-prod`
- Bridge runtime URL setting: `http://ca-patchforge-runtime-prod`
- Production auth setting: `PATCHFORGE_AUTH_REQUIRED=true`
- Allowed CORS/custom origin: `https://patchforge.diiac.io`
- Custom domains:
  - UI: `patchforge.diiac.io`
  - API: `api.patchforge.diiac.io`
- Managed certificate references:
  - `mc-acae-diiac-pat-patchforge-diiac-9158`
  - `mc-acae-diiac-pat-api-patchforge-d-1628`
- Key Vault signing key reference: `pf-pack-signing-prod`
- Key Vault signing key ID reference: `https://kv-diiac-patchforge-prod.vault.azure.net/keys/pf-pack-signing-prod`
- PostgreSQL password secret name: `patchforge-postgres-admin-password`
- Latest current release image tag documented in `CURRENT_RELEASE.md`: `pfaz10-20260530-e728ec0`
- PF-AZ10 manifest image tag also present: `pfaz10-20260527-513fea2`
- Latest active revisions documented in `CURRENT_RELEASE.md`:
  - UI: `ca-patchforge-ui-prod--0000021`
  - Bridge/API: `ca-patchforge-bridge-prod--0000020`
  - Runtime: `ca-patchforge-runtime-prod--0000019`
  - SRA: `ca-patchforge-sra-prod--0000018`
  - Worker: `ca-patchforge-worker-prod--0000018`
  - Scheduler: `ca-patchforge-scheduler-prod--0000018`

## Live URLs Discovered

- Public UI custom domain: `https://patchforge.diiac.io/`
- API health custom domain: `https://api.patchforge.diiac.io/health`
- API readiness custom domain: `https://api.patchforge.diiac.io/readiness`
- Public UI default Container Apps URL: `https://ca-patchforge-ui-prod.lemonpebble-11b2e331.uksouth.azurecontainerapps.io/`
- Bridge health default Container Apps URL: `https://ca-patchforge-bridge-prod.lemonpebble-11b2e331.uksouth.azurecontainerapps.io/health`
- Bridge readiness default Container Apps URL: `https://ca-patchforge-bridge-prod.lemonpebble-11b2e331.uksouth.azurecontainerapps.io/readiness`
- Runtime internal FQDN: `ca-patchforge-runtime-prod.internal.lemonpebble-11b2e331.uksouth.azurecontainerapps.io`
- SRA internal FQDN: `ca-patchforge-sra-prod.internal.lemonpebble-11b2e331.uksouth.azurecontainerapps.io`
- Worker internal FQDN: `ca-patchforge-worker-prod.internal.lemonpebble-11b2e331.uksouth.azurecontainerapps.io`
- Scheduler internal FQDN: `ca-patchforge-scheduler-prod.internal.lemonpebble-11b2e331.uksouth.azurecontainerapps.io`

## Build, Push, Deploy, And Release Scripts

- Image build/push plan: `scripts/build_push_images.ps1`
- Azure deployment plan/what-if: `scripts/plan_azure_deployment.ps1`
- Azure bootstrap deploy script: `scripts/deploy_azure_bootstrap.ps1`
- IaC validation: `scripts/validate_iac.ps1`
- Local dev start: `scripts/start_local_dev.ps1`
- Release evidence folders: `docs/release/evidence/`

No deploy command was run.

## Restore Point

- Restore point type: immutable git tag
- Restore point name: `restore/pre-patchforge-rebuild-a4384cc-20260601`
- Restore point target: `a4384cc`
- Restore point pushed: no

## PF0 Acceptance Statement

- Local repo path confirmed.
- Remote confirmed.
- Branch confirmed.
- Commit confirmed.
- Required docs and Azure deployment files inspected where present.
- Azure hosting model documented.
- Restore point created before product code changes.
- PF0 evidence file created after restore point.
- No product code was changed before the restore point.
- No deployment was run.
- No real secrets or real customer data were used.
- No Pharma repository files were inspected or changed.

## Blockers Or Gaps

- Working tree had pre-existing uncommitted changes in `README.md` and `docs/operations/PATCHFORGE_OPERATIONAL_USER_GUIDE.md`; they are not PF0 changes and were preserved.
- `docs/README.md`, `backend-ui-bridge/package.json`, and `live_verification.json` were not present.
- Azure live state was discovered from repository docs and evidence only; no live Azure read operation or deployment was run.

## Canonical Blueprint Pass Update

Update timestamp: 2026-06-01T20:51:22+01:00

This section records the PF0 reconciliation pass requested after the canonical catalogue-first rebuild brief was supplied.

Current repository state before blueprint creation:

```text
git status --short --branch
## codex/patchforge-rebuild-20260601

git rev-parse --show-toplevel
F:/code/diiac/patchforge

git rev-parse --abbrev-ref HEAD
codex/patchforge-rebuild-20260601

git rev-parse --short HEAD
7d2a121

git remote -v
origin  https://github.com/neil9bailey/diiac-patchforge.git (fetch)
origin  https://github.com/neil9bailey/diiac-patchforge.git (push)
```

Current canonical rebuild restore point:

- Restore point type: annotated git tag
- Restore point name: `restore/pre-patchforge-rebuild-7d2a121-20260601`
- Restore point target: `7d2a121`
- Restore point pushed: no

Documentation and repository identity remain aligned:

- Confirmed local repo path: `F:\code\diiac\patchforge`
- Confirmed Git remote: `https://github.com/neil9bailey/diiac-patchforge.git`
- No conflict was found between the repository remote and PatchForge documentation.
- The prohibited Pharma repository was not inspected or modified.

PF0 files required by the canonical brief:

- `docs/product/PATCHFORGE_INTELLIGENCE_REBUILD_BLUEPRINT.md`
- `docs/release/evidence/2026-06-01-patchforge-rebuild/PATCHFORGE_PURGE_PLAN.md`
- `scripts/validate_patchforge_blueprint.py`
- `docs/README.md`

Azure configuration summary remains:

- Hosting model: Azure Container Apps
- Public UI URL: `https://patchforge.diiac.io/`
- API health endpoint: `https://api.patchforge.diiac.io/health`
- API readiness endpoint: `https://api.patchforge.diiac.io/readiness`
- Resource group: `rg-diiac-patchforge-prod`
- ACR: `acrdiiacpatchforgeprod.azurecr.io`
- Frontend app: `ca-patchforge-ui-prod`
- Bridge/API app: `ca-patchforge-bridge-prod`
- Runtime app: `ca-patchforge-runtime-prod`
- SRA app: `ca-patchforge-sra-prod`
- Worker app: `ca-patchforge-worker-prod`
- Scheduler app: `ca-patchforge-scheduler-prod`
- Key Vault: `kv-diiac-patchforge-prod`
- Signing key reference: `pf-pack-signing-prod`

No deployment, production purge, production data mutation, or GitHub push was performed during this PF0 reconciliation pass.
