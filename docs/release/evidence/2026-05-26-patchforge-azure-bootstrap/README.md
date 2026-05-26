# PatchForge Azure Bootstrap Evidence

Date: 2026-05-26

## Scope

PatchForge Azure bootstrap was deployed into the DIIaC tenant and subscription using a new dedicated PatchForge resource group.

No IT Services resources were modified.

## Target

| Field | Value |
| --- | --- |
| Tenant | `diiac.io` |
| Tenant ID | `67f8be6c-07da-4a7c-bb0a-d6bcb38cd6da` |
| Subscription | `Azure subscription 1` |
| Subscription ID | `9ae9da49-de67-443b-af55-ce9db33ed8f4` |
| Region | `uksouth` |
| Resource group | `rg-diiac-patchforge-prod` |

## Deployment Commands

Base resources:

```powershell
az deployment sub create `
  --name pf-base-20260526-r3 `
  --location uksouth `
  --template-file infra/bicep/main.bicep `
  --parameters infra/parameters/prod.bicepparam deployContainerApps=false acrSku=Basic
```

Bootstrap images:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/build_push_images.ps1 `
  -RegistryName acrdiiacpatchforgeprod `
  -ImageTag bootstrap `
  -Execute
```

Container Apps:

```powershell
az deployment sub create `
  --name pf-apps-20260526 `
  --location uksouth `
  --template-file infra/bicep/main.bicep `
  --parameters infra/parameters/prod.bicepparam deployContainerApps=true acrSku=Basic
```

## Live Resources

| Resource | Value |
| --- | --- |
| ACR | `acrdiiacpatchforgeprod.azurecr.io` |
| ACA environment | `acae-diiac-patchforge-prod` |
| ACA default domain | `lemonpebble-11b2e331.uksouth.azurecontainerapps.io` |
| ACA static IP | `4.250.136.215` |
| UI app | `ca-patchforge-ui-prod` |
| Bridge/API app | `ca-patchforge-bridge-prod` |
| Runtime app | `ca-patchforge-runtime-prod` |
| SRA app | `ca-patchforge-sra-prod` |
| Worker app | `ca-patchforge-worker-prod` |
| Scheduler app | `ca-patchforge-scheduler-prod` |
| Key Vault | `kv-diiac-patchforge-prod` |
| Storage | `stdiiacpatchforgeprod01` |
| Log Analytics | `law-diiac-patchforge-prod` |

## Public URLs

| Surface | URL | Smoke result |
| --- | --- | --- |
| UI | `https://ca-patchforge-ui-prod.lemonpebble-11b2e331.uksouth.azurecontainerapps.io/` | HTTP 200 |
| Bridge health | `https://ca-patchforge-bridge-prod.lemonpebble-11b2e331.uksouth.azurecontainerapps.io/health` | HTTP 200 |
| Bridge readiness | `https://ca-patchforge-bridge-prod.lemonpebble-11b2e331.uksouth.azurecontainerapps.io/readiness` | HTTP 200 |

Internal-only surfaces:

- `ca-patchforge-runtime-prod.internal.lemonpebble-11b2e331.uksouth.azurecontainerapps.io`
- `ca-patchforge-sra-prod.internal.lemonpebble-11b2e331.uksouth.azurecontainerapps.io`
- `ca-patchforge-worker-prod.internal.lemonpebble-11b2e331.uksouth.azurecontainerapps.io`
- `ca-patchforge-scheduler-prod.internal.lemonpebble-11b2e331.uksouth.azurecontainerapps.io`

## Image Repositories

- `diiac/patchforge-frontend:bootstrap`
- `diiac/patchforge-bridge:bootstrap`
- `diiac/patchforge-runtime:bootstrap`
- `diiac/patchforge-sra-agent:bootstrap`
- `diiac/patchforge-ingest-worker:bootstrap`
- `diiac/patchforge-scheduler:bootstrap`

## Notes

The first ACR deployment attempts failed because the original registry policy block caused Azure to reject both `Standard` and `Basic` SKU paths with `SkuNotSupported`. The bootstrap IaC now uses a minimal `Basic` ACR configuration with admin user disabled and managed-identity RBAC for pulls.

PostgreSQL was not created in this bootstrap deployment. PatchForge is still running the current local JSON storage placeholder until the database password, network model, and migration path are confirmed.

DNS has not been updated. `patchforge.diiac.io` and `api.patchforge.diiac.io` still need custom domain binding and DNS cutover.

