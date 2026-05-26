# PatchForge DIIaC Tenant Reference

Date: 2026-05-26

This document captures non-secret DIIaC tenant and Azure deployment reference details discovered from the DIIaC IT Services repository. It is intended to guide PatchForge Azure planning and what-if validation only.

## Source Review

Source repository reviewed read-only:

```text
F:\code\diiac\itservices.diiac.io
```

Observed repository status at review time:

```text
main...origin/main [ahead 1]
```

PatchForge did not modify the IT Services repository.

Source files consulted:

- `AGENTS.md`
- `customer-config/diiac/config.env`
- `infra/aca-dedicated-ui/itservices-prod.sub.bicepparam`
- `infra/aca-dedicated-ui/itservices-prod.parameters.json`
- `docs/current/CURRENT_RELEASE.md`
- `docs/release/evidence/2026-05-24-decision-control-centre-azure-rollout/deploy-apply/cp4_account_context_diiac-itservices-prod-20260524-decisionctl-apply.json`

## Redaction Boundary

Only non-secret identifiers and resource names are recorded here.

Do not copy secrets, client secrets, tokens, certificates, passwords, connection strings, private keys, or production signing material from IT Services into PatchForge.

The IT Services configuration indicates that secrets are held in Azure Key Vault. PatchForge must use its own dedicated Key Vault and managed identities for production deployment unless the user explicitly instructs otherwise.

## Tenant And Subscription

| Field | Value |
| --- | --- |
| DIIaC domain | `diiac.io` |
| Azure cloud | `AzureCloud` |
| Entra tenant ID | `67f8be6c-07da-4a7c-bb0a-d6bcb38cd6da` |
| Azure subscription ID | `9ae9da49-de67-443b-af55-ce9db33ed8f4` |
| Azure subscription name | `Azure subscription 1` |
| Account observed in context evidence | `nbailey@diiac.io` |
| Primary Azure region | `uksouth` |

PatchForge deployment planning should assume this tenant and subscription unless the user directs otherwise.

## Current IT Services Production Reference

These resources are the observed IT Services production footprint. They are reference points only and must not be reused as PatchForge resource names.

| Component | Value |
| --- | --- |
| IT Services public URL | `https://itservices.diiac.io` |
| Simulation dashboard URL | `https://itservices-sim.diiac.io` |
| Resource group | `RG_DIIAC_ITSERVICES_PROD` |
| Azure Container Registry | `acrdiiacitsvcui` |
| ACR login server | `acrdiiacitsvcui.azurecr.io` |
| Container Apps environment | `acae-diiac-itservices-prod` |
| Managed identity | `id-diiac-itservices-prod` |
| Key Vault | `kv-diiac-itservices` |
| Storage account | `stdiiacitsvcui01` |
| Log Analytics workspace | `law-diiac-itservices-prod` |
| Runtime app | `rt-diiac-itservices-prod` |
| Bridge app | `br-diiac-itservices-prod` |
| Frontend app | `ui-diiac-itservices-prod` |
| Simulation app | `sim-diiac-itservices-prod` |

Observed Container Apps default domain:

```text
delightfulsmoke-25980b22.uksouth.azurecontainerapps.io
```

Observed service FQDNs:

| Service | FQDN or URL |
| --- | --- |
| Bridge | `br-diiac-itservices-prod.delightfulsmoke-25980b22.uksouth.azurecontainerapps.io` |
| Runtime internal URL | `https://rt-diiac-itservices-prod.internal.delightfulsmoke-25980b22.uksouth.azurecontainerapps.io` |
| UI default FQDN | `ui-diiac-itservices-prod.delightfulsmoke-25980b22.uksouth.azurecontainerapps.io` |

## Entra Reference

The current IT Services configuration records:

| Field | Value |
| --- | --- |
| API app ID | `5d144b76-b9d4-4db7-af10-00c7c98037b9` |
| UI app ID | `5d144b76-b9d4-4db7-af10-00c7c98037b9` |
| Expected audience | `api://5d144b76-b9d4-4db7-af10-00c7c98037b9` |
| Admin group ID | `8a75c082-61b1-433a-9f2b-1ad6fc60540a` |
| Standard group ID | `8d989893-378e-45e0-ac67-3d1a3acee7c4` |
| V2 issuer | `https://login.microsoftonline.com/67f8be6c-07da-4a7c-bb0a-d6bcb38cd6da/v2.0` |
| Legacy issuer | `https://sts.windows.net/67f8be6c-07da-4a7c-bb0a-d6bcb38cd6da/` |
| OIDC discovery | `https://login.microsoftonline.com/67f8be6c-07da-4a7c-bb0a-d6bcb38cd6da/v2.0/.well-known/openid-configuration` |
| JWKS URI | `https://login.microsoftonline.com/67f8be6c-07da-4a7c-bb0a-d6bcb38cd6da/discovery/v2.0/keys` |

PatchForge should use dedicated PatchForge app registrations and app roles unless the user explicitly asks to reuse the IT Services app registration. Reusing the same app registration would couple product authorization boundaries and should be treated as an exception.

## DNS And Certificates Reference

Observed IT Services custom domains:

| Domain | Purpose |
| --- | --- |
| `itservices.diiac.io` | IT Services frontend |
| `itservices-sim.diiac.io` | IT Services simulation dashboard |

Observed IT Services managed certificate resource IDs:

```text
/subscriptions/9ae9da49-de67-443b-af55-ce9db33ed8f4/resourceGroups/RG_DIIAC_ITSERVICES_PROD/providers/Microsoft.App/managedEnvironments/acae-diiac-itservices-prod/managedCertificates/cert-itservices-diiac-io
/subscriptions/9ae9da49-de67-443b-af55-ce9db33ed8f4/resourceGroups/RG_DIIAC_ITSERVICES_PROD/providers/Microsoft.App/managedEnvironments/acae-diiac-itservices-prod/managedCertificates/cert-itservices-sim-diiac-io
```

PatchForge DNS targets remain:

- `patchforge.diiac.io`
- `api.patchforge.diiac.io`

DNS changes are not required until the PatchForge Container Apps endpoints and certificate binding plan are confirmed.

## PatchForge Deployment Mapping

Recommended PatchForge dedicated resources remain:

| Resource | PatchForge target |
| --- | --- |
| Resource group | `rg-diiac-patchforge-prod` |
| ACR | `acrdiiacpatchforgeprod` |
| Container Apps environment | `acae-diiac-patchforge-prod` |
| Frontend app | `ca-patchforge-ui-prod` |
| Bridge app | `ca-patchforge-bridge-prod` |
| Runtime app | `ca-patchforge-runtime-prod` |
| SRA app | `ca-patchforge-sra-prod` |
| Worker app | `ca-patchforge-worker-prod` |
| Scheduler app | `ca-patchforge-scheduler-prod` |
| Storage | `stdiiacpatchforgeprod01` |
| Key Vault | `kv-diiac-patchforge-prod` |
| Log Analytics | `law-diiac-patchforge-prod` |
| Managed identity | `id-diiac-patchforge-prod` |
| PostgreSQL | `psql-diiac-patchforge-prod` |
| Database | `patchforge_prod` |
| Region | `uksouth` |

## Discrepancies To Verify

The IT Services repo contains a few differences that should not be silently inherited:

- `customer-config/diiac/config.env` records `AZURE_RESOURCE_GROUP=rg-diiac-prod`, while current IT Services production/IaC evidence uses `RG_DIIAC_ITSERVICES_PROD`.
- The IT Services Bicep parameter files include image tag `1.7.0-approvalexport-2304fae`, while `docs/current/CURRENT_RELEASE.md` records current live images as `1.7.0-reportgap-7ae776d`.
- IT Services API and UI app IDs are currently the same value in configuration. PatchForge should confirm whether it needs separate UI/API app registrations before Entra setup.

## Access Gates Before Azure Work

Before PatchForge what-if:

- confirm use of subscription `9ae9da49-de67-443b-af55-ce9db33ed8f4`
- confirm target resource group `rg-diiac-patchforge-prod`
- confirm deployment region `uksouth`
- confirm who will run the Azure context and what-if command

Before PatchForge deployment:

- confirm explicit permission to create or manage PatchForge Azure resources
- confirm dedicated PatchForge Entra app registrations and app roles
- confirm dedicated PatchForge Key Vault and signing model
- confirm Container Apps custom domain strategy
- confirm DNS update timing for `patchforge.diiac.io` and `api.patchforge.diiac.io`

