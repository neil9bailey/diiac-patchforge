# PatchForge Azure Access Checklist

## Access Needed For What-If

Before running Azure what-if, confirm:

- tenant ID for `diiac.io`: `67f8be6c-07da-4a7c-bb0a-d6bcb38cd6da`
- subscription ID: `9ae9da49-de67-443b-af55-ce9db33ed8f4`
- subscription name: `Azure subscription 1`
- target region: `uksouth`
- resource group name: `rg-diiac-patchforge-prod`
- identity allowed to run subscription-scope what-if

Source reference: `docs/deployment/PATCHFORGE_DIIAC_TENANT_REFERENCE.md`.

## Access Needed For Deployment

Before deployment, confirm permission to create or manage:

- resource groups
- managed identities
- role assignments
- Azure Container Registry
- Azure Container Apps
- Log Analytics
- Storage Account and containers
- Key Vault with RBAC authorization
- PostgreSQL Flexible Server or Azure SQL

## Safe Context Commands

Use process-scoped Azure context:

```powershell
Get-AzContext | Select-Object Account, Subscription, Tenant, Environment
Get-AzSubscription | Select-Object Name, Id, TenantId, State
Set-AzContext -Subscription <subscription-id> -Tenant <tenant-id> -Scope Process
```

## What-If Only

Use:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/plan_azure_deployment.ps1 `
  -SubscriptionId 9ae9da49-de67-443b-af55-ce9db33ed8f4 `
  -TenantId 67f8be6c-07da-4a7c-bb0a-d6bcb38cd6da `
  -RunWhatIf
```

This script is designed to run what-if only and does not deploy resources.
