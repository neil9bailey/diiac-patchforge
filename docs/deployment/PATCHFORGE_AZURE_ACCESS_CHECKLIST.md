# PatchForge Azure Access Checklist

## Access Needed For What-If

Before running Azure what-if, confirm:

- tenant ID for `diiac.io`
- subscription ID or subscription name
- target region, initially expected as `uksouth`
- resource group name, initially `rg-diiac-patchforge-prod`
- identity allowed to run subscription-scope what-if

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
  -SubscriptionId <subscription-id> `
  -TenantId <tenant-id> `
  -RunWhatIf
```

This script is designed to run what-if only and does not deploy resources.

