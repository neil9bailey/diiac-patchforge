[CmdletBinding()]
param(
    [string]$SubscriptionId,
    [string]$TenantId,
    [string]$Location = "uksouth",
    [string]$TemplateFile = "infra/bicep/main.bicep",
    [string]$ParameterFile = "infra/parameters/prod.bicepparam",
    [switch]$RunWhatIf
)

$ErrorActionPreference = "Stop"
$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$templatePath = Resolve-Path (Join-Path $repoRoot $TemplateFile)
$parameterPath = Resolve-Path (Join-Path $repoRoot $ParameterFile)

Write-Host "PatchForge Azure deployment plan"
Write-Host "This script does not create or mutate resources."
Write-Host "Template: $templatePath"
Write-Host "Parameters: $parameterPath"
Write-Host "Location: $Location"

Write-Host ""
Write-Host "Before deployment, confirm:"
Write-Host "- Azure tenant and subscription"
Write-Host "- target region"
Write-Host "- production/non-production sequence"
Write-Host "- Key Vault signing strategy"
Write-Host "- DNS plan for patchforge.diiac.io and api.patchforge.diiac.io"
Write-Host "- PostgreSQL password supplied securely if createPostgres=true"

if (-not $RunWhatIf) {
    Write-Host ""
    Write-Host "What-if command preview:"
    Write-Host "az login --tenant <tenant-id>"
    Write-Host "az account set --subscription <subscription-id>"
    Write-Host "az deployment sub what-if --location $Location --template-file `"$templatePath`" --parameters `"$parameterPath`" --validation-level ProviderNoRbac"
    Write-Host ""
    Write-Host "Run with -RunWhatIf after Azure access is confirmed to execute what-if only."
    exit 0
}

if ([string]::IsNullOrWhiteSpace($SubscriptionId) -or [string]::IsNullOrWhiteSpace($TenantId)) {
    throw "SubscriptionId and TenantId are required for -RunWhatIf."
}

$az = Get-Command az -ErrorAction SilentlyContinue
if ($null -eq $az) {
    throw "Azure CLI is required for -RunWhatIf."
}

az account show --query "{name:name, id:id, tenantId:tenantId}" --output table
az account set --subscription $SubscriptionId

$currentTenant = az account show --query tenantId -o tsv
if ($currentTenant -ne $TenantId) {
    throw "Current Azure CLI tenant '$currentTenant' does not match requested tenant '$TenantId'. Run az login --tenant $TenantId first."
}

az deployment sub what-if `
    --location $Location `
    --template-file $templatePath `
    --parameters $parameterPath `
    --validation-level ProviderNoRbac

Write-Host "PatchForge what-if complete. No deployment was run."

