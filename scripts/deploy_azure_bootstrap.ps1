[CmdletBinding()]
param(
    [string]$SubscriptionId = "9ae9da49-de67-443b-af55-ce9db33ed8f4",
    [string]$TenantId = "67f8be6c-07da-4a7c-bb0a-d6bcb38cd6da",
    [string]$Location = "uksouth",
    [string]$RegistryName = "acrdiiacpatchforgeprod",
    [string]$ImageTag = "bootstrap",
    [string]$AcrSku = "Basic",
    [switch]$Execute
)

$ErrorActionPreference = "Stop"
$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$templatePath = Resolve-Path (Join-Path $repoRoot "infra/bicep/main.bicep")
$parameterPath = Resolve-Path (Join-Path $repoRoot "infra/parameters/prod.bicepparam")
$buildScript = Resolve-Path (Join-Path $repoRoot "scripts/build_push_images.ps1")
$validateScript = Resolve-Path (Join-Path $repoRoot "scripts/validate_iac.ps1")

Write-Host "PatchForge Azure bootstrap deployment"
Write-Host "Tenant: $TenantId"
Write-Host "Subscription: $SubscriptionId"
Write-Host "Location: $Location"
Write-Host "Registry: $RegistryName.azurecr.io"
Write-Host "Image tag: $ImageTag"
Write-Host "ACR SKU: $AcrSku"

if (-not $Execute) {
    Write-Host ""
    Write-Host "Dry run only. Re-run with -Execute to create/update Azure resources."
    Write-Host "Phases:"
    Write-Host "1. Validate IaC"
    Write-Host "2. Deploy base resources with deployContainerApps=false"
    Write-Host "3. Build and push bootstrap images"
    Write-Host "4. Deploy Container Apps with deployContainerApps=true"
    exit 0
}

$az = Get-Command az -ErrorAction SilentlyContinue
if ($null -eq $az) {
    throw "Azure CLI is required."
}

powershell -NoProfile -ExecutionPolicy Bypass -File $validateScript

az account set --subscription $SubscriptionId
$currentTenant = az account show --query tenantId -o tsv
if ($currentTenant -ne $TenantId) {
    throw "Current Azure CLI tenant '$currentTenant' does not match requested tenant '$TenantId'. Run az login --tenant $TenantId first."
}

$stamp = Get-Date -Format "yyyyMMdd-HHmmss"

az deployment sub create `
    --name "pf-base-$stamp" `
    --location $Location `
    --template-file $templatePath `
    --parameters $parameterPath deployContainerApps=false acrSku=$AcrSku

powershell -NoProfile -ExecutionPolicy Bypass -File $buildScript `
    -RegistryName $RegistryName `
    -ImageTag $ImageTag `
    -Execute

az deployment sub create `
    --name "pf-apps-$stamp" `
    --location $Location `
    --template-file $templatePath `
    --parameters $parameterPath deployContainerApps=true acrSku=$AcrSku imageTag=$ImageTag

Write-Host "PatchForge Azure bootstrap deployment complete."

