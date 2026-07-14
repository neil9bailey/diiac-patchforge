[CmdletBinding()]
param(
    [string]$SubscriptionId,
    [string]$TenantId,
    [string]$Location = "uksouth",
    [string]$TemplateFile = "infra/bicep/main.bicep",
    [string]$ParameterFile = "infra/parameters/prod.bicepparam",
    [string]$ImageTag = "",
    [string]$AcrSku = "",
    [switch]$RunWhatIf
)

$ErrorActionPreference = "Stop"
$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")

function Invoke-CheckedNative {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Command,
        [Parameter(Mandatory = $true)]
        [string[]]$Arguments,
        [switch]$CaptureOutput
    )

    if ($CaptureOutput) {
        $output = & $Command @Arguments
        $exitCode = $LASTEXITCODE
        if ($exitCode -ne 0) {
            throw "$Command failed with exit code $exitCode."
        }
        return @($output)
    }

    & $Command @Arguments
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0) {
        throw "$Command failed with exit code $exitCode."
    }
}

$templatePath = (Resolve-Path (Join-Path $repoRoot $TemplateFile)).Path
$parameterPath = (Resolve-Path (Join-Path $repoRoot $ParameterFile)).Path
$parameterOverrides = @()
if (-not [string]::IsNullOrWhiteSpace($ImageTag)) {
    $parameterOverrides += "imageTag=$ImageTag"
}
if (-not [string]::IsNullOrWhiteSpace($AcrSku)) {
    $parameterOverrides += "acrSku=$AcrSku"
}
$parameterArgs = @($parameterPath) + $parameterOverrides

Write-Host "PatchForge Azure deployment plan"
Write-Host "This script does not create or mutate resources."
Write-Host "Template: $templatePath"
Write-Host "Parameters: $parameterPath"
if ($parameterOverrides.Count -gt 0) {
    Write-Host "Parameter overrides: $($parameterOverrides -join ', ')"
}
Write-Host "Location: $Location"

Write-Host ""
Write-Host "Before deployment, confirm:"
Write-Host "- Azure tenant and subscription"
Write-Host "- target region"
Write-Host "- production/non-production sequence"
Write-Host "- Key Vault signing strategy"
Write-Host "- DNS plan for patchforge.diiac.io and api.patchforge.diiac.io"
Write-Host "- PostgreSQL password supplied securely if postgresMode=create"

if (-not $RunWhatIf) {
    Write-Host ""
    Write-Host "What-if command preview:"
    Write-Host "az login --tenant <tenant-id>"
    Write-Host "az account set --subscription <subscription-id>"
    $overridePreview = if ($parameterOverrides.Count -gt 0) { " $($parameterOverrides -join ' ')" } else { "" }
    Write-Host "az deployment sub what-if --location $Location --template-file `"$templatePath`" --parameters `"$parameterPath`"$overridePreview --validation-level ProviderNoRbac"
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

Invoke-CheckedNative -Command "az" -Arguments @("account", "show", "--query", "{name:name, id:id, tenantId:tenantId}", "--output", "table")
Invoke-CheckedNative -Command "az" -Arguments @("account", "set", "--subscription", $SubscriptionId)

$currentTenant = (Invoke-CheckedNative -Command "az" -Arguments @("account", "show", "--query", "tenantId", "-o", "tsv") -CaptureOutput | Select-Object -First 1)
if ($currentTenant -ne $TenantId) {
    throw "Current Azure CLI tenant '$currentTenant' does not match requested tenant '$TenantId'. Run az login --tenant $TenantId first."
}

$whatIfArgs = @(
    "deployment", "sub", "what-if",
    "--location", $Location,
    "--template-file", $templatePath,
    "--parameters"
) + $parameterArgs + @(
    "--validation-level", "ProviderNoRbac"
)

Invoke-CheckedNative -Command "az" -Arguments $whatIfArgs

Write-Host "PatchForge what-if complete. No deployment was run."
