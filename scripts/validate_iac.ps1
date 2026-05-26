[CmdletBinding()]
param(
    [string]$TemplateFile = "infra/bicep/main.bicep",
    [string]$ParameterFile = "infra/parameters/prod.bicepparam"
)

$ErrorActionPreference = "Stop"
$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$templatePath = Resolve-Path (Join-Path $repoRoot $TemplateFile)
$parameterPath = Resolve-Path (Join-Path $repoRoot $ParameterFile)

Write-Host "PatchForge IaC validation"
Write-Host "Template: $templatePath"
Write-Host "Parameters: $parameterPath"

$requiredFiles = @(
    "infra/bicep/main.bicep",
    "infra/bicep/container-apps.bicep",
    "infra/bicep/storage.bicep",
    "infra/bicep/keyvault.bicep",
    "infra/bicep/postgres-or-sql.bicep",
    "infra/bicep/monitoring.bicep",
    "infra/parameters/prod.bicepparam"
)

foreach ($file in $requiredFiles) {
    $path = Join-Path $repoRoot $file
    if (-not (Test-Path $path)) {
        throw "Required IaC file missing: $file"
    }
}

$secretPattern = "(client_secret|password\s*=\s*['""][^'""]{8,}|access_token|BEGIN PRIVATE KEY)"
$iacText = Get-ChildItem -Path (Join-Path $repoRoot "infra") -Recurse -File |
    Where-Object { $_.Extension -in ".bicep", ".bicepparam", ".ps1" } |
    ForEach-Object { Get-Content -Raw -LiteralPath $_.FullName }

if (($iacText -join "`n") -match $secretPattern) {
    throw "Potential secret-like value found in IaC. Review before committing."
}

$az = Get-Command az -ErrorAction SilentlyContinue
if ($null -eq $az) {
    Write-Warning "Azure CLI is not available; skipped az bicep build."
    exit 0
}

az bicep version
if ($LASTEXITCODE -ne 0) {
    throw "az bicep version failed."
}

az bicep build --file $templatePath
if ($LASTEXITCODE -ne 0) {
    throw "az bicep build failed."
}

Write-Host "PatchForge IaC validation complete. No deployment was run."
