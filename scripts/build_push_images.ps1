[CmdletBinding()]
param(
    [string]$RegistryName = "acrdiiacpatchforgeprod",
    [string]$ImageTag = "bootstrap",
    [switch]$Execute
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

$images = @(
    @{ Name = "diiac/patchforge-frontend"; Path = "Frontend"; Dockerfile = "Frontend/Dockerfile" },
    @{ Name = "diiac/patchforge-bridge"; Path = "backend-api"; Dockerfile = "backend-api/Dockerfile" },
    @{ Name = "diiac/patchforge-runtime"; Path = "."; Dockerfile = "runtime/Dockerfile" },
    @{ Name = "diiac/patchforge-sra-agent"; Path = "backend-api"; Dockerfile = "backend-api/Dockerfile" },
    @{ Name = "diiac/patchforge-ingest-worker"; Path = "backend-api"; Dockerfile = "backend-api/Dockerfile" },
    @{ Name = "diiac/patchforge-scheduler"; Path = "backend-api"; Dockerfile = "backend-api/Dockerfile" }
)

Write-Host "PatchForge image build/push plan"
Write-Host "Registry: $RegistryName.azurecr.io"
Write-Host "Tag: $ImageTag"

foreach ($image in $images) {
    $context = Join-Path $repoRoot $image.Path
    $dockerfile = Join-Path $repoRoot $image.Dockerfile
    $fullName = "$RegistryName.azurecr.io/$($image.Name):$ImageTag"
    Write-Host "docker build -f `"$dockerfile`" -t $fullName `"$context`""
    Write-Host "docker push $fullName"
}

if (-not $Execute) {
    Write-Host ""
    Write-Host "Dry run only. Re-run with -Execute after Dockerfiles, Azure access, and ACR login are confirmed."
    exit 0
}

$docker = Get-Command docker -ErrorAction SilentlyContinue
if ($null -eq $docker) {
    throw "Docker is required to build images."
}

$az = Get-Command az -ErrorAction SilentlyContinue
if ($null -eq $az) {
    throw "Azure CLI is required to log in to ACR."
}

Invoke-CheckedNative -Command "docker" -Arguments @("version")
Invoke-CheckedNative -Command "az" -Arguments @("acr", "login", "--name", $RegistryName)

foreach ($image in $images) {
    $existingTags = Invoke-CheckedNative -Command "az" -Arguments @(
        "acr", "repository", "show-tags",
        "--name", $RegistryName,
        "--repository", $image.Name,
        "--output", "tsv"
    ) -CaptureOutput
    if (@($existingTags) -contains $ImageTag) {
        throw "Refusing to reuse existing ACR tag '$ImageTag' for $($image.Name). Choose a new immutable tag."
    }
}

foreach ($image in $images) {
    $context = Join-Path $repoRoot $image.Path
    $dockerfile = Join-Path $repoRoot $image.Dockerfile
    if (-not (Test-Path $dockerfile)) {
        throw "Missing Dockerfile for $($image.Name): $dockerfile"
    }

    $fullName = "$RegistryName.azurecr.io/$($image.Name):$ImageTag"
    Invoke-CheckedNative -Command "docker" -Arguments @("build", "-f", $dockerfile, "-t", $fullName, $context)
    Invoke-CheckedNative -Command "docker" -Arguments @("push", $fullName)
}

Write-Host "PatchForge image build/push complete."
