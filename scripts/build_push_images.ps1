[CmdletBinding()]
param(
    [string]$RegistryName = "acrdiiacpatchforgeprod",
    [string]$ImageTag = "bootstrap",
    [switch]$Execute
)

$ErrorActionPreference = "Stop"
$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$images = @(
    @{ Name = "diiac/patchforge-frontend"; Path = "Frontend" },
    @{ Name = "diiac/patchforge-bridge"; Path = "backend-api" },
    @{ Name = "diiac/patchforge-runtime"; Path = "runtime" },
    @{ Name = "diiac/patchforge-sra-agent"; Path = "backend-api" },
    @{ Name = "diiac/patchforge-ingest-worker"; Path = "backend-api" },
    @{ Name = "diiac/patchforge-scheduler"; Path = "backend-api" }
)

Write-Host "PatchForge image build/push plan"
Write-Host "Registry: $RegistryName.azurecr.io"
Write-Host "Tag: $ImageTag"

foreach ($image in $images) {
    $context = Join-Path $repoRoot $image.Path
    $fullName = "$RegistryName.azurecr.io/$($image.Name):$ImageTag"
    Write-Host "docker build -t $fullName `"$context`""
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

az acr login --name $RegistryName

foreach ($image in $images) {
    $context = Join-Path $repoRoot $image.Path
    $dockerfile = Join-Path $context "Dockerfile"
    if (-not (Test-Path $dockerfile)) {
        throw "Missing Dockerfile for $($image.Name): $dockerfile"
    }

    $fullName = "$RegistryName.azurecr.io/$($image.Name):$ImageTag"
    docker build -t $fullName $context
    docker push $fullName
}

Write-Host "PatchForge image build/push complete."

