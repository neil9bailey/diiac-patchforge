param(
  [string]$OutputDirectory = "artifacts\collector\windows",
  [string]$ExeName = "patchforge-collector.exe",
  [string]$NodePath = "node",
  [string]$EsbuildPackage = "esbuild",
  [string]$PostjectPackage = "postject"
)

$ErrorActionPreference = "Stop"

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$collectorEntry = Resolve-Path (Join-Path $repoRoot "collector\patchforge-collector.mjs")
$outputRoot = Join-Path $repoRoot $OutputDirectory
$workRoot = Join-Path $outputRoot "sea-build"
$bundledEntry = Join-Path $workRoot "patchforge-collector.sea.cjs"
$blobPath = Join-Path $workRoot "patchforge-collector.blob"
$seaConfigPath = Join-Path $workRoot "sea-config.json"
$exePath = Join-Path $outputRoot $ExeName
$packageRoot = Join-Path $outputRoot "package"
$zipPath = Join-Path $outputRoot "patchforge-collector-windows.zip"

New-Item -ItemType Directory -Path $workRoot -Force | Out-Null
New-Item -ItemType Directory -Path $packageRoot -Force | Out-Null

$nodeCommand = Get-Command $NodePath -ErrorAction SilentlyContinue
if ($null -eq $nodeCommand) {
  throw "Node.js is required to build the collector EXE."
}

$nodeVersion = & $NodePath --version
Write-Host "Building PatchForge collector EXE with $nodeVersion"

& npx --yes $EsbuildPackage $collectorEntry.Path --bundle --platform=node --format=cjs --target=node24 --log-override:empty-import-meta=silent --outfile=$bundledEntry
if ($LASTEXITCODE -ne 0) {
  throw "Bundling the collector SEA entry failed."
}

$seaConfig = [ordered]@{
  main = $bundledEntry
  output = $blobPath
  disableExperimentalSEAWarning = $true
}
[System.IO.File]::WriteAllText(
  $seaConfigPath,
  (($seaConfig | ConvertTo-Json -Depth 5) + [Environment]::NewLine),
  [System.Text.UTF8Encoding]::new($false)
)

& $NodePath --experimental-sea-config $seaConfigPath
if ($LASTEXITCODE -ne 0) {
  throw "Node SEA blob generation failed."
}

$nodeExe = $nodeCommand.Source
Copy-Item -LiteralPath $nodeExe -Destination $exePath -Force

$signtool = Get-Command signtool.exe -ErrorAction SilentlyContinue
if ($null -ne $signtool) {
  & $signtool.Source remove /s $exePath | Out-Null
} else {
  Write-Warning "signtool.exe was not found. If postject fails on a signed node.exe, install Windows SDK tools and rerun."
}

$sentinelFuse = "NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2"
& npx --yes $PostjectPackage $exePath NODE_SEA_BLOB $blobPath --sentinel-fuse $sentinelFuse
if ($LASTEXITCODE -ne 0) {
  throw "Embedding the SEA blob into $exePath failed."
}

Write-Host "Created $exePath"
Write-Host "Optional: sign $exePath with an Authenticode code-signing certificate before customer distribution."

Copy-Item -LiteralPath $exePath -Destination (Join-Path $packageRoot $ExeName) -Force
foreach ($scriptName in @(
  "new_patchforge_collector_windows_config.ps1",
  "install_patchforge_collector_windows.ps1",
  "setup_patchforge_collector_windows.ps1"
)) {
  Copy-Item -LiteralPath (Join-Path $PSScriptRoot $scriptName) -Destination (Join-Path $packageRoot $scriptName) -Force
}

$packageReadme = @"
PatchForge Windows Collector

Run these commands from an elevated PowerShell prompt on the customer machine:

1. Sign in for PatchForge API access:
   az login --tenant 67f8be6c-07da-4a7c-bb0a-d6bcb38cd6da

2. Configure and install the scheduled collector:
   powershell -NoProfile -ExecutionPolicy Bypass -File .\setup_patchforge_collector_windows.ps1 -CollectorExePath .\patchforge-collector.exe -Site "Primary site" -RunNow

No secrets are embedded in this package. The collector uses PATCHFORGE_COLLECTOR_TOKEN when set, otherwise Azure CLI token acquisition.
"@

[System.IO.File]::WriteAllText(
  (Join-Path $packageRoot "README.txt"),
  ($packageReadme + [Environment]::NewLine),
  [System.Text.UTF8Encoding]::new($false)
)

Compress-Archive -Path (Join-Path $packageRoot "*") -DestinationPath $zipPath -Force
Write-Host "Created customer package $packageRoot"
Write-Host "Created customer package archive $zipPath"
