param(
  [string]$OutputDirectory = "artifacts\collector\windows",
  [string]$ExeName = "patchforge-collector.exe",
  [string]$NodePath = "node",
  [string]$EsbuildPackage = "esbuild@0.28.1",
  [string]$PostjectPackage = "postject@1.0.0-alpha.6",
  [string]$SigningCertificateThumbprint = "",
  [string]$TimestampUrl = "http://timestamp.digicert.com",
  [switch]$RequireSigning
)

$ErrorActionPreference = "Stop"

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$sourceCommit = & git -C $repoRoot rev-parse HEAD
if ($LASTEXITCODE -ne 0) {
  throw "Unable to resolve the collector source commit."
}
$sourceCommit = ([string]$sourceCommit).Trim()
$trackedStatus = & git -C $repoRoot status --porcelain --untracked-files=no
if ($LASTEXITCODE -ne 0) {
  throw "Unable to verify the collector source worktree state."
}
$sourceWorktreeDirty = -not [string]::IsNullOrWhiteSpace(($trackedStatus -join [Environment]::NewLine))
$signatureRequired = [bool]$RequireSigning -or -not [string]::IsNullOrWhiteSpace($SigningCertificateThumbprint)
if ($signatureRequired -and $sourceWorktreeDirty) {
  throw "Refusing to publish a signed collector package from a dirty tracked worktree. Commit and verify the intended source first."
}
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

if ($signatureRequired) {
  if ($null -eq $signtool) {
    throw "signtool.exe is required for an Authenticode-signed customer package."
  }
  if ([string]::IsNullOrWhiteSpace($SigningCertificateThumbprint)) {
    throw "-SigningCertificateThumbprint is required when signing is requested."
  }
  & $signtool.Source sign /sha1 $SigningCertificateThumbprint /fd SHA256 /tr $TimestampUrl /td SHA256 $exePath
  if ($LASTEXITCODE -ne 0) {
    throw "Authenticode signing failed for $exePath."
  }
}

$signature = Get-AuthenticodeSignature -LiteralPath $exePath
if ($signatureRequired -and $signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid) {
  throw "Collector Authenticode verification failed with status $($signature.Status)."
}

$exeSha256 = (Get-FileHash -LiteralPath $exePath -Algorithm SHA256).Hash.ToLowerInvariant()
$packageVersion = "$(Get-Date -Format 'yyyyMMdd').$($sourceCommit.Substring(0, 8))"
$manifest = [ordered]@{
  product = "DIIaC PatchForge Windows Collector"
  package_version = $packageVersion
  source_commit = $sourceCommit
  source_worktree_dirty = $sourceWorktreeDirty
  built_at_utc = [DateTime]::UtcNow.ToString("o")
  exe_name = $ExeName
  exe_sha256 = $exeSha256
  signature_required = $signatureRequired
  signature_status = [string]$signature.Status
  signer_thumbprint = if ($signature.SignerCertificate) { [string]$signature.SignerCertificate.Thumbprint } else { $null }
  signer_subject = if ($signature.SignerCertificate) { [string]$signature.SignerCertificate.Subject } else { $null }
  advisory_only = $true
  no_vulnerability_scanning = $true
  no_patch_deployment = $true
  no_production_mutation = $true
}
$manifestPath = Join-Path $outputRoot "collector-package-manifest.json"
[System.IO.File]::WriteAllText(
  $manifestPath,
  (($manifest | ConvertTo-Json -Depth 8) + [Environment]::NewLine),
  [System.Text.UTF8Encoding]::new($false)
)

Write-Host "Created $exePath"
Write-Host "Signature status: $($signature.Status)"
Write-Host "Package manifest: $manifestPath"

Copy-Item -LiteralPath $exePath -Destination (Join-Path $packageRoot $ExeName) -Force
foreach ($scriptName in @(
  "new_patchforge_collector_windows_config.ps1",
  "install_patchforge_collector_windows.ps1",
  "setup_patchforge_collector_windows.ps1",
  "uninstall_patchforge_collector_windows.ps1",
  "revoke_patchforge_collector_windows.ps1",
  "verify_patchforge_collector_windows_package.ps1"
)) {
  Copy-Item -LiteralPath (Join-Path $PSScriptRoot $scriptName) -Destination (Join-Path $packageRoot $scriptName) -Force
}
Copy-Item -LiteralPath $manifestPath -Destination (Join-Path $packageRoot "collector-package-manifest.json") -Force

$verificationSwitch = if ($signatureRequired) { "" } else { " -AllowUnsignedDevelopmentPackage  # development only; do not distribute" }

$packageReadme = @"
PatchForge Windows Collector

Run these commands from an elevated PowerShell prompt on the customer machine:

1. Verify package integrity and Authenticode trust:
   powershell -NoProfile -ExecutionPolicy Bypass -File .\verify_patchforge_collector_windows_package.ps1 -CollectorExePath .\patchforge-collector.exe$verificationSwitch

2. Configure and install the scheduled collector. For unattended SYSTEM/service-account use, configure Azure managed identity or confirm an OS-injected credential environment:
   powershell -NoProfile -ExecutionPolicy Bypass -File .\setup_patchforge_collector_windows.ps1 -CollectorExePath .\patchforge-collector.exe -Site "Primary site" -RunNow

Upgrade by rerunning setup with -Upgrade. Revoke with revoke_patchforge_collector_windows.ps1. Uninstall with uninstall_patchforge_collector_windows.ps1.

No secrets are embedded in this package or config. The collector uses PATCHFORGE_COLLECTOR_TOKEN from the process environment, a managed identity, or the scheduled user's Azure CLI identity.
"@

[System.IO.File]::WriteAllText(
  (Join-Path $packageRoot "README.txt"),
  ($packageReadme + [Environment]::NewLine),
  [System.Text.UTF8Encoding]::new($false)
)

Compress-Archive -Path (Join-Path $packageRoot "*") -DestinationPath $zipPath -Force

$verifyArguments = @(
  "-NoProfile",
  "-ExecutionPolicy", "Bypass",
  "-File", (Join-Path $PSScriptRoot "verify_patchforge_collector_windows_package.ps1"),
  "-CollectorExePath", (Join-Path $packageRoot $ExeName),
  "-ManifestPath", (Join-Path $packageRoot "collector-package-manifest.json")
)
if (-not $signatureRequired) {
  $verifyArguments += "-AllowUnsignedDevelopmentPackage"
}
& powershell @verifyArguments | Out-Null
if ($LASTEXITCODE -ne 0) {
  throw "Packaged collector verification failed."
}
Write-Host "Created customer package $packageRoot"
Write-Host "Created customer package archive $zipPath"
