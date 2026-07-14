$ErrorActionPreference = "Stop"

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) "patchforge-collector-lifecycle-$([Guid]::NewGuid().ToString('N'))"
New-Item -ItemType Directory -Path $tempRoot -Force | Out-Null

try {
  $configPath = Join-Path $tempRoot "patchforge-collector.config.json"
  $heartbeatPath = Join-Path $tempRoot "collector-heartbeat.json"
  $revocationPath = Join-Path $tempRoot "collector.revoked.json"
  & (Join-Path $PSScriptRoot "new_patchforge_collector_windows_config.ps1") `
    -OutputPath $configPath `
    -CollectorId "collector-lifecycle-test" `
    -Site "Lifecycle test" `
    -AzureCliManagedIdentity `
    -ManagedIdentityClientIdEnv "COLLECTOR_TEST_CLIENT_ID" `
    -CollectorVersion "test-version" `
    -PackageDigest "sha256:test" `
    -HeartbeatFile $heartbeatPath `
    -RevocationFile $revocationPath

  $configText = Get-Content -Raw -LiteralPath $configPath
  $config = $configText | ConvertFrom-Json
  if (-not [bool]$config.auth.azureCliManagedIdentity) { throw "Managed identity configuration was not preserved." }
  if ($config.auth.managedIdentityClientIdEnv -ne "COLLECTOR_TEST_CLIENT_ID") { throw "Managed identity environment reference mismatch." }
  if ($config.lifecycle.revocationFile -ne $revocationPath) { throw "Revocation path mismatch." }
  if ($config.lifecycle.heartbeatFile -ne $heartbeatPath) { throw "Heartbeat path mismatch." }
  if ($configText -match '(?i)client_secret|password\s*[:=]|bearer\s+[a-z0-9]') { throw "Generated config appears to contain a raw credential." }

  $fakeExe = Join-Path $tempRoot "patchforge-collector.exe"
  [System.IO.File]::WriteAllBytes($fakeExe, [System.Text.Encoding]::UTF8.GetBytes("unsigned development collector test"))
  $hash = (Get-FileHash -LiteralPath $fakeExe -Algorithm SHA256).Hash.ToLowerInvariant()
  $manifestPath = Join-Path $tempRoot "collector-package-manifest.json"
  $manifest = [ordered]@{
    package_version = "test-version"
    source_commit = "test-commit"
    exe_sha256 = $hash
    signature_required = $false
    signer_thumbprint = $null
  }
  [System.IO.File]::WriteAllText(
    $manifestPath,
    (($manifest | ConvertTo-Json) + [Environment]::NewLine),
    [System.Text.UTF8Encoding]::new($false)
  )
  $verified = & (Join-Path $PSScriptRoot "verify_patchforge_collector_windows_package.ps1") `
    -CollectorExePath $fakeExe `
    -ManifestPath $manifestPath `
    -AllowUnsignedDevelopmentPackage
  if (-not [bool]$verified.verified -or $verified.sha256 -ne $hash) { throw "Unsigned development package verification failed." }

  $parseTargets = Get-ChildItem -LiteralPath $PSScriptRoot -Filter "*patchforge_collector_windows*.ps1"
  foreach ($target in $parseTargets) {
    $tokens = $null
    $errors = $null
    [System.Management.Automation.Language.Parser]::ParseFile($target.FullName, [ref]$tokens, [ref]$errors) | Out-Null
    if ($errors.Count) { throw "PowerShell parse failed for $($target.Name): $($errors.Message -join '; ')" }
  }

  Write-Host "PatchForge collector lifecycle checks passed."
} finally {
  $resolvedTemp = [System.IO.Path]::GetFullPath($tempRoot)
  $systemTemp = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath())
  if (-not $resolvedTemp.StartsWith($systemTemp, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "Refusing to remove unexpected lifecycle-test path: $resolvedTemp"
  }
  if (Test-Path -LiteralPath $resolvedTemp) {
    Remove-Item -LiteralPath $resolvedTemp -Recurse -Force
  }
}
