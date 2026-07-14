param(
  [Parameter(Mandatory = $true)]
  [string]$CollectorExePath,
  [string]$ManifestPath = "",
  [switch]$AllowUnsignedDevelopmentPackage
)

$ErrorActionPreference = "Stop"

$resolvedExe = (Resolve-Path -LiteralPath $CollectorExePath).Path
if ([string]::IsNullOrWhiteSpace($ManifestPath)) {
  $ManifestPath = Join-Path (Split-Path -Parent $resolvedExe) "collector-package-manifest.json"
}
if (-not (Test-Path -LiteralPath $ManifestPath)) {
  throw "Collector package manifest not found: $ManifestPath"
}

$manifest = Get-Content -Raw -LiteralPath $ManifestPath | ConvertFrom-Json
$actualHash = (Get-FileHash -LiteralPath $resolvedExe -Algorithm SHA256).Hash.ToLowerInvariant()
$expectedHash = [string]$manifest.exe_sha256
if ([string]::IsNullOrWhiteSpace($expectedHash) -or $actualHash -ne $expectedHash.ToLowerInvariant()) {
  throw "Collector EXE SHA-256 does not match the package manifest."
}

$signature = Get-AuthenticodeSignature -LiteralPath $resolvedExe
$signatureValid = $signature.Status -eq [System.Management.Automation.SignatureStatus]::Valid
$signatureRequired = [bool]$manifest.signature_required -or -not [bool]$AllowUnsignedDevelopmentPackage
if ([bool]$manifest.source_worktree_dirty -and -not $AllowUnsignedDevelopmentPackage) {
  throw "Collector package manifest records a dirty source worktree and is not eligible for customer installation."
}
if ($signatureRequired -and -not $signatureValid) {
  throw "Collector Authenticode signature is required but status is $($signature.Status)."
}

$expectedThumbprint = [string]$manifest.signer_thumbprint
if ($signatureValid -and -not [string]::IsNullOrWhiteSpace($expectedThumbprint)) {
  $actualThumbprint = [string]$signature.SignerCertificate.Thumbprint
  if ($actualThumbprint -ne $expectedThumbprint) {
    throw "Collector signer thumbprint does not match the package manifest."
  }
}

[pscustomobject]@{
  verified = $true
  exe_path = $resolvedExe
  sha256 = $actualHash
  signature_status = [string]$signature.Status
  signature_valid = $signatureValid
  signer_thumbprint = if ($signature.SignerCertificate) { [string]$signature.SignerCertificate.Thumbprint } else { $null }
  package_version = [string]$manifest.package_version
  source_commit = [string]$manifest.source_commit
  source_worktree_dirty = [bool]$manifest.source_worktree_dirty
}
