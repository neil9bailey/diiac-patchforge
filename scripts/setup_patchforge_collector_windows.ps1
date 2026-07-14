param(
  [Parameter(Mandatory = $true)]
  [string]$CollectorExePath,

  [string]$ConfigPath = "$env:ProgramData\PatchForge\Collector\patchforge-collector.config.json",
  [string]$InstallDirectory = "$env:ProgramFiles\PatchForge Collector",
  [string]$ManifestPath = "",
  [string]$TaskName = "PatchForgeCollector",
  [int]$IntervalMinutes = 240,
  [string]$ApiBaseUrl = "https://api.patchforge.diiac.io",
  [string]$TenantId = "diiac.io",
  [string]$CollectorId = "",
  [string]$CollectorName = "",
  [string]$Site = "Primary site",
  [string]$Environment = "production",
  [bool]$EnableHyperV = $true,
  [bool]$EnableAzureCliInventory = $false,
  [switch]$AzureCliManagedIdentity,
  [string]$ManagedIdentityClientIdEnv = "PATCHFORGE_COLLECTOR_MANAGED_IDENTITY_CLIENT_ID",
  [string]$AzureSubscription = "",
  [string]$HttpJsonUrl = "",
  [string]$HttpJsonTokenEnv = "NMS_READONLY_TOKEN",
  [ValidateSet("CurrentUser", "System", "ServiceAccount")]
  [string]$RunAs = "CurrentUser",
  [string]$ServiceAccount = "",
  [switch]$EnvironmentCredentialAvailable,
  [switch]$AllowUnsignedDevelopmentPackage,
  [switch]$Upgrade,
  [switch]$Reactivate,
  [switch]$RunNow
)

$ErrorActionPreference = "Stop"

$configScript = Join-Path $PSScriptRoot "new_patchforge_collector_windows_config.ps1"
$installScript = Join-Path $PSScriptRoot "install_patchforge_collector_windows.ps1"
if ([string]::IsNullOrWhiteSpace($ManifestPath)) {
  $ManifestPath = Join-Path (Split-Path -Parent $CollectorExePath) "collector-package-manifest.json"
}
$manifest = Get-Content -Raw -LiteralPath $ManifestPath | ConvertFrom-Json

& $configScript `
  -OutputPath $ConfigPath `
  -ApiBaseUrl $ApiBaseUrl `
  -TenantId $TenantId `
  -CollectorId $CollectorId `
  -CollectorName $CollectorName `
  -Site $Site `
  -Environment $Environment `
  -AzureCliManagedIdentity:$AzureCliManagedIdentity `
  -ManagedIdentityClientIdEnv $ManagedIdentityClientIdEnv `
  -CollectorVersion ([string]$manifest.package_version) `
  -PackageDigest ([string]$manifest.exe_sha256) `
  -DisableHyperV:(!$EnableHyperV) `
  -EnableAzureCliInventory:$EnableAzureCliInventory `
  -AzureSubscription $AzureSubscription `
  -HttpJsonUrl $HttpJsonUrl `
  -HttpJsonTokenEnv $HttpJsonTokenEnv

& $installScript `
  -CollectorExePath $CollectorExePath `
  -ConfigPath $ConfigPath `
  -InstallDirectory $InstallDirectory `
  -ManifestPath $ManifestPath `
  -TaskName $TaskName `
  -IntervalMinutes $IntervalMinutes `
  -RunAs $RunAs `
  -ServiceAccount $ServiceAccount `
  -EnvironmentCredentialAvailable:$EnvironmentCredentialAvailable `
  -AllowUnsignedDevelopmentPackage:$AllowUnsignedDevelopmentPackage `
  -Upgrade:$Upgrade `
  -Reactivate:$Reactivate `
  -RunNow:$RunNow

Write-Host "PatchForge collector Windows setup complete."
Write-Host "Authentication is environment-only, managed identity, or the scheduled user's Azure CLI cache; no secret was written to config."
