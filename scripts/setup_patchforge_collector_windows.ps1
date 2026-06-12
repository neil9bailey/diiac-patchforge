param(
  [Parameter(Mandatory = $true)]
  [string]$CollectorExePath,

  [string]$ConfigPath = "$env:ProgramData\PatchForge\Collector\patchforge-collector.config.json",
  [string]$InstallDirectory = "$env:ProgramFiles\PatchForge Collector",
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
  [string]$AzureSubscription = "",
  [string]$HttpJsonUrl = "",
  [string]$HttpJsonTokenEnv = "NMS_READONLY_TOKEN",
  [ValidateSet("CurrentUser", "System")]
  [string]$RunAs = "CurrentUser",
  [switch]$RunNow
)

$ErrorActionPreference = "Stop"

$configScript = Join-Path $PSScriptRoot "new_patchforge_collector_windows_config.ps1"
$installScript = Join-Path $PSScriptRoot "install_patchforge_collector_windows.ps1"

& $configScript `
  -OutputPath $ConfigPath `
  -ApiBaseUrl $ApiBaseUrl `
  -TenantId $TenantId `
  -CollectorId $CollectorId `
  -CollectorName $CollectorName `
  -Site $Site `
  -Environment $Environment `
  -DisableHyperV:(!$EnableHyperV) `
  -EnableAzureCliInventory:$EnableAzureCliInventory `
  -AzureSubscription $AzureSubscription `
  -HttpJsonUrl $HttpJsonUrl `
  -HttpJsonTokenEnv $HttpJsonTokenEnv

& $installScript `
  -CollectorExePath $CollectorExePath `
  -ConfigPath $ConfigPath `
  -InstallDirectory $InstallDirectory `
  -TaskName $TaskName `
  -IntervalMinutes $IntervalMinutes `
  -RunAs $RunAs `
  -RunNow:$RunNow

Write-Host "PatchForge collector Windows setup complete."
Write-Host "If PATCHFORGE_COLLECTOR_TOKEN is not set, sign in with Azure CLI as the scheduled-task user:"
Write-Host "az login --tenant 67f8be6c-07da-4a7c-bb0a-d6bcb38cd6da"
