param(
  [string]$OutputPath = "$env:ProgramData\PatchForge\Collector\patchforge-collector.config.json",
  [string]$ApiBaseUrl = "https://api.patchforge.diiac.io",
  [string]$TenantId = "diiac.io",
  [string]$CollectorId = "",
  [string]$CollectorName = "",
  [string]$Site = "Primary site",
  [string]$Environment = "production",
  [string]$CredentialReference = "customer-vault:patchforge/read-only-discovery",
  [string]$AzureTenantId = "67f8be6c-07da-4a7c-bb0a-d6bcb38cd6da",
  [string]$AzureCliScope = "api://ec30b0eb-cfc4-48cc-a5f2-2a1345d96736/PatchForge.Access",
  [switch]$AzureCliManagedIdentity,
  [string]$ManagedIdentityClientIdEnv = "PATCHFORGE_COLLECTOR_MANAGED_IDENTITY_CLIENT_ID",
  [string]$CollectorVersion = "customer-managed",
  [string]$PackageDigest = "",
  [string]$HeartbeatFile = "$env:ProgramData\PatchForge\Collector\collector-heartbeat.json",
  [string]$RevocationFile = "$env:ProgramData\PatchForge\Collector\collector.revoked.json",
  [string]$SpoolDirectory = "$env:ProgramData\PatchForge\Collector\spool",
  [ValidateRange(1, 10000)]
  [int]$MaxSpoolEntries = 100,
  [ValidateRange(65536, 104857600)]
  [int]$MaxSpoolEntryBytes = 8388608,
  [ValidateRange(1, 20)]
  [int]$MaxReplayAttempts = 5,
  [switch]$DisableHyperV,
  [switch]$EnableAzureCliInventory,
  [string]$AzureSubscription = "",
  [string]$HttpJsonUrl = "",
  [string]$HttpJsonTokenEnv = "NMS_READONLY_TOKEN"
)

$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($CollectorId)) {
  $CollectorId = "collector-$($env:COMPUTERNAME.ToLowerInvariant())"
}
if ([string]::IsNullOrWhiteSpace($CollectorName)) {
  $CollectorName = "PatchForge Collector $env:COMPUTERNAME"
}

$configDirectory = Split-Path -Parent $OutputPath
if (-not [string]::IsNullOrWhiteSpace($configDirectory)) {
  New-Item -ItemType Directory -Path $configDirectory -Force | Out-Null
}

$categories = @(
  "network_device",
  "security_appliance",
  "physical_server",
  "virtual_server",
  "hypervisor",
  "cloud_resource",
  "endpoint",
  "storage",
  "application_platform"
)

$adapters = @(
  [ordered]@{
    type = "local_host"
    enabled = $true
  },
  [ordered]@{
    type = "hyperv"
    enabled = -not [bool]$DisableHyperV
  },
  [ordered]@{
    type = "azure_cli"
    enabled = [bool]$EnableAzureCliInventory
    subscription = $AzureSubscription
  }
)

if (-not [string]::IsNullOrWhiteSpace($HttpJsonUrl)) {
  $adapters += [ordered]@{
    type = "http_json"
    enabled = $true
    url = $HttpJsonUrl
    headers = [ordered]@{
      Authorization = "Bearer env:$HttpJsonTokenEnv"
    }
    assetPath = "items"
    fieldMap = [ordered]@{
      asset_id = "id"
      category = "category"
      hostname = "hostname"
      vendor_name = "vendor"
      product_family = "product"
      model = "model"
      firmware_version = "version"
      ip_addresses = "ip"
    }
  }
}

$config = [ordered]@{
  apiBaseUrl = $ApiBaseUrl
  tenantId = $TenantId
  collector = [ordered]@{
    collector_id = $CollectorId
    name = $CollectorName
    site = $Site
    environment = $Environment
    categories = $categories
    package_channel = "windows_exe_day1"
  }
  policy = [ordered]@{
    policy_id = "policy-$CollectorId"
    collector_id = $CollectorId
    name = "$CollectorName read-only discovery"
    categories = $categories
    credential_reference = $CredentialReference
    scope = [ordered]@{
      sites = @($Site)
      source_systems = @("local_host", "hyperv", "azure_cli", "http_json")
    }
  }
  auth = [ordered]@{
    bearerTokenEnv = "PATCHFORGE_COLLECTOR_TOKEN"
    azureCliScope = $AzureCliScope
    azureTenantId = $AzureTenantId
    azureCliManagedIdentity = [bool]$AzureCliManagedIdentity
    managedIdentityClientIdEnv = $ManagedIdentityClientIdEnv
  }
  lifecycle = [ordered]@{
    heartbeatFile = $HeartbeatFile
    revocationFile = $RevocationFile
    spoolDirectory = $SpoolDirectory
    maxSpoolEntries = $MaxSpoolEntries
    maxSpoolEntryBytes = $MaxSpoolEntryBytes
    maxReplayAttempts = $MaxReplayAttempts
    collectorVersion = $CollectorVersion
    packageDigest = if ([string]::IsNullOrWhiteSpace($PackageDigest)) { $null } else { $PackageDigest }
  }
  adapters = $adapters
}

[System.IO.File]::WriteAllText(
  $OutputPath,
  (($config | ConvertTo-Json -Depth 20) + [Environment]::NewLine),
  [System.Text.UTF8Encoding]::new($false)
)

Write-Host "Created PatchForge collector config: $OutputPath"
Write-Host "No secrets were written. Authentication uses OS-injected PATCHFORGE_COLLECTOR_TOKEN, Azure managed identity, or the scheduled user's Azure CLI identity."
