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
  }
  adapters = $adapters
}

[System.IO.File]::WriteAllText(
  $OutputPath,
  (($config | ConvertTo-Json -Depth 20) + [Environment]::NewLine),
  [System.Text.UTF8Encoding]::new($false)
)

Write-Host "Created PatchForge collector config: $OutputPath"
Write-Host "No secrets were written. The collector will use PATCHFORGE_COLLECTOR_TOKEN if present, otherwise Azure CLI token acquisition for $AzureCliScope."
