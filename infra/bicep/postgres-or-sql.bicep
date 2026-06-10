targetScope = 'resourceGroup'

param location string = resourceGroup().location
param tags object = {}
param createPostgres bool = false
param postgresServerName string
param databaseName string = 'patchforge_prod'
param administratorLogin string = 'patchforgeadmin'
param allowAzureServicesFirewallRule bool = true

@description('Explicit client IP ranges allowed through the PostgreSQL firewall. Each entry: { name: string, startIpAddress: string, endIpAddress: string }. Use these together with allowAzureServicesFirewallRule=false to remove the broad 0.0.0.0 Azure-services rule.')
param allowedClientIpRanges array = []

@minValue(7)
@maxValue(35)
@description('PostgreSQL automated backup retention in days. Default preserves the current 7-day posture.')
param backupRetentionDays int = 7

@allowed([
  'Disabled'
  'Enabled'
])
@description('Geo-redundant backup for PostgreSQL. Default Disabled preserves current posture. WARNING: this setting can only be chosen at server creation; flipping it on an existing server forces a replacement (data migration required). See docs/operations/BACKUP_RECOVERY_RUNBOOK.md before changing.')
param geoRedundantBackup string = 'Disabled'

@allowed([
  'Disabled'
  'SameZone'
  'ZoneRedundant'
])
@description('High availability mode for PostgreSQL. Default Disabled preserves current posture. HA requires General Purpose or Memory Optimized SKU; the current Standard_B1ms Burstable SKU does not support it.')
param highAvailabilityMode string = 'Disabled'

@secure()
param administratorPassword string = ''

resource postgresServer 'Microsoft.DBforPostgreSQL/flexibleServers@2023-12-01-preview' = if (createPostgres) {
  name: postgresServerName
  location: location
  tags: tags
  sku: {
    name: 'Standard_B1ms'
    tier: 'Burstable'
  }
  properties: {
    version: '16'
    administratorLogin: administratorLogin
    administratorLoginPassword: administratorPassword
    authConfig: {
      activeDirectoryAuth: 'Disabled'
      passwordAuth: 'Enabled'
    }
    backup: {
      backupRetentionDays: backupRetentionDays
      geoRedundantBackup: geoRedundantBackup
    }
    highAvailability: {
      mode: highAvailabilityMode
    }
    storage: {
      storageSizeGB: 32
    }
  }
}

resource patchForgeDatabase 'Microsoft.DBforPostgreSQL/flexibleServers/databases@2023-12-01-preview' = if (createPostgres) {
  name: databaseName
  parent: postgresServer
  properties: {
    charset: 'UTF8'
    collation: 'en_US.utf8'
  }
}

resource allowAzureServices 'Microsoft.DBforPostgreSQL/flexibleServers/firewallRules@2023-12-01-preview' = if (createPostgres && allowAzureServicesFirewallRule) {
  name: 'AllowAzureServices'
  parent: postgresServer
  properties: {
    startIpAddress: '0.0.0.0'
    endIpAddress: '0.0.0.0'
  }
}

resource allowedClientRules 'Microsoft.DBforPostgreSQL/flexibleServers/firewallRules@2023-12-01-preview' = [for range in allowedClientIpRanges: if (createPostgres) {
  name: range.name
  parent: postgresServer
  properties: {
    startIpAddress: range.startIpAddress
    endIpAddress: range.endIpAddress
  }
}]

output databaseHost string = createPostgres ? '${postgresServerName}.postgres.database.azure.com' : 'local-json-storage-placeholder'
output databaseName string = databaseName
output databaseMode string = createPostgres ? 'postgresql-flexible-server' : 'placeholder'
