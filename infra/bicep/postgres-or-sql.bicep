targetScope = 'resourceGroup'

param location string = resourceGroup().location
param tags object = {}
@description('PostgreSQL lifecycle mode: disabled, existing, or create.')
@allowed([
  'disabled'
  'existing'
  'create'
])
param postgresMode string = 'disabled'
param postgresServerName string
param databaseName string = 'patchforge_prod'
param administratorLogin string = 'patchforgeadmin'
param allowAzureServicesFirewallRule bool = true

@secure()
param administratorPassword string = ''

var createPostgres = postgresMode == 'create'
var referenceExistingPostgres = postgresMode == 'existing'

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
      backupRetentionDays: 7
      geoRedundantBackup: 'Disabled'
    }
    highAvailability: {
      mode: 'Disabled'
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

resource existingPostgresServer 'Microsoft.DBforPostgreSQL/flexibleServers@2023-12-01-preview' existing = if (referenceExistingPostgres) {
  name: postgresServerName
}

resource existingPatchForgeDatabase 'Microsoft.DBforPostgreSQL/flexibleServers/databases@2023-12-01-preview' existing = if (referenceExistingPostgres) {
  name: databaseName
  parent: existingPostgresServer
}

output databaseHost string = createPostgres
  ? '${postgresServerName}.postgres.database.azure.com'
  : referenceExistingPostgres
    ? existingPostgresServer!.properties.fullyQualifiedDomainName
    : 'local-json-storage-placeholder'
output databaseName string = databaseName
output databaseMode string = createPostgres
  ? 'managed-postgresql-flexible-server'
  : referenceExistingPostgres
    ? 'existing-postgresql-flexible-server'
    : 'disabled'
output databaseResourceId string = createPostgres
  ? patchForgeDatabase.id
  : referenceExistingPostgres
    ? existingPatchForgeDatabase!.id
    : ''
output databaseCharset string = createPostgres
  ? 'UTF8'
  : referenceExistingPostgres
    ? existingPatchForgeDatabase!.properties.charset
    : ''
