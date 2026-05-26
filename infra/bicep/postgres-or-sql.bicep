targetScope = 'resourceGroup'

param location string = resourceGroup().location
param tags object = {}
param createPostgres bool = false
param postgresServerName string
param databaseName string = 'patchforge_prod'
param administratorLogin string = 'patchforgeadmin'

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

output databaseHost string = createPostgres ? '${postgresServerName}.postgres.database.azure.com' : 'local-json-storage-placeholder'
output databaseName string = databaseName
output databaseMode string = createPostgres ? 'postgresql-flexible-server' : 'placeholder'
