targetScope = 'subscription'

@description('Azure region for PatchForge resources.')
param location string = 'uksouth'

@description('PatchForge production resource group name.')
param resourceGroupName string = 'rg-diiac-patchforge-prod'

@description('Environment name used in tags and app settings.')
param environmentName string = 'prod'

@description('Whether the bridge/API should use public ingress. Set false for private-only deployments.')
param bridgeExternalIngress bool = true

@description('Whether to deploy Container Apps. Set false for the first infrastructure pass so ACR can be created and images pushed before app revisions are created.')
param deployContainerApps bool = true

@description('Whether to create PostgreSQL Flexible Server. Keep false until a secure administrator password and network model are confirmed.')
param createPostgres bool = false

@description('PostgreSQL administrator login. Only used when createPostgres is true.')
param postgresAdministratorLogin string = 'patchforgeadmin'

@secure()
@description('PostgreSQL administrator password. Supply securely at deployment time only.')
param postgresAdministratorPassword string = ''

@description('Container image tag used for initial container app placeholders.')
param imageTag string = 'bootstrap'

@allowed([
  'Basic'
  'Standard'
  'Premium'
])
@description('Azure Container Registry SKU. Basic is used for bootstrap compatibility; raise to Premium later if private endpoint or advanced registry features are required.')
param acrSku string = 'Basic'

@description('Common tags for PatchForge resources.')
param tags object = {
  product: 'DIIaC PatchForge'
  owner: 'DIIaC'
  environment: 'prod'
  managedBy: 'bicep'
  boundary: 'governance-only'
}

var names = {
  acr: 'acrdiiacpatchforgeprod'
  containerAppsEnvironment: 'acae-diiac-patchforge-prod'
  logAnalytics: 'law-diiac-patchforge-prod'
  storage: 'stdiiacpatchforgeprod01'
  keyVault: 'kv-diiac-patchforge-prod'
  postgres: 'psql-diiac-patchforge-prod'
  database: 'patchforge_prod'
  identities: {
    ui: 'id-patchforge-ui-prod'
    bridge: 'id-patchforge-bridge-prod'
    runtime: 'id-patchforge-runtime-prod'
    sra: 'id-patchforge-sra-prod'
    worker: 'id-patchforge-worker-prod'
  }
}

resource patchForgeResourceGroup 'Microsoft.Resources/resourceGroups@2024-03-01' = {
  name: resourceGroupName
  location: location
  tags: tags
}

module identities 'identity.bicep' = {
  name: 'patchforge-identities'
  scope: patchForgeResourceGroup
  params: {
    location: location
    tags: tags
    identityNames: names.identities
  }
}

module monitoring 'monitoring.bicep' = {
  name: 'patchforge-monitoring'
  scope: patchForgeResourceGroup
  params: {
    location: location
    tags: tags
    logAnalyticsWorkspaceName: names.logAnalytics
  }
}

module registry 'container-registry.bicep' = {
  name: 'patchforge-registry'
  scope: patchForgeResourceGroup
  params: {
    location: location
    tags: tags
    registryName: names.acr
    registrySku: acrSku
    pullPrincipalIds: [
      identities.outputs.principalIds.ui
      identities.outputs.principalIds.bridge
      identities.outputs.principalIds.runtime
      identities.outputs.principalIds.sra
      identities.outputs.principalIds.worker
    ]
  }
}

module storage 'storage.bicep' = {
  name: 'patchforge-storage'
  scope: patchForgeResourceGroup
  params: {
    location: location
    tags: tags
    storageAccountName: names.storage
    blobContributorPrincipalIds: [
      identities.outputs.principalIds.bridge
      identities.outputs.principalIds.runtime
      identities.outputs.principalIds.sra
      identities.outputs.principalIds.worker
    ]
  }
}

module keyVault 'keyvault.bicep' = {
  name: 'patchforge-keyvault'
  scope: patchForgeResourceGroup
  params: {
    location: location
    tags: tags
    keyVaultName: names.keyVault
    secretReaderPrincipalIds: [
      identities.outputs.principalIds.bridge
      identities.outputs.principalIds.sra
      identities.outputs.principalIds.worker
    ]
    cryptoUserPrincipalIds: [
      identities.outputs.principalIds.runtime
    ]
  }
}

module database 'postgres-or-sql.bicep' = {
  name: 'patchforge-database'
  scope: patchForgeResourceGroup
  params: {
    location: location
    tags: tags
    createPostgres: createPostgres
    postgresServerName: names.postgres
    databaseName: names.database
    administratorLogin: postgresAdministratorLogin
    administratorPassword: postgresAdministratorPassword
  }
}

module containerApps 'container-apps.bicep' = if (deployContainerApps) {
  name: 'patchforge-container-apps'
  scope: patchForgeResourceGroup
  params: {
    location: location
    tags: tags
    environmentName: names.containerAppsEnvironment
    logAnalyticsCustomerId: monitoring.outputs.workspaceCustomerId
    logAnalyticsSharedKey: monitoring.outputs.workspaceSharedKey
    acrLoginServer: registry.outputs.loginServer
    imageTag: imageTag
    bridgeExternalIngress: bridgeExternalIngress
    managedIdentityResourceIds: identities.outputs.resourceIds
    managedIdentityClientIds: identities.outputs.clientIds
    storageAccountName: storage.outputs.storageAccountName
    keyVaultUri: keyVault.outputs.vaultUri
    databaseHost: database.outputs.databaseHost
    databaseName: names.database
    environmentLabel: environmentName
  }
}

output resourceGroup string = patchForgeResourceGroup.name
output frontendUrlPlaceholder string = 'https://patchforge.diiac.io'
output apiUrlPlaceholder string = 'https://api.patchforge.diiac.io'
output acrLoginServer string = registry.outputs.loginServer
output storageAccountName string = storage.outputs.storageAccountName
output keyVaultUri string = keyVault.outputs.vaultUri
output containerAppsEnvironmentId string = deployContainerApps ? containerApps!.outputs.environmentId : ''
