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

@description('PostgreSQL lifecycle mode: disabled for local JSON, existing to reference live resources without modifying them, or create for a new managed server.')
@allowed([
  'disabled'
  'existing'
  'create'
])
param postgresMode string = 'disabled'

@description('PostgreSQL administrator login. The password is only used when postgresMode is create.')
param postgresAdministratorLogin string = 'patchforgeadmin'

@secure()
@description('PostgreSQL administrator password. Supply securely at deployment time only.')
param postgresAdministratorPassword string = ''

@description('Container image tag used for initial container app placeholders.')
param imageTag string = 'bootstrap'

@description('Immutable source commit represented by the deployed image tag and report renderer.')
param sourceCommitSha string = 'local'

@description('Product baseline stamped into decision packs and reports.')
param productBaseline string = 'PF-LOCAL'

@description('Report context contract version stamped into decision packs and reports.')
param reportContextVersion string = 'patchforge-report-context.local.v1'

@description('PatchForge API app identifier URI used as the Entra access-token audience.')
param entraAudience string = 'api://ec30b0eb-cfc4-48cc-a5f2-2a1345d96736'

@description('Whether the Bridge/API requires Microsoft Entra bearer tokens for PatchForge API routes.')
param authRequired bool = true

@description('Key Vault key name used by the runtime for production decision-pack signing.')
param keyVaultSigningKeyName string = 'pf-pack-signing-prod'

@description('Optional Key Vault key version used by the runtime for production decision-pack signing. Leave blank to use the current key version.')
param keyVaultSigningKeyVersion string = ''

@description('Key Vault secret name containing the PostgreSQL administrator password for the bridge storage adapter.')
param postgresPasswordSecretName string = 'patchforge-postgres-admin-password'

@description('Whether the Bridge/API should enable the optional OpenAI-native advisory agent layer.')
param openAiAgentEnabled bool = false

@description('OpenAI model used by the optional Bridge/API advisory agent layer when enabled.')
param openAiModel string = 'gpt-5.4'

@description('Optional Key Vault secret name containing the OpenAI API key for the Bridge/API. Leave blank to keep OPENAI_API_KEY unset.')
param openAiApiKeySecretName string = ''

@description('Optional Key Vault URI containing the OpenAI API key secret. Leave blank to use the dedicated PatchForge Key Vault.')
param openAiApiKeyVaultUri string = ''

@description('OpenAI advisory agent request timeout in milliseconds.')
param openAiTimeoutMs int = 15000

@description('Maximum output tokens allowed for optional OpenAI advisory agent responses.')
param openAiMaxOutputTokens int = 1000

@description('Whether to add the PostgreSQL firewall rule that allows Azure services to reach the server.')
param allowAzureServicesToPostgres bool = true

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
    postgresMode: postgresMode
    postgresServerName: names.postgres
    databaseName: names.database
    administratorLogin: postgresAdministratorLogin
    administratorPassword: postgresAdministratorPassword
    allowAzureServicesFirewallRule: allowAzureServicesToPostgres
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
    databaseUser: postgresAdministratorLogin
    databasePasswordSecretName: postgresPasswordSecretName
    storageMode: database.outputs.databaseMode == 'disabled' ? 'local-json' : 'postgresql'
    entraTenantId: subscription().tenantId
    entraAudience: entraAudience
    authRequired: authRequired
    openAiAgentEnabled: openAiAgentEnabled
    openAiModel: openAiModel
    openAiApiKeySecretName: openAiApiKeySecretName
    openAiApiKeyVaultUri: openAiApiKeyVaultUri
    openAiTimeoutMs: openAiTimeoutMs
    openAiMaxOutputTokens: openAiMaxOutputTokens
    keyVaultSigningKeyId: empty(keyVaultSigningKeyVersion)
      ? '${keyVault.outputs.vaultUri}keys/${keyVaultSigningKeyName}'
      : '${keyVault.outputs.vaultUri}keys/${keyVaultSigningKeyName}/${keyVaultSigningKeyVersion}'
    environmentLabel: environmentName
    sourceCommitSha: sourceCommitSha
    productBaseline: productBaseline
    reportContextVersion: reportContextVersion
  }
}

output resourceGroup string = patchForgeResourceGroup.name
output frontendUrlPlaceholder string = 'https://patchforge.diiac.io'
output apiUrlPlaceholder string = 'https://api.patchforge.diiac.io'
output acrLoginServer string = registry.outputs.loginServer
output storageAccountName string = storage.outputs.storageAccountName
output keyVaultUri string = keyVault.outputs.vaultUri
output containerAppsEnvironmentId string = deployContainerApps ? containerApps!.outputs.environmentId : ''
