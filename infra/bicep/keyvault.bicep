targetScope = 'resourceGroup'

param location string = resourceGroup().location
param tags object = {}
param keyVaultName string
param secretReaderPrincipalIds array = []
param cryptoUserPrincipalIds array = []

var keyVaultSecretsUserRoleDefinitionId = subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '4633458b-17de-408a-b874-0445c86b69e6')
var keyVaultCryptoUserRoleDefinitionId = subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '12338af0-0e69-4776-bea7-57ae8d297424')

resource vault 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: keyVaultName
  location: location
  tags: tags
  properties: {
    tenantId: subscription().tenantId
    sku: {
      family: 'A'
      name: 'standard'
    }
    enableRbacAuthorization: true
    enabledForDeployment: false
    enabledForDiskEncryption: false
    enabledForTemplateDeployment: false
    enableSoftDelete: true
    softDeleteRetentionInDays: 90
    enablePurgeProtection: true
    publicNetworkAccess: 'Enabled'
  }
}

resource secretReaderAssignments 'Microsoft.Authorization/roleAssignments@2022-04-01' = [for principalId in secretReaderPrincipalIds: {
  name: guid(vault.id, principalId, keyVaultSecretsUserRoleDefinitionId)
  scope: vault
  properties: {
    principalId: principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: keyVaultSecretsUserRoleDefinitionId
  }
}]

resource cryptoUserAssignments 'Microsoft.Authorization/roleAssignments@2022-04-01' = [for principalId in cryptoUserPrincipalIds: {
  name: guid(vault.id, principalId, keyVaultCryptoUserRoleDefinitionId)
  scope: vault
  properties: {
    principalId: principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: keyVaultCryptoUserRoleDefinitionId
  }
}]

output vaultName string = vault.name
output vaultUri string = vault.properties.vaultUri
output vaultId string = vault.id

