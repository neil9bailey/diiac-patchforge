targetScope = 'resourceGroup'

param location string = resourceGroup().location
param tags object = {}
param registryName string
@allowed([
  'Basic'
  'Standard'
  'Premium'
])
param registrySku string = 'Basic'
param pullPrincipalIds array = []

var acrPullRoleDefinitionId = subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '7f951dda-4ed3-4680-a7ca-43fe172d538d')

resource registry 'Microsoft.ContainerRegistry/registries@2025-11-01' = {
  name: registryName
  location: location
  tags: tags
  sku: {
    name: registrySku
  }
  properties: {
    adminUserEnabled: false
    anonymousPullEnabled: false
    dataEndpointEnabled: false
    encryption: {
      status: 'disabled'
    }
    policies: {
      azureADAuthenticationAsArmPolicy: {
        status: 'enabled'
      }
    }
    networkRuleBypassAllowedForTasks: false
    roleAssignmentMode: 'LegacyRegistryPermissions'
    publicNetworkAccess: 'Enabled'
  }
}

resource acrPullAssignments 'Microsoft.Authorization/roleAssignments@2022-04-01' = [for principalId in pullPrincipalIds: {
  name: guid(registry.id, principalId, acrPullRoleDefinitionId)
  scope: registry
  properties: {
    principalId: principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: acrPullRoleDefinitionId
  }
}]

output registryName string = registry.name
output loginServer string = registry.properties.loginServer
output registryId string = registry.id
