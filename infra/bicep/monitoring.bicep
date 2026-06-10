targetScope = 'resourceGroup'

param location string = resourceGroup().location
param tags object = {}
param logAnalyticsWorkspaceName string

@minValue(30)
@maxValue(730)
@description('Log Analytics workspace retention in days. Default 30 preserves current posture; maximum 730.')
param retentionInDays int = 30

resource workspace 'Microsoft.OperationalInsights/workspaces@2022-10-01' = {
  name: logAnalyticsWorkspaceName
  location: location
  tags: tags
  properties: {
    sku: {
      name: 'PerGB2018'
    }
    retentionInDays: retentionInDays
    features: {
      searchVersion: 1
      enableLogAccessUsingOnlyResourcePermissions: true
    }
  }
}

output workspaceId string = workspace.id
output workspaceCustomerId string = workspace.properties.customerId

@secure()
output workspaceSharedKey string = workspace.listKeys().primarySharedKey

