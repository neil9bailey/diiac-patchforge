targetScope = 'resourceGroup'

param location string = resourceGroup().location
param tags object = {}
param identityNames object

resource uiIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: identityNames.ui
  location: location
  tags: tags
}

resource bridgeIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: identityNames.bridge
  location: location
  tags: tags
}

resource runtimeIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: identityNames.runtime
  location: location
  tags: tags
}

resource sraIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: identityNames.sra
  location: location
  tags: tags
}

resource workerIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: identityNames.worker
  location: location
  tags: tags
}

output resourceIds object = {
  ui: uiIdentity.id
  bridge: bridgeIdentity.id
  runtime: runtimeIdentity.id
  sra: sraIdentity.id
  worker: workerIdentity.id
}

output clientIds object = {
  ui: uiIdentity.properties.clientId
  bridge: bridgeIdentity.properties.clientId
  runtime: runtimeIdentity.properties.clientId
  sra: sraIdentity.properties.clientId
  worker: workerIdentity.properties.clientId
}

output principalIds object = {
  ui: uiIdentity.properties.principalId
  bridge: bridgeIdentity.properties.principalId
  runtime: runtimeIdentity.properties.principalId
  sra: sraIdentity.properties.principalId
  worker: workerIdentity.properties.principalId
}

