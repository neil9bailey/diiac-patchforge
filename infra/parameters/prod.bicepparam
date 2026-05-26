using '../bicep/main.bicep'

param location = 'uksouth'
param resourceGroupName = 'rg-diiac-patchforge-prod'
param environmentName = 'prod'
param bridgeExternalIngress = true
param createPostgres = false
param postgresAdministratorLogin = 'patchforgeadmin'
param imageTag = 'bootstrap'
param tags = {
  product: 'DIIaC PatchForge'
  owner: 'DIIaC'
  environment: 'prod'
  managedBy: 'bicep'
  boundary: 'governance-only'
}

