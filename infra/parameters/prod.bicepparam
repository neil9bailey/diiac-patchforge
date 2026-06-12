using '../bicep/main.bicep'

param location = 'uksouth'
param resourceGroupName = 'rg-diiac-patchforge-prod'
param environmentName = 'prod'
param bridgeExternalIngress = true
param deployContainerApps = true
param createPostgres = false
param postgresAdministratorLogin = 'patchforgeadmin'
param imageTag = 'bootstrap'
param openAiAgentEnabled = true
param openAiModel = 'gpt-5.4'
param openAiApiKeySecretName = 'diiac-openai-api-key'
param openAiApiKeyVaultUri = 'https://kv-diiac-itservices.vault.azure.net/'
param acrSku = 'Basic'
param tags = {
  product: 'DIIaC PatchForge'
  owner: 'DIIaC'
  environment: 'prod'
  managedBy: 'bicep'
  boundary: 'governance-only'
}
