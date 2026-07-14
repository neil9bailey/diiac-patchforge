using '../bicep/main.bicep'

param location = 'uksouth'
param resourceGroupName = 'rg-diiac-patchforge-prod'
param environmentName = 'prod'
param bridgeExternalIngress = true
param deployContainerApps = true
param postgresMode = 'existing'
param postgresAdministratorLogin = 'patchforgeadmin'
param imageTag = 'pfaz-modern-ui-20260711-907995f'
param sourceCommitSha = '907995fdf1ea290a7e551463e461af8a884cf44c'
param productBaseline = 'PF-AZ-MODERN-UI-20260711'
param reportContextVersion = 'patchforge-report-context.pfaz-modern-ui-20260711.v1'
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
