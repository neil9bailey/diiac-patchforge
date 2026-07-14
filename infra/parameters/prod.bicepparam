using '../bicep/main.bicep'

param location = 'uksouth'
param resourceGroupName = 'rg-diiac-patchforge-prod'
param environmentName = 'prod'
param bridgeExternalIngress = true
param containerAppScaleProfile = 'cost-optimized'
param deployContainerApps = true
param postgresMode = 'existing'
param postgresAdministratorLogin = 'patchforgeadmin'
param imageTag = 'pfaz-enterprise-20260714d-f51802d'
param sourceCommitSha = 'f51802d3544260259c252e6be88d6e7bae596868'
param productBaseline = 'PF-AZ-ENTERPRISE-AUTOMATION-20260714D'
param reportContextVersion = 'patchforge-report-context.pfaz-enterprise-20260714d.v1'
param openAiAgentEnabled = true
param searchMode = 'postgres'
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
