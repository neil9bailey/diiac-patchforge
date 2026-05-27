targetScope = 'resourceGroup'

param location string = resourceGroup().location
param tags object = {}
param environmentName string
param logAnalyticsCustomerId string

@secure()
param logAnalyticsSharedKey string

param acrLoginServer string
param imageTag string = 'bootstrap'
param bridgeExternalIngress bool = true
param managedIdentityResourceIds object
param managedIdentityClientIds object
param storageAccountName string
param keyVaultUri string
param databaseHost string
param databaseName string
param databaseUser string = 'patchforgeadmin'
param databasePasswordSecretName string = 'patchforge-postgres-admin-password'
param storageMode string = 'postgresql'
param defaultTenant string = 'diiac.io'
param entraTenantId string = '67f8be6c-07da-4a7c-bb0a-d6bcb38cd6da'
param entraAudience string = 'api://ec30b0eb-cfc4-48cc-a5f2-2a1345d96736'
param authRequired bool = true
param keyVaultSigningKeyId string = ''
param runtimeInternalUrl string = 'http://ca-patchforge-runtime-prod'
param allowedOrigins string = 'https://patchforge.diiac.io'
param uiCustomDomain string = 'patchforge.diiac.io'
param apiCustomDomain string = 'api.patchforge.diiac.io'
param uiManagedCertificateName string = 'mc-acae-diiac-pat-patchforge-diiac-9158'
param apiManagedCertificateName string = 'mc-acae-diiac-pat-api-patchforge-d-1628'
param environmentLabel string = 'prod'

var commonEnv = [
  {
    name: 'APP_ENV'
    value: 'production'
  }
  {
    name: 'PATCHFORGE_ENV'
    value: 'production'
  }
  {
    name: 'PATCHFORGE_ENVIRONMENT'
    value: environmentLabel
  }
  {
    name: 'PATCHFORGE_BOUNDARY'
    value: 'governance-only-no-scanner-no-exploit-no-deployment'
  }
  {
    name: 'PATCHFORGE_STORAGE_ACCOUNT'
    value: storageAccountName
  }
  {
    name: 'PATCHFORGE_DEFAULT_TENANT'
    value: defaultTenant
  }
  {
    name: 'PATCHFORGE_KEYVAULT_URI'
    value: keyVaultUri
  }
  {
    name: 'PATCHFORGE_DATABASE_HOST'
    value: databaseHost
  }
  {
    name: 'PATCHFORGE_DATABASE_NAME'
    value: databaseName
  }
  {
    name: 'PATCHFORGE_DATABASE_USER'
    value: databaseUser
  }
  {
    name: 'PATCHFORGE_DATABASE_PASSWORD_SECRET_NAME'
    value: databasePasswordSecretName
  }
  {
    name: 'PATCHFORGE_STORAGE_MODE'
    value: storageMode
  }
  {
    name: 'PATCHFORGE_ENTRA_TENANT_ID'
    value: entraTenantId
  }
  {
    name: 'PATCHFORGE_ENTRA_AUDIENCE'
    value: entraAudience
  }
  {
    name: 'PATCHFORGE_AUTH_REQUIRED'
    value: string(authRequired)
  }
  {
    name: 'PATCHFORGE_KEYVAULT_SIGNING_KEY_ID'
    value: keyVaultSigningKeyId
  }
  {
    name: 'PATCHFORGE_RUNTIME_URL'
    value: runtimeInternalUrl
  }
  {
    name: 'PATCHFORGE_ALLOWED_ORIGINS'
    value: allowedOrigins
  }
  {
    name: 'PATCHFORGE_AGENT_INTAKE_ENABLED'
    value: 'true'
  }
  {
    name: 'PATCHFORGE_PUBLIC_SOURCE_FEEDS_ENABLED'
    value: 'true'
  }
  {
    name: 'PATCHFORGE_WORKER_ENABLED'
    value: 'true'
  }
  {
    name: 'PATCHFORGE_SCHEDULER_ENABLED'
    value: 'true'
  }
  {
    name: 'PATCHFORGE_SCHEDULER_INTERVAL_MS'
    value: '21600000'
  }
  {
    name: 'PATCHFORGE_SCHEDULER_CISA_LIMIT'
    value: '10'
  }
  {
    name: 'PATCHFORGE_SCHEDULER_EPSS_LIMIT'
    value: '10'
  }
]

var appDefinitions = [
  {
    name: 'ca-patchforge-ui-prod'
    containerName: 'patchforge-ui'
    image: '${acrLoginServer}/diiac/patchforge-frontend:${imageTag}'
    identityId: managedIdentityResourceIds.ui
    clientId: managedIdentityClientIds.ui
    external: true
    targetPort: 8080
    cpu: json('0.5')
    memory: '1Gi'
    minReplicas: 1
    maxReplicas: 3
    role: 'frontend'
    customDomain: uiCustomDomain
    managedCertificateName: uiManagedCertificateName
  }
  {
    name: 'ca-patchforge-bridge-prod'
    containerName: 'patchforge-bridge'
    image: '${acrLoginServer}/diiac/patchforge-bridge:${imageTag}'
    identityId: managedIdentityResourceIds.bridge
    clientId: managedIdentityClientIds.bridge
    external: bridgeExternalIngress
    targetPort: 8080
    cpu: json('0.5')
    memory: '1Gi'
    minReplicas: 1
    maxReplicas: 5
    role: 'bridge-api'
    customDomain: apiCustomDomain
    managedCertificateName: apiManagedCertificateName
  }
  {
    name: 'ca-patchforge-runtime-prod'
    containerName: 'patchforge-runtime'
    image: '${acrLoginServer}/diiac/patchforge-runtime:${imageTag}'
    identityId: managedIdentityResourceIds.runtime
    clientId: managedIdentityClientIds.runtime
    external: false
    targetPort: 8080
    cpu: json('0.5')
    memory: '1Gi'
    minReplicas: 1
    maxReplicas: 3
    role: 'runtime-governance'
    customDomain: ''
    managedCertificateName: ''
  }
  {
    name: 'ca-patchforge-sra-prod'
    containerName: 'patchforge-sra'
    image: '${acrLoginServer}/diiac/patchforge-sra-agent:${imageTag}'
    identityId: managedIdentityResourceIds.sra
    clientId: managedIdentityClientIds.sra
    external: false
    targetPort: 8080
    cpu: json('0.5')
    memory: '1Gi'
    minReplicas: 0
    maxReplicas: 3
    role: 'sra-advisory-only'
    customDomain: ''
    managedCertificateName: ''
  }
  {
    name: 'ca-patchforge-worker-prod'
    containerName: 'patchforge-worker'
    image: '${acrLoginServer}/diiac/patchforge-ingest-worker:${imageTag}'
    identityId: managedIdentityResourceIds.worker
    clientId: managedIdentityClientIds.worker
    external: false
    targetPort: 8080
    cpu: json('0.5')
    memory: '1Gi'
    minReplicas: 0
    maxReplicas: 5
    role: 'ingest-export-worker'
    customDomain: ''
    managedCertificateName: ''
  }
  {
    name: 'ca-patchforge-scheduler-prod'
    containerName: 'patchforge-scheduler'
    image: '${acrLoginServer}/diiac/patchforge-scheduler:${imageTag}'
    identityId: managedIdentityResourceIds.worker
    clientId: managedIdentityClientIds.worker
    external: false
    targetPort: 8080
    cpu: json('0.25')
    memory: '0.5Gi'
    minReplicas: 1
    maxReplicas: 1
    role: 'scheduler'
    customDomain: ''
    managedCertificateName: ''
  }
]

resource managedEnvironment 'Microsoft.App/managedEnvironments@2023-05-01' = {
  name: environmentName
  location: location
  tags: tags
  properties: {
    appLogsConfiguration: {
      destination: 'log-analytics'
      logAnalyticsConfiguration: {
        customerId: logAnalyticsCustomerId
        sharedKey: logAnalyticsSharedKey
      }
    }
    zoneRedundant: false
  }
}

resource containerApps 'Microsoft.App/containerApps@2024-03-01' = [for app in appDefinitions: {
  name: app.name
  location: location
  tags: union(tags, {
    component: app.role
  })
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${app.identityId}': {}
    }
  }
  properties: {
    managedEnvironmentId: managedEnvironment.id
    configuration: {
      activeRevisionsMode: 'Single'
      ingress: {
        external: app.external
        targetPort: app.targetPort
        transport: 'auto'
        allowInsecure: false
        customDomains: (!empty(app.customDomain) && !empty(app.managedCertificateName)) ? [
          {
            name: app.customDomain
            bindingType: 'SniEnabled'
            certificateId: '${managedEnvironment.id}/managedCertificates/${app.managedCertificateName}'
          }
        ] : []
      }
      registries: [
        {
          server: acrLoginServer
          identity: app.identityId
        }
      ]
    }
    template: {
      containers: [
        {
          name: app.containerName
          image: app.image
          env: concat(commonEnv, [
            {
              name: 'AZURE_CLIENT_ID'
              value: app.clientId
            }
            {
              name: 'PATCHFORGE_COMPONENT'
              value: app.role
            }
          ])
          resources: {
            cpu: app.cpu
            memory: app.memory
          }
        }
      ]
      scale: {
        minReplicas: app.minReplicas
        maxReplicas: app.maxReplicas
      }
    }
  }
}]

output environmentId string = managedEnvironment.id
output containerAppNames array = [for app in appDefinitions: app.name]
