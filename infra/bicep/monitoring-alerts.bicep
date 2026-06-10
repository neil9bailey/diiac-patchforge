targetScope = 'resourceGroup'

param location string = resourceGroup().location
param tags object = {}

@description('Email address that receives PatchForge operational alerts.')
param alertEmail string

@description('Action group resource name.')
param actionGroupName string = 'ag-patchforge-ops-prod'

@description('Container App names that receive replica restart alerts. Apps are expected to exist in this resource group.')
param containerAppNames array = []

@description('PostgreSQL Flexible Server name for CPU and storage alerts. Leave empty to skip database alerts.')
param postgresServerName string = ''

@description('Log Analytics workspace resource id backing the optional Application Insights availability test.')
param logAnalyticsWorkspaceId string = ''

@description('Whether to create an Application Insights availability (standard web) test against the public API health endpoint. Requires logAnalyticsWorkspaceId.')
param enableAvailabilityTest bool = false

@description('URL probed by the optional availability test.')
param availabilityTestUrl string = 'https://api.patchforge.diiac.io/health'

@description('Replica restart count threshold per app over the 15-minute alert window.')
param restartCountThreshold int = 3

resource actionGroup 'Microsoft.Insights/actionGroups@2023-01-01' = {
  name: actionGroupName
  location: 'global'
  tags: tags
  properties: {
    groupShortName: 'pf-ops'
    enabled: true
    emailReceivers: [
      {
        name: 'patchforge-ops-email'
        emailAddress: alertEmail
        useCommonAlertSchema: true
      }
    ]
  }
}

resource containerAppRestartAlerts 'Microsoft.Insights/metricAlerts@2018-03-01' = [for appName in containerAppNames: {
  name: 'alert-${appName}-restarts'
  location: 'global'
  tags: tags
  properties: {
    description: 'PatchForge Container App ${appName} replica restarts exceeded ${restartCountThreshold} in 15 minutes.'
    severity: 2
    enabled: true
    scopes: [
      resourceId('Microsoft.App/containerApps', appName)
    ]
    evaluationFrequency: 'PT5M'
    windowSize: 'PT15M'
    criteria: {
      'odata.type': 'Microsoft.Azure.Monitor.SingleResourceMultipleMetricCriteria'
      allOf: [
        {
          criterionType: 'StaticThresholdCriterion'
          name: 'ReplicaRestarts'
          metricNamespace: 'Microsoft.App/containerApps'
          metricName: 'RestartCount'
          operator: 'GreaterThan'
          threshold: restartCountThreshold
          timeAggregation: 'Maximum'
        }
      ]
    }
    actions: [
      {
        actionGroupId: actionGroup.id
      }
    ]
  }
}]

resource postgresCpuAlert 'Microsoft.Insights/metricAlerts@2018-03-01' = if (!empty(postgresServerName)) {
  name: 'alert-${postgresServerName}-cpu'
  location: 'global'
  tags: tags
  properties: {
    description: 'PatchForge PostgreSQL CPU above 80 percent for 15 minutes.'
    severity: 2
    enabled: true
    scopes: [
      resourceId('Microsoft.DBforPostgreSQL/flexibleServers', postgresServerName)
    ]
    evaluationFrequency: 'PT5M'
    windowSize: 'PT15M'
    criteria: {
      'odata.type': 'Microsoft.Azure.Monitor.SingleResourceMultipleMetricCriteria'
      allOf: [
        {
          criterionType: 'StaticThresholdCriterion'
          name: 'CpuPercent'
          metricNamespace: 'Microsoft.DBforPostgreSQL/flexibleServers'
          metricName: 'cpu_percent'
          operator: 'GreaterThan'
          threshold: 80
          timeAggregation: 'Average'
        }
      ]
    }
    actions: [
      {
        actionGroupId: actionGroup.id
      }
    ]
  }
}

resource postgresStorageAlert 'Microsoft.Insights/metricAlerts@2018-03-01' = if (!empty(postgresServerName)) {
  name: 'alert-${postgresServerName}-storage'
  location: 'global'
  tags: tags
  properties: {
    description: 'PatchForge PostgreSQL storage above 80 percent. Plan a storage increase before the server becomes read-only.'
    severity: 1
    enabled: true
    scopes: [
      resourceId('Microsoft.DBforPostgreSQL/flexibleServers', postgresServerName)
    ]
    evaluationFrequency: 'PT5M'
    windowSize: 'PT15M'
    criteria: {
      'odata.type': 'Microsoft.Azure.Monitor.SingleResourceMultipleMetricCriteria'
      allOf: [
        {
          criterionType: 'StaticThresholdCriterion'
          name: 'StoragePercent'
          metricNamespace: 'Microsoft.DBforPostgreSQL/flexibleServers'
          metricName: 'storage_percent'
          operator: 'GreaterThan'
          threshold: 80
          timeAggregation: 'Average'
        }
      ]
    }
    actions: [
      {
        actionGroupId: actionGroup.id
      }
    ]
  }
}

resource availabilityAppInsights 'Microsoft.Insights/components@2020-02-02' = if (enableAvailabilityTest && !empty(logAnalyticsWorkspaceId)) {
  name: 'appi-patchforge-availability-prod'
  location: location
  tags: tags
  kind: 'web'
  properties: {
    Application_Type: 'web'
    WorkspaceResourceId: logAnalyticsWorkspaceId
  }
}

resource availabilityWebTest 'Microsoft.Insights/webtests@2022-06-15' = if (enableAvailabilityTest && !empty(logAnalyticsWorkspaceId)) {
  name: 'webtest-patchforge-api-health'
  location: location
  tags: union(tags, {
    'hidden-link:${availabilityAppInsights!.id}': 'Resource'
  })
  kind: 'standard'
  properties: {
    SyntheticMonitorId: 'webtest-patchforge-api-health'
    Name: 'PatchForge API health availability'
    Description: 'Probes the public PatchForge API health endpoint every five minutes.'
    Enabled: true
    Frequency: 300
    Timeout: 30
    Kind: 'standard'
    RetryEnabled: true
    Locations: [
      {
        Id: 'emea-gb-db3-azr'
      }
      {
        Id: 'emea-nl-ams-azr'
      }
      {
        Id: 'emea-fr-pra-edge'
      }
    ]
    Request: {
      RequestUrl: availabilityTestUrl
      HttpVerb: 'GET'
      ParseDependentRequests: false
    }
    ValidationRules: {
      ExpectedHttpStatusCode: 200
      SSLCheck: true
      SSLCertRemainingLifetimeCheck: 7
    }
  }
}

resource availabilityAlert 'Microsoft.Insights/metricAlerts@2018-03-01' = if (enableAvailabilityTest && !empty(logAnalyticsWorkspaceId)) {
  name: 'alert-patchforge-api-availability'
  location: 'global'
  tags: tags
  properties: {
    description: 'PatchForge public API health endpoint failed availability checks from multiple locations.'
    severity: 1
    enabled: true
    scopes: [
      availabilityWebTest!.id
      availabilityAppInsights!.id
    ]
    evaluationFrequency: 'PT5M'
    windowSize: 'PT5M'
    criteria: {
      'odata.type': 'Microsoft.Azure.Monitor.WebtestLocationAvailabilityCriteria'
      webTestId: availabilityWebTest!.id
      componentId: availabilityAppInsights!.id
      failedLocationCount: 2
    }
    actions: [
      {
        actionGroupId: actionGroup.id
      }
    ]
  }
}

output actionGroupId string = actionGroup.id
