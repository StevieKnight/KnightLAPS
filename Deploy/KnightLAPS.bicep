@description('Provide the App registration application identifier.')
param ApplicationID string

@description('Provide a name for the Function App that consists of alphanumerics. Name must be globally unique in Azure and cannot start or end with a hyphen. e.g. KnightLAPS-Company')
param KnightLAPSAppName string

// Collectet infos to app service plan
@allowed([
  'Y1'
  'EP1'
  'EP2'
  'EP3'
])
@description('Select the desired App Service Plan of the Function App. Select Y1 for free consumption based deployment.')
param FunctionAppServicePlanSKU string = 'Y1'

@description('Provide a name for the 1Password Connect Server e.g. 1passwordconnect.azurewebsites.net')
param OnePasswordConnectHost string

@description('Provide a AuthToken for the 1Password Connect Server')
@secure()
param OnePasswordConnectAuthToken string


@description('Provide a name form the 1Password Vault UUID for save the passwords')
@secure()
param VaultUUID string

param location string  = resourceGroup().location

// Define variables and convert to allow character
// Please change the naming according to company specifications
var UniqueString = uniqueString(resourceGroup().id)
var KnightLAPSAppNameNoDash = replace(KnightLAPSAppName, '-', '')
var KnightLAPSAppNameNoDashUnderScore = replace(KnightLAPSAppNameNoDash, '_', '')
var StorageAccountName = toLower('sahq${take(KnightLAPSAppNameNoDashUnderScore, 15)}${take(UniqueString, 5)}')
var FunctionAppServicePlanName = 'fa-asp-${KnightLAPSAppName}'
var FunctionAppInsightsName = 'fa-ai-${KnightLAPSAppName}'
var KeyVaultAppSettingsName = 'key-${take(KnightLAPSAppName, 21)}'
var LogAnalyticsWorkspaceName = 'log-aws-${KnightLAPSAppName}'
var KeyVaultHostname = '${KeyVaultAppSettingsName}.vault.azure.net'

// Create app service plan for Function App
resource FunctionAppServicePlan 'Microsoft.Web/serverfarms@2022-03-01' = {
  name: FunctionAppServicePlanName
  location: location
  kind: 'Windows'
  sku: {
    name: FunctionAppServicePlanSKU
  }
  properties: {}
}

// Create Log Analytics workspace
resource LogAnalyticsWorkspace 'Microsoft.OperationalInsights/workspaces@2022-10-01' = {
  name: LogAnalyticsWorkspaceName
  location: location
  properties: {
    sku: {
      name: 'PerGB2018'
    }
  }
}

// Create application insights for Function App
resource FunctionAppInsightsComponents 'Microsoft.Insights/components@2020-02-02' = {
  name: FunctionAppInsightsName
  location: location
  kind: 'web'
  properties: {
    Application_Type: 'web'
    WorkspaceResourceId: LogAnalyticsWorkspace.id
  }
  tags: {'hidden-link:${resourceId('Microsoft.Web/sites', FunctionAppInsightsName)}': 'Resource' }
}

// Create storage account for Function App
resource StorageAccount 'Microsoft.Storage/storageAccounts@2021-02-01' = {
  name: StorageAccountName
  location: location
  kind: 'StorageV2'
  sku: {
    name: 'Standard_LRS'
  }
  properties: {
    supportsHttpsTrafficOnly: true
    accessTier: 'Hot'
    allowBlobPublicAccess: false
    minimumTlsVersion: 'TLS1_2'
    allowSharedKeyAccess: true
  }
}

// Create function app
resource FunctionApp 'Microsoft.Web/sites@2020-12-01' = {
  name: KnightLAPSAppName
  location: location
  kind: 'functionapp'
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    serverFarmId: FunctionAppServicePlan.id
    containerSize: 1536
    httpsOnly: true
    siteConfig: {
      ftpsState: 'Disabled'
      minTlsVersion: '1.2'
      powerShellVersion: '7.2'
      scmType: 'None'
      appSettings: [
        {
          name: 'AzureWebJobsStorage'
          value: 'DefaultEndpointsProtocol=https;AccountName=${StorageAccount.name};AccountKey=${StorageAccount.listKeys().keys[0].value}'
        }
        {
          name: 'WEBSITE_CONTENTAZUREFILECONNECTIONSTRING'
          value: 'DefaultEndpointsProtocol=https;AccountName=${StorageAccount.name};AccountKey=${StorageAccount.listKeys().keys[0].value}'
        }
        {
          name: 'WEBSITE_RUN_FROM_PACKAGE'
          value: '1'
        }
        {
          name: 'AzureWebJobsDisableHomepage'
          value: 'true'
        }
        {
          name: 'FUNCTIONS_EXTENSION_VERSION'
          value: '~4'
        }
        {
          name: 'FUNCTIONS_WORKER_PROCESS_COUNT'
          value: '3'
        }
        {
          name: 'FUNCTIONS_WORKER_RUNTIME'
          value: 'powershell'
        }
        {
          name: 'PSWorkerInProcConcurrencyUpperBound'
          value: '10'
        }
        {
          name: 'APPINSIGHTS_INSTRUMENTATIONKEY'
          value: FunctionAppInsightsComponents.properties.InstrumentationKey
        }
        {
          name: 'APPLICATIONINSIGHTS_CONNECTION_STRING'
          value: FunctionAppInsightsComponents.properties.ConnectionString
        }
        {
          name: 'OnePasswordHost'
          value: OnePasswordConnectHost
        }
        {
          name: 'OnePasswordAccessTokenName'
          value: '1PasswordToken'
        }
        {
          name: 'PWAllowedCharacters'
          value: 'abcdefghjkmnpqrtuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ!$%23456789'
        }
        {
          name: 'PWLength'
          value: '12'
        }
        {
          name: 'PWAgeinDay'
          value: '0'
        }
        {
          name: 'OnBoardingUnTrustModus'
          value: 'False'
        }
        {
          name: 'VaultUUID'
          value: VaultUUID
        }
        {
          name: 'KeyVaultHost'
          value: KeyVaultHostname
        }

      ]
    }
  }
}



// Create Key Vault for Function App application settings
resource KeyVaultAppSettings 'Microsoft.KeyVault/vaults@2022-07-01' = {
  name: KeyVaultAppSettingsName
  location: location
  properties: {
    enabledForDeployment: false
    enabledForTemplateDeployment: false
    enabledForDiskEncryption: false
    tenantId: subscription().tenantId
    accessPolicies: [
      {
        tenantId: FunctionApp.identity.tenantId
        objectId: FunctionApp.identity.principalId
        permissions: {
          secrets: [
            'get'
          ]
        }
      }
    ]
    sku: {
      name: 'standard'
      family: 'A'
    }
  }
}

// Collect Log Analytics workspace properties to be added to Key Vault as secrets
var LogAnalyticsWorkspaceId = LogAnalyticsWorkspace.properties.customerId
var LogAnalyticsWorkspaceSharedKey = LogAnalyticsWorkspace.listKeys().primarySharedKey

// Construct secrets in Key Vault
resource WorkspaceIdSecret 'Microsoft.KeyVault/vaults/secrets@2022-07-01' = {
  parent: KeyVaultAppSettings
  name: 'LogAnalyticsWorkspaceId'
  properties: {
    value: LogAnalyticsWorkspaceId
  }
}

resource SharedKeySecret 'Microsoft.KeyVault/vaults/secrets@2022-07-01' = {
  parent: KeyVaultAppSettings
  name: 'LogAnalyticsWorkspaceSharedKey'
  properties: {
    value: LogAnalyticsWorkspaceSharedKey
  }
}

resource OnePasswordAuthTokenSecret 'Microsoft.KeyVault/vaults/secrets@2022-07-01' = {
  parent: KeyVaultAppSettings
  name: '1PasswordToken'
  properties: {
    value: OnePasswordConnectAuthToken
  }
}

// Add ZipDeploy for Function App
resource FunctionAppZipDeploy 'Microsoft.Web/sites/extensions@2015-08-01' = {
  parent: FunctionApp
  name: 'ZipDeploy'
  properties: {
      packageUri: 'https://github.com/StevieKnight/KnightLAPS/blob/main/Packages/KnigthLAPS-Function-APP-current.zip'
  }
}

