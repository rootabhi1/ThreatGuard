// ============================================================================
//  Threat Modeler — Bicep deployment for Azure App Service for Containers
//
//  Deploys: Resource Group (use the one you target with az deployment group),
//           ACR, App Service Plan (Linux), Web App for Containers, role
//           assignment so the Web App can pull from ACR via managed identity.
//
//  This template assumes the image already exists in ACR. Build it first:
//      az acr build -t threat-modeler:v1 -r <acrName> -f Dockerfile .
//
//  Deploy:
//      az group create -n threat-modeler-rg -l eastus
//      az deployment group create \
//        -g threat-modeler-rg \
//        -f deploy/azure/main.bicep \
//        -p location=eastus appName=threat-modeler-prod \
//           acrName=tmacrXXXXXX imageTag=v1 \
//           anthropicApiKey='sk-ant-...'
// ============================================================================

@description('Azure region for all resources.')
param location string = resourceGroup().location

@description('Globally unique App Service name. Forms the URL <appName>.azurewebsites.net.')
@minLength(2)
@maxLength(60)
param appName string

@description('Globally unique ACR name (5-50 lowercase alphanumeric).')
@minLength(5)
@maxLength(50)
param acrName string

@description('App Service Plan name.')
param planName string = '${appName}-plan'

@description('App Service Plan SKU. B1 ~$13/mo, P1V3 production-grade.')
@allowed([
  'B1'
  'B2'
  'B3'
  'P0V3'
  'P1V3'
  'P2V3'
])
param planSku string = 'B1'

@description('Image name in the registry.')
param imageName string = 'threat-modeler'

@description('Image tag to deploy.')
param imageTag string = 'v1'

@description('Optional Anthropic API key for LLM-enriched threat detail. Leave empty to disable.')
@secure()
param anthropicApiKey string = ''

// ---- Container Registry ---------------------------------------------------
resource acr 'Microsoft.ContainerRegistry/registries@2023-07-01' = {
  name: acrName
  location: location
  sku: {
    name: 'Basic'
  }
  properties: {
    adminUserEnabled: false
  }
}

// ---- App Service Plan -----------------------------------------------------
resource plan 'Microsoft.Web/serverfarms@2023-12-01' = {
  name: planName
  location: location
  kind: 'linux'
  sku: {
    name: planSku
  }
  properties: {
    reserved: true   // required for Linux
  }
}

// ---- Web App for Containers ----------------------------------------------
resource webapp 'Microsoft.Web/sites@2023-12-01' = {
  name: appName
  location: location
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    serverFarmId: plan.id
    httpsOnly: true
    siteConfig: {
      linuxFxVersion: 'DOCKER|${acr.properties.loginServer}/${imageName}:${imageTag}'
      acrUseManagedIdentityCreds: true
      alwaysOn: planSku != 'F1' && planSku != 'B1'   // B1 supports it but defaults off — set explicitly
      ftpsState: 'Disabled'
      http20Enabled: true
      minTlsVersion: '1.2'
      appSettings: concat([
        {
          name: 'WEBSITES_PORT'
          value: '8000'
        }
        {
          name: 'PORT'
          value: '8000'
        }
        {
          name: 'HOST'
          value: '0.0.0.0'
        }
        {
          name: 'WEBSITES_CONTAINER_START_TIME_LIMIT'
          value: '600'
        }
        {
          name: 'DOCKER_REGISTRY_SERVER_URL'
          value: 'https://${acr.properties.loginServer}'
        }
      ], !empty(anthropicApiKey) ? [{
        name: 'ANTHROPIC_API_KEY'
        value: anthropicApiKey
      }] : [])
    }
  }
}

// ---- Role assignment: Web App's managed identity → AcrPull on ACR --------
// Built-in role definition ID for AcrPull
var acrPullRoleId = subscriptionResourceId(
  'Microsoft.Authorization/roleDefinitions',
  '7f951dda-4ed3-4680-a7ca-43fe172d538d'
)

resource acrPullRoleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: acr
  name: guid(acr.id, webapp.id, 'AcrPull')
  properties: {
    principalId: webapp.identity.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: acrPullRoleId
  }
}

// ---- Outputs --------------------------------------------------------------
output appUrl string = 'https://${webapp.properties.defaultHostName}'
output acrLoginServer string = acr.properties.loginServer
output webappName string = webapp.name
output principalId string = webapp.identity.principalId
