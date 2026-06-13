// PIM Manager -- 24/7 hosted on App Service for Containers, locked down.
// Linux App Service plan + Web App for Containers, system-assigned Managed
// Identity (-> Azure SQL over the SQL Private Endpoint, no secret), VNet
// integration for OUTBOUND, a Private Endpoint for INBOUND (private-only -- the
// app manages tier-0), and Entra Easy Auth in front. The per-session token is
// still required on /api (defense in depth). The LOCAL loopback edition remains
// the break-glass path if this app plan is down.
//
//   az deployment group create -g <rg> -f main.bicep -p @main.parameters.json

targetScope = 'resourceGroup'

param location string = resourceGroup().location
param appName string
param planName string = '${appName}-plan'

@description('Container image, e.g. <acr>.azurecr.io/pim-manager:1.0.0')
param containerImage string
@description('ACR login server, e.g. <acr>.azurecr.io')
param acrLoginServer string

@description('Subnet (delegated to Microsoft.Web/serverFarms) for OUTBOUND VNet integration.')
param vnetIntegrationSubnetId string
@description('Subnet for the INBOUND private endpoint.')
param privateEndpointSubnetId string
@description('VNet id for the private DNS zone link.')
param vnetId string

@description('Entra app registration (client) id for Easy Auth.')
param easyAuthClientId string

@description('Azure SQL server FQDN (passwordless MI auth) + database.')
param sqlServerFqdn string
param sqlDatabaseName string = 'PIM4EntraPS'

resource plan 'Microsoft.Web/serverfarms@2023-12-01' = {
  name: planName
  location: location
  sku: { name: 'P1v3', tier: 'PremiumV3' }   // PremiumV3: VNet integration + private endpoints + always-on
  kind: 'linux'
  properties: { reserved: true }
}

resource app 'Microsoft.Web/sites@2023-12-01' = {
  name: appName
  location: location
  kind: 'app,linux,container'
  identity: { type: 'SystemAssigned' }
  properties: {
    serverFarmId: plan.id
    httpsOnly: true
    publicNetworkAccess: 'Disabled'                 // inbound private-only
    virtualNetworkSubnetId: vnetIntegrationSubnetId // outbound -> SQL PE
    siteConfig: {
      linuxFxVersion: 'DOCKER|${containerImage}'
      alwaysOn: true
      ftpsState: 'Disabled'
      minTlsVersion: '1.2'
      vnetRouteAllEnabled: true
      acrUseManagedIdentityCreds: true
      appSettings: [
        { name: 'DOCKER_REGISTRY_SERVER_URL', value: 'https://${acrLoginServer}' }
        { name: 'WEBSITES_PORT', value: '8080' }
        { name: 'PIM_HOSTED', value: '1' }
        { name: 'PIM_StorageBackend', value: 'sql' }
        { name: 'PIM_SqlServer', value: sqlServerFqdn }
        { name: 'PIM_SqlDatabase', value: sqlDatabaseName }
      ]
    }
  }
}

// Entra Easy Auth -- require authentication; unauthenticated -> 401 (the app also
// fails closed if the principal header is missing).
resource auth 'Microsoft.Web/sites/config@2023-12-01' = {
  parent: app
  name: 'authsettingsV2'
  properties: {
    globalValidation: {
      requireAuthentication: true
      unauthenticatedClientAction: 'Return401'
    }
    identityProviders: {
      azureActiveDirectory: {
        enabled: true
        registration: {
          clientId: easyAuthClientId
          openIdIssuer: '${environment().authentication.loginEndpoint}${tenant().tenantId}/v2.0'
        }
        validation: { allowedAudiences: [ 'api://${easyAuthClientId}' ] }
      }
    }
    login: { tokenStore: { enabled: true } }
  }
}

// Private Endpoint for INBOUND (private-only) + private DNS.
resource pe 'Microsoft.Network/privateEndpoints@2023-09-01' = {
  name: '${appName}-pe'
  location: location
  properties: {
    subnet: { id: privateEndpointSubnetId }
    privateLinkServiceConnections: [
      {
        name: '${appName}-plsc'
        properties: { privateLinkServiceId: app.id, groupIds: [ 'sites' ] }
      }
    ]
  }
}

resource dnsZone 'Microsoft.Network/privateDnsZones@2020-06-01' = {
  name: 'privatelink.azurewebsites.net'
  location: 'global'
}
resource dnsLink 'Microsoft.Network/privateDnsZones/virtualNetworkLinks@2020-06-01' = {
  parent: dnsZone
  name: '${appName}-vnetlink'
  location: 'global'
  properties: { registrationEnabled: false, virtualNetwork: { id: vnetId } }
}
resource peDnsGroup 'Microsoft.Network/privateEndpoints/privateDnsZoneGroups@2023-09-01' = {
  parent: pe
  name: 'default'
  properties: {
    privateDnsZoneConfigs: [ { name: 'web', properties: { privateDnsZoneId: dnsZone.id } } ]
  }
}

output appPrincipalId string = app.identity.principalId
output defaultHostName string = app.properties.defaultHostName
@description('Internal URL (resolves to the private endpoint inside the VNet).')
output internalUrl string = 'https://${app.properties.defaultHostName}'
