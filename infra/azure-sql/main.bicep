// PIM4EntraPS -- prod Azure SQL data store, locked down.
// AAD-only auth (no SQL logins), PUBLIC NETWORK ACCESS DISABLED, reachable only
// via a Private Endpoint + private DNS. The Manager/engine authenticate with a
// Managed Identity (no secret anywhere). After deploy, grant the MI a contained
// DB user with grant-mi.sql (run from a host on the VNet / via the AAD admin).
//
// Deploy (from a box that can reach the target RG):
//   az deployment group create -g <rg> -f main.bicep -p @main.parameters.json

targetScope = 'resourceGroup'

@description('Location for all resources.')
param location string = resourceGroup().location

@description('SQL logical server name (globally unique, lowercase).')
param sqlServerName string

@description('Database name.')
param databaseName string = 'PIM4EntraPS'

@description('AAD admin login (group display name or UPN) -- prefer a group.')
param aadAdminLogin string

@description('AAD admin object id (the group/user that administers the server).')
param aadAdminObjectId string

@allowed([ 'User', 'Group', 'Application' ])
@description('AAD admin principal type.')
param aadAdminPrincipalType string = 'Group'

@description('Resource id of the subnet that will host the private endpoint.')
param privateEndpointSubnetId string

@description('Resource id of the VNet to link the private DNS zone to.')
param vnetId string

@description('Database SKU (default: serverless General Purpose, 2 vCore).')
param skuName string = 'GP_S_Gen5_2'

@allowed([ 'GeneralPurpose', 'Standard', 'BasicPool' ])
param skuTier string = 'GeneralPurpose'

resource sql 'Microsoft.Sql/servers@2023-08-01-preview' = {
  name: sqlServerName
  location: location
  identity: { type: 'SystemAssigned' }
  properties: {
    version: '12.0'
    minimalTlsVersion: '1.2'
    publicNetworkAccess: 'Disabled'   // no public access -- private endpoint only
    restrictOutboundNetworkAccess: 'Disabled'
    administrators: {
      administratorType: 'ActiveDirectory'
      principalType: aadAdminPrincipalType
      login: aadAdminLogin
      sid: aadAdminObjectId
      tenantId: tenant().tenantId
      azureADOnlyAuthentication: true  // AAD-only -- no SQL logins/passwords
    }
  }
}

resource db 'Microsoft.Sql/servers/databases@2023-08-01-preview' = {
  parent: sql
  name: databaseName
  location: location
  sku: { name: skuName, tier: skuTier }
  properties: {
    zoneRedundant: false
    readScale: 'Disabled'
  }
}

// --- Private Endpoint + private DNS -------------------------------------------
resource pe 'Microsoft.Network/privateEndpoints@2023-09-01' = {
  name: '${sqlServerName}-pe'
  location: location
  properties: {
    subnet: { id: privateEndpointSubnetId }
    privateLinkServiceConnections: [
      {
        name: '${sqlServerName}-plsc'
        properties: {
          privateLinkServiceId: sql.id
          groupIds: [ 'sqlServer' ]
        }
      }
    ]
  }
}

resource dnsZone 'Microsoft.Network/privateDnsZones@2020-06-01' = {
  name: 'privatelink${environment().suffixes.sqlServerHostname}' // privatelink.database.windows.net
  location: 'global'
}

resource dnsLink 'Microsoft.Network/privateDnsZones/virtualNetworkLinks@2020-06-01' = {
  parent: dnsZone
  name: '${sqlServerName}-vnetlink'
  location: 'global'
  properties: {
    registrationEnabled: false
    virtualNetwork: { id: vnetId }
  }
}

resource peDnsGroup 'Microsoft.Network/privateEndpoints/privateDnsZoneGroups@2023-09-01' = {
  parent: pe
  name: 'default'
  properties: {
    privateDnsZoneConfigs: [
      { name: 'sql', properties: { privateDnsZoneId: dnsZone.id } }
    ]
  }
}

output sqlServerFqdn string = sql.properties.fullyQualifiedDomainName
output databaseName string = databaseName
@description('Build the passwordless connection string from this; auth is the MI token.')
output connectionStringHint string = 'Server=tcp:${sql.properties.fullyQualifiedDomainName},1433;Database=${databaseName};Encrypt=True;TrustServerCertificate=False;Connection Timeout=30'
