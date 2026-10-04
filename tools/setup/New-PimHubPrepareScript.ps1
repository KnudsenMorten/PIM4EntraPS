#Requires -Version 5.1
<#
.SYNOPSIS
    Write the script the HUB NETWORK OWNER runs before (or during) a private PIM install: the hub side of the peering with
    exactly the name PIM setup looks for, optionally the rights for the deploy identity, and a check of both sides.

.DESCRIPTION
    Use it when the hub VNet belongs to another team or another subscription. Hand the written file to the hub owner; they run
    it (Azure Cloud Shell is fine); then continue the PIM install. Nothing here touches Azure -- it only writes a file.
    Setup writes the same script by itself when it cannot create the hub side of the peering.

.EXAMPLE
    ./New-PimHubPrepareScript.ps1 -SpokeSubscriptionId <pim-sub> -SpokeResourceGroup rg-pim-prod -SpokeVnetName vnet-pim-prod `
        -HubSubscriptionId <hub-sub> -HubResourceGroup rg-connectivity -HubVnetName vnet-hub -DeployPrincipalObjectId <object id>
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$SpokeSubscriptionId,
    [Parameter(Mandatory)][string]$SpokeResourceGroup,
    [Parameter(Mandatory)][string]$SpokeVnetName,
    [Parameter(Mandatory)][string]$HubResourceGroup,
    [Parameter(Mandatory)][string]$HubVnetName,
    [string]$HubSubscriptionId = '',
    [string]$DeployPrincipalObjectId = '',
    [ValidateSet('ServicePrincipal', 'User', 'Group')][string]$DeployPrincipalType = 'ServicePrincipal',
    [string]$DnsResourceGroup = '',
    [string]$EnvironmentLabel = '',
    [string]$OutDirectory = (Get-Location).Path
)
$ErrorActionPreference = 'Stop'
. (Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'engine\_shared\PIM-Reachability.ps1')
$r = New-PimHubPrepareScript -SpokeVnetName $SpokeVnetName -SpokeResourceGroup $SpokeResourceGroup -SpokeSubscriptionId $SpokeSubscriptionId `
        -HubVnetName $HubVnetName -HubResourceGroup $HubResourceGroup -HubSubscriptionId $HubSubscriptionId `
        -DeployPrincipalObjectId $DeployPrincipalObjectId -DeployPrincipalType $DeployPrincipalType -DnsResourceGroup $DnsResourceGroup -EnvironmentLabel $EnvironmentLabel
if (-not $r.ok) { throw "no script written: $($r.reason)" }
$path = Join-Path $OutDirectory $r.fileName
[IO.File]::WriteAllText($path, $r.text, (New-Object Text.UTF8Encoding $false))
Write-Host "Written: $path" -ForegroundColor Green
Write-Host "Give it to the owner of '$HubVnetName'. It creates the peering '$($r.hubPeeringName)' on the hub$(if ($DeployPrincipalObjectId) { ' and grants the deploy identity its rights' }), then shows both sides."
$path
