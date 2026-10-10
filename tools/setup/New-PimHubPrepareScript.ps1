#Requires -Version 5.1

<#
.SYNOPSIS
    Writes the script the hub network owner runs before (or during) a private PIM Manager installation: the hub side of the peering with exactly the name PIM setup looks for, optionally the rights for the deploy identity, and a check of both sides. It only writes a file; nothing in Azure is touched.

.DESCRIPTION
    Use it when the hub VNet belongs to another team or another subscription. Hand the written file to the hub owner; they run
    it (Azure Cloud Shell is fine); then continue the PIM install. Setup writes the same script by itself when it cannot
    create the hub side of the peering.
    The written file (prepare-hub-<name>.ps1) creates the hub-side peering, and -- only when -DeployPrincipalObjectId is
    given -- grants that identity Network Contributor on the hub VNet (and Private DNS Zone Contributor on -DnsResourceGroup
    when that is given). It never deletes anything and is safe to run twice.
    -HubSubscriptionId is optional: empty = the hub is in the same subscription as the PIM network (-SpokeSubscriptionId).

.EXAMPLE
    ./New-PimHubPrepareScript.ps1 -SpokeSubscriptionId <pim-sub> -SpokeResourceGroup rg-pim-prod -SpokeVnetName vnet-pim-prod `
        -HubSubscriptionId <hub-sub> -HubResourceGroup rg-connectivity -HubVnetName vnet-hub -DeployPrincipalObjectId <object id>

.EXAMPLE
    # preview: the file name and what the hub owner's script will do; nothing is written
    ./New-PimHubPrepareScript.ps1 -SpokeSubscriptionId <pim-sub> -SpokeResourceGroup rg-pim-prod -SpokeVnetName vnet-pim-prod `
        -HubResourceGroup rg-connectivity -HubVnetName vnet-hub -WhatIf

.LINK
    https://invardia.com/docs/pim/scripts/New-PimHubPrepareScript/
#>
[CmdletBinding(SupportsShouldProcess)]
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
. (Join-Path $PSScriptRoot '..\..\engine\_shared\PIM-Reachability.ps1')
. (Join-Path $PSScriptRoot '_PimScriptDoc.ps1')
$null = Start-PimScriptRun -Script 'New-PimHubPrepareScript'
try {
    $r = New-PimHubPrepareScript -SpokeVnetName $SpokeVnetName -SpokeResourceGroup $SpokeResourceGroup -SpokeSubscriptionId $SpokeSubscriptionId `
            -HubVnetName $HubVnetName -HubResourceGroup $HubResourceGroup -HubSubscriptionId $HubSubscriptionId `
            -DeployPrincipalObjectId $DeployPrincipalObjectId -DeployPrincipalType $DeployPrincipalType -DnsResourceGroup $DnsResourceGroup -EnvironmentLabel $EnvironmentLabel
    if (-not $r.ok) { throw "no script written: $($r.reason)" }
    $path = Join-Path $OutDirectory $r.fileName
    $what = "the hub owner's script: peering '$($r.hubPeeringName)' on '$HubVnetName'$(if ("$DeployPrincipalObjectId".Trim()) { ' + rights for the deploy identity' })"
    if ($PSCmdlet.ShouldProcess($path, "write $what")) {
        [IO.File]::WriteAllText($path, $r.text, (New-Object Text.UTF8Encoding $false))
        Write-Host "Written: $path" -ForegroundColor Green
        Write-Host "Give it to the owner of '$HubVnetName'. It creates the peering '$($r.hubPeeringName)' on the hub$(if ($DeployPrincipalObjectId) { ' and grants the deploy identity its rights' }), then shows both sides."
        $path
    } else {
        Write-Host "preview only -- nothing was written ($($r.fileName), $(@($r.text -split "`n").Count) lines)"
    }
} finally { Stop-PimScriptRun -Script 'New-PimHubPrepareScript' }
