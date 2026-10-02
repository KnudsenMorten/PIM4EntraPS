#Requires -Version 5.1
<#
.SYNOPSIS
    REQ 92 NET-2 -- rebuild a PIM environment that was built EXTERNAL so it is INTERNAL-ONLY (reachable only from its
    VNet and the networks peered to it). PLANS by default; changes nothing without -Apply.

.DESCRIPTION
    The Container Apps environment's internal-only flag is IMMUTABLE, so the only way to change it is to delete and
    recreate the environment. This is the SAME tool as Rebuild-PimEnvExternal.ps1 run in the other direction: a fresh
    capture of the live environment, delete the jobs / Manager / environment, recreate it --internal-only true on the
    SAME subnet and workspace, restore the Manager (ingress internal first) and every job from the capture and DIFF
    them, repair the identity-keyed state (SQL contained users, Azure roles, and with -HostingAccessTenantId the Graph
    app roles), attach Easy Auth, then publish the private DNS zone for the new default domain (apex + wildcard A ->
    the environment's static IP) linked to the spoke VNet and every -HubVnetId.

    Nothing that holds data is touched (SQL, registry, Key Vault, storage, VNet, identities, workspace) -- the
    keep-list is recorded before and re-verified after, exactly as on the external path.

    What it does NOT change on its own, and says so in the plan (REQ 92 NET-3):
      * the registry's public network access -- only with -LockRegistry, and refused without a private endpoint
        (the environment pulls images and the in-cloud updater builds over it);
      * a SQL private endpoint -- New-PimHostingPrerequisites.ps1 -SqlPrivateEndpoint adds it.

.EXAMPLE
    # 1. plan (writes a capture, changes nothing)
    ./Rebuild-PimEnvInternal.ps1 -Tag ab123 -SubscriptionId <sub> -ResourceGroup rg-automateit-ab123 `
        -HubVnetId /subscriptions/<hubsub>/resourceGroups/<hubrg>/providers/Microsoft.Network/virtualNetworks/<hub>

    # 2. do it
    ./Rebuild-PimEnvInternal.ps1 ... -EasyAuthTenantId <tenant> -HostingAccessTenantId <tenant> `
        -HostingAccessClientId <cert SPN> -HostingAccessCertThumbprint <thumb> -SqlServer <server> -Apply
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Tag,
    [Parameter(Mandatory)][string]$SubscriptionId,
    [Parameter(Mandatory)][string]$ResourceGroup,
    [string]$EnvName = 'cae-pim',
    [string]$ManagerApp = 'ca-pim-manager',
    [string]$CaptureDir,
    [string]$EasyAuthTenantId,
    [string]$AzureConfigDir,
    [switch]$SkipEasyAuth,
    [switch]$ResumeFromCapture,
    [int]$DeleteTimeoutSeconds = 2700,
    [string]$SqlServer,
    [string]$SqlDatabase = 'PimPlatform',
    [string]$SqlAdminClientId,
    [string]$SqlAdminClientSecret,
    [string]$SqlAdminCertThumbprint,
    [switch]$SkipIdentityRepair,
    [string[]]$EasyAuthAllowedPrincipals = @(),
    [switch]$EasyAuthAllowAllTenantUsers,
    [string[]]$HubVnetId = @(),
    [string]$PrivateDnsResourceGroup,
    [switch]$LockRegistry,
    [string]$HostingAccessTenantId,
    [string]$HostingAccessClientId,
    [string]$HostingAccessCertThumbprint,
    [switch]$Apply
)
$ErrorActionPreference = 'Stop'
$p = @{} + $PSBoundParameters
$p['ToExposure'] = 'Internal'
& (Join-Path $PSScriptRoot 'Rebuild-PimEnvExternal.ps1') @p
