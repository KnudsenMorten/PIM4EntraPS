#requires -Version 5.1
<#
.SYNOPSIS
    DEPRECATED redirect -> Grant-PimGraphAppRoles.ps1 (pure REST, certificate auth).

.DESCRIPTION
    This was the Microsoft.Graph SDK + DEVICE-CODE admin-consent grant script. Two
    hard reasons it is retired:
      * It used Connect-MgGraph -UseDeviceCode. Device-code is BLOCKED by managed
        Conditional Access (docs/REQUIREMENTS.md §22) and is never allowed.
      * It pulled in the Microsoft.Graph SDK; the engine + setup family are pure REST.

    The canonical, cert-authenticated, module-free, NO-device-code equivalent is:

        setup/Grant-PimGraphAppRoles.ps1

    which idempotently grants the engine SPN its required Graph app-roles, authenticating
    as an ADMIN SPN by CERTIFICATE over Graph REST.

    This shim forwards the engine AppId + the requested permissions to that script. The
    old script signed the human in interactively; the REST script needs an admin SPN
    that can write appRoleAssignments, so this shim REQUIRES -AdminClientId +
    -AdminCertThumbprint (no interactive / device-code fallback).

.PARAMETER AppId
    The engine app (client) id whose SPN should receive the permissions. (Old name.)

.PARAMETER Permissions
    Graph application-permission VALUES to grant. Passed through unchanged.

.PARAMETER TenantId
    Target tenant id (required by the REST grant script).

.PARAMETER AdminClientId
    Admin SPN (Privileged Role Admin / mgmt SPN) app id used to authenticate.

.PARAMETER AdminCertThumbprint
    Thumbprint of the admin SPN's certificate in the local cert store.

.NOTES
    REST + certificate, PS 5.1-safe, no Microsoft.Graph module, NO device-code.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]   $AppId,
    [string[]]                        $Permissions,
    [Parameter(Mandatory)][string]   $TenantId,
    [Parameter(Mandatory)][string]   $AdminClientId,
    [Parameter(Mandatory)][string]   $AdminCertThumbprint
)
$ErrorActionPreference = 'Stop'
$here = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
$rest = Join-Path $here 'Grant-PimGraphAppRoles.ps1'
if (-not (Test-Path -LiteralPath $rest)) {
    throw "Pure-REST grant script not found at '$rest'. The legacy device-code/SDK script has been retired; restore Grant-PimGraphAppRoles.ps1."
}

Write-Host "[redirect] setup/Grant-PimEngineAdminConsent.ps1 (SDK + device-code) is deprecated -> Grant-PimGraphAppRoles.ps1 (REST, cert)." -ForegroundColor Yellow

$fwd = @{
    TenantId            = $TenantId
    AdminClientId       = $AdminClientId
    AdminCertThumbprint = $AdminCertThumbprint
    EngineAppId         = $AppId
}
if ($Permissions) { $fwd.Permissions = $Permissions }

& $rest @fwd
