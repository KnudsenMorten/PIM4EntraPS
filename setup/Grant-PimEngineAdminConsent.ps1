#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Applications, Microsoft.Graph.Authentication
<#
.SYNOPSIS
    Idempotently grant tenant-wide admin consent to an EXISTING engine SPN
    for one or more Microsoft Graph application permissions.

.DESCRIPTION
    Companion to Install-PimEngineAppRegistration.ps1. That script creates
    a NEW app registration with the right perms. This script just adds
    missing app-role assignments to an app registration that ALREADY exists
    (e.g., the SPN was created by another bootstrap, or new perms were added
    to a later PIM4EntraPS release and the existing SPN needs to catch up).

    Idempotent: skips perms already granted; only writes the missing ones.

.PARAMETER AppId
    The application (client) id of the engine app registration.

.PARAMETER Permissions
    Array of Microsoft Graph application-permission VALUES (not Ids), e.g.
    'AdministrativeUnit.ReadWrite.All', 'PrivilegedAccess.ReadWrite.AzureADGroup'.

.PARAMETER TenantId
    Optional tenant id. If omitted, uses whatever Connect-MgGraph defaulted to.

.EXAMPLE
    .\Grant-PimEngineAdminConsent.ps1 -AppId '6b4dde9b-2aaf-480e-bc94-f21dc417f180' `
        -Permissions @('AdministrativeUnit.ReadWrite.All',
                       'PrivilegedAccess.ReadWrite.AzureADGroup')

.NOTES
    Caller must have Privileged Role Administrator (or Global Administrator).
    Uses Connect-MgGraph device-code flow by default -- works in any PS session,
    no browser required on the host (the URL + code prompt can be completed
    on any device).
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]   $AppId,
    [Parameter(Mandatory)][string[]] $Permissions,
    [string]                         $TenantId
)

$ErrorActionPreference = 'Stop'

Write-Host ""
Write-Host "Grant-PimEngineAdminConsent" -ForegroundColor Cyan
Write-Host "  Engine SPN AppId   : $AppId"
Write-Host "  Permissions to add : $($Permissions -join ', ')"
if ($TenantId) { Write-Host "  Tenant             : $TenantId" }
Write-Host ""

# --- Step 1: connect with the right caller scopes
$callerScopes = @('Application.Read.All','AppRoleAssignment.ReadWrite.All','Directory.Read.All')
Write-Host "[ 1 / 5 ] Connecting to Microsoft Graph (device-code) ..." -ForegroundColor Yellow
Write-Host "          Caller scopes: $($callerScopes -join ', ')"
Write-Host "          You will see a device-code URL + code below. Visit, enter the code, sign in as a Priv Role Admin / Global Admin."
Write-Host ""

$connectArgs = @{
    Scopes      = $callerScopes
    UseDeviceCode = $true
    NoWelcome   = $true
}
if ($TenantId) { $connectArgs.TenantId = $TenantId }
Connect-MgGraph @connectArgs

$ctx = Get-MgContext
Write-Host ""
Write-Host "[ 1 / 5 ] OK -- connected as $($ctx.Account) to tenant $($ctx.TenantId)" -ForegroundColor Green

# --- Step 2: resolve the engine SPN
Write-Host ""
Write-Host "[ 2 / 5 ] Resolving engine SPN by AppId ..." -ForegroundColor Yellow
$engineSpn = Get-MgServicePrincipal -Filter "appId eq '$AppId'" -ErrorAction Stop
if (-not $engineSpn) { throw "Engine SPN not found for AppId '$AppId'." }
Write-Host "[ 2 / 5 ] OK -- engine SPN: $($engineSpn.DisplayName) (Id: $($engineSpn.Id))" -ForegroundColor Green

# --- Step 3: resolve the Microsoft Graph resource SPN
Write-Host ""
Write-Host "[ 3 / 5 ] Resolving Microsoft Graph resource SPN ..." -ForegroundColor Yellow
$msGraphSpn = Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'" -ErrorAction Stop
if (-not $msGraphSpn) { throw "Microsoft Graph SPN not found in this tenant (this should never happen)." }
Write-Host "[ 3 / 5 ] OK -- Microsoft Graph resourceId: $($msGraphSpn.Id)" -ForegroundColor Green

# --- Step 4: list currently-granted assignments on the engine SPN against Graph
Write-Host ""
Write-Host "[ 4 / 5 ] Reading existing AppRoleAssignments on engine SPN ..." -ForegroundColor Yellow
$existingAssignments = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $engineSpn.Id -All
$existingForGraph = $existingAssignments | Where-Object { $_.ResourceId -eq $msGraphSpn.Id }
Write-Host "[ 4 / 5 ] OK -- $($existingForGraph.Count) Graph permission(s) already granted." -ForegroundColor Green

# Map existing AppRoleId -> AppRole.Value for skip-detection
$grantedRoleIds   = @($existingForGraph | ForEach-Object { $_.AppRoleId })
$grantedRoleValues = @()
foreach ($r in $grantedRoleIds) {
    $appRole = $msGraphSpn.AppRoles | Where-Object Id -eq $r
    if ($appRole) { $grantedRoleValues += $appRole.Value }
}

# --- Step 5: grant each missing permission
Write-Host ""
Write-Host "[ 5 / 5 ] Granting requested permissions ..." -ForegroundColor Yellow
$results = @()
foreach ($permValue in $Permissions) {
    $appRole = $msGraphSpn.AppRoles | Where-Object { $_.Value -eq $permValue -and $_.AllowedMemberTypes -contains 'Application' }
    if (-not $appRole) {
        Write-Warning "  '$permValue' is not a valid Microsoft Graph application permission (no matching AppRole). Skipping."
        $results += [pscustomobject]@{ Permission = $permValue; Action = 'invalid'; AppRoleId = $null }
        continue
    }

    if ($grantedRoleValues -contains $permValue) {
        Write-Host "  - $permValue : already granted, skipping" -ForegroundColor DarkGray
        $results += [pscustomobject]@{ Permission = $permValue; Action = 'already-granted'; AppRoleId = $appRole.Id }
        continue
    }

    try {
        $params = @{
            ServicePrincipalId = $engineSpn.Id
            PrincipalId        = $engineSpn.Id
            ResourceId         = $msGraphSpn.Id
            AppRoleId          = $appRole.Id
        }
        $null = New-MgServicePrincipalAppRoleAssignment @params -ErrorAction Stop
        Write-Host "  + $permValue : GRANTED" -ForegroundColor Green
        $results += [pscustomobject]@{ Permission = $permValue; Action = 'granted'; AppRoleId = $appRole.Id }
    } catch {
        Write-Warning "  X $permValue : FAILED -- $($_.Exception.Message)"
        $results += [pscustomobject]@{ Permission = $permValue; Action = "failed: $($_.Exception.Message)"; AppRoleId = $appRole.Id }
    }
}

Write-Host ""
Write-Host "Summary:" -ForegroundColor Cyan
$results | Format-Table -AutoSize

$granted   = ($results | Where-Object Action -eq 'granted').Count
$existing  = ($results | Where-Object Action -eq 'already-granted').Count
$failed    = ($results | Where-Object { $_.Action -like 'failed:*' }).Count
$invalid   = ($results | Where-Object Action -eq 'invalid').Count

Write-Host "  Newly granted   : $granted"
Write-Host "  Already granted : $existing"
Write-Host "  Failed          : $failed"
Write-Host "  Invalid         : $invalid"
Write-Host ""

if ($granted -gt 0) {
    Write-Host "Done. New permissions are effective immediately for the engine SPN." -ForegroundColor Green
    Write-Host "Restart any long-running engine process (it caches the token + perms at connect time)." -ForegroundColor Yellow
} elseif ($failed -eq 0 -and $invalid -eq 0) {
    Write-Host "Nothing to do -- all requested permissions were already granted." -ForegroundColor DarkGray
} else {
    Write-Warning "One or more permissions failed or were invalid. See summary above."
}

Disconnect-MgGraph | Out-Null
