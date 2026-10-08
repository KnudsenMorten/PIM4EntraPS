#Requires -Version 5.1
<#
.SYNOPSIS
    Give the PIM Manager engine identity the Microsoft Graph (and other API) application permissions and Azure role
    assignments it is missing. Run once, as a Global Administrator (or Privileged Role Administrator for the
    application permissions; Owner / User Access Administrator at the scope for an Azure role).

.DESCRIPTION
    PIM Manager shows this command with your environment's exact values (Overview > permission check, and the Get
    Started step "Engine permissions"): the page itself is read-only on purpose -- an identity that can grant
    permissions could give itself anything.

    No PowerShell modules: plain REST + .NET, Windows PowerShell 5.1 or PowerShell 7. You sign in in the browser
    (Microsoft Edge is opened; the default browser when Edge is not installed). Azure role assignments ask for a second,
    quick sign-in to Azure.

    The script is idempotent: what the engine identity already holds is reported and left alone. Every grant is read
    back. At the end it prints, per permission: granted / already there / refused (with the reason), and exits 1 when
    anything was refused. A new grant reaches the engine's token within about 30 minutes; then press
    "Verify permissions" in PIM Manager.

    Download: Invoke-WebRequest https://invardia.com/support/pim/Grant-PimEnginePermissions.ps1 -OutFile Grant-PimEnginePermissions.ps1

.PARAMETER TenantId
    Your tenant id. The sign-in is refused when it lands in another tenant.
.PARAMETER EngineObjectId
    Object id of the engine identity's service principal (shown in PIM Manager).
.PARAMETER GraphPermissions
    Microsoft Graph application permissions, e.g. 'Group.ReadWrite.All','RoleManagement.ReadWrite.Directory'.
.PARAMETER AppRoles
    Application permissions of other APIs as '<permission>@<API application id>',
    e.g. 'Exchange.ManageAsApp@00000002-0000-0ff1-ce00-000000000000'.
.PARAMETER AzureRoleAssignments
    Azure roles as '<role name or role definition id>@<scope>',
    e.g. 'User Access Administrator@/providers/Microsoft.Management/managementGroups/<tenant id>'.
.PARAMETER UseEdge
    $true (default): open Microsoft Edge for the sign-in. $false: the default browser.
.PARAMETER GraphAccessToken
    Automation: a Microsoft Graph token (delegated AppRoleAssignment.ReadWrite.All + Application.Read.All) instead of
    the browser sign-in.
.PARAMETER ArmAccessToken
    Automation: an Azure Resource Manager token instead of the second browser sign-in.
.PARAMETER PlanOnly
    Read and report what would be granted; change nothing.
.PARAMETER PassThru
    Also return the result rows as objects.

.EXAMPLE
    .\Grant-PimEnginePermissions.ps1 -TenantId '<tenant id>' -EngineObjectId '<object id>' -GraphPermissions 'Group.ReadWrite.All','User.ReadWrite.All'
.EXAMPLE
    .\Grant-PimEnginePermissions.ps1 -TenantId '<tenant id>' -EngineObjectId '<object id>' -AzureRoleAssignments 'User Access Administrator@/providers/Microsoft.Management/managementGroups/<tenant id>'
#>
[CmdletBinding()]
param(
    [string]$TenantId,
    [Parameter(Mandatory)][string]$EngineObjectId,
    [string[]]$GraphPermissions = @(),
    [string[]]$AppRoles = @(),
    [string[]]$AzureRoleAssignments = @(),
    [bool]$UseEdge = $true,
    [string]$GraphAccessToken,
    [string]$ArmAccessToken,
    [switch]$PlanOnly,
    [switch]$PassThru
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '_PimEnginePermissions.ps1')

Write-Host "Grant-PimEnginePermissions -- PIM Manager $(Get-PimEpSolutionVersion)" -ForegroundColor Cyan
Write-Host "PowerShell : $($PSVersionTable.PSVersion) ($($PSVersionTable.PSEdition))" -ForegroundColor Cyan

if (-not (Test-PimEpGuid $EngineObjectId)) { throw "-EngineObjectId must be the engine identity's object id (a GUID): '$EngineObjectId'." }
if ($TenantId -and -not (Test-PimEpGuid $TenantId)) { throw "-TenantId must be the tenant id (a GUID): '$TenantId'." }
$EngineObjectId = $EngineObjectId.ToLowerInvariant()

$appSpecs = New-Object System.Collections.Generic.List[object]
foreach ($g in @(ConvertTo-PimEpList $GraphPermissions)) { $appSpecs.Add((ConvertTo-PimEpAppRoleSpec -Spec $g)) }
foreach ($a in @(ConvertTo-PimEpList $AppRoles)) {
    if ($a -notmatch '@') { throw "-AppRoles entries are '<permission>@<API application id>': '$a' (Microsoft Graph permissions go in -GraphPermissions)." }
    $appSpecs.Add((ConvertTo-PimEpAppRoleSpec -Spec $a))
}
$azSpecs = New-Object System.Collections.Generic.List[object]
foreach ($z in @(ConvertTo-PimEpList $AzureRoleAssignments)) { $azSpecs.Add((ConvertTo-PimEpAzureRoleSpec -Spec $z)) }
if (-not $appSpecs.Count -and -not $azSpecs.Count) { throw 'Nothing to grant: pass -GraphPermissions, -AppRoles and/or -AzureRoleAssignments.' }

$tenant = if ($TenantId) { $TenantId } else { 'organizations' }
$assertTenant = {
    param([string]$Token, [string]$What)
    $c = ConvertFrom-PimEpJwtClaims $Token
    if ($TenantId -and $c -and $c.PSObject.Properties['tid'] -and "$($c.tid)" -ne $TenantId) {
        throw "The $What sign-in landed in tenant $($c.tid), not $TenantId. Sign in with an account of the right tenant."
    }
    $c
}

# ---- Microsoft Graph sign-in + the engine identity ------------------------------------------------------------------
$account = $null
$results = New-Object System.Collections.Generic.List[object]
if ($appSpecs.Count) {
    if ($GraphAccessToken) { $gTok = $GraphAccessToken }
    else {
        Write-Host "Signing in to Microsoft Graph (permissions asked: $((Get-PimEpGraphScopes) -join ', '))..." -ForegroundColor Yellow
        try { $gTok = "$((Get-PimEpInteractiveToken -ClientId (Get-PimEpGraphCliClientId) -Scopes (Get-PimEpGraphScopes) -Tenant $tenant -UseEdge $UseEdge).access_token)" }
        catch { throw ("Sign-in failed: $($_.Exception.Message)`n$(Get-PimEpBrokenAuthHelp)") }
    }
    $claims = & $assertTenant $gTok 'Microsoft Graph'
    if ($claims) { foreach ($n in 'upn', 'preferred_username', 'unique_name') { if ($claims.PSObject.Properties[$n] -and $claims.$n) { $account = "$($claims.$n)"; break } } }
    if ($claims -and -not $TenantId -and $claims.PSObject.Properties['tid']) { $tenant = "$($claims.tid)" }
    Set-PimEpToken -Api graph -AccessToken $gTok
    Write-Host "Signed in$(if ($account) { " as $account" })." -ForegroundColor Green

    try { $eng = Invoke-PimEpRest -Api graph -Path "/servicePrincipals/$($EngineObjectId)?`$select=id,appId,displayName,servicePrincipalType" }
    catch {
        if ((Get-PimEpErrorStatus "$_") -eq 404) { throw "No service principal with object id $EngineObjectId in this tenant. Copy the object id from PIM Manager again." }
        throw "Could not read the engine identity: $_"
    }
    Write-Host "Engine identity: $($eng.displayName) ($($eng.servicePrincipalType), object id $EngineObjectId)" -ForegroundColor Cyan
    foreach ($r in @(Invoke-PimEpAppRoleGrant -EngineObjectId $EngineObjectId -Specs $appSpecs.ToArray() -PlanOnly:$PlanOnly)) { $results.Add($r) }
}

# ---- Azure role assignments -------------------------------------------------------------------------------------------
if ($azSpecs.Count) {
    if ($ArmAccessToken) { $aTok = $ArmAccessToken }
    else {
        Write-Host 'Signing in to Azure for the role assignment(s)...' -ForegroundColor Yellow
        try { $aTok = "$((Get-PimEpInteractiveToken -ClientId (Get-PimEpAzurePowerShellClientId) -Scopes @((Get-PimEpArmScope)) -Tenant $tenant -UseEdge $UseEdge -LoginHint $account).access_token)" }
        catch { throw ("Azure sign-in failed: $($_.Exception.Message)`n$(Get-PimEpBrokenAuthHelp)") }
    }
    [void](& $assertTenant $aTok 'Azure')
    Set-PimEpToken -Api arm -AccessToken $aTok
    foreach ($r in @(Invoke-PimEpAzureRoleGrant -EngineObjectId $EngineObjectId -Specs $azSpecs.ToArray() -PlanOnly:$PlanOnly)) { $results.Add($r) }
}

# ---- report -------------------------------------------------------------------------------------------------------------
Write-Host ''
Write-Host $(if ($PlanOnly) { 'Plan (nothing was changed):' } else { 'Result:' }) -ForegroundColor Cyan
foreach ($l in @(Format-PimEpResults -Results $results.ToArray())) {
    $color = if ($l -match '^\s+refused') { 'Red' } elseif ($l -match '^\s+granted') { 'Green' } else { 'Gray' }
    Write-Host $l -ForegroundColor $color
}
$refused = @($results | Where-Object { $_.status -eq 'refused' }).Count
$granted = @($results | Where-Object { $_.status -eq 'granted' }).Count
Write-Host ''
if ($granted) { Write-Host "A new grant reaches the engine's token within about 30 minutes. Then press Verify permissions in PIM Manager." -ForegroundColor Yellow }
if ($refused) { Write-Host "$refused permission(s) were refused -- see the reasons above." -ForegroundColor Red }
if ($PassThru) { $results.ToArray() }
if ($refused) { exit 1 }
