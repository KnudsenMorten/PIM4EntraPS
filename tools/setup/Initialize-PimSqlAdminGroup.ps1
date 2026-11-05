#Requires -Version 7.0

<#
.SYNOPSIS
    Make a role-assignable security group (default grp-pim-sql-admins) the Microsoft Entra admin of a PIM Manager
    environment's Azure SQL server, with the environment's managed identities and the nightly updater as its members.
    The Invardia Support app is never added. One command, idempotent, every change read back; -WhatIf shows every
    change first. Signs in in the browser as the person running it (or, inside an Invardia support session, as the
    Invardia Support app), or uses a certificate identity from the repository -- never a client secret, no other tools
    or modules.

.DESCRIPTION
    Makes a security group (default 'grp-pim-sql-admins') the SQL server's Microsoft Entra admin, with
    these members:
      * the environment's user-assigned identity  (id-pim-<token>; found in the resource group, or named)
      * the SQL identity id-pim-sql-<token>, when the environment has one (private SQL)
      * the nightly updater's system-assigned identity (ca-pim-update), when the job exists
      * the application a build runs as (-SetupIdentityAppId), for the length of that build
      * any -ExtraMemberObjectIds
      * the CURRENT admin, so converging never takes access away from whoever has it now
    The Invardia Support app is NOT a member: its one standing database right is its read-only database user
    (Grant-PimSupportAccess.ps1); admin rights only inside an open support session. Named with -SupportAppId or
    -SupportObjectId, it is not added and the run says so. A membership an earlier version gave is left as found.
    Entra-only authentication is left as it is and verified afterwards. Existing contained database users
    are not touched. Every change is read back; a second run reports no changes.

    -ReleaseOwnMembership takes the APPLICATION this run signs in as (-ClientId with -CertThumbprint, or the Invardia
    Support session) out of the group again, and reads it back. Only that one membership: no other member is touched.
    The one-shot MSP build uses it at its end when its setting releaseOwnBuildMembership is on (off by default).

    Why: the unattended updater checks the database schema before it rolls a release. It can only do that
    if its managed identity can log in, and a group that holds every identity that must administer the
    store is the one arrangement that survives an identity being added later without a database login
    being created by hand. See docs/DESIGN.md (the SQL admin group) and the framework contract in the
    repository's DOCS/REQUIREMENTS.md section 4.5.

.PARAMETER SupportAppId
    The application (client) id of the Invardia Support app. It is NOT added as a member (no standing database
    administrator); the run says so. The old name -TroubleshootingAppId still works.

.PARAMETER SupportObjectId
    The Invardia Support app's service principal object id, instead of -SupportAppId (also not added).
    The old name -TroubleshootingObjectId still works.

.PARAMETER SetupIdentityAppId
    The application (client) id a build runs as: added as a member for the length of that build.

.PARAMETER ReleaseOwnMembership
    Take the application this run signs in as out of the group and read it back; nothing else is changed. Needs
    -ClientId with -CertThumbprint (or the Invardia Support session in this window).

.PARAMETER MembersOnly
    Do not create the group or move the admin: only add the members, and only when the group already IS
    the server's admin. This is what Deploy-PimUpdateJob.ps1 does on every run.

.PARAMETER PlanOnly
    Read everything and print the plan. Changes nothing. (-WhatIf does the same and prints each change as a
    "What if:" line.)

.PARAMETER TenantId
    The tenant of the environment. Required for the browser sign-in (the sign-in and every token are pinned to it).

.PARAMETER ClientId
    Automation from the repository only: with -CertThumbprint, a certificate identity in the local store instead of
    the browser sign-in. Not needed for the downloaded script.

.EXAMPLE
    # A browser window opens: sign in as yourself (an administrator of the tenant).
    .\Initialize-PimSqlAdminGroup.ps1 -SubscriptionId <subscription id> -ResourceGroup <resource group> -SqlServerName <sql server> `
        -TenantId <tenant id> -SupportAppId <Invardia Support app id> -WhatIf
    Preview, then run the same command without -WhatIf.

.NOTES
    Requirements:
      PowerShell: 7.0 or later (pwsh). Windows PowerShell 5.1 is not supported.
      Role: Privileged Role Administrator (Microsoft Entra; the group is role-assignable); Contributor or Owner on the
            SQL server and Reader on the environment's resource group (Azure).
      Hosts: login.microsoftonline.com, graph.microsoft.com, management.azure.com

.LINK
    https://invardia.com/docs/pim/scripts/Initialize-PimSqlAdminGroup/
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$SubscriptionId,
    [Parameter(Mandatory)][string]$ResourceGroup,
    [Parameter(Mandatory)][string]$SqlServerName,
    [string]$SqlResourceGroup,
    [string]$TenantId,
    [string]$GroupName = 'grp-pim-sql-admins',
    [string]$GroupObjectId,
    [string]$EnvironmentIdentityName,
    [string]$SqlAdminIdentityName,
    [string]$UpdateJobName = 'ca-pim-update',
    # The Invardia Support app. The old names (-TroubleshootingAppId / -TroubleshootingObjectId) still bind.
    [Alias('TroubleshootingAppId')][string]$SupportAppId,
    [Alias('TroubleshootingObjectId')][string]$SupportObjectId,
    # the application a build runs as: a member for the length of that build
    [string]$SetupIdentityAppId,
    [string[]]$ExtraMemberObjectIds = @(),
    # Certificate auth from the local store. Omit both to sign in in the browser (or use the Invardia support session).
    [string]$ClientId,
    [string]$CertThumbprint,
    [switch]$MembersOnly,
    [switch]$DoNotKeepCurrentAdmin,
    [switch]$PlanOnly,
    # take the application this run signs in as out of the group again (its OWN membership only), read back
    [switch]$ReleaseOwnMembership
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '..\..\engine\_shared\PIM-Rest.ps1')   # the ONE token client (framework 12.17)
. (Join-Path $PSScriptRoot '_PimSignedIn.ps1')                    # the sign-in rule: the Support session, else the browser
. (Join-Path $PSScriptRoot '_PimSqlAdminGroup.ps1')
. (Join-Path $PSScriptRoot '..\..\engine\_shared\PIM-InstallNames.ps1')   # CR5 step 2: the updater job by either of its names
. (Join-Path $PSScriptRoot '_PimScriptDoc.ps1')
$null = Start-PimScriptRun -Script 'Initialize-PimSqlAdminGroup'
try {
# -WhatIf: read everything, print each change as a "What if:" line, change nothing (the -PlanOnly path of the helper).
if ($WhatIfPreference) { $PlanOnly = [switch]$true }

$server = ("$SqlServerName".Trim() -split '\.')[0]
Write-Host "`n=== SQL admin group: $GroupName -> $server ===" -ForegroundColor Cyan
Write-Host "    subscription $SubscriptionId / $ResourceGroup$(if ($PlanOnly) { '   (PLAN ONLY -- nothing is changed)' })" -ForegroundColor DarkGray

# Framework 12.17 -- ONE sign-in rule. Without a certificate: the Invardia Support session open in this window
# (Use-PimSupportAppRestSession), otherwise the person's own browser sign-in (Set-PimSignedInGlobals registers it in PIM-Rest;
# auth code + PKCE, never device code). Every token is pinned to -TenantId and checked.
$authLabel = "certificate ($ClientId)"
if (-not "$CertThumbprint".Trim()) {
    if ("$TenantId".Trim() -notmatch '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$') { throw 'Initialize-PimSqlAdminGroup: pass -TenantId <tenant id> -- the sign-in is pinned to that tenant.' }
    $supportApp = Use-PimSupportAppRestSession -TenantId $TenantId -SubscriptionId $SubscriptionId
    if ($supportApp) { $authLabel = "the Invardia Support app $supportApp (support session)" }
    else { Set-PimSignedInGlobals -TenantId $TenantId; $authLabel = 'your browser sign-in' }
}
$inv = New-PimSqlAdminGroupInvokers -SubscriptionId $SubscriptionId -TenantId $TenantId -ClientId $ClientId -CertThumbprint $CertThumbprint
Write-Host "    auth: $authLabel in tenant $($inv.TenantId)" -ForegroundColor DarkGray

if ($ReleaseOwnMembership) {
    # OPEN-01 item 4: the run's OWN application leaves the group -- the identity it signs in as, never a name it is given
    $ownApp = if ("$CertThumbprint".Trim()) { "$ClientId".Trim() } elseif ("$supportApp".Trim()) { "$supportApp".Trim() } else { '' }
    if (-not $ownApp) { throw 'Initialize-PimSqlAdminGroup: -ReleaseOwnMembership releases the application this run signs in as (-ClientId with -CertThumbprint, or the Invardia Support session); a person''s membership is released by the installer. Nothing was changed.' }
    $ownOid = Resolve-PimServicePrincipalObjectId -Graph $inv.Graph -AppId $ownApp
    $sqlRg = if ("$SqlResourceGroup".Trim()) { "$SqlResourceGroup".Trim() } else { $ResourceGroup }
    if ($PlanOnly) {
        Write-Host "What if: take this run's own application (app $ownApp, object $ownOid) out of '$GroupName' and read it back; no other member is touched"
        Write-Host '==> OK -- plan only, nothing changed' -ForegroundColor Green
        exit 0
    }
    $rel = Invoke-PimSqlAdminGroupSetupRelease -Graph $inv.Graph -Arm $inv.Arm -SubscriptionId $SubscriptionId -SqlResourceGroup $sqlRg -SqlServerName $server `
               -MemberObjectId $ownOid -OwnObjectId $ownOid -GroupName $GroupName -Label "this run's own application (app $ownApp)"
    if ($rel.ok) { Write-Host "==> OK -- $($rel.reason)" -ForegroundColor Green; exit 0 }
    Write-Host "==> NOT RELEASED -- $($rel.reason)" -ForegroundColor Red
    exit 1
}

$r = Invoke-PimSqlAdminGroupStep -Graph $inv.Graph -Arm $inv.Arm -TenantId $inv.TenantId -SubscriptionId $SubscriptionId `
        -ResourceGroup $ResourceGroup -SqlResourceGroup $SqlResourceGroup -SqlServerName $server -GroupName $GroupName -GroupObjectId $GroupObjectId `
        -EnvironmentIdentityName $EnvironmentIdentityName -SqlAdminIdentityName $SqlAdminIdentityName -UpdateJobName $UpdateJobName `
        -SupportAppId $SupportAppId -SupportObjectId $SupportObjectId -SetupIdentityAppId $SetupIdentityAppId -ExtraMemberObjectIds $ExtraMemberObjectIds `
        -Mode $(if ($MembersOnly) { 'membersOnly' } else { 'converge' }) -DoNotKeepCurrentAdmin:$DoNotKeepCurrentAdmin -PlanOnly:$PlanOnly
Write-PimSqlAdminGroupReport -Result $r

if ($WhatIfPreference -and $r.plan) {
    # The changes the run WOULD make, as PowerShell's own "What if:" lines (ShouldProcess answers $false under -WhatIf).
    $p = $r.plan
    $sqlTarget = "SQL server $server (subscription $SubscriptionId, resource group $(if ("$SqlResourceGroup".Trim()) { $SqlResourceGroup } else { $ResourceGroup }))"
    if ($p.createGroup) { [void]$PSCmdlet.ShouldProcess("Microsoft Graph: security group '$GroupName' (tenant $($inv.TenantId))", 'create ROLE-ASSIGNABLE security group (isAssignableToRole = true)') }
    foreach ($a in @($p.add)) { [void]$PSCmdlet.ShouldProcess("group '$GroupName'", "add member $($a.label) ($($a.objectId))") }
    if ($p.setAdmin) { [void]$PSCmdlet.ShouldProcess($sqlTarget, "make '$GroupName' the Microsoft Entra admin (was $(if ($r.adminBefore) { "'$($r.adminBefore)'" } else { 'none' }))") }
    if (-not $p.changes) { Write-Host "What if: no change -- '$GroupName' is already the Entra admin of $server and holds every member." }
}

if ($r.ok) {
    $what = if ($PlanOnly) { "plan: $(@($r.plan.messages).Count) line(s), nothing changed" }
            elseif ($r.blocked) { "nothing changed: $($r.blocked)" }
            else { "'$GroupName' is the Entra admin of $server with every member (read back)" }
    Write-Host "==> OK -- $what" -ForegroundColor Green
    exit 0
}
Write-Host "==> NOT CONVERGED -- see [FAIL] above." -ForegroundColor Red
exit 1
} finally { Stop-PimScriptRun -Script 'Initialize-PimSqlAdminGroup' }
