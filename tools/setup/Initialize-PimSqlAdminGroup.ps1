#Requires -Version 5.1

<#
.SYNOPSIS
    Make a role-assignable security group (default grp-pim-sql-admins) the Microsoft Entra admin of a PIM Manager
    environment's Azure SQL server, with the environment's managed identities, the nightly updater and the Invardia
    Support app as its members. One command, idempotent, every change read back; -WhatIf shows every change first.
    Runs as the account signed in to az (az login), or a certificate identity from the repository -- never a client
    secret.

.DESCRIPTION
    Makes a security group (default 'grp-pim-sql-admins') the SQL server's Microsoft Entra admin, with
    these members:
      * the environment's user-assigned identity  (id-pim-<token>; found in the resource group, or named)
      * the SQL identity id-pim-sql-<token>, when the environment has one (private SQL)
      * the nightly updater's system-assigned identity (ca-pim-update), when the job exists
      * the Invardia Support app (-SupportAppId or -SupportObjectId)
      * any -ExtraMemberObjectIds
      * the CURRENT admin, so converging never takes access away from whoever has it now
    Entra-only authentication is left as it is and verified afterwards. Existing contained database users
    are not touched. Every change is read back; a second run reports no changes.

    Why: the unattended updater checks the database schema before it rolls a release. It can only do that
    if its managed identity can log in, and a group that holds every identity that must administer the
    store is the one arrangement that survives an identity being added later without a database login
    being created by hand. See docs/DESIGN.md (the SQL admin group) and the framework contract in the
    repository's DOCS/REQUIREMENTS.md section 4.5.

.PARAMETER SupportAppId
    The application (client) id of the Invardia Support app; its service principal is added as a member.
    The old name -TroubleshootingAppId still works.

.PARAMETER SupportObjectId
    The Invardia Support app's service principal object id, instead of -SupportAppId.
    The old name -TroubleshootingObjectId still works.

.PARAMETER MembersOnly
    Do not create the group or move the admin: only add the members, and only when the group already IS
    the server's admin. This is what Deploy-PimUpdateJob.ps1 does on every run.

.PARAMETER PlanOnly
    Read everything and print the plan. Changes nothing. (-WhatIf does the same and prints each change as a
    "What if:" line.)

.PARAMETER ClientId
    Automation from the repository only: with -CertThumbprint, a certificate identity in the local store instead of
    the az sign-in. Not needed for the downloaded script.

.EXAMPLE
    az login --tenant <tenant id>
    .\Initialize-PimSqlAdminGroup.ps1 -SubscriptionId <subscription id> -ResourceGroup <resource group> -SqlServerName <sql server> `
        -TenantId <tenant id> -SupportAppId <Invardia Support app id> -WhatIf
    Preview, then run the same command without -WhatIf.

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
    [string[]]$ExtraMemberObjectIds = @(),
    # Certificate auth from the local store. Omit both to use the signed-in az context.
    [string]$ClientId,
    [string]$CertThumbprint,
    [switch]$MembersOnly,
    [switch]$DoNotKeepCurrentAdmin,
    [switch]$PlanOnly
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '_PimSqlAdminGroup.ps1')
. (Join-Path $PSScriptRoot '_PimScriptDoc.ps1')
$null = Start-PimScriptRun -Script 'Initialize-PimSqlAdminGroup'
try {
# -WhatIf: read everything, print each change as a "What if:" line, change nothing (the -PlanOnly path of the helper).
if ($WhatIfPreference) { $PlanOnly = [switch]$true }

$server = ("$SqlServerName".Trim() -split '\.')[0]
Write-Host "`n=== SQL admin group: $GroupName -> $server ===" -ForegroundColor Cyan
Write-Host "    subscription $SubscriptionId / $ResourceGroup$(if ($PlanOnly) { '   (PLAN ONLY -- nothing is changed)' })" -ForegroundColor DarkGray

$inv = New-PimSqlAdminGroupInvokers -SubscriptionId $SubscriptionId -TenantId $TenantId -ClientId $ClientId -CertThumbprint $CertThumbprint
Write-Host "    auth: $(if ("$CertThumbprint".Trim()) { "certificate ($ClientId)" } else { 'signed-in az context' }) in tenant $($inv.TenantId)" -ForegroundColor DarkGray

$r = Invoke-PimSqlAdminGroupStep -Graph $inv.Graph -Arm $inv.Arm -TenantId $inv.TenantId -SubscriptionId $SubscriptionId `
        -ResourceGroup $ResourceGroup -SqlResourceGroup $SqlResourceGroup -SqlServerName $server -GroupName $GroupName -GroupObjectId $GroupObjectId `
        -EnvironmentIdentityName $EnvironmentIdentityName -SqlAdminIdentityName $SqlAdminIdentityName -UpdateJobName $UpdateJobName `
        -SupportAppId $SupportAppId -SupportObjectId $SupportObjectId -ExtraMemberObjectIds $ExtraMemberObjectIds `
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
