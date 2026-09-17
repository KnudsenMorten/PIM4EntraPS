#Requires -Version 5.1
<#
.SYNOPSIS
    Converge an environment's SQL server onto the SQL ADMIN GROUP model. One command, idempotent,
    unattended. Certificate or signed-in (certificate) az context only -- never a client secret.

.DESCRIPTION
    Makes a security group (default 'grp-pim-sql-admins') the SQL server's Microsoft Entra admin, with
    these members:
      * the environment's user-assigned identity  (id-pim-<token>; found in the resource group, or named)
      * the SQL identity id-pim-sql-<token>, when the environment has one (private SQL)
      * the nightly updater's system-assigned identity (ca-pim-update), when the job exists
      * the troubleshooting identity (-TroubleshootingAppId or -TroubleshootingObjectId)
      * any -ExtraMemberObjectIds
      * the CURRENT admin, so converging never takes access away from whoever has it now
    Entra-only authentication is left as it is and verified afterwards. Existing contained database users
    are not touched. Every change is read back; a second run reports no changes.

    Why: the unattended updater checks the database schema before it rolls a release. It can only do that
    if its managed identity can log in, and a group that holds every identity that must administer the
    store is the one arrangement that survives an identity being added later without a database login
    being created by hand. See docs/DESIGN.md (the SQL admin group) and the framework contract in the
    repository's DOCS/REQUIREMENTS.md section 4.5.

.PARAMETER MembersOnly
    Do not create the group or move the admin: only add the members, and only when the group already IS
    the server's admin. This is what Deploy-PimUpdateJob.ps1 does on every run.

.PARAMETER PlanOnly
    Read everything and print the plan. Changes nothing.

.EXAMPLE
    .\Initialize-PimSqlAdminGroup.ps1 -SubscriptionId <sub> -ResourceGroup rg-automateit-x -SqlServerName sql-ait-x `
        -TenantId <tenant> -ClientId <deploy app id> -CertThumbprint <thumb> -TroubleshootingAppId <app id> -PlanOnly
#>
[CmdletBinding()]
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
    [string]$TroubleshootingAppId,
    [string]$TroubleshootingObjectId,
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

$server = ("$SqlServerName".Trim() -split '\.')[0]
Write-Host "`n=== SQL admin group: $GroupName -> $server ===" -ForegroundColor Cyan
Write-Host "    subscription $SubscriptionId / $ResourceGroup$(if ($PlanOnly) { '   (PLAN ONLY -- nothing is changed)' })" -ForegroundColor DarkGray

$inv = New-PimSqlAdminGroupInvokers -SubscriptionId $SubscriptionId -TenantId $TenantId -ClientId $ClientId -CertThumbprint $CertThumbprint
Write-Host "    auth: $(if ("$CertThumbprint".Trim()) { "certificate ($ClientId)" } else { 'signed-in az context' }) in tenant $($inv.TenantId)" -ForegroundColor DarkGray

$r = Invoke-PimSqlAdminGroupStep -Graph $inv.Graph -Arm $inv.Arm -TenantId $inv.TenantId -SubscriptionId $SubscriptionId `
        -ResourceGroup $ResourceGroup -SqlResourceGroup $SqlResourceGroup -SqlServerName $server -GroupName $GroupName -GroupObjectId $GroupObjectId `
        -EnvironmentIdentityName $EnvironmentIdentityName -SqlAdminIdentityName $SqlAdminIdentityName -UpdateJobName $UpdateJobName `
        -TroubleshootingAppId $TroubleshootingAppId -TroubleshootingObjectId $TroubleshootingObjectId -ExtraMemberObjectIds $ExtraMemberObjectIds `
        -Mode $(if ($MembersOnly) { 'membersOnly' } else { 'converge' }) -DoNotKeepCurrentAdmin:$DoNotKeepCurrentAdmin -PlanOnly:$PlanOnly
Write-PimSqlAdminGroupReport -Result $r

if ($r.ok) {
    $what = if ($PlanOnly) { "plan: $(@($r.plan.messages).Count) line(s), nothing changed" }
            elseif ($r.blocked) { "nothing changed: $($r.blocked)" }
            else { "'$GroupName' is the Entra admin of $server with every member (read back)" }
    Write-Host "==> OK -- $what" -ForegroundColor Green
    exit 0
}
Write-Host "==> NOT CONVERGED -- see [FAIL] above." -ForegroundColor Red
exit 1
