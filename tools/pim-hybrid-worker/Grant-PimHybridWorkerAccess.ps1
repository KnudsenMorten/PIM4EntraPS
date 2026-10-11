#Requires -Version 5.1

<#
.SYNOPSIS
    §80.2 PIMHYBRIDWRK -- what the worker VM's managed identity may do outside AD. Least privilege, read-before-write.

.DESCRIPTION
    Grants the hybrid worker's managed identity (Azure VM or Azure Arc server) exactly what it needs outside Active
    Directory: a database user in the PIM store, read-only Microsoft Graph roles and read access to the PIM source
    store.

      SQL     a contained user created from the identity's appId SID (no server identity / Directory Readers needed), in
              db_datareader + db_datawriter. NEVER db_ddladmin: the worker changes rows (its scheduler state, run history,
              audit), never the schema.
      Graph   application roles, READ ONLY: Group.Read.All, User.Read.All, PrivilegedAssignmentSchedule.Read.AzureADGroup
              (the active PIM-for-Groups members JIT membership mirrors). Mail.Send is deliberately NOT granted: a new AD
              admin account whose initial password cannot be mailed is HELD by hybrid-ad-apply and reported, not created
              with a password nobody receives. Grant it yourself (-GrantMailSend) when you want those creates.
      Source  Storage Blob Data Reader on the ONE container that holds pim-src-<version>.tar.gz + channel.json, so the
              worker updates itself with its identity -- no SAS, no PAT on the machine.

    Runs in Windows PowerShell 5.1 or PowerShell 7 (on a PS 7 transport failure the SQL step re-runs in a 5.1 child).
    -WhatIf prints the plan.

    §100.63(b) ON-PREMISES (Azure Arc): -ArcMachineResourceId instead of -PrincipalId reads the Arc machine's
    system-assigned identity from ARM (Microsoft.HybridCompute/machines, identity.principalId) and grants it the SAME
    rights. Name the SQL user per worker (-SqlUserName) when you run more than one.

.EXAMPLE
    powershell.exe -File .\Grant-PimHybridWorkerAccess.ps1 -SubscriptionId <sub> -TenantId <tenant> `
        -ArcMachineResourceId /subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.HybridCompute/machines/<server> `
        -SqlServer <server>.database.windows.net -SourceContainerId <storage-id>/blobServices/default/containers/pim-src

.EXAMPLE
    powershell.exe -File .\Grant-PimHybridWorkerAccess.ps1 -SubscriptionId <sub> -TenantId <tenant> -PrincipalId <mi-object-id> `
        -SqlServer <server>.database.windows.net -SqlDatabase PimPlatform -SourceContainerId <storage-id>/blobServices/default/containers/pim-src

.LINK
    https://invardia.com/docs/pim/scripts/Grant-PimHybridWorkerAccess/
#>
[CmdletBinding(SupportsShouldProcess, DefaultParameterSetName = 'Principal')]
param(
    [Parameter(Mandatory)][string]$SubscriptionId,
    [Parameter(Mandatory)][string]$TenantId,
    [Parameter(Mandatory, ParameterSetName = 'Principal')][string]$PrincipalId,
    # §100.63(b) the on-premises worker: the Azure Arc machine whose system-assigned identity gets exactly the same rights
    [Parameter(Mandatory, ParameterSetName = 'Arc')][string]$ArcMachineResourceId,
    [string]$ArcApiVersion = '2024-07-10',
    [string]$SqlServer = '',
    [string]$SqlDatabase = 'PimPlatform',
    [string]$SqlUserName = 'PIMHYBRIDWRK',
    [string]$SourceContainerId = '',
    [switch]$GrantMailSend
)
$ErrorActionPreference = 'Stop'

# 12.7 run frame: "<Script> version <x.y.z> - documentation: <page>" as the first line + a transcript in the temp folder.
. (Join-Path $PSScriptRoot '..\setup\_PimScriptDoc.ps1')
$null = Start-PimScriptRun -Script 'Grant-PimHybridWorkerAccess'
try {

function Step($m) { Write-Host "[grant] $m" -ForegroundColor Cyan }
function Info($m) { Write-Host "        $m" -ForegroundColor Gray }
# 100.41 (framework 12.17 NO-AZ): Graph / ARM / SQL tokens come from PIM-Rest's ONE token client (engine/_shared/PIM-ArmSetup.ps1):
# a calling run's REST session as it is; standalone, the Invardia Support app's session or the person signed in. No az.
$solRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
if (-not (Get-Command Get-PimRestToken -ErrorAction SilentlyContinue)) { . (Join-Path $solRoot 'engine\_shared\PIM-Rest.ps1') }
if (-not (Get-Command Invoke-PimSetupArm -ErrorAction SilentlyContinue)) { . (Join-Path $solRoot 'engine\_shared\PIM-ArmSetup.ps1') }
if (-not "$($global:PIM_SetupRestMode)".Trim()) { [void](Connect-PimSetupRest -SubscriptionId $SubscriptionId -TenantId $TenantId) }
# Graph calls follow the session's tenant, so the session must be pinned to -TenantId (was: the az profile's tenant).
if ("$($global:PIM_TenantId)".Trim() -and "$($global:PIM_TenantId)".Trim().ToLowerInvariant() -ne "$TenantId".Trim().ToLowerInvariant()) {
    throw "the REST session is signed in to tenant '$($global:PIM_TenantId)', not '$TenantId' -- refusing (Graph calls follow the session's tenant)"
}
$acct = Get-PimArmSubscription -SubscriptionId $SubscriptionId
if ("$($acct.tenantId)" -ne $TenantId) { throw "subscription $SubscriptionId reads tenant '$($acct.tenantId)', not '$TenantId' -- refusing" }

if ($PSCmdlet.ParameterSetName -eq 'Arc') {
    # The Arc machine's system-assigned identity (identity.principalId on Microsoft.HybridCompute/machines) -- every grant
    # below is then the SAME code as for the Azure VM worker, with this principal.
    if ($ArcMachineResourceId -notmatch '^/subscriptions/([^/]+)/resourceGroups/[^/]+/providers/Microsoft\.HybridCompute/machines/[^/]+$') { throw "not an Azure Arc machine resource id: '$ArcMachineResourceId'" }
    $arcMachine = Invoke-PimSetupArm -Path $ArcMachineResourceId -ApiVersion $ArcApiVersion -NotFoundOk
    if (-not $arcMachine) { throw "Arc machine not found: $ArcMachineResourceId" }
    $PrincipalId = "$($arcMachine.identity.principalId)"
    if (-not $PrincipalId) { throw "the Arc machine $($arcMachine.name) carries no system-assigned identity (identity.principalId) -- is the Connected Machine agent connected?" }
    Step "Arc machine $($arcMachine.name) ($("$($arcMachine.properties.status)")): identity $PrincipalId"
}

$sp = Invoke-PimSetupGraph -Path "/servicePrincipals/$PrincipalId`?`$select=id,appId,displayName" -NotFoundOk
if (-not $sp.appId) { throw "no service principal $PrincipalId in tenant $TenantId" }
Step "identity $($sp.displayName) (object $($sp.id), app $($sp.appId))"

# ---- Graph app roles (read only)
$gsp = @(Invoke-PimSetupGraph -Path "/servicePrincipals?`$filter=appId eq '00000003-0000-0000-c000-000000000000'&`$select=id,appRoles" -All | Where-Object { $_ })[0]
$want = @('Group.Read.All', 'User.Read.All', 'PrivilegedAssignmentSchedule.Read.AzureADGroup'); if ($GrantMailSend) { $want += 'Mail.Send' }
$have = @(@(Invoke-PimSetupGraph -Path "/servicePrincipals/$PrincipalId/appRoleAssignments" -All) | Where-Object { $_ } | Where-Object { $_.resourceId -eq $gsp.id } | ForEach-Object { $_.appRoleId })
foreach ($name in $want) {
    $role = $gsp.appRoles | Where-Object { $_.value -eq $name -and $_.allowedMemberTypes -contains 'Application' } | Select-Object -First 1
    if (-not $role) { throw "Graph has no application role '$name'" }
    if ($have -contains $role.id) { Info "Graph ${name}: already granted"; continue }
    if ($PSCmdlet.ShouldProcess($sp.displayName, "grant Graph $name")) {
        [void](Invoke-PimSetupGraph -Method POST -Path "/servicePrincipals/$($gsp.id)/appRoleAssignedTo" -Body @{ principalId = $sp.id; resourceId = $gsp.id; appRoleId = $role.id })
        Info "Graph ${name}: granted (a new app-role grant takes ~25 min to reach the identity's tokens)"
    }
}

# ---- source container
if ($SourceContainerId) {
    $ra = @(@(Get-PimArmRoleAssignments -Scope $SourceContainerId -PrincipalId $sp.id -Role 'Storage Blob Data Reader' -SubscriptionId $SubscriptionId) | Where-Object { $_ -and $_.principalId })   # @($null).Count is 1
    if ($ra.Count) { Info 'Storage Blob Data Reader on the source container: already granted' }
    elseif ($PSCmdlet.ShouldProcess($SourceContainerId, 'Storage Blob Data Reader')) {
        [void](New-PimArmRoleAssignment -Scope $SourceContainerId -PrincipalId $sp.id -PrincipalType ServicePrincipal -Role 'Storage Blob Data Reader' -SubscriptionId $SubscriptionId)
        Info 'Storage Blob Data Reader on the source container: granted'
    }
}

# ---- SQL contained user
# §100.63: through the hybrid worker's ONE SQL helper (_PimHybridWorkerSql.ps1): the driver setup already uses (PIM-SqlStore
# Resolve-PimSqlClientType: Microsoft.Data.SqlClient when present, else System.Data.SqlClient -- in-box on 5.1, shipped with
# PowerShell 7), the token on the connection, and -- PowerShell 7 only, on a transport failure -- the same statements once
# more in a Windows PowerShell 5.1 child (token on stdin). Works on PS 5.1 and 7; no module. The T-SQL converges the user
# (CREATE USER ... WITH SID = <appId>, TYPE = E; a same-name user with another SID is replaced) and its two roles.
if ($SqlServer) {
    . (Join-Path $PSScriptRoot '_PimHybridWorkerSql.ps1')
    Assert-PimHwSqlUserName -UserName $SqlUserName
    $userSql = Get-PimHwSqlUserSql -UserName $SqlUserName -AppId $sp.appId -Roles @('db_datareader', 'db_datawriter')
    if ($PSCmdlet.ShouldProcess("$SqlServer/$SqlDatabase", "CREATE USER [$SqlUserName] WITH SID (type E) when missing; db_datareader + db_datawriter")) {
        $tok = "$(Get-PimRestToken -Resource 'https://database.windows.net' -TenantId $TenantId)"
        $r = @(Invoke-PimHybridWorkerSql -Server $SqlServer -Database $SqlDatabase -AccessToken $tok -Batches @($userSql))
        $tok = $null
        Info "SQL connected as $($r[-1]); user ${SqlUserName}: db_datareader + db_datawriter (never db_ddladmin)"
    }
}
Step 'done'

} finally { Stop-PimScriptRun -Script 'Grant-PimHybridWorkerAccess' }
