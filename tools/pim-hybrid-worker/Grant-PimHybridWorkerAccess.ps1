#Requires -Version 5.1
<#
.SYNOPSIS
    §80.2 PIMHYBRIDWRK -- what the worker VM's managed identity may do outside AD. Least privilege, read-before-write.

.DESCRIPTION
      SQL     a contained user created from the identity's appId SID (no server identity / Directory Readers needed), in
              db_datareader + db_datawriter. NEVER db_ddladmin: the worker changes rows (its scheduler state, run history,
              audit), never the schema.
      Graph   application roles, READ ONLY: Group.Read.All, User.Read.All, PrivilegedAssignmentSchedule.Read.AzureADGroup
              (the active PIM-for-Groups members JIT membership mirrors). Mail.Send is deliberately NOT granted: a new AD
              admin account whose initial password cannot be mailed is HELD by hybrid-ad-apply and reported, not created
              with a password nobody receives. Grant it yourself (-GrantMailSend) when you want those creates.
      Source  Storage Blob Data Reader on the ONE container that holds pim-src-<version>.tar.gz + channel.json, so the
              worker updates itself with its identity -- no SAS, no PAT on the machine.

    Run in Windows PowerShell 5.1 (the SQL login with an access token is reliable there). -WhatIf prints the plan.

.EXAMPLE
    powershell.exe -File .\Grant-PimHybridWorkerAccess.ps1 -SubscriptionId <sub> -TenantId <tenant> -PrincipalId <mi-object-id> `
        -SqlServer <server>.database.windows.net -SqlDatabase PimPlatform -SourceContainerId <storage-id>/blobServices/default/containers/pim-src
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$SubscriptionId,
    [Parameter(Mandatory)][string]$TenantId,
    [Parameter(Mandatory)][string]$PrincipalId,
    [string]$SqlServer = '',
    [string]$SqlDatabase = 'PimPlatform',
    [string]$SqlUserName = 'PIMHYBRIDWRK',
    [string]$SourceContainerId = '',
    [switch]$GrantMailSend
)
$ErrorActionPreference = 'Stop'
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
if ($SqlServer) {
    if ($SqlUserName -notmatch '^[A-Za-z0-9_-]{1,64}$') { throw "invalid SQL user name '$SqlUserName'" }
    $sid = '0x' + ((([guid]$sp.appId).ToByteArray() | ForEach-Object { $_.ToString('X2') }) -join '')
    $tok = "$(Get-PimRestToken -Resource 'https://database.windows.net' -TenantId $TenantId)"
    $cn = New-Object System.Data.SqlClient.SqlConnection("Server=tcp:$SqlServer,1433;Database=$SqlDatabase;Encrypt=True;TrustServerCertificate=False;Connection Timeout=60")
    $cn.AccessToken = $tok
    $cn.Open()
    try {
        $q = { param($t) $c = $cn.CreateCommand(); $c.CommandText = $t; $c.ExecuteScalar() }
        Info "SQL connected as $(& $q 'SELECT USER_NAME()')"
        $exists = & $q "SELECT COUNT(*) FROM sys.database_principals WHERE name = N'$SqlUserName'"
        if (-not $exists -and $PSCmdlet.ShouldProcess("$SqlServer/$SqlDatabase", "CREATE USER [$SqlUserName] WITH SID (type E)")) {
            [void](& $q "CREATE USER [$SqlUserName] WITH SID = $sid, TYPE = E")
        }
        foreach ($r in 'db_datareader', 'db_datawriter') {
            $in = & $q "SELECT COUNT(*) FROM sys.database_role_members m JOIN sys.database_principals r ON r.principal_id = m.role_principal_id JOIN sys.database_principals u ON u.principal_id = m.member_principal_id WHERE r.name = N'$r' AND u.name = N'$SqlUserName'"
            if (-not $in -and $PSCmdlet.ShouldProcess($SqlUserName, "ALTER ROLE $r ADD MEMBER")) { [void](& $q "ALTER ROLE [$r] ADD MEMBER [$SqlUserName]") }
        }
        Info "SQL user ${SqlUserName}: db_datareader + db_datawriter (never db_ddladmin)"
    } finally { $cn.Close() }
}
Step 'done'
