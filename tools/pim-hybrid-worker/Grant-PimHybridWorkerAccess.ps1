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
function AzJson { $ErrorActionPreference = 'Continue'; $o = & az @args 2>$null; if ($LASTEXITCODE -ne 0) { throw "az $($args[0..3] -join ' ') failed (exit $LASTEXITCODE)" }; if ("$o".Trim()) { ($o -join "`n") | ConvertFrom-Json } }
$acct = AzJson account show --subscription $SubscriptionId -o json
if ("$($acct.tenantId)" -ne $TenantId) { throw "the az profile is signed in to tenant '$($acct.tenantId)', not '$TenantId' -- set AZURE_CONFIG_DIR (Graph calls follow the profile, not --subscription)" }

$sp = AzJson rest --method GET --url "https://graph.microsoft.com/v1.0/servicePrincipals/$PrincipalId`?`$select=id,appId,displayName" -o json
if (-not $sp.appId) { throw "no service principal $PrincipalId in tenant $TenantId" }
Step "identity $($sp.displayName) (object $($sp.id), app $($sp.appId))"

# ---- Graph app roles (read only)
$graph = AzJson rest --method GET --url "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId eq '00000003-0000-0000-c000-000000000000'&`$select=id,appRoles" -o json
$gsp = @($graph.value)[0]
$want = @('Group.Read.All', 'User.Read.All', 'PrivilegedAssignmentSchedule.Read.AzureADGroup'); if ($GrantMailSend) { $want += 'Mail.Send' }
$have = @((AzJson rest --method GET --url "https://graph.microsoft.com/v1.0/servicePrincipals/$PrincipalId/appRoleAssignments" -o json).value | Where-Object { $_.resourceId -eq $gsp.id } | ForEach-Object { $_.appRoleId })
foreach ($name in $want) {
    $role = $gsp.appRoles | Where-Object { $_.value -eq $name -and $_.allowedMemberTypes -contains 'Application' } | Select-Object -First 1
    if (-not $role) { throw "Graph has no application role '$name'" }
    if ($have -contains $role.id) { Info "Graph ${name}: already granted"; continue }
    if ($PSCmdlet.ShouldProcess($sp.displayName, "grant Graph $name")) {
        $body = Join-Path $env:TEMP "pim-approle-$([guid]::NewGuid().ToString('N')).json"
        try {
            @{ principalId = $sp.id; resourceId = $gsp.id; appRoleId = $role.id } | ConvertTo-Json -Compress | Set-Content -LiteralPath $body -Encoding ascii
            [void](AzJson rest --method POST --url "https://graph.microsoft.com/v1.0/servicePrincipals/$($gsp.id)/appRoleAssignedTo" --headers 'Content-Type=application/json' --body "@$body" -o json)
        } finally { Remove-Item -LiteralPath $body -Force -ErrorAction SilentlyContinue }
        Info "Graph ${name}: granted (a new app-role grant takes ~25 min to reach the identity's tokens)"
    }
}

# ---- source container
if ($SourceContainerId) {
    $ra = @(@(AzJson role assignment list --assignee $sp.id --scope $SourceContainerId --role 'Storage Blob Data Reader' --subscription $SubscriptionId -o json) | Where-Object { $_ -and $_.principalId })   # @($null).Count is 1
    if ($ra.Count) { Info 'Storage Blob Data Reader on the source container: already granted' }
    elseif ($PSCmdlet.ShouldProcess($SourceContainerId, 'Storage Blob Data Reader')) {
        [void](AzJson role assignment create --assignee-object-id $sp.id --assignee-principal-type ServicePrincipal --role 'Storage Blob Data Reader' --scope $SourceContainerId --subscription $SubscriptionId -o json)
        Info 'Storage Blob Data Reader on the source container: granted'
    }
}

# ---- SQL contained user
if ($SqlServer) {
    if ($SqlUserName -notmatch '^[A-Za-z0-9_-]{1,64}$') { throw "invalid SQL user name '$SqlUserName'" }
    $sid = '0x' + ((([guid]$sp.appId).ToByteArray() | ForEach-Object { $_.ToString('X2') }) -join '')
    $tok = (AzJson account get-access-token --resource https://database.windows.net/ --tenant $TenantId -o json).accessToken
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
