#Requires -Version 5.1
<#
.SYNOPSIS
    §100.63 -- the hybrid worker scripts' ONE way to run T-SQL against the PIM store with an Entra access token, on
    Windows PowerShell 5.1 AND PowerShell 7. Dot-sourced by Grant-PimHybridWorkerAccess.ps1 and Remove-PimHybridWorker.ps1.

.DESCRIPTION
    The driver is the one PIM's setup already uses (engine/_shared/PIM-SqlStore.ps1 Resolve-PimSqlClientType):
    Microsoft.Data.SqlClient when it is loaded (or $env:PIM_SQLCLIENT_DLL points at it), else System.Data.SqlClient --
    in-box on Windows PowerShell 5.1 and shipped with PowerShell 7. The token is set on the connection (.AccessToken);
    no password, no module.
    PowerShell 7 SAFETY NET: setup measured a PS 7 login failing with "connection forcibly closed" (_PimSetupSql.ps1). When
    the in-process open fails with a TRANSPORT error under PowerShell 7 and Windows PowerShell 5.1 is present, the SAME
    batches run once more in a powershell.exe child; the token travels on the child's STANDARD INPUT, never on its command
    line or in a file. A login / permission error is not retried (it would fail the same way).
    Test seam: $global:PimHwSqlInvoker = { param($Server, $Database, $AccessToken, $Batches) <results> } replaces the
    network entirely.
#>

$script:PimHwSqlRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)

function ConvertTo-PimHwSqlSid {
    # PURE. The contained-user SID of an Entra app / managed identity = its appId GUID bytes.
    param([Parameter(Mandatory)][string]$AppId)
    return '0x' + ((([guid]$AppId).ToByteArray() | ForEach-Object { $_.ToString('X2') }) -join '')
}

function Assert-PimHwSqlUserName {
    param([Parameter(Mandatory)][string]$UserName)
    if ($UserName -notmatch '^[A-Za-z0-9_-]{1,64}$') { throw "invalid SQL user name '$UserName'" }
}

function Get-PimHwSqlUserSql {
    <#
      PURE. The T-SQL that converges the worker's contained user: created WITH SID from the appId (TYPE = E, never FROM
      EXTERNAL PROVIDER), same name + different SID (the identity was rebuilt) = owned schemas to dbo, drop, recreate (the
      BUG-47 shape of setup's Get-PimSqlContainedUserSql), then the role memberships. NEVER db_ddladmin (refused).
    #>
    param([Parameter(Mandatory)][string]$UserName, [Parameter(Mandatory)][string]$AppId, [string[]]$Roles = @('db_datareader', 'db_datawriter'))
    Assert-PimHwSqlUserName -UserName $UserName
    foreach ($r in $Roles) { if ($r -notin @('db_datareader', 'db_datawriter')) { throw "the hybrid worker gets db_datareader + db_datawriter only, not '$r'" } }
    $sid = ConvertTo-PimHwSqlSid -AppId $AppId
    $l = New-Object System.Collections.Generic.List[string]
    $l.Add("IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name = N'$UserName' AND sid = $sid)")
    $l.Add('BEGIN')
    $l.Add("    IF EXISTS (SELECT 1 FROM sys.database_principals WHERE name = N'$UserName')")
    $l.Add('    BEGIN')
    $l.Add('        DECLARE @reassign NVARCHAR(MAX);')
    $l.Add("        SELECT @reassign = STRING_AGG('ALTER AUTHORIZATION ON SCHEMA::' + QUOTENAME(s.name) + ' TO [dbo];', ' ')")
    $l.Add("        FROM sys.schemas s JOIN sys.database_principals p ON s.principal_id = p.principal_id WHERE p.name = N'$UserName';")
    $l.Add('        IF @reassign IS NOT NULL EXEC sp_executesql @reassign;')
    $l.Add("        DROP USER [$UserName];")
    $l.Add('    END')
    $l.Add("    CREATE USER [$UserName] WITH SID = $sid, TYPE = E;")
    $l.Add('END')
    foreach ($r in $Roles) { $l.Add("IF IS_ROLEMEMBER('$r', N'$UserName') = 0 ALTER ROLE [$r] ADD MEMBER [$UserName];") }
    $l.Add("SELECT USER_NAME();")
    return ($l -join "`r`n")
}

function Get-PimHwSqlDropUserSql {
    # PURE. DROP the worker's user ONLY when it carries the worker identity's SID -- a same-named user of anything else stays.
    # Answers 'dropped' / 'other-sid' / 'absent'.
    param([Parameter(Mandatory)][string]$UserName, [Parameter(Mandatory)][string]$AppId)
    Assert-PimHwSqlUserName -UserName $UserName
    $sid = ConvertTo-PimHwSqlSid -AppId $AppId
    return (@(
        "IF EXISTS (SELECT 1 FROM sys.database_principals WHERE name = N'$UserName' AND sid = $sid)",
        "BEGIN DROP USER [$UserName]; SELECT 'dropped'; END",
        "ELSE IF EXISTS (SELECT 1 FROM sys.database_principals WHERE name = N'$UserName') SELECT 'other-sid'",
        "ELSE SELECT 'absent';") -join "`r`n")
}

function Test-PimHwSqlTransportFailure {
    # PURE. Is this an open failure the 5.1 child can help with (a transport / TLS break), not a login or permission one?
    param([AllowEmptyString()][string]$Message)
    if ("$Message" -match '(?i)Login failed|not currently configured to accept this token|permission|denied|Cannot open (server|database)') { return $false }
    return ("$Message" -match '(?i)forcibly closed|transport-level|pre-login|SSL Provider|TLS|existing connection was|An established connection was aborted|connection was closed')
}

# The driver resolution setup already uses (PIM-SqlStore.ps1), loaded at FILE scope so it lands in the caller's scope.
if (-not (Get-Command Resolve-PimSqlClientType -ErrorAction SilentlyContinue)) { . (Join-Path $script:PimHwSqlRoot 'engine\_shared\PIM-SqlStore.ps1') }

function Get-PimHwSqlClientType { return (Resolve-PimSqlClientType) }

function Invoke-PimHwSqlInProcess {
    param([string]$Server, [string]$Database, [string]$AccessToken, [string[]]$Batches)
    $type = Get-PimHwSqlClientType
    $cn = $type::new("Server=tcp:$Server,1433;Database=$Database;Encrypt=True;TrustServerCertificate=False;Connection Timeout=60")
    $cn.AccessToken = $AccessToken
    $cn.Open()
    try {
        $out = New-Object System.Collections.Generic.List[object]
        foreach ($b in $Batches) { $c = $cn.CreateCommand(); $c.CommandText = $b; $c.CommandTimeout = 120; $out.Add($c.ExecuteScalar()) }
        return , $out.ToArray()
    } finally { $cn.Close() }
}

function Invoke-PimHwSqlChild51 {
    # The same batches in a Windows PowerShell 5.1 child (System.Data.SqlClient in-box). Token + batches on stdin as JSON.
    param([string]$Server, [string]$Database, [string]$AccessToken, [string[]]$Batches)
    $exe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    if (-not (Test-Path -LiteralPath $exe)) { throw 'Windows PowerShell 5.1 is not on this machine' }
    $child = @'
$ErrorActionPreference = 'Stop'
$in = [Console]::In.ReadToEnd() | ConvertFrom-Json
$cn = New-Object System.Data.SqlClient.SqlConnection("Server=tcp:$($in.server),1433;Database=$($in.database);Encrypt=True;TrustServerCertificate=False;Connection Timeout=60")
$cn.AccessToken = "$($in.token)"
try {
    $cn.Open()
    $r = @(foreach ($b in @($in.batches)) { $c = $cn.CreateCommand(); $c.CommandText = "$b"; $c.CommandTimeout = 120; $v = $c.ExecuteScalar(); if ($v -is [DBNull]) { $null } else { "$v" } })
    [Console]::Out.Write((ConvertTo-Json -InputObject @{ ok = $true; results = $r } -Compress))
} catch { [Console]::Out.Write((ConvertTo-Json -InputObject @{ ok = $false; error = "$($_.Exception.Message)" } -Compress)) } finally { $cn.Close() }
'@
    $enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($child))
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $exe; $psi.Arguments = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand $enc"
    $psi.UseShellExecute = $false; $psi.RedirectStandardInput = $true; $psi.RedirectStandardOutput = $true; $psi.RedirectStandardError = $true; $psi.CreateNoWindow = $true
    $p = [System.Diagnostics.Process]::Start($psi)
    $p.StandardInput.Write((ConvertTo-Json -InputObject @{ server = $Server; database = $Database; token = $AccessToken; batches = @($Batches) } -Compress -Depth 4))
    $p.StandardInput.Close()
    $o = $p.StandardOutput.ReadToEnd(); $e = $p.StandardError.ReadToEnd(); $p.WaitForExit()
    $r = $null; try { $r = $o | ConvertFrom-Json } catch { throw "the Windows PowerShell 5.1 SQL child returned no result ($($e.Trim()))" }
    if (-not $r.ok) { throw "SQL (Windows PowerShell 5.1 child): $($r.error)" }
    return , @($r.results)
}

function Invoke-PimHybridWorkerSql {
    <#
      Runs each batch (ExecuteScalar) on ONE connection; returns the first column of each, in order. PS 5.1 + 7.
      -NoChildFallback: never start the 5.1 child.
    #>
    param([Parameter(Mandatory)][string]$Server, [Parameter(Mandatory)][string]$Database, [Parameter(Mandatory)][string]$AccessToken,
          [Parameter(Mandatory)][string[]]$Batches, [switch]$NoChildFallback)
    if ($global:PimHwSqlInvoker) { return (& $global:PimHwSqlInvoker $Server $Database $AccessToken $Batches) }
    $first = $null
    try { return (Invoke-PimHwSqlInProcess -Server $Server -Database $Database -AccessToken $AccessToken -Batches $Batches) }
    catch { $first = $_ }
    $msg = "$($first.Exception.Message)"; if ($first.Exception.InnerException) { $msg += " | $($first.Exception.InnerException.Message)" }
    if ($NoChildFallback -or $PSVersionTable.PSEdition -ne 'Core' -or -not (Test-PimHwSqlTransportFailure -Message $msg) -or $env:OS -ne 'Windows_NT') { throw $first }
    Write-Host "        SQL: PowerShell 7 could not open the connection ($msg) -- retrying the same statements in Windows PowerShell 5.1" -ForegroundColor Yellow
    return (Invoke-PimHwSqlChild51 -Server $Server -Database $Database -AccessToken $AccessToken -Batches $Batches)
}
