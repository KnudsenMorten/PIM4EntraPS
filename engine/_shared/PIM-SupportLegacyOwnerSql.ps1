#Requires -Version 5.1
<#
.SYNOPSIS
    SECAUDIT-1a 4a (framework, owner-decided; PIM REQUIREMENTS 104.8) -- the DATABASE JOB's half: read both proofs at this
    install, and only then take the Invardia Support app's LEGACY standing db_owner away, read it back, audit it and record
    the answer for the updater. Loaded ONLY by tools\pim-engine\dbinit-job-entry.ps1 (the in-network database job, its
    identity in the SQL admin group) -- never on the update path (tests\Test-PimSqlAccess.ps1 L2).
    The rules and the updater's half: engine\_shared\PIM-SupportLegacyOwner.ps1 (loaded first).

.DESCRIPTION
    Get-PimSupportLegacyOwnerFactsSql    ONE read-only JSON scalar: the Support app's user BY SID, its direct db_owner and
                                         pim_support_read membership, the open markers of its SID, the JIT open / close
                                         proof (markers PreExisting = 0, revoked by the job)
    Get-PimSupportLegacyOwnerDecision    PURE: facts -> remove | clean | open-session | proof-missing | refused
    Get-PimSupportLegacyOwnerRemoveSql   ONE batch, one transaction: EVERY rule checked AGAIN inside it (the markers of the
                                         SID read under UPDLOCK + HOLDLOCK, so a support grant cannot start in between), then
                                         the ONE statement that takes the Support app's user (found by SID) out of db_owner.
                                         Any rule that fails = THROW, the transaction rolls back, nothing changed.
    Invoke-PimSupportLegacyOwnerStep     facts -> decision -> the batch -> read back -> audit row -> the answer recorded
                                         (pim.Settings SupportLegacyOwner). Never throws.
    Never another principal (the SID is the Support app's own), never another role, never the user itself, never the
    read-only role. ASCII only; PS 5.1 + 7.
#>
Set-StrictMode -Off

function Get-PimSupportLegacyOwnerFactsSql {
    <# PURE. ONE read-only JSON scalar about the Support app's database user (found BY SID from -AppId). Compiles without the support schema. #>
    param([Parameter(Mandatory)][string]$AppId)
    $sid = ConvertTo-PimSupportLegacyOwnerSid -AppId $AppId
    $mem = { param($role) "(SELECT COUNT(*) FROM sys.database_role_members rm JOIN sys.database_principals r ON r.principal_id = rm.role_principal_id JOIN sys.database_principals p ON p.principal_id = rm.member_principal_id WHERE r.name = N'$role' AND p.sid = @sid)" }
    return @"
SET NOCOUNT ON;
DECLARE @sid VARBINARY(16) = $sid;
DECLARE @inst BIT = CASE WHEN OBJECT_ID(N'[pimsupport].[GrantMarker]') IS NOT NULL AND OBJECT_ID(N'[pimsupport].[Consent]') IS NOT NULL THEN 1 ELSE 0 END;
DECLARE @consentApp NVARCHAR(36) = NULL, @open INT = NULL, @proof INT = NULL, @proofLast NVARCHAR(30) = NULL;
IF @inst = 1
    EXEC sys.sp_executesql N'SELECT @c = CONVERT(NVARCHAR(36), SupportAppId) FROM [pimsupport].[Consent] WHERE Id = 1;
SELECT @o = COUNT(*) FROM [pimsupport].[GrantMarker] WHERE UserSid = @s AND RevokedUtc IS NULL;
SELECT @p = COUNT(*), @l = CONVERT(NVARCHAR(30), MAX(RevokedUtc), 126) FROM [pimsupport].[GrantMarker]
 WHERE UserSid = @s AND RoleName = N''db_owner'' AND PreExisting = 0 AND RevokedUtc IS NOT NULL AND RevokedBy = N''job'';',
        N'@s VARBINARY(16), @c NVARCHAR(36) OUTPUT, @o INT OUTPUT, @p INT OUTPUT, @l NVARCHAR(30) OUTPUT',
        @s = @sid, @c = @consentApp OUTPUT, @o = @open OUTPUT, @p = @proof OUTPUT, @l = @proofLast OUTPUT;
DECLARE @n SYSNAME = NULL, @t NVARCHAR(2) = NULL;
SELECT @n = name, @t = type FROM sys.database_principals WHERE sid = @sid;
SELECT (SELECT @inst AS installed, LOWER(@consentApp) AS consentAppId, CASE WHEN @n IS NULL THEN 0 ELSE 1 END AS userExists, @n AS userName, @t AS userType,
               $(& $mem 'db_owner') AS inOwner,
               $(& $mem 'pim_support_read') AS inRead,
               @open AS openMarkers, @proof AS jitClosedByJob, @proofLast AS jitClosedLastUtc
        FOR JSON PATH, INCLUDE_NULL_VALUES, WITHOUT_ARRAY_WRAPPER) AS result;
"@
}

function ConvertFrom-PimSupportLegacyOwnerFacts {
    <# PURE. The facts scalar -> an object with typed fields, or THROWS (no answer is never "clean"). #>
    param([AllowNull()]$Raw)
    $t = "$Raw".Trim()
    if (-not $t.StartsWith('{')) { throw 'the database did not answer the Support user facts' }
    $a = $t | ConvertFrom-Json
    $i = { param($n) $v = $a.$n; if ($null -eq $v) { $null } else { [int]$v } }
    return [pscustomobject][ordered]@{
        installed = ((& $i 'installed') -eq 1); consentAppId = "$($a.consentAppId)".Trim().ToLowerInvariant(); userExists = ((& $i 'userExists') -eq 1)
        userName = "$($a.userName)"; userType = "$($a.userType)".Trim().ToUpperInvariant(); inOwner = [int](& $i 'inOwner'); inRead = [int](& $i 'inRead')
        openMarkers = (& $i 'openMarkers'); jitClosedByJob = (& $i 'jitClosedByJob'); jitClosedLastUtc = "$($a.jitClosedLastUtc)"
    }
}

function Get-PimSupportLegacyOwnerDecision {
    <#
      PURE. -Facts (ConvertFrom-PimSupportLegacyOwnerFacts) for the Support app -AppId -> @{ action; state; missing; reason }.
        action remove  = both proofs hold, no support session open, the user holds a DIRECT db_owner
        state          removed (after the batch) | clean | open-session | proof-missing | refused
      P1 = the user is a direct member of pim_support_read. P2 = at least one db_owner marker of its SID with PreExisting = 0,
      revoked by the job. An unrevoked marker of its SID (an open session, or one past its end the sweep has not closed yet)
      = leave it: the just-in-time path owns it.
    #>
    param([Parameter(Mandatory)]$Facts, [Parameter(Mandatory)][string]$AppId)
    $o = { param($a, $s, $r, $m = @()) [pscustomobject]@{ action = $a; state = $s; reason = $r; missing = @($m) } }
    $id = "$AppId".Trim().ToLowerInvariant()
    if (-not $Facts.userExists) { return (& $o 'nothing' 'clean' 'the Support app has no database user here -- nothing to remove') }
    if ($Facts.userType -and $Facts.userType -notin @('E', 'X')) { return (& $o 'nothing' 'refused' "the principal with the Support app's SID is not an Entra user (type $($Facts.userType)) -- not touched") }
    if ($Facts.consentAppId -and $Facts.consentAppId -ne $id) { return (& $o 'nothing' 'refused' 'the app id asked for is not the Support app the support access records -- not touched') }
    if ([int]$Facts.inOwner -lt 1) { return (& $o 'nothing' 'clean' 'the Support user holds no direct db_owner -- nothing to remove') }
    if ($Facts.installed -and [int]$Facts.openMarkers -gt 0) { return (& $o 'nothing' 'open-session' 'a support session of the Support app is open (an unrevoked time-limited grant) -- the just-in-time path owns it; not touched') }
    $miss = New-Object System.Collections.Generic.List[string]; $why = New-Object System.Collections.Generic.List[string]
    if ([int]$Facts.inRead -lt 1) { $miss.Add('p1'); $why.Add("proof 1: the Support app's read-only user is not in pim_support_read") }
    if (-not $Facts.installed) { $miss.Add('p2'); $why.Add('proof 2: time-limited support access is not set up here, so no open / close was ever recorded') }
    elseif ([int]$Facts.jitClosedByJob -lt 1) { $miss.Add('p2'); $why.Add('proof 2: no time-limited support access was opened and closed by the job here yet') }
    if ($miss.Count) { return (& $o 'nothing' 'proof-missing' ($why -join '; ') @($miss.ToArray())) }
    return (& $o 'remove' '' "both proofs hold (the read-only user is in place; $([int]$Facts.jitClosedByJob) open / close by the job, last $($Facts.jitClosedLastUtc))")
}

function Get-PimSupportLegacyOwnerRemoveSql {
    <#
      PURE. THE ONE REMOVAL. One batch, one transaction, XACT_ABORT: the Support app's user BY SID; every rule checked AGAIN
      inside (no unrevoked marker of its SID -- read under UPDLOCK + HOLDLOCK, so the signed grant cannot open one meanwhile;
      proof 2; proof 1 as a DIRECT pim_support_read membership); only a DIRECT db_owner membership of THAT user is dropped.
      Anything else = THROW 5113x, rolled back, nothing changed.
    #>
    param([Parameter(Mandatory)][string]$AppId)
    $sid = ConvertTo-PimSupportLegacyOwnerSid -AppId $AppId
    return @"
SET NOCOUNT ON; SET XACT_ABORT ON;
DECLARE @sid VARBINARY(16) = $sid, @n SYSNAME = NULL, @q NVARCHAR(400), @open INT = 0, @proof INT = 0;
SELECT @n = name FROM sys.database_principals WHERE sid = @sid AND type IN ('E', 'X');
IF @n IS NULL THROW 51131, N'support-legacy-owner: the Support app''s database user is not there -- nothing was changed.', 1;
IF OBJECT_ID(N'[pimsupport].[GrantMarker]') IS NULL THROW 51133, N'support-legacy-owner: proof 2 is missing (no time-limited support access here) -- nothing was changed.', 1;
BEGIN TRANSACTION;
EXEC sys.sp_executesql N'SELECT @o = COUNT(*) FROM [pimsupport].[GrantMarker] WITH (UPDLOCK, HOLDLOCK) WHERE UserSid = @s AND RevokedUtc IS NULL;
SELECT @p = COUNT(*) FROM [pimsupport].[GrantMarker] WHERE UserSid = @s AND RoleName = N''db_owner'' AND PreExisting = 0 AND RevokedUtc IS NOT NULL AND RevokedBy = N''job'';',
    N'@s VARBINARY(16), @o INT OUTPUT, @p INT OUTPUT', @s = @sid, @o = @open OUTPUT, @p = @proof OUTPUT;
IF @open > 0 THROW 51132, N'support-legacy-owner: a support session is open -- nothing was changed.', 1;
IF @proof < 1 THROW 51133, N'support-legacy-owner: proof 2 is missing -- nothing was changed.', 1;
IF NOT EXISTS (SELECT 1 FROM sys.database_role_members rm JOIN sys.database_principals r ON r.principal_id = rm.role_principal_id
               JOIN sys.database_principals p ON p.principal_id = rm.member_principal_id WHERE r.name = N'pim_support_read' AND p.sid = @sid)
    THROW 51134, N'support-legacy-owner: proof 1 is missing -- nothing was changed.', 1;
IF EXISTS (SELECT 1 FROM sys.database_role_members rm JOIN sys.database_principals r ON r.principal_id = rm.role_principal_id
           JOIN sys.database_principals p ON p.principal_id = rm.member_principal_id WHERE r.name = N'db_owner' AND p.sid = @sid)
BEGIN
    SET @q = N'ALTER ROLE [db_owner] DROP MEMBER ' + QUOTENAME(@n) + N';';
    EXEC sys.sp_executesql @q;
END
COMMIT TRANSACTION;
"@
}

function Invoke-PimSupportLegacyOwnerStep {
    <#
      The database job's step. Never throws.
        -Scalar { param($sql) }  ONE scalar (the facts)        -Exec { param($sql) }  a batch without an answer
        -AppId                   the Support app's id (asked by the updater; checked against the recorded consent)
        -Audit  { param($record) }  one PIM audit row (Write-PimSqlAuditEvent) -- the removal and a refused / failed try
        -Record { param($value) }   the answer for the updater (pim.Settings SupportLegacyOwner)
      Returns @{ state = removed | clean | open-session | proof-missing | refused | failed; missing; reason; lines }.
    #>
    param([Parameter(Mandatory)][scriptblock]$Scalar, [Parameter(Mandatory)][scriptblock]$Exec, [Parameter(Mandatory)][AllowEmptyString()][string]$AppId,
          [scriptblock]$Audit = $null, [scriptblock]$Record = $null, [datetime]$NowUtc = [datetime]::UtcNow)
    $res = [ordered]@{ state = ''; missing = @(); reason = ''; userName = ''; lines = @() }
    $lines = New-Object System.Collections.Generic.List[string]
    $short = { param($e) ((("$($e.Exception.Message)") -split "`n")[0]).Trim() }
    $f0 = $null
    try {
        if (-not (Test-PimSupportLegacyOwnerAppId $AppId)) { $res.state = 'refused'; $res.reason = 'no Support app id was asked for -- nothing read or changed' }
        else {
            $f0 = ConvertFrom-PimSupportLegacyOwnerFacts (& $Scalar (Get-PimSupportLegacyOwnerFactsSql -AppId $AppId))
            $res.userName = "$($f0.userName)"
            $d = Get-PimSupportLegacyOwnerDecision -Facts $f0 -AppId $AppId
            $res.reason = $d.reason; $res.missing = @($d.missing)
            if ($d.action -ne 'remove') { $res.state = $d.state }
            else {
                $lines.Add("$($d.reason) -- the standing db_owner of the Support app's database user [$($f0.userName)] is removed")
                [void](& $Exec (Get-PimSupportLegacyOwnerRemoveSql -AppId $AppId))
                # READ BACK: no db_owner any more, the read-only role intact, still the same user
                $f1 = ConvertFrom-PimSupportLegacyOwnerFacts (& $Scalar (Get-PimSupportLegacyOwnerFactsSql -AppId $AppId))
                if ($f1.userExists -and [int]$f1.inOwner -eq 0 -and [int]$f1.inRead -ge 1) {
                    $res.state = 'removed'; $res.reason = 'legacy standing db_owner removed (SECAUDIT-1a 4a), read back: no db_owner, pim_support_read intact'
                } else {
                    $res.state = 'failed'; $res.reason = "the read-back did not confirm it (db_owner $([int]$f1.inOwner), pim_support_read $([int]$f1.inRead))"
                }
            }
        }
    } catch {
        $m = & $short $_
        $res.state = $(if ($m -match 'support-legacy-owner: (a support session is open)') { 'open-session' } elseif ($m -match 'support-legacy-owner: proof (\d)') { 'proof-missing' } else { 'failed' })
        if ($res.state -eq 'proof-missing') { $res.missing = @("p$($Matches[1])") }
        $res.reason = "nothing was changed: $m"
    }
    $lines.Add("support-legacy-owner: $($res.state) -- $($res.reason)")
    # one PIM audit row for a removal and for a try that did not complete (a plain 'not yet' writes none)
    if ($Audit -and $res.state -in @('removed', 'failed')) {
        try {
            & $Audit ([pscustomobject][ordered]@{ action = 'support.access.legacy-owner.remove'; target = "database user [$($res.userName)] (the Invardia Support app, by SID)"; role = 'db_owner'
                                                    rule = 'SECAUDIT-1a 4a'; result = $(if ($res.state -eq 'removed') { 'ok' } else { 'failed' }); detail = $res.reason })
        } catch { $lines.Add("the audit row could not be written ($(& $short $_))") }
    }
    if ($Record) {
        try {
            & $Record ([ordered]@{ state = $res.state; missing = @($res.missing); reason = $res.reason; appId = "$AppId".Trim().ToLowerInvariant()
                                   atUtc = $NowUtc.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture) })
        } catch { $lines.Add("the answer for the updater could not be recorded ($(& $short $_)) -- the updater asks again") }
    }
    $res.lines = @($lines.ToArray())
    return [pscustomobject]$res
}
