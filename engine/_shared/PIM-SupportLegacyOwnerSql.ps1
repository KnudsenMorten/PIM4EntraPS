#Requires -Version 5.1
<#
.SYNOPSIS
    SECAUDIT-1a 4a (framework, owner-decided; PIM REQUIREMENTS 104.8 / 104.9) -- the DATABASE JOB's half: "remove, then prove,
    else restore". The Invardia Support app's LEGACY standing db_owner is taken away, then ONE just-in-time add + take-back is
    proved through the SAME signed procedures the support SQL access job uses; if any proof step fails, exactly what was
    removed is put back. Loaded ONLY by tools\pim-engine\dbinit-job-entry.ps1 (the in-network database job, its identity in
    the SQL admin group) -- never on the update path (tests\Test-PimSqlAccess.ps1 L2). Needs engine\_shared\PIM-SupportJit.ps1
    (the signed grant / revoke callers) and engine\_shared\PIM-SupportLegacyOwner.ps1 (the rules) loaded first.

.DESCRIPTION
    WHY "remove, then prove" (Invardia ruling 2026-11-17, option B): at an install whose Support user still holds the legacy
    db_owner, every JIT grant records PreExisting = 1 and its revoke never removes it (4c) -- so a proof recorded BEFORE the
    removal ("a PreExisting = 0 marker revoked by the job", 3.1.44) can never exist there. The proof is therefore made right
    AFTER the removal, by the job itself:
      1 preconditions: the user BY SID (an Entra principal; the app id = the recorded consent's), a DIRECT db_owner member,
        a DIRECT pim_support_read member (P1), no unrevoked marker of its SID (no open session), the signed procedures there,
        the recorded consent = setup (the signed grant gives db_owner only at that level -- the proof never widens a consent
        and never goes around the procedures; any other consent = nothing removed, reported once)
      2 the ONE guarded statement: the direct db_owner membership is dropped (every precondition checked again inside)
      3 PROVE through [pimsupport].[usp_SupportGrant] (Invoke-PimSupportJitGrant: level setup, a 10-minute end, Reason
        "SECAUDIT-1a 4a proof after legacy removal", OpenedBy "job:dbinit") -> a marker PreExisting = 0 and the user IN
        db_owner; then [pimsupport].[usp_SupportRevoke] @Mode all, @Source job (Invoke-PimSupportJitRevoke) -> NOT in db_owner,
        the marker revoked by the job, pim_support_read intact (read back)
      4 any proof step fails -> RESTORE: an open proof marker is closed first, then the direct db_owner membership is put back
        (nothing else), read back; state failed with the reason. A proof marker that cannot be closed (its end would take the
        restored right away) = state restore-pending: the next run of this step puts it back once the marker is closed
      5 success -> state removed, audit rows (the removal; the grant / revoke rows of the signed path)
    Never another principal or role, never DROP USER, the read-only role never touched. ASCII only; PS 5.1 + 7.
#>
Set-StrictMode -Off

function Get-PimSupportLegacyOwnerProofReason { <# PURE. LITERAL. The proof grant's reason. #> return 'SECAUDIT-1a 4a proof after legacy removal' }
function Get-PimSupportLegacyOwnerProofOpenedBy { <# PURE. LITERAL. Who opens the proof grant. #> return 'job:dbinit' }
function Get-PimSupportLegacyOwnerProofMinutes { <# PURE. LITERAL. The proof grant's end, minutes ahead (it is taken back at once). #> return 10 }

function Get-PimSupportLegacyOwnerFactsSql {
    <# PURE. ONE read-only JSON scalar about the Support app's database user (found BY SID from -AppId). Compiles without the support schema. #>
    param([Parameter(Mandatory)][string]$AppId)
    $sid = ConvertTo-PimSupportLegacyOwnerSid -AppId $AppId
    $mem = { param($role) "(SELECT COUNT(*) FROM sys.database_role_members rm JOIN sys.database_principals r ON r.principal_id = rm.role_principal_id JOIN sys.database_principals p ON p.principal_id = rm.member_principal_id WHERE r.name = N'$role' AND p.sid = @sid)" }
    return @"
SET NOCOUNT ON;
DECLARE @sid VARBINARY(16) = $sid;
DECLARE @inst BIT = CASE WHEN OBJECT_ID(N'[pimsupport].[GrantMarker]') IS NOT NULL AND OBJECT_ID(N'[pimsupport].[Consent]') IS NOT NULL THEN 1 ELSE 0 END;
DECLARE @procs BIT = CASE WHEN OBJECT_ID(N'[pimsupport].[usp_SupportGrant]') IS NOT NULL AND OBJECT_ID(N'[pimsupport].[usp_SupportRevoke]') IS NOT NULL THEN 1 ELSE 0 END;
DECLARE @consentApp NVARCHAR(36) = NULL, @consentLevel NVARCHAR(20) = NULL, @open INT = NULL, @proof INT = NULL;
IF @inst = 1
    EXEC sys.sp_executesql N'SELECT @c = CONVERT(NVARCHAR(36), SupportAppId), @lv = ConsentLevel FROM [pimsupport].[Consent] WHERE Id = 1;
SELECT @o = COUNT(*) FROM [pimsupport].[GrantMarker] WHERE UserSid = @s AND RevokedUtc IS NULL;
SELECT @p = COUNT(*) FROM [pimsupport].[GrantMarker] WHERE UserSid = @s AND RoleName = N''db_owner'' AND PreExisting = 0 AND RevokedUtc IS NOT NULL AND RevokedBy = N''job'';',
        N'@s VARBINARY(16), @c NVARCHAR(36) OUTPUT, @lv NVARCHAR(20) OUTPUT, @o INT OUTPUT, @p INT OUTPUT',
        @s = @sid, @c = @consentApp OUTPUT, @lv = @consentLevel OUTPUT, @o = @open OUTPUT, @p = @proof OUTPUT;
DECLARE @n SYSNAME = NULL, @t NVARCHAR(2) = NULL;
SELECT @n = name, @t = type FROM sys.database_principals WHERE sid = @sid;
SELECT (SELECT @inst AS installed, @procs AS procedures, LOWER(@consentApp) AS consentAppId, @consentLevel AS consentLevel,
               CASE WHEN @n IS NULL THEN 0 ELSE 1 END AS userExists, @n AS userName, @t AS userType,
               $(& $mem 'db_owner') AS inOwner,
               $(& $mem 'pim_support_read') AS inRead,
               @open AS openMarkers, @proof AS jitClosedByJob
        FOR JSON PATH, INCLUDE_NULL_VALUES, WITHOUT_ARRAY_WRAPPER) AS result;
"@
}

function Get-PimSupportLegacyOwnerMarkerSql {
    <# PURE. ONE read-only JSON scalar: the marker of ONE grant (by its id) -- found, role, pre-existing, revoked, by whom. #>
    param([Parameter(Mandatory)][string]$GrantId)
    $g = [guid]::Empty
    if (-not [guid]::TryParse("$GrantId".Trim(), [ref]$g) -or $g -eq [guid]::Empty) { throw "Get-PimSupportLegacyOwnerMarkerSql: '$GrantId' is not a grant id." }
    return @"
SET NOCOUNT ON;
DECLARE @found INT = 0, @role SYSNAME = NULL, @pre BIT = NULL, @rev INT = 0, @by NVARCHAR(20) = NULL;
IF OBJECT_ID(N'[pimsupport].[GrantMarker]') IS NOT NULL
    EXEC sys.sp_executesql N'SELECT TOP 1 @f = 1, @r = RoleName, @p = PreExisting, @v = CASE WHEN RevokedUtc IS NULL THEN 0 ELSE 1 END, @b = RevokedBy
  FROM [pimsupport].[GrantMarker] WHERE GrantId = @g ORDER BY MarkerId DESC;',
        N'@g UNIQUEIDENTIFIER, @f INT OUTPUT, @r SYSNAME OUTPUT, @p BIT OUTPUT, @v INT OUTPUT, @b NVARCHAR(20) OUTPUT',
        @g = '$g', @f = @found OUTPUT, @r = @role OUTPUT, @p = @pre OUTPUT, @v = @rev OUTPUT, @b = @by OUTPUT;
SELECT (SELECT @found AS found, @role AS role, @pre AS preExisting, @rev AS revoked, @by AS revokedBy FOR JSON PATH, INCLUDE_NULL_VALUES, WITHOUT_ARRAY_WRAPPER) AS result;
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
        installed = ((& $i 'installed') -eq 1); procedures = ((& $i 'procedures') -eq 1); consentAppId = "$($a.consentAppId)".Trim().ToLowerInvariant()
        consentLevel = "$($a.consentLevel)".Trim().ToLowerInvariant(); userExists = ((& $i 'userExists') -eq 1)
        userName = "$($a.userName)"; userType = "$($a.userType)".Trim().ToUpperInvariant(); inOwner = [int](& $i 'inOwner'); inRead = [int](& $i 'inRead')
        openMarkers = (& $i 'openMarkers'); jitClosedByJob = (& $i 'jitClosedByJob')
    }
}

function Get-PimSupportLegacyOwnerDecision {
    <#
      PURE. -Facts (ConvertFrom-PimSupportLegacyOwnerFacts) for the Support app -AppId -> @{ action; state; missing; reason }.
        action remove = the Support user (an Entra principal, the recorded Support app) holds a DIRECT db_owner, is a direct
                        member of pim_support_read (P1), no unrevoked marker of its SID (no open session), the signed
                        procedures are there and the recorded consent is setup (the signed grant gives db_owner only then)
      missing: p1 | module (the support access procedures are not there) | consent (the recorded consent is not setup)
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
    if ([int]$Facts.inRead -lt 1) { $miss.Add('p1'); $why.Add("the Support app's read-only user is not in pim_support_read") }
    if (-not $Facts.installed -or -not $Facts.procedures) { $miss.Add('module'); $why.Add('time-limited support access is not set up here, so the add + take-back cannot be proved') }
    elseif ($Facts.consentLevel -ne 'setup') { $miss.Add('consent'); $why.Add("the recorded support consent is '$($Facts.consentLevel)', not setup: the signed grant gives no db_owner, so the add + take-back cannot be proved") }
    if ($miss.Count) { return (& $o 'nothing' 'proof-missing' ($why -join '; ') @($miss.ToArray())) }
    return (& $o 'remove' '' 'the read-only user is in place, no session is open and the support access procedures are there')
}

function Get-PimSupportLegacyOwnerRemoveSql {
    <#
      PURE. THE ONE REMOVAL. One batch, one transaction, XACT_ABORT: the Support app's user BY SID; every precondition checked
      AGAIN inside (no unrevoked marker of its SID -- read under UPDLOCK + HOLDLOCK, so the signed grant cannot open one
      meanwhile; P1 as a DIRECT pim_support_read membership); only a DIRECT db_owner membership of THAT user is dropped.
      Anything else = THROW 5113x, rolled back, nothing changed.
    #>
    param([Parameter(Mandatory)][string]$AppId)
    $sid = ConvertTo-PimSupportLegacyOwnerSid -AppId $AppId
    return @"
SET NOCOUNT ON; SET XACT_ABORT ON;
DECLARE @sid VARBINARY(16) = $sid, @n SYSNAME = NULL, @q NVARCHAR(400), @open INT = 0;
SELECT @n = name FROM sys.database_principals WHERE sid = @sid AND type IN ('E', 'X');
IF @n IS NULL THROW 51131, N'support-legacy-owner: the Support app''s database user is not there -- nothing was changed.', 1;
IF OBJECT_ID(N'[pimsupport].[GrantMarker]') IS NULL OR OBJECT_ID(N'[pimsupport].[usp_SupportGrant]') IS NULL THROW 51133, N'support-legacy-owner: time-limited support access is not set up here -- nothing was changed.', 1;
BEGIN TRANSACTION;
EXEC sys.sp_executesql N'SELECT @o = COUNT(*) FROM [pimsupport].[GrantMarker] WITH (UPDLOCK, HOLDLOCK) WHERE UserSid = @s AND RevokedUtc IS NULL;',
    N'@s VARBINARY(16), @o INT OUTPUT', @s = @sid, @o = @open OUTPUT;
IF @open > 0 THROW 51132, N'support-legacy-owner: a support session is open -- nothing was changed.', 1;
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

function Get-PimSupportLegacyOwnerRestoreSql {
    <#
      PURE. THE RESTORE (only after this step removed the membership and a proof step failed): the direct db_owner membership
      of the Support app's user, found BY SID (type E / X), put back -- exactly what was removed, nothing else. Idempotent.
    #>
    param([Parameter(Mandatory)][string]$AppId)
    $sid = ConvertTo-PimSupportLegacyOwnerSid -AppId $AppId
    return @"
SET NOCOUNT ON; SET XACT_ABORT ON;
DECLARE @sid VARBINARY(16) = $sid, @n SYSNAME = NULL, @q NVARCHAR(400);
SELECT @n = name FROM sys.database_principals WHERE sid = @sid AND type IN ('E', 'X');
IF @n IS NULL THROW 51135, N'support-legacy-owner: the Support app''s database user is not there -- nothing to restore.', 1;
IF NOT EXISTS (SELECT 1 FROM sys.database_role_members rm JOIN sys.database_principals r ON r.principal_id = rm.role_principal_id
               JOIN sys.database_principals p ON p.principal_id = rm.member_principal_id WHERE r.name = N'db_owner' AND p.sid = @sid)
BEGIN
    SET @q = N'ALTER ROLE [db_owner] ADD MEMBER ' + QUOTENAME(@n) + N';';
    EXEC sys.sp_executesql @q;
END
"@
}

function Invoke-PimSupportLegacyOwnerStep {
    <#
      The database job's step: remove, then prove, else restore. Never throws.
        -Scalar { param($sql) }  ONE scalar (the facts, the marker read AND the signed procedures' answers)
        -Exec   { param($sql) }  a batch without an answer (the removal / the restore)
        -AppId                   the Support app's id (asked by the updater; checked against the recorded consent)
        -Audit  { param($record) }  PIM audit rows (Write-PimSqlAuditEvent): the removal, a restore, the signed path's own rows
        -Record { param($value) }   the answer for the updater (pim.Settings SupportLegacyOwner)
        -PreviousRecord             the last answer: restore-pending is finished first
      Returns @{ state = removed | clean | open-session | proof-missing | refused | failed | restore-pending; restored;
                 missing; reason; lines }.
    #>
    param([Parameter(Mandatory)][scriptblock]$Scalar, [Parameter(Mandatory)][scriptblock]$Exec, [Parameter(Mandatory)][AllowEmptyString()][string]$AppId,
          [scriptblock]$Audit = $null, [scriptblock]$Record = $null, [AllowNull()]$PreviousRecord = $null, [datetime]$NowUtc = [datetime]::UtcNow)
    $res = [ordered]@{ state = ''; restored = $false; missing = @(); reason = ''; userName = ''; grantId = ''; lines = @() }
    $lines = New-Object System.Collections.Generic.List[string]
    $short = { param($e) ((("$($e.Exception.Message)") -split "`n")[0]).Trim() }
    $facts = { ConvertFrom-PimSupportLegacyOwnerFacts (& $Scalar (Get-PimSupportLegacyOwnerFactsSql -AppId $AppId)) }
    $marker = { param($gid) $t = "$(& $Scalar (Get-PimSupportLegacyOwnerMarkerSql -GrantId $gid))".Trim(); if (-not $t.StartsWith('{')) { throw 'the database did not answer the marker read' }; $t | ConvertFrom-Json }
    $audit1 = { param($action, $result, $detail) if ($Audit) { try { & $Audit ([pscustomobject][ordered]@{ action = $action; target = "database user [$($res.userName)] (the Invardia Support app, by SID)"; role = 'db_owner'; rule = 'SECAUDIT-1a 4a'; result = $result; detail = $detail }) } catch { $lines.Add("an audit row could not be written ($(& $short $_))") } } }
    # RESTORE: an open proof marker closed first (its end would take the restored right away), then the direct membership back
    $restore = {
        param([string]$why)
        $pending = $false
        try {
            if ($res.grantId) {
                $m = & $marker $res.grantId
                if ([int]$m.found -eq 1 -and [int]$m.revoked -eq 0) {
                    [void](Invoke-PimSupportJitRevoke -Sql $Scalar -Mode 'all' -Source 'job' -Audit $Audit -Quiet)
                    $m = & $marker $res.grantId
                    if ([int]$m.found -eq 1 -and [int]$m.revoked -eq 0) { $pending = $true }
                }
            }
        } catch { $pending = $true }
        try {
            [void](& $Exec (Get-PimSupportLegacyOwnerRestoreSql -AppId $AppId))
            $fr = & $facts
            $res.restored = ([int]$fr.inOwner -ge 1 -and [int]$fr.inRead -ge 1)
        } catch { $res.restored = $false; $why = "$why; the restore failed ($(& $short $_))" }
        $res.state = $(if ($pending -or -not $res.restored) { 'restore-pending' } else { 'failed' })
        $res.reason = "$why -- $(if ($res.state -eq 'failed') { 'the db_owner membership was put back (read back); nothing else changed' } else { 'the db_owner membership is NOT safely back yet (the proof grant is still open or the restore did not read back); the next run of this step puts it back' })"
        & $audit1 'support.access.legacy-owner.restore' $(if ($res.state -eq 'failed') { 'ok' } else { 'failed' }) $res.reason
    }
    try { do {
        if (-not (Test-PimSupportLegacyOwnerAppId $AppId)) { $res.state = 'refused'; $res.reason = 'no Support app id was asked for -- nothing read or changed'; break }
        $f0 = & $facts
        $res.userName = "$($f0.userName)"
        # an earlier run could not put the membership back safely: finish that first (only once no proof grant is open)
        if ("$(Get-PimSupportLegacyOwnerField $PreviousRecord 'state')" -eq 'restore-pending' -and $f0.userExists -and [int]$f0.inOwner -lt 1) {
            if ([int]$f0.openMarkers -gt 0) { $res.state = 'restore-pending'; $res.reason = 'a time-limited grant is still open -- the db_owner membership is put back once it is closed'; break }
            [void](& $Exec (Get-PimSupportLegacyOwnerRestoreSql -AppId $AppId))
            $fr = & $facts
            if ([int]$fr.inOwner -ge 1) { $res.state = 'failed'; $res.restored = $true; $res.reason = 'the db_owner membership an earlier proof could not keep was put back (read back)' }
            else { $res.state = 'restore-pending'; $res.reason = 'the db_owner membership did not read back after the restore -- tried again next run' }
            & $audit1 'support.access.legacy-owner.restore' $(if ($res.restored) { 'ok' } else { 'failed' }) $res.reason
            break
        }
        $d = Get-PimSupportLegacyOwnerDecision -Facts $f0 -AppId $AppId
        $res.reason = $d.reason; $res.missing = @($d.missing)
        if ($d.action -ne 'remove') { $res.state = $d.state; break }
        # ---- 2. the ONE guarded removal, read back
        try { [void](& $Exec (Get-PimSupportLegacyOwnerRemoveSql -AppId $AppId)) }
        catch {
            $m = & $short $_
            $res.state = $(if ($m -match 'support-legacy-owner: a support session is open') { 'open-session' } elseif ($m -match 'support-legacy-owner: proof 1') { 'proof-missing' } else { 'failed' })
            if ($res.state -eq 'proof-missing') { $res.missing = @('p1') }
            $res.reason = "nothing was changed: $m"; break
        }
        $f1 = & $facts
        if ([int]$f1.inOwner -ge 1) { $res.state = 'failed'; $res.reason = 'the removal did not read back -- the db_owner membership is still there, nothing else changed'; break }
        $lines.Add("the legacy standing db_owner of the Support app's database user [$($res.userName)] is removed -- now the add + take-back is proved")
        # ---- 3a. PROVE the add: the SIGNED grant procedure, as the support SQL access job calls it
        $until = $NowUtc.ToUniversalTime().AddMinutes((Get-PimSupportLegacyOwnerProofMinutes)).ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture)
        $g = Invoke-PimSupportJitGrant -Sql $Scalar -Level 'setup' -Hours 1 -UntilUtc $until -Reason (Get-PimSupportLegacyOwnerProofReason) -OpenedBy (Get-PimSupportLegacyOwnerProofOpenedBy)
        if ("$($g.grantId)".Trim()) { $res.grantId = "$($g.grantId)".Trim() }
        & $audit1 'support.access.open' $(if ($g.ok) { 'ok' } else { 'failed' }) "SECAUDIT-1a 4a proof: level $($g.level), grant $($res.grantId), until $($g.untilUtc) $($g.problem)"
        $why = ''
        if (-not $g.ok) { $why = "the proof grant failed ($($g.problem))" }
        elseif ($g.level -ne 'setup' -or [int]$g.rolesAdded -ne 1 -or $g.extended -or $g.preExisting -or -not $g.inOwner -or -not $res.grantId) { $why = "the proof grant did not add db_owner as a new time-limited grant (level $($g.level), added $($g.rolesAdded), extended $($g.extended), pre-existing $($g.preExisting))" }
        else {
            $m1 = & $marker $res.grantId
            if ([int]$m1.found -ne 1 -or "$($m1.role)" -ne 'db_owner' -or [int]$m1.preExisting -ne 0 -or [int]$m1.revoked -ne 0) { $why = 'the proof grant''s marker did not read back as an open db_owner grant with PreExisting = 0' }
        }
        if ($why) { & $restore $why; break }
        # ---- 3b. PROVE the take-back: the SIGNED revoke procedure, source job
        $rv = Invoke-PimSupportJitRevoke -Sql $Scalar -Mode 'all' -Source 'job' -Audit $Audit -Quiet
        $mine = @(@($rv.revoked) | Where-Object { "$($_.grantId)" -eq $res.grantId -and $_.roleRemoved })
        $f2 = & $facts
        $m2 = & $marker $res.grantId
        if (-not $rv.ok -or $mine.Count -ne 1) { $why = "the proof take-back failed ($(@($rv.problems) -join '; '))" }
        elseif ([int]$f2.inOwner -ne 0 -or [int]$f2.inRead -lt 1 -or [int]$f2.openMarkers -gt 0) { $why = "the take-back did not read back (db_owner $([int]$f2.inOwner), pim_support_read $([int]$f2.inRead), open $([int]$f2.openMarkers))" }
        elseif ([int]$m2.revoked -ne 1 -or "$($m2.revokedBy)" -ne 'job' -or [int]$m2.preExisting -ne 0) { $why = 'the proof marker did not read back as revoked by the job' }
        if ($why) { & $restore $why; break }
        $res.state = 'removed'
        $res.reason = 'legacy standing db_owner removed and a JIT add + take-back proved (SECAUDIT-1a 4a), read back: no db_owner, pim_support_read intact'
        & $audit1 'support.access.legacy-owner.remove' 'ok' $res.reason
    } while ($false) } catch {
        $m = & $short $_
        if ($lines.Count -and -not $res.state) { & $restore "the step stopped ($m)" }
        else { $res.state = 'failed'; $res.reason = "nothing was changed: $m" }
    }
    $lines.Add("support-legacy-owner: $($res.state) -- $($res.reason)")
    if ($Record) {
        try {
            & $Record ([ordered]@{ state = $res.state; restored = [bool]$res.restored; missing = @($res.missing); reason = $res.reason; appId = "$AppId".Trim().ToLowerInvariant()
                                   atUtc = $NowUtc.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture) })
        } catch { $lines.Add("the answer for the updater could not be recorded ($(& $short $_)) -- the updater asks again") }
    }
    $res.lines = @($lines.ToArray())
    return [pscustomobject]$res
}
