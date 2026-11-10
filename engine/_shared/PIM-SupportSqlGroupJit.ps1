# =================================================================================================
# PIM-SupportSqlGroupJit.ps1 -- SUPPORT-SQL-JIT-1 (framework rule, owner-approved 2026-11-09): the Invardia Support app is
# a member of the install's SQL admin group (the SQL server's Entra administrator) ONLY while a support session is open,
# through a TIME-LIMITED ACTIVE PIM-for-Groups member assignment that this code makes, reads back, records and takes away.
#
#   * OPEN (Invardia's answer: consent setup, session open, level setup, maxUntil ahead): ONE request
#       POST /identityGovernance/privilegedAccess/group/assignmentScheduleRequests
#       { accessId: member, principalId: <the Support app's service principal>, groupId: <the SQL admin group>,
#         action: adminAssign (adminExtend when THIS code's grant is there and ends earlier),
#         scheduleInfo: { startDateTime: now, expiration: { type: afterDateTime, endDateTime: min(maxUntil, now + 24 h) } } }
#     MEMBER only -- ownership is never GIVEN (only the swap below removes a permanent one). NEVER permanent: there is no code path that sends noExpiration (or afterDuration). Read back,
#     then recorded: { requestId; scheduleId; endUtc } (the caller keeps it with the support state of the update run).
#   * CLOSED (or a later answer without an open session) and the record names a grant: adminRemove of that MEMBER assignment,
#     read back gone. Only when the group's assignments were READ and show THIS code's grant and NO permanent member
#     assignment of the Support app -- adminRemove names (principal, group, accessId), not a schedule, so it is never sent
#     where it could take a standing assignment this code did not make.
#   * NO ANSWER (a lost close): nothing changes -- the assignment ends by itself at its end date (at most 24 h).
#   * THE SWAP (framework IDENTITY-MOVE-1 13, owner 2026-11-09: the product finishes it) -- ONLY in a run whose answer says a
#     SETUP session is open, and only until sqlGroup.swapDone is set: the Support app's PERMANENT member / owner assignments
#     are FIRST written to sqlGroup.permanentRemoved (accessId, memberType, start, id, a timestamp -- written to the store
#     before anything is removed), THEN the permanent member is removed (read back), the time-limited member given (read
#     back; retried once in the run; NEVER the permanent one put back), THEN the permanent owner removed (read back) --
#     ownership is never given. swapDone = the time when the time-limited member AND no permanent member / owner read back.
#     After swapDone permanents are never touched again (reported if one reappears). No session open = no swap.
#   * NEVER touched otherwise: an assignment this code did not make (a time-limited one of someone else).
#   * Outside a session nothing changes: the Support app keeps only its read-only database user (pim_support_read).
#
# Graph application permissions (the updater's ONE list, engine/_shared/PIM-UpdaterGraphRoles.ps1 -- already held):
#   PrivilegedAssignmentSchedule.ReadWrite.AzureADGroup (adminAssign / adminExtend / adminRemove), PrivilegedAssignmentSchedule
#   .Read.AzureADGroup (the group's assignmentScheduleInstances), Application.Read.All (the Support app's service principal by
#   its appId). A refusal NAMES the permission and changes nothing.
#
# Seams (nothing here signs in): -Graph { param($Method, $Path, $Body) } (Graph v1.0 path, throws on an HTTP error),
# -ResolveGroup { } -> @{ groupId; name; reason } (the SQL server's Entra admin, read by the caller), -Sleep { param($s) },
# -NowUtc. PURE decision functions first. Never throws (every caller-facing function). ASCII only; PS 5.1 + 7; no modules, no az.
# =================================================================================================
Set-StrictMode -Off

function Get-PimSupportSqlGroupJitMaxHours { <# PURE. The longest a time-limited SQL admin membership may run (a literal). #> return 24 }
function Get-PimSupportSqlGroupJitRetryMinutes { <# PURE. A refused GIVE is not asked again within this many minutes (a literal). #> return 60 }
function Get-PimSupportSqlGroupJitMinExtendSeconds { <# PURE. An extend that moves the end by no more than this is not asked (a literal). Graph refuses
    a tiny adminExtend with 400 ActiveDurationTooShort ("Minimum Required is 5 minutes") -- seen live 2026-11-09/10 at 68 s and
    ~2 min moves, right after the grant; every 15-minute move went through. #> return 300 }
function Get-PimSupportSqlGroupJitCheckMinutes { <# PURE. With nothing to do, the group's assignments are read (for the finding) at most this often (a literal). #> return 60 }
function Get-PimSupportSqlGroupJitSlackSeconds { <# PURE. Two end times this close are the same end (Graph rounds; a literal). #> return 120 }
function Get-PimSupportSqlGroupJitReadBackWaits { <# PURE. Seconds waited before each read-back try (a literal). #> return @(0, 5, 10, 20) }
function Get-PimSupportSqlGroupJitAccessId { <# PURE. The ONLY access this code ever asks for (a literal -- never owner). #> return 'member' }
function Get-PimSupportSqlGroupJitJustification { <# PURE. The request's justification (a literal). #> return 'PIM Manager: Invardia support session open -- time-limited SQL admin membership (SUPPORT-SQL-JIT-1)' }
function Get-PimSupportSqlGroupJitRequestPath { <# PURE. The PIM-for-Groups assignment request collection (a literal). #> return '/identityGovernance/privilegedAccess/group/assignmentScheduleRequests' }

function ConvertTo-PimSupportSqlGroupJitUtc {
    # PURE. A time (ISO 8601 text, a [datetime] from PowerShell 7's ConvertFrom-Json, a [DateTimeOffset]) -> UTC [datetime], or $null.
    param([AllowNull()]$Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [datetime]) { if ($Value.Kind -eq [DateTimeKind]::Unspecified) { return [datetime]::SpecifyKind($Value, [DateTimeKind]::Utc) }; return $Value.ToUniversalTime() }
    if ($Value -is [DateTimeOffset]) { return $Value.UtcDateTime }
    $t = "$Value".Trim(); if (-not $t) { return $null }
    if ($t -notmatch '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}') { return $null }
    $o = [DateTimeOffset]::MinValue
    if ([DateTimeOffset]::TryParse($t, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AssumeUniversal, [ref]$o)) { return $o.UtcDateTime }
    return $null
}

function Format-PimSupportSqlGroupJitUtc {
    # PURE. yyyy-MM-ddTHH:mm:ssZ (invariant), '' for $null.
    param([AllowNull()]$Utc)
    if ($null -eq $Utc) { return '' }
    return ([datetime]$Utc).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture)
}

function Get-PimSupportSqlGroupJitField {
    # PURE. A property of a PSCustomObject or a dictionary; $null when absent.
    param([AllowNull()][object]$Object, [string]$Name)
    if ($null -eq $Object -or $Object -is [string]) { return $null }
    if ($Object -is [System.Collections.IDictionary]) { if ($Object.Contains($Name)) { return $Object[$Name] }; return $null }
    $p = $Object.PSObject.Properties[$Name]; if ($p) { return $p.Value }
    return $null
}

function Get-PimSupportSqlGroupJitGraphError {
    # PURE. The first line of a Graph failure + its refusal body (ErrorDetails), at most 300 characters.
    param([AllowNull()]$ErrorRecord)
    if ($null -eq $ErrorRecord) { return '' }
    $m = ''
    try { $m = ((("$($ErrorRecord.Exception.Message)") -split "`n")[0]).Trim() } catch { $m = "$ErrorRecord" }
    try { if ($ErrorRecord.ErrorDetails -and "$($ErrorRecord.ErrorDetails.Message)".Trim()) { $m = "$m $((("$($ErrorRecord.ErrorDetails.Message)") -split "`n")[0])".Trim() } } catch { }
    if ($m.Length -gt 300) { $m = $m.Substring(0, 297) + '...' }
    return $m
}

function Test-PimSupportSqlGroupJitPermissionError {
    # PURE. A refusal that means "this identity may not".
    param([AllowEmptyString()][AllowNull()][string]$Message)
    return [bool]("$Message" -match '(?i)\b403\b|Forbidden|Authorization_RequestDenied|Insufficient privileges|InsufficientPermissions|PermissionScopeNotGranted')
}

function Get-PimSupportSqlGroupJitWanted {
    <#
      PURE. What Invardia's answer (the consent channel's parsed answer: { ok; consent; session = { open; level; maxUntil } })
      asks of the SQL admin group NOW. Returns @{ known; open; untilUtc ([datetime] or $null); reason }.
        known $false  no readable answer (a lost close / a lost open): NOTHING changes
        open  $true   consent setup AND the session open AND its level setup AND maxUntil ahead;
                      untilUtc = min(maxUntil, now + 24 h) -- never later, never without an end
    #>
    param([AllowNull()]$Answer, [datetime]$NowUtc = [datetime]::UtcNow)
    $now = $NowUtc.ToUniversalTime()
    $o = @{ known = $false; open = $false; untilUtc = $null; reason = '' }
    if ($null -eq $Answer -or (Get-PimSupportSqlGroupJitField $Answer 'ok') -ne $true) {
        $why = "$(Get-PimSupportSqlGroupJitField $Answer 'problem')".Trim(); if (-not $why) { $why = 'no answer' }
        $o.reason = "Invardia's answer could not be read ($why)"; return $o
    }
    $o.known = $true
    $consent = "$(Get-PimSupportSqlGroupJitField $Answer 'consent')".Trim().ToLowerInvariant()
    $s = Get-PimSupportSqlGroupJitField $Answer 'session'
    $sOpen = ((Get-PimSupportSqlGroupJitField $s 'open') -eq $true)
    $lvl = "$(Get-PimSupportSqlGroupJitField $s 'level')".Trim().ToLowerInvariant()
    $mu = ConvertTo-PimSupportSqlGroupJitUtc (Get-PimSupportSqlGroupJitField $s 'maxUntil')
    if (-not $sOpen) { $o.reason = 'the support session is closed'; return $o }
    if ($consent -ne 'setup') { $o.reason = "consent $(if ($consent) { $consent } else { '(none read)' }) never gives SQL admin"; return $o }
    if ($lvl -ne 'setup') { $o.reason = "the session's level is $(if ($lvl) { $lvl } else { '(none)' }), not setup"; return $o }
    if (-not $mu) { $o.reason = 'the open session has no readable end'; return $o }
    if ($mu -le $now) { $o.reason = "the support session ended at $(Format-PimSupportSqlGroupJitUtc $mu)"; return $o }
    $cap = $now.AddHours((Get-PimSupportSqlGroupJitMaxHours))
    $o.open = $true; $o.untilUtc = $(if ($mu -lt $cap) { $mu } else { $cap }); $o['capped'] = [bool]($mu -gt $cap)
    $o.reason = "support session open (setup) until $(Format-PimSupportSqlGroupJitUtc $mu)$(if ($mu -gt $cap) { " -- capped at $(Get-PimSupportSqlGroupJitMaxHours) h: $(Format-PimSupportSqlGroupJitUtc $cap)" })"
    return $o
}

function ConvertTo-PimSupportSqlGroupJitAssignments {
    <#
      PURE. The group's ACTIVE PIM-for-Groups assignments (assignmentScheduleInstances, or assignmentSchedules) of ONE
      principal -> @( @{ id; scheduleId; accessId; permanent; endUtc } ). An instance without an end (or expiration
      noExpiration) is PERMANENT. Matched on the principal HERE (a principalId filter on Graph omits schedules).
    #>
    param([AllowNull()][object[]]$Items, [Parameter(Mandatory)][string]$PrincipalId)
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($i in @($Items)) {
        if ($null -eq $i) { continue }
        if ("$(Get-PimSupportSqlGroupJitField $i 'principalId')".Trim() -ine "$PrincipalId".Trim()) { continue }
        $exp = Get-PimSupportSqlGroupJitField (Get-PimSupportSqlGroupJitField $i 'scheduleInfo') 'expiration'
        $endRaw = Get-PimSupportSqlGroupJitField $i 'endDateTime'
        if ($null -eq $endRaw -and $exp) { $endRaw = Get-PimSupportSqlGroupJitField $exp 'endDateTime' }
        $end = ConvertTo-PimSupportSqlGroupJitUtc $endRaw
        $perm = (-not $end) -or ("$(Get-PimSupportSqlGroupJitField $exp 'type')" -ieq 'noExpiration')
        $sid = "$(Get-PimSupportSqlGroupJitField $i 'assignmentScheduleId')".Trim(); if (-not $sid) { $sid = "$(Get-PimSupportSqlGroupJitField $i 'id')".Trim() }
        $acc = "$(Get-PimSupportSqlGroupJitField $i 'accessId')".Trim().ToLowerInvariant(); if (-not $acc) { $acc = 'member' }
        $mt = "$(Get-PimSupportSqlGroupJitField $i 'memberType')".Trim()
        $stU = Format-PimSupportSqlGroupJitUtc (ConvertTo-PimSupportSqlGroupJitUtc (Get-PimSupportSqlGroupJitField $i 'startDateTime'))
        $out.Add(@{ id = "$(Get-PimSupportSqlGroupJitField $i 'id')".Trim(); scheduleId = $sid; accessId = $acc; permanent = [bool]$perm; endUtc = $(if ($perm) { $null } else { $end })
                    memberType = $mt; startUtc = $stU })
    }
    return @($out.ToArray())
}

function Test-PimSupportSqlGroupJitOurs {
    <#
      PURE. Is -Assignment the grant -Grant records (THIS code made it)? A time-limited MEMBER assignment of the recorded
      principal whose schedule id is the recorded one, or whose end is the recorded end (within the slack). A permanent one
      is NEVER ours. No record = nothing is ours.
    #>
    param([AllowNull()]$Assignment, [AllowNull()]$Grant)
    if ($null -eq $Assignment -or $null -eq $Grant) { return $false }
    if ($Assignment.permanent -or "$($Assignment.accessId)" -ne (Get-PimSupportSqlGroupJitAccessId)) { return $false }
    $gs = "$(Get-PimSupportSqlGroupJitField $Grant 'scheduleId')".Trim()
    if ($gs -and "$($Assignment.scheduleId)" -ieq $gs) { return $true }
    $ge = ConvertTo-PimSupportSqlGroupJitUtc (Get-PimSupportSqlGroupJitField $Grant 'endUtc')
    if ($ge -and $Assignment.endUtc -and [Math]::Abs(($Assignment.endUtc - $ge).TotalSeconds) -le (Get-PimSupportSqlGroupJitSlackSeconds)) { return $true }
    return $false
}

function Get-PimSupportSqlGroupJitDecision {
    <#
      PURE. (what the answer wants, the Support app's assignments on the group, the recorded grant, the last failure) ->
      @{ action = nothing | assign | extend | remove | forget; untilUtc; ours; permanent[]; reason }.
        -Wanted       Get-PimSupportSqlGroupJitWanted
        -Assignments  ConvertTo-PimSupportSqlGroupJitAssignments, or $null when they could not be read
        -Grant        the recorded grant ($null = this code made none)
        -Last         the last attempt { atUtc; action; result } (the retry pause of a GIVE)
      Rules: no answer -> nothing (the grant ends by itself). Not read -> nothing (never a write blind). A PERMANENT member
      assignment -> nothing (already a member; never touched; reported). Open: this code's grant ending earlier -> extend;
      none -> assign, unless another time-limited member assignment (not this code's) is there -> nothing. Closed: this
      code's grant there -> remove; recorded but gone -> forget. A refused assign / extend is not asked again within 60 min;
      a remove is never paused.
    #>
    # IDENTITY-MOVE-1 13 (owner 2026-11-09, the product finishes the move): -SwapDone '' + an OPEN setup session + a PERMANENT
    # member / owner assignment of the Support app -> 'swap' (record them, remove the permanent member, give the time-limited
    # one, remove the permanent owner). Only ever while a session is open. Once -SwapDone is set, permanents are never
    # touched again (a permanent member then blocks, as before).
    param([Parameter(Mandatory)]$Wanted, [AllowNull()][object[]]$Assignments, [AllowNull()]$Grant, [AllowNull()]$Last = $null,
          [datetime]$NowUtc = [datetime]::UtcNow, [int]$RetryMinutes = (Get-PimSupportSqlGroupJitRetryMinutes), [AllowEmptyString()][AllowNull()][string]$SwapDone = '')
    $now = $NowUtc.ToUniversalTime()
    $d = @{ action = 'nothing'; untilUtc = $Wanted.untilUtc; ours = $null; permanent = @(); reason = '' }
    $gEnd = ConvertTo-PimSupportSqlGroupJitUtc (Get-PimSupportSqlGroupJitField $Grant 'endUtc')
    if (-not $Wanted.known) {
        $d.reason = "$($Wanted.reason) -- nothing changes$(if ($Grant) { "; this code's time-limited membership ends by itself at $(Format-PimSupportSqlGroupJitUtc $gEnd)" })"
        return $d
    }
    if ($null -eq $Assignments) { $d.reason = "the SQL admin group's assignments could not be read -- nothing changes (never a write without the read)"; return $d }
    $all = @($Assignments)
    $d.permanent = @(@($all | Where-Object { $_.permanent } | ForEach-Object { "$($_.accessId)" }) | Sort-Object -Unique)
    $permMember = [bool](@($all | Where-Object { $_.permanent -and $_.accessId -eq (Get-PimSupportSqlGroupJitAccessId) }).Count)
    $ours = @($all | Where-Object { Test-PimSupportSqlGroupJitOurs -Assignment $_ -Grant $Grant }) | Select-Object -First 1
    $d.ours = $ours
    $foreignTimed = @($all | Where-Object { -not $_.permanent -and $_.accessId -eq (Get-PimSupportSqlGroupJitAccessId) -and -not (Test-PimSupportSqlGroupJitOurs -Assignment $_ -Grant $Grant) })
    if ($Wanted.open -and -not "$SwapDone".Trim() -and @($d.permanent).Count) {
        $d.action = 'swap'
        $d.reason = "$($Wanted.reason): the Support app's PERMANENT $(@($d.permanent) -join ' + ') assignment is swapped for a time-limited membership until $(Format-PimSupportSqlGroupJitUtc $Wanted.untilUtc) (recorded first; ownership is not given back)"
        return $d
    }
    if ($permMember) {
        $d.reason = "the Support app holds a PERMANENT member assignment on the SQL admin group (not made by this code) -- nothing written$(if ("$SwapDone".Trim()) { " (the swap was done $($SwapDone): permanents are never touched again)" } else { '; the updater swaps it for a time-limited one in the next open support session' })"
        return $d
    }
    if ($Wanted.open) {
        $until = [datetime]$Wanted.untilUtc
        if ($ours) {
            # capped at 24 h, the end moves on with every run: extended only when it is at least an hour short (not every 15 min).
            # Otherwise only a move of MORE than 5 min is asked: Graph refuses a shorter one (ActiveDurationTooShort) -- no red.
            $short = $(if ($Wanted['capped']) { -3600 } else { -(Get-PimSupportSqlGroupJitMinExtendSeconds) })
            if ($ours.endUtc -lt $until.AddSeconds($short)) { $d.action = 'extend'; $d.reason = "$($Wanted.reason): this code's membership ends $(Format-PimSupportSqlGroupJitUtc $ours.endUtc) -- extended to $(Format-PimSupportSqlGroupJitUtc $until)" }
            else { $d.reason = "$($Wanted.reason): the time-limited membership is in place until $(Format-PimSupportSqlGroupJitUtc $ours.endUtc)" }
        } elseif ($foreignTimed.Count) {
            $d.reason = "$($Wanted.reason): a time-limited member assignment this code did not make is there (ends $(Format-PimSupportSqlGroupJitUtc $foreignTimed[0].endUtc)) -- not touched"
        } else {
            $d.action = 'assign'; $d.reason = "$($Wanted.reason): time-limited membership until $(Format-PimSupportSqlGroupJitUtc $until)"
        }
        if ($d.action -in @('assign', 'extend') -and $Last -and "$(Get-PimSupportSqlGroupJitField $Last 'result')" -eq 'failed' -and "$(Get-PimSupportSqlGroupJitField $Last 'action')" -eq $d.action) {
            $at = ConvertTo-PimSupportSqlGroupJitUtc (Get-PimSupportSqlGroupJitField $Last 'atUtc')
            if ($at -and $now -lt $at.AddMinutes($RetryMinutes)) {
                $d.reason = "$($d.reason) -- NOT asked again yet: the same request was refused at $(Format-PimSupportSqlGroupJitUtc $at); next try after $(Format-PimSupportSqlGroupJitUtc $at.AddMinutes($RetryMinutes))"
                $d.action = 'nothing'
            }
        }
        return $d
    }
    if ($ours) { $d.action = 'remove'; $d.reason = "$($Wanted.reason) -- this code's time-limited membership (until $(Format-PimSupportSqlGroupJitUtc $ours.endUtc)) is taken away"; return $d }
    if ($Grant) { $d.action = 'forget'; $d.reason = "$($Wanted.reason) -- this code's time-limited membership is no longer there (it ended $(Format-PimSupportSqlGroupJitUtc $gEnd)); the record is cleared"; return $d }
    $d.reason = "$($Wanted.reason) -- no time-limited membership; nothing to do"
    return $d
}

function New-PimSupportSqlGroupJitRequestBody {
    <#
      PURE. THE request body -- the ONLY place one is built. accessId is ALWAYS member. adminAssign / adminExtend carry an
      explicit end (expiration afterDateTime + endDateTime); without -EndUtc it THROWS -- there is no permanent form here.
      adminRemove carries no schedule. -RemoveAccess owner: ONLY with adminRemove (the swap takes the Support app's permanent
      owner assignment away; ownership is never given -- any other action with it THROWS).
    #>
    param([Parameter(Mandatory)][ValidateSet('adminAssign', 'adminExtend', 'adminRemove')][string]$Action,
          [Parameter(Mandatory)][string]$PrincipalId, [Parameter(Mandatory)][string]$GroupId, [AllowNull()]$EndUtc = $null,
          [datetime]$NowUtc = [datetime]::UtcNow, [ValidateSet('member', 'owner')][string]$RemoveAccess = 'member')
    if ($RemoveAccess -ne 'member' -and $Action -ne 'adminRemove') { throw 'New-PimSupportSqlGroupJitRequestBody: ownership is only ever REMOVED, never given' }
    $acc = Get-PimSupportSqlGroupJitAccessId
    if ($Action -eq 'adminRemove') { $acc = $RemoveAccess }
    $b = [ordered]@{ accessId = $acc; principalId = "$PrincipalId".Trim(); groupId = "$GroupId".Trim(); action = $Action
                     justification = (Get-PimSupportSqlGroupJitJustification) }
    if ($Action -ne 'adminRemove') {
        $end = ConvertTo-PimSupportSqlGroupJitUtc $EndUtc
        if (-not $end) { throw 'New-PimSupportSqlGroupJitRequestBody: a time-limited request needs its end -- no permanent request is ever built' }
        $now = $NowUtc.ToUniversalTime()
        if ($end -le $now) { throw 'New-PimSupportSqlGroupJitRequestBody: the end lies in the past' }
        if ($end -gt $now.AddHours((Get-PimSupportSqlGroupJitMaxHours)).AddSeconds(60)) { throw "New-PimSupportSqlGroupJitRequestBody: the end is more than $(Get-PimSupportSqlGroupJitMaxHours) h away" }
        $b['scheduleInfo'] = [ordered]@{ startDateTime = (Format-PimSupportSqlGroupJitUtc $now)
                                         expiration = [ordered]@{ type = 'afterDateTime'; endDateTime = (Format-PimSupportSqlGroupJitUtc $end) } }
    }
    return $b
}

function Invoke-PimSupportSqlGroupJitReadAssignments {
    <#
      READ ONLY. The Support app's ACTIVE PIM-for-Groups assignments on the group (every page), filtered by groupId AND
      principalId (IDENTITY-MOVE-1 13: an unfiltered list answers NOTHING for some callers). Never throws. @{ ok; items; error }.
    #>
    param([Parameter(Mandatory)][scriptblock]$Graph, [Parameter(Mandatory)][string]$GroupId, [Parameter(Mandatory)][string]$PrincipalId)
    try {
        $all = New-Object System.Collections.Generic.List[object]
        $path = "/identityGovernance/privilegedAccess/group/assignmentScheduleInstances?`$filter=groupId eq '$GroupId' and principalId eq '$PrincipalId'"
        $guard = 0
        while ($path -and $guard -lt 50) {
            $guard++
            $page = & $Graph 'GET' $path $null
            foreach ($v in @((Get-PimSupportSqlGroupJitField $page 'value'))) { if ($v) { $all.Add($v) } }
            $path = "$(Get-PimSupportSqlGroupJitField $page '@odata.nextLink')".Trim()
        }
        return @{ ok = $true; items = @($all.ToArray()); error = '' }
    } catch { return @{ ok = $false; items = $null; error = (Get-PimSupportSqlGroupJitGraphError $_) } }
}

function Resolve-PimSupportSqlGroupJitPrincipal {
    # READ ONLY. The Support app's service principal object id from its application (client) id. Never throws. @{ id; reason }.
    param([Parameter(Mandatory)][scriptblock]$Graph, [AllowEmptyString()][AllowNull()][string]$AppId)
    $a = "$AppId".Trim().ToLowerInvariant()
    if ($a -notmatch '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$') { return @{ id = ''; reason = 'no Support app id is known' } }
    try {
        $r = & $Graph 'GET' ("/servicePrincipals?`$filter=appId eq '$a'" + '&$select=id,appId') $null
        $sp = @(@(Get-PimSupportSqlGroupJitField $r 'value') | Where-Object { $_ -and "$(Get-PimSupportSqlGroupJitField $_ 'appId')".Trim() -ieq $a })[0]
        if (-not $sp) { return @{ id = ''; reason = 'the Support app has no service principal in this tenant' } }
        return @{ id = "$(Get-PimSupportSqlGroupJitField $sp 'id')".Trim().ToLowerInvariant(); reason = '' }
    } catch {
        $m = Get-PimSupportSqlGroupJitGraphError $_
        return @{ id = ''; reason = "the Support app's service principal could not be read ($m)$(if (Test-PimSupportSqlGroupJitPermissionError $m) { ' -- the updater needs Application.Read.All' })" }
    }
}

function Get-PimSupportSqlGroupJitFindingText {
    # PURE. The finding in plain words for a permanent assignment of the Support app on the SQL admin group ('' = none).
    param([AllowNull()][object[]]$Permanent)
    $p = @(@($Permanent) | Where-Object { "$_".Trim() } | ForEach-Object { "$_".Trim().ToLowerInvariant() } | Sort-Object -Unique)
    if (-not $p.Count) { return '' }
    return "WARNING: the Invardia Support app holds a PERMANENT $($p -join ' + ') assignment on the SQL admin group -- it is SQL admin even with no support session open (the updater swaps it for a time-limited membership in the next open support session)"
}

function Invoke-PimSupportSqlGroupJitStep {
    <#
      The updater's step, after the consent decision, on EVERY run. NEVER throws, never fails the update.
        -Answer        the consent channel's parsed answer of THIS run ({ ok; consent; appId; session })
        -AppId         the Support app's application id (the answer's, else the database's) -- else the record's
        -Previous      the record of the last run ({ groupId; principalId; appId; checkedUtc; permanent; grant; last }) or $null
        -Graph         { param($Method, $Path, $Body) }
        -ResolveGroup  { } -> @{ groupId; name; reason } -- called only when Graph work is due
      Graph is asked ONLY when something may be due: an open session, a recorded grant with an answer, or (for the finding)
      at most once an hour. No answer = no Graph at all.
      Returns [pscustomobject]@{ ok; action; result; changed; say; line; finding; record }. record = the new record (keep it
      with the support state); changed = it differs from -Previous; say = the line is worth printing.
    #>
    param([AllowNull()]$Answer, [AllowEmptyString()][AllowNull()][string]$AppId = '', [AllowNull()]$Previous = $null,
          [AllowNull()][scriptblock]$Graph, [AllowNull()][scriptblock]$ResolveGroup, [datetime]$NowUtc = [datetime]::UtcNow,
          [scriptblock]$Sleep = $null, [int[]]$ReadBackWaits = (Get-PimSupportSqlGroupJitReadBackWaits),
          # IDENTITY-MOVE-1 13: { param($Record) } writes the record NOW (throws on failure) -- the swap writes the permanent
          # assignments it is about to remove BEFORE the first remove; no writer / a failed write = the swap does not start
          [AllowNull()][scriptblock]$SaveRecord = $null)
    if (-not $Sleep) { $Sleep = { param($s) Start-Sleep -Seconds $s } }
    $now = $NowUtc.ToUniversalTime()
    $out = [ordered]@{ ok = $true; action = 'nothing'; result = 'ok'; changed = $false; say = $false; line = ''; finding = ''; record = $Previous }
    try {
        $prevGrant = Get-PimSupportSqlGroupJitField $Previous 'grant'
        if ($prevGrant -and -not "$(Get-PimSupportSqlGroupJitField $prevGrant 'endUtc')".Trim()) { $prevGrant = $null }
        $prevPerm = @(@(Get-PimSupportSqlGroupJitField $Previous 'permanent') | Where-Object { "$_".Trim() })
        $out.finding = Get-PimSupportSqlGroupJitFindingText $prevPerm
        $wanted = Get-PimSupportSqlGroupJitWanted -Answer $Answer -NowUtc $now
        $appIdUse = "$AppId".Trim().ToLowerInvariant(); if (-not $appIdUse) { $appIdUse = "$(Get-PimSupportSqlGroupJitField $Previous 'appId')".Trim().ToLowerInvariant() }

        # ---- is any Graph work due? ----------------------------------------------------------------------------------
        $lastCheck = ConvertTo-PimSupportSqlGroupJitUtc (Get-PimSupportSqlGroupJitField $Previous 'checkedUtc')
        $due = $false
        if ($wanted.known -and ($wanted.open -or $prevGrant)) { $due = $true }
        elseif ($wanted.known -and (-not $lastCheck -or $now -ge $lastCheck.AddMinutes((Get-PimSupportSqlGroupJitCheckMinutes)))) { $due = $true }
        if (-not $due) {
            $d0 = Get-PimSupportSqlGroupJitDecision -Wanted $wanted -Assignments @() -Grant $prevGrant -NowUtc $now
            $out.line = "support SQL group: $(if ($wanted.known) { "$($wanted.reason) -- nothing to do (checked $(Format-PimSupportSqlGroupJitUtc $lastCheck))" } else { $d0.reason })"
            return [pscustomobject]$out
        }
        if (-not $Graph) { $out.line = 'support SQL group: Microsoft Graph is not available in this run -- nothing changes'; return [pscustomobject]$out }
        if (-not $appIdUse) { $out.line = "support SQL group: no Support app id is known -- nothing changes"; return [pscustomobject]$out }

        # ---- the group and the Support app's service principal (cached in the record) -------------------------------------
        $gid = ''; $gname = ''
        if ($ResolveGroup) {
            $gr = $null; try { $gr = & $ResolveGroup } catch { $gr = @{ groupId = ''; reason = (Get-PimSupportSqlGroupJitGraphError $_) } }
            $gid = "$(Get-PimSupportSqlGroupJitField $gr 'groupId')".Trim().ToLowerInvariant(); $gname = "$(Get-PimSupportSqlGroupJitField $gr 'name')".Trim()
            if (-not $gid) { $out.line = "support SQL group: the SQL admin group is not known ($("$(Get-PimSupportSqlGroupJitField $gr 'reason')".Trim())) -- nothing changes"; $out.result = 'skipped'; $out.say = [bool]$wanted.open; return [pscustomobject]$out }
        }
        if (-not $gid) { $out.line = 'support SQL group: the SQL admin group is not known -- nothing changes'; $out.result = 'skipped'; return [pscustomobject]$out }
        $pid0 = ''
        if ("$(Get-PimSupportSqlGroupJitField $Previous 'appId')".Trim() -ieq $appIdUse) { $pid0 = "$(Get-PimSupportSqlGroupJitField $Previous 'principalId')".Trim().ToLowerInvariant() }
        if (-not $pid0) {
            $sgjPrincipal = Resolve-PimSupportSqlGroupJitPrincipal -Graph $Graph -AppId $appIdUse
            if (-not $sgjPrincipal.id) { $out.ok = (-not $wanted.open); $out.result = 'failed'; $out.say = $true; $out.line = "support SQL group: $($sgjPrincipal.reason) -- nothing changes"; return [pscustomobject]$out }
            $pid0 = $sgjPrincipal.id
        }
        # a grant recorded for ANOTHER group or principal is not this one's (never acted on here; it ends by itself)
        if ($prevGrant -and ("$(Get-PimSupportSqlGroupJitField $Previous 'groupId')".Trim() -ine $gid -or "$(Get-PimSupportSqlGroupJitField $Previous 'principalId')".Trim() -ine $pid0)) { $prevGrant = $null }

        # ---- read, decide ---------------------------------------------------------------------------------------------
        $swapDone = "$(Get-PimSupportSqlGroupJitField $Previous 'swapDone')".Trim()
        $swapDoneU = ConvertTo-PimSupportSqlGroupJitUtc (Get-PimSupportSqlGroupJitField $Previous 'swapDone'); if ($swapDoneU) { $swapDone = Format-PimSupportSqlGroupJitUtc $swapDoneU }
        $permRemoved = Get-PimSupportSqlGroupJitField $Previous 'permanentRemoved'
        $rd = Invoke-PimSupportSqlGroupJitReadAssignments -Graph $Graph -GroupId $gid -PrincipalId $pid0
        $asg = $null; if ($rd.ok) { $asg = @(ConvertTo-PimSupportSqlGroupJitAssignments -Items $rd.items -PrincipalId $pid0) }
        $dec = Get-PimSupportSqlGroupJitDecision -Wanted $wanted -Assignments $asg -Grant $prevGrant -Last (Get-PimSupportSqlGroupJitField $Previous 'last') -NowUtc $now -SwapDone $swapDone
        $out.action = "$($dec.action)"
        $perm = $(if ($rd.ok) { @($dec.permanent) } else { $prevPerm })
        $out.finding = Get-PimSupportSqlGroupJitFindingText $perm
        $grant = $prevGrant; $detail = ''; $res = 'ok'
        # -> @{ read = [bool] (at least one read answered); items = the last list read } -- a wrapper, so an EMPTY list read
        # back (the membership gone) is never mistaken for "not read"
        $readBack = {
            param($want)
            $last = @{ read = $false; items = @() }
            foreach ($w in @($ReadBackWaits)) {
                if ([int]$w -gt 0) { & $Sleep ([int]$w) }
                $r = Invoke-PimSupportSqlGroupJitReadAssignments -Graph $Graph -GroupId $gid -PrincipalId $pid0
                if ($r.ok) { $last = @{ read = $true; items = @(ConvertTo-PimSupportSqlGroupJitAssignments -Items $r.items -PrincipalId $pid0) }; if (& $want $last.items) { break } }
            }
            return $last
        }
        $post = {
            param($body)
            $r = & $Graph 'POST' (Get-PimSupportSqlGroupJitRequestPath) $body
            $st = "$(Get-PimSupportSqlGroupJitField $r 'status')".Trim()
            # a give that is not provisioned, or a remove that is not done, is a refusal (adminRemove answers Revoked when done)
            $bad = '(?i)^(Denied|Failed|Canceled|PendingApproval|PendingAdminDecision)'
            if ("$($body.action)" -ne 'adminRemove') { $bad = '(?i)^(Denied|Failed|Canceled|Revoked|PendingApproval|PendingAdminDecision)' }
            if ($st -match $bad) { throw "the request was not done (status $st)" }
            return $r
        }
        $gEndTxt = Format-PimSupportSqlGroupJitUtc (ConvertTo-PimSupportSqlGroupJitUtc (Get-PimSupportSqlGroupJitField $prevGrant 'endUtc'))
        # ONE time-limited member request (adminAssign / adminExtend) + its read-back -> @{ ok; refused; grant; detail }. Never
        # anything but the builder's time-limited member form.
        $give = {
            param([string]$act, [datetime]$until)
            $g = @{ ok = $false; refused = $false; grant = $null; detail = '' }
            $r = $null
            try { $r = & $post (New-PimSupportSqlGroupJitRequestBody -Action $act -PrincipalId $pid0 -GroupId $gid -EndUtc $until -NowUtc $now) }
            catch {
                # REFUSED: reported, never asked again in another form (no permanent, no other duration)
                $m = Get-PimSupportSqlGroupJitGraphError $_
                $g.refused = $true
                $g.detail = "$act refused: $m$(if (Test-PimSupportSqlGroupJitPermissionError $m) { ' -- the updater needs PrivilegedAssignmentSchedule.ReadWrite.AzureADGroup' })"
                return $g
            }
            $want = { param($l) [bool](@(@($l) | Where-Object { -not $_.permanent -and $_.accessId -eq 'member' -and $_.endUtc -and [Math]::Abs(($_.endUtc - $until).TotalSeconds) -le (Get-PimSupportSqlGroupJitSlackSeconds) }).Count) }
            $back = & $readBack $want
            $hit = @(@($back.items) | Where-Object { -not $_.permanent -and $_.accessId -eq 'member' -and $_.endUtc -and [Math]::Abs(($_.endUtc - $until).TotalSeconds) -le (Get-PimSupportSqlGroupJitSlackSeconds) }) | Select-Object -First 1
            $g.grant = [ordered]@{ requestId = "$(Get-PimSupportSqlGroupJitField $r 'id')".Trim(); scheduleId = $(if ($hit) { "$($hit.scheduleId)" } else { "$(Get-PimSupportSqlGroupJitField $r 'targetScheduleId')".Trim() })
                                   endUtc = (Format-PimSupportSqlGroupJitUtc $(if ($hit) { $hit.endUtc } else { $until })); madeUtc = (Format-PimSupportSqlGroupJitUtc $now); action = $act; readBack = [bool]$hit }
            if (-not $hit) { $g.detail = "$act accepted (request $($g.grant.requestId)) but the membership was NOT read back -- recorded; it ends by itself at $($g.grant.endUtc)" }
            else { $g.ok = $true; $g.detail = "$($act): the Support app is a member of the SQL admin group until $($g.grant.endUtc) (read back; request $($g.grant.requestId))" }
            return $g
        }
        # ONE adminRemove of a PERMANENT assignment (-acc member | owner) + its read-back (no permanent one of that access left)
        $takePermanent = {
            param([string]$acc)
            try { [void](& $post (New-PimSupportSqlGroupJitRequestBody -Action 'adminRemove' -PrincipalId $pid0 -GroupId $gid -NowUtc $now -RemoveAccess $acc)) }
            catch { return @{ ok = $false; detail = "the permanent $acc assignment could NOT be removed: $(Get-PimSupportSqlGroupJitGraphError $_)" } }
            $none = { param($l) -not [bool](@(@($l) | Where-Object { $_.permanent -and $_.accessId -eq $acc }).Count) }
            $back = & $readBack $none
            if ($back.read -and (& $none $back.items)) { return @{ ok = $true; detail = "the permanent $acc assignment is removed (read back)" } }
            return @{ ok = $false; detail = "the permanent $acc assignment was NOT read back as removed" }
        }
        $finalItems = $null     # the last list read after this run's writes ($null = take the first read)
        switch ($dec.action) {
            { $_ -in @('assign', 'extend') } {
                $act = $(if ($dec.action -eq 'extend') { 'adminExtend' } else { 'adminAssign' })
                $g = & $give $act ([datetime]$dec.untilUtc)
                $detail = $g.detail
                if ($g.refused) { $res = 'failed'; break }
                $grant = $g.grant
                if (-not $g.ok) { $res = 'failed' }
            }
            'swap' {
                # IDENTITY-MOVE-1 13: the product finishes the move, only while a setup session is open (support keeps write
                # access through it: the database-level JIT gives db_owner for the session anyway).
                $pItems = @(@($asg) | Where-Object { $_.permanent })
                $parts = New-Object System.Collections.Generic.List[string]
                # (1) the record FIRST -- nothing is removed before it is written
                $entry = [ordered]@{ atUtc = (Format-PimSupportSqlGroupJitUtc $now)
                                     items = @($pItems | ForEach-Object { [ordered]@{ accessId = "$($_.accessId)"; memberType = "$($_.memberType)"; start = "$($_.startUtc)"; id = "$($_.id)" } }) }
                # an earlier record (a swap that did not finish) is kept beside it, never overwritten
                $earlier = $null
                if (Get-PimSupportSqlGroupJitField $permRemoved 'atUtc') { $earlier = [ordered]@{ atUtc = "$(Get-PimSupportSqlGroupJitField $permRemoved 'atUtc')"; items = @(Get-PimSupportSqlGroupJitField $permRemoved 'items') } }
                $permRemoved = [ordered]@{ atUtc = $entry.atUtc; items = $entry.items; earlier = $earlier }
                $pre = [ordered]@{ groupId = $gid; principalId = $pid0; appId = $appIdUse; checkedUtc = (Format-PimSupportSqlGroupJitUtc $now); permanent = @($dec.permanent)
                                   grant = $grant; last = (Get-PimSupportSqlGroupJitField $Previous 'last'); permanentRemoved = $permRemoved; swapDone = '' }
                $saved = $false
                if ($SaveRecord) { try { & $SaveRecord $pre; $saved = $true } catch { $parts.Add("the record of the permanent assignments could NOT be written ($(Get-PimSupportSqlGroupJitGraphError $_))") } }
                else { $parts.Add('there is no way to write the record of the permanent assignments in this run') }
                if (-not $saved) { $res = 'failed'; $permRemoved = Get-PimSupportSqlGroupJitField $Previous 'permanentRemoved'; $detail = "swap NOT started: $($parts -join '; ') -- nothing was removed"; break }
                $parts.Add("recorded $(@($pItems).Count) permanent assignment(s) first")
                $memberOk = $true
                # (2) the permanent MEMBER out
                if (@($pItems | Where-Object { $_.accessId -eq 'member' }).Count) {
                    $t = & $takePermanent 'member'; $parts.Add($t.detail)
                    if (-not $t.ok) { $memberOk = $false; $res = 'failed' }
                }
                # (3) the time-limited member in -- retried ONCE in this run; NEVER the permanent one back
                if ($memberOk) {
                    $g = & $give 'adminAssign' ([datetime]$dec.untilUtc)
                    if (-not $g.ok) { $parts.Add("$($g.detail) -- tried again"); $g = & $give 'adminAssign' ([datetime]$dec.untilUtc) }
                    if ($g.grant) { $grant = $g.grant }
                    $parts.Add($g.detail)
                    if (-not $g.ok) {
                        $res = 'failed'
                        $parts.Add('WARNING: the time-limited membership could NOT be given twice -- the Support app is NOT in the SQL admin group now (the permanent one is NOT put back); the open session still gives db_owner through the database-level time-limited access, so support is not cut off; the next run tries again')
                    }
                }
                # (4) the permanent OWNER out -- ownership is never given back
                if (@($pItems | Where-Object { $_.accessId -eq 'owner' }).Count) {
                    $t = & $takePermanent 'owner'; $parts.Add($t.detail)
                    if (-not $t.ok) { $res = 'failed' }
                }
                $fr = Invoke-PimSupportSqlGroupJitReadAssignments -Graph $Graph -GroupId $gid -PrincipalId $pid0
                if ($fr.ok) { $finalItems = @(ConvertTo-PimSupportSqlGroupJitAssignments -Items $fr.items -PrincipalId $pid0) } else { $finalItems = $null; $parts.Add("the end state could not be read ($($fr.error))") }
                $detail = "swap: $($parts -join '; ')"
                if (-not $fr.ok) { $res = 'failed' }
            }
            'remove' {
                $refused = $false
                try { [void](& $post (New-PimSupportSqlGroupJitRequestBody -Action 'adminRemove' -PrincipalId $pid0 -GroupId $gid -NowUtc $now)) }
                catch {
                    $m = Get-PimSupportSqlGroupJitGraphError $_
                    $refused = $true
                    $res = 'failed'; $detail = "adminRemove refused: $m -- the membership ends by itself at $gEndTxt; every run tries again$(if (Test-PimSupportSqlGroupJitPermissionError $m) { ' (the updater needs PrivilegedAssignmentSchedule.ReadWrite.AzureADGroup)' })"
                }
                if ($refused) { break }
                $gone = { param($l) -not [bool](@(@($l) | Where-Object { Test-PimSupportSqlGroupJitOurs -Assignment $_ -Grant $prevGrant }).Count) }
                $back = & $readBack $gone
                if ($back.read -and (& $gone $back.items)) { $grant = $null; $detail = 'adminRemove: the time-limited membership is gone (read back)' }
                else { $res = 'failed'; $detail = "adminRemove accepted but the membership was NOT read back as gone -- every run tries again; it ends by itself at $gEndTxt" }
            }
            'forget' { $grant = $null }
        }
        if ($res -eq 'failed') { $out.ok = $false }
        $out.result = $res
        # the end state: after a swap its own final read, else this run's read (an assign / extend just read itself back)
        if ($null -ne $finalItems) { $perm = @(@($finalItems | Where-Object { $_.permanent } | ForEach-Object { "$($_.accessId)" }) | Sort-Object -Unique) }
        elseif ($dec.action -eq 'swap') { $perm = $prevPerm }
        $out.finding = Get-PimSupportSqlGroupJitFindingText $perm
        $oursNow = $false
        if ($grant) {
            if ($null -ne $finalItems) { $oursNow = [bool](@($finalItems | Where-Object { Test-PimSupportSqlGroupJitOurs -Assignment $_ -Grant $grant }).Count) }
            elseif ($dec.action -in @('assign', 'extend')) { $oursNow = ($res -eq 'ok') }
            elseif ($rd.ok -and $dec.action -eq 'nothing') { $oursNow = [bool](@(@($asg) | Where-Object { Test-PimSupportSqlGroupJitOurs -Assignment $_ -Grant $grant }).Count) }
        }
        # swapDone: ONCE the time-limited member reads back AND no permanent member / owner reads back (in an open session)
        if (-not $swapDone -and $wanted.open -and $rd.ok -and $oursNow -and -not @($perm).Count -and ($dec.action -ne 'swap' -or $null -ne $finalItems)) {
            $swapDone = Format-PimSupportSqlGroupJitUtc $now
            $detail = "$detail$(if ($detail) { ' -- ' })swap done: time-limited only (swapped $swapDone)"
        }
        $last = Get-PimSupportSqlGroupJitField $Previous 'last'
        if ($dec.action -ne 'nothing') { $last = [ordered]@{ atUtc = (Format-PimSupportSqlGroupJitUtc $now); action = "$($dec.action)"; result = $res; detail = $detail } }
        $out.record = [ordered]@{ groupId = $gid; principalId = $pid0; appId = $appIdUse; checkedUtc = $(if ($rd.ok) { Format-PimSupportSqlGroupJitUtc $now } else { "$(Get-PimSupportSqlGroupJitField $Previous 'checkedUtc')" })
                                  permanent = @($perm); grant = $grant; last = $last; permanentRemoved = $permRemoved; swapDone = $swapDone }
        $out.changed = $true
        $newFinding = ((@($perm) | Sort-Object) -join ',') -ne ((@($prevPerm) | Sort-Object) -join ',')
        $out.say = [bool](($dec.action -ne 'nothing') -or ($res -eq 'failed') -or ((-not $rd.ok) -and $wanted.open) -or ($newFinding -and $out.finding))
        $out.line = "support SQL group$(if ($gname) { " ($gname)" }): $($dec.action)$(if ($dec.action -ne 'nothing') { " ($res)" }) -- $($dec.reason)$(if ($detail) { " -- $detail" })$(if (-not $rd.ok) { " -- read: $($rd.error)" })$(if ($out.finding) { " -- $($out.finding)" })"
    } catch {
        $out.ok = $false; $out.result = 'failed'; $out.say = $true
        $out.line = "support SQL group: the step stopped ($(Get-PimSupportSqlGroupJitGraphError $_)) -- nothing more changes; a time-limited membership ends by itself"
    }
    return [pscustomobject]$out
}
