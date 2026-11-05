#Requires -Version 5.1
<#
.SYNOPSIS
    PIM DBINIT-MEMBERSHIP (framework 4.5 point 5, owner via Invardia 2026-11-05) -- the database job's identity (id-pim-dbinit)
    is put into the install's SQL admin group ONLY by the product's own update code, never by a hand-made Graph call, and the
    database job is never started on a membership that was not read back.

.DESCRIPTION
    THE ORDER (framework 4.5 point 5):
      (a) a direct member add (POST /groups/<group>/members/$ref);
      (b) else an ACTIVE PIM-for-Groups member assignment (POST /identityGovernance/privilegedAccess/group/
          assignmentScheduleRequests, accessId member, action adminAssign) -- PERMANENT first (noExpiration); TIME-LIMITED only
          when the group's PIM policy refuses a permanent one, and then the run SAYS so, with the end date;
      (c) READ BACK (the identity's memberOf, or the group's assignmentScheduleInstances) BEFORE the dependent job starts;
      (d) both refused = both errors named, and the dependent job is NOT started.
    RENEWAL: a time-limited assignment that ends within 30 days is renewed (adminExtend while it runs, adminRenew once it has
    ended -- the Graph semantics PIM's engine uses for its own groups, engine/_shared/PIM-EngineProviders.ps1
    Invoke-PimGraphScheduleMaintenance) and read back. A renewal that fails is a WARNING with the end date, never a failed update.
    PERMISSIONS (framework 4.5 G5, Invardia, binding 2026-11-05 -- the ONE list: engine/_shared/PIM-UpdaterGraphRoles.ps1):
    PrivilegedAssignmentSchedule.ReadWrite.AzureADGroup (b + renewal), PrivilegedAssignmentSchedule.Read.AzureADGroup (the
    read-back through the group's assignments), RoleManagementPolicy.Read.AzureADGroup (the policy maximum), GroupMember.Read.All
    (read only: the group and the identity's memberOf). No directory-role right, no group write right: the SQL admin group is ROLE-ASSIGNABLE at most installs ON PURPOSE (SEC-32), so the direct add (a) is refused there --
    EXPECTED, (b) follows quietly, and (a) is never named as a missing right. The group's isAssignableToRole is only READ (for
    the line) -- the group is NEVER changed, replaced or re-created here. A refusal of (b) or of the read NAMES the missing
    permission and changes nothing -- nothing is ever granted here.
    PURE functions first, then the Invoke- functions with injected seams:
      -Graph { param($Method, $Path, $Body) }  (Graph v1.0 path; throws on an HTTP error)
      -Arm   { param($Method, $Path, $Body) }  (path WITH api-version)
      -Sleep { param($Seconds) }
    Loaded ONLY by the updater (tools/pim-engine/update-job-entry.ps1), after PIM-DbInitJob.ps1 (Get-PimDbInitUaMap,
    Get-PimDbInitJobEnv, Get-PimDbInitObjField). Kept out of PIM-DbInitJob.ps1 on purpose: that file is read-only for
    memberships (Test-PimDbInitJob Z3) and is loaded by setup scripts a customer runs (Test-PimScriptDocs B2).
    Never starts a job. Never throws (every caller-facing function). ASCII only; PS 5.1 + 7; no modules, no az.
#>
Set-StrictMode -Off

function Get-PimDbInitMembershipRenewDays { <# PURE. A time-limited membership is renewed when it ends within this many days (a literal). #> return 30 }
function Get-PimDbInitMembershipDurations { <# PURE. The durations asked when the policy refuses a permanent assignment and its maximum is not readable (a literal ladder). #> return @('P365D', 'P180D', 'P90D', 'P30D', 'P14D', 'P7D', 'P1D') }
function Get-PimDbInitMembershipReadBackWaits { <# PURE. Seconds waited before each read-back try (a literal). #> return @(0, 10, 20, 30) }

function Get-PimDbInitTokenWaitHours { <# PURE. Framework 4.5 G3a: a managed identity's token keeps its old group claims up to this long after a FRESH membership (a literal). #> return 24 }
function Get-PimDbInitTokenRetryMinutes { <# PURE. While waiting for the token, a job that runs as the identity is started again at most this often (a literal). #> return 60 }
function Get-PimDbInitAddedSetting { <# PURE. The pim.Settings name the updater records a FRESH membership add in (a literal). #> return 'DbInitMembershipAdded' }
function Get-PimDbInitTokenWaitSetting { <# PURE. The pim.Settings name of the last 'waiting for the token' (a literal). #> return 'DbInitTokenWait' }

function Test-PimDbInitLoginFailed {
    # PURE. A job ended because the database refused the identity's sign-in (the old token, framework 4.5 G3a).
    param([AllowNull()][object[]]$Problems)
    return [bool](@(@($Problems) | Where-Object { "$_" -match "(?i)Login failed for user|\b18456\b|token-identified principal" }).Count)
}

function Get-PimDbInitTokenWait {
    <#
      PURE. Framework 4.5 G3a (binding 2026-11-05): a managed identity's token keeps its OLD group claims for up to ~24 h, so
      right after a FRESH add the Graph read-back is true while the identity's SQL sign-in through the group can still fail.
        -AddedUtc      when THIS product's code added the membership (pim.Settings DbInitMembershipAdded); $null / '' = the
                       membership existed before (a hand-made one) -> never waiting: a failure stays a failure
        -Problems      a job run's problems (the login failure is read from them) -- or $null before a start
        -LastWaitUtc   the last 'waiting' (pim.Settings DbInitTokenWait)
      Returns @{ window; hold; wait; untilUtc; reason }:
        window  the add is less than 24 h old
        hold    BEFORE a start: inside the window and the last wait less than 60 min ago -> do not start (no retry storm)
        wait    AFTER a run: the login failed inside the window -> 'waiting for the token to refresh', NOT failed
    #>
    param([AllowNull()]$AddedUtc, [AllowNull()][object[]]$Problems = $null, [AllowNull()]$LastWaitUtc = $null, [datetime]$NowUtc = [datetime]::UtcNow)
    $o = @{ window = $false; hold = $false; wait = $false; untilUtc = ''; reason = '' }
    $now = $NowUtc.ToUniversalTime()
    $added = ConvertTo-PimDbInitUtc $AddedUtc
    if (-not $added) { return $o }
    $until = $added.AddHours((Get-PimDbInitTokenWaitHours))
    if ($now -ge $until -or $added -gt $now.AddMinutes(5)) { return $o }
    $o.window = $true; $o.untilUtc = Format-PimDbInitUtc $until
    $why = "waiting for the token to refresh: the database job identity was added to the SQL admin group at $(Format-PimDbInitUtc $added); its token can keep the old group claims until $($o.untilUtc) (framework 4.5 G3a)"
    $last = ConvertTo-PimDbInitUtc $LastWaitUtc
    if ($null -eq $Problems -and $last -and $now -lt $last.AddMinutes((Get-PimDbInitTokenRetryMinutes))) {
        $o.hold = $true; $o.reason = "$why -- not started again before $(Format-PimDbInitUtc $last.AddMinutes((Get-PimDbInitTokenRetryMinutes)))"
        return $o
    }
    if ($null -ne $Problems -and (Test-PimDbInitLoginFailed $Problems)) { $o.wait = $true; $o.reason = "$why -- the sign-in was refused; tried again in $(Get-PimDbInitTokenRetryMinutes) min" }
    return $o
}

function Get-PimDbInitMembershipPermission {
    <#
      PURE. The Graph application permission a step needs (literals; named in a refusal). Framework 4.5 G5 (Invardia, binding
      2026-11-05): the identity holds the PIM-for-Groups rights + GroupMember.Read.All (read only), no group write and no
      directory role -- a role-assignable group (SEC-32) refuses the direct add
      (a) without a directory-role right, and that refusal is EXPECTED: (b) follows quietly and (a) is never named as a missing
      right. SI proved at a customer that the PIM-for-Groups rights alone add and read back a member of a role-assignable group.
    #>
    param([ValidateSet('pim', 'read', 'memberof')][string]$Step)
    switch ($Step) {
        'pim'      { return 'PrivilegedAssignmentSchedule.ReadWrite.AzureADGroup' }
        'read'     { return 'PrivilegedAssignmentSchedule.Read.AzureADGroup' }
        # the member-side read GET /servicePrincipals/{id}/memberOf reads a SERVICE PRINCIPAL: GroupMember.Read.All AND
        # Application.Read.All (framework 4.5 G5, Invardia 2026-11-05, cea85308) -- a refusal names both
        'memberof' { return @('GroupMember.Read.All', 'Application.Read.All') }
    }
}
function Get-PimDbInitGroupRoleAssignable {
    # READ ONLY. The group's isAssignableToRole: $true / $false, $null when it could not be read. Never throws, never writes.
    param([Parameter(Mandatory)][scriptblock]$Graph, [Parameter(Mandatory)][string]$GroupId)
    try {
        $g = & $Graph 'GET' ("/groups/$GroupId" + '?$select=id,isAssignableToRole') $null
        $v = Get-PimDbInitObjField $g 'isAssignableToRole'
        if ($v -eq $true -or "$v" -ieq 'true') { return $true }
        if ($v -eq $false -or "$v" -ieq 'false') { return $false }
    } catch { }
    return $null
}

function Get-PimDbInitGraphError {
    # PURE. The text of a Graph failure: the first line of the message + the refusal body (ErrorDetails) when there is one.
    param([AllowNull()]$ErrorRecord)
    if ($null -eq $ErrorRecord) { return '' }
    $m = ''
    try { $m = ((("$($ErrorRecord.Exception.Message)") -split "`n")[0]).Trim() } catch { $m = "$ErrorRecord" }
    try { if ($ErrorRecord.ErrorDetails -and "$($ErrorRecord.ErrorDetails.Message)".Trim()) { $m = "$m $((("$($ErrorRecord.ErrorDetails.Message)") -split "`n")[0])".Trim() } } catch { }
    if ($m.Length -gt 300) { $m = $m.Substring(0, 297) + '...' }
    return $m
}

function Test-PimDbInitPermissionError {
    # PURE. A refusal that means "this identity may not" (never retried, never papered over).
    param([AllowEmptyString()][string]$Message)
    return ("$Message" -match '(?i)\b403\b|Forbidden|Authorization_RequestDenied|Insufficient privileges|InsufficientPermissions|PermissionScopeNotGranted|AuthorizationFailed')
}

function Test-PimDbInitPermanentRefused {
    # PURE. The group's PIM policy refuses a PERMANENT (or too long) assignment: Expiration_Admin_Assignment / isExpirationRequired.
    param([AllowEmptyString()][string]$Message)
    if (Test-PimDbInitPermissionError $Message) { return $false }
    return ("$Message" -match '(?i)ExpirationRule|greater than (the )?maximum allowed duration|isExpirationRequired|expiration is required|permanent assignments? (is|are) not allowed')
}

function Test-PimDbInitAlreadyMember {
    # PURE. The write found the membership already there (members/$ref: "added object references already exist";
    # a schedule request: RoleAssignmentExists).
    param([AllowEmptyString()][string]$Message)
    return ("$Message" -match '(?i)added object references already exist|RoleAssignmentExists|already exists')
}

function ConvertTo-PimDbInitUtc {
    # PURE. A Graph time (ISO 8601 text, or a [datetime] from PowerShell 7's ConvertFrom-Json) -> UTC [datetime], or $null.
    param([AllowNull()]$Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [datetime]) { if ($Value.Kind -eq [DateTimeKind]::Unspecified) { return [datetime]::SpecifyKind($Value, [DateTimeKind]::Utc) }; return $Value.ToUniversalTime() }
    $t = "$Value".Trim(); if (-not $t) { return $null }
    $o = [DateTimeOffset]::MinValue
    if ([DateTimeOffset]::TryParse($t, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AssumeUniversal, [ref]$o)) { return $o.UtcDateTime }
    return $null
}

function Format-PimDbInitUtc {
    # PURE. yyyy-MM-dd HH:mm UTC (invariant), '' for $null.
    param([AllowNull()]$Utc)
    if ($null -eq $Utc) { return '' }
    return (([datetime]$Utc).ToUniversalTime().ToString('yyyy-MM-dd HH:mm', [Globalization.CultureInfo]::InvariantCulture) + ' UTC')
}

function ConvertFrom-PimDbInitDuration {
    # PURE. An ISO 8601 duration (P180D, PT8H) -> [timespan], or $null.
    param([AllowEmptyString()][string]$Duration)
    try { return [System.Xml.XmlConvert]::ToTimeSpan("$Duration".Trim()) } catch { return $null }
}

function New-PimDbInitPimRequestBody {
    <#
      PURE. A PIM-for-Groups ACTIVE member schedule request (the engine's New-PimGroupMembershipBody shape):
      accessId member, the action, a justification, and scheduleInfo -- -Duration '' = noExpiration (PERMANENT), else
      afterDuration <ISO 8601>.
    #>
    param([Parameter(Mandatory)][string]$PrincipalId, [Parameter(Mandatory)][string]$GroupId,
          [ValidateSet('adminAssign', 'adminExtend', 'adminRenew')][string]$Action = 'adminAssign',
          [AllowEmptyString()][string]$Duration = '', [datetime]$NowUtc = [datetime]::UtcNow,
          [string]$Justification = 'PIM Manager update: the database job identity in the SQL admin group (framework 4.5 point 5)')
    $exp = if ("$Duration".Trim()) { @{ type = 'afterDuration'; duration = "$Duration".Trim() } } else { @{ type = 'noExpiration' } }
    return @{ accessId = 'member'; principalId = $PrincipalId; groupId = $GroupId; action = $Action; justification = $Justification
              scheduleInfo = @{ startDateTime = $NowUtc.ToUniversalTime().ToString('o'); expiration = $exp } }
}

function Get-PimDbInitMembershipState {
    <#
      PURE. Is -PrincipalId a member, and HOW?
        -Instances  the group's ACTIVE assignmentScheduleInstances (Graph objects), or $null when they could not be read
        -MemberOf   $true / $false from the identity's memberOf, or $null when it could not be read
      An ACTIVE PIM 'member' instance of the principal wins (a PIM member also shows in memberOf): no end = pim-permanent,
      an end = pim-timed (+ endUtc, daysLeft). Else memberOf $true = direct. Unknown stays unknown ($null) -- never guessed.
      renew: adminExtend when a time-limited membership ends within -RenewDays; adminRenew when an instance of the principal
      is listed with an end already past (it has ended; it is then NOT a member).
      Returns [ordered]@{ member; via; endUtc; daysLeft; renew; reason }.
    #>
    param([Parameter(Mandatory)][string]$PrincipalId, [AllowNull()][object[]]$Instances, [AllowNull()]$MemberOf,
          [datetime]$NowUtc = [datetime]::UtcNow, [int]$RenewDays = (Get-PimDbInitMembershipRenewDays))
    $now = $NowUtc.ToUniversalTime()
    $o = [ordered]@{ member = $null; via = ''; endUtc = $null; daysLeft = $null; renew = 'none'; reason = '' }
    $mine = @()
    if ($null -ne $Instances) {
        $mine = @(@($Instances) | Where-Object { $_ -and "$(Get-PimDbInitObjField $_ 'principalId')".Trim() -ieq "$PrincipalId".Trim() -and
                                                ("$(Get-PimDbInitObjField $_ 'accessId')".Trim() -in @('', 'member')) })
    }
    if ($mine.Count) {
        # the longest-running one decides (a permanent one beats any end)
        $perm = @($mine | Where-Object { -not (ConvertTo-PimDbInitUtc (Get-PimDbInitObjField $_ 'endDateTime')) })
        if ($perm.Count) { $o.member = $true; $o.via = 'pim-permanent'; $o.reason = 'an active permanent PIM-for-Groups member assignment'; return $o }
        $best = @($mine | Sort-Object { ConvertTo-PimDbInitUtc (Get-PimDbInitObjField $_ 'endDateTime') } -Descending)[0]
        $end = ConvertTo-PimDbInitUtc (Get-PimDbInitObjField $best 'endDateTime')
        $o.endUtc = $end
        $o.daysLeft = [math]::Floor(($end - $now).TotalDays)
        if ($end -le $now) {
            $o.member = $false; $o.via = 'pim-ended'; $o.renew = 'adminRenew'
            $o.reason = "the time-limited PIM-for-Groups member assignment ended $(Format-PimDbInitUtc $end)"
            return $o
        }
        $o.member = $true; $o.via = 'pim-timed'
        if ($end -le $now.AddDays($RenewDays)) { $o.renew = 'adminExtend' }
        $o.reason = "an active TIME-LIMITED PIM-for-Groups member assignment, ends $(Format-PimDbInitUtc $end)"
        return $o
    }
    if ($MemberOf -eq $true) {
        # 2026-11-05: a PIM member is in memberOf too -- without a readable instance list the way is not known, only the fact
        $o.member = $true; $o.via = $(if ($null -ne $Instances) { 'direct' } else { 'member' })
        $o.reason = $(if ($null -ne $Instances) { 'a direct member' } else { 'a member (the group''s PIM assignments were not readable)' })
        return $o
    }
    if ($MemberOf -eq $false) {
        $o.member = $false; $o.reason = 'not a member'
        return $o
    }
    if ($null -ne $Instances) { $o.reason = 'no PIM-for-Groups assignment; a direct membership could not be read' }
    else { $o.reason = 'neither the memberships nor the group''s PIM assignments could be read' }
    return $o
}

function Get-PimDbInitJobStartGate {
    <#
      PURE. Framework 4.5 point 5 (c)/(d): the database job (or a job copied from it) may start ONLY when the membership of its
      identity in the SQL admin group was READ BACK as true in this run. Anything else -- not a member, not read, not read
      back, both writes refused -- = NOT started, with the reason. -Membership: Invoke-PimDbInitMembershipRead /
      Invoke-PimDbInitMembershipEnsure's result. Returns @{ start; reason }.
    #>
    # 3.0.48 (D): -Proof = an EARLIER proof of the membership (Get-PimDbInitStoredProof: a prior run's read-back stored in
    # pim.Settings, or Get-PimDbInitJobRunProof: the database job's last successful run). It opens the gate ONLY when the
    # membership is NOT READABLE now -- a read that says 'not a member' always closes it, and never proven + unreadable closes it.
    param([AllowNull()]$Membership, [AllowNull()]$Proof = $null, [string]$PrincipalId = '', [string]$GroupId = '', [datetime]$NowUtc = [datetime]::UtcNow)
    $mb = $null; $rb = $null
    if ($null -ne $Membership) {
        $rb = Get-PimDbInitObjField $Membership 'readBack'; $mb = Get-PimDbInitObjField $Membership 'member'
        if ($rb -eq $true -and $mb -eq $true) { return @{ start = $true; reason = "the membership was read back ($("$(Get-PimDbInitObjField $Membership 'via')"))" } }
    }
    $why = 'the membership could not be read'
    if ($null -eq $Membership) { $why = 'not read in this run' }
    else {
        $errs = @(@(Get-PimDbInitObjField $Membership 'errors') | Where-Object { "$_".Trim() })
        $why = if ("$(Get-PimDbInitObjField $Membership 'reason')".Trim()) { "$(Get-PimDbInitObjField $Membership 'reason')".Trim() } elseif ($errs.Count) { $errs -join ' | ' } elseif ($mb -eq $false) { 'not a member' } else { 'the membership could not be read' }
    }
    if ($mb -ne $false -and $null -ne $Proof) {
        $pv = Test-PimDbInitMembershipProof -Proof $Proof -PrincipalId $PrincipalId -GroupId $GroupId -NowUtc $NowUtc
        if ($pv.ok) { return @{ start = $true; proven = $true; reason = "the membership is not readable now ($why); $($pv.reason)" } }
        $why = "$why; $($pv.reason)"
    } elseif ($mb -ne $false) { $why = "$why; never proven before" }
    if ($null -eq $Membership -and $null -eq $Proof) { return @{ start = $false; reason = 'the SQL admin group membership of the database job identity was not read back in this run and was never proven -- the job is not started' } }
    return @{ start = $false; reason = "the database job identity is not READ BACK as a member of the SQL admin group ($why) -- the job is not started" }
}

function Get-PimDbInitProofSetting { <# PURE. The pim.Settings name the updater records a READ-BACK membership in (a literal). #> return 'DbInitMembershipProof' }

function New-PimDbInitMembershipProof {
    <#
      PURE. 3.0.48 (D): the record of a READ-BACK membership (Invoke-PimDbInitMembershipEnsure .readBack + .member), kept in
      pim.Settings (Get-PimDbInitProofSetting) so a later run whose read is refused (e.g. a Graph token without its roles yet)
      does not block a job on an identity that WAS proven. $null when there is nothing proven.
    #>
    param([AllowNull()]$Membership, [Parameter(Mandatory)][string]$PrincipalId, [string]$GroupId = '', [datetime]$NowUtc = [datetime]::UtcNow)
    if ($null -eq $Membership -or (Get-PimDbInitObjField $Membership 'readBack') -ne $true -or (Get-PimDbInitObjField $Membership 'member') -ne $true) { return $null }
    $end = ConvertTo-PimDbInitUtc (Get-PimDbInitObjField $Membership 'endUtc')
    return [ordered]@{ source = 'read-back'; principalId = "$PrincipalId".Trim(); groupId = "$GroupId".Trim(); via = "$(Get-PimDbInitObjField $Membership 'via')"
                       endUtc = $(if ($end) { $end.ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture) } else { '' })
                       atUtc = $NowUtc.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture) }
}

function Get-PimDbInitStoredProof {
    <# PURE. The stored proof from a pim.Settings value (a JSON string or an object); $null when absent / unreadable. Never throws. #>
    param([AllowNull()]$Value)
    try {
        if ($null -eq $Value) { return $null }
        if ($Value -is [string]) { if (-not "$Value".Trim().StartsWith('{')) { return $null }; return ("$Value" | ConvertFrom-Json) }
        return $Value
    } catch { return $null }
}

function Get-PimDbInitJobRunProof {
    <#
      READ ONLY. 3.0.48 (D) / the 3.0.46 proof-by-run: the database job's identity has no database user of its own, so its
      LAST execution that Succeeded signed in THROUGH the SQL admin group. -JobPath: the job's ARM id (no api-version).
      Returns a proof (source job-run) or $null (no run, the last run not Succeeded, ARM unreadable). Never throws.
    #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [Parameter(Mandatory)][string]$JobPath, [string]$PrincipalId = '')
    try {
        $ex = & $Arm 'GET' "$("$JobPath".TrimEnd('/'))/executions?api-version=2024-03-01" $null
        $last = @(@((Get-PimDbInitObjField $ex 'value')) | Where-Object { $_ } | Sort-Object { "$(Get-PimDbInitObjField (Get-PimDbInitObjField $_ 'properties') 'startTime')" } -Descending)[0]
        if (-not $last) { return $null }
        $p = Get-PimDbInitObjField $last 'properties'
        if ("$(Get-PimDbInitObjField $p 'status')" -ne 'Succeeded') { return $null }
        return [ordered]@{ source = 'job-run'; principalId = "$PrincipalId".Trim(); groupId = ''; via = "$(Get-PimDbInitObjField $last 'name')"; endUtc = ''; atUtc = "$(Get-PimDbInitObjField $p 'startTime')" }
    } catch { return $null }
}

function Test-PimDbInitMembershipProof {
    <#
      PURE. Does -Proof prove THIS identity's membership? The principal must match (and the group, when both are known); a
      proven TIME-LIMITED membership whose end has passed proves nothing. Returns @{ ok; reason }.
    #>
    param([AllowNull()]$Proof, [string]$PrincipalId = '', [string]$GroupId = '', [datetime]$NowUtc = [datetime]::UtcNow)
    if ($null -eq $Proof) { return @{ ok = $false; reason = 'never proven before' } }
    $pp = "$(Get-PimDbInitObjField $Proof 'principalId')".Trim(); $pg = "$(Get-PimDbInitObjField $Proof 'groupId')".Trim()
    if ("$PrincipalId".Trim() -and $pp -and $pp -ine "$PrincipalId".Trim()) { return @{ ok = $false; reason = 'the earlier proof is for another identity' } }
    if (-not $pp -and "$PrincipalId".Trim()) { return @{ ok = $false; reason = 'the earlier proof names no identity' } }
    if ("$GroupId".Trim() -and $pg -and $pg -ine "$GroupId".Trim()) { return @{ ok = $false; reason = 'the earlier proof is for another group' } }
    $end = ConvertTo-PimDbInitUtc (Get-PimDbInitObjField $Proof 'endUtc')
    if ($end -and $end -le $NowUtc.ToUniversalTime()) { return @{ ok = $false; reason = "the proven membership was time-limited and ended $(Format-PimDbInitUtc $end)" } }
    $src = "$(Get-PimDbInitObjField $Proof 'source')"; $at = "$(Get-PimDbInitObjField $Proof 'atUtc')".Trim()
    $what = if ($src -eq 'job-run') { "proven by the database job's run $(Get-PimDbInitObjField $Proof 'via') (Succeeded$(if ($at) { " $at" }))" } else { "proven by an earlier update's read-back$(if ($at) { " at $at" })" }
    return @{ ok = $true; reason = $what }
}

function Get-PimDbInitAdminGroup {
    <#
      READ ONLY. The SQL server's Entra admin (ARM .../administrators): @{ isGroup; groupId; name; reason }. isGroup $false
      when the admin is a user / an app; $null when it could not be read or its type is not stated. Never throws.
    #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [Parameter(Mandatory)][string]$ResourceGroupId, [AllowEmptyString()][string]$SqlServer)
    $o = @{ isGroup = $null; groupId = ''; name = ''; reason = '' }
    $srv = ("$SqlServer".Trim() -split '\.')[0]
    if ($srv -notmatch '^[a-z0-9][a-z0-9-]{0,62}$') { $o.reason = 'the SQL server is not named'; return $o }
    try {
        $r = & $Arm 'GET' "$("$ResourceGroupId".TrimEnd('/'))/providers/Microsoft.Sql/servers/$srv/administrators?api-version=2021-11-01" $null
        $adm = if ($r -and $r.PSObject.Properties['value']) { @(@($r.value) | Where-Object { $_ })[0] } else { $r }
    } catch { $o.reason = "the SQL server's Entra admin could not be read: $(Get-PimDbInitGraphError $_)"; return $o }
    if (-not $adm) { $o.isGroup = $false; $o.reason = 'the SQL server has no Entra admin'; return $o }
    $p = Get-PimDbInitObjField $adm 'properties'
    $o.name = "$(Get-PimDbInitObjField $p 'login')".Trim()
    $sid = "$(Get-PimDbInitObjField $p 'sid')".Trim()
    $g = [guid]::Empty
    if ([guid]::TryParse($sid, [ref]$g)) { $o.groupId = $sid.ToLowerInvariant() }
    $pt = "$(Get-PimDbInitObjField $p 'principalType')".Trim()
    if ($pt -and $pt -ine 'Group') { $o.isGroup = $false; $o.reason = "the SQL Entra admin is a $pt, not a group" }
    elseif ($pt) { $o.isGroup = $true }
    else { $o.reason = "the SQL Entra admin's type is not stated" }
    if (-not $o.groupId) { $o.isGroup = $null; $o.reason = "the SQL admin group's object id could not be read" }
    return $o
}

function Invoke-PimDbInitMembershipRead {
    <#
      READ ONLY. The group's ACTIVE PIM assignments (assignmentScheduleInstances, filtered by the GROUP and matched on the
      principal here -- a principalId filter omits schedules) and the identity's memberOf; -> Get-PimDbInitMembershipState
      + readErrors[] + missing[] (the permission a refused read needs). Never throws.
    #>
    param([Parameter(Mandatory)][scriptblock]$Graph, [Parameter(Mandatory)][string]$GroupId, [Parameter(Mandatory)][string]$PrincipalId,
          [datetime]$NowUtc = [datetime]::UtcNow)
    $errs = New-Object System.Collections.Generic.List[string]
    $inst = $null; $instErr = ''; $moErr = ''
    try {
        $all = New-Object System.Collections.Generic.List[object]
        $path = "/identityGovernance/privilegedAccess/group/assignmentScheduleInstances?`$filter=groupId eq '$GroupId'"
        $guard = 0
        while ($path -and $guard -lt 50) {
            $guard++
            $page = & $Graph 'GET' $path $null
            foreach ($v in @((Get-PimDbInitObjField $page 'value'))) { if ($v) { $all.Add($v) } }
            $path = "$(Get-PimDbInitObjField $page '@odata.nextLink')".Trim()
        }
        $inst = $all.ToArray()
    } catch { $instErr = Get-PimDbInitGraphError $_; [void]$errs.Add("the group's PIM assignments could not be read: $instErr") }
    $mo = $null
    try {
        $path = "/servicePrincipals/$PrincipalId/memberOf/microsoft.graph.group" + '?$select=id&$top=999'
        $guard = 0; $found = $false
        while ($path -and $guard -lt 50 -and -not $found) {
            $guard++
            $page = & $Graph 'GET' $path $null
            foreach ($m in @((Get-PimDbInitObjField $page 'value'))) { if ("$(Get-PimDbInitObjField $m 'id')".Trim() -ieq $GroupId) { $found = $true; break } }
            $path = "$(Get-PimDbInitObjField $page '@odata.nextLink')".Trim()
        }
        $mo = $found
    } catch {
        # G5 (updated 2026-11-05): the identity holds GroupMember.Read.All for this read; a refusal names it. When the group's
        # assignments WERE read (a PIM member shows there) the read-back still decides from them.
        $moErr = Get-PimDbInitGraphError $_
        if ($null -eq $inst) { [void]$errs.Add("the identity's memberships could not be read: $(Get-PimDbInitGraphError $_)") }
    }
    $s = Get-PimDbInitMembershipState -PrincipalId $PrincipalId -Instances $inst -MemberOf $mo -NowUtc $NowUtc
    $s['readErrors'] = @($errs.ToArray())
    $s['missing'] = @(@(if ($null -eq $inst -and (Test-PimDbInitPermissionError $instErr)) { Get-PimDbInitMembershipPermission -Step read }) + @(if ($moErr -and (Test-PimDbInitPermissionError $moErr)) { Get-PimDbInitMembershipPermission -Step memberof }))
    return $s
}

function Invoke-PimDbInitPimRequest {
    <#
      One ACTIVE PIM-for-Groups member request (-Action adminAssign / adminExtend / adminRenew): PERMANENT first; on the
      policy's refusal of a permanent one, the policy's maximum (Expiration_Admin_Assignment, read when readable), else the
      ladder (Get-PimDbInitMembershipDurations). Any other refusal ends it at once. Never throws.
      Returns @{ ok; permanent; duration; already; error; permanentRefused }.
    #>
    param([Parameter(Mandatory)][scriptblock]$Graph, [Parameter(Mandatory)][string]$GroupId, [Parameter(Mandatory)][string]$PrincipalId,
          [ValidateSet('adminAssign', 'adminExtend', 'adminRenew')][string]$Action = 'adminAssign', [datetime]$NowUtc = [datetime]::UtcNow)
    $o = @{ ok = $false; permanent = $false; duration = ''; already = $false; error = ''; permanentRefused = $false }
    $path = '/identityGovernance/privilegedAccess/group/assignmentScheduleRequests'
    try { [void](& $Graph 'POST' $path (New-PimDbInitPimRequestBody -PrincipalId $PrincipalId -GroupId $GroupId -Action $Action -NowUtc $NowUtc)); $o.ok = $true; $o.permanent = $true; return $o }
    catch {
        $m = Get-PimDbInitGraphError $_
        if ($Action -eq 'adminAssign' -and (Test-PimDbInitAlreadyMember $m)) { $o.ok = $true; $o.already = $true; return $o }
        if (-not (Test-PimDbInitPermanentRefused $m)) { $o.error = $m; return $o }
        $o.permanentRefused = $true; $o.error = $m
    }
    $tries = New-Object System.Collections.Generic.List[string]
    try {
        $pa = & $Graph 'GET' ("/policies/roleManagementPolicyAssignments?`$filter=scopeId eq '$GroupId' and scopeType eq 'Group' and roleDefinitionId eq 'member'" + '&$expand=policy($expand=rules)') $null
        $rules = @(Get-PimDbInitObjField (Get-PimDbInitObjField (@(Get-PimDbInitObjField $pa 'value') | Where-Object { $_ } | Select-Object -First 1) 'policy') 'rules')
        $max = "$(Get-PimDbInitObjField (@($rules | Where-Object { "$(Get-PimDbInitObjField $_ 'id')" -eq 'Expiration_Admin_Assignment' })[0]) 'maximumDuration')".Trim()
        if ($max -and (ConvertFrom-PimDbInitDuration $max)) { $tries.Add($max) }
    } catch { }
    foreach ($d in @(Get-PimDbInitMembershipDurations)) { if (-not $tries.Contains($d)) { $tries.Add($d) } }
    foreach ($d in $tries) {
        try { [void](& $Graph 'POST' $path (New-PimDbInitPimRequestBody -PrincipalId $PrincipalId -GroupId $GroupId -Action $Action -Duration $d -NowUtc $NowUtc)); $o.ok = $true; $o.duration = $d; $o.error = ''; return $o }
        catch {
            $m = Get-PimDbInitGraphError $_
            if ($Action -eq 'adminAssign' -and (Test-PimDbInitAlreadyMember $m)) { $o.ok = $true; $o.already = $true; $o.error = ''; return $o }
            $o.error = $m
            if (-not (Test-PimDbInitPermanentRefused $m)) { return $o }
        }
    }
    return $o
}

function Invoke-PimDbInitMembershipEnsure {
    <#
      Framework 4.5 point 5 for the database job identity: make sure -PrincipalId is in the SQL admin group -GroupId by
      (a) a direct add, else (b) an ACTIVE PIM-for-Groups assignment (permanent first; time-limited only on the policy's
      refusal, SAID with the end date), then (c) READ BACK; (d) both refused = both errors named, member $false. A member
      already: nothing written; a time-limited one ending within 30 days is RENEWED (adminExtend) and read back -- a failed
      renewal is a WARNING with the end date, never a failure. Never throws. Never starts a job.
      Returns [pscustomobject]@{ ok; member; readBack; via; endUtc; timeLimited; renewed; renewFailed; changed; warnings;
                                 lines; errors; missing; reason; note }.
        note = the one line the heartbeat carries (time-limited / renewal) ('' when there is nothing to say).
    #>
    param([Parameter(Mandatory)][scriptblock]$Graph, [Parameter(Mandatory)][string]$GroupId, [string]$GroupName = '',
          [Parameter(Mandatory)][string]$PrincipalId, [string]$IdentityName = '', [datetime]$NowUtc = [datetime]::UtcNow,
          [scriptblock]$Sleep = $null, [int[]]$ReadBackWaits = (Get-PimDbInitMembershipReadBackWaits),
          [string]$Who = "the updater's identity")
    if (-not $Sleep) { $Sleep = { param($s) Start-Sleep -Seconds $s } }
    $lines = New-Object System.Collections.Generic.List[object]
    $errors = New-Object System.Collections.Generic.List[string]; $missing = New-Object System.Collections.Generic.List[string]
    $idn = $(if ("$IdentityName".Trim()) { "$IdentityName".Trim() } else { $PrincipalId }); $gn = $(if ("$GroupName".Trim()) { "$GroupName".Trim() } else { $GroupId })
    $add = { param($level, $text) $lines.Add([pscustomobject]@{ id = 'dbinit-member'; level = $level; text = "database job identity: $text" }) }
    $o = [ordered]@{ ok = $false; member = $null; readBack = $false; via = ''; endUtc = $null; timeLimited = $false; renewed = $false; renewFailed = $false
                     roleAssignable = $null; addedUtc = ''; changed = 0; warnings = 0; lines = $null; errors = $null; missing = $null; reason = ''; note = '' }
    $fin = {
        $o.lines = @($lines.ToArray()); $o.errors = @($errors.ToArray()); $o.missing = @($missing.ToArray() | Select-Object -Unique)
        $o.changed = @($lines | Where-Object { $_.level -eq 'changed' }).Count; $o.warnings = @($lines | Where-Object { $_.level -eq 'warn' }).Count
        $o.ok = ($o.member -eq $true -and $o.readBack -eq $true)
        return [pscustomobject]$o
    }
    $readBack = {
        param($want)
        $last = $null
        foreach ($w in @($ReadBackWaits)) {
            if ([int]$w -gt 0) { & $Sleep ([int]$w) }
            $last = Invoke-PimDbInitMembershipRead -Graph $Graph -GroupId $GroupId -PrincipalId $PrincipalId -NowUtc $NowUtc
            if (& $want $last) { break }
        }
        return $last
    }
    try {
        $g = [guid]::Empty
        if (-not [guid]::TryParse("$GroupId", [ref]$g) -or -not [guid]::TryParse("$PrincipalId", [ref]$g)) {
            $o.reason = 'the SQL admin group or the identity is not known by its object id -- nothing done'; & $add 'warn' $o.reason; return (& $fin)
        }
        $st = Invoke-PimDbInitMembershipRead -Graph $Graph -GroupId $GroupId -PrincipalId $PrincipalId -NowUtc $NowUtc
        if ($st.member -eq $true) {
            $o.member = $true; $o.readBack = $true; $o.via = "$($st.via)"; $o.endUtc = $st.endUtc; $o.timeLimited = ($st.via -eq 'pim-timed'); $o.reason = "$($st.reason)"
            if ($st.renew -ne 'adminExtend') {
                & $add 'info' "$idn is a member of $gn ($($st.reason)) -- nothing written"
                if ($o.timeLimited) { $o.note = "member through a TIME-LIMITED PIM assignment, ends $(Format-PimDbInitUtc $st.endUtc)" }
                return (& $fin)
            }
            # ---- RENEWAL: time-limited, ends within 30 days -------------------------------------------------------------
            $roleAsg = Get-PimDbInitGroupRoleAssignable -Graph $Graph -GroupId $GroupId; $o.roleAssignable = $roleAsg
            $oldEnd = $st.endUtc
            $rq = Invoke-PimDbInitPimRequest -Graph $Graph -GroupId $GroupId -PrincipalId $PrincipalId -Action 'adminExtend' -NowUtc $NowUtc
            if ($rq.ok) {
                $after = & $readBack { param($r) $r.member -eq $true -and ($r.via -eq 'pim-permanent' -or ($r.endUtc -and $oldEnd -and $r.endUtc -gt $oldEnd)) }
                if ($after.member -eq $true -and ($after.via -eq 'pim-permanent' -or ($after.endUtc -and $after.endUtc -gt $oldEnd))) {
                    $o.renewed = $true; $o.via = "$($after.via)"; $o.endUtc = $after.endUtc; $o.timeLimited = ($after.via -eq 'pim-timed')
                    $what = if ($after.via -eq 'pim-permanent') { 'now PERMANENT' } else { "TIME-LIMITED: the group's PIM policy refuses a permanent assignment; now ends $(Format-PimDbInitUtc $after.endUtc)" }
                    & $add 'changed' "$idn renewed in $gn (it ended $(Format-PimDbInitUtc $oldEnd)) -- $what (read back)"
                    $o.note = $(if ($o.timeLimited) { "member through a TIME-LIMITED PIM assignment, renewed, ends $(Format-PimDbInitUtc $after.endUtc)" } else { '' })
                    return (& $fin)
                }
                $rq.error = 'the renewal was accepted but the new end was not read back'
            }
            $o.renewFailed = $true
            if (Test-PimDbInitPermissionError $rq.error) { [void]$missing.Add((Get-PimDbInitMembershipPermission -Step pim)) }
            & $add 'warn' "WARNING: $idn's time-limited membership of $gn ENDS $(Format-PimDbInitUtc $oldEnd) and the renewal failed: $($rq.error)$(if (Test-PimDbInitPermissionError $rq.error) { " -- $Who needs $(Get-PimDbInitMembershipPermission -Step pim)" }) -- the next update tries again"
            $o.note = "WARNING: membership ends $(Format-PimDbInitUtc $oldEnd), renewal failed"
            return (& $fin)
        }
        # ---- not a member (or not readable): (a) then (b) ---------------------------------------------------------------
        $why = "$($st.reason)"
        # SEC-32 (owner, kept 2026-11-05): the SQL admin group is ROLE-ASSIGNABLE at most installs, on purpose. It is never
        # changed or replaced here; its isAssignableToRole is READ only so a refusal names the exact permission it needs.
        $roleAsg = Get-PimDbInitGroupRoleAssignable -Graph $Graph -GroupId $GroupId; $o.roleAssignable = $roleAsg
        if ($roleAsg -eq $true) { $gn = "$gn (role-assignable)" }
        # (a) a direct member add
        $directErr = ''; $wrote = $false
        try {
            [void](& $Graph 'POST' "/groups/$GroupId/members/`$ref" @{ '@odata.id' = "https://graph.microsoft.com/v1.0/directoryObjects/$PrincipalId" })
            $o.via = 'direct'; $wrote = $true
        } catch {
            $directErr = Get-PimDbInitGraphError $_
            if (Test-PimDbInitAlreadyMember $directErr) { $directErr = ''; $o.via = 'already' }
        }
        $timed = ''
        if ($directErr) {
            # G5: a refused direct add is EXPECTED on a role-assignable group -- (b) follows quietly; (a) is never a missing right
            # (b) an ACTIVE PIM-for-Groups member assignment (adminRenew for an assignment that has just ended)
            $act = $(if ($st.renew -eq 'adminRenew') { 'adminRenew' } else { 'adminAssign' })
            $rq = Invoke-PimDbInitPimRequest -Graph $Graph -GroupId $GroupId -PrincipalId $PrincipalId -Action $act -NowUtc $NowUtc
            if (-not $rq.ok -and $act -eq 'adminRenew' -and -not (Test-PimDbInitPermissionError $rq.error)) {
                $rq = Invoke-PimDbInitPimRequest -Graph $Graph -GroupId $GroupId -PrincipalId $PrincipalId -Action 'adminAssign' -NowUtc $NowUtc
            }
            if (-not $rq.ok) {
                if (Test-PimDbInitPermissionError $rq.error) { [void]$missing.Add((Get-PimDbInitMembershipPermission -Step pim)) }
                [void]$errors.Add("(a) direct add refused: $directErr"); [void]$errors.Add("(b) PIM-for-Groups active assignment refused: $($rq.error)")
                # 3.0.48 (C): 'not a member' only when the read SAID so -- an unreadable membership stays unknown ($null), never
                # a 'missing' (live internal 2026-11-05: the updater's token did not carry its new Graph roles yet)
                $o.member = $(if ($st.member -eq $false) { $false } else { $null }); $o.readBack = $false
                $o.reason = "$idn could NOT be put into $gn ($why): (a) direct add refused: $directErr | (b) PIM-for-Groups active assignment refused: $($rq.error)"
                if ($missing.Count) { $o.reason += " -- $Who is missing: $(@($missing.ToArray() | Select-Object -Unique) -join '; ') (nothing was changed; nothing is granted here)" }
                & $add 'warn' $o.reason
                return (& $fin)
            }
            $o.via = $(if ($rq.already) { 'already' } elseif ($rq.permanent) { 'pim-permanent' } else { 'pim-timed' }); if (-not $rq.already) { $wrote = $true }
            if (-not $rq.permanent -and -not $rq.already) { $timed = "$($rq.duration)" }
        }
        # (c) READ BACK
        $rb = & $readBack { param($r) $r.member -eq $true }
        if ($rb.member -ne $true) {
            $o.member = $(if ($rb.member -eq $false) { $false } else { $null }); $o.readBack = $false
            $o.reason = "$idn was put into $gn ($($o.via)) but the membership was NOT read back ($($rb.reason)$(if (@($rb.readErrors).Count) { '; ' + (@($rb.readErrors) -join '; ') }))"
            foreach ($mm in @($rb.missing)) { [void]$missing.Add($mm) }
            [void]$errors.Add($o.reason)
            & $add 'warn' "$($o.reason) -- the database job is not started on it"
            return (& $fin)
        }
        $o.member = $true; $o.readBack = $true; $o.endUtc = $rb.endUtc
        # framework 4.5 G3a: a FRESH add -- the identity's token can keep the old group claims up to 24 h; the callers record this
        if ($wrote) { $o.addedUtc = $NowUtc.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture) }
        if ("$($rb.via)" -in @('pim-permanent', 'pim-timed', 'direct')) { $o.via = "$($rb.via)" }
        $o.timeLimited = ($o.via -eq 'pim-timed')
        if ($o.via -eq 'direct') {
            & $add 'changed' "$idn added to $gn as a direct member (read back)$(if ($why) { " -- was: $why" })"
        } elseif ($o.timeLimited) {
            $endTxt = if ($rb.endUtc) { Format-PimDbInitUtc $rb.endUtc } else { 'an end not read' }
            & $add 'changed' "$idn added to $gn as an ACTIVE PIM-for-Groups member -- TIME-LIMITED: the group's PIM policy refuses a permanent assignment ($($timed)); it ends $endTxt and is renewed by the update from 30 days before (read back)"
            $o.note = "member through a TIME-LIMITED PIM assignment, ends $endTxt"
        } else {
            & $add 'changed' "$idn added to $gn as a PERMANENT active PIM-for-Groups member (read back)"
        }
        $o.reason = "read back: $($rb.reason)"
    } catch { $o.reason = "not checked: $(Get-PimDbInitGraphError $_)"; [void]$errors.Add($o.reason); & $add 'warn' $o.reason }
    return (& $fin)
}

function Invoke-PimDbInitMembershipGate {
    <#
      READ ONLY, for the moment BEFORE a job that runs as the database job's identity is started (the support consent job is a
      copy of it). Reads the database job (ARM): its identity (PIM_DBINIT_MI_CLIENT_ID among its user-assigned identities) and
      SQL server; the server's Entra admin group (ARM); then the membership (Graph, Invoke-PimDbInitMembershipRead) and decides
      with Get-PimDbInitJobStartGate. No job = absent (the caller's own 'not ready' path decides). Never writes, never throws.
      Returns @{ start; absent; reason; membership }.
    #>
    # 3.0.48 (D): -Proof = the stored proof (pim.Settings, Get-PimDbInitProofSetting) of an earlier read-back; when the
    # membership is NOT READABLE now and none is stored, the job's last successful run is asked (Get-PimDbInitJobRunProof).
    param([Parameter(Mandatory)][scriptblock]$Arm, [AllowNull()][scriptblock]$Graph, [Parameter(Mandatory)][string]$SubscriptionId,
          [Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$JobName, [AllowNull()]$Proof = $null,
          [datetime]$NowUtc = [datetime]::UtcNow)
    $o = @{ start = $false; absent = $false; reason = ''; membership = $null }
    $rgId = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup"
    try {
        $job = $null
        try { $job = & $Arm 'GET' "$rgId/providers/Microsoft.App/jobs/$JobName`?api-version=2024-03-01" $null }
        catch {
            if ("$($_.Exception.Message)" -match '(?i)HTTP 404\b|ResourceNotFound|NotFound') { $o.absent = $true; $o.reason = "no job '$JobName'"; return $o }
            $o.reason = "the database job could not be read ($(Get-PimDbInitGraphError $_)) -- the job is not started"; return $o
        }
        if (-not $job) { $o.absent = $true; $o.reason = "no job '$JobName'"; return $o }
        $env = Get-PimDbInitJobEnv -Job $job
        $cid = "$($env['PIM_DBINIT_MI_CLIENT_ID'])".Trim()
        $ua = @(Get-PimDbInitUaMap -Resource $job | Where-Object { $cid -and $_.clientId -ieq $cid })[0]
        if (-not $ua -or -not "$($ua.principalId)".Trim()) { $o.reason = "the database job names no identity it signs in with (PIM_DBINIT_MI_CLIENT_ID among its identities) -- the job is not started"; return $o }
        $idn = (("$($ua.id)" -split '/') | Where-Object { $_ })[-1]
        $adm = Get-PimDbInitAdminGroup -Arm $Arm -ResourceGroupId $rgId -SqlServer "$($env['PIM_SqlServer'])"
        if ($adm.isGroup -eq $false) { $o.reason = "$($adm.reason) -- the database job cannot act as an admin through a group; it is not started"; return $o }
        if (-not $adm.groupId) { $o.reason = "$($adm.reason) -- the job is not started"; return $o }
        if (-not $Graph) { $o.reason = 'Microsoft Graph was not asked -- the membership is not read back; the job is not started'; return $o }
        $m = Invoke-PimDbInitMembershipRead -Graph $Graph -GroupId $adm.groupId -PrincipalId "$($ua.principalId)" -NowUtc $NowUtc
        $m['readBack'] = ($m.member -eq $true)
        $m['errors'] = @($m.readErrors)
        $o.membership = $m
        $pf = $Proof
        if ($m.member -ne $true -and $m.member -ne $false -and -not (Test-PimDbInitMembershipProof -Proof $pf -PrincipalId "$($ua.principalId)" -GroupId $adm.groupId -NowUtc $NowUtc).ok) {
            $pf = Get-PimDbInitJobRunProof -Arm $Arm -JobPath "$rgId/providers/Microsoft.App/jobs/$JobName" -PrincipalId "$($ua.principalId)"
        }
        $gate = Get-PimDbInitJobStartGate -Membership $m -Proof $pf -PrincipalId "$($ua.principalId)" -GroupId $adm.groupId -NowUtc $NowUtc
        $o.start = [bool]$gate.start
        $o.reason = "$idn in $(if ($adm.name) { $adm.name } else { $adm.groupId }): $($gate.reason)$(if (@($m.missing).Count) { " -- the updater's identity needs $(@($m.missing) -join '; ') to read it" })"
    } catch { $o.start = $false; $o.reason = "the membership gate stopped ($(Get-PimDbInitGraphError $_)) -- the job is not started" }
    return $o
}

function Invoke-PimDbInitMembershipBeforeStart {
    <#
      SETUP's call site (owner 2026-11-05 "both setup and upd"): right BEFORE the install starts the database job for the first
      time (tools/setup/Setup-PimContainers.ps1 Invoke-PimDbInitJob), the SAME membership convergence the updater runs
      (Invoke-PimDbInitMembershipEnsure: (a) direct, (b) ACTIVE PIM for Groups permanent first, (c) read back) for the job's
      identity -- as the identity running setup. Reads the identity's object id (ARM) and the SQL server's Entra admin (ARM).
        * the admin is a GROUP  -> ensure; start only when it was READ BACK (else NOT started, both errors named);
        * the admin is NOT a group (an older install whose admin is a single identity) -> nothing to join; started as before,
          and said (SEC-03: the group-as-admin move is a separate step);
        * anything unreadable -> NOT started, with the reason.
      Never throws. Returns @{ start; reason; membership }.
    #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [AllowNull()][scriptblock]$Graph, [Parameter(Mandatory)][string]$ResourceGroupId,
          [AllowEmptyString()][string]$SqlServer, [AllowEmptyString()][string]$IdentityResourceId, [string]$IdentityPrincipalId = '',
          [datetime]$NowUtc = [datetime]::UtcNow, [scriptblock]$Sleep = $null, [int[]]$ReadBackWaits = (Get-PimDbInitMembershipReadBackWaits))
    $o = @{ start = $false; reason = ''; membership = $null }
    try {
        $idn = (("$IdentityResourceId" -split '/') | Where-Object { $_ } | Select-Object -Last 1)
        $oid = "$IdentityPrincipalId".Trim()
        if (-not $oid -and "$IdentityResourceId".Trim()) {
            try { $ui = & $Arm 'GET' "$("$IdentityResourceId".Trim())?api-version=2023-01-31" $null; $oid = "$(Get-PimDbInitObjField (Get-PimDbInitObjField $ui 'properties') 'principalId')".Trim() }
            catch { $o.reason = "the database job identity $idn could not be read ($(Get-PimDbInitGraphError $_)) -- the job is not started"; return $o }
        }
        $g = [guid]::Empty
        if (-not [guid]::TryParse($oid, [ref]$g)) { $o.reason = 'the database job identity is not known by its object id -- the job is not started'; return $o }
        $adm = Get-PimDbInitAdminGroup -Arm $Arm -ResourceGroupId $ResourceGroupId -SqlServer $SqlServer
        if ($adm.isGroup -eq $false) { $o.start = $true; $o.reason = "$($adm.reason) -- no group to join; started as before (the group-as-admin move is a separate step)"; return $o }
        if (-not $adm.groupId) { $o.reason = "$($adm.reason) -- the job is not started"; return $o }
        if (-not $Graph) { $o.reason = 'Microsoft Graph was not asked -- the membership is not read back; the job is not started'; return $o }
        $m = Invoke-PimDbInitMembershipEnsure -Graph $Graph -GroupId $adm.groupId -GroupName $adm.name -PrincipalId $oid -IdentityName $(if ($idn) { $idn } else { $oid }) -NowUtc $NowUtc -Sleep $Sleep -ReadBackWaits $ReadBackWaits -Who 'the identity running setup'
        $o.membership = $m
        $gate = Get-PimDbInitJobStartGate -Membership $m
        $o.start = [bool]$gate.start
        $o.reason = $(if ($gate.start) { "$(if ($idn) { $idn } else { $oid }) read back as a member of $(if ($adm.name) { $adm.name } else { $adm.groupId })$(if ($m.note) { " -- $($m.note)" })" } else { "$($gate.reason)" })
    } catch { $o.start = $false; $o.reason = "the membership step stopped ($(Get-PimDbInitGraphError $_)) -- the job is not started" }
    return $o
}
