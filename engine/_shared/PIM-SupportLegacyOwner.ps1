#Requires -Version 5.1
<#
.SYNOPSIS
    SECAUDIT-1a 4a (framework, owner-decided; PIM REQUIREMENTS 104.8) -- the Invardia Support app's LEGACY standing db_owner
    is removed DELIBERATELY, as the last step of the switch to just-in-time support access, and only after both proofs at
    THIS install. This file is the UPDATER's half and the shared literals: it decides, starts the database job and reads the
    result back. It carries NO security statement (tests\Test-PimSqlAccess.ps1 L2 -- this file is on the update path); the
    statements are in engine\_shared\PIM-SupportLegacyOwnerSql.ps1, loaded ONLY by the database job.

.DESCRIPTION
    THE RULE (framework SECAUDIT-1a, rule 4a NEVER-LOSE-SQL-ACCESS + 4c): the Support app's database user holds db_owner ONLY
    inside an open support session (the signed procedures of the support SQL access job, [pimsupport].[GrantMarker]). The JIT
    revoke / sweep never removes a db_owner no marker added -- so an install that still holds the OLD standing db_owner keeps
    it until THIS step removes it, once:
      P1  the Support app's read-only user exists and is in pim_support_read (read back, by SID)
      P2  one JIT open / close worked at THIS install with a real SQL sign-in: a [pimsupport].[GrantMarker] row for the
          Support app's SID, role db_owner, PreExisting = 0 (the grant ADDED it), RevokedUtc set, RevokedBy = 'job' (the
          support SQL access job took it back). The marker is the only record of the JIT path in the database; the Support
          app's own sign-ins are not recorded in it (sessions are transient), so the marker is the proof.
    Never while a support session is open (an unrevoked marker of the Support app's SID: the JIT owns it); never with a proof
    missing (what is missing is reported ONCE); never any other principal or role. The user is found BY SID from the app id.

    WHO: the database job (caj-pim-dbinit / ca-pim-dbinit, its identity in the SQL admin group). The updater (pim_updater +
    db_ddladmin) cannot change db_owner membership. A role REMOVAL waits for the run end (framework 8.18 SCHEMA-QUIESCE-818:
    class 'removal', never in a grants-only run) -- so the updater starts a FULL run of the database job, only after the job
    roll, only when no PIM job runs, only on a job that is on this release and whose identity reads back as a member of the
    SQL admin group (the same gates as the access cut-over and the support consent job).

    THE UPDATER (Invoke-PimSupportLegacyOwnerUpdaterStep, after the web-identity trim, step 2h-bis):
      trim says the Support user holds db_owner outside a session ('held')
        -> read-only user NOT in place (P1, from [pimsupport].[usp_SupportState]) = nothing started, reported once
        -> the job's last answer (pim.Settings SupportLegacyOwner) was 'not yet' less than a day ago = wait
        -> else: PIM_DBINIT_SUPPORT_LEGACY_OWNER = {"appId": ...} on the database job, ONE execution, waited for (bounded),
           the job's answer read, the state READ BACK through the signed state procedure
      'removed' + read back (inOwner false, readOnly true) -> ONE note to Invardia (fix-request channel, code
        sql-support-owner-removed), then quiet: the trim no longer reports SQL-SUPPORT-OWNER (the user holds no db_owner)
      a proof missing -> ONE fix request per missing proof (sql-support-owner-proof); a failure -> one (sql-support-owner-failed)
    Every line is an INFO line (internal support hygiene, TRIM-INTERNAL-1): never a customer mail, never a failed update.
    PIM_SUPPORT_LEGACY_OWNER on the updater job: on (default) | off.

    ASCII only; PS 5.1 + 7; no modules, no az.
#>
Set-StrictMode -Off

function Get-PimSupportLegacyOwnerSettingName { <# PURE. LITERAL. The database job's answer (pim.Settings). #> return 'SupportLegacyOwner' }
function Get-PimSupportLegacyOwnerNotesSettingName { <# PURE. LITERAL. What the updater already told Invardia (pim.Settings). #> return 'SupportLegacyOwnerNotes' }
function Get-PimSupportLegacyOwnerEnvName { <# PURE. LITERAL. The database job's setting that asks for the step. #> return 'PIM_DBINIT_SUPPORT_LEGACY_OWNER' }
function Get-PimSupportLegacyOwnerStepId { <# PURE. LITERAL. The database job's step id (class removal). #> return 'support-legacy-owner' }
function Get-PimSupportLegacyOwnerRetryHours { <# PURE. LITERAL. A 'not yet' answer of the job is asked again after this. #> return 24 }
function Get-PimSupportLegacyOwnerFixJob { <# PURE. LITERAL. The uplink job the notes are filed under (the updater's run). #> return 'pim-update' }
function Get-PimSupportLegacyOwnerNoteText { <# PURE. LITERAL. The note to Invardia after the read-back. #> return 'legacy standing db_owner removed (SECAUDIT-1a 4a), read back' }

function Test-PimSupportLegacyOwnerAppId {
    <# PURE. Is this an application (client) id (a non-empty GUID)? #>
    param([AllowNull()][AllowEmptyString()][string]$AppId)
    $t = "$AppId".Trim()
    if ($t -notmatch '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$') { return $false }
    return ([guid]$t -ne [guid]::Empty)
}

function ConvertTo-PimSupportLegacyOwnerAsk {
    <#
      PURE. The database job's setting -> @{ ok; asked; appId; reason }. Unset = not asked (ok, nothing to do). JSON
      {"appId":"<guid>", "askedUtc": "..."} or a bare app id. Anything else = REFUSED (nothing is read or changed).
    #>
    param([AllowNull()][AllowEmptyString()][string]$Value)
    $o = [ordered]@{ ok = $true; asked = $false; appId = ''; reason = '' }
    $v = "$Value".Trim()
    if (-not $v) { $o.reason = 'not asked'; return [pscustomobject]$o }
    $id = ''
    if ($v.StartsWith('{')) { try { $j = $v | ConvertFrom-Json; if ($j.PSObject.Properties['appId']) { $id = "$($j.appId)".Trim() } } catch { $id = '' } }
    else { $id = $v }
    if (-not (Test-PimSupportLegacyOwnerAppId $id)) { $o.ok = $false; $o.reason = "$(Get-PimSupportLegacyOwnerEnvName) does not name the Support app's id -- nothing was read or changed"; return [pscustomobject]$o }
    $o.asked = $true; $o.appId = $id.ToLowerInvariant()
    return [pscustomobject]$o
}

function ConvertTo-PimSupportLegacyOwnerSid {
    <# PURE. The app (client) id as a SQL SID literal: the GUID's bytes in ToByteArray order, hex (the same SID every Support-app path uses). #>
    param([Parameter(Mandatory)][string]$AppId)
    if (-not (Test-PimSupportLegacyOwnerAppId $AppId)) { throw "ConvertTo-PimSupportLegacyOwnerSid: '$AppId' is not an application (client) id." }
    return ('0x' + ((@(([guid]"$AppId".Trim()).ToByteArray()) | ForEach-Object { $_.ToString('X2') }) -join ''))
}

function Get-PimSupportLegacyOwnerField {
    param([AllowNull()]$Object, [string]$Name)
    if ($null -eq $Object) { return $null }
    if ($Object -is [System.Collections.IDictionary]) { if ($Object.Contains($Name)) { return $Object[$Name] }; return $null }
    if ($Object.PSObject.Properties[$Name]) { return $Object.$Name }
    return $null
}

function ConvertFrom-PimSupportLegacyOwnerUtc {
    <# PURE. An ISO time (text, or a [datetime] from PS 7's ConvertFrom-Json) -> UTC [datetime] or $null. #>
    param([AllowNull()]$Value)
    if ($Value -is [datetime]) { if ($Value.Kind -eq [DateTimeKind]::Unspecified) { return [datetime]::SpecifyKind($Value, [DateTimeKind]::Utc) }; return $Value.ToUniversalTime() }
    $d = [datetime]::MinValue
    if ([datetime]::TryParse("$Value".Trim(), [Globalization.CultureInfo]::InvariantCulture, ([Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal), [ref]$d)) { return $d }
    return $null
}

function Get-PimSupportLegacyOwnerRecordAt {
    <# PURE. The job answer's time as yyyy-MM-ddTHH:mm:ssZ ('' when none) -- one spelling whatever ConvertFrom-Json made of it. #>
    param([AllowNull()]$Record)
    $d = ConvertFrom-PimSupportLegacyOwnerUtc (Get-PimSupportLegacyOwnerField $Record 'atUtc')
    if ($null -eq $d) { return '' }
    return $d.ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture)
}

function ConvertTo-PimSupportLegacyOwnerRecord {
    <# PURE. The stored answer of the database job (pim.Settings value, text or object) -> an object, or $null. #>
    param([AllowNull()]$Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [string]) { if (-not "$Value".Trim().StartsWith('{')) { return $null }; try { $Value = $Value | ConvertFrom-Json } catch { return $null } }
    if ($Value -is [string]) { try { $Value = $Value | ConvertFrom-Json } catch { return $null } }
    if (-not "$(Get-PimSupportLegacyOwnerField $Value 'state')".Trim()) { return $null }
    return $Value
}

function Get-PimSupportLegacyOwnerUpdaterDecision {
    <#
      PURE. What the updater does this run. -SupportOwner: the web-identity trim's database verdict (held | clean | in-session
      | n/a | unread). -State: ConvertFrom-PimSupportConsentState of [pimsupport].[usp_SupportState] ($null = not read).
      -Record: the database job's last answer. -Notes: what was already told to Invardia (keys). -Mode on | off.
      Returns @{ action = nothing | note | report-p1 | wait | start; reason }.
    #>
    param([AllowEmptyString()][string]$SupportOwner = '', [AllowNull()]$State = $null, [AllowNull()]$Record = $null, [AllowNull()]$Notes = $null,
          [AllowEmptyString()][string]$Mode = 'on', [datetime]$NowUtc = [datetime]::UtcNow)
    $o = { param($a, $r) [pscustomobject]@{ action = $a; reason = $r } }
    $m = "$Mode".Trim().ToLowerInvariant()
    if ($m -in @('off', '0', 'false', 'no')) { return (& $o 'nothing' 'switched off (PIM_SUPPORT_LEGACY_OWNER=off) -- nothing read or started') }
    $rs = "$(Get-PimSupportLegacyOwnerField $Record 'state')".Trim()
    $noteKey = "removed|$(Get-PimSupportLegacyOwnerRecordAt $Record)"
    $told = $false
    if ($Notes) { $told = [bool]($null -ne (Get-PimSupportLegacyOwnerField $Notes $noteKey)) }
    switch ("$SupportOwner".Trim().ToLowerInvariant()) {
        'clean' {
            if ($rs -eq 'removed' -and -not $told) { return (& $o 'note' 'the legacy standing db_owner was removed by the database job and the Support user holds no db_owner now -- Invardia is told once') }
            return (& $o 'nothing' 'the Support user holds no db_owner')
        }
        'held' { }
        'in-session' { return (& $o 'nothing' 'a support session is open -- the just-in-time path owns the db_owner; nothing is touched') }
        default { return (& $o 'nothing' "the Support user's db_owner was not judged this run ($SupportOwner) -- nothing is touched") }
    }
    if ($null -eq $State -or -not [bool](Get-PimSupportLegacyOwnerField $State 'read')) { return (& $o 'nothing' 'the support access state could not be read -- nothing is started') }
    if ((Get-PimSupportLegacyOwnerField $State 'jitOpen') -eq $true) { return (& $o 'nothing' 'a support session is open -- the just-in-time path owns the db_owner; nothing is touched') }
    if ((Get-PimSupportLegacyOwnerField $State 'readOnly') -ne $true) { return (& $o 'report-p1' "the Support app's read-only user is not in place (proof 1) -- the standing db_owner stays") }
    if ($rs -and $rs -ne 'removed') {
        $at = ConvertFrom-PimSupportLegacyOwnerUtc (Get-PimSupportLegacyOwnerField $Record 'atUtc')
        if ($null -ne $at -and ($NowUtc.ToUniversalTime() - $at).TotalHours -lt (Get-PimSupportLegacyOwnerRetryHours)) {
            return (& $o 'wait' "the database job answered '$rs' at $($at.ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture)) -- asked again after $(Get-PimSupportLegacyOwnerRetryHours) h")
        }
    }
    return (& $o 'start' 'both proofs are checked by the database job at this install; the standing db_owner goes only when both hold')
}

function Get-PimSupportLegacyOwnerReportParts {
    <# PURE. The job's answer -> the fix-request items it opens: @(@{ part; code }) (never the same item twice: the caller remembers them). #>
    param([AllowNull()]$Record)
    $rs = "$(Get-PimSupportLegacyOwnerField $Record 'state')".Trim()
    $out = New-Object System.Collections.Generic.List[object]
    switch ($rs) {
        'removed' { $out.Add(@{ part = 'sql-support-owner.removed'; code = 'sql-support-owner-removed' }) }
        'proof-missing' { foreach ($p in @(Get-PimSupportLegacyOwnerField $Record 'missing')) { if ("$p" -in @('p1', 'p2')) { $out.Add(@{ part = "sql-support-owner.$p"; code = 'sql-support-owner-proof' }) } } }
        'failed' { $out.Add(@{ part = 'sql-support-owner.failed'; code = 'sql-support-owner-failed' }) }
        'refused' { $out.Add(@{ part = 'sql-support-owner.failed'; code = 'sql-support-owner-failed' }) }
    }
    return @($out.ToArray())
}

function Invoke-PimSupportLegacyOwnerJobRun {
    <#
      Set the database job's setting (one write, read back by the setter), start ONE execution, wait for it (bounded).
      Never throws. -Arm (method, path, body); -SetEnv (sub, rg, job, values); -Start (sub, rg, job) -> @{ ok; execution; reason };
      -Sleep (seconds). Returns @{ started; execution; status; reason }.
    #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [Parameter(Mandatory)][scriptblock]$SetEnv, [Parameter(Mandatory)][scriptblock]$Start,
          [Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$JobName,
          [Parameter(Mandatory)][string]$AppId, [scriptblock]$Sleep = $null, [int]$WaitSeconds = 900, [int]$PollSeconds = 20, [datetime]$NowUtc = [datetime]::UtcNow)
    $o = [ordered]@{ started = $false; execution = ''; status = ''; reason = '' }
    if (-not $Sleep) { $Sleep = { param($s) Start-Sleep -Seconds $s } }
    try {
        if (-not (Test-PimSupportLegacyOwnerAppId $AppId)) { $o.reason = 'the Support app id is not known -- nothing started'; return [pscustomobject]$o }
        $ask = ConvertTo-Json -Compress -InputObject ([ordered]@{ appId = "$AppId".Trim().ToLowerInvariant(); askedUtc = $NowUtc.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture) })
        $vals = [ordered]@{}; $vals[(Get-PimSupportLegacyOwnerEnvName)] = $ask
        [void](& $SetEnv $SubscriptionId $ResourceGroup $JobName $vals)
        $st = & $Start $SubscriptionId $ResourceGroup $JobName
        if (-not $st -or -not $st.ok) { $o.reason = "the database job could not be started ($("$($st.reason)"))"; return [pscustomobject]$o }
        $o.started = $true; $o.execution = "$($st.execution)"
        $base = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.App/jobs/$JobName/executions/$($o.execution)?api-version=2024-03-01"
        $waited = 0
        while ($waited -lt $WaitSeconds) {
            & $Sleep $PollSeconds; $waited += $PollSeconds
            $ex = $null; try { $ex = & $Arm 'GET' $base $null } catch { $ex = $null }
            $s = if ($ex) { "$($ex.properties.status)" } else { '' }
            if ($s -in @('Succeeded', 'Failed', 'Stopped', 'Degraded')) { $o.status = $s; break }
        }
        if (-not $o.status) { $o.status = "still running after $WaitSeconds s" }
    } catch { $o.reason = ((("$($_.Exception.Message)") -split "`n")[0]).Trim() }
    return [pscustomobject]$o
}

function Invoke-PimSupportLegacyOwnerUpdaterStep {
    <#
      The updater's step. Never throws; never a warning line (internal hygiene); never fails the update.
        -SupportOwner / -SupportAppId   the web-identity trim's database verdict and the Support app id it read
        -ReadState      { } -> ConvertFrom-PimSupportConsentState of the signed state procedure ($null = no database session)
        -GetSetting     { param($name) } / -SetSetting { param($name, $value) }   pim.Settings
        -Gate           { } -> @{ start; reason }  the job on this release + its identity a member + no PIM job running
        -RunJob         { param($appId) } -> Invoke-PimSupportLegacyOwnerJobRun's answer
        -FixRequest     { param($part, $code, $since) } -> @{ registered; reason }
      Returns @{ state; action; reason; removed; readBack; reported = @(); lines = @(@{ level; text }) }.
    #>
    param([AllowEmptyString()][string]$SupportOwner = '', [AllowEmptyString()][string]$SupportAppId = '',
          [scriptblock]$ReadState = $null, [scriptblock]$GetSetting = $null, [scriptblock]$SetSetting = $null,
          [scriptblock]$Gate = $null, [scriptblock]$RunJob = $null, [scriptblock]$FixRequest = $null,
          [AllowEmptyString()][string]$Mode = 'on', [datetime]$NowUtc = [datetime]::UtcNow)
    $res = [ordered]@{ state = ''; action = ''; reason = ''; removed = $false; readBack = $false; reported = @(); lines = @() }
    $lines = New-Object System.Collections.Generic.List[object]
    $say = { param($lv, $t) $lines.Add(@{ level = $lv; text = "support db_owner: $t" }) }
    $short = { param($e) ((("$($e.Exception.Message)") -split "`n")[0]).Trim() }
    try { do {
        $readRec = { $r = $null; if ($GetSetting) { try { $r = ConvertTo-PimSupportLegacyOwnerRecord (& $GetSetting (Get-PimSupportLegacyOwnerSettingName)) } catch { $r = $null } }; $r }
        $notes = $null; $notesOk = $false
        if ($GetSetting) { try { $notes = & $GetSetting (Get-PimSupportLegacyOwnerNotesSettingName); if ($notes -is [string]) { $notes = $(if ("$notes".Trim()) { $notes | ConvertFrom-Json } else { $null }) }; $notesOk = $true } catch { $notes = $null } }
        $rec = & $readRec
        $state = $null
        if ("$SupportOwner".Trim().ToLowerInvariant() -eq 'held' -and $ReadState) { try { $state = & $ReadState } catch { $state = $null } }
        $d = Get-PimSupportLegacyOwnerUpdaterDecision -SupportOwner $SupportOwner -State $state -Record $rec -Notes $notes -Mode $Mode -NowUtc $NowUtc
        $res.action = $d.action; $res.reason = $d.reason
        # ONE note / fix request per item, remembered here (never sent again on the next run)
        $nb = @{ v = $notes }   # a holder: the closure below updates what was told for the rest of this run
        $tell = {
            param($part, $code, $since, $key)
            if ($nb.v -and $null -ne (Get-PimSupportLegacyOwnerField $nb.v $key)) { return }
            $fr = $null
            if ($FixRequest) { try { $fr = & $FixRequest $part $code $since } catch { $fr = @{ registered = $false; reason = (& $short $_) } } }
            $res.reported += @{ part = $part; code = $code; registered = [bool](Get-PimSupportLegacyOwnerField $fr 'registered'); reason = "$(Get-PimSupportLegacyOwnerField $fr 'reason')" }
            if ($notesOk -and $SetSetting) {
                $m = [ordered]@{}
                if ($nb.v) { $names = if ($nb.v -is [System.Collections.IDictionary]) { @($nb.v.Keys) } else { @($nb.v.PSObject.Properties | ForEach-Object { $_.Name }) }; foreach ($n in $names) { $m["$n"] = Get-PimSupportLegacyOwnerField $nb.v "$n" } }
                $m[$key] = $NowUtc.ToUniversalTime().ToString('o')
                try { [void](& $SetSetting (Get-PimSupportLegacyOwnerNotesSettingName) $m) } catch { & $say 'info' "what was told to support could not be stored ($(& $short $_)) -- it may be told again" }
                $nb.v = [pscustomobject]$m
            }
        }
        switch ($d.action) {
            'nothing' { $res.state = $(if ("$SupportOwner".Trim().ToLowerInvariant() -eq 'clean') { 'clean' } else { 'n/a' }); & $say 'info' $d.reason }
            'note' {
                $res.state = 'removed'; $res.removed = $true; $res.readBack = $true
                & $tell 'sql-support-owner.removed' 'sql-support-owner-removed' "$(Get-PimSupportLegacyOwnerRecordAt $rec)" "removed|$(Get-PimSupportLegacyOwnerRecordAt $rec)"
                & $say 'changed' "$(Get-PimSupportLegacyOwnerNoteText) -- told to PIM Manager support (internal)"
            }
            'report-p1' {
                $res.state = 'proof-missing'
                & $tell 'sql-support-owner.p1' 'sql-support-owner-proof' '' 'missing|p1'
                & $say 'info' "$($d.reason); reported to PIM Manager support (internal, once)"
            }
            'wait' {
                $res.state = 'waiting'
                foreach ($p in @(Get-PimSupportLegacyOwnerReportParts -Record $rec)) { & $tell $p.part $p.code '' "missing|$(($p.part -split '\.')[-1])" }
                & $say 'info' $d.reason
            }
            'start' {
                if (-not (Test-PimSupportLegacyOwnerAppId $SupportAppId)) { $res.state = 'n/a'; & $say 'info' 'the Support app id is not known this run -- nothing started'; break }
                $g = $null; if ($Gate) { try { $g = & $Gate } catch { $g = @{ start = $false; reason = (& $short $_) } } } else { $g = @{ start = $false; reason = 'no database job gate in this process' } }
                if (-not $g.start) { $res.state = 'not-started'; & $say 'info' "the database job is not started this run: $($g.reason) -- the standing db_owner stays; the next update asks again"; break }
                if (-not $RunJob) { $res.state = 'not-started'; & $say 'info' 'no job starter in this process -- nothing started'; break }
                $run = & $RunJob $SupportAppId
                if (-not $run.started) { $res.state = 'not-started'; & $say 'info' "the database job was not started: $($run.reason) -- the standing db_owner stays"; break }
                & $say 'info' "database job execution $($run.execution): $($run.status)"
                $rec2 = & $readRec
                $rs = "$(Get-PimSupportLegacyOwnerField $rec2 'state')"
                $fresh = $false
                $at2 = ConvertFrom-PimSupportLegacyOwnerUtc (Get-PimSupportLegacyOwnerField $rec2 'atUtc')
                if ($null -ne $at2 -and $at2 -ge $NowUtc.ToUniversalTime().AddMinutes(-5)) { $fresh = $true }
                if (-not $rec2 -or -not $fresh) { $res.state = 'no-answer'; & $say 'info' "the database job left no answer of this run (status $($run.status)) -- the next update looks again"; break }
                $res.state = $rs
                if ($rs -eq 'removed') {
                    # READ BACK through the signed state procedure, as the updater: no db_owner, the read-only user intact
                    $s2 = $null; if ($ReadState) { try { $s2 = & $ReadState } catch { $s2 = $null } }
                    if ($s2 -and [bool](Get-PimSupportLegacyOwnerField $s2 'read') -and (Get-PimSupportLegacyOwnerField $s2 'inOwner') -eq $false -and (Get-PimSupportLegacyOwnerField $s2 'readOnly') -eq $true) {
                        $res.removed = $true; $res.readBack = $true
                        & $tell 'sql-support-owner.removed' 'sql-support-owner-removed' "$(Get-PimSupportLegacyOwnerRecordAt $rec2)" "removed|$(Get-PimSupportLegacyOwnerRecordAt $rec2)"
                        & $say 'changed' "$(Get-PimSupportLegacyOwnerNoteText) -- told to PIM Manager support (internal)"
                    } else {
                        $res.state = 'read-back-open'
                        & $say 'info' 'the database job says removed, but the read-back through the support state did not confirm it yet -- the next update reads it again'
                    }
                } else {
                    foreach ($p in @(Get-PimSupportLegacyOwnerReportParts -Record $rec2)) { & $tell $p.part $p.code '' "missing|$(($p.part -split '\.')[-1])" }
                    & $say 'info' "the standing db_owner stays: $("$(Get-PimSupportLegacyOwnerField $rec2 'reason')".Trim())"
                }
            }
        }
    } while ($false) } catch { $res.state = 'failed'; & $say 'info' "not checked ($(& $short $_)) -- the update is unaffected" }
    $res.lines = @($lines.ToArray())
    return [pscustomobject]$res
}
