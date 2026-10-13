<#
  _accountStates.ps1 -- PIM 100.132 (owner 2026-10-13 evening: "did we not agree upon a redesign ... where there would be a
  state of the account like found in pim, not found in entra" / "why dont we have it for all groups, accounts view").

  ONE answer for the page: the state of every administrator account PIM Manager defines (and of every admin-named account
  the engine's own read found with no row), IN WORDS, computed from STORED FACTS ONLY -- the same model as the group states
  (_states.ps1, 100.118), whose helpers this file uses (it is dot-sourced after it). Nothing here reads the tenant, writes
  anything, stages anything, or changes a guard. GET /api/account-states (Admin) -> Get-PimAccountStates.

  THE FACTS, and where each one is stored:
    defined          pim.Rows entity 'Account-Definitions-Admins' (DataJson + UpdatedUtc = when the row was last committed).
    staged           the shared pending changes, raw text parsed here (unreadable = NOT KNOWN, never "nothing staged").
    queued           pim.ChangeQueue, the open entries (pending / committed / applying) -- an open entry is ALWAYS waiting
                     (blue), never red (owner 2026-10-13: "make sure that a new user which is in the queue doesnt become red").
    in Entra ID      the tenant cache kind 'drift' (written by the drift-snapshot job, every 4 hours): its scope 'Admins' is
                     the ENGINE'S OWN read of the admin accounts -- the accounts whose name starts with one of the admin
                     naming prefixes, plus every account a row names -- diffed against the rows: missing = a row with no
                     account, changed = an account that differs from its row (enabled state or attributes), extra = an
                     admin-named account with no row. A row that is in neither list was matched (equal). The read is used
                     only when it is fresh (Get-PimGroupStateMaxReadAgeHours), the scope was checked, and no item was cut
                     off (truncated = 0); otherwise "Not checked". A read that cannot be loaded is "Not known".
                     A row the read did not cover (committed after the read) is never "Missing": the account was not
                     looked for. It is "Waiting to be created" while nothing says it was created, and "Not checked" when
                     the engine recorded creating it after the read.
    could not be created   pim.Settings 'EngineItemFailures' scope Admins, read RAW -- and only for a failing run AFTER the
                     row was last committed (positive evidence).
    it existed       pim.ManagedKeys (scope admins) + pim.CommitApplied (scope Admins), used only when OLDER than the read.
    pinned delete    pim.Settings 'AdminDeletePins' read RAW: approved = a one-time delete waits; deleted = done (tombstone).

  THE STATES (words, colour, sort rank come from _states.ps1's Get-PimStateToneOf / Get-PimStateRankOf):
    Active, Waiting for commit, Waiting to be created (+ the scheduled date), Waiting to be disabled, Could not be created,
    Disabled (as the row asks), Marked for deletion (+ whether a pinned delete waits), Deleted -- account gone, Missing in
    Entra ID, AD only, Not managed, Not checked, Not known.

  Every reader is a seam (-ReadRows, -ReadPending, -ReadQueue, -ReadDrift, -ReadFailures, -ReadEvidence, -ReadPins) so
  tests/Test-PimAccountStates.ps1 seeds the facts. ASCII only.
#>

function Get-PimAccountStateEntity { 'Account-Definitions-Admins' }

function Get-PimAccountStateCatalog {
    # PURE. Every account state, in display order: id, the WORDS shown, the tone, the sort rank, and what it means.
    $c = @(
        [ordered]@{ id = 'active';          label = 'Active';                 meaning = 'Defined in PIM Manager, found in Microsoft Entra ID, and as its row asks.' }
        [ordered]@{ id = 'waiting-commit';  label = 'Waiting for commit';     meaning = 'Staged (or proposed in the change queue), not committed. Nothing happens until it is committed.' }
        [ordered]@{ id = 'waiting-create';  label = 'Waiting to be created';  meaning = 'Committed, and not in Microsoft Entra ID yet: the engine creates it on its next run, or on its scheduled date.' }
        [ordered]@{ id = 'waiting-disable'; label = 'Waiting to be disabled'; meaning = 'Its row asks Disabled / Revoked / Removed and the last read found the account not yet as asked.' }
        [ordered]@{ id = 'create-failed';   label = 'Could not be created';   meaning = 'Committed, not in Microsoft Entra ID, and an engine run after the commit failed on it.' }
        [ordered]@{ id = 'disabled';        label = 'Disabled';               meaning = 'Its row asks Disabled / Revoked / Removed, and the account is as asked.' }
        [ordered]@{ id = 'marked-delete';   label = 'Marked for deletion';    meaning = 'Its row says AccountStatus = Deleted and the account still exists.' }
        [ordered]@{ id = 'deleted-gone';    label = 'Deleted -- account gone'; meaning = 'Its row says AccountStatus = Deleted and the account is no longer in Microsoft Entra ID. The row is kept as history.' }
        [ordered]@{ id = 'missing';         label = 'Missing in Entra ID';    meaning = 'Defined, it was in Microsoft Entra ID before, and the last read did not find it: it was deleted outside PIM Manager.' }
        [ordered]@{ id = 'ad-only';         label = 'AD only';                meaning = 'An on-premises Active Directory admin (TargetPlatform AD): it lives in AD, not in Microsoft Entra ID.' }
        [ordered]@{ id = 'not-managed';     label = 'Not managed';            meaning = 'In Microsoft Entra ID with an admin naming prefix, and no row in PIM Manager names it.' }
        [ordered]@{ id = 'not-checked';     label = 'Not checked';            meaning = 'Whether it is in Microsoft Entra ID was not checked: no read, an old read, or a change after the last read.' }
        [ordered]@{ id = 'unknown';         label = 'Not known';              meaning = 'A stored fact this state needs could not be read. The reason is given; nothing is guessed.' }
    )
    foreach ($x in $c) { $x['tone'] = (Get-PimStateToneOf -State $x.id); $x['rank'] = (Get-PimStateRankOf -State $x.id) }
    return $c
}

function ConvertTo-PimAccountStateKey {
    # PURE. The account-name part of a UPN / user name, lower case -- the key the engine's Admins scope uses (KeyOf).
    param([AllowNull()][string]$Name)
    $s = "$Name".Trim(); $i = $s.IndexOf('@'); if ($i -ge 0) { $s = $s.Substring(0, $i) }
    return $s.ToLowerInvariant()
}

function Read-PimAccountStateRows {
    # The stored admin rows with the time each was last committed (__updatedUtc). THROWS when the store cannot be read.
    param([Parameter(Mandatory)][string]$ConnectionString)
    $raw = @(Invoke-PimSqlQuery -ConnectionString $ConnectionString -Sql 'SELECT [Key] AS RowKey, DataJson, UpdatedUtc FROM pim.Rows WHERE Entity = @e' -Parameters @{ e = (Get-PimAccountStateEntity) })
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($x in $raw) {
        if ($null -eq $x) { continue }
        $j = "$($x.DataJson)".Trim(); if (-not $j) { continue }
        $o = ConvertFrom-Json -InputObject $j
        if ($null -eq $o) { continue }
        Add-Member -InputObject $o -NotePropertyName '__updatedUtc' -NotePropertyValue $x.UpdatedUtc -Force
        $out.Add($o)
    }
    return $out.ToArray()
}

function Read-PimAccountStateEvidenceRows {
    # The stored evidence that an admin account existed, rows @{ name; kind; firstUtc; lastUtc } (as the group reader).
    # THROWS when the store cannot be read. Read-only.
    param([Parameter(Mandatory)][string]$ConnectionString)
    $out = New-Object System.Collections.Generic.List[object]
    $led = @(Invoke-PimSqlQuery -ConnectionString $ConnectionString -Sql "IF OBJECT_ID('pim.ManagedKeys') IS NOT NULL SELECT [Key] AS AcctKey, FirstSeenUtc FROM pim.ManagedKeys WHERE LOWER(Scope) = 'admins'" -Parameters @{})
    foreach ($r in $led) {
        if ($null -eq $r -or -not "$($r.AcctKey)".Trim()) { continue }
        $out.Add([pscustomobject]@{ name = (ConvertTo-PimAccountStateKey -Name "$($r.AcctKey)"); kind = 'ledger'; firstUtc = $r.FirstSeenUtc; lastUtc = $r.FirstSeenUtc })
    }
    $app = @(Invoke-PimSqlQuery -ConnectionString $ConnectionString -Parameters @{} -Sql @"
IF OBJECT_ID('pim.CommitApplied') IS NOT NULL
SELECT LOWER(LiveKey) AS AcctKey, Result, MIN(AppliedUtc) AS FirstUtc, MAX(AppliedUtc) AS LastUtc
FROM pim.CommitApplied
WHERE LOWER(Scope) = 'admins' AND Result IN ('created', 'updated', 'already present', 'removed')
GROUP BY LOWER(LiveKey), Result
"@)
    foreach ($r in $app) {
        if ($null -eq $r -or -not "$($r.AcctKey)".Trim()) { continue }
        $out.Add([pscustomobject]@{ name = (ConvertTo-PimAccountStateKey -Name "$($r.AcctKey)"); kind = "$($r.Result)".Trim().ToLowerInvariant(); firstUtc = $r.FirstUtc; lastUtc = $r.LastUtc })
    }
    return $out.ToArray()
}

function Read-PimAccountStateMemberships {
    # The admin named by each stored membership row (PIM-Assignments-Admins.Username), as text. THROWS when unreadable.
    param([Parameter(Mandatory)][string]$ConnectionString)
    $rows = @(Invoke-PimSqlQuery -ConnectionString $ConnectionString -Parameters @{ e = 'PIM-Assignments-Admins' } -Sql 'SELECT JSON_VALUE(DataJson, ''$.Username'') AS Username FROM pim.Rows WHERE Entity = @e AND ISJSON(DataJson) = 1')
    return @($rows | Where-Object { $null -ne $_ } | ForEach-Object { "$($_.Username)" })
}

function ConvertFrom-PimAccountStateFailures {
    # PURE. The RAW 'EngineItemFailures' text -> @{ ok; error; byKey = @{ key -> record } } for scope Admins. Unreadable = ok $false.
    param([AllowNull()][string]$Raw)
    $out = @{ ok = $true; error = ''; byKey = @{} }
    if ($null -eq $Raw -or "$Raw".Trim() -eq '' -or "$Raw".Trim() -eq 'null') { return $out }
    try {
        $v = ConvertFrom-PimGroupStateJson -Text "$Raw"
        if ($v -is [string]) { if ("$v".Trim() -eq '') { return $out }; $v = ConvertFrom-PimGroupStateJson -Text "$v" }
        foreach ($f in @($v)) {
            if ($null -eq $f) { continue }
            if ($f -is [string] -or $f -is [ValueType]) { throw 'the stored value is not a list of failing items' }
            $sp = $f.PSObject.Properties['scope']; $kp = $f.PSObject.Properties['key']
            if (-not $sp -or -not $kp) { throw 'a stored item has no scope or no key' }
            if ("$($sp.Value)".Trim() -ine 'Admins') { continue }
            $k = ConvertTo-PimAccountStateKey -Name "$($kp.Value)"
            if (-not $k) { continue }
            $out.byKey[$k] = [ordered]@{ code = (Get-PimGroupStateField -Row $f -Name 'code'); title = (Get-PimGroupStateField -Row $f -Name 'title')
                message = (Get-PimGroupStateField -Row $f -Name 'message'); op = (Get-PimGroupStateField -Row $f -Name 'op')
                lastSeenUtc = (Format-PimGroupStateUtc -Value $(if ($f.PSObject.Properties['lastSeenUtc']) { $f.lastSeenUtc } else { $null })) }
        }
    } catch { return @{ ok = $false; error = "$($_.Exception.Message)"; byKey = @{} } }
    return $out
}

function ConvertFrom-PimAccountStatePins {
    # PURE. The RAW 'AdminDeletePins' text -> @{ ok; error; byKey = @{ key -> the LATEST pin } }. Unreadable = ok $false.
    param([AllowNull()][string]$Raw)
    $out = @{ ok = $true; error = ''; byKey = @{} }
    if ($null -eq $Raw -or "$Raw".Trim() -eq '' -or "$Raw".Trim() -eq 'null') { return $out }
    try {
        $o = ConvertFrom-PimGroupStateJson -Text "$Raw"
        if ($o -is [string]) { $o = ConvertFrom-PimGroupStateJson -Text "$o" }
        if ($null -eq $o -or $o -is [ValueType] -or $o -is [string] -or -not $o.PSObject.Properties['pins']) { throw "the stored 'AdminDeletePins' record has no pins list" }
        foreach ($p in @($o.pins)) {
            if ($null -eq $p) { continue }
            $k = ConvertTo-PimAccountStateKey -Name (Get-PimGroupStateField -Row $p -Name 'key')
            if ($k) { $out.byKey[$k] = $p }   # stored in time order: the last one is the latest
        }
    } catch { return @{ ok = $false; error = "$($_.Exception.Message)"; byKey = @{} } }
    return $out
}

function Read-PimAccountStateDrift {
    <#
      PURE over the stored 'drift' document. -> @{ status = 'fresh' | 'old' | 'none' | 'no-time' | 'unreadable' | 'scope-not-checked';
      readUtc; ageHours; maxAgeHours; error; text; missing = @{ key }; changed = @{ key }; extra = @{ key -> label } }.
    #>
    param([AllowNull()][object]$Doc, [AllowNull()][string]$ReadError = '', [Parameter(Mandatory)][datetime]$NowUtc)
    $maxAge = [int](Get-PimGroupStateMaxReadAgeHours)
    $o = [ordered]@{ status = 'none'; readUtc = ''; ageHours = $null; maxAgeHours = $maxAge; error = ''; text = ''; missing = @{}; changed = @{}; extra = @{}; count = 0 }
    if ("$ReadError".Trim()) { $o.status = 'unreadable'; $o.error = "$ReadError"; return $o }
    if ($null -eq $Doc) { return $o }
    $sp = if ($Doc -is [System.Collections.IDictionary]) { $Doc['scopes'] } else { $(if ($Doc.PSObject.Properties['scopes']) { $Doc.scopes } else { $null }) }
    if ($null -eq $sp) { $o.status = 'unreadable'; $o.error = 'the stored read has no list of scopes'; return $o }
    $stamp = if ($Doc -is [System.Collections.IDictionary]) { $Doc['refreshedUtc'] } else { $(if ($Doc.PSObject.Properties['refreshedUtc']) { $Doc.refreshedUtc } else { $null }) }
    $read = ConvertTo-PimGroupStateUtc -Value $stamp
    if ($null -eq $read) { $o.status = 'no-time'; return $o }
    $o.readUtc = $read.ToString('yyyy-MM-ddTHH:mm:ssZ')
    $age = ($NowUtc.ToUniversalTime() - $read).TotalHours
    $o.ageHours = [int][Math]::Floor([Math]::Max(0, $age))
    if ($age -gt $maxAge) { $o.status = 'old'; return $o }
    $sc = @(@($sp) | Where-Object { $null -ne $_ -and "$(Get-PimGroupStateField -Row $_ -Name 'scope')" -ieq 'Admins' })[0]
    if ($null -eq $sc) { $o.status = 'scope-not-checked'; $o.error = 'the last read has no area for the administrator accounts'; return $o }
    $ok = "$(Get-PimGroupStateField -Row $sc -Name 'ok')"; $chk = "$(Get-PimGroupStateField -Row $sc -Name 'checked')"; $trunc = "$(Get-PimGroupStateField -Row $sc -Name 'truncated')"
    if ($ok -ine 'True' -or $chk -ine 'True') {
        $why = (Get-PimGroupStateField -Row $sc -Name 'notCheckedReason'); if (-not $why) { $why = (Get-PimGroupStateField -Row $sc -Name 'error') }
        $o.status = 'scope-not-checked'; $o.error = $(if ($why) { $why } else { 'the area was not checked' }); return $o
    }
    if ($trunc -and $trunc -ne '0') { $o.status = 'scope-not-checked'; $o.error = "the last read listed only part of its findings ($trunc not listed)"; return $o }
    $items = if ($sc -is [System.Collections.IDictionary]) { $sc['items'] } else { $sc.items }
    foreach ($it in @($items)) {
        if ($null -eq $it) { continue }
        $k = ConvertTo-PimAccountStateKey -Name (Get-PimGroupStateField -Row $it -Name 'key')
        if (-not $k) { continue }
        switch ((Get-PimGroupStateField -Row $it -Name 'type').ToLowerInvariant()) {
            'missing' { $o.missing[$k] = $true }
            'changed' { $o.changed[$k] = $true }
            'extra'   { $lb = Get-PimGroupStateField -Row $it -Name 'label'; $o.extra[$k] = $(if ($lb) { $lb } else { $k }) }
        }
    }
    $o.count = [int](Get-PimGroupStateField -Row $sc -Name 'live')
    $o.status = 'fresh'
    return $o
}

function Get-PimAccountStatePinText {
    # PURE. What the pin says about a row marked Deleted whose account still exists.
    param([AllowNull()][object]$Pins, [Parameter(Mandatory)][string]$Key)
    if ($null -eq $Pins -or -not $Pins.ok) { return " Whether a pinned one-time delete waits could not be read$(if ($Pins -and "$($Pins.error)".Trim()) { " ($("$($Pins.error)".Trim()))" })." }
    $p = if ($Pins.byKey.ContainsKey($Key)) { $Pins.byKey[$Key] } else { $null }
    if ($null -eq $p) { return ' No pinned delete waits: an operator has to confirm the delete again (Delete account) before the engine deletes it.' }
    $st = (Get-PimGroupStateField -Row $p -Name 'status').ToLowerInvariant()
    $by = Get-PimGroupStateField -Row $p -Name 'approvedBy'
    switch ($st) {
        'approved' { return " A pinned one-time delete waits for the next engine run$(if ($by) { " (approved by $by)" })." }
        'claimed'  { return ' A delete was started and never confirmed: nothing more is done until an operator confirms the delete again.' }
        'failed'   { return ' The last delete call failed; the next engine run tries it again (the same account only).' }
        'deleted'  { return ' The pinned delete was done once; it acts on no account again.' }
    }
    return " The stored delete pin has a state PIM Manager does not recognise ($st)."
}

function Resolve-PimAccountState {
    <#
      PURE. The state of ONE admin row. Returns @{ state; reason; why; inEntra; scheduledUtc }.
        -Row       the stored row (+ __updatedUtc); -Key its account-name key
        -Drift     Read-PimAccountStateDrift's answer
        -Evidence  @{ ok; error } and -Seen the evidence record of this key (ConvertTo-PimGroupStateEvidence) or $null
        -Failures  @{ ok; error } and -Fail the failing item of this key or $null
        -Queue     @{ ok; error } and -Queued the open change-queue entry of this key or $null
        -Pins      ConvertFrom-PimAccountStatePins' answer
    #>
    param([Parameter(Mandatory)][object]$Row, [Parameter(Mandatory)][string]$Key, [Parameter(Mandatory)][object]$Drift,
          [Parameter(Mandatory)][object]$Evidence, [AllowNull()][object]$Seen, [Parameter(Mandatory)][object]$Failures, [AllowNull()][object]$Fail,
          [Parameter(Mandatory)][object]$Queue, [AllowNull()][object]$Queued, [AllowNull()][object]$Pins, [Parameter(Mandatory)][datetime]$NowUtc)
    $r = { param($s, $t, $w, $ie, $sch) [ordered]@{ state = "$s"; reason = "$t"; why = "$w"; inEntra = "$ie"; scheduledUtc = "$sch" } }
    $now = $NowUtc.ToUniversalTime()
    $margin = [int](Get-PimGroupStateReadMarginMinutes)
    $status = (Get-PimGroupStateField -Row $Row -Name 'AccountStatus')
    $st = $status.ToLowerInvariant()
    $asksOff = $st -in @('disabled', 'revoked', 'removed')
    $isDeleted = ($st -eq 'deleted')
    $commit = ConvertTo-PimGroupStateUtc -Value $(if ($Row -is [System.Collections.IDictionary]) { $Row['__updatedUtc'] } elseif ($Row.PSObject.Properties['__updatedUtc']) { $Row.__updatedUtc } else { $null })

    # 1. AD only: it lives in on-premises AD, never in Microsoft Entra ID
    if ((Get-PimGroupStateField -Row $Row -Name 'TargetPlatform') -ieq 'AD') {
        return (& $r 'ad-only' "An on-premises Active Directory admin (TargetPlatform AD$(if ($status) { ", AccountStatus $status" })): it lives in AD and is not looked for in Microsoft Entra ID." 'ad-only' 'not-applicable' '')
    }
    # 2. scheduled: not created before its ProvisionDate (the engine holds the row back until then)
    $pdRaw = Get-PimGroupStateField -Row $Row -Name 'ProvisionDate'
    $pd = if ($pdRaw) { ConvertTo-PimGroupStateUtc -Value $pdRaw } else { $null }
    if (-not $isDeleted -and -not $asksOff -and $null -ne $pd -and $pd -gt $now.AddSeconds(60)) {
        $pdT = $pd.ToString('yyyy-MM-ddTHH:mm:ssZ')
        return (& $r 'waiting-create' "It is scheduled: the engine creates it on $pdT (its ProvisionDate), not before." 'scheduled' 'not-yet' $pdT)
    }
    $qTxt = { param($q) "$($q.status)$(if ($null -ne $q.enqueuedUtc -and "$($q.enqueuedUtc)".Trim()) { ", queued $(Format-PimGroupStateUtc -Value $q.enqueuedUtc)" })" }

    # 3. the read
    $ds = "$($Drift.status)"
    $job = 'drift-snapshot'
    if ($ds -eq 'unreadable') { return (& $r 'unknown' "The stored read of the administrator accounts could not be loaded ($($Drift.error)), so whether this account exists is not known." 'read-unreadable' 'unknown' '') }
    if ($ds -ne 'fresh') {
        if ($Queued) { return (& $r 'waiting-create' "A change for it waits in the change queue ($(& $qTxt $Queued)); there is no usable read of Microsoft Entra ID to say more." 'queued' 'not-checked' '') }
        $t = switch ($ds) {
            'none'              { "The administrator accounts in Microsoft Entra ID have not been read yet (the job $job reads them)." }
            'no-time'           { 'The stored read of the administrator accounts carries no time, so it is not used.' }
            'old'               { "The last read of the administrator accounts is from $($Drift.readUtc) ($($Drift.ageHours) hours ago); a read older than $($Drift.maxAgeHours) hours is not used (the job $job reads them)." }
            'scope-not-checked' { "The last read of Microsoft Entra ID did not check the administrator accounts ($($Drift.error))." }
            default             { "The stored read of the administrator accounts is in a state PIM Manager does not recognise ($ds)." }
        }
        return (& $r 'not-checked' ($t + ' So whether this account exists is not checked.') "read-$ds" 'not-checked' '')
    }
    $readTxt = "$($Drift.readUtc)"
    $read = ConvertTo-PimGroupStateUtc -Value $Drift.readUtc
    $edge = $read.AddMinutes(-1 * $margin)
    $inMissing = $Drift.missing.ContainsKey($Key)
    $inChanged = $Drift.changed.ContainsKey($Key)
    $rowBefore = ($null -ne $commit -and $commit -le $edge)

    # 4. AccountStatus = Deleted
    if ($isDeleted) {
        $tomb = ($Pins -and $Pins.ok -and $Pins.byKey.ContainsKey($Key) -and (Get-PimGroupStateField -Row $Pins.byKey[$Key] -Name 'status') -ieq 'deleted')
        if ($tomb) {
            $done = Get-PimGroupStateField -Row $Pins.byKey[$Key] -Name 'doneUtc'
            return (& $r 'deleted-gone' "Its row says AccountStatus = Deleted and PIM Manager deleted the account$(if ($done) { " on $(Format-PimGroupStateUtc -Value $done)" }) (the pinned one-time delete). The row is kept as history." 'deleted-by-pin' 'no' '')
        }
        if ($inChanged) {
            return (& $r 'marked-delete' ("Its row says AccountStatus = Deleted and the account is still in Microsoft Entra ID (read $readTxt)." + (Get-PimAccountStatePinText -Pins $Pins -Key $Key)) 'delete-waits' 'yes' '')
        }
        if ($inMissing -or $rowBefore) {
            return (& $r 'deleted-gone' "Its row says AccountStatus = Deleted and the last read of Microsoft Entra ID ($readTxt) found no account for it. The row is kept as history; nothing is created or deleted for it." 'gone' 'no' '')
        }
        return (& $r 'not-checked' "Its row was marked Deleted after the last read of Microsoft Entra ID ($readTxt), so whether the account is still there is not checked yet (the job $job reads it)." 'changed-after-read' 'not-checked' '')
    }

    # 5. the account was found (matched or different)
    $hadBefore = ($Seen -and $null -ne $Seen.firstUtc -and $Seen.firstUtc -le $edge)
    $covered = $rowBefore -or $hadBefore
    $failTxt = ''
    if ($Fail -and "$($Fail.title)$($Fail.message)".Trim()) { $failTxt = " The last engine run reported a problem on it: $("$($Fail.title)".Trim()) $("$($Fail.message)".Trim())".TrimEnd() }
    if ($covered -and -not $inMissing) {
        if ($asksOff) {
            if ($inChanged) { return (& $r 'waiting-disable' ("Its row asks AccountStatus = $status and the last read ($readTxt) found the account not yet as asked (still enabled, or an attribute differs). The next engine run brings it in line." + $failTxt) 'differs' 'yes' '') }
            return (& $r 'disabled' ("Its row asks AccountStatus = $status and the account is as asked (read $readTxt)." + $failTxt) '' 'yes' '')
        }
        if ($inChanged) { return (& $r 'active' ("In Microsoft Entra ID (read $readTxt). The read found something that differs from its row; the next engine run corrects it." + $failTxt) 'differs' 'yes' '') }
        return (& $r 'active' ("Defined in PIM Manager and found in Microsoft Entra ID, as its row asks (read $readTxt)." + $failTxt) '' 'yes' '')
    }

    # 6. not in the read (or committed after it)
    if (-not $Evidence.ok) {
        return (& $r 'unknown' "It is not in the last read of Microsoft Entra ID ($readTxt) as found, and what PIM Manager recorded about it could not be read ($($Evidence.error)). So it is not known whether it is waiting, was created after the read, or is gone." 'evidence-unreadable' 'unknown' '')
    }
    if ($Seen -and $null -ne $Seen.lastUtc -and $Seen.lastUtc -ge $edge) {
        return (& $r 'not-checked' "The engine created or confirmed it on $(Format-PimGroupStateUtc -Value $Seen.lastUtc), at or after the last read of Microsoft Entra ID ($readTxt). The next read shows whether it is there (the job $job)." 'created-after-read' 'not-checked' '')
    }
    # an open change-queue entry always wins over every red answer
    if ($Queued) {
        return (& $r 'waiting-create' "It is not in Microsoft Entra ID yet (read $readTxt), and a change for it waits in the change queue ($(& $qTxt $Queued)). $(if ("$($Queued.status)" -eq 'pending') { 'It is done once that change is committed and the engine has run.' } else { 'The engine creates it when it runs the queue.' })" 'queued' 'no' '')
    }
    $queueBad = -not $Queue.ok
    $queueTxt = if ($queueBad) { " Whether a change for it waits in the change queue could not be read ($($Queue.error))." } else { '' }
    if ($asksOff -and -not $hadBefore) {
        return (& $r 'disabled' "Its row asks AccountStatus = $status, so the account is not created (a disabled, revoked or removed admin is never provisioned). There is no account in Microsoft Entra ID (read $readTxt)." 'not-provisioned' 'no' '')
    }
    if (-not $Failures.ok) {
        return (& $r 'unknown' "It is not in the last read of Microsoft Entra ID ($readTxt), and whether the last engine run failed on it could not be read ($($Failures.error))." 'failures-unreadable' 'unknown' '')
    }
    $failNote = ''
    if ($Fail) {
        $ft = ConvertTo-PimGroupStateUtc -Value $Fail.lastSeenUtc
        $afterCommit = ($null -ne $ft) -and ($null -eq $commit -or $ft -ge $commit.AddMinutes(-1 * $margin))
        if ($afterCommit) {
            $t = "It is not in Microsoft Entra ID (read $readTxt) and the last engine run failed on it ($("$($Fail.lastSeenUtc)".Trim())): "
            $t += ("$("$($Fail.title)".Trim()) $("$($Fail.message)".Trim())".Trim())
            if (-not "$($Fail.title)$($Fail.message)".Trim()) { $t += 'no reason was recorded' }
            $t += '. The reason and the fix are under Jobs > Engine logs & errors.'
            if ($queueBad) { return (& $r 'unknown' ($t + $queueTxt + ' So it is not said that it could not be created.') 'queue-unreadable' 'unknown' '') }
            return (& $r 'create-failed' $t 'run-failed' 'no' '')
        }
        $failNote = " An engine run reported a problem on it$(if ($null -ne $ft) { " on $(Format-PimGroupStateUtc -Value $ft)" } else { ' (no time recorded)' }), before its row was last committed; the next run shows whether the change fixed it."
    }
    if ($hadBefore -and $inMissing) {
        $t = "It was in Microsoft Entra ID (PIM Manager recorded it on $(Format-PimGroupStateUtc -Value $Seen.lastUtc)) and the last read ($readTxt) did not find it: it was deleted outside PIM Manager. The engine creates it again on its next run unless its row says otherwise."
        if ($queueBad) { return (& $r 'unknown' ($t + $queueTxt + ' So it is not said that it is missing.') 'queue-unreadable' 'unknown' '') }
        return (& $r 'missing' $t 'deleted-outside' 'no' '')
    }
    $tw = if ($rowBefore) { "It is committed and not in Microsoft Entra ID yet (read $readTxt). The engine creates it on its next run." }
          else { "It was committed after the last read of Microsoft Entra ID ($readTxt) and nothing says it was created yet. The engine creates it on its next run." }
    return (& $r 'waiting-create' ($tw + $failNote) 'next-run' $(if ($rowBefore) { 'no' } else { 'not-yet' }) '')
}

function Get-PimAccountStates {
    <#
      The whole answer of GET /api/account-states:
        @{ ok; error; computedUtc; tenantRead; sources; catalog; counts; total; accounts }
      accounts = @(@{ key; name; upn; userName; hasRow; state; label; tone; rank; reason; why; inEntra; scheduledUtc; staged;
                      stagedText; stagedBy }), sorted by name. ok = $false ONLY when the rows themselves could not be read.
      Seams (tests): -ReadRows, -ReadPending, -ReadQueue, -ReadDrift { -> the 'drift' document or $null; throws = not loaded },
      -ReadFailures, -ReadEvidence, -ReadPins, -NowUtc.
    #>
    param([scriptblock]$ReadRows, [scriptblock]$ReadPending, [scriptblock]$ReadQueue, [scriptblock]$ReadDrift, [scriptblock]$ReadFailures,
          [scriptblock]$ReadEvidence, [scriptblock]$ReadPins, [scriptblock]$ReadMemberships, [datetime]$NowUtc = [datetime]::UtcNow)
    $now = $NowUtc.ToUniversalTime()
    $entity = Get-PimAccountStateEntity
    $catalog = @(Get-PimAccountStateCatalog)
    $labelOf = @{}; foreach ($c in $catalog) { $labelOf[$c.id] = $c.label }
    $counts = [ordered]@{}; foreach ($c in $catalog) { $counts[$c.id] = 0 }
    $sources = [ordered]@{}
    $base = [ordered]@{ ok = $false; error = ''; computedUtc = $now.ToString('yyyy-MM-ddTHH:mm:ssZ'); tenantRead = $null; sources = $sources; catalog = $catalog
                        counts = $counts; total = 0; accounts = @() }
    $cs = { Get-PimManagerSettingCs }

    # ---- 1. the rows (without them there is no list) ------------------------------------------------------------------
    $rows = $null
    try {
        $rows = if ($ReadRows) { & $ReadRows } else { Read-PimAccountStateRows -ConnectionString (& $cs) }
        if ($null -eq $rows) { throw 'the reader answered nothing' }
    } catch {
        $sources['rows'] = [ordered]@{ ok = $false; error = "$($_.Exception.Message)" }
        $base.error = "The administrator rows could not be read ($($_.Exception.Message)), so no account state is known."
        return $base
    }
    $sources['rows'] = [ordered]@{ ok = $true; error = '' }

    # ---- 2. staged / queued -------------------------------------------------------------------------------------------
    $stagedOk = $true; $stagedErr = ''; $stagedByKey = @{}
    try {
        $raw = if ($ReadPending) { & $ReadPending } else {
            if (-not (Get-Command Read-PimSharedPendingStore -ErrorAction SilentlyContinue)) { throw 'the reader of the pending changes is not loaded in this process' }
            (Read-PimSharedPendingStore -ConnectionString (& $cs)).raw
        }
        if ($null -ne $raw -and "$raw".Trim() -ne '' -and "$raw".Trim() -ne 'null') {
            $doc = ConvertFrom-PimGroupStateJson -Text "$raw"
            if ($doc -is [string]) { $doc = ConvertFrom-PimGroupStateJson -Text "$doc" }
            if ($null -eq $doc -or $doc -is [ValueType] -or $doc -is [string]) { throw 'the stored pending changes are not a document' }
            $bp = $doc.PSObject.Properties['bases']
            if ($bp -and $null -ne $bp.Value -and $bp.Value.PSObject.Properties[$entity]) {
                foreach ($ch in @($bp.Value.PSObject.Properties[$entity].Value.changes)) {
                    if ($null -eq $ch) { continue }
                    $op = (Get-PimGroupStateField -Row $ch -Name 'op').ToLowerInvariant()
                    if ($op -notin @('add', 'modify', 'remove')) { continue }
                    $src = if ($ch.PSObject.Properties['row'] -and $null -ne $ch.row) { $ch.row } elseif ($ch.PSObject.Properties['before']) { $ch.before } else { $null }
                    $nm = Get-PimGroupStateField -Row $src -Name 'UserPrincipalName'; if (-not $nm) { $nm = Get-PimGroupStateField -Row $src -Name 'UserName' }
                    if (-not $nm) { $nm = Get-PimGroupStateField -Row $ch -Name 'key' }
                    $k = ConvertTo-PimAccountStateKey -Name $nm
                    if (-not $k) { continue }
                    $stagedByKey[$k] = [pscustomobject]@{ op = $op; row = $(if ($ch.PSObject.Properties['row']) { $ch.row } else { $null }); name = $nm; by = (Get-PimGroupStateField -Row $ch -Name 'by') }
                }
            }
        }
    } catch { $stagedOk = $false; $stagedErr = "$($_.Exception.Message)"; $stagedByKey = @{} }
    $sources['staged'] = [ordered]@{ ok = $stagedOk; error = $stagedErr }

    $queue = @{ ok = $true; error = '' }; $queuedBy = @{}
    try {
        $qRows = if ($ReadQueue) { & $ReadQueue @($entity) } else { Read-PimStateQueueRows -ConnectionString (& $cs) -Entities @($entity) }
        foreach ($q in @($qRows)) {
            if ($null -eq $q) { continue }
            if ("$($q.op)".Trim() -and "$($q.op)".Trim() -notin @('Create', 'Update')) { continue }
            $k = ConvertTo-PimAccountStateKey -Name (Get-PimGroupStateField -Row $q -Name 'name')
            if ($k) { $queuedBy[$k] = $q }
        }
    } catch { $queue = @{ ok = $false; error = "$($_.Exception.Message)" }; $queuedBy = @{} }
    $sources['queue'] = [ordered]@{ ok = [bool]$queue.ok; error = "$($queue.error)" }

    # ---- 3. the read (the engine's own read of the admin accounts, stored by the drift-snapshot job) -------------------
    $dDoc = $null; $dErr = ''
    try {
        if ($ReadDrift) { $dDoc = & $ReadDrift }
        else {
            if (-not (Get-Command Get-PimTenantCacheEntry -ErrorAction SilentlyContinue)) { throw 'the reader of the stored tenant lists is not loaded in this process' }
            $dDoc = Get-PimTenantCacheEntry -Kind 'drift'
            if ($null -eq $dDoc -and (Get-Command Get-PimTenantCacheReadError -ErrorAction SilentlyContinue)) { $w = "$(Get-PimTenantCacheReadError -Kind 'drift')"; if ($w.Trim()) { throw $w } }
        }
    } catch { $dErr = "$($_.Exception.Message)"; if (-not $dErr.Trim()) { $dErr = 'the read failed' } }
    $drift = Read-PimAccountStateDrift -Doc $dDoc -ReadError $dErr -NowUtc $now
    $drift.text = switch ("$($drift.status)") {
        'fresh'             { "The administrator accounts were read on $($drift.readUtc) (the engine's own read; $($drift.extra.Count) admin-named account(s) without a row)." }
        'old'               { "The last read of the administrator accounts is from $($drift.readUtc) ($($drift.ageHours) hours ago) -- too old to say which accounts exist." }
        'none'              { 'The administrator accounts have not been read yet (the job drift-snapshot reads them).' }
        'no-time'           { 'The stored read of the administrator accounts carries no time, so it is not used.' }
        'scope-not-checked' { "The last read did not check the administrator accounts: $($drift.error)" }
        default             { "The stored read of the administrator accounts could not be loaded: $($drift.error)" }
    }
    $base.tenantRead = [ordered]@{ status = $drift.status; readUtc = $drift.readUtc; ageHours = $drift.ageHours; maxAgeHours = $drift.maxAgeHours; error = $drift.error; text = $drift.text; job = 'drift-snapshot' }

    # ---- 4. failures, evidence, pins ----------------------------------------------------------------------------------
    $fail = $null
    try {
        $rawF = if ($ReadFailures) { & $ReadFailures } else { Get-PimSqlSettingRaw -ConnectionString (& $cs) -Name 'EngineItemFailures' }
        $fail = ConvertFrom-PimAccountStateFailures -Raw $(if ($null -eq $rawF) { $null } else { "$rawF" })
    } catch { $fail = @{ ok = $false; error = "$($_.Exception.Message)"; byKey = @{} } }
    $sources['failures'] = [ordered]@{ ok = [bool]$fail.ok; error = "$($fail.error)" }
    $evid = @{ ok = $true; error = '' }; $evBy = @{}
    try {
        $evRows = if ($ReadEvidence) { & $ReadEvidence } else { Read-PimAccountStateEvidenceRows -ConnectionString (& $cs) }
        $evBy = ConvertTo-PimGroupStateEvidence -Rows @($evRows)
    } catch { $evid = @{ ok = $false; error = "$($_.Exception.Message)" }; $evBy = @{} }
    $sources['evidence'] = [ordered]@{ ok = [bool]$evid.ok; error = "$($evid.error)" }
    $pins = $null
    try {
        $rawP = if ($ReadPins) { & $ReadPins } else { Get-PimSqlSettingRaw -ConnectionString (& $cs) -Name 'AdminDeletePins' }
        $pins = ConvertFrom-PimAccountStatePins -Raw $(if ($null -eq $rawP) { $null } else { "$rawP" })
    } catch { $pins = @{ ok = $false; error = "$($_.Exception.Message)"; byKey = @{} } }
    $sources['pins'] = [ordered]@{ ok = [bool]$pins.ok; error = "$($pins.error)" }
    # the memberships each admin still has in PIM Manager (PIM-Assignments-Admins rows naming it): a gone account's rows
    # are taken out together with them (the commit refuses an admin row taken out while a membership still names it, PIM-FK-002)
    $memOk = $true; $memErr = ''; $memBy = @{}
    try {
        $mRows = if ($ReadMemberships) { & $ReadMemberships } else { Read-PimAccountStateMemberships -ConnectionString (& $cs) }
        foreach ($m in @($mRows)) { $mk2 = ConvertTo-PimAccountStateKey -Name "$m"; if ($mk2) { $memBy[$mk2] = [int]$memBy[$mk2] + 1 } }
    } catch { $memOk = $false; $memErr = "$($_.Exception.Message)"; $memBy = @{} }
    $sources['memberships'] = [ordered]@{ ok = $memOk; error = $memErr }

    # ---- 5. one state per account -------------------------------------------------------------------------------------
    $out = New-Object System.Collections.Generic.List[object]
    $rowKeys = @{}
    $mk = {
        param($key, $name, $upn, $un, $hasRow, $res, $staged, $stagedText, $stagedBy)
        $s = "$($res.state)"
        [ordered]@{ key = $key; name = $name; upn = $upn; userName = $un; hasRow = [bool]$hasRow
            state = $s; label = $(if ($labelOf.ContainsKey($s)) { $labelOf[$s] } else { $s }); tone = (Get-PimStateToneOf -State $s); rank = (Get-PimStateRankOf -State $s)
            reason = "$($res.reason)"; why = "$($res.why)"; inEntra = "$($res.inEntra)"; scheduledUtc = "$($res.scheduledUtc)"
            staged = $staged; stagedText = $stagedText; stagedBy = $stagedBy }
    }
    foreach ($row in @($rows)) {
        if ($null -eq $row) { continue }
        $upn = Get-PimGroupStateField -Row $row -Name 'UserPrincipalName'; $un = Get-PimGroupStateField -Row $row -Name 'UserName'
        $k = ConvertTo-PimAccountStateKey -Name $(if ($upn) { $upn } else { $un })
        if (-not $k) { continue }
        $rowKeys[$k] = $true
        $res = Resolve-PimAccountState -Row $row -Key $k -Drift $drift -Evidence $evid -Seen $(if ($evBy.ContainsKey($k)) { $evBy[$k] } else { $null }) `
                                       -Failures $fail -Fail $(if ($fail.byKey.ContainsKey($k)) { $fail.byKey[$k] } else { $null }) `
                                       -Queue $queue -Queued $(if ($queuedBy.ContainsKey($k)) { $queuedBy[$k] } else { $null }) -Pins $pins -NowUtc $now
        $staged = ''; $stagedText = ''; $stagedBy = ''
        if (-not $stagedOk) { $staged = 'unknown'; $stagedText = "What is staged for it could not be read ($stagedErr)." }
        elseif ($stagedByKey.ContainsKey($k)) {
            $ch = $stagedByKey[$k]; $stagedBy = "$($ch.by)"
            if ($ch.op -eq 'remove') { $staged = 'stop'; $stagedText = 'Staged, not committed: the row is taken out of PIM Manager.' }
            else { $staged = 'change'; $stagedText = "Staged, not committed: a change to this row$(if ((Get-PimGroupStateField -Row $ch.row -Name 'AccountStatus')) { " (AccountStatus $((Get-PimGroupStateField -Row $ch.row -Name 'AccountStatus')))" })." }
        }
        $o = & $mk $k $(if ($upn) { $upn } else { $un }) $upn $un $true $res $staged $stagedText $stagedBy
        # how many memberships still name it ($null = could not be read); said on a gone account (owner 2026-10-13)
        $o['memberships'] = $(if ($memOk) { [int]$memBy[$k] } else { $null })
        if ($o.state -eq 'deleted-gone') {
            if (-not $memOk) { $o.reason += " Whether memberships in PIM Manager still name it could not be read ($memErr)." }
            elseif ([int]$memBy[$k] -gt 0) { $o.reason += " $([int]$memBy[$k]) membership(s) in PIM Manager still name it: take the row out together with them (one step on its row)." }
        }
        $out.Add($o)
    }
    # staged and not stored yet: Waiting for commit
    if ($stagedOk) {
        foreach ($k in @($stagedByKey.Keys)) {
            if ($rowKeys.ContainsKey($k)) { continue }
            $ch = $stagedByKey[$k]
            if ($ch.op -eq 'remove' -or $null -eq $ch.row) { continue }
            $rowKeys[$k] = $true
            $res = [ordered]@{ state = 'waiting-commit'; reason = "It is staged in Pending changes$(if ("$($ch.by)".Trim()) { " by $("$($ch.by)".Trim())" }) and not committed. Nothing happens until it is committed."; why = 'staged'; inEntra = 'not-yet'; scheduledUtc = '' }
            $out.Add((& $mk $k "$($ch.name)" (Get-PimGroupStateField -Row $ch.row -Name 'UserPrincipalName') (Get-PimGroupStateField -Row $ch.row -Name 'UserName') $false $res 'add' 'Staged, not committed: a new administrator.' "$($ch.by)"))
        }
    }
    # queued and not stored yet: proposed (pending) = Waiting for commit, committed / applying = Waiting to be created
    foreach ($k in @($queuedBy.Keys)) {
        if ($rowKeys.ContainsKey($k)) { continue }
        $q = $queuedBy[$k]; $rowKeys[$k] = $true
        $nm = Get-PimGroupStateField -Row $q.payload -Name 'UserPrincipalName'; if (-not $nm) { $nm = Get-PimGroupStateField -Row $q.payload -Name 'UserName' }; if (-not $nm) { $nm = $k }
        $qs = "$($q.status)"
        $res = if ($qs -eq 'pending') { [ordered]@{ state = 'waiting-commit'; reason = 'It is in the change queue, not committed yet. Nothing happens until it is committed.'; why = 'queued'; inEntra = 'not-yet'; scheduledUtc = '' } }
               else { [ordered]@{ state = 'waiting-create'; reason = "It is committed in the change queue ($qs). The engine creates it when it runs the queue."; why = 'queued'; inEntra = 'not-yet'; scheduledUtc = '' } }
        $out.Add((& $mk $k $nm (Get-PimGroupStateField -Row $q.payload -Name 'UserPrincipalName') (Get-PimGroupStateField -Row $q.payload -Name 'UserName') $false $res '' '' ''))
    }
    # in Microsoft Entra ID with an admin naming prefix, and no row (the engine's read lists them as extra)
    if ("$($drift.status)" -eq 'fresh') {
        foreach ($k in @($drift.extra.Keys)) {
            if ($rowKeys.ContainsKey($k)) { continue }
            if (-not $stagedOk) {
                $res = [ordered]@{ state = 'unknown'; reason = "It is in Microsoft Entra ID (read $($drift.readUtc)) and no stored row names it; whether one is staged could not be read ($stagedErr)."; why = 'staged-unreadable'; inEntra = 'yes'; scheduledUtc = '' }
            } else {
                $res = [ordered]@{ state = 'not-managed'; reason = "It is in Microsoft Entra ID (read $($drift.readUtc)) with an admin naming prefix, and no row in PIM Manager names it. PIM Manager reports it and never disables or deletes it for that."; why = 'no-row'; inEntra = 'yes'; scheduledUtc = '' }
            }
            $out.Add((& $mk $k "$($drift.extra[$k])" '' '' $false $res '' '' ''))
        }
    }

    $sorted = @($out | Sort-Object { "$($_.name)".ToLowerInvariant() })
    foreach ($a in $sorted) { if ($counts.Contains($a.state)) { $counts[$a.state] = [int]$counts[$a.state] + 1 } }
    $base.ok = $true
    $base.accounts = $sorted
    $base.total = $sorted.Count
    return $base
}
