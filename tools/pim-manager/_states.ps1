<#
  _states.ps1 -- PIM 100.118 (owner 2026-10-13, customer meeting: "when we in delegation overviewe see the groups, we new
  to have a way to see if the group state is valid ... people are confused about the state and the different
  remove/delete options we have") + the leftovers of 100.117 ("the group is gone -- remove this row").

  ONE answer for the page: the state of every group PIM Manager defines (and of every group in Microsoft Entra ID that
  carries the PIM naming and has no definition), IN WORDS, computed from STORED FACTS ONLY. Nothing here reads the tenant,
  writes anything, stages anything, or changes a guard. GET /api/group-states (Admin) -> Get-PimGroupStates.

  THE FACTS, and where each one is stored:
    defined          pim.Rows, the eight group-definition record types (Get-PimManagerGroupRetirementEntities), read in
                     one query (Get-PimManagerEntityRowsBulk). Lifecycle starting with "retire" = marked for deletion.
    staged           the shared pending changes (Read-PimSharedPendingStore). Its parser turns unreadable text into "nothing
                     staged", so the raw text is parsed here once more: unreadable = NOT KNOWN, never "nothing staged".
    in Entra ID      the tenant cache kind 'pim-groups' (tools/pim-manager/_tenantSync.ps1). It is written only when the
                     read of the tenant completed, and it lists ONLY groups whose name starts with the PIM group prefix
                     (Get-PimTenantSyncGroupPrefix). So: a name without that prefix is NOT CHECKED (never "missing"); a
                     read older than Get-PimGroupStateMaxReadAgeHours is NOT CHECKED; a read that could not be loaded is
                     NOT KNOWN.
    could not be created   pim.Settings 'EngineItemFailures', scope Groups, read RAW (Get-PimEngineItemFailures answers an
                     empty list when the read fails -- that would read as "nothing failed").
    it existed       pim.ManagedKeys (scope groups: the engine matched or created the group) and pim.CommitApplied (scope
                     Groups: created / updated / already present). It counts as "existed before the read" only when it is
                     OLDER than the tenant read (less a margin): a group the engine created after the read is not in the
                     cache yet and must never be shown as missing.
    why a marked group waits   Get-PimManagerGroupRetirementState (the switch, the job, the removal guard's numbers and
                     its last recorded stop) + Get-PimGuardHolds -Fresh (throws when the store cannot be read).

  A fact that cannot be read gives the state "Not known" with the reason -- never a guess. The actions the remove / delete
  dialog may offer are decided HERE, per group (actions.stop / .keep / .delete): no delete is offered on "Not known", nor
  where there is nothing to delete.

  Every reader is a seam (-ReadRows, -ReadPending, -ReadCache, -ReadFailures, -ReadEvidence, -ReadHolds, -Retirement) so
  tests/Test-PimGroupStates.ps1 seeds the facts. Literals come from functions: a $script: variable is $null in a child
  scope behind a load guard. ASCII only.
#>

function Get-PimGroupStateMaxReadAgeHours {
    # PURE. The tenant lists are read every 12 hours (the job 'tenant-cache'); a read older than two cycles + 2 hours is
    # not used to say that a group exists or is gone.
    26
}
function Get-PimGroupStateReadMarginMinutes {
    # PURE. The cache's time is stamped when the read ENDS, and a group created minutes before a read may not be listed
    # by the directory yet. Evidence younger than (read - this margin) is "created at or after the read".
    10
}
function Get-PimGroupStateJobName { 'tenant-cache' }

function Get-PimGroupStateCatalog {
    # PURE. Every state, in display order: id, the WORDS shown, a tone for the colour, and what it means.
    @(
        [ordered]@{ id = 'managed';          label = 'Managed';              tone = 'ok';    meaning = 'Defined in PIM Manager and found in Microsoft Entra ID.' }
        [ordered]@{ id = 'waiting-commit';   label = 'Waiting for commit';   tone = 'info';  meaning = 'Staged in Pending changes, not committed. Nothing happens until it is committed.' }
        [ordered]@{ id = 'waiting-create';   label = 'Waiting to be created'; tone = 'info'; meaning = 'Committed, and not in Microsoft Entra ID yet. The engine creates it on its next run.' }
        [ordered]@{ id = 'create-failed';    label = 'Could not be created'; tone = 'bad';   meaning = 'Committed, not in Microsoft Entra ID, and the last engine run failed on it.' }
        [ordered]@{ id = 'marked-delete';    label = 'Marked for deletion';  tone = 'wait';  meaning = 'Its definition is marked Retire and the group is still in Microsoft Entra ID.' }
        [ordered]@{ id = 'deleted-row-left'; label = 'Deleted -- row left';  tone = 'wait';  meaning = 'Marked Retire and no longer in Microsoft Entra ID: only the row is left. Take the row out to finish.' }
        [ordered]@{ id = 'missing';          label = 'Missing in Entra ID';  tone = 'bad';   meaning = 'Defined, it was in Microsoft Entra ID before, and the last read did not find it: it was deleted outside PIM Manager.' }
        [ordered]@{ id = 'not-managed';      label = 'Not managed';          tone = 'muted'; meaning = 'In Microsoft Entra ID with the PIM naming, and no group definition in PIM Manager names it.' }
        [ordered]@{ id = 'not-checked';      label = 'Not checked';          tone = 'muted'; meaning = 'Whether it is in Microsoft Entra ID was not checked: no read, an old read, or a name the read does not cover.' }
        [ordered]@{ id = 'unknown';          label = 'Not known';            tone = 'warn';  meaning = 'A stored fact this state needs could not be read. The reason is given; nothing is guessed.' }
    )
}

function ConvertTo-PimGroupStateUtc {
    # PURE. A stored time (a [datetime] from SQL or from ConvertFrom-Json, or text) -> [datetime] in UTC, or $null.
    # A [datetime] without a kind is a SQL DATETIME2 written with SYSUTCDATETIME(): it IS UTC.
    param([AllowNull()][object]$Value)
    if ($null -eq $Value -or $Value -is [DBNull]) { return $null }
    if ($Value -is [datetimeoffset]) { return $Value.UtcDateTime }
    if ($Value -is [datetime]) {
        if ($Value.Kind -eq [System.DateTimeKind]::Unspecified) { return [datetime]::SpecifyKind($Value, [System.DateTimeKind]::Utc) }
        return $Value.ToUniversalTime()
    }
    $s = "$Value".Trim()
    if (-not $s) { return $null }
    $d = [datetime]::MinValue
    $styles = [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal
    if ([datetime]::TryParse($s, [System.Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$d)) { return $d }
    return $null
}
function Format-PimGroupStateUtc {
    # PURE. UTC as the page's fmtTime reads it (ISO 8601 with Z); '' for $null.
    param([AllowNull()][object]$Value)
    $d = ConvertTo-PimGroupStateUtc -Value $Value
    if ($null -eq $d) { return '' }
    return $d.ToString('yyyy-MM-ddTHH:mm:ssZ')
}
function Get-PimGroupStateField {
    # PURE. One column of a row (hashtable / ordered map / object), as trimmed text; '' when absent.
    param([AllowNull()][object]$Row, [Parameter(Mandatory)][string]$Name)
    if ($null -eq $Row) { return '' }
    if ($Row -is [System.Collections.IDictionary]) {
        foreach ($k in @($Row.Keys)) { if ("$k" -ieq $Name) { return "$($Row[$k])".Trim() } }
        return ''
    }
    $p = $Row.PSObject.Properties[$Name]
    if ($p) { return "$($p.Value)".Trim() }
    return ''
}

function ConvertFrom-PimGroupStateJson {
    # PURE. ConvertFrom-Json that THROWS on text that is not complete JSON. PowerShell 7's ConvertFrom-Json accepts a
    # truncated array ('[{"a":1}' reads as one object), which would turn a broken stored value into "read fine"; so where
    # System.Text.Json is present (PowerShell 7) the text is validated by it first. Windows PowerShell 5.1's parser is
    # strict by itself.
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Text)
    if ('System.Text.Json.JsonDocument' -as [type]) {
        $doc = [System.Text.Json.JsonDocument]::Parse($Text)   # throws on anything that is not one complete JSON value
        $doc.Dispose()
    }
    return (ConvertFrom-Json -InputObject $Text)
}

function ConvertFrom-PimGroupStateFailures {
    <#
      PURE. The RAW text of pim.Settings 'EngineItemFailures' -> @{ ok; error; groups = @{ name(lower) -> record };
      retire = @{ name(lower) -> record } } (scope Groups / scope GroupRetirement; record = code, title, message, op,
      lastSeenUtc). $null or blank = nothing is failing (ok). Text that is not the list the engine writes = ok $false:
      "nothing failed" is never concluded from a value that could not be read. The engine stores the list as JSON text
      inside the setting, so a first parse that yields text is parsed once more.
    #>
    param([AllowNull()][string]$Raw)
    $out = @{ ok = $true; error = ''; groups = @{}; retire = @{} }
    if ($null -eq $Raw -or "$Raw".Trim() -eq '' -or "$Raw".Trim() -eq 'null') { return $out }
    try {
        $v = ConvertFrom-PimGroupStateJson -Text "$Raw"
        if ($v -is [string]) {
            if ("$v".Trim() -eq '') { return $out }
            $v = ConvertFrom-PimGroupStateJson -Text "$v"
        }
        foreach ($f in @($v)) {
            if ($null -eq $f) { continue }
            if ($f -is [string] -or $f -is [ValueType]) { throw 'the stored value is not a list of failing items' }
            $sp = $f.PSObject.Properties['scope']; $kp = $f.PSObject.Properties['key']
            if (-not $sp -or -not $kp) { throw 'a stored item has no scope or no key' }
            $scope = "$($sp.Value)".Trim().ToLowerInvariant()
            if ($scope -ne 'groups' -and $scope -ne 'groupretirement') { continue }
            $key = "$($kp.Value)".Trim().ToLowerInvariant()
            if (-not $key) { continue }
            $rec = [ordered]@{
                code = (Get-PimGroupStateField -Row $f -Name 'code'); title = (Get-PimGroupStateField -Row $f -Name 'title')
                message = (Get-PimGroupStateField -Row $f -Name 'message'); op = (Get-PimGroupStateField -Row $f -Name 'op')
                lastSeenUtc = (Format-PimGroupStateUtc -Value $(if ($f.PSObject.Properties['lastSeenUtc']) { $f.lastSeenUtc } else { $null }))
            }
            if ($scope -eq 'groups') { $out.groups[$key] = $rec } else { $out.retire[$key] = $rec }
        }
    } catch {
        return @{ ok = $false; error = "$($_.Exception.Message)"; groups = @{}; retire = @{} }
    }
    return $out
}

function Read-PimGroupStateEvidenceRows {
    <#
      The stored evidence that a group existed, as rows @{ name; kind = 'ledger' | 'created' | 'updated' | 'already present'
      | 'removed'; firstUtc; lastUtc }. THROWS when the store cannot be read. A store from before these tables exist
      answers no rows (nothing was ever recorded), which is not an error. PIM-ManagedKeys.ps1 is not loaded in the Manager,
      so the two small reads are written here (read-only).
    #>
    param([Parameter(Mandatory)][string]$ConnectionString)
    $out = New-Object System.Collections.Generic.List[object]
    $led = @(Invoke-PimSqlQuery -ConnectionString $ConnectionString -Sql "IF OBJECT_ID('pim.ManagedKeys') IS NOT NULL SELECT [Key] AS GroupKey, FirstSeenUtc FROM pim.ManagedKeys WHERE LOWER(Scope) = 'groups'" -Parameters @{})
    foreach ($r in $led) {
        if ($null -eq $r -or -not "$($r.GroupKey)".Trim()) { continue }
        $out.Add([pscustomobject]@{ name = "$($r.GroupKey)"; kind = 'ledger'; firstUtc = $r.FirstSeenUtc; lastUtc = $r.FirstSeenUtc })
    }
    $app = @(Invoke-PimSqlQuery -ConnectionString $ConnectionString -Parameters @{} -Sql @"
IF OBJECT_ID('pim.CommitApplied') IS NOT NULL
SELECT LOWER(LiveKey) AS GroupKey, Result, MIN(AppliedUtc) AS FirstUtc, MAX(AppliedUtc) AS LastUtc
FROM pim.CommitApplied
WHERE LOWER(Scope) IN ('groups', 'groupretirement') AND Result IN ('created', 'updated', 'already present', 'removed')
GROUP BY LOWER(LiveKey), Result
"@)
    foreach ($r in $app) {
        if ($null -eq $r -or -not "$($r.GroupKey)".Trim()) { continue }
        $out.Add([pscustomobject]@{ name = "$($r.GroupKey)"; kind = "$($r.Result)".Trim().ToLowerInvariant(); firstUtc = $r.FirstUtc; lastUtc = $r.LastUtc })
    }
    return $out.ToArray()
}

function ConvertTo-PimGroupStateEvidence {
    # PURE. Evidence rows -> @{ name(lower) -> @{ firstUtc; lastUtc; removedUtc } }. first / last cover the POSITIVE
    # evidence only (ledger, created, updated, already present); removedUtc is the engine's last recorded delete.
    param([AllowNull()][object[]]$Rows)
    $h = @{}
    foreach ($r in @($Rows)) {
        if ($null -eq $r) { continue }
        $n = (Get-PimGroupStateField -Row $r -Name 'name').ToLowerInvariant()
        if (-not $n) { continue }
        $kind = (Get-PimGroupStateField -Row $r -Name 'kind').ToLowerInvariant()
        $fRaw = if ($r -is [System.Collections.IDictionary]) { $r['firstUtc'] } else { $r.firstUtc }
        $lRaw = if ($r -is [System.Collections.IDictionary]) { $r['lastUtc'] } else { $r.lastUtc }
        $f = ConvertTo-PimGroupStateUtc -Value $fRaw
        $l = ConvertTo-PimGroupStateUtc -Value $lRaw
        if ($null -eq $l) { $l = $f }
        if ($null -eq $f) { $f = $l }
        if ($null -eq $f) { continue }   # evidence without a time proves nothing about "before the read"
        if (-not $h.ContainsKey($n)) { $h[$n] = @{ firstUtc = $null; lastUtc = $null; removedUtc = $null } }
        $e = $h[$n]
        if ($kind -eq 'removed') {
            if ($null -eq $e.removedUtc -or $l -gt $e.removedUtc) { $e.removedUtc = $l }
            continue
        }
        if ($kind -notin @('ledger', 'created', 'updated', 'already present')) { continue }
        if ($null -eq $e.firstUtc -or $f -lt $e.firstUtc) { $e.firstUtc = $f }
        if ($null -eq $e.lastUtc -or $l -gt $e.lastUtc) { $e.lastUtc = $l }
    }
    return $h
}

function Get-PimGroupStateActions {
    <#
      PURE. What the remove / delete dialog may offer for one group, by its state. Three choices, each @{ offered; why }:
        stop   = take the row out of PIM Manager (the group and its access stay in Microsoft Entra ID);
        keep   = remove the access, keep the group;
        delete = remove the access and delete the group in Microsoft Entra ID.
      -HasRow $false (no committed row: only staged, or not defined at all) offers nothing from the stored row.
      No delete on "Not known"; no delete where there is nothing to delete.
    #>
    param([Parameter(Mandatory)][string]$State, [bool]$HasRow = $true)
    $yes = { [ordered]@{ offered = $true; why = '' } }
    $no = { param($w) [ordered]@{ offered = $false; why = "$w" } }
    if (-not $HasRow) {
        $w = if ($State -eq 'not-managed') { 'It has no row in PIM Manager, so there is nothing to take out or mark here.' }
             else { 'It is only staged. Discard or commit it under Pending changes.' }
        return [ordered]@{ stop = (& $no $w); keep = (& $no $w); delete = (& $no $w) }
    }
    switch ($State) {
        'managed'          { return [ordered]@{ stop = (& $yes); keep = (& $yes); delete = (& $yes) } }
        'not-checked'      { return [ordered]@{ stop = (& $yes); keep = (& $yes); delete = (& $yes) } }
        'marked-delete'    { return [ordered]@{ stop = (& $yes); keep = (& $yes); delete = (& $no 'It is already marked for deletion.') } }
        'deleted-row-left' { $w = 'The group is no longer in Microsoft Entra ID: only the row is left.'; return [ordered]@{ stop = (& $yes); keep = (& $no $w); delete = (& $no $w) } }
        'waiting-create'   { return [ordered]@{ stop = (& $yes); keep = (& $yes); delete = (& $no 'The group is not in Microsoft Entra ID yet, so there is nothing to delete. Take the row out instead.') } }
        'create-failed'    { return [ordered]@{ stop = (& $yes); keep = (& $yes); delete = (& $no 'The group is not in Microsoft Entra ID, so there is nothing to delete. Take the row out instead.') } }
        'missing'          { return [ordered]@{ stop = (& $yes); keep = (& $yes); delete = (& $no 'The group is not in Microsoft Entra ID any more, so there is nothing to delete. Take the row out instead.') } }
        default            { return [ordered]@{ stop = (& $yes); keep = (& $yes); delete = (& $no 'The state of this group is not known, so deleting it is not offered. Nothing is deleted on a guess.') } }
    }
}

function Get-PimGroupStateDeleteWarning {
    <#
      PURE. Owner 2026-10-13 (wizard, on "may a Not checked group be marked for deletion"): "Offer it with a warning".
      For a group whose state is "Not checked" the delete stays offered, and the dialog must show THIS sentence and ask
      the person to confirm. It says what PIM Manager does not know and WHY, from the reason the state was not checked
      (-Why, as Resolve-PimGroupState answers it). '' for every other state: nothing changes for a Managed group, and
      "Not known" offers no delete at all.
    #>
    param([Parameter(Mandatory)][string]$State, [string]$Why = '', [AllowNull()][object]$Cache = $null, [string]$EvidenceUtc = '')
    if ($State -ne 'not-checked') { return '' }
    $readTxt = ''; $age = ''; $max = [int](Get-PimGroupStateMaxReadAgeHours); $pfx = ''
    if ($null -ne $Cache) {
        $readTxt = Format-PimGroupStateUtc -Value $Cache.readUtc
        if ($null -ne $Cache.ageHours) { $age = "$([int]$Cache.ageHours)" }
        if ($null -ne $Cache.maxAgeHours) { $max = [int]$Cache.maxAgeHours }
        $pfx = "$($Cache.prefix)"
    }
    switch ($Why) {
        'name-not-covered'   {
            if ($pfx) { return "PIM Manager has not seen this group: its reading of Microsoft Entra ID lists only groups whose name starts with '$pfx', and this name does not." }
            return 'PIM Manager has not seen this group: the group prefix its reading of Microsoft Entra ID uses could not be read, so no name is covered.'
        }
        'no-read'            { return 'PIM Manager has not seen this group: there is no reading of Microsoft Entra ID yet.' }
        'no-read-time'       { return 'PIM Manager has not seen this group: the stored reading of Microsoft Entra ID carries no time, so it is not used.' }
        'read-old'           { return "PIM Manager has not seen this group recently: the last reading of Microsoft Entra ID is from $readTxt$(if ($age) { " ($age hours ago)" }), and a reading older than $max hours is not used." }
        'created-after-read' { return "PIM Manager has not seen this group in a reading yet: it was created or confirmed$(if ($EvidenceUtc) { " on $EvidenceUtc" }) after the last reading of Microsoft Entra ID$(if ($readTxt) { " ($readTxt)" })." }
    }
    return 'PIM Manager has not checked whether this group is in Microsoft Entra ID.'
}

function Resolve-PimGroupState {
    <#
      PURE. The state of ONE group that has a committed definition row. Returns @{ state; reason; why; inEntra }.
        -Cache      @{ status = 'fresh' | 'old' | 'none' | 'no-time' | 'unreadable'; readUtc; ageHours; maxAgeHours; error; prefix }
        -InCache    the name is in the cache's list (only read when the cache is fresh and covers the name)
        -Evidence   @{ ok; error } and -Seen the record of this name (ConvertTo-PimGroupStateEvidence) or $null
                    (NOT "-Ev": that is the alias of the common parameter -ErrorVariable, and a function with a
                    [Parameter()] attribute refuses a parameter of that name at its first call)
        -Failures   @{ ok; error } and -Fail / -RetireFail the failing-item record of this name or $null
        -Retirement the object of Get-PimManagerGroupRetirementState (or $null = not read)
        -Holds      @{ ok; error; list } -- the guard holds for group deletion
    #>
    param([Parameter(Mandatory)][string]$Name, [bool]$Retire, [Parameter(Mandatory)][object]$Cache, [bool]$InCache,
          [Parameter(Mandatory)][object]$Evidence, [AllowNull()][object]$Seen, [Parameter(Mandatory)][object]$Failures, [AllowNull()][object]$Fail,
          [AllowNull()][object]$RetireFail, [AllowNull()][object]$Retirement, [AllowNull()][object]$Holds)
    $r = { param($s, $t, $w, $ie) [ordered]@{ state = "$s"; reason = "$t"; why = "$w"; inEntra = "$ie" } }
    $mark = if ($Retire) { ' Its definition is marked Retire.' } else { '' }
    $st = "$($Cache.status)"
    $job = Get-PimGroupStateJobName
    if ($st -eq 'unreadable') { return (& $r 'unknown' ("The stored read of Microsoft Entra ID could not be loaded ($($Cache.error)), so whether this group exists is not known." + $mark) 'cache-unreadable' 'unknown') }
    if ($st -eq 'none') { return (& $r 'not-checked' ("Microsoft Entra ID has not been read yet (the job $job reads it), so whether this group exists is not checked." + $mark) 'no-read' 'not-checked') }
    if ($st -eq 'no-time') { return (& $r 'not-checked' ("The stored read of Microsoft Entra ID carries no time, so it is not used to say whether this group exists." + $mark) 'no-read-time' 'not-checked') }
    $readTxt = Format-PimGroupStateUtc -Value $Cache.readUtc
    if ($st -eq 'old') { return (& $r 'not-checked' ("The last read of Microsoft Entra ID is from $readTxt ($([int]$Cache.ageHours) hours ago). A read older than $([int]$Cache.maxAgeHours) hours is not used, so whether this group exists is not checked (the job $job reads it)." + $mark) 'read-old' 'not-checked') }
    if ($st -ne 'fresh') { return (& $r 'unknown' ("The stored read of Microsoft Entra ID is in a state PIM Manager does not recognise ($st)." + $mark) 'cache-unreadable' 'unknown') }
    $pfx = "$($Cache.prefix)"
    if (-not $pfx -or -not $Name.StartsWith($pfx, [System.StringComparison]::OrdinalIgnoreCase)) {
        $t = if ($pfx) { "The read of Microsoft Entra ID lists only groups whose name starts with '$pfx'. This name does not, so whether it exists is not checked." }
             else { 'The group prefix the read of Microsoft Entra ID uses could not be read, so whether this group exists is not checked.' }
        return (& $r 'not-checked' ($t + $mark) 'name-not-covered' 'not-checked')
    }
    if ($InCache) {
        if (-not $Retire) {
            $t = "Defined in PIM Manager and found in Microsoft Entra ID (read $readTxt)."
            if ($Fail -and "$($Fail.title)$($Fail.message)".Trim()) { $t += " The last engine run reported a problem on it: $("$($Fail.title)".Trim()) $("$($Fail.message)".Trim())".TrimEnd() }
            return (& $r 'managed' $t '' 'yes')
        }
        # marked Retire and still there: why it waits -- only what the store says
        $t = "Its definition is marked Retire and the group is still in Microsoft Entra ID (read $readTxt). "
        $why = 'switch-unknown'
        if ($null -eq $Retirement) { $t += 'Whether group deletion is switched on could not be read.' }
        else {
            $place = "$($Retirement.place)"; $jobDel = "$($Retirement.job)"
            if ("$($Retirement.effective)" -eq 'off') { $why = 'switch-off'; $t += "Group deletion is switched off ($($Retirement.text)), so nothing is deleted. A SuperAdmin switches it on under $place." }
            elseif ("$($Retirement.effective)" -eq 'on') {
                $why = 'next-full-run'
                $t += "Group deletion is on ($($Retirement.text)). It waits for the next full engine run (the job $jobDel, daily; Run now under Jobs)."
                $gs = $Retirement.lastGuardStop
                if ($gs -and "$($gs.atUtc)".Trim()) { $t += " The removal guard stopped a group-deletion run on $(Format-PimGroupStateUtc -Value $gs.atUtc) ($([int]$gs.held) deletion(s) held back; that run deleted no group)." }
            }
            else { $t += "Whether group deletion is on is not known ($($Retirement.text)). The switch is under $place." }
            if ("$($Retirement.envNote)".Trim()) { $t += " $("$($Retirement.envNote)".Trim())" }
        }
        if ($null -eq $Holds -or -not $Holds.ok) {
            $t += " Whether a guard holds it could not be read$(if ($Holds -and "$($Holds.error)".Trim()) { " ($("$($Holds.error)".Trim()))" })."
        } elseif (@($Holds.list).Count) {
            $h = @($Holds.list)[0]
            $why = 'guard'
            $hId = Get-PimGroupStateField -Row $h -Name 'guardId'; $hN = Get-PimGroupStateField -Row $h -Name 'count'
            $hAt = if ($h -is [System.Collections.IDictionary]) { $h['firstSeenUtc'] } elseif ($h.PSObject.Properties['firstSeenUtc']) { $h.firstSeenUtc } else { $null }
            $hSince = Format-PimGroupStateUtc -Value $hAt
            $t += " A guard holds group deletion: $hId$(if ($hN) { ", $hN item(s)" })$(if ($hSince) { ", since $hSince" }). A SuperAdmin decides under Operations > Guards."
        }
        if ($RetireFail -and "$($RetireFail.title)$($RetireFail.message)".Trim()) { $t += " The last run failed on deleting it: $("$($RetireFail.title)".Trim()) $("$($RetireFail.message)".Trim())".TrimEnd() }
        return (& $r 'marked-delete' $t $why 'yes')
    }
    # not in a fresh read that covers the name
    if (-not $Evidence.ok) {
        return (& $r 'unknown' ("It is not in the last read of Microsoft Entra ID ($readTxt), and what PIM Manager recorded about it could not be read ($($Evidence.error)). So it is not known whether it was created after that read, is waiting, or is gone." + $mark) 'evidence-unreadable' 'unknown')
    }
    $readUtc = ConvertTo-PimGroupStateUtc -Value $Cache.readUtc
    $edge = $readUtc.AddMinutes(-1 * [int](Get-PimGroupStateReadMarginMinutes))
    if ($Seen -and $null -ne $Seen.lastUtc -and $Seen.lastUtc -ge $edge) {
        return (& $r 'not-checked' ("The engine created or confirmed it on $(Format-PimGroupStateUtc -Value $Seen.lastUtc), at or after the last read of Microsoft Entra ID ($readTxt). The next read shows whether it is there (the job $job)." + $mark) 'created-after-read' 'not-checked')
    }
    $had = ($Seen -and $null -ne $Seen.firstUtc)
    if ($Retire) {
        $t = "It is not in Microsoft Entra ID (read $readTxt). "
        if ($Seen -and $null -ne $Seen.removedUtc) { $t += "The engine recorded deleting it on $(Format-PimGroupStateUtc -Value $Seen.removedUtc). " }
        elseif ($had) { $t += "PIM Manager last recorded it there on $(Format-PimGroupStateUtc -Value $Seen.lastUtc). " }
        else { $t += 'PIM Manager has no record that it was ever there. ' }
        $t += 'Only the row is left, still marked Retire: take the row out to finish.'
        return (& $r 'deleted-row-left' $t 'row-left' 'no')
    }
    if (-not $Failures.ok) {
        return (& $r 'unknown' "It is not in the last read of Microsoft Entra ID ($readTxt), and whether the last engine run failed on it could not be read ($($Failures.error))." 'failures-unreadable' 'unknown')
    }
    if ($Fail) {
        $t = "It is not in Microsoft Entra ID (read $readTxt) and the last engine run failed on it$(if ("$($Fail.lastSeenUtc)".Trim()) { " ($("$($Fail.lastSeenUtc)".Trim()))" }): "
        $t += ("$("$($Fail.title)".Trim()) $("$($Fail.message)".Trim())".Trim())
        if (-not "$($Fail.title)$($Fail.message)".Trim()) { $t += 'no reason was recorded' }
        $t += '. The reason and the fix are under Jobs > Engine logs & errors.'
        if ($had) { $t += " It was in Microsoft Entra ID before (recorded $(Format-PimGroupStateUtc -Value $Seen.firstUtc))." }
        return (& $r 'create-failed' $t 'run-failed' 'no')
    }
    if ($had) {
        return (& $r 'missing' "It was in Microsoft Entra ID (PIM Manager recorded it on $(Format-PimGroupStateUtc -Value $Seen.lastUtc)) and the last read ($readTxt) did not find it: it was deleted outside PIM Manager. The engine creates it again on its next run unless its row is taken out first." 'deleted-outside' 'no')
    }
    return (& $r 'waiting-create' "It is committed and not in Microsoft Entra ID yet (read $readTxt). The engine creates it on its next run." 'next-run' 'no')
}

function Get-PimGroupStates {
    <#
      The whole answer of GET /api/group-states:
        @{ ok; error; computedUtc; tenantRead; sources; catalog; counts; total; groups; rowsLeft; deletePending }
      groups = @(@{ key; name; tag; entity; lifecycle; hasRow; state; label; tone; reason; why; inEntra; staged; stagedText;
                    stagedBy; actions }), sorted by name. ok = $false ONLY when the group definitions themselves could not be
      read (then there is no list at all, and the page shows "Not known" on what it has).
      Seams (tests): -ReadRows { param($entities) -> @{ entity = rows } }, -ReadPending { -> raw text of the shared pending
      store, or $null }, -ReadCache { -> the 'pim-groups' document or $null (never read); throws = could not be loaded },
      -ReadFailures { -> raw text of 'EngineItemFailures' }, -ReadEvidence { -> evidence rows }, -ReadHolds { -> holds },
      -Retirement (the object of Get-PimManagerGroupRetirementState), -Prefix, -NowUtc.
    #>
    param([scriptblock]$ReadRows, [scriptblock]$ReadPending, [scriptblock]$ReadCache, [scriptblock]$ReadFailures, [scriptblock]$ReadEvidence,
          [scriptblock]$ReadHolds, [AllowNull()][object]$Retirement = $null, [switch]$NoRetirementRead, [AllowNull()][string]$Prefix = $null,
          [datetime]$NowUtc = [datetime]::UtcNow)
    $now = $NowUtc.ToUniversalTime()
    $catalog = @(Get-PimGroupStateCatalog)
    $labelOf = @{}; $toneOf = @{}
    foreach ($c in $catalog) { $labelOf[$c.id] = $c.label; $toneOf[$c.id] = $c.tone }
    $counts = [ordered]@{}; foreach ($c in $catalog) { $counts[$c.id] = 0 }
    $sources = [ordered]@{}
    $base = [ordered]@{ ok = $false; error = ''; computedUtc = $now.ToString('yyyy-MM-ddTHH:mm:ssZ'); tenantRead = $null; sources = $sources; catalog = $catalog
                        counts = $counts; total = 0; groups = @(); rowsLeft = 0; deletePending = 0 }

    # ---- 1. the definitions (without them there is no list) ---------------------------------------------------------
    $ents = @(Get-PimManagerGroupRetirementEntities)
    $all = $null
    try {
        $all = if ($ReadRows) { & $ReadRows $ents } else { Get-PimManagerEntityRowsBulk -Entities $ents }
        if ($null -eq $all) { throw 'the reader answered nothing' }
    } catch {
        $sources['definitions'] = [ordered]@{ ok = $false; error = "$($_.Exception.Message)" }
        $base.error = "The group definitions could not be read ($($_.Exception.Message)), so no group state is known."
        return $base
    }
    $sources['definitions'] = [ordered]@{ ok = $true; error = '' }
    $defs = New-Object System.Collections.Generic.List[object]
    $defNames = @{}
    foreach ($e in $ents) {
        foreach ($row in @($all[$e])) {
            if ($null -eq $row) { continue }
            $gn = Get-PimGroupStateField -Row $row -Name 'GroupName'
            if (-not $gn) { continue }   # PIM-Definitions-Departments also holds owner rows without a group
            $lc = Get-PimGroupStateField -Row $row -Name 'Lifecycle'
            $defs.Add([pscustomobject]@{ entity = "$e"; name = $gn; tag = (Get-PimGroupStateField -Row $row -Name 'GroupTag'); lifecycle = $lc; retire = ($lc -match '(?i)^retire'); row = $row })
            $defNames[$gn.ToLowerInvariant()] = $true
        }
    }

    # ---- 2. what is staged (unreadable = not known, never "nothing staged") ---------------------------------------------
    $stagedOk = $true; $stagedErr = ''
    $stagedByKey = @{}        # entity|rowkey(lower) -> change
    $stagedAdds = New-Object System.Collections.Generic.List[object]
    try {
        $raw = $null
        if ($ReadPending) { $raw = & $ReadPending }
        else {
            if (-not (Get-Command Read-PimSharedPendingStore -ErrorAction SilentlyContinue)) { throw 'the reader of the pending changes is not loaded in this process' }
            $raw = (Read-PimSharedPendingStore -ConnectionString (Get-PimManagerSettingCs)).raw
        }
        if ($null -ne $raw -and "$raw".Trim() -ne '' -and "$raw".Trim() -ne 'null') {
            $doc = ConvertFrom-PimGroupStateJson -Text "$raw"
            if ($doc -is [string]) { $doc = ConvertFrom-PimGroupStateJson -Text "$doc" }
            if ($null -eq $doc -or $doc -is [ValueType] -or $doc -is [string]) { throw 'the stored pending changes are not a document' }
            $bp = $doc.PSObject.Properties['bases']
            if ($bp -and $null -ne $bp.Value) {
                foreach ($b in @($bp.Value.PSObject.Properties)) {
                    if ($ents -notcontains "$($b.Name)") { continue }
                    foreach ($ch in @($b.Value.changes)) {
                        if ($null -eq $ch) { continue }
                        $op = (Get-PimGroupStateField -Row $ch -Name 'op').ToLowerInvariant()
                        $key = (Get-PimGroupStateField -Row $ch -Name 'key').ToLowerInvariant()
                        if (-not $key -or $op -notin @('add', 'modify', 'remove')) { continue }
                        $chRow = if ($ch.PSObject.Properties['row']) { $ch.row } else { $null }
                        $rec = [pscustomobject]@{ entity = "$($b.Name)"; key = $key; op = $op; row = $chRow; by = (Get-PimGroupStateField -Row $ch -Name 'by') }
                        $stagedByKey["$($b.Name)|$key"] = $rec
                    }
                }
            }
        }
    } catch { $stagedOk = $false; $stagedErr = "$($_.Exception.Message)"; $stagedByKey = @{} }
    $sources['staged'] = [ordered]@{ ok = $stagedOk; error = $stagedErr }
    $haveKeyFn = [bool](Get-Command Get-PimSharedPendingRowKey -ErrorAction SilentlyContinue)
    $rowKeyOf = {
        param($entity, $row)
        $k = ''
        if ($haveKeyFn) { try { $k = "$(Get-PimSharedPendingRowKey -Base $entity -Row $row)" } catch { $k = '' } }
        if (-not $k) { $k = Get-PimGroupStateField -Row $row -Name 'GroupTag' }
        if (-not $k) { $k = Get-PimGroupStateField -Row $row -Name 'GroupName' }
        return "$k".Trim().ToLowerInvariant()
    }

    # ---- 3. the read of the tenant ------------------------------------------------------------------------------------
    $maxAge = [int](Get-PimGroupStateMaxReadAgeHours)
    $cache = [ordered]@{ status = 'none'; readUtc = ''; ageHours = $null; maxAgeHours = $maxAge; error = ''; prefix = ''; count = 0; job = (Get-PimGroupStateJobName) }
    $inEntra = @{}
    try {
        $docC = $null
        if ($ReadCache) { $docC = & $ReadCache }
        else {
            if (-not (Get-Command Get-PimTenantCacheEntry -ErrorAction SilentlyContinue)) { throw 'the reader of the stored tenant lists is not loaded in this process' }
            $docC = Get-PimTenantCacheEntry -Kind 'pim-groups'
            if ($null -eq $docC -and (Get-Command Get-PimTenantCacheReadError -ErrorAction SilentlyContinue)) {
                $why = "$(Get-PimTenantCacheReadError -Kind 'pim-groups')"
                if ($why.Trim()) { throw $why }
            }
        }
        if ($null -ne $docC) {
            $ip = if ($docC -is [System.Collections.IDictionary]) { $docC.Contains('items') } else { [bool]$docC.PSObject.Properties['items'] }
            if (-not $ip) { throw 'the stored read has no list of groups' }
            $items = if ($docC -is [System.Collections.IDictionary]) { $docC['items'] } else { $docC.items }
            $stamp = if ($docC -is [System.Collections.IDictionary]) { $docC['refreshedUtc'] } else { $(if ($docC.PSObject.Properties['refreshedUtc']) { $docC.refreshedUtc } else { $null }) }
            foreach ($it in @($items)) {
                if ($null -eq $it) { continue }
                $dn = (Get-PimGroupStateField -Row $it -Name 'displayName')
                if ($dn) { $inEntra[$dn.ToLowerInvariant()] = $dn }
            }
            $cache.count = $inEntra.Count
            $read = ConvertTo-PimGroupStateUtc -Value $stamp
            if ($null -eq $read) { $cache.status = 'no-time' }
            else {
                $cache.readUtc = $read.ToString('yyyy-MM-ddTHH:mm:ssZ')
                $age = ($now - $read).TotalHours
                $cache.ageHours = [int][Math]::Floor([Math]::Max(0, $age))
                $cache.status = if ($age -gt $maxAge) { 'old' } else { 'fresh' }
            }
        }
    } catch { $cache.status = 'unreadable'; $cache.error = "$($_.Exception.Message)"; $inEntra = @{} }
    $pfx = "$Prefix"
    if (-not $PSBoundParameters.ContainsKey('Prefix') -or $null -eq $Prefix) {
        $pfx = ''
        if (Get-Command Get-PimTenantSyncGroupPrefix -ErrorAction SilentlyContinue) { try { $pfx = "$(Get-PimTenantSyncGroupPrefix)" } catch { $pfx = '' } }
    }
    $cache.prefix = $pfx
    $cache['text'] = switch ("$($cache.status)") {
        'fresh'      { "Microsoft Entra ID was read on $($cache.readUtc) ($($cache.count) groups whose name starts with '$pfx')." }
        'old'        { "The last read of Microsoft Entra ID is from $($cache.readUtc) ($($cache.ageHours) hours ago) -- too old to say which groups exist (a read older than $maxAge hours is not used)." }
        'none'       { "Microsoft Entra ID has not been read yet (the job $(Get-PimGroupStateJobName) reads it)." }
        'no-time'    { 'The stored read of Microsoft Entra ID carries no time, so it is not used.' }
        default      { "The stored read of Microsoft Entra ID could not be loaded: $($cache.error)" }
    }
    $base.tenantRead = $cache

    # ---- 4. the failing items, the evidence, the holds, the switch ---------------------------------------------------
    $fail = $null
    try {
        $rawF = $null
        if ($ReadFailures) { $rawF = & $ReadFailures }
        else { $rawF = Get-PimSqlSettingRaw -ConnectionString (Get-PimManagerSettingCs) -Name 'EngineItemFailures' }
        $fail = ConvertFrom-PimGroupStateFailures -Raw $(if ($null -eq $rawF) { $null } else { "$rawF" })
    } catch { $fail = @{ ok = $false; error = "$($_.Exception.Message)"; groups = @{}; retire = @{} } }
    $sources['failures'] = [ordered]@{ ok = [bool]$fail.ok; error = "$($fail.error)" }

    $evid = @{ ok = $true; error = '' }; $evBy = @{}
    try {
        $evRows = if ($ReadEvidence) { & $ReadEvidence } else { Read-PimGroupStateEvidenceRows -ConnectionString (Get-PimManagerSettingCs) }
        $evBy = ConvertTo-PimGroupStateEvidence -Rows @($evRows)
    } catch { $evid = @{ ok = $false; error = "$($_.Exception.Message)" }; $evBy = @{} }
    $sources['evidence'] = [ordered]@{ ok = [bool]$evid.ok; error = "$($evid.error)" }

    $holds = @{ ok = $true; error = ''; list = @() }
    try {
        $hl = $null
        if ($ReadHolds) { $hl = & $ReadHolds }
        else {
            if (-not (Get-Command Get-PimGuardHolds -ErrorAction SilentlyContinue)) { throw 'the reader of the guard holds is not loaded in this process' }
            $hl = Get-PimGuardHolds -Fresh
        }
        $holds.list = @(@($hl) | Where-Object { $null -ne $_ -and "$($_.scope)".Trim() -ieq 'GroupRetirement' })
    } catch { $holds = @{ ok = $false; error = "$($_.Exception.Message)"; list = @() } }
    $sources['holds'] = [ordered]@{ ok = [bool]$holds.ok; error = "$($holds.error)" }

    $ret = $Retirement
    if ($null -eq $ret -and -not $NoRetirementRead -and (Get-Command Get-PimManagerGroupRetirementState -ErrorAction SilentlyContinue)) {
        # the rows are here already: the Retire count is taken from them, not read a second time
        $rowsAgain = { param($e) $all }.GetNewClosure()
        try { $ret = Get-PimManagerGroupRetirementState -ReadRows $rowsAgain } catch { $ret = $null }
    }
    $sources['retirement'] = [ordered]@{ ok = ($null -ne $ret); effective = $(if ($ret) { "$($ret.effective)" } else { 'unknown' }); text = $(if ($ret) { "$($ret.text)" } else { '' })
                                          place = $(if ($ret) { "$($ret.place)" } else { '' }); job = $(if ($ret) { "$($ret.job)" } else { '' }) }

    # ---- 5. one state per group ---------------------------------------------------------------------------------------
    $out = New-Object System.Collections.Generic.List[object]
    $seenStaged = @{}
    foreach ($d in $defs) {
        $lower = $d.name.ToLowerInvariant()
        $ev = if ($evBy.ContainsKey($lower)) { $evBy[$lower] } else { $null }
        $f = if ($fail.groups.ContainsKey($lower)) { $fail.groups[$lower] } else { $null }
        $rf = if ($fail.retire.ContainsKey($lower)) { $fail.retire[$lower] } else { $null }
        $res = Resolve-PimGroupState -Name $d.name -Retire ([bool]$d.retire) -Cache $cache -InCache ($inEntra.ContainsKey($lower)) -Evidence $evid -Seen $ev `
                                     -Failures $fail -Fail $f -RetireFail $rf -Retirement $ret -Holds $holds
        $staged = ''; $stagedText = ''; $stagedBy = ''
        if (-not $stagedOk) { $staged = 'unknown'; $stagedText = "What is staged for it could not be read ($stagedErr)." }
        else {
            $sk = "$($d.entity)|$(& $rowKeyOf $d.entity $d.row)"
            if ($stagedByKey.ContainsKey($sk)) {
                $ch = $stagedByKey[$sk]; $seenStaged[$sk] = $true; $stagedBy = "$($ch.by)"
                if ($ch.op -eq 'remove') { $staged = 'stop'; $stagedText = 'Staged, not committed: the row is taken out of PIM Manager (the group stays in Microsoft Entra ID).' }
                elseif ((Get-PimGroupStateField -Row $ch.row -Name 'Lifecycle') -match '(?i)^retire' -and -not $d.retire) { $staged = 'delete'; $stagedText = 'Staged, not committed: delete the group in Microsoft Entra ID.' }
                else { $staged = 'change'; $stagedText = 'Staged, not committed: a change to this row.' }
            }
        }
        $out.Add([ordered]@{
            key = "$($d.entity)|$lower"; name = $d.name; tag = $d.tag; entity = $d.entity; lifecycle = $d.lifecycle; hasRow = $true
            state = $res.state; label = $labelOf[$res.state]; tone = $toneOf[$res.state]; reason = $res.reason; why = $res.why; inEntra = $res.inEntra
            staged = $staged; stagedText = $stagedText; stagedBy = $stagedBy
            actions = (Get-PimGroupStateActions -State $res.state -HasRow $true)
            # "Offer it with a warning" (owner 2026-10-13): the delete of a Not checked group is offered, and must be confirmed
            deleteNeedsConfirm = ($res.state -eq 'not-checked')
            deleteWarning = (Get-PimGroupStateDeleteWarning -State $res.state -Why $res.why -Cache $cache -EvidenceUtc $(if ($ev -and $null -ne $ev.lastUtc) { Format-PimGroupStateUtc -Value $ev.lastUtc } else { '' }))
        })
    }
    # staged and not stored yet: Waiting for commit
    $stagedNames = @{}
    if ($stagedOk) {
        foreach ($sk in @($stagedByKey.Keys)) {
            if ($seenStaged.ContainsKey($sk)) { continue }
            $ch = $stagedByKey[$sk]
            if ($ch.op -eq 'remove' -or $null -eq $ch.row) { continue }
            $gn = Get-PimGroupStateField -Row $ch.row -Name 'GroupName'
            if (-not $gn) { continue }
            $lower = $gn.ToLowerInvariant()
            $stagedNames[$lower] = $true
            if ($defNames.ContainsKey($lower)) { continue }   # a stored row of that name is listed already (a staged re-key of it)
            $t = "It is staged in Pending changes$(if ("$($ch.by)".Trim()) { " by $("$($ch.by)".Trim())" }) and not committed. Nothing happens until it is committed."
            if ("$($cache.status)" -eq 'fresh' -and $inEntra.ContainsKey($lower)) { $t += ' A group with this name is already in Microsoft Entra ID.' }
            $out.Add([ordered]@{
                key = "$($ch.entity)|$lower"; name = $gn; tag = (Get-PimGroupStateField -Row $ch.row -Name 'GroupTag'); entity = "$($ch.entity)"; lifecycle = (Get-PimGroupStateField -Row $ch.row -Name 'Lifecycle'); hasRow = $false
                state = 'waiting-commit'; label = $labelOf['waiting-commit']; tone = $toneOf['waiting-commit']; reason = $t; why = 'staged'
                inEntra = $(if ("$($cache.status)" -ne 'fresh') { 'not-checked' } elseif ($inEntra.ContainsKey($lower)) { 'yes' } else { 'no' })
                staged = 'add'; stagedText = 'Staged, not committed: a new group.'; stagedBy = "$($ch.by)"
                actions = (Get-PimGroupStateActions -State 'waiting-commit' -HasRow $false)
            })
        }
    }
    # in Microsoft Entra ID with the PIM naming, and no definition
    if ("$($cache.status)" -eq 'fresh') {
        foreach ($lower in @($inEntra.Keys)) {
            if ($defNames.ContainsKey($lower)) { continue }
            if ($stagedOk -and $stagedNames.ContainsKey($lower)) { continue }
            $s = 'not-managed'
            $t = "It is in Microsoft Entra ID (read $($cache.readUtc)) with the PIM naming, and no group definition in PIM Manager names it."
            $w = 'no-definition'
            if (-not $stagedOk) { $s = 'unknown'; $w = 'staged-unreadable'; $t = "It is in Microsoft Entra ID (read $($cache.readUtc)) and no stored group definition names it; whether one is staged could not be read ($stagedErr)." }
            $out.Add([ordered]@{
                key = "|$lower"; name = "$($inEntra[$lower])"; tag = ''; entity = ''; lifecycle = ''; hasRow = $false
                state = $s; label = $labelOf[$s]; tone = $toneOf[$s]; reason = $t; why = $w; inEntra = 'yes'
                staged = ''; stagedText = ''; stagedBy = ''
                actions = (Get-PimGroupStateActions -State $s -HasRow $false)
            })
        }
    }

    # ---- 6. the removal guard's limit, counted over the groups that are REALLY left to delete --------------------------
    $pendingDelete = @($out | Where-Object { $_.state -eq 'marked-delete' })
    $budget = $null
    if ($ret -and $ret.limits -and $null -ne $ret.limits.budget) { $budget = [int]$ret.limits.budget }
    if ($ret -and "$($ret.effective)" -eq 'on' -and $null -ne $budget -and $pendingDelete.Count -gt $budget) {
        foreach ($g in $pendingDelete) {
            if ($g.why -eq 'next-full-run') { $g.why = 'guard-limit' }
            $g.reason = "$($g.reason) $($pendingDelete.Count) groups marked for deletion are still in Microsoft Entra ID and the removal guard lets one run delete at most $budget. While more than that are left, a run deletes none of them."
        }
    }

    $sorted = @($out | Sort-Object { "$($_.name)".ToLowerInvariant() }, { "$($_.entity)" })
    foreach ($g in $sorted) { $counts[$g.state] = [int]$counts[$g.state] + 1 }
    $base.ok = $true
    $base.groups = $sorted
    $base.total = $sorted.Count
    $base.rowsLeft = [int]$counts['deleted-row-left']
    $base.deletePending = $pendingDelete.Count
    return $base
}
