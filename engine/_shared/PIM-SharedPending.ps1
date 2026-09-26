<#
  PIM-SharedPending.ps1 -- §79.13 SHARED PENDING CHANGES (operator 2026-09-25).

  Operator: "pending commitment must exist in sql and not in the browser. it must be possible that another person can
  approve a commitment (2nd approver) ... pending commitment must be shared across all (stored in sql - not browser).
  Otherwise 2 people can make same changes - it must be locked to control that".

  Until 2.4.427 a staged (uncommitted) change lived only in ONE browser (pendingChanges + a localStorage draft). Nobody
  else saw it, two administrators could stage conflicting edits to the same row, and nobody could commit or approve what
  a colleague had staged. This file is the PURE core of the replacement; the Manager owns the endpoints and the storage.

  THE MODEL
    One document in pim.Settings['PendingChanges'], written only by compare-and-swap (Set-PimSqlSettingIfUnchanged):
      { version; bases: { <entity>: { version; changes: [ change ] } } }
      change = { key; op = add|modify|remove; row; before; by; atUtc }
    * key    -- the entity's natural row key, as the page derives it (pendingRowKey). ONE change per key: that is the lock.
    * row    -- the row as it will be stored (add / modify). before -- the stored row it replaces (modify / remove).
    * by     -- the Manager identity that staged it. atUtc -- when it was first staged.

  THE LOCK
    A page submits its WHOLE change set for an entity, against the entity version it last saw (a stale version is
    refused, so a page can never "remove" a change it has not seen yet). Merge-PimSharedPendingChanges then decides,
    key by key:
      * a key nobody holds                         -> the submitter now holds it;
      * a key the submitter holds                  -> replaced (content changed) or kept (unchanged);
      * a key ANOTHER person holds, same content   -> kept, still theirs (the page is only echoing it back);
      * a key ANOTHER person holds, other content,
        or left out of the submission (= unstaged)  -> LOCKED: refused, nothing written.
    So two people can never change the same row at the same time, and nobody can silently undo a colleague's staged work.

  CLEAN-UP
    A change leaves the document when the stored rows already say what it says (Test-PimSharedPendingSatisfied): an
    add/modify whose row is stored, a remove whose row is gone. Run after every commit and on every read -- so a
    commit by anyone, through any path, clears exactly the changes it carried out, and nothing it did not.

  All functions here are PURE (no SQL, no clock unless passed) and run on pwsh 7 and Windows PowerShell 5.1.
#>

Set-StrictMode -Off

$script:PimSharedPendingSettingName = 'PendingChanges'
$script:PimSharedPendingOps = @('add', 'modify', 'remove')

function Get-PimSharedPendingSettingName { $script:PimSharedPendingSettingName }

function ConvertTo-PimSharedPendingRowMap {
    # A row (hashtable / ordered / PSCustomObject / $null) as an ordered string map. Values are compared as trimmed
    # strings, the same way the page's pendingRowSig compares them, so a number and its text never differ.
    param([AllowNull()][object]$Row)
    $m = [ordered]@{}
    if ($null -eq $Row) { return $m }
    if ($Row -is [System.Collections.IDictionary]) { foreach ($k in $Row.Keys) { $m["$k"] = (ConvertTo-PimSharedPendingText $Row[$k]) } }
    else { foreach ($p in $Row.PSObject.Properties) { $m[$p.Name] = (ConvertTo-PimSharedPendingText $p.Value) } }
    return $m
}

function ConvertTo-PimSharedPendingText {
    # A cell value as text. R25-15: a [datetime] (pwsh 7's ConvertFrom-Json makes one of an ISO string) is written back as
    # round-trip ISO ('o'), never as culture text ("09/25/2026 10:00:00", no time zone) -- which made an unchanged change
    # compare as 'changed', never match its stored row, and read as local time in the browser.
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return '' }
    if ($Value -is [datetime]) { return $Value.ToString('o', [Globalization.CultureInfo]::InvariantCulture) }
    if ($Value -is [datetimeoffset]) { return $Value.ToString('o', [Globalization.CultureInfo]::InvariantCulture) }
    return "$Value"
}

function ConvertFrom-PimSharedPendingJson {
    # R25-15: parse the stored document WITHOUT date conversion. pwsh 7.4 (the container) has no -DateKind, and its
    # ConvertFrom-Json turns every ISO string -- atUtc, a date in a staged row -- into a [datetime]. System.Text.Json keeps
    # strings as strings. Windows PowerShell 5.1's ConvertFrom-Json does not convert ISO strings, so it is used there.
    param([string]$Json)
    if ($PSVersionTable.PSVersion.Major -lt 6) { return ($Json | ConvertFrom-Json) }
    $d = [System.Text.Json.JsonDocument]::Parse($Json)
    try { return (ConvertFrom-PimSharedPendingJsonElement $d.RootElement) } finally { $d.Dispose() }
}

function ConvertFrom-PimSharedPendingJsonElement {
    param($E)
    switch ("$($E.ValueKind)") {
        'Object' { $o = [ordered]@{}; foreach ($p in $E.EnumerateObject()) { $o[$p.Name] = (ConvertFrom-PimSharedPendingJsonElement $p.Value) }; return [pscustomobject]$o }
        'Array'  { $a = New-Object System.Collections.Generic.List[object]; foreach ($x in $E.EnumerateArray()) { $a.Add((ConvertFrom-PimSharedPendingJsonElement $x)) }; return ,($a.ToArray()) }
        'String' { return $E.GetString() }
        'Number' { $l = 0L; if ($E.TryGetInt64([ref]$l)) { return $l }; return $E.GetDouble() }
        'True'   { return $true }
        'False'  { return $false }
        default  { return $null }
    }
}

function Test-PimSharedPendingRowMatch {
    # True when $Stored carries every NON-EMPTY value $Wanted names (a stored row may carry extra columns the page never
    # sent, e.g. a stamp). Column names compare case-insensitively; values exactly (after trim).
    # 🔴 R25-09: -Exact names the columns the change CHANGES; those must match even when the wanted value is EMPTY (a
    # change that clears a cell is not "already done" while the stored cell still holds a value). A missing stored column
    # reads as empty.
    param([AllowNull()][object]$Wanted, [AllowNull()][object]$Stored, [string[]]$Exact = @())
    if ($null -eq $Wanted -or $null -eq $Stored) { return $false }
    $w = ConvertTo-PimSharedPendingRowMap $Wanted
    $s = @{}; foreach ($kv in (ConvertTo-PimSharedPendingRowMap $Stored).GetEnumerator()) { $s["$($kv.Key)".ToLowerInvariant()] = "$($kv.Value)".Trim() }
    $ex = @{}; foreach ($c in @($Exact)) { if ("$c".Trim()) { $ex["$c".ToLowerInvariant()] = $true } }
    $any = $false
    foreach ($kv in $w.GetEnumerator()) {
        $v = "$($kv.Value)".Trim()
        $lk = "$($kv.Key)".ToLowerInvariant()
        if (-not $v -and -not $ex.ContainsKey($lk)) { continue }
        $any = $true
        $sv = $s[$lk]
        if ("$sv" -cne $v) { return $false }
    }
    return $any
}

function Get-PimSharedPendingRowKey {
    # The page's natural row key (pim-manager.html pendingRowKey), lower-case; '' when none. Mirrored here so a staged
    # change can be matched to THE stored row it is about, never to "any row that happens to carry its values".
    param([string]$Base, [AllowNull()][object]$Row)
    if ($null -eq $Row) { return '' }
    $m = ConvertTo-PimSharedPendingRowMap $Row
    $li = @{}; foreach ($kv in $m.GetEnumerator()) { $li["$($kv.Key)".ToLowerInvariant()] = "$($kv.Value)".Trim() }
    $g = { param($n) $v = $li["$n".ToLowerInvariant()]; if ($null -eq $v) { '' } else { "$v" } }
    $first = { param([string[]]$ns) foreach ($n in $ns) { $v = & $g $n; if ($v) { return $v } }; return '' }
    $k = switch -Regex ("$Base") {
        '^PIM-Definitions-AU$'                 { & $g 'AdministrativeUnitTag'; break }
        '^PIM-Definitions-Departments$'        { & $first @('Department', 'DepartmentName', 'GroupTag', 'GroupName'); break }
        '^PIM-Definitions-'                    { & $g 'GroupTag'; break }
        '^Account-Definitions-Admins(-Central)?$' { & $g 'UserName'; break }
        '^PIM-Offboarding$'                    { & $first @('Username', 'UserName', 'UserPrincipalName', 'Upn'); break }
        '^PIM-Discovery$'                      { & $first @('DiscoveryTag', 'Tag', 'GroupTag'); break }
        '^PIM-Assignments-Admins$'             { (& $g 'Username') + '|' + (& $g 'GroupTag'); break }
        '^PIM-Assignments-Groups$'             { (& $g 'TargetGroupTag') + '|' + (& $g 'SourceGroupTag'); break }
        '^PIM-Assignments-Roles-Groups$'       { (& $g 'GroupTag') + '|' + (& $g 'RoleDefinitionName'); break }
        '^PIM-Assignments-Roles-AUs$'          { (& $g 'GroupTag') + '|' + (& $g 'AdministrativeUnitTag') + '|' + (& $g 'RoleDefinitionName'); break }
        '^PIM-Assignments-Azure-Resources$'    { (& $g 'GroupTag') + '|' + (& $g 'AzScope') + '|' + (& $g 'AzScopePermission'); break }
        default                                { & $first @('GroupTag', 'GroupName') }
    }
    $k = "$k".Trim()
    if (-not $k -or $k -match '^\|+$') { return '' }
    return $k.ToLowerInvariant()
}

function Get-PimSharedPendingChangedColumns {
    # The columns a change CHANGES: every column of an add; for a modify, every column whose value differs from before
    # (either side); none for a remove.
    param([AllowNull()][object]$Change)
    if ($null -eq $Change) { return @() }
    $op = "$(Get-PimSharedPendingField $Change 'op')".ToLowerInvariant()
    if ($op -eq 'remove') { return @() }
    $r = ConvertTo-PimSharedPendingRowMap (Get-PimSharedPendingField $Change 'row')
    if ($op -eq 'add') { return @($r.Keys | ForEach-Object { "$_" }) }
    $b = ConvertTo-PimSharedPendingRowMap (Get-PimSharedPendingField $Change 'before')
    $bl = @{}; foreach ($kv in $b.GetEnumerator()) { $bl["$($kv.Key)".ToLowerInvariant()] = "$($kv.Value)".Trim() }
    $rl = @{}; foreach ($kv in $r.GetEnumerator()) { $rl["$($kv.Key)".ToLowerInvariant()] = "$($kv.Value)".Trim() }
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($kv in $r.GetEnumerator()) { if ("$($kv.Value)".Trim() -cne "$($bl["$($kv.Key)".ToLowerInvariant()])") { $out.Add("$($kv.Key)") } }
    foreach ($kv in $b.GetEnumerator()) { if (-not $rl.ContainsKey("$($kv.Key)".ToLowerInvariant()) -and "$($kv.Value)".Trim()) { $out.Add("$($kv.Key)") } }
    return @($out.ToArray())
}

function Get-PimSharedPendingChangeSig {
    # The CONTENT of a change (op + row + before), so "the same change echoed back" can be told from "a different change
    # to the same row". Owner and time are deliberately not part of it.
    param([AllowNull()][object]$Change)
    if ($null -eq $Change) { return '' }
    $norm = {
        param($r)
        $m = ConvertTo-PimSharedPendingRowMap $r
        $keys = @($m.Keys | Sort-Object)
        ($keys | ForEach-Object { "$_=$("$($m[$_])".Trim())" }) -join [string][char]31   # not "`u{1F}": that escape is pwsh 7 only
    }
    return ("{0}|{1}|{2}" -f "$($Change.op)".ToLowerInvariant(), (& $norm $Change.row), (& $norm $Change.before))
}

function Get-PimSharedPendingField {
    param([AllowNull()][object]$Item, [string]$Name)
    if ($null -eq $Item) { return $null }
    if ($Item -is [System.Collections.IDictionary]) { if ($Item.Contains($Name)) { return $Item[$Name] } else { return $null } }
    $p = $Item.PSObject.Properties[$Name]; if ($p) { return $p.Value } else { return $null }
}

function ConvertTo-PimSharedPendingChange {
    # Normalise one submitted change; $null when it is not a usable change (no key, unknown op, add/modify without a row).
    param([AllowNull()][object]$Change)
    if ($null -eq $Change) { return $null }
    $key = "$(Get-PimSharedPendingField $Change 'key')".Trim().ToLowerInvariant()
    $op  = "$(Get-PimSharedPendingField $Change 'op')".Trim().ToLowerInvariant()
    if (-not $key -or $script:PimSharedPendingOps -notcontains $op) { return $null }
    $row = Get-PimSharedPendingField $Change 'row'; $before = Get-PimSharedPendingField $Change 'before'
    if ($op -ne 'remove' -and $null -eq $row) { return $null }
    if ($op -eq 'remove' -and $null -eq $before) { return $null }
    [ordered]@{
        key    = $key; op = $op
        row    = $(if ($op -eq 'remove') { $null } else { ConvertTo-PimSharedPendingRowMap $row })
        before = $(if ($null -eq $before) { $null } else { ConvertTo-PimSharedPendingRowMap $before })
        by     = "$(Get-PimSharedPendingField $Change 'by')"
        atUtc  = (ConvertTo-PimSharedPendingText (Get-PimSharedPendingField $Change 'atUtc'))
    }
}

function Merge-PimSharedPendingChanges {
    <#
      The lock (see the header). -Current: the entity's stored change list. -Submitted: the submitter's WHOLE change set
      for the entity. Returns { ok; changes[]; locked[]; added; replaced; dropped }. ok=$false => write NOTHING.
      locked[] = { key; by; atUtc; reason = 'changed' | 'unstaged' }.
    #>
    [CmdletBinding()]
    param(
        [AllowNull()][AllowEmptyCollection()][object[]]$Current = @(),
        [AllowNull()][AllowEmptyCollection()][object[]]$Submitted = @(),
        [Parameter(Mandatory)][string]$By,
        [datetime]$NowUtc = [datetime]::UtcNow
    )
    $me = "$By".Trim().ToLowerInvariant()
    $now = $NowUtc.ToUniversalTime().ToString('o')
    $cur = [ordered]@{}
    foreach ($c in @($Current)) { $n = ConvertTo-PimSharedPendingChange $c; if ($n) { $cur[$n.key] = $n } }
    $sub = [ordered]@{}
    foreach ($s in @($Submitted)) { $n = ConvertTo-PimSharedPendingChange $s; if ($n) { $sub[$n.key] = $n } }

    $out = New-Object System.Collections.Generic.List[object]
    $locked = New-Object System.Collections.Generic.List[object]
    $added = 0; $replaced = 0; $dropped = 0
    foreach ($k in @($sub.Keys)) {
        $s = $sub[$k]
        if ($cur.Contains($k)) {
            $c = $cur[$k]
            $mine = ("$($c.by)".Trim().ToLowerInvariant() -eq $me)
            $same = ((Get-PimSharedPendingChangeSig $c) -ceq (Get-PimSharedPendingChangeSig $s))
            if ($same) { $out.Add($c); continue }
            if (-not $mine) { $locked.Add([ordered]@{ key = $k; by = "$($c.by)"; atUtc = "$($c.atUtc)"; reason = 'changed' }); continue }
            $s.by = $By; $s.atUtc = $now; $out.Add($s); $replaced++
        } else {
            $s.by = $By; $s.atUtc = $now; $out.Add($s); $added++
        }
    }
    foreach ($k in @($cur.Keys)) {
        if ($sub.Contains($k)) { continue }
        $c = $cur[$k]
        if ("$($c.by)".Trim().ToLowerInvariant() -eq $me) { $dropped++; continue }
        $locked.Add([ordered]@{ key = $k; by = "$($c.by)"; atUtc = "$($c.atUtc)"; reason = 'unstaged' })
    }
    [pscustomobject]@{
        ok = ($locked.Count -eq 0); changes = @($out.ToArray()); locked = @($locked.ToArray())
        added = $added; replaced = $replaced; dropped = $dropped
    }
}

function Test-PimSharedPendingSatisfied {
    # True when the stored rows already carry out $Change: add/modify -> a stored row matches its row; remove -> no stored
    # row matches what it removes.
    # 🔴 R25-08 / R25-09: with -Base, a change is matched to the stored row with ITS KEY (the page's pendingRowKey): a
    # remove is carried out only when no stored row has that key any more (not when the row merely changed), and an
    # add / modify only when that row carries every column the change changes -- emptied cells included.
    # Without -Base, or when the change's key is not the one its own row gives (an unknown entity), the content match
    # is used, still with the emptied-cell rule.
    param([AllowNull()][object]$Change, [AllowNull()][AllowEmptyCollection()][object[]]$StoredRows = @(), [string]$Base = '')
    $c = ConvertTo-PimSharedPendingChange $Change
    if (-not $c) { return $true }   # an unusable entry is dropped, never kept forever
    $exact = @(Get-PimSharedPendingChangedColumns $c)
    $own = if ($c.op -eq 'remove') { $c.before } else { $c.row }
    $byKey = ("$Base".Trim() -and (Get-PimSharedPendingRowKey -Base $Base -Row $own) -eq $c.key)
    $cands = if ($byKey) { @(@($StoredRows) | Where-Object { $null -ne $_ -and (Get-PimSharedPendingRowKey -Base $Base -Row $_) -eq $c.key }) } else { @($StoredRows) }
    if ($c.op -eq 'remove') {
        if ($byKey) { return (@($cands).Count -eq 0) }
        foreach ($r in $cands) { if (Test-PimSharedPendingRowMatch -Wanted $c.before -Stored $r) { return $false } }
        return $true
    }
    foreach ($r in $cands) { if (Test-PimSharedPendingRowMatch -Wanted $c.row -Stored $r -Exact $exact) { return $true } }
    return $false
}

function Get-PimSharedPendingCommitClassification {
    <#
      PURE. R25-06 / R25-07 / R25-08 -- what a commit does to the shared pending changes of -Base, entry by entry of its
      diff (Compare-PimRowSets: adds, modifies { before; after; diffCols }, removes). Each entry is keyed (pendingRowKey)
      and is either:
        * CARRIED  -- a staged change with that key exists, is the same op, the rows after the commit carry it out
                      (Test-PimSharedPendingSatisfied -Base), and the entry changes no column the change does not;
        * DIRECT   -- anything else: the committer's own edit (returned change-shaped: key; op; row; before; by = committer).
      A DIRECT entry on a key ANOTHER person holds is LOCKED (R25-06): the commit must be refused -- it would overwrite or
      undo a colleague's staged change. Returns { ok; carried[]; direct[]; locked[] { key; by; reason } }.
    #>
    param(
        [Parameter(Mandatory)][string]$Base,
        [AllowNull()][AllowEmptyCollection()][object[]]$Changes = @(),
        [AllowNull()][object]$Diff,
        [AllowNull()][AllowEmptyCollection()][object[]]$AfterRows = @(),
        [Parameter(Mandatory)][string]$Committer
    )
    $me = "$Committer".Trim().ToLowerInvariant()
    $byKey = @{}
    foreach ($c in @($Changes)) { $n = ConvertTo-PimSharedPendingChange $c; if ($n) { $byKey[$n.key] = $n } }
    $carried = New-Object System.Collections.Generic.List[object]; $direct = New-Object System.Collections.Generic.List[object]; $locked = New-Object System.Collections.Generic.List[object]
    $entries = New-Object System.Collections.Generic.List[object]
    foreach ($a in @($Diff.adds))    { if ($null -ne $a) { $entries.Add([ordered]@{ op = 'add'; row = $a; before = $null; cols = @((ConvertTo-PimSharedPendingRowMap $a).Keys | ForEach-Object { "$_" }) }) } }
    foreach ($m in @($Diff.modifies)) {
        if ($null -eq $m) { continue }
        $g = { param($n) if ($m -is [System.Collections.IDictionary]) { $m[$n] } else { $m.$n } }
        $entries.Add([ordered]@{ op = 'modify'; row = (& $g 'after'); before = (& $g 'before'); cols = @(@(& $g 'diffCols') | Where-Object { "$_".Trim() } | ForEach-Object { "$_" }) })
    }
    foreach ($r in @($Diff.removes)) { if ($null -ne $r) { $entries.Add([ordered]@{ op = 'remove'; row = $null; before = $r; cols = @() }) } }
    foreach ($e in $entries) {
        $keys = @(@((Get-PimSharedPendingRowKey -Base $Base -Row $e.row), (Get-PimSharedPendingRowKey -Base $Base -Row $e.before)) | Where-Object { $_ } | Select-Object -Unique)
        $ch = $null; foreach ($k in $keys) { if ($byKey.ContainsKey($k)) { $ch = $byKey[$k]; break } }
        $isCarried = $false
        if ($ch -and $ch.op -eq $e.op -and (Test-PimSharedPendingSatisfied -Change $ch -StoredRows $AfterRows -Base $Base)) {
            $mine = @(Get-PimSharedPendingChangedColumns $ch | ForEach-Object { "$_".ToLowerInvariant() })
            $extra = @($e.cols | Where-Object { $mine -notcontains "$_".ToLowerInvariant() })
            $isCarried = ($e.op -eq 'remove' -or $extra.Count -eq 0)
        }
        if ($isCarried) { $carried.Add($ch); continue }
        $k0 = if ($keys.Count) { $keys[0] } else { '' }
        $direct.Add([ordered]@{ key = $k0; op = $e.op; row = $e.row; before = $e.before; by = $Committer; atUtc = '' })
        foreach ($k in $keys) {
            if ($byKey.ContainsKey($k) -and "$($byKey[$k].by)".Trim().ToLowerInvariant() -ne $me) {
                $locked.Add([ordered]@{ key = $k; by = "$($byKey[$k].by)"; atUtc = "$($byKey[$k].atUtc)"; reason = 'held' }); break
            }
        }
    }
    [pscustomobject]@{ ok = ($locked.Count -eq 0); carried = @($carried.ToArray()); direct = @($direct.ToArray()); locked = @($locked.ToArray()) }
}

function Select-PimSharedPendingOutstanding {
    # The changes the stored rows do NOT yet carry out. Returns { changes[]; cleared }.
    param([AllowNull()][AllowEmptyCollection()][object[]]$Changes = @(), [AllowNull()][AllowEmptyCollection()][object[]]$StoredRows = @(), [string]$Base = '')
    $keep = New-Object System.Collections.Generic.List[object]; $cleared = 0
    foreach ($c in @($Changes)) {
        if ($null -eq $c) { continue }
        if (Test-PimSharedPendingSatisfied -Change $c -StoredRows $StoredRows -Base $Base) { $cleared++ } else { $keep.Add($c) }
    }
    [pscustomobject]@{ changes = @($keep.ToArray()); cleared = $cleared }
}

function Get-PimSharedPendingCommitStagers {
    <#
      SECOND APPROVER input: which staged changes a commit would carry out, and who staged each. -Changes: the entity's
      shared changes; -BeforeRows / -AfterRows: the stored rows now and as the commit would leave them. A change the
      commit carries out = not satisfied before, satisfied after. Returns @{ carried = [ change ]; stagers = [ by ] }.
    #>
    param(
        [AllowNull()][AllowEmptyCollection()][object[]]$Changes = @(),
        [AllowNull()][AllowEmptyCollection()][object[]]$BeforeRows = @(),
        [AllowNull()][AllowEmptyCollection()][object[]]$AfterRows = @(),
        [string]$Base = ''
    )
    $carried = New-Object System.Collections.Generic.List[object]
    foreach ($c in @($Changes)) {
        if ($null -eq $c) { continue }
        if ((-not (Test-PimSharedPendingSatisfied -Change $c -StoredRows $BeforeRows -Base $Base)) -and (Test-PimSharedPendingSatisfied -Change $c -StoredRows $AfterRows -Base $Base)) { $carried.Add($c) }
    }
    [pscustomobject]@{
        carried = @($carried.ToArray())
        stagers = @($carried | ForEach-Object { "$(Get-PimSharedPendingField $_ 'by')" } | Where-Object { $_ } | Sort-Object -Unique)
    }
}

function Test-PimSharedPendingSecondApprover {
    <#
      The SECOND-APPROVER rule (setting 'PendingSecondApprover': off | sensitive | all; default off).
      A commit is refused when it carries out a staged change the COMMITTER staged themselves and the mode covers it
      (all = every change; sensitive = a change Get-PimAuthoringSensitivity classes as sensitive, passed in as
      -IsSensitive). -Uncarried: the commit's own row changes that no staged change accounts for (a direct edit) --
      those were made by the committer, so they count as the committer's own.
      Returns { allowed; reason; own[] }.
    #>
    param(
        [ValidateSet('off', 'sensitive', 'all')][string]$Mode = 'off',
        [Parameter(Mandatory)][string]$Committer,
        [AllowNull()][AllowEmptyCollection()][object[]]$Carried = @(),
        [int]$Uncarried = 0,
        [scriptblock]$IsSensitive = { param($c) $false },
        # 🔴 R25-07: the commit's DIRECT edits (Get-PimSharedPendingCommitClassification .direct) -- made by the committer,
        # so they are the committer's own: under 'sensitive' each goes through -IsSensitive like a staged change does.
        # (Before, 'sensitive' never looked at them: 7 direct edits with nothing staged were allowed.)
        [AllowNull()][AllowEmptyCollection()][object[]]$Direct = @()
    )
    if ($Mode -eq 'off') { return [pscustomobject]@{ allowed = $true; reason = 'second approver not required (off)'; own = @() } }
    $me = "$Committer".Trim().ToLowerInvariant()
    $own = @(@($Carried) | Where-Object { $_ -and "$(Get-PimSharedPendingField $_ 'by')".Trim().ToLowerInvariant() -eq $me })
    $own = @($own) + @(@($Direct) | Where-Object { $null -ne $_ })
    if ($Mode -eq 'sensitive') { $own = @($own | Where-Object { & $IsSensitive $_ }) }
    $direct = ($Mode -eq 'all' -and $Uncarried -gt 0)
    if (-not $own.Count -and -not $direct) { return [pscustomobject]@{ allowed = $true; reason = 'every change was staged by someone else'; own = @() } }
    $n = $own.Count + $(if ($direct) { $Uncarried } else { 0 })
    [pscustomobject]@{
        allowed = $false
        reason  = ("A second administrator must commit this: {0} change(s) in it were staged by you ({1}), and this environment requires a different person to commit {2} changes (Settings: second approver = {3})." -f $n, $Committer, $(if ($Mode -eq 'all') { 'all' } else { 'sensitive' }), $Mode)
        own     = @($own | ForEach-Object { "$(Get-PimSharedPendingField $_ 'key')" })
    }
}

# ---- the STORE (SQL; not pure) ---------------------------------------------------------------------------------------
function ConvertTo-PimSharedPendingDoc {
    # Parse the stored JSON into { version; bases = @{ <base> = @{ version; changes = @(...) } } }. Anything unreadable
    # is an EMPTY document -- never an exception, because a broken pending store must not take the Manager down.
    param([AllowNull()][string]$Json)
    $doc = @{ version = 0; bases = @{} }
    if (-not "$Json".Trim()) { return $doc }
    $o = $null; try { $o = ConvertFrom-PimSharedPendingJson $Json } catch { return $doc }
    if ($null -eq $o) { return $doc }
    $doc.version = [int]("$($o.version)" -as [int])
    if ($o.bases) {
        foreach ($p in $o.bases.PSObject.Properties) {
            $chs = @(@($p.Value.changes) | Where-Object { $_ } | ForEach-Object { ConvertTo-PimSharedPendingChange $_ } | Where-Object { $_ })
            # by / atUtc survive the normalisation (ConvertTo-PimSharedPendingChange keeps them).
            $doc.bases[$p.Name] = @{ version = [int]("$($p.Value.version)" -as [int]); changes = $chs }
        }
    }
    return $doc
}

function ConvertFrom-PimSharedPendingDoc {
    param([Parameter(Mandatory)][hashtable]$Doc)
    $bases = [ordered]@{}
    foreach ($k in @($Doc.bases.Keys | Sort-Object)) {
        $b = $Doc.bases[$k]
        if (-not @($b.changes).Count) { continue }   # an entity with nothing pending is not stored
        $bases[$k] = [ordered]@{ version = [int]$b.version; changes = @($b.changes) }
    }
    ([ordered]@{ version = [int]$Doc.version; bases = $bases } | ConvertTo-Json -Depth 8 -Compress)
}

function Read-PimSharedPendingStore {
    param([Parameter(Mandatory)][string]$ConnectionString)
    $raw = Get-PimSqlSettingRaw -ConnectionString $ConnectionString -Name (Get-PimSharedPendingSettingName)
    [pscustomobject]@{ raw = $raw; doc = (ConvertTo-PimSharedPendingDoc $raw) }
}

function Update-PimSharedPendingStore {
    <#
      Read -> mutate -> compare-and-swap, retried when another writer got in between (up to -Attempts). -Mutate gets the
      document hashtable and returns $true to write it or $false to leave the store as it is; it may put its outcome in
      $Doc['__result']. Returns { ok; written; doc; result; reason }. ok=$false only when every attempt lost the race.
    #>
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][scriptblock]$Mutate, [int]$Attempts = 5)
    for ($i = 0; $i -lt $Attempts; $i++) {
        $st = Read-PimSharedPendingStore -ConnectionString $ConnectionString
        $doc = $st.doc
        $write = [bool](& $Mutate $doc)
        $result = $doc['__result']; [void]$doc.Remove('__result')
        if (-not $write) { return [pscustomobject]@{ ok = $true; written = $false; doc = $doc; result = $result; reason = '' } }
        $doc.version = [int]$doc.version + 1
        $json = ConvertFrom-PimSharedPendingDoc -Doc $doc
        $n = Set-PimSqlSettingIfUnchanged -ConnectionString $ConnectionString -Name (Get-PimSharedPendingSettingName) -NewValueJson $json -ExpectedValueJson $st.raw
        if ([int]$n -ge 1) { return [pscustomobject]@{ ok = $true; written = $true; doc = $doc; result = $result; reason = '' } }
        Start-Sleep -Milliseconds (40 * ($i + 1))
    }
    [pscustomobject]@{ ok = $false; written = $false; doc = $null; result = $null; reason = "the pending-changes store kept changing under this write ($Attempts attempts) -- try again" }
}

function Invoke-PimSharedPendingReconcile {
    # Drop, for each named entity (or every entity when -Bases is empty), the changes the stored rows already carry out.
    # -ReadRows { param($base) <stored rows> }. Returns { cleared; doc }.
    param([Parameter(Mandatory)][string]$ConnectionString, [string[]]$Bases = @(), [Parameter(Mandatory)][scriptblock]$ReadRows)
    $u = Update-PimSharedPendingStore -ConnectionString $ConnectionString -Mutate {
        param($doc)
        $cleared = 0
        $names = if (@($Bases).Count) { @($Bases) } else { @($doc.bases.Keys) }
        foreach ($b in $names) {
            if (-not $doc.bases.ContainsKey($b) -or -not @($doc.bases[$b].changes).Count) { continue }
            $sel = Select-PimSharedPendingOutstanding -Changes @($doc.bases[$b].changes) -StoredRows @(& $ReadRows $b) -Base $b
            if ($sel.cleared) { $doc.bases[$b].changes = @($sel.changes); $doc.bases[$b].version = [int]$doc.bases[$b].version + 1; $cleared += $sel.cleared }
        }
        $doc['__result'] = $cleared
        return ($cleared -gt 0)
    }
    [pscustomobject]@{ cleared = [int]$u.result; doc = $u.doc; ok = $u.ok }
}
