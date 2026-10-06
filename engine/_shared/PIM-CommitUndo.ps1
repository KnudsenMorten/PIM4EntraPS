<#
  CONFIG-1.2 (framework DOCS/REQUIREMENTS.md) / PIM 96.2 -- UNDO A COMMIT, built on the change journal (PIM-CommitJournal.ps1).

  Operator 2026-10-06: "people make mistakes, so we need a way to undo a commit in a undo-way (super user can see all, admin can
  undo his own changes)". Decisions (D3): SuperAdmin sees and undoes EVERY commit; Admin sees and undoes ONLY the commits (rows)
  they initiated; Delegated / Reader: none.

  * Undo = a NEW commit with the INVERSE of the journal rows: Add -> remove that row, Remove -> add BeforeJson back, Modify -> the
    BeforeJson values. This file only PLANS it (pure). The Manager hands the plan to the page, which STAGES it into Pending
    changes; the normal commit (approvals, second approver, every gate) writes it, journaled with UndoOf = the undone commit.
    Nothing here writes pim.Rows.
  * Per row selectable, the whole commit ticked by default. CONFLICT: a row changed again by a LATER commit is shown "changed
    since by <who> in <commit>" and is NOT ticked -- reverting it must be ticked on purpose.
  * Pure functions take the journal rows as input (unit-testable without SQL); the two Get-* readers below are the only SQL.
#>

function Resolve-PimCommitUndoId {
    <# PURE. A commit id as the API / a PUT body may carry it: 1-64 of [A-Za-z0-9-_], else '' (refused). #>
    param([AllowNull()][object]$Value)
    $v = "$Value".Trim()
    if ($v -match '^[A-Za-z0-9_\-]{1,64}$') { return $v }
    return ''
}

function Test-PimCommitUndoActorMatch {
    <#
      PURE. Is a journal InitiatedBy this person? Equal (case-insensitive), or the BUG-262 recorded form "<tag> (as <identity>)"
      a local Manager writes. An empty identity never matches (fail closed).
    #>
    param([AllowNull()][string]$Recorded, [AllowNull()][string]$Identity)
    $r = "$Recorded".Trim(); $i = "$Identity".Trim()
    if (-not $r -or -not $i) { return $false }
    if ($r -ieq $i) { return $true }
    return $r.EndsWith(" (as $i)", [System.StringComparison]::OrdinalIgnoreCase)
}

function Get-PimCommitUndoAccess {
    <#
      PURE. Who may see / undo a commit (CONFIG-1.2, D3). -Entries = that commit's journal rows (InitiatedBy per row).
      @{ canSee; all (may undo every row); reason }. SuperAdmin: every commit. Admin: a commit with at least one row they
      initiated (and only those rows are undoable -- Get-PimCommitUndoPlan). Delegated / Reader / anything else: none.
    #>
    param([AllowNull()][string]$Role, [AllowNull()][string]$Identity, [AllowNull()][object[]]$Entries = @())
    $ro = "$Role".Trim()
    if ($ro -ieq 'SuperAdmin') { return @{ canSee = $true; all = $true; reason = '' } }
    if ($ro -ine 'Admin') { return @{ canSee = $false; all = $false; reason = "Commit history and undo are for an Admin (own commits) or a SuperAdmin (every commit); your role is '$ro'." } }
    $own = @(@($Entries) | Where-Object { $_ -and (Test-PimCommitUndoActorMatch -Recorded "$($_.InitiatedBy)" -Identity $Identity) })
    if ($own.Count -gt 0) { return @{ canSee = $true; all = $false; reason = '' } }
    return @{ canSee = $false; all = $false; reason = 'An Admin sees and undoes only the commits they initiated; this one is not yours (a SuperAdmin can undo it).' }
}

function ConvertTo-PimCommitUndoUtc {
    <# PURE. A journal time (DATETIME2, stored UTC, read back with Kind Unspecified) -> ISO-8601 UTC 'o' string; '' when none. #>
    param([AllowNull()][object]$Value)
    if ($null -eq $Value -or $Value -is [DBNull] -or "$Value" -eq '') { return '' }
    if ($Value -is [datetime]) { return ([datetime]::SpecifyKind($Value, [System.DateTimeKind]::Utc)).ToString('o') }
    try { return ([datetime]::Parse("$Value", [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AdjustToUniversal -bor [Globalization.DateTimeStyles]::AssumeUniversal)).ToString('o') } catch { return "$Value" }
}

function ConvertFrom-PimCommitUndoJson {
    <# PURE. A stored row's JSON -> an object; '' / null / unparsable -> $null. #>
    param([AllowNull()][object]$Json)
    if ($null -eq $Json -or $Json -is [DBNull]) { return $null }
    $s = "$Json".Trim(); if (-not $s) { return $null }
    try { return ($s | ConvertFrom-Json) } catch { return $null }
}

function Get-PimCommitUndoPlan {
    <#
      PURE. The undo plan of one commit.
        -Entries   : that commit's journal rows (Id, Entity, Key, Op, BeforeJson, AfterJson, InitiatedBy, ApprovedBy, ...)
        -LaterRows : journal rows of LATER commits on the same (Entity, Key) (Get-PimCommitUndoLaterRows), any order
        -Role / -Identity : the viewer (Get-PimCommitUndoAccess)
      Returns { commitId; rows[]; counts } -- one plan row per (Entity, Key):
        entity, key, op (what the commit did), inverse (remove | add | modify -- what the undo stages), before / after (the
        stored rows as objects), row (the row the undo stages: BeforeJson for add / modify, AfterJson -- to find it -- for
        remove), initiatedBy, allowed (+ note), conflict + changedSince { by; commitId; utc; op } (the LATEST later change),
        selected (allowed and no conflict and valid).
    #>
    param([string]$CommitId = '', [AllowNull()][object[]]$Entries = @(), [AllowNull()][object[]]$LaterRows = @(),
          [AllowNull()][string]$Role, [AllowNull()][string]$Identity)
    $acc = Get-PimCommitUndoAccess -Role $Role -Identity $Identity -Entries @($Entries)
    $rows = New-Object System.Collections.Generic.List[object]
    # One plan row per (Entity, Key): first journal row's Before, last row's After (a commit normally writes a key once).
    $order = New-Object System.Collections.Generic.List[string]
    $byKey = @{}
    foreach ($e in @($Entries | Where-Object { $_ })) {
        $k = ("{0}`n{1}" -f "$($e.Entity)", "$($e.Key)").ToLowerInvariant()
        if (-not $byKey.ContainsKey($k)) { $byKey[$k] = @{ first = $e; last = $e }; $order.Add($k) } else { $byKey[$k].last = $e }
    }
    # The latest LATER change per (Entity, Key).
    $later = @{}
    foreach ($l in @($LaterRows | Where-Object { $_ })) {
        $k = ("{0}`n{1}" -f "$($l.Entity)", "$($l.Key)").ToLowerInvariant()
        $cur = $later[$k]
        $lid = 0L; try { $lid = [long]$l.Id } catch { }
        $cid = -1L; if ($cur) { try { $cid = [long]$cur.Id } catch { } }
        if (-not $cur -or $lid -ge $cid) { $later[$k] = $l }
    }
    foreach ($k in $order) {
        $f = $byKey[$k].first; $z = $byKey[$k].last
        $beforeJ = $f.BeforeJson; $afterJ = $z.AfterJson
        $before = ConvertFrom-PimCommitUndoJson $beforeJ; $after = ConvertFrom-PimCommitUndoJson $afterJ
        # The net op of the commit on this key (Add then Modify is still an Add; Modify then Remove is a Remove).
        $op = if ($null -eq $before -and $null -ne $after) { 'Add' } elseif ($null -ne $before -and $null -eq $after) { 'Remove' } elseif ($null -ne $before) { 'Modify' } else { "$($f.Op)" }
        $inverse = switch ($op) { 'Add' { 'remove' } 'Remove' { 'add' } 'Modify' { 'modify' } default { '' } }
        $valid = $true; $note = ''
        if (-not $inverse -or ($inverse -eq 'remove' -and $null -eq $after) -or ($inverse -in @('add', 'modify') -and $null -eq $before)) {
            $valid = $false; $note = 'The journal row has no usable before / after record, so it cannot be reversed.'
        }
        $ini = "$($f.InitiatedBy)"
        $allowed = [bool]$acc.all -or (Test-PimCommitUndoActorMatch -Recorded $ini -Identity $Identity)
        if ($acc.canSee -and -not $allowed -and -not $note) { $note = "Initiated by $ini -- an Admin undoes only their own changes (a SuperAdmin can undo it)." }
        $lc = $later[$k]; $since = $null
        if ($lc) { $since = [ordered]@{ by = "$($lc.InitiatedBy)"; commitId = "$($lc.CommitId)"; utc = (ConvertTo-PimCommitUndoUtc $lc.CommittedUtc); op = "$($lc.Op)" } }
        if ($since -and $valid -and -not $note) { $note = "Changed since by $($since.by) in commit $($since.commitId) -- not ticked; reverting it overwrites that later change." }
        $rows.Add([pscustomobject][ordered]@{
            entity = "$($f.Entity)"; key = "$($f.Key)"; op = $op; inverse = $inverse
            before = $before; after = $after
            row = $(if ($inverse -eq 'remove') { $after } else { $before })
            initiatedBy = $ini; approvedBy = "$($f.ApprovedBy)"
            allowed = [bool]($allowed -and $acc.canSee -and $valid)
            conflict = [bool]($null -ne $since); changedSince = $since
            selected = [bool]($allowed -and $acc.canSee -and $valid -and $null -eq $since)
            note = $note
        })
    }
    $arr = @($rows.ToArray())
    return [pscustomobject][ordered]@{
        commitId = "$CommitId"; canSee = [bool]$acc.canSee; reason = "$($acc.reason)"; rows = $arr
        counts = [ordered]@{ rows = $arr.Count; selected = @($arr | Where-Object { $_.selected }).Count
                             conflicts = @($arr | Where-Object { $_.conflict }).Count; notAllowed = @($arr | Where-Object { -not $_.allowed }).Count }
    }
}

function Get-PimCommitUndoHistory {
    <#
      The commit history list (newest first) for the Commit history page: CommitId, CommittedUtc, InitiatedBy (first row),
      Initiators (how many people), ApprovedBy, Source, UndoOf, UndoneBy (a later commit that undid it), Rows, Entities, Entity
      (first). -OwnIdentity: only commits with at least one row that person initiated (an Admin; CONFIG-1.2). '' = every commit
      (a SuperAdmin) -- the CALLER decides which by role; never pass '' for an Admin.
    #>
    param([Parameter(Mandatory)][string]$ConnectionString, [string]$OwnIdentity = '', [int]$Top = 200, [int]$Days = 90)
    $p = @{ d = [Math]::Max(1, $Days); t = [Math]::Max(1, [Math]::Min(1000, $Top)) }
    $having = ''
    if ("$OwnIdentity".Trim()) {
        $id = "$OwnIdentity".Trim()
        $p['i'] = $id
        $p['il'] = '% (as ' + ($id -replace '([\[%_])', '[$1]') + ')'
        $having = 'HAVING SUM(CASE WHEN InitiatedBy = @i OR InitiatedBy LIKE @il THEN 1 ELSE 0 END) > 0'
    }
    $out = @(Invoke-PimSqlQuery -ConnectionString $ConnectionString -Parameters $p -Sql @"
WITH c AS (
    SELECT CommitId, MIN(Id) AS FirstId, MIN(CommittedUtc) AS CommittedUtc, MIN(InitiatedBy) AS InitiatedBy,
           COUNT(DISTINCT InitiatedBy) AS Initiators, MAX(ApprovedBy) AS ApprovedBy, MIN(Source) AS Source, MAX(UndoOf) AS UndoOf,
           COUNT(*) AS [Rows], COUNT(DISTINCT Entity) AS Entities, MIN(Entity) AS Entity
    FROM pim.CommitJournal WHERE CommittedUtc >= DATEADD(DAY, -@d, SYSUTCDATETIME())
    GROUP BY CommitId
    $having
)
SELECT TOP (@t) c.CommitId, c.CommittedUtc, c.InitiatedBy, c.Initiators, c.ApprovedBy, c.Source, c.UndoOf, c.[Rows], c.Entities, c.Entity,
       (SELECT TOP 1 u.CommitId FROM pim.CommitJournal u WHERE u.UndoOf = c.CommitId ORDER BY u.Id DESC) AS UndoneBy
FROM c ORDER BY c.FirstId DESC
"@)
    foreach ($r in $out) { $r.CommittedUtc = ConvertTo-PimCommitUndoUtc $r.CommittedUtc }
    return $out
}

function Get-PimCommitUndoLaterRows {
    <# The journal rows of LATER commits on the same (Entity, Key) as the given commit's rows (the conflict check's input). #>
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][string]$CommitId)
    return @(Invoke-PimSqlQuery -ConnectionString $ConnectionString -Parameters @{ c = $CommitId } -Sql @"
SELECT j.Id, j.CommitId, j.CommittedUtc, j.Entity, j.[Key], j.Op, j.InitiatedBy
FROM pim.CommitJournal j
WHERE j.CommitId <> @c AND EXISTS (SELECT 1 FROM pim.CommitJournal o WHERE o.CommitId = @c AND o.Entity = j.Entity AND o.[Key] = j.[Key] AND j.Id > o.Id)
ORDER BY j.Id
"@)
}
