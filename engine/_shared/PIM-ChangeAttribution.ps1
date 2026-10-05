<#
  AUDIT-1 actor (operator 2026-10-05: "actor must be the person who a) triggered it and b) approved it if enabled").

  THE DEFECT (measured on internal, 2026-10-05): every directory change the engine applied was recorded with
  Actor = 'engine', and nothing tied it to the commit that asked for it -- the Manager's config.save carried no
  correlation id and the engine's rows carried only the job run. "Who granted this?" could not be answered from the trail.

  THE FIX: the commit records, per changed row, WHO initiated it (the administrator who staged it, else the committer) and
  WHO approved it (a second administrator who committed a colleague's staged change, or the approver of a maker/checker
  approval), under a commit id. pim.ChangeAttribution, keyed by the STORE key (Entity, Key) -- so a REMOVED row is still
  attributed after it is gone. The engine maps each change it applies back to its stored row (the item carries the row:
  Get-PimStoreRowKey on the row's own SourceEntity / entity, and for the definitions family the group tag / name) and
  records Actor = the initiator, with approvedBy, commitId and the run in After, and CorrelationId = the commit id, so the
  request -> commit -> applied change joins up. A change no commit names (a scheduled reconcile, an automatic expiry)
  stays Actor 'engine', and says so.
#>

$script:PimAttributionDays = 30

function Get-PimChangeAttributionDdl {
    @"
IF OBJECT_ID('pim.ChangeAttribution') IS NULL
CREATE TABLE pim.ChangeAttribution (
    Entity        NVARCHAR(100) NOT NULL,
    [Key]         NVARCHAR(400) NOT NULL,
    Op            NVARCHAR(10)  NOT NULL,
    InitiatedBy   NVARCHAR(200) NOT NULL,
    ApprovedBy    NVARCHAR(200) NULL,
    CommitId      NVARCHAR(64)  NOT NULL,
    CommittedUtc  DATETIME2     NOT NULL CONSTRAINT DF_ChangeAttr_Ts DEFAULT SYSUTCDATETIME(),
    CONSTRAINT PK_pim_ChangeAttribution PRIMARY KEY (Entity, [Key])
);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_pim_ChangeAttribution_Ts')
CREATE INDEX IX_pim_ChangeAttribution_Ts ON pim.ChangeAttribution (CommittedUtc DESC);
"@
}

function ConvertTo-PimCommitAttributionEntries {
    <#
      PURE. One entry per row a commit changes: @{ key; op; initiatedBy; approvedBy }.
      -Classification: Get-PimSharedPendingCommitClassification's result (carried[] = a colleague's staged change carried out,
      .by = who staged it; direct[] = the committer's own edit). Without it, -Diff (adds / removes / modifies) is used and
      every row is the committer's.
      approvedBy: the committer when they carried out a change SOMEONE ELSE staged (the second approver), else the approver
      of the maker/checker approval that authorised the commit (-Approver), else empty.
    #>
    param([string]$Base, [Parameter(Mandatory)][string]$Committer, [object]$Classification = $null, [object]$Diff = $null, [string]$Approver = '')
    $c = "$Committer".Trim()
    $ap = "$Approver".Trim()
    $out = New-Object System.Collections.Generic.List[object]
    $seen = @{}
    # A definition row is keyed by its group TAG; the engine's policy / owner / AU changes name only the group NAME, so a
    # definitions commit also records 'name:<GroupName>' (same attribution) for Resolve-PimChangeAttribution's family lookup.
    $isDef = ("$Base" -like 'PIM-Definitions-*')
    $add = {
        param($key, $op, $by, $row)
        $k = "$key".Trim(); if (-not $k) { return }
        if ($isDef -and $row) {
            $gn = ''; if ($row -is [System.Collections.IDictionary]) { $gn = "$($row['GroupName'])" } elseif ($row.PSObject.Properties['GroupName']) { $gn = "$($row.GroupName)" }
            $gn = $gn.Trim()
            if ($gn -and $gn.ToLowerInvariant() -ne $k.ToLowerInvariant()) { & $add ('name:' + $gn) $op $by $null }
        }
        $lk = $k.ToLowerInvariant(); if ($seen.ContainsKey($lk)) { return }; $seen[$lk] = $true
        $ini = if ("$by".Trim()) { "$by".Trim() } else { $c }
        $apv = if ($ini.ToLowerInvariant() -ne $c.ToLowerInvariant()) { $c } elseif ($ap -and $ap.ToLowerInvariant() -ne $ini.ToLowerInvariant()) { $ap } else { '' }
        $o = switch -Regex ("$op") { '^(?i)(remove|delete)' { 'Remove' } '^(?i)(add|create)' { 'Create' } default { 'Update' } }
        $out.Add([ordered]@{ key = $k; op = $o; initiatedBy = $ini; approvedBy = $apv })
    }
    if ($Classification) {
        foreach ($x in @($Classification.carried)) { if ($x) { & $add $x.key $x.op $x.by $(if ($x.PSObject.Properties['row'] -and $x.row) { $x.row } elseif ($x.PSObject.Properties['before']) { $x.before } else { $null }) } }
        foreach ($x in @($Classification.direct))  { if ($x) { & $add $x.key $x.op $c $(if ($x.PSObject.Properties['row'] -and $x.row) { $x.row } elseif ($x.PSObject.Properties['before']) { $x.before } else { $null }) } }
    }
    if ($Diff -and (Get-Command Get-PimStoreRowKey -ErrorAction SilentlyContinue)) {
        $f = { param($o, $n) if ($o -is [System.Collections.IDictionary]) { $o[$n] } elseif ($o -and $o.PSObject.Properties[$n]) { $o.$n } else { $null } }
        foreach ($r in @(& $f $Diff 'adds'))     { if ($r) { try { & $add (Get-PimStoreRowKey -Base $Base -Row $r) 'Create' $c $r } catch { } } }
        foreach ($r in @(& $f $Diff 'removes'))  { if ($r) { try { & $add (Get-PimStoreRowKey -Base $Base -Row $r) 'Remove' $c $r } catch { } } }
        foreach ($m in @(& $f $Diff 'modifies')) { if ($m) { $r = & $f $m 'after'; if ($r) { try { & $add (Get-PimStoreRowKey -Base $Base -Row $r) 'Update' $c $r } catch { } } } }
    }
    return @($out.ToArray())
}

function Save-PimChangeAttribution {
    <# Upserts one row per entry (the latest commit of a row wins). Returns the number written. Throws on a store error. #>
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][string]$Entity, [Parameter(Mandatory)][string]$CommitId,
          [object[]]$Entries = @(), [scriptblock]$Exec = $null)
    $n = 0
    $sql = @"
MERGE pim.ChangeAttribution AS t
USING (SELECT @e AS Entity, @k AS [Key]) AS s ON t.Entity = s.Entity AND t.[Key] = s.[Key]
WHEN MATCHED THEN UPDATE SET Op = @o, InitiatedBy = @i, ApprovedBy = @a, CommitId = @c, CommittedUtc = SYSUTCDATETIME()
WHEN NOT MATCHED THEN INSERT (Entity, [Key], Op, InitiatedBy, ApprovedBy, CommitId) VALUES (@e, @k, @o, @i, @a, @c);
"@
    foreach ($x in @($Entries)) {
        if (-not $x) { continue }
        $p = @{ e = $Entity; k = "$($x.key)"; o = "$($x.op)"; i = "$($x.initiatedBy)"; a = $(if ("$($x.approvedBy)".Trim()) { "$($x.approvedBy)" } else { $null }); c = $CommitId }
        if ($Exec) { & $Exec $sql $p } else { [void](Invoke-PimSqlNonQuery -ConnectionString $ConnectionString -Sql $sql -Parameters $p) }
        $n++
    }
    return $n
}

function Get-PimChangeAttributionIndex {
    <# The recent attributions, as a lookup: 'entity|key' (lower) -> record. Never throws (an empty index attributes nothing). #>
    param([Parameter(Mandatory)][string]$ConnectionString, [int]$Days = $script:PimAttributionDays)
    $ix = @{}
    try {
        $rows = @(Invoke-PimSqlQuery -ConnectionString $ConnectionString -Sql "SELECT Entity, [Key], Op, InitiatedBy, ApprovedBy, CommitId, CommittedUtc FROM pim.ChangeAttribution WHERE CommittedUtc >= DATEADD(DAY, -@d, SYSUTCDATETIME())" -Parameters @{ d = $Days })
        foreach ($r in $rows) { $ix[("{0}|{1}" -f "$($r.Entity)", "$($r.Key)").ToLowerInvariant()] = $r }
    } catch { Write-Warning "[audit] change attribution could not be read (changes are recorded as 'engine'): $($_.Exception.Message)" }
    return $ix
}

function Resolve-PimChangeAttribution {
    <#
      PURE. Which commit asked for the change the engine is applying? -Item: the engine item (entity, key, desired / live /
      row). Tries, in order: the row's SourceEntity and the item's entity, each with Get-PimStoreRowKey of the row; then, for
      the definitions family ('PIM-Definitions'), every PIM-Definitions-* entity with the row's GroupTag / GroupName.
      Returns the newest matching record, or $null.
    #>
    param([hashtable]$Index, [string]$Entity, [object]$Row)
    if (-not $Index -or -not $Index.Count -or $null -eq $Row) { return $null }
    $f = { param($o, $n) if ($o -is [System.Collections.IDictionary]) { "$($o[$n])" } elseif ($o.PSObject.Properties[$n]) { "$($o.$n)" } else { '' } }
    $bases = New-Object System.Collections.Generic.List[string]
    $se = & $f $Row 'SourceEntity'; if ($se) { $bases.Add($se) }
    if ("$Entity".Trim()) { $bases.Add("$Entity".Trim()) }
    $cands = New-Object System.Collections.Generic.List[object]
    foreach ($b in $bases) {
        $k = ''; if (Get-Command Get-PimStoreRowKey -ErrorAction SilentlyContinue) { try { $k = "$(Get-PimStoreRowKey -Base $b -Row $Row)" } catch { $k = '' } }
        if ($k) { $hit = $Index[("{0}|{1}" -f $b, $k).ToLowerInvariant()]; if ($hit) { $cands.Add($hit) } }
    }
    if (-not $cands.Count -and @($bases | Where-Object { $_ -match '^(?i)PIM-Definitions' }).Count) {
        $vals = @((& $f $Row 'GroupTag'), (& $f $Row 'GroupName')) | Where-Object { $_ } | ForEach-Object { $_.ToLowerInvariant() }
        foreach ($ik in @($Index.Keys)) {
            $parts = $ik.Split('|', 2)
            if ($parts.Count -eq 2 -and $parts[0] -like 'pim-definitions-*' -and ($vals -contains $parts[1] -or ($parts[1].StartsWith('name:') -and $vals -contains $parts[1].Substring(5)))) { $cands.Add($Index[$ik]) }
        }
    }
    if (-not $cands.Count) { return $null }
    return @($cands | Sort-Object { [datetime]$_.CommittedUtc } -Descending)[0]
}
