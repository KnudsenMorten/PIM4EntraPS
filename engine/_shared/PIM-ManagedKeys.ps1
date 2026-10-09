<#
  SEC-80 (§33.38, operator 2026-10-06: "it must only impact defined perm per pim manager def, not things like delegations
  or admins that exist outside pim manager").

  THE DEFECT: a prune (-Mode Full -Prune) removed EVERY live item whose key no desired row had (Compare-PimDesiredVsLive).
  What a provider reads live is wider than what PIM Manager defines -- every member of a PIM group, every grant a PIM group
  holds, every tenant role of a user named in a Roles-Direct row -- so a prune reached memberships, roles and assignments
  someone made by hand, outside PIM. The guards that existed (opt-in, empty-desired, the removal budget) cap HOW MUCH a prune
  removes, never WHAT.

  THE FIX: a ledger of the live items PIM manages, per scope (pim.ManagedKeys). A key enters it only when the engine has
  MATCHED a live item to a desired row (nochange / update) or CREATED it from one; it leaves when PIM removes the item, or
  when a complete live read no longer finds it. A prune removes ONLY ledger keys; every other live-not-desired item is
  UNMANAGED -- reported, never removed. Targeted Action=Remove rows are not prunes (the row is the definition) and pass.
  A provider whose desired and live keys do not correspond can never prune: nothing it reads ever enters the ledger.
  An unreadable ledger prunes nothing (fail safe).

  Test seam: $global:PIM_ManagedKeysStore = @{} keeps the ledger in memory (scope -> @{ key -> $true }) instead of SQL.
  A value may also be a hashtable @{ confirmedUtc; commitId; sourceEntity; sourceKey } (a CONFIRMED key, below).

  96.5 decision D2 (operator 2026-10-06): "matched" = RECOGNISED, which is NOT enough for the daily reconcile to remove a
  leftover. The ledger therefore also says whether a key is CONFIRMED: ConfirmedUtc + CommitId (+ the store row it came
  from, SourceEntity / SourceKey, so the reconcile can find that row's journal history). A key is confirmed ONLY when
    (a) PIM CREATED it (the create applied), or
    (b) a FULL live read after a PIM commit saw it live, where that commit's create had failed (the applied outcome
        recorded 'failed' -- the platform took the request although the call errored).
  A key PIM only MATCHED (it existed before PIM, was imported, or answered "already exists") is never confirmed.
  Additive schema only: the columns are added to a table from an earlier build, never changed.
#>

function Get-PimManagedKeysDdl {
    @"
IF OBJECT_ID('pim.ManagedKeys') IS NULL
CREATE TABLE pim.ManagedKeys (
    Scope         NVARCHAR(50)  NOT NULL,
    [Key]         NVARCHAR(400) NOT NULL,
    FirstSeenUtc  DATETIME2     NOT NULL CONSTRAINT DF_ManagedKeys_First DEFAULT SYSUTCDATETIME(),
    ConfirmedUtc  DATETIME2     NULL,
    CommitId      NVARCHAR(64)  NULL,
    SourceEntity  NVARCHAR(100) NULL,
    SourceKey     NVARCHAR(400) NULL,
    CONSTRAINT PK_pim_ManagedKeys PRIMARY KEY (Scope, [Key])
);
IF COL_LENGTH('pim.ManagedKeys','ConfirmedUtc') IS NULL ALTER TABLE pim.ManagedKeys ADD ConfirmedUtc DATETIME2 NULL;
IF COL_LENGTH('pim.ManagedKeys','CommitId') IS NULL ALTER TABLE pim.ManagedKeys ADD CommitId NVARCHAR(64) NULL;
IF COL_LENGTH('pim.ManagedKeys','SourceEntity') IS NULL ALTER TABLE pim.ManagedKeys ADD SourceEntity NVARCHAR(100) NULL;
IF COL_LENGTH('pim.ManagedKeys','SourceKey') IS NULL ALTER TABLE pim.ManagedKeys ADD SourceKey NVARCHAR(400) NULL;
"@
}

function Get-PimManagedKeyNorm { param([string]$Key) "$Key".Trim().ToLowerInvariant() }

function Get-PimManagedKeys {
    <# The scope's ledger as @{ key(lower) -> $true }. THROWS when it cannot be read (the caller then prunes nothing). #>
    param([string]$ConnectionString, [Parameter(Mandatory)][string]$Scope)
    $s = "$Scope".Trim().ToLowerInvariant()
    if ($global:PIM_ManagedKeysStore -is [hashtable]) {
        $h = @{}; if ($global:PIM_ManagedKeysStore.ContainsKey($s)) { foreach ($k in @($global:PIM_ManagedKeysStore[$s].Keys)) { $h[$k] = $true } }
        return $h
    }
    if (-not "$ConnectionString".Trim()) { throw 'no SQL store to read the managed-key ledger from' }
    $h = @{}
    # A store from before this build has no table yet: that is an EMPTY ledger (nothing proven managed), not an error.
    $rows = @(Invoke-PimSqlQuery -ConnectionString $ConnectionString -Sql "IF OBJECT_ID('pim.ManagedKeys') IS NOT NULL SELECT [Key] FROM pim.ManagedKeys WHERE Scope = @s" -Parameters @{ s = $s })
    foreach ($r in $rows) { if ($r -and "$($r.Key)") { $h[(Get-PimManagedKeyNorm $r.Key)] = $true } }
    return $h
}

function Update-PimManagedKeys {
    <# Adds and removes ledger keys for one scope (one round trip each). Returns @{ added; removed }. Throws on a store error. #>
    param([string]$ConnectionString, [Parameter(Mandatory)][string]$Scope, [string[]]$Add = @(), [string[]]$Remove = @())
    $s = "$Scope".Trim().ToLowerInvariant()
    $a = @(@($Add) | ForEach-Object { Get-PimManagedKeyNorm $_ } | Where-Object { $_ -and $_.Length -le 400 } | Select-Object -Unique)
    $r = @(@($Remove) | ForEach-Object { Get-PimManagedKeyNorm $_ } | Where-Object { $_ } | Select-Object -Unique)
    if ($global:PIM_ManagedKeysStore -is [hashtable]) {
        if (-not $global:PIM_ManagedKeysStore.ContainsKey($s)) { $global:PIM_ManagedKeysStore[$s] = @{} }
        foreach ($k in $a) { if (-not $global:PIM_ManagedKeysStore[$s].ContainsKey($k)) { $global:PIM_ManagedKeysStore[$s][$k] = $true } }
        foreach ($k in $r) { [void]$global:PIM_ManagedKeysStore[$s].Remove($k) }
        return [pscustomobject]@{ added = $a.Count; removed = $r.Count }
    }
    if (-not "$ConnectionString".Trim()) { throw 'no SQL store to write the managed-key ledger to' }
    $toJson = { param($arr) if (@($arr).Count) { ConvertTo-Json -InputObject @($arr) -Compress } else { '[]' } }
    if ($a.Count) {
        $sql = (Get-PimManagedKeysDdl) + @"

INSERT INTO pim.ManagedKeys (Scope, [Key])
SELECT DISTINCT @s, j.[value] FROM OPENJSON(@j) j
WHERE NOT EXISTS (SELECT 1 FROM pim.ManagedKeys m WHERE m.Scope = @s AND m.[Key] = j.[value]);
"@
        [void](Invoke-PimSqlNonQuery -ConnectionString $ConnectionString -Sql $sql -Parameters @{ s = $s; j = (& $toJson $a) })
    }
    if ($r.Count) {
        [void](Invoke-PimSqlNonQuery -ConnectionString $ConnectionString -Parameters @{ s = $s; j = (& $toJson $r) } `
            -Sql "IF OBJECT_ID('pim.ManagedKeys') IS NOT NULL DELETE FROM pim.ManagedKeys WHERE Scope = @s AND [Key] IN (SELECT [value] FROM OPENJSON(@j))")
    }
    return [pscustomobject]@{ added = $a.Count; removed = $r.Count }
}

function Split-PimPruneByLedger {
    <#
      PURE. Splits a diff's remove list. A TARGETED removal (an Action=Remove row) always stays. A PRUNE item stays only when
      its key is in -Ledger; every other prune item is UNMANAGED (defined outside PIM Manager) and is returned apart, never
      removed. -Ledger $null = the ledger could not be read: every prune item is unmanaged (fail safe).
      Returns @{ remove; unmanaged }.
    #>
    param([object[]]$Remove = @(), [AllowNull()][hashtable]$Ledger)
    $keep = New-Object System.Collections.Generic.List[object]
    $un = New-Object System.Collections.Generic.List[object]
    foreach ($i in @($Remove)) {
        if ($null -eq $i) { continue }
        $targeted = ($i.PSObject.Properties['targeted'] -and $i.targeted)
        if ($targeted) { $keep.Add($i); continue }
        $k = Get-PimManagedKeyNorm "$($i.key)"
        if ($null -ne $Ledger -and $k -and $Ledger.ContainsKey($k)) { $keep.Add($i) } else { $un.Add($i) }
    }
    return [pscustomobject]@{ remove = $keep.ToArray(); unmanaged = $un.ToArray() }
}

function Get-PimManagedKeysDelta {
    <#
      PURE. What a finished (non-WhatIf) scope pass changes in its ledger.
        add    = keys PIM matched to a desired row (-Matched: nochange + update) or created from one (-Created), not yet in it;
        remove = ledger keys PIM removed this pass (-Removed), and -- only when -LiveComplete (the live read covered the whole
                 scope, not a narrowed or partial read) -- ledger keys the live read no longer finds.
    #>
    param([hashtable]$Ledger = @{}, [string[]]$Matched = @(), [string[]]$Created = @(), [string[]]$Removed = @(),
          [string[]]$LiveKeys = @(), [switch]$LiveComplete)
    if ($null -eq $Ledger) { $Ledger = @{} }
    $add = New-Object System.Collections.Generic.List[string]
    $seen = @{}
    foreach ($k in @(@($Matched) + @($Created))) {
        $n = Get-PimManagedKeyNorm $k
        if ($n -and -not $Ledger.ContainsKey($n) -and -not $seen.ContainsKey($n)) { $seen[$n] = $true; $add.Add($n) }
    }
    $rem = @{}
    foreach ($k in @($Removed)) { $n = Get-PimManagedKeyNorm $k; if ($n -and $Ledger.ContainsKey($n)) { $rem[$n] = $true } }
    if ($LiveComplete) {
        $live = @{}; foreach ($k in @($LiveKeys)) { $n = Get-PimManagedKeyNorm $k; if ($n) { $live[$n] = $true } }
        foreach ($k in @($Ledger.Keys)) { if (-not $live.ContainsKey($k) -and -not $seen.ContainsKey($k)) { $rem[$k] = $true } }
    }
    return [pscustomobject]@{ add = $add.ToArray(); remove = @($rem.Keys) }
}

function ConvertTo-PimManagedKeyRecord {
    <# PURE. One ledger entry as a record (the in-memory value may be $true or a hashtable; a SQL row has the columns). #>
    param([string]$Key, [AllowNull()][object]$Value)
    $f = { param($n) if ($Value -is [System.Collections.IDictionary]) { $Value[$n] } elseif ($null -ne $Value -and $Value -isnot [bool] -and $Value.PSObject.Properties[$n]) { $Value.$n } else { $null } }
    $nz = { param($v) if ($null -eq $v -or $v -is [DBNull] -or "$v".Trim() -eq '') { $null } else { $v } }
    $conf = & $nz (& $f 'confirmedUtc'); if ($null -eq $conf) { $conf = & $nz (& $f 'ConfirmedUtc') }
    $cid = & $nz (& $f 'commitId'); if ($null -eq $cid) { $cid = & $nz (& $f 'CommitId') }
    $se = & $nz (& $f 'sourceEntity'); if ($null -eq $se) { $se = & $nz (& $f 'SourceEntity') }
    $sk = & $nz (& $f 'sourceKey'); if ($null -eq $sk) { $sk = & $nz (& $f 'SourceKey') }
    return [pscustomobject]@{ key = (Get-PimManagedKeyNorm $Key); confirmedUtc = $conf; commitId = $(if ($null -ne $cid) { "$cid" } else { '' })
                              sourceEntity = $(if ($null -ne $se) { "$se" } else { '' }); sourceKey = $(if ($null -ne $sk) { "$sk" } else { '' })
                              confirmed = ($null -ne $conf) }
}

function Get-PimManagedKeyRecords {
    <#
      96.5 / D2. The scope's ledger WITH its provenance: @{ key(lower) -> record { key; confirmed; confirmedUtc; commitId;
      sourceEntity; sourceKey } }. THROWS when it cannot be read (the reconcile then removes nothing). A store from before
      this build (no table, or no columns yet) reads as unconfirmed keys -- never as confirmed.
    #>
    param([string]$ConnectionString, [Parameter(Mandatory)][string]$Scope)
    $s = "$Scope".Trim().ToLowerInvariant()
    $h = @{}
    if ($global:PIM_ManagedKeysStore -is [hashtable]) {
        if ($global:PIM_ManagedKeysStore.ContainsKey($s)) { foreach ($k in @($global:PIM_ManagedKeysStore[$s].Keys)) { $h[$k] = ConvertTo-PimManagedKeyRecord -Key $k -Value $global:PIM_ManagedKeysStore[$s][$k] } }
        return $h
    }
    if (-not "$ConnectionString".Trim()) { throw 'no SQL store to read the managed-key ledger from' }
    $sql = @"
IF OBJECT_ID('pim.ManagedKeys') IS NOT NULL AND COL_LENGTH('pim.ManagedKeys','ConfirmedUtc') IS NOT NULL
    EXEC sp_executesql N'SELECT [Key], ConfirmedUtc, CommitId, SourceEntity, SourceKey FROM pim.ManagedKeys WHERE Scope = @s', N'@s NVARCHAR(50)', @s = @s;
ELSE IF OBJECT_ID('pim.ManagedKeys') IS NOT NULL
    SELECT [Key], CAST(NULL AS DATETIME2) AS ConfirmedUtc, CAST(NULL AS NVARCHAR(64)) AS CommitId, CAST(NULL AS NVARCHAR(100)) AS SourceEntity, CAST(NULL AS NVARCHAR(400)) AS SourceKey FROM pim.ManagedKeys WHERE Scope = @s;
"@
    foreach ($r in @(Invoke-PimSqlQuery -ConnectionString $ConnectionString -Sql $sql -Parameters @{ s = $s })) {
        if ($r -and "$($r.Key)") { $rec = ConvertTo-PimManagedKeyRecord -Key "$($r.Key)" -Value $r; $h[$rec.key] = $rec }
    }
    return $h
}

function Set-PimManagedKeyConfirmations {
    <#
      96.5 / D2. Marks ledger keys CONFIRMED: -Items @(@{ key; commitId; sourceEntity; sourceKey }). A key not in the ledger
      yet is added confirmed; a key already confirmed keeps its FIRST confirmation (time + commit), only a missing store
      reference is filled in. Returns the number of items handled. Throws on a store error (the caller warns; a ledger that
      falls behind only makes the reconcile remove LESS).
    #>
    param([string]$ConnectionString, [Parameter(Mandatory)][string]$Scope, [object[]]$Items = @(), [datetime]$NowUtc = [datetime]::UtcNow)
    $s = "$Scope".Trim().ToLowerInvariant()
    $f = { param($o, $n) if ($o -is [System.Collections.IDictionary]) { "$($o[$n])" } elseif ($null -ne $o -and $o.PSObject.Properties[$n]) { "$($o.$n)" } else { '' } }
    $list = New-Object System.Collections.Generic.List[object]
    $seen = @{}
    foreach ($i in @($Items)) {
        if ($null -eq $i) { continue }
        $k = Get-PimManagedKeyNorm (& $f $i 'key'); if (-not $k -or $k.Length -gt 400 -or $seen.ContainsKey($k)) { continue }
        $seen[$k] = $true
        $list.Add([ordered]@{ k = $k; c = (& $f $i 'commitId').Trim(); e = (& $f $i 'sourceEntity').Trim(); sk = (& $f $i 'sourceKey').Trim() })
    }
    if (-not $list.Count) { return 0 }
    if ($global:PIM_ManagedKeysStore -is [hashtable]) {
        if (-not $global:PIM_ManagedKeysStore.ContainsKey($s)) { $global:PIM_ManagedKeysStore[$s] = @{} }
        foreach ($x in $list) {
            $cur = $global:PIM_ManagedKeysStore[$s][$x.k]
            if ($cur -is [System.Collections.IDictionary] -and $cur['confirmedUtc']) {
                if (-not "$($cur['sourceKey'])" -and $x.sk) { $cur['sourceEntity'] = $x.e; $cur['sourceKey'] = $x.sk }
                continue
            }
            $global:PIM_ManagedKeysStore[$s][$x.k] = @{ confirmedUtc = $NowUtc.ToUniversalTime().ToString('o'); commitId = $x.c; sourceEntity = $x.e; sourceKey = $x.sk }
        }
        return $list.Count
    }
    if (-not "$ConnectionString".Trim()) { throw 'no SQL store to write the managed-key ledger to' }
    # The DDL in its own batch: the MERGE below names the new columns, which must exist when it is compiled.
    [void](Invoke-PimSqlNonQuery -ConnectionString $ConnectionString -Sql (Get-PimManagedKeysDdl))
    $json = ConvertTo-Json -InputObject @($list.ToArray()) -Compress -Depth 4
    [void](Invoke-PimSqlNonQuery -ConnectionString $ConnectionString -Parameters @{ s = $s; j = $json; n = $NowUtc.ToUniversalTime() } -Sql @"
MERGE pim.ManagedKeys AS t
USING (SELECT DISTINCT j.k, NULLIF(j.c, '') AS c, NULLIF(j.e, '') AS e, NULLIF(j.sk, '') AS sk
       FROM OPENJSON(@j) WITH (k NVARCHAR(400) '$.k', c NVARCHAR(64) '$.c', e NVARCHAR(100) '$.e', sk NVARCHAR(400) '$.sk') j) AS x
   ON t.Scope = @s AND t.[Key] = x.k
WHEN MATCHED AND (t.ConfirmedUtc IS NULL OR (t.SourceKey IS NULL AND x.sk IS NOT NULL)) THEN UPDATE SET
    ConfirmedUtc = COALESCE(t.ConfirmedUtc, @n),
    CommitId     = CASE WHEN t.ConfirmedUtc IS NULL THEN x.c ELSE t.CommitId END,
    SourceEntity = CASE WHEN t.ConfirmedUtc IS NULL OR t.SourceKey IS NULL THEN x.e ELSE t.SourceEntity END,
    SourceKey    = CASE WHEN t.ConfirmedUtc IS NULL OR t.SourceKey IS NULL THEN x.sk ELSE t.SourceKey END
WHEN NOT MATCHED THEN INSERT (Scope, [Key], ConfirmedUtc, CommitId, SourceEntity, SourceKey) VALUES (@s, x.k, @n, x.c, x.e, x.sk);
"@)
    return $list.Count
}

function Get-PimEverAppliedKeys {
    <#
      100.27 REMOVE-NEVER-APPLIED (owner 2026-10-09: "it will not go away in internal"). Which of -Keys (live keys of one
      scope) PIM has EVER applied, by the two records the engine keeps: the managed-key ledger (pim.ManagedKeys -- PIM matched
      or created the item) and the applied outcome per commit (pim.CommitApplied -- created / updated / already present).
      Returns @{ ok; applied = @{ key(lower) -> 'ledger' | 'created' | 'updated' | 'already present' }; error }.
      ok = $false when EITHER record could not be read: the caller must then treat every key as possibly applied (a Remove
      that is skipped wrongly would leave access in place, so "never applied" is only ever concluded from a complete read).
      Test seams: $global:PIM_ManagedKeysStore and $global:PIM_CommitAppliedStore.
    #>
    param([string]$ConnectionString, [Parameter(Mandatory)][string]$Scope, [string[]]$Keys = @())
    $want = @{}; foreach ($k in @($Keys)) { $n = Get-PimManagedKeyNorm $k; if ($n) { $want[$n] = $true } }
    $out = @{}
    if (-not $want.Count) { return [pscustomobject]@{ ok = $true; applied = $out; error = '' } }
    try {
        $ledger = Get-PimManagedKeys -ConnectionString $ConnectionString -Scope $Scope
        foreach ($k in @($want.Keys)) { if ($ledger.ContainsKey($k)) { $out[$k] = 'ledger' } }
        $rows = @()
        if ($global:PIM_CommitAppliedStore -is [System.Collections.Generic.List[object]]) {
            $rows = @($global:PIM_CommitAppliedStore | Where-Object { "$($_.Scope)" -ieq $Scope })
        } elseif ($global:PIM_ManagedKeysStore -is [hashtable]) {
            $rows = @()   # an in-memory ledger without an in-memory outcome store: the ledger is the whole answer
        } else {
            if (-not "$ConnectionString".Trim()) { throw 'no SQL store to read the applied outcomes from' }
            $json = ConvertTo-Json -InputObject @($want.Keys) -Compress
            $rows = @(Invoke-PimSqlQuery -ConnectionString $ConnectionString -Parameters @{ s = $Scope; j = $json } -Sql @"
IF OBJECT_ID('pim.CommitApplied') IS NOT NULL
SELECT LiveKey, Result FROM pim.CommitApplied
WHERE Scope = @s AND Result IN ('created', 'updated', 'already present') AND LOWER(LiveKey) IN (SELECT LOWER([value]) FROM OPENJSON(@j))
"@)
        }
        foreach ($r in $rows) {
            $lk = Get-PimManagedKeyNorm "$($r.LiveKey)"
            if ($want.ContainsKey($lk) -and -not $out.ContainsKey($lk) -and "$($r.Result)" -in @('created', 'updated', 'already present')) { $out[$lk] = "$($r.Result)" }
        }
        return [pscustomobject]@{ ok = $true; applied = $out; error = '' }
    } catch {
        return [pscustomobject]@{ ok = $false; applied = $out; error = "$($_.Exception.Message)" }
    }
}
