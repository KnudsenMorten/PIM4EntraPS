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
#>

function Get-PimManagedKeysDdl {
    @"
IF OBJECT_ID('pim.ManagedKeys') IS NULL
CREATE TABLE pim.ManagedKeys (
    Scope         NVARCHAR(50)  NOT NULL,
    [Key]         NVARCHAR(400) NOT NULL,
    FirstSeenUtc  DATETIME2     NOT NULL CONSTRAINT DF_ManagedKeys_First DEFAULT SYSUTCDATETIME(),
    CONSTRAINT PK_pim_ManagedKeys PRIMARY KEY (Scope, [Key])
);
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
        foreach ($k in $a) { $global:PIM_ManagedKeysStore[$s][$k] = $true }
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
