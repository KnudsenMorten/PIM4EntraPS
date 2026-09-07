# =============================================================================================
# PIM-Reconcile.ps1 -- DOES THE v2 SQL STORE ACTUALLY CONTAIN THE v1 DATA?
#
# 🔴 WHY THIS EXISTS. On 2026-08-30 the production Delegation Map showed an empty People column.
# The cause: `Account-Definitions-Admins` had imported **ZERO of 8 rows** at cutover. The cutover
# reported success -- truthfully, by its own definition, because it only ever claimed "I inserted
# the rows I could key". Nothing in the product had ever compared what v1 held against what v2
# stored, so an entity landing at zero was invisible for months.
#
# 🔑 THE SHAPE OF THE MISS, and it is the one this file exists to end: the migration LOGIC was
# tested offline and correct; the migration OUTCOME was never verified against reality. A planner
# that is provably right about rows it processes says nothing about rows it never saw.
#
# WHAT MAKES THIS HARD TO GET RIGHT -- every one of these was met for real on 2026-08-30:
#   * v1 CSVs contain EMPTY PADDING ROWS. Counting them as data produced a "148 rows missing, 14%
#     data loss" scare that was simply false. Empty rows are classified, never counted as loss.
#   * v1 contains LITERAL DUPLICATES (3 rows in PIM-Assignments-Roles-AUs). Collapsing them is
#     correct, so it must be reported as `collapsed`, not as loss.
#   * v2 is legitimately NEWER in places: 4 Entra roles exist in v2 that v1 predates, and two role
#     names were RENAMED by Microsoft (Group->Groups Administrator). Extra rows in v2 are therefore
#     a normal state, and must be reported SEPARATELY from missing ones.
#   * The importer's key derivation can return BLANK for a real row, and the importer then skips it
#     in silence. That is the actual bug class, so blank keys on NON-EMPTY rows are their own
#     verdict -- never folded into "missing".
#
# 🔒 SO THE VERDICT IS NOT A BOOLEAN. "v1 and v2 differ" is useless; which WAY they differ, and
# why, is the whole value. PURE: no SQL, no files, no network -- the caller supplies both sides.
#
# PS 5.1 COMPATIBLE: no ternary, no ?., Set-StrictMode -Off, null-guarded.
# =============================================================================================

Set-StrictMode -Off

function Test-PimRowIsEmpty {
    <#
      Is this a padding row rather than data? True when EVERY property is blank.
      🪤 This function is the difference between an accurate report and a false data-loss alarm.
      A v1 CSV with 53 trailing empty lines is not a store that lost 53 rows.
    #>
    [CmdletBinding()] param($Row)
    if ($null -eq $Row) { return $true }
    $joined = ''
    if ($Row -is [System.Collections.IDictionary]) {
        foreach ($k in @($Row.Keys)) { $joined += "$($Row[$k])".Trim() }
    } else {
        foreach ($p in $Row.PSObject.Properties) { $joined += "$($p.Value)".Trim() }
    }
    return (-not $joined)
}

function Get-PimReconcileEntity {
    <#
      Reconcile ONE entity. PURE.

      -SourceRows : the v1 rows as parsed (padding rows included -- they are classified here).
      -StoreKeys  : the keys currently in the v2 store for this entity.
      -KeyOf      : scriptblock deriving a key from a source row (normally Get-PimStoreRowKey).

      Returns @{ entity; sourceTotal; empty; real; distinct; blankKey; collapsed; missing;
                 extra; verdict; detail } where `verdict` is one of:
        missing-entirely -- the store has NOTHING and the source has rows. THE CASE THAT HAPPENED,
                            and it gets its own name because "8 missing" and "the entity never
                            imported" are read very differently by whoever is on call.
        blank-keys       -- real source rows whose key cannot be derived. These are the rows the
                            importer drops SILENTLY; this verdict is what makes them audible.
        missing          -- keys in the source that the store does not have.
        extra            -- keys the store has that the source does not. NOT a failure on its own:
                            v2 is legitimately ahead of v1 in places.
        match            -- every real, keyable source row is present.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Entity,
        [AllowEmptyCollection()][object[]]$SourceRows = @(),
        [AllowEmptyCollection()][string[]]$StoreKeys = @(),
        [Parameter(Mandatory)][scriptblock]$KeyOf
    )
    $empty = 0
    $blank = New-Object System.Collections.Generic.List[object]
    $counts = @{}          # key -> occurrences in source
    foreach ($r in @($SourceRows)) {
        if (Test-PimRowIsEmpty -Row $r) { $empty++; continue }
        $k = "$(& $KeyOf $r)".Trim()
        if (-not $k) { $blank.Add($r) | Out-Null; continue }
        if ($counts.ContainsKey($k)) { $counts[$k]++ } else { $counts[$k] = 1 }
    }
    $real     = @($SourceRows).Count - $empty
    $distinct = $counts.Keys.Count
    # A duplicate is COLLAPSED, not lost -- the store is right to hold one row per key.
    $collapsed = 0
    foreach ($k in $counts.Keys) { if ($counts[$k] -gt 1) { $collapsed += ($counts[$k] - 1) } }

    $have = @{}
    foreach ($s in @($StoreKeys)) { $kk = "$s".Trim(); if ($kk) { $have[$kk] = 1 } }
    $missing = @(@($counts.Keys) | Where-Object { -not $have.ContainsKey($_) } | Sort-Object)
    $extra   = @(@($have.Keys)   | Where-Object { -not $counts.ContainsKey($_) } | Sort-Object)

    # 🔒 ORDER MATTERS. An entity that imported nothing is reported as that, not as "N missing" --
    # the two demand different responses, and the first is the one that hid for months.
    $verdict = 'match'
    if     ($distinct -gt 0 -and @($StoreKeys).Count -eq 0) { $verdict = 'missing-entirely' }
    elseif ($blank.Count -gt 0)                             { $verdict = 'blank-keys' }
    elseif ($missing.Count -gt 0)                           { $verdict = 'missing' }
    elseif ($extra.Count -gt 0)                             { $verdict = 'extra' }

    $detail = switch ($verdict) {
        'missing-entirely' { "the store holds NOTHING for this entity while the source has $distinct keyable row(s) -- it never imported" }
        'blank-keys'       { "$($blank.Count) non-empty source row(s) yield NO key, so the importer skips them silently -- fix the key derivation, not the data" }
        'missing'          { "$($missing.Count) source key(s) are absent from the store" }
        'extra'            { "$($extra.Count) store key(s) are not in the source -- often legitimate (v2 ahead of v1), but say so deliberately" }
        default            { '' }
    }
    return [ordered]@{
        entity = $Entity; sourceTotal = @($SourceRows).Count; empty = $empty; real = $real
        distinct = $distinct; blankKey = $blank.Count; collapsed = $collapsed
        missing = $missing; extra = $extra; verdict = $verdict; detail = $detail
    }
}

function Get-PimReconcileVerdict {
    <#
      Roll per-entity results into one answer. PURE.

      🔒 `extra` alone is NOT a failure -- v2 being ahead of v1 is a normal, intended state, and a
      check that cries wolf over it gets switched off. `missing-entirely`, `blank-keys` and
      `missing` ARE failures.
      🪤 An entity that was never CHECKED is not a pass either: `checked` is reported so "we looked
      at 3 of 14 entities and they were fine" cannot masquerade as a clean bill of health. That
      distinction is the one this project keeps having to relearn.
    #>
    [CmdletBinding()] param([AllowEmptyCollection()][object[]]$Results = @())
    $r = @($Results)
    $fail = @($r | Where-Object { $_.verdict -in @('missing-entirely','blank-keys','missing') })
    $info = @($r | Where-Object { $_.verdict -eq 'extra' })
    return [ordered]@{
        checked  = $r.Count
        ok       = ($fail.Count -eq 0 -and $r.Count -gt 0)
        failed   = @($fail)
        advisory = @($info)
        reason   = $(if ($r.Count -eq 0) { 'NOTHING was reconciled -- that is not a pass' }
                     elseif ($fail.Count) { "$($fail.Count) of $($r.Count) entity(ies) do not reconcile" }
                     else { "all $($r.Count) entity(ies) reconcile" })
    }
}
