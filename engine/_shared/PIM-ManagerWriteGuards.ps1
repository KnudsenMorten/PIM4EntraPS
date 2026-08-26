# PIM4EntraPS -- server-side WRITE GUARDS for the Manager (Batch 1: server-side
# enforcement + safety guards). PURE, time-free, dependency-light decision
# helpers so the GUI can never be the only enforcement boundary -- the server
# re-checks portal scope, an empty/large-delta safety threshold, and exposes one
# uniform "is this row in my scope?" decision for every write path.
#
# These mirror the engine's disable-guard philosophy (a prior incident
# mass-disabled 53 users from an empty/over-broad desired set): a commit that
# empties the store OR removes more than a sane fraction/count of the current
# rows is REFUSED unless the caller explicitly confirms. SuperAdmin still bypasses
# SCOPE checks (as everywhere in the Manager), but the empty/large-delta guard is
# a SAFETY net that applies to everyone (it can be cleared with an explicit
# confirm flag -- it is a "are you sure?", not a permission wall).
#
# Pure: no persistence, no network, no $script:/$global: reads except the
# threshold knobs (which fall back to safe defaults). Fully testable offline.

Set-StrictMode -Off

function Get-PimCommitGuardThresholds {
    # The empty/large-delta guard knobs, customizable but with safe defaults:
    #   PIM_CommitMaxRemovePct  -- refuse a commit that removes MORE than this
    #                              fraction (0..1) of the current rows. Default 0.5.
    #   PIM_CommitMaxRemoveAbs  -- refuse a commit that removes MORE than this
    #                              absolute count of rows. Default 25.
    #   PIM_CommitMinForEmptyGuard -- only apply the "after-set is empty" refusal
    #                              when the BEFORE set had at least this many rows
    #                              (so legitimately clearing a 1-2 row test entity
    #                              isn't blocked). Default 1 (any non-empty before).
    # A caller MAY override per-call; otherwise these resolve from $global:PIM_*.
    param(
        [Nullable[double]]$MaxRemovePct,
        [Nullable[int]]$MaxRemoveAbs,
        [Nullable[int]]$MinForEmptyGuard
    )
    $pct = if ($null -ne $MaxRemovePct) { [double]$MaxRemovePct }
           elseif ($null -ne $global:PIM_CommitMaxRemovePct) { [double]$global:PIM_CommitMaxRemovePct }
           else { 0.5 }
    $abs = if ($null -ne $MaxRemoveAbs) { [int]$MaxRemoveAbs }
           elseif ($null -ne $global:PIM_CommitMaxRemoveAbs) { [int]$global:PIM_CommitMaxRemoveAbs }
           else { 25 }
    $minEmpty = if ($null -ne $MinForEmptyGuard) { [int]$MinForEmptyGuard }
                elseif ($null -ne $global:PIM_CommitMinForEmptyGuard) { [int]$global:PIM_CommitMinForEmptyGuard }
                else { 1 }
    if ($pct -lt 0) { $pct = 0 } ; if ($pct -gt 1) { $pct = 1 }
    if ($abs -lt 0) { $abs = 0 }
    if ($minEmpty -lt 0) { $minEmpty = 0 }
    return @{ maxRemovePct = $pct; maxRemoveAbs = $abs; minForEmptyGuard = $minEmpty }
}

function Test-PimCommitDeltaGuard {
    # THE empty-set / large-delta safety guard for the commit + restore paths.
    # PURE decision (no I/O). Mirrors the engine disable-guard: a write that empties
    # a previously-populated store, or removes more than a sane fraction/count of the
    # current rows, is REFUSED unless $Confirm is set (an explicit operator
    # acknowledgement). It never blocks ADDS or modifies, and never blocks a small,
    # in-bounds removal.
    #
    # Inputs:
    #   $BeforeCount -- rows currently in the store for this entity.
    #   $AfterCount  -- rows the commit would leave (the after-set size).
    #   $RemoveCount -- rows the commit REMOVES (Before-only keys). When not supplied,
    #                   it is conservatively derived as max(0, Before - After) -- a
    #                   pure replace where After<Before. Pass the KEYED diff's
    #                   removes.Count for precision (add+remove can keep size equal
    #                   while still removing rows).
    #   $Confirm     -- operator explicitly acknowledged a destructive commit.
    #
    # Returns @{ allowed; reason; rule; removeCount; removePct; threshold } where rule
    # is 'ok' | 'empty-set' | 'over-threshold' | 'confirmed'.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][int]$BeforeCount,
        [Parameter(Mandatory)][int]$AfterCount,
        [Nullable[int]]$RemoveCount,
        [switch]$Confirm,
        [Nullable[double]]$MaxRemovePct,
        [Nullable[int]]$MaxRemoveAbs,
        [Nullable[int]]$MinForEmptyGuard
    )
    $th = Get-PimCommitGuardThresholds -MaxRemovePct $MaxRemovePct -MaxRemoveAbs $MaxRemoveAbs -MinForEmptyGuard $MinForEmptyGuard
    $before = [Math]::Max(0, $BeforeCount)
    $after  = [Math]::Max(0, $AfterCount)
    $removed = if ($null -ne $RemoveCount) { [Math]::Max(0, [int]$RemoveCount) } else { [Math]::Max(0, $before - $after) }
    $pct = if ($before -gt 0) { [double]$removed / [double]$before } else { 0.0 }

    # ADD-ONLY / pure-grow / no-removal commits are always fine.
    if ($removed -le 0) {
        return [pscustomobject]@{ allowed = $true; reason = 'no rows removed -- safe commit'; rule = 'ok'; removeCount = 0; removePct = 0.0; threshold = $th }
    }

    $emptyHit = ($after -eq 0 -and $before -ge $th.minForEmptyGuard)
    $overHit  = ($removed -gt $th.maxRemoveAbs) -or ($pct -gt $th.maxRemovePct)

    if (-not $emptyHit -and -not $overHit) {
        return [pscustomobject]@{ allowed = $true; reason = ("removes {0} of {1} row(s) -- within safety threshold" -f $removed, $before); rule = 'ok'; removeCount = $removed; removePct = $pct; threshold = $th }
    }

    if ($Confirm) {
        $why = if ($emptyHit) { 'empties the store' } else { 'removes a large share of rows' }
        return [pscustomobject]@{ allowed = $true; reason = ("destructive commit ({0}) explicitly confirmed" -f $why); rule = 'confirmed'; removeCount = $removed; removePct = $pct; threshold = $th }
    }

    if ($emptyHit) {
        return [pscustomobject]@{
            allowed = $false; rule = 'empty-set'; removeCount = $removed; removePct = $pct; threshold = $th
            reason = ("This commit would EMPTY the entity (was {0} row(s), would be 0). This is the precondition of a mass-disable incident -- re-submit with confirm=true to proceed if intended." -f $before)
        }
    }
    return [pscustomobject]@{
        allowed = $false; rule = 'over-threshold'; removeCount = $removed; removePct = $pct; threshold = $th
        reason = ("This commit removes {0} of {1} row(s) ({2:P0}), over the safety threshold (max {3} rows or {4:P0}). Re-submit with confirm=true to proceed if intended." -f $removed, $before, $pct, $th.maxRemoveAbs, $th.maxRemovePct)
    }
}

function Test-PimPortalRowsInScope {
    # Server-side PORTAL SCOPE gate for WRITES (PUT /api/csv|data, authoring, revoke).
    # PURE: given the caller's portal profile + the rows a write would AFFECT (the
    # after-set delta rows AND/OR the removed-by-omission rows), decide whether EVERY
    # affected row is inside the caller's tier/level/service/scope ceiling. A
    # SuperAdmin (or a caller with no portal profile when $RequireProfile is not set)
    # passes. Any affected row the caller could not SEE/MANAGE -> denied, with the
    # offending row names listed so the server can return a clear error.
    #
    # CRITICAL: this is what stops "delete-by-omission" -- a scoped caller cannot
    # remove an out-of-scope row they can't even see by submitting an after-set that
    # silently drops it. The CALLER passes BOTH the changed/added rows AND the
    # removed rows (Before-only) so an omission of a privileged row is caught.
    #
    # Inputs:
    #   $Profile      -- the caller's portal-admin profile object (or $null).
    #   $Rows         -- the definition rows to validate (affected: adds+modifies+removes).
    #   $Base         -- the entity base (for facet name-grammar fallback).
    #   $IsSuperAdmin -- bypass (sees/manages everything).
    #   $RequireProfile -- when set, a non-super caller WITHOUT a profile is denied
    #                      (fail-closed). Default OFF (no-profile = the legacy
    #                      single-operator / Admin path, unchanged).
    #   $RequireManage -- when set, validate manage capability (Test-PimPortalCanManageGroup),
    #                     not just visibility. Writes use this; reads use visibility.
    #
    # Returns @{ allowed; reason; denied=[ {name; service; tier; level} ]; checked }.
    [CmdletBinding()]
    param(
        [AllowNull()][object]$Profile,
        [AllowNull()][AllowEmptyCollection()][object[]]$Rows = @(),
        [string]$Base = '',
        [switch]$IsSuperAdmin,
        [switch]$RequireProfile,
        [switch]$RequireManage,
        # When set, a row whose scoping facets (tier AND level AND service) are NOT
        # derivable is SKIPPED rather than denied. Used for principal-centric inputs
        # (e.g. active-assignment revoke rows that carry a role/scope but no group
        # tier/level grammar) where the primary enforcement is the read-side scope
        # filter; a definition-row write path leaves this OFF (fail-closed on a row
        # we cannot place).
        [switch]$SkipUnscopableRows
    )
    if ($IsSuperAdmin) {
        return [pscustomobject]@{ allowed = $true; reason = 'SuperAdmin -- scope bypass'; denied = @(); checked = 0 }
    }
    if ($null -eq $Profile) {
        if ($RequireProfile) {
            return [pscustomobject]@{ allowed = $false; reason = 'no portal profile for caller (fail-closed)'; denied = @(); checked = 0 }
        }
        # No profile + not requiring one = the legacy non-delegated path. The flat
        # Manager role gate (Admin+) already governed it; scope is not narrowed.
        return [pscustomobject]@{ allowed = $true; reason = 'no portal profile -- scope not narrowed (flat role gate applies)'; denied = @(); checked = 0 }
    }
    if (-not (Get-Command Get-PimGroupFacets -ErrorAction SilentlyContinue)) {
        # Portal lib not loaded -> cannot evaluate facets. Fail CLOSED for a scoped
        # caller (better to block a delegated write than silently allow out-of-scope).
        return [pscustomobject]@{ allowed = $false; reason = 'portal-access library not loaded -- cannot evaluate scope (fail-closed)'; denied = @(); checked = 0 }
    }
    $denied = New-Object System.Collections.ArrayList
    $checked = 0
    foreach ($r in @($Rows)) {
        if ($null -eq $r) { continue }
        $f = Get-PimGroupFacets -Row $r -Base $Base
        # A row with no derivable tier/level/service grammar cannot be placed against
        # a tier/level ceiling. For principal-centric inputs (revoke), skip it (the
        # read-side filter is the primary gate); for definition writes, fail-closed.
        $unscopable = ($null -eq $f.tier -and $null -eq $f.level -and ("$($f.service)" -eq 'unknown' -or -not "$($f.service)".Trim()))
        if ($unscopable -and $SkipUnscopableRows) { continue }
        $checked++
        $ok = if ($RequireManage -and (Get-Command Test-PimPortalCanManageGroup -ErrorAction SilentlyContinue)) {
            [bool](Test-PimPortalCanManageGroup -Profile $Profile -Facets $f)
        } else {
            [bool](Test-PimPortalCanSeeGroup -Profile $Profile -Facets $f)
        }
        if (-not $ok) {
            [void]$denied.Add([pscustomobject]@{ name = "$($f.name)"; service = "$($f.service)"; tier = $f.tier; level = $f.level })
        }
    }
    if ($denied.Count -gt 0) {
        $names = (@($denied | ForEach-Object { if ("$($_.name)".Trim()) { "$($_.name)" } else { '(unnamed row)' } }) | Select-Object -First 10) -join ', '
        return [pscustomobject]@{
            allowed = $false
            reason  = ("{0} affected row(s) are outside your delegated scope (tier/level/service/scope) and cannot be created, changed, or removed by you: {1}" -f $denied.Count, $names)
            denied  = @($denied.ToArray()); checked = $checked
        }
    }
    return [pscustomobject]@{ allowed = $true; reason = 'all affected rows in scope'; denied = @(); checked = $checked }
}

function Get-PimWriteAffectedRows {
    # Helper: from a Compare-PimRowSets diff, collect EVERY row a write touches --
    # adds + the AFTER side of modifies + removes (Before-only). The removes are the
    # delete-by-omission rows a scoped caller must not be able to drop silently.
    # PURE; returns an object[]. Tolerant of a diff missing any bucket.
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Diff)
    $out = New-Object System.Collections.ArrayList
    foreach ($a in @($Diff.adds))    { if ($null -ne $a) { [void]$out.Add($a) } }
    foreach ($m in @($Diff.modifies)) {
        if ($null -eq $m) { continue }
        # modify entries are @{ before; after; diffCols } -- validate the AFTER state,
        # and also the BEFORE (so a scoped caller can't MODIFY an out-of-scope row).
        if ($m.PSObject.Properties['after']  -and $null -ne $m.after)  { [void]$out.Add($m.after) }
        if ($m.PSObject.Properties['before'] -and $null -ne $m.before) { [void]$out.Add($m.before) }
    }
    foreach ($r in @($Diff.removes)) { if ($null -ne $r) { [void]$out.Add($r) } }
    return $out.ToArray()
}
