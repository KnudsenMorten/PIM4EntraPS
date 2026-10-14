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
#
# PIM 100.119 (owner 2026-10-13) REPLACES two things said above: the check is a COUNT only (no fraction of the
# rows), and it is no longer cleared by the person who committed ("confirm"): a SUPERADMIN approves exactly the
# rows in the commit popup, with a reason, recorded. The count is the limit set on Operations > Guards.

Set-StrictMode -Off

# The limit of the commit removal check (a count inside a floor and a ceiling; default 25) -- its own file.
if (-not (Get-Command Get-PimGuardLimit -ErrorAction SilentlyContinue) -and (Test-Path -LiteralPath (Join-Path $PSScriptRoot 'PIM-GuardLimits.ps1'))) { . (Join-Path $PSScriptRoot 'PIM-GuardLimits.ps1') }

function Get-PimCommitGuardThresholds {
    # The numbers of the commit removal check:
    #   PIM_CommitMaxRemoveAbs  -- refuse a commit that removes MORE than this
    #                              count of rows. Default 25 (see PIM 100.119 below). Can only LOWER the limit.
    #   PIM_CommitMinForEmptyGuard -- NO LONGER READ (see the fix list note below): the "no original row
    #                              survives" case applies to every list that has at least 1 row.
    #
    # PIM 100.119 (owner 2026-10-13: "50% group deletions of 3 groups would trigger if i select 2/3 ... drop the
    # percentage in the guards and focus alone on amounts"): THE SHARE IS GONE. The check is a COUNT -- more than
    # maxRemoveAbs rows of one list in one commit -- plus "this commit would EMPTY the list" (not a share). The count is
    # the limit a SuperAdmin sets on Operations > Guards (PIM-GuardLimits.ps1, pim.Settings 'GuardLimits', inside its
    # floor and ceiling; default 25, a literal fallback here). $global:PIM_CommitMaxRemovePct is no longer read.
    # $global:PIM_CommitMaxRemoveAbs can only LOWER the limit for this process (tests, a stricter host).
    #
    # PIM 100.119, fix list 2026-10-13 ("no guard can be switched off"; "a setting may only LOWER a limit"):
    #   * -MaxRemoveAbs (a caller's own number) can only LOWER the limit too -- it used to REPLACE it, so a caller
    #     passing 100000 had no count check at all.
    #   * the "no original row survives" case applies to EVERY list that has rows. $global:PIM_CommitMinForEmptyGuard and
    #     -MinForEmptyGuard used to raise the size a list needed before that case applied (1000 = the case never
    #     applied): both are still ACCEPTED so an older caller keeps binding, and are IGNORED. The number is the
    #     literal 1.
    param(
        [Nullable[int]]$MaxRemoveAbs,
        [Nullable[int]]$MinForEmptyGuard
    )
    $lim = 25
    if (Get-Command Get-PimGuardLimit -ErrorAction SilentlyContinue) { try { $lim = [int](Get-PimGuardLimit -GuardId 'manager.commit-removal' -Fallback 25) } catch { $lim = 25 } }
    if ($lim -lt 1) { $lim = 25 }
    $abs = $lim
    # CR4 GUARD-STRICT (framework §12.11b): for 24 h after an engine-changing release, half the configured limit
    if (Get-Command Get-PimGuardStrictState -ErrorAction SilentlyContinue) {
        try { if ((Get-PimGuardStrictState).active) { $h = Get-PimGuardStrictHalf -Configured $lim; if ($h -lt $abs) { $abs = $h } } } catch { }
    }
    if ($null -ne $MaxRemoveAbs -and [int]$MaxRemoveAbs -lt $abs) { $abs = [int]$MaxRemoveAbs }
    if ($null -ne $global:PIM_CommitMaxRemoveAbs -and "$($global:PIM_CommitMaxRemoveAbs)" -match '^\d+$' -and [int]$global:PIM_CommitMaxRemoveAbs -lt $abs) { $abs = [int]$global:PIM_CommitMaxRemoveAbs }
    if ($abs -lt 0) { $abs = 0 }
    return @{ maxRemoveAbs = $abs; minForEmptyGuard = 1 }
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
    # Returns @{ allowed; reason; rule; removeCount; limit; threshold } where rule
    # is 'ok' | 'empty-set' | 'over-threshold' | 'approved'.
    #
    # PIM 100.119 (owner 2026-10-13): COUNTS ONLY -- no share of the list decides anything (2 of 3 does not trip; 26 of
    # 1000 does). And the way through is no longer "the same person confirms": -Approved means A SUPERADMIN APPROVED
    # EXACTLY THESE ROWS in the commit popup, with a reason -- the CALLER proves that (role, reason, the list hash) before
    # it passes the switch; this function only decides whether an approval is needed at all.
    # -Confirm is still ACCEPTED so an older caller keeps binding, and is IGNORED: it approves nothing.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][int]$BeforeCount,
        [Parameter(Mandatory)][int]$AfterCount,
        [Nullable[int]]$RemoveCount,
        [switch]$Approved,
        [switch]$Confirm,
        [Nullable[int]]$MaxRemoveAbs,
        [Nullable[int]]$MinForEmptyGuard
    )
    $th = Get-PimCommitGuardThresholds -MaxRemoveAbs $MaxRemoveAbs -MinForEmptyGuard $MinForEmptyGuard
    $before = [Math]::Max(0, $BeforeCount)
    $after  = [Math]::Max(0, $AfterCount)
    $removed = if ($null -ne $RemoveCount) { [Math]::Max(0, [int]$RemoveCount) } else { [Math]::Max(0, $before - $after) }
    $lim = [int]$th.maxRemoveAbs

    # ADD-ONLY / pure-grow / no-removal commits are always fine.
    if ($removed -le 0) {
        return [pscustomobject]@{ allowed = $true; reason = 'no rows removed -- safe commit'; rule = 'ok'; removeCount = 0; limit = $lim; threshold = $th }
    }

    # PIM 100.119 A1 (owner 2026-10-13, after the review) -- THREE cases, counts only:
    #   (i)   more than the limit removed from one list in one commit                                    'over-threshold'
    #   (ii)  NO ORIGINAL ROW SURVIVES: removed >= before (it was "after = 0", which a commit that removes all 25 rows
    #         and adds one new row walked past)                                                          'empty-set'
    #   (iii) the commit would leave FEW of the original rows: keep (2) or fewer, of a list that has more than minList (5)
    #         rows -- 24 of 25 asks, 4 of 6 asks, 3 of 6 does not, and 2 of 3 does not (the owner's example) 'few-left'
    # keep and minList are literals from functions (PIM-GuardLimits.ps1) and are not settable.
    $keep = 2; $minList = 5
    if (Get-Command Get-PimCommitGuardFewLeftRows -ErrorAction SilentlyContinue) { $keep = [int](Get-PimCommitGuardFewLeftRows); $minList = [int](Get-PimCommitGuardFewLeftMinList) }
    $survive = [Math]::Max(0, $before - $removed)
    $emptyHit = ($removed -ge $before -and $before -ge $th.minForEmptyGuard -and $before -gt 0)
    $overHit  = ($removed -gt $lim)
    $fewHit   = ($before -gt $minList -and $survive -le $keep)

    if (-not $emptyHit -and -not $overHit -and -not $fewHit) {
        return [pscustomobject]@{ allowed = $true; reason = ("removes {0} of {1} row(s) -- within the limit of {2} rows per commit" -f $removed, $before, $lim); rule = 'ok'; removeCount = $removed; limit = $lim; survive = $survive; keep = $keep; minList = $minList; threshold = $th }
    }

    $rule = if ($emptyHit) { 'empty-set' } elseif ($overHit) { 'over-threshold' } else { 'few-left' }
    if ($Approved) {
        $why = if ($emptyHit) { 'keeps none of the rows the list has' } elseif ($overHit) { "removes more than $lim rows" } else { "leaves $survive of $before rows" }
        return [pscustomobject]@{ allowed = $true; reason = ("the commit ({0}) was approved by a SuperAdmin" -f $why); rule = 'approved'; tripped = $rule; removeCount = $removed; limit = $lim; survive = $survive; keep = $keep; minList = $minList; threshold = $th }
    }

    if ($emptyHit) {
        return [pscustomobject]@{
            allowed = $false; rule = 'empty-set'; removeCount = $removed; limit = $lim; survive = $survive; keep = $keep; minList = $minList; threshold = $th
            reason = ("This commit takes out ALL {0} row(s) the list has now -- none of them would be left{1}. Nothing was saved. A SuperAdmin must approve exactly these rows before it is saved." -f $before, $(if ($after -gt 0) { " (the $after row(s) it would hold afterwards are new)" } else { '' }))
        }
    }
    if (-not $overHit) {
        return [pscustomobject]@{
            allowed = $false; rule = 'few-left'; removeCount = $removed; limit = $lim; survive = $survive; keep = $keep; minList = $minList; threshold = $th
            reason = ("This commit takes {0} of {1} row(s) out of the list and would leave {2} of them -- {3} or fewer left of a list that has more than {4} rows. Nothing was saved. A SuperAdmin must approve exactly these rows before it is saved." -f $removed, $before, $survive, $keep, $minList)
        }
    }
    return [pscustomobject]@{
        allowed = $false; rule = 'over-threshold'; removeCount = $removed; limit = $lim; survive = $survive; keep = $keep; minList = $minList; threshold = $th
        reason = ("This commit takes {0} of {1} row(s) out of the list -- more than the limit of {2} rows in one commit. Nothing was saved. A SuperAdmin must approve exactly these rows before it is saved." -f $removed, $before, $lim)
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
        # 🔴 §33.28 (found with BUG-198): Compare-PimRowSets builds each modify as an [ordered]
        # DICTIONARY, and PSObject.Properties does not expose a dictionary's keys -- so this read
        # nothing and EVERY modify was silently dropped from the scope check and the maker/checker
        # classification. Read both shapes.
        foreach ($side in @('after', 'before')) {
            $v = $null
            if ($m -is [System.Collections.IDictionary]) { if ($m.Contains($side)) { $v = $m[$side] } }
            elseif ($m.PSObject.Properties[$side]) { $v = $m.PSObject.Properties[$side].Value }
            if ($null -ne $v) { [void]$out.Add($v) }
        }
    }
    foreach ($r in @($Diff.removes)) { if ($null -ne $r) { [void]$out.Add($r) } }
    return $out.ToArray()
}
