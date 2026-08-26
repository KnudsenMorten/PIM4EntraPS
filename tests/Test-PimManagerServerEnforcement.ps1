#Requires -Version 5.1
<#
.SYNOPSIS
    Batch 1 -- server-side enforcement + safety guards for the PIM Manager.
    Proves, per fix, BOTH the happy path (authorized SuperAdmin / in-scope Admin
    still succeeds) AND that the previously-allowed bypass is now DENIED.

.DESCRIPTION
    Two audits (read-only) found that several Manager write/read paths trusted the
    GUI to gate and never re-enforced on the server. This suite locks the server
    side closed. Pure decision logic lives in testable helpers
    (engine/_shared/PIM-ManagerWriteGuards.ps1 +
    engine/_shared/PIM-PortalAccess.ps1) which are dot-sourced and exercised
    directly; the wiring (which handler calls which gate, and the HTML button
    gate) is asserted by STATIC source checks over Open-PimManager.ps1 /
    pim-manager.html (no live tenant / no browser).

    Fixes proven:
      1. Maker/checker on the GENERAL commit path (plain PUT calls
         Test-PimAuthoringCommitAllowed, not just /api/authoring/*).
      2. Portal scope on writes (PUT/authoring/revoke): an out-of-scope (T0) row
         -- incl. delete-by-omission -- is rejected; in-scope succeeds; SuperAdmin
         bypasses.
      3. GET /api/active-assignments now has a min-role gate + per-caller scope
         filter (was ungated, whole-tenant).
      4. /api/audit + /api/audit/export require Admin; add-exemption requires
         SuperAdmin (its siblings' role); Map "Assign" button gated roleAtLeast('Admin').
      5. Empty-set / large-delta guard on commit + restore; restore takes a
         pre-restore snapshot.

    Run standalone (exit 0 green / 1 red) or via Run-AllPimTests.ps1.
#>
[CmdletBinding()] param()

$ErrorActionPreference = 'Stop'
$pass = 0; $fail = 0
function T($n, $c) { if ($c) { Write-Host "  PASS $n" -ForegroundColor Green; $script:pass++ } else { Write-Host "  FAIL $n" -ForegroundColor Red; $script:fail++ } }

$solRoot   = Split-Path -Parent $PSScriptRoot
$mgrDir    = Join-Path $solRoot 'tools\pim-manager'
$srvPath   = Join-Path $mgrDir 'Open-PimManager.ps1'
$htmlPath  = Join-Path $mgrDir 'pim-manager.html'
$portalLib = Join-Path $solRoot 'engine\_shared\PIM-PortalAccess.ps1'
$guardLib  = Join-Path $solRoot 'engine\_shared\PIM-ManagerWriteGuards.ps1'

T 'Open-PimManager.ps1 present'        (Test-Path -LiteralPath $srvPath)
T 'pim-manager.html present'           (Test-Path -LiteralPath $htmlPath)
T 'PIM-PortalAccess.ps1 present'       (Test-Path -LiteralPath $portalLib)
T 'PIM-ManagerWriteGuards.ps1 present' (Test-Path -LiteralPath $guardLib)
if ($fail) { Write-Host "`n RESULT: $pass pass, $fail fail" -ForegroundColor Red; exit 1 }

. $portalLib
. $guardLib
# Maker/checker gate libs (for the FIX 1 happy-path decision proof). Load order:
# ApprovalGate -> SensitiveAuthoring (the latter calls Test-PimApprovalApprovedFor).
foreach ($dep in 'PIM-ApprovalGate.ps1','PIM-Authoring.ps1','PIM-SensitiveAuthoring.ps1') {
    $p = Join-Path $solRoot "engine\_shared\$dep"
    if (Test-Path -LiteralPath $p) { try { . $p } catch {} }
}

$src  = [System.IO.File]::ReadAllText($srvPath)
$html = [System.IO.File]::ReadAllText($htmlPath)

# A delegated portal profile: tierMax=1 EXCLUDES Tier-0; manage caps; all services.
$deleg = [pscustomobject]@{ identity = 'deleg@example.test'; tierMax = 1; services = @('*'); capabilities = @('manage-direct','manage-indirect','assign','assign-admin') }
$t0row = [pscustomobject]@{ GroupName = 'PIM-Entra-GA-L0-T0-MP-ID';        Workload = 'Entra';    TierLevel = 'T0'; Level = 'L0' }
$t1row = [pscustomobject]@{ GroupName = 'PIM-Defender-Ops-L2-T1-WDP-ID';  Workload = 'Defender'; TierLevel = 'T1'; Level = 'L2' }

# ===========================================================================
# FIX 5 -- empty-set / large-delta guard (the 53-user mass-disable precondition)
# ===========================================================================
Write-Host "`n-- FIX 5: empty-set / large-delta commit + restore guard --" -ForegroundColor Cyan

$gEmpty = Test-PimCommitDeltaGuard -BeforeCount 10 -AfterCount 0
T 'DENY: a commit that empties a populated entity is refused'        ((-not $gEmpty.allowed) -and $gEmpty.rule -eq 'empty-set')
$gEmptyOk = Test-PimCommitDeltaGuard -BeforeCount 10 -AfterCount 0 -Confirm
T 'ALLOW: empty commit proceeds WITH explicit confirm'              ($gEmptyOk.allowed -and $gEmptyOk.rule -eq 'confirmed')
$gOver = Test-PimCommitDeltaGuard -BeforeCount 100 -AfterCount 100 -RemoveCount 60
T 'DENY: removing 60% (add+remove keeps size) is over threshold'     ((-not $gOver.allowed) -and $gOver.rule -eq 'over-threshold')
$gOverAbs = Test-PimCommitDeltaGuard -BeforeCount 1000 -AfterCount 970 -RemoveCount 30
T 'DENY: removing 30 rows is over the absolute cap (25)'             ((-not $gOverAbs.allowed) -and $gOverAbs.rule -eq 'over-threshold')
$gSmall = Test-PimCommitDeltaGuard -BeforeCount 10 -AfterCount 8 -RemoveCount 2
T 'ALLOW: a small in-bounds removal commits (happy path)'           ($gSmall.allowed -and $gSmall.rule -eq 'ok')
$gAdd = Test-PimCommitDeltaGuard -BeforeCount 5 -AfterCount 9 -RemoveCount 0
T 'ALLOW: an add-only commit is never blocked'                      ($gAdd.allowed -and $gAdd.rule -eq 'ok')
$gFresh = Test-PimCommitDeltaGuard -BeforeCount 0 -AfterCount 0
T 'ALLOW: empty->empty (fresh/no-op) is not a destructive empty'    ($gFresh.allowed -and $gFresh.rule -eq 'ok')
# Threshold knobs are honoured.
$gKnob = Test-PimCommitDeltaGuard -BeforeCount 10 -AfterCount 7 -RemoveCount 3 -MaxRemoveAbs 2 -MaxRemovePct 1
T 'knob: a lowered absolute cap (2) refuses a 3-row removal'        (-not $gKnob.allowed)

# Wiring: the commit (PUT) + restore paths call the guard; restore snapshots first.
T 'wire: PUT handler reads a confirm flag for the delta guard'      ($src -match 'confirmDestructive')
T 'wire: PUT handler calls Test-PimCommitDeltaGuard'                ($src -match 'Test-PimCommitDeltaGuard\s+-BeforeCount')
T 'wire: restore calls Test-PimCommitDeltaGuard'                    (([regex]::Matches($src,'Test-PimCommitDeltaGuard')).Count -ge 2)
T 'wire: restore takes a PRE-RESTORE snapshot (New-PimCommitSnapshot)'  ($src -match 'pre-restore of snapshot')
T 'wire: restore returns preRestoreSnapshotId'                      ($src -match 'preRestoreSnapshotId')

# ===========================================================================
# FIX 2 -- portal scope on WRITES (incl. delete-by-omission)
# ===========================================================================
Write-Host "`n-- FIX 2: portal scope re-enforced on writes --" -ForegroundColor Cyan

$sT0 = Test-PimPortalRowsInScope -Profile $deleg -Rows @($t0row) -Base 'PIM-Assignments-Admins' -RequireManage
T 'DENY: scoped (tierMax=1) caller cannot write a T0 row'           (-not $sT0.allowed)
$sT1 = Test-PimPortalRowsInScope -Profile $deleg -Rows @($t1row) -Base 'PIM-Assignments-Admins' -RequireManage
T 'ALLOW: scoped caller writes an in-scope T1 row (happy path)'     ($sT1.allowed)
$sSuper = Test-PimPortalRowsInScope -Profile $deleg -Rows @($t0row) -Base 'x' -RequireManage -IsSuperAdmin
T 'ALLOW: SuperAdmin bypasses scope on a T0 row'                    ($sSuper.allowed)
$sNoProf = Test-PimPortalRowsInScope -Profile $null -Rows @($t0row) -Base 'x' -RequireManage
T 'ALLOW: no-profile caller not narrowed (flat role gate applies)'  ($sNoProf.allowed)
$sFailClosed = Test-PimPortalRowsInScope -Profile $null -Rows @($t0row) -Base 'x' -RequireManage -RequireProfile
T 'DENY: with -RequireProfile a no-profile caller fails CLOSED'     (-not $sFailClosed.allowed)
# delete-by-omission: the affected set INCLUDES removed rows; an out-of-scope removed row is denied.
$diffRemoves = [pscustomobject]@{ adds = @(); modifies = @(); removes = @($t0row) }
$affected = Get-PimWriteAffectedRows -Diff $diffRemoves
$sOmit = Test-PimPortalRowsInScope -Profile $deleg -Rows $affected -Base 'PIM-Assignments-Admins' -RequireManage
T 'DENY: delete-by-omission of an out-of-scope T0 row is rejected'  ((-not $sOmit.allowed) -and @($sOmit.denied).Count -eq 1)
# Get-PimWriteAffectedRows collects adds + modify(before/after) + removes.
$diffAll = [pscustomobject]@{ adds = @($t1row); modifies = @([pscustomobject]@{ before = $t0row; after = $t1row; diffCols = @('x') }); removes = @() }
$aff2 = Get-PimWriteAffectedRows -Diff $diffAll
T 'affected-rows includes adds + modify before/after'              (@($aff2).Count -eq 3)

# Wiring: each write path resolves caller scope + calls the scope gate.
T 'wire: a Get-PimManagerCallerScope helper exists'                ($src -match 'function Get-PimManagerCallerScope')
T 'wire: PUT handler calls Test-PimPortalRowsInScope'              ($src -match 'Test-PimPortalRowsInScope -Profile \$callerScope')
T 'wire: revoke handler calls Test-PimPortalRowsInScope'          ($src -match 'Test-PimPortalRowsInScope -Profile \$revokeScope')
T 'wire: authoring handler calls Test-PimPortalRowsInScope'       ($src -match 'Test-PimPortalRowsInScope -Profile \$authScope')
T 'wire: PUT bounds after-set via Select-PimPortalVisibleRows'    ($src -match 'Select-PimPortalVisibleRows -Profile \$callerScope')

# ===========================================================================
# FIX 1 -- maker/checker on the GENERAL commit (plain PUT), not just authoring
# ===========================================================================
Write-Host "`n-- FIX 1: maker/checker on the plain PUT commit path --" -ForegroundColor Cyan

# The gate itself: a sensitive change with NO approval is blocked; a non-sensitive
# change is allowed. (We assert the gate IS invoked from the PUT path; the gate's
# own decision logic is covered by Test-PimSensitiveAuthoring.ps1.)
T 'wire: PUT handler calls the SAME gate authoring uses'           ($src -match "Test-PimAuthoringCommitAllowed -Action 'review-save'")
T 'wire: PUT handler returns 409 + approvalRequired when blocked'  ($src -match 'approvalRequired = \$true')
T 'wire: authoring /sensitivity path still calls the gate (unchanged)'  ($src -match "Test-PimAuthoringCommitAllowed -Action \`$action")
# Idempotent/safe: a non-sensitive change must still be allowed by the gate.
if (Get-Command Test-PimAuthoringCommitAllowed -ErrorAction SilentlyContinue) {
    $plainRow = [pscustomobject]@{ GroupTag = 'demo'; UserName = 'svc-x' }
    $nonSens = Test-PimAuthoringCommitAllowed -Action 'review-save' -Base 'PIM-Assignments-Admins' -Rows @($plainRow) -Requests @()
    T 'ALLOW: a non-sensitive plain commit passes the maker/checker gate'  ($nonSens.allowed)
} else {
    T 'ALLOW: a non-sensitive plain commit passes (gate lib present)'      $false
}

# ===========================================================================
# FIX 3 -- GET /api/active-assignments gated + per-caller scope filter
# ===========================================================================
Write-Host "`n-- FIX 3: active-assignments role gate + scope filter --" -ForegroundColor Cyan

# Locate the active-assignments handler block and assert it now contains a min-role
# gate (it previously had NONE) -- the 403 must appear BEFORE the cache fetch.
$aaIdx = $src.IndexOf("'/api/active-assignments*'")
T 'active-assignments handler located'                            ($aaIdx -ge 0)
if ($aaIdx -ge 0) {
    $aaBlock = $src.Substring($aaIdx, [Math]::Min(2400, $src.Length - $aaIdx))
    T 'DENY-path: active-assignments now requires Admin'          ($aaBlock -match "Test-PimManagerRoleAtLeast -Minimum 'Admin'")
    T 'active-assignments scope-filters per caller'               ($aaBlock -match 'Test-PimPortalRowsInScope -Profile \$aaScope')
}

# ===========================================================================
# FIX 4 -- audit + export gated (Admin); add-exemption gated (SuperAdmin);
#          Map "Assign" button gated roleAtLeast('Admin')
# ===========================================================================
Write-Host "`n-- FIX 4: audit / export / add-exemption / Map-Assign gates --" -ForegroundColor Cyan

$auIdx = $src.IndexOf("'/api/audit' -and")
T 'audit handler located'                                         ($auIdx -ge 0)
if ($auIdx -ge 0) {
    $auBlock = $src.Substring($auIdx, [Math]::Min(1600, $src.Length - $auIdx))
    T 'DENY-path: GET /api/audit now requires Admin'             ($auBlock -match "Test-PimManagerRoleAtLeast -Minimum 'Admin'")
}
$exIdx = $src.IndexOf("'/api/audit/export' -and")
T 'audit/export handler located'                                 ($exIdx -ge 0)
if ($exIdx -ge 0) {
    $exBlock = $src.Substring($exIdx, [Math]::Min(900, $src.Length - $exIdx))
    T 'DENY-path: GET /api/audit/export now requires Admin'      ($exBlock -match "Test-PimManagerRoleAtLeast -Minimum 'Admin'")
}
# add-exemption: POST /api/conformance/exemptions must require SuperAdmin (its siblings' role).
$addExIdx = $src.IndexOf("'/api/conformance/exemptions' -and `$method -eq 'POST'")
T 'add-exemption handler located'                                ($addExIdx -ge 0)
if ($addExIdx -ge 0) {
    $addExBlock = $src.Substring($addExIdx, [Math]::Min(700, $src.Length - $addExIdx))
    T 'DENY-path: add-exemption now requires SuperAdmin'        ($addExBlock -match "Test-PimManagerRoleAtLeast -Minimum 'SuperAdmin'")
}
# Map "Assign" button gated like the adjacent "Stage removal".
T 'DENY-path: Map Assign button gated roleAtLeast(Admin) (admin node)'      ($html -match "isServer && roleAtLeast\('Admin'\) && n\.kind === 'admin'")
T 'DENY-path: Map Assign button gated roleAtLeast(Admin) (role-group node)' ($html -match "isServer && roleAtLeast\('Admin'\) && n\.kind === 'role-group'")
T 'ALLOW-path: adjacent Stage-removal button keeps its Admin gate (unchanged)' ($html -match "isServer && roleAtLeast\('Admin'\) && mapNodeHasGrant")

Write-Host ""
if ($fail) { Write-Host " RESULT: $pass pass, $fail fail" -ForegroundColor Red; exit 1 }
Write-Host " RESULT: $pass pass, 0 fail" -ForegroundColor Green
exit 0
