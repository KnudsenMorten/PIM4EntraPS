#Requires -Version 5.1
<#
.SYNOPSIS
    §35.2 -- the account-operations grid. Offline: static asserts over the shipped server +
    GUI, plus the scoping predicate driven for real. No tenant, no network, no writes.

    The operator's ask: "an easy grid way to handle new/modify of accounts, so i can
    enable/disable accounts, reset tap, create new admin, flag for deletion, revoke sessions."

    The properties worth pinning are not "does it draw a table":
      * §35.3 SCOPING IS ENFORCED IN THE ENDPOINT, NOT THE GRID. An admin the caller cannot
        manage is never RETURNED, so it cannot be drawn and cannot be bulk-selected. A grid
        makes select-all trivial, which is the exact shape of the 2026-06-15 incident that
        disabled 53 accounts -- so the narrowing must happen where the data is produced.
      * A SCOPED LIST SAYS SO. "You are seeing a subset" and "there are only 3 admins" are
        different facts and an operator must be able to tell them apart.
      * FLAG FOR DELETION RAISES A REQUEST -- it does not delete. Offboarding is never
        automatic (§27), and the confirm text has to say that, because the button name does not.
      * REVOKE SESSIONS SAYS WHAT IT DOES NOT DO -- the account survives. Without that the
        operator cannot tell it apart from disabling.
      * THE GRID -> WIZARD JUMP EXISTS. §35.6 chose two surfaces; that jump is what stops them
        being two disconnected tools, and it is the part most likely to be dropped as polish.

    Run standalone (exit 0 green / 1 red) or via Run-AllPimTests.ps1.
#>
[CmdletBinding()] param()

$ErrorActionPreference = 'Stop'
$pass = 0; $fail = 0
function T($n, $c) { if ($c) { Write-Host "  PASS $n" -ForegroundColor Green; $script:pass++ } else { Write-Host "  FAIL $n" -ForegroundColor Red; $script:fail++ } }

$root   = Split-Path -Parent $PSScriptRoot
$srvP   = Join-Path $root 'tools\pim-manager\Open-PimManager.ps1'
$guiP   = Join-Path $root 'tools\pim-manager\pim-manager.html'
$portal = Join-Path $root 'engine\_shared\PIM-PortalAccess.ps1'
T 'Open-PimManager.ps1 present' (Test-Path -LiteralPath $srvP)
T 'pim-manager.html present'    (Test-Path -LiteralPath $guiP)
T 'PIM-PortalAccess.ps1 present' (Test-Path -LiteralPath $portal)
if ($fail) { Write-Host "`n RESULT: $pass pass, $fail fail" -ForegroundColor Red; exit 1 }

# Comments stripped: a source-scan must read CODE. This file's own prose names the things it
# forbids, and so does the server's -- the trap documented in Test-PimAdminTapReset.
$srv = (Get-Content -LiteralPath $srvP -Raw) -replace '(?m)^\s*#.*$', ''
$gui = (Get-Content -LiteralPath $guiP -Raw) -replace '(?m)^\s*//.*$', ''
. (Join-Path $PSScriptRoot '_shared\PimSourceScope.ps1')

# === the endpoint ===========================================================
Write-Host "`n-- GET /api/admin-accounts --" -ForegroundColor Cyan
T 'the endpoint exists'                    ($srv -match "'/api/admin-accounts'")
T 'it reads the managed admin definitions' ($srv -match "(?s)/api/admin-accounts.{0,1500}?Account-Definitions-Admins")
# THE headline: scoping happens here, so an unmanageable row is never emitted.
T 'it filters rows through the §35.3 predicate' ($srv -match "(?s)/api/admin-accounts.{0,2500}?Test-PimPortalCanManageAdmin")
T 'an unmanageable row is SKIPPED, not merely flagged' ($srv -match '(?s)if \(-not \$mayManage\) \{ \$hidden\+\+; continue \}')
T 'it reports how many rows were hidden'   ($srv -match 'hiddenByScope')
T 'it reports THAT it is scoped'           ($srv -match 'scoped\s*=')
T 'SuperAdmin bypasses the narrowing'      ($srv -match '(?s)/api/admin-accounts.{0,2500}?-IsSuperAdmin:\$isSuper')
# Per-verb capability + a reason, so the GUI can disable honestly instead of failing on click.
T 'per-row canResetTap is computed'        ($srv -match 'canResetTap')
T 'a blocked TAP reset carries a REASON'   ($srv -match 'resetTapWhy')
T 'the TAP reason names the missing ManagerEmail' ($srv -match 'no ManagerEmail on the row')
T 'per-row canRevokeSessions is computed'  ($srv -match 'canRevokeSessions')
T 'a row already flagged is reported'      ($srv -match 'alreadyFlagged')

# === the grid ===============================================================
Write-Host "`n-- the grid --" -ForegroundColor Cyan
T 'the grid renderer exists'               ($gui -match 'function renderAccountGrid')
T 'it consumes the scoped endpoint'        ($gui -match "api\('GET', '/api/admin-accounts'\)")
T 'a scoped list SAYS it is scoped'        ($gui -match 'scoped to the accounts you may manage')
T '   ...and says it is not the directory' ($gui -match 'This is not the whole directory')
T 'read-only access is explained'          ($gui -match 'manage-account')

Write-Host "`n-- the six verbs --" -ForegroundColor Cyan
T 'reset TAP'          ($gui -match 'acctTap')
T 'revoke sessions'    ($gui -match 'acctRevoke' -and $gui -match "/api/admin-sessions/revoke")
T 'flag for deletion'  ($gui -match 'acctFlag')
T 'create new admin'   ($gui -match 'acctNew')
T 'modify / give access jump' ($gui -match 'acctAccess')
T 'a filter box (a grid of admins is unusable without one)' ($gui -match 'acctFilter')

Write-Host "`n-- the destructive verbs say what they actually do --" -ForegroundColor Cyan
# Offboarding is never automatic (§27). The button says "Flag for deletion"; the confirm has to
# say that nothing is deleted now and that a SECOND administrator must approve.
T 'flag-for-deletion raises an approval REQUEST' ($gui -match "api\('POST', '/api/approvals'")
T '   ...and says nothing is deleted now'        ($gui -match 'Nothing is disabled or deleted now')
T '   ...and names the second approver'          ($gui -match 'A different administrator must approve')
# Revoke is destructive-but-recoverable; saying so is what separates it from disabling.
T 'revoke says the account is NOT disabled'      ($gui -match 'The account is NOT disabled')
T '   ...and that the user simply signs in again' ($gui -match 'must sign in again')

Write-Host "`n-- §35.6: two surfaces, ONE workflow --" -ForegroundColor Cyan
# The jump is the load-bearing half of choosing separate surfaces. Without it the operator
# leaves the grid, finds the wizard, and re-identifies the same person by hand.
T 'the grid can hand a person to the wizard' ($gui -match 'PIM_WIZARD_PREFILL')
T '   ...carrying that admin'                ($gui -match 'PIM_WIZARD_PREFILL = \{ admin:')

Write-Host "`n-- the grid does not invent write paths --" -ForegroundColor Cyan
# Every verb routes to an endpoint that already existed and already carries its guards.
# A grid that grew its own account-write path would bypass DisableGuard / the approval gate.
# Scan ONLY the grid's own source -- the whole file legitimately contains the Approvals tab's
# /decide and /execute calls, and a file-wide scan would flag those and prove nothing.
#
# 🪤 §37.4 -- THIS REGION USED TO BE CUT POSITIONALLY, AND IT WAS WRONG. It ran from
# IndexOf('function renderAccountGrid') to IndexOf('async function renderAccounts'): 9092
# characters, against a renderAccountGrid of 5814. The 3279-character over-reach swallowed
# acctRevokeSessions and acctFlagForDeletion whole. That is not a cosmetic slip -- measured
# 2026-09-02, renderAccountGrid contains **no write calls at all**, so EVERY endpoint the scan
# credited to "the grid" came from the two swallowed functions, and the anti-vacuity guard below
# ("the grid does write SOMEWHERE") was passing entirely on out-of-scope code.
# Session 38 reasoned that IndexOf..IndexOf pairs are safe because they "fail LOUDLY (negative
# length throws)". They do -- on REORDER or REMOVAL. They are silent on OVER-REACH, which is the
# case that was actually live here.
#
# The fix is to name the surface instead of guessing its extent. The account grid is four
# functions: the renderer, its wiring, and the two verbs it delegates to. Naming them means a new
# neighbour cannot silently join the scan, and a rename crashes instead of quietly narrowing it.
#
# 🪤 AND THE SCAN KNEW ONLY ONE CALL IDIOM, WHICH IS ITS OWN FAIL-OPEN. The grid has THREE
# destructive verbs, not two: revoke, flag-for-deletion, and TAP reset. The first two go through
# `api('POST', …)`; `resetAdminTap` writes with a raw `await fetch('/api/admin-tap/reset', {method:
# 'POST'})`, which the `api\(` regex below cannot see AT ALL. 📌 The proof that this was not
# intended: `$allowed` already names `/api/admin-tap/reset` -- the author expected that write to be
# found, and it never was, in the old region or the new one. A dead allow-list entry is what an
# unscanned write path looks like from the outside. Both idioms are matched now.
$gridFns = 'renderAccountGrid','wireAccountGrid','acctRevokeSessions','acctFlagForDeletion','resetAdminTap'
$gridSrc = ($gridFns | ForEach-Object { Get-PimSourceJsFunctionBody -Text $gui -Name $_ }) -join "`n"
T 'the grid region is locatable for scanning' ($gridSrc.Length -gt 0)
$gridWrites = @(
    @([regex]::Matches($gridSrc, "api\('(POST|PUT|DELETE)', '(/api/[A-Za-z0-9_/\-]+)'"))   | ForEach-Object { $_.Groups[2].Value }
    @([regex]::Matches($gridSrc, "(?s)fetch\('(/api/[A-Za-z0-9_/\-]+)'\s*,\s*\{[^}]*?method:\s*'(?:POST|PUT|DELETE)'")) | ForEach-Object { $_.Groups[1].Value }
) | Sort-Object -Unique
$allowed = @('/api/admin-sessions/revoke','/api/approvals','/api/admin-tap/reset')
$offenders = @($gridWrites | Where-Object { $allowed -notcontains $_ })
if ($offenders.Count) { Write-Host ("      (grid writes to: {0})" -f ($offenders -join ', ')) -ForegroundColor Yellow }
T 'grid writes only go to pre-existing guarded endpoints' ($offenders.Count -eq 0)
# 🪤 "not vacuous" used to mean ">= 1 write", and it passed on writes that belonged to functions
# the region had swallowed by accident. The floor is now the THREE verbs the grid actually has, so
# a scan that silently stops seeing one of them goes red instead of quietly proving less.
if ($gridWrites.Count -lt 3) { Write-Host ("      (grid writes seen: {0})" -f ($gridWrites -join ', ')) -ForegroundColor Yellow }
T 'the grid does write SOMEWHERE (the scan is not vacuous)' ($gridWrites.Count -ge 1)
T '   ...and all THREE destructive verbs are in scope, both call idioms' ($gridWrites.Count -ge 3)

# === the predicate, driven for real =========================================
Write-Host "`n-- the scoping predicate itself --" -ForegroundColor Cyan
. $portal
$mk = { param($caps, $managed) [pscustomobject]@{ capabilities = $caps; managedAdmins = $managed } }
$t = 'Admin-JDO-ID@contoso.onmicrosoft.com'
T 'no profile -> the grid would be empty'      (-not (Test-PimPortalCanManageAdmin -Profile $null -AdminName $t))
T 'assign-admin does not populate the grid'    (-not (Test-PimPortalCanManageAdmin -Profile (& $mk @('assign-admin') @('*')) -AdminName $t))
T 'manage-account + * populates it'            (Test-PimPortalCanManageAdmin -Profile (& $mk @('manage-account') @('*')) -AdminName $t)
T 'SuperAdmin always populates it'             (Test-PimPortalCanManageAdmin -Profile $null -AdminName $t -IsSuperAdmin)

Write-Host "`n RESULT: $pass pass, $fail fail" -ForegroundColor $(if ($fail) { 'Red' } else { 'Green' })
exit $(if ($fail) { 1 } else { 0 })
