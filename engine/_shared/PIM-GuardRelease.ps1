#Requires -Version 5.1
<#
.SYNOPSIS
  PIM s96.6 / framework GUARD-1.6 (operator 2026-10-06: "I need a way to release guards"): RELEASING A GUARD.

.DESCRIPTION
  A release is explicit and narrow -- there is no "turn the guard off":
    * ONE guard, ONE scope (the engine scope the guard holds), bound to the EXACT PLAN HASH it releases (SHA-256 over the
      guard id, the scope and the sorted item keys the guard held). A changed plan has a different hash and needs a new
      release.
    * ONE RUN (consumed by the first apply run that uses it) or UNTIL a time -- at most 24 h; it expires by itself.
    * SuperAdmin only, a reason of at least 10 characters, audited (AUDIT-1 'guard.release', 'guard.release.approve',
      'guard.release.revoke', and 'guard.release.used' when the engine consumes it).
    * Optional second person (framework CONFIG-1.5, PIM D5): setting 'GuardReleaseSecondPerson' { enabled } -- default OFF,
      the same model as 'ApprovalSelfApprove'. When ON a release is created PENDING and a DIFFERENT SuperAdmin approves it.

  PIM 100.119 (owner 2026-10-13): COUNTS ONLY -- no percentage in any rule or text here -- and an approval of an EXACT
  list has no ceiling (the release ceilings "50" and "25 %" are gone: what is approved is the list itself, item by item).
  A guard's limit is a count a SuperAdmin sets inside a floor and a ceiling (PIM-GuardLimits.ps1). No guard can be switched
  off. Two ways to approve what a guard holds, both for an exact list, both SuperAdmin only, both recorded:
    * AT COMMIT (the commit popup): 'GuardApprovals' -- see "Approvals given at commit" below. The removal budget and group
      deletion: the approved items are applied by the run without counting against the budget, each item ONCE.
    * AFTER THE RUN HELD IT (Operations > Guards): a release, as before, bound to the plan hash.

  What a release can do:
    engine.remove-budget      G4: the held plan is applied for that run -- exactly the plan the hash names, whatever its size.
    engine.disable-guard      G2 (row-driven account disables): the held list of accounts is disabled for that run -- exactly
                              that list. G1 (desired set resolved) and G3 (opt-in) are NOT releasable.
    engine.empty-desired      the prune of a scope whose definitions are gone runs for that run (the live items are still
                              filtered by the managed-key ledger, and G4 still caps them).
    engine.last-global-admin  PIM 100.72 (7): the held changes that would remove the last Global Administrator apply for
                              that run (PIM-LastPrivileged.ps1).
  PIM 100.72 (4): 'engine.ledger-unreadable' is no longer a guard (telemetry; the prune stays fail-closed, nothing to release).

  NEVER releasable (hard-coded, refused at creation AND at use, tested): the break-glass exclusion, an admin account
  deletion by a prune, shared workload assignments (SEC-83), groups PIM does not own (SEC-85), items that fail the s96.5
  removal rules. Those protections live in the providers and the disable selector and a release never reaches them.

  Store: pim.Settings (SQL) -- 'GuardReleases' { releases: [...] }, 'GuardHolds' { holds: [...] } and 'GuardApprovals'
  { approvals: [...]; lastStops: {...} }. The engine consumes a one-run release, and the items of an approval, with an
  atomic compare-and-set (Set-PimSqlSettingIfUnchanged) so two runs cannot both use them.
  Test seam: $global:PIM_GuardReleaseStore = @{} (setting name -> JSON text) replaces SQL.
#>

Set-StrictMode -Off

# PIM 100.119: the limit of a guard (a count inside a floor and a ceiling) -- its own file, loaded here when it is not yet.
if (-not (Get-Command Get-PimGuardLimit -ErrorAction SilentlyContinue) -and (Test-Path -LiteralPath (Join-Path $PSScriptRoot 'PIM-GuardLimits.ps1'))) { . (Join-Path $PSScriptRoot 'PIM-GuardLimits.ps1') }

function Get-PimGuardReleaseCatalog {
    <#
      PURE. EVERY guard the Guards page lists (PIM 100.119: "we need to show in Guards all guards").
        protects  what it protects, in one sentence
        what      the rule and how what it holds is approved ({limit} = the limit in effect, filled in by Get-PimGuardsView)
        release   release  = a SuperAdmin releases the held plan on the Guards page (and, for the removal budget, approves
                             the exact list in the commit popup)
                  commit   = a SuperAdmin approves the exact list in the commit popup
                  approval = approved on the Approvals page
                  info     = nothing to approve here
                  never    = LOCKED: no limit, no exemption, no approval, no switch
        locked    the reason a 'never' guard is locked (shown on its row)
      No guard has an "off".
    #>
    @(
        # PIM 100.119 (1)(2): the commit removal check is a guard again -- a SuperAdmin approves it in the commit popup.
        [pscustomobject]@{ guardId = 'manager.commit-removal'; title = 'Commit removal check'; release = 'commit'; locked = ''
            protects = 'A list in the configuration from losing many rows, or all of them, in one commit.'
            what = 'A commit is not saved until a SuperAdmin approves exactly the rows it takes out, in the commit popup, with a reason, when it (1) takes more than {limit} rows out of one list, or (2) keeps none of the rows the list has now, or (3) would leave {keep} rows or fewer of a list that has more than {minList} rows. The numbers in (2) and (3) are fixed.' }
        [pscustomobject]@{ guardId = 'engine.remove-budget'; title = 'Removal budget'; release = 'release'; locked = ''
            protects = 'Access in the tenant from being removed in bulk by one engine run.'
            what = 'At most {limit} removals per scope per run; more are held and none of them is applied. A SuperAdmin approves the exact list when it is committed (the commit popup) and the run then applies exactly those items, whatever their number; a list the run already holds is released here for exactly that plan. This covers group deletion (Lifecycle = Retire), group deletes from the Drift page, offboarding, and -- in a managed tenant -- the rows the managing tenant stopped sending (rows it withdrew by name are not counted).' }
        [pscustomobject]@{ guardId = 'engine.disable-guard'; title = 'Account-disable circuit breaker'; release = 'release'; locked = ''
            protects = 'Admin accounts from being disabled in bulk by one engine run.'
            what = 'At most {limit} accounts disabled per run; more are held and none of them is disabled. A SuperAdmin releases exactly the held list of accounts here, for one run.' }
        [pscustomobject]@{ guardId = 'engine.empty-desired'; title = 'Empty definitions'; release = 'release'; locked = ''
            protects = 'A scope whose definitions were lost from being read as "remove everything".'
            what = 'A scope whose definitions are gone is never pruned. A release lets ONE run prune it (managed items only, the removal budget still applies).' }
        # PIM 100.72 (7): removing the LAST Global Administrator does not heal -- held; released only for exactly that plan, one run.
        [pscustomobject]@{ guardId = 'engine.last-global-admin'; title = 'Last Global Administrator'; release = 'release'; locked = ''
            protects = 'The tenant from being left without a Global Administrator.'
            what = 'A change that would leave the tenant with no Global Administrator is held (the rest of the run goes ahead). Give another person Global Administrator first; a release lets ONE run apply exactly the held plan.' }
        # PIM 100.72 (4): 'engine.ledger-unreadable' is telemetry, not a guard (Get-PimNotAGuardIds) -- the prune still removes
        # nothing while the ledger cannot be read, and heals on the next run that reads it.
        # PIM 100.82 (owner 2026-10-11): many policy changes in one run HOLD again (2.4.594 only warned), weakening or not; a SuperAdmin approves.
        [pscustomobject]@{ guardId = 'engine.policy-mass-change'; title = 'Policy mass-change breaker'; release = 'approval'; locked = ''
            protects = 'The activation and assignment settings of your roles and groups from changing without a SuperAdmin having seen the change.'
            # PIM 100.93 (owner 2026-10-12: "it must still be approved as guard"): EVERY change set, whatever its size.
            what = 'Holds EVERY policy change set, whatever its size: a policy changes only from a choice made on Templates > Policy settings, and nothing is written until a SuperAdmin approves that exact change set on the Approvals page (valid 24 h). The same person may approve, as a second step.' }
        [pscustomobject]@{ guardId = 'engine.offboarding-approval'; title = 'Offboarding approval'; release = 'approval'; locked = ''
            protects = 'An admin from being disabled or offboarded on one person''s word.'
            what = 'A disable or offboarding waits for its approval on the Approvals page.' }
        # CODE REVIEW 1 FIXES 2026-10-13 (lane review1), owner decision (61): "make a guard here - only 1 admin can be deleted at
        # the time". The number is the owner's own and FIXED (not a customer setting); approval = the managing tenant's SuperAdmin.
        [pscustomobject]@{ guardId = 'msp.central-admin-delete'; title = 'Central admin delete (managed tenants)'; release = 'info'; locked = ''
            protects = 'The admins of every managed tenant from being deleted in bulk by one central decision.'
            what = 'A central admin deleted on the managing tenant is deleted in a managed tenant only when a SuperAdmin of the managing tenant approved that delete, and one approval names exactly ONE admin (an approval naming two or more is refused). A managed tenant deletes at most 1 central admin per run; a second approved one waits for the next run and stays disabled meanwhile. Without the approval the account is only disabled. The number 1 is fixed by the product owner and is not a setting.' }
        # CODE REVIEW 2 FIXES 2026-10-13 (lane review2, owner decisions 58 + 60): two numbers that were literals in the code.
        [pscustomobject]@{ guardId = 'manager.bulk-revoke'; title = 'Bulk revoke'; release = 'approval'; locked = ''
            protects = 'Active and eligible assignments from being revoked in bulk in one click.'
            what = 'A revoke of more than {limit} assignments in one batch must be confirmed with its exact count, and needs an APPROVED request on the Approvals page. The approver has permission over the assignments (scope and level) or is a SuperAdmin, and is never the person who asked.' }
        [pscustomobject]@{ guardId = 'engine.admin-delete'; title = 'Admin account deletes per run'; release = 'info'; locked = ''
            protects = 'Admin accounts from being deleted in bulk by one engine run.'
            what = 'At most {limit} admin accounts are deleted in one engine run (rows set to AccountStatus = Deleted); the rest wait for the next run. Every delete itself was approved before it was stored.' }
        # CODE REVIEW 2 FIXES 2026-10-13 (lane review2, owner decision 60): the hybrid Active Directory guards are listed
        # too ("we need to show in Guards all guards"). Their time windows are NOT counts and stay FIXED -- stated here.
        [pscustomobject]@{ guardId = 'hybrid-ad.members-kept'; title = 'AD sync keeps members on a doubt'; release = 'approval'; locked = ''
            protects = 'Members of an Active Directory group from being removed because Entra ID could not be read or confirmed.'
            what = 'When the Entra group behind an Active Directory group cannot be confirmed, its AD members are KEPT, never removed. Kept for 30 minutes = an alert, again every 4 hours until it heals (fixed times, not counts). It heals by itself when Entra ID answers; a group that is gone is decided by a SuperAdmin on Settings > Hybrid Active Directory.' }
        [pscustomobject]@{ guardId = 'hybrid-ad.waiting-for-superadmin'; title = 'AD group waits for a SuperAdmin'; release = 'approval'; locked = ''
            protects = 'An Active Directory group whose Entra group is gone, was never found or was replaced from being emptied or deleted without a person deciding.'
            what = 'The group is held and nothing is removed until a SuperAdmin decides on Settings > Hybrid Active Directory. "Gone" counts after 24 hours; the alert is sent at once and then once a day; a decision is used within 48 hours (fixed times, not counts).' }
        [pscustomobject]@{ guardId = 'hybrid-ad.cleanup.approve'; title = 'AD clean-up approval'; release = 'approval'; locked = ''
            protects = 'Groups in Active Directory from being deleted without a SuperAdmin having read the exact list.'
            what = 'An Active Directory group is deleted only from a list a SuperAdmin approved, item by item, on Settings > Hybrid Active Directory. The approval is used within 72 hours; a "delete in AD too" request waits at most 30 days (fixed times, not counts) and deletes only the exact AD object it named when it was made (same distinguished name and creation date, no new member).' }
        [pscustomobject]@{ guardId = 'hybrid-ad.server-groups.approve'; title = 'Server groups approval'; release = 'approval'; locked = ''
            protects = 'Active Directory from getting server groups created for servers nobody approved.'
            what = 'New servers wait in a list; their server groups are created only after a SuperAdmin approves that exact list on Settings > Hybrid Active Directory. The approval is used once, within 72 hours (a fixed time, not a count).' }
        [pscustomobject]@{ guardId = 'engine.reconcile-paused'; title = 'Daily reconcile paused'; release = 'info'; locked = ''
            protects = 'The tenant from the daily reconcile while somebody has paused it.'
            what = 'Resumed on the Jobs page (s96.5).' }
        [pscustomobject]@{ guardId = 'engine.break-glass'; title = 'Break-glass exclusion'; release = 'never'
            protects = 'The emergency accounts you reach for when everything else is locked out.'
            locked = 'Without a break-glass account a lockout cannot be repaired.'
            what = 'A break-glass account is never disabled, revoked or offboarded.' }
        [pscustomobject]@{ guardId = 'engine.prune-admin-delete'; title = 'Admin deletion by a prune'; release = 'never'
            protects = 'Admin accounts from being deleted by a clean-up run.'
            locked = 'A deleted account cannot be brought back by the next run.'
            what = 'A prune or reconcile never deletes an admin account; only the operator''s Delete account does.' }
        [pscustomobject]@{ guardId = 'engine.shared-workload-assignment'; title = 'Shared workload assignments (SEC-83)'; release = 'never'
            protects = 'The access of other principals that share a Defender XDR or Intune assignment with a PIM group.'
            locked = 'Removing the assignment would take away access PIM Manager does not manage.'
            what = 'A Defender XDR / Intune assignment that also holds another principal is never deleted.' }
        [pscustomobject]@{ guardId = 'engine.unowned-group'; title = 'Groups PIM does not own (SEC-85)'; release = 'never'
            protects = 'The members of groups PIM Manager does not manage.'
            locked = 'PIM Manager only changes what it defines.'
            what = 'Memberships in groups PIM does not manage are never removed.' }
        [pscustomobject]@{ guardId = 'engine.reconcile-unproven'; title = 'Removal rules of the reconcile (96.5)'; release = 'never'
            protects = 'Access PIM Manager cannot prove it created.'
            locked = 'An item nobody defined here is never PIM Manager''s to remove.'
            what = 'An item PIM did not define, did not make live, or did not remove is never removed.' }
        # PIM 100.72 (7): with no SuperAdmin left nobody could release, approve or undo it -- never releasable.
        [pscustomobject]@{ guardId = 'manager.last-superadmin'; title = 'Last PIM Manager SuperAdmin'; release = 'never'
            protects = 'The last person who can approve, release and undo in PIM Manager.'
            locked = 'With no SuperAdmin left nobody could approve anything again.'
            what = 'The Manager access map never ends without a SuperAdmin. Add another SuperAdmin first.' }
    )
}

function Get-PimGuardNeverReleasable {
    <# PURE. The guard ids no release can ever cover -- a literal list, not derived, so a catalog edit cannot widen it. #>
    @('engine.break-glass', 'engine.prune-admin-delete', 'engine.shared-workload-assignment', 'engine.unowned-group', 'engine.reconcile-unproven', 'manager.last-superadmin')
}

function Test-PimGuardReleasable {
    <# PURE. @{ ok; reason } -- only the engine guards with release = 'release' may be released (remove-budget, disable-guard,
       empty-desired, last-global-admin). #>
    param([string]$GuardId)
    $id = "$GuardId".Trim().ToLowerInvariant()
    if (-not $id) { return [pscustomobject]@{ ok = $false; reason = 'no guard named' } }
    if ($id -in @(Get-PimGuardNeverReleasable)) { return [pscustomobject]@{ ok = $false; reason = "the guard '$id' is NEVER releasable" } }
    $c = @(Get-PimGuardReleaseCatalog | Where-Object { $_.guardId -eq $id })
    if (-not $c.Count) { return [pscustomobject]@{ ok = $false; reason = "unknown guard '$id'" } }
    if ($c[0].release -eq 'approval') { return [pscustomobject]@{ ok = $false; reason = "'$id' is released through its own approval (Approvals page), not here" } }
    if ($c[0].release -eq 'commit') { return [pscustomobject]@{ ok = $false; reason = "'$id' is approved by a SuperAdmin in the commit popup, not here" } }
    if ($c[0].release -ne 'release') { return [pscustomobject]@{ ok = $false; reason = "'$id' has no release" } }
    return [pscustomobject]@{ ok = $true; reason = '' }
}

function Get-PimGuardHoldItemCap {
    <# PURE. LITERAL. CODE REVIEW 2 FIXES 2026-10-13 (owner decision 60: "no 500-item release cap"): a hold record carries
       its WHOLE list, whatever its size (pim.Settings.ValueJson is NVARCHAR(MAX)), so a SuperAdmin release works for any
       size. This number is no longer a cap: it is only the size an OLDER version cut a list at -- a hold that older
       version wrote with itemsTruncated is still not releasable, and the next run records the list in full. #>
    500
}

function Get-PimGuardReleaseLifetimeHours {
    <# PURE. LITERAL. The longest a release lasts (one-run that no run used, or "until"): 24 h. #>
    24
}

function Get-PimGuardClockSkewMinutes {
    <# PURE. LITERAL. How far in the future a record's creation time may lie before it is not believed: 5 minutes. #>
    5
}

function Test-PimGuardRecordWindow {
    <#
      PURE (PIM 100.119 B2). Do the times of an approval / release record make sense? $true only when
        * -StartUtc (created / approved) is there, parses, and is not later than now + the clock skew (5 minutes), and
        * -ExpiresUtc parses and is not later than that start + the literal lifetime of the record's kind.
      Anything else -- no start, a start "tomorrow", an end in 2099 -- is $false, and the record is never usable.
    #>
    param([AllowNull()][object]$StartUtc, [AllowNull()][object]$ExpiresUtc, [Parameter(Mandatory)][int]$LifetimeHours, [datetime]$NowUtc = [datetime]::UtcNow)
    $s = ConvertTo-PimGuardUtc $StartUtc
    $e = ConvertTo-PimGuardUtc $ExpiresUtc
    if (-not $s -or -not $e) { return $false }
    if ($s -gt $NowUtc.ToUniversalTime().AddMinutes([int](Get-PimGuardClockSkewMinutes))) { return $false }
    if ($e -gt $s.AddHours($LifetimeHours)) { return $false }
    return $true
}

function Get-PimGuardApprovalLifetimeHours {
    <# PURE. LITERAL. How long an approval given at commit stays usable when no run has applied it: 48 h. Group deletion
       is applied by the DAILY full run only, so 24 h (the policy change-set lifetime) could end minutes before the run
       that should use it; 48 h always covers one daily run and the one after a failed run. #>
    48
}

function Get-PimGuardPlanHash {
    <#
      PURE. SHA-256 (lower-case hex) over 'guard|<id>', 'scope|<scope>' and the item keys (lower-case, trimmed, de-duplicated,
      ordinally sorted), joined with LF. Same items in any order = the same hash; one item more, less or different = another.
    #>
    param([Parameter(Mandatory)][string]$GuardId, [string]$Scope = '', [AllowNull()][AllowEmptyCollection()][string[]]$Keys = @())
    $k = New-Object System.Collections.Generic.List[string]
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    foreach ($x in @($Keys)) { $s = "$x".Trim().ToLowerInvariant(); if ($s -and $seen.Add($s)) { $k.Add($s) } }
    $arr = $k.ToArray(); [Array]::Sort($arr, [StringComparer]::Ordinal)
    $lines = @("guard|$("$GuardId".Trim().ToLowerInvariant())", "scope|$("$Scope".Trim().ToLowerInvariant())") + @($arr)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { $bytes = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes(($lines -join "`n"))) } finally { $sha.Dispose() }
    -join ($bytes | ForEach-Object { $_.ToString('x2') })
}

function ConvertTo-PimGuardUtc {
    <# PURE. A date (string / datetime) as UTC, or $null when it does not parse. #>
    param([AllowNull()][object]$Value)
    if ($null -eq $Value -or "$Value".Trim() -eq '') { return $null }
    if ($Value -is [datetime]) { return $Value.ToUniversalTime() }
    try { return ([datetimeoffset]::Parse("$Value", [Globalization.CultureInfo]::InvariantCulture)).UtcDateTime } catch { return $null }
}

function Get-PimGuardReleaseState {
    <# PURE. pending | active | consumed | revoked | expired -- the state a record is in at -NowUtc. #>
    param([Parameter(Mandatory)][object]$Release, [datetime]$NowUtc = [datetime]::UtcNow)
    $st = "$($Release.status)".Trim().ToLowerInvariant()
    if ($st -in @('consumed', 'revoked')) { return $st }
    $exp = ConvertTo-PimGuardUtc $Release.expiresUtc
    if (-not $exp -or $NowUtc.ToUniversalTime() -ge $exp) { return 'expired' }
    # PIM 100.119 B2: a record is usable only when its own times make sense -- a hand-written or restored record with an
    # end in 2099, no creation time, or one "created tomorrow" is expired, never usable.
    if (-not (Test-PimGuardRecordWindow -StartUtc $Release.createdUtc -ExpiresUtc $Release.expiresUtc -LifetimeHours (Get-PimGuardReleaseLifetimeHours) -NowUtc $NowUtc)) { return 'expired' }
    if (-not "$($Release.id)".Trim() -or -not "$($Release.createdBy)".Trim()) { return 'expired' }
    if ($st -eq 'pending') { return 'pending' }
    if ($st -eq 'active') { return 'active' }
    return 'expired'   # an unknown status is never usable
}

function New-PimGuardRelease {
    <#
      PURE. A new release record for the CURRENT hold of one guard + scope. THROWS 'REFUSED -- ...' on every rule it breaks:
      SuperAdmin, a releasable guard, a reason (>= 10 characters), a 64-hex plan hash EQUAL to the hold's, one-run or until
      (until in the future, at most 24 h), and a hold that carries its WHOLE list (PIM 100.119: the release is for exactly
      the list the SuperAdmin can read; there is no count ceiling and no percentage).
    #>
    param([Parameter(Mandatory)][string]$GuardId, [string]$Scope = '', [Parameter(Mandatory)][string]$PlanHash, [AllowNull()][object]$Hold,
          [ValidateSet('one-run', 'until')][string]$Mode = 'one-run', [AllowNull()][object]$UntilUtc, [string]$Reason = '',
          [Parameter(Mandatory)][string]$By, [string]$Role = '', [bool]$SecondPerson = $false, [datetime]$NowUtc = [datetime]::UtcNow)
    $now = $NowUtc.ToUniversalTime()
    if (-not (Test-PimGuardSuperAdminRole -Role $Role)) { throw 'REFUSED -- only a SuperAdmin may release a guard.' }   # B4: the one role rule
    if (-not "$By".Trim() -or "$By".Trim() -eq '<unauthenticated>') { throw 'REFUSED -- the releasing person is unknown.' }
    $id = "$GuardId".Trim().ToLowerInvariant()
    $rl = Test-PimGuardReleasable -GuardId $id
    if (-not $rl.ok) { throw "REFUSED -- $($rl.reason)." }
    if ("$Reason".Trim().Length -lt 10) { throw 'REFUSED -- a reason of at least 10 characters is required.' }
    $h = "$PlanHash".Trim().ToLowerInvariant()
    if ($h -notmatch '^[0-9a-f]{64}$') { throw "REFUSED -- '$PlanHash' is not a plan hash (64 hex characters)." }
    if (-not $Hold) { throw "REFUSED -- '$id' holds nothing in '$Scope' right now; a release covers a held plan, never a future one." }
    if ("$($Hold.guardId)".Trim().ToLowerInvariant() -ne $id -or "$($Hold.scope)".Trim().ToLowerInvariant() -ne "$Scope".Trim().ToLowerInvariant()) {
        throw 'REFUSED -- the hold is for another guard or scope.'
    }
    if ("$($Hold.planHash)".Trim().ToLowerInvariant() -ne $h) {
        throw "REFUSED -- plan hash $h does not match what the guard holds now ($($Hold.planHash)). The plan changed: review it and release the current one."
    }
    $count = 0; [void][int]::TryParse("$($Hold.count)", [ref]$count)
    # PIM 100.119: no ceiling on an exact list -- but the list must BE exact: a hold whose item list had to be cut cannot
    # be read in full on the page, so it is not released there.
    if ($Hold.PSObject.Properties['itemsTruncated'] -and $Hold.itemsTruncated) {
        throw ("REFUSED -- the held plan has {0} item(s), and an older version recorded only the first {1} of them, so it cannot be read item by item here. The next run records the whole list; release it then (or approve the list when it is committed)." -f $count, (Get-PimGuardHoldItemCap))
    }
    $max = $now.AddHours(24)
    if ($Mode -eq 'until') {
        $u = ConvertTo-PimGuardUtc $UntilUtc
        if (-not $u) { throw 'REFUSED -- an "until" release needs a valid end time.' }
        if ($u -le $now) { throw 'REFUSED -- the end time is in the past.' }
        if ($u -gt $max.AddMinutes(1)) { throw 'REFUSED -- a release lasts at most 24 hours.' }
        if ($u -gt $max) { $u = $max }
        $exp = $u
    } else { $exp = $max }   # a one-run release that no run used also ends after 24 h
    [pscustomobject][ordered]@{
        id = [guid]::NewGuid().ToString(); guardId = $id; scope = "$Scope".Trim(); planHash = $h; mode = $Mode
        raiseTo = $count; createdBy = "$By".Trim(); createdUtc = $now.ToString('o'); reason = "$Reason".Trim()
        expiresUtc = $exp.ToString('o'); status = $(if ($SecondPerson) { 'pending' } else { 'active' }); secondPerson = [bool]$SecondPerson
        approvedBy = ''; approvedUtc = ''; consumedUtc = ''; consumedBy = ''; revokedBy = ''; revokedUtc = ''; usedCount = 0
    }
}

function Approve-PimGuardRelease {
    <# PURE. The second person approves a PENDING release. THROWS: not SuperAdmin, the same person, not pending (or expired). #>
    param([Parameter(Mandatory)][object]$Release, [Parameter(Mandatory)][string]$By, [string]$Role = '', [datetime]$NowUtc = [datetime]::UtcNow)
    if (-not (Test-PimGuardSuperAdminRole -Role $Role)) { throw 'REFUSED -- only a SuperAdmin may approve a guard release.' }
    if ("$By".Trim() -ieq "$($Release.createdBy)".Trim()) { throw 'REFUSED -- the second person must be a different SuperAdmin than the one who released it.' }
    $st = Get-PimGuardReleaseState -Release $Release -NowUtc $NowUtc
    if ($st -ne 'pending') { throw "REFUSED -- the release is $st, not waiting for approval." }
    $r = [pscustomobject]@{}; foreach ($p in $Release.PSObject.Properties) { $r | Add-Member -NotePropertyName $p.Name -NotePropertyValue $p.Value }
    $r.status = 'active'; $r.approvedBy = "$By".Trim(); $r.approvedUtc = $NowUtc.ToUniversalTime().ToString('o')
    $r
}

function Revoke-PimGuardRelease {
    <# PURE. End a pending / active release now. THROWS: not SuperAdmin, already ended. #>
    param([Parameter(Mandatory)][object]$Release, [Parameter(Mandatory)][string]$By, [string]$Role = '', [datetime]$NowUtc = [datetime]::UtcNow)
    if (-not (Test-PimGuardSuperAdminRole -Role $Role)) { throw 'REFUSED -- only a SuperAdmin may revoke a guard release.' }
    $st = Get-PimGuardReleaseState -Release $Release -NowUtc $NowUtc
    if ($st -notin @('pending', 'active')) { throw "REFUSED -- the release is already $st." }
    $r = [pscustomobject]@{}; foreach ($p in $Release.PSObject.Properties) { $r | Add-Member -NotePropertyName $p.Name -NotePropertyValue $p.Value }
    $r.status = 'revoked'; $r.revokedBy = "$By".Trim(); $r.revokedUtc = $NowUtc.ToUniversalTime().ToString('o')
    $r
}

function Test-PimGuardReleaseCovers {
    <# PURE. Does an ACTIVE release cover what this run asks for? The release is bound to the plan hash (the exact list);
       the count it was given for (raiseTo) must cover the request as well -- a record whose count is smaller than the plan
       it names is not used. PIM 100.119: no ceiling, no percentage. #>
    param([Parameter(Mandatory)][object]$Release, [int]$Requested = 0)
    if ("$($Release.guardId)".Trim().ToLowerInvariant() -in @('engine.remove-budget', 'engine.disable-guard')) {
        $raise = 0; [void][int]::TryParse("$($Release.raiseTo)", [ref]$raise)
        if ($Requested -gt $raise) { return $false }
    }
    return $true
}

function Find-PimGuardRelease {
    <#
      PURE. The first ACTIVE release of -GuardId for -Scope bound to exactly -PlanHash, or $null. A never-releasable guard
      returns $null whatever the store holds (a hand-written record cannot open it).
    #>
    param([AllowNull()][object[]]$Releases, [Parameter(Mandatory)][string]$GuardId, [string]$Scope = '', [Parameter(Mandatory)][string]$PlanHash,
          [datetime]$NowUtc = [datetime]::UtcNow)
    $id = "$GuardId".Trim().ToLowerInvariant()
    if (-not (Test-PimGuardReleasable -GuardId $id).ok) { return $null }
    $h = "$PlanHash".Trim().ToLowerInvariant(); if ($h -notmatch '^[0-9a-f]{64}$') { return $null }
    $sc = "$Scope".Trim().ToLowerInvariant()
    foreach ($r in @($Releases)) {
        if ($null -eq $r) { continue }
        if ("$($r.guardId)".Trim().ToLowerInvariant() -ne $id) { continue }
        if ("$($r.scope)".Trim().ToLowerInvariant() -ne $sc) { continue }
        if ("$($r.planHash)".Trim().ToLowerInvariant() -ne $h) { continue }
        if ((Get-PimGuardReleaseState -Release $r -NowUtc $NowUtc) -ne 'active') { continue }
        return $r
    }
    return $null
}

function Compress-PimGuardReleases {
    <# PURE. Drop records that ENDED more than -KeepDays (7) ago -- the audit keeps the history. #>
    param([AllowNull()][object[]]$Releases, [datetime]$NowUtc = [datetime]::UtcNow, [int]$KeepDays = 7)
    $cut = $NowUtc.ToUniversalTime().AddDays(-1 * [Math]::Max(1, $KeepDays))
    @(@($Releases) | Where-Object {
        if ($null -eq $_) { return $false }
        $st = Get-PimGuardReleaseState -Release $_ -NowUtc $NowUtc
        if ($st -in @('pending', 'active')) { return $true }
        $end = ConvertTo-PimGuardUtc $(if ("$($_.consumedUtc)") { $_.consumedUtc } elseif ("$($_.revokedUtc)") { $_.revokedUtc } else { $_.expiresUtc })
        return ($end -and $end -ge $cut)
    })
}

# ------------------------------------------------------------------------------------------------------------------------
# Store access (pim.Settings). Readers return $null / @() when there is no store; the engine-facing writers NEVER throw.
# ------------------------------------------------------------------------------------------------------------------------
function Get-PimGuardStoreCs {
    try { if (Get-Command Get-PimManagerSettingCs -ErrorAction SilentlyContinue) { $c = Get-PimManagerSettingCs; if ("$c".Trim()) { return "$c" } } } catch { }
    if ("$($global:PIM_EngineSqlCs)".Trim()) { return "$($global:PIM_EngineSqlCs)" }
    if (Get-Command Get-PimSqlSettingsConnectionString -ErrorAction SilentlyContinue) { try { $c = Get-PimSqlSettingsConnectionString; if ("$c".Trim()) { return "$c" } } catch { } }
    return $null
}

function Get-PimGuardStoreText {
    <# The setting's JSON text exactly as stored, or $null. THROWS only when a configured store fails. #>
    param([Parameter(Mandatory)][string]$Name)
    if ($global:PIM_GuardReleaseStore -is [hashtable]) { $v = $global:PIM_GuardReleaseStore[$Name]; if ($null -eq $v) { return $null }; return "$v" }
    $cs = Get-PimGuardStoreCs
    if ($cs -and (Get-Command Get-PimSqlSettingRaw -ErrorAction SilentlyContinue)) { return (Get-PimSqlSettingRaw -ConnectionString $cs -Name $Name) }
    if (Get-Command Get-PimSetting -ErrorAction SilentlyContinue) {
        $v = Get-PimSetting -Name $Name
        if ($null -eq $v) { return $null }
        if ($v -is [string]) { return $v }
        return (ConvertTo-Json -InputObject $v -Depth 10 -Compress)
    }
    return $null
}

function Set-PimGuardStoreText {
    <#
      Write the setting. -Expected given (CAS) = only if the stored text is still exactly that; returns 1 written / 0 lost.
      THROWS when there is no store or the store rejects the write (the Manager reports it; the engine catches it).
    #>
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][string]$Json, [AllowNull()][string]$Expected, [switch]$Cas)
    if ($global:PIM_GuardReleaseStore -is [hashtable]) {
        if ($Cas) { $cur = $global:PIM_GuardReleaseStore[$Name]; if ("$cur" -cne "$Expected") { return 0 } }
        $global:PIM_GuardReleaseStore[$Name] = $Json; return 1
    }
    $cs = Get-PimGuardStoreCs
    if ($cs -and $Cas -and (Get-Command Set-PimSqlSettingIfUnchanged -ErrorAction SilentlyContinue)) {
        return [int](Set-PimSqlSettingIfUnchanged -ConnectionString $cs -Name $Name -NewValueJson $Json -ExpectedValueJson $Expected)
    }
    if ($cs -and (Get-Command Set-PimSqlSetting -ErrorAction SilentlyContinue)) { Set-PimSqlSetting -ConnectionString $cs -Name $Name -ValueJson $Json; return 1 }
    if (Get-Command Set-PimSetting -ErrorAction SilentlyContinue) { [void](Set-PimSetting -Name $Name -Value ($Json | ConvertFrom-Json)); return 1 }
    throw "no settings store to write '$Name' to"
}

function ConvertFrom-PimGuardList {
    <# PURE. { <Prop>: [...] } JSON text (or an object) -> the array. #>
    param([AllowNull()][object]$Value, [Parameter(Mandatory)][string]$Prop)
    if ($null -eq $Value -or "$Value".Trim() -eq '') { return @() }
    $o = $Value; if ($Value -is [string]) { try { $o = $Value | ConvertFrom-Json } catch { return @() } }
    if ($o -and $o.PSObject.Properties[$Prop]) { return @(@($o.$Prop) | Where-Object { $null -ne $_ }) }
    return @()
}

function Get-PimGuardReleases {
    <# Every stored release record (raw). @() when there is none or no store. #>
    $t = $null; try { $t = Get-PimGuardStoreText -Name 'GuardReleases' } catch { return @() }
    return @(ConvertFrom-PimGuardList -Value $t -Prop 'releases')
}

function Save-PimGuardReleases {
    <#
      Write the list (compressed). THROWS on a store failure -- the Manager must never claim a release it did not store.
      -Cas -ExpectedText <what was read>: only if nobody (an engine run consuming a release) changed it since; returns 1 / 0.
    #>
    param([AllowNull()][object[]]$Releases, [datetime]$NowUtc = [datetime]::UtcNow, [AllowNull()][string]$ExpectedText, [switch]$Cas)
    $keep = @(Compress-PimGuardReleases -Releases $Releases -NowUtc $NowUtc)
    $json = ConvertTo-Json -InputObject ([ordered]@{ releases = $keep }) -Depth 8 -Compress
    if ($Cas) { return [int](Set-PimGuardStoreText -Name 'GuardReleases' -Json $json -Expected $ExpectedText -Cas) }
    return [int](Set-PimGuardStoreText -Name 'GuardReleases' -Json $json)
}

function Get-PimGuardHolds {
    <#
      Every current hold (guardId, scope, planHash, count, items, ...). @() when none / no store.
      The engine asks once per scope, so the SQL read is cached for 30 s per process, and a store that failed is not asked
      again for 5 minutes (a hold is a display aid; the release itself is always read fresh by Use-PimGuardRelease).
    #>
    param([switch]$Fresh)
    if ($global:PIM_GuardReleaseStore -is [hashtable]) { return @(ConvertFrom-PimGuardList -Value $global:PIM_GuardReleaseStore['GuardHolds'] -Prop 'holds') }
    $now = [datetime]::UtcNow
    if (-not $Fresh -and $global:PIM_GuardStoreDownUntil -is [datetime] -and $now -lt $global:PIM_GuardStoreDownUntil) { return @() }
    $c = $global:PIM_GuardHoldsCache
    if (-not $Fresh -and $c -is [hashtable] -and $c['at'] -is [datetime] -and ($now - $c['at']).TotalSeconds -lt 30) { return @(ConvertFrom-PimGuardList -Value $c['text'] -Prop 'holds') }
    $t = $null
    # -Fresh (a writer, or the Manager page) THROWS on a store failure: a writer that read "no holds" from a failed store
    # would overwrite every other hold with its own one.
    try { $t = Get-PimGuardStoreText -Name 'GuardHolds' } catch { $global:PIM_GuardStoreDownUntil = $now.AddMinutes(5); if ($Fresh) { throw }; return @() }
    $global:PIM_GuardHoldsCache = @{ at = $now; text = $t }
    return @(ConvertFrom-PimGuardList -Value $t -Prop 'holds')
}

function Save-PimGuardHoldList {
    <# Write the hold list and refresh the cache. THROWS on a store failure (callers catch). #>
    param([AllowNull()][object[]]$Holds)
    $json = ConvertTo-Json -InputObject ([ordered]@{ holds = @($Holds) }) -Depth 8 -Compress
    [void](Set-PimGuardStoreText -Name 'GuardHolds' -Json $json)
    $global:PIM_GuardHoldsCache = @{ at = [datetime]::UtcNow; text = $json }
}

function Get-PimGuardHold {
    <# PURE over a list. The hold of one guard + scope, or $null. #>
    param([AllowNull()][object[]]$Holds, [string]$GuardId, [string]$Scope = '')
    $id = "$GuardId".Trim().ToLowerInvariant(); $sc = "$Scope".Trim().ToLowerInvariant()
    foreach ($h in @($Holds)) { if ($h -and "$($h.guardId)".Trim().ToLowerInvariant() -eq $id -and "$($h.scope)".Trim().ToLowerInvariant() -eq $sc) { return $h } }
    return $null
}

function Update-PimGuardHoldList {
    <# PURE. The hold list with one hold set (-Hold) or cleared (-Clear for -GuardId/-Scope[/-RunKind]). @{ holds; changed }. #>
    param([AllowNull()][object[]]$Holds, [AllowNull()][object]$Hold, [string]$GuardId = '', [string]$Scope = '', [string]$RunKind = '', [switch]$Clear)
    $id = if ($Hold) { "$($Hold.guardId)".Trim().ToLowerInvariant() } else { "$GuardId".Trim().ToLowerInvariant() }
    $sc = if ($Hold) { "$($Hold.scope)".Trim().ToLowerInvariant() } else { "$Scope".Trim().ToLowerInvariant() }
    $out = New-Object System.Collections.Generic.List[object]; $changed = $false; $old = $null
    foreach ($h in @($Holds)) {
        if ($null -eq $h) { continue }
        if ("$($h.guardId)".Trim().ToLowerInvariant() -eq $id -and "$($h.scope)".Trim().ToLowerInvariant() -eq $sc) {
            if ($Clear -and $RunKind -and "$($h.runKind)" -and "$($h.runKind)" -ne $RunKind) { $out.Add($h); continue }   # another kind of run holds it
            $old = $h; $changed = $true; continue
        }
        $out.Add($h)
    }
    if (-not $Clear -and $Hold) {
        if ($old -and "$($old.firstSeenUtc)" -and "$($old.planHash)" -eq "$($Hold.planHash)") { $Hold.firstSeenUtc = "$($old.firstSeenUtc)" }
        $out.Add($Hold); $changed = $true
        if ($old -and (ConvertTo-Json -InputObject $old -Depth 6 -Compress) -eq (ConvertTo-Json -InputObject $Hold -Depth 6 -Compress)) { $changed = $false }
    }
    return @{ holds = $out.ToArray(); changed = $changed }
}

function Set-PimGuardHold {
    <# Engine: record what a guard holds now (the Guards page offers its release). NEVER throws; no store = no-op. #>
    param([Parameter(Mandatory)][object]$Hold)
    try {
        $all = @(Get-PimGuardHolds -Fresh)
        $u = Update-PimGuardHoldList -Holds $all -Hold $Hold
        if ($u.changed) { Save-PimGuardHoldList -Holds @($u.holds) }
        return $true
    } catch { return $false }
}

function Clear-PimGuardHold {
    <# Engine: the guard no longer holds this scope (for this kind of run). NEVER throws; no store / no hold = no write. #>
    param([Parameter(Mandatory)][string]$GuardId, [string]$Scope = '', [string]$RunKind = '')
    try {
        $all = @(Get-PimGuardHolds)
        if (-not $all.Count) { return $false }
        if (-not (Get-PimGuardHold -Holds $all -GuardId $GuardId -Scope $Scope)) { return $false }
        $all = @(Get-PimGuardHolds -Fresh)
        $u = Update-PimGuardHoldList -Holds $all -GuardId $GuardId -Scope $Scope -RunKind $RunKind -Clear
        if ($u.changed) { Save-PimGuardHoldList -Holds @($u.holds) }
        return [bool]$u.changed
    } catch { return $false }
}

function Use-PimGuardRelease {
    <#
      Engine: is this exact plan released? Returns the release record (and, for a ONE-RUN release, marks it consumed by an
      atomic compare-and-set first -- a run that loses the race does not get it), or $null. NEVER throws.
      A release that does not cover -Requested is not used (and not consumed).
    #>
    param([Parameter(Mandatory)][string]$GuardId, [string]$Scope = '', [Parameter(Mandatory)][string]$PlanHash,
          [int]$Requested = 0, [string]$RunKind = '', [datetime]$NowUtc = [datetime]::UtcNow)
    try {
        for ($try = 0; $try -lt 3; $try++) {
            $text = Get-PimGuardStoreText -Name 'GuardReleases'
            $all = @(ConvertFrom-PimGuardList -Value $text -Prop 'releases')
            $rel = Find-PimGuardRelease -Releases $all -GuardId $GuardId -Scope $Scope -PlanHash $PlanHash -NowUtc $NowUtc
            if (-not $rel) { return $null }
            if (-not (Test-PimGuardReleaseCovers -Release $rel -Requested $Requested)) { return $null }
            $now = $NowUtc.ToUniversalTime().ToString('o')
            $used = 0; [void][int]::TryParse("$($rel.usedCount)", [ref]$used)
            $new = foreach ($r in $all) {
                if ("$($r.id)" -eq "$($rel.id)") {
                    $c = [pscustomobject]@{}; foreach ($p in $r.PSObject.Properties) { $c | Add-Member -NotePropertyName $p.Name -NotePropertyValue $p.Value }
                    if (-not $c.PSObject.Properties['usedCount']) { $c | Add-Member -NotePropertyName usedCount -NotePropertyValue 0 }
                    if (-not $c.PSObject.Properties['consumedUtc']) { $c | Add-Member -NotePropertyName consumedUtc -NotePropertyValue '' }
                    if (-not $c.PSObject.Properties['consumedBy']) { $c | Add-Member -NotePropertyName consumedBy -NotePropertyValue '' }
                    $c.usedCount = $used + 1
                    if ("$($r.mode)" -ne 'until') { $c.status = 'consumed'; $c.consumedUtc = $now; $c.consumedBy = "engine $RunKind".Trim() }
                    $c
                } else { $r }
            }
            $json = ConvertTo-Json -InputObject ([ordered]@{ releases = @($new) }) -Depth 8 -Compress
            $w = Set-PimGuardStoreText -Name 'GuardReleases' -Json $json -Expected $text -Cas
            if ([int]$w -ne 1) { continue }   # another run changed the list: read again
            try {
                if (Get-Command Write-PimAuditEvent -ErrorAction SilentlyContinue) {
                    Write-PimAuditEvent -Action 'guard.release.used' -Target "$($rel.guardId)" -After @{ releaseId = "$($rel.id)"; scope = "$($rel.scope)"; planHash = "$($rel.planHash)"; mode = "$($rel.mode)"; requested = $Requested; releasedBy = "$($rel.createdBy)"; approvedBy = "$($rel.approvedBy)"; run = $RunKind } | Out-Null
                }
            } catch { }
            return $rel
        }
        Write-Warning "[guard] $GuardId ${Scope}: the release could not be consumed (the store kept changing) -- the guard holds this run."
        return $null
    } catch {
        Write-Warning "[guard] $GuardId ${Scope}: releases could not be read ($($_.Exception.Message)) -- the guard holds this run."
        return $null
    }
}

function Invoke-PimGuardHoldOrRelease {
    <#
      Engine: a RELEASABLE guard tripped on a run that writes. Hash the plan, use a matching release, or record the hold so the
      Guards page can show it and offer its release. NEVER throws. Returns @{ released; release; planHash }.
      -WhatIf (a plan): never uses a release and records nothing.
    #>
    param([Parameter(Mandatory)][string]$GuardId, [string]$Scope = '', [AllowNull()][AllowEmptyCollection()][string[]]$Keys = @(),
          [int]$Count = 0, [AllowNull()][object]$Measured, [string]$RunKind = '', [switch]$WhatIf,
          [switch]$NoHold, [datetime]$NowUtc = [datetime]::UtcNow)
    $res = [pscustomobject]@{ released = $false; release = $null; planHash = '' }
    try {
        $res.planHash = Get-PimGuardPlanHash -GuardId $GuardId -Scope $Scope -Keys @($Keys)
        if ($WhatIf) { return $res }
        $rel = Use-PimGuardRelease -GuardId $GuardId -Scope $Scope -PlanHash $res.planHash -Requested $Count -RunKind $RunKind -NowUtc $NowUtc
        if ($rel) {
            $res.released = $true; $res.release = $rel
            [void](Clear-PimGuardHold -GuardId $GuardId -Scope $Scope)
            try { Write-Host ("[engine] {0}: guard {1} RELEASED for this run by {2}{3} (plan {4}, {5}): {6}" -f $Scope, $GuardId, $rel.createdBy, $(if ("$($rel.approvedBy)") { " + $($rel.approvedBy)" } else { '' }), $res.planHash.Substring(0, 12), $rel.mode, $rel.reason) -ForegroundColor Magenta } catch { }
            return $res
        }
        if (-not $NoHold) {
            # CODE REVIEW 2 FIXES 2026-10-13 (owner decision 60): the WHOLE list, whatever its size -- it was cut at 500, and
            # a cut hold could never be released. A release is for a list that can be read item by item.
            $allKeys = @(@($Keys) | Where-Object { "$_".Trim() } | ForEach-Object { "$_" })
            $hold = [pscustomobject][ordered]@{ guardId = "$GuardId".Trim().ToLowerInvariant(); scope = "$Scope".Trim(); planHash = $res.planHash; count = $Count
                items = @($allKeys); itemsTruncated = $false
                measured = $Measured; runKind = $RunKind; firstSeenUtc = $NowUtc.ToUniversalTime().ToString('o'); lastSeenUtc = $NowUtc.ToUniversalTime().ToString('o') }
            [void](Set-PimGuardHold -Hold $hold)
        }
    } catch { }
    return $res
}

function Resolve-PimRemoveBudgetRelease {
    <#
      Engine, G4 (BUG-291). Called with the removal-budget decision of a scope on a run that writes. NEVER throws.
        allowed decision  -> the hold of this scope (same kind of run) is cleared; returns $null.
        tripped decision  -> the plan (every remove and type-change key) is hashed; a matching ACTIVE release lets THIS run
                             apply exactly that plan, whatever its size (PIM 100.119: no ceiling), and is consumed
                             (one-run); returns @{ decision (allowed); used }. No release -> the hold is recorded; $null.
    #>
    param([Parameter(Mandatory)][object]$Decision, [string]$Scope = '', [object[]]$Remove = @(), [object[]]$Retype = @(), [int]$Scanned = 0, [string]$RunKind = '')
    try {
        if ($Decision.allowed) { [void](Clear-PimGuardHold -GuardId 'engine.remove-budget' -Scope $Scope -RunKind $RunKind); return $null }
        $keys = @(@(@($Remove) | Where-Object { $_ } | ForEach-Object { "remove|$($_.key)" }) + @(@($Retype) | Where-Object { $_ } | ForEach-Object { "retype|$($_.key)" }))
        $n = $keys.Count
        $g = Invoke-PimGuardHoldOrRelease -GuardId 'engine.remove-budget' -Scope $Scope -Keys $keys -Count $n -RunKind $RunKind `
                -Measured @{ toRemove = $n; budget = [int]$Decision.budget; scanned = $Scanned }
        if (-not $g.released) { return $null }
        $lim = [int]$g.release.raiseTo
        if ($n -gt $lim) { return $null }
        try { Write-Host ("[engine] {0,-20} removal budget: the released plan goes ahead for this run -- exactly these {1} removal(s)" -f $Scope, $n) -ForegroundColor Magenta } catch { }
        return [pscustomobject]@{
            decision = [pscustomobject]@{ allowed = $true; abort = $false; tripped = $null; reason = 'released for this run'; toRemove = $n; budget = $lim; scope = $Scope; operation = 'remove'; scanned = $Scanned }
            used = [pscustomobject]@{ guardId = 'engine.remove-budget'; releaseId = "$($g.release.id)"; planHash = $g.planHash } }
    } catch { return $null }
}

# ------------------------------------------------------------------------------------------------------------------------
# PIM 100.119: APPROVALS GIVEN AT COMMIT (owner 2026-10-13: "we need an easy way for a super admin to accept a guard in the
# popup ... and APPROVE it" / "approve at commit ... that EXACT list once").
#
# A SuperAdmin approves, in the commit popup, the exact list a guard would stop:
#   manager.commit-removal   the rows the commit takes out of one list. Used by that commit itself; kept as the record.
#   engine.remove-budget     the removals (rows marked Action = Remove) of one list, and group deletions (Lifecycle =
#                            Retire), that are more than one run may apply. The run applies exactly the approved ITEMS
#                            without counting them against the budget -- any number; every item ONCE; anything that is not
#                            in the list is judged against the budget as always.
# THE IDENTITY OF AN ITEM (Get-PimGuardItemId) is what both sides can compute from the stored row alone:
#   remove|<list>|<the row's store key>            the store key is the columns that NAME the delegation
#   delete-group|<list>|<the row's store key>|<group name>
# Only lists whose store key names exactly what is removed can be approved this way (Get-PimGuardApprovableEntities, a
# literal list); every other list keeps the release of the held plan on the Guards page. A row the MANAGING tenant sent
# (Owner set, not Local) has no identity here: a managed tenant's SuperAdmin cannot approve it.
# NEVER-RELEASABLE guards take no approval: refused at creation and ignored at use, as for a release.
# Store: pim.Settings 'GuardApprovals' { approvals: [...]; lastStops: { <guardId>: { atUtc; by; base; count; limit } } }.
# ------------------------------------------------------------------------------------------------------------------------
function Get-PimGuardCommitApprovable {
    <# PURE. LITERAL. The guards that can be approved in the commit popup. #>
    @('manager.commit-removal', 'engine.remove-budget')
}

function Get-PimGuardApprovableEntities {
    <# PURE. LITERAL. The lists whose Action = Remove rows can be approved at commit: their store key (Get-PimStoreRowKey)
       names exactly the delegation the row removes. #>
    @('PIM-Assignments-Admins', 'PIM-Assignments-Groups', 'PIM-Assignments-Roles-Groups', 'PIM-Assignments-Roles-AUs',
      'PIM-Assignments-Azure-Resources', 'PIM-Assignments-Roles-Direct')
}

function Get-PimGuardGroupDeletionEntities {
    <# PURE. LITERAL. The lists whose Lifecycle = Retire rows delete a group (the engine's Get-PimRetireGroupRows reads the
       same eight; tests/Test-PimGuardCommitApproval.ps1 holds the lists equal). #>
    @('PIM-Definitions-Roles', 'PIM-Definitions-Services', 'PIM-Definitions-Organization', 'PIM-Definitions-Tasks',
      'PIM-Definitions-Departments', 'PIM-Definitions-Processes', 'PIM-Definitions-Projects', 'PIM-Definitions-CrossOrg')
}

function Get-PimGuardRowValue {
    <# PURE. One column of a row (object or dictionary) as trimmed text; '' when it is not there. #>
    param([AllowNull()][object]$Row, [string]$Name)
    if ($null -eq $Row) { return '' }
    if ($Row -is [System.Collections.IDictionary]) { if ($Row.Contains($Name)) { return "$($Row[$Name])".Trim() }; return '' }
    $p = $Row.PSObject.Properties[$Name]
    if ($p -and $null -ne $p.Value) { return "$($p.Value)".Trim() }
    return ''
}

function Test-PimGuardRowFromManagingTenant {
    <# PURE. A row the managing tenant sent: Owner is set and is not Local (the same test the Manager's row gate uses). #>
    param([AllowNull()][object]$Row)
    $o = Get-PimGuardRowValue -Row $Row -Name 'Owner'
    return [bool]($o -and $o -ine 'Local')
}

function Get-PimGuardItemId {
    <#
      PURE. The identity of ONE removal, the same on the Manager (at commit) and in the engine (at apply):
        -Kind remove        'remove|<list>|<store key>'                      for a row marked Action = Remove
        -Kind delete-group  'delete-group|<list>|<store key>|<group name>'   for a definition row marked Lifecycle = Retire
      '' = this item has NO identity and can never be covered by an approval: a list that is not approvable, a row with no
      store key, a row the managing tenant sent, a group row without a name, or the store-key function is not loaded.
    #>
    param([string]$Entity, [AllowNull()][object]$Row, [ValidateSet('remove', 'delete-group')][string]$Kind = 'remove')
    $e = "$Entity".Trim()
    if (-not $e -or $null -eq $Row) { return '' }
    $list = if ($Kind -eq 'delete-group') { @(Get-PimGuardGroupDeletionEntities) } else { @(Get-PimGuardApprovableEntities) }
    $hit = @($list | Where-Object { $_ -ieq $e })
    if (-not $hit.Count) { return '' }
    if (Test-PimGuardRowFromManagingTenant -Row $Row) { return '' }
    if (-not (Get-Command Get-PimStoreRowKey -ErrorAction SilentlyContinue)) { return '' }
    $k = ''
    try { $k = "$(Get-PimStoreRowKey -Base $hit[0] -Row $Row)".Trim() } catch { $k = '' }
    if (-not $k) { return '' }
    # PIM 100.119 B3: '|' joins the parts of the identity. For a group deletion the store key is ONE column (the tag)
    # followed by the group name, so a '|' in either would let two different rows share one identity (tag 'k' + name
    # 'x|y' = tag 'k|x' + name 'y'): such a row has no identity. For a removal the key is the LAST part and its own
    # '|' separates its columns (user|group, group|role|scope): the key must have exactly the number of parts its list has
    # columns (Get-PimGuardEntityKeyParts) -- one '|' more means a column VALUE carries the separator, and that row has
    # no identity either.
    if ($Kind -eq 'delete-group') {
        $gn = Get-PimGuardRowValue -Row $Row -Name 'GroupName'
        if (-not $gn) { return '' }
        if ($k.Contains('|') -or $gn.Contains('|')) { return '' }
        return ("delete-group|{0}|{1}|{2}" -f $hit[0], $k, $gn).ToLowerInvariant()
    }
    $parts = (Get-PimGuardEntityKeyParts)["$($hit[0])"]
    if (-not $parts -or @($k.Split('|')).Count -ne [int]$parts) { return '' }
    return ("remove|{0}|{1}" -f $hit[0], $k).ToLowerInvariant()
}

function Get-PimGuardEntityKeyParts {
    <# PURE. LITERAL. How many columns the store key of each approvable list has (Get-PimStoreRowKey joins them with '|'). #>
    @{ 'PIM-Assignments-Admins' = 2; 'PIM-Assignments-Groups' = 2; 'PIM-Assignments-Roles-Groups' = 2; 'PIM-Assignments-Roles-AUs' = 3
       'PIM-Assignments-Azure-Resources' = 3; 'PIM-Assignments-Roles-Direct' = 3 }
}

function ConvertTo-PimGuardItemIdList {
    <# PURE. Item ids: lower-case, trimmed, de-duplicated, ordinally sorted; empty ones dropped. #>
    param([AllowNull()][AllowEmptyCollection()][string[]]$ItemIds = @())
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    $l = New-Object System.Collections.Generic.List[string]
    foreach ($x in @($ItemIds)) { $s = "$x".Trim().ToLowerInvariant(); if ($s -and $seen.Add($s)) { $l.Add($s) } }
    $a = $l.ToArray(); [Array]::Sort($a, [StringComparer]::Ordinal)
    return $a   # emitted item by item: every caller wraps the call in @( ) (a ",$a" return nests inside @( ))
}

function Get-PimGuardListHash {
    <# PURE. The hash the popup shows and sends back: SHA-256 over the guard, the scope and the exact item ids. #>
    param([Parameter(Mandatory)][string]$GuardId, [string]$Scope = '', [AllowNull()][AllowEmptyCollection()][string[]]$ItemIds = @())
    Get-PimGuardPlanHash -GuardId $GuardId -Scope $Scope -Keys @(ConvertTo-PimGuardItemIdList -ItemIds $ItemIds)
}

function Get-PimGuardApprovalState {
    <# PURE. pending | active | consumed | revoked | expired -- the state an approval record is in at -NowUtc. #>
    param([Parameter(Mandatory)][object]$Approval, [datetime]$NowUtc = [datetime]::UtcNow)
    $st = "$($Approval.status)".Trim().ToLowerInvariant()
    if ($st -in @('consumed', 'revoked')) { return $st }
    $exp = ConvertTo-PimGuardUtc $Approval.expiresUtc
    if (-not $exp -or $NowUtc.ToUniversalTime() -ge $exp) { return 'expired' }
    # PIM 100.119 B2: usable only when the record is whole and its own times make sense -- approved at a time that
    # parses and is not in the future (5 minutes of clock skew), ending no later than that time + the literal lifetime
    # (48 h), with an id, the person who approved, where it came from, and at least one item.
    if (-not (Test-PimGuardRecordWindow -StartUtc $Approval.approvedUtc -ExpiresUtc $Approval.expiresUtc -LifetimeHours (Get-PimGuardApprovalLifetimeHours) -NowUtc $NowUtc)) { return 'expired' }
    if (-not "$($Approval.id)".Trim() -or -not "$($Approval.approvedBy)".Trim() -or "$($Approval.source)".Trim() -ne 'commit') { return 'expired' }
    if (-not @(@($Approval.items) | Where-Object { "$_".Trim() }).Count) { return 'expired' }
    if ($st -eq 'pending') { return 'pending' }
    if ($st -eq 'active') { return 'active' }
    return 'expired'   # an unknown status is never usable
}

function Approve-PimGuardApproval {
    <# PURE. The second person approves a PENDING approval (the setting 'GuardReleaseSecondPerson' is ON). THROWS: not a
       SuperAdmin, the same person, not pending (or expired). #>
    param([Parameter(Mandatory)][object]$Approval, [Parameter(Mandatory)][string]$By, [string]$Role = '', [datetime]$NowUtc = [datetime]::UtcNow)
    if (-not (Test-PimGuardSuperAdminRole -Role $Role)) { throw 'REFUSED -- only a SuperAdmin may approve what a guard stops.' }
    if ("$By".Trim() -ieq "$($Approval.approvedBy)".Trim()) { throw 'REFUSED -- the second person must be a different SuperAdmin than the one who approved it first.' }
    $st = Get-PimGuardApprovalState -Approval $Approval -NowUtc $NowUtc
    if ($st -ne 'pending') { throw "REFUSED -- the approval is $st, not waiting for a second person." }
    $r = [pscustomobject]@{}; foreach ($p in $Approval.PSObject.Properties) { $r | Add-Member -NotePropertyName $p.Name -NotePropertyValue $p.Value }
    foreach ($n in 'secondBy', 'secondUtc') { if (-not $r.PSObject.Properties[$n]) { $r | Add-Member -NotePropertyName $n -NotePropertyValue '' } }
    $r.status = 'active'; $r.secondBy = "$By".Trim(); $r.secondUtc = $NowUtc.ToUniversalTime().ToString('o')
    $r
}

function Test-PimGuardCommitApprovable {
    <# PURE. @{ ok; reason } -- may -GuardId be approved at commit? Never-releasable guards: NEVER. #>
    param([string]$GuardId)
    $id = "$GuardId".Trim().ToLowerInvariant()
    if (-not $id) { return [pscustomobject]@{ ok = $false; reason = 'no guard named' } }
    if ($id -in @(Get-PimGuardNeverReleasable)) { return [pscustomobject]@{ ok = $false; reason = "the guard '$id' is NEVER releasable: it takes no approval, no exemption and no limit" } }
    if ($id -notin @(Get-PimGuardCommitApprovable)) { return [pscustomobject]@{ ok = $false; reason = "'$id' is not approved in the commit popup" } }
    return [pscustomobject]@{ ok = $true; reason = '' }
}

function New-PimGuardApproval {
    <#
      PURE. The record of ONE approval given in the commit popup. THROWS 'REFUSED -- ...' on every rule it breaks:
      a SuperAdmin (exactly that role), a known person, a guard that can be approved at commit, a reason of at least 10
      characters, at least one item, and -ListHash EQUAL to the hash of exactly -ItemIds (what the person was shown is what
      is recorded -- a list that changed in between is refused).
      -Consumed: the approval is used by the commit that carries it (manager.commit-removal); the record is the evidence.
      -SecondPerson (the setting 'GuardReleaseSecondPerson' is ON): an approval a RUN will use is stored PENDING until a
      DIFFERENT SuperAdmin approves it on the Guards page -- the same rule as for a release.
    #>
    param([Parameter(Mandatory)][string]$GuardId, [string]$Scope = '', [AllowNull()][AllowEmptyCollection()][string[]]$ItemIds = @(),
          [AllowNull()][AllowEmptyCollection()][string[]]$Labels = @(), [string]$ListHash = '', [string]$Reason = '',
          [Parameter(Mandatory)][string]$By, [string]$Role = '', [string]$Base = '', [string]$CommitId = '', [switch]$Consumed,
          [bool]$SecondPerson = $false, [datetime]$NowUtc = [datetime]::UtcNow)
    $now = $NowUtc.ToUniversalTime()
    if (-not (Test-PimGuardSuperAdminRole -Role $Role)) { throw 'REFUSED -- only a SuperAdmin may approve what a guard stops.' }
    if (-not "$By".Trim() -or "$By".Trim() -eq '<unauthenticated>') { throw 'REFUSED -- the approving person is unknown.' }
    $id = "$GuardId".Trim().ToLowerInvariant()
    $ca = Test-PimGuardCommitApprovable -GuardId $id
    if (-not $ca.ok) { throw "REFUSED -- $($ca.reason)." }
    if ("$Reason".Trim().Length -lt 10) { throw 'REFUSED -- a reason of at least 10 characters is required.' }
    $items = @(ConvertTo-PimGuardItemIdList -ItemIds $ItemIds)
    if (-not $items.Count) { throw 'REFUSED -- there is nothing to approve: the list is empty.' }
    $h = Get-PimGuardListHash -GuardId $id -Scope $Scope -ItemIds $items
    if ("$ListHash".Trim().ToLowerInvariant() -ne $h) {
        throw 'REFUSED -- the list changed after it was shown: what you approved is not what would be saved now. Review the list and approve it again.'
    }
    [pscustomobject][ordered]@{
        id = [guid]::NewGuid().ToString(); guardId = $id; scope = "$Scope".Trim(); base = "$Base".Trim(); source = 'commit'; commitId = "$CommitId".Trim()
        items = @($items); labels = @(@($Labels) | Where-Object { "$_".Trim() } | Select-Object -First 200 | ForEach-Object { "$_" }); count = $items.Count; listHash = $h
        reason = "$Reason".Trim(); approvedBy = "$By".Trim(); approvedUtc = $now.ToString('o')
        expiresUtc = $now.AddHours([int](Get-PimGuardApprovalLifetimeHours)).ToString('o')
        status = $(if ($Consumed) { 'consumed' } elseif ($SecondPerson) { 'pending' } else { 'active' }); secondPerson = [bool]($SecondPerson -and -not $Consumed); secondBy = ''; secondUtc = ''
        used = @($(if ($Consumed) { $items } else { @() })); usedCount = $(if ($Consumed) { $items.Count } else { 0 })
        consumedUtc = $(if ($Consumed) { $now.ToString('o') } else { '' }); consumedBy = $(if ($Consumed) { 'the commit that carried it' } else { '' })
        revokedBy = ''; revokedUtc = ''
    }
}

function Revoke-PimGuardApproval {
    <# PURE. End a PENDING / ACTIVE approval now (its unused items are held again). THROWS: not SuperAdmin, already ended. #>
    param([Parameter(Mandatory)][object]$Approval, [Parameter(Mandatory)][string]$By, [string]$Role = '', [datetime]$NowUtc = [datetime]::UtcNow)
    if (-not (Test-PimGuardSuperAdminRole -Role $Role)) { throw 'REFUSED -- only a SuperAdmin may revoke an approval.' }
    $st = Get-PimGuardApprovalState -Approval $Approval -NowUtc $NowUtc
    if ($st -notin @('pending', 'active')) { throw "REFUSED -- the approval is already $st." }
    $r = [pscustomobject]@{}; foreach ($p in $Approval.PSObject.Properties) { $r | Add-Member -NotePropertyName $p.Name -NotePropertyValue $p.Value }
    foreach ($n in 'revokedBy', 'revokedUtc') { if (-not $r.PSObject.Properties[$n]) { $r | Add-Member -NotePropertyName $n -NotePropertyValue '' } }
    $r.status = 'revoked'; $r.revokedBy = "$By".Trim(); $r.revokedUtc = $NowUtc.ToUniversalTime().ToString('o')
    $r
}

function Get-PimGuardApprovalOpenItems {
    <# PURE. The item ids of -Approvals a run may still use: ACTIVE records of a commit-approvable -GuardId, minus the items
       already used. Returns a hashtable itemId -> the approval record. A never-releasable or unknown guard: empty. #>
    param([AllowNull()][object[]]$Approvals, [Parameter(Mandatory)][string]$GuardId, [datetime]$NowUtc = [datetime]::UtcNow)
    $open = @{}
    $id = "$GuardId".Trim().ToLowerInvariant()
    if (-not (Test-PimGuardCommitApprovable -GuardId $id).ok) { return $open }
    foreach ($a in @($Approvals)) {
        if ($null -eq $a) { continue }
        if ("$($a.guardId)".Trim().ToLowerInvariant() -ne $id) { continue }
        if ((Get-PimGuardApprovalState -Approval $a -NowUtc $NowUtc) -ne 'active') { continue }
        if (-not "$($a.approvedBy)".Trim()) { continue }   # a record nobody approved opens nothing
        $used = @{}; foreach ($u in @($a.used)) { $s = "$u".Trim().ToLowerInvariant(); if ($s) { $used[$s] = $true } }
        foreach ($i in @($a.items)) { $s = "$i".Trim().ToLowerInvariant(); if ($s -and -not $used.ContainsKey($s) -and -not $open.ContainsKey($s)) { $open[$s] = $a } }
    }
    return $open
}

function Compress-PimGuardApprovals {
    <# PURE. Drop records that ENDED more than -KeepDays (30) ago -- the audit keeps the history. #>
    param([AllowNull()][object[]]$Approvals, [datetime]$NowUtc = [datetime]::UtcNow, [int]$KeepDays = 30)
    $cut = $NowUtc.ToUniversalTime().AddDays(-1 * [Math]::Max(1, $KeepDays))
    @(@($Approvals) | Where-Object {
        if ($null -eq $_) { return $false }
        if ((Get-PimGuardApprovalState -Approval $_ -NowUtc $NowUtc) -in @('pending', 'active')) { return $true }
        $end = ConvertTo-PimGuardUtc $(if ("$($_.consumedUtc)") { $_.consumedUtc } elseif ("$($_.revokedUtc)") { $_.revokedUtc } else { $_.expiresUtc })
        return ($end -and $end -ge $cut)
    })
}

function Get-PimGuardApprovalsDoc {
    <# The stored approvals: @{ text; approvals; lastStops }. THROWS only when a configured store fails. #>
    $t = Get-PimGuardStoreText -Name 'GuardApprovals'
    $stops = @{}
    if ("$t".Trim()) {
        try {
            $o = "$t" | ConvertFrom-Json
            if ($o -and $o.PSObject.Properties['lastStops'] -and $o.lastStops) { foreach ($p in @($o.lastStops.PSObject.Properties)) { $stops["$($p.Name)".ToLowerInvariant()] = $p.Value } }
        } catch { $stops = @{} }
    }
    return @{ text = $t; approvals = @(ConvertFrom-PimGuardList -Value $t -Prop 'approvals'); lastStops = $stops }
}

function Save-PimGuardApprovalsDoc {
    <# Write the approvals (compressed) and the last stops. -Cas -ExpectedText: only if nobody changed it since; 1 / 0.
       THROWS on a store failure -- the Manager must never claim an approval it did not store. #>
    param([AllowNull()][object[]]$Approvals, [AllowNull()][hashtable]$LastStops, [datetime]$NowUtc = [datetime]::UtcNow, [AllowNull()][string]$ExpectedText, [switch]$Cas)
    $keep = @(Compress-PimGuardApprovals -Approvals $Approvals -NowUtc $NowUtc)
    $ls = [ordered]@{}; if ($LastStops) { foreach ($k in @($LastStops.Keys | Sort-Object)) { $ls["$k"] = $LastStops[$k] } }
    $json = ConvertTo-Json -InputObject ([ordered]@{ approvals = $keep; lastStops = $ls }) -Depth 8 -Compress
    if ($Cas) { return [int](Set-PimGuardStoreText -Name 'GuardApprovals' -Json $json -Expected $ExpectedText -Cas) }
    return [int](Set-PimGuardStoreText -Name 'GuardApprovals' -Json $json)
}

function Add-PimGuardApproval {
    <# Manager: store new approval records (compare-and-set, re-read up to 3 times). THROWS when they are not stored. #>
    param([Parameter(Mandatory)][object[]]$Approvals, [datetime]$NowUtc = [datetime]::UtcNow)
    for ($try = 0; $try -lt 3; $try++) {
        $doc = Get-PimGuardApprovalsDoc
        $w = Save-PimGuardApprovalsDoc -Approvals (@($doc.approvals) + @($Approvals)) -LastStops $doc.lastStops -NowUtc $NowUtc -ExpectedText $doc.text -Cas
        if ([int]$w -eq 1) { return $true }
    }
    throw 'the approval could not be stored (the approvals kept changing) -- nothing was approved'
}

function Set-PimGuardLastStop {
    <# Manager: remember when a commit guard last stopped a commit (the Guards page's "last trip"). NEVER throws. #>
    param([Parameter(Mandatory)][string]$GuardId, [string]$By = '', [string]$Base = '', [int]$Count = 0, [int]$Limit = 0, [datetime]$NowUtc = [datetime]::UtcNow)
    try {
        for ($try = 0; $try -lt 3; $try++) {
            $doc = Get-PimGuardApprovalsDoc
            $stops = $doc.lastStops
            $stops["$GuardId".Trim().ToLowerInvariant()] = [ordered]@{ atUtc = $NowUtc.ToUniversalTime().ToString('o'); by = "$By"; base = "$Base"; count = $Count; limit = $Limit }
            $w = Save-PimGuardApprovalsDoc -Approvals @($doc.approvals) -LastStops $stops -NowUtc $NowUtc -ExpectedText $doc.text -Cas
            if ([int]$w -eq 1) { return $true }
        }
    } catch { }
    return $false
}

function Use-PimGuardApprovalItems {
    <#
      Engine: which of -ItemIds did a SuperAdmin approve at commit? Each one found in an ACTIVE approval of -GuardId is
      marked USED first (atomic compare-and-set -- a run that loses the race does not get it), so an item is let through
      ONCE; an approval whose items are all used is consumed. Returns @{ ids = [string[]]; approvals = @(...) }.
      NEVER throws: any failure = nothing approved (the guard decides as if there were no approval).
      -WhatIf (a plan): nothing is approved and nothing is marked.
    #>
    param([Parameter(Mandatory)][string]$GuardId, [AllowNull()][AllowEmptyCollection()][string[]]$ItemIds = @(), [string]$Scope = '', [string]$RunKind = '',
          [switch]$WhatIf, [datetime]$NowUtc = [datetime]::UtcNow)
    $none = [pscustomobject]@{ ids = @(); approvals = @() }
    try {
        if ($WhatIf) { return $none }
        $want = @(ConvertTo-PimGuardItemIdList -ItemIds $ItemIds)
        if (-not $want.Count) { return $none }
        for ($try = 0; $try -lt 3; $try++) {
            $doc = Get-PimGuardApprovalsDoc
            $open = Get-PimGuardApprovalOpenItems -Approvals @($doc.approvals) -GuardId $GuardId -NowUtc $NowUtc
            if (-not $open.Count) { return $none }
            $hit = @($want | Where-Object { $open.ContainsKey($_) })
            if (-not $hit.Count) { return $none }
            $byAppr = @{}; foreach ($h in $hit) { $aid = "$($open[$h].id)"; if (-not $byAppr.ContainsKey($aid)) { $byAppr[$aid] = New-Object System.Collections.Generic.List[string] }; $byAppr[$aid].Add($h) }
            $now = $NowUtc.ToUniversalTime().ToString('o')
            $usedAppr = New-Object System.Collections.Generic.List[object]
            $new = foreach ($a in @($doc.approvals)) {
                if ($a -and $byAppr.ContainsKey("$($a.id)")) {
                    $c = [pscustomobject]@{}; foreach ($p in $a.PSObject.Properties) { $c | Add-Member -NotePropertyName $p.Name -NotePropertyValue $p.Value }
                    foreach ($n in 'used', 'usedCount', 'consumedUtc', 'consumedBy') { if (-not $c.PSObject.Properties[$n]) { $c | Add-Member -NotePropertyName $n -NotePropertyValue $(if ($n -eq 'used') { @() } elseif ($n -eq 'usedCount') { 0 } else { '' }) } }
                    $u = @(ConvertTo-PimGuardItemIdList -ItemIds (@(@($a.used) | ForEach-Object { "$_" }) + @($byAppr["$($a.id)"].ToArray())))
                    $c.used = @($u); $c.usedCount = $u.Count
                    $all = @(ConvertTo-PimGuardItemIdList -ItemIds @(@($a.items) | ForEach-Object { "$_" }))
                    if ($u.Count -ge $all.Count) { $c.status = 'consumed'; $c.consumedUtc = $now; $c.consumedBy = "engine $RunKind".Trim() }
                    $usedAppr.Add([pscustomobject]@{ id = "$($a.id)"; approvedBy = "$($a.approvedBy)"; reason = "$($a.reason)"; items = @($byAppr["$($a.id)"].ToArray()); left = ($all.Count - $u.Count) })
                    $c
                } else { $a }
            }
            $w = Save-PimGuardApprovalsDoc -Approvals @($new) -LastStops $doc.lastStops -NowUtc $NowUtc -ExpectedText $doc.text -Cas
            if ([int]$w -ne 1) { continue }   # another run changed the list: read again
            foreach ($ua in $usedAppr) {
                try {
                    if (Get-Command Write-PimAuditEvent -ErrorAction SilentlyContinue) {
                        Write-PimAuditEvent -Action 'guard.approval.used' -Target "$GuardId" -After @{ approvalId = "$($ua.id)"; scope = "$Scope"; approvedBy = "$($ua.approvedBy)"; reason = "$($ua.reason)"; items = @($ua.items); itemsLeft = [int]$ua.left; run = $RunKind } | Out-Null
                    }
                } catch { }
            }
            return [pscustomobject]@{ ids = @($hit); approvals = @($usedAppr.ToArray()) }
        }
        Write-Warning "[guard] $GuardId ${Scope}: the approvals could not be used (the store kept changing) -- the guard decides without them this run."
        return $none
    } catch {
        Write-Warning "[guard] $GuardId ${Scope}: the approvals could not be read ($($_.Exception.Message)) -- the guard decides without them this run."
        return $none
    }
}

function Resolve-PimRemoveBudgetApproval {
    <#
      Engine, the removal budget (PIM 100.119 (4)): split the removals of one scope into the ITEMS a SuperAdmin approved at
      commit and the rest. Only a TARGETED removal carries a row (Action = Remove) and so an identity; a prune item and a
      reconcile removal never do, and stay in 'rest'. One Remove row can match two live items (eligible and active): both
      are that one item. NEVER throws. Returns @{ approved; rest; ids; approvals }.
      -WhatIf (a plan): nothing is approved, nothing is marked used.
    #>
    param([string]$Scope = '', [string]$Entity = '', [AllowNull()][object[]]$Remove = @(), [string]$RunKind = '', [switch]$WhatIf, [datetime]$NowUtc = [datetime]::UtcNow)
    $res = [pscustomobject]@{ approved = @(); rest = @(@($Remove) | Where-Object { $_ }); ids = @(); approvals = @() }
    try {
        if ($WhatIf -or -not "$Entity".Trim()) { return $res }
        $idOf = @{}; $ids = New-Object System.Collections.Generic.List[string]
        $i = 0
        foreach ($x in @($res.rest)) {
            $i++
            if (-not ($x.PSObject.Properties['targeted'] -and $x.targeted -and $x.PSObject.Properties['row'] -and $x.row)) { continue }
            $id = Get-PimGuardItemId -Entity $Entity -Row $x.row -Kind remove
            if ($id) { $idOf[$i] = $id; $ids.Add($id) }
        }
        if (-not $ids.Count) { return $res }
        $u = Use-PimGuardApprovalItems -GuardId 'engine.remove-budget' -ItemIds $ids.ToArray() -Scope $Scope -RunKind $RunKind -NowUtc $NowUtc
        if (-not @($u.ids).Count) { return $res }
        $ok = @{}; foreach ($k in @($u.ids)) { $ok["$k"] = $true }
        $ap = New-Object System.Collections.Generic.List[object]; $rs = New-Object System.Collections.Generic.List[object]
        $i = 0
        foreach ($x in @($res.rest)) { $i++; if ($idOf.ContainsKey($i) -and $ok.ContainsKey($idOf[$i])) { $ap.Add($x) } else { $rs.Add($x) } }
        try { Write-Host ("[engine] {0,-20} {1} removal(s) were approved by a SuperAdmin when they were committed ({2}) -- applied without counting against the removal budget" -f $Scope, $ap.Count, ((@($u.approvals | ForEach-Object { $_.approvedBy } | Select-Object -Unique)) -join ', ')) -ForegroundColor Magenta } catch { }
        return [pscustomobject]@{ approved = $ap.ToArray(); rest = $rs.ToArray(); ids = @($u.ids); approvals = @($u.approvals) }
    } catch { return $res }
}

function Test-PimGuardReleaseSecondPersonOn {
    <# The setting 'GuardReleaseSecondPerson' { enabled } -- default OFF (CONFIG-1.5 / D5). A read failure = OFF is NOT safe, so it is ON. #>
    try {
        $t = Get-PimGuardStoreText -Name 'GuardReleaseSecondPerson'
        if (-not "$t".Trim()) { return $false }
        $o = $t | ConvertFrom-Json
        return [bool]($o -and $o.PSObject.Properties['enabled'] -and $o.enabled)
    } catch { return $true }
}

function Get-PimGuardsView {
    <#
      PURE. The Guards page model: every catalog guard with its state (clear / holding), what it holds now (the holds of
      that guard, the policy breaker's per-provider trips folded in), the releases of it, and whether it is releasable.
    #>
    <# PIM 100.119 (6): every row also says what the guard PROTECTS, its LIMIT (value, floor, default, ceiling, who set it --
       $null when the guard has none), whether an exemption can be approved (exemption = 'commit' | 'release' |
       'commit+release' | 'approvals' | 'none' | 'locked') with the approvals given at commit, and its last trip. A
       never-releasable guard is LOCKED with the reason; there is no "off" for any guard. #>
    param([AllowNull()][object[]]$Trips, [AllowNull()][object[]]$Holds, [AllowNull()][object[]]$Releases, [AllowNull()][object[]]$Approvals,
          [AllowNull()][hashtable]$LastStops, [datetime]$NowUtc = [datetime]::UtcNow)
    $rel = @(@($Releases) | Where-Object { $_ } | ForEach-Object {
        $c = [pscustomobject]@{}; foreach ($p in $_.PSObject.Properties) { $c | Add-Member -NotePropertyName $p.Name -NotePropertyValue $p.Value }
        $c | Add-Member -NotePropertyName state -NotePropertyValue (Get-PimGuardReleaseState -Release $_ -NowUtc $NowUtc) -Force
        $c })
    $apr = @(@($Approvals) | Where-Object { $_ } | ForEach-Object {
        $c = [pscustomobject]@{}; foreach ($p in $_.PSObject.Properties) { $c | Add-Member -NotePropertyName $p.Name -NotePropertyValue $p.Value }
        $c | Add-Member -NotePropertyName state -NotePropertyValue (Get-PimGuardApprovalState -Approval $_ -NowUtc $NowUtc) -Force
        $c })
    $never = @(Get-PimGuardNeverReleasable)
    $atCommit = @(Get-PimGuardCommitApprovable)
    $cat = foreach ($g in @(Get-PimGuardReleaseCatalog)) {
        $id = $g.guardId
        $isNever = ($id -in $never)
        $hs = @(@($Holds) | Where-Object { $_ -and "$($_.guardId)".Trim().ToLowerInvariant() -eq $id })
        $tr = @(@($Trips) | Where-Object { $_ -and ("$($_.guardId)" -eq $id -or "$($_.guardId)".StartsWith("$id.")) })
        $last = @($tr | Sort-Object { "$($_.lastSeenUtc)" } -Descending | Select-Object -First 1)
        $lastUtc = if ($last.Count) { "$($last[0].lastSeenUtc)" } else { '' }
        $stop = $null
        if ($LastStops -and $LastStops.ContainsKey($id)) { $stop = $LastStops[$id]; if ("$($stop.atUtc)" -and (-not $lastUtc -or "$($stop.atUtc)" -gt $lastUtc)) { $lastUtc = "$($stop.atUtc)" } }
        $lim = $null
        if (-not $isNever -and (Get-Command Get-PimGuardLimitState -ErrorAction SilentlyContinue)) { try { $lim = Get-PimGuardLimitState -GuardId $id -Fresh } catch { $lim = $null } }
        # CODE REVIEW 2 FIXES 2026-10-13 (owner decision 59: "Show it, keep 0 possible"): the EFFECTIVE number in this process
        # next to the stored one -- a server setting may lower it (0 = a full stop) and the page says so; it never raises it.
        if ($lim -and (Get-Command Get-PimGuardEffectiveLimit -ErrorAction SilentlyContinue)) {
            $eff = $null; try { $eff = Get-PimGuardEffectiveLimit -GuardId $id } catch { $eff = $null }
            if ($eff) {
                $lim | Add-Member -NotePropertyName effective -NotePropertyValue ([int]$eff.effective) -Force
                $lim | Add-Member -NotePropertyName effectiveNote -NotePropertyValue "$($eff.note)" -Force
                $lim | Add-Member -NotePropertyName serverSetting -NotePropertyValue "$($eff.knob)" -Force
                $lim | Add-Member -NotePropertyName serverSettingValue -NotePropertyValue "$($eff.knobValue)" -Force
                $lim | Add-Member -NotePropertyName lowered -NotePropertyValue ([bool]$eff.lowered) -Force
            }
        }
        $what = "$($g.what)"
        if ($what.Contains('{limit}')) { $what = $what.Replace('{limit}', $(if ($lim -and $lim.PSObject.Properties['effective']) { "$([int]$lim.effective)" } elseif ($lim) { "$([int]$lim.value)" } else { 'the limit' })) }
        if ($what.Contains('{keep}') -and (Get-Command Get-PimCommitGuardFewLeftRows -ErrorAction SilentlyContinue)) { $what = $what.Replace('{keep}', "$([int](Get-PimCommitGuardFewLeftRows))").Replace('{minList}', "$([int](Get-PimCommitGuardFewLeftMinList))") }
        $releasable = [bool](Test-PimGuardReleasable -GuardId $id).ok
        $commitOk = (-not $isNever) -and ($id -in $atCommit)
        $ex = if ($isNever) { 'locked' } elseif ($commitOk -and $releasable) { 'commit+release' } elseif ($commitOk) { 'commit' } elseif ($releasable) { 'release' } elseif ("$($g.release)" -eq 'approval') { 'approvals' } else { 'none' }
        [pscustomobject][ordered]@{
            guardId = $id; title = $g.title; protects = "$($g.protects)"; what = $what; release = $g.release; never = $isNever
            locked = $isNever; lockedReason = $(if ($isNever) { "$($g.locked)" } else { '' }); canSwitchOff = $false
            releasable = $releasable; exemption = $ex; limit = $lim
            state = $(if ($hs.Count) { 'holding' } else { 'clear' }); holds = @($hs)
            lastTripUtc = $lastUtc; tripCount = $(if ($last.Count) { [int]("0$($last[0].tripCount)" -replace '[^0-9]', '') } else { 0 }); lastStop = $stop
            releases = @($rel | Where-Object { "$($_.guardId)" -eq $id } | Sort-Object { "$($_.createdUtc)" } -Descending)
            approvals = @($(if ($isNever) { @() } else { @($apr | Where-Object { "$($_.guardId)" -eq $id } | Sort-Object { "$($_.approvedUtc)" } -Descending) }))
        }
    }
    return @($cat)
}
