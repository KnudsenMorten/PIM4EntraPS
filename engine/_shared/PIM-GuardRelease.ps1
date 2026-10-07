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

  What a release can do (the ceilings are literals here, never $script: values -- see BUG-79-6b):
    engine.remove-budget      G4: the removal budget is RAISED for that run to the plan's count, at most 50 (the release
                              ceiling; the configured budget itself still defaults to 5 and can only be lowered).
    engine.disable-guard      G2 (account-disable blast radius): raised for that run to the plan's count, at most 50
                              accounts and 25 % of the scanned population (the breaker's own ceilings). G1 (desired set
                              resolved) and G3 (opt-in) are NOT releasable.
    engine.empty-desired      the prune of a scope whose definitions are gone runs for that run (the live items are still
                              filtered by the managed-key ledger, and G4 still caps them).
    engine.ledger-unreadable  the prune of a scope whose managed-key ledger could not be read runs for that run (G4 still
                              caps it).

  NEVER releasable (hard-coded, refused at creation AND at use, tested): the break-glass exclusion, an admin account
  deletion by a prune, shared workload assignments (SEC-83), groups PIM does not own (SEC-85), items that fail the s96.5
  removal rules. Those protections live in the providers and the disable selector and a release never reaches them.

  Store: pim.Settings (SQL) -- 'GuardReleases' { releases: [...] } and 'GuardHolds' { holds: [...] }. The engine consumes a
  one-run release with an atomic compare-and-set (Set-PimSqlSettingIfUnchanged) so two runs cannot both use it.
  Test seam: $global:PIM_GuardReleaseStore = @{} (setting name -> JSON text) replaces SQL.
#>

Set-StrictMode -Off

function Get-PimGuardReleaseCatalog {
    <# PURE. Every guard the Guards page lists and how it is released. release = release | approval | info | never. #>
    @(
        [pscustomobject]@{ guardId = 'engine.remove-budget'; title = 'Removal budget (G4)'; release = 'release'; ceiling = 50; ceilingPercent = $null
            what = 'At most 5 removals per scope per run. A release raises it for ONE run to exactly the held plan, at most 50.' }
        [pscustomobject]@{ guardId = 'engine.disable-guard'; title = 'Account-disable circuit breaker (G2)'; release = 'release'; ceiling = 50; ceilingPercent = 25
            what = 'At most 5 accounts / 10 % disabled per run. A release raises it for ONE run to the held plan, at most 50 accounts and 25 %.' }
        [pscustomobject]@{ guardId = 'engine.empty-desired'; title = 'Empty definitions'; release = 'release'; ceiling = $null; ceilingPercent = $null
            what = 'A scope whose definitions are gone is never pruned. A release lets ONE run prune it (managed items only, the removal budget still applies).' }
        [pscustomobject]@{ guardId = 'engine.ledger-unreadable'; title = 'Managed-key ledger unreadable'; release = 'release'; ceiling = $null; ceilingPercent = $null
            what = 'Without the ledger a prune removes nothing. A release lets ONE run prune the held plan (the removal budget still applies).' }
        [pscustomobject]@{ guardId = 'engine.policy-mass-change'; title = 'Policy mass-change breaker'; release = 'approval'; ceiling = $null; ceilingPercent = $null
            what = 'Approved by its plan hash on the Approvals / Jobs page (valid 24 h).' }
        [pscustomobject]@{ guardId = 'engine.offboarding-approval'; title = 'Offboarding approval'; release = 'approval'; ceiling = $null; ceilingPercent = $null
            what = 'A disable or offboarding waits for its approval on the Approvals page.' }
        [pscustomobject]@{ guardId = 'engine.reconcile-paused'; title = 'Daily reconcile paused'; release = 'info'; ceiling = $null; ceilingPercent = $null
            what = 'Resumed on the Jobs page (s96.5).' }
        [pscustomobject]@{ guardId = 'engine.break-glass'; title = 'Break-glass exclusion'; release = 'never'; ceiling = $null; ceilingPercent = $null
            what = 'A break-glass account is never disabled, revoked or offboarded.' }
        [pscustomobject]@{ guardId = 'engine.prune-admin-delete'; title = 'Admin deletion by a prune'; release = 'never'; ceiling = $null; ceilingPercent = $null
            what = 'A prune or reconcile never deletes an admin account; only the operator''s Delete account does.' }
        [pscustomobject]@{ guardId = 'engine.shared-workload-assignment'; title = 'Shared workload assignments (SEC-83)'; release = 'never'; ceiling = $null; ceilingPercent = $null
            what = 'A Defender XDR / Intune assignment that also holds another principal is never deleted.' }
        [pscustomobject]@{ guardId = 'engine.unowned-group'; title = 'Groups PIM does not own (SEC-85)'; release = 'never'; ceiling = $null; ceilingPercent = $null
            what = 'Memberships in groups PIM does not manage are never removed.' }
        [pscustomobject]@{ guardId = 'engine.reconcile-unproven'; title = 'Removal rules of the reconcile (96.5)'; release = 'never'; ceiling = $null; ceilingPercent = $null
            what = 'An item PIM did not define, did not make live, or did not remove is never removed.' }
    )
}

function Get-PimGuardNeverReleasable {
    <# PURE. The guard ids no release can ever cover -- a literal list, not derived, so a catalog edit cannot widen it. #>
    @('engine.break-glass', 'engine.prune-admin-delete', 'engine.shared-workload-assignment', 'engine.unowned-group', 'engine.reconcile-unproven')
}

function Test-PimGuardReleasable {
    <# PURE. @{ ok; reason } -- only the four engine guards with release = 'release' may be released. #>
    param([string]$GuardId)
    $id = "$GuardId".Trim().ToLowerInvariant()
    if (-not $id) { return [pscustomobject]@{ ok = $false; reason = 'no guard named' } }
    if ($id -in @(Get-PimGuardNeverReleasable)) { return [pscustomobject]@{ ok = $false; reason = "the guard '$id' is NEVER releasable" } }
    $c = @(Get-PimGuardReleaseCatalog | Where-Object { $_.guardId -eq $id })
    if (-not $c.Count) { return [pscustomobject]@{ ok = $false; reason = "unknown guard '$id'" } }
    if ($c[0].release -eq 'approval') { return [pscustomobject]@{ ok = $false; reason = "'$id' is released through its own approval (Approvals page), not here" } }
    if ($c[0].release -ne 'release') { return [pscustomobject]@{ ok = $false; reason = "'$id' has no release" } }
    return [pscustomobject]@{ ok = $true; reason = '' }
}

function Get-PimGuardReleaseCeiling {
    <# PURE. The most one release can open: @{ count; percent } -- $null = no count ceiling of its own. LITERALS. #>
    param([string]$GuardId)
    switch ("$GuardId".Trim().ToLowerInvariant()) {
        'engine.remove-budget' { return [pscustomobject]@{ count = 50; percent = $null } }
        'engine.disable-guard' { return [pscustomobject]@{ count = 50; percent = 25 } }
        default { return [pscustomobject]@{ count = $null; percent = $null } }
    }
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
    if ($st -eq 'pending') { return 'pending' }
    if ($st -eq 'active') { return 'active' }
    return 'expired'   # an unknown status is never usable
}

function New-PimGuardRelease {
    <#
      PURE. A new release record for the CURRENT hold of one guard + scope. THROWS 'REFUSED -- ...' on every rule it breaks:
      SuperAdmin, a releasable guard, a reason (>= 10 characters), a 64-hex plan hash EQUAL to the hold's, one-run or until
      (until in the future, at most 24 h), the plan within the guard's release ceiling.
    #>
    param([Parameter(Mandatory)][string]$GuardId, [string]$Scope = '', [Parameter(Mandatory)][string]$PlanHash, [AllowNull()][object]$Hold,
          [ValidateSet('one-run', 'until')][string]$Mode = 'one-run', [AllowNull()][object]$UntilUtc, [string]$Reason = '',
          [Parameter(Mandatory)][string]$By, [string]$Role = '', [bool]$SecondPerson = $false, [datetime]$NowUtc = [datetime]::UtcNow)
    $now = $NowUtc.ToUniversalTime()
    if ("$Role".Trim() -ne 'SuperAdmin') { throw 'REFUSED -- only a SuperAdmin may release a guard.' }
    if (-not "$By".Trim()) { throw 'REFUSED -- the releasing person is unknown.' }
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
    $ceil = Get-PimGuardReleaseCeiling -GuardId $id
    if ($null -ne $ceil.count -and $count -gt [int]$ceil.count) {
        throw ("REFUSED -- the held plan has {0} item(s), over the release ceiling of {1}. Apply it in smaller batches." -f $count, $ceil.count)
    }
    if ($null -ne $ceil.percent -and $Hold.PSObject.Properties['percent'] -and "$($Hold.percent)" -ne '') {
        $pct = 0.0; [void][double]::TryParse("$($Hold.percent)", [Globalization.NumberStyles]::Float, [Globalization.CultureInfo]::InvariantCulture, [ref]$pct)
        if ($pct -gt [double]$ceil.percent) { throw ("REFUSED -- the held plan disables {0:N1} % of the scanned accounts, over the release ceiling of {1} %." -f $pct, $ceil.percent) }
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
    if ("$Role".Trim() -ne 'SuperAdmin') { throw 'REFUSED -- only a SuperAdmin may approve a guard release.' }
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
    if ("$Role".Trim() -ne 'SuperAdmin') { throw 'REFUSED -- only a SuperAdmin may revoke a guard release.' }
    $st = Get-PimGuardReleaseState -Release $Release -NowUtc $NowUtc
    if ($st -notin @('pending', 'active')) { throw "REFUSED -- the release is already $st." }
    $r = [pscustomobject]@{}; foreach ($p in $Release.PSObject.Properties) { $r | Add-Member -NotePropertyName $p.Name -NotePropertyValue $p.Value }
    $r.status = 'revoked'; $r.revokedBy = "$By".Trim(); $r.revokedUtc = $NowUtc.ToUniversalTime().ToString('o')
    $r
}

function Test-PimGuardReleaseCovers {
    <# PURE. Does an ACTIVE release cover what this run asks for? Count within raiseTo and the ceiling; percent within the ceiling. #>
    param([Parameter(Mandatory)][object]$Release, [int]$Requested = 0, [double]$RequestedPercent = -1)
    $ceil = Get-PimGuardReleaseCeiling -GuardId "$($Release.guardId)"
    if ($null -ne $ceil.count) {
        $raise = 0; [void][int]::TryParse("$($Release.raiseTo)", [ref]$raise)
        $lim = [Math]::Min($raise, [int]$ceil.count)
        if ($Requested -gt $lim) { return $false }
    }
    if ($null -ne $ceil.percent -and $RequestedPercent -ge 0 -and $RequestedPercent -gt [double]$ceil.percent) { return $false }
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
      A release that does not cover -Requested / -RequestedPercent is not used (and not consumed).
    #>
    param([Parameter(Mandatory)][string]$GuardId, [string]$Scope = '', [Parameter(Mandatory)][string]$PlanHash,
          [int]$Requested = 0, [double]$RequestedPercent = -1, [string]$RunKind = '', [datetime]$NowUtc = [datetime]::UtcNow)
    try {
        for ($try = 0; $try -lt 3; $try++) {
            $text = Get-PimGuardStoreText -Name 'GuardReleases'
            $all = @(ConvertFrom-PimGuardList -Value $text -Prop 'releases')
            $rel = Find-PimGuardRelease -Releases $all -GuardId $GuardId -Scope $Scope -PlanHash $PlanHash -NowUtc $NowUtc
            if (-not $rel) { return $null }
            if (-not (Test-PimGuardReleaseCovers -Release $rel -Requested $Requested -RequestedPercent $RequestedPercent)) { return $null }
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
          [int]$Count = 0, [double]$Percent = -1, [AllowNull()][object]$Measured, [string]$RunKind = '', [switch]$WhatIf,
          [switch]$NoHold, [datetime]$NowUtc = [datetime]::UtcNow)
    $res = [pscustomobject]@{ released = $false; release = $null; planHash = '' }
    try {
        $res.planHash = Get-PimGuardPlanHash -GuardId $GuardId -Scope $Scope -Keys @($Keys)
        if ($WhatIf) { return $res }
        $rel = Use-PimGuardRelease -GuardId $GuardId -Scope $Scope -PlanHash $res.planHash -Requested $Count -RequestedPercent $Percent -RunKind $RunKind -NowUtc $NowUtc
        if ($rel) {
            $res.released = $true; $res.release = $rel
            [void](Clear-PimGuardHold -GuardId $GuardId -Scope $Scope)
            try { Write-Host ("[engine] {0}: guard {1} RELEASED for this run by {2}{3} (plan {4}, {5}): {6}" -f $Scope, $GuardId, $rel.createdBy, $(if ("$($rel.approvedBy)") { " + $($rel.approvedBy)" } else { '' }), $res.planHash.Substring(0, 12), $rel.mode, $rel.reason) -ForegroundColor Magenta } catch { }
            return $res
        }
        if (-not $NoHold) {
            $items = @(@($Keys) | Where-Object { "$_".Trim() } | Select-Object -First 50 | ForEach-Object { "$_" })
            $hold = [pscustomobject][ordered]@{ guardId = "$GuardId".Trim().ToLowerInvariant(); scope = "$Scope".Trim(); planHash = $res.planHash; count = $Count
                percent = $(if ($Percent -ge 0) { [Math]::Round($Percent, 1) } else { $null }); items = @($items); itemsTruncated = (@($Keys).Count -gt 50)
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
        tripped decision  -> the plan (every remove and type-change key) is hashed; a matching ACTIVE release raises the
                             budget for THIS run to the plan's count, at most 50 (literal), and is consumed (one-run);
                             returns @{ decision (allowed); used }. No release -> the hold is recorded; returns $null.
    #>
    param([Parameter(Mandatory)][object]$Decision, [string]$Scope = '', [object[]]$Remove = @(), [object[]]$Retype = @(), [int]$Scanned = 0, [string]$RunKind = '')
    try {
        if ($Decision.allowed) { [void](Clear-PimGuardHold -GuardId 'engine.remove-budget' -Scope $Scope -RunKind $RunKind); return $null }
        $keys = @(@(@($Remove) | Where-Object { $_ } | ForEach-Object { "remove|$($_.key)" }) + @(@($Retype) | Where-Object { $_ } | ForEach-Object { "retype|$($_.key)" }))
        $n = $keys.Count
        $g = Invoke-PimGuardHoldOrRelease -GuardId 'engine.remove-budget' -Scope $Scope -Keys $keys -Count $n -RunKind $RunKind `
                -Measured @{ toRemove = $n; budget = [int]$Decision.budget; scanned = $Scanned }
        if (-not $g.released) { return $null }
        $lim = [Math]::Min([int]$g.release.raiseTo, 50)
        if ($n -gt $lim) { return $null }
        try { Write-Host ("[engine] {0,-20} removal budget RAISED for this run to {1} (released plan, ceiling 50): {2} removal(s) go ahead" -f $Scope, $lim, $n) -ForegroundColor Magenta } catch { }
        return [pscustomobject]@{
            decision = [pscustomobject]@{ allowed = $true; abort = $false; tripped = $null; reason = 'released for this run'; toRemove = $n; budget = $lim; scope = $Scope; operation = 'remove'; scanned = $Scanned }
            used = [pscustomobject]@{ guardId = 'engine.remove-budget'; releaseId = "$($g.release.id)"; planHash = $g.planHash } }
    } catch { return $null }
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
    param([AllowNull()][object[]]$Trips, [AllowNull()][object[]]$Holds, [AllowNull()][object[]]$Releases, [datetime]$NowUtc = [datetime]::UtcNow)
    $rel = @(@($Releases) | Where-Object { $_ } | ForEach-Object {
        $c = [pscustomobject]@{}; foreach ($p in $_.PSObject.Properties) { $c | Add-Member -NotePropertyName $p.Name -NotePropertyValue $p.Value }
        $c | Add-Member -NotePropertyName state -NotePropertyValue (Get-PimGuardReleaseState -Release $_ -NowUtc $NowUtc) -Force
        $c })
    $never = @(Get-PimGuardNeverReleasable)
    $cat = foreach ($g in @(Get-PimGuardReleaseCatalog)) {
        $id = $g.guardId
        $hs = @(@($Holds) | Where-Object { $_ -and "$($_.guardId)".Trim().ToLowerInvariant() -eq $id })
        $tr = @(@($Trips) | Where-Object { $_ -and ("$($_.guardId)" -eq $id -or "$($_.guardId)".StartsWith("$id.")) })
        $last = @($tr | Sort-Object { "$($_.lastSeenUtc)" } -Descending | Select-Object -First 1)
        [pscustomobject][ordered]@{
            guardId = $id; title = $g.title; what = $g.what; release = $g.release; never = ($id -in $never)
            releasable = [bool](Test-PimGuardReleasable -GuardId $id).ok; ceiling = $g.ceiling; ceilingPercent = $g.ceilingPercent
            state = $(if ($hs.Count) { 'holding' } else { 'clear' }); holds = @($hs)
            lastTripUtc = $(if ($last.Count) { "$($last[0].lastSeenUtc)" } else { '' }); tripCount = $(if ($last.Count) { [int]("0$($last[0].tripCount)" -replace '[^0-9]', '') } else { 0 })
            releases = @($rel | Where-Object { "$($_.guardId)" -eq $id } | Sort-Object { "$($_.createdUtc)" } -Descending)
        }
    }
    return @($cat)
}
