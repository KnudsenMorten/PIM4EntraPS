# =============================================================================
# 🔴 71.23 -- Get-PimAdminAutoDisableDate (PIM-DateSafe.ps1) decides which column carries an admin's
# auto-disable date, and REFUSES a row that carries both names with different dates. The downlink
# publishes that decision into the bundle, so it must never fall back to reading a column itself --
# a local fallback would be exactly the silent guess the resolver exists to prevent. The engine host
# always has DateSafe loaded; an offline test that dot-sources only this file did not, so load it
# here when it is missing rather than degrade.
if (-not (Get-Command Get-PimAdminAutoDisableDate -ErrorAction SilentlyContinue)) {
    $__dsPath = Join-Path $PSScriptRoot 'PIM-DateSafe.ps1'
    if (Test-Path -LiteralPath $__dsPath) { . $__dsPath }
}

# PIM-Downlink.ps1 -- the PURE, offline-testable decision brain for the §31.3
# master->managed (slave) admin/permission SYNC (downlink) + the scenario-bound
# engine runner. Phase 2 of the §31 hosting/edition scenario matrix (S1-S6).
#
# WHAT this delivers (the §31.3 wiring gap the live matrix asserts):
#   * a ring-gated master->managed admin/permission downlink: PULL the master's
#     SIGNED baseline (RSA-SHA256, same trust model as .pimlicense -- verify with
#     the embedded PUBLIC cert, refuse on bad sig / expiry / rollback), FILTER the
#     admin set to admin.Ring <= slave.Ring, STAGE per-tenant sync files in the
#     resolved folder (central-msp vs local-slave), and APPLY into the slave by
#     composing the EXISTING Invoke-PimMspFanout (pull-not-push: the MASTER never
#     writes into a managed tenant; the central/managed engine applies the synced
#     rows into the slave via ITS OWN per-tenant SPN).
#   * a scenario-bound runner: resolve the scenario, and for single/master run the
#     engine apply; for managed run the downlink-sync THEN the engine apply.
#
# DESIGN TENETS (non-negotiable, mirror the rest of PIM4EntraPS):
#   * PURE core here: NO az / Graph / SQL / HTTP / file I/O / global mutation in
#     the decision functions -- they take FACTS, return PLANS/decisions. The thin
#     live wrappers (setup/Invoke-PimDownlinkSync.ps1 + setup/Invoke-PimScenarioRun.ps1)
#     gather the facts (pull the signed bundle, read the registry, write files, run
#     the fan-out/engine) and ACT on these plans. That keeps every risky decision --
#     "does this signature verify?", "which admins does this ring reach?", "where do
#     the sync files go?", "is the second pass a no-op?", "which topology branch?" --
#     unit-testable in real PS 5.1 with NO live tenant.
#   * pull-not-push + ring-gated + guardrails: the downlink only ever PULLS the
#     ring's approved baseline; an admin above the slave's ring is never synced; the
#     apply composes the engine's mass-disable guard (empty desired never prunes).
#   * idempotent: a second pass produces zero changes (find-or-create fan-out +
#     anti-rollback baseline marker + stable sync-file content hash).
#
# PS 5.1 COMPATIBLE: no ?. / ??, no RSA.ImportFromPem, no ternary, Set-StrictMode
#   -Off, null-guarded property access, .ToArray() not @() on List[object].
#
# REUSE (does not reinvent): Resolve-PimScenarioContext / Get-PimScenarioEntryPlan
#   (PIM-ScenarioProfile.ps1), Test-PimBaselineDoc / Get-PimBaselineBundle
#   (PIM-Baseline.ps1), Invoke-PimMspFanout.ps1 (the real admin-creation engine),
#   Invoke-PimEngineCore.ps1 (engine apply). This file MAPS + ORCHESTRATES them.
# =============================================================================

Set-StrictMode -Off

# Idempotent dot-source of the scenario resolver + the baseline verifier so this
# module stands alone if loaded first. (PIM-ScenarioProfile.ps1 dot-sources THIS
# file at its tail so the live matrix -- which loads PIM-ScenarioProfile.ps1 --
# resolves Invoke-PimManagedDownlink / Invoke-PimScenarioDeploy via Get-Command.)
if ($PSScriptRoot) {
    if (-not (Get-Command Resolve-PimScenarioContext -ErrorAction SilentlyContinue)) {
        $__sp = Join-Path $PSScriptRoot 'PIM-ScenarioProfile.ps1'
        if (Test-Path -LiteralPath $__sp) { . $__sp }
    }
    if (-not (Get-Command Test-PimBaselineDoc -ErrorAction SilentlyContinue)) {
        $__bl = Join-Path $PSScriptRoot 'PIM-Baseline.ps1'
        if (Test-Path -LiteralPath $__bl) { . $__bl }
    }
    # MSP-2: Invoke-PimDownlinkAssignmentApply writes the projected roles into the
    # slave's desired store. The PURE functions above need none of this, so the load
    # stays lazy-by-availability like the two above it.
    if (-not (Get-Command Get-PimSqlRows -ErrorAction SilentlyContinue)) {
        $__ss = Join-Path $PSScriptRoot 'PIM-SqlStore.ps1'
        if (Test-Path -LiteralPath $__ss) { . $__ss }
    }
}

# ---------------------------------------------------------------------------
# Small null-safe property reader (IDictionary OR PSCustomObject). Mirrors
# Get-PimScenarioValue so this file is self-contained.
# ---------------------------------------------------------------------------
function Get-PimDownlinkValue {
    param([object]$Object, [Parameter(Mandatory)][string]$Key)
    if ($null -eq $Object) { return $null }
    if ($Object -is [System.Collections.IDictionary]) {
        if ($Object.Contains($Key)) { return $Object[$Key] }
        return $null
    }
    $p = $Object.PSObject.Properties[$Key]
    if ($p) { return $p.Value }
    return $null
}

# 71.15 (pure) -- a lifecycle DATE field as text, whatever the JSON parser made of it. pwsh 7's ConvertFrom-Json and
# Invoke-RestMethod turn an ISO-8601 string ('2026-10-01T08:00:00Z') into a [datetime], and "$value" then renders it in
# the host culture ('10/01/2026 08:00:00'), dropping the zone. The slave's copy of a master's ProvisionDate /
# TAPStartDate / AutoDisableDate must stay the ISO text the master wrote, so a [datetime] is rendered back as ISO-8601
# (UTC with Z when the parser knew it was UTC; without a zone when it did not). Anything else is the trimmed text.
function ConvertTo-PimDownlinkLifecycleText {
    param([object]$Value)
    if ($null -eq $Value) { return '' }
    if ($Value -is [datetime]) {
        $inv = [Globalization.CultureInfo]::InvariantCulture
        if ($Value.Kind -eq [DateTimeKind]::Unspecified) { return $Value.ToString('yyyy-MM-ddTHH:mm:ss', $inv) }
        return $Value.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ', $inv)
    }
    if ($Value -is [datetimeoffset]) { return $Value.UtcDateTime.ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture) }
    return "$Value".Trim()
}

# ---------------------------------------------------------------------------
# ASSIGNMENT PROVIDER (pure). Which baseline admins does THIS slave receive?
#
# 🪤 THIS IS NOT VERSION SELECTION, AND IT IS NOT THE AutomateIT RING-1 GATE.
#   "Ring" means three different things around PIM; conflating them produces
#   wrong fixes (see engine/_shared/PIM-RingGate.ps1 for the full map):
#     * RING-1 plane 1 -- the AutomateIT operator picks which CODE VERSION a
#       customer receives. Decided in the sync engine, before PIM is on disk.
#     * RING-1 plane 2 -- an MSP master picks which TEMPLATE VERSION a managed
#       tenant may pull (Get-PimTemplateRingPlan).
#     * THIS ONE -- ASSIGNMENT SCOPING: which ADMINS reach which TENANTS. No
#       version is selected here, ever.
#   This is the "master-store assignment provider" that AutomateIT RING-1 phase 1
#   item 3 refers to. It is genuinely PIM's own, RING-1 does not replace it, and
#   it must NOT be merged into either version-selection plane.
#
#   Engine ring semantics (matches pim.vw_AdminTenantTargets `a.Ring <= t.Ring`
#   and the seeder's Get-ExpectedAdminsForSlave): a ring-0 admin is BROAD and
#   reaches every slave; a ring-2 admin only reaches ring>=2 (test) slaves.
#   => an admin reaches the slave when admin.Ring <= slave.Ring.
# Input rows may be hashtables OR PSCustomObjects (UserName + Ring). Returns the
# filtered subset (same shape) sorted by Ring then UserName for determinism.
# ---------------------------------------------------------------------------
function Select-PimUnrecognisableAdmins {
    <#
      IMP-13 -- WOULD THE SLAVE'S OWN ENGINE EVEN SEE THE ACCOUNTS THIS SYNC IS ABOUT TO CREATE?

      The Admins provider limits its live set to accounts whose UPN starts with a configured
      `AdminAccountPatterns` prefix -- fail-closed, and correctly so. A synced MSP admin lands as
      `<MSP UserName>@<slave domain>`, so if the slave's conventions do not include the MSP's
      prefix the live set EXCLUDES them, the diff reads "not present", and **every tick tries to
      create them again**.

      🔴 THE HARM IS NOT THE LOOP, IT IS WHAT THE LOOP LEAVES BEHIND. Each pass creates a
      PRIVILEGED ACCOUNT in the customer's tenant that the customer's own engine will never manage,
      never review, and never disable -- an orphan admin, produced by a sync that reported success.
      Not creating it is strictly safer than creating one nobody owns.

      🔒 AND THE FIX IS *NOT* TO WIDEN THE CUSTOMER'S PATTERNS FROM OUR SIDE. `AdminAccountPatterns`
      is the customer's own fail-closed scoping control; merging the MSP's prefix into it would be
      the master editing a customer's security configuration to make its own write succeed. That is
      exactly what §22 ("MSP never writes to a customer tenant") and the MSP-3 consent model forbid,
      and it would be indistinguishable from the sync quietly granting itself more reach. So this
      DETECTS and REPORTS; the operator (or onboarding) fixes the convention, on the customer side.

      Returns @{ checked; unrecognised; recognised; prefixes; reason }.
      🪤 `checked = $false` when no prefixes are known -- the S5 master-side case, where we simply
      cannot see the slave's config. That is "we did not look", NOT "it is fine", and the caller must
      not read an empty `unrecognised` list as a clean bill of health.
      PURE: no store, no network.
    #>
    [CmdletBinding()]
    param(
        [AllowEmptyCollection()][string[]]$AdminUserNames = @(),
        [AllowEmptyCollection()][string[]]$SlaveAdminPrefixes = @()
    )
    $pref = @(@($SlaveAdminPrefixes) | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
    if (-not $pref.Count) {
        return [ordered]@{
            checked = $false; unrecognised = @(); recognised = @($AdminUserNames); prefixes = @()
            reason  = "the slave's admin naming prefixes are not known here, so recognisability was NOT evaluated (this is 'did not look', not 'they are fine')"
        }
    }
    $bad = New-Object System.Collections.Generic.List[string]
    $ok  = New-Object System.Collections.Generic.List[string]
    foreach ($u in @($AdminUserNames)) {
        $n = "$u".Trim()
        if (-not $n) { continue }
        $lc = $n.ToLowerInvariant()
        $hit = $false
        foreach ($p in $pref) { if ($lc.StartsWith($p.ToLowerInvariant())) { $hit = $true; break } }
        if ($hit) { $ok.Add($n) | Out-Null } else { $bad.Add($n) | Out-Null }
    }
    $badArr = @($bad.ToArray())
    return [ordered]@{
        checked      = $true
        unrecognised = $badArr
        recognised   = @($ok.ToArray())
        prefixes     = $pref
        reason       = $(if ($badArr.Count) {
                            "$($badArr.Count) admin(s) do not match the slave's admin naming prefixes ($($pref -join ', ')) -- the slave's engine would NOT see them, so each tick would create them again and leave an unmanaged privileged account behind. Add the MSP's prefix to the CUSTOMER's AdminAccountPatterns (their config, their decision), or rename the admins."
                        } else { '' })
    }
}

# ---------------------------------------------------------------------------
# Is this admin synced to slaves at all? (pure) -- REQUIREMENTS 68.6 row 35.
# Operator 2026-09-13: "slaves import admins from central if defined per admins at master".
# The master's admin row decides: ManagementMode=msp syncs; blank or 'local' does not.
# A row that carries NO ManagementMode field at all is a pim.CentralAdmins registry row (the
# bundle shape before 2026-09-13). That registry holds MSP admins only, so it is msp by
# construction -- treating it as 'local' would retract every existing MSP admin on update.
# ---------------------------------------------------------------------------
function Test-PimDownlinkAdminSynced {
    param([object]$Admin)
    if ($null -eq $Admin) { return @{ synced = $false; reason = 'no admin row' } }
    $has = $false
    if ($Admin -is [System.Collections.IDictionary]) { $has = $Admin.Contains('ManagementMode') }
    else { $has = [bool]$Admin.PSObject.Properties['ManagementMode'] }
    # §71: an explicit Replicate on the row decides, through the one rule every other replicable row
    # uses. Absent it, the pre-§71 reading below runs unchanged. (A Target=none row is left to the
    # target gate, which reports it as MSP-local by declaration -- and since §71.7 (b) the producer
    # no longer puts such a row in the bundle at all.)
    $repRaw = "$(Get-PimDownlinkValue -Object $Admin -Key 'Replicate')".Trim()
    if ($repRaw) {
        # A BUNDLE row: the producer ships registry rows without ManagementMode and definition rows
        # with ManagementMode='msp', so a row lacking the field here is a registry row (-AdminSource).
        $rm = Get-PimReplicateMode -Row $Admin -Kind 'admin' -AdminSource Registry
        return @{ synced = ($rm.mode -eq 'Yes'); reason = "$($rm.reason)" }
    }
    if (-not $has) { return @{ synced = $true; reason = 'central registry row (MSP by construction)' } }
    $mode = "$(Get-PimDownlinkValue -Object $Admin -Key 'ManagementMode')".Trim()
    if ($mode -ieq 'msp') { return @{ synced = $true; reason = 'ManagementMode=msp at the master' } }
    $shown = if ($mode) { $mode } else { '(blank)' }
    return @{ synced = $false; reason = "ManagementMode=$shown at the master -- only msp admins are synced to slaves" }
}

# ---------------------------------------------------------------------------
# MASTER SIDE (pure): which of the master's own Account-Definitions-Admins rows are CENTRAL
# admins to publish -- REQUIREMENTS 68.6 row 35. The row is the definition: ManagementMode=msp
# (sync on/off), Ring (which slaves), Target (tags that narrow the ring; blank = every slave in
# the ring). Names are taken from the row as the customer's naming produced them -- nothing is
# derived or reshaped here. Every row that is NOT published is reported with its reason.
# Returns @{ synced; notSynced; mspWithoutRing; adOnly } -- synced rows carry ManagementMode='msp'
# so the slave-side gate (Test-PimDownlinkAdminSynced) reads the master's decision, plus the
# governance fields (AccountStatus / AutoDisableDate) that must flow down from the source.
# ---------------------------------------------------------------------------
function Get-PimCentralAdminsFromDefinitions {
    param([object[]]$Rows = @())
    $synced = New-Object System.Collections.Generic.List[object]
    $notSynced = New-Object System.Collections.Generic.List[object]
    $noRing = New-Object System.Collections.Generic.List[object]
    $adOnly = New-Object System.Collections.Generic.List[object]
    foreach ($r in @($Rows)) {
        if ($null -eq $r) { continue }
        $un = "$(Get-PimDownlinkValue -Object $r -Key 'UserName')".Trim()
        if (-not $un) { $upn = "$(Get-PimDownlinkValue -Object $r -Key 'UserPrincipalName')".Trim(); if ($upn) { $un = ($upn -split '@')[0] } }
        if (-not $un) { continue }
        $mode = "$(Get-PimDownlinkValue -Object $r -Key 'ManagementMode')".Trim()
        # §71: Replicate must agree with ManagementMode, and Target=none keeps the admin MSP-local.
        # Both are decided by the shared rule; a row carrying neither reads exactly as before.
        $repRaw = "$(Get-PimDownlinkValue -Object $r -Key 'Replicate')".Trim()
        $rm = Get-PimReplicateMode -Row $r -Kind 'admin' -AdminSource Definition
        if (($repRaw -or $mode -ieq 'msp') -and $rm.mode -ne 'Yes') {
            $notSynced.Add([ordered]@{ UserName = $un; reason = "$($rm.reason) -- not synced" }) | Out-Null
            continue
        }
        if ($mode -ine 'msp' -and -not $repRaw) {
            # masterOnly marks a BLANK ManagementMode (the value empty or the field absent, as in a v1 CSV): the
            # bundle reports it as not published, because Get-PimReplicateMode now reads it the same way (No).
            # An explicit 'local' is the operator's own declaration and is not reported (unchanged).
            $notSynced.Add([ordered]@{ UserName = $un; reason = "ManagementMode=$(if ($mode) { $mode } else { '(blank)' }) -- not synced"; masterOnly = (-not $mode) }) | Out-Null
            continue
        }
        if ("$(Get-PimDownlinkValue -Object $r -Key 'TargetPlatform')".Trim() -ieq 'AD') {
            $adOnly.Add([ordered]@{ UserName = $un; reason = 'TargetPlatform=AD -- an on-premises-only admin does not exist in a slave (Entra) tenant' }) | Out-Null
            continue
        }
        $ring = "$(Get-PimDownlinkValue -Object $r -Key 'Ring')".Trim()
        if ($ring -notmatch '^\d+$') {
            $noRing.Add([ordered]@{ UserName = $un; reason = "ManagementMode=msp but Ring='$ring' -- no ring reaches no slave (set Ring to a whole number: 0, 1, 2, ...)" }) | Out-Null
            continue
        }
        $tapLife = "$(Get-PimDownlinkValue -Object $r -Key 'TAPLifetimeHours')".Trim()
        $one = [ordered]@{
            UserName         = $un
            DisplayName      = "$(Get-PimDownlinkValue -Object $r -Key 'DisplayName')"
            FirstName        = "$(Get-PimDownlinkValue -Object $r -Key 'FirstName')"
            LastName         = "$(Get-PimDownlinkValue -Object $r -Key 'LastName')"
            Initials         = "$(Get-PimDownlinkValue -Object $r -Key 'Initials')"
            UsageLocation    = "$(Get-PimDownlinkValue -Object $r -Key 'UsageLocation')"
            Purpose          = "$(Get-PimDownlinkValue -Object $r -Key 'Purpose')"
            Ring             = [int]$ring
            Template         = "$(Get-PimDownlinkValue -Object $r -Key 'Template')"
            Target           = "$(Get-PimDownlinkValue -Object $r -Key 'Target')".Trim()
            # 71.19: the SPONSOR DEPARTMENT travels with the admin -- it is what decides who receives its mail and TAP in
            # the managed tenant (that department's row is auto-included as a dependency). ManagerEmail still travels as
            # legacy data for a master that has not moved to departments yet.
            Department       = "$(Get-PimDownlinkValue -Object $r -Key 'Department')".Trim()
            ManagerEmail     = "$(Get-PimDownlinkValue -Object $r -Key 'ManagerEmail')"
            TapLifetimeHours = $tapLife
            AccountStatus    = "$(Get-PimDownlinkValue -Object $r -Key 'AccountStatus')".Trim()
            # 🔴 71.23 -- the bundle carries AutoDisableDate, NOT the legacy OffboardDate. The master
            # resolves either column name on its own row (Get-PimAdminAutoDisableDate) and publishes
            # ONE name, so a slave can never receive both and have to guess between them.
            # UPGRADE ORDER: a slave older than 2.4.364 does not know this key, so master and slave
            # must both be at 2.4.364+ (they are built together; ring 1 is the only live MSP pair).
            AutoDisableDate  = ConvertTo-PimDownlinkLifecycleText (Get-PimAdminAutoDisableDate -Row $r).raw
            ManagementMode   = 'msp'
        }
        # carried only when the master set it, so a row authored before §71 ships the same bytes
        if ($repRaw) { $one['Replicate'] = 'Yes' }
        # 71.15 -- THE ADMIN LIFECYCLE FIELDS the slave's engine reads, taken from the master's definition (governance
        # follows the SOURCE, row 35). Only AccountStatus/AutoDisableDate/TAPLifetimeHours were published, so the slave apply
        # filled the rest with its own defaults (ProvisionDate Now, no TAPStartDate).
        #   ProvisionDate   -> when the account may be created (Test-PimAdminProvisionDue)
        #   TAPStartDate    -> when its TAP starts / is deferred (Select-PimAdminTapCandidates)
        # 🔴 NO retention/delete field (71.21, operator "we will newer delete an accounnt" + "i dont want it to be shown
        # as it confuses"): PIM never deletes a user account anywhere, the field is not supported, and the bundle must
        # not carry anything that implies a slave may delete.
        # NOT CreateTAP (71.17, operator "tap is on for all"): nothing on either side may read it, so it is not published.
        # NOT StatusChangeCode: that is the slave's own authorisation for a local status change, and a central row's
        # status is authorised by the signed bundle instead. Each key is emitted ONLY when the master set it, so a row
        # without them ships the same bytes as before.
        foreach ($lf in 'ProvisionDate','TAPStartDate') {
            $lv = ConvertTo-PimDownlinkLifecycleText (Get-PimDownlinkValue -Object $r -Key $lf)
            if ($lv) { $one[$lf] = $lv }
        }
        $synced.Add($one) | Out-Null
    }
    return @{ synced = $synced.ToArray(); notSynced = $notSynced.ToArray(); mspWithoutRing = $noRing.ToArray(); adOnly = $adOnly.ToArray() }
}

function Select-PimDownlinkAdmins {
    param(
        [object[]]$Admins = @(),
        [Parameter(Mandatory)][int]$SlaveRing
    )
    $keep = New-Object System.Collections.Generic.List[object]
    foreach ($a in @($Admins)) {
        if ($null -eq $a) { continue }
        if (-not (Test-PimDownlinkAdminSynced -Admin $a).synced) { continue }   # row 35: the master's row must say msp
        $ringRaw = Get-PimDownlinkValue -Object $a -Key 'Ring'
        if ($null -eq $ringRaw -or "$ringRaw".Trim() -eq '') { continue }   # no ring => not eligible (fail-safe)
        $ring = [int]$ringRaw
        if ($ring -le $SlaveRing) { $keep.Add($a) | Out-Null }
    }
    $sorted = @($keep.ToArray() | Sort-Object `
        @{ Expression = { [int](Get-PimDownlinkValue -Object $_ -Key 'Ring') } }, `
        @{ Expression = { "$(Get-PimDownlinkValue -Object $_ -Key 'UserName')".ToLowerInvariant() } })
    # Return as a plain array. NB: do NOT `return ,$sorted` -- the unary comma wraps
    # the already-array $sorted into a 1-element array-of-array, which @() at the call
    # site only unwraps one level (leaving a single Object[] element). Plain return +
    # @() wrap at the call site is the PS 5.1-safe contract.
    return $sorted
}

# ---------------------------------------------------------------------------
# RING-GATE VERDICT (pure). Given what the gate SELECTED for ONE customer at
# several rings -- @{ 0 = <rows>; 1 = <rows>; 2 = <rows> } -- decide whether the
# ring gate actually gates. Operator directive 2026-08-07: express the MSP ring
# promise as ONE customer whose ring MOVES, so it can be measured on a two-tenant
# fleet instead of blocking on a third, slave-only tenant.
#
# WHY THIS SHAPE. Asking "does admin X exist in the slave tenant?" is unanswerable
# when the slave IS the master (the master holds every admin from its own estate).
# Asking "for THIS customer, what does the gate SELECT at ring N?" is a property of
# the DECISION, not of the tenant's population -- so a shared tenant cannot confound
# it, and one customer is enough.
#
# Three checks, none of which can pass by accident:
#   1. MONOTONIC  -- a wider ring may only ADD. If a narrow ring selects someone a
#                    wider one does not, it is not a ring gate.
#   2. EXCLUSION  -- nothing above ring N may be selected AT ring N (the leak).
#   3. BOTH WAYS  -- somebody must be excluded at the narrowest ring and admitted at
#                    the widest. Without this the result is VACUOUS: an estate whose
#                    admins all sit at ring 0 satisfies 1 and 2 while proving nothing.
#                    Vacuous is reported as such -- never as a quiet pass.
#
# Returns @{ ok; vacuous; failures = @(); gained = @(); names = @{ring=@(names)} }.
# ok=$true only when there were no failures AND the result is not vacuous.
# NO I/O, NO globals -- offline-testable, and used by BOTH the live scenario matrix
# and tests/Test-PimDownlink.ps1 so the two can never drift.
# ---------------------------------------------------------------------------
function Test-PimDownlinkRingGate {
    param(
        [Parameter(Mandatory)][hashtable]$RingRows
    )
    $rings = @($RingRows.Keys | ForEach-Object { [int]$_ } | Sort-Object)
    $failures = New-Object System.Collections.Generic.List[string]
    $names = @{}
    foreach ($r in $rings) {
        $names[$r] = @(@($RingRows[$r]) | ForEach-Object { "$(Get-PimDownlinkValue -Object $_ -Key 'UserName')" })
    }

    # 1. MONOTONIC across each adjacent pair.
    for ($i = 0; $i -lt ($rings.Count - 1); $i++) {
        $lo = $rings[$i]; $hi = $rings[$i + 1]
        $lost = @($names[$lo] | Where-Object { $names[$hi] -notcontains $_ })
        if ($lost.Count) { $failures.Add("ring $lo selected admin(s) that the wider ring $hi did not -- not a monotonic gate: $($lost -join ', ')") | Out-Null }
    }

    # 2. EXCLUSION: nothing above the ring may be selected at it.
    foreach ($r in $rings) {
        $over = @(@($RingRows[$r]) | Where-Object {
                    $rv = Get-PimDownlinkValue -Object $_ -Key 'Ring'
                    ($null -ne $rv) -and ("$rv".Trim() -ne '') -and ([int]$rv -gt $r)
                 } | ForEach-Object { "$(Get-PimDownlinkValue -Object $_ -Key 'UserName')(ring $(Get-PimDownlinkValue -Object $_ -Key 'Ring'))" })
        if ($over.Count) { $failures.Add("RING LEAK at ring ${r}: selected admin(s) above the ring: $($over -join ', ')") | Out-Null }
    }

    # 3. BOTH DIRECTIONS on one customer.
    $lowest = $rings[0]; $highest = $rings[$rings.Count - 1]
    $gained = @($names[$highest] | Where-Object { $names[$lowest] -notcontains $_ })
    $vacuous = ($gained.Count -eq 0)

    # WHY vacuous, in the caller's words. These two look identical in the result but have
    # completely different causes, and conflating them cost a live session a diagnosis:
    # an EMPTY baseline (the bundle carries no admin rows at all -- e.g. it was generated
    # before the estate was seeded) is a BROKEN INPUT, whereas an all-at-the-widest-ring
    # estate is a legitimate shape that simply cannot exercise the exclusion direction.
    $vacuousReason = $null
    if ($vacuous) {
        $vacuousReason = if (@($names[$highest]).Count -eq 0) {
            "the baseline carries NO admin rows at all (0 selected even at the widest ring $highest) -- this is an EMPTY/BROKEN baseline input, not an estate shape. Check that the signed bundle was generated AFTER the estate was seeded."
        } else {
            "every one of the $(@($names[$highest]).Count) baseline admin(s) already reaches the narrowest ring $lowest, so widening the ring adds nobody and the exclusion direction cannot be exercised. Seed an admin above ring $lowest to make this measurable."
        }
    }

    return @{
        ok            = (($failures.Count -eq 0) -and (-not $vacuous))
        vacuous       = $vacuous
        vacuousReason = $vacuousReason
        failures      = @($failures.ToArray())
        gained        = @($gained)
        names         = $names
    }
}

# ---------------------------------------------------------------------------
# SIGNATURE / VALIDITY VERIFY (pure). Verify a signed baseline document with a
# CALLER-SUPPLIED public key (the real key never leaves mgmt1; tests pass an
# EPHEMERAL test key). Mirrors Test-PimBaselineDoc but lets a test inject the
# verifying RSA so we can prove valid / tampered / wrong-key WITHOUT the prod key
# and WITHOUT RSA.ImportFromPem (PS 5.1).
#
# -Doc           : @{ payloadB64; signature; keyThumbprint } (the signed bundle).
# -PublicKey     : an [RSA] (or an X509Certificate2) to verify with. When omitted,
#                  falls back to the embedded PIM4EntraPS-Baseline public cert (via
#                  Test-PimBaselineDoc) so production verification is unchanged.
# -AllowedKind   : accepted payload.kind values (default 'baseline').
# -NowUtc        : clock injection for expiry tests (default [datetime]::UtcNow).
# -LastVersion   : anti-rollback floor (default 0; payload.version must be >=).
# -RevokedSigners: SEC-25 -- signer ids this tenant has revoked (its pim.Settings
#                  'BaselineRevokedSigners'). The signer is the key that VERIFIES the
#                  document (Get-PimBaselineDocSignerId), never its keyThumbprint claim.
# Returns @{ ok; reason; payload; code; signer } -- ok=$false on any failure (never
# throws on a bad sig/expiry/rollback/revoked; throws only on a structurally-broken
# doc). `code` classifies a refusal for callers that must branch on it without
# parsing prose: format | signature | revoked | product | kind | expired | rollback.
# ---------------------------------------------------------------------------
function Test-PimDownlinkBaseline {
    param(
        [Parameter(Mandatory)][object]$Doc,
        [object]$PublicKey,
        [string[]]$AllowedKind = @('baseline'),
        [datetime]$NowUtc = ([datetime]::UtcNow),
        [int64]$LastVersion = 0,
        [AllowEmptyCollection()][string[]]$RevokedSigners = @()
    )
    $payloadB64 = "$(Get-PimDownlinkValue -Object $Doc -Key 'payloadB64')"
    $sigB64     = "$(Get-PimDownlinkValue -Object $Doc -Key 'signature')"
    if (-not $payloadB64.Trim() -or -not $sigB64.Trim()) {
        return @{ ok = $false; reason = 'not a signed bundle (payloadB64/signature missing)'; payload = $null; code = 'format'; signer = '' }
    }
    # SEC-25: the revoked-signer gate. Checked BEFORE the signature is trusted -- a revoked key is refused
    # whether or not its signature still verifies (that is what revoking a compromised key means).
    $signer = ''
    if (Get-Command Get-PimBaselineDocSignerId -ErrorAction SilentlyContinue) {
        try { $signer = "$(Get-PimBaselineDocSignerId -Doc $Doc -PublicKey $PublicKey)" } catch { $signer = '' }
    }
    $revokedNorm = @(@($RevokedSigners) | Where-Object { "$_".Trim() } | ForEach-Object {
        if (Get-Command ConvertTo-PimBaselineSignerId -ErrorAction SilentlyContinue) { ConvertTo-PimBaselineSignerId -Value "$_" } else { "$_".Trim() } } | Where-Object { $_ })
    if ($revokedNorm.Count) {
        if (-not $signer) {
            return @{ ok = $false; reason = 'SIGNER UNKNOWN -- the verifying key could not be identified, so the revocation list cannot be applied; refusing'; payload = $null; code = 'revoked'; signer = '' }
        }
        if ($revokedNorm -ccontains $signer) {
            return @{ ok = $false; reason = "SIGNER REVOKED -- the bundle is signed by $signer, which this tenant has revoked (pim.Settings 'BaselineRevokedSigners'); nothing it signed is applied"; payload = $null; code = 'revoked'; signer = $signer }
        }
    }

    $payloadBytes = $null; $sigBytes = $null
    try {
        $payloadBytes = [Convert]::FromBase64String($payloadB64)
        $sigBytes     = [Convert]::FromBase64String($sigB64)
    } catch {
        return @{ ok = $false; reason = "base64 decode failed: $($_.Exception.Message)"; payload = $null; code = 'format'; signer = $signer }
    }

    # Resolve the verifying RSA public key.
    $rsa = $null
    if ($null -ne $PublicKey) {
        if ($PublicKey -is [System.Security.Cryptography.RSA]) { $rsa = $PublicKey }
        elseif ($PublicKey -is [System.Security.Cryptography.X509Certificates.X509Certificate2]) {
            $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($PublicKey)
        } else {
            return @{ ok = $false; reason = 'unsupported -PublicKey type (need [RSA] or X509Certificate2)'; payload = $null; code = 'format'; signer = $signer }
        }
    }

    $ok = $false
    if ($rsa) {
        try {
            $ok = $rsa.VerifyData($payloadBytes, $sigBytes, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
        } catch {
            return @{ ok = $false; reason = "signature verify threw: $($_.Exception.Message)"; payload = $null; code = 'signature'; signer = $signer }
        }
        if (-not $ok) { return @{ ok = $false; reason = 'SIGNATURE INVALID -- bundle tampered or signed by the wrong key'; payload = $null; code = 'signature'; signer = $signer } }
    } else {
        # No explicit key: defer to the embedded prod public cert via Test-PimBaselineDoc.
        if (-not (Get-Command Test-PimBaselineDoc -ErrorAction SilentlyContinue)) {
            return @{ ok = $false; reason = 'no -PublicKey and Test-PimBaselineDoc (embedded cert) not loaded'; payload = $null; code = 'signature'; signer = $signer }
        }
        $p = $null
        try {
            $p = Test-PimBaselineDoc -Doc $Doc -AllowedKind $AllowedKind
        } catch {
            return @{ ok = $false; reason = "embedded-cert verify failed: $($_.Exception.Message)"; payload = $null; code = 'signature'; signer = $signer }
        }
        # Test-PimBaselineDoc already enforced product/kind. Continue with expiry/rollback below.
        $fin = Test-PimDownlinkBaselineFinish -PayloadObject $p -AllowedKind $AllowedKind -NowUtc $NowUtc -LastVersion $LastVersion
        $fin['signer'] = $signer
        return $fin
    }

    # Parse the now-trusted payload and run the shape/expiry/rollback gates.
    $payloadObj = $null
    try { $payloadObj = [System.Text.Encoding]::UTF8.GetString($payloadBytes) | ConvertFrom-Json }
    catch { return @{ ok = $false; reason = "payload JSON parse failed: $($_.Exception.Message)"; payload = $null; code = 'format'; signer = $signer } }
    $fin = Test-PimDownlinkBaselineFinish -PayloadObject $payloadObj -AllowedKind $AllowedKind -NowUtc $NowUtc -LastVersion $LastVersion
    $fin['signer'] = $signer
    return $fin
}

# Shared post-signature gates (product/kind/expiry/anti-rollback). Pure.
function Test-PimDownlinkBaselineFinish {
    param(
        [Parameter(Mandatory)][object]$PayloadObject,
        [string[]]$AllowedKind = @('baseline'),
        [datetime]$NowUtc = ([datetime]::UtcNow),
        [int64]$LastVersion = 0
    )
    $p = $PayloadObject
    if ("$(Get-PimDownlinkValue -Object $p -Key 'product')" -ne 'PIM4EntraPS') {
        return @{ ok = $false; reason = "unexpected bundle product '$(Get-PimDownlinkValue -Object $p -Key 'product')'"; payload = $null; code = 'product' }
    }
    $kind = "$(Get-PimDownlinkValue -Object $p -Key 'kind')"
    if (@($AllowedKind) -notcontains $kind) {
        return @{ ok = $false; reason = "unexpected bundle kind '$kind' (allowed: $($AllowedKind -join ', '))"; payload = $null; code = 'kind' }
    }
    $validTo = "$(Get-PimDownlinkValue -Object $p -Key 'validToUtc')"
    if ($validTo.Trim()) {
        $vt = $null
        try { $vt = [datetime]::Parse($validTo, [System.Globalization.CultureInfo]::InvariantCulture) } catch {}
        if ($vt -and $NowUtc.ToUniversalTime() -gt $vt.ToUniversalTime()) {
            return @{ ok = $false; reason = "baseline bundle expired ($validTo)"; payload = $null; code = 'expired' }
        }
    }
    $ver = 0
    $verRaw = Get-PimDownlinkValue -Object $p -Key 'version'
    if ($null -ne $verRaw -and "$verRaw".Trim()) { try { $ver = [int64]$verRaw } catch { $ver = 0 } }
    if ($ver -lt [int64]$LastVersion) {
        return @{ ok = $false; reason = "baseline rollback refused: bundle version $ver < last-applied $LastVersion"; payload = $null; code = 'rollback' }
    }
    return @{ ok = $true; reason = "verified (version $ver, kind $kind)"; payload = $p; code = 'ok' }
}

# ---------------------------------------------------------------------------
# SEC-25 -- THE CENTRAL KILL SWITCH ON THE PULL PATH (pure).
#
# The master publishes a SIGNED kind='central-kill' manifest (DESIGN 13.17) next to the bundle. It is
# verified exactly like the bundle -- same keys, same revoked-signer list -- and an ACTIVE one stops the
# downlink: nothing more is taken from the master while the kill stands, and the run says so, loudly,
# naming what the manifest kills. (Applying the kills themselves is the engine kill-switch pipeline's
# job -- Resolve-PimCentralKill -> AccountStatus flips -- and is not done here.)
#   -Doc      : the pulled manifest, or $null when the master publishes none.
#   -Checked  : $false when no source was consulted (e.g. a -BaselineDocPath run with no kill source) --
#               reported as NOT CHECKED, never as "no kill".
#   -FetchError : the transport failure text when the source could not be read (404 is "none", decided by
#               the caller) -- that is a REFUSAL: a kill we could not read must not read as "no kill".
# Returns @{ state = none|active|expired|invalid|unknown|notchecked; blocks; kills; reason; signer }.
#   blocks=$true for active, invalid and unknown (fail closed); false for none, expired and notchecked.
# ---------------------------------------------------------------------------
function Get-PimCentralKillState {
    param(
        [AllowNull()][object]$Doc,
        [bool]$Checked = $true,
        [string]$FetchError = '',
        [string]$NotCheckedReason = '',
        [object]$PublicKey,
        [AllowEmptyCollection()][string[]]$RevokedSigners = @(),
        [datetime]$NowUtc = ([datetime]::UtcNow)
    )
    if ("$FetchError".Trim()) {
        return @{ state = 'unknown'; blocks = $true; kills = @(); signer = ''
                  reason = "CENTRAL KILL UNKNOWN -- the kill manifest could not be read ($FetchError); refusing to pull while a kill might be standing" }
    }
    if (-not $Checked) {
        $why = if ("$NotCheckedReason".Trim()) { "$NotCheckedReason".Trim() } else { 'central kill NOT CHECKED -- no kill source for this run (a -BaselineDocPath run, or -CentralKillUrl none)' }
        return @{ state = 'notchecked'; blocks = $false; kills = @(); signer = ''; reason = $why }
    }
    if ($null -eq $Doc) { return @{ state = 'none'; blocks = $false; kills = @(); signer = ''; reason = 'no central kill published' } }
    $v = Test-PimDownlinkBaseline -Doc $Doc -PublicKey $PublicKey -AllowedKind @('central-kill') -NowUtc $NowUtc -RevokedSigners @($RevokedSigners)
    if (-not $v.ok) {
        if ("$($v.code)" -eq 'expired') {
            return @{ state = 'expired'; blocks = $false; kills = @(); signer = "$($v.signer)"; reason = "central kill manifest present but EXPIRED -- not in force ($($v.reason))" }
        }
        # A manifest we cannot verify is refused -- and so is the pull. Whoever can write a bad manifest to the
        # master's container can equally corrupt the bundle, so this costs no availability the bundle does not
        # already cost, and it keeps "a kill we could not verify" from ever reading as "no kill".
        return @{ state = 'invalid'; blocks = $true; kills = @(); signer = "$($v.signer)"; reason = "CENTRAL KILL MANIFEST INVALID -- $($v.reason); refusing to pull until it verifies or is withdrawn" }
    }
    $kills = @(@(Get-PimDownlinkValue -Object $v.payload -Key 'kills') | Where-Object { $null -ne $_ })
    if (-not $kills.Count) {
        return @{ state = 'none'; blocks = $false; kills = @(); signer = "$($v.signer)"; reason = 'central kill manifest verified and EMPTY -- no kill in force' }
    }
    $names = @($kills | ForEach-Object {
        $u = "$(Get-PimDownlinkValue -Object $_ -Key 'upn')".Trim(); if (-not $u) { $u = "$(Get-PimDownlinkValue -Object $_ -Key 'userName')".Trim() }
        "$u ($("$(Get-PimDownlinkValue -Object $_ -Key 'status')".Trim()))" })
    return @{ state = 'active'; blocks = $true; kills = $kills; signer = "$($v.signer)"
              reason = "CENTRAL KILL ACTIVE -- the master's signed kill manifest is in force ($($kills.Count) entr$(if ($kills.Count -eq 1) { 'y' } else { 'ies' }): $($names -join ', ')); this tenant takes NOTHING from the master until it is withdrawn" }
}

# ---------------------------------------------------------------------------
# IMP-38 -- THE TEMPLATE VERSION GATE USES THE SLAVE'S **LOCAL** RING (pure).
#
# The template ring map (config/template-ring-map.sample.json) is written by the MASTER, and its
# `assignments[<tenant>].<Template>.ring` / `default` would put the master in charge of which ring a
# managed tenant is on. Every ring is LOCAL in the slave (DESIGN; operator 2026-09-18), so that half of
# the map is IGNORED here: only `promotions` (which version the master approves FOR a ring) is read, and
# the ring it is read for is this tenant's own -SlaveRing. A master assignment that disagrees is reported,
# never obeyed. 📌 The gate stays INERT on the scheduled pull: downlink-job-entry passes no map, and a map
# is armed only by an operator passing -TemplateRingMapPath/-Url to the slave-side entry scripts.
# Returns @{ plan; ignoredMasterRing; note }.
# ---------------------------------------------------------------------------
function Get-PimLocalTemplateRingPlan {
    param(
        [Parameter(Mandatory)][object]$RingMap,
        [Parameter(Mandatory)][string]$TenantId,
        [Parameter(Mandatory)][int]$SlaveRing,
        [string]$Template = 'Baseline',
        [string]$Channel = 'managed'
    )
    $masterRing = $null
    if (Get-Command Resolve-PimRingAssignment -ErrorAction SilentlyContinue) {
        try {
            $ma = Resolve-PimRingAssignment -Assignments (Get-PimDownlinkValue -Object $RingMap -Key 'assignments') -TenantId $TenantId `
                      -Solution $Template -DefaultRing (Get-PimDownlinkValue -Object $RingMap -Key 'default')
            if ($ma.Assigned) { $masterRing = [int]$ma.Ring }
        } catch { $masterRing = $null }
    }
    $localAssign = [pscustomobject]@{ $TenantId = [pscustomobject]@{ $Template = [pscustomobject]@{ ring = [int]$SlaveRing } } }
    $plan = Get-PimTemplateRingPlan -Template $Template -TenantId $TenantId -Assignments $localAssign `
                -Promotions (Get-PimDownlinkValue -Object $RingMap -Key 'promotions') -Channel $Channel -DefaultRing $null
    $note = "version gate keyed on this tenant's LOCAL ring $SlaveRing (the map's assignments/default are the master's and are not used)"
    $ignored = $null
    if ($null -ne $masterRing -and $masterRing -ne [int]$SlaveRing) {
        $ignored = $masterRing
        $note = "the master's map assigns ring $masterRing to this tenant -- IGNORED: the ring is local, and this tenant is on ring $SlaveRing"
    }
    return @{ plan = $plan; ignoredMasterRing = $ignored; note = $note }
}

# ---------------------------------------------------------------------------
# SYNC-FILE PATH RESOLUTION (pure). Where does the downlink stage the per-tenant
# sync files for THIS scenario? The matrix reads:
#     central (S5): $env:PIM_SyncRootCentral / <tenantId> / *.json
#     local   (S6): $env:PIM_SyncRootLocal   / <tenantId> / *.json
# Resolution rule (mirrors Get-PimScenarioEntryPlan .syncFileLocation):
#     syncFileLocation = 'central-msp'  -> root = -CentralRoot   (per-tenant subfolder)
#     syncFileLocation = 'local-slave'  -> root = -LocalRoot
#     syncFileLocation = 'none'         -> no staging (single/non-managed)
# Returns @{ stage; root; tenantFolder; files=@{name->relpath} } -- stage=$false
# when the scenario stages nothing (none). PURE: builds paths, writes nothing.
# ---------------------------------------------------------------------------
function Resolve-PimDownlinkSyncPath {
    param(
        [Parameter(Mandatory)][string]$SyncFileLocation,   # none | central-msp | local-slave
        [Parameter(Mandatory)][string]$TenantId,
        [string]$CentralRoot,
        [string]$LocalRoot
    )
    $loc = "$SyncFileLocation".Trim().ToLowerInvariant()
    if ($loc -eq 'none' -or -not $loc) {
        return @{ stage = $false; root = ''; tenantFolder = ''; reason = 'scenario stages no sync files (syncFileLocation=none)'; files = @{} }
    }
    $root = $null
    if ($loc -eq 'central-msp') { $root = $CentralRoot }
    elseif ($loc -eq 'local-slave') { $root = $LocalRoot }
    else { return @{ stage = $false; root = ''; tenantFolder = ''; reason = "unknown syncFileLocation '$SyncFileLocation'"; files = @{} } }

    if (-not "$root".Trim()) {
        return @{ stage = $true; root = ''; tenantFolder = ''; reason = "syncFileLocation=$loc but no staging root supplied"; files = @{} }
    }
    $tenantFolder = Join-Path $root "$TenantId"
    return @{
        stage        = $true
        root         = "$root"
        tenantFolder = $tenantFolder
        reason       = "stage per-tenant sync files under $tenantFolder"
        files        = @{
            admins      = (Join-Path $tenantFolder 'admins.sync.json')
            manifest    = (Join-Path $tenantFolder 'manifest.sync.json')
            # MSP-2 / control #2. Staged only when the plan produced a projection;
            # the staging loop iterates $plan.content, so an absent projection
            # simply never writes this file.
            assignments = (Join-Path $tenantFolder 'assignments.sync.json')
        }
    }
}

# ---------------------------------------------------------------------------
# MSP-4 -- ARTIFACT TARGETING: which TENANTS does this artifact go to? (pure)
#
# Operator, 2026-08-13: *"not all roles / admins / definitions / policies go out to
# all"* and *"this role goes to only 5/28 tenants"*. So targeting is a property of the
# ARTIFACT, naming the tenants it reaches.
#
# 🔑 THREE NARROWINGS, KEPT ORTHOGONAL ON PURPOSE. PIM has already been bitten by
# conflating meanings of "ring" (see the note on Select-PimDownlinkAdmins), so:
#     RING   = which VERSION a tenant may take          (Get-PimTemplateRingPlan)
#     TARGET = which TENANTS an artifact reaches        (THIS function)
#     POLICY = which ROLE TAGS a relationship accepts   (Select-PimProjectedAssignments)
#     GATE   = which CLASSES a customer consents to     (RING-1 capabilities)
# Each reports separately. Collapse them and a missing role has four plausible causes
# and no way to tell them apart.
#
# TARGET GRAMMAR -- a semicolon/comma list of selectors, matched case-insensitively:
#     ''  or  '*'  or  'all'   -> every tenant (THE DEFAULT: absent target = today's
#                                 behaviour, so nothing changes for existing rows)
#     'none'                   -> MSP-LOCAL. Never leaves the master. See below.
#     'tag:<name>'             -> tenants carrying that tag
#     'tenant:<guid>'          -> one explicit tenant
#     a bare word              -> treated as 'tag:<word>' (the common case reads well)
# 'none' WINS over everything else in the same expression: a row that says it is
# MSP-local cannot also be published by a second selector someone added later.
#
# 🔒 WHY 'none' IS EXPLICIT RATHER THAN JUST OMITTING THE ROW. Today "not published" is
# expressed by absence, so *MSP-local by intent* and *forgotten to publish* look
# identical. Declaring it makes the intent reviewable -- the plan can report "3
# artifacts are MSP-local by declaration" separately from "0 matched this tenant",
# which are opposite findings.
#
# Returns @{ match; reason } -- reason is always populated, including on a match, so
# "why did this arrive / not arrive" is answerable from the plan alone.
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# AUTHORING CHECK (pure) for an admin row's Target -- REQUIREMENTS 68.6 row 35. The same grammar
# Test-PimArtifactTarget reads (tag:<t> / bare tag / tenant:<guid> / all / * / none, ; or ,
# separated). -KnownTags is the MSP registry's tenant tag list; -TagsKnown says whether that list
# was actually read. An unknown tag is only reported when the list is KNOWN -- "not checked" must
# never read as "fine" or as "wrong".
# Returns @{ ok; tokens; tags; unknownTags; malformed; checkedTags; normalized }.
# ---------------------------------------------------------------------------
function Test-PimAdminTargetSelector {
    param([AllowEmptyString()][string]$Target, [string[]]$KnownTags = @(), [switch]$TagsKnown)
    $t = "$Target".Trim()
    $known = New-Object System.Collections.Generic.HashSet[string]
    foreach ($k in @($KnownTags)) { if ("$k".Trim()) { [void]$known.Add("$k".Trim().ToLowerInvariant()) } }
    $tokens = @($t -split '[;,]' | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
    $tags = New-Object System.Collections.Generic.List[string]
    $unknown = New-Object System.Collections.Generic.List[string]
    $bad = New-Object System.Collections.Generic.List[string]
    $norm = New-Object System.Collections.Generic.List[string]
    foreach ($tok in $tokens) {
        $l = $tok.ToLowerInvariant()
        if ($l -in @('*', 'all', 'none')) { $norm.Add($l); continue }
        if ($l -like 'tenant:*') {
            if ($l.Substring(7).Trim() -match '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$') { $norm.Add($l); continue }
            $bad.Add($tok); continue
        }
        $tag = if ($l -like 'tag:*') { $tok.Substring(4).Trim() } else { $tok }
        # §71 / framework MSP-4 SURFACE: a tag is a free `key:value` label (region:eu), and `a+b` is
        # ALL-OF (the tenant must carry both). Each part is validated on its own, so `tag:eu+` is
        # malformed rather than silently read as `tag:eu`.
        $parts = @($tag -split '\+' | ForEach-Object { "$_".Trim() })
        if (-not $tag -or @($parts | Where-Object { -not $_ -or $_ -notmatch '^[A-Za-z0-9._:-]+$' }).Count) { $bad.Add($tok); continue }
        foreach ($p in $parts) {
            $tags.Add($p)
            if ($TagsKnown -and -not $known.Contains($p.ToLowerInvariant())) { $unknown.Add($p) }
        }
        $norm.Add("tag:$($parts -join '+')")
    }
    return @{
        ok          = ($bad.Count -eq 0 -and $unknown.Count -eq 0)
        tokens      = $tokens
        tags        = $tags.ToArray()
        unknownTags = $unknown.ToArray()
        malformed   = $bad.ToArray()
        checkedTags = [bool]$TagsKnown
        normalized  = ($norm.ToArray() -join ';')
    }
}

function Test-PimArtifactTarget {
    param(
        [string]$Target,
        [Parameter(Mandatory)][string]$TenantId,
        [string[]]$TenantTags = @()
    )
    $t = "$Target".Trim()
    if (-not $t) { return @{ match = $true; reason = 'no target set -- reaches every managed tenant' } }

    $sel = @($t -split '[;,]' | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
    if (-not $sel.Count) { return @{ match = $true; reason = 'no target set -- reaches every managed tenant' } }

    $lower = { param($s) "$s".Trim().ToLowerInvariant() }
    # 'none' is checked FIRST and unconditionally: MSP-local must not be overridable by
    # another selector sitting beside it in the same expression.
    foreach ($s in $sel) { if ((& $lower $s) -eq 'none') { return @{ match = $false; reason = 'master tenant only by declaration (target=none) -- never replicated to managed tenants' } } }

    $tags = New-Object System.Collections.Generic.HashSet[string]
    foreach ($g in @($TenantTags)) { [void]$tags.Add((& $lower $g)) }
    $tid = & $lower $TenantId

    foreach ($s in $sel) {
        $l = & $lower $s
        if ($l -eq '*' -or $l -eq 'all') { return @{ match = $true; reason = 'targets all tenants' } }
        if ($l -like 'tenant:*') {
            if ($l.Substring(7).Trim() -eq $tid) { return @{ match = $true; reason = "explicitly targeted by tenant id" } }
            continue
        }
        $tag = $l
        if ($l -like 'tag:*') { $tag = $l.Substring(4).Trim() }
        if (-not $tag) { continue }
        # §71: `a+b` is ALL-OF. Tag terms stay ANY-OF across the list; within one term every part
        # must be carried. An empty part (`eu+`) can never be satisfied -- a malformed term narrows
        # to nothing rather than widening to its valid half.
        if ($tag.Contains('+')) {
            $parts = @($tag -split '\+' | ForEach-Object { "$_".Trim() })
            if (@($parts | Where-Object { -not $_ }).Count) { continue }
            if (-not @($parts | Where-Object { -not $tags.Contains($_) }).Count) {
                return @{ match = $true; reason = "tenant carries all of the tags '$($parts -join "' + '")'" }
            }
            continue
        }
        if ($tags.Contains($tag)) { return @{ match = $true; reason = "tenant carries the tag '$tag'" } }
    }
    return @{ match = $false; reason = "tenant matches none of the target selectors ($($sel -join ', '))" }
}

# =============================================================================
# §71 -- MSP REPLICATION TARGETING (framework DOCS/REQUIREMENTS.md MSP-4 -> "MSP-4 SURFACE --
# THE REPLICATION TARGET CONTRACT"). PURE.
#
# Every replicable master row carries Replicate (No | Yes | Follow) + Ring + Target, and a
# managed tenant T receives row R iff  Replicate != No  AND  ring(R) admits ring(T)  AND  Target
# matches T. Ring AND target, never OR. A row another reaching row NEEDS is auto-included for T
# even when its own fields would exclude it, and that inclusion is WARNED, naming the row, the
# dependent and the tenant. Follow = "only as a dependency / follower".
#
# 🔒 BLANK = TODAY (v1->v2 no regression). Blank Replicate is the documented default for the row's
# kind, and each default reproduces the behaviour before §71 byte for byte:
#     admin       -> ManagementMode=msp => Yes (at its Ring), anything else => No -- including an
#                    Account-Definitions-Admins row with NO ManagementMode field (a v1 CSV import):
#                    blank ManagementMode = master tenant only. Only a pim.CentralAdmins registry row
#                    (Owner='MSP', which has no ManagementMode column) is MSP by construction => Yes,
#                    and the CALLER says which one it holds (-AdminSource), never the row's shape.
#     membership  -> Follow (follows its admin)
#     group       -> Follow (included when a replicated row needs it)
#     nesting     -> Follow (follows its role group)
#     binding     -> Follow (an Entra role binding follows its group)
#     resource    -> NOT replicated. PIM-Assignments-Roles-AUs / -Azure-Resources / -Workloads name
#                    objects that live in ONE tenant (an AU, a subscription scope, a workspace); they
#                    were never in the bundle, so blank keeps them out and only an EXPLICIT Follow/Yes
#                    carries them. Reported as an operator decision in §71.
# A non-admin row with a blank Ring is not narrowed by ring; an admin with no Ring still reaches no
# slave (the pre-§71 rule, unchanged).
# =============================================================================
function Get-PimReplicationKindForEntity {
    param([string]$Entity)
    switch -Regex ("$Entity".Trim()) {
        '^Account-Definitions-Admins$'                                          { return 'admin' }
        '^PIM-Assignments-Admins$'                                              { return 'membership' }
        '^PIM-Definitions-(Roles|Organization|Departments|Projects|CrossOrg|Processes|Tasks|Services)$' { return 'group' }
        '^PIM-Assignments-Groups$'                                              { return 'nesting' }
        '^PIM-Assignments-Roles-Groups$'                                        { return 'binding' }
        '^PIM-Assignments-(Roles-AUs|Azure-Resources|Workloads)$'               { return 'resource' }
    }
    return ''
}

function Get-PimReplicationEntities {
    # The entities that carry Replicate/Ring/Target (§71.4). Order = authoring order in the grid.
    return @('Account-Definitions-Admins','PIM-Assignments-Admins',
             'PIM-Definitions-Roles','PIM-Definitions-Organization','PIM-Definitions-Departments','PIM-Definitions-Projects','PIM-Definitions-CrossOrg',
             'PIM-Definitions-Processes','PIM-Definitions-Tasks','PIM-Definitions-Services',
             'PIM-Assignments-Groups','PIM-Assignments-Roles-Groups',
             'PIM-Assignments-Roles-AUs','PIM-Assignments-Azure-Resources','PIM-Assignments-Workloads')
}

function Get-PimReplicateMode {
    <#
      The EFFECTIVE Replicate of one row. Returns @{ mode = Yes|No|Follow; explicit; valid; reason }.
      `valid=$false` rows are FAIL-CLOSED to No, and the reason says why -- the validator and the PUT
      gate refuse them, but a row that slips past both must narrow, never widen.

      -AdminSource (admins only) -- WHERE the admin row came from, declared by the caller:
        Definition (default) = an Account-Definitions-Admins row (pim.Rows / a CSV / the grid). Blank
                     ManagementMode -- the value empty OR the field absent, as in a v1 CSV -- is
                     "master tenant only" => No, which is exactly what the bundle producer does
                     (Get-PimCentralAdminsFromDefinitions never publishes it).
        Registry   = a pim.CentralAdmins row (Owner='MSP'), or a bundle row the producer took from it.
                     That table has no ManagementMode column and holds MSP admins only, so a row
                     WITHOUT the field is MSP by construction => Yes.
      The row's shape cannot tell the two apart (a registry row carries FirstName / DisplayName too),
      so the signal is the caller's: only the registry probe in Select-PimBaselineBundleContent and
      the slave-side gate over bundle rows (Test-PimDownlinkAdminSynced) pass Registry. The default is
      the narrow reading, so a caller that forgets to say narrows -- never widens.
    #>
    param([object]$Row, [Parameter(Mandatory)][ValidateSet('admin','membership','group','nesting','binding','resource')][string]$Kind,
          [ValidateSet('Definition','Registry')][string]$AdminSource = 'Definition')
    $raw = "$(Get-PimDownlinkValue -Object $Row -Key 'Replicate')".Trim()
    $norm = ''
    if ($raw) {
        if ($raw -ieq 'yes') { $norm = 'Yes' } elseif ($raw -ieq 'no') { $norm = 'No' } elseif ($raw -ieq 'follow') { $norm = 'Follow' }
        else { return @{ mode = 'No'; explicit = $true; valid = $false; reason = "Replicate='$raw' is not No, Yes or Follow -- treated as No (fail closed)" } }
    }
    $tgt = "$(Get-PimDownlinkValue -Object $Row -Key 'Target')"
    $isNone = [bool](@($tgt -split '[;,]' | Where-Object { "$_".Trim() -ieq 'none' }).Count)

    if ($Kind -eq 'admin') {
        $hasMm = $false
        if ($Row -is [System.Collections.IDictionary]) { $hasMm = $Row.Contains('ManagementMode') }
        elseif ($null -ne $Row) { $hasMm = [bool]$Row.PSObject.Properties['ManagementMode'] }
        $mm = "$(Get-PimDownlinkValue -Object $Row -Key 'ManagementMode')".Trim()
        # no ManagementMode field on a REGISTRY row (pim.CentralAdmins, declared by the caller) = MSP by
        # construction. On a definition row a missing field is blank = master tenant only.
        $regByConstruction = (-not $hasMm) -and $AdminSource -eq 'Registry'
        $mmMode = if ($regByConstruction) { 'Yes' } elseif ($mm -ieq 'msp') { 'Yes' } else { 'No' }
        if ($norm -eq 'Follow') {
            return @{ mode = 'No'; explicit = $true; valid = $false; reason = 'Replicate=Follow is not valid on an admin (nothing depends on an admin) -- use Yes or No' }
        }
        # 2.4.378 (operator: "you decide"): a DEFINITION admin whose ManagementMode field is ABSENT (a v1 CSV) is held to the
        # same rule as an empty one -- Replicate must agree with ManagementMode, so Replicate=Yes without ManagementMode=msp
        # is REFUSED (fail closed), not published. Only a registry row (declared by the caller) is MSP by construction.
        if ($norm -and ($hasMm -or $AdminSource -eq 'Definition') -and $norm -ne $mmMode) {
            $shown = if ($mm) { $mm } else { '(blank)' }
            return @{ mode = 'No'; explicit = $true; valid = $false; reason = "ManagementMode=$shown and Replicate=$norm disagree -- refused (msp goes with Yes, local/blank with No)" }
        }
        $mode = if ($norm) { $norm } else { $mmMode }
        if ($mode -eq 'Yes' -and $isNone) { return @{ mode = 'No'; explicit = $true; valid = $true; reason = 'master tenant only by declaration (Target=none) -- never published' } }
        $why = if ($norm) { "Replicate=$norm" } elseif ($regByConstruction) { 'central registry row (MSP by construction)' } elseif ($mode -eq 'Yes') { 'ManagementMode=msp' } elseif (-not $mm) { 'ManagementMode blank -- master tenant only' } else { "ManagementMode=$mm -- not replicated" }
        return @{ mode = $mode; explicit = [bool]$norm; valid = $true; reason = $why }
    }
    if ($isNone -and $norm -ne 'No') { return @{ mode = 'No'; explicit = $true; valid = $true; reason = 'master tenant only by declaration (Target=none) -- never replicated' } }
    if ($norm) {
        $why = if ($norm -eq 'No') { 'Replicate=No -- not replicated' } else { "Replicate=$norm" }
        return @{ mode = $norm; explicit = $true; valid = $true; reason = $why }
    }
    if ($Kind -eq 'resource') {
        return @{ mode = 'No'; explicit = $false; valid = $true; reason = 'a tenant-scoped resource binding is not replicated unless Replicate is set to Follow or Yes' }
    }
    return @{ mode = 'Follow'; explicit = $false; valid = $true; reason = 'Replicate blank = Follow (replicated when a replicated row needs it)' }
}

function Test-PimReplicationRingAdmits {
    param([object]$Row, [Parameter(Mandatory)][string]$Kind, [Parameter(Mandatory)][int]$TenantRing)
    $r = "$(Get-PimDownlinkValue -Object $Row -Key 'Ring')".Trim()
    if (-not $r) {
        if ($Kind -eq 'admin') { return @{ admits = $false; reason = 'no Ring -- an admin without a ring reaches no slave' } }
        return @{ admits = $true; reason = 'no Ring set -- not narrowed by ring' }
    }
    if ($r -notmatch '^\d+$') { return @{ admits = $false; reason = "Ring='$r' is not a ring number -- reaches no tenant (fail closed)" } }
    if ([int]$r -le $TenantRing) { return @{ admits = $true; reason = "ring $r admits tenant ring $TenantRing" } }
    return @{ admits = $false; reason = "its Ring $r is above this tenant's ring $TenantRing" }
}

function Test-PimReplicationReach {
    <#
      THE REACH RULE for one row and one tenant (framework MSP-4 SURFACE item 4). Returns
      @{ reach; mode; axis = ''|replicate|ring|target; reason }. For a Follow row, reach=$true means
      "it may follow here" -- its own Ring/Target do not exclude this tenant.
    #>
    param(
        [object]$Row,
        [Parameter(Mandatory)][ValidateSet('admin','membership','group','nesting','binding','resource')][string]$Kind,
        [Parameter(Mandatory)][string]$TenantId,
        [Parameter(Mandatory)][int]$TenantRing,
        [string[]]$TenantTags = @()
    )
    $m = Get-PimReplicateMode -Row $Row -Kind $Kind
    if ($m.mode -eq 'No') { return @{ reach = $false; mode = 'No'; axis = 'replicate'; reason = "$($m.reason)" } }
    $rg = Test-PimReplicationRingAdmits -Row $Row -Kind $Kind -TenantRing $TenantRing
    if (-not $rg.admits) { return @{ reach = $false; mode = $m.mode; axis = 'ring'; reason = "$($rg.reason)" } }
    $tv = Test-PimArtifactTarget -Target "$(Get-PimDownlinkValue -Object $Row -Key 'Target')" -TenantId $TenantId -TenantTags @($TenantTags)
    if (-not $tv.match) { return @{ reach = $false; mode = $m.mode; axis = 'target'; reason = "$($tv.reason)" } }
    return @{ reach = $true; mode = $m.mode; axis = ''; reason = "$($tv.reason)" }
}

function Get-PimReplicationDependencyWarning {
    # $null when a NEEDED row may simply follow here; otherwise the reason its own fields would have
    # kept it out -- which is exactly what the auto-include warning has to say.
    param([object]$Row, [Parameter(Mandatory)][string]$Kind, [Parameter(Mandatory)][string]$TenantId, [Parameter(Mandatory)][int]$TenantRing, [string[]]$TenantTags = @())
    $r = Test-PimReplicationReach -Row $Row -Kind $Kind -TenantId $TenantId -TenantRing $TenantRing -TenantTags @($TenantTags)
    if ($r.reach) { return $null }
    return "$($r.reason)"
}

function Test-PimReplicationRowFields {
    <#
      AUTHORING CHECK (pure) for one row's replication fields -- shared by the validator, the Manager's
      PUT gate and the reach preview, so the three can never disagree about what is acceptable.
      Returns @{ ok; errors = @(); warnings = @() }. Errors refuse the write; warnings do not.
    #>
    param([object]$Row, [Parameter(Mandatory)][string]$Entity, [string[]]$KnownTags = @(), [switch]$TagsKnown)
    $kind = Get-PimReplicationKindForEntity -Entity $Entity
    $errors = New-Object System.Collections.Generic.List[string]
    $warnings = New-Object System.Collections.Generic.List[string]
    if (-not $kind) { return @{ ok = $true; errors = @(); warnings = @() } }
    # the only admin entity is Account-Definitions-Admins, so an admin row here is a DEFINITION row
    $m = Get-PimReplicateMode -Row $Row -Kind $kind -AdminSource Definition
    if (-not $m.valid) { $errors.Add("$($m.reason)") | Out-Null }
    $ring = "$(Get-PimDownlinkValue -Object $Row -Key 'Ring')".Trim()
    if ($ring -and $ring -notmatch '^\d+$') { $warnings.Add("Ring '$ring' is not a whole number -- it reaches no tenant") | Out-Null }   # DOC-16 a vs c (2.4.371): any whole number is a ring
    $tgt = "$(Get-PimDownlinkValue -Object $Row -Key 'Target')".Trim()
    if ($tgt) {
        $sel = Test-PimAdminTargetSelector -Target $tgt -KnownTags @($KnownTags) -TagsKnown:([bool]$TagsKnown)
        if (@($sel.malformed).Count)   { $errors.Add("Target '$tgt' is malformed: $(@($sel.malformed) -join ', ') (use tag:<key:value>, tag:a+b, tenant:<id>, or leave blank)") | Out-Null }
        if (@($sel.unknownTags).Count) { $warnings.Add("Target '$tgt' names tag(s) no managed tenant carries: $(@($sel.unknownTags) -join ', ')") | Out-Null }
    }
    return @{ ok = ($errors.Count -eq 0); errors = @($errors.ToArray()); warnings = @($warnings.ToArray()); kind = $kind; mode = $m.mode }
}

function Test-PimReplicationWriteAllowed {
    <#
      THE MASTER-ONLY GATE for a grid/wizard write (§71.5). Pure: the Manager passes the rows it is
      about to commit, the rows currently stored, and whether this tenant is the MSP master.
        * NOT the master -> a row may not INTRODUCE or CHANGE Replicate, nor Ring/Target on a non-admin
          entity (an admin's Ring/Target predate §71 and keep working on every tenant). Managed tenants
          never edit targets; single tenants have nothing to target.
        * the master     -> every changed row must pass Test-PimReplicationRowFields (errors refuse).
      Returns @{ allowed; reason; refused = @( @{ key; reason } ) }.
    #>
    param(
        [Parameter(Mandatory)][string]$Entity,
        [AllowEmptyCollection()][object[]]$Rows = @(),
        [AllowEmptyCollection()][object[]]$CurrentRows = @(),
        [bool]$IsMaster,
        [string[]]$KnownTags = @(),
        [switch]$TagsKnown
    )
    $kind = Get-PimReplicationKindForEntity -Entity $Entity
    if (-not $kind) { return @{ allowed = $true; reason = ''; refused = @() } }
    # Operator 2026-09-15: every MSP sync surface belongs to the MSP MASTER only -- "not relevant for single mode", and a
    # managed tenant never edits what the master sends. So off the master an admin's Ring / Target are refused too
    # (the v2 engine reads an admin's Ring only in the MSP downlink), and so is switching ManagementMode to msp.
    $fields = @('Replicate','Ring','Target')
    $keyOf = {
        param($r)
        if (Get-Command Get-PimStoreRowKey -ErrorAction SilentlyContinue) { return (Get-PimStoreRowKey -Base $Entity -Row $r) }
        return "$(Get-PimDownlinkValue -Object $r -Key 'GroupTag')$(Get-PimDownlinkValue -Object $r -Key 'UserName')"
    }
    $cur = @{}
    foreach ($c in @($CurrentRows)) { if ($null -eq $c) { continue }; $k = "$(& $keyOf $c)"; if ($k) { $cur[$k.ToLowerInvariant()] = $c } }
    $refused = New-Object System.Collections.Generic.List[object]
    foreach ($r in @($Rows)) {
        if ($null -eq $r) { continue }
        $k = "$(& $keyOf $r)"
        $old = if ($k -and $cur.ContainsKey($k.ToLowerInvariant())) { $cur[$k.ToLowerInvariant()] } else { $null }
        $changed = $false
        foreach ($f in $fields) {
            $nv = "$(Get-PimDownlinkValue -Object $r -Key $f)".Trim()
            $ov = "$(Get-PimDownlinkValue -Object $old -Key $f)".Trim()
            if ($nv -ne $ov) { $changed = $true; break }
        }
        if (-not $changed -and $kind -eq 'admin') {
            $nm = "$(Get-PimDownlinkValue -Object $r -Key 'ManagementMode')".Trim()
            $om = "$(Get-PimDownlinkValue -Object $old -Key 'ManagementMode')".Trim()
            if ($nm -ine $om) {
                # master: a ManagementMode change must still agree with Replicate; elsewhere only local/blank is allowed
                if ($IsMaster -or ($nm -and $nm -ine 'local')) { $changed = $true }
            }
        }
        if (-not $changed) { continue }
        if (-not $IsMaster) {
            $refused.Add([ordered]@{ key = $k; reason = "MSP sync / replication fields (Replicate, Ring, Target, ManagementMode=msp) can only be set on the MSP master -- this tenant is not the master" }) | Out-Null
            continue
        }
        $chk = Test-PimReplicationRowFields -Row $r -Entity $Entity -KnownTags @($KnownTags) -TagsKnown:([bool]$TagsKnown)
        if (-not $chk.ok) { $refused.Add([ordered]@{ key = $k; reason = (@($chk.errors) -join '; ') }) | Out-Null }
    }
    $arr = @($refused.ToArray())
    return [ordered]@{
        allowed = ($arr.Count -eq 0)
        reason  = $(if ($arr.Count) { "$($arr.Count) row(s) refused: $((@($arr | Select-Object -First 3 | ForEach-Object { "$($_.key): $($_.reason)" })) -join ' | ')" } else { '' })
        refused = $arr
    }
}

function Select-PimBaselineBundleContent {
    <#
      §71.6 -- WHAT GOES INTO THE ONE SIGNED BUNDLE (the producer's decision, as a PURE function so it
      is testable offline and shared with the Manager's reach preview). Get-PimBaselineBundlePayload (PIM-BaselinePublish.ps1)
      does the SQL reads and the signing; this decides the rows.

      🔒 BYTE-FOR-BYTE FOR BLANK DATA. Field lists, key order and sort order are the pre-§71 producer's
      exactly; Replicate/Ring are added to a shipped row ONLY when the master set them. The MSP pair
      sim compares the signed payload against a golden captured from the code before this change.

      WHAT CHANGED, AND WHY:
        * (71.7 a) group definitions are read from EVERY entity the engine creates groups from --
          Departments, Processes, Projects and CrossOrg were missing, so a membership into a DEPT- /
          PROJ- / CORG- group shipped without its group.
        * (71.7 b) a row that is Replicate=No or Target=none is NOT put in the bundle -- unless another
          shipped row depends on it (framework MSP-4 SURFACE item 6). An MSP-local admin must not sit in
          a payload 28 customers can read.
        * Replicate=Yes groups / nestings / bindings SEED the model on their own (a group can now go to
          slaves without an admin needing it), and the nesting closure iterates to a FIXPOINT, so every
          row any tenant could need is present; each tenant then decides for itself.
        * tenant-scoped resource bindings (Roles-AUs / Azure-Resources / Workloads) ship only when
          explicitly Follow/Yes, under `definitions.resourceBindings`, with the AU definitions the
          Roles-AUs rows need under `definitions.aus`. Both keys are ABSENT when empty.

      -RegistryRows      pim.CentralAdmins rows, already shaped by the caller's Select-Object.
      -RegistryReplicate UserName(lowercase) -> the registry's Replicate column, when it exists.
      -Entities          entity name -> parsed rows from pim.Rows.
      Returns @{ rows; assignments; definitions; report }.
    #>
    [CmdletBinding()]
    param(
        [AllowEmptyCollection()][object[]]$RegistryRows = @(),
        [hashtable]$RegistryReplicate = @{},
        [hashtable]$Entities = @{}
    )
    $getEnt = { param($n) if ($Entities.ContainsKey($n)) { return @(@($Entities[$n]) | Where-Object { $null -ne $_ }) } else { return @() } }
    $lc = { param($s) "$s".Trim().ToLowerInvariant() }
    $notPublished = New-Object System.Collections.Generic.List[object]

    # 1. admins -- the registry first (the explicit MSP list), then ManagementMode=msp definitions.
    $rowList = New-Object System.Collections.Generic.List[object]
    foreach ($r in @($RegistryRows)) {
        if ($null -eq $r) { continue }
        $un = "$(Get-PimDownlinkValue -Object $r -Key 'UserName')".Trim()
        $rep = ''
        if ($RegistryReplicate.ContainsKey($un.ToLowerInvariant())) { $rep = "$($RegistryReplicate[$un.ToLowerInvariant()])" }
        $probe = [pscustomobject]@{ Replicate = $rep; Target = "$(Get-PimDownlinkValue -Object $r -Key 'Target')" }
        # a pim.CentralAdmins registry row -- MSP by construction unless its own Replicate / Target say otherwise
        $rm = Get-PimReplicateMode -Row $probe -Kind 'admin' -AdminSource Registry
        if ($rm.mode -ne 'Yes') { $notPublished.Add([ordered]@{ kind = 'admin'; name = $un; reason = "$($rm.reason)" }) | Out-Null; continue }
        $rowList.Add($r) | Out-Null
    }
    $adminByLower = @{}
    foreach ($r in $rowList.ToArray()) { $adminByLower["$(Get-PimDownlinkValue -Object $r -Key 'UserName')".Trim().ToLowerInvariant()] = "$(Get-PimDownlinkValue -Object $r -Key 'UserName')".Trim() }
    $defAdmins = Get-PimCentralAdminsFromDefinitions -Rows @(& $getEnt 'Account-Definitions-Admins')
    $added = 0
    foreach ($d in @($defAdmins.synced)) {
        $k = "$($d.UserName)".Trim().ToLowerInvariant()
        if ($adminByLower.ContainsKey($k)) { continue }
        $rowList.Add([pscustomobject]$d) | Out-Null
        $adminByLower[$k] = "$($d.UserName)".Trim()
        $added++
    }
    foreach ($x in @($defAdmins.notSynced)) {
        if ("$($x.reason)" -match 'Replicate|Target=none|disagree') { $notPublished.Add([ordered]@{ kind = 'admin'; name = "$($x.UserName)"; reason = "$($x.reason)" }) | Out-Null }
        # A definition admin with a BLANK ManagementMode (no Replicate) stays on the master, and Get-PimReplicateMode
        # says No for it too -- listed, so "not replicated" is never silent (a v1 CSV admin has no ManagementMode).
        elseif ($x.Contains('masterOnly') -and $x['masterOnly']) { $notPublished.Add([ordered]@{ kind = 'admin'; name = "$($x.UserName)"; reason = 'ManagementMode blank -- master tenant only' }) | Out-Null }
    }

    # 2. memberships of the published admins
    $assignObjs = New-Object System.Collections.Generic.List[object]
    $skipped = 0
    foreach ($j in (& $getEnt 'PIM-Assignments-Admins')) {
        $u = "$($j.Username)"; if (-not $u) { $u = "$($j.UserName)" }
        $u = $u.Trim(); if (-not $u) { continue }
        if ("$($j.Action)" -eq 'Remove') { continue }
        $local = $u; $at = $u.IndexOf('@'); if ($at -gt 0) { $local = $u.Substring(0, $at) }
        $key = $local.ToLowerInvariant()
        if (-not $adminByLower.ContainsKey($key)) { $skipped++; continue }
        $mm = Get-PimReplicateMode -Row $j -Kind 'membership'
        if ($mm.mode -eq 'No') { $notPublished.Add([ordered]@{ kind = 'membership'; name = "$($adminByLower[$key]) -> $($j.GroupTag)"; reason = "$($mm.reason)" }) | Out-Null; continue }
        $a = [ordered]@{
            UserName            = $adminByLower[$key]
            GroupTag            = "$($j.GroupTag)"
            AssignmentType      = "$($j.AssignmentType)"
            Permanent           = "$($j.Permanent)"
            NumOfDaysWhenExpire = "$($j.NumOfDaysWhenExpire)"
            AutoExtend          = "$($j.AutoExtend)"
            Target              = "$($j.Target)"
        }
        if ("$($j.Replicate)".Trim()) { $a['Replicate'] = "$($j.Replicate)".Trim() }
        if ("$($j.Ring)".Trim())      { $a['Ring']      = "$($j.Ring)".Trim() }
        $assignObjs.Add($a) | Out-Null
    }
    $assignArr = @($assignObjs.ToArray() | Sort-Object @{ e = { "$($_.UserName)".ToLowerInvariant() } }, @{ e = { "$($_.GroupTag)".ToLowerInvariant() } })

    # 3. the group model: seeds, then the nesting closure to a fixpoint
    $defEntities = @('PIM-Definitions-Roles','PIM-Definitions-Services','PIM-Definitions-Organization','PIM-Definitions-Tasks',
                     'PIM-Definitions-Departments','PIM-Definitions-Processes','PIM-Definitions-Projects','PIM-Definitions-CrossOrg','PIM-Definitions')
    $allDefs = New-Object System.Collections.Generic.List[object]
    foreach ($e in $defEntities) {
        foreach ($d in (& $getEnt $e)) {
            Add-Member -InputObject $d -NotePropertyName '__srcEntity' -NotePropertyValue $e -Force
            $allDefs.Add($d) | Out-Null
        }
    }
    $opt = {
        # the §71 fields, appended only when set (the no-regression rule)
        param($target, $row)
        foreach ($f in @('Replicate','Ring','Target')) {
            $v = "$(Get-PimDownlinkValue -Object $row -Key $f)".Trim()
            if ($v -and -not $target.Contains($f)) { $target[$f] = $v }
        }
    }
    $need = @{}
    $projTags = @{}
    foreach ($a in $assignArr) { $projTags[(& $lc $a.GroupTag)] = $true; $need[(& $lc $a.GroupTag)] = $true }
    foreach ($d in $allDefs.ToArray()) {
        if ((Get-PimReplicateMode -Row $d -Kind 'group').mode -eq 'Yes' -and (& $lc $d.GroupTag)) { $need[(& $lc $d.GroupTag)] = $true }
    }
    $allNest = @(& $getEnt 'PIM-Assignments-Groups' | Where-Object { "$($_.Action)" -ne 'Remove' })
    foreach ($n in $allNest) {
        if ((Get-PimReplicateMode -Row $n -Kind 'nesting').mode -eq 'Yes') { $need[(& $lc $n.TargetGroupTag)] = $true; $need[(& $lc $n.SourceGroupTag)] = $true }
    }
    $allBind = @(& $getEnt 'PIM-Assignments-Roles-Groups' | Where-Object { "$($_.Action)" -ne 'Remove' })
    foreach ($b in $allBind) { if ((Get-PimReplicateMode -Row $b -Kind 'binding').mode -eq 'Yes') { $need[(& $lc $b.GroupTag)] = $true } }
    $resEntities = @('PIM-Assignments-Roles-AUs','PIM-Assignments-Azure-Resources','PIM-Assignments-Workloads')
    $allRes = New-Object System.Collections.Generic.List[object]
    foreach ($e in $resEntities) {
        foreach ($rr in (& $getEnt $e)) {
            if ("$($rr.Action)" -eq 'Remove') { continue }
            $rmode = (Get-PimReplicateMode -Row $rr -Kind 'resource').mode
            if ($rmode -eq 'No') { continue }
            $allRes.Add(@{ Entity = $e; Row = $rr; Mode = $rmode }) | Out-Null
            if ($rmode -eq 'Yes') { $need[(& $lc $rr.GroupTag)] = $true }
        }
    }
    # 71.19 -- THE SPONSOR DEPARTMENT OF EVERY PUBLISHED ADMIN IS A DEPENDENCY. An admin's mail and TAP go to its
    # department's OWNERS, and the slave resolves that from its own replicated PIM-Definitions-Departments rows -- so a
    # department left behind by targeting means an admin nobody can deliver a credential to. Auto-included exactly like a
    # group a replicated membership depends on (reported, never silent); an admin naming a department that has no row at
    # all is reported too, because that is the same failure one step earlier.
    $deptDeps = New-Object System.Collections.Generic.List[object]
    $deptByName = @{}
    foreach ($d in $allDefs.ToArray()) {
        if ("$($d.__srcEntity)" -ne 'PIM-Definitions-Departments') { continue }
        $dn = "$(Get-PimDownlinkValue -Object $d -Key 'Department')".Trim()
        if ($dn) { $deptByName[(& $lc $dn)] = $d }
    }
    foreach ($ar in $rowList.ToArray()) {
        $adn = "$(Get-PimDownlinkValue -Object $ar -Key 'Department')".Trim()
        if (-not $adn) { continue }
        $drow = $deptByName[(& $lc $adn)]
        $an = "$(Get-PimDownlinkValue -Object $ar -Key 'UserName')".Trim()
        if (-not $drow) {
            $notPublished.Add([ordered]@{ kind = 'department'; name = $adn; reason = "sponsor department of '$an' has no PIM-Definitions-Departments row -- its mail/TAP recipient cannot be resolved in a managed tenant" }) | Out-Null
            continue
        }
        $dtag = & $lc $drow.GroupTag
        if ($dtag -and -not $need.ContainsKey($dtag)) {
            $need[$dtag] = $true
            $deptDeps.Add([ordered]@{ kind = 'department'; name = "$($drow.GroupTag)"; reason = "sponsor department '$adn' of admin '$an' -- carried so the managed tenant can resolve that admin's mail/TAP recipient from its owners" }) | Out-Null
        }
    }
    $nestOk = @($allNest | Where-Object { (Get-PimReplicateMode -Row $_ -Kind 'nesting').mode -ne 'No' })
    $guard = 0
    do {
        $grew = $false
        foreach ($n in $nestOk) {
            $t = & $lc $n.TargetGroupTag; $s = & $lc $n.SourceGroupTag
            if ($s -and $need.ContainsKey($t) -and -not $need.ContainsKey($s)) { $need[$s] = $true; $grew = $true }
        }
        $guard++
    } while ($grew -and $guard -le ($nestOk.Count + 1))
    $need.Remove('') | Out-Null

    $nestArr = @($nestOk | Where-Object { $need.ContainsKey((& $lc $_.TargetGroupTag)) } | ForEach-Object {
        $o = [ordered]@{
            TargetGroupTag = "$($_.TargetGroupTag)"; SourceGroupTag = "$($_.SourceGroupTag)"
            AssignmentType = "$($_.AssignmentType)"; Permanent = "$($_.Permanent)"
            NumOfDaysWhenExpire = "$($_.NumOfDaysWhenExpire)"; AutoExtend = "$($_.AutoExtend)"
        }
        & $opt $o $_
        $o
    } | Sort-Object @{ e = { "$($_.SourceGroupTag)".ToLowerInvariant() } }, @{ e = { "$($_.TargetGroupTag)".ToLowerInvariant() } })

    $dependencyIncluded = New-Object System.Collections.Generic.List[object]
    foreach ($dd in $deptDeps.ToArray()) { $dependencyIncluded.Add($dd) | Out-Null }   # 71.19 sponsor departments
    $defArr = @($allDefs.ToArray() | Where-Object { $need.ContainsKey((& $lc $_.GroupTag)) } | ForEach-Object {
        if ((Get-PimReplicateMode -Row $_ -Kind 'group').mode -eq 'No') {
            $dependencyIncluded.Add([ordered]@{ kind = 'group'; name = "$($_.GroupTag)"; reason = 'Replicate=No, but a replicated row depends on it -- carried so each tenant can auto-include it (warned per tenant)' }) | Out-Null
        }
        $o = [ordered]@{
            GroupTag = "$($_.GroupTag)"; GroupName = "$($_.GroupName)"; GroupDescription = "$($_.GroupDescription)"
            IsRoleAssignable = "$($_.IsRoleAssignable)"; Workload = "$($_.Workload)"; Level = "$($_.Level)"
            Plane = "$($_.Plane)"; CPPlatform = "$($_.CPPlatform)"; Department = "$($_.Department)"
            PolicyTemplate = "$($_.PolicyTemplate)"
            SourceEntity = "$($_.__srcEntity)"
        }
        # 71.19: the department's OWNERS travel with it -- they are who an admin's mail and TAP go to in the managed
        # tenant. Emitted only when set, so a row without owners ships the same bytes as before.
        $__own = "$(Get-PimDownlinkValue -Object $_ -Key 'Owners')".Trim()
        if ($__own) { $o['Owners'] = $__own }
        & $opt $o $_
        $o
    } | Sort-Object @{ e = { "$($_.GroupTag)".ToLowerInvariant() } })

    $bindArr = @($allBind | Where-Object { (Get-PimReplicateMode -Row $_ -Kind 'binding').mode -ne 'No' -and $need.ContainsKey((& $lc $_.GroupTag)) } | ForEach-Object {
        $o = [ordered]@{
            GroupTag = "$($_.GroupTag)"; RoleDefinitionName = "$($_.RoleDefinitionName)"
            AssignmentType = "$($_.AssignmentType)"; Permanent = "$($_.Permanent)"
            NumOfDaysWhenExpire = "$($_.NumOfDaysWhenExpire)"; AutoExtend = "$($_.AutoExtend)"
            Plane = "$($_.Plane)"; PermissionScope = "$($_.PermissionScope)"
        }
        & $opt $o $_
        $o
    } | Sort-Object @{ e = { "$($_.GroupTag)".ToLowerInvariant() } }, @{ e = { "$($_.RoleDefinitionName)".ToLowerInvariant() } })

    $resArr = @($allRes.ToArray() | Where-Object { $need.ContainsKey((& $lc $_.Row.GroupTag)) } | ForEach-Object {
        $o = [ordered]@{ Entity = "$($_.Entity)" }
        foreach ($p in @($_.Row.PSObject.Properties)) {
            if ($p.Name -in @('Owner', 'Origin', '__srcEntity')) { continue }
            $o[$p.Name] = "$($p.Value)"
        }
        $o
    } | Sort-Object @{ e = { "$($_.Entity)" } }, @{ e = { "$($_.GroupTag)".ToLowerInvariant() } })
    $auNeed = @{}
    foreach ($x in $resArr) { if ("$($x.Entity)" -eq 'PIM-Assignments-Roles-AUs' -and "$($x.AdministrativeUnitTag)".Trim()) { $auNeed[(& $lc $x.AdministrativeUnitTag)] = $true } }
    $ausArr = @(& $getEnt 'PIM-Definitions-AU' | Where-Object { $auNeed.ContainsKey((& $lc $_.AdministrativeUnitTag)) } | ForEach-Object {
        $o = [ordered]@{}
        foreach ($p in @($_.PSObject.Properties)) { if ($p.Name -in @('Owner', 'Origin')) { continue }; $o[$p.Name] = "$($p.Value)" }
        $o
    } | Sort-Object @{ e = { "$($_.AdministrativeUnitTag)".ToLowerInvariant() } })

    $definitions = [ordered]@{ groups = $defArr; nestings = $nestArr; roleBindings = $bindArr }
    if ($resArr.Count) { $definitions['resourceBindings'] = $resArr }
    if ($ausArr.Count) { $definitions['aus'] = $ausArr }

    $orphan = @($projTags.Keys | Where-Object { $t = $_; -not @($defArr | Where-Object { "$($_.GroupTag)".Trim().ToLowerInvariant() -eq $t }).Count })
    return @{
        rows        = @($rowList.ToArray())
        assignments = $assignArr
        definitions = $definitions
        report      = @{
            defAdmins          = $defAdmins
            addedFromDefinitions = $added
            skippedAssignments = $skipped
            notPublished       = @($notPublished.ToArray())
            dependencyIncluded = @($dependencyIncluded.ToArray())
            orphanTags         = $orphan
        }
    }
}

function New-PimBaselinePayload {
    # The payload object, key order identical to the pre-§71 producer. Pure (the caller supplies the
    # version and both timestamps), so the Manager's reach preview can build the very same thing.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$Content,
        [object]$ProjectionPolicy = ([ordered]@{}),
        [object]$TenantTags = ([ordered]@{}),
        [int64]$Version = 0,
        [string]$Scope = 'fleet',
        [string]$GeneratedAtUtc = '',
        [string]$ValidToUtc = ''
    )
    return [ordered]@{
        product          = 'PIM4EntraPS'
        kind             = 'baseline'
        version          = $Version
        scope            = $Scope
        generatedAtUtc   = $GeneratedAtUtc
        validToUtc       = $ValidToUtc
        rows             = $Content.rows
        assignments      = $Content.assignments
        definitions      = $Content.definitions
        projectionPolicy = $ProjectionPolicy
        tenantTags       = $TenantTags
    }
}

# ---------------------------------------------------------------------------
# MSP-4 -- CLASS GATING via RING-1 capabilities (pure).
#
# The CUSTOMER decides WHETHER, in their own manifest (`blockCapabilities` in their
# bootstrap file). This maps a downlink artifact class onto the capability name that
# governs it, so the customer's existing opt-out reaches the downlink without PIM
# inventing a second consent mechanism -- which the standing rule forbids.
#
# 🪤 A BLOCKED CLASS IS 'Held', NOT 'nothing to do'. The distinction is the whole
# reason RING-1's vocabulary is Allowed/Held/Refused: a customer who declined role
# changes and a master who published none must not produce the same report.
# ---------------------------------------------------------------------------
function Get-PimDownlinkCapabilityName {
    param([Parameter(Mandatory)][ValidateSet('admins','roles','groups','policies')][string]$Class)
    switch ($Class) {
        'admins'   { return 'msp-admins' }
        'roles'    { return 'msp-roles' }
        'groups'   { return 'msp-groups' }
        'policies' { return 'msp-policies' }
    }
}

function Test-PimDownlinkClassAllowed {
    <#
      Is this artifact class allowed for this tenant? -BlockedCapabilities is the
      customer's own list, exactly as RING-1 resolves it. Absent => nothing blocked =>
      today's behaviour, which keeps this inert until a customer opts out.
    #>
    param(
        [Parameter(Mandatory)][ValidateSet('admins','roles','groups','policies')][string]$Class,
        [string[]]$BlockedCapabilities = @()
    )
    $cap = Get-PimDownlinkCapabilityName -Class $Class
    foreach ($b in @($BlockedCapabilities)) {
        if ("$b".Trim().ToLowerInvariant() -eq $cap) {
            return @{ allowed = $false; capability = $cap; reason = "the customer blocked '$cap' in their own manifest" }
        }
    }
    return @{ allowed = $true; capability = $cap; reason = '' }
}

function Select-PimCustomerBlockedCapabilities {
    <#
      SEC-10 / MSP-3 step 4 -- read the CUSTOMER's opt-outs out of THEIR OWN manifest.

      🔴 WHY THIS EXISTS. The class gate above was built, unit-tested and proven against a
      real bundle -- and **no runtime path could reach it**. `Get-PimDownlinkPlan` honours
      `-BlockedCapabilities`, but `Invoke-PimManagedDownlink` did not declare the parameter
      and the entry script never read the manifest, so in production the customer's list was
      ALWAYS empty and the customer veto SEC-10 is about did not exist outside the tests.
      That is BUG-29's shape exactly, one layer further out: the orchestrator's own comment
      on `-RingPlan` says *"this parameter is the link that was missing -- the gate existed
      and nothing could reach it"*, and the same sentence had become true of this one.

      PURE on purpose: it takes the ALREADY-PARSED manifest object, so the file read stays in
      the entry script and this stays offline-testable. Shape is the platform's, not PIM's --
      `Solutions[]` entries carrying `Name` + `blockCapabilities`, exactly as
      `SOLUTIONS/PlatformConfiguration/INTERNAL/Sync-AutomateIT-Engine.ps1` parses it. Do not
      invent a PIM-private consent file: the customer's own bootstrap manifest is the strongest
      form the customer gate can take (their file, their choice), which is what makes SEC-10
      closable by ADOPTION rather than invention.

      Absent manifest / absent solution / absent key => @() => nothing blocked => exactly
      today's behaviour. The gate stays inert until a customer actually opts out.
    #>
    param(
        [Parameter()][AllowNull()][object]$Manifest,
        [Parameter(Mandatory)][string]$Solution
    )
    if ($null -eq $Manifest) { return @() }
    $want = "$Solution".Trim().ToLowerInvariant()
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($s in @($Manifest.Solutions)) {
        if (-not $s) { continue }
        if ("$($s.Name)".Trim().ToLowerInvariant() -ne $want) { continue }
        if (-not ($s.PSObject.Properties.Name -contains 'blockCapabilities')) { continue }
        foreach ($b in @($s.blockCapabilities)) {
            $n = "$b".Trim()
            if ($n -and ($out -notcontains $n)) { [void]$out.Add($n) }
        }
    }
    # .ToArray() -- never a bare @($list) on a List[object]; see the trap note in TESTS.md.
    return $out.ToArray()
}

function New-PimAcceptanceRecord {
    <#
      MSP-3 step 5 -- THE UPLINK PAYLOAD. Pure.

      MSP-3's ACCEPT step is two gates: the MSP publishes, the customer accepts. Both now exist and
      are audited (SEC-10b / BUG-78 / BUG-79). **Nothing reported what they DECIDED**, so from the
      operator's side "the customer declined roles", "the ring held the version" and "that tenant
      has not run in a week" were the same observation: silence.

      🔒 WHY THE FRAMEWORK INSISTS ON CAPABILITIES, NOT JUST VERSIONS. Framework §8: *"It must report
      capabilities, not just versions -- otherwise 'held by policy' and 'failed to apply' are
      identical, which is precisely the ambiguity ring gating introduces."* So this record carries
      the four-state RING-1 vocabulary, not a boolean: what RAN, what the operator HELD, what the
      customer BLOCKED, and what was withheld by TARGETING (which is none of the three -- it means
      the artifact was never offered to this tenant at all).

      🪤 AND THE FIELD THAT MAKES SILENCE VISIBLE IS THE TIMESTAMP, not the outcome. §8 again: *"A
      customer whose sync never ran sends no email. Absence of failure mail is indistinguishable
      from health."* `decidedAtUtc` is what lets the operator see a tenant that has stopped
      reporting, which is the failure no outcome field can express.

      🔒 SCOPE, STATED PLAINLY: this builds the PAYLOAD and nothing else. The TRANSPORT -- the
      authenticated append-only API in the operator tenant, backed by SQL -- is framework §8.2 and
      belongs to `SOLUTIONS/PlatformMonitoring`, not to PIM. PIM must not invent a second one: an
      inbound path from ~30 customers into the operator environment is exactly the decision §8.2
      already took deliberately, and a PIM-private variant would bypass that reasoning. What PIM
      owes is a record the transport can carry, and that record existing at all is the half that
      unblocks the other.

      PURE: no clock (pass -NowUtc), no disk, no network -- so the shape is testable offline and the
      timestamp is injectable rather than untestable.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Plan,
        [Parameter(Mandatory)][string]$TenantId,
        [object]$RingPlan,
        [string[]]$BlockedCapabilities = @(),
        [string]$DecidedBy = '',
        [datetime]$NowUtc = ([datetime]::UtcNow),
        # §71: the applies' retraction report (Invoke-PimDownlinkDefinitionApply/-AssignmentApply results).
        # Optional; when given, what WOULD be removed and what WAS removed are recorded -- audited, never silent.
        [object[]]$ApplyResults = @(),
        [switch]$WhatIfMode
    )
    # 🪤 A REFUSAL PLAN IS A DIFFERENT SHAPE. The early returns in Get-PimDownlinkPlan (ring hold,
    # bad signature, version mismatch) carry only ok/reason/scenarioId/ring/admins/sync/content/
    # baselineVersion/verify -- no classHeld, no notTargeted, no retracts. And `@($null).Count` is
    # **1**, not 0 (measured under BUG-70b earlier today), so counting those fields naively would
    # report a refused run as having held exactly one thing. Every count here goes through this
    # helper, which treats "the property does not exist" as zero rather than as one phantom item.
    $countOf = { param($v) if ($null -eq $v) { 0 } else { @($v).Count } }
    $held    = if ($null -eq $Plan.classHeld)   { @() } else { @($Plan.classHeld) }
    $skipped = if ($null -eq $Plan.notTargeted) { @() } else { @($Plan.notTargeted) }

    # Which classes actually ran = the ones the downlink carries, minus the ones held. Named
    # explicitly rather than derived at the far end, because "not mentioned" is not an outcome.
    $allClasses = @('msp-admins', 'msp-roles', 'msp-groups')
    $blockedSet = @($BlockedCapabilities | Where-Object { $_ })
    $heldCaps   = @($blockedSet)   # a class in classHeld is there because the CUSTOMER blocked it
    $ranCaps    = @($allClasses | Where-Object { $heldCaps -notcontains $_ })

    $ringAction  = if ($RingPlan) { "$($RingPlan.Action)" } else { 'track-current' }
    $ringNumber  = if ($RingPlan -and $null -ne $RingPlan.Ring) { $RingPlan.Ring } else { $null }
    $ringVersion = if ($RingPlan -and "$($RingPlan.Version)".Trim()) { "$($RingPlan.Version)" } else { '' }

    return [ordered]@{
        schema           = 1
        solution         = 'PIM4EntraPS'
        kind             = 'msp-downlink-acceptance'
        tenantId         = "$TenantId"
        scenarioId       = "$($Plan.scenarioId)"
        # OUTCOME -- ok=$false is a REFUSAL (bad signature, ring hold, version mismatch), which is a
        # different thing from "applied nothing because the customer blocked it all".
        accepted         = [bool]$Plan.ok
        reason           = "$($Plan.reason)"
        whatIf           = [bool]$WhatIfMode
        # WHAT ARRIVED
        baselineVersion  = $Plan.baselineVersion
        assignmentRing   = $Plan.ring
        # BUG-175: THE SLAVE REPORTS ITS OWN RING. The ring that gated this run is the slave's LOCAL -SlaveRing (its job
        # argument) -- authoritative. The master's platform.Tenants.Ring is only the master's copy and can drift; this
        # field is what lets a reader of the record (and a future uplink) see the value that actually decided.
        slaveRing        = $Plan.ring
        slaveRingSource  = 'local'
        # THE OPERATOR'S GATE (RING-1 plane 2)
        ringAction       = $ringAction
        ring             = $ringNumber
        ringApprovesVersion = $ringVersion
        # THE CUSTOMER'S GATE -- the four states, kept distinct on purpose
        capabilitiesRan     = @($ranCaps)
        capabilitiesBlocked = @($heldCaps)
        # counts, so a fleet view can aggregate without parsing prose
        adminsProjected  = (& $countOf $Plan.admins)
        rolesProjected   = (& $countOf $Plan.assignments)
        heldCount        = $held.Count
        notTargetedCount = $skipped.Count
        # 🔒 Carried explicitly: a downlink never retracts. Without this the operator cannot tell a
        # narrowing from a revocation, which is the exact misreading MSP-4 was corrected for.
        retracts         = [bool]$Plan.retracts
        # §71 -- dependencies included with a warning, and the retraction report (report-first).
        autoIncludedCount = (& $countOf $Plan.autoIncluded)
        wouldRetract     = @(@($ApplyResults) | Where-Object { $_ } | ForEach-Object { @($_.wouldRetract) + @($_.retractHeld) } | Where-Object { "$_".Trim() })
        retracted        = [int]((@($ApplyResults) | Where-Object { $_ } | ForEach-Object { [int]$_.removed } | Measure-Object -Sum).Sum)
        decidedBy        = "$DecidedBy"
        decidedAtUtc     = $NowUtc.ToString('o')
    }
}

function Write-PimAcceptanceRecord {
    <#
      MSP-3 step 5 -- persist the acceptance record so the state EXISTS before a transport does.

      Written NEXT TO the tenant's sync files, because that folder is already the per-tenant
      artifact location the downlink owns and the operator already knows to look in. One file per
      tenant, overwritten each run: this is CURRENT STATE ("where does this tenant stand"), not a
      log. A history belongs in the §8 SQL backend, which can retain properly; a growing pile of
      JSON on a customer's disk is not an audit trail, it is litter nobody prunes.

      🔒 BEST-EFFORT BY DESIGN, and this is a deliberate asymmetry worth defending: failing to
      RECORD what happened must never fail the downlink that already happened. The record is
      observability; the downlink is the work. Inverting that would let a full disk or a locked
      file turn a successful, already-applied sync into a reported failure -- and the operator
      would then "fix" a sync that was never broken.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Record,
        [Parameter(Mandatory)][string]$Folder,
        [switch]$Quiet
    )
    try {
        if (-not (Test-Path -LiteralPath $Folder)) { New-Item -ItemType Directory -Path $Folder -Force | Out-Null }
        $path = Join-Path $Folder 'acceptance-latest.json'
        ($Record | ConvertTo-Json -Depth 6) | Set-Content -LiteralPath $path -Encoding UTF8
        if (-not $Quiet) {
            Write-Host ("  [uplink] acceptance recorded: {0} (accepted={1}, ran=[{2}], blocked=[{3}])" -f `
                $path, $Record.accepted, (@($Record.capabilitiesRan) -join ','), (@($Record.capabilitiesBlocked) -join ',')) -ForegroundColor DarkCyan
        }
        return $path
    } catch {
        Write-Warning ("  [uplink] could not write the acceptance record to '$Folder': $($_.Exception.Message). " +
                       "The downlink itself is unaffected -- this is observability, not the work.")
        return $null
    }
}

function Resolve-PimCustomerBlockedCapabilities {
    <#
      BUG-79 -- the IO half of the customer gate, SHARED by every entry point that can reach the
      downlink. `Select-PimCustomerBlockedCapabilities` above is the pure decision; this finds the
      file, reads it, and applies the three-way absent / present / unreadable policy.

      🔑 WHY THIS IS A FUNCTION AND NOT COPIED INTO EACH ENTRY SCRIPT. BUG-79 was first written up
      as an operator decision -- *"should the scenario-run entry DUPLICATE this resolution, or just
      accept the answer as pass-through?"* -- and that framing was wrong: the third option is to
      share it, which is neither. Duplicating it would put the refuse-on-unparseable rule in two
      places and guarantee they drift; bare pass-through would leave the identical silent hole for
      anyone who forgets to supply the parameter. One resolver, called by both, has neither defect.

      🔒 THE THREE CASES ARE DELIBERATELY DISTINCT, and collapsing any two is a security bug:
        * NO manifest      -> @() . The normal single-tenant state. Nothing blocked.
        * manifest present -> whatever it says, possibly @() ("blocks nothing" IS an answer).
        * present, UNREADABLE -> THROW. Reading a corrupt opt-out list as "blocked nothing" is
          consent by parse error; reading it as "blocked everything" strands the downlink on a
          trailing comma. Neither silent reading is ever discovered; a refusal is fixed in a minute.

      -SolutionRoot is the solution directory (…\SOLUTIONS\PIM4EntraPS); the manifest is resolved
      two levels above it, which is C:\AutomateIT\bootstrap\Sync-AutomateIT.json on a customer.
      Returns $null when there is nothing to say, so a caller can tell "no manifest" from "@()" and
      keep the gate inert rather than forwarding an empty list it never actually read.
    #>
    [CmdletBinding()]
    param(
        [string]$ManifestPath,
        [string]$SolutionRoot,
        [string]$Solution = 'PIM4EntraPS',
        [switch]$Quiet
    )
    $path = "$ManifestPath".Trim()
    if (-not $path) {
        if (-not "$SolutionRoot".Trim()) { return $null }
        # 🔴 THE CONTAINER HAS ONE FEWER DIRECTORY LEVEL THAN A CUSTOMER INSTALL, AND THIS LINE
        # ASSUMED THE CUSTOMER SHAPE. On a customer the solution sits at
        # C:\AutomateIT\SOLUTIONS\PIM4EntraPS, so "two levels up" is C:\AutomateIT and the manifest
        # is beside it. In the pim-manager IMAGE the solution is at /app/PIM4EntraPS -- there is no
        # SOLUTIONS level -- so two levels up walks off the top of the filesystem, Split-Path
        # returns EMPTY, and Join-Path threw
        #     Cannot bind argument to parameter 'Path' because it is an empty string
        # MEASURED 2026-09-03: this killed RIDE's downlink Job on every run, before a single line
        # of downlink work, and the message named neither this function nor a manifest -- the same
        # code plans correctly on Windows, which is why it survived every offline test.
        # Running out of parents is not an error: it means there is no customer manifest root here,
        # which is exactly the "nothing to say" case this function already returns $null for.
        $up1 = Split-Path -Parent $SolutionRoot
        $up2 = if ("$up1".Trim()) { Split-Path -Parent $up1 } else { '' }
        if (-not "$up2".Trim()) {
            if (-not $Quiet) { Write-Host ("  customer gate: no manifest root two levels above '$SolutionRoot' (container layout) -- class gate INERT (the customer blocks nothing)") -ForegroundColor DarkYellow }
            return $null
        }
        # Built with Combine rather than the old 'bootstrap\Sync-AutomateIT.json' literal.
        # 📌 To be accurate about why: PowerShell's FileSystem provider DOES normalise a backslash
        # to '/' on Linux -- measured in this same run, where a path built as 'setup\Invoke-...ps1'
        # resolved and reported back as /app/PIM4EntraPS/setup/Invoke-PimScenarioRun.ps1. So the
        # separator was NOT the failure here, and an earlier note claiming it would silently miss a
        # customer manifest was wrong. Combine is used because it states the intent platform-
        # independently, not because the old form was broken.
        $path = [System.IO.Path]::Combine($up2, 'bootstrap', 'Sync-AutomateIT.json')
    }
    if (-not (Test-Path -LiteralPath $path)) {
        # Say it out loud. A silent absence is exactly how BUG-29 survived for months.
        if (-not $Quiet) { Write-Host ("  customer gate: no manifest at $path -- class gate INERT (the customer blocks nothing)") -ForegroundColor DarkYellow }
        return $null
    }
    $blocked = $null
    try {
        $manifest = (Get-Content -Raw -LiteralPath $path) | ConvertFrom-Json
        $blocked = @(Select-PimCustomerBlockedCapabilities -Manifest $manifest -Solution $Solution)
    } catch {
        throw ("the customer manifest '$path' exists but could NOT be parsed " +
               "($($_.Exception.Message)). Refusing to run: an unreadable opt-out list must never " +
               "be treated as 'the customer blocked nothing'. Fix the JSON, or pass " +
               "-BlockedCapabilities explicitly to state the intent.")
    }
    if (-not $Quiet) {
        Write-Host ("  customer gate: {0} -> {1}" -f $path,
            $(if (@($blocked).Count) { "BLOCKS $(@($blocked) -join ', ')" } else { 'blocks nothing' })) -ForegroundColor Cyan
    }
    return $blocked
}

# ---------------------------------------------------------------------------
# MSP-2 / control #2 -- ROLE PROJECTION (pure).
#
# WHAT THIS IS. Control #1 creates the master's admins in the slave. Control #2
# gives them their ROLES there. The currency is the GROUP TAG: on the master an
# admin holds roles by being an eligible/active member of a PIM group, and the
# slave's engine already knows how to make an admin a member of the group with a
# given tag (the AdminMembers provider, entity PIM-Assignments-Admins). So the
# projection re-stages the master's memberships as slave desired rows and the
# EXISTING delegation path does the rest -- deliberately NOT a second mechanism.
#
# WHY A FILTER AT ALL. An MSP does not grant every customer the same delegation,
# so which tags project is a property of the RELATIONSHIP. The policy rows come
# from pim.TenantRoleProjection (see sql/platform-schema.sql for the semantics);
# this function is their single interpreter.
#
# 🪤 UNRESOLVABLE TAGS ARE REPORTED, NOT DROPPED. A tag the slave has no group for
# would fail at apply with "unresolved principal/group". When -SlaveGroupTags is
# supplied, those rows are separated into `unresolved` with a reason rather than
# staged -- an admin silently missing a role is exactly the failure class that
# cost session 23 five blockers. Omit -SlaveGroupTags to skip the check.
#
# Returns @{ projected; excluded; unresolved } -- `excluded`/`unresolved` rows each
# carry a `reason`, so the plan can always say why a role did NOT arrive.
# PURE: no I/O, no globals.
# ---------------------------------------------------------------------------
function Test-PimProjectionTagMatch {
    # Case-insensitive exact match, or a trailing-* prefix match ('ROLE-*').
    param([string]$Tag, [string]$Pattern)
    $t = "$Tag".Trim().ToLowerInvariant()
    $p = "$Pattern".Trim().ToLowerInvariant()
    if (-not $t -or -not $p) { return $false }
    if ($p.EndsWith('*')) { return $t.StartsWith($p.Substring(0, $p.Length - 1)) }
    return ($t -eq $p)
}

function Select-PimProjectedAssignments {
    param(
        # Master PIM-Assignments-Admins rows: UserName (the LOGIN name, not the
        # master UPN -- the downlink rewrites the UPN per slave), GroupTag,
        # AssignmentType, Permanent, NumOfDaysWhenExpire, AutoExtend.
        [object[]]$Assignments = @(),
        # The admin set that survived the ring gate. An assignment whose admin did
        # NOT reach this slave must not project either, or a ring-2 consultant's
        # roles would land in a tenant the consultant themselves never reaches.
        [string[]]$AdminUserNames = @(),
        # pim.TenantRoleProjection rows for THIS tenant: @{ Mode; GroupTag }.
        [object[]]$Policy = @(),
        # Optional: the group tags that actually exist in the slave.
        [string[]]$SlaveGroupTags,
        # The admins dropped by the artifact TARGET selector rather than by the ring.
        # 🔑 WITHOUT THIS, ONE AXIS WEARS ANOTHER'S NAME. Both narrowings remove an admin from
        # -AdminUserNames, so from in here they are indistinguishable -- and the message said
        # "ring" for both. MSP-4's whole premise is that the four narrowings stay apart because
        # each has a DIFFERENT FIX: a ring is raised, a Target is rewritten. Telling an operator
        # to raise a ring that was never the reason is worse than saying nothing.
        [string[]]$NotTargetedAdminNames = @()
    )
    $allowed = New-Object System.Collections.Generic.HashSet[string]
    foreach ($u in @($AdminUserNames)) { [void]$allowed.Add("$u".Trim().ToLowerInvariant()) }
    $notTargetedAdmins = New-Object System.Collections.Generic.HashSet[string]
    foreach ($u in @($NotTargetedAdminNames)) { [void]$notTargetedAdmins.Add("$u".Trim().ToLowerInvariant()) }

    $allowRules = @(@($Policy) | Where-Object { "$(Get-PimDownlinkValue -Object $_ -Key 'Mode')".Trim().ToLowerInvariant() -eq 'allow' })
    $denyRules  = @(@($Policy) | Where-Object { "$(Get-PimDownlinkValue -Object $_ -Key 'Mode')".Trim().ToLowerInvariant() -eq 'deny'  })
    $haveTagCheck = $PSBoundParameters.ContainsKey('SlaveGroupTags') -and $null -ne $SlaveGroupTags
    $slaveTags = New-Object System.Collections.Generic.HashSet[string]
    foreach ($g in @($SlaveGroupTags)) { [void]$slaveTags.Add("$g".Trim().ToLowerInvariant()) }

    $projected  = New-Object System.Collections.Generic.List[object]
    $excluded   = New-Object System.Collections.Generic.List[object]
    $unresolved = New-Object System.Collections.Generic.List[object]

    foreach ($a in @($Assignments)) {
        $user = "$(Get-PimDownlinkValue -Object $a -Key 'UserName')".Trim()
        $tag  = "$(Get-PimDownlinkValue -Object $a -Key 'GroupTag')".Trim()
        $mark = { param($list, $why) $r = [ordered]@{ UserName = $user; GroupTag = $tag; reason = $why }; $list.Add($r) | Out-Null }

        if (-not $user -or -not $tag) { & $mark $excluded 'malformed row (missing UserName or GroupTag)'; continue }
        # the admin must have survived the ring gate for this slave
        if ($allowed.Count -and -not $allowed.Contains($user.ToLowerInvariant())) {
            if ($notTargetedAdmins.Contains($user.ToLowerInvariant())) {
                & $mark $excluded "admin '$user' is not TARGETED at this tenant -- their roles do not project either"
            } else {
                & $mark $excluded "admin '$user' did not reach this tenant's ring -- their roles do not either"
            }
            continue
        }
        # deny wins over allow, always
        $hitDeny = @($denyRules | Where-Object { Test-PimProjectionTagMatch -Tag $tag -Pattern "$(Get-PimDownlinkValue -Object $_ -Key 'GroupTag')" })
        if ($hitDeny.Count) { & $mark $excluded "denied by relationship policy (deny '$(Get-PimDownlinkValue -Object $hitDeny[0] -Key 'GroupTag')')"; continue }
        # allow rules present => allow-LIST. Absent => allow all (the default).
        if ($allowRules.Count) {
            $hitAllow = @($allowRules | Where-Object { Test-PimProjectionTagMatch -Tag $tag -Pattern "$(Get-PimDownlinkValue -Object $_ -Key 'GroupTag')" })
            if (-not $hitAllow.Count) { & $mark $excluded 'not in the relationship allow-list'; continue }
        }
        if ($haveTagCheck -and -not $slaveTags.Contains($tag.ToLowerInvariant())) {
            & $mark $unresolved "no group with tag '$tag' exists in this tenant -- the role cannot be granted here"; continue
        }
        $projected.Add([ordered]@{
            UserName            = $user
            GroupTag            = $tag
            AssignmentType      = "$(Get-PimDownlinkValue -Object $a -Key 'AssignmentType')"
            Permanent           = "$(Get-PimDownlinkValue -Object $a -Key 'Permanent')"
            NumOfDaysWhenExpire = "$(Get-PimDownlinkValue -Object $a -Key 'NumOfDaysWhenExpire')"
            AutoExtend          = "$(Get-PimDownlinkValue -Object $a -Key 'AutoExtend')"
        }) | Out-Null
    }
    # deterministic order -- the sync files are compared byte-for-byte for idempotency
    $sort = { @($args[0] | Sort-Object @{ e = { "$($_.UserName)".ToLowerInvariant() } }, @{ e = { "$($_.GroupTag)".ToLowerInvariant() } }) }
    # 🪤 The outer @() is LOAD-BEARING, not decoration. A scriptblock that outputs a
    # ONE-element array has it unrolled to a scalar at the call boundary, so a single
    # result came back as a bare OrderedDictionary -- and `$result.excluded[0]` then
    # indexes the DICTIONARY BY KEY '0' and yields $null instead of the row. Every
    # single-row case (one denial, one unresolved tag) silently read as "no reason
    # given". Caught by the offline tests; re-forcing the array here fixes it for
    # every caller rather than making each one remember to wrap.
    return @{
        projected  = @(& $sort $projected.ToArray())
        excluded   = @(& $sort $excluded.ToArray())
        unresolved = @(& $sort $unresolved.ToArray())
    }
}

# ---------------------------------------------------------------------------
# BUG-59 -- WHICH GROUPS THE SLAVE NEEDS (pure). Operator decision 2026-08-13:
# "MSP groups, customer may extend".
#
# THE PROBLEM THIS SOLVES. A projected membership grants nothing in a tenant that has
# no group carrying that tag, and a managed tenant is EMPTY on day one (measured: both
# RIDE and HOGYM have zero rows). Memberships-only would therefore be a correct
# projection that delivers nothing. So the baseline can STAND UP its own model.
#
# THE RULE, and it is a yielding one:
#   * the slave ALREADY has a group with the tag  -> DEFER. It is the customer's group;
#     we add our admin to it and touch neither its definition nor its role bindings.
#   * the slave does NOT                          -> CREATE it, stamped Owner='MSP'.
# So an MSP model works in an empty tenant, and a customer who has built their own
# delegation keeps ownership of it. The tag is the contract; who owns the group is not.
#
# 🔒 WHAT WE DO **NOT** WRITE INTO A CUSTOMER-OWNED GROUP. A nesting is applied only when
# its TARGET (the ROLE group that receives the permission) is one we created, and a role
# binding only when its group is one we created. Otherwise the MSP would be handing the
# customer's own role group -- the one their people are members of -- the privileges of an
# MSP service group, which is a privilege change disguised as a sync.
#
# 🔴 BUG-61 -- this guard used to inspect the SOURCE, which is the SERVICE group and is
# therefore always ours. It protected the end that never needed protecting and left the
# customer's group exposed. Direction, once, for both walkers below: TargetGroupTag is the
# ROLE group (from PIM-Definitions-Roles); SourceGroupTag is the permission group the
# permission comes FROM. Live, the role group is a MEMBER OF the service group.
#
# Returns @{ create; defer; nestings; roleBindings; skipped } -- `defer` and `skipped`
# carry reasons, so the plan can always explain why a group was not created.
# PURE: no I/O, no globals.
# ---------------------------------------------------------------------------
function Select-PimProjectedDefinitions {
    param(
        # payload.definitions -> @{ groups; nestings; roleBindings [; resourceBindings; aus] }
        [object]$Definitions,
        # the tags actually projected AFTER ring + policy filtering (from
        # Select-PimProjectedAssignments .projected) -- never the master's whole model.
        [string[]]$ProjectedTags = @(),
        # tags that already exist in the slave (its own PIM-Definitions).
        [string[]]$SlaveGroupTags = @(),
        # §71 -- THIS tenant, for the replication reach rule. ABSENT => no replication evaluation at all
        # and the result is exactly the pre-§71 one (the parameter is the opt-in, like -RingPlan).
        [string]$TenantId,
        [int]$TenantRing = 0,
        [string[]]$TenantTags = @(),
        # §71 -- the projected memberships themselves, only to NAME the dependent in a warning.
        [object[]]$ProjectedAssignments = @()
    )
    $lower = { param($s) "$s".Trim().ToLowerInvariant() }
    $groups       = @(); $nestings = @(); $bindings = @(); $resBindings = @(); $aus = @()
    if ($Definitions) {
        $g = Get-PimDownlinkValue -Object $Definitions -Key 'groups';           if ($g) { $groups      = @($g) }
        $n = Get-PimDownlinkValue -Object $Definitions -Key 'nestings';         if ($n) { $nestings    = @($n) }
        $b = Get-PimDownlinkValue -Object $Definitions -Key 'roleBindings';     if ($b) { $bindings    = @($b) }
        $rb = Get-PimDownlinkValue -Object $Definitions -Key 'resourceBindings'; if ($rb) { $resBindings = @($rb) }
        $au = Get-PimDownlinkValue -Object $Definitions -Key 'aus';             if ($au) { $aus         = @($au) }
    }
    $slaveHas = New-Object System.Collections.Generic.HashSet[string]
    foreach ($t in @($SlaveGroupTags)) { [void]$slaveHas.Add((& $lower $t)) }

    # §71 -- the replication rule, per row, for THIS tenant. Every helper below is a no-op when no
    # tenant was given, which is what keeps an older caller byte-identical.
    $evalRep = $PSBoundParameters.ContainsKey('TenantId') -and "$TenantId".Trim()
    $groupByTag = @{}
    foreach ($grp in $groups) { $lt = & $lower (Get-PimDownlinkValue -Object $grp -Key 'GroupTag'); if ($lt -and -not $groupByTag.ContainsKey($lt)) { $groupByTag[$lt] = $grp } }
    $autoInc  = New-Object System.Collections.Generic.List[object]
    $notRep   = New-Object System.Collections.Generic.List[object]
    $warned   = New-Object System.Collections.Generic.HashSet[string]
    $reachOf  = {
        param($row, $kind)
        if (-not $evalRep) { return @{ reach = $true; mode = 'Follow'; axis = ''; reason = '' } }
        return (Test-PimReplicationReach -Row $row -Kind $kind -TenantId $TenantId -TenantRing $TenantRing -TenantTags @($TenantTags))
    }
    $warnGroup = {
        # A group this tenant NEEDS is included regardless; if its own fields would have kept it out,
        # say so -- naming the row, the dependent and the tenant (framework MSP-4 SURFACE item 5).
        param($lt, $dependent)
        if (-not $evalRep) { return }
        if (-not $groupByTag.ContainsKey($lt)) { return }
        $grp = $groupByTag[$lt]
        $w = Get-PimReplicationDependencyWarning -Row $grp -Kind 'group' -TenantId $TenantId -TenantRing $TenantRing -TenantTags @($TenantTags)
        if ($w -and $warned.Add($lt)) {
            $tag = "$(Get-PimDownlinkValue -Object $grp -Key 'GroupTag')"
            $autoInc.Add([ordered]@{
                kind = 'group'; GroupTag = $tag; dependent = "$dependent"; tenantId = "$TenantId"
                reason = "group '$tag' is AUTO-INCLUDED for tenant $TenantId because $dependent needs it, although $w"
            }) | Out-Null
        }
    }

    # Closure: the projected role groups + every group reachable through nesting.
    #
    # 🪤 THIS MUST ITERATE TO A FIXPOINT, not walk the list once. A single pass only
    # reaches ONE level: given A -> B -> C it pulls in B and stops, so C is never
    # created and the admin silently gets part of their delegation. Nesting depth is a
    # modelling choice the master makes, not something this code may cap. Bounded by
    # the tag count so a cycle in the master's model terminates instead of hanging.
    $need = New-Object System.Collections.Generic.HashSet[string]
    foreach ($t in @($ProjectedTags)) {
        $lt = & $lower $t
        [void]$need.Add($lt)
        if ($evalRep) {
            $who = @(@($ProjectedAssignments) | Where-Object { (& $lower (Get-PimDownlinkValue -Object $_ -Key 'GroupTag')) -eq $lt } | Select-Object -First 1)
            $dep = if ($who.Count) { "membership $(Get-PimDownlinkValue -Object $who[0] -Key 'UserName') -> $t" } else { "a membership into $t" }
            & $warnGroup $lt $dep
        }
    }
    if ($evalRep) {
        # §71 SEEDS: a Replicate=Yes row that reaches this tenant stands up its part of the model on its
        # own; one that does not is reported, so "not replicated here" is never silent.
        foreach ($grp in $groups) {
            if ((Get-PimReplicateMode -Row $grp -Kind 'group').mode -ne 'Yes') { continue }
            $r = & $reachOf $grp 'group'
            $lt = & $lower (Get-PimDownlinkValue -Object $grp -Key 'GroupTag')
            if ($r.reach) { [void]$need.Add($lt) }
            else { $notRep.Add([ordered]@{ kind = 'group'; GroupTag = "$(Get-PimDownlinkValue -Object $grp -Key 'GroupTag')"; axis = "$($r.axis)"; reason = "$($r.reason)" }) | Out-Null }
        }
        foreach ($nst in $nestings) {
            if ((Get-PimReplicateMode -Row $nst -Kind 'nesting').mode -ne 'Yes') { continue }
            $r = & $reachOf $nst 'nesting'
            $tg = "$(Get-PimDownlinkValue -Object $nst -Key 'TargetGroupTag')"; $sg = "$(Get-PimDownlinkValue -Object $nst -Key 'SourceGroupTag')"
            if (-not $r.reach) { $notRep.Add([ordered]@{ kind = 'nesting'; GroupTag = $tg; SourceGroupTag = $sg; axis = "$($r.axis)"; reason = "$($r.reason)" }) | Out-Null; continue }
            foreach ($x in @($tg, $sg)) { $lx = & $lower $x; if ($lx) { [void]$need.Add($lx); & $warnGroup $lx "nesting $tg <- $sg" } }
        }
        foreach ($bnd in @($bindings) + @($resBindings)) {
            $kind = if ("$(Get-PimDownlinkValue -Object $bnd -Key 'Entity')".Trim()) { 'resource' } else { 'binding' }
            if ((Get-PimReplicateMode -Row $bnd -Kind $kind).mode -ne 'Yes') { continue }
            $r = & $reachOf $bnd $kind
            $gt = "$(Get-PimDownlinkValue -Object $bnd -Key 'GroupTag')"
            if (-not $r.reach) { $notRep.Add([ordered]@{ kind = $kind; GroupTag = $gt; axis = "$($r.axis)"; reason = "$($r.reason)" }) | Out-Null; continue }
            $lg = & $lower $gt; if ($lg) { [void]$need.Add($lg); & $warnGroup $lg "binding on $gt" }
        }
    }
    $nestVerdict = @{}
    $nestKey = { param($nst) "$(& $lower (Get-PimDownlinkValue -Object $nst -Key 'TargetGroupTag'))|$(& $lower (Get-PimDownlinkValue -Object $nst -Key 'SourceGroupTag'))" }
    foreach ($nst in $nestings) { $nestVerdict[(& $nestKey $nst)] = (& $reachOf $nst 'nesting') }
    $guard = 0
    $maxRounds = [Math]::Max(1, @($nestings).Count + 1)
    do {
        $added = $false
        foreach ($nst in $nestings) {
            $src = & $lower (Get-PimDownlinkValue -Object $nst -Key 'SourceGroupTag')
            $tgt = & $lower (Get-PimDownlinkValue -Object $nst -Key 'TargetGroupTag')
            if (-not $src) { continue }
            # §71: a nesting whose OWN fields keep it out of this tenant does not carry its source group in.
            if (-not $nestVerdict[(& $nestKey $nst)].reach) { continue }
            # BUG-61: walk ROLE -> SERVICE. `need` starts as the projected ROLE tags, and a
            # nesting names its role group in TARGET, so the group to pull in is the SOURCE.
            if ($need.Contains($tgt) -and -not $need.Contains($src)) {
                [void]$need.Add($src); $added = $true
                & $warnGroup $src "nesting $(Get-PimDownlinkValue -Object $nst -Key 'TargetGroupTag') <- $(Get-PimDownlinkValue -Object $nst -Key 'SourceGroupTag')"
            }
        }
        $guard++
    } while ($added -and $guard -lt $maxRounds)

    $create = New-Object System.Collections.Generic.List[object]
    $defer  = New-Object System.Collections.Generic.List[object]
    $skip   = New-Object System.Collections.Generic.List[object]
    $mine   = New-Object System.Collections.Generic.HashSet[string]   # tags WE create
    foreach ($grp in $groups) {
        $tag = "$(Get-PimDownlinkValue -Object $grp -Key 'GroupTag')".Trim()
        $lt  = & $lower $tag
        if (-not $lt) { continue }
        if (-not $need.Contains($lt)) {
            $skip.Add([ordered]@{ GroupTag = $tag; reason = 'not reached by any projected assignment' }) | Out-Null; continue
        }
        if ($slaveHas.Contains($lt)) {
            $defer.Add([ordered]@{ GroupTag = $tag; reason = 'a group with this tag already exists in the tenant -- the customer owns it, left untouched' }) | Out-Null; continue
        }
        [void]$mine.Add($lt)
        $create.Add($grp) | Out-Null
    }

    # only wire up the groups we own (see the 🔒 note above). The group that must be OURS is
    # the TARGET -- the role group the permission lands on.
    $outNest = New-Object System.Collections.Generic.List[object]
    foreach ($nst in $nestings) {
        $tgt = & $lower (Get-PimDownlinkValue -Object $nst -Key 'TargetGroupTag')
        if (-not $need.Contains($tgt)) { continue }
        $v = $nestVerdict[(& $nestKey $nst)]
        if (-not $v.reach) {
            $notRep.Add([ordered]@{ kind = 'nesting'; GroupTag = "$(Get-PimDownlinkValue -Object $nst -Key 'TargetGroupTag')"; SourceGroupTag = "$(Get-PimDownlinkValue -Object $nst -Key 'SourceGroupTag')"; axis = "$($v.axis)"; reason = "$($v.reason)" }) | Out-Null
            $skip.Add([ordered]@{ GroupTag = "$(Get-PimDownlinkValue -Object $nst -Key 'TargetGroupTag')"; reason = "nesting NOT replicated to this tenant -- $($v.reason)" }) | Out-Null
            continue
        }
        if (-not $mine.Contains($tgt)) {
            $skip.Add([ordered]@{ GroupTag = "$(Get-PimDownlinkValue -Object $nst -Key 'TargetGroupTag')"; reason = 'nesting NOT applied -- the role group is customer-owned, and an MSP sync must not hand it further permissions' }) | Out-Null
            continue
        }
        $outNest.Add($nst) | Out-Null
    }
    $outBind = New-Object System.Collections.Generic.List[object]
    foreach ($bnd in $bindings) {
        $gt = & $lower (Get-PimDownlinkValue -Object $bnd -Key 'GroupTag')
        if (-not $need.Contains($gt)) { continue }
        $v = & $reachOf $bnd 'binding'
        if (-not $v.reach) {
            $notRep.Add([ordered]@{ kind = 'binding'; GroupTag = "$(Get-PimDownlinkValue -Object $bnd -Key 'GroupTag')"; RoleDefinitionName = "$(Get-PimDownlinkValue -Object $bnd -Key 'RoleDefinitionName')"; axis = "$($v.axis)"; reason = "$($v.reason)" }) | Out-Null
            continue
        }
        if (-not $mine.Contains($gt)) {
            $skip.Add([ordered]@{ GroupTag = "$(Get-PimDownlinkValue -Object $bnd -Key 'GroupTag')"; reason = 'role binding NOT applied -- the group is customer-owned, and its Entra roles are theirs to set' }) | Out-Null
            continue
        }
        $outBind.Add($bnd) | Out-Null
    }
    # §71: tenant-scoped resource bindings (only ever present when the master explicitly replicated
    # them). Same two guards; a tag with NO group definition at all (an Azure permission group is
    # defined by its Azure-Resources rows) counts as ours unless the customer already has that tag.
    $outRes = New-Object System.Collections.Generic.List[object]
    foreach ($rbd in $resBindings) {
        $gt = & $lower (Get-PimDownlinkValue -Object $rbd -Key 'GroupTag')
        if (-not $need.Contains($gt)) { continue }
        $v = & $reachOf $rbd 'resource'
        if (-not $v.reach) {
            $notRep.Add([ordered]@{ kind = 'resource'; GroupTag = "$(Get-PimDownlinkValue -Object $rbd -Key 'GroupTag')"; Entity = "$(Get-PimDownlinkValue -Object $rbd -Key 'Entity')"; axis = "$($v.axis)"; reason = "$($v.reason)" }) | Out-Null
            continue
        }
        $ours = $mine.Contains($gt) -or (-not $groupByTag.ContainsKey($gt) -and -not $slaveHas.Contains($gt))
        if (-not $ours) {
            $skip.Add([ordered]@{ GroupTag = "$(Get-PimDownlinkValue -Object $rbd -Key 'GroupTag')"; reason = 'resource binding NOT applied -- the group is customer-owned' }) | Out-Null
            continue
        }
        $outRes.Add($rbd) | Out-Null
    }
    $auNeed = New-Object System.Collections.Generic.HashSet[string]
    foreach ($x in $outRes.ToArray()) {
        if ("$(Get-PimDownlinkValue -Object $x -Key 'Entity')" -eq 'PIM-Assignments-Roles-AUs') { [void]$auNeed.Add((& $lower (Get-PimDownlinkValue -Object $x -Key 'AdministrativeUnitTag'))) }
    }
    $outAus = @(@($aus) | Where-Object { $auNeed.Contains((& $lower (Get-PimDownlinkValue -Object $_ -Key 'AdministrativeUnitTag'))) })

    $sortTag = { @($args[0] | Sort-Object @{ e = { "$(Get-PimDownlinkValue -Object $_ -Key 'GroupTag')".ToLowerInvariant() } }) }
    return @{
        create       = @(& $sortTag $create.ToArray())
        defer        = @(& $sortTag $defer.ToArray())
        skipped      = @(& $sortTag $skip.ToArray())
        nestings     = @($outNest.ToArray() | Sort-Object @{ e = { "$(Get-PimDownlinkValue -Object $_ -Key 'SourceGroupTag')".ToLowerInvariant() } }, @{ e = { "$(Get-PimDownlinkValue -Object $_ -Key 'TargetGroupTag')".ToLowerInvariant() } })
        roleBindings = @($outBind.ToArray() | Sort-Object @{ e = { "$(Get-PimDownlinkValue -Object $_ -Key 'GroupTag')".ToLowerInvariant() } }, @{ e = { "$(Get-PimDownlinkValue -Object $_ -Key 'RoleDefinitionName')".ToLowerInvariant() } })
        # §71 -- all four are EMPTY for a bundle authored without replication fields.
        resourceBindings = @($outRes.ToArray())
        aus              = @($outAus)
        # Dependencies included although their own fields would have excluded them (the warning).
        autoIncluded     = @($autoInc.ToArray())
        # Rows whose own Replicate/Ring/Target keep them out of THIS tenant.
        notReplicated    = @($notRep.ToArray())
    }
}

# ---------------------------------------------------------------------------
# SYNC-FILE CONTENT (pure). Build the deterministic per-tenant sync payloads from
# the ring-filtered admin set + the verified baseline meta. Stable JSON (sorted
# keys, fixed order) so re-staging identical input yields byte-identical files
# (the idempotency contract for the file layer). Returns @{ admins; manifest }.
# ---------------------------------------------------------------------------
function New-PimDownlinkSyncContent {
    param(
        [object[]]$Admins = @(),
        [Parameter(Mandatory)][string]$TenantId,
        [int]$SlaveRing = 2,
        [int64]$BaselineVersion = 0,
        [string]$Scope = 'fleet',
        # MSP-2 / control #2: the Select-PimProjectedAssignments result. Omitted =>
        # no assignments file is produced and the manifest reports 0, which is
        # exactly the pre-control-#2 behaviour (so an old master that publishes no
        # assignments keeps working unchanged).
        [hashtable]$Projection
    )
    $adminRows = @(@($Admins) | ForEach-Object {
        [ordered]@{
            UserName    = "$(Get-PimDownlinkValue -Object $_ -Key 'UserName')"
            DisplayName = "$(Get-PimDownlinkValue -Object $_ -Key 'DisplayName')"
            Ring        = [int](Get-PimDownlinkValue -Object $_ -Key 'Ring')
            Template    = "$(Get-PimDownlinkValue -Object $_ -Key 'Template')"
        }
    } | Sort-Object @{ e = { $_.Ring } }, @{ e = { "$($_.UserName)".ToLowerInvariant() } })

    $adminsDoc = [ordered]@{
        product   = 'PIM4EntraPS'
        kind      = 'downlink-admins'
        tenantId  = "$TenantId"
        slaveRing = [int]$SlaveRing
        version   = [int64]$BaselineVersion
        scope     = "$Scope"
        admins    = $adminRows
    }
    # MSP-2: the projected role memberships, staged as their own file so the admin
    # file's bytes (and therefore its idempotency hash) are unchanged for a master
    # that publishes no assignments.
    $projRows = @(); $exclRows = @(); $unresRows = @()
    if ($Projection) {
        if ($Projection.ContainsKey('projected'))  { $projRows  = @($Projection['projected']) }
        if ($Projection.ContainsKey('excluded'))   { $exclRows  = @($Projection['excluded']) }
        if ($Projection.ContainsKey('unresolved')) { $unresRows = @($Projection['unresolved']) }
    }

    $manifestDoc = [ordered]@{
        product       = 'PIM4EntraPS'
        kind          = 'downlink-manifest'
        tenantId      = "$TenantId"
        slaveRing     = [int]$SlaveRing
        version       = [int64]$BaselineVersion
        adminCount    = $adminRows.Count
        adminUserNames = @($adminRows | ForEach-Object { $_.UserName })
        # counted, not just listed: "0 projected" must be visible in the manifest
        # rather than inferred from an absent file.
        assignmentCount           = $projRows.Count
        assignmentExcludedCount   = $exclRows.Count
        assignmentUnresolvedCount = $unresRows.Count
    }
    $out = @{
        admins   = ($adminsDoc   | ConvertTo-Json -Depth 8)
        manifest = ($manifestDoc | ConvertTo-Json -Depth 8)
    }
    if ($Projection) {
        $assignDoc = [ordered]@{
            product     = 'PIM4EntraPS'
            kind        = 'downlink-assignments'
            tenantId    = "$TenantId"
            slaveRing   = [int]$SlaveRing
            version     = [int64]$BaselineVersion
            scope       = "$Scope"
            assignments = $projRows
            # carried so the operator can see WHY a role did not arrive without
            # re-running the plan -- the whole point of the reason strings.
            excluded    = $exclRows
            unresolved  = $unresRows
        }
        $out['assignments'] = ($assignDoc | ConvertTo-Json -Depth 8)
    }
    return $out
}

# ---------------------------------------------------------------------------
# DOWNLINK DECISION PLAN (pure). The end-to-end ring-gated downlink decision for
# ONE managed tenant, built from FACTS the live wrapper gathers:
#   -Scenario        : S5 | S6 (or a descriptor) -- resolved for hosting/sync loc.
#   -Doc             : the pulled signed baseline document (verified here).
#   -PublicKey       : verifying RSA/cert (tests inject an ephemeral key; prod omits
#                      to use the embedded cert).
#   -BaselineAdmins  : the admin rows carried by the verified baseline payload
#                      (UserName+Ring+Template+DisplayName). When omitted, taken
#                      from the verified payload.rows.
#   -TenantId/-SlaveRing : the managed tenant + its registry ring.
#   -CentralRoot/-LocalRoot : sync-file staging roots (per syncFileLocation).
#   -NowUtc/-LastVersion : expiry + anti-rollback inputs.
# Returns a decision object the wrapper executes:
#   { ok; reason; scenarioId; ring; sync=<Resolve-PimDownlinkSyncPath>;
#     admins=<ring-filtered set>; content=<New-PimDownlinkSyncContent>;
#     baselineVersion; verify=<Test-PimDownlinkBaseline meta> }.
# ok=$false (with reason) when verification fails -> the wrapper REFUSES to stage
# or apply (bad sig / expired / rollback). NO I/O, NO globals.
# ---------------------------------------------------------------------------
function Get-PimDownlinkPlan {
    param(
        [Parameter(Mandatory)][object]$Scenario,
        [Parameter(Mandatory)][object]$Doc,
        [object]$PublicKey,
        [object[]]$BaselineAdmins,
        [Parameter(Mandatory)][string]$TenantId,
        [Parameter(Mandatory)][int]$SlaveRing,
        [string]$CentralRoot,
        [string]$LocalRoot,
        [datetime]$NowUtc = ([datetime]::UtcNow),
        [int64]$LastVersion = 0,
        [string]$Scope = 'fleet',
        # RING-1 plane 2 (optional). A Get-PimTemplateRingPlan result for THIS managed
        # tenant. See the version-gate block below for why this is opt-in.
        [object]$RingPlan,
        # MSP-2 / control #2 (optional, and INERT when absent -- same non-breaking
        # rule as -RingPlan above). The master's PIM-Assignments-Admins rows for the
        # baseline admins; when omitted, taken from payload.assignments if the bundle
        # carries them, so an OLD bundle simply projects nothing.
        [object[]]$BaselineAssignments,
        # pim.TenantRoleProjection rows for THIS tenant. Absent/empty => allow all.
        [object[]]$ProjectionPolicy = @(),
        # The group tags that exist in the slave, for the unresolved-tag check.
        [string[]]$SlaveGroupTags,
        # MSP-4 (optional, inert when absent -- same non-breaking rule as -RingPlan).
        # This tenant's tags, for artifact targeting. Taken from the signed bundle's
        # tenantTags map when not passed explicitly.
        [string[]]$TenantTags,
        # The customer's own blocked capabilities (RING-1). Absent => nothing blocked.
        [string[]]$BlockedCapabilities = @(),
        # IMP-13. The SLAVE's own admin naming prefixes (its AdminAccountPatterns). Absent =>
        # recognisability is NOT evaluated and the plan says so -- it is never assumed fine.
        # Available in S6 (the downlink runs inside the slave); typically unknown master-side.
        [string[]]$SlaveAdminPrefixes = @(),
        # SEC-25: the signer ids THIS tenant has revoked (its pim.Settings). A revoked signer is refused.
        [AllowEmptyCollection()][string[]]$RevokedSigners = @(),
        # SEC-25: a Get-PimCentralKillState result. blocks=$true (active / invalid / unknown) refuses the plan.
        [object]$CentralKill
    )
    $ctx = Resolve-PimScenarioContext -Scenario $Scenario
    if (-not [bool]$ctx.syncAdminsPermissions) {
        return @{ ok = $false; reason = "scenario $($ctx.id) is not a managed/sync scenario (syncAdminsPermissions=false)"; scenarioId = "$($ctx.id)"; admins = @(); sync = $null; content = $null; baselineVersion = 0; verify = $null }
    }

    # 0) SEC-25: the central kill switch. Checked FIRST -- while a kill stands nothing is taken from the master.
    if ($null -ne $CentralKill -and [bool](Get-PimDownlinkValue -Object $CentralKill -Key 'blocks')) {
        return @{ ok = $false; reason = "$(Get-PimDownlinkValue -Object $CentralKill -Key 'reason')"; scenarioId = "$($ctx.id)"; ring = $SlaveRing; admins = @(); sync = $null; content = $null; baselineVersion = 0; verify = $null; centralKill = $CentralKill }
    }

    # 1) verify the pulled baseline (sig + revoked signer + product/kind + expiry + anti-rollback).
    $verify = Test-PimDownlinkBaseline -Doc $Doc -PublicKey $PublicKey -AllowedKind @('baseline') -NowUtc $NowUtc -LastVersion $LastVersion -RevokedSigners @($RevokedSigners)
    if (-not $verify.ok) {
        return @{ ok = $false; reason = "baseline verify failed: $($verify.reason)"; scenarioId = "$($ctx.id)"; ring = $SlaveRing; admins = @(); sync = $null; content = $null; baselineVersion = 0; verify = $verify }
    }
    $payload = $verify.payload
    $blVersion = 0
    $vr = Get-PimDownlinkValue -Object $payload -Key 'version'
    if ($null -ne $vr -and "$vr".Trim()) { try { $blVersion = [int64]$vr } catch { $blVersion = 0 } }

    # 1b) RING-1 plane 2 VERSION GATE -- opt-in, and INERT when -RingPlan is absent.
    #
    # 🔒 WHY OPT-IN. This mirrors the AutomateIT non-breaking rule exactly: the
    # platform ships `default: null` so unassigned targets keep TODAY'S behaviour,
    # and the new code stays inert until a target is deliberately opted in. Same
    # here -- no -RingPlan means the pull behaves precisely as it did before this
    # gate existed, so the six VERIFIED s31 scenarios are unaffected.
    #
    # ⚠️ WHAT THIS FIXES. Get-PimUpdateSourceProfile documents the from-master pull
    # as "ringGated ... the pull only takes the ring's approved version (never a
    # version above the tenant's ring)". That was NOT implemented: the master
    # publishes ONE baseline-latest.json containing every admin row, the managed
    # tenant always pulls latest, and the only ring use was the admin filter in
    # step 3 below. The version was never checked against a ring at all -- it was
    # taken straight from the payload, gated only by signature/expiry/anti-rollback.
    # Recorded as docs/REQUIREMENTS.md sec.33 BUG-29. When a caller supplies a plan,
    # the decision comes from the VENDORED PLATFORM CORE (PIM-RingGate.ps1), never
    # from PIM-private hold/allow logic -- PIM consumes the AutomateIT design here.
    if ($PSBoundParameters.ContainsKey('RingPlan') -and $null -ne $RingPlan) {
        $action = "$($RingPlan.Action)"
        if ($action -eq 'hold') {
            return @{ ok = $false; reason = "ring HOLD: $($RingPlan.Reason) -- nothing is approved for ring $($RingPlan.Ring), so this tenant pulls nothing (a forgotten promotion must not look like success)"; scenarioId = "$($ctx.id)"; ring = $SlaveRing; admins = @(); sync = $null; content = $null; baselineVersion = $blVersion; verify = $verify }
        }
        # 'track-current' = unassigned = today's behaviour: no version restriction.
        if ($action -eq 'update') {
            $approved = "$($RingPlan.Version)".Trim()
            if ($approved -and "$blVersion" -ne $approved) {
                return @{ ok = $false; reason = "ring version mismatch: baseline v$blVersion was pulled but ring $($RingPlan.Ring) approves v$approved -- refusing (forward-only: promote a newer version, never accept an unapproved one)"; scenarioId = "$($ctx.id)"; ring = $SlaveRing; admins = @(); sync = $null; content = $null; baselineVersion = $blVersion; verify = $verify }
            }
        }
    }

    # 2) the admin set to consider = explicit -BaselineAdmins, else payload.rows.
    $src = @()
    if ($PSBoundParameters.ContainsKey('BaselineAdmins') -and $null -ne $BaselineAdmins) { $src = @($BaselineAdmins) }
    else { $src = @(Get-PimDownlinkValue -Object $payload -Key 'rows') }

    # 3) ring-gate to admin.Ring <= slave.Ring -- after the row-35 mode gate, whose skips are
    #    REPORTED (never silent): an admin the master no longer marks msp is not sent, and the
    #    slave-side apply withdraws it only inside the retraction budget.
    $notSynced = New-Object System.Collections.Generic.List[object]
    foreach ($a in @($src)) {
        $ms = Test-PimDownlinkAdminSynced -Admin $a
        if (-not $ms.synced) {
            $un = "$(Get-PimDownlinkValue -Object $a -Key 'UserName')"
            $notSynced.Add([ordered]@{ kind = 'admin'; name = $un; UserName = $un; GroupTag = ''; reason = $ms.reason }) | Out-Null
        }
    }
    $admins = @(Select-PimDownlinkAdmins -Admins $src -SlaveRing $SlaveRing)

    # 3a) MSP-4 TARGETING + CLASS GATING.
    # Tags come from the caller, else from the signed bundle's per-tenant map -- the
    # same delivery the projection policy uses, and for the same reason: a downlink
    # running inside the slave has no credential for the master's registry.
    $effTags = @()
    if ($PSBoundParameters.ContainsKey('TenantTags') -and $null -ne $TenantTags) { $effTags = @($TenantTags) }
    else {
        $tagMap = Get-PimDownlinkValue -Object $payload -Key 'tenantTags'
        if ($tagMap) {
            $mine = Get-PimDownlinkValue -Object $tagMap -Key "$TenantId".Trim().ToLowerInvariant()
            if (-not $mine) { $mine = Get-PimDownlinkValue -Object $tagMap -Key "$TenantId".Trim() }
            if ($mine) { $effTags = @($mine) }
        }
    }
    $targetSkips = New-Object System.Collections.Generic.List[object]
    $classHeld   = New-Object System.Collections.Generic.List[object]
    # IMP-13. Kept as its OWN list, not merged into the two above: four narrowings with one report
    # means four possible causes and no way to tell them apart, and this one's fix lives in the
    # CUSTOMER's naming conventions rather than in a ring or a Target.
    $unrecognisedAdmins = New-Object System.Collections.Generic.List[object]

    # admins: the class gate first (a blocked class means NONE of them, and says so),
    # then per-artifact targeting.
    $adminClass = Test-PimDownlinkClassAllowed -Class 'admins' -BlockedCapabilities $BlockedCapabilities
    if (-not $adminClass.allowed) {
        foreach ($a in $admins) { $classHeld.Add([ordered]@{ kind = 'admin'; name = "$(Get-PimDownlinkValue -Object $a -Key 'UserName')"; UserName = "$(Get-PimDownlinkValue -Object $a -Key 'UserName')"; GroupTag = ''; reason = $adminClass.reason }) | Out-Null }
        $admins = @()
    } else {
        $keepAdmins = New-Object System.Collections.Generic.List[object]
        foreach ($a in $admins) {
            $tv = Test-PimArtifactTarget -Target "$(Get-PimDownlinkValue -Object $a -Key 'Target')" -TenantId $TenantId -TenantTags $effTags
            if ($tv.match) { $keepAdmins.Add($a) | Out-Null }
            # MSP-4: `name` is the human label; `UserName`/`GroupTag` are the FIELDS a consumer
            # keys on. The reach transpose has to answer "which tenants does THIS TAG reach", and
            # parsing the tag back out of "user -> tag" is how a display string quietly becomes an
            # interface. Same reasoning as `retracts` being a field rather than a log sentence.
            else { $targetSkips.Add([ordered]@{ kind = 'admin'; name = "$(Get-PimDownlinkValue -Object $a -Key 'UserName')"; UserName = "$(Get-PimDownlinkValue -Object $a -Key 'UserName')"; GroupTag = ''; reason = $tv.reason }) | Out-Null }
        }
        $admins = @($keepAdmins.ToArray())
    }

    # IMP-13 -- WITHHOLD admins the slave's own engine could never see. Applied AFTER the ring and
    # targeting gates so it reports on what would actually have been created, and kept separate
    # from them because it has a different fix: this one is repaired in the CUSTOMER's naming
    # conventions, not in a ring or a Target.
    # 🔴 Withheld rather than created: an account the slave's Admins provider does not match is
    # never in its live set, so the diff says "not present" forever -- every tick recreates it and
    # leaves another unmanaged privileged account in the customer's tenant. Not creating it is
    # strictly safer than creating one nobody owns.
    $adminRecog = Select-PimUnrecognisableAdmins -SlaveAdminPrefixes $SlaveAdminPrefixes `
                    -AdminUserNames @(@($admins) | ForEach-Object { "$(Get-PimDownlinkValue -Object $_ -Key 'UserName')" })
    if ($adminRecog.checked -and @($adminRecog.unrecognised).Count) {
        $unrec = New-Object System.Collections.Generic.HashSet[string]
        foreach ($u in @($adminRecog.unrecognised)) { [void]$unrec.Add("$u".Trim().ToLowerInvariant()) }
        $keepRecog = New-Object System.Collections.Generic.List[object]
        foreach ($a in @($admins)) {
            $un = "$(Get-PimDownlinkValue -Object $a -Key 'UserName')".Trim()
            if ($unrec.Contains($un.ToLowerInvariant())) {
                $unrecognisedAdmins.Add([ordered]@{ kind = 'admin'; name = $un; UserName = $un; GroupTag = ''
                                                    reason = "the slave's admin naming prefixes ($($adminRecog.prefixes -join ', ')) do not match '$un' -- its engine would never see this account, so it would be recreated every tick and left unmanaged" }) | Out-Null
            } else { $keepRecog.Add($a) | Out-Null }
        }
        $admins = @($keepRecog.ToArray())
    }

    # 3b) MSP-2 / control #2: project the master's role memberships for exactly the
    # admins that survived the ring gate, through the relationship's policy.
    $srcAssign = $null
    if ($PSBoundParameters.ContainsKey('BaselineAssignments') -and $null -ne $BaselineAssignments) { $srcAssign = @($BaselineAssignments) }
    else {
        $fromPayload = Get-PimDownlinkValue -Object $payload -Key 'assignments'
        if ($null -ne $fromPayload) { $srcAssign = @($fromPayload) }
    }
    # 🔴 REQ-M (2.4.376): a bundle with group DEFINITIONS but no memberships ("assignments": [] -- which
    # Get-PimDownlinkValue unrolls to $null) skipped the whole definitions plan below, so a Replicate=Yes
    # group, nesting or binding -- a §71 SEED that stands on its own -- reached NO tenant while the master's
    # preview said "0 of N". No memberships is an empty set, not "no projection".
    if ($null -eq $srcAssign -and $null -ne (Get-PimDownlinkValue -Object $payload -Key 'definitions')) { $srcAssign = @() }
    # roles: same two narrowings, applied BEFORE the relationship policy so the plan can
    # tell "the customer declined role changes" from "the policy denied this tag".
    $roleClass = Test-PimDownlinkClassAllowed -Class 'roles' -BlockedCapabilities $BlockedCapabilities
    if ($null -ne $srcAssign) {
        if (-not $roleClass.allowed) {
            foreach ($a in @($srcAssign)) { $classHeld.Add([ordered]@{ kind = 'role'; name = "$(Get-PimDownlinkValue -Object $a -Key 'UserName') -> $(Get-PimDownlinkValue -Object $a -Key 'GroupTag')"; UserName = "$(Get-PimDownlinkValue -Object $a -Key 'UserName')"; GroupTag = "$(Get-PimDownlinkValue -Object $a -Key 'GroupTag')"; reason = $roleClass.reason }) | Out-Null }
            $srcAssign = @()
        } else {
            $keepA = New-Object System.Collections.Generic.List[object]
            foreach ($a in @($srcAssign)) {
                # §71: the membership's own Replicate/Ring/Target (blank = Follow the admin). The reason for
                # a plain Target miss is Test-PimArtifactTarget's own, word for word, as before.
                $tv = Test-PimReplicationReach -Row $a -Kind 'membership' -TenantId $TenantId -TenantRing $SlaveRing -TenantTags $effTags
                $tv['match'] = [bool]$tv.reach
                if ($tv.match) { $keepA.Add($a) | Out-Null }
                else { $targetSkips.Add([ordered]@{ kind = 'role'; name = "$(Get-PimDownlinkValue -Object $a -Key 'UserName') -> $(Get-PimDownlinkValue -Object $a -Key 'GroupTag')"; UserName = "$(Get-PimDownlinkValue -Object $a -Key 'UserName')"; GroupTag = "$(Get-PimDownlinkValue -Object $a -Key 'GroupTag')"; reason = $tv.reason }) | Out-Null }
            }
            $srcAssign = @($keepA.ToArray())
        }
    }

    $projection = $null
    $definitionPlan = $null
    if ($null -ne $srcAssign) {
        # The policy is AUTHORED in the master registry but DELIVERED in the signed bundle,
        # keyed by tenant id. A downlink running inside the slave (S6) has no credential for
        # the master's SQL, so a registry read there is impossible -- and reading it from the
        # signed payload is stronger anyway: the managed tenant cannot widen its own
        # projection without breaking the signature. An explicit -ProjectionPolicy still wins,
        # for tests and for an operator overriding a single run.
        $effPolicy = @($ProjectionPolicy)
        if (-not $effPolicy.Count) {
            $polMap = Get-PimDownlinkValue -Object $payload -Key 'projectionPolicy'
            if ($polMap) {
                $mine = Get-PimDownlinkValue -Object $polMap -Key "$TenantId".Trim().ToLowerInvariant()
                if (-not $mine) { $mine = Get-PimDownlinkValue -Object $polMap -Key "$TenantId".Trim() }
                if ($mine) { $effPolicy = @($mine) }
            }
        }
        $selArgs = @{
            Assignments    = $srcAssign
            AdminUserNames = @(@($admins) | ForEach-Object { "$(Get-PimDownlinkValue -Object $_ -Key 'UserName')" })
            Policy         = $effPolicy
            # 🔒 DECLARED **AND** FORWARDED. Session 32's one defect shape, four times over, was a
            # parameter that existed on the callee and was never passed by the caller -- PowerShell
            # binds only declared names, so nothing errors and the gate simply never sees anything.
            # The admin target-skips are already in $targetSkips by this point (the admin gate runs
            # above), so this is the honest set, not an empty placeholder.
            NotTargetedAdminNames = @($targetSkips.ToArray() | Where-Object { "$($_.kind)" -eq 'admin' } | ForEach-Object { "$($_.UserName)" })
        }
        # BUG-59: with definitions in the bundle, an unknown tag is no longer automatically
        # unresolvable -- we may be about to CREATE that group. So the unresolved check is
        # made against the slave's tags PLUS the tags the bundle can stand up.
        $creatableTags = @()
        $defsIn = Get-PimDownlinkValue -Object $payload -Key 'definitions'
        if ($defsIn) {
            $gg = Get-PimDownlinkValue -Object $defsIn -Key 'groups'
            if ($gg) { $creatableTags = @(@($gg) | ForEach-Object { "$(Get-PimDownlinkValue -Object $_ -Key 'GroupTag')" }) }
        }
        if ($PSBoundParameters.ContainsKey('SlaveGroupTags') -and $null -ne $SlaveGroupTags) {
            $selArgs['SlaveGroupTags'] = @(@($SlaveGroupTags) + $creatableTags | Where-Object { "$_".Trim() } | Select-Object -Unique)
        }
        $projection = Select-PimProjectedAssignments @selArgs

        # decide, per tag, whether the slave needs OUR group or already has its own.
        # A customer who blocked 'msp-groups' gets none of ours -- they define their own.
        $grpClass = Test-PimDownlinkClassAllowed -Class 'groups' -BlockedCapabilities $BlockedCapabilities
        if ($defsIn -and -not $grpClass.allowed) {
            $classHeld.Add([ordered]@{ kind = 'groups'; name = '(all group definitions)'; reason = $grpClass.reason }) | Out-Null
            $defsIn = $null
        }
        if ($defsIn) {
            $defArgs = @{
                Definitions   = $defsIn
                ProjectedTags = @(@($projection.projected) | ForEach-Object { "$($_.GroupTag)" })
                # §71: THIS tenant evaluates the reach rule and its own dependency closure (framework
                # MSP-4 SURFACE item 6). With a bundle that carries no replication fields every row is
                # Follow and the result is the pre-§71 one.
                TenantId      = $TenantId
                TenantRing    = $SlaveRing
                TenantTags    = @($effTags)
                ProjectedAssignments = @($projection.projected)
            }
            if ($PSBoundParameters.ContainsKey('SlaveGroupTags') -and $null -ne $SlaveGroupTags) { $defArgs['SlaveGroupTags'] = $SlaveGroupTags }
            $definitionPlan = Select-PimProjectedDefinitions @defArgs
        }
    }

    # 4) resolve the sync-file staging path for this scenario.
    $sync = Resolve-PimDownlinkSyncPath -SyncFileLocation "$($ctx.syncFileLocation)" -TenantId $TenantId -CentralRoot $CentralRoot -LocalRoot $LocalRoot

    # 5) build the deterministic per-tenant sync content.
    $contentArgs = @{ Admins = $admins; TenantId = $TenantId; SlaveRing = $SlaveRing; BaselineVersion = $blVersion; Scope = $Scope }
    if ($null -ne $projection) { $contentArgs['Projection'] = $projection }
    $content = New-PimDownlinkSyncContent @contentArgs

    # 🔴 "PROJECTED", never "reach" -- and the difference is security-relevant, not stylistic.
    # This sentence used to read "N admin(s) reach slave ring M". A narrowing run therefore
    # printed "1 admin(s) reach" while THREE admins still held live access in that tenant:
    # desired fell 3 -> 2 -> 1, live stayed 3, remove=0 throughout. Target controls FUTURE
    # PROJECTION, not PRESENT STATE -- un-targeting an admin withholds the next projection, it
    # does not take anything away. Reading "1 admin(s) reach" as "the other two no longer have
    # access there" is exactly the misreading to prevent, and the ring-0 Global Administrator is
    # the account it would most likely be made about. A plan is a statement about what WILL be
    # sent, so it is worded in the tense it actually has.
    $reason = "downlink plan for $($ctx.id): $($admins.Count) admin(s) PROJECTED to slave ring $SlaveRing from baseline v$blVersion"
    if ($null -ne $projection) {
        $reason += "; $(@($projection.projected).Count) role assignment(s) projected"
        $nEx = @($projection.excluded).Count; $nUn = @($projection.unresolved).Count
        if ($nEx) { $reason += ", $nEx excluded by policy/ring" }
        # surfaced in the reason, not only in the file -- an unresolvable tag is a
        # role the admin will NOT get, and that must be readable at a glance.
        if ($nUn) { $reason += ", $nUn UNRESOLVED (no such group tag in this tenant)" }
    }
    if ($null -ne $definitionPlan) {
        $nC = @($definitionPlan.create).Count; $nD = @($definitionPlan.defer).Count
        if ($nC) { $reason += "; $nC group(s) to CREATE (Owner=MSP)" }
        if ($nD) { $reason += ", $nD already owned by the customer (left untouched)" }
        # §71: a dependency included against its own fields is a WARNING the operator must see.
        $nA = @($definitionPlan.autoIncluded).Count
        if ($nA) { $reason += "; $nA dependenc(ies) AUTO-INCLUDED against their own Replicate/Ring/Target (see autoIncluded)" }
    }
    # MSP-4: report the two new narrowings SEPARATELY from the policy's. Four different
    # reasons a thing can be absent, four different fixes -- merging them would leave an
    # operator guessing which one applied.
    if ($targetSkips.Count) {
        $reason += "; $($targetSkips.Count) artifact(s) not TARGETED at this tenant"
        # A withheld ADMIN is the case that gets misread, so it is named as such and the
        # non-retraction is said in the SAME breath rather than left to be inferred from a
        # remove=0 further down the log. "Not sent" and "taken away" are the two readings this
        # line has to keep apart.
        # 🪤 `.ToArray()`, NOT `@($targetSkips)`. Wrapping THE LIST (rather than its array) in
        # @() throws "Argument types do not match" -- a message that names no variable and
        # underlines the whole pipeline. MEASURED in fresh processes on BOTH hosts: this is NOT
        # a 5.1-vs-7 divergence (pwsh 7.6.3 and Windows PowerShell 5.1 both throw), so it is not
        # a HOST-1 case. The actual discriminator is how the list was CONSTRUCTED:
        #   New-Object System.Collections.Generic.List[object]   -> @($list) THROWS   (both hosts)
        #   [System.Collections.Generic.List[object]]::new()     -> @($list) works    (both hosts)
        # ...despite both reporting the identical type name. Safe forms either way: pipe it
        # (`@($list | Where-Object {...})` enumerates fine) or materialise it with .ToArray().
        # The neighbouring `notTargeted = @($targetSkips.ToArray())` already had the right idiom;
        # the first version of this line did not copy it.
        $adminSkips = @($targetSkips.ToArray() | Where-Object { "$($_.kind)" -eq 'admin' })
        if ($adminSkips.Count) {
            $reason += " ($($adminSkips.Count) of them ADMIN(S) -- WITHHELD, NOT RETRACTED: whatever access they already hold in this tenant is UNCHANGED by this plan)"
        }
    }
    if ($notSynced.Count)   { $reason += "; $($notSynced.Count) admin(s) NOT SYNCED -- their row at the master is not ManagementMode=msp (a slave that still holds them withdraws them only inside its retraction budget)" }
    if ($classHeld.Count)   { $reason += "; $($classHeld.Count) HELD -- the customer blocked that capability" }
    # IMP-13: named in the reason, because the operator cannot fix this one from our side and the
    # symptom without it (an account recreated on every tick, forever) points nowhere near the cause.
    if ($unrecognisedAdmins.Count) {
        $reason += "; $($unrecognisedAdmins.Count) admin(s) WITHHELD -- the slave's admin naming prefixes do not match them, so its engine would never see the accounts and would recreate them every tick (fix the CUSTOMER's AdminAccountPatterns)"
    }

    return @{
        ok              = $true
        reason          = $reason
        scenarioId      = "$($ctx.id)"
        ring            = $SlaveRing
        sync            = $sync
        admins          = $admins
        assignments     = $(if ($null -ne $projection) { @($projection.projected) } else { @() })
        projection      = $projection
        definitions     = $definitionPlan
        notTargeted     = @($targetSkips.ToArray())
        # §71 -- FIELDS, like notTargeted: dependencies included with a warning, and group-model rows
        # whose own replication fields keep them out of this tenant.
        autoIncluded    = $(if ($null -ne $definitionPlan) { @($definitionPlan.autoIncluded) } else { @() })
        notReplicated   = $(if ($null -ne $definitionPlan) { @($definitionPlan.notReplicated) } else { @() })
        # Row 35: admins the master does not mark ManagementMode=msp. A FIELD, like notTargeted.
        notSynced       = @($notSynced.ToArray())
        # A downlink plan NEVER removes access -- it only decides what is SENT. Stated as a
        # field so a caller can assert it directly instead of inferring it from remove=0, which
        # is the inference that went wrong. Retraction is a destructive CROSS-TENANT act and
        # must be its own explicit operation; it must never ride in as a side effect of
        # narrowing a Target. If this field is ever anything but $false, that decision was made
        # somewhere it should not have been.
        retracts        = $false
        classHeld       = @($classHeld.ToArray())
        # IMP-13. A FIELD, so a caller asserts the property instead of parsing the reason line --
        # the same rule `retracts` established. `adminRecognitionChecked` is the load-bearing half:
        # an EMPTY unrecognisedAdmins list means "none" only when this is $true; when it is $false
        # nobody looked, and the two must never read alike.
        unrecognisedAdmins      = @($unrecognisedAdmins.ToArray())
        adminRecognitionChecked = [bool]$adminRecog.checked
        tenantTags      = @($effTags)
        content         = $content
        baselineVersion = $blVersion
        verify          = $verify
    }
}

# ---------------------------------------------------------------------------
# IDEMPOTENCY DECISION (pure). Given the freshly-computed sync content + what is
# ALREADY staged on disk (the wrapper reads the existing files' text), decide
# whether the second pass is a no-op. Compares the stable JSON byte-for-byte.
# Returns @{ changed; changedFiles=@(...); detail }. changed=$false => idempotent.
# ---------------------------------------------------------------------------
function Test-PimDownlinkIdempotent {
    param(
        [Parameter(Mandatory)][hashtable]$NewContent,    # @{ admins; manifest } (strings)
        [hashtable]$ExistingContent = @{}                # @{ admins; manifest } current on-disk text (missing = '')
    )
    $changed = New-Object System.Collections.Generic.List[string]
    foreach ($k in @($NewContent.Keys)) {
        $new = "$($NewContent[$k])"
        $old = ''
        if ($ExistingContent.ContainsKey($k)) { $old = "$($ExistingContent[$k])" }
        # normalise line endings so a CRLF/LF round-trip on disk isn't a false change.
        $newN = $new -replace "`r`n", "`n"
        $oldN = $old -replace "`r`n", "`n"
        if ($newN -ne $oldN) { $changed.Add($k) | Out-Null }
    }
    $arr = @($changed.ToArray())
    return @{
        changed      = ($arr.Count -gt 0)
        changedFiles = $arr
        detail       = $(if ($arr.Count) { "would rewrite: $($arr -join ', ')" } else { 'all sync files identical (idempotent no-op)' })
    }
}

# ---------------------------------------------------------------------------
# SCENARIO RUNNER PLAN (pure). The topology branch for the scenario-bound runner:
#   single  (S1/S2)        -> engine apply only.
#   master  (S3/S4)        -> engine apply only (master hosts its own estate).
#   managed (S5/S6)        -> downlink-sync THEN engine apply.
# Returns @{ scenarioId; role; steps=@('downlink-sync'?, 'engine-apply'); runDownlink; runEngine; reason }.
# PURE: decides the ordered step list; the live runner executes each step.
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# IMP-12 -- WHICH SIDE CREATES THE ACCOUNTS (pure). PUSH means the central MSP host
# holds each customer's credential and writes the accounts itself (the fan-out); PULL
# means the managed tenant's own engine does, from desired rows the downlink staged.
#
# Decided from `syncFileLocation` rather than the scenario NAME: 'central-msp' says the
# central host is where the work happens, which IS the question being asked -- and it
# keeps working if another central-hosted scenario is ever added.
# Returns $true for push (S5-shaped), $false for pull (S6-shaped) and for anything that
# stages nothing, because "no sync files" cannot mean "push into the customer".
# ---------------------------------------------------------------------------
function Test-PimDownlinkPushTopology {
    param([Parameter(Mandatory)][object]$Scenario)
    $c = Resolve-PimScenarioContext -Scenario $Scenario
    return ("$($c.syncFileLocation)".Trim().ToLowerInvariant() -eq 'central-msp')
}

function Get-PimScenarioRunPlan {
    param([Parameter(Mandatory)][object]$Scenario)
    $ctx = Resolve-PimScenarioContext -Scenario $Scenario
    $role = "$($ctx.role)"
    $runDownlink = [bool]$ctx.syncAdminsPermissions   # true only for managed (S5/S6)
    $steps = New-Object System.Collections.Generic.List[string]
    if ($runDownlink) { $steps.Add('downlink-sync') | Out-Null }
    $steps.Add('engine-apply') | Out-Null
    $reason = if ($runDownlink) {
        "managed scenario $($ctx.id) ($role): ring pull -> master->slave sync -> engine apply"
    } else {
        "$role scenario $($ctx.id): engine apply only (no downlink)"
    }
    return @{
        scenarioId  = "$($ctx.id)"
        role        = $role
        runDownlink = $runDownlink
        runEngine   = $true
        steps       = @($steps.ToArray())
        reason      = $reason
    }
}

# =============================================================================
# THIN LIVE ORCHESTRATORS (named to satisfy the live matrix's capability probe).
# These compose the pure cores above with the EXISTING live engines. They DO
# touch the world (verify+stage files, run the fan-out + engine) -- but ONLY when
# explicitly invoked by the live wrappers / main session. The matrix's
# Test-SyncWiringBuilt only needs these to be DEFINED (Get-Command), which is the
# §31.3 "wiring exists + is invokable" contract; the live outcome (admins created
# in the slave) is proven by running them against the real tenants.
#
# IMPORTANT (pull-not-push): the MASTER never writes into a managed tenant. The
# central/managed engine host runs Invoke-PimManagedDownlink, which applies the
# synced rows into the slave via the SLAVE's OWN per-tenant SPN (Invoke-PimMspFanout
# authenticates per-tenant from pim.CentralAdmins + platform.TenantApps and creates
# the admins IN the slave). The downlink only stages the ring's signed baseline.
# =============================================================================

# SEC-25 -- FETCH the master's signed central-kill manifest for the pull (thin I/O; the verdict is the pure
# Get-PimCentralKillState). Where it lives: -CentralKillUrl, else the SIBLING of the bundle URL
# (<container>/central-kill.json -- the same public-but-signed / private-endpoint transport, DESIGN 13.7).
#   * 404          -> @{ checked = $true;  doc = $null }  (the master publishes no kill: none in force)
#   * other failure-> @{ checked = $true;  error = '...' } (UNKNOWN -> the pull refuses: fail closed)
#   * 'none', or no URL to derive one from -> @{ checked = $false } (reported NOT CHECKED, loudly)
# -Fetcher is a test seam: { param($url, $headers) <parsed doc>; throw with .Exception.Response.StatusCode on HTTP errors }.
function Get-PimCentralKillSource {
    param(
        [string]$CentralKillUrl,
        [string]$BaselineUrl,
        [string]$AccessToken,
        [scriptblock]$Fetcher
    )
    $u = "$CentralKillUrl".Trim()
    if ($u -ieq 'none') { return @{ checked = $false; doc = $null; error = ''; url = '' } }
    $derived = $false
    if (-not $u -and "$BaselineUrl".Trim()) {
        $derived = $true
        $b = ("$BaselineUrl".Trim() -replace '[?#].*$', '')
        $slash = $b.LastIndexOf('/')
        if ($slash -gt 8) { $u = $b.Substring(0, $slash + 1) + 'central-kill.json' }
    }
    if (-not $u) { return @{ checked = $false; doc = $null; error = ''; url = '' } }
    if (-not $Fetcher) { $Fetcher = { param($url, $headers) Invoke-RestMethod -Method GET -Uri $url -Headers $headers -ErrorAction Stop } }
    $headers = @{ 'x-ms-version' = '2021-08-06' }
    if ("$AccessToken".Trim()) { $headers['Authorization'] = "Bearer $AccessToken" }
    try {
        $raw = & $Fetcher $u $headers
        $doc = $raw
        if ($raw -is [string]) { $br = $raw.IndexOf('{'); if ($br -gt 0) { $raw = $raw.Substring($br) }; $doc = $raw | ConvertFrom-Json }
        return @{ checked = $true; doc = $doc; error = ''; url = $u }
    } catch {
        $code = 0
        try { $resp = $_.Exception.Response; if ($resp) { $code = [int]$resp.StatusCode } } catch { $code = 0 }
        if ($code -eq 404) { return @{ checked = $true; doc = $null; error = ''; url = $u } }
        # 🪤 MEASURED LIVE on RIDE, 2026-09-18 (2.4.370): the DERIVED sibling of a bundle URL on a store that is NOT
        # publicly readable answers 401/403. That is not "a kill might be standing". It is "nobody configured a
        # kill location this identity can read", and it refused every pull. A location the operator did not
        # configure is reported NOT CHECKED, loudly, with the way to enforce it. An EXPLICIT -CentralKillUrl
        # (PIM_CentralKillUrl) stays strictly fail-closed on any non-404 failure.
        if ($derived -and ($code -eq 401 -or $code -eq 403)) {
            return @{ checked = $false; doc = $null; error = ''; url = $u
                      note = "central kill NOT CHECKED -- the default location $($u) answered HTTP $code (the bundle store is not publicly readable, and the bundle link does not cover the kill manifest). Set PIM_CentralKillUrl to a location this job can read to enforce the check." }
        }
        $m = "$($_.Exception.Message)"
        return @{ checked = $true; doc = $null; url = $u
                  error = "GET $($u) failed$(if ($code) { " (HTTP $code)" }): $($m.Substring(0, [Math]::Min(300, $m.Length)))" }
    }
}

# Invoke-PimManagedDownlink -- the ring-gated master->managed admin/permission
# downlink for ONE managed tenant. Verifies + stages the sync files (pure plan),
# then (unless -WhatIfMode) applies into the slave by composing Invoke-PimMspFanout.
#   -Scenario        : S5 | S6 (or descriptor).
#   -Doc             : the pulled signed baseline document.
#   -PublicKey       : verifying key (omit in prod -> embedded cert).
#   -TenantId/-SlaveRing : the managed tenant + ring.
#   -CentralRoot/-LocalRoot : sync-file staging roots.
#   -SqlServer/-SqlDatabase : the registry the fan-out reads (slave creation).
#   -WhatIfMode      : default ON (verify + stage files + PLAN the fan-out only).
# Returns the decision/plan object + a `staged` list + the fan-out result (live).
function Invoke-PimManagedDownlink {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Scenario,
        [Parameter(Mandatory)][object]$Doc,
        [object]$PublicKey,
        [object[]]$BaselineAdmins,
        [Parameter(Mandatory)][string]$TenantId,
        [Parameter(Mandatory)][int]$SlaveRing,
        [string]$CentralRoot = $env:PIM_SyncRootCentral,
        [string]$LocalRoot   = $env:PIM_SyncRootLocal,
        [string]$SqlServer,
        [string]$SqlDatabase,
        [datetime]$NowUtc = ([datetime]::UtcNow),
        [int64]$LastVersion = 0,
        # BUG-29 wiring. A Get-PimTemplateRingPlan result for THIS managed tenant.
        # Forwarded to Get-PimDownlinkPlan ONLY when supplied, so the gate stays
        # opt-in end-to-end: without it this orchestrator behaves exactly as it did
        # when S5/S6 were VERIFIED. This parameter is the link that was missing --
        # the gate existed and nothing could reach it.
        [object]$RingPlan,
        # MSP-2 / control #2 wiring, all optional and INERT when absent (same
        # non-breaking rule as -RingPlan). -SlaveStoreConnectionString is what turns
        # role projection from "staged to a file" into "applied in the slave".
        [object[]]$BaselineAssignments,
        [object[]]$ProjectionPolicy = @(),
        [string[]]$SlaveGroupTags,
        [string]$SlaveStoreConnectionString,
        # SEC-10 / MSP-3 step 4 -- THE CUSTOMER'S OWN VETO, and this parameter is the link
        # that was missing. Get-PimDownlinkPlan has honoured -BlockedCapabilities since
        # MSP-4 and the class gate was proven against a real bundle -- but this orchestrator
        # did not DECLARE the parameter, so the entry path could never pass one and the gate
        # was unreachable in production. That is BUG-29's shape exactly, one layer out: the
        # -RingPlan comment above ("the gate existed and nothing could reach it") had become
        # true of this gate too. Forwarded ONLY when supplied, so an absent list is
        # byte-identical to previous behaviour.
        [string[]]$BlockedCapabilities,
        # IMP-13: the SLAVE's own admin naming prefixes. DECLARED here as well as on the plan,
        # because PowerShell binds only declared names -- a gate the orchestrator cannot accept is
        # a gate no entry point can reach, which is this file's most expensive recurring defect
        # (BUG-29, SEC-10b, BUG-78, BUG-79). Same inert-when-absent rule as the two gates above.
        [string[]]$SlaveAdminPrefixes,
        # IMP-12: the managed tenant's default verified domain, used to build each synced
        # admin's UPN on the S6 pull path. Omitted => resolved from the ambient tenant when
        # we are running inside it; never guessed.
        [string]$SlaveDefaultDomain,
        # TAP intent for the synced admins -- enforced ON (71.17). -CreateTapDefault is kept only so existing callers bind.
        # 🔴 71.19: -DefaultManagerEmail is GONE. Who receives an admin's TAP is its SPONSOR DEPARTMENT's owners, resolved
        # in the slave from the department rows the bundle carries (Get-PimAdminMailRecipientPlan) -- a fleet-wide fallback
        # address was papering over a missing department link, and it is exactly the "manager on the person" the design
        # forbids (REQUIREMENTS §62).
        [string]$CreateTapDefault = 'TRUE',
        [int]$TapLifetimeHoursDefault = 8,
        [switch]$AllowFullPrune,
        # §71 / framework MSP-4 SURFACE item 8: synced rows that stop reaching this tenant are REPORTED
        # ('would remove') and withdrawn only with this opt-in, inside the removal budget. Declared
        # here AND on Sync-PimMasterToSlave -- PowerShell binds only declared names.
        [switch]$AllowRetraction,
        # SEC-25: where the master's signed central-kill manifest came from, as the entry script found it:
        # @{ checked = $bool; doc = <manifest or $null>; error = '<transport failure>' }. Unbound => the kill
        # is reported NOT CHECKED (never "no kill"). Verified here, against THIS tenant's revoked signers.
        [object]$CentralKillSource,
        [switch]$WhatIfMode = $true
    )
    # 0) SEC-24 / SEC-25 -- THIS TENANT'S TRUST STATE, from its OWN store (pim.Settings; never a file).
    #    * the anti-rollback floor: the last bundle version this tenant APPLIED. The effective floor is the
    #      higher of it and -LastVersion, so an older signed bundle that has not expired is refused.
    #    * the revoked signers: a bundle (or kill manifest) signed by one of them is refused.
    #    🔴 Before this, the scheduled pull passed -LastVersion 0 all the way down and the only floor that
    #    existed was a FILE the container lost on every execution -- anti-rollback did nothing, and a
    #    compromised signing key could not be revoked at all.
    #    A store that cannot be READ is a refusal: an unknown floor is not floor 0.
    $trustFloor = [int64]0
    $revoked = @()
    $trustRead = $false
    if ("$SlaveStoreConnectionString".Trim()) {
        try {
            $trustFloor = [int64](Get-PimBaselineAppliedVersion -ConnectionString $SlaveStoreConnectionString)
            $revoked = @(Get-PimBaselineRevokedSignerIds -ConnectionString $SlaveStoreConnectionString)
            $trustRead = $true
        } catch {
            $msg = "REFUSED: could not read this tenant's trust state (anti-rollback floor / revoked signers) from its store: $($_.Exception.Message)"
            Write-Host "[downlink] $msg" -ForegroundColor Red
            return ([pscustomobject]@{ ok = $false; reason = $msg; plan = $null; staged = @(); fanout = $null; slaveRing = $SlaveRing; slaveRingSource = 'local' })
        }
    }
    $effFloor = [int64]$LastVersion
    if ($trustFloor -gt $effFloor) { $effFloor = $trustFloor }
    if ($trustRead) {
        Write-Host ("[downlink] trust: anti-rollback floor v{0} (store v{1}, -LastVersion v{2}); {3} revoked signer(s)" -f $effFloor, $trustFloor, $LastVersion, @($revoked).Count) -ForegroundColor DarkGray
    } else {
        Write-Host ("[downlink] trust: NO slave store -- the anti-rollback floor is only -LastVersion v{0} and NO revoked-signer list was read; nothing from this bundle is applied to a store on this run" -f $LastVersion) -ForegroundColor Yellow
    }
    # SEC-25: the central kill, verified against the same keys + revoked list as the bundle.
    $kill = $null
    if ($PSBoundParameters.ContainsKey('CentralKillSource') -and $null -ne $CentralKillSource) {
        $kc = Get-PimDownlinkValue -Object $CentralKillSource -Key 'checked'
        $kill = Get-PimCentralKillState -Doc (Get-PimDownlinkValue -Object $CentralKillSource -Key 'doc') `
                    -Checked ($null -eq $kc -or [bool]$kc) -FetchError "$(Get-PimDownlinkValue -Object $CentralKillSource -Key 'error')" `
                    -NotCheckedReason "$(Get-PimDownlinkValue -Object $CentralKillSource -Key 'note')" `
                    -PublicKey $PublicKey -RevokedSigners @($revoked) -NowUtc $NowUtc
    } else {
        $kill = Get-PimCentralKillState -Doc $null -Checked $false
    }
    Write-Host "[downlink] $($kill.reason)" -ForegroundColor $(if ($kill.blocks) { 'Red' } elseif ($kill.state -in @('notchecked', 'expired')) { 'Yellow' } else { 'DarkGray' })

    # 1) PURE plan: verify + ring-filter + resolve paths + build content.
    $planArgs = @{ RevokedSigners = @($revoked); CentralKill = $kill }
    if ($PSBoundParameters.ContainsKey('RingPlan') -and $null -ne $RingPlan) { $planArgs['RingPlan'] = $RingPlan }
    if ($PSBoundParameters.ContainsKey('BaselineAssignments') -and $null -ne $BaselineAssignments) { $planArgs['BaselineAssignments'] = $BaselineAssignments }
    if ($PSBoundParameters.ContainsKey('SlaveGroupTags') -and $null -ne $SlaveGroupTags) { $planArgs['SlaveGroupTags'] = $SlaveGroupTags }
    if (@($ProjectionPolicy).Count) { $planArgs['ProjectionPolicy'] = $ProjectionPolicy }
    # SEC-10: same inert-when-absent rule as -RingPlan. Bound-and-empty is forwarded too --
    # "the customer blocks nothing" is a real answer the plan should report as such, and it
    # is NOT the same as "nobody ever asked", which is what an unbound parameter means.
    if ($PSBoundParameters.ContainsKey('BlockedCapabilities') -and $null -ne $BlockedCapabilities) { $planArgs['BlockedCapabilities'] = $BlockedCapabilities }
    # IMP-13: DECLARED above AND FORWARDED here. Declaring without forwarding is the same defect
    # wearing a parameter -- the caller supplies it and it dies inside the function.
    if ($PSBoundParameters.ContainsKey('SlaveAdminPrefixes') -and $null -ne $SlaveAdminPrefixes) { $planArgs['SlaveAdminPrefixes'] = $SlaveAdminPrefixes }
    $plan = Get-PimDownlinkPlan -Scenario $Scenario -Doc $Doc -PublicKey $PublicKey `
        -BaselineAdmins $BaselineAdmins -TenantId $TenantId -SlaveRing $SlaveRing `
        -CentralRoot $CentralRoot -LocalRoot $LocalRoot -NowUtc $NowUtc -LastVersion $effFloor @planArgs
    if (-not $plan.ok) {
        Write-Host "[downlink] REFUSED: $($plan.reason)" -ForegroundColor Red
        # 🔑 A REFUSAL IS THE CASE THE OPERATOR MOST NEEDS TO SEE, so it is recorded on the way out
        # rather than only on the success path. A ring HOLD, a bad signature or a version mismatch
        # all land here -- and every one of them otherwise looks, from the operator's side,
        # identical to a tenant that simply never ran. That indistinguishability is the whole
        # reason framework §8 exists; a record written only when things go well would reproduce it.
        # The refusal plan has no staging folder, so this falls back to the resolved local/central
        # root and still lands somewhere the operator looks.
        $refFolder = if ($plan.sync -and "$($plan.sync.tenantFolder)".Trim()) { $plan.sync.tenantFolder }
                     elseif ("$LocalRoot".Trim())   { Join-Path $LocalRoot $TenantId }
                     elseif ("$CentralRoot".Trim()) { Join-Path $CentralRoot $TenantId }
                     else { '' }
        $refRecord = New-PimAcceptanceRecord -Plan $plan -TenantId $TenantId -RingPlan $RingPlan `
            -BlockedCapabilities $BlockedCapabilities -NowUtc $NowUtc -WhatIfMode:$WhatIfMode
        $refPath = $null
        if ("$refFolder".Trim()) { $refPath = Write-PimAcceptanceRecord -Record $refRecord -Folder $refFolder }
        return ([pscustomobject]@{ ok = $false; reason = $plan.reason; plan = $plan; staged = @(); fanout = $null; acceptance = $refRecord; acceptancePath = $refPath
                                   slaveRing = $SlaveRing; slaveRingSource = 'local'; trust = @{ floor = $effFloor; storeFloor = $trustFloor; revokedSigners = @($revoked).Count; read = $trustRead; centralKill = $kill } })
    }
    Write-Host "[downlink] $($plan.reason)" -ForegroundColor Cyan

    # 2) STAGE the per-tenant sync files (idempotent: only rewrite on change).
    $staged = New-Object System.Collections.Generic.List[object]
    $sync = $plan.sync
    if ($sync -and [bool]$sync.stage -and "$($sync.tenantFolder)".Trim()) {
        if (-not (Test-Path -LiteralPath $sync.tenantFolder)) { New-Item -ItemType Directory -Force -Path $sync.tenantFolder | Out-Null }
        $existing = @{}
        foreach ($k in @($plan.content.Keys)) {
            $fp = $sync.files[$k]
            if ($fp -and (Test-Path -LiteralPath $fp)) { try { $existing[$k] = [System.IO.File]::ReadAllText($fp) } catch {} }
        }
        $idem = Test-PimDownlinkIdempotent -NewContent $plan.content -ExistingContent $existing
        foreach ($k in @($plan.content.Keys)) {
            $fp = $sync.files[$k]
            if (-not $fp) { continue }
            if ($idem.changedFiles -contains $k -or -not (Test-Path -LiteralPath $fp)) {
                [System.IO.File]::WriteAllText($fp, "$($plan.content[$k])", (New-Object System.Text.UTF8Encoding($false)))
                $staged.Add([pscustomobject]@{ file = $fp; action = 'written' }) | Out-Null
            } else {
                $staged.Add([pscustomobject]@{ file = $fp; action = 'unchanged' }) | Out-Null
            }
        }
        Write-Host "[downlink] sync files: $($idem.detail) ($($sync.tenantFolder))" -ForegroundColor DarkGray
    } else {
        Write-Host "[downlink] no sync-file staging for this scenario ($($sync.reason))" -ForegroundColor DarkGray
    }

    # 3) CREATE THE ACCOUNTS -- by one of two routes, and WHICH one is a property of the
    #    topology, not a preference.
    #
    #    S5 (central-hosted managed): the central host holds each customer's SPN + cert, so
    #    it composes Invoke-PimMspFanout, which authenticates per tenant and writes the
    #    accounts itself. Ring-aware via pim.vw_AdminTenantTargets.
    #
    #    S6 (local-hosted managed): the downlink already runs INSIDE the managed tenant,
    #    whose own engine has the identity and the tick schedule. Handing it desired rows
    #    (Invoke-PimDownlinkAdminApply) is both simpler and the only thing consistent with
    #    MSP-3's pull-not-push -- the master never writes into the customer.
    #
    # 🪤 IMP-12 -- THIS BRANCH DID NOT EXIST, AND ITS ABSENCE WAS SILENT. Invoke-PimDownlinkAdminApply
    # was built for exactly this and then called by NOTHING but its own unit test, while this
    # orchestrator ran the fan-out on BOTH topologies. On S6 the fan-out is the wrong mechanism
    # (and IMP-11 records that its cross-tenant reach is unavailable anyway), so the accounts were
    # never created -- and every projected membership then pointed at a principal that does not
    # exist. The roles apply reported success while granting nothing.
    $fanout = $null
    $adminApply = $null
    # 🪤 The decision is its own PURE function, and it resolves the scenario itself. An
    # earlier draft read `$ctx.id` -- but `$ctx` belongs to Get-PimDownlinkPlan and does not
    # exist here, so it answered "not push" for EVERY scenario and quietly disabled the
    # fan-out on the one topology that needs it. A branch this consequential gets a function
    # with a test, not an inline string comparison against a variable from another scope.
    $isPushTopology = Test-PimDownlinkPushTopology -Scenario $Scenario
    if ($isPushTopology) {
        $fanoutScript = Join-Path (Split-Path -Parent $PSScriptRoot) '..\setup\Invoke-PimMspFanout.ps1'
        $fanoutScript = (Resolve-Path -LiteralPath $fanoutScript -ErrorAction SilentlyContinue)
        if ($fanoutScript) {
            # 🔴 NO `.\SQLEXPRESS` FALLBACK (operator 2026-08-28: SQL Express is not used, anywhere).
            # This is the MSP FAN-OUT -- it writes accounts into managed tenants' stores. An
            # unconfigured server defaulting to a local database meant the most consequential
            # write path in the solution could aim itself at whatever happened to be installed on
            # the box, and report a clean run. Refuse instead: PIM-SqlStore.ps1 records the two
            # false greens (BUG-78, TEST-32) this default already produced.
            $srv = if ("$SqlServer".Trim()) { "$SqlServer".Trim() } else { "$($global:PIM_SqlServer)".Trim() }
            if (-not $srv) {
                $msg = 'fan-out REFUSED: no SQL server configured (pass -SqlServer or set $global:PIM_SqlServer to the Azure SQL FQDN). There is no local default -- SQL Express is not a store this product uses.'
                Write-Host "[downlink] $msg" -ForegroundColor Red
                return ([pscustomobject]@{ ok = $false; reason = $msg; plan = $plan; staged = @($staged.ToArray()); fanout = $null })
            }
            $db  = if ("$SqlDatabase".Trim()) { $SqlDatabase } elseif ($global:PIM_SqlDatabase) { "$($global:PIM_SqlDatabase)" } else { 'PimPlatform' }
            try {
                $fanout = & $fanoutScript -ServerInstance $srv -Database $db -WhatIfMode:$WhatIfMode
            } catch {
                Write-Host "[downlink] fan-out apply failed: $($_.Exception.Message)" -ForegroundColor Red
                return ([pscustomobject]@{ ok = $false; reason = "fan-out failed: $($_.Exception.Message)"; plan = $plan; staged = @($staged.ToArray()); fanout = $null })
            }
        } else {
            Write-Host "[downlink] Invoke-PimMspFanout.ps1 not found -- staged sync files only (no apply)." -ForegroundColor Yellow
        }
    } elseif ("$SlaveStoreConnectionString".Trim()) {
        # The slave's UPNs are <UserName>@<its default domain>, so the domain is required.
        # Resolve it from the ambient tenant when we are running inside it (S6), and REFUSE
        # rather than guess: a wrong domain creates accounts nobody can sign in to and
        # memberships that resolve to nothing.
        # 🔑 REQ-T (2.4.377): THIS TENANT'S OWN "Admin account domain" SETTING DECIDES, like every slave-side setting
        # (ring included, DESIGN). The master's suffix is never carried: a replicated admin is <UserName>@<the domain
        # THIS tenant chose>, and only when it chose none (blank = default domain, the v1 behaviour) do -SlaveDefaultDomain
        # and then the ambient default domain apply.
        $dom = "$(Get-PimSlaveAdminUpnDomain -ConnectionString $SlaveStoreConnectionString)".Trim()
        if (-not $dom) { $dom = "$SlaveDefaultDomain".Trim() }
        if (-not $dom -and (Get-Command Get-PimTargetDefaultDomain -ErrorAction SilentlyContinue)) {
            try { $dom = "$(Get-PimTargetDefaultDomain)".Trim() } catch { $dom = '' }
        }
        if ($dom) {
            $adminApply = Invoke-PimDownlinkAdminApply -ConnectionString $SlaveStoreConnectionString `
                -Admins @($plan.admins) -DefaultDomain $dom `
                -CreateTapDefault $CreateTapDefault -TapLifetimeHoursDefault $TapLifetimeHoursDefault `
                -AllowFullPrune:$AllowFullPrune -AllowRetraction:$AllowRetraction -WhatIfMode:$WhatIfMode
            Write-Host "[downlink] admins (S6 pull, domain $dom): $($adminApply.detail)" -ForegroundColor $(if ($adminApply.ok) { 'Green' } else { 'Red' })
            foreach ($x in @($adminApply.wouldRetract)) { if ("$x".Trim()) { Write-Host "[downlink]   WOULD REMOVE $x (no longer reaches this tenant; reported only -- pass -AllowRetraction)" -ForegroundColor Yellow } }
        } else {
            Write-Host "[downlink] admins NOT staged: no slave default domain (-SlaveDefaultDomain, or an ambient tenant to read it from). Refusing to build UPNs at a guessed domain." -ForegroundColor Yellow
        }
    } else {
        Write-Host "[downlink] admins NOT staged: this is a pull topology and no -SlaveStoreConnectionString was supplied (sync files only)." -ForegroundColor Yellow
    }

    # 4) MSP-2 / control #2: put the projected roles into the slave's DESIRED store,
    #    AFTER step 3 has provided the accounts (order matters -- a membership row
    #    whose principal does not exist yet resolves to nothing at engine-apply).
    #    The slave's engine grants them on its next run through its normal path.
    $assignApply = $null
    $defApply = $null
    if ("$SlaveStoreConnectionString".Trim()) {
        if ($null -eq $plan.projection) {
            Write-Host "[downlink] no role projection in this baseline (older master, or no assignments published) -- nothing to apply." -ForegroundColor DarkGray
        } else {
            # BUG-59: groups FIRST -- a membership whose group does not exist yet is
            # unresolvable, so applying these in the other order would sync a set of
            # assignments the engine could not act on until the following run.
            if ($null -ne $plan.definitions) {
                $defApply = Invoke-PimDownlinkDefinitionApply -ConnectionString $SlaveStoreConnectionString `
                    -DefinitionPlan $plan.definitions -AllowFullPrune:$AllowFullPrune -AllowRetraction:$AllowRetraction -WhatIfMode:$WhatIfMode
                Write-Host "[downlink] groups: $($defApply.detail)" -ForegroundColor $(if ($defApply.ok) { 'Green' } else { 'Red' })
                foreach ($d in @($plan.definitions.defer)) {
                    Write-Host "[downlink]   DEFERRED $($d.GroupTag): $($d.reason)" -ForegroundColor DarkGray
                }
            }
            $assignApply = Invoke-PimDownlinkAssignmentApply -ConnectionString $SlaveStoreConnectionString `
                -Assignments @($plan.assignments) -AllowFullPrune:$AllowFullPrune -AllowRetraction:$AllowRetraction -WhatIfMode:$WhatIfMode
            $col = if ($assignApply.ok) { 'Green' } else { 'Red' }
            Write-Host "[downlink] roles: $($assignApply.detail)" -ForegroundColor $col
            foreach ($u in @($plan.projection.unresolved)) {
                Write-Host "[downlink]   UNRESOLVED $($u.UserName) -> $($u.GroupTag): $($u.reason)" -ForegroundColor Yellow
            }
            # §71: every dependency included against its own fields is a warning, named, never silent.
            foreach ($w in @($plan.autoIncluded)) { Write-Host "[downlink]   [warn] $($w.reason)" -ForegroundColor Yellow }
            foreach ($x in @($defApply.wouldRetract) + @($assignApply.wouldRetract)) { if ("$x".Trim()) { Write-Host "[downlink]   WOULD REMOVE $x (no longer reaches this tenant; reported only -- pass -AllowRetraction)" -ForegroundColor Yellow } }
        }
    } elseif ($null -ne $plan.projection -and @($plan.assignments).Count) {
        # staged but not applied -- say so, rather than letting a projected count in
        # the plan read as "the roles are in the slave".
        Write-Host "[downlink] $(@($plan.assignments).Count) role assignment(s) projected but NOT applied: no -SlaveStoreConnectionString supplied (staged to file only)." -ForegroundColor Yellow
    }

    # SEC-24 -- RECORD THE APPLIED VERSION as this tenant's new anti-rollback floor (its OWN pim.Settings).
    # Only after a real apply into the store (not WhatIf), and only when no apply step failed: a floor raised
    # over a failed apply would mark a version as applied that is not. Monotonic + read back (Set-PimBaselineApplied).
    # 🔒 A floor that cannot be RECORDED fails the run: the next pull would otherwise still accept the older bundle
    # this one superseded, and a green run is the one nobody re-reads.
    $floorRecorded = $null
    if (-not $WhatIfMode -and $trustRead -and [int64]$plan.baselineVersion -gt 0) {
        $applyFailed = @(@($adminApply, $defApply, $assignApply) | Where-Object { $null -ne $_ -and -not [bool]$_.ok })
        if ($applyFailed.Count) {
            Write-Host "[downlink] anti-rollback floor NOT advanced: $($applyFailed.Count) apply step(s) failed, so v$($plan.baselineVersion) is not recorded as applied" -ForegroundColor Yellow
        } else {
            try {
                $floorRecorded = Set-PimBaselineApplied -ConnectionString $SlaveStoreConnectionString -Version ([int64]$plan.baselineVersion) `
                                     -SignerId "$($plan.verify.signer)" -TenantId $TenantId
                if ($floorRecorded.changed) { Write-Host "[downlink] anti-rollback floor raised v$($floorRecorded.previous) -> v$($floorRecorded.version) (pim.Settings)" -ForegroundColor DarkGray }
            } catch {
                $msg = "APPLIED, but the anti-rollback floor could NOT be recorded ($($_.Exception.Message)) -- an older signed bundle would still be accepted on the next pull"
                Write-Host "[downlink] $msg" -ForegroundColor Red
                return ([pscustomobject]@{ ok = $false; reason = $msg; plan = $plan; staged = @($staged.ToArray()); fanout = $fanout; admins = $adminApply; definitions = $defApply; assignments = $assignApply
                                           slaveRing = $SlaveRing; slaveRingSource = 'local'; trust = @{ floor = $effFloor; storeFloor = $trustFloor; revokedSigners = @($revoked).Count; read = $trustRead; centralKill = $kill; recorded = $null } })
            }
        }
    }

    # MSP-3 step 5 -- record what the two gates DECIDED, so the operator can tell a customer who
    # declined from a ring that held from a tenant that has simply stopped running. Emitted on
    # every managed run, WhatIf included (a plan is a decision too, and it is flagged as such in
    # the record). Best-effort: see Write-PimAcceptanceRecord for why this must never fail the run.
    $acceptance = New-PimAcceptanceRecord -Plan $plan -TenantId $TenantId -RingPlan $RingPlan `
        -BlockedCapabilities $BlockedCapabilities -NowUtc $NowUtc -ApplyResults @($adminApply, $defApply, $assignApply) -WhatIfMode:$WhatIfMode
    $acceptancePath = $null
    if ($plan.sync -and "$($plan.sync.tenantFolder)".Trim()) {
        $acceptancePath = Write-PimAcceptanceRecord -Record $acceptance -Folder $plan.sync.tenantFolder
    }

    # 🔴 FAIL CLOSED ON A FAILED APPLY (2026-09-18). This used to return ok=$true whatever the admin / group / role apply
    # returned, so a pull whose account apply FAILED logged "DOWNLINK APPLIED" and the scheduled job exited 0 -- a
    # red step inside a green run, the shape nobody re-reads. A run with any failed apply step is now NOT ok and says
    # which steps failed (partial = something else did apply); the caller (Invoke-PimScenarioDeploy) stops there.
    $failedSteps = New-Object System.Collections.Generic.List[string]
    foreach ($__ap in @(@('admins', $adminApply), @('groups', $defApply), @('roles', $assignApply))) {
        if ($null -ne $__ap[1] -and -not [bool]$__ap[1].ok) { $failedSteps.Add("$($__ap[0]): $($__ap[1].detail)") | Out-Null }
    }
    if ($failedSteps.Count) {
        $appliedCount = @(@($adminApply, $defApply, $assignApply) | Where-Object { $null -ne $_ -and [bool]$_.ok }).Count
        $msg = "APPLY FAILED ($($failedSteps.Count) step(s)$(if ($appliedCount) { "; PARTIAL -- $appliedCount other step(s) applied" })): $($failedSteps.ToArray() -join ' | ')"
        Write-Host "[downlink] $msg" -ForegroundColor Red
        return ([pscustomobject]@{ ok = $false; partial = [bool]$appliedCount; failedSteps = @($failedSteps.ToArray()); reason = $msg; plan = $plan; staged = @($staged.ToArray()); fanout = $fanout
                                   admins = $adminApply; definitions = $defApply; assignments = $assignApply; acceptance = $acceptance; acceptancePath = $acceptancePath
                                   slaveRing = $SlaveRing; slaveRingSource = 'local'; trust = @{ floor = $effFloor; storeFloor = $trustFloor; revokedSigners = @($revoked).Count; read = $trustRead; centralKill = $kill; recorded = $floorRecorded } })
    }

    # BUG-175: slaveRing is the LOCAL ring that gated this run (authoritative), reported back in the result.
    return ([pscustomobject]@{ ok = $true; partial = $false; failedSteps = @(); reason = $plan.reason; plan = $plan; staged = @($staged.ToArray()); fanout = $fanout; admins = $adminApply; definitions = $defApply; assignments = $assignApply; acceptance = $acceptance; acceptancePath = $acceptancePath
                               slaveRing = $SlaveRing; slaveRingSource = 'local'; trust = @{ floor = $effFloor; storeFloor = $trustFloor; revokedSigners = @($revoked).Count; read = $trustRead; centralKill = $kill; recorded = $floorRecorded } })
}

# ---------------------------------------------------------------------------
# MSP-2 / control #2 -- APPLY the projected roles into the SLAVE's desired store.
#
# The projected rows are written as ordinary PIM-Assignments-Admins desired rows,
# so the slave's engine grants them through its NORMAL delegation path (the
# AdminMembers provider makes the admin an eligible/active member of the tagged
# PIM group). There is deliberately no second grant mechanism here -- this function
# only puts desired state in the store.
#
# 🪤 WHY NOT Set-PimSqlEntityRows. That helper is a FULL-SET replace: it deletes
# every current key not in the submitted set. The slave's own local admins have
# their own rows in this same entity, so a full-set replace would delete the
# customer's entire delegation on the first sync. Rows are therefore upserted
# individually and stamped with their OWNER, and only rows carrying Owner='MSP'
# are ever pruned -- which is also fix-shape item 5: a decouple removes exactly
# what the sync added, and nothing else.
#
# 📌 OWNER IS THE PROJECT'S EXISTING PROVENANCE VOCABULARY -- do not invent another.
# `Owner` = MSP | Local is the documented split (docs/REQUIREMENTS.md s4 + s19,
# sql/platform-schema.sql; the retired local store pim.LocalAdmins was Owner='Local'
# provenance). Crucially the tag is PROVENANCE, NOT A GATE --
# "local plane fully autonomous; Owner tag = provenance not a gate" (s4) -- which is
# exactly how it is used here: it scopes what the SYNC may retract, and constrains
# the customer not at all.
#
# 🔒 EMPTY-DESIRED GUARD. An empty projection does NOT prune, mirroring the engine's
# mass-disable guard: "the master published nothing this run" and "the master
# revoked everything" look identical from here, and the safe reading is the first.
# Pass -AllowFullPrune to actually withdraw everything (the decouple path).
# Returns @{ ok; created; updated; removed; skippedForeign; wouldPrune; detail }.
# ---------------------------------------------------------------------------
function Invoke-PimDownlinkAssignmentApply {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ConnectionString,   # the SLAVE's desired store
        [object[]]$Assignments = @(),                      # $plan.assignments (already projected+filtered)
        [string]$Owner = 'MSP',
        [switch]$AllowFullPrune,
        # §71 / framework MSP-4 SURFACE item 8 -- RETRACTION IS REPORT-FIRST. A synced row that no
        # longer reaches this tenant is reported as "would remove" and is removed ONLY with this opt-in,
        # and then only inside the removal budget (PIM_RemoveMaxCount). -AllowFullPrune (the deliberate
        # decouple) still withdraws everything.
        [switch]$AllowRetraction,
        [switch]$WhatIfMode = $true
    )
    $entity = 'PIM-Assignments-Admins'
    $existing = @()
    try { $existing = @(Get-PimSqlRows -ConnectionString $ConnectionString -Entity $entity) }
    catch { return @{ ok = $false; created = 0; updated = 0; removed = 0; skippedForeign = 0; wouldPrune = @(); wouldRetract = @(); retractHeld = @(); detail = "could not read $entity from the slave store: $($_.Exception.Message)" } }

    $keyOf = { param($u, $t) "$u|$t" }
    # what the sync currently owns in this store. An UNSTAMPED row is Local by
    # default -- the customer's rows predate this feature and must never be
    # inferred into MSP ownership, because that would make them prunable.
    $ownedKeys = @{}
    foreach ($e in $existing) {
        if ("$(Get-PimDownlinkValue -Object $e -Key 'Owner')" -ne $Owner) { continue }
        $u = "$(Get-PimDownlinkValue -Object $e -Key 'Username')"; if (-not $u) { $u = "$(Get-PimDownlinkValue -Object $e -Key 'UserName')" }
        $ownedKeys[(& $keyOf $u "$(Get-PimDownlinkValue -Object $e -Key 'GroupTag')")] = $true
    }
    $foreign = @($existing).Count - $ownedKeys.Count

    $created = 0; $updated = 0; $desiredKeys = @{}
    foreach ($a in @($Assignments)) {
        $u = "$(Get-PimDownlinkValue -Object $a -Key 'UserName')"; if (-not $u) { $u = "$(Get-PimDownlinkValue -Object $a -Key 'Username')" }
        $tag = "$(Get-PimDownlinkValue -Object $a -Key 'GroupTag')"
        if (-not "$u".Trim() -or -not "$tag".Trim()) { continue }
        $k = & $keyOf $u $tag
        $desiredKeys[$k] = $true
        # 'Username' (lower n) is the natural-key property Get-PimStoreRowKey reads for
        # this entity; writing 'UserName' would derive a BLANK key and drop the row.
        # The value is the BARE central login name on purpose: Resolve-PimPrincipalId
        # has a documented master->slave fallback that resolves a no-'@' value as
        # <UserName>@<slave default domain>, which is where the fan-out created it.
        $row = [ordered]@{
            Username            = "$u"
            GroupTag            = "$tag"
            AssignmentType      = $(if ("$(Get-PimDownlinkValue -Object $a -Key 'AssignmentType')".Trim()) { "$(Get-PimDownlinkValue -Object $a -Key 'AssignmentType')" } else { 'Eligible' })
            Action              = 'Assign'
            Permanent           = "$(Get-PimDownlinkValue -Object $a -Key 'Permanent')"
            NumOfDaysWhenExpire = "$(Get-PimDownlinkValue -Object $a -Key 'NumOfDaysWhenExpire')"
            AutoExtend          = "$(Get-PimDownlinkValue -Object $a -Key 'AutoExtend')"
            Owner               = $Owner
        }
        if ($ownedKeys.ContainsKey($k)) { $updated++ } else { $created++ }
        if (-not $WhatIfMode) { Set-PimSqlRow -ConnectionString $ConnectionString -Entity $entity -Key $k -Data $row }
    }

    # only what THIS sync previously added and no longer projects is ever a candidate
    $stale = @($ownedKeys.Keys | Where-Object { -not $desiredKeys.ContainsKey($_) } | Sort-Object)
    $removed = 0; $wouldPrune = @(); $wouldRetract = @(); $retractHeld = @()
    $budget = Get-PimDownlinkRetractionBudget
    if ($stale.Count) {
        if (@($Assignments).Count -eq 0 -and -not $AllowFullPrune) {
            $wouldPrune = $stale
        } elseif (-not $AllowFullPrune -and -not $AllowRetraction) {
            $wouldRetract = $stale
        } elseif (-not $AllowFullPrune -and $stale.Count -gt $budget) {
            $retractHeld = $stale
        } else {
            foreach ($k in $stale) {
                if (-not $WhatIfMode) { Remove-PimSqlRow -ConnectionString $ConnectionString -Entity $entity -Key $k }
                $removed++
            }
        }
    }
    # ${entity} braces are required: "$entity:" parses '$entity:' as a SCOPE qualifier.
    $detail = "${entity}: +$created ~$updated -$removed (left $foreign local row(s) untouched)"
    if ($wouldPrune.Count) { $detail += "; REFUSED to prune $($wouldPrune.Count) synced row(s) because the projection was EMPTY -- pass -AllowFullPrune to withdraw them" }
    if ($wouldRetract.Count) { $detail += "; WOULD REMOVE $($wouldRetract.Count) synced row(s) that no longer reach this tenant -- reported only (retraction needs the removal opt-in)" }
    if ($retractHeld.Count) { $detail += "; HELD: $($retractHeld.Count) retraction(s) exceed the removal budget of $budget -- NOTHING withdrawn" }
    if ($WhatIfMode) { $detail = "[whatif] $detail" }
    return @{ ok = $true; created = $created; updated = $updated; removed = $removed; skippedForeign = $foreign; wouldPrune = $wouldPrune; wouldRetract = $wouldRetract; retractHeld = $retractHeld; retractionBudget = $budget; detail = $detail }
}

# ---------------------------------------------------------------------------
# BUG-59 -- APPLY the group DEFINITIONS the projection needs into the slave's store.
#
# Same discipline as the membership apply: upsert by the entity's natural key, stamp
# Owner='MSP', and prune ONLY Owner='MSP' rows. A customer group that already carries
# the tag never reaches here -- Select-PimProjectedDefinitions defers it -- so this
# function only ever writes groups the tenant did not have.
#
# ⚠️ ORDER MATTERS AND IS NOT COSMETIC. Definitions must land BEFORE the memberships
# that reference them (a membership whose group does not exist is unresolvable), and
# the groups themselves before their nestings/bindings. The engine's own commit order
# encodes the same rule -- Get-PimEntityOrderRank puts *definitions* ahead of
# *assignments* -- so this mirrors it rather than inventing a second ordering.
# Returns @{ ok; created; updated; removed; skippedForeign; detail } summed over the
# three entities.
# ---------------------------------------------------------------------------
function Invoke-PimDownlinkDefinitionApply {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ConnectionString,
        [Parameter(Mandatory)][hashtable]$DefinitionPlan,   # Select-PimProjectedDefinitions result
        [string]$Owner = 'MSP',
        [switch]$AllowFullPrune,
        # §71 / framework MSP-4 SURFACE item 8 -- retraction is REPORT-FIRST (see the membership apply).
        [switch]$AllowRetraction,
        [switch]$WhatIfMode = $true
    )
    # entity -> (rows, natural-key property list). Mirrors Get-PimStoreRowKey exactly;
    # a key derived differently here would orphan every row it wrote.
    #
    # 🪤 BUG-60 -- A GROUP MUST LAND IN AN ENTITY THE ENGINE ACTUALLY READS. This wrote every
    # group to 'PIM-Definitions', and NO provider reads that entity: the Groups provider builds
    # its desired set from PIM-Definitions-Roles / -Services / -Organization / -Tasks
    # (Get-PimGroupDefinitionRows) and Get-PimDesiredRows matches the name EXACTLY.
    # ('PIM-Definitions' is only the change-QUEUE label the provider stamps on its diffs.) So the
    # synced groups sat in the slave's store, correct and complete, and its engine never saw them
    # -- the projected memberships then failed as unresolvable. Each group now goes back into the
    # entity it came from on the master (carried as SourceEntity in the signed bundle).
    $groupsByEntity = @{}
    foreach ($g in @($DefinitionPlan.create)) {
        $e = "$(Get-PimDownlinkValue -Object $g -Key 'SourceEntity')".Trim()
        # An older bundle carries no SourceEntity. Services is the right default: it is the
        # entity the permission groups live in, and it is where the discovery/import paths
        # already write. A wrong-but-read entity beats a right-but-invisible one.
        if (-not $e -or $e -eq 'PIM-Definitions') { $e = 'PIM-Definitions-Services' }
        if (-not $groupsByEntity.ContainsKey($e)) { $groupsByEntity[$e] = New-Object System.Collections.Generic.List[object] }
        $groupsByEntity[$e].Add($g) | Out-Null
    }
    # Prune has to look in EVERY definition entity we could ever have written -- including the
    # legacy 'PIM-Definitions' -- or a group this sync placed before the fix would become
    # unreachable garbage that nothing withdraws.
    # §71.7 (a): Departments / Processes / Projects / CrossOrg groups now travel too, so they are
    # written back to (and pruned from) their own entities like the other four.
    $defEntities = @('PIM-Definitions-Roles','PIM-Definitions-Services','PIM-Definitions-Organization','PIM-Definitions-Tasks',
                     'PIM-Definitions-Departments','PIM-Definitions-Processes','PIM-Definitions-Projects','PIM-Definitions-CrossOrg','PIM-Definitions')
    $work = @()
    foreach ($e in $defEntities) {
        $rows = if ($groupsByEntity.ContainsKey($e)) { @($groupsByEntity[$e].ToArray()) } else { @() }
        # Departments is keyed the store's way (Department first -- Get-PimStoreRowKey), and it is ALSO
        # the customer's department/owner store, so a row there that is not ours is NEVER taken over:
        # an MSP DEPT- group sponsored by 'IT' must not overwrite the customer's own 'IT' owner row.
        $isDept = ($e -eq 'PIM-Definitions-Departments')
        $work += @{ Entity = $e; Rows = $rows; Keys = @('GroupTag'); IsGroupClass = $true; UseStoreKey = $isDept; NeverTakeOver = $isDept }
    }
    $work += @{ Entity = 'PIM-Assignments-Groups';       Rows = @($DefinitionPlan.nestings);     Keys = @('TargetGroupTag', 'SourceGroupTag') }
    $work += @{ Entity = 'PIM-Assignments-Roles-Groups'; Rows = @($DefinitionPlan.roleBindings); Keys = @('GroupTag', 'RoleDefinitionName') }
    # §71: tenant-scoped resource bindings + the AU definitions they need. Only ever non-empty when the
    # master EXPLICITLY replicated them; a customer row carrying the same key is never taken over.
    $resByEntity = @{ 'PIM-Assignments-Roles-AUs' = @(); 'PIM-Assignments-Azure-Resources' = @(); 'PIM-Assignments-Workloads' = @() }
    foreach ($rb in @($DefinitionPlan.resourceBindings)) {
        $e = "$(Get-PimDownlinkValue -Object $rb -Key 'Entity')".Trim()
        if ($resByEntity.ContainsKey($e)) { $resByEntity[$e] = @($resByEntity[$e]) + @($rb) }
    }
    $work += @{ Entity = 'PIM-Assignments-Roles-AUs';       Rows = @($resByEntity['PIM-Assignments-Roles-AUs']);       Keys = @('GroupTag', 'AdministrativeUnitTag', 'RoleDefinitionName'); NeverTakeOver = $true }
    $work += @{ Entity = 'PIM-Assignments-Azure-Resources'; Rows = @($resByEntity['PIM-Assignments-Azure-Resources']); Keys = @('GroupTag', 'AzScope', 'AzScopePermission'); NeverTakeOver = $true }
    $work += @{ Entity = 'PIM-Assignments-Workloads';       Rows = @($resByEntity['PIM-Assignments-Workloads']);       Keys = @('GroupTag'); NeverTakeOver = $true }
    $work += @{ Entity = 'PIM-Definitions-AU';              Rows = @($DefinitionPlan.aus);                             Keys = @('AdministrativeUnitTag'); NeverTakeOver = $true }

    $created = 0; $updated = 0; $removed = 0; $foreign = 0; $parts = @(); $takeOverRefused = 0
    $wouldPrune = New-Object System.Collections.Generic.List[string]
    $stalePending = New-Object System.Collections.Generic.List[object]   # @{ Entity; Key } -- decided after every entity is read
    foreach ($w in $work) {
        $entity = "$($w.Entity)"
        $existing = @()
        try { $existing = @(Get-PimSqlRows -ConnectionString $ConnectionString -Entity $entity) }
        catch { return @{ ok = $false; created = $created; updated = $updated; removed = $removed; skippedForeign = $foreign; wouldPrune = @(); wouldRetract = @(); retractHeld = @(); detail = "could not read $entity from the slave store: $($_.Exception.Message)" } }

        $keyFor = {
            param($row)
            if ($w.UseStoreKey -and (Get-Command Get-PimStoreRowKey -ErrorAction SilentlyContinue)) { return "$(Get-PimStoreRowKey -Base $w.Entity -Row $row)" }
            $vals = @($w.Keys | ForEach-Object { "$(Get-PimDownlinkValue -Object $row -Key $_)" })
            ($vals -join '|')
        }
        $ownedKeys = @{}
        $foreignKeys = @{}
        foreach ($e in $existing) {
            $k = & $keyFor $e
            if ("$(Get-PimDownlinkValue -Object $e -Key 'Owner')" -ne $Owner) {
                if ("$k".Trim() -and "$k" -notmatch '^\|+$') { $foreignKeys[$k.ToLowerInvariant()] = $true }
                continue
            }
            # 🪤 A row that derives a BLANK key ('' or just separators) is one this entity
            # cannot address -- Get-PimStoreRowKey returns '' for exactly these, and the
            # write path below already skips them. The prune path must skip them too, or a
            # row belonging to a DIFFERENT entity (or a malformed one) is counted as ours
            # and offered up for deletion under a key that addresses nothing.
            if (-not "$k".Trim() -or "$k" -match '^\|+$') { continue }
            $ownedKeys[$k] = $true
        }
        $foreign += (@($existing).Count - $ownedKeys.Count)

        $desired = @{}
        $wrote = 0
        foreach ($r in @($w.Rows)) {
            $k = & $keyFor $r
            if (-not "$k".Trim() -or "$k" -match '^\|+$') { continue }
            $desired[$k] = $true
            if ($w.NeverTakeOver -and $foreignKeys.ContainsKey($k.ToLowerInvariant())) { $takeOverRefused++; continue }
            # rebuild as a plain ordered row + the Owner stamp; the bundle rows are
            # PSCustomObjects from JSON and must not be written back verbatim.
            $row = [ordered]@{}
            $props = if ($r -is [System.Collections.IDictionary]) { @($r.Keys | ForEach-Object { [pscustomobject]@{ Name = "$_"; Value = $r[$_] } }) } else { @($r.PSObject.Properties) }
            foreach ($p in $props) {
                # SourceEntity / Entity are ROUTING for this function, not columns of the row, and the
                # §71 fields are the MASTER's authoring decision -- meaningless inside a managed tenant,
                # whose own GUI neither shows nor accepts them.
                if ($p.Name -in @('SourceEntity', 'Entity', 'Replicate', 'Ring', 'Target')) { continue }
                $row[$p.Name] = "$($p.Value)"
            }
            $row['Owner'] = $Owner
            if (-not $row.Contains('Action') -and ($w.IsGroupClass -or -not $w.NeverTakeOver)) { $row['Action'] = 'Assign' }
            if ($ownedKeys.ContainsKey($k)) { $updated++ } else { $created++ }
            $wrote++
            if (-not $WhatIfMode) { Set-PimSqlRow -ConnectionString $ConnectionString -Entity $entity -Key $k -Data $row }
        }
        $stale = @($ownedKeys.Keys | Where-Object { -not $desired.ContainsKey($_) } | Sort-Object)
        if ($stale.Count) {
            # The mass-revoke guard asks "did the master publish NOTHING of this KIND",
            # never "nothing in this one entity". Groups are spread over several definition
            # entities, so a per-entity test would refuse forever to clean up an entity the
            # groups have legitimately MOVED OUT OF (e.g. off the legacy 'PIM-Definitions'
            # after BUG-60) -- leaving the same tag defined twice.
            $classEmpty = if ($w.IsGroupClass) { @($DefinitionPlan.create).Count -eq 0 } else { @($w.Rows).Count -eq 0 }
            if ($classEmpty -and -not $AllowFullPrune) {
                # Same mass-revoke guard as the other two applies -- and it must SAY SO.
                # It used to skip silently, so "the master published no groups this run"
                # and "nothing needed removing" produced identical output. Reporting a
                # refusal is the whole point of having one.
                foreach ($k in $stale) { $wouldPrune.Add("$entity|$k") | Out-Null }
            } else {
                foreach ($k in $stale) { $stalePending.Add(@{ Entity = $entity; Key = $k }) | Out-Null }
            }
        }
        # Only report an entity that took part -- five empty group buckets in the detail line
        # would bury the one that did something.
        if (@($w.Rows).Count -or $stale.Count) { $parts += ("{0}:+{1}" -f $entity.Replace('PIM-', ''), $wrote) }
    }
    # §71 -- RETRACTION, decided ONCE over every entity: report-first, opt-in, inside the budget.
    $wouldRetract = @(); $retractHeld = @()
    $budget = Get-PimDownlinkRetractionBudget
    $staleArr = @($stalePending.ToArray())
    if ($staleArr.Count) {
        $labels = @($staleArr | ForEach-Object { "$($_.Entity)|$($_.Key)" })
        if (-not $AllowFullPrune -and -not $AllowRetraction) { $wouldRetract = $labels }
        elseif (-not $AllowFullPrune -and $staleArr.Count -gt $budget) { $retractHeld = $labels }
        else {
            foreach ($s in $staleArr) {
                if (-not $WhatIfMode) { Remove-PimSqlRow -ConnectionString $ConnectionString -Entity $s.Entity -Key $s.Key }
                $removed++
            }
        }
    }
    $detail = "definitions +$created ~$updated -$removed ($($parts -join ' ')); left $foreign customer-owned row(s) untouched"
    if ($takeOverRefused) { $detail += "; $takeOverRefused row(s) NOT written -- the customer already has a row with that key" }
    if ($wouldPrune.Count) { $detail += "; REFUSED to prune $($wouldPrune.Count) synced row(s) because the master published none -- pass -AllowFullPrune to withdraw them" }
    if ($wouldRetract.Count) { $detail += "; WOULD REMOVE $($wouldRetract.Count) synced row(s) that no longer reach this tenant -- reported only (retraction needs the removal opt-in)" }
    if ($retractHeld.Count) { $detail += "; HELD: $($retractHeld.Count) retraction(s) exceed the removal budget of $budget -- NOTHING withdrawn" }
    if ($WhatIfMode) { $detail = "[whatif] $detail" }
    return @{ ok = $true; created = $created; updated = $updated; removed = $removed; skippedForeign = $foreign; wouldPrune = @($wouldPrune.ToArray()); wouldRetract = $wouldRetract; retractHeld = $retractHeld; retractionBudget = $budget; takeOverRefused = $takeOverRefused; detail = $detail }
}

function Get-PimDownlinkRetractionBudget {
    # §71 -- the removal budget a downlink retraction runs under: the engine's own G4 budget when it is
    # loaded (hard ceiling 5), else the same knob read directly, else 5. Never above the engine's.
    if (Get-Command Get-PimRemoveBudget -ErrorAction SilentlyContinue) { try { return [int](Get-PimRemoveBudget) } catch { } }
    $budget = 5
    if (Get-Command Get-PimSafetyKnob -ErrorAction SilentlyContinue) {
        $kb = 0; if ([int]::TryParse("$(Get-PimSafetyKnob -Name 'PIM_RemoveMaxCount')", [ref]$kb) -and $kb -ge 0 -and $kb -le 5) { $budget = $kb }
    }
    return $budget
}

# ---------------------------------------------------------------------------
# CONTROL #1 on the S6 (pull) path -- stage the baseline ADMINS as desired rows in
# the slave's own store, so the SLAVE's engine creates them.
#
# WHY THIS EXISTS ALONGSIDE Invoke-PimMspFanout. The fan-out PUSHES: it authenticates
# per-tenant with a certificate from Cert:\LocalMachine\My and writes the accounts to
# Graph itself. That works for a central MSP host holding every customer's cert -- but
# it is S5-shaped, and IMP-11 records that S5's cross-tenant reach is not currently
# available. On the S6 path the downlink already runs INSIDE the managed tenant, whose
# own engine has the identity and the tick schedule to create accounts. Handing it
# desired rows is therefore both simpler and more faithful to pull-not-push: the master
# never writes into the customer, and the customer's engine does exactly what it does
# for its own local admins.
#
# Row shape mirrors Invoke-PimMspFanout's exactly (the established contract). UPN is rebuilt
# per slave (<UserName>@<default domain>), which is what makes origin legible in the name and a
# later decouple able to find precisely these. Owner='MSP' scopes the prune, exactly as the
# other two applies.
#
# 🔑 CreateTAP IS ON BY DEFAULT (operator decision, 2026-08-13). This used to be hardcoded
# 'FALSE' here and in the fan-out, reasoning that a sync must not silently mint a credential in
# a customer tenant. Measured against a real managed tenant, that reasoning inverted: the six
# synced accounts existed, were enabled, held their delegation -- and NOBODY COULD SIGN IN AS
# THEM, because the only credential path an engine-created admin has is the TAP it mints on
# creation. The MSP was left administering a customer it had no key to. Withholding the
# credential did not make the privilege smaller; it only made it unusable while remaining fully
# granted. The intent now travels from the master's registry (pim.CentralAdmins.CreateTap,
# default 1) and this apply defaults ON when the bundle predates those columns.
# 🪤 A TAP still needs somewhere to go, and 71.19 fixed WHERE: the admin's SPONSOR DEPARTMENT's owners. The synced row
# therefore carries its Department, and the bundle carries that department's row (auto-included as a dependency), so the
# slave resolves the recipient exactly as the master does. Nothing here can compensate for a slave that cannot send mail
# at all -- that is the sender-mailbox half of the same gap.
# ---------------------------------------------------------------------------
function Get-PimSlaveAdminUpnDomain {
    # REQ-T: the managed tenant's OWN "Admin account domain" -- the naming key AdminAccountUpnSuffix in ITS store's
    # pim.Settings['NamingConventions'] (a key stored as its own row wins). '' when unset or unreadable: the caller
    # falls back to the default domain, it never guesses one. PURE apart from the one settings read.
    param([string]$ConnectionString)
    if (-not "$ConnectionString".Trim() -or -not (Get-Command Get-PimSqlSetting -ErrorAction SilentlyContinue)) { return '' }
    $v = ''
    try {
        $own = Get-PimSqlSetting -ConnectionString $ConnectionString -Name 'AdminAccountUpnSuffix'
        if ($own -is [string]) { $v = $own }
        if (-not "$v".Trim()) {
            $nc = Get-PimSqlSetting -ConnectionString $ConnectionString -Name 'NamingConventions'
            if ($nc -is [string]) { try { $nc = $nc | ConvertFrom-Json } catch { $nc = $null } }
            if ($nc) { $v = if ($nc -is [System.Collections.IDictionary]) { "$($nc['AdminAccountUpnSuffix'])" } else { "$($nc.AdminAccountUpnSuffix)" } }
        }
    } catch { return '' }
    return "$v".Trim().TrimStart('@')
}

function Invoke-PimDownlinkAdminApply {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ConnectionString,
        [object[]]$Admins = @(),                       # $plan.admins (ring-filtered baseline rows)
        [Parameter(Mandatory)][string]$DefaultDomain,  # the SLAVE's default domain
        [string]$Owner = 'MSP',
        # 71.17 -- TAP IS ON FOR ALL (operator 2026-09-15 "tap is on for all"). -CreateTapDefault is kept so existing
        # callers still bind, and has NO effect: every synced (Entra) admin row is stored CreateTAP=TRUE. A 'FALSE' is
        # reported, never honoured.
        [string]$CreateTapDefault = 'TRUE',
        [int]$TapLifetimeHoursDefault = 8,
        [switch]$AllowFullPrune,
        # §71 / framework MSP-4 SURFACE item 8 -- retraction is REPORT-FIRST for admins too (§71.11, found LIVE
        # on RIDE 2026-09-15): an admin that stops reaching this tenant is reported as 'would remove' and its
        # central row withdrawn only with this opt-in, inside the removal budget. -AllowFullPrune still wins.
        [switch]$AllowRetraction,
        [switch]$WhatIfMode = $true
    )
    # 🔑 REQUIREMENTS 68.6 row 35 (operator 2026-09-13): "slaves ... have their own admins.
    # separate table." Central admins imported from the master live in their OWN entity; the
    # slave's Account-Definitions-Admins holds only the slave's own admins. The engine reads both
    # (Get-PimDesiredRows unions them, central rows stamped AdminSource=central) and governs each
    # by its SOURCE. Keep this name identical to PIM-EngineCore.ps1 Get-PimCentralAdminEntityName.
    $localEntity = 'Account-Definitions-Admins'
    $entity = 'Account-Definitions-Admins-Central'
    $existing = @()
    $localRows = @()
    try { $existing = @(Get-PimSqlRows -ConnectionString $ConnectionString -Entity $entity) }
    catch { return @{ ok = $false; created = 0; updated = 0; removed = 0; skippedForeign = 0; detail = "could not read $entity from the slave store: $($_.Exception.Message)" } }
    try { $localRows = @(Get-PimSqlRows -ConnectionString $ConnectionString -Entity $localEntity) }
    catch { return @{ ok = $false; created = 0; updated = 0; removed = 0; skippedForeign = 0; detail = "could not read $localEntity from the slave store: $($_.Exception.Message)" } }

    # ONE-TIME MIGRATION: before this change the sync wrote central admins INTO the slave's own
    # entity, stamped Owner=$Owner. Move exactly those (copy first, then remove -- a failure in
    # between leaves a duplicate, never a lost admin). Unstamped / Local rows stay where they are.
    $migrated = 0
    $existingKeys = @{}
    foreach ($e in $existing) { $existingKeys["$(Get-PimDownlinkValue -Object $e -Key 'UserName')"] = $true }
    $mig = New-Object System.Collections.Generic.List[object]
    foreach ($lr in $localRows) {
        if ("$(Get-PimDownlinkValue -Object $lr -Key 'Owner')" -ne $Owner) { continue }
        $mk = "$(Get-PimDownlinkValue -Object $lr -Key 'UserName')"
        if (-not $mk) { continue }
        if (-not $WhatIfMode) {
            if (-not $existingKeys.ContainsKey($mk)) { Set-PimSqlRow -ConnectionString $ConnectionString -Entity $entity -Key $mk -Data $lr }
            Remove-PimSqlRow -ConnectionString $ConnectionString -Entity $localEntity -Key $mk
        }
        if (-not $existingKeys.ContainsKey($mk)) { $mig.Add($lr) | Out-Null; $existingKeys[$mk] = $true }
        $migrated++
    }
    $existing = @($existing) + @($mig.ToArray())

    $ownedKeys = @{}
    foreach ($e in $existing) {
        if ("$(Get-PimDownlinkValue -Object $e -Key 'Owner')" -ne $Owner) { continue }
        $ownedKeys["$(Get-PimDownlinkValue -Object $e -Key 'UserName')"] = $true
    }
    # the slave's OWN admins: everything in its own entity that this sync did not plant
    $foreign = @($localRows | Where-Object { "$(Get-PimDownlinkValue -Object $_ -Key 'Owner')" -ne $Owner }).Count

    $created = 0; $updated = 0; $desired = @{}; $tapOn = 0; $tapNoRecipient = 0; $tapIgnored = 0
    foreach ($a in @($Admins)) {
        $un = "$(Get-PimDownlinkValue -Object $a -Key 'UserName')".Trim()
        if (-not $un) { continue }
        $desired[$un] = $true

        # --- 71.17 TAP IS ON FOR ALL. A synced admin is always an Entra admin (TargetPlatform=ID below), and every Entra
        # admin gets a TAP -- the bundle's CreateTap (an older bundle, or a registry row) and -CreateTapDefault are NOT
        # honoured. 2.4.362 briefly carried a master's CreateTAP=FALSE to the slave (71.15); stored there it silenced the
        # "TAP on but nowhere to deliver it" warning while the engine still (correctly) planned the TAP.
        $tapRaw = "$(Get-PimDownlinkValue -Object $a -Key 'CreateTap')".Trim()
        if (-not $tapRaw) { $tapRaw = "$(Get-PimDownlinkValue -Object $a -Key 'CreateTAP')".Trim() }
        if (($tapRaw -and $tapRaw -notmatch '(?i)^(true|1|yes)$') -or "$CreateTapDefault" -notmatch '(?i)^(true|1|yes)$') { $tapIgnored++ }
        $createTap = 'TRUE'

        $lifeRaw = "$(Get-PimDownlinkValue -Object $a -Key 'TapLifetimeHours')".Trim()
        if (-not $lifeRaw) { $lifeRaw = "$(Get-PimDownlinkValue -Object $a -Key 'TAPLifetimeHours')".Trim() }
        $life = 0; [void][int]::TryParse($lifeRaw, [ref]$life)
        if ($life -le 0) { $life = $TapLifetimeHoursDefault }

        # 71.19: the recipient is resolved IN THE SLAVE from the admin's sponsor department (the bundle carries both the
        # admin's Department and that department's row). ManagerEmail travels only as legacy data. The count below reports
        # the rows that would have NO recipient at all -- neither a department nor the legacy address.
        $mgr = "$(Get-PimDownlinkValue -Object $a -Key 'ManagerEmail')".Trim()
        $dept = "$(Get-PimDownlinkValue -Object $a -Key 'Department')".Trim()
        if ($createTap -eq 'TRUE') { $tapOn++; if (-not $mgr -and -not $dept) { $tapNoRecipient++ } }

        $row = [ordered]@{
            FirstName             = "$(Get-PimDownlinkValue -Object $a -Key 'FirstName')"
            LastName              = "$(Get-PimDownlinkValue -Object $a -Key 'LastName')"
            Initials              = "$(Get-PimDownlinkValue -Object $a -Key 'Initials')"
            Purpose               = "$(Get-PimDownlinkValue -Object $a -Key 'Purpose')"
            TargetUsage           = 'Cloud'
            TargetPlatform        = 'ID'
            UserType              = 'External'
            UserName              = $un
            DisplayName           = "$(Get-PimDownlinkValue -Object $a -Key 'DisplayName')"
            UserPrincipalName     = "$un@$DefaultDomain"
            UsageLocation         = "$(Get-PimDownlinkValue -Object $a -Key 'UsageLocation')"
            Company               = ''
            # 71.19: the SPONSOR DEPARTMENT is what decides this admin's mail/TAP recipient in THIS tenant -- the
            # department's row (with its Owners) arrives in the same bundle.
            Department            = $dept
            Notes                 = "MSP downlink (central admin ring $(Get-PimDownlinkValue -Object $a -Key 'Ring'))"
            ManagerEmail          = $mgr
            StartDate             = ''
            # 71.15: the master's lifecycle values win; absent = the previous defaults (Now / no TAP start / no delete).
            ProvisionDate         = $(if (ConvertTo-PimDownlinkLifecycleText (Get-PimDownlinkValue -Object $a -Key 'ProvisionDate')) { ConvertTo-PimDownlinkLifecycleText (Get-PimDownlinkValue -Object $a -Key 'ProvisionDate') } else { 'Now' })
            CreateTAP             = $createTap
            TAPStartDate          = ConvertTo-PimDownlinkLifecycleText (Get-PimDownlinkValue -Object $a -Key 'TAPStartDate')
            TAPLifetimeHours      = "$life"
            # Governance follows the SOURCE (row 35): the master's status and offboarding decision
            # flow down with the row. A bundle that predates these fields means Enabled / none.
            # 🔴 71.20 -- THE MASTER'S STATUS, VERBATIM, INCLUDING BLANK. This defaulted to 'Enabled', and an explicit
            # 'Enabled' is the ONE value that RE-ENABLES a disabled account (Get-PimAdminStatusDecision) -- so a master
            # that simply left the column blank re-enabled an account the customer had disabled, on the next pull.
            # Blank now stays blank: the slave then leaves the live account exactly as it is.
            AccountStatus         = "$(Get-PimDownlinkValue -Object $a -Key 'AccountStatus')".Trim()
            StatusChangeCode      = ''
            Ring                  = "$(Get-PimDownlinkValue -Object $a -Key 'Ring')"
            Target                = "$(Get-PimDownlinkValue -Object $a -Key 'Target')".Trim()
            ManagementMode        = 'msp'
            AdminSource           = 'central'
            Template              = "$(Get-PimDownlinkValue -Object $a -Key 'Template')"
            # 71.23: written under the NEW name only -- never both, so the slave row cannot conflict.
            AutoDisableDate       = ConvertTo-PimDownlinkLifecycleText (Get-PimAdminAutoDisableDate -Row $a).raw
            # 71.21: no DeleteAfterDays column at all -- PIM never deletes an account and the field is
            # not supported, so a central row cannot carry anything that reads like "this slave deletes it".
            Owner                 = $Owner
        }
        if ($ownedKeys.ContainsKey($un)) { $updated++ } else { $created++ }
        if (-not $WhatIfMode) { Set-PimSqlRow -ConnectionString $ConnectionString -Entity $entity -Key $un -Data $row }
    }

    # same empty-desired guard as the membership apply: "published nothing" and
    # "withdrew everyone" are indistinguishable here, and the safe reading is the first.
    $stale = @($ownedKeys.Keys | Where-Object { -not $desired.ContainsKey($_) } | Sort-Object)
    $removed = 0; $wouldPrune = @(); $retractHeld = @(); $wouldRetract = @()
    # Row 35: an admin the master stops marking msp (or narrows away) is a cross-tenant retraction.
    # 🔴 §71.11 -- IT USED TO BE WITHDRAWN AT ONCE (inside the budget), while the group and membership applies
    # beside it were already report-first. Measured on RIDE 2026-09-15: re-targeting one SAMPLE admin away
    # from the tenant removed its central row on the next pull while its membership stayed "WOULD REMOVE".
    # Framework MSP-4 SURFACE item 8 is one rule for every row: reported, and removed only under the removal
    # opt-in (-AllowRetraction) + the budget (PIM_RemoveMaxCount, default 5), or the decouple (-AllowFullPrune).
    $budget = 5
    if (Get-Command Get-PimSafetyKnob -ErrorAction SilentlyContinue) {
        $kb = 0; if ([int]::TryParse("$(Get-PimSafetyKnob -Name 'PIM_RemoveMaxCount')", [ref]$kb) -and $kb -ge 0) { $budget = $kb }
    }
    if ($stale.Count) {
        if (@($Admins).Count -eq 0 -and -not $AllowFullPrune) { $wouldPrune = $stale }
        elseif (-not $AllowFullPrune -and -not $AllowRetraction) { $wouldRetract = $stale }
        elseif ($stale.Count -gt $budget -and -not $AllowFullPrune) { $retractHeld = $stale }
        else {
            foreach ($k in $stale) {
                if (-not $WhatIfMode) { Remove-PimSqlRow -ConnectionString $ConnectionString -Entity $entity -Key $k }
                $removed++
            }
        }
    }
    $detail = "${entity}: +$created ~$updated -$removed (left $foreign of the slave's own admin row(s) untouched); TAP on for $tapOn"
    if ($migrated) { $detail += "; MIGRATED $migrated central admin row(s) out of $localEntity into $entity (one-time)" }
    if ($wouldRetract.Count) { $detail += "; WOULD REMOVE $($wouldRetract.Count) central admin(s) that no longer reach this tenant -- reported only (retraction needs the removal opt-in, -AllowRetraction)" }
    if ($retractHeld.Count) { $detail += "; HELD: would withdraw $($retractHeld.Count) central admin(s), over the retraction budget of $budget -- NOTHING withdrawn (check the master's ManagementMode / Ring / Target, then re-run with -AllowFullPrune or raise PIM_RemoveMaxCount)" }
    # Surfaced, never swallowed: a TAP with no recipient is minted, mailed nowhere, and the code
    # is unrecoverable afterwards. That must read as a WARNING in the sync output, not as success.
    if ($tapNoRecipient) { $detail += "; WARNING $tapNoRecipient admin(s) get a TAP (enforced for every admin) but name NO sponsor department (and carry no legacy ManagerEmail) -- the engine REFUSES to issue a TAP it cannot deliver, so they cannot sign in: set the admin's Department at the master and give that department Owners" }
    if ($tapIgnored) { $detail += "; NOTE CreateTAP=FALSE on $tapIgnored admin(s) was IGNORED -- a TAP is enforced for every Entra admin" }
    if ($wouldPrune.Count) { $detail += "; REFUSED to prune $($wouldPrune.Count) synced admin(s) on an EMPTY baseline -- pass -AllowFullPrune" }
    if ($WhatIfMode) { $detail = "[whatif] $detail" }
    return @{ ok = $true; created = $created; updated = $updated; removed = $removed; skippedForeign = $foreign; wouldPrune = $wouldPrune; wouldRetract = @($wouldRetract | ForEach-Object { "$entity|$_" }); retractHeld = $retractHeld; retractionBudget = $budget; migrated = $migrated; entity = $entity; tapEnabled = $tapOn; tapWithoutRecipient = $tapNoRecipient; tapFalseIgnored = $tapIgnored; detail = $detail }
}

# Sync-PimMasterToSlave -- alias-style entry the matrix also probes for. Thin
# pass-through to Invoke-PimManagedDownlink (one orchestrator, two recognised names).
function Sync-PimMasterToSlave {
    [CmdletBinding()] param(
        [Parameter(Mandatory)][object]$Scenario,
        [Parameter(Mandatory)][object]$Doc,
        [object]$PublicKey,
        [object[]]$BaselineAdmins,
        [Parameter(Mandatory)][string]$TenantId,
        [Parameter(Mandatory)][int]$SlaveRing,
        [string]$CentralRoot = $env:PIM_SyncRootCentral,
        [string]$LocalRoot   = $env:PIM_SyncRootLocal,
        [string]$SqlServer, [string]$SqlDatabase,
        [datetime]$NowUtc = ([datetime]::UtcNow),
        [int64]$LastVersion = 0,
        # MSP-2 / control #2 -- declared here too, or @PSBoundParameters could never
        # carry them through this entry point (PowerShell binds only declared names).
        [object]$RingPlan,
        [object[]]$BaselineAssignments,
        [object[]]$ProjectionPolicy = @(),
        [string[]]$SlaveGroupTags,
        [string]$SlaveStoreConnectionString,
        # SEC-10: declared here for the reason stated directly above -- PowerShell binds only
        # DECLARED names, so leaving it out would make this entry point silently drop the
        # customer's veto while appearing to forward everything. That is the same class of
        # miss that left the gate unreachable in the first place.
        [string[]]$BlockedCapabilities,
        # IMP-13: the SLAVE's own admin naming prefixes. DECLARED here as well as on the plan,
        # because PowerShell binds only declared names -- a gate the orchestrator cannot accept is
        # a gate no entry point can reach, which is this file's most expensive recurring defect
        # (BUG-29, SEC-10b, BUG-78, BUG-79). Same inert-when-absent rule as the two gates above.
        [string[]]$SlaveAdminPrefixes,
        # IMP-12: the managed tenant's default verified domain, used to build each synced
        # admin's UPN on the S6 pull path. Omitted => resolved from the ambient tenant when
        # we are running inside it; never guessed.
        [string]$SlaveDefaultDomain,
        [switch]$AllowFullPrune,
        # §71: declared, or @PSBoundParameters could never carry the retraction opt-in through.
        [switch]$AllowRetraction,
        # SEC-25: the central-kill source -- declared for the same reason (PowerShell binds only declared names).
        [object]$CentralKillSource,
        [switch]$WhatIfMode = $true
    )
    Invoke-PimManagedDownlink @PSBoundParameters
}

# Invoke-PimScenarioDeploy / Invoke-PimScenarioSync -- the scenario-bound RUNNER
# the matrix probes for (scenario-runner-triggers-engine + idempotent-second-pass).
# Resolves the scenario, then per topology: single/master -> engine apply; managed
# -> downlink-sync THEN engine apply. Returns the run-plan + per-step results.
#   -Scenario : S1..S6 (or descriptor).
#   -EngineScope/-EngineMode : forwarded to Invoke-PimEngineCore (default All/Delta).
#   -Doc/-PublicKey/-TenantId/-SlaveRing/... : forwarded to the downlink (managed only).
#   -WhatIfMode : default ON (plan/preview; no live writes).
function Invoke-PimScenarioDeploy {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Scenario,
        [string]$EngineScope = 'All',
        [ValidateSet('Full','Delta')][string]$EngineMode = 'Delta',
        # downlink inputs (managed scenarios only)
        [object]$Doc,
        [object]$PublicKey,
        [object[]]$BaselineAdmins,
        [string]$TenantId,
        [int]$SlaveRing = 2,
        [string]$CentralRoot = $env:PIM_SyncRootCentral,
        [string]$LocalRoot   = $env:PIM_SyncRootLocal,
        [string]$SqlServer, [string]$SqlDatabase,
        # IMP-12: on a PULL scenario the accounts + roles are staged into the managed
        # tenant's OWN store, so the runner has to be able to name it. Without these the
        # downlink step still verifies and stages files, and says out loud that it applied
        # nothing -- which is the honest outcome, not a silent one.
        [string]$SlaveStoreConnectionString,
        # BOTH downlink gates, declared on the scenario runner because it is the THIRD entry
        # that reaches Invoke-PimManagedDownlink and a gate only some entries can carry is a
        # gate you cannot reason about.
        #   -RingPlan            = the OPERATOR's version gate (BUG-29 / RING-1 plane 2)
        #   -BlockedCapabilities = the CUSTOMER's class veto (SEC-10 / MSP-3 step 4)
        # BUG-78: -RingPlan was missing here, so a downlink driven through this runner had NO
        # version gate at all -- silently, and looking exactly like a clean run. That was the
        # third instance of one pattern, which is why the fix shipped with the INVENTORY
        # ASSERTION in tests/Test-PimDownlink.ps1 rather than as a fourth one-off: the guard
        # walks every function reaching the orchestrator and fails if a gate is undeclared or
        # unforwarded, so instance four cannot land quietly the way these three did.
        [object]$RingPlan,
        [string[]]$BlockedCapabilities,
        #   -SlaveAdminPrefixes  = the CUSTOMER's admin naming conventions (IMP-13)
        # Added 2026-08-29 because the gate INVENTORY named this forwarder the moment the gate was
        # declared -- nobody had to remember that this function existed, which is the whole point
        # of auditing the chain instead of listing the instances.
        [string[]]$SlaveAdminPrefixes,
        [string]$SlaveDefaultDomain,
        # (71.19 removed -DefaultManagerEmail here too: the slave resolves the recipient from the admin's sponsor
        # department, which the bundle carries.)
        # 71.14: the downlink's removal opt-in, declared on the scenario runner so the scheduled pull job can carry it
        # (PIM_DOWNLINK_ALLOW_RETRACTION=true). Default OFF: retraction stays report-first, and ON is still capped by the
        # removal budget inside the apply functions.
        [switch]$AllowRetraction,
        # SEC-25: the master's central-kill source (@{ checked; doc; error }), forwarded to the orchestrator.
        [object]$CentralKillSource,
        [datetime]$NowUtc = ([datetime]::UtcNow),
        [int64]$LastVersion = 0,
        [switch]$WhatIfMode = $true
    )
    $run = Get-PimScenarioRunPlan -Scenario $Scenario
    Write-Host "[scenario-run] $($run.reason)" -ForegroundColor Cyan
    $results = New-Object System.Collections.Generic.List[object]

    # 1) managed: downlink-sync first.
    if ($run.runDownlink) {
        if (-not ($Doc -and "$TenantId".Trim())) {
            Write-Host "[scenario-run] managed scenario but no -Doc/-TenantId supplied -- skipping downlink step." -ForegroundColor Yellow
            $results.Add([pscustomobject]@{ step = 'downlink-sync'; ok = $false; detail = 'no baseline doc / tenant id supplied' }) | Out-Null
        } else {
            $dlPass = @{}
            $__slaveCs = "$SlaveStoreConnectionString".Trim()
            # 🔴 BUG-79 -- WITHOUT A SLAVE STORE THE PULL STAGES FILES AND THE ENGINE READS SQL, SO
            # NOTHING EVER ARRIVES. The downlink reported, correctly and uselessly:
            #     [downlink] admins NOT staged: this is a pull topology and no
            #                -SlaveStoreConnectionString was supplied (sync files only).
            # and the engine then refused with "the desired store has NO definition/admin rows"
            # -- its empty-desired guard doing exactly the right thing over a store nobody filled.
            # 🔒 WHY DEFAULTING THIS IS **NOT** THE FORBIDDEN PUSH PATH. MSP-3's rule is "no
            # component ever writes ACROSS A TENANT BOUNDARY", and the handoff rightly warns against
            # threading a slave connection string through the MASTER's tooling. This is the mirror
            # image: on `local-slave` the job is running INSIDE the managed tenant, as that tenant's
            # own identity, and the ambient store IS its own store. A tenant writing to its own
            # database is the pull model working, not a boundary being crossed.
            # ⛔ SCOPED TO local-slave ON PURPOSE. On `central-msp` (S5) the ambient store is the
            # MASTER's, and defaulting there would write a slave's projection into the master's
            # database -- the precise mistake MSP-3 exists to prevent. So the default is keyed on
            # the resolved hostingLocation, never on "a store happens to be configured".
            if (-not $__slaveCs) {
                $__ctx = $null
                try { $__ctx = Resolve-PimScenarioContext -Scenario $Scenario } catch { $__ctx = $null }
                if ("$($__ctx.hostingLocation)".Trim().ToLowerInvariant() -eq 'local-slave' -and
                    (Get-Command Get-PimSqlConnectionString -ErrorAction SilentlyContinue)) {
                    try { $__slaveCs = "$(Get-PimSqlConnectionString)".Trim() } catch { $__slaveCs = '' }
                    if ($__slaveCs) {
                        Write-Host "[scenario-run] slave store: none supplied -- using this tenant's OWN ambient store (local-slave; the pull model writes into its own database)" -ForegroundColor DarkGray
                    } else {
                        Write-Host "[scenario-run] slave store: none supplied and the ambient store could not be resolved -- admins will be staged to FILES ONLY and the engine will find an empty desired set." -ForegroundColor Yellow
                    }
                }
            }
            if ($__slaveCs) { $dlPass['SlaveStoreConnectionString'] = $__slaveCs }
            # 🔴 BUG-81 -- THE UPN DOMAIN. The downlink refuses, correctly, to invent one:
            #     [downlink] admins NOT staged: no slave default domain (-SlaveDefaultDomain, or an
            #                ambient tenant to read it from). Refusing to build UPNs at a guessed domain.
            # That refusal is right -- a guessed domain creates admins nobody can sign in as -- but
            # IMP-12 already says the value is "resolved from the ambient tenant when we are running
            # inside it; never guessed", and on local-slave we ARE inside it. Nothing was doing that
            # resolution, so the refusal fired on every run and no admin ever reached the store.
            # Same boundary rule as the store above: ambient ONLY for local-slave. On central-msp the
            # ambient tenant is the MASTER, and stamping the master's domain onto a slave's admins
            # would be silently wrong in a way that looks fine in the log.
            if (-not "$SlaveDefaultDomain".Trim()) {
                $__ctx2 = $null
                try { $__ctx2 = Resolve-PimScenarioContext -Scenario $Scenario } catch { $__ctx2 = $null }
                if ("$($__ctx2.hostingLocation)".Trim().ToLowerInvariant() -eq 'local-slave' -and
                    -not (Get-Command Get-PimRestDefaultDomain -ErrorAction SilentlyContinue)) {
                    # 🪤 Do NOT let a missing helper skip this in silence -- that is exactly how the
                    # first version of this fix did nothing at all while the log blamed "no ambient
                    # tenant to read it from".
                    Write-Host '[scenario-run] slave domain: Get-PimRestDefaultDomain is NOT LOADED, so the domain cannot be resolved (dot-source engine/_shared/PIM-AccountRest.ps1). Admins will not be staged.' -ForegroundColor Yellow
                }
                if ("$($__ctx2.hostingLocation)".Trim().ToLowerInvariant() -eq 'local-slave' -and
                    (Get-Command Get-PimRestDefaultDomain -ErrorAction SilentlyContinue)) {
                    try {
                        $__dom = "$(Get-PimRestDefaultDomain)".Trim()
                        if ($__dom) {
                            $dlPass['SlaveDefaultDomain'] = $__dom
                            Write-Host "[scenario-run] slave domain: none supplied -- resolved '$__dom' from this tenant (local-slave)" -ForegroundColor DarkGray
                        }
                    } catch {
                        Write-Host "[scenario-run] slave domain: could not resolve it from this tenant ($($_.Exception.Message)) -- admins will NOT be staged rather than built at a guessed domain." -ForegroundColor Yellow
                    }
                }
            }
            if ("$SlaveDefaultDomain".Trim())         { $dlPass['SlaveDefaultDomain']         = $SlaveDefaultDomain }
            # Both gates forwarded on the same inert-when-absent rule the orchestrator uses:
            # bound-and-empty IS forwarded ("blocks nothing" is an answer; "nobody asked" is
            # not), unbound is not forwarded at all.
            if ($PSBoundParameters.ContainsKey('RingPlan') -and $null -ne $RingPlan) { $dlPass['RingPlan'] = $RingPlan }
            if ($PSBoundParameters.ContainsKey('BlockedCapabilities') -and $null -ne $BlockedCapabilities) { $dlPass['BlockedCapabilities'] = $BlockedCapabilities }
            if ($PSBoundParameters.ContainsKey('SlaveAdminPrefixes') -and $null -ne $SlaveAdminPrefixes) { $dlPass['SlaveAdminPrefixes'] = $SlaveAdminPrefixes }
            if ($AllowRetraction) { $dlPass['AllowRetraction'] = $true }   # 71.14: only an explicit ON is forwarded
            if ($PSBoundParameters.ContainsKey('CentralKillSource') -and $null -ne $CentralKillSource) { $dlPass['CentralKillSource'] = $CentralKillSource }
            $dl = Invoke-PimManagedDownlink -Scenario $Scenario -Doc $Doc -PublicKey $PublicKey `
                -BaselineAdmins $BaselineAdmins -TenantId $TenantId -SlaveRing $SlaveRing `
                -CentralRoot $CentralRoot -LocalRoot $LocalRoot -SqlServer $SqlServer -SqlDatabase $SqlDatabase `
                -NowUtc $NowUtc -LastVersion $LastVersion -WhatIfMode:$WhatIfMode @dlPass
            $results.Add([pscustomobject]@{ step = 'downlink-sync'; ok = [bool]$dl.ok; detail = "$($dl.reason)"; result = $dl }) | Out-Null
            if (-not $dl.ok) {
                return ([pscustomobject]@{ ok = $false; scenarioId = $run.scenarioId; plan = $run; steps = @($results.ToArray()) })
            }
        }
    }

    # 2) engine apply (all scenarios). Composes Invoke-PimEngineCore (which honours
    #    the mass-disable guard + empty-desired-never-prunes).
    $engine = $null
    $engineScript = Join-Path (Split-Path -Parent $PSScriptRoot) '..\tools\pim-engine\Invoke-PimEngineCore.ps1'
    $engineScript = (Resolve-Path -LiteralPath $engineScript -ErrorAction SilentlyContinue)
    if ($engineScript) {
        try {
            $engineArgs = @{ Scope = $EngineScope; Mode = $EngineMode }
            if ($WhatIfMode) { $engineArgs.WhatIf = $true }
            $engine = & $engineScript @engineArgs
            # The engine entry emits a tagged summary object (kind='pim-engine-summary')
            # carrying the REAL create/update/remove counts. Extract it so the caller (the
            # live matrix's idempotent-second-pass step) can assert zero changes on pass 2.
            $summary = $null
            foreach ($o in @($engine)) {
                if ($o -and ($o.PSObject.Properties['kind']) -and "$($o.kind)" -eq 'pim-engine-summary') { $summary = $o }
            }
            $cu = if ($summary) { [int]$summary.create } else { -1 }
            $uu = if ($summary) { [int]$summary.update } else { -1 }
            $ru = if ($summary) { [int]$summary.remove } else { -1 }
            $eu = if ($summary) { [int]$summary.errors } else { -1 }
            # 71.13: errors that are ONLY approval holds (policy mass-change breaker) do not fail the step -- it is
            # 'held', needs an approval, and says which. A real item failure alongside a hold still fails it.
            $engineHeld = [bool]($summary -and $summary.PSObject.Properties['outcome'] -and "$($summary.outcome)" -eq 'held')
            $okEngine = if ($summary) { ($eu -eq 0) -or $engineHeld } else { $true }
            $det = if ($summary) { "engine ran ($EngineScope/$EngineMode$(if($WhatIfMode){' whatif'})): create=$cu update=$uu remove=$ru errors=$eu$(if ($engineHeld) { " -- NEEDS APPROVAL: $($summary.heldDetail)" })" }
                   else { "engine ran ($EngineScope/$EngineMode$(if($WhatIfMode){' whatif'})) -- no structured summary returned" }
            $results.Add([pscustomobject]@{ step = 'engine-apply'; ok = $okEngine; held = $engineHeld; detail = $det; result = $engine; changeSummary = $summary }) | Out-Null
            if (-not $okEngine) {
                return ([pscustomobject]@{ ok = $false; scenarioId = $run.scenarioId; plan = $run; steps = @($results.ToArray()); changeSummary = $summary })
            }
        } catch {
            Write-Host "[scenario-run] engine apply failed: $($_.Exception.Message)" -ForegroundColor Red
            $results.Add([pscustomobject]@{ step = 'engine-apply'; ok = $false; detail = "$($_.Exception.Message)" }) | Out-Null
            return ([pscustomobject]@{ ok = $false; scenarioId = $run.scenarioId; plan = $run; steps = @($results.ToArray()) })
        }
    } else {
        Write-Host "[scenario-run] Invoke-PimEngineCore.ps1 not found -- engine step skipped." -ForegroundColor Yellow
        $results.Add([pscustomobject]@{ step = 'engine-apply'; ok = $false; detail = 'engine entry not found' }) | Out-Null
    }

    $okAll = -not (@($results.ToArray()) | Where-Object { -not $_.ok })
    # Surface the engine change summary at the top level so the live matrix can assert
    # idempotency (create+update+remove == 0 on a second pass) without re-digging the steps.
    $cs = $null
    foreach ($st in @($results.ToArray())) { if ($st.step -eq 'engine-apply' -and $st.changeSummary) { $cs = $st.changeSummary } }
    $heldAll = [bool]$okAll -and [bool](@($results.ToArray()) | Where-Object { $_.PSObject.Properties['held'] -and $_.held })
    return ([pscustomobject]@{ ok = [bool]$okAll; held = $heldAll; scenarioId = $run.scenarioId; plan = $run; steps = @($results.ToArray()); changeSummary = $cs })
}

# alias name the matrix also probes for.
function Invoke-PimScenarioSync {
    [CmdletBinding()] param(
        [Parameter(Mandatory)][object]$Scenario,
        [string]$EngineScope = 'All',
        [ValidateSet('Full','Delta')][string]$EngineMode = 'Delta',
        [object]$Doc, [object]$PublicKey, [object[]]$BaselineAdmins,
        [string]$TenantId, [int]$SlaveRing = 2,
        [string]$CentralRoot = $env:PIM_SyncRootCentral, [string]$LocalRoot = $env:PIM_SyncRootLocal,
        [string]$SqlServer, [string]$SqlDatabase,
        [datetime]$NowUtc = ([datetime]::UtcNow), [int64]$LastVersion = 0,
        [switch]$WhatIfMode = $true
    )
    Invoke-PimScenarioDeploy @PSBoundParameters
}
