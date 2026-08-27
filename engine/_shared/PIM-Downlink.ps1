# =============================================================================
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
function Select-PimDownlinkAdmins {
    param(
        [object[]]$Admins = @(),
        [Parameter(Mandatory)][int]$SlaveRing
    )
    $keep = New-Object System.Collections.Generic.List[object]
    foreach ($a in @($Admins)) {
        if ($null -eq $a) { continue }
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
# Returns @{ ok; reason; payload } -- ok=$false on any failure (never throws on a
# bad sig/expiry/rollback; throws only on a structurally-broken doc).
# ---------------------------------------------------------------------------
function Test-PimDownlinkBaseline {
    param(
        [Parameter(Mandatory)][object]$Doc,
        [object]$PublicKey,
        [string[]]$AllowedKind = @('baseline'),
        [datetime]$NowUtc = ([datetime]::UtcNow),
        [int64]$LastVersion = 0
    )
    $payloadB64 = "$(Get-PimDownlinkValue -Object $Doc -Key 'payloadB64')"
    $sigB64     = "$(Get-PimDownlinkValue -Object $Doc -Key 'signature')"
    if (-not $payloadB64.Trim() -or -not $sigB64.Trim()) {
        return @{ ok = $false; reason = 'not a signed bundle (payloadB64/signature missing)'; payload = $null }
    }

    $payloadBytes = $null; $sigBytes = $null
    try {
        $payloadBytes = [Convert]::FromBase64String($payloadB64)
        $sigBytes     = [Convert]::FromBase64String($sigB64)
    } catch {
        return @{ ok = $false; reason = "base64 decode failed: $($_.Exception.Message)"; payload = $null }
    }

    # Resolve the verifying RSA public key.
    $rsa = $null
    if ($null -ne $PublicKey) {
        if ($PublicKey -is [System.Security.Cryptography.RSA]) { $rsa = $PublicKey }
        elseif ($PublicKey -is [System.Security.Cryptography.X509Certificates.X509Certificate2]) {
            $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($PublicKey)
        } else {
            return @{ ok = $false; reason = 'unsupported -PublicKey type (need [RSA] or X509Certificate2)'; payload = $null }
        }
    }

    $ok = $false
    if ($rsa) {
        try {
            $ok = $rsa.VerifyData($payloadBytes, $sigBytes, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
        } catch {
            return @{ ok = $false; reason = "signature verify threw: $($_.Exception.Message)"; payload = $null }
        }
        if (-not $ok) { return @{ ok = $false; reason = 'SIGNATURE INVALID -- bundle tampered or signed by the wrong key'; payload = $null } }
    } else {
        # No explicit key: defer to the embedded prod public cert via Test-PimBaselineDoc.
        if (-not (Get-Command Test-PimBaselineDoc -ErrorAction SilentlyContinue)) {
            return @{ ok = $false; reason = 'no -PublicKey and Test-PimBaselineDoc (embedded cert) not loaded'; payload = $null }
        }
        try {
            $p = Test-PimBaselineDoc -Doc $Doc -AllowedKind $AllowedKind
            # Test-PimBaselineDoc already enforced product/kind. Continue with expiry/rollback below.
            $payloadObj = $p
            return (Test-PimDownlinkBaselineFinish -PayloadObject $payloadObj -AllowedKind $AllowedKind -NowUtc $NowUtc -LastVersion $LastVersion)
        } catch {
            return @{ ok = $false; reason = "embedded-cert verify failed: $($_.Exception.Message)"; payload = $null }
        }
    }

    # Parse the now-trusted payload and run the shape/expiry/rollback gates.
    $payloadObj = $null
    try { $payloadObj = [System.Text.Encoding]::UTF8.GetString($payloadBytes) | ConvertFrom-Json }
    catch { return @{ ok = $false; reason = "payload JSON parse failed: $($_.Exception.Message)"; payload = $null } }
    return (Test-PimDownlinkBaselineFinish -PayloadObject $payloadObj -AllowedKind $AllowedKind -NowUtc $NowUtc -LastVersion $LastVersion)
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
        return @{ ok = $false; reason = "unexpected bundle product '$(Get-PimDownlinkValue -Object $p -Key 'product')'"; payload = $null }
    }
    $kind = "$(Get-PimDownlinkValue -Object $p -Key 'kind')"
    if (@($AllowedKind) -notcontains $kind) {
        return @{ ok = $false; reason = "unexpected bundle kind '$kind' (allowed: $($AllowedKind -join ', '))"; payload = $null }
    }
    $validTo = "$(Get-PimDownlinkValue -Object $p -Key 'validToUtc')"
    if ($validTo.Trim()) {
        $vt = $null
        try { $vt = [datetime]::Parse($validTo, [System.Globalization.CultureInfo]::InvariantCulture) } catch {}
        if ($vt -and $NowUtc.ToUniversalTime() -gt $vt.ToUniversalTime()) {
            return @{ ok = $false; reason = "baseline bundle expired ($validTo)"; payload = $null }
        }
    }
    $ver = 0
    $verRaw = Get-PimDownlinkValue -Object $p -Key 'version'
    if ($null -ne $verRaw -and "$verRaw".Trim()) { try { $ver = [int64]$verRaw } catch { $ver = 0 } }
    if ($ver -lt [int64]$LastVersion) {
        return @{ ok = $false; reason = "baseline rollback refused: bundle version $ver < last-applied $LastVersion"; payload = $null }
    }
    return @{ ok = $true; reason = "verified (version $ver, kind $kind)"; payload = $p }
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
    foreach ($s in $sel) { if ((& $lower $s) -eq 'none') { return @{ match = $false; reason = 'MSP-local by declaration (target=none) -- never published' } } }

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
        if ($tag -and $tags.Contains($tag)) { return @{ match = $true; reason = "tenant carries the tag '$tag'" } }
    }
    return @{ match = $false; reason = "tenant matches none of the target selectors ($($sel -join ', '))" }
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
        [string[]]$SlaveGroupTags
    )
    $allowed = New-Object System.Collections.Generic.HashSet[string]
    foreach ($u in @($AdminUserNames)) { [void]$allowed.Add("$u".Trim().ToLowerInvariant()) }

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
            & $mark $excluded "admin '$user' did not reach this tenant's ring -- their roles do not either"; continue
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
        # payload.definitions -> @{ groups; nestings; roleBindings }
        [object]$Definitions,
        # the tags actually projected AFTER ring + policy filtering (from
        # Select-PimProjectedAssignments .projected) -- never the master's whole model.
        [string[]]$ProjectedTags = @(),
        # tags that already exist in the slave (its own PIM-Definitions).
        [string[]]$SlaveGroupTags = @()
    )
    $lower = { param($s) "$s".Trim().ToLowerInvariant() }
    $groups       = @(); $nestings = @(); $bindings = @()
    if ($Definitions) {
        $g = Get-PimDownlinkValue -Object $Definitions -Key 'groups';       if ($g) { $groups   = @($g) }
        $n = Get-PimDownlinkValue -Object $Definitions -Key 'nestings';     if ($n) { $nestings = @($n) }
        $b = Get-PimDownlinkValue -Object $Definitions -Key 'roleBindings'; if ($b) { $bindings = @($b) }
    }
    $slaveHas = New-Object System.Collections.Generic.HashSet[string]
    foreach ($t in @($SlaveGroupTags)) { [void]$slaveHas.Add((& $lower $t)) }

    # Closure: the projected role groups + every group reachable through nesting.
    #
    # 🪤 THIS MUST ITERATE TO A FIXPOINT, not walk the list once. A single pass only
    # reaches ONE level: given A -> B -> C it pulls in B and stops, so C is never
    # created and the admin silently gets part of their delegation. Nesting depth is a
    # modelling choice the master makes, not something this code may cap. Bounded by
    # the tag count so a cycle in the master's model terminates instead of hanging.
    $need = New-Object System.Collections.Generic.HashSet[string]
    foreach ($t in @($ProjectedTags)) { [void]$need.Add((& $lower $t)) }
    $guard = 0
    $maxRounds = [Math]::Max(1, @($nestings).Count + 1)
    do {
        $added = $false
        foreach ($nst in $nestings) {
            $src = & $lower (Get-PimDownlinkValue -Object $nst -Key 'SourceGroupTag')
            $tgt = & $lower (Get-PimDownlinkValue -Object $nst -Key 'TargetGroupTag')
            if (-not $src) { continue }
            # BUG-61: walk ROLE -> SERVICE. `need` starts as the projected ROLE tags, and a
            # nesting names its role group in TARGET, so the group to pull in is the SOURCE.
            if ($need.Contains($tgt) -and -not $need.Contains($src)) { [void]$need.Add($src); $added = $true }
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
        if (-not $mine.Contains($gt)) {
            $skip.Add([ordered]@{ GroupTag = "$(Get-PimDownlinkValue -Object $bnd -Key 'GroupTag')"; reason = 'role binding NOT applied -- the group is customer-owned, and its Entra roles are theirs to set' }) | Out-Null
            continue
        }
        $outBind.Add($bnd) | Out-Null
    }

    $sortTag = { @($args[0] | Sort-Object @{ e = { "$(Get-PimDownlinkValue -Object $_ -Key 'GroupTag')".ToLowerInvariant() } }) }
    return @{
        create       = @(& $sortTag $create.ToArray())
        defer        = @(& $sortTag $defer.ToArray())
        skipped      = @(& $sortTag $skip.ToArray())
        nestings     = @($outNest.ToArray() | Sort-Object @{ e = { "$(Get-PimDownlinkValue -Object $_ -Key 'SourceGroupTag')".ToLowerInvariant() } }, @{ e = { "$(Get-PimDownlinkValue -Object $_ -Key 'TargetGroupTag')".ToLowerInvariant() } })
        roleBindings = @($outBind.ToArray() | Sort-Object @{ e = { "$(Get-PimDownlinkValue -Object $_ -Key 'GroupTag')".ToLowerInvariant() } }, @{ e = { "$(Get-PimDownlinkValue -Object $_ -Key 'RoleDefinitionName')".ToLowerInvariant() } })
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
        [string[]]$BlockedCapabilities = @()
    )
    $ctx = Resolve-PimScenarioContext -Scenario $Scenario
    if (-not [bool]$ctx.syncAdminsPermissions) {
        return @{ ok = $false; reason = "scenario $($ctx.id) is not a managed/sync scenario (syncAdminsPermissions=false)"; scenarioId = "$($ctx.id)"; admins = @(); sync = $null; content = $null; baselineVersion = 0; verify = $null }
    }

    # 1) verify the pulled baseline (sig + product/kind + expiry + anti-rollback).
    $verify = Test-PimDownlinkBaseline -Doc $Doc -PublicKey $PublicKey -AllowedKind @('baseline') -NowUtc $NowUtc -LastVersion $LastVersion
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

    # 3) ring-gate to admin.Ring <= slave.Ring.
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

    # admins: the class gate first (a blocked class means NONE of them, and says so),
    # then per-artifact targeting.
    $adminClass = Test-PimDownlinkClassAllowed -Class 'admins' -BlockedCapabilities $BlockedCapabilities
    if (-not $adminClass.allowed) {
        foreach ($a in $admins) { $classHeld.Add([ordered]@{ kind = 'admin'; name = "$(Get-PimDownlinkValue -Object $a -Key 'UserName')"; reason = $adminClass.reason }) | Out-Null }
        $admins = @()
    } else {
        $keepAdmins = New-Object System.Collections.Generic.List[object]
        foreach ($a in $admins) {
            $tv = Test-PimArtifactTarget -Target "$(Get-PimDownlinkValue -Object $a -Key 'Target')" -TenantId $TenantId -TenantTags $effTags
            if ($tv.match) { $keepAdmins.Add($a) | Out-Null }
            else { $targetSkips.Add([ordered]@{ kind = 'admin'; name = "$(Get-PimDownlinkValue -Object $a -Key 'UserName')"; reason = $tv.reason }) | Out-Null }
        }
        $admins = @($keepAdmins.ToArray())
    }

    # 3b) MSP-2 / control #2: project the master's role memberships for exactly the
    # admins that survived the ring gate, through the relationship's policy.
    $srcAssign = $null
    if ($PSBoundParameters.ContainsKey('BaselineAssignments') -and $null -ne $BaselineAssignments) { $srcAssign = @($BaselineAssignments) }
    else {
        $fromPayload = Get-PimDownlinkValue -Object $payload -Key 'assignments'
        if ($null -ne $fromPayload) { $srcAssign = @($fromPayload) }
    }
    # roles: same two narrowings, applied BEFORE the relationship policy so the plan can
    # tell "the customer declined role changes" from "the policy denied this tag".
    $roleClass = Test-PimDownlinkClassAllowed -Class 'roles' -BlockedCapabilities $BlockedCapabilities
    if ($null -ne $srcAssign) {
        if (-not $roleClass.allowed) {
            foreach ($a in @($srcAssign)) { $classHeld.Add([ordered]@{ kind = 'role'; name = "$(Get-PimDownlinkValue -Object $a -Key 'UserName') -> $(Get-PimDownlinkValue -Object $a -Key 'GroupTag')"; reason = $roleClass.reason }) | Out-Null }
            $srcAssign = @()
        } else {
            $keepA = New-Object System.Collections.Generic.List[object]
            foreach ($a in @($srcAssign)) {
                $tv = Test-PimArtifactTarget -Target "$(Get-PimDownlinkValue -Object $a -Key 'Target')" -TenantId $TenantId -TenantTags $effTags
                if ($tv.match) { $keepA.Add($a) | Out-Null }
                else { $targetSkips.Add([ordered]@{ kind = 'role'; name = "$(Get-PimDownlinkValue -Object $a -Key 'UserName') -> $(Get-PimDownlinkValue -Object $a -Key 'GroupTag')"; reason = $tv.reason }) | Out-Null }
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

    $reason = "downlink plan for $($ctx.id): $($admins.Count) admin(s) reach slave ring $SlaveRing from baseline v$blVersion"
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
    }
    # MSP-4: report the two new narrowings SEPARATELY from the policy's. Four different
    # reasons a thing can be absent, four different fixes -- merging them would leave an
    # operator guessing which one applied.
    if ($targetSkips.Count) { $reason += "; $($targetSkips.Count) artifact(s) not TARGETED at this tenant" }
    if ($classHeld.Count)   { $reason += "; $($classHeld.Count) HELD -- the customer blocked that capability" }

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
        classHeld       = @($classHeld.ToArray())
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
        # IMP-12: the managed tenant's default verified domain, used to build each synced
        # admin's UPN on the S6 pull path. Omitted => resolved from the ambient tenant when
        # we are running inside it; never guessed.
        [string]$SlaveDefaultDomain,
        # TAP intent for the synced admins (operator decision 2026-08-13 -- ON by default).
        # Per-admin values in the bundle win; these are only the fallback for a master whose
        # registry predates the columns. -DefaultManagerEmail is what stops a minted TAP from
        # being delivered nowhere when the registry carries no manager address.
        [string]$CreateTapDefault = 'TRUE',
        [int]$TapLifetimeHoursDefault = 8,
        [string]$DefaultManagerEmail = '',
        [switch]$AllowFullPrune,
        [switch]$WhatIfMode = $true
    )
    # 1) PURE plan: verify + ring-filter + resolve paths + build content.
    $planArgs = @{}
    if ($PSBoundParameters.ContainsKey('RingPlan') -and $null -ne $RingPlan) { $planArgs['RingPlan'] = $RingPlan }
    if ($PSBoundParameters.ContainsKey('BaselineAssignments') -and $null -ne $BaselineAssignments) { $planArgs['BaselineAssignments'] = $BaselineAssignments }
    if ($PSBoundParameters.ContainsKey('SlaveGroupTags') -and $null -ne $SlaveGroupTags) { $planArgs['SlaveGroupTags'] = $SlaveGroupTags }
    if (@($ProjectionPolicy).Count) { $planArgs['ProjectionPolicy'] = $ProjectionPolicy }
    $plan = Get-PimDownlinkPlan -Scenario $Scenario -Doc $Doc -PublicKey $PublicKey `
        -BaselineAdmins $BaselineAdmins -TenantId $TenantId -SlaveRing $SlaveRing `
        -CentralRoot $CentralRoot -LocalRoot $LocalRoot -NowUtc $NowUtc -LastVersion $LastVersion @planArgs
    if (-not $plan.ok) {
        Write-Host "[downlink] REFUSED: $($plan.reason)" -ForegroundColor Red
        return ([pscustomobject]@{ ok = $false; reason = $plan.reason; plan = $plan; staged = @(); fanout = $null })
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
            $srv = if ("$SqlServer".Trim()) { $SqlServer } elseif ($global:PIM_SqlServer) { "$($global:PIM_SqlServer)" } else { '.\SQLEXPRESS' }
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
        $dom = "$SlaveDefaultDomain".Trim()
        if (-not $dom -and (Get-Command Get-PimTargetDefaultDomain -ErrorAction SilentlyContinue)) {
            try { $dom = "$(Get-PimTargetDefaultDomain)".Trim() } catch { $dom = '' }
        }
        if ($dom) {
            $adminApply = Invoke-PimDownlinkAdminApply -ConnectionString $SlaveStoreConnectionString `
                -Admins @($plan.admins) -DefaultDomain $dom `
                -CreateTapDefault $CreateTapDefault -TapLifetimeHoursDefault $TapLifetimeHoursDefault `
                -DefaultManagerEmail $DefaultManagerEmail `
                -AllowFullPrune:$AllowFullPrune -WhatIfMode:$WhatIfMode
            Write-Host "[downlink] admins (S6 pull, domain $dom): $($adminApply.detail)" -ForegroundColor $(if ($adminApply.ok) { 'Green' } else { 'Red' })
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
                    -DefinitionPlan $plan.definitions -AllowFullPrune:$AllowFullPrune -WhatIfMode:$WhatIfMode
                Write-Host "[downlink] groups: $($defApply.detail)" -ForegroundColor $(if ($defApply.ok) { 'Green' } else { 'Red' })
                foreach ($d in @($plan.definitions.defer)) {
                    Write-Host "[downlink]   DEFERRED $($d.GroupTag): $($d.reason)" -ForegroundColor DarkGray
                }
            }
            $assignApply = Invoke-PimDownlinkAssignmentApply -ConnectionString $SlaveStoreConnectionString `
                -Assignments @($plan.assignments) -AllowFullPrune:$AllowFullPrune -WhatIfMode:$WhatIfMode
            $col = if ($assignApply.ok) { 'Green' } else { 'Red' }
            Write-Host "[downlink] roles: $($assignApply.detail)" -ForegroundColor $col
            foreach ($u in @($plan.projection.unresolved)) {
                Write-Host "[downlink]   UNRESOLVED $($u.UserName) -> $($u.GroupTag): $($u.reason)" -ForegroundColor Yellow
            }
        }
    } elseif ($null -ne $plan.projection -and @($plan.assignments).Count) {
        # staged but not applied -- say so, rather than letting a projected count in
        # the plan read as "the roles are in the slave".
        Write-Host "[downlink] $(@($plan.assignments).Count) role assignment(s) projected but NOT applied: no -SlaveStoreConnectionString supplied (staged to file only)." -ForegroundColor Yellow
    }

    return ([pscustomobject]@{ ok = $true; reason = $plan.reason; plan = $plan; staged = @($staged.ToArray()); fanout = $fanout; admins = $adminApply; definitions = $defApply; assignments = $assignApply })
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
# sql/local-schema.sql, sql/platform-schema.sql) and it is already implemented the
# same way where the container merges a pulled baseline with the local store:
# Start-PimEngineContainer.ps1:107-108 stamps baseline rows Owner='MSP' and
# pim.LocalAdmins rows Owner='Local'. Crucially the tag is PROVENANCE, NOT A GATE --
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
        [switch]$WhatIfMode = $true
    )
    $entity = 'PIM-Assignments-Admins'
    $existing = @()
    try { $existing = @(Get-PimSqlRows -ConnectionString $ConnectionString -Entity $entity) }
    catch { return @{ ok = $false; created = 0; updated = 0; removed = 0; skippedForeign = 0; wouldPrune = @(); detail = "could not read $entity from the slave store: $($_.Exception.Message)" } }

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

    # prune only what THIS sync previously added and no longer projects
    $stale = @($ownedKeys.Keys | Where-Object { -not $desiredKeys.ContainsKey($_) })
    $removed = 0; $wouldPrune = @()
    if ($stale.Count) {
        if (@($Assignments).Count -eq 0 -and -not $AllowFullPrune) {
            $wouldPrune = $stale
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
    if ($WhatIfMode) { $detail = "[whatif] $detail" }
    return @{ ok = $true; created = $created; updated = $updated; removed = $removed; skippedForeign = $foreign; wouldPrune = $wouldPrune; detail = $detail }
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
    $defEntities = @('PIM-Definitions-Roles','PIM-Definitions-Services','PIM-Definitions-Organization','PIM-Definitions-Tasks','PIM-Definitions')
    $work = @()
    foreach ($e in $defEntities) {
        $rows = if ($groupsByEntity.ContainsKey($e)) { @($groupsByEntity[$e].ToArray()) } else { @() }
        $work += @{ Entity = $e; Rows = $rows; Keys = @('GroupTag'); IsGroupClass = $true }
    }
    $work += @{ Entity = 'PIM-Assignments-Groups';       Rows = @($DefinitionPlan.nestings);     Keys = @('TargetGroupTag', 'SourceGroupTag') }
    $work += @{ Entity = 'PIM-Assignments-Roles-Groups'; Rows = @($DefinitionPlan.roleBindings); Keys = @('GroupTag', 'RoleDefinitionName') }
    $created = 0; $updated = 0; $removed = 0; $foreign = 0; $parts = @()
    $wouldPrune = New-Object System.Collections.Generic.List[string]
    foreach ($w in $work) {
        $entity = "$($w.Entity)"
        $existing = @()
        try { $existing = @(Get-PimSqlRows -ConnectionString $ConnectionString -Entity $entity) }
        catch { return @{ ok = $false; created = $created; updated = $updated; removed = $removed; skippedForeign = $foreign; detail = "could not read $entity from the slave store: $($_.Exception.Message)" } }

        $keyFor = {
            param($row)
            $vals = @($w.Keys | ForEach-Object { "$(Get-PimDownlinkValue -Object $row -Key $_)" })
            ($vals -join '|')
        }
        $ownedKeys = @{}
        foreach ($e in $existing) {
            if ("$(Get-PimDownlinkValue -Object $e -Key 'Owner')" -ne $Owner) { continue }
            $k = & $keyFor $e
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
        foreach ($r in @($w.Rows)) {
            $k = & $keyFor $r
            if (-not "$k".Trim() -or "$k" -match '^\|+$') { continue }
            $desired[$k] = $true
            # rebuild as a plain ordered row + the Owner stamp; the bundle rows are
            # PSCustomObjects from JSON and must not be written back verbatim.
            $row = [ordered]@{}
            foreach ($p in @($r.PSObject.Properties)) {
                # SourceEntity is ROUTING for this function, not a column of the row. The
                # engine derives its own SourceEntity when it reads the definitions back, so
                # persisting ours would put two different meanings behind one name.
                if ($p.Name -eq 'SourceEntity') { continue }
                $row[$p.Name] = "$($p.Value)"
            }
            $row['Owner'] = $Owner
            if (-not $row.Contains('Action')) { $row['Action'] = 'Assign' }
            if ($ownedKeys.ContainsKey($k)) { $updated++ } else { $created++ }
            if (-not $WhatIfMode) { Set-PimSqlRow -ConnectionString $ConnectionString -Entity $entity -Key $k -Data $row }
        }
        $stale = @($ownedKeys.Keys | Where-Object { -not $desired.ContainsKey($_) })
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
                foreach ($k in $stale) {
                    if (-not $WhatIfMode) { Remove-PimSqlRow -ConnectionString $ConnectionString -Entity $entity -Key $k }
                    $removed++
                }
            }
        }
        # Only report an entity that took part -- five empty group buckets in the detail line
        # would bury the one that did something.
        if (@($w.Rows).Count -or $stale.Count) { $parts += ("{0}:+{1}" -f $entity.Replace('PIM-', ''), @($w.Rows).Count) }
    }
    $detail = "definitions +$created ~$updated -$removed ($($parts -join ' ')); left $foreign customer-owned row(s) untouched"
    if ($wouldPrune.Count) { $detail += "; REFUSED to prune $($wouldPrune.Count) synced row(s) because the master published none -- pass -AllowFullPrune to withdraw them" }
    if ($WhatIfMode) { $detail = "[whatif] $detail" }
    return @{ ok = $true; created = $created; updated = $updated; removed = $removed; skippedForeign = $foreign; wouldPrune = @($wouldPrune.ToArray()); detail = $detail }
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
# 🪤 CreateTAP alone is NOT enough, and this is the half that fails silently: AdminTap mails the
# code to ManagerEmail, so an empty ManagerEmail mints a TAP that is delivered NOWHERE and can
# never be recovered (the code is readable only at creation). Carry it, or pass
# -DefaultManagerEmail. Nothing here can compensate for a slave that cannot send mail at all --
# that is the sender-mailbox half of the same gap.
# ---------------------------------------------------------------------------
function Invoke-PimDownlinkAdminApply {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ConnectionString,
        [object[]]$Admins = @(),                       # $plan.admins (ring-filtered baseline rows)
        [Parameter(Mandatory)][string]$DefaultDomain,  # the SLAVE's default domain
        [string]$Owner = 'MSP',
        # The fleet-wide fallbacks, applied per row only when the bundle carries no value.
        # $CreateTapDefault is the operator's "default ON"; pass 'FALSE' to opt a relationship out.
        [string]$CreateTapDefault = 'TRUE',
        [int]$TapLifetimeHoursDefault = 8,
        [string]$DefaultManagerEmail = '',
        [switch]$AllowFullPrune,
        [switch]$WhatIfMode = $true
    )
    $entity = 'Account-Definitions-Admins'
    $existing = @()
    try { $existing = @(Get-PimSqlRows -ConnectionString $ConnectionString -Entity $entity) }
    catch { return @{ ok = $false; created = 0; updated = 0; removed = 0; skippedForeign = 0; detail = "could not read $entity from the slave store: $($_.Exception.Message)" } }

    $ownedKeys = @{}
    foreach ($e in $existing) {
        if ("$(Get-PimDownlinkValue -Object $e -Key 'Owner')" -ne $Owner) { continue }
        $ownedKeys["$(Get-PimDownlinkValue -Object $e -Key 'UserName')"] = $true
    }
    $foreign = @($existing).Count - $ownedKeys.Count

    $created = 0; $updated = 0; $desired = @{}; $tapOn = 0; $tapNoRecipient = 0
    foreach ($a in @($Admins)) {
        $un = "$(Get-PimDownlinkValue -Object $a -Key 'UserName')".Trim()
        if (-not $un) { continue }
        $desired[$un] = $true

        # --- TAP intent: the bundle's value wins; absent/blank falls back to the default (ON).
        # SQL BIT arrives as True/False, an older bundle as the string 'TRUE'/'FALSE', and a
        # registry predating the column as nothing at all -- all three resolve here so the
        # decision is made ONCE rather than at three call sites.
        $tapRaw = "$(Get-PimDownlinkValue -Object $a -Key 'CreateTap')".Trim()
        if (-not $tapRaw) { $tapRaw = "$(Get-PimDownlinkValue -Object $a -Key 'CreateTAP')".Trim() }
        $createTap = if ($tapRaw) { if ($tapRaw -match '(?i)^(true|1|yes)$') { 'TRUE' } else { 'FALSE' } }
                     elseif ("$CreateTapDefault" -match '(?i)^(true|1|yes)$') { 'TRUE' } else { 'FALSE' }

        $lifeRaw = "$(Get-PimDownlinkValue -Object $a -Key 'TapLifetimeHours')".Trim()
        if (-not $lifeRaw) { $lifeRaw = "$(Get-PimDownlinkValue -Object $a -Key 'TAPLifetimeHours')".Trim() }
        $life = 0; [void][int]::TryParse($lifeRaw, [ref]$life)
        if ($life -le 0) { $life = $TapLifetimeHoursDefault }

        $mgr = "$(Get-PimDownlinkValue -Object $a -Key 'ManagerEmail')".Trim()
        if (-not $mgr) { $mgr = "$DefaultManagerEmail".Trim() }

        if ($createTap -eq 'TRUE') { $tapOn++; if (-not $mgr) { $tapNoRecipient++ } }

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
            Notes                 = "MSP downlink (central admin ring $(Get-PimDownlinkValue -Object $a -Key 'Ring'))"
            ManagerEmail          = $mgr
            StartDate             = ''
            ProvisionDate         = 'Now'
            CreateTAP             = $createTap
            TAPStartDate          = ''
            TAPLifetimeHours      = "$life"
            AccountStatus         = 'Enabled'
            StatusChangeCode      = ''
            Ring                  = "$(Get-PimDownlinkValue -Object $a -Key 'Ring')"
            Template              = "$(Get-PimDownlinkValue -Object $a -Key 'Template')"
            OffboardDate          = ''
            DeleteAfterDays       = ''
            Owner                 = $Owner
        }
        if ($ownedKeys.ContainsKey($un)) { $updated++ } else { $created++ }
        if (-not $WhatIfMode) { Set-PimSqlRow -ConnectionString $ConnectionString -Entity $entity -Key $un -Data $row }
    }

    # same empty-desired guard as the membership apply: "published nothing" and
    # "withdrew everyone" are indistinguishable here, and the safe reading is the first.
    $stale = @($ownedKeys.Keys | Where-Object { -not $desired.ContainsKey($_) })
    $removed = 0; $wouldPrune = @()
    if ($stale.Count) {
        if (@($Admins).Count -eq 0 -and -not $AllowFullPrune) { $wouldPrune = $stale }
        else {
            foreach ($k in $stale) {
                if (-not $WhatIfMode) { Remove-PimSqlRow -ConnectionString $ConnectionString -Entity $entity -Key $k }
                $removed++
            }
        }
    }
    $detail = "${entity}: +$created ~$updated -$removed (left $foreign local admin row(s) untouched); TAP on for $tapOn"
    # Surfaced, never swallowed: a TAP with no recipient is minted, mailed nowhere, and the code
    # is unrecoverable afterwards. That must read as a WARNING in the sync output, not as success.
    if ($tapNoRecipient) { $detail += "; WARNING $tapNoRecipient admin(s) have CreateTAP=TRUE but NO ManagerEmail -- their TAP would be minted and never delivered (pass -DefaultManagerEmail)" }
    if ($wouldPrune.Count) { $detail += "; REFUSED to prune $($wouldPrune.Count) synced admin(s) on an EMPTY baseline -- pass -AllowFullPrune" }
    if ($WhatIfMode) { $detail = "[whatif] $detail" }
    return @{ ok = $true; created = $created; updated = $updated; removed = $removed; skippedForeign = $foreign; wouldPrune = $wouldPrune; tapEnabled = $tapOn; tapWithoutRecipient = $tapNoRecipient; detail = $detail }
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
        # IMP-12: the managed tenant's default verified domain, used to build each synced
        # admin's UPN on the S6 pull path. Omitted => resolved from the ambient tenant when
        # we are running inside it; never guessed.
        [string]$SlaveDefaultDomain,
        [switch]$AllowFullPrune,
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
        [string]$SlaveDefaultDomain,
        # BUG-84: the fallback delivery address for a synced admin's TAP. The AdminTap guard
        # REFUSES to mint a credential it cannot deliver -- correctly, and by design (BUG-66/69) --
        # so an admin row with no ManagerEmail produces an account nobody can sign in as. The
        # downlink already says so ("... pass -DefaultManagerEmail"), and Invoke-PimManagedDownlink
        # already accepts it; nothing forwarded it, so the advice named a parameter the caller had
        # no way to supply. Per-admin ManagerEmail from the bundle still WINS -- this is only the
        # fallback for a master registry that predates the column.
        [string]$DefaultManagerEmail = '',
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
                            Write-Host "[scenario-run] slave domain: none supplied -- resolved '$__dom' from this tenant (local-slave; IMP-12)" -ForegroundColor DarkGray
                        }
                    } catch {
                        Write-Host "[scenario-run] slave domain: could not resolve it from this tenant ($($_.Exception.Message)) -- admins will NOT be staged rather than built at a guessed domain." -ForegroundColor Yellow
                    }
                }
            }
            if ("$SlaveDefaultDomain".Trim())         { $dlPass['SlaveDefaultDomain']         = $SlaveDefaultDomain }
            if ("$DefaultManagerEmail".Trim())        { $dlPass['DefaultManagerEmail']        = $DefaultManagerEmail }
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
            $okEngine = if ($summary) { ($eu -eq 0) } else { $true }
            $det = if ($summary) { "engine ran ($EngineScope/$EngineMode$(if($WhatIfMode){' whatif'})): create=$cu update=$uu remove=$ru errors=$eu" }
                   else { "engine ran ($EngineScope/$EngineMode$(if($WhatIfMode){' whatif'})) -- no structured summary returned" }
            $results.Add([pscustomobject]@{ step = 'engine-apply'; ok = $okEngine; detail = $det; result = $engine; changeSummary = $summary }) | Out-Null
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
    return ([pscustomobject]@{ ok = [bool]$okAll; scenarioId = $run.scenarioId; plan = $run; steps = @($results.ToArray()); changeSummary = $cs })
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
