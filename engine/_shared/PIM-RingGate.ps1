# =============================================================================
# PIM-RingGate.ps1 -- PIM's consumer of the AutomateIT RING-1 ring + capability
# design. PURE: no disk, no network, no SQL, no globals, no side effects.
#
# -----------------------------------------------------------------------------
# 🔒 THE PLATFORM OWNS THIS DESIGN. THIS FILE DOES NOT.
# -----------------------------------------------------------------------------
# The source of truth is the FRAMEWORK file `sync/_AitRings.ps1` (AutomateIT
# repo-root DOCS/REQUIREMENTS.md, "RING-1 -- Generic ring + capability gating").
# PIM4EntraPS is an ordinary SOLUTION on top of AutomateIT -- Platform* IS
# AutomateIT itself -- so PIM CONSUMES this design and must never redefine it.
# Operator decision 2026-08-07: PIM's own ring model becomes one PROVIDER behind
# the platform design, not the definition of it.
#
# WHY THIS IS A VENDORED COPY RATHER THAN A DOT-SOURCE
#   `sync/_AitRings.ps1` is NEVER WRITTEN TO A CUSTOMER'S DISK. The sync engine
#   (SOLUTIONS/PlatformConfiguration/INTERNAL/Sync-AutomateIT-Engine.ps1) reads it
#   out of the downloaded zipball IN MEMORY, writes a temp copy, dot-sources it,
#   and deletes it immediately. `sync/` is not part of any solution's payload, so
#   at PIM runtime on a customer machine the platform core does not exist on disk
#   and cannot be dot-sourced. PIM therefore carries its own copy of the PURE
#   decision functions.
#   This is the trade PIM's CLAUDE.md prescribes: "Duplicating a little logic into
#   this solution is the CORRECT trade versus widening a shared tool. Isolation
#   beats DRY here." The copy is kept honest by tests/Test-PimDeployContract.ps1,
#   which diffs PIM's verdicts against the real `sync/_AitRings.ps1` whenever that
#   file is reachable (i.e. in the dev tree) and REPORTS drift. It cannot FAIL on
#   a shared file PIM does not own -- reporting is the rule for that case.
#
# ⚠️ IF YOU CHANGE A DECISION RULE HERE, YOU ARE FORKING THE PLATFORM.
#   Change `sync/_AitRings.ps1` first (that is a framework change, with framework
#   approval), then re-vendor. The four-state result and the two distinctions the
#   framework calls load-bearing are reproduced EXACTLY:
#     * $null RingAllow ("no ring restriction") is NOT the same as an empty array
#       ("nothing approved") -- collapsing them loses operator intent.
#     * Held ("the operator has not promoted this") is NOT the same as Blocked
#       ("the customer opted out") -- collapsing them makes a stalled rollout
#       indistinguishable from a healthy opt-out in the heartbeat uplink.
#
# -----------------------------------------------------------------------------
# TWO PLANES -- same mechanism, separate instance (operator decision 2026-08-07)
# -----------------------------------------------------------------------------
# "Ring" means two different things in PIM, and conflating them produces wrong
# fixes. They are the SAME MECHANISM applied to DIFFERENT PAYLOADS on DIFFERENT
# planes, and neither is a substitute for the other:
#
#   PLANE 1 -- the AutomateIT operator -> ~30 customers.   Payload: CODE VERSION.
#     Map: sync/release-map.json. Decided by the platform, in the sync engine,
#     BEFORE PIM code is even on disk. PIM does not participate at runtime; it
#     only DECLARES its capabilities in solution.deploy.json. Nothing in this
#     file runs on plane 1.
#
#   PLANE 2 -- a PIM MSP MASTER -> its own managed tenants. Payload: the signed
#     BASELINE TEMPLATE VERSION (S5/S6 managed downlink pull). Map: the MSP
#     master's own store. This is the plane THIS FILE serves.
#
#   WHY THEY STAY SEPARATE. A PIM customer who is an MSP master runs its own
#   downstream fleet. Its rollout waves are ITS business, not the AutomateIT
#   operator's -- so the AutomateIT operator's ring assignment must not silently
#   dictate which template version a third party's managed tenants receive.
#   Same mechanism, two independently-owned maps.
#
#   🪤 A THIRD thing is also called "ring" in PIM and is NOT version selection at
#   all: `admin.Ring <= tenant.Ring` (pim.vw_AdminTenantTargets,
#   Select-PimDownlinkAdmins in PIM-Downlink.ps1) decides WHICH ADMINS REACH
#   WHICH TENANTS. That is ASSIGNMENT SCOPING. It is genuinely PIM's own, it is
#   unchanged by RING-1, and it is the "master-store assignment provider" RING-1
#   phase 1 item 3 refers to. Do not merge it into either plane above.
#
# PS 5.1 COMPATIBLE: no ?. / ??, no ternary. Note the `@()` discipline -- always
# wrap a VARIABLE, never a pipeline (`@(Get-Content ... | ConvertFrom-Json)` is a
# 1-element array under 5.1 and an N-element array under 7 -- that is BUG-26).
# =============================================================================

Set-StrictMode -Off

# ---------------------------------------------------------------------------
# VENDORED from Get-AitRingCapabilityDecision (sync/_AitRings.ps1).
# Keep behaviourally identical -- see the fork warning in the header.
# ---------------------------------------------------------------------------
function Get-PimRingCapabilityDecision {
    <#
    .SYNOPSIS
        PURE. Decide, for ONE solution/template, which capabilities may run.

    .DESCRIPTION
        Applies the two gates IN ORDER and reports every capability's outcome, so
        a caller (and the uplink) can always tell WHY something did not run:

          Run      -- declared, ring-approved, not blocked. Execute it.
          Held     -- declared but NOT in the ring's allow list. The operator has
                      not promoted this capability to this ring yet.
          Blocked  -- declared and ring-approved, but the CUSTOMER opted out.
          Refused  -- the customer tried to block a capability marked REQUIRED.
                      The block is IGNORED (honouring it would leave a broken
                      install) and surfaced so the manifest can be corrected.

    .PARAMETER Declared
        The solution's capabilities, from solution.deploy.json:
        @{ name = 'schema'; optional = $false }

    .PARAMETER RingAllow
        Capability names approved for this ring. $null means "the ring places no
        capability restriction". An EMPTY array means "nothing approved" and is
        deliberately NOT the same thing.

    .PARAMETER CustomerBlocked
        Capability names the customer opted out of, from their local manifest.

    .PARAMETER CoRequisites
        Gate 3, VENDORED from the platform 2026-08-07 (PLAT-03). Capability pairs the
        SOLUTION declares must move together, from its solution.deploy.json
        'coRequisiteCapabilities'. When one half runs and the other does not, the
        dependent half is DEMOTED to Held -- never the other force-promoted, because
        the operator is the one owner allowed to hold anything. Half a release is
        never applied. $null/empty => byte-identical behaviour to before.

        🔒 This WAS PIM-private detection (Test-PimCoRequisiteCapabilities, below).
        It is now a PLATFORM concept and PIM consumes it, per the RING-1 direction.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Declared,
        [Parameter()][AllowNull()][string[]]$RingAllow,
        [Parameter()][AllowNull()][string[]]$CustomerBlocked,
        [Parameter()][AllowNull()][object[]]$CoRequisites
    )

    $run     = New-Object System.Collections.Generic.List[string]
    $held    = New-Object System.Collections.Generic.List[string]
    $blocked = New-Object System.Collections.Generic.List[string]
    $refused = New-Object System.Collections.Generic.List[string]

    # $null (key absent) = no ring restriction. An EMPTY list = nothing approved.
    # "I have not said anything about capabilities" and "I approve none of them"
    # are different operator intents and must not collapse.
    $ringUnrestricted = ($null -eq $RingAllow)
    $blockSet = @($CustomerBlocked | Where-Object { $_ })

    foreach ($cap in @($Declared)) {
        if (-not $cap) { continue }
        $name = [string]$cap.name
        if (-not $name) { continue }
        $isOptional = [bool]$cap.optional

        # --- gate 1: the OPERATOR's ring allow-list -------------------------
        if (-not $ringUnrestricted -and ($blockSet -notcontains $name) -and (@($RingAllow) -notcontains $name)) {
            [void]$held.Add($name)
            continue
        }

        # --- gate 2: the CUSTOMER's block -----------------------------------
        # PLAT-04 (vendored 2026-08-07): only NOTED here. Recording Refused before the
        # ring check produced a capability that was Refused AND Held at once, and the
        # Refused half claimed "the block was ignored, it will run" about something that
        # was never going to run. Run/Held/Blocked are mutually exclusive OUTCOMES;
        # Refused is an advisory on a capability that IS running, i.e. a subset of Run.
        $refusedBlock = $false
        if ($blockSet -contains $name) {
            if (-not $isOptional) {
                $refusedBlock = $true
            } else {
                [void]$blocked.Add($name)
                continue
            }
        }

        # A required capability held by the ring is still held -- checked above.
        if (-not $ringUnrestricted -and (@($RingAllow) -notcontains $name)) {
            [void]$held.Add($name)
            continue
        }

        [void]$run.Add($name)
        if ($refusedBlock) { [void]$refused.Add($name) }
    }

    # --- gate 3: the SOLUTION's co-requisite pairs ---------------------------
    # Applied after both gates because it reasons about the OUTCOME, not about which
    # gate withheld the partner. Iterated to a fixed point so a chain resolves in one
    # call, bounded by the capability count.
    $coHeld = New-Object System.Collections.Generic.List[string]
    if (@($CoRequisites).Count) {
        for ($i = 0; $i -lt (@($Declared).Count + 1); $i++) {
            $changed = $false
            foreach ($rule in @($CoRequisites)) {
                if (-not $rule) { continue }
                $cap = [string]$rule.capability
                if (-not $cap -or ($run -notcontains $cap)) { continue }
                foreach ($needed in @($rule.requiresAlso)) {
                    $n = [string]$needed
                    if (-not $n -or ($run -contains $n)) { continue }
                    $why = if ($held -contains $n) { 'HELD by the ring' }
                           elseif ($blocked -contains $n) { 'BLOCKED by the customer' }
                           else { 'not approved' }
                    [void]$run.Remove($cap)
                    if ($held -notcontains $cap) { [void]$held.Add($cap) }
                    [void]$refused.Remove($cap)   # PLAT-04: Refused stays a subset of Run
                    [void]$coHeld.Add("'$cap' held: its co-requisite '$n' is not running ($why) -- promote '$n' to this ring as well")
                    $changed = $true
                    break
                }
            }
            if (-not $changed) { break }
        }
    }

    return [pscustomobject]@{
        Run     = $run.ToArray()
        Held    = $held.ToArray()
        Blocked = $blocked.ToArray()
        Refused = $refused.ToArray()
        CoRequisiteHeld = $coHeld.ToArray()
    }
}

# ---------------------------------------------------------------------------
# VENDORED from Resolve-AitRingAssignment (sync/_AitRings.ps1).
# ---------------------------------------------------------------------------
function Resolve-PimRingAssignment {
    <#
    .SYNOPSIS
        PURE. Which ring is this target in, for this solution/template?

    .DESCRIPTION
        🔒 Returns Assigned=$false when the target has no entry. That is the
        NON-BREAKING RULE: the caller must then behave exactly as it does today.
        Absence is NOT ring 3 and it is NOT an error.

    .PARAMETER DefaultRing
        Optional fleet-wide fallback. $null means unassigned targets keep today's
        behaviour. Set it ONLY when the whole fleet is ready to move at once.
    #>
    [CmdletBinding()]
    param(
        [Parameter()][AllowNull()][object]$Assignments,
        [Parameter(Mandatory)][string]$TenantId,
        [Parameter(Mandatory)][string]$Solution,
        [Parameter()][AllowNull()][object]$DefaultRing
    )

    $entry = $null
    if ($Assignments -and $TenantId) {
        foreach ($p in $Assignments.PSObject.Properties) {
            if ("$($p.Name)" -ieq "$TenantId") { $entry = $p.Value; break }
        }
    }

    $ring = $null
    if ($entry) {
        foreach ($p in $entry.PSObject.Properties) {
            if ("$($p.Name)" -ieq "$Solution") {
                if ($null -ne $p.Value -and $p.Value.PSObject.Properties.Name -contains 'ring') {
                    $ring = $p.Value.ring
                } else {
                    $ring = $p.Value    # allow the shorthand  "<name>": 2
                }
                break
            }
        }
    }

    if ($null -eq $ring -and $null -ne $DefaultRing) { $ring = $DefaultRing }

    if ($null -eq $ring -or "$ring" -eq '') {
        return [pscustomobject]@{ Assigned = $false; Ring = $null; Reason = 'no ring assigned -- keep current behaviour' }
    }
    return [pscustomobject]@{ Assigned = $true; Ring = [int]$ring; Reason = '' }
}

# ---------------------------------------------------------------------------
# VENDORED from Resolve-AitRelease (sync/_AitRings.ps1).
# ---------------------------------------------------------------------------
function Resolve-PimRingRelease {
    <#
    .SYNOPSIS
        PURE. Which VERSION is approved for a ring, on a channel?

    .DESCRIPTION
        ⚠️ A ring with NO promotion entry returns Approved=$false: the caller must
        HOLD. That is deliberately different from an UNASSIGNED target (which keeps
        today's behaviour) -- an assigned target whose ring has no approved version
        must NOT silently fall back to the latest. Otherwise a forgotten promotion
        looks exactly like success.
    #>
    [CmdletBinding()]
    param(
        [Parameter()][AllowNull()][object]$Promotions,
        [Parameter(Mandatory)][string]$Solution,
        [Parameter(Mandatory)][int]$Ring,
        [Parameter()][string]$Channel = 'internal'
    )

    $sol = $null
    if ($Promotions) {
        foreach ($p in $Promotions.PSObject.Properties) {
            if ("$($p.Name)" -ieq "$Solution") { $sol = $p.Value; break }
        }
    }
    if (-not $sol) {
        return [pscustomobject]@{ Approved = $false; Version = $null; Allow = $null; Reason = "no promotion entry for '$Solution'" }
    }

    $chan = $null
    foreach ($p in $sol.PSObject.Properties) {
        if ("$($p.Name)" -ieq "$Channel") { $chan = $p.Value; break }
    }
    if (-not $chan) {
        return [pscustomobject]@{ Approved = $false; Version = $null; Allow = $null; Reason = "'$Solution' has no '$Channel' channel" }
    }

    $slot = $null
    foreach ($p in $chan.PSObject.Properties) {
        if ("$($p.Name)" -eq "$Ring") { $slot = $p.Value; break }
    }
    if ($null -eq $slot) {
        return [pscustomobject]@{ Approved = $false; Version = $null; Allow = $null; Reason = "nothing promoted to ring $Ring for '$Solution' on '$Channel'" }
    }

    # Two accepted shapes: a bare version string, or { version, allow }.
    # A bare string means "this version, no capability restriction" -- Allow stays
    # $null, which the capability decision reads as "unrestricted".
    $version = $null; $allow = $null
    if ($slot -is [string]) {
        $version = [string]$slot
    } else {
        if ($slot.PSObject.Properties.Name -contains 'version') { $version = [string]$slot.version }
        if ($slot.PSObject.Properties.Name -contains 'allow')   { $allow = @($slot.allow) }
    }

    if (-not $version) {
        return [pscustomobject]@{ Approved = $false; Version = $null; Allow = $null; Reason = "ring $Ring entry for '$Solution' has no version (explicitly not promoted)" }
    }
    return [pscustomobject]@{ Approved = $true; Version = $version; Allow = $allow; Reason = '' }
}

# ---------------------------------------------------------------------------
# PLANE 2 -- the MSP master's own template ring gate.
# Composed from the VENDORED parts above, so plane 2 behaves identically to
# plane 1 by construction rather than by a second implementation.
# ---------------------------------------------------------------------------
function Get-PimTemplateRingPlan {
    <#
    .SYNOPSIS
        PURE. The whole ring decision for ONE template on ONE managed tenant, in
        one object -- the S5/S6 managed downlink's version gate.

    .DESCRIPTION
        This is PLANE 2 (see the file header): a PIM MSP MASTER deciding which
        signed baseline TEMPLATE VERSION each of ITS managed tenants may pull.
        It is NOT the AutomateIT operator's code-version gate (plane 1), and the
        two maps are owned by different parties.

        Returns the framework's action vocabulary unchanged, so an uplink can
        report both planes with one schema:

          track-current  -- unassigned. Behave EXACTLY as today (non-breaking).
          hold           -- assigned, but nothing approved for that ring.
          update         -- assigned and approved. Pull Version, run Run[].

        🔓 NOTE ON HASHING. Plane 1 hashes tenant ids because its map travels
        inside the snapshot EVERY customer downloads, so a plaintext id would
        disclose the customer list to every other customer. Plane 2's map lives in
        the MSP master's OWN store and is never shipped to a third party, so a
        plain tenant id is correct here -- the master already knows its own
        managed tenants. Do not copy the hashing across "for consistency": it
        would only make the master's own map unreadable to its owner.

    .PARAMETER Template
        The template/baseline name being gated (plane 1's "solution" slot).

    .PARAMETER TenantId
        The MANAGED tenant id. Plain, not hashed -- see above.

    .PARAMETER Declared
        The template's declared capabilities: @{ name = '...'; optional = $bool }.

    .PARAMETER CustomerBlocked
        Capabilities the MANAGED tenant has opted out of.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Template,
        [Parameter(Mandatory)][string]$TenantId,
        [Parameter()][AllowNull()][object]$Assignments,
        [Parameter()][AllowNull()][object]$Promotions,
        [Parameter()][AllowEmptyCollection()][object[]]$Declared = @(),
        [Parameter()][AllowNull()][string[]]$CustomerBlocked,
        [Parameter()][string]$Channel = 'managed',
        [Parameter()][AllowNull()][object]$DefaultRing
    )

    $assign = Resolve-PimRingAssignment -Assignments $Assignments -TenantId $TenantId `
                  -Solution $Template -DefaultRing $DefaultRing
    if (-not $assign.Assigned) {
        return [pscustomobject]@{
            Plane = 'template'; Template = $Template; Action = 'track-current'
            Ring = $null; Version = $null; Capabilities = $null; Reason = $assign.Reason
        }
    }

    $rel = Resolve-PimRingRelease -Promotions $Promotions -Solution $Template `
               -Ring $assign.Ring -Channel $Channel
    if (-not $rel.Approved) {
        return [pscustomobject]@{
            Plane = 'template'; Template = $Template; Action = 'hold'
            Ring = $assign.Ring; Version = $null; Capabilities = $null; Reason = $rel.Reason
        }
    }

    $caps = Get-PimRingCapabilityDecision -Declared $Declared -RingAllow $rel.Allow -CustomerBlocked $CustomerBlocked
    return [pscustomobject]@{
        Plane = 'template'; Template = $Template; Action = 'update'
        Ring = $assign.Ring; Version = $rel.Version; Capabilities = $caps; Reason = ''
    }
}

# ---------------------------------------------------------------------------
# 🔁 NO LONGER PIM-SPECIFIC. Promoted to the platform 2026-08-07 (PLAT-03): the
# rule now lives in sync/_AitRings.ps1 as gate 3 of Get-AitRingCapabilityDecision
# and is ENFORCED there (the dependent capability is demoted to Held, and a plan
# with nothing left to run becomes Action='hold'), rather than merely detected.
#
# This function is KEPT, and is now a REPORTER over the enforced result, for two
# reasons that still hold on a customer tree:
#   1. it is the only way to explain a decision that came from a map PIM cannot
#      see (tests/Test-PimDeployContract.ps1 reads promotion maps directly), and
#   2. gate 3 is inert when a caller passes no -CoRequisites, so a PIM code path
#      that resolves capabilities WITHOUT the contract still needs the check.
# Its verdict must AGREE with gate 3; Test-PimDeployContract.ps1 asserts that.
# ---------------------------------------------------------------------------
function Test-PimCoRequisiteCapabilities {
    <#
    .SYNOPSIS
        PURE. Does a capability decision violate a co-requisite rule -- i.e. did
        one half of a pair that must move together end up Run while the other
        ended up Held?

    .DESCRIPTION
        🔒 WHY THIS EXISTS. The customer-block gate REFUSES a block on a REQUIRED
        capability, so a customer cannot brick their own install. The OPERATOR's
        ring allow-list has NO such protection, and correctly so -- the operator
        must be able to hold anything. But that leaves a real hole for PIM:

          allow: [ 'code' ]   ->   Run: [code]   Held: [schema, ...]

        which deploys new engine/Manager code against an UN-UPGRADED database.
        That is the exact skew 'schema' is marked required to prevent, arriving
        through the operator's gate instead of the customer's. Measured against
        the shipped sync/release-map.sample.json on 2026-08-07, whose PIM entry
        promotes ring 2 with allow:['code'] and produces precisely that state.

        This is a PIM invariant, declared in PIM's solution.deploy.json under
        'coRequisiteCapabilities'. It is reported, never silently repaired: the
        fix is a one-line promotion-map edit by the operator, and PIM must not
        pretend a half-approved release is a whole one.

    .PARAMETER Decision
        A Get-PimRingCapabilityDecision result (Run/Held/Blocked/Refused).

    .PARAMETER CoRequisites
        From solution.deploy.json: @{ capability = 'code'; requiresAlso = @('schema') }

    .OUTPUTS
        @{ ok = $bool; violations = string[] }
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Decision,
        [Parameter()][AllowEmptyCollection()][object[]]$CoRequisites = @()
    )

    $violations = New-Object System.Collections.Generic.List[string]
    if ($Decision) {
        $running = @($Decision.Run)
        foreach ($rule in @($CoRequisites)) {
            if (-not $rule) { continue }
            $cap = [string]$rule.capability
            if (-not $cap) { continue }
            if ($running -notcontains $cap) { continue }   # not running => nothing to co-require
            foreach ($needed in @($rule.requiresAlso)) {
                $n = [string]$needed
                if (-not $n) { continue }
                if ($running -notcontains $n) {
                    $violations.Add("'$cap' will run but its co-requisite '$n' will not (it is $(
                        if (@($Decision.Held) -contains $n) { 'HELD by the ring' }
                        elseif (@($Decision.Blocked) -contains $n) { 'BLOCKED by the customer' }
                        else { 'not approved' }
                    )) -- promote '$n' to this ring as well")
                }
            }
        }
    }

    return [pscustomobject]@{
        ok         = ($violations.Count -eq 0)
        violations = $violations.ToArray()
    }
}
