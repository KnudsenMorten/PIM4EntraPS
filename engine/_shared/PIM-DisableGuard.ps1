<#
  PIM4EntraPS -- account-disable SAFETY GUARDS (circuit breaker).

  WHY THIS EXISTS (incident 2026-06-15)
  -------------------------------------
  The REST 'Admins' engine provider (New-PimAdminsProvider) reads LIVE = the WHOLE
  tenant user population and, under -Mode Full -Prune, treats every live user NOT
  present in the desired Account-Definitions-Admins set as a "remove" -> it sets
  accountEnabled=$false. A run whose desired admin set was read EMPTY/WRONG (e.g. a
  config-key rename leaving the SQL entity unresolved) therefore concluded "disable
  (almost) everything it scanned" and disabled the entire scanned population.

  These guards make a mass account-disable IMPOSSIBLE without a deliberate, positively
  confirmed desired set, a sane blast radius, and an explicit opt-in:

    GUARD 1  Never disable on an empty/unresolved desired set.
             A disable requires a POSITIVELY-confirmed desired set. If the desired
             set is null, empty, or could not be positively resolved (the SQL read
             threw / the store was unreachable), the disable pass ABORTS fail-hard.
             This is the same intent as the create engine's empty-store preflight,
             extended to the disable path (which previously had no such gate of its
             own once a provider opted out of the generic empty-desired prune guard).

    GUARD 2  Mass-disable circuit breaker.
             Refuse to disable when the number OR the % of accounts to disable in a
             single run exceeds a conservative threshold. On a trip the WHOLE disable
             pass aborts (disable NOTHING -- never a partial mass-disable), logs loudly
             and surfaces an alert. Thresholds are configurable; defaults are safe.

    GUARD 3  Feature OFF by default.
             The account-disable / offboarding capability is DISABLED unless an
             explicit, persisted opt-in is set. With it off, zero disables ever run.

  All three are PURE decision functions (no I/O) so they are fully unit-testable and
  identical offline and live. PS 5.1-safe: no ?./??, no ternary, null-guarded.
#>

Set-StrictMode -Off

# IMP-03: the one visible way to swallow a non-fatal error (loaded defensively --
# this file is dot-sourced standalone by its own suite).
if (-not (Get-Command Write-PimSwallowed -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot 'PIM-Swallow.ps1') }

# =============================================================================
# SEC-07 -- ONE reader for every safety knob.
#
# The hosted engine is configured ENTIRELY by container environment variables
# (Setup-PimContainers.ps1 sets PIM_HOSTED / PIM_StorageBackend / PIM_SqlServer /
# PIM_SqlDatabase / PIM_TenantId that way, and nothing else supplies these names:
# Invoke-PimEngineCore hydrates five unrelated globals, does not load the legacy
# `PIM4EntraPS.custom.ps1`, and Import-PimSettingsFromStore lands pim.Settings in
# $global:PIM_NamingConventions).
#
# Two knobs in THIS file already read the environment -- PIM_TestTenantIds, which
# decides where destructive features default ON, and PIM_BREAKGLASS_ACCOUNTS. The
# others did not, so in the deployed fleet an operator could not turn the
# account-disable feature OFF and could not LOWER a cap: the setting was accepted,
# reported as available, and silently ignored. That is IMP-01's lesson repeating --
# a cap that can be neutered is not a cap, and a switch that can be ignored is not a
# switch. Measured live by the TEST-11 matrix (case D8): with
# PIM_AccountDisableEnabled=false set as an env var, the guard reported
# `tripped=mass-disable` (a DIFFERENT guard happening to catch the pass) instead of
# `feature-off`.
#
# Precedence is $global: first, then the environment, then the built-in default --
# so an in-process caller (the Manager, a test) still wins over ambient config, and
# nothing that worked before changes.
# =============================================================================
function Get-PimSafetyKnob {
    <#
      PURE-ish. Resolve one safety knob: $global:<Name> -> $env:<EnvName|Name> -> $null.
      $false is a VALUE, not "unset" -- only $null / empty / whitespace fall through,
      or an explicit opt-OUT would be indistinguishable from no setting at all.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Name, [string]$EnvName)
    $g = Get-Variable -Name $Name -Scope Global -ValueOnly -ErrorAction SilentlyContinue
    if ($null -ne $g -and "$g".Trim() -ne '') { return $g }
    $en = if ("$EnvName".Trim()) { "$EnvName".Trim() } else { $Name }
    $e = [Environment]::GetEnvironmentVariable($en, 'Process')
    if ($null -ne $e -and "$e".Trim() -ne '') { return $e }
    return $null
}

# The complete knob inventory. Test-PimSafetyKnobEnvFallback (tests/Test-PimSafetyKnobs.ps1)
# asserts that EVERY entry here is honoured from the environment, so a knob cannot be
# added later without one.
function Get-PimSafetyKnobNames {
    [CmdletBinding()] param()
    @(
        @{ name = 'PIM_AccountDisableEnabled'; env = 'PIM_AccountDisableEnabled'; what = 'the account-disable opt-in/opt-out' }
        @{ name = 'PIM_DisableMaxCount';       env = 'PIM_DisableMaxCount';       what = 'G2 absolute blast-radius cap' }
        @{ name = 'PIM_DisableMaxPercent';     env = 'PIM_DisableMaxPercent';     what = 'G2 percentage blast-radius cap' }
        @{ name = 'PIM_RemoveMaxCount';        env = 'PIM_RemoveMaxCount';        what = 'G4 universal removal budget' }
        # 🔴 71.22 -- PIM_RemoveUnmanagedAdmins IS GONE. It gated a capability that no longer
        # exists: PIM never disables an account merely because it is absent from the desired set
        # (operator, 2026-09-16). Nothing reads the knob, so listing it would advertise a switch
        # that does nothing -- and a switch that does nothing is how it comes back.
        @{ name = 'PIM_TestTenantIds';         env = 'PIM_TestTenantIds';         what = 'which tenants classify as test' }
        @{ name = 'PIM_BreakGlassAccounts';    env = 'PIM_BREAKGLASS_ACCOUNTS';   what = 'accounts that may never be disabled' }
        @{ name = 'PIM_AlertRecipient';        env = 'PIM_AlertRecipient';        what = 'who is paged when a guard trips' }
    )
}

# ---- environment class (operator decision: test vs protected) ----------------
# Refinement of the post-incident flat OFF-by-default (PR #76): a flat OFF blocks
# legitimate testing in true test tenants. We instead make the destructive feature
# flags ENVIRONMENT-AWARE while keeping the real (protected) tenant safe and the
# catastrophe guards (G1 empty-desired + G2 mass-disable breaker) ALWAYS ON.
#
#   env = test       -> the CONNECTED tenant id is in $global:PIM_TestTenantIds.
#                       Destructive features DEFAULT ON (operator is in a sandbox).
#   env = protected  -> anything else, INCLUDING the real internal tenant and an
#                       unknown/absent tenant id. Destructive features DEFAULT OFF.
#
# An EXPLICIT operator setting (true/false) on a feature flag ALWAYS overrides the
# env default in either direction. The env class only decides the DEFAULT used when
# the flag is left unset. Layer 1 (env=protected default OFF) + layer 2 (explicit
# opt-in still possible) + layer 3 (always-on breaker) make a silent real-tenant
# mass-disable impossible.

function Get-PimTestTenantIds {
    # The list of tenant ids classified as TEST (destructive default ON).
    #
    # SEC-02: this list used to SHIP with two real tenant GUIDs baked in. That is a leak
    # of real identifiers into a tree that is mirrored publicly (solution.publish.json has
    # publishReady:true), and worse, it is the list that decides where destructive features
    # default ON -- so the security posture of a deployment was set by a literal published
    # to the world. The real values now live only in `internal/` (stripped at publish) and
    # are supplied at runtime.
    #
    # The built-in default is now EMPTY, which is the fail-SAFE direction: with no list
    # configured, no tenant classifies as 'test', so Resolve-PimEnvironmentClass returns
    # 'protected' for everything and destructive features default OFF. A test tenant must
    # be named deliberately, never inherited from shipped source.
    #
    # Configure via $global:PIM_TestTenantIds or $env:PIM_TestTenantIds (string or array;
    # comma/semicolon/whitespace separated).
    $v = Get-PimSafetyKnob -Name 'PIM_TestTenantIds'
    if ($null -eq $v) { return @() }
    $list = @()
    foreach ($x in @($v)) {
        if ($null -eq $x) { continue }
        foreach ($p in ("$x" -split '[,;\s]+')) { $t = "$p".Trim(); if ($t) { $list += $t.ToLowerInvariant() } }
    }
    return $list
}

function Resolve-PimEnvironmentClass {
    # Classify the CONNECTED tenant. Returns 'test' when its id is in the test-tenant
    # list, otherwise 'protected' (the SAFE default -- real tenant, unknown, or absent).
    # $TenantId override is for tests / explicit callers; otherwise the connected tenant
    # id is resolved the canonical way (Get-PimTenantId -> $global:/$env: -> $null).
    [CmdletBinding()]
    param([string]$TenantId = $null)
    $tid = $TenantId
    if (-not $tid) {
        if (Get-Command Get-PimTenantId -ErrorAction SilentlyContinue) { $tid = Get-PimTenantId }
        if (-not $tid) { $tid = "$($global:PIM_TenantId)" }
    }
    $tid = "$tid".Trim().ToLowerInvariant()
    if (-not $tid) { return 'protected' }            # unknown/absent -> safe default
    $testIds = @(Get-PimTestTenantIds | ForEach-Object { "$_".Trim().ToLowerInvariant() })
    if ($testIds -contains $tid) { return 'test' }
    return 'protected'
}

function Resolve-PimDestructiveFeatureDefault {
    # The env-driven DEFAULT for a destructive feature flag when the operator has NOT
    # set it explicitly. ON in a test tenant, OFF in a protected one. Pure boolean.
    [CmdletBinding()]
    param([string]$TenantId = $null)
    return ((Resolve-PimEnvironmentClass -TenantId $TenantId) -eq 'test')
}

function Test-PimExplicitFlagValue {
    # Interpret a possibly-set feature flag value. Returns:
    #   $true  -> explicitly truthy
    #   $false -> explicitly falsy
    #   $null  -> NOT explicitly set (null/empty/whitespace) => caller uses env default
    # Keeps the same truthy vocabulary used across the engine. PS 5.1-safe.
    [CmdletBinding()]
    param([object]$Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [bool]) { return [bool]$Value }
    $s = "$Value".Trim()
    if (-not $s) { return $null }
    $sl = $s.ToLowerInvariant()
    if ($sl -in @('1','true','yes','y','on','enable','enabled'))  { return $true }
    if ($sl -in @('0','false','no','n','off','disable','disabled')) { return $false }
    # any other non-empty string: treat as NOT a clear opt-in (safe), but it WAS set,
    # so honour it as falsy rather than silently flipping to the env default.
    return $false
}

# ---- tunables (safe defaults; override via $global:* or config) --------------
# These describe the maximum BLAST RADIUS a single run may disable. Conservative on
# purpose: a real offboarding disables a handful of accounts, never dozens/hundreds.
# IMP-01: the overrides below are CLAMPED. §22 states as a rule "Do NOT raise the caps or
# auto-enable the opt-in to 'make a run go through'" -- but until now nothing in code
# enforced it, so `$global:PIM_DisableMaxCount = 100000` silently neutered G2 while the
# guard still reported itself as active. A cap that can be raised without limit is not a
# circuit breaker, it is a suggestion. The ceilings are deliberately generous enough for
# any legitimate offboarding batch and far below "the whole tenant".
$script:PimDisableMaxCountCeiling   = 50
$script:PimDisableMaxPercentCeiling = 25

function Get-PimDisableMaxCount {
    # Absolute cap: refuse a run that would disable MORE than this many accounts.
    # CmdletBinding so a caller can route/suppress the override warnings below
    # (-WarningAction / -WarningVariable); without it those are silently unbound.
    [CmdletBinding()] param()
    $v = Get-PimSafetyKnob -Name 'PIM_DisableMaxCount'      # SEC-07: $global: then $env:
    if ($null -ne $v -and "$v" -match '^\d+$') {
        $req = [int]$v
        if ($req -gt $script:PimDisableMaxCountCeiling) {
            Write-Warning ("PIM_DisableMaxCount={0} exceeds the hard ceiling {1} -- CLAMPED to {1}. The mass-disable breaker cannot be raised past its ceiling." -f $req, $script:PimDisableMaxCountCeiling)
            return $script:PimDisableMaxCountCeiling
        }
        Write-Warning ("PIM_DisableMaxCount override IN EFFECT: {0} (default 5). The mass-disable breaker is running wider than standard." -f $req)
        return $req
    }
    return 5
}
function Get-PimDisableMaxPercent {
    # Relative cap (% of the SCANNED live population): refuse a run that would disable
    # MORE than this fraction of everything it looked at. 0 disables this dimension.
    [CmdletBinding()] param()
    $v = Get-PimSafetyKnob -Name 'PIM_DisableMaxPercent'    # SEC-07: $global: then $env:
    if ($null -ne $v -and "$v" -match '^\d+(\.\d+)?$') {
        $req = [double]$v
        if ($req -gt $script:PimDisableMaxPercentCeiling) {
            Write-Warning ("PIM_DisableMaxPercent={0} exceeds the hard ceiling {1} -- CLAMPED to {1}." -f $req, $script:PimDisableMaxPercentCeiling)
            return [double]$script:PimDisableMaxPercentCeiling
        }
        Write-Warning ("PIM_DisableMaxPercent override IN EFFECT: {0} (default 10)." -f $req)
        return $req
    }
    return 10
}

function Test-PimAccountDisableEnabled {
    # GUARD 3 -- the opt-in, now ENVIRONMENT-AWARE.
    #   * An explicit -Override (tests / callers) ALWAYS wins.
    #   * Else an explicitly-set $global:PIM_AccountDisableEnabled (true/false) wins.
    #   * Else the ENV DEFAULT: ON in a test tenant, OFF in a protected one.
    # This keeps the real (protected) tenant OFF-by-default (layer 1) while letting a
    # true test tenant exercise the path without a manual flag -- and an operator can
    # still explicitly flip it either way (layer 2). The catastrophe guards (G1/G2)
    # remain ALWAYS ON regardless of env. $TenantId override is for tests.
    [CmdletBinding()]
    param([object]$Override = $null, [string]$TenantId = $null)
    if ($null -ne $Override) {
        $ov = Test-PimExplicitFlagValue -Value $Override
        if ($null -ne $ov) { return [bool]$ov }
    }
    # SEC-07: $global: then $env:. Before this, an operator's explicit opt-OUT set on the
    # container app was accepted and silently ignored -- the env default decided instead.
    $explicit = Test-PimExplicitFlagValue -Value (Get-PimSafetyKnob -Name 'PIM_AccountDisableEnabled')
    if ($null -ne $explicit) { return [bool]$explicit }
    return [bool](Resolve-PimDestructiveFeatureDefault -TenantId $TenantId)
}

function Test-PimDesiredSetResolved {
    # GUARD 1 (input half) -- was the desired set POSITIVELY resolved? A disable may
    # proceed only against a desired set we are sure about. Returns $false when the set
    # is null, empty, or was flagged unresolved (a SQL read that errored). $Resolved is
    # the explicit "the read succeeded" signal the caller passes from Get-PimDesiredRows;
    # when omitted we fall back to "non-empty == resolved".
    [CmdletBinding()]
    param([object[]]$Desired = @(), [Nullable[bool]]$Resolved = $null)
    $count = @($Desired | Where-Object { $null -ne $_ }).Count
    if ($null -ne $Resolved -and -not $Resolved) { return $false }
    return ($count -gt 0)
}

function Test-PimMassDisableSafe {
    # GUARD 2 -- blast-radius check. Returns the decision object for a disable pass.
    #   abort  = $true  -> DO NOT disable anything this run (caller must skip ALL removes)
    #   reason = why
    # Trips when the proposed disable count exceeds the absolute cap OR the % cap.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][int]$ToDisable,   # how many accounts this run would disable
        [Parameter(Mandatory)][int]$Scanned,     # size of the scanned live population
        [int]$MaxCount = -1,
        [double]$MaxPercent = -1
    )
    if ($MaxCount   -lt 0) { $MaxCount   = Get-PimDisableMaxCount }
    if ($MaxPercent -lt 0) { $MaxPercent = Get-PimDisableMaxPercent }
    if ($ToDisable -le 0) {
        return [pscustomobject]@{ abort=$false; reason='nothing to disable'; toDisable=$ToDisable; scanned=$Scanned; maxCount=$MaxCount; maxPercent=$MaxPercent }
    }
    if ($ToDisable -gt $MaxCount) {
        return [pscustomobject]@{ abort=$true; reason=("would disable $ToDisable accounts (> absolute cap $MaxCount)"); toDisable=$ToDisable; scanned=$Scanned; maxCount=$MaxCount; maxPercent=$MaxPercent }
    }
    if ($MaxPercent -gt 0 -and $Scanned -gt 0) {
        $pct = (100.0 * $ToDisable / $Scanned)
        if ($pct -gt $MaxPercent) {
            return [pscustomobject]@{ abort=$true; reason=("would disable $ToDisable of $Scanned scanned accounts ({0:N1}% > cap {1}%)" -f $pct, $MaxPercent); toDisable=$ToDisable; scanned=$Scanned; maxCount=$MaxCount; maxPercent=$MaxPercent }
        }
    }
    return [pscustomobject]@{ abort=$false; reason='within blast-radius limits'; toDisable=$ToDisable; scanned=$Scanned; maxCount=$MaxCount; maxPercent=$MaxPercent }
}

function Test-PimDisablePassAllowed {
    # The single decision the engine asks before APPLYING any account-disable removals.
    # Composes all three guards. Returns:
    #   { allowed=[bool]; abort=[bool]; reason; tripped=<which guard>; ...blast-radius fields }
    # allowed=$true ONLY when: the feature is opted in (G3) AND the desired set is
    # positively resolved (G1) AND the blast radius is within limits (G2). Otherwise the
    # WHOLE disable pass must be skipped -- never a partial mass-disable.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][int]$ToDisable,
        [Parameter(Mandatory)][int]$Scanned,
        [object[]]$Desired = @(),
        [Nullable[bool]]$DesiredResolved = $null,
        [object]$FeatureOverride = $null,
        [int]$MaxCount = -1,
        [double]$MaxPercent = -1,
        # BUG-03: the tenant the decision is made AGAINST. Previously this function had no
        # -TenantId at all, so it always resolved the tenant from Get-PimTenantId /
        # $global:PIM_TenantId while callers reported an environment class computed from
        # their OWN -TenantId. A sweep invoked with an explicit -TenantId could therefore
        # print environment=test while the guard had actually decided against the ambient
        # (or absent) tenant and applied the protected default -- a safety readout that
        # disagrees with the decision it describes. Forwarded to G3 below, and echoed back
        # as .tenantId/.environment so the caller reports the class the guard USED.
        [string]$TenantId = $null
    )
    $envUsed = if (Get-Command Resolve-PimEnvironmentClass -ErrorAction SilentlyContinue) { Resolve-PimEnvironmentClass -TenantId $TenantId } else { 'protected' }
    # G3: feature opt-in
    if (-not (Test-PimAccountDisableEnabled -Override $FeatureOverride -TenantId $TenantId)) {
        return [pscustomobject]@{ allowed=$false; abort=$true; tripped='feature-off'; reason='account-disable is OFF (opt-in required: set PIM_AccountDisableEnabled)'; toDisable=$ToDisable; scanned=$Scanned; tenantId=$TenantId; environment=$envUsed }
    }
    # G1: positively-resolved, non-empty desired set
    if (-not (Test-PimDesiredSetResolved -Desired $Desired -Resolved $DesiredResolved)) {
        return [pscustomobject]@{ allowed=$false; abort=$true; tripped='empty-desired'; reason='desired set is empty/unresolved -- refusing to disable (a disable requires a positively-confirmed desired set)'; toDisable=$ToDisable; scanned=$Scanned; tenantId=$TenantId; environment=$envUsed }
    }
    # G2: blast radius
    $mass = Test-PimMassDisableSafe -ToDisable $ToDisable -Scanned $Scanned -MaxCount $MaxCount -MaxPercent $MaxPercent
    if ($mass.abort) {
        return [pscustomobject]@{ allowed=$false; abort=$true; tripped='mass-disable'; reason=("circuit breaker: " + $mass.reason); toDisable=$ToDisable; scanned=$Scanned; maxCount=$mass.maxCount; maxPercent=$mass.maxPercent; tenantId=$TenantId; environment=$envUsed }
    }
    return [pscustomobject]@{ allowed=$true; abort=$false; tripped=$null; reason='ok'; toDisable=$ToDisable; scanned=$Scanned; maxCount=$mass.maxCount; maxPercent=$mass.maxPercent; tenantId=$TenantId; environment=$envUsed }
}

# =============================================================================
# EXPLICIT per-row disables (v1 parity, operator 2026-09-12: "we cannot leave customers on
# pim v1 in a worse situation going to pim v2").
#
# The guards above were built for the INFERRED disable: "this live admin is not in my desired
# set, so disable it" -- the path that disabled 53 users on 2026-06-15. A row that SAYS
# AccountStatus=Disabled / Revoked, or carries a past AutoDisableDate, is a different thing: the
# operator asked for it, by name, on that row. v1 honoured it on every run with no opt-in, and a
# kill switch that is OFF by default is not a kill switch -- a revoked admin would stay usable.
#
# So an explicit disable keeps G1 (the desired set must be positively resolved) and G2's
# ABSOLUTE cap (a bulk "set AccountStatus" edit across many rows still trips it), but:
#   * G3 defaults ON for it. An EXPLICIT PIM_AccountDisableEnabled=false still wins (SEC-07: a
#     switch that can be ignored is not a switch), so an operator can still turn it off.
#   * G2's PERCENTAGE dimension is not applied. It measures "share of the scanned population",
#     which is the right signal for an inferred removal and the wrong one here: in an 8-admin
#     tenant disabling ONE named admin is 12.5% and would trip the 10% cap on every run.
# =============================================================================
function Resolve-PimExplicitDisableOverride {
    # $true when the account-disable knob is UNSET (explicit per-row disables are on by
    # default); $null when the operator set it either way, so G3 reads their value.
    [CmdletBinding()] param()
    $explicit = Test-PimExplicitFlagValue -Value (Get-PimSafetyKnob -Name 'PIM_AccountDisableEnabled')
    if ($null -eq $explicit) { return $true }
    return $null
}

function Test-PimExplicitDisablePassAllowed {
    # The decision for a pass of EXPLICIT per-row disables (kill switch, offboarding). Same
    # return shape as Test-PimDisablePassAllowed -- it IS that function, with the two
    # differences documented above.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][int]$ToDisable,
        [Parameter(Mandatory)][int]$Scanned,
        [object[]]$Desired = @(),
        [Nullable[bool]]$DesiredResolved = $null,
        [int]$MaxCount = -1,
        [string]$TenantId = $null
    )
    return (Test-PimDisablePassAllowed -ToDisable $ToDisable -Scanned $Scanned -Desired $Desired -DesiredResolved $DesiredResolved `
                -FeatureOverride (Resolve-PimExplicitDisableOverride) -MaxCount $MaxCount -MaxPercent 0 -TenantId $TenantId)
}

# =============================================================================
# BUG-12 -- WHICH ACCOUNTS MAY THE ADMINS SCOPE EVEN CONSIDER?
#
# The root cause of the 2026-06-15 incident, still present until 2026-08-06: the
# Admins provider's GetLive was `/users` with NO filter -- the WHOLE tenant user
# population -- while GetDesired is the admin definitions. Measured on the live
# tenant: 79 users returned, of which 13 were admin accounts and 66 were ordinary
# users (59 enabled). So the provider asked "which of these 79 is not one of my 8
# admins?" and answered 71. The incident was closed with guards; the MODEL that
# produced it was not changed.
#
# The guards cannot fix this because they are blast-radius limiters, not
# correctness controls: a tenant with 50 users of which 47 are defined admins
# yields 3 removals -- under every threshold -- and disables 3 real people
# silently. Small tenants get the LEAST protection.
#
# The fix is to make an ordinary user impossible to classify as a removal:
# restrict the live population to ADMIN ACCOUNTS, by the naming convention the
# solution already owns (s17, config-driven, per-tenant overridable).
#
# FAILS CLOSED. If no admin naming prefix can be resolved we THROW rather than
# scanning everything -- an unfiltered fallback is exactly the defect. (Note the
# legacy Graph-module helper Get-PimAdminsFiltered does fall back to
# `Get-MgUser -All`; that fallback must never be copied here.)
# =============================================================================
# --- BUG-14 / IMP-39: break-glass, available to the ENGINE ---------------------------
# BUG-14: these existed only in PIM-ApprovalGate.ps1, which the REST engine does NOT load -- so the
# path that actually sets accountEnabled=$false had no break-glass exclusion at all.
# IMP-39 (§33.28): the list now lives in SQL (pim.Settings['BreakGlassAccounts'], unioned with the
# legacy global/env), and the ONE definition of Get-PimBreakGlassIdentifiers / Test-PimRowIsBreakGlass
# is PIM-BreakGlassAccounts.ps1. An unreadable store makes EVERY row read as break-glass (fail safe).
if (-not (Get-Command Get-PimBreakGlassAccountList -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot 'PIM-BreakGlassAccounts.ps1') }

function Get-PimUpnLocalPart {
    # BUG-13. The identity-bearing half of a UPN, lower-cased. Admin accounts are named
    # by convention (Admin-MOK-ID); the DOMAIN is a tenant detail, and a tenant
    # legitimately holds admins across several verified domains.
    [CmdletBinding()] param([string]$Upn)
    $s = "$Upn".Trim()
    if (-not $s) { return '' }
    $i = $s.IndexOf('@')
    if ($i -lt 0) { return $s.ToLowerInvariant() }
    return $s.Substring(0, $i).ToLowerInvariant()
}

function Select-PimDisableRemovals {
    <#
      BUG-13 + BUG-14 + 🔴 71.22. Classify a disable scope's proposed account removals.
      PURE. Returns @{ remove; breakGlass; unmanaged; attributable; reportOnly; reason }.

      🔴 71.22 -- `remove` IS ALWAYS EMPTY. PIM never disables a user account merely because
      it is absent from the desired set (operator, 2026-09-16: "i dont like flow 3 and that
      should be removed"). The three classes are now REPORTS, not decisions:
        * BREAK-GLASS (BUG-14) -- the account you reach for when everything else is locked
          out. By design absent from normal definitions, so it landed in the removal set.
        * ATTRIBUTABLE (BUG-13) -- the identity IS desired but the KEY did not match (a
          second verified domain). Matching is domain-independent (local part); anything
          still reported here is a key defect to fix.
        * UNMANAGED -- genuinely absent from the desired set. Reported so the operator can
          SEE it. Disabling it is a human decision, taken on the row itself
          (AccountStatus=Disabled, or an AutoDisableDate) -- never inferred from absence.

      Group and membership pruning is a DIFFERENT path and is unaffected: this function only
      ever saw ACCOUNTS (isAccountDisable scopes).
    #>
    [CmdletBinding()]
    param(
        [object[]]$Remove = @(),
        [object[]]$Desired = @(),
        [string]$UpnProperty = 'userPrincipalName'
    )
    $bg = @()
    if (Get-Command Get-PimBreakGlassIdentifiers -ErrorAction SilentlyContinue) { $bg = @(Get-PimBreakGlassIdentifiers) }

    # Desired identities, domain-independent.
    $desiredLocals = @{}
    foreach ($d in @($Desired)) {
        if ($null -eq $d) { continue }
        foreach ($k in 'userPrincipalName','UserPrincipalName','UPN','upn','UserName','Username') {
            $p = $d.PSObject.Properties[$k]
            if ($p -and "$($p.Value)".Trim()) {
                $lp = Get-PimUpnLocalPart -Upn "$($p.Value)"
                if ($lp) { $desiredLocals[$lp] = $true }
            }
        }
    }
    # 🔴 71.22 -- "ABSENT FROM THE DESIRED SET" IS NO LONGER A REASON TO TOUCH AN ACCOUNT.
    # Operator, 2026-09-16: "i dont like flow 3 and that should be removed."
    # The MSP reading (2026-08-06) was that the desired set is AUTHORITATIVE, so an admin who
    # had left was SUPPOSED to be deprovisioned here -- which made "not in my CSV" a disable
    # instruction, guarded only by opt-in + breaker + budget. Every one of those guards is a
    # ceiling on how MANY accounts get disabled, not a check on WHETHER the reason is sound; a
    # partial read, a renamed domain or a half-loaded desired set all look identical to "they
    # left". The capability is REMOVED, not defaulted off, along with its PIM_RemoveUnmanagedAdmins
    # knob -- a knob is one config mistake away from being back on.
    # What remains is the REPORT: the run still says exactly which live admin accounts are not in
    # the desired set, because seeing them is useful. Acting on them is a human decision, made
    # through the row (AccountStatus / AutoDisableDate), which is flows 1 and 2 -- both untouched.
    # tests/Test-PimNoUnmanagedDisable.ps1 fails the suite if this path ever comes back.
    $keep = New-Object System.Collections.Generic.List[object]
    $bgHit = New-Object System.Collections.Generic.List[string]
    $unmanaged = New-Object System.Collections.Generic.List[string]
    $attributable = New-Object System.Collections.Generic.List[string]
    foreach ($r in @($Remove)) {
        if ($null -eq $r) { continue }
        $row = if ($r.PSObject.Properties['live'] -and $r.live) { $r.live } else { $r }
        $upn = "$($row.$UpnProperty)"
        if (-not $upn) { $upn = "$($r.key)" }

        # 1. BREAK-GLASS -- never removable, no override (BUG-14).
        if ($bg.Count -gt 0 -and (Test-PimRowIsBreakGlass -Row $row -Identifiers $bg)) { [void]$bgHit.Add($upn); continue }

        # 2. ATTRIBUTABLE to a desired row -- this account IS managed, so it must not be
        #    disabled at all. Reaching here means the diff keyed it as "not desired"
        #    while its identity IS desired: a key mismatch (BUG-13's shape, e.g. a second
        #    verified domain). Excluding it is the safe reading, and it is REPORTED
        #    because a key mismatch is a defect to fix, not a condition to live with.
        $lp = Get-PimUpnLocalPart -Upn $upn
        if ($desiredLocals.ContainsKey($lp)) { [void]$attributable.Add($upn); continue }

        # 3. UNMANAGED -- genuinely absent from the desired set. 71.21/71.22: REPORTED ONLY.
        #    It is never added to $keep, under any flag, in any mode, in any tenant.
        [void]$unmanaged.Add($upn)
    }
    # $keep can only ever be EMPTY now: branch 1 excludes break-glass, branch 2 excludes an
    # attributable key mismatch, branch 3 reports. It is still returned (rather than a bare @())
    # so the caller's shape is unchanged and a future branch cannot silently bypass this comment.
    return [pscustomobject]@{
        remove       = $keep.ToArray()
        breakGlass   = $bgHit.ToArray()
        unmanaged    = $unmanaged.ToArray()
        attributable = $attributable.ToArray()
        reportOnly   = $true
        reason       = ("{0} kept, {1} break-glass excluded, {2} attributable-to-desired excluded (key mismatch), {3} unmanaged REPORTED ONLY -- PIM never disables an account merely because it is absent from the desired set (71.22)" -f `
                        $keep.Count, $bgHit.Count, $attributable.Count, $unmanaged.Count)
    }
}

# IMP-33: the unmanaged-admin report functions live in their own file (the Manager loads ONLY that file -- loading this
# one there changed its offboard gate). Loaded here so every engine path that has the guard has the report too.
. (Join-Path $PSScriptRoot 'PIM-UnmanagedAdmins.ps1')

function Get-PimAdminAccountPrefixes {
    <#
      PURE. The UPN prefixes that identify an ADMIN account, from
      $global:PIM_NamingConventions.AdminAccountPatterns (string[] | hashtable |
      string) with AdminAccountPattern/HighPriv as legacy fallbacks. A pattern may
      be a template ('Admin-{Initial}{Platform}') -- we take the LITERAL HEAD up to
      the first '{', which is what a startswith filter can actually use.
      Returns a de-duplicated, lower-cased string[]; EMPTY when nothing is configured
      (the caller must treat empty as fail-closed, never as "match everything").
    #>
    [CmdletBinding()] param([object]$NamingConventions = $null)
    $nc = $NamingConventions; if (-not $nc) { $nc = $global:PIM_NamingConventions }
    $out = New-Object System.Collections.Generic.List[string]
    $add = {
        param($v)
        $s = "$v".Trim()
        if (-not $s) { return }
        $i = $s.IndexOf('{')
        if ($i -ge 0) { $s = $s.Substring(0, $i) }     # literal head of a template
        $s = $s.Trim()
        if (-not $s) { return }                        # a pure template ('{X}...') yields nothing
        $lc = $s.ToLowerInvariant()
        if (-not $out.Contains($lc)) { [void]$out.Add($lc) }
    }
    # 🔴 2026-09-20 -- RESOLVE {AdminWord} AND {AdminTypePrefix} BEFORE TAKING THE LITERAL HEAD.
    # Operator: "a customer must be able to choose any acronym for admin, like adm, admin, etc."
    # $add takes the head up to the first '{', so a fully tokenised pattern such as
    # '{AdminTypePrefix}{AdminWord}-{Initial}{Platform}' begins with '{' and contributed NOTHING --
    # the prefix list then fell back to the shipped literals ('Admin-', 'x-Admin', 'g-Admin').
    # For a customer using AdminWord='adm' that is the IMP-13 catastrophe in slow motion: their real
    # accounts are 'adm-mok-id', no prefix matches, the Admins provider's live set is empty, and every
    # admin is RE-CREATED on every tick -- silently accumulating unmanaged privileged accounts.
    # Expanding the two tokens we actually know turns that pattern into 'adm-' and 'x-adm-', which is
    # what a startswith filter needs. Unknown tokens ({Initial}, {Platform}) still end the head.
    $expand = {
        param($tpl)
        $t = "$tpl"
        if (-not $t.Trim()) { return @() }
        $word = 'Admin'
        try { if ("$($nc.AdminWord)".Trim()) { $word = "$($nc.AdminWord)".Trim() } } catch { }
        $t = $t.Replace('{AdminWord}', $word)
        if ($t -notmatch '\{AdminTypePrefix\}') { return @($t) }
        # One candidate per configured admin-type prefix ('' , 'x-', ...), so every type is matchable.
        $tp = $null
        try { $tp = $nc.AdminTypePrefixes } catch { $tp = $null }
        $vals = New-Object System.Collections.Generic.List[string]
        if ($tp -is [System.Collections.IDictionary]) { foreach ($v in $tp.Values) { [void]$vals.Add("$v") } }
        elseif ($tp -is [System.Management.Automation.PSCustomObject]) { foreach ($p in $tp.PSObject.Properties) { [void]$vals.Add("$($p.Value)") } }
        if (-not $vals.Count) { [void]$vals.Add('') }
        # 2026-09-21 (operator: "make sure i can use any variables here"): a prefix may itself carry tokens
        # ('adm-{TenantCommonName}-', '{AdminWord}-'). Expand the two we know AFTER inserting it, the way the name
        # generator does (Expand-PimNamePattern now repeats until stable). {TenantCommonName} only when it is SET:
        # blank, the generator collapses the '--' it leaves, and a head carrying '--' would match no real account --
        # leaving the token in place instead ends the head at '{', which is broader and therefore safe.
        $tcn = ''
        # the SAME cleaning the generator applies (ConvertTo-PimNamePart): spaces -> '-', keep [A-Za-z0-9.-]
        try { $tcn = (("$($nc.TenantCommonName)".Trim() -replace '\s+', '-') -replace '[^A-Za-z0-9.\-]', '') } catch { $tcn = '' }
        @($vals | ForEach-Object {
            $e = $t.Replace('{AdminTypePrefix}', "$_").Replace('{AdminWord}', $word)
            if ($tcn) { $e = [regex]::Replace($e, '\{TenantCommonName\}', $tcn, 'IgnoreCase') }
            $e -replace '--+', '-'
        })
    }
    if ($nc) {
        $pats = $null
        try { $pats = $nc.AdminAccountPatterns } catch { $pats = $null }
        if ($pats -is [System.Collections.IDictionary]) { foreach ($v in $pats.Values) { foreach ($e in (& $expand $v)) { & $add $e } } }
        elseif ($pats -is [string]) { foreach ($e in (& $expand $pats)) { & $add $e } }
        elseif ($pats -is [System.Collections.IEnumerable]) { foreach ($v in $pats) { foreach ($e in (& $expand $v)) { & $add $e } } }
        foreach ($k in 'AdminAccountPattern','AdminAccountPatternHighPriv') {
            try { if ("$($nc.$k)".Trim()) { foreach ($e in (& $expand $nc.$k)) { & $add $e } } } catch { }
        }
    }
    return $out.ToArray()
}

function Test-PimIsAdminAccountName {
    # PURE. Does this UPN/name look like an ADMIN account under the configured
    # prefixes? Empty prefix list => $false (fail closed), never $true.
    [CmdletBinding()] param([string]$Name, [string[]]$Prefixes = @())
    $n = "$Name".Trim().ToLowerInvariant()
    if (-not $n) { return $false }
    foreach ($p in @($Prefixes)) {
        $pp = "$p".Trim().ToLowerInvariant()
        if ($pp -and $n.StartsWith($pp)) { return $true }
    }
    return $false
}

function Assert-PimAdminPopulationComparable {
    <#
      BUG-12's structural assertion: the two sides of the comparison must be drawn
      from the SAME population. Given the live rows the Admins scope will diff and
      the configured prefixes, returns @{ ok; offenders; reason }.
      An ordinary user in the LIVE set is a hard stop -- that is the incident shape.
    #>
    [CmdletBinding()]
    param([object[]]$Live = @(), [string[]]$Prefixes = @(), [string]$UpnProperty = 'userPrincipalName',
          # 🔴 2026-09-22 (operator: "you can not block admins due to different name pattern"). Accounts
          # a DESIRED ROW names are part of this population by definition -- PIM is already managing
          # them, by the store, not by what they are called. On a managed tenant those rows come from
          # the master and carry ITS naming, so without this the assertion would reject the very rows
          # the tenant was told to hold. It does NOT widen discovery: the caller passes only the UPNs
          # its desired set actually names, so an account no row asks for still cannot get in here.
          [string[]]$AlsoAllowed = @())
    if (@($Prefixes).Count -eq 0) {
        return [pscustomobject]@{ ok=$false; offenders=@()
            reason='no admin naming prefix is configured -- refusing to treat the whole user population as admin candidates (set $global:PIM_NamingConventions.AdminAccountPatterns)' }
    }
    $allow = New-Object System.Collections.Generic.HashSet[string] ([StringComparer]::OrdinalIgnoreCase)
    foreach ($a in @($AlsoAllowed)) { if ("$a".Trim()) { [void]$allow.Add("$a".Trim()) } }
    $bad = New-Object System.Collections.Generic.List[string]
    foreach ($l in @($Live)) {
        if ($null -eq $l) { continue }
        $upn = "$($l.$UpnProperty)"
        if ($allow.Contains("$upn".Trim())) { continue }
        if (-not (Test-PimIsAdminAccountName -Name $upn -Prefixes $Prefixes)) { [void]$bad.Add($upn) }
    }
    if ($bad.Count -gt 0) {
        return [pscustomobject]@{ ok=$false; offenders=$bad.ToArray()
            reason=("{0} non-admin account(s) reached the Admins scope's live set (e.g. {1}). Desired is admin definitions, so these would be classed as removals -- the 2026-06-15 incident shape. Refusing." -f $bad.Count, (($bad | Select-Object -First 3) -join ', ')) }
    }
    return [pscustomobject]@{ ok=$true; offenders=@(); reason='live set contains only admin accounts' }
}

# =============================================================================
# G4 -- UNIVERSAL REMOVAL BUDGET (operator directive 2026-08-06)
#
# The existing breaker (G1/G2/G3) guards ONE path: providers flagged isAccountDisable,
# i.e. Admins. Nothing capped removals anywhere else -- a -Prune on RolesAUs,
# GroupMembers or AzRes could remove EVERY live row (BUG-11), and the offboarding
# delete / group-retirement paths had no ceiling at all.
#
# BUG-12 is why a per-scope ceiling matters even when the desired set is "correct": the
# Admins provider compares the WHOLE user population against the admin definitions, so
# a legitimate-looking config can still classify real users as removals.
#
# This gate is DELIBERATELY DIFFERENT from the others:
#   * ALWAYS ON -- not opt-in, not environment-aware. It applies in a test tenant too.
#   * applies to EVERY scope's remove set and to the delete paths, not just disable.
#   * HARD CEILING of 5. An operator may lower it; RAISING it above 5 is clamped, the
#     same lesson as IMP-01 (an override that can neuter the guard is not a guard).
# A trip DROPS the whole remove set for that scope -- never a partial removal -- and
# ALERTS by email, because the operator's instruction was that this must be noticed.
# =============================================================================
$script:PimRemoveBudgetDefault = 5
$script:PimRemoveBudgetCeiling = 5

function Get-PimRemoveBudget {
    # The max removals/deletes allowed in ONE scope pass. Lowering is honoured; raising
    # above the ceiling is clamped and warned about (IMP-01's lesson).
    [CmdletBinding()] param()
    $req = Get-PimSafetyKnob -Name 'PIM_RemoveMaxCount'     # SEC-07: $global: then $env:
    if ($null -eq $req -or "$req".Trim() -eq '') { return $script:PimRemoveBudgetDefault }
    $n = 0
    if (-not [int]::TryParse("$req".Trim(), [ref]$n)) { return $script:PimRemoveBudgetDefault }
    if ($n -lt 0) { return 0 }
    if ($n -gt $script:PimRemoveBudgetCeiling) {
        Write-Warning ("PIM_RemoveMaxCount={0} exceeds the hard ceiling {1} -- CLAMPED. The removal budget cannot be raised above {1}." -f $n, $script:PimRemoveBudgetCeiling)
        return $script:PimRemoveBudgetCeiling
    }
    return $n
}

function Test-PimRemoveBudgetAllowed {
    <#
      G4. Is a removal/delete pass of $ToRemove items allowed in scope $Scope?
      PURE + always-on. Returns the same decision shape as the disable guard so callers
      and tests treat them alike.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][int]$ToRemove,
        [string]$Scope = '',
        [int]$Scanned = 0,
        [string]$Operation = 'remove',
        # WHAT the removals are, so the alert can say it (operator 2026-09-20: the mail read as though the
        # engine had decided to delete things by itself). Optional: 0/0 keeps the old generic wording.
        [int]$TypeChanges = 0,
        [int]$RemoveRows = 0
    )
    $budget = Get-PimRemoveBudget
    if ($ToRemove -le 0) {
        return [pscustomobject]@{ allowed=$true; abort=$false; tripped=$null; reason='nothing to remove'
                                  toRemove=$ToRemove; budget=$budget; scope=$Scope; operation=$Operation; scanned=$Scanned
                                  typeChanges=$TypeChanges; removeRows=$RemoveRows }
    }
    if ($ToRemove -gt $budget) {
        return [pscustomobject]@{ allowed=$false; abort=$true; tripped='remove-budget'
            reason=("{0} would {1} {2} item(s) in scope '{3}' -- over the removal budget of {4}. Dropping ALL removals for this scope (never a partial mass-removal)." -f 'engine', $Operation, $ToRemove, $Scope, $budget)
            toRemove=$ToRemove; budget=$budget; scope=$Scope; operation=$Operation; scanned=$Scanned
            typeChanges=$TypeChanges; removeRows=$RemoveRows }
    }
    return [pscustomobject]@{ allowed=$true; abort=$false; tripped=$null
        reason=("{0} {1} item(s) is within the removal budget of {2}" -f $Operation, $ToRemove, $budget)
        toRemove=$ToRemove; budget=$budget; scope=$Scope; operation=$Operation; scanned=$Scanned
        typeChanges=$TypeChanges; removeRows=$RemoveRows }
}

# =============================================================================
# 🔴 BUG-184 (§33.28) -- THE THREE SAFETY ALERTS WERE NEVER SENT.
# The removal-budget trip, the account-disable circuit breaker and the policy mass-change HOLD all
# called `Send-PimNotifyMail -Type 'alert'`. There is no 'alert' template -- only 'alert-notice' -- so
# every send returned { sent=$false; reason="no template 'alert'" }, the result was piped to Out-Null,
# and the budget path then printed "alert emailed to <x>" anyway. The token names (Subject/Body) did
# not match the template's either (AlertTitle/AlertDetail/...).
# ONE sender for all three now: the real template, the template's own tokens, the result READ, and a
# failed or impossible send REPORTED as such -- never "emailed" unless it was.
# Recipients: the PIM_AlertRecipient knob (';'/',' list) UNION the Manager's Alerting recipients
# (pim.Settings['Alerting'], the same list the job-failure alert uses), so an environment configured
# only in the Manager is paged too.
# =============================================================================
function Get-PimSafetyAlertRecipients {
    [CmdletBinding()] param()
    $out = New-Object System.Collections.Generic.List[string]
    $add = { param($v) $t = "$v".Trim(); if ($t -and -not (@($out) | Where-Object { $_ -ieq $t })) { $out.Add($t) } }
    foreach ($x in ("$(Get-PimSafetyKnob -Name 'PIM_AlertRecipient')" -split '[;,]')) { & $add $x }   # SEC-07: one reader
    if (Get-Command Get-PimJobAlertingConfig -ErrorAction SilentlyContinue) {
        try { foreach ($x in @((Get-PimJobAlertingConfig).recipients)) { & $add $x } }
        catch { Write-Warning "[engine] the Manager's alert recipients (pim.Settings['Alerting']) could not be read: $($_.Exception.Message)" }
    }
    return $out.ToArray()
}

function Send-PimSafetyAlert {
    <#
      Send one safety alert through the 'alert-notice' template to every configured recipient.
      NEVER throws (a failed alert must never mask the safe outcome it reports). Returns
        @{ status = sent|partial|failed|no-recipient|no-mailer|debounced; sent; recipients; failures; detail }
      and says on the console exactly which of those happened. -SwallowScope names the IMP-03 scope a
      failure is recorded under, so each caller keeps its own.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][string]$Detail,
        [string]$Event = 'engine-failure',
        [string]$Tab = 'jobs',
        [string]$SwallowScope = 'safety-alert-mail',
        [int]$DebounceMinutes = 60,
        # The one-line verdict, and what the reader should DO. Optional: both default (see the tokens below).
        [string]$Headline = '',
        [string]$Action = '',
        # §79.14: files for every recipient -- @{ name; contentType; bytes } (the CAB workbook of a policy hold).
        [object[]]$Attachments = @()
    )
    $res = [ordered]@{ status = ''; sent = 0; recipients = @(); failures = @(); detail = '' }
    try {
        $to = @(Get-PimSafetyAlertRecipients)
        $res.recipients = $to
        if (-not $to.Count) {
            $res.status = 'no-recipient'
            $res.detail = "NO alert recipient is configured (PIM_AlertRecipient, or Manager > Alerting recipients) -- '$Title' could NOT be emailed"
            try { Write-Host "  [engine] $($res.detail)" -ForegroundColor Red } catch { }
            return [pscustomobject]$res
        }
        if (-not (Get-Command Send-PimNotifyMail -ErrorAction SilentlyContinue)) {
            $res.status = 'no-mailer'
            $res.detail = "the mail sender is not loaded in this runtime -- '$Title' was NOT emailed to $($to -join ', ')"
            try { Write-Host "  [engine] $($res.detail)" -ForegroundColor Red } catch { }
            if (Get-Command Write-PimSwallowed -ErrorAction SilentlyContinue) {
                Write-PimSwallowed -Scope $SwallowScope -ErrorRecord $null -Consequence "the safety alert '$Title' was NOT sent (no mail sender loaded) -- nobody is being paged for this trip"
            }
            return [pscustomobject]$res
        }
        # Debounce against the shared alert feed, so a breaker that stays tripped does not mail every tick.
        $cs = $null; $key = $null
        if (Get-Command Get-PimSqlSettingsConnectionString -ErrorAction SilentlyContinue) { try { $cs = Get-PimSqlSettingsConnectionString } catch { $cs = $null } }
        if ($DebounceMinutes -gt 0 -and $cs -and (Get-Command Test-PimAlertDebounced -ErrorAction SilentlyContinue) -and
            (Get-Command Read-PimAlertFeedSql -ErrorAction SilentlyContinue) -and (Get-Command Get-PimAlertDedupeKey -ErrorAction SilentlyContinue)) {
            try {
                $key = Get-PimAlertDedupeKey -Event $Event -Title $Title -Detail $Detail
                if (Test-PimAlertDebounced -Feed (Read-PimAlertFeedSql -ConnectionString $cs) -DedupeKey $key -DebounceMinutes $DebounceMinutes) {
                    $res.status = 'debounced'
                    $res.detail = "'$Title' was already alerted within the last $DebounceMinutes minute(s) -- not re-sent"
                    try { Write-Host "  [engine] $($res.detail)" -ForegroundColor DarkYellow } catch { }
                    return [pscustomobject]$res
                }
            } catch { }
        }
        $tokens = @{
            AlertTitle  = $Title
            AlertEvent  = $Event
            AlertDetail = $Detail
            AlertTab    = $Tab
            TenantName  = $(if ("$($global:PIM_TenantName)".Trim()) { "$($global:PIM_TenantName)" } else { 'this tenant' })
            Instance    = 'engine'
            WhenUtc     = [datetime]::UtcNow.ToString('yyyy-MM-dd HH:mm:ss') + ' UTC'
            # The verdict and the next step, kept OUT of the detail so the reader gets them first.
            # Defaulted here so every existing caller keeps working without passing them.
            AlertHeadline = $(if ("$Headline".Trim()) { "$Headline" } else { 'A PIM4EntraPS alert was raised for your privileged-access estate.' })
            AlertAction   = $(if ("$Action".Trim()) { "$Action" } else { "Open the PIM Manager and review the $Tab view." })
        }
        $fails = New-Object System.Collections.Generic.List[string]
        foreach ($r in $to) {
            $why = ''
            try {
                $m = Send-PimNotifyMail -Type 'alert-notice' -Tokens $tokens -Recipient $r -Attachments @($Attachments)
                $ok = $false
                if ($m -is [hashtable]) { $ok = [bool]$m['sent']; $why = "$($m['reason'])" }
                elseif ($m -and $m.PSObject.Properties['sent']) { $ok = [bool]$m.sent; $why = "$($m.reason)" }
                else { $why = 'the mail sender returned no result' }
                if ($ok) { $res.sent++ } else { $fails.Add("${r}: $(if ($why) { $why } else { 'not sent' })") }
            } catch { $fails.Add("${r}: $($_.Exception.Message)") }
        }
        $res.failures = $fails.ToArray()
        if ($res.sent -and -not $fails.Count) { $res.status = 'sent' } elseif ($res.sent) { $res.status = 'partial' } else { $res.status = 'failed' }
        if ($res.sent) { try { Write-Host ("  [engine] safety alert emailed to {0} of {1} recipient(s)" -f $res.sent, $to.Count) -ForegroundColor Yellow } catch { } }
        if ($fails.Count) {
            $res.detail = "safety alert '$Title' was NOT sent to: " + ($fails -join '; ')
            try { Write-Host "  [engine] $($res.detail)" -ForegroundColor Red } catch { }
            try { Write-Warning $res.detail } catch { }
            if (Get-Command Write-PimSwallowed -ErrorAction SilentlyContinue) {
                $cons = if ($res.sent) { "the safety alert '$Title' reached only $($res.sent) of $($to.Count) recipient(s)" } else { "the safety alert '$Title' was NOT sent -- nobody is being paged for this trip" }
                Write-PimSwallowed -Scope $SwallowScope -ErrorRecord $null -Consequence ($cons + ' (' + ($fails -join '; ') + ')')
            }
        }
        # Record it in the shared alert feed (the proof, and what the debounce reads next tick).
        if ($cs -and (Get-Command New-PimAlertRecord -ErrorAction SilentlyContinue) -and (Get-Command Write-PimAlertFeedSql -ErrorAction SilentlyContinue)) {
            try {
                $sr = [ordered]@{ event = $Event; fired = $true; sent = $res.sent; recipients = @($to); reason = ($fails -join '; ') }
                [void](Write-PimAlertFeedSql -ConnectionString $cs -Record (New-PimAlertRecord -Event $Event -Title $Title -Detail $Detail -LinkTab $Tab -SendResult $sr -Instance 'engine'))
            } catch { Write-Warning "[engine] safety alert '$Title' was raised but NOT recorded in the alert feed ($($_.Exception.Message))." }
        }
    } catch {
        $res.status = 'failed'; $res.detail = "safety alert '$Title' failed: $($_.Exception.Message)"
        try { Write-Warning $res.detail } catch { }
        if (Get-Command Write-PimSwallowed -ErrorAction SilentlyContinue) {
            Write-PimSwallowed -Scope $SwallowScope -ErrorRecord $_ -Consequence "the safety alert '$Title' was NOT sent -- nobody is being paged for this trip"
        }
    }
    return [pscustomobject]$res
}


function Write-PimRemoveBudgetAlert {
    # Loud + EMAILED alert when G4 trips. NEVER throws (an alert failure must not mask the
    # abort). The recipient is CONFIGURED, never hardcoded: a real address in shipped
    # source is exactly what SEC-05 removed. Set $global:PIM_AlertRecipient (or
    # $env:PIM_AlertRecipient), or the Manager's Alerting recipients.
    # BUG-184: sent through Send-PimSafetyAlert ('alert-notice', result READ) -- the console says
    # "emailed" only when a mail actually went out. -PassThru returns the send result.
    # -PlanOnly: the run is a PLAN / verify (-WhatIf), which removes nothing whatever the budget says. It is
    # logged as a plan finding and NEITHER audited as a trip NOR mailed. Incident 2026-09-18: once BUG-184 made
    # these alerts really send, the read-only convergence check mailed "engine-failure: REMOVAL BUDGET tripped"
    # on every full plan, although nothing had been, or could be, removed.
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Decision, [switch]$PassThru, [switch]$PlanOnly)
    if ($PlanOnly) {
        $pm = ("[engine] PLAN ONLY -- scope '{0}': {1} live item(s) are not in the desired set (budget {2}). This run removes nothing; no alert is sent for a plan." -f `
                $Decision.scope, $Decision.toRemove, $Decision.budget)
        try { Write-Host $pm -ForegroundColor DarkYellow } catch { }
        if ($PassThru) { return [pscustomobject]@{ sent = $false; skipped = $true; reason = 'plan-only run: nothing is removed, so no alert' } }
        return
    }
    $msg = ("[engine] REMOVAL BUDGET EXCEEDED in scope '{0}': {1} would {2} {3} item(s), budget {4}. Removed NOTHING in this scope." -f `
            $Decision.scope, 'the engine', $Decision.operation, $Decision.toRemove, $Decision.budget)
    try { Write-Host $msg -ForegroundColor Red } catch { }
    try { Write-Warning $msg } catch { }
    # 🔑 2026-09-20 (operator: "text is wrong (budget ??) confusing") -- WHAT THE MAIL SAYS.
    # The old mail was the console line verbatim, plus the same two numbers again:
    #   "the engine would remove 9 item(s), budget 5. Removed NOTHING in this scope. Scanned: 247.
    #    Budget: 5. Nothing was removed. Investigate the desired set before re-running."
    # Three faults, all of which made a SAFE outcome read as a dangerous one:
    #   1. "budget" is an internal term. Nothing told the reader it is a per-run safety ceiling.
    #   2. "the engine would remove N items" reads as the engine deciding to delete things on its own.
    #      It never does: a removal comes either from a row the operator marked Action=Remove, or from an
    #      assignment TYPE CHANGE (Eligible <-> Active), which deletes the old type before writing the new.
    #      The kind is known here and was simply not said.
    #   3. The headline fact -- NOTHING WAS CHANGED -- came third, after the alarming part.
    # The mail now leads with the verdict, names the kind, and gives one instruction.
    $kinds = @()
    if ($Decision.PSObject.Properties['typeChanges'] -and [int]$Decision.typeChanges -gt 0) { $kinds += ("{0} assignment type change(s) (Eligible/Active swap, which deletes the old type first)" -f [int]$Decision.typeChanges) }
    if ($Decision.PSObject.Properties['removeRows'] -and [int]$Decision.removeRows -gt 0)   { $kinds += ("{0} row(s) marked Action=Remove" -f [int]$Decision.removeRows) }
    $what = if ($kinds.Count) { ($kinds -join ' and ') } else { ("{0} item(s)" -f $Decision.toRemove) }
    $headline = ("Nothing was changed. PIM4EntraPS stopped itself before deleting {0} in '{1}'." -f $Decision.toRemove, $Decision.scope)
    $detail = ("A single engine run is allowed to delete at most {0} item(s) in one area -- a safety ceiling that exists so a bad " +
               "read or a bulk edit can never clear out access in one pass. This run wanted to delete {1}, which is over that ceiling, " +
               "so it applied NONE of them and left '{2}' exactly as it was. {3}") -f `
               $Decision.budget, $what, $Decision.scope, $(if ($kinds.Count) { '' } else { 'Nothing else in this run was affected.' })
    $action = ("Open Jobs > Engine logs &amp; errors and read the {0} held item(s) -- each one names exactly what it would have deleted. " +
               "If they are all intended, apply them in batches of at most {1}. If they are NOT intended, nothing needs undoing: " +
               "no change was made.") -f $Decision.toRemove, $Decision.budget
    try {
        if (Get-Command Write-PimAuditEvent -ErrorAction SilentlyContinue) {
            Write-PimAuditEvent -Action 'engine.remove.budget.exceeded' -Target "$($Decision.scope)" -After @{
                operation=$Decision.operation; toRemove=$Decision.toRemove; budget=$Decision.budget; scanned=$Decision.scanned } | Out-Null
        }
    } catch {
        if (Get-Command Write-PimSwallowed -ErrorAction SilentlyContinue) {
            Write-PimSwallowed -Scope 'remove-budget-audit' -ErrorRecord $_ -Consequence 'the removal-budget trip was NOT written to the audit trail'
        }
    }
    $r = Send-PimSafetyAlert -SwallowScope 'remove-budget-alert-mail' `
            -Title ("{0} deletion(s) in '{1}' were blocked -- nothing was changed" -f $Decision.toRemove, $Decision.scope) `
            -Headline $headline -Detail $detail -Action $action
    if ($PassThru) { return $r }
}

function Write-PimDisableAbortAlert {
    # Loud, structured alert when a disable pass is aborted by a guard. Best-effort: logs
    # to the console + the run-log; raises a run-log/audit event when those helpers exist
    # so the operator + monitoring see it. NEVER throws (an alert failure must not mask
    # the abort, which is the safe outcome).
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Scope, [Parameter(Mandatory)][object]$Decision, [switch]$PassThru)
    $msg = ("[engine] {0}: account-disable pass ABORTED by safety guard [{1}] -- {2}. Disabled NOTHING this run." -f $Scope, $Decision.tripped, $Decision.reason)
    Write-Host $msg -ForegroundColor Red
    try { if (Get-Command Write-Warning -ErrorAction SilentlyContinue) { Write-Warning $msg } } catch {}
    # IMP-03: the two channels below stay non-rethrowing -- BUG-01's whole point is that
    # a trip must be announced, and an alert-channel failure must not turn a safe abort
    # into an exception. But a channel that fails silently is the same as no alert at
    # all, so each one says so on the console/warning stream it still has.
    try {
        if (Get-Command Write-PimAuditEvent -ErrorAction SilentlyContinue) {
            Write-PimAuditEvent -Action 'account.disable.aborted' -Target $Scope -After @{ tripped=$Decision.tripped; reason=$Decision.reason; toDisable=$Decision.toDisable; scanned=$Decision.scanned } | Out-Null
        }
    } catch {
        if (Get-Command Write-PimSwallowed -ErrorAction SilentlyContinue) {
            Write-PimSwallowed -Scope 'disable-abort-audit' -ErrorRecord $_ `
                -Consequence ("the circuit-breaker trip for '{0}' was NOT written to the audit trail (the console line above is the only record)" -f $Scope)
        }
    }
    # SEC-07 (same class): the recipient is read $global: then $env: (the containers set it as an ENV
    # VAR). BUG-184: through Send-PimSafetyAlert, so the send actually uses a template that exists and
    # a failed send is reported under 'disable-abort-alert-mail' ("nobody is being paged").
    $r = Send-PimSafetyAlert -SwallowScope 'disable-abort-alert-mail' `
            -Title ("account-disable circuit breaker tripped -- {0} [{1}]" -f $Scope, $Decision.tripped) -Detail $msg
    if ($PassThru) { return $r }
}
