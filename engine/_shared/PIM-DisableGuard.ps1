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
        @{ name = 'PIM_RemoveUnmanagedAdmins'; env = 'PIM_RemoveUnmanagedAdmins'; what = 'the report-only brake on unmanaged admin removal' }
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
            Write-Warning ("PIM_DisableMaxCount={0} exceeds the hard ceiling {1} -- CLAMPED to {1}. The mass-disable breaker cannot be raised past its ceiling (REQUIREMENTS §22)." -f $req, $script:PimDisableMaxCountCeiling)
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
            Write-Warning ("PIM_DisableMaxPercent={0} exceeds the hard ceiling {1} -- CLAMPED to {1} (REQUIREMENTS §22)." -f $req, $script:PimDisableMaxPercentCeiling)
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
# --- BUG-14: break-glass, available to the ENGINE ----------------------------------
# These existed only in PIM-ApprovalGate.ps1 (Manager revoke guard + approval-gated
# offboarding), which the REST engine does NOT load -- so the path that actually sets
# accountEnabled=$false had no break-glass exclusion at all. Defined here, guarded, so
# whichever file loads first provides the ONE definition and the other skips: the engine
# and the Manager must never disagree about what break-glass means.
if (-not (Get-Command Get-PimBreakGlassIdentifiers -ErrorAction SilentlyContinue)) {
    function Get-PimBreakGlassIdentifiers {
        # Break-glass / emergency principals to NEVER auto-disable/revoke/offboard.
        # UPNs and/or object ids; case-insensitive. $global:PIM_BreakGlassAccounts
        # (string[] or ';'/',' separated) or $env:PIM_BREAKGLASS_ACCOUNTS.
        # SEC-07: one reader for every knob. Behaviour is unchanged here -- this one
        # already honoured the environment; routing it through Get-PimSafetyKnob is what
        # lets Test-PimSafetyKnobs assert the whole inventory uniformly.
        $raw = Get-PimSafetyKnob -Name 'PIM_BreakGlassAccounts' -EnvName 'PIM_BREAKGLASS_ACCOUNTS'
        if (-not $raw) { return @() }
        $list = if ($raw -is [string]) { $raw -split '[;,]' } else { @($raw) }
        return @($list | ForEach-Object { "$_".Trim().ToLowerInvariant() } | Where-Object { $_ })
    }
}
if (-not (Get-Command Test-PimRowIsBreakGlass -ErrorAction SilentlyContinue)) {
    function Test-PimRowIsBreakGlass {
        param([Parameter(Mandatory)]$Row, [string[]]$Identifiers)
        if (-not $Identifiers -or $Identifiers.Count -eq 0) { return $false }
        $cand = @()
        foreach ($k in 'id','principalId','principal','principalUpn','principalName','target','userPrincipalName','UserPrincipalName','Username') {
            $p = $Row.PSObject.Properties[$k]
            if ($p -and "$($p.Value)".Trim()) { $cand += "$($p.Value)".Trim().ToLowerInvariant() }
        }
        foreach ($c in $cand) { if ($Identifiers -contains $c) { return $true } }
        return $false
    }
}

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
      BUG-13 + BUG-14. Decide which of a disable scope's proposed removals may actually
      proceed. PURE. Returns @{ remove; breakGlass; unmanaged; reason }.

      Two exclusions, both defaulting to SAFE:
        * BREAK-GLASS (BUG-14) -- never removable. No opt-in, no override. It is the
          account you reach for when everything else is locked out, and it is by design
          absent from normal definitions, so it lands in the removal set by default.
        * UNMANAGED (BUG-13) -- a live admin whose identity matches NO desired row. The
          desired UPN is built from ONE default domain, so an admin on another verified
          domain can never match and would be classed as a removal. Matching is now
          domain-INDEPENDENT (local part), and anything still unattributable is treated
          as unmanaged: reported, not removed, unless the operator explicitly opts in
          with $global:PIM_RemoveUnmanagedAdmins.

      Deprovisioning genuinely rogue admin accounts is still possible -- it just has to
      be asked for, rather than being the default reading of "not in my CSV".
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
    # MSP MODEL (operator 2026-08-06): the desired set is AUTHORITATIVE. The same admin
    # legitimately holds accounts across several tenants/domains, and when they stop
    # working for the MSP those accounts MUST be disabled/deleted -- that is the
    # deprovisioning flow, not an accident. So an unmanaged admin stays REMOVABLE by
    # default; it is reported for visibility, and the real brakes are the existing gates
    # (account-disable opt-in, empty-desired, mass-disable cap, G4 budget, break-glass).
    # $global:PIM_RemoveUnmanagedAdmins = $false is available as an extra brake for an
    # operator who wants reporting only.
    $allowUnmanaged = $true
    if (Get-Command Test-PimExplicitFlagValue -ErrorAction SilentlyContinue) {
        $ex = Test-PimExplicitFlagValue -Value (Get-PimSafetyKnob -Name 'PIM_RemoveUnmanagedAdmins')   # SEC-07
        if ($null -ne $ex) { $allowUnmanaged = [bool]$ex }
    }

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

        # 3. UNMANAGED -- genuinely absent from the desired set. Deprovisioning these is
        #    a real feature, but it must be ASKED FOR, not be the default reading of
        #    "not in my CSV".
        [void]$unmanaged.Add($upn)
        if (-not $allowUnmanaged) { continue }
        [void]$keep.Add($r)
    }
    return [pscustomobject]@{
        remove       = $keep.ToArray()
        breakGlass   = $bgHit.ToArray()
        unmanaged    = $unmanaged.ToArray()
        attributable = $attributable.ToArray()
        reason       = ("{0} kept, {1} break-glass excluded, {2} attributable-to-desired excluded (key mismatch), {3} unmanaged{4}" -f `
                        $keep.Count, $bgHit.Count, $attributable.Count, $unmanaged.Count,
                        $(if ($allowUnmanaged) { ' (opt-in ON: unmanaged ARE removable)' } else { ' excluded (set PIM_RemoveUnmanagedAdmins -- global or env -- to allow)' }))
    }
}

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
    if ($nc) {
        $pats = $null
        try { $pats = $nc.AdminAccountPatterns } catch { $pats = $null }
        if ($pats -is [System.Collections.IDictionary]) { foreach ($v in $pats.Values) { & $add $v } }
        elseif ($pats -is [string]) { & $add $pats }
        elseif ($pats -is [System.Collections.IEnumerable]) { foreach ($v in $pats) { & $add $v } }
        foreach ($k in 'AdminAccountPattern','AdminAccountPatternHighPriv') {
            try { if ("$($nc.$k)".Trim()) { & $add $nc.$k } } catch { }
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
    param([object[]]$Live = @(), [string[]]$Prefixes = @(), [string]$UpnProperty = 'userPrincipalName')
    if (@($Prefixes).Count -eq 0) {
        return [pscustomobject]@{ ok=$false; offenders=@()
            reason='no admin naming prefix is configured -- refusing to treat the whole user population as admin candidates (set $global:PIM_NamingConventions.AdminAccountPatterns)' }
    }
    $bad = New-Object System.Collections.Generic.List[string]
    foreach ($l in @($Live)) {
        if ($null -eq $l) { continue }
        $upn = "$($l.$UpnProperty)"
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
        [string]$Operation = 'remove'
    )
    $budget = Get-PimRemoveBudget
    if ($ToRemove -le 0) {
        return [pscustomobject]@{ allowed=$true; abort=$false; tripped=$null; reason='nothing to remove'
                                  toRemove=$ToRemove; budget=$budget; scope=$Scope; operation=$Operation; scanned=$Scanned }
    }
    if ($ToRemove -gt $budget) {
        return [pscustomobject]@{ allowed=$false; abort=$true; tripped='remove-budget'
            reason=("{0} would {1} {2} item(s) in scope '{3}' -- over the removal budget of {4}. Dropping ALL removals for this scope (never a partial mass-removal)." -f 'engine', $Operation, $ToRemove, $Scope, $budget)
            toRemove=$ToRemove; budget=$budget; scope=$Scope; operation=$Operation; scanned=$Scanned }
    }
    return [pscustomobject]@{ allowed=$true; abort=$false; tripped=$null
        reason=("{0} {1} item(s) is within the removal budget of {2}" -f $Operation, $ToRemove, $budget)
        toRemove=$ToRemove; budget=$budget; scope=$Scope; operation=$Operation; scanned=$Scanned }
}

function Write-PimRemoveBudgetAlert {
    # Loud + EMAILED alert when G4 trips. NEVER throws (an alert failure must not mask the
    # abort). The recipient is CONFIGURED, never hardcoded: a real address in shipped
    # source is exactly what SEC-05 removed. Set $global:PIM_AlertRecipient (or
    # $env:PIM_AlertRecipient) -- the real value lives in internal/ and the container env.
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Decision)
    $msg = ("[engine] REMOVAL BUDGET EXCEEDED in scope '{0}': {1} would {2} {3} item(s), budget {4}. Removed NOTHING in this scope." -f `
            $Decision.scope, 'the engine', $Decision.operation, $Decision.toRemove, $Decision.budget)
    try { Write-Host $msg -ForegroundColor Red } catch { }
    try { Write-Warning $msg } catch { }
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
    $to = "$(Get-PimSafetyKnob -Name 'PIM_AlertRecipient')".Trim()   # SEC-07: one reader
    if (-not $to) {
        # Not silent: an alert with nowhere to go is itself a finding the operator must see.
        try { Write-Host "  [engine] NO PIM_AlertRecipient configured -- the removal-budget alert could not be EMAILED." -ForegroundColor Red } catch { }
        return
    }
    try {
        if (Get-Command Send-PimNotifyMail -ErrorAction SilentlyContinue) {
            Send-PimNotifyMail -Type 'alert' -Recipient $to -Tokens @{
                Subject = ("PIM REMOVAL BUDGET tripped -- scope '{0}' ({1} {2} blocked)" -f $Decision.scope, $Decision.toRemove, $Decision.operation)
                Body    = ($msg + "`r`n`r`nScanned: $($Decision.scanned)`r`nBudget : $($Decision.budget)`r`nNothing was removed. Investigate the desired set before re-running.")
            } | Out-Null
            Write-Host ("  [engine] removal-budget alert emailed to {0}" -f $to) -ForegroundColor Yellow
        }
    } catch {
        if (Get-Command Write-PimSwallowed -ErrorAction SilentlyContinue) {
            Write-PimSwallowed -Scope 'remove-budget-alert-mail' -ErrorRecord $_ -Consequence "the removal-budget alert mail to $to was NOT sent -- nobody is being told about this trip"
        }
    }
}

function Write-PimDisableAbortAlert {
    # Loud, structured alert when a disable pass is aborted by a guard. Best-effort: logs
    # to the console + the run-log; raises a run-log/audit event when those helpers exist
    # so the operator + monitoring see it. NEVER throws (an alert failure must not mask
    # the abort, which is the safe outcome).
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Scope, [Parameter(Mandatory)][object]$Decision)
    $msg = ("[engine] {0}: account-disable pass ABORTED by safety guard [{1}] -- {2}. Disabled NOTHING this run." -f $Scope, $Decision.tripped, $Decision.reason)
    Write-Host $msg -ForegroundColor Red
    try { if (Get-Command Write-Warning -ErrorAction SilentlyContinue) { Write-Warning $msg } } catch {}
    # IMP-03: the two catches below stay non-rethrowing -- BUG-01's whole point is that
    # a trip must be announced, and an alert-channel failure must not turn a safe abort
    # into an exception. But a channel that fails silently is the same as no alert at
    # all, so each one now says so on the console/warning stream it still has.
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
    try {
        # SEC-07 (same class). This read ONLY $global:PIM_AlertRecipient, while the G4
        # budget alert reads $global: then $env:. The containers set PIM_AlertRecipient as
        # an ENV VAR -- so in the deployed fleet the G4 trip emailed and this one, the
        # ORIGINAL circuit breaker from the 2026-06-15 incident, never did. BUG-01's whole
        # point is that a trip must be announced.
        $to = "$(Get-PimSafetyKnob -Name 'PIM_AlertRecipient')".Trim()
        if ((Get-Command Send-PimNotifyMail -ErrorAction SilentlyContinue) -and $to) {
            Send-PimNotifyMail -Type 'alert' -Tokens @{ Subject='PIM account-disable circuit breaker tripped'; Body=$msg } -Recipient $to | Out-Null
        }
    } catch {
        if (Get-Command Write-PimSwallowed -ErrorAction SilentlyContinue) {
            Write-PimSwallowed -Scope 'disable-abort-alert-mail' -ErrorRecord $_ `
                -Consequence 'the circuit-breaker alert mail was NOT sent -- nobody is being paged for this trip'
        }
    }
}
