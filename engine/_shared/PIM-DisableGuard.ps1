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
    # The list of tenant ids classified as TEST (destructive default ON). Operator-
    # configurable via $global:PIM_TestTenantIds (string or array). Default = the two
    # PIM MSP test tenants. The real internal tenant is deliberately NOT in here.
    $v = $global:PIM_TestTenantIds
    $defaults = @(
        '4ff34194-fb38-4949-8e2a-58dac8f096c2',   # PIM MSP test tenant 1
        '9927fa1f-a09b-4244-8aba-60fb9ce7335e'     # PIM MSP test tenant 2
    )
    if ($null -eq $v) { return $defaults }
    $list = @()
    foreach ($x in @($v)) {
        if ($null -eq $x) { continue }
        foreach ($p in ("$x" -split '[,;\s]+')) { $t = "$p".Trim(); if ($t) { $list += $t.ToLowerInvariant() } }
    }
    if ($list.Count -eq 0) { return $defaults }
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
function Get-PimDisableMaxCount {
    # Absolute cap: refuse a run that would disable MORE than this many accounts.
    $v = $global:PIM_DisableMaxCount
    if ($null -ne $v -and "$v" -match '^\d+$') { return [int]$v }
    return 5
}
function Get-PimDisableMaxPercent {
    # Relative cap (% of the SCANNED live population): refuse a run that would disable
    # MORE than this fraction of everything it looked at. 0 disables this dimension.
    $v = $global:PIM_DisableMaxPercent
    if ($null -ne $v -and "$v" -match '^\d+(\.\d+)?$') { return [double]$v }
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
    $explicit = Test-PimExplicitFlagValue -Value $global:PIM_AccountDisableEnabled
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
        [double]$MaxPercent = -1
    )
    # G3: feature opt-in
    if (-not (Test-PimAccountDisableEnabled -Override $FeatureOverride)) {
        return [pscustomobject]@{ allowed=$false; abort=$true; tripped='feature-off'; reason='account-disable is OFF (opt-in required: set PIM_AccountDisableEnabled)'; toDisable=$ToDisable; scanned=$Scanned }
    }
    # G1: positively-resolved, non-empty desired set
    if (-not (Test-PimDesiredSetResolved -Desired $Desired -Resolved $DesiredResolved)) {
        return [pscustomobject]@{ allowed=$false; abort=$true; tripped='empty-desired'; reason='desired set is empty/unresolved -- refusing to disable (a disable requires a positively-confirmed desired set)'; toDisable=$ToDisable; scanned=$Scanned }
    }
    # G2: blast radius
    $mass = Test-PimMassDisableSafe -ToDisable $ToDisable -Scanned $Scanned -MaxCount $MaxCount -MaxPercent $MaxPercent
    if ($mass.abort) {
        return [pscustomobject]@{ allowed=$false; abort=$true; tripped='mass-disable'; reason=("circuit breaker: " + $mass.reason); toDisable=$ToDisable; scanned=$Scanned; maxCount=$mass.maxCount; maxPercent=$mass.maxPercent }
    }
    return [pscustomobject]@{ allowed=$true; abort=$false; tripped=$null; reason='ok'; toDisable=$ToDisable; scanned=$Scanned; maxCount=$mass.maxCount; maxPercent=$mass.maxPercent }
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
    try {
        if (Get-Command Write-PimAuditEvent -ErrorAction SilentlyContinue) {
            Write-PimAuditEvent -Action 'account.disable.aborted' -Target $Scope -After @{ tripped=$Decision.tripped; reason=$Decision.reason; toDisable=$Decision.toDisable; scanned=$Decision.scanned } | Out-Null
        }
    } catch {}
    try {
        if ((Get-Command Send-PimNotifyMail -ErrorAction SilentlyContinue) -and "$($global:PIM_AlertRecipient)".Trim()) {
            Send-PimNotifyMail -Type 'alert' -Tokens @{ Subject='PIM account-disable circuit breaker tripped'; Body=$msg } -Recipient "$($global:PIM_AlertRecipient)" | Out-Null
        }
    } catch {}
}
