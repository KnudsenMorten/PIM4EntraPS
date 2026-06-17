#Requires -Version 5.1
<#
.SYNOPSIS
    Inactivity sweep for privileged admins (REQUIREMENTS §25c "Inactivity
    auto-disable sweep" / DESIGN §17.18 step 4). PURE, offline, unit-testable
    decision core -- no Graph, no SQL, no destructive write of its own.

.DESCRIPTION
    A standing privileged account that nobody has signed into for months is a
    pure liability: it widens the attack surface and is exactly what an access
    review is meant to catch. This sweep finds those accounts by comparing each
    admin's last interactive sign-in (Graph `signInActivity.lastSignInDateTime`)
    against an inactivity threshold (per delegation-unit `InactivityDisableDays`,
    else a global default), and either FLAGS them (Report -- the safe default) or
    proposes a DISABLE (Enforce). It also benefits non-delegated admins as plain
    hygiene.

    Two modes, mirroring the rest of the destructive engine:
      * Report  (DEFAULT) -- never disables; every inactive admin is FLAGGED for a
                  human (a row + an audit/notice the caller can act on). No guard
                  needed because nothing is disabled.
      * Enforce          -- proposes a disable for each inactive admin, but the
                  disable pass is run THROUGH the existing account-disable circuit
                  breaker (PIM-DisableGuard: G1 positively-resolved desired set,
                  G2 mass-disable blast-radius cap, G3 explicit opt-in / env class)
                  so a sweep can NEVER silently disable a population -- the same
                  net that exists for the Admins provider after the 2026-06-15
                  incident. This lib NEVER calls the disabler itself; it returns a
                  plan + a guard verdict the (already-built, approval-gated) account-
                  status path consumes.

    Accounts that must NEVER be auto-disabled (break-glass / emergency / super-admin
    / an explicitly protected row) are classified `protected` and excluded from the
    disable count regardless of mode.

    PowerShell 5.1 safe: no ?./??, no ternary; nullable dates handled explicitly;
    List[object] materialised with .ToArray() (never @()-wrapped).
#>

Set-StrictMode -Off

# --- field accessor (ordered hashtable OR PSCustomObject) ---------------------
function Get-PimIaField {
    param($Row, [string[]]$Names)
    if ($null -eq $Row) { return $null }
    foreach ($n in $Names) {
        if ($Row -is [System.Collections.IDictionary]) {
            if ($Row.Contains($n)) { return $Row[$n] }
        } elseif ($Row.PSObject.Properties[$n]) {
            return $Row.PSObject.Properties[$n].Value
        }
    }
    return $null
}

function Test-PimIaTruthy {
    param([object]$Value)
    if ($null -eq $Value) { return $false }
    if ($Value -is [bool]) { return [bool]$Value }
    $s = "$Value".Trim().ToLowerInvariant()
    return ($s -in @('1','true','yes','y','on','enabled'))
}

# --- last sign-in -> whole days since (UTC) ----------------------------------
# Accepts an ISO-8601 string OR a [datetime] OR $null. Returns:
#   an int (>= 0) days since the last sign-in, OR
#   $null when there is NO recorded sign-in (never signed in / unknown).
# An unparseable value is treated as unknown ($null), never as "0 days" (which
# would wrongly read as "very active").
function Get-PimAdminLastSignInDays {
    [CmdletBinding()]
    param([object]$LastSignIn, [datetime]$Now = ([datetime]::UtcNow))
    if ($null -eq $LastSignIn) { return $null }
    $dt = $null
    if ($LastSignIn -is [datetime]) {
        $dt = $LastSignIn.ToUniversalTime()
    } else {
        $s = "$LastSignIn".Trim()
        if (-not $s) { return $null }
        $parsed = [datetime]::MinValue
        $styles = [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal
        if ([datetime]::TryParse($s, [System.Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$parsed)) {
            $dt = $parsed.ToUniversalTime()
        } else {
            return $null
        }
    }
    $span = $Now.ToUniversalTime() - $dt
    $days = [int][math]::Floor($span.TotalDays)
    if ($days -lt 0) { $days = 0 }     # a future stamp clamps to 0 (treated as active)
    return $days
}

# --- threshold resolution -----------------------------------------------------
# Per-admin inactivity threshold in days: the row's own InactivityDisableDays (or
# its unit's) wins; else the global default ($global:PIM_InactivityDisableDays);
# else $Default. A value of 0 / blank / non-numeric = NO sweep for that admin
# (the feature is opt-in per unit -- a unit that hasn't set it is never swept).
# Returns an int > 0 (sweep applies) or $null (do not sweep this admin).
function Resolve-PimInactivityThreshold {
    [CmdletBinding()]
    param([object]$Row, [int]$Default = 0)
    $raw = Get-PimIaField -Row $Row -Names @('InactivityDisableDays','InactivityDays')
    if ($null -eq $raw -or -not ("$raw".Trim())) {
        $g = $global:PIM_InactivityDisableDays
        if ($null -ne $g -and "$g" -match '^\d+$' -and [int]$g -gt 0) { return [int]$g }
        if ($Default -gt 0) { return $Default }
        return $null
    }
    if ("$raw".Trim() -match '^\d+$') {
        $n = [int]("$raw".Trim())
        if ($n -gt 0) { return $n }
        return $null     # 0 = explicitly disabled for this admin/unit
    }
    return $null
}

# --- protected-account predicate ---------------------------------------------
# An account that must NEVER be auto-disabled by a sweep: an explicit Protected /
# BreakGlass / Emergency flag, a super-admin marker, or a UPN/name matching the
# configured break-glass pattern. Pure; no I/O.
function Test-PimAdminSweepProtected {
    [CmdletBinding()]
    param([object]$Row)
    foreach ($f in 'Protected','BreakGlass','Emergency','IsBreakGlass','NoAutoDisable','SuperAdmin','IsSuperAdmin') {
        if (Test-PimIaTruthy (Get-PimIaField -Row $Row -Names @($f))) { return $true }
    }
    $purpose = "$(Get-PimIaField -Row $Row -Names @('Purpose'))".ToLowerInvariant()
    if ($purpose -match 'break.?glass|emergency') { return $true }
    $upn = "$(Get-PimIaField -Row $Row -Names @('UserPrincipalName','Upn','UserName','Id'))".ToLowerInvariant()
    $pat = "$($global:PIM_BreakGlassPattern)".Trim().ToLowerInvariant()
    if ($pat -and $upn -and $upn -match [regex]::Escape($pat)) { return $true }
    if ($upn -match 'break.?glass|emergency') { return $true }
    return $false
}

function New-PimSweepRow {
    param(
        [string]$Upn, [string]$Label, [string]$Status, [string]$Action,
        $Days = $null, $Threshold = $null, [bool]$Protected = $false, [string]$Reason = ''
    )
    return [ordered]@{
        userPrincipalName = $Upn
        displayName       = $Label
        status            = $Status
        action            = $Action
        daysSinceSignIn   = $Days          # $null = never / unknown
        thresholdDays     = $Threshold     # $null = not swept
        protected         = $Protected
        reason            = $Reason
    }
}

# =============================================================================
# THE SWEEP PLAN -- pure classification over a set of admin records
# =============================================================================
# Each input admin row carries (any subset; accessor is forgiving):
#   UserPrincipalName / Upn / UserName / Id   -- the principal key
#   DisplayName                               -- label (optional)
#   LastSignIn / LastSignInDateTime / signInActivity.lastSignInDateTime (string|datetime|null)
#   InactivityDisableDays / InactivityDays    -- per-row threshold (optional)
#   Purpose / Protected / BreakGlass / SuperAdmin ... -- protection signals
#   AccountStatus / accountEnabled            -- skip an already-disabled account
#
# status per admin:
#   active            -- signed in within the threshold
#   inactive          -- threshold elapsed since last sign-in -> a sweep candidate
#   never-signed-in   -- no sign-in on record AND past the grace -> candidate
#   not-swept         -- no threshold resolves for this admin (unit hasn't opted in)
#   protected         -- never auto-disable (break-glass / super-admin / flagged)
#   already-disabled  -- AccountStatus already Disabled/Revoked (nothing to do)
#
# action per admin (what the caller should do):
#   none     -- active / not-swept / already-disabled
#   flag     -- a candidate in Report mode (the default), OR a protected candidate
#               in either mode (surfaced for a human, never auto-disabled)
#   disable  -- a candidate in Enforce mode (subject to the guard verdict below)
function Get-PimInactivitySweepPlan {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Admins,
        [ValidateSet('Report','Enforce')][string]$Mode = 'Report',
        [int]$DefaultThresholdDays = 0,
        # Accounts with NO sign-in on record are only treated as inactive once this
        # many days have passed since they were created (so a just-provisioned admin
        # who hasn't logged in yet is not immediately a candidate). 0 = treat a
        # never-signed-in admin as inactive immediately.
        [int]$NeverSignedInGraceDays = 0,
        [datetime]$Now = ([datetime]::UtcNow)
    )

    $rows = New-Object System.Collections.Generic.List[object]
    $cActive=0; $cInactive=0; $cNever=0; $cNotSwept=0; $cProtected=0; $cDisabled=0
    $disableCandidates = 0

    foreach ($a in @($Admins)) {
        if ($null -eq $a) { continue }
        $upn = "$(Get-PimIaField -Row $a -Names @('UserPrincipalName','Upn','UserName','Id'))".Trim()
        if (-not $upn) { continue }
        $label = "$(Get-PimIaField -Row $a -Names @('DisplayName','Name'))"
        if (-not "$label".Trim()) { $label = $upn }

        # already-disabled?
        $acctStatus = "$(Get-PimIaField -Row $a -Names @('AccountStatus'))".Trim().ToLowerInvariant()
        $acctEnabledRaw = Get-PimIaField -Row $a -Names @('accountEnabled','AccountEnabled','Enabled')
        $isDisabled = ($acctStatus -in @('disabled','revoked')) -or (($null -ne $acctEnabledRaw) -and -not (Test-PimIaTruthy $acctEnabledRaw))
        if ($isDisabled) {
            $cDisabled++
            $rows.Add((New-PimSweepRow -Upn $upn -Label $label -Status 'already-disabled' -Action 'none' -Reason 'account already disabled/revoked'))
            continue
        }

        $threshold = Resolve-PimInactivityThreshold -Row $a -Default $DefaultThresholdDays
        if ($null -eq $threshold) {
            $cNotSwept++
            $rows.Add((New-PimSweepRow -Upn $upn -Label $label -Status 'not-swept' -Action 'none' -Reason 'no inactivity threshold set for this admin/unit'))
            continue
        }

        $lastRaw = Get-PimIaField -Row $a -Names @('LastSignIn','LastSignInDateTime','lastSignInDateTime')
        if ($null -eq $lastRaw) {
            $sia = Get-PimIaField -Row $a -Names @('signInActivity','SignInActivity')
            if ($null -ne $sia) { $lastRaw = Get-PimIaField -Row $sia -Names @('lastSignInDateTime','LastSignInDateTime') }
        }
        $days = Get-PimAdminLastSignInDays -LastSignIn $lastRaw -Now $Now

        $protected = Test-PimAdminSweepProtected -Row $a

        $status = 'active'; $isCandidate = $false; $reason = ''
        if ($null -eq $days) {
            # never signed in -- a candidate once past the grace window. We can only
            # apply the grace if we know how old the account is; absent a created date
            # we treat NeverSignedInGraceDays=0 as "candidate now".
            $createdDays = Get-PimAdminLastSignInDays -LastSignIn (Get-PimIaField -Row $a -Names @('CreatedDateTime','createdDateTime','Created')) -Now $Now
            $pastGrace = $true
            if ($NeverSignedInGraceDays -gt 0 -and $null -ne $createdDays) { $pastGrace = ($createdDays -ge $NeverSignedInGraceDays) }
            if ($pastGrace) {
                $status = 'never-signed-in'; $isCandidate = $true
                $reason = "no interactive sign-in on record (threshold $threshold d)"
            } else {
                $status = 'active'; $reason = "recently created, no sign-in yet (within $NeverSignedInGraceDays d grace)"
            }
        } elseif ($days -ge $threshold) {
            $status = 'inactive'; $isCandidate = $true
            $reason = "last sign-in $days d ago (>= threshold $threshold d)"
        } else {
            $status = 'active'; $reason = "last sign-in $days d ago (< threshold $threshold d)"
        }

        # action + counts. A protected candidate is surfaced (flag) and counted
        # ONLY in the protected bucket -- never in inactive/never (so the candidate
        # totals reflect what could actually be acted on).
        $action = 'none'
        if ($isCandidate) {
            if ($protected) {
                $action = 'flag'
                $status = 'protected'
                $cProtected++
            } else {
                if ($status -eq 'inactive') { $cInactive++ } else { $cNever++ }
                if ($Mode -eq 'Enforce') { $action = 'disable'; $disableCandidates++ }
                else { $action = 'flag' }
            }
        } else {
            if ($status -eq 'active') { $cActive++ }
        }

        $rows.Add((New-PimSweepRow -Upn $upn -Label $label -Status $status -Action $action -Days $days -Threshold $threshold -Protected $protected -Reason $reason))
    }

    $rowArr = $rows.ToArray()
    return [ordered]@{
        mode               = $Mode
        scanned            = $rowArr.Count
        active             = $cActive
        inactive           = $cInactive
        neverSignedIn      = $cNever
        protected          = $cProtected
        notSwept           = $cNotSwept
        alreadyDisabled    = $cDisabled
        candidates         = ($cInactive + $cNever)
        disableCandidates  = $disableCandidates   # what Enforce would disable (pre-guard)
        rows               = $rowArr
        generatedUtc       = $Now.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    }
}

# =============================================================================
# ENFORCE GUARD VERDICT -- compose the plan's disable count with the existing
# account-disable circuit breaker so a sweep can NEVER mass-disable. Report mode
# needs no guard (it disables nothing). Returns the disable plan + the verdict;
# the CALLER (the approval-gated account-status path) is the only thing that
# actually disables -- this lib never writes.
# =============================================================================
function Get-PimInactivitySweepDecision {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Plan,
        # The positively-resolved desired admin set (so G1 can confirm the run is
        # working from a real config, not an empty/failed read). Pass-through to the guard.
        [object[]]$Desired = @(),
        [Nullable[bool]]$DesiredResolved = $null,
        [object]$FeatureOverride = $null,
        [string]$TenantId = $null
    )
    $mode = "$($Plan.mode)"
    $toDisable = [int]$Plan.disableCandidates
    $scanned   = [int]$Plan.scanned

    if ($mode -ne 'Enforce') {
        return [pscustomobject]@{
            mode='Report'; willDisable=0; flagged=[int]$Plan.candidates
            allowed=$false; abort=$false; tripped=$null
            reason='report mode -- flags inactive admins, disables nothing'
            scanned=$scanned
        }
    }

    if (-not (Get-Command Test-PimDisablePassAllowed -ErrorAction SilentlyContinue)) {
        # The guard lib must be loaded for an Enforce sweep -- fail CLOSED (disable nothing).
        return [pscustomobject]@{
            mode='Enforce'; willDisable=0; flagged=[int]$Plan.candidates
            allowed=$false; abort=$true; tripped='guard-unavailable'
            reason='account-disable guard (PIM-DisableGuard) not loaded -- refusing to disable'
            scanned=$scanned
        }
    }

    $verdict = Test-PimDisablePassAllowed -ToDisable $toDisable -Scanned $scanned `
        -Desired $Desired -DesiredResolved $DesiredResolved -FeatureOverride $FeatureOverride
    # The guard already factors TenantId via the global; expose the env class for the report.
    $envClass = if (Get-Command Resolve-PimEnvironmentClass -ErrorAction SilentlyContinue) { Resolve-PimEnvironmentClass -TenantId $TenantId } else { 'protected' }

    return [pscustomobject]@{
        mode='Enforce'
        willDisable= $(if ($verdict.allowed) { $toDisable } else { 0 })
        flagged    = [int]$Plan.candidates
        allowed    = [bool]$verdict.allowed
        abort      = [bool]$verdict.abort
        tripped    = $verdict.tripped
        reason     = $verdict.reason
        scanned    = $scanned
        environment= $envClass
    }
}
