#Requires -Version 5.1
<#
.SYNOPSIS
    Offline proof for the inactivity sweep (REQUIREMENTS §25c "Inactivity
    auto-disable sweep"). Drives the PURE decision core
    (engine/_shared/PIM-InactivitySweep.ps1) over SEEDED admin records -- no
    Graph, no SQL, NO destructive write (the disable applier is never called;
    only the plan + the guard verdict are computed).

    Asserts:
      * last-sign-in -> days math (ISO string / datetime / null / future);
      * threshold resolution (per-row wins, global default, 0/blank = not swept);
      * protected-account detection (break-glass / super-admin / flag / pattern);
      * plan classification: active / inactive / never-signed-in / not-swept /
        protected / already-disabled, with the right action per mode;
      * Report mode (default) FLAGS inactive admins and disables NOTHING;
      * Enforce mode proposes disables but the GUARD verdict blocks a mass /
        opted-out / empty-desired run and allows a small opted-in run;
      * a protected inactive admin is surfaced (flag) but NEVER counted to disable.

    Run standalone (exit 0 green / 1 red) or via Run-AllPimTests.ps1.
#>
[CmdletBinding()] param()

$ErrorActionPreference = 'Stop'
$pass = 0; $fail = 0
function T($n, $c) { if ($c) { Write-Host "  PASS $n" -ForegroundColor Green; $script:pass++ } else { Write-Host "  FAIL $n" -ForegroundColor Red; $script:fail++ } }

$shared = Join-Path (Split-Path -Parent $PSScriptRoot) 'engine\_shared'
$lib   = Join-Path $shared 'PIM-InactivitySweep.ps1'
$guard = Join-Path $shared 'PIM-DisableGuard.ps1'
T 'PIM-InactivitySweep.ps1 present' (Test-Path -LiteralPath $lib)
T 'PIM-DisableGuard.ps1 present'    (Test-Path -LiteralPath $guard)
if (-not (Test-Path -LiteralPath $lib) -or -not (Test-Path -LiteralPath $guard)) { Write-Host "`n RESULT: $pass pass, $fail fail" -ForegroundColor Red; exit 1 }
. $guard    # the real circuit breaker -- the Enforce verdict composes it (no write)
. $lib

$now = [datetime]::SpecifyKind([datetime]'2026-06-17T00:00:00', [System.DateTimeKind]::Utc)

# === day math ===============================================================
Write-Host "`n-- last sign-in -> days since --" -ForegroundColor Cyan
T 'ISO string 100 d ago -> 100' ((Get-PimAdminLastSignInDays -LastSignIn '2026-03-09T00:00:00Z' -Now $now) -eq 100)
T 'datetime 10 d ago -> 10'     ((Get-PimAdminLastSignInDays -LastSignIn ($now.AddDays(-10)) -Now $now) -eq 10)
T 'null -> $null (never/unknown)' ($null -eq (Get-PimAdminLastSignInDays -LastSignIn $null -Now $now))
T 'garbage -> $null (not 0)'      ($null -eq (Get-PimAdminLastSignInDays -LastSignIn 'not-a-date' -Now $now))
T 'future stamp clamps to 0'      ((Get-PimAdminLastSignInDays -LastSignIn ($now.AddDays(5)) -Now $now) -eq 0)

# === threshold resolution ===================================================
Write-Host "`n-- threshold resolution --" -ForegroundColor Cyan
$global:PIM_InactivityDisableDays = $null
T 'per-row InactivityDisableDays wins' ((Resolve-PimInactivityThreshold -Row @{ InactivityDisableDays = '45' }) -eq 45)
T 'blank row -> not swept ($null)'     ($null -eq (Resolve-PimInactivityThreshold -Row @{ }))
T '0 -> explicitly not swept'          ($null -eq (Resolve-PimInactivityThreshold -Row @{ InactivityDisableDays = '0' }))
$global:PIM_InactivityDisableDays = 90
T 'global default applies when row blank' ((Resolve-PimInactivityThreshold -Row @{ }) -eq 90)
$global:PIM_InactivityDisableDays = $null
T '-Default param applies when nothing set' ((Resolve-PimInactivityThreshold -Row @{ } -Default 60) -eq 60)

# === protected detection ====================================================
Write-Host "`n-- protected-account detection --" -ForegroundColor Cyan
T 'BreakGlass flag -> protected'   (Test-PimAdminSweepProtected -Row @{ UserPrincipalName='x@t'; BreakGlass=$true })
T 'SuperAdmin flag -> protected'   (Test-PimAdminSweepProtected -Row @{ UserPrincipalName='x@t'; SuperAdmin='true' })
T 'Purpose break-glass -> protected' (Test-PimAdminSweepProtected -Row @{ UserPrincipalName='x@t'; Purpose='Break-Glass' })
T 'UPN containing emergency -> protected' (Test-PimAdminSweepProtected -Row @{ UserPrincipalName='emergency-admin@t' })
T 'ordinary admin -> not protected' (-not (Test-PimAdminSweepProtected -Row @{ UserPrincipalName='mok@t'; Purpose='Day2Day' }))

# === the plan ===============================================================
Write-Host "`n-- sweep plan classification + actions --" -ForegroundColor Cyan
$admins = @(
    @{ UserPrincipalName='active@t';   DisplayName='Active';   LastSignIn=$now.AddDays(-5).ToString('o');   InactivityDisableDays='90' }   # active
    @{ UserPrincipalName='stale@t';    DisplayName='Stale';    LastSignIn=$now.AddDays(-120).ToString('o'); InactivityDisableDays='90' }   # inactive
    @{ UserPrincipalName='stale2@t';   DisplayName='Stale2';   LastSignIn=$now.AddDays(-200).ToString('o'); InactivityDisableDays='90' }   # inactive
    @{ UserPrincipalName='never@t';    DisplayName='Never';    LastSignIn=$null;                              InactivityDisableDays='90' }   # never-signed-in
    @{ UserPrincipalName='nounit@t';   DisplayName='NoUnit';   LastSignIn=$now.AddDays(-300).ToString('o') }                                # not-swept (no threshold)
    @{ UserPrincipalName='bg@t';       DisplayName='BreakGlass'; LastSignIn=$now.AddDays(-400).ToString('o'); InactivityDisableDays='90'; BreakGlass=$true }  # protected (would be inactive)
    @{ UserPrincipalName='gone@t';     DisplayName='Gone';     LastSignIn=$now.AddDays(-500).ToString('o'); InactivityDisableDays='90'; AccountStatus='Disabled' }  # already-disabled
)

$rep = Get-PimInactivitySweepPlan -Admins $admins -Mode Report -Now $now
$byU = @{}; foreach ($r in $rep.rows) { $byU[$r.userPrincipalName] = $r }
T 'active admin -> status active, action none' ($byU['active@t'].status -eq 'active' -and $byU['active@t'].action -eq 'none')
T 'stale admin -> status inactive'             ($byU['stale@t'].status -eq 'inactive')
T 'never-signed-in -> status never-signed-in'  ($byU['never@t'].status -eq 'never-signed-in')
T 'no-threshold admin -> not-swept/none'       ($byU['nounit@t'].status -eq 'not-swept' -and $byU['nounit@t'].action -eq 'none')
T 'break-glass inactive -> protected'          ($byU['bg@t'].status -eq 'protected')
T 'already-disabled admin -> already-disabled/none' ($byU['gone@t'].status -eq 'already-disabled' -and $byU['gone@t'].action -eq 'none')

# Report mode: every candidate is FLAGGED, nothing proposed for disable.
T 'Report: inactive count = 3 (stale, stale2, never)' ($rep.inactive + $rep.neverSignedIn -eq 3)
T 'Report: disableCandidates = 0 (flags only)'        ($rep.disableCandidates -eq 0)
T 'Report: stale action = flag'                       ($byU['stale@t'].action -eq 'flag')
T 'Report: protected count = 1'                       ($rep.protected -eq 1)

# Enforce mode: candidates propose a disable (EXCEPT the protected one).
$enf = Get-PimInactivitySweepPlan -Admins $admins -Mode Enforce -Now $now
$byUe = @{}; foreach ($r in $enf.rows) { $byUe[$r.userPrincipalName] = $r }
T 'Enforce: stale action = disable'                   ($byUe['stale@t'].action -eq 'disable')
T 'Enforce: protected NEVER becomes disable'          ($byUe['bg@t'].action -eq 'flag')
T 'Enforce: disableCandidates = 3 (stale, stale2, never; NOT bg, NOT gone)' ($enf.disableCandidates -eq 3)

# === Enforce guard verdict (composes the real circuit breaker) ==============
Write-Host "`n-- Enforce guard verdict (no real disable) --" -ForegroundColor Cyan
# Report verdict: never disables, no guard needed.
$vRep = Get-PimInactivitySweepDecision -Plan $rep
T 'Report verdict: willDisable 0, not aborted' ($vRep.willDisable -eq 0 -and -not $vRep.abort -and $vRep.flagged -eq 3)

# Enforce, feature OFF (protected env default) -> blocked (tripped feature-off).
$global:PIM_AccountDisableEnabled = $null
$vOff = Get-PimInactivitySweepDecision -Plan $enf -Desired @(@{x=1}) -DesiredResolved $true -TenantId 'protected-unknown'
T 'Enforce feature-off -> blocked, disables 0' ($vOff.allowed -eq $false -and $vOff.willDisable -eq 0 -and $vOff.tripped -eq 'feature-off')

# Enforce, opted in, but desired UNRESOLVED -> blocked (G1).
$vEmpty = Get-PimInactivitySweepDecision -Plan $enf -Desired @() -DesiredResolved $false -FeatureOverride $true
T 'Enforce empty/unresolved desired -> blocked (G1)' ($vEmpty.allowed -eq $false -and $vEmpty.tripped -eq 'empty-desired')

# Enforce, opted in + desired resolved, but 3 disables under a cap of 2 -> mass-disable trip (G2).
$global:PIM_DisableMaxCount = 2; $global:PIM_DisableMaxPercent = 0
$vMass = Get-PimInactivitySweepDecision -Plan $enf -Desired @(@{x=1}) -DesiredResolved $true -FeatureOverride $true
T 'Enforce over-cap -> blocked (G2 mass-disable), disables 0' ($vMass.allowed -eq $false -and $vMass.tripped -eq 'mass-disable' -and $vMass.willDisable -eq 0)

# Enforce, opted in + desired resolved + within cap -> ALLOWED.
$global:PIM_DisableMaxCount = 10; $global:PIM_DisableMaxPercent = 0
$vOk = Get-PimInactivitySweepDecision -Plan $enf -Desired @(@{x=1}) -DesiredResolved $true -FeatureOverride $true
T 'Enforce opted-in + within cap -> allowed, willDisable 3' ($vOk.allowed -eq $true -and $vOk.willDisable -eq 3)
# cleanup tunables
$global:PIM_DisableMaxCount = $null; $global:PIM_DisableMaxPercent = $null; $global:PIM_AccountDisableEnabled = $null

# === BUG-01: a blocked Enforce sweep must ALERT, not return quietly ==========
# The guard behaving correctly is only half the job -- if the breaker stops a
# sweep and says nothing, the operator sees a sweep that "ran", disabled nothing,
# and reads the estate as clean. Stub the alert so we record the call instead of
# writing to the console/audit/mail, then prove it fires exactly on the blocked
# ENFORCE path (and never on an allowed run or in Report mode).
Write-Host "`n-- BUG-01: blocked Enforce sweep raises the abort alert --" -ForegroundColor Cyan
$realAlert = (Get-Command Write-PimDisableAbortAlert -EA SilentlyContinue).ScriptBlock
$script:alertCalls = @()
function Write-PimDisableAbortAlert { [CmdletBinding()] param([Parameter(Mandatory)][string]$Scope,[Parameter(Mandatory)][object]$Decision)
    $script:alertCalls += [pscustomobject]@{ scope = $Scope; decision = $Decision } }

# Blocked by G2 (3 disables against a cap of 2) -> exactly one alert, carrying the
# scope + the SAME verdict the caller returned (so the alert can't describe a
# different decision than the one that was made).
$global:PIM_AccountDisableEnabled = $true; $global:PIM_DisableMaxCount = 2; $global:PIM_DisableMaxPercent = 0
$script:alertCalls = @()
$vMass2 = Get-PimInactivitySweepDecision -Plan $enf -Desired @(@{x=1}) -DesiredResolved $true -FeatureOverride $true
T 'BUG-01: blocked Enforce sweep raises exactly ONE alert' (@($script:alertCalls).Count -eq 1)
T 'BUG-01: alert scope names the sweep'                    (@($script:alertCalls)[0].scope -eq 'inactivity-sweep')
T 'BUG-01: alert carries the tripped guard (mass-disable)' ("$(@($script:alertCalls)[0].decision.tripped)" -eq 'mass-disable')
T 'BUG-01: alert decision matches the returned verdict'    ("$(@($script:alertCalls)[0].decision.reason)" -eq "$($vMass2.reason)")
T 'BUG-01: the sweep still disables nothing'               ($vMass2.allowed -eq $false -and $vMass2.willDisable -eq 0)

# An ALLOWED run must stay silent -- an alert on a healthy sweep is noise, and
# noise is how a real breaker trip gets ignored.
$global:PIM_DisableMaxCount = 10
$script:alertCalls = @()
$vOk2 = Get-PimInactivitySweepDecision -Plan $enf -Desired @(@{x=1}) -DesiredResolved $true -FeatureOverride $true
T 'BUG-01: an ALLOWED Enforce sweep raises NO alert' ($vOk2.allowed -eq $true -and @($script:alertCalls).Count -eq 0)

# Report mode never reaches the guard, so it must never alert either.
$script:alertCalls = @()
$null = Get-PimInactivitySweepDecision -Plan $rep
T 'BUG-01: Report mode raises NO alert' (@($script:alertCalls).Count -eq 0)

# The alert must be BEST-EFFORT: a throwing alert must not turn a safe abort into
# an exception. Prove the caller still returns its blocked verdict.
function Write-PimDisableAbortAlert { [CmdletBinding()] param([Parameter(Mandatory)][string]$Scope,[Parameter(Mandatory)][object]$Decision)
    throw 'simulated alert failure (mail/audit down)' }
$global:PIM_DisableMaxCount = 2
$vThrow = $null; $threw = $false
try { $vThrow = Get-PimInactivitySweepDecision -Plan $enf -Desired @(@{x=1}) -DesiredResolved $true -FeatureOverride $true } catch { $threw = $true }
T 'BUG-01: a FAILING alert never masks the abort (verdict still returned)' (-not $threw -and $vThrow -and $vThrow.allowed -eq $false -and $vThrow.willDisable -eq 0)

# restore the real alert + cleanup tunables
if ($realAlert) { Set-Item -Path function:Write-PimDisableAbortAlert -Value $realAlert }
$global:PIM_DisableMaxCount = $null; $global:PIM_DisableMaxPercent = $null; $global:PIM_AccountDisableEnabled = $null

# === BUG-03: the sweep reports the environment the GUARD decided against =====
# The sweep used to compute `environment` from its OWN -TenantId while the guard
# resolved the tenant from the ambient global -- so the readout could say
# environment=test while the decision had applied the PROTECTED default.
Write-Host "`n-- BUG-03: reported env matches the decision --" -ForegroundColor Cyan
$global:PIM_TestTenantIds = @('11111111-1111-1111-1111-111111111111')
Remove-Variable -Name PIM_TenantId -Scope Global -ErrorAction SilentlyContinue
$global:PIM_AccountDisableEnabled = $null   # let the ENV default decide, as in production
$global:PIM_DisableMaxCount = 10; $global:PIM_DisableMaxPercent = 0
$sTest = Get-PimInactivitySweepDecision -Plan $enf -Desired @(@{x=1}) -DesiredResolved $true -TenantId '11111111-1111-1111-1111-111111111111'
T 'BUG-03: explicit TEST tenant -> env default ON, sweep allowed' ($sTest.allowed -eq $true)
T 'BUG-03: sweep reports environment=test'                        ("$($sTest.environment)" -eq 'test')
$sProt = Get-PimInactivitySweepDecision -Plan $enf -Desired @(@{x=1}) -DesiredResolved $true -TenantId '99999999-9999-9999-9999-999999999999'
T 'BUG-03: explicit UNKNOWN tenant -> protected default, blocked' ($sProt.allowed -eq $false -and "$($sProt.tripped)" -eq 'feature-off')
T 'BUG-03: sweep reports environment=protected'                   ("$($sProt.environment)" -eq 'protected')
# The readout can no longer contradict the decision: allowed and environment move together.
T 'BUG-03: report and decision agree across both tenants' (($sTest.allowed -ne $sProt.allowed) -and ("$($sTest.environment)" -ne "$($sProt.environment)"))
$global:PIM_TestTenantIds = $null; $global:PIM_AccountDisableEnabled = $null
$global:PIM_DisableMaxCount = $null; $global:PIM_DisableMaxPercent = $null

# === empty / robustness =====================================================
Write-Host "`n-- robustness --" -ForegroundColor Cyan
$empty = Get-PimInactivitySweepPlan -Admins @() -Now $now
T 'empty admin set -> no rows, no crash' ($empty.scanned -eq 0 -and @($empty.rows).Count -eq 0)
T 'empty plan verdict (Report) -> 0/none' ((Get-PimInactivitySweepDecision -Plan $empty).willDisable -eq 0)

Write-Host "`n RESULT: $pass pass, $fail fail" -ForegroundColor $(if ($fail) { 'Red' } else { 'Green' })
if ($fail) { exit 1 } else { exit 0 }
