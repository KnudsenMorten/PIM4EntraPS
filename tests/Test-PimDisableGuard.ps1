<#
  Offline tests for the ACCOUNT-DISABLE CIRCUIT BREAKER (PIM-DisableGuard.ps1 +
  PIM-EngineCore wiring). Incident 2026-06-15: the REST 'Admins' provider disabled
  the entire scanned tenant population (accountEnabled=$false) because its desired
  admin set read empty/wrong while its GetLive is the whole tenant.

  These tests prove the three guards:
    G1  empty / unresolved desired set -> ABORT (zero disables, not disable-all)
    G2  blast radius over threshold    -> ABORT (zero disables; never partial)
    G3  feature OFF by default          -> zero disables
  plus: a single genuinely-offboarded account (feature ON, within limits, resolved
  desired) STILL disables; and a reproduction of the 06:00 condition (whole-population
  remove) now ABORTS.

  Pure + in-memory; no network; PS 5.1-safe. Rerun anytime.
#>
[CmdletBinding()] param()
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $here) { $here = 'C:\SCRIPTS\AutomateIT\SOLUTIONS\PIM4EntraPS\tests' }
. "$here\..\engine\_shared\PIM-ChangeQueue.ps1"
. "$here\..\engine\_shared\PIM-EngineCore.ps1"
. "$here\..\engine\_shared\PIM-DisableGuard.ps1"

$pass=0; $fail=0
function Assert($n,$c){ if($c){ $script:pass++; Write-Host "  PASS  $n" -ForegroundColor Green } else { $script:fail++; Write-Host "  FAIL  $n" -ForegroundColor Red } }

Write-Host "=== PIM-DisableGuard (account-disable circuit breaker) ===" -ForegroundColor Cyan

# ---------------------------------------------------------------------------
# PURE guard decision functions
# ---------------------------------------------------------------------------

# --- env classification (operator decision: test vs protected) -------------
# SEC-02: these are SYNTHETIC ids, and the test-tenant list is now configured EXPLICITLY.
# There is no longer a shipped default list -- the real tenant GUIDs used to be baked into
# PIM-DisableGuard.ps1 (and copied into this test), which published, in a public mirror, the
# very list that decides where destructive features default ON. A test tenant must now be
# named on purpose. These asserts therefore configure the list first.
$REAL_TENANT   = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'   # stands in for the real internal tenant (protected)
$TEST_2LK      = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'   # stands in for MSP test tenant 1
$TEST_MGDOP    = 'cccccccc-cccc-cccc-cccc-cccccccccccc'   # stands in for MSP test tenant 2
$global:PIM_TestTenantIds = @($TEST_2LK, $TEST_MGDOP)
Assert "ENV configured test tenant 1 -> test" ((Resolve-PimEnvironmentClass -TenantId $TEST_2LK) -eq 'test')
Assert "ENV configured test tenant 2 -> test" ((Resolve-PimEnvironmentClass -TenantId $TEST_MGDOP) -eq 'test')
Assert "ENV real internal tenant -> protected" ((Resolve-PimEnvironmentClass -TenantId $REAL_TENANT) -eq 'protected')
Assert "ENV unknown tenant -> protected" ((Resolve-PimEnvironmentClass -TenantId '00000000-0000-0000-0000-000000000000') -eq 'protected')
Assert "ENV absent tenant -> protected"  ((Resolve-PimEnvironmentClass -TenantId '') -eq 'protected')
Assert "ENV case-insensitive test match" ((Resolve-PimEnvironmentClass -TenantId $TEST_2LK.ToUpper()) -eq 'test')
# SEC-02 fail-safe: with NO list configured, nothing is a test tenant -- so a deployment that
# never names one gets the protected (destructive-OFF) default everywhere.
$global:PIM_TestTenantIds = $null; $prevEnvList = $env:PIM_TestTenantIds; $env:PIM_TestTenantIds = $null
Assert "SEC-02: no list configured -> the former default tenants are NOT test" ((Resolve-PimEnvironmentClass -TenantId $TEST_2LK) -eq 'protected')
Assert "SEC-02: no list configured -> the list is empty"                       (@(Get-PimTestTenantIds).Count -eq 0)
$env:PIM_TestTenantIds = $prevEnvList
# operator can reclassify via $global:PIM_TestTenantIds (string or array)
$global:PIM_TestTenantIds = '11111111-1111-1111-1111-111111111111'
Assert "ENV custom list: previous test tenant no longer test" ((Resolve-PimEnvironmentClass -TenantId $TEST_2LK) -eq 'protected')
Assert "ENV custom list: listed id is test"          ((Resolve-PimEnvironmentClass -TenantId '11111111-1111-1111-1111-111111111111') -eq 'test')
# Restore the synthetic list for the G3 block below -- with no list, nothing is a test tenant.
$global:PIM_TestTenantIds = @($TEST_2LK, $TEST_MGDOP)

# G3 -- feature flag is now ENVIRONMENT-AWARE when unset; explicit override always wins.
$global:PIM_AccountDisableEnabled = $null
Assert "G3 unset + protected env -> OFF"  (-not (Test-PimAccountDisableEnabled -TenantId $REAL_TENANT))
Assert "G3 unset + test env -> ON"        (Test-PimAccountDisableEnabled -TenantId $TEST_2LK)
Assert "G3 unset + test tenant 2 -> ON"  (Test-PimAccountDisableEnabled -TenantId $TEST_MGDOP)
Assert "G3 unset + unknown env -> OFF"    (-not (Test-PimAccountDisableEnabled -TenantId 'deadbeef-0000-0000-0000-000000000000'))
# explicit operator setting overrides env default in BOTH directions
Assert "G3 explicit OFF in test env wins" (-not (Test-PimAccountDisableEnabled -Override $false -TenantId $TEST_2LK))
Assert "G3 explicit ON in protected env wins" (Test-PimAccountDisableEnabled -Override $true -TenantId $REAL_TENANT)
# persisted $global override (protected env) flips on; clears back to env default
$global:PIM_AccountDisableEnabled = $true
Assert "G3 persisted ON in protected env wins" (Test-PimAccountDisableEnabled -TenantId $REAL_TENANT)
$global:PIM_AccountDisableEnabled = $false
Assert "G3 persisted OFF in test env wins" (-not (Test-PimAccountDisableEnabled -TenantId $TEST_2LK))
$global:PIM_AccountDisableEnabled = $null
# override truthy-string parsing still works (explicit wins over env)
Assert "G3 explicit override ON"         (Test-PimAccountDisableEnabled -Override $true -TenantId $REAL_TENANT)
Assert "G3 string 'true' ON"             (Test-PimAccountDisableEnabled -Override 'true' -TenantId $REAL_TENANT)
Assert "G3 string 'enabled' ON"          (Test-PimAccountDisableEnabled -Override 'enabled' -TenantId $REAL_TENANT)
Assert "G3 string 'no' OFF (in test env)" (-not (Test-PimAccountDisableEnabled -Override 'no' -TenantId $TEST_2LK))

# G1 -- desired-set resolution
Assert "G1 empty desired = unresolved"    (-not (Test-PimDesiredSetResolved -Desired @()))
Assert "G1 null-only desired = unresolved" (-not (Test-PimDesiredSetResolved -Desired @($null)))
Assert "G1 non-empty + resolved = ok"     (Test-PimDesiredSetResolved -Desired @([pscustomobject]@{x=1}) -Resolved $true)
Assert "G1 non-empty but read FAILED = unresolved" (-not (Test-PimDesiredSetResolved -Desired @([pscustomobject]@{x=1}) -Resolved $false))

# G2 -- mass-disable circuit breaker (absolute + percent)
Assert "G2 zero to disable = safe"        (-not (Test-PimMassDisableSafe -ToDisable 0 -Scanned 100).abort)
Assert "G2 within abs cap = safe"         (-not (Test-PimMassDisableSafe -ToDisable 3 -Scanned 100 -MaxCount 5 -MaxPercent 0).abort)
Assert "G2 over abs cap = abort"          ((Test-PimMassDisableSafe -ToDisable 6 -Scanned 1000 -MaxCount 5 -MaxPercent 0).abort)
Assert "G2 over percent cap = abort"      ((Test-PimMassDisableSafe -ToDisable 3 -Scanned 10 -MaxCount 100 -MaxPercent 10).abort)
Assert "G2 default caps trip the 53/53 incident" ((Test-PimMassDisableSafe -ToDisable 53 -Scanned 53).abort)

# Composite decision: all three guards combine; allowed ONLY when all pass.
$d_off  = Test-PimDisablePassAllowed -ToDisable 1 -Scanned 100 -Desired @([pscustomobject]@{x=1}) -DesiredResolved $true -FeatureOverride $false
Assert "composite: feature off -> not allowed (tripped feature-off)" (-not $d_off.allowed -and $d_off.tripped -eq 'feature-off')
$d_emp  = Test-PimDisablePassAllowed -ToDisable 1 -Scanned 100 -Desired @() -DesiredResolved $false -FeatureOverride $true
Assert "composite: empty desired -> not allowed (tripped empty-desired)" (-not $d_emp.allowed -and $d_emp.tripped -eq 'empty-desired')
$d_mass = Test-PimDisablePassAllowed -ToDisable 53 -Scanned 53 -Desired @([pscustomobject]@{x=1}) -DesiredResolved $true -FeatureOverride $true
Assert "composite: mass-disable -> not allowed (tripped mass-disable)" (-not $d_mass.allowed -and $d_mass.tripped -eq 'mass-disable')
$d_ok   = Test-PimDisablePassAllowed -ToDisable 1 -Scanned 100 -Desired @([pscustomobject]@{x=1}) -DesiredResolved $true -FeatureOverride $true
Assert "composite: opt-in + resolved + 1/100 -> ALLOWED" ($d_ok.allowed -and -not $d_ok.abort)

# Catastrophe guards (G1 empty-desired + G2 mass-disable breaker) are ALWAYS ON,
# independent of the environment class. We simulate "feature defaulted ON because we
# are in a test tenant" by passing FeatureOverride=$true (the env-default outcome for a
# test tenant) and confirm the breaker + empty-desired STILL abort. Then confirm the
# same in a protected env (feature would be OFF, which also aborts -- belt and braces).
# --- test env (feature ON via env default): catastrophe guards still fire ---
$d_test_empty = Test-PimDisablePassAllowed -ToDisable 1 -Scanned 100 -Desired @() -DesiredResolved $false -FeatureOverride $true
Assert "ALWAYS-ON G1 in TEST env: empty-desired aborts even when feature ON" (-not $d_test_empty.allowed -and $d_test_empty.tripped -eq 'empty-desired')
$d_test_mass = Test-PimDisablePassAllowed -ToDisable 53 -Scanned 53 -Desired @([pscustomobject]@{x=1}) -DesiredResolved $true -FeatureOverride $true
Assert "ALWAYS-ON G2 in TEST env: mass-disable aborts even when feature ON" (-not $d_test_mass.allowed -and $d_test_mass.tripped -eq 'mass-disable')
# --- protected env (feature OFF via env default): aborts on feature-off first ---
$d_prot_empty = Test-PimDisablePassAllowed -ToDisable 1 -Scanned 100 -Desired @() -DesiredResolved $false -FeatureOverride $false
Assert "PROTECTED env: empty-desired pass not allowed (feature-off short-circuits)" (-not $d_prot_empty.allowed)
$d_prot_mass = Test-PimDisablePassAllowed -ToDisable 53 -Scanned 53 -Desired @([pscustomobject]@{x=1}) -DesiredResolved $true -FeatureOverride $false
Assert "PROTECTED env: mass-disable pass not allowed" (-not $d_prot_mass.allowed)

# ---------------------------------------------------------------------------
# ENGINE-CORE wiring: an account-disable provider (mirrors New-PimAdminsProvider:
# GetLive = whole tenant, ApplyRemove = disable). We count disables actually applied.
# ---------------------------------------------------------------------------
$script:__disabled = 0
$keyOf = { param($r) "$($r.upn)" }
$equalEnabled = { param($d,$l) [bool]$l.enabled }   # desired = exists+enabled (like Admins)

# Whole "tenant" the provider scans (the GetLive). 53 enabled users -- the incident shape.
$tenant = @(1..53 | ForEach-Object { [pscustomobject]@{ upn = ("u{0}@x" -f $_); enabled = $true } })

function Register-DisableProvider {
    # NOTE: $Live is taken as a PARAMETER (defaulting to the script-scope $tenant) so the
    # GetLive closure captures it as a local via .GetNewClosure(); capturing the bare
    # script-scope $tenant did not survive into the engine's invocation scope (live read
    # back empty/1) which masked the breaker assertions.
    param([object[]]$Desired, [Nullable[bool]]$Resolved, [object]$FeatureOverride, [object[]]$Live = $script:tenant)
    Register-PimEngineProvider -Provider @{
        scope = 'AdminsTest'; entity = 'Account-Definitions-Admins'; isAccountDisable = $true
        disableFeatureOverride = $FeatureOverride
        GetDesired = { param($ctx) $Desired }.GetNewClosure()
        GetLive    = { param($ctx) $Live }.GetNewClosure()
        KeyOf = $keyOf; Equal = $equalEnabled
        ApplyCreate = { param($i,$c) }
        ApplyUpdate = { param($i,$c) }
        ApplyRemove = { param($i,$c) $script:__disabled++ }
    }
    # stamp resolution the way Get-PimDesiredRows would
    if ($null -eq $global:PIM_DesiredResolved -or -not ($global:PIM_DesiredResolved -is [hashtable])) { $global:PIM_DesiredResolved = @{} }
    $global:PIM_DesiredResolved['Account-Definitions-Admins'] = $Resolved
}

Write-Host "`n[engine wiring]" -ForegroundColor Cyan

# REPRO the 06:00 incident: desired admin set read EMPTY (rename/key mismatch) while
# GetLive = the whole 53-user tenant, run Full+Prune+feature ON. The pre-guard
# empty-desired check zeroes prune AND the breaker would abort -> ZERO disables.
$script:__disabled = 0
Register-DisableProvider -Desired @() -Resolved $false -FeatureOverride $true
$rRepro = Invoke-PimEngineScope -Scope 'AdminsTest' -Mode Full -Prune
Assert "REPRO empty-desired whole-tenant: ZERO disabled (not 53)" ($script:__disabled -eq 0)
Assert "REPRO reports remove=0 (nothing disabled)"               ($rRepro.remove -eq 0)

# Desired NON-EMPTY but WRONG (resolved to 2 unrelated rows) -> 53 would be removed;
# breaker (default caps) must abort the WHOLE pass: zero disables, disableAborted set.
$script:__disabled = 0
$wrongDesired = @([pscustomobject]@{ upn='other1@x'; enabled=$true }, [pscustomobject]@{ upn='other2@x'; enabled=$true })
Register-DisableProvider -Desired $wrongDesired -Resolved $true -FeatureOverride $true
$rWrong = Invoke-PimEngineScope -Scope 'AdminsTest' -Mode Full -Prune
Assert "WRONG-desired mass remove: breaker ABORTS, zero disabled" ($script:__disabled -eq 0)
Assert "WRONG-desired: disableAborted = mass-disable"            ($rWrong.disableAborted -eq 'mass-disable')

# Feature OFF (default) but a legit single removal pending -> still zero disables.
$script:__disabled = 0
# desired = 52 of the 53 are admins (so exactly 1 would be removed -> within blast radius)
$desired52 = @($tenant | Select-Object -First 52 | ForEach-Object { [pscustomobject]@{ upn=$_.upn; enabled=$true } })
Register-DisableProvider -Desired $desired52 -Resolved $true -FeatureOverride $false
$rOff = Invoke-PimEngineScope -Scope 'AdminsTest' -Mode Full -Prune
Assert "feature OFF: zero disabled even for a single legit removal" ($script:__disabled -eq 0)
Assert "feature OFF: disableAborted = feature-off"                  ($rOff.disableAborted -eq 'feature-off')

# Feature ON, single genuinely-offboarded account, resolved desired, within caps ->
# the legit path STILL disables exactly 1.
$script:__disabled = 0
Register-DisableProvider -Desired $desired52 -Resolved $true -FeatureOverride $true
$rLegit = Invoke-PimEngineScope -Scope 'AdminsTest' -Mode Full -Prune
Assert "feature ON + 1 offboarded + within caps: disables exactly 1" ($script:__disabled -eq 1 -and $rLegit.remove -eq 1)
Assert "legit path: no abort"                                        ($null -eq $rLegit.disableAborted)

# Delta (no prune) never removes -> never disables, regardless of feature/desired.
$script:__disabled = 0
Register-DisableProvider -Desired $desired52 -Resolved $true -FeatureOverride $true
$rDelta = Invoke-PimEngineScope -Scope 'AdminsTest' -Mode Delta
Assert "Delta mode: zero disables (no prune path)" ($script:__disabled -eq 0 -and $rDelta.remove -eq 0)

# ENV-aware engine wiring: simulate a TEST tenant (feature defaults ON) but with the
# 06:00 incident shape (empty-desired, whole 53-user tenant). The catastrophe guard
# (G1 empty-desired) must STILL abort -> ZERO disables, even though env=test => ON.
$script:__disabled = 0
$global:PIM_TestTenantIds = @($TEST_2LK)                         # SEC-02: named explicitly, no shipped default
$global:PIM_TenantId = $TEST_2LK                                 # a configured test tenant => env=test
$global:PIM_AccountDisableEnabled = $null                        # unset => env default (ON in test)
Register-DisableProvider -Desired @() -Resolved $false -FeatureOverride (Test-PimAccountDisableEnabled)
$rTestEnv = Invoke-PimEngineScope -Scope 'AdminsTest' -Mode Full -Prune
Assert "TEST env + empty-desired: env defaults feature ON" (Test-PimAccountDisableEnabled)
Assert "TEST env + empty-desired whole-tenant: ZERO disabled (G1 always-on)" ($script:__disabled -eq 0)

# Same TEST env, WRONG (non-empty) desired -> breaker (G2 always-on) aborts the pass.
$script:__disabled = 0
$wrong2 = @([pscustomobject]@{ upn='other1@x'; enabled=$true }, [pscustomobject]@{ upn='other2@x'; enabled=$true })
Register-DisableProvider -Desired $wrong2 -Resolved $true -FeatureOverride (Test-PimAccountDisableEnabled)
$rTestMass = Invoke-PimEngineScope -Scope 'AdminsTest' -Mode Full -Prune
Assert "TEST env + wrong-desired: breaker ABORTS, zero disabled (G2 always-on)" ($script:__disabled -eq 0 -and $rTestMass.disableAborted -eq 'mass-disable')

# PROTECTED tenant (real internal): feature DEFAULTS OFF -> zero disables even for a
# single legit removal, no explicit flag needed.
$script:__disabled = 0
$global:PIM_TenantId = $REAL_TENANT                              # not in the list => protected
$global:PIM_AccountDisableEnabled = $null
$desired52b = @($tenant | Select-Object -First 52 | ForEach-Object { [pscustomobject]@{ upn=$_.upn; enabled=$true } })
Register-DisableProvider -Desired $desired52b -Resolved $true -FeatureOverride (Test-PimAccountDisableEnabled)
$rProt = Invoke-PimEngineScope -Scope 'AdminsTest' -Mode Full -Prune
Assert "PROTECTED env: feature defaults OFF -> zero disabled" ($script:__disabled -eq 0 -and $rProt.disableAborted -eq 'feature-off')

# === IMP-01: the caps are CLAMPED, and an override is never silent ===========
# §22 says "Do NOT raise the caps to make a run go through" -- but nothing enforced it,
# so PIM_DisableMaxCount = 100000 neutered G2 while the guard still reported itself
# active. A breaker that can be raised without limit is a suggestion, not a breaker.
Write-Host "`n-- IMP-01: override clamping --" -ForegroundColor Cyan
$global:PIM_DisableMaxCount = $null; $global:PIM_DisableMaxPercent = $null
Assert "IMP-01: default count cap is 5"    ((Get-PimDisableMaxCount) -eq 5)
Assert "IMP-01: default percent cap is 10" ((Get-PimDisableMaxPercent) -eq 10)
$global:PIM_DisableMaxCount = 100000
Assert "IMP-01: an absurd count override is CLAMPED to the ceiling" ((Get-PimDisableMaxCount -WarningAction SilentlyContinue) -eq 50)
$global:PIM_DisableMaxPercent = 100
Assert "IMP-01: an absurd percent override is CLAMPED to the ceiling" ((Get-PimDisableMaxPercent -WarningAction SilentlyContinue) -eq 25)
# A modest, legitimate override still works -- clamping must not break a real batch.
$global:PIM_DisableMaxCount = 12; $global:PIM_DisableMaxPercent = 15
Assert "IMP-01: a modest count override is honoured"   ((Get-PimDisableMaxCount -WarningAction SilentlyContinue) -eq 12)
Assert "IMP-01: a modest percent override is honoured" ((Get-PimDisableMaxPercent -WarningAction SilentlyContinue) -eq 15)
# ...and it WARNS, so an override can never be in effect silently.
$warns = @(); $null = Get-PimDisableMaxCount -WarningVariable warns -WarningAction SilentlyContinue
Assert "IMP-01: an override in effect emits a warning" (@($warns).Count -ge 1)
$warnsClamp = @(); $global:PIM_DisableMaxCount = 100000
$null = Get-PimDisableMaxCount -WarningVariable warnsClamp -WarningAction SilentlyContinue
Assert "IMP-01: the clamp warning says CLAMPED" ("$warnsClamp" -match 'CLAMPED')
# The clamp must actually BITE end-to-end: 100 disables must still abort under an
# absurd override, because the effective cap is the ceiling, not the requested value.
$global:PIM_DisableMaxCount = 100000; $global:PIM_DisableMaxPercent = 0
$clamped = Test-PimMassDisableSafe -ToDisable 100 -Scanned 1000 -WarningAction SilentlyContinue
Assert "IMP-01: 100 disables STILL abort despite a 100000 override" ($clamped.abort -eq $true)
Assert "IMP-01: the decision reports the CLAMPED cap, not the requested one" ($clamped.maxCount -eq 50)
$global:PIM_DisableMaxCount = $null; $global:PIM_DisableMaxPercent = $null

# === BUG-03: the reported environment is the one the guard DECIDED against ====
# Test-PimDisablePassAllowed had no -TenantId, so it resolved the tenant from the
# ambient global while callers reported a class computed from their own -TenantId.
# A safety readout that can disagree with its own decision is worse than none.
Write-Host "`n-- BUG-03: guard reports the tenant it used --" -ForegroundColor Cyan
$global:PIM_TestTenantIds = @('11111111-1111-1111-1111-111111111111')
Remove-Variable -Name PIM_TenantId -Scope Global -ErrorAction SilentlyContinue
$global:PIM_AccountDisableEnabled = $null   # let the ENV default decide, as in production
$vTest = Test-PimDisablePassAllowed -ToDisable 1 -Scanned 100 -Desired @(@{x=1}) -DesiredResolved $true -TenantId '11111111-1111-1111-1111-111111111111'
Assert "BUG-03: explicit TEST tenant -> env default ON, allowed" ($vTest.allowed -eq $true)
Assert "BUG-03: verdict echoes environment=test"                 ("$($vTest.environment)" -eq 'test')
Assert "BUG-03: verdict echoes the tenant it decided against"    ("$($vTest.tenantId)" -eq '11111111-1111-1111-1111-111111111111')
$vProt = Test-PimDisablePassAllowed -ToDisable 1 -Scanned 100 -Desired @(@{x=1}) -DesiredResolved $true -TenantId '99999999-9999-9999-9999-999999999999'
Assert "BUG-03: explicit UNKNOWN tenant -> protected default OFF" ($vProt.allowed -eq $false -and "$($vProt.tripped)" -eq 'feature-off')
Assert "BUG-03: verdict echoes environment=protected"             ("$($vProt.environment)" -eq 'protected')
# The exact disagreement the finding described: same call, two tenants, opposite
# decisions -- proving the class now follows the decision instead of being computed
# beside it. Before the fix both calls decided against the ambient tenant.
Assert "BUG-03: the two tenants genuinely decide differently" ($vTest.allowed -ne $vProt.allowed)
$global:PIM_TestTenantIds = $null; $global:PIM_AccountDisableEnabled = $null

# === BUG-01: the abort alert is wired on ALL THREE guard-composing paths =====
# Each path's BEHAVIOUR is proved in its own suite (offboard in Test-PimApprovalGate,
# sweep in Test-PimInactivitySweep). This is the inventory check that stops a fourth
# caller -- or a deletion -- from going silent again: the defect was precisely that
# two of the three composite callers never told anyone.
Write-Host "`n-- BUG-01: abort-alert wiring across every disable path --" -ForegroundColor Cyan
$sharedDir = Join-Path (Split-Path -Parent $here) 'engine\_shared'
$alertCallers = @(
    @{ file = 'PIM-EngineCore.ps1';      why = 'engine disable pass' },
    @{ file = 'PIM-ApprovalGate.ps1';    why = 'offboard execution gate (gate 3)' },
    @{ file = 'PIM-InactivitySweep.ps1'; why = 'Enforce-mode inactivity sweep' }
)
foreach ($c in $alertCallers) {
    $p = Join-Path $sharedDir $c.file
    $txt = if (Test-Path -LiteralPath $p) { [System.IO.File]::ReadAllText($p) } else { '' }
    Assert "BUG-01: $($c.file) raises the abort alert ($($c.why))" ($txt -match 'Write-PimDisableAbortAlert\s+-Scope')
}
# Every composite caller of the guard must be one of the known alerting callers --
# a NEW caller that never alerts is the exact regression this finding was about.
$guardCallers = @(Get-ChildItem -LiteralPath $sharedDir -Filter '*.ps1' -File |
    Where-Object { ([System.IO.File]::ReadAllText($_.FullName)) -match 'Test-PimDisablePassAllowed\s+-ToDisable' } |
    ForEach-Object { $_.Name } | Sort-Object)
$known = @($alertCallers | ForEach-Object { $_.file })
$unexpected = @($guardCallers | Where-Object { $known -notcontains $_ })
Assert ("BUG-01: no un-alerted caller of the disable guard" + $(if ($unexpected.Count) { " -- found: $($unexpected -join ', ')" } else { '' })) ($unexpected.Count -eq 0)

# cleanup
$global:PIM_AccountDisableEnabled = $null
$global:PIM_DesiredResolved = $null
$global:PIM_TestTenantIds = $null
Remove-Variable -Name PIM_TenantId -Scope Global -ErrorAction SilentlyContinue

Write-Host ("`n=== RESULT: {0} passed, {1} failed ===" -f $pass,$fail) -ForegroundColor ($(if($fail){'Red'}else{'Green'}))
if ($fail) { exit 1 }
