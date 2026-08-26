#Requires -Version 5.1
<#
.SYNOPSIS
    SEC-07 -- every destructive-safety knob must be settable the way the product is
    actually deployed, and the environment must NOT become a way around the ceilings.

    The hosted engine is configured entirely by container environment variables. Two
    knobs in PIM-DisableGuard already honoured the environment (PIM_TestTenantIds --
    which decides where destructive features default ON -- and PIM_BREAKGLASS_ACCOUNTS);
    the rest read $global: only. So in the deployed fleet an operator could not turn the
    account-disable feature OFF and could not LOWER a cap: the setting was accepted,
    reported as available, and silently ignored.

    Measured live by the TEST-11 matrix (case D8): with PIM_AccountDisableEnabled=false
    set as an env var, the guard reported tripped='mass-disable' -- a DIFFERENT guard
    happening to catch the pass -- instead of 'feature-off'. That is exactly how a
    silently-ignored safety switch stays unnoticed, and it is why the matrix asserts
    WHICH guard fired rather than merely that something stopped the run.

    Also covered: the alert recipient. Write-PimRemoveBudgetAlert read $global: then
    $env:, but Write-PimDisableAbortAlert read $global: ONLY -- so in the deployed fleet
    the G4 budget trip emailed and the ORIGINAL 2026-06-15 circuit breaker never did.

    The two assertions that keep this fixed:
      1. EVERY knob in the inventory is honoured from the environment
      2. the environment is NOT a bypass -- the IMP-01 ceilings still clamp

    Offline. No tenant, no network.
#>
[CmdletBinding()] param()

$ErrorActionPreference = 'Stop'
$pass = 0; $fail = 0
function Assert($n, $c) { if ($c) { Write-Host "  PASS  $n" -ForegroundColor Green; $script:pass++ } else { Write-Host "  FAIL  $n" -ForegroundColor Red; $script:fail++ } }

$solRoot = Split-Path -Parent $PSScriptRoot
$shared  = Join-Path $solRoot 'engine\_shared'
. (Join-Path $shared 'PIM-Swallow.ps1')
. (Join-Path $shared 'PIM-DateSafe.ps1')
. (Join-Path $shared 'PIM-DisableGuard.ps1')

Write-Host "=== SEC-07: the safety knobs are settable the way the product is deployed ===" -ForegroundColor Cyan

$TEST_TENANT = '00000000-aaaa-bbbb-cccc-000000000001'

function Clear-Knobs {
    foreach ($k in (Get-PimSafetyKnobNames)) {
        Set-Variable -Name $k.name -Scope Global -Value $null -ErrorAction SilentlyContinue
        [Environment]::SetEnvironmentVariable($k.env, $null, 'Process')
    }
}
function Set-Env($name, $value) { [Environment]::SetEnvironmentVariable($name, $value, 'Process') }

# ---------------------------------------------------------------------------
Write-Host "`n[the reader itself]" -ForegroundColor Cyan
Clear-Knobs
Assert "nothing set -> `$null"                        ($null -eq (Get-PimSafetyKnob -Name 'PIM_DisableMaxCount'))
Set-Env 'PIM_DisableMaxCount' '7'
Assert "env alone is honoured"                        ("$(Get-PimSafetyKnob -Name 'PIM_DisableMaxCount')" -eq '7')
$global:PIM_DisableMaxCount = 3
Assert "an in-process global WINS over the env"       ("$(Get-PimSafetyKnob -Name 'PIM_DisableMaxCount')" -eq '3')
$global:PIM_DisableMaxCount = ''
Assert "an EMPTY global falls through to the env"     ("$(Get-PimSafetyKnob -Name 'PIM_DisableMaxCount')" -eq '7')
Clear-Knobs
$global:PIM_AccountDisableEnabled = $false
Assert "`$false is a VALUE, not 'unset'"              ((Get-PimSafetyKnob -Name 'PIM_AccountDisableEnabled') -is [bool])
Clear-Knobs
Set-Env 'PIM_BREAKGLASS_ACCOUNTS' 'bg@example.test'
Assert "a differing env NAME is honoured"             ("$(Get-PimSafetyKnob -Name 'PIM_BreakGlassAccounts' -EnvName 'PIM_BREAKGLASS_ACCOUNTS')" -eq 'bg@example.test')

# ---------------------------------------------------------------------------
Write-Host "`n[every knob, through the ENVIRONMENT only]" -ForegroundColor Cyan

# 1. the opt-out -- THE one D8 measured
Clear-Knobs
Set-Env 'PIM_TestTenantIds' $TEST_TENANT
Assert "test-tenant list from env -> class 'test'"    ((Resolve-PimEnvironmentClass -TenantId $TEST_TENANT) -eq 'test')
Assert "  ...so the feature DEFAULTS on there"        (Test-PimAccountDisableEnabled -TenantId $TEST_TENANT)
Set-Env 'PIM_AccountDisableEnabled' 'false'
Assert "explicit env opt-OUT beats the env default"   (-not (Test-PimAccountDisableEnabled -TenantId $TEST_TENANT))
$d = Test-PimDisablePassAllowed -ToDisable 1 -Scanned 8 -Desired @([pscustomobject]@{ x=1 }) -DesiredResolved $true -TenantId $TEST_TENANT
Assert "  ...and the guard reports 'feature-off'"     ("$($d.tripped)" -eq 'feature-off' -and -not $d.allowed)
Set-Env 'PIM_AccountDisableEnabled' 'true'
Assert "explicit env opt-IN is honoured too"          (Test-PimAccountDisableEnabled -TenantId '99999999-9999-9999-9999-999999999999')

# 2. the caps
Clear-Knobs
Set-Env 'PIM_DisableMaxCount'   '3'
Set-Env 'PIM_DisableMaxPercent' '15'
Assert "G2 absolute cap from env"                     ((Get-PimDisableMaxCount -WarningAction SilentlyContinue) -eq 3)
Assert "G2 percentage cap from env"                   ((Get-PimDisableMaxPercent -WarningAction SilentlyContinue) -eq 15)
Assert "  ...and a lowered cap really bites"          ((Test-PimMassDisableSafe -ToDisable 4 -Scanned 100 -WarningAction SilentlyContinue).abort)

# 3. the G4 budget
Clear-Knobs
Set-Env 'PIM_RemoveMaxCount' '2'
Assert "G4 budget lowered from env"                   ((Get-PimRemoveBudget -WarningAction SilentlyContinue) -eq 2)
Assert "  ...and a 3-row removal is refused"          (-not (Test-PimRemoveBudgetAllowed -ToRemove 3 -Scope 'X' -WarningAction SilentlyContinue).allowed)

# 4. the report-only brake on unmanaged admins
Clear-Knobs
Set-Env 'PIM_RemoveUnmanagedAdmins' 'false'
$rem = @([pscustomobject]@{ key='ghost'; live=[pscustomobject]@{ userPrincipalName='ghost@example.test'; id='g1' } })
$sel = Select-PimDisableRemovals -Remove $rem -Desired @([pscustomobject]@{ UserPrincipalName='real@example.test' })
Assert "report-only brake from env keeps unmanaged"   (@($sel.remove).Count -eq 0 -and @($sel.unmanaged).Count -eq 1)

# 5. break-glass
Clear-Knobs
Set-Env 'PIM_BREAKGLASS_ACCOUNTS' 'bg1@example.test;bg2@example.test'
Assert "break-glass list from env"                    (@(Get-PimBreakGlassIdentifiers).Count -eq 2)

# 6. the alert recipient -- the half that was silently dead in the fleet
Clear-Knobs
$script:MailTo = @()
function Send-PimNotifyMail { param([string]$Type, [hashtable]$Tokens, [string]$Recipient) $script:MailTo += "$Recipient" }
Set-Env 'PIM_AlertRecipient' 'ops@example.test'
Write-PimRemoveBudgetAlert -Decision ([pscustomobject]@{ scope='X'; operation='remove'; toRemove=9; budget=5; scanned=20 })
Assert "G4 budget alert emails using the env value"   ($script:MailTo -contains 'ops@example.test')
$script:MailTo = @()
Write-PimDisableAbortAlert -Scope 'Admins' -Decision ([pscustomobject]@{ tripped='mass-disable'; reason='r'; toDisable=9; scanned=20 })
Assert "DISABLE-abort alert emails using the env value (was `$global:-only)" ($script:MailTo -contains 'ops@example.test')

# ---------------------------------------------------------------------------
Write-Host "`n[the environment is NOT a bypass -- the IMP-01 ceilings still clamp]" -ForegroundColor Cyan
Clear-Knobs
Set-Env 'PIM_DisableMaxCount'   '100000'
Set-Env 'PIM_DisableMaxPercent' '100'
Set-Env 'PIM_RemoveMaxCount'    '100000'
$w = @()
$c = Get-PimDisableMaxCount   -WarningVariable +w -WarningAction SilentlyContinue
$p = Get-PimDisableMaxPercent -WarningVariable +w -WarningAction SilentlyContinue
$b = Get-PimRemoveBudget      -WarningVariable +w -WarningAction SilentlyContinue
Assert "an absurd env absolute cap is CLAMPED"        ($c -eq 50)
Assert "an absurd env percentage cap is CLAMPED"      ($p -eq 25)
Assert "an absurd env removal budget is CLAMPED"      ($b -eq 5)
Assert "  ...and every clamp WARNS"                   (@($w).Count -ge 3)
Assert "  ...and the clamp still bites end-to-end"    ((Test-PimMassDisableSafe -ToDisable 100 -Scanned 200 -WarningAction SilentlyContinue).abort)

# ---------------------------------------------------------------------------
# The regression that would undo this: a new knob added with a direct $global: read.
Write-Host "`n[structural: no safety knob may be read directly from `$global:]" -ForegroundColor Cyan
$src = Get-Content -LiteralPath (Join-Path $shared 'PIM-DisableGuard.ps1') -Raw
# Strip BLOCK comments as well as line comments before scanning. The file documents the
# knobs by name in its help text, and a doc mention must not read as a code path -- the
# first cut of this test failed on a `<# ... #>` paragraph, which is a false positive of
# exactly the kind that trains people to ignore a suite.
$code = [regex]::Replace($src, '(?s)<#.*?#>', '')
$code = ($code -split "`r?`n" | Where-Object { $_ -notmatch '^\s*#' }) -join "`n"
foreach ($k in (Get-PimSafetyKnobNames)) {
    Assert "$($k.name) is read via Get-PimSafetyKnob" ($code -match [regex]::Escape("Get-PimSafetyKnob -Name '$($k.name)'"))
    Assert "  ...and NOT directly from `$global:"     ($code -notmatch [regex]::Escape("`$global:$($k.name)"))
}
Assert "the inventory covers all 8 knobs"             (@(Get-PimSafetyKnobNames).Count -eq 8)

Clear-Knobs
Write-Host ("`n=== RESULT: {0} passed, {1} failed ===" -f $pass, $fail) -ForegroundColor $(if ($fail) { 'Red' } else { 'Green' })
if ($fail) { exit 1 }
exit 0
