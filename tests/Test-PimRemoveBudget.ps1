#Requires -Version 5.1
<#
.SYNOPSIS
    G4 -- the UNIVERSAL REMOVAL BUDGET (max 5 removals/deletes per pass) + its email alert.

    Operator directive 2026-08-06: "we must add a gate of max 5 deletes or prunes as extra
    gate. and email to <alert recipient> about it."

    WHY a fourth guard. G1/G2/G3 protect ONE path -- providers flagged isAccountDisable,
    i.e. Admins. Nothing capped removals anywhere else:
      * a -Prune on RolesAUs / GroupMembers / AzRes could remove EVERY live row, because
        their desired keys can never match their live keys (BUG-11);
      * the offboarding sweep DELETES accounts and had no ceiling of any kind;
      * group retirement DELETES groups -- the naming-prefix check guards WHICH, never
        HOW MANY.
    BUG-12 is why a ceiling matters even when the desired set looks correct.

    This gate is deliberately unlike the others: ALWAYS ON (not opt-in, not
    environment-aware) and its ceiling CANNOT be raised -- an override that can neuter a
    guard is not a guard (IMP-01's lesson).

    Offline. No tenant, no network, no mail actually sent.
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

Write-Host "=== G4 universal removal budget (max 5) ===" -ForegroundColor Cyan

Remove-Variable -Name PIM_RemoveMaxCount -Scope Global -ErrorAction SilentlyContinue

# --- the budget itself --------------------------------------------------------
Assert "default budget is 5"                         ((Get-PimRemoveBudget) -eq 5)
$global:PIM_RemoveMaxCount = 2
Assert "an operator may LOWER it"                    ((Get-PimRemoveBudget) -eq 2)
$global:PIM_RemoveMaxCount = 100000
Assert "raising it is CLAMPED to the ceiling (5)"    ((Get-PimRemoveBudget -WarningAction SilentlyContinue) -eq 5)
$global:PIM_RemoveMaxCount = 0
Assert "0 means remove nothing at all"               ((Get-PimRemoveBudget) -eq 0)
$global:PIM_RemoveMaxCount = 'not-a-number'
Assert "garbage falls back to the default, not to unlimited" ((Get-PimRemoveBudget) -eq 5)
Remove-Variable -Name PIM_RemoveMaxCount -Scope Global -ErrorAction SilentlyContinue

# --- the decision -------------------------------------------------------------
$d = Test-PimRemoveBudgetAllowed -ToRemove 0 -Scope 'Groups' -Scanned 100
Assert "nothing to remove -> allowed, no trip"       ($d.allowed -and -not $d.abort)
$d = Test-PimRemoveBudgetAllowed -ToRemove 5 -Scope 'Groups' -Scanned 100
Assert "exactly 5 is ALLOWED (boundary, inclusive)"  ($d.allowed -and -not $d.abort)
$d = Test-PimRemoveBudgetAllowed -ToRemove 6 -Scope 'Groups' -Scanned 100
Assert "6 TRIPS the budget"                          ((-not $d.allowed) -and $d.abort -and $d.tripped -eq 'remove-budget')
Assert "  ...and the reason names the scope + counts" (("$($d.reason)" -match 'Groups') -and ("$($d.reason)" -match '\b6\b'))

# THE case this gate exists for: BUG-11's prune-everything shape.
$d = Test-PimRemoveBudgetAllowed -ToRemove 205 -Scope 'RolesAUs' -Scanned 205 -Operation 'remove'
Assert "BUG-11 shape (205 removals) is BLOCKED"      ((-not $d.allowed) -and $d.abort)
# ...and BUG-12's shape: 71 ordinary users classed as removals.
$d = Test-PimRemoveBudgetAllowed -ToRemove 71 -Scope 'Admins' -Scanned 79 -Operation 'disable'
Assert "BUG-12 shape (71 disables) is BLOCKED"       ((-not $d.allowed) -and $d.abort)

# ALWAYS ON: unlike the disable guard, no feature flag and no test-tenant class can turn
# this off. A tenant classified 'test' must still be capped.
$global:PIM_TestTenantIds = @('11111111-1111-1111-1111-111111111111')
$global:PIM_TenantId      = '11111111-1111-1111-1111-111111111111'
$global:PIM_AccountDisableEnabled = $true
$d = Test-PimRemoveBudgetAllowed -ToRemove 50 -Scope 'Admins' -Scanned 60
Assert "still trips in a TEST tenant with disable ON (always-on gate)" ((-not $d.allowed) -and $d.abort)
Remove-Variable -Name PIM_TestTenantIds,PIM_TenantId,PIM_AccountDisableEnabled -Scope Global -ErrorAction SilentlyContinue

# --- the ALERT: it must be sent, and it must never throw ----------------------
$script:sent = New-Object System.Collections.Generic.List[object]
function Send-PimNotifyMail { param($Type,$Tokens,$Recipient) $script:sent.Add([pscustomobject]@{ to=$Recipient; subject=$Tokens.Subject; body=$Tokens.Body }) }
$global:PIM_AlertRecipient = 'ops@example.invalid'
$d = Test-PimRemoveBudgetAllowed -ToRemove 99 -Scope 'AzRes' -Scanned 120 -Operation 'remove'
$threw = $false
try { Write-PimRemoveBudgetAlert -Decision $d -WarningAction SilentlyContinue 6>$null } catch { $threw = $true }
Assert "the alert never throws"                      (-not $threw)
Assert "an email IS sent"                            ($script:sent.Count -eq 1)
Assert "  ...to the CONFIGURED recipient"            ("$($script:sent[0].to)" -eq 'ops@example.invalid')
Assert "  ...with the scope + counts in the subject" (("$($script:sent[0].subject)" -match 'AzRes') -and ("$($script:sent[0].subject)" -match '99'))
Assert "  ...and 'Removed NOTHING' in the body"      ("$($script:sent[0].body)" -match 'Removed NOTHING')

# A send failure must not become the failure.
$script:sent.Clear()
function Send-PimNotifyMail { param($Type,$Tokens,$Recipient) throw 'smtp down' }
$threw = $false
try { Write-PimRemoveBudgetAlert -Decision $d -WarningAction SilentlyContinue 6>$null 3>$null } catch { $threw = $true }
Assert "a failed send does not throw"                (-not $threw)
Assert "  ...and IS reported as swallowed (IMP-03)"  (@(Get-PimSwallowedErrors -Scope 'remove-budget-alert-mail').Count -ge 1)

# No recipient configured -> must be LOUD, not silent. (The address is configuration, never
# shipped source -- a real address in source is exactly what SEC-05 removed.)
Remove-Variable -Name PIM_AlertRecipient -Scope Global -ErrorAction SilentlyContinue
$env:PIM_AlertRecipient = ''
$threw = $false
try { Write-PimRemoveBudgetAlert -Decision $d -WarningAction SilentlyContinue 6>$null } catch { $threw = $true }
Assert "no configured recipient still does not throw" (-not $threw)

# --- the WIRING: the gate has to actually be called ---------------------------
$core = [System.IO.File]::ReadAllText((Join-Path $shared 'PIM-EngineCore.ps1'))
Assert "the engine calls the budget for EVERY scope's removes" ($core -match 'Test-PimRemoveBudgetAllowed')
Assert "  ...and DROPS the whole remove set on a trip"         ($core -match 'Write-PimRemoveBudgetAlert[\s\S]{0,400}?remove = @\(\)')
$fn = [System.IO.File]::ReadAllText((Join-Path $shared 'PIM-Functions.psm1'))
Assert "the offboarding/DELETE sweep is budgeted"              ($fn -match "Scope 'AdminOffboarding'[\s\S]{0,200}?offboard/delete" -or $fn -match "offboard/delete")
Assert "group RETIREMENT (delete group) is budgeted"           ($fn -match "delete group")
# The engine gate must run for PLAN too, so a -WhatIf shows the abort rather than hiding it.
Assert "the budget runs before the plan is printed (plan shows the abort)" `
    ($core -match 'Test-PimRemoveBudgetAllowed[\s\S]{0,900}?Progress logging')

# No real address may be hardcoded -- SEC-05.
$guard = [System.IO.File]::ReadAllText((Join-Path $shared 'PIM-DisableGuard.ps1'))
Assert "the alert recipient is CONFIGURED, never hardcoded"    ($guard -notmatch '@2linkit\.net' -and $guard -match 'PIM_AlertRecipient')

Write-Host ""
Write-Host ("G4 removal budget: {0} passed, {1} failed" -f $pass, $fail) -ForegroundColor $(if ($fail) { 'Red' } else { 'Green' })
if ($fail) { exit 1 }
exit 0
