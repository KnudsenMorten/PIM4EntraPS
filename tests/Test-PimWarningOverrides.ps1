<#
  Offline tests for the validator WARNING OVERRIDE / acknowledgement post-filter
  (engine/_shared/PIM-WarningOverrides.ps1 -- REQUIREMENTS § 11). PURE -- no
  network, time injected for expiry. Mirrors the contract:
    * suppress by code
    * suppress by code + instance scope (subject/target)
    * suppress by pattern (wildcard)
    * mandatory reason enforced (and mandatory code / expiresOn)
    * expired override -> finding RESURFACES as active (counted)
    * acknowledged findings are COUNTED, not dropped
#>
[CmdletBinding()] param()
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $here) { $here = 'C:\SCRIPTS\AutomateIT\SOLUTIONS\PIM4EntraPS\tests' }
. "$here\..\engine\_shared\PIM-WarningOverrides.ps1"

$pass=0; $fail=0
function Assert($n,$c){ if($c){ $script:pass++; Write-Host "  PASS  $n" -ForegroundColor Green } else { $script:fail++; Write-Host "  FAIL  $n" -ForegroundColor Red } }

$now = ([datetime]'2026-06-15T12:00:00Z').ToUniversalTime()

# Helper: a validator-shaped finding.
function NewF($sev,$code,$subject,$target,$msg,$csv='PIM-Assignments-Admins',$row=3) {
    [pscustomobject]@{
        Severity=$sev; Code=$code; Csv=$csv; Row=$row; Column='GroupTag'
        Message=$msg; Suggestion='x'; Subject=$subject; Target=$target
    }
}

Write-Host "=== PIM-WarningOverrides tests ===" -ForegroundColor Cyan

# Representative finding set (the operator's real noise + a hard error).
$findings = @(
    NewF 'warning' 'PIM-DUP-001'    'Admin-PAW-ID@contoso.com' 'entra:application developer' "Admin 'Admin-PAW-ID@contoso.com' reaches target 'entra:application developer' via 2 role-group paths: A, B."
    NewF 'warning' 'PIM-DUP-001'    'Admin-PAW-MP@contoso.com' 'az:/sub/x:owner'            "Admin 'Admin-PAW-MP@contoso.com' reaches target 'az:/sub/x:owner' via 2 role-group paths: C, D."
    NewF 'warning' 'PIM-ORPHAN-001' 'break-glass-01@contoso.com' ''                          "Admin 'break-glass-01@contoso.com' has zero rows."
    NewF 'error'   'PIM-FK-001'     '' ''                                                    "GroupTag 'TYPO' not defined."
)

# ---------------------------------------------------------------------------
# 1. Suppress by CODE (no scope, no pattern -> all of that code)
# ---------------------------------------------------------------------------
Write-Host "-- suppress by code --" -ForegroundColor DarkCyan
$cfg = @{ overrides = @(@{ code='PIM-DUP-001'; reason='accepted bundle layout'; expiresOn='2026-12-31' }) }
$r = Apply-PimWarningOverrides -Findings $findings -Config $cfg -AsOf $now
Assert "both PIM-DUP-001 acknowledged"                 ($r.acknowledged -eq 2)
Assert "acknowledged findings are KEPT (not dropped)"  (@($r.findings).Count -eq 4)
$dups = @($r.findings | Where-Object { $_.Code -eq 'PIM-DUP-001' })
Assert "downgraded to severity 'acknowledged'"         (@($dups | Where-Object { $_.Severity -eq 'acknowledged' }).Count -eq 2)
Assert "annotated with reason"                          ($dups[0].AckReason -eq 'accepted bundle layout')
Assert "original severity preserved for audit"         ($dups[0].OriginalSeverity -eq 'warning')
Assert "ORPHAN untouched by a DUP-only override"       ((@($r.findings | Where-Object { $_.Code -eq 'PIM-ORPHAN-001' })[0]).Severity -eq 'warning')

# ---------------------------------------------------------------------------
# 2. Suppress by CODE + INSTANCE SCOPE (subject + target)
# ---------------------------------------------------------------------------
Write-Host "-- suppress by code + instance scope --" -ForegroundColor DarkCyan
$cfg = @{ overrides = @(@{ code='PIM-DUP-001'; reason='reviewed'; expiresOn='2026-12-31';
            scope=@{ subject='Admin-PAW-ID@contoso.com'; target='entra:application developer' } }) }
$r = Apply-PimWarningOverrides -Findings $findings -Config $cfg -AsOf $now
Assert "only the matching instance acknowledged"       ($r.acknowledged -eq 1)
$ack = @($r.findings | Where-Object { $_.Severity -eq 'acknowledged' })
Assert "it is the ID/application-developer instance"   ($ack[0].Subject -eq 'Admin-PAW-ID@contoso.com')
$other = @($r.findings | Where-Object { $_.Subject -eq 'Admin-PAW-MP@contoso.com' })[0]
Assert "the other DUP instance stays active"           ($other.Severity -eq 'warning')

# scope mismatch on target -> no suppression
$cfg = @{ overrides = @(@{ code='PIM-DUP-001'; reason='r'; expiresOn='2026-12-31';
            scope=@{ subject='Admin-PAW-ID@contoso.com'; target='WRONG' } }) }
$r = Apply-PimWarningOverrides -Findings $findings -Config $cfg -AsOf $now
Assert "scope target mismatch -> not suppressed"       ($r.acknowledged -eq 0)

# ---------------------------------------------------------------------------
# 3. Suppress by PATTERN (wildcard over subject/target/message)
# ---------------------------------------------------------------------------
Write-Host "-- suppress by pattern --" -ForegroundColor DarkCyan
$cfg = @{ overrides = @(@{ code='PIM-DUP-001'; reason='all PAW admins'; expiresOn='2026-12-31';
            pattern='Admin-PAW-*@contoso.com' }) }
$r = Apply-PimWarningOverrides -Findings $findings -Config $cfg -AsOf $now
Assert "pattern matches both PAW admins"               ($r.acknowledged -eq 2)

$cfg = @{ overrides = @(@{ code='PIM-DUP-001'; reason='only MP'; expiresOn='2026-12-31';
            pattern='*az:/sub/*' }) }
$r = Apply-PimWarningOverrides -Findings $findings -Config $cfg -AsOf $now
Assert "pattern over target matches only one"          ($r.acknowledged -eq 1)

# ---------------------------------------------------------------------------
# 4. Mandatory fields enforced (code, reason, expiresOn-unless-noExpiry)
# ---------------------------------------------------------------------------
Write-Host "-- mandatory fields --" -ForegroundColor DarkCyan
$cfg = @{ overrides = @(@{ code='PIM-DUP-001'; expiresOn='2026-12-31' }) }   # no reason
$r = Apply-PimWarningOverrides -Findings $findings -Config $cfg -AsOf $now
Assert "missing reason -> override ignored"            ($r.acknowledged -eq 0)
Assert "missing reason -> reported as invalid"         (@($r.invalidOverrides | Where-Object { $_.reason -like '*reason*' }).Count -eq 1)

$cfg = @{ overrides = @(@{ reason='r'; expiresOn='2026-12-31' }) }           # no code
$r = Apply-PimWarningOverrides -Findings $findings -Config $cfg -AsOf $now
Assert "missing code -> override ignored + reported"   ($r.acknowledged -eq 0 -and @($r.invalidOverrides | Where-Object { $_.reason -like '*code*' }).Count -eq 1)

$cfg = @{ overrides = @(@{ code='PIM-DUP-001'; reason='r' }) }               # no expiresOn, no noExpiry
$r = Apply-PimWarningOverrides -Findings $findings -Config $cfg -AsOf $now
Assert "no expiresOn + no noExpiry -> ignored"         ($r.acknowledged -eq 0 -and @($r.invalidOverrides | Where-Object { $_.reason -like '*expiresOn*' }).Count -eq 1)

$cfg = @{ overrides = @(@{ code='PIM-DUP-001'; reason='r'; noExpiry=$true }) } # explicit no-expiry OK
$r = Apply-PimWarningOverrides -Findings $findings -Config $cfg -AsOf $now
Assert "explicit noExpiry -> valid + suppresses"       ($r.acknowledged -eq 2 -and @($r.invalidOverrides).Count -eq 0)

# ---------------------------------------------------------------------------
# 5. Expired override -> finding RESURFACES as active (counted)
# ---------------------------------------------------------------------------
Write-Host "-- expired override resurfaces --" -ForegroundColor DarkCyan
$cfg = @{ overrides = @(@{ code='PIM-DUP-001'; reason='expired ack'; expiresOn='2026-01-01' }) }
$r = Apply-PimWarningOverrides -Findings $findings -Config $cfg -AsOf $now
Assert "expired -> nothing acknowledged"               ($r.acknowledged -eq 0)
Assert "expired -> counted as expiredToActive"         ($r.expiredToActive -eq 2)
$resurfaced = @($r.findings | Where-Object { $_.Code -eq 'PIM-DUP-001' })
Assert "expired finding stays ACTIVE (warning)"        (@($resurfaced | Where-Object { $_.Severity -eq 'warning' }).Count -eq 2)
Assert "expired finding annotated AckExpired"          ($resurfaced[0].AckExpired -eq $true)

# boundary: expires today -> still suppresses through end of day
$cfg = @{ overrides = @(@{ code='PIM-DUP-001'; reason='today'; expiresOn='2026-06-15' }) }
$r = Apply-PimWarningOverrides -Findings $findings -Config $cfg -AsOf $now
Assert "expiresOn == today -> still suppresses"        ($r.acknowledged -eq 2)

# unparseable date -> fail-safe (treated as expired, never indefinite)
$cfg = @{ overrides = @(@{ code='PIM-DUP-001'; reason='typo'; expiresOn='not-a-date' }) }
$r = Apply-PimWarningOverrides -Findings $findings -Config $cfg -AsOf $now
Assert "unparseable expiresOn -> not suppressed"       ($r.acknowledged -eq 0)

# ---------------------------------------------------------------------------
# 6. Errors are never acknowledged
# ---------------------------------------------------------------------------
Write-Host "-- errors are hard gates --" -ForegroundColor DarkCyan
$cfg = @{ overrides = @(@{ code='PIM-FK-001'; reason='try to silence an error'; expiresOn='2026-12-31' }) }
$r = Apply-PimWarningOverrides -Findings $findings -Config $cfg -AsOf $now
Assert "error severity never downgraded"               ($r.acknowledged -eq 0 -and (@($r.findings | Where-Object { $_.Code -eq 'PIM-FK-001' })[0]).Severity -eq 'error')

# ---------------------------------------------------------------------------
# 7. Empty / missing config -> pass-through
# ---------------------------------------------------------------------------
Write-Host "-- no config pass-through --" -ForegroundColor DarkCyan
$r = Apply-PimWarningOverrides -Findings $findings -AsOf $now
Assert "no config -> all findings unchanged"           ($r.acknowledged -eq 0 -and @($r.findings).Count -eq 4)

Write-Host "`n  $pass passed, $fail failed" -ForegroundColor $(if($fail){'Red'}else{'Green'})
if ($fail) { exit 1 }
