<#
  Offline tests for the PIM4EntraPS lifecycle / governance helpers
  (engine/_shared/PIM-Governance.ps1 -- REQUIREMENTS § 13). All four backlog
  items: scheduled creation + TAP due-logic, lifecycle-calendar orchestration,
  KV-backed break-glass verify (constant-time + lockout + TTL clamp), and the
  access-review feedback loop. PURE -- no network, no clock (time injected).
#>
[CmdletBinding()] param()
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $here) { $here = 'C:\SCRIPTS\AutomateIT\SOLUTIONS\PIM4EntraPS\tests' }
. "$here\..\engine\_shared\PIM-DateExpression.ps1"
. "$here\..\engine\_shared\PIM-ChangeQueue.ps1"
. "$here\..\engine\_shared\PIM-Lifecycle.ps1"
. "$here\..\engine\_shared\PIM-Governance.ps1"

$pass=0; $fail=0
function Assert($n,$c){ if($c){ $script:pass++; Write-Host "  PASS  $n" -ForegroundColor Green } else { $script:fail++; Write-Host "  FAIL  $n" -ForegroundColor Red } }
$now = ([datetime]'2026-06-14T12:00:00Z').ToUniversalTime()

Write-Host "=== PIM-Governance tests ===" -ForegroundColor Cyan

# ---------------------------------------------------------------------------
# 1. Scheduled creation + TAP
# ---------------------------------------------------------------------------
Write-Host "-- scheduled creation + TAP --" -ForegroundColor DarkCyan

$d = Get-PimScheduledCreationDue -NowUtc $now -ProvisionUtc $null -TapStartUtc $null -CreateTap $false
Assert "no provision date -> create immediately"        ($d.createAccount -and -not $d.tapDue)

$d = Get-PimScheduledCreationDue -NowUtc $now -ProvisionUtc $now.AddDays(5) -CreateTap $false
Assert "future provision date -> not yet"               (-not $d.createAccount -and $d.reason -eq 'account-scheduled-future')

$d = Get-PimScheduledCreationDue -NowUtc $now -ProvisionUtc $now.AddHours(-1) -CreateTap $false
Assert "past provision date -> create due"              ($d.createAccount)

$d = Get-PimScheduledCreationDue -NowUtc $now -ProvisionUtc $now.AddHours(-1) -TapStartUtc $now.AddHours(2) -CreateTap $true -TapLeadHours 24
Assert "TAP within lead window -> tap due"              ($d.createAccount -and $d.tapDue -and $d.tapReason -eq 'tap-within-lead-window')

$d = Get-PimScheduledCreationDue -NowUtc $now -ProvisionUtc $now.AddHours(-1) -TapStartUtc $now.AddDays(10) -CreateTap $true -TapLeadHours 24
Assert "far-future TAP -> deferred"                     ($d.createAccount -and -not $d.tapDue -and $d.tapReason -eq 'tap-deferred')

$d = Get-PimScheduledCreationDue -NowUtc $now -ProvisionUtc $now.AddDays(2) -TapStartUtc $now -CreateTap $true
Assert "TAP waits for the account even if TAP start passed" (-not $d.createAccount -and -not $d.tapDue -and $d.tapReason -eq 'tap-waits-for-account')

# row-driven (resolves date expressions)
$rows = @(
    [pscustomobject]@{ UserName='svc-future';  ProvisionDate='2026-06-20'; CreateTAP='true';  TAPStartDate='2026-06-20' }   # future
    [pscustomobject]@{ UserName='svc-now';      ProvisionDate='2026-06-13'; CreateTAP='true';  TAPStartDate='2026-06-14' }   # due, tap within 24h
    [pscustomobject]@{ UserName='svc-done';     ProvisionDate='2026-06-13'; Provisioned='true' }                            # already done -> skip
    [pscustomobject]@{ UserName='svc-noschedule' }                                                                          # no dates -> immediate
)
$due = @(Get-PimDueScheduledCreations -Rows $rows -NowUtc $now)
Assert "due set excludes already-provisioned + future"  ((@($due.row.UserName) -contains 'svc-now') -and (@($due.row.UserName) -contains 'svc-noschedule') -and (@($due.row.UserName) -notcontains 'svc-done') -and (@($due.row.UserName) -notcontains 'svc-future'))
$nowDue = @($due | Where-Object { $_.row.UserName -eq 'svc-now' })[0]
Assert "due row carries the decision (tap due within lead)" ($nowDue.decision.createAccount -and $nowDue.decision.tapDue)

# ---------------------------------------------------------------------------
# 2. Lifecycle calendar (surfaces the tested core)
# ---------------------------------------------------------------------------
Write-Host "-- lifecycle calendar --" -ForegroundColor DarkCyan

$items = @(
    [pscustomobject]@{ UserName='a@x'; ExpiresUtc=$now.AddDays(3).ToString('o');  AutoExtend='false' }   # escalation (7d stage), no renew
    [pscustomobject]@{ UserName='b@x'; ExpiresUtc=$now.AddDays(5).ToString('o');  AutoExtend='true'  }   # within renew window -> renew
    [pscustomobject]@{ UserName='c@x'; ExpiresUtc=$now.AddDays(200).ToString('o') }                      # outside horizon -> nothing
)
$cal = Build-PimLifecycleCalendar -Items $items -NowUtc $now -HorizonDays 30 -RenewWithinDays 7 -ExtendDays 90
Assert "calendar upcoming filters horizon"              (@($cal.upcoming).Count -eq 2)
Assert "calendar raises an escalation for a@x"          ((@($cal.escalations.key) -contains 'a@x'))
Assert "calendar auto-renews AutoExtend b@x only"       (@($cal.renewals).Count -eq 1 -and $cal.renewals[0].key -eq 'b@x')

# new escalation fires once, then is suppressed by the notify log until the reminder interval
$cal2 = Build-PimLifecycleCalendar -Items $items -NowUtc $now -NotifyLog @{ 'a@x' = [pscustomobject]@{ stage = $cal.escalations[0].stage; notifiedUtc = $now.ToString('o') } }
Assert "same-stage escalation suppressed by notify log" (-not (@($cal2.escalations.key) -contains 'a@x'))

# renewals -> change-queue Update records
$changes = @(Get-PimLifecycleRenewalChanges -Calendar $cal -Entity 'PIM-Definitions-Admins' -DateField 'ExpiresUtc')
Assert "renewal -> change-queue Update record"          ($changes.Count -eq 1 -and $changes[0].op -eq 'Update' -and $changes[0].key -eq 'b@x' -and $changes[0].payload.AutoRenewed -eq $true)

# escalation send (WhatIf -> renders, never sends; updates the notify log)
$resolver = { param($sym,$item) if ($sym -eq 'owner') { "owner-of-$($item.UserName)" } else { $null } }
$send = Send-PimLifecycleEscalations -Calendar $cal -RecipientResolver $resolver -WhatIf
Assert "escalation send returns a per-recipient result"  (@($send.results).Count -ge 1)
Assert "escalation send updates the notify log"          ($send.notifyLog.ContainsKey('a@x'))

# ---------------------------------------------------------------------------
# 3. Emergency break-glass (KV-backed, constant-time, lockout, TTL)
# ---------------------------------------------------------------------------
Write-Host "-- emergency break-glass --" -ForegroundColor DarkCyan

$secret = 'correct horse battery staple'
$hash   = Get-PimSha256Hex -Text $secret
Assert "sha256 hex is 64 lowercase hex chars"          ($hash -match '^[0-9a-f]{64}$')
Assert "passcode matches expected hash"                (Test-PimPasscodeHash -Passcode $secret -ExpectedHashHex $hash)
Assert "wrong passcode rejected"                       (-not (Test-PimPasscodeHash -Passcode 'nope' -ExpectedHashHex $hash))
Assert "empty expected hash never matches"             (-not (Test-PimPasscodeHash -Passcode $secret -ExpectedHashHex ''))
Assert "constant-time equal true for equal"            (Test-PimConstantTimeEqual 'abc' 'abc')
Assert "constant-time equal false for different len"   (-not (Test-PimConstantTimeEqual 'abc' 'abcd'))

# TTL clamp
Assert "TTL unset -> default 4h"                       ((Get-PimEmergencyTtlHours -RequestedHours $null) -eq 4)
Assert "TTL clamps to max 24h"                         ((Get-PimEmergencyTtlHours -RequestedHours 99) -eq 24)
Assert "TTL clamps to min 1h"                          ((Get-PimEmergencyTtlHours -RequestedHours 0) -eq 1)

# lockout
$fails = @($now.AddMinutes(-1), $now.AddMinutes(-2), $now.AddMinutes(-3), $now.AddMinutes(-4), $now.AddMinutes(-5))
$lk = Test-PimLockout -Failures $fails -NowUtc $now
Assert "5 failures within window -> locked"            ($lk.locked)
$old = @($now.AddMinutes(-20), $now.AddMinutes(-30))
$lk2 = Test-PimLockout -Failures ($fails + $old) -NowUtc $now
Assert "out-of-window failures pruned"                 ($lk2.recentFailures.Count -eq 5)

# end-to-end verify composing the helpers
$v = Resolve-PimEmergencyVerification -Passcode $secret -ExpectedHashHex $hash -NowUtc $now -Failures @()
Assert "verify ok on correct passcode"                ($v.ok)
$v = Resolve-PimEmergencyVerification -Passcode 'wrong' -ExpectedHashHex $hash -NowUtc $now -Failures @()
Assert "verify records a failure on miss"             (-not $v.ok -and $v.error -eq 'invalid passcode' -and $v.recentFailures.Count -eq 1)
$v = Resolve-PimEmergencyVerification -Passcode $secret -ExpectedHashHex $hash -NowUtc $now -Failures $fails
Assert "verify refuses while locked (even if correct)" (-not $v.ok -and $v.error -like 'locked:*')
$v = Resolve-PimEmergencyVerification -Passcode $secret -ExpectedHashHex '' -NowUtc $now -Failures @()
Assert "verify errors when no passcode configured"    (-not $v.ok -and $v.error -like 'no emergency passcode*')

# KV-first hash resolution (local fallback used when no vault configured)
$global:PIM_EmergencyVault = $null
$global:PIM_EmergencyPasscodeHash = $hash
$res = Resolve-PimEmergencyExpectedHash
Assert "expected hash falls back to local config"     ($res.hash -eq $hash -and $res.source -eq 'local')
$global:PIM_EmergencyPasscodeHash = $null
$res = Resolve-PimEmergencyExpectedHash
Assert "no hash anywhere -> source none"              ($res.hash -eq '' -and $res.source -eq 'none')

# ---------------------------------------------------------------------------
# 4. Access-review feedback loop
# ---------------------------------------------------------------------------
Write-Host "-- access-review feedback loop --" -ForegroundColor DarkCyan

$auto = Get-PimAccessReviewDecision -Item ([pscustomobject]@{ UserName='svc@x'; AutoExtend='true'; Owners='o1@x' })
Assert "AutoExtend row -> auto-extend, no owner gate"  ($auto.action -eq 'auto-extend' -and $auto.reviewers.Count -eq 0)

$gated = Get-PimAccessReviewDecision -Item ([pscustomobject]@{ UserName='u@x'; Owners='o1@x|o2@x' })
Assert "non-auto row -> owner-approval"                ($gated.action -eq 'owner-approval')
Assert "owners parsed pipe-joined"                     (@($gated.reviewers) -contains 'o1@x' -and @($gated.reviewers) -contains 'o2@x')

$fb = Get-PimAccessReviewDecision -Item ([pscustomobject]@{ UserName='u2@x'; Department='Finance' })
Assert "owner falls back to department"                ($fb.reviewers.Count -eq 1 -and $fb.reviewers[0] -eq 'Finance')

$plan = @(Get-PimAccessReviewPlan -Items @(
    [pscustomobject]@{ UserName='a'; AutoExtend='yes' },
    [pscustomobject]@{ UserName='b'; Owners='o@x' }
))
Assert "review plan maps each item"                    ($plan.Count -eq 2 -and ($plan | Where-Object { $_.key -eq 'a' }).action -eq 'auto-extend')

# feedback records close the loop
$deny = New-PimReviewFeedbackRecord -Key 'u@x' -Outcome 'Deny' -NowUtc $now -DecidedBy 'o1@x'
Assert "Deny -> suppress re-add, no new expiry"        ($deny.suppressReAdd -and $null -eq $deny.newExpiryUtc)
$appr = New-PimReviewFeedbackRecord -Key 'u@x' -Outcome 'Approve' -NowUtc $now -ExtendDays 90
Assert "Approve -> not suppressed, new expiry set"     (-not $appr.suppressReAdd -and $appr.newExpiryUtc)

# engine guard: latest decision wins
Assert "denied key is suppressed from re-add"          (Test-PimReviewSuppressesReAdd -Key 'u@x' -Feedback @($deny))
Assert "approved key is not suppressed"                (-not (Test-PimReviewSuppressesReAdd -Key 'u@x' -Feedback @($appr)))
$older = New-PimReviewFeedbackRecord -Key 'u@x' -Outcome 'Deny' -NowUtc $now.AddDays(-1)
$newer = New-PimReviewFeedbackRecord -Key 'u@x' -Outcome 'Approve' -NowUtc $now
Assert "latest decision wins (approve after deny)"     (-not (Test-PimReviewSuppressesReAdd -Key 'u@x' -Feedback @($older,$newer)))
Assert "unknown key -> not suppressed"                 (-not (Test-PimReviewSuppressesReAdd -Key 'zzz' -Feedback @($deny)))

Write-Host ("`n=== RESULT: {0} passed, {1} failed ===" -f $pass,$fail) -ForegroundColor ($(if($fail){'Red'}else{'Green'}))
if ($fail) { exit 1 }
