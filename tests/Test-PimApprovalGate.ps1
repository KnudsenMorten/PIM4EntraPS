<#
  Offline tests for APPROVAL-GATED OFFBOARDING + REVOKE (PIM-ApprovalGate.ps1,
  REQUIREMENTS §27 H3/H4). Closes the incident gap: a destructive identity action
  (offboard/revoke/disable) needs a maker/checker approval before it may execute, and
  automatic offboarding stays PROHIBITED.

  Coverage:
    * Request lifecycle: create -> Pending; approve/deny by id; maker != checker;
      idempotent re-decision; expiry of stale pending; once-only execution latch.
    * Offboard sequence plan (disable -> revoke active -> schedule delete).
    * Offboard executes ONLY when an Approved request exists; never with -Automatic;
      break-glass excluded; DisableGuard circuit breaker NOT bypassed.
    * Revoke needs approval ONLY above the safety threshold; small/break-glass-safe
      ops keep the interim guard; break-glass always excluded.
    * Persistence round-trip via the in-memory/file fallback store.

  Pure + in-memory; no network; PS 5.1-safe. Rerun anytime.
#>
[CmdletBinding()] param()
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $here) { $here = 'C:\SCRIPTS\AutomateIT\SOLUTIONS\PIM4EntraPS\tests' }
. "$here\..\engine\_shared\PIM-DisableGuard.ps1"
. "$here\..\engine\_shared\PIM-ApprovalGate.ps1"

$pass=0; $fail=0
function Assert($n,$c){ if($c){ $script:pass++; Write-Host "  PASS  $n" -ForegroundColor Green } else { $script:fail++; Write-Host "  FAIL  $n" -ForegroundColor Red } }

# Isolate the persistence store to a temp file (no SQL; no Set/Get-PimSetting loaded).
$global:PIM_ApprovalStatePath = Join-Path $env:TEMP ("pim-approval-test-{0}.json" -f ([guid]::NewGuid().ToString('N').Substring(0,8)))
if (Test-Path -LiteralPath $global:PIM_ApprovalStatePath) { Remove-Item -LiteralPath $global:PIM_ApprovalStatePath -Force }
$global:PIM_BreakGlassAccounts = $null
$global:PIM_AllowSelfApprove = $null
$global:PIM_AccountDisableEnabled = $true   # feature ON so the DisableGuard composite is exercised, not short-circuited
$global:PIM_TestTenantIds = $null

Write-Host "=== PIM-ApprovalGate (approval-gated offboarding + revoke) ===" -ForegroundColor Cyan

# ---------------------------------------------------------------------------
# 1. PURE request model + decision core
# ---------------------------------------------------------------------------
$now = [datetime]::UtcNow
$req = New-PimApprovalRequest -Requestor 'maker@contoso' -Action 'Offboard' -Target 'bob@contoso' -Justification 'left the company' -Ticket 'INC-100' -NowUtc $now
Assert "new request status Pending"        ("$($req.status)" -eq 'Pending')
Assert "new request action normalized"     ("$($req.action)" -eq 'offboard')
Assert "new request keeps requestor"       ("$($req.requestor)" -eq 'maker@contoso')
Assert "new request keeps ticket"          ("$($req.ticket)" -eq 'INC-100')
Assert "new request has guid id"           ("$($req.id)" -match '^[0-9a-f-]{36}$')

$badThrew=$false; try { New-PimApprovalRequest -Requestor 'm' -Action 'nuke' -Target 't' | Out-Null } catch { $badThrew=$true }
Assert "unknown action rejected"           $badThrew

# approve (maker != checker)
$d1 = Resolve-PimApprovalDecision -Request $req -Approver 'checker@contoso' -Decision 'approve' -NowUtc $now
Assert "approve ok"                        ($d1.ok -and "$($d1.request.status)" -eq 'Approved')
Assert "approve records approver"          ("$($d1.request.approver)" -eq 'checker@contoso')
Assert "approve sets decidedUtc"           ("$($d1.request.decidedUtc)".Trim() -ne '')

# maker == checker blocked (separation of duties)
$dSelf = Resolve-PimApprovalDecision -Request $req -Approver 'maker@contoso' -Decision 'approve' -NowUtc $now
Assert "self-approve blocked by default"   (-not $dSelf.ok -and "$($dSelf.request.status)" -eq 'Pending')
# ...unless explicitly allowed
$dSelfOk = Resolve-PimApprovalDecision -Request $req -Approver 'maker@contoso' -Decision 'approve' -AllowSelfApprove $true -NowUtc $now
Assert "self-approve allowed when opted-in" ($dSelfOk.ok -and "$($dSelfOk.request.status)" -eq 'Approved')

# deny is always allowed by the same person? deny doesn't need separation; allowed.
$dDeny = Resolve-PimApprovalDecision -Request $req -Approver 'checker@contoso' -Decision 'deny' -Note 'not authorized' -NowUtc $now
Assert "deny ok"                           ($dDeny.ok -and "$($dDeny.request.status)" -eq 'Denied')
Assert "deny records note"                 ("$($dDeny.request.decisionNote)" -eq 'not authorized')

# re-deciding a decided request is a no-op (idempotent)
$d2 = Resolve-PimApprovalDecision -Request $d1.request -Approver 'other@contoso' -Decision 'deny' -NowUtc $now
Assert "re-decide Approved is no-op"       (-not $d2.ok -and "$($d2.status)" -eq 'Approved')

# expiry: a pending request past TTL cannot be approved (auto -> Expired)
$old = New-PimApprovalRequest -Requestor 'm@contoso' -Action 'revoke' -Target 'x' -NowUtc $now.AddHours(-200)
Assert "old pending detected expired"      (Test-PimApprovalRequestExpired -Request $old -NowUtc $now -TtlHours 72)
$dExp = Resolve-PimApprovalDecision -Request $old -Approver 'c@contoso' -Decision 'approve' -NowUtc $now -TtlHours 72
Assert "expired pending not approvable"    (-not $dExp.ok -and "$($dExp.request.status)" -eq 'Expired')
Assert "fresh pending not expired"         (-not (Test-PimApprovalRequestExpired -Request $req -NowUtc $now -TtlHours 72))

# ---------------------------------------------------------------------------
# 2. Approved-for predicate (what the executor checks)
# ---------------------------------------------------------------------------
$approved = $d1.request   # Approved offboard for bob@contoso
$reqSet = @($approved, $dDeny.request, $old)
Assert "approved-for finds matching"       ($null -ne (Test-PimApprovalApprovedFor -Requests $reqSet -Action 'offboard' -Target 'bob@contoso' -NowUtc $now))
Assert "approved-for case-insensitive"     ($null -ne (Test-PimApprovalApprovedFor -Requests $reqSet -Action 'Offboard' -Target 'BOB@CONTOSO' -NowUtc $now))
Assert "approved-for wrong action -> none" ($null -eq (Test-PimApprovalApprovedFor -Requests $reqSet -Action 'revoke' -Target 'bob@contoso' -NowUtc $now))
Assert "approved-for wrong target -> none" ($null -eq (Test-PimApprovalApprovedFor -Requests $reqSet -Action 'offboard' -Target 'alice@contoso' -NowUtc $now))
Assert "denied request not approved-for"   ($null -eq (Test-PimApprovalApprovedFor -Requests @($dDeny.request) -Action 'revoke' -Target 'x' -NowUtc $now))
# a stale Approved (decided long ago) is not executable
$staleApproved = $approved.PSObject.Copy(); $staleApproved.decidedUtc = $now.AddHours(-500).ToString('o')
Assert "stale Approved not executable"     ($null -eq (Test-PimApprovalApprovedFor -Requests @($staleApproved) -Action 'offboard' -Target 'bob@contoso' -NowUtc $now -TtlHours 72))

# ---------------------------------------------------------------------------
# 3. Persistence round-trip (file/in-mem fallback; no SQL)
# ---------------------------------------------------------------------------
$stored = Add-PimApprovalRequest -Requestor 'maker@contoso' -Action 'offboard' -Target 'carol@contoso' -Ticket 'INC-200' -NowUtc $now
Assert "Add returns stored request"        ("$($stored.status)" -eq 'Pending')
$readback = @(Get-PimApprovalRequests -Target 'carol@contoso')
Assert "Get reads back persisted request"  ($readback.Count -eq 1 -and "$($readback[0].id)" -eq "$($stored.id)")
$dec = Set-PimApprovalDecision -Id $stored.id -Approver 'checker@contoso' -Decision 'approve' -NowUtc $now
Assert "Set-PimApprovalDecision approves"   ($dec.ok -and "$($dec.request.status)" -eq 'Approved')
$afterApprove = @(Get-PimApprovalRequests -Status 'Approved' -Target 'carol@contoso')
Assert "approval persisted to store"        ($afterApprove.Count -eq 1)
# self-approve via the persisted entry point is blocked too
$stored2 = Add-PimApprovalRequest -Requestor 'solo@contoso' -Action 'revoke' -Target 'batch-A' -NowUtc $now
$selfDec = Set-PimApprovalDecision -Id $stored2.id -Approver 'solo@contoso' -Decision 'approve' -NowUtc $now
Assert "persisted self-approve blocked"     (-not $selfDec.ok)
Assert "missing id -> not ok"               (-not (Set-PimApprovalDecision -Id 'no-such-id' -Approver 'c' -Decision 'approve').ok)

# once-only execution latch
$ex1 = Set-PimApprovalRequestExecuted -Id $stored.id -NowUtc $now
Assert "first execute latch ok"            ($ex1.ok -and "$($ex1.request.status)" -eq 'Executed')
$ex2 = Set-PimApprovalRequestExecuted -Id $stored.id -NowUtc $now
Assert "second execute is no-op"           (-not $ex2.ok)
# an Executed request no longer counts as approved-for (cannot drive a 2nd run)
Assert "executed request not approved-for" ($null -eq (Test-PimApprovalApprovedFor -Requests @(Get-PimApprovalRequests) -Action 'offboard' -Target 'carol@contoso' -NowUtc $now))
# cannot execute a non-approved request
$exBad = Set-PimApprovalRequestExecuted -Id $stored2.id -NowUtc $now
Assert "execute of Pending refused"        (-not $exBad.ok)

# ---------------------------------------------------------------------------
# 4. OFFBOARDING-WITH-APPROVAL
# ---------------------------------------------------------------------------
$plan = @(Get-PimOffboardSequencePlan -Target 'bob@contoso' -DeleteAfterDays 30 -NowUtc $now)
Assert "offboard plan has 3 steps"         ($plan.Count -eq 3)
Assert "offboard step1 disable"            ("$($plan[0].step)" -eq 'disable')
Assert "offboard step2 revoke-active"      ("$($plan[1].step)" -eq 'revoke-active')
Assert "offboard step3 schedule-delete"    ("$($plan[2].step)" -eq 'schedule-delete')
Assert "offboard delete is SCHEDULED"      ("$($plan[2].scheduledDeleteUtc)".Trim() -ne '')

# desired set positively resolved (so DisableGuard G1 passes)
$desired = @([pscustomobject]@{ UserName='someadmin' })

# (a) APPROVED offboard request present -> allowed
$allowApproved = @($d1.request)   # Approved offboard for bob@contoso
$g = Test-PimOffboardExecutionAllowed -Target 'bob@contoso' -Requests $allowApproved -ToDisable 1 -Scanned 50 -Desired $desired -DesiredResolved $true -NowUtc $now
Assert "offboard allowed WITH approval"     ($g.allowed -and $null -ne $g.approval)

# (b) NO approval -> blocked
$gNone = Test-PimOffboardExecutionAllowed -Target 'bob@contoso' -Requests @() -ToDisable 1 -Scanned 50 -Desired $desired -DesiredResolved $true -NowUtc $now
Assert "offboard blocked WITHOUT approval"  (-not $gNone.allowed -and "$($gNone.gate)" -eq 'no-approval')

# (c) -Automatic -> ALWAYS refused, even with an approval (automatic offboarding prohibited)
$gAuto = Test-PimOffboardExecutionAllowed -Target 'bob@contoso' -Requests $allowApproved -Automatic -ToDisable 1 -Scanned 50 -Desired $desired -DesiredResolved $true -NowUtc $now
Assert "automatic offboarding refused"      (-not $gAuto.allowed -and "$($gAuto.gate)" -eq 'automatic-prohibited')

# (d) break-glass target excluded even WITH approval
$global:PIM_BreakGlassAccounts = 'bob@contoso'
$bgApproved = @($d1.request)
$gBg = Test-PimOffboardExecutionAllowed -Target 'bob@contoso' -Requests $bgApproved -ToDisable 1 -Scanned 50 -Desired $desired -DesiredResolved $true -NowUtc $now
Assert "break-glass offboard excluded"      (-not $gBg.allowed -and "$($gBg.gate)" -eq 'break-glass')
$global:PIM_BreakGlassAccounts = $null

# (e) DisableGuard NOT bypassed: empty/unresolved desired -> blocked even WITH approval
$gEmpty = Test-PimOffboardExecutionAllowed -Target 'bob@contoso' -Requests $allowApproved -ToDisable 1 -Scanned 50 -Desired @() -DesiredResolved $false -NowUtc $now
Assert "offboard blocked on unresolved desired" (-not $gEmpty.allowed -and "$($gEmpty.gate)" -like 'disable-guard:*')
# (e2) mass-disable circuit breaker still fires (over the absolute cap) even WITH approval
$gMass = Test-PimOffboardExecutionAllowed -Target 'bob@contoso' -Requests $allowApproved -ToDisable 9999 -Scanned 10000 -Desired $desired -DesiredResolved $true -NowUtc $now
Assert "offboard blocked by mass-disable breaker" (-not $gMass.allowed -and "$($gMass.gate)" -like 'disable-guard:*')

# ---------------------------------------------------------------------------
# 5. REVOKE-WITH-APPROVAL
# ---------------------------------------------------------------------------
$global:PIM_RevokeApprovalThreshold = 5
function New-Rows([int]$n, [string]$prefix='p') {
    $a = New-Object System.Collections.ArrayList
    for ($i=0; $i -lt $n; $i++) { [void]$a.Add([pscustomobject]@{ id="r$i"; principalId="$prefix-$i"; principal="$prefix-$i@contoso"; type='pim-for-groups' }) }
    return $a.ToArray()
}

# small batch (<= threshold) -> no approval required, interim guard applies
$small = New-Rows 3
$needSmall = Test-PimRevokeApprovalRequired -Rows $small
Assert "small batch needs NO approval"      (-not $needSmall.required -and $needSmall.toRevokeCount -eq 3)
$gSmall = Test-PimRevokeExecutionAllowed -Rows $small -Target 'batch-small' -Requests @() -NowUtc $now
Assert "small batch allowed (interim guard)" ($gSmall.allowed -and "$($gSmall.gate)" -eq 'interim-guard')

# big batch (> threshold) -> approval REQUIRED; without it -> blocked
$big = New-Rows 12
$needBig = Test-PimRevokeApprovalRequired -Rows $big
Assert "big batch needs approval"           ($needBig.required -and $needBig.toRevokeCount -eq 12)
$gBigNo = Test-PimRevokeExecutionAllowed -Rows $big -Target 'batch-big' -Requests @() -NowUtc $now
Assert "big batch blocked without approval"  (-not $gBigNo.allowed -and "$($gBigNo.gate)" -eq 'no-approval')

# big batch WITH an Approved revoke request for that target -> allowed
$revReq = New-PimApprovalRequest -Requestor 'maker@contoso' -Action 'revoke' -Target 'batch-big' -NowUtc $now
$revApproved = (Resolve-PimApprovalDecision -Request $revReq -Approver 'checker@contoso' -Decision 'approve' -NowUtc $now).request
$gBigYes = Test-PimRevokeExecutionAllowed -Rows $big -Target 'batch-big' -Requests @($revApproved) -NowUtc $now
Assert "big batch allowed with approval"     ($gBigYes.allowed -and "$($gBigYes.gate)" -eq 'approved')

# break-glass rows always excluded; a big batch that is ALL break-glass drops below threshold
$global:PIM_BreakGlassAccounts = (0..11 | ForEach-Object { "p-$_" }) -join ';'
$needAllBg = Test-PimRevokeApprovalRequired -Rows $big
Assert "all-break-glass batch -> 0 to revoke" ($needAllBg.toRevokeCount -eq 0 -and $needAllBg.skippedCount -eq 12)
Assert "all-break-glass needs NO approval"   (-not $needAllBg.required)
$global:PIM_BreakGlassAccounts = 'p-0;p-1'   # exclude 2 of 12 -> 10 still > threshold
$needPartBg = Test-PimRevokeApprovalRequired -Rows $big
Assert "partial break-glass excluded + counted" ($needPartBg.toRevokeCount -eq 10 -and $needPartBg.skippedCount -eq 2)
Assert "partial-bg big batch still needs approval" ($needPartBg.required)
$global:PIM_BreakGlassAccounts = $null

# threshold is operator-tunable
$global:PIM_RevokeApprovalThreshold = 20
Assert "raised threshold: 12 no longer needs approval" (-not (Test-PimRevokeApprovalRequired -Rows $big).required)
$global:PIM_RevokeApprovalThreshold = $null

# ---------------------------------------------------------------------------
# cleanup + summary
# ---------------------------------------------------------------------------
if (Test-Path -LiteralPath $global:PIM_ApprovalStatePath) { Remove-Item -LiteralPath $global:PIM_ApprovalStatePath -Force -ErrorAction SilentlyContinue }
$global:PIM_ApprovalStatePath = $null
$global:PIM_AccountDisableEnabled = $null

Write-Host ("`n=== RESULT: {0} passed, {1} failed ===" -f $pass, $fail) -ForegroundColor $(if ($fail) {'Red'} else {'Green'})
if ($fail) { exit 1 } else { exit 0 }
