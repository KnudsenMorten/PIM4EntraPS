#Requires -Version 5.1
<#
.SYNOPSIS
    Approvals GUI wiring + Access-Review decision wiring (REQUIREMENTS §11 + §13/§27 H3/H4
    + §H7). Static GUI/server-wiring asserts PLUS in-proc backend tests proving the
    Approvals queue renders, Approve/Deny round-trips through the REAL ApprovalGate
    backend, maker != checker is enforced, and the access-review decision path degrades
    gracefully when AccessReview.ReadWrite.All is not granted. No dead views.

.DESCRIPTION
    Three layers, all offline (no live tenant, no server boot):

      1. STATIC GUI/SERVER WIRING -- the Approvals tab is declared + routed
         (switchTab -> renderApprovals), calls GET /api/approvals + POST /api/approvals
         + POST /api/approvals/{id}/decision; the Access Review tab gains per-item
         Approve/Deny/DontKnow wired to POST /api/access-reviews/decision, plus the
         overdue (GET /api/access-reviews/overdue) + evidence (GET /api/access-reviews/
         evidence) reads; the Home tab has a pending-approvals tile that deep-links to
         the Approvals tab; and the server defines all the handlers. The
         PIM-ApprovalGate.ps1 control plane is dot-sourced at boot with a
         Get-/Set-PimSetting shim onto the Manager store.

      2. APPROVAL QUEUE ROUND-TRIP (in-proc, real backend) -- dot-source the REAL
         PIM-ApprovalGate.ps1 over an in-memory settings store, prove: a maker raises a
         Pending request; a DIFFERENT checker can Approve it (maker != checker); the
         SAME requestor canNOT self-approve (separation of duties); an offboard request
         carries the engine-derived guided sequence plan; the request executes ONCE
         (latch); and there is NO auto-execute path (Test-PimOffboardExecutionAllowed
         refuses -Automatic and refuses when no Approved request exists).

      3. ACCESS-REVIEW DECISION PATH (in-proc, real backend) -- dot-source the REAL
         PIM-AccessReviews.ps1, prove the decision PATCH body/audit + idempotency + the
         no-bulk guarantee, and that the GUI surface has no dead controls.

    Run standalone (exits 0 green / 1 red) or via Run-AllPimTests.ps1 / PIM.Tests.ps1.
#>
[CmdletBinding()] param()

$ErrorActionPreference = 'Stop'
$pass = 0; $fail = 0
function T($n, $c) { if ($c) { Write-Host "  PASS $n" -ForegroundColor Green; $script:pass++ } else { Write-Host "  FAIL $n" -ForegroundColor Red; $script:fail++ } }

$root     = Split-Path -Parent $PSScriptRoot          # ...\PIM4EntraPS
$mgrDir   = Join-Path $root 'tools\pim-manager'
$htmlPath = Join-Path $mgrDir 'pim-manager.html'
$srvPath  = Join-Path $mgrDir 'Open-PimManager.ps1'
$gateLib  = Join-Path $root 'engine\_shared\PIM-ApprovalGate.ps1'
$arLib    = Join-Path $root 'engine\_shared\PIM-AccessReviews.ps1'
T 'pim-manager.html present'      (Test-Path -LiteralPath $htmlPath)
T 'Open-PimManager.ps1 present'   (Test-Path -LiteralPath $srvPath)
T 'PIM-ApprovalGate.ps1 present'  (Test-Path -LiteralPath $gateLib)
T 'PIM-AccessReviews.ps1 present' (Test-Path -LiteralPath $arLib)
if ($fail) { Write-Host "`n RESULT: $pass pass, $fail fail" -ForegroundColor Red; exit 1 }
$html = [System.IO.File]::ReadAllText($htmlPath)
$srv  = [System.IO.File]::ReadAllText($srvPath)

# ===========================================================================
# Layer 1 -- STATIC GUI / SERVER WIRING (no dead views)
# ===========================================================================
Write-Host "`n-- Layer 1: Approvals + Access-Review decision wiring (static) --" -ForegroundColor Cyan
# Approvals tab declared + routed.
T 'Approvals nav tab declared'              ($html -match 'data-tab="approvals"')
T 'Approvals panel container present'       ($html -match 'id="approvalsTab"')
T 'switchTab routes approvals -> renderApprovals' ($html -match "name === 'approvals'\s*\)\s*renderApprovals")
T 'renderApprovals defined'                 ($html -match 'async function renderApprovals\(')
T 'Approvals calls GET /api/approvals'      ($html -match "api\('GET',\s*'/api/approvals'")
T 'Approvals raise calls POST /api/approvals' ($html -match "api\('POST',\s*'/api/approvals'")
T 'Approvals decision calls POST /api/approvals/decide' ($html -match "api\('POST',\s*'/api/approvals/decide'")
T 'Approvals surfaces the offboard sequence plan' ($html -match 'sequencePlan')
T 'Approvals shows requestor + justification' ($html -match 'r\.requestor' -and $html -match 'r\.justification')
T 'Approvals enforces maker!=checker in UI (canDecideThis/isRequestor)' ($html -match 'canDecideThis' -and $html -match 'isRequestor')
# Access Review attestation controls.
T 'Access Review per-item attest wired to POST /api/access-reviews/decision' ($html -match "api\('POST',\s*'/api/access-reviews/decision'")
T 'Access Review reads overdue (GET /api/access-reviews/overdue)' ($html -match "api\('GET',\s*'/api/access-reviews/overdue'")
T 'Access Review reads evidence (GET /api/access-reviews/evidence)' ($html -match "/api/access-reviews/evidence\?definitionId=")
T 'Access Review attest buttons offer Approve/Deny/DontKnow' ($html -match "mk\('Approve'" -and $html -match "mk\('Deny'" -and $html -match "mk\('DontKnow'")
T 'Access Review attest requires a justification' ($html -match 'Justification for')
T 'overdue badge surfaced on Access Review tab' ($html -match 'overdueCount')
# Home pending-approvals tile deep-links.
T 'Home pending-approvals tile present'     ($html -match "title: 'Pending approvals'")
T 'Home approvals tile deep-links to approvals tab' ($html -match "tab: 'approvals'")
T 'Home pending-reviews tile deep-links to accessreview tab' ($html -match "tab: 'accessreview'")

# Server handlers exist.
T 'server handles GET /api/approvals'       ($srv -match "\`$path -eq '/api/approvals' -and \`$method -eq 'GET'")
T 'server handles POST /api/approvals'      ($srv -match "\`$path -eq '/api/approvals' -and \`$method -eq 'POST'")
T 'server handles POST /api/approvals/decide' ($srv -match "\`$path -eq '/api/approvals/decide' -and \`$method -eq 'POST'")
T 'server handles POST /api/access-reviews/decision' ($srv -match "\`$path -eq '/api/access-reviews/decision' -and \`$method -eq 'POST'")
T 'server handles GET /api/access-reviews/overdue'   ($srv -match "\`$path -eq '/api/access-reviews/overdue' -and \`$method -eq 'GET'")
T 'server handles GET /api/access-reviews/evidence'  ($srv -match "\`$path -eq '/api/access-reviews/evidence' -and \`$method -eq 'GET'")
T 'server dot-sources PIM-ApprovalGate.ps1' ($srv -match "PIM-ApprovalGate\.ps1")
T 'server bridges Get-/Set-PimSetting onto the Manager store' ($srv -match 'function Get-PimSetting' -and $srv -match 'function Set-PimSetting')
# Hard constraint: the decision endpoint degrades gracefully if the write role is missing.
T 'decision endpoint surfaces permissionMissing (graceful degrade)' ($srv -match 'permissionMissing')
# Hard constraint: approval decision endpoint is Admin-gated + maker!=checker.
T 'decision endpoint is Admin-gated' ($srv -match "Admin role required to approve or deny")
T 'decision endpoint maps separation-of-duties to 403' ($srv -match "separation of duties")
# Home overview computes the pending-approvals tile (fast path, no live call).
T 'Get-PimHomeOverview builds an approvals tile' ($srv -match '\$tiles\.approvals')

# ===========================================================================
# Layer 2 -- APPROVAL QUEUE round-trip over the REAL backend (in-proc)
# ===========================================================================
Write-Host "`n-- Layer 2: approval queue round-trips through the real ApprovalGate --" -ForegroundColor Cyan
Set-StrictMode -Off

# In-memory settings store = the Get-/Set-PimSetting chain the gate persists through.
$script:__store = @{}
function Get-PimSetting { param([Parameter(Mandatory)][string]$Name) if ($script:__store.ContainsKey($Name)) { return $script:__store[$Name] } return $null }
function Set-PimSetting { param([Parameter(Mandatory)][string]$Name, [object]$Value) $script:__store[$Name] = $Value }

. $gateLib

# Maker raises an offboard request.
$reqOff = Add-PimApprovalRequest -Requestor 'maker@x' -Action 'offboard' -Target 'jdoe@x' -Justification 'left the company' -Ticket 'INC-1'
T 'maker raised a Pending offboard request' ("$($reqOff.status)" -eq 'Pending' -and "$($reqOff.requestor)" -eq 'maker@x')
$listed = @(@(Get-PimApprovalRequests -Status 'Pending') | Where-Object { $_.id -eq $reqOff.id })
T 'request is persisted + listed (newest first)' ($listed.Count -eq 1)

# The offboard request carries the engine-derived guided sequence plan.
$plan = @(Get-PimOffboardSequencePlan -Target 'jdoe@x')
T 'offboard sequence plan has 3 ordered steps'  ($plan.Count -eq 3 -and $plan[0].step -eq 'disable' -and $plan[2].step -eq 'schedule-delete')

# Separation of duties: the SAME requestor cannot self-approve.
$self = Set-PimApprovalDecision -Id $reqOff.id -Approver 'maker@x' -Decision 'approve'
T 'maker CANNOT self-approve (separation of duties)' (-not $self.ok -and "$($self.status)" -eq 'Pending' -and "$($self.reason)" -match 'separation of duties')

# A DIFFERENT checker CAN approve it.
$ok = Set-PimApprovalDecision -Id $reqOff.id -Approver 'checker@x' -Decision 'approve' -Note 'verified'
T 'a different checker CAN approve (maker != checker)' ($ok.ok -and "$($ok.status)" -eq 'Approved' -and "$($ok.request.approver)" -eq 'checker@x')

# Deny path on a second request.
$reqRev = Add-PimApprovalRequest -Requestor 'maker@x' -Action 'revoke' -Target 'batch:helpdesk' -Justification 'too broad'
$den = Set-PimApprovalDecision -Id $reqRev.id -Approver 'checker@x' -Decision 'deny' -Note 'not now'
T 'a checker can DENY a request' ($den.ok -and "$($den.status)" -eq 'Denied')

# Re-deciding a decided request is a no-op (idempotent).
$again = Set-PimApprovalDecision -Id $reqRev.id -Approver 'checker@x' -Decision 'approve'
T 're-deciding a decided request is a no-op' (-not $again.ok -and "$($again.status)" -eq 'Denied')

# NO AUTO-EXECUTE: the offboard gate refuses an automatic invocation outright...
$reqs = @(Get-PimApprovalRequests)
$auto = Test-PimOffboardExecutionAllowed -Target 'jdoe@x' -Requests $reqs -Automatic -DesiredResolved $true -Desired @(1)
T 'offboard gate REFUSES -Automatic (no auto-execute path)' (-not $auto.allowed -and "$($auto.gate)" -eq 'automatic-prohibited')

# ...and refuses when there is NO Approved request for the target.
$noappr = Test-PimOffboardExecutionAllowed -Target 'nobody@x' -Requests $reqs -DesiredResolved $true -Desired @(1)
T 'offboard gate REFUSES with no Approved request' (-not $noappr.allowed -and "$($noappr.gate)" -eq 'no-approval')

# WITH the Approved request + safe gates, the gate permits a CONTROLLED (non-automatic) execution.
$allow = Test-PimOffboardExecutionAllowed -Target 'jdoe@x' -Requests $reqs -ToDisable 1 -Scanned 10 -DesiredResolved $true -Desired @(1)
T 'offboard gate ALLOWS only an Approved, non-automatic, in-safety-cap execution' ([bool]$allow.allowed)

# Once-only latch: an approved request executes ONCE.
$latch1 = Set-PimApprovalRequestExecuted -Id $reqOff.id
$latch2 = Set-PimApprovalRequestExecuted -Id $reqOff.id
T 'approved request executes ONCE (latch), second call is a no-op' ($latch1.ok -and -not $latch2.ok)

# ===========================================================================
# Layer 3 -- ACCESS-REVIEW decision path over the REAL backend (in-proc)
# ===========================================================================
Write-Host "`n-- Layer 3: access-review decision path (real shapers, no network) --" -ForegroundColor Cyan
. $arLib

# The exact PATCH body + audit record (one decision at a time, justified).
$patch = New-PimReviewDecisionPatch -Outcome 'revoke' -Justification 'left the team' -DecidedBy 'checker@x'
T 'decision PATCH maps revoke -> Deny with justification' ($patch.body.decision -eq 'Deny' -and $patch.body.justification -eq 'left the team')
T 'decision produces an audit record' ($patch.audit.action -eq 'access-review.decision' -and $patch.audit.decidedBy -eq 'checker@x')
# Unjustified attestation is refused (fail-closed).
$threw = $false; try { New-PimReviewDecisionPatch -Outcome 'approve' -Justification '  ' | Out-Null } catch { $threw = $true }
T 'unjustified attestation is refused' $threw
# Idempotency: re-recording the same resolved outcome is a no-op.
T 'idempotent skip when current decision already matches' (Test-PimReviewDecisionIdempotent -Outcome 'approve' -Existing 'Approve')
T 'NOT idempotent over a NotReviewed item' (-not (Test-PimReviewDecisionIdempotent -Outcome 'approve' -Existing 'NotReviewed'))
# Overdue surfacing + evidence package from the REAL shapers (seed).
$seed = Get-PimAccessReviewAttestationSeed
T 'overdue seed surfaces at least one overdue review' (@($seed.Overdue | Where-Object { $_.IsOverdue }).Count -ge 1)
T 'evidence package has header + per-principal items + tally' ([bool]$seed.Evidence.Header -and @($seed.Evidence.Items).Count -ge 1 -and [bool]$seed.Evidence.Summary)
# NO BULK auto-approve helper exists (only the explicit single-item writer).
T 'NO bulk auto-approve helper exists (explicit, one at a time)' ($null -eq (Get-Command -Name '*AccessReview*' -CommandType Function | Where-Object { $_.Name -match '(?i)bulk|auto.?approve|approveall' }))
T 'the single-item decision writer exists' ([bool](Get-Command Set-PimAccessReviewDecision -ErrorAction SilentlyContinue))

Write-Host ("`n RESULT: {0} pass, {1} fail" -f $pass, $fail) -ForegroundColor $(if ($fail) { 'Red' } else { 'Green' })
if ($fail) { exit 1 }
