<#
  Offline tests for MAKER/CHECKER second-person approval on SENSITIVE authoring /
  onboarding (engine/_shared/PIM-SensitiveAuthoring.ps1, REQUIREMENTS s28 [M4]).

  Closes the [M4] gap: a SENSITIVE authoring/onboarding change (privileged-role
  attach, guest-into-privileged-group, disable/offboard) may not commit on one
  person's say-so -- a DIFFERENT administrator (the checker) must approve it first.
  Reuses the EXISTING approval machinery (PIM-ApprovalGate.ps1) -- no parallel
  approval system.

  Coverage:
    * Classification -- privileged-role attach / guest-into-privileged-group /
      disable+offboard are SENSITIVE; an ordinary (non-privileged) attach / a
      non-guest onboard is NOT.
    * Commit gate -- a sensitive action requires a SECOND approver (an Approved
      'authoring' request for the change's target); a NON-sensitive action is
      unaffected (commits with no approval); same-person (maker == checker)
      approval is refused (separation of duties); an approved sensitive change
      commits.
    * End-to-end round-trip over the persisted approval store: maker raises ->
      checker approves -> commit gate allows -> once-only execution latch.

  Pure + in-memory; no network; PS 5.1-safe. Rerun anytime.
#>
[CmdletBinding()] param()
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $here) { $here = 'C:\SCRIPTS\AutomateIT\SOLUTIONS\PIM4EntraPS\tests' }
. "$here\..\engine\_shared\PIM-Authoring.ps1"
. "$here\..\engine\_shared\PIM-ApprovalGate.ps1"
. "$here\..\engine\_shared\PIM-SensitiveAuthoring.ps1"

$pass=0; $fail=0
function Assert($n,$c){ if($c){ $script:pass++; Write-Host "  PASS  $n" -ForegroundColor Green } else { $script:fail++; Write-Host "  FAIL  $n" -ForegroundColor Red } }

# Isolate the persistence store to a temp file (no SQL; no Set/Get-PimSetting loaded).
$global:PIM_ApprovalStatePath = Join-Path $env:TEMP ("pim-m4-test-{0}.json" -f ([guid]::NewGuid().ToString('N').Substring(0,8)))
if (Test-Path -LiteralPath $global:PIM_ApprovalStatePath) { Remove-Item -LiteralPath $global:PIM_ApprovalStatePath -Force }
$global:PIM_AllowSelfApprove = $null

Write-Host "=== PIM-SensitiveAuthoring (maker/checker on sensitive authoring [M4]) ===" -ForegroundColor Cyan
$now = [datetime]::UtcNow

# ---------------------------------------------------------------------------
# 1. CLASSIFICATION -- which changes are SENSITIVE
# ---------------------------------------------------------------------------
# (a) privileged-role attach: a Global Administrator row attached to a group.
$privRoleRow = [pscustomobject]@{ GroupTag='T0-GlobalAdmins'; RoleDefinitionName='Global Administrator'; AssignmentType='Eligible'; Plane='CP'; TierLevel='0' }
$cls = Get-PimAuthoringSensitivity -Action 'bulk-attach' -Base 'PIM-Assignments-Roles-Groups' -Rows @($privRoleRow)
Assert "privileged-role attach is sensitive"          ($cls.sensitive -and $cls.privilegedRowCount -eq 1)
Assert "privileged-role attach has a reason"           (@($cls.reasons).Count -ge 1)

# privileged by ROLE NAME alone (no tier/plane columns)
$privByName = [pscustomobject]@{ GroupTag='HelpdeskGroup'; RoleDefinitionName='Privileged Role Administrator'; AssignmentType='Eligible' }
Assert "privileged role detected by name"              (Test-PimRowIsPrivileged -Row $privByName)
Assert "non-privileged role NOT flagged"               (-not (Test-PimRowIsPrivileged -Row ([pscustomobject]@{ GroupTag='Readers'; RoleDefinitionName='Message Center Reader'; TierLevel='3' })))

# privileged by tier/plane marker
Assert "Tier-0 row privileged"                         (Test-PimRowIsPrivileged -Row ([pscustomobject]@{ GroupTag='g'; RoleDefinitionName='Some Custom Role'; TierLevel='T0' }))
Assert "Control-plane row privileged"                  (Test-PimRowIsPrivileged -Row ([pscustomobject]@{ GroupTag='g'; RoleDefinitionName='Some Custom Role'; Plane='CP' }))
Assert "Azure Owner scope privileged"                  (Test-PimRowIsPrivileged -Row ([pscustomobject]@{ GroupTag='g'; AzScope='/subscriptions/x'; AzScopePermission='Owner' }))

# (b) guest-into-PRIVILEGED-group: a guest admin row whose group is privileged.
$guestPrivRow = [pscustomobject]@{ UserName='partner#EXT#@contoso.onmicrosoft.com'; UserType='Guest'; GroupTag='T0-GlobalAdmins'; TierLevel='0'; RoleDefinitionName='Global Administrator' }
$clsGuest = Get-PimAuthoringSensitivity -Action 'import-admins' -Base 'Account-Definitions-Admins' -Rows @($guestPrivRow)
Assert "guest-into-privileged-group is sensitive"      ($clsGuest.sensitive -and $clsGuest.guestRowCount -eq 1)
Assert "guest detected by UserType"                    (Test-PimRowIsGuest -Row ([pscustomobject]@{ UserName='x'; UserType='Guest' }))
Assert "guest detected by #EXT# UPN"                   (Test-PimRowIsGuest -Row ([pscustomobject]@{ UserPrincipalName='a_contoso.com#EXT#@fabrikam.onmicrosoft.com' }))
Assert "member (non-guest) NOT flagged guest"          (-not (Test-PimRowIsGuest -Row ([pscustomobject]@{ UserName='alice@contoso.com'; UserType='Member' })))

# guest into a NON-privileged group is ordinary onboarding (NOT flagged for the guest-priv reason)
$guestPlainRow = [pscustomobject]@{ UserName='vendor#EXT#@contoso.onmicrosoft.com'; UserType='Guest'; GroupTag='ReadOnlyReporting'; TierLevel='3'; RoleDefinitionName='Reports Reader' }
$clsGuestPlain = Get-PimAuthoringSensitivity -Action 'import-admins' -Base 'Account-Definitions-Admins' -Rows @($guestPlainRow)
Assert "guest into NON-privileged group NOT sensitive" (-not $clsGuestPlain.sensitive)

# (c) disable / offboard actions are sensitive regardless of rows
$clsDisable = Get-PimAuthoringSensitivity -Action 'disable' -Base 'Account-Definitions-Admins' -Rows @()
Assert "disable action is sensitive"                   ($clsDisable.sensitive -and $clsDisable.isDisableOrOffboard)
$clsOffboard = Get-PimAuthoringSensitivity -Action 'offboard' -Base 'Account-Definitions-Admins' -Rows @()
Assert "offboard action is sensitive"                  ($clsOffboard.sensitive -and $clsOffboard.isDisableOrOffboard)

# NON-sensitive ordinary authoring: clone of an ordinary Tier-3 definition
$ordinaryRow = [pscustomobject]@{ GroupTag='AppRegReaders'; RoleDefinitionName='Directory Readers'; AssignmentType='Eligible'; TierLevel='3'; Plane='WDP' }
$clsOrd = Get-PimAuthoringSensitivity -Action 'clone' -Base 'PIM-Definitions-Roles' -Rows @($ordinaryRow)
Assert "ordinary (non-privileged) clone NOT sensitive" (-not $clsOrd.sensitive)
Assert "predicate agrees: ordinary not sensitive"      (-not (Test-PimAuthoringActionSensitive -Action 'clone' -Base 'PIM-Definitions-Roles' -Rows @($ordinaryRow)))
Assert "predicate agrees: privileged IS sensitive"     (Test-PimAuthoringActionSensitive -Action 'bulk-attach' -Base 'PIM-Assignments-Roles-Groups' -Rows @($privRoleRow))

# classification also follows a Get-PimAuthoringPreview result (adds/removes rows)
$pv = Get-PimAuthoringPreview -Base 'PIM-Assignments-Roles-Groups' -Before @() -After @($privRoleRow) -Mode 'append' -Action 'bulk-attach'
Assert "sensitivity follows the preview adds"          ((Get-PimAuthoringSensitivity -Action 'bulk-attach' -Base 'PIM-Assignments-Roles-Groups' -Preview $pv).sensitive)

# stable target key
$tgt = Get-PimSensitiveAuthoringTarget -Action 'Bulk-Attach' -Base 'PIM-Assignments-Roles-Groups'
Assert "target key normalized + stable"                ($tgt -eq 'authoring:bulk-attach:PIM-Assignments-Roles-Groups')

# ---------------------------------------------------------------------------
# 2. COMMIT GATE -- second approver required for sensitive, none for ordinary
# ---------------------------------------------------------------------------
# (i) NON-sensitive change commits with NO approval (unaffected by [M4])
$gOrd = Test-PimAuthoringCommitAllowed -Action 'clone' -Base 'PIM-Definitions-Roles' -Rows @($ordinaryRow) -Requests @() -NowUtc $now
Assert "non-sensitive commit allowed w/o approval"     ($gOrd.allowed -and "$($gOrd.gate)" -eq 'not-sensitive' -and -not $gOrd.sensitive)

# (ii) SENSITIVE change is BLOCKED without a second approver
$gNo = Test-PimAuthoringCommitAllowed -Action 'bulk-attach' -Base 'PIM-Assignments-Roles-Groups' -Rows @($privRoleRow) -Requests @() -NowUtc $now
Assert "sensitive commit blocked w/o approval"         (-not $gNo.allowed -and "$($gNo.gate)" -eq 'needs-approval' -and $gNo.sensitive)
Assert "blocked result names the target to approve"    ("$($gNo.target)" -eq 'authoring:bulk-attach:PIM-Assignments-Roles-Groups')

# (iii) maker raises an 'authoring' request; SAME person cannot approve it (separation of duties)
$mkReq = New-PimApprovalRequest -Requestor 'maker@contoso' -Action 'authoring' -Target $gNo.target -Justification 'attach GA to T0 group' -NowUtc $now
$self = Resolve-PimApprovalDecision -Request $mkReq -Approver 'maker@contoso' -Decision 'approve' -NowUtc $now
Assert "same-person approval refused (maker==checker)"  (-not $self.ok -and "$($self.request.status)" -eq 'Pending')
# still blocked: the self-approve did not produce an Approved request
$gStillNo = Test-PimAuthoringCommitAllowed -Action 'bulk-attach' -Base 'PIM-Assignments-Roles-Groups' -Rows @($privRoleRow) -Requests @($self.request) -NowUtc $now
Assert "sensitive still blocked after self-approve"     (-not $gStillNo.allowed -and "$($gStillNo.gate)" -eq 'needs-approval')

# (iv) a DIFFERENT person approves -> the sensitive change may now commit
$approved = (Resolve-PimApprovalDecision -Request $mkReq -Approver 'checker@contoso' -Decision 'approve' -NowUtc $now).request
Assert "second person approves"                         ("$($approved.status)" -eq 'Approved' -and "$($approved.approver)" -eq 'checker@contoso')
$gYes = Test-PimAuthoringCommitAllowed -Action 'bulk-attach' -Base 'PIM-Assignments-Roles-Groups' -Rows @($privRoleRow) -Requests @($approved) -NowUtc $now
Assert "approved -> sensitive commit allowed"           ($gYes.allowed -and "$($gYes.gate)" -eq 'approved' -and $null -ne $gYes.approval)

# (v) an approval for a DIFFERENT target does NOT unlock this change
$otherApproved = (Resolve-PimApprovalDecision -Request (New-PimApprovalRequest -Requestor 'm@contoso' -Action 'authoring' -Target 'authoring:disable:Account-Definitions-Admins' -NowUtc $now) -Approver 'c@contoso' -Decision 'approve' -NowUtc $now).request
$gWrong = Test-PimAuthoringCommitAllowed -Action 'bulk-attach' -Base 'PIM-Assignments-Roles-Groups' -Rows @($privRoleRow) -Requests @($otherApproved) -NowUtc $now
Assert "approval for a different target does not unlock" (-not $gWrong.allowed -and "$($gWrong.gate)" -eq 'needs-approval')

# ---------------------------------------------------------------------------
# 3. END-TO-END over the persisted approval store (file/in-mem fallback)
# ---------------------------------------------------------------------------
$disableTarget = Get-PimSensitiveAuthoringTarget -Action 'disable' -Base 'Account-Definitions-Admins'
# maker raises through the persisted entry point
$stored = Add-PimApprovalRequest -Requestor 'maker@contoso' -Action 'authoring' -Target $disableTarget -Justification 'offboard leaver' -Ticket 'INC-9' -NowUtc $now
Assert "persisted authoring request Pending"           ("$($stored.status)" -eq 'Pending')
# commit blocked while only Pending
$g1 = Test-PimAuthoringCommitAllowed -Action 'disable' -Base 'Account-Definitions-Admins' -Requests @(Get-PimApprovalRequests) -NowUtc $now
Assert "disable commit blocked while Pending"          (-not $g1.allowed)
# self-approve via persisted path blocked
$selfDec = Set-PimApprovalDecision -Id $stored.id -Approver 'maker@contoso' -Decision 'approve' -NowUtc $now
Assert "persisted self-approve blocked"                (-not $selfDec.ok)
# different checker approves
$dec = Set-PimApprovalDecision -Id $stored.id -Approver 'checker@contoso' -Decision 'approve' -NowUtc $now
Assert "persisted second-person approve ok"            ($dec.ok -and "$($dec.request.status)" -eq 'Approved')
# commit now allowed
$g2 = Test-PimAuthoringCommitAllowed -Action 'disable' -Base 'Account-Definitions-Admins' -Requests @(Get-PimApprovalRequests) -NowUtc $now
Assert "disable commit allowed after approval"         ($g2.allowed -and "$($g2.gate)" -eq 'approved')
# once-only latch: after commit, the approval is consumed and cannot drive a second commit
$lat = Set-PimApprovalRequestExecuted -Id $stored.id -NowUtc $now
Assert "approval latched executed on commit"           ($lat.ok -and "$($lat.request.status)" -eq 'Executed')
$g3 = Test-PimAuthoringCommitAllowed -Action 'disable' -Base 'Account-Definitions-Admins' -Requests @(Get-PimApprovalRequests) -NowUtc $now
Assert "executed approval cannot drive 2nd commit"     (-not $g3.allowed)

# ---------------------------------------------------------------------------
# cleanup + summary
# ---------------------------------------------------------------------------
if (Test-Path -LiteralPath $global:PIM_ApprovalStatePath) { Remove-Item -LiteralPath $global:PIM_ApprovalStatePath -Force -ErrorAction SilentlyContinue }
$global:PIM_ApprovalStatePath = $null

Write-Host ("`n=== RESULT: {0} passed, {1} failed ===" -f $pass, $fail) -ForegroundColor $(if ($fail) {'Red'} else {'Green'})
if ($fail) { exit 1 } else { exit 0 }
