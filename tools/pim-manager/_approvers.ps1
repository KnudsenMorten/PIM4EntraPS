<#
  _approvers.ps1 -- WHO MAY APPROVE A DESTRUCTIVE REQUEST (CODE REVIEW 2 FIXES 2026-10-13, lane review2; owner decision 58:
  "Permission over target, never self"). Dot-sourced by Open-PimManager.ps1 after _revaudit.ps1. ONE function decides it for
  every caller -- POST /api/approvals/decide today, and the sponsor's account-delete proposal (lane review1) on the same page
  and route: Test-PimApprovalApproverAllowed.

  THE RULE (approving; denying is unchanged -- a deny releases nothing):
    * the actions it governs: offboard, disable, delete (an account delete), revoke (an over-limit bulk revoke). Every other
      kind of request ('authoring', ...) keeps its own rule and is answered "not governed here".
    * the approver is a SIGNED-IN person (never the unauthenticated placeholder) and is NEVER the person who asked -- not even
      a SuperAdmin, and the setting ApprovalSelfApprove does not apply to these actions.
    * a SuperAdmin approves any of them.
    * an Admin approves only when he has permission over the TARGET -- the same rule as a revoke (tools/pim-manager/_revaudit.ps1):
        - inside his scope: his portal profile (departments / managed admins), judged on the STORED admin row of the target;
        - and the target is not MORE privileged than he is (level 0 = most privileged; the same level or a less privileged
          one is allowed). An Admin without a level never approves for an L0 / L1 target (owner decision 55).
      A target whose admin row or level cannot be read is refused (fail closed) -- a SuperAdmin can still approve.
      A revoke request is judged on the assignments it carries (detail.rows); a request that carries only readable lines has
      no assignments to judge, so only a SuperAdmin approves it.
  Returns @{ allowed; governed; code; reason; status (HTTP: 200 / 403 / 503) }.
  Codes: not-governed | not-signed-in | self | role | out-of-scope | more-privileged | level-unknown | target-unknown |
         no-rows | revoke-refused | directory-unreadable | superadmin | permission.
  No $script: defaults (BUG-79-6b): every constant is a function or a literal.
#>
Set-StrictMode -Off

function Get-PimApprovalGovernedActions {
    <# PURE. LITERAL. The request kinds whose APPROVER this file decides. CODE REVIEW 1 FIXES 2026-10-13 (lane review1, owner
       decisions 52 + 53): 'admin-delete' -- a sponsor's PROPOSED account delete, approved by "Anyone with permission over him"
       (the delete rule: Test-PimRevauditAdminTarget -Action delete) or a SuperAdmin, never by the proposer. #>
    @('offboard', 'disable', 'delete', 'revoke', 'admin-delete')
}

function Test-PimApprovalApproverDecision {
    <#
      PURE. The verdict, from facts only (tests call it directly):
        -Request  the approval request (action, requestor, target, detail)
        -Caller   @{ role; identity; isSuperAdmin; profile; level (int or $null) }
        -Admins   the stored Account-Definitions-Admins rows
        -RevokeVerdict  for a revoke with rows: the result of the revoke rule for the caller (Test-PimRevauditRequest)
    #>
    param([AllowNull()][object]$Request, [hashtable]$Caller = @{}, [object[]]$Admins = @(), [AllowNull()][object]$RevokeVerdict = $null)
    $mk = { param($ok, $code, $why, $st) [pscustomobject]@{ allowed = [bool]$ok; governed = $true; code = $code; reason = $why; status = [int]$st } }
    $act = "$(if ($Request) { $Request.action })".Trim().ToLowerInvariant()
    if ($act -notin @(Get-PimApprovalGovernedActions)) { return [pscustomobject]@{ allowed = $true; governed = $false; code = 'not-governed'; reason = ''; status = 200 } }
    $me = "$($Caller.identity)".Trim()
    if (-not $me -or $me -eq '<unauthenticated>') { return (& $mk $false 'not-signed-in' 'Only a signed-in person can approve this request.' 403) }
    $req = "$($Request.requestor)".Trim()
    if ($req -and [string]::Equals($req, $me, [StringComparison]::OrdinalIgnoreCase)) {
        return (& $mk $false 'self' ("You asked for this {0} yourself, so you cannot approve it -- another person with permission over the target, or a SuperAdmin, approves it. Self-approval does not apply to an offboarding, an account delete or a bulk revoke." -f $act) 403)
    }
    $isSuper = [bool]$Caller.isSuperAdmin
    if (-not $isSuper -and (Get-Command Test-PimGuardSuperAdminRole -ErrorAction SilentlyContinue)) { $isSuper = [bool](Test-PimGuardSuperAdminRole -Role "$($Caller.role)") }
    if ($isSuper) { return (& $mk $true 'superadmin' 'SuperAdmin' 200) }
    if ("$($Caller.role)" -ne 'Admin') { return (& $mk $false 'role' "An Admin with permission over the target, or a SuperAdmin, approves this request -- you are signed in as $($Caller.role)." 403) }
    if ($act -eq 'revoke') {
        $rows = @()
        if ($Request.detail -and $Request.detail.PSObject.Properties['rows']) { $rows = @(@($Request.detail.rows) | Where-Object { $null -ne $_ }) }
        if (-not $rows.Count) { return (& $mk $false 'no-rows' 'This revoke request carries no assignments that can be checked against your scope and level, so only a SuperAdmin can approve it.' 403) }
        if ($null -eq $RevokeVerdict) { return (& $mk $false 'revoke-refused' 'Your permission over the assignments of this revoke could not be checked -- not approved.' 403) }
        if (-not $RevokeVerdict.allowed) { return (& $mk $false 'revoke-refused' ("You do not have permission over every assignment of this revoke: {0}" -f "$($RevokeVerdict.reason)") 403) }
        return (& $mk $true 'permission' 'permission over every assignment' 200)
    }
    # offboard / disable / delete: the target is an admin, judged on his STORED row
    $tgt = "$($Request.target)".Trim()
    $row = $null
    if (Get-Command Find-PimRevauditAdminRow -ErrorAction SilentlyContinue) { $row = Find-PimRevauditAdminRow -Admins @($Admins) -Names @($tgt) }
    if (-not $row) { return (& $mk $false 'target-unknown' ("'{0}' is not a defined admin in the stored list, so your permission over him cannot be checked -- a SuperAdmin approves it." -f $tgt) 403) }
    # review 1 fixes (decisions 52 + 53): a proposed account delete is approved under THE delete rule (same rule as revoke,
    # incl. the profile's account-operation right and level ceiling) -- the rule Delete account itself applies.
    if ($act -eq 'admin-delete') {
        if (-not (Get-Command Test-PimRevauditAdminTarget -ErrorAction SilentlyContinue)) { return (& $mk $false 'out-of-scope' 'the delete rule (_revaudit.ps1) is not loaded -- not approved' 503) }
        $dv = Test-PimRevauditAdminTarget -Caller $Caller -AdminRow $row -Action delete
        if (-not $dv.allowed) { return (& $mk $false "$($dv.code)" ("You may not approve the delete of '{0}': {1}" -f $tgt, "$($dv.reason)") 403) }
        return (& $mk $true 'permission' 'permission over the admin (scope and level)' 200)
    }
    $facts = @{ known = $true; principal = $tgt; adminRow = $row; missing = @(); facets = @(); groupDepartments = @()
                adminDepartment = ("$(Get-PimRevauditRowValue $row @('Department'))").ToLowerInvariant() }
    $why = ''
    if (Get-Command Test-PimRevauditScope -ErrorAction SilentlyContinue) { $why = Test-PimRevauditScope -Profile $Caller.profile -Facts $facts }
    else { $why = 'the scope rule (_revaudit.ps1) is not loaded' }
    if ($why) { return (& $mk $false 'out-of-scope' ("'{0}' is outside your scope -- {1}" -f $tgt, $why) 403) }
    $tl = Get-PimRevauditAdminLevel -AdminRow $row
    $cl = $Caller.level
    if ($null -eq $tl) { return (& $mk $false 'level-unknown' ("The level of '{0}' cannot be read from his admin row, so it cannot be compared with yours -- a SuperAdmin approves it (or set Level on the admin)." -f $tgt) 403) }
    if ($null -ne $cl) {
        if ([int]$tl -lt [int]$cl) { return (& $mk $false 'more-privileged' ("'{0}' is level L{1}, more privileged than your level L{2} -- you cannot approve this for him." -f $tgt, $tl, $cl) 403) }
    } elseif ([int]$tl -le 1) {
        return (& $mk $false 'more-privileged' ("'{0}' is level L{1}; an Admin without a level of his own does not approve this for an L0 or L1 admin -- a SuperAdmin does." -f $tgt, $tl) 403)
    }
    return (& $mk $true 'permission' 'permission over the target' 200)
}

function Test-PimApprovalApproverAllowed {
    <#
      THE ONE CHECK every approval route calls (POST /api/approvals/decide; lane review1's account-delete proposal). Reads the
      signed-in caller (Get-PimManagerRole, Get-PimManagerCallerScope) and the stored admins (Get-PimRevauditDirectory), then
      asks Test-PimApprovalApproverDecision. -Decision 'deny' is never refused here. NEVER throws: a failure refuses (503).
    #>
    param([AllowNull()][object]$Request, [string]$Decision = 'approve')
    if ("$Decision".Trim().ToLowerInvariant() -ne 'approve') { return [pscustomobject]@{ allowed = $true; governed = $false; code = 'not-governed'; reason = ''; status = 200 } }
    try {
        $act = "$(if ($Request) { $Request.action })".Trim().ToLowerInvariant()
        if ($act -notin @(Get-PimApprovalGovernedActions)) { return [pscustomobject]@{ allowed = $true; governed = $false; code = 'not-governed'; reason = ''; status = 200 } }
        $role = $null; try { $role = Get-PimManagerRole } catch { $role = $null }
        $scope = $null; try { if (Get-Command Get-PimManagerCallerScope -ErrorAction SilentlyContinue) { $scope = Get-PimManagerCallerScope } } catch { $scope = $null }
        $caller = @{ role = "$(if ($role) { $role.role })"; identity = "$(if ($role) { $role.identity })"; profile = $(if ($scope) { $scope.profile } else { $null }); level = $null; isSuperAdmin = $false }
        if (Get-Command Test-PimGuardSignedInSuperAdmin -ErrorAction SilentlyContinue) { $caller.isSuperAdmin = [bool](Test-PimGuardSignedInSuperAdmin -Role $caller.role -Identity $caller.identity) }
        $admins = @(); $rv = $null
        if (-not $caller.isSuperAdmin) {
            $dir = Get-PimRevauditDirectory
            if (-not $dir.ok) { return [pscustomobject]@{ allowed = $false; governed = $true; code = 'directory-unreadable'; reason = "The stored admins could not be read ($($dir.error)), so your permission over the target cannot be decided -- nothing was approved. Try again; a SuperAdmin is not limited by this."; status = 503 } }
            $admins = @($dir.admins)
            $caller.level = Get-PimRevauditCallerLevel -Profile $caller.profile -Identity $caller.identity -Admins $admins
            if ($act -eq 'revoke' -and $Request.detail -and $Request.detail.PSObject.Properties['rows'] -and @($Request.detail.rows).Count) {
                $rv = Test-PimRevauditRequest -Rows @($Request.detail.rows)
            }
        }
        return (Test-PimApprovalApproverDecision -Request $Request -Caller $caller -Admins $admins -RevokeVerdict $rv)
    } catch {
        return [pscustomobject]@{ allowed = $false; governed = $true; code = 'check-failed'; reason = "Who may approve this could not be decided ($($_.Exception.Message)) -- nothing was approved."; status = 503 }
    }
}
