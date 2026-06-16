<#
  PIM4EntraPS -- MAKER/CHECKER second-person approval on SENSITIVE authoring /
  onboarding (REQUIREMENTS s28 [M4]).

  WHY THIS EXISTS
  ---------------
  The Authoring / Onboarding surfaces let ONE administrator stage and commit a
  change to the desired store. For the MOST sensitive of those changes -- attaching
  a PRIVILEGED role/scope to a delegation group, putting a GUEST/external account
  INTO a privileged group, or DISABLING / OFFBOARDING an account -- a single
  unchecked operator is the exact "no independent second pair of eyes" gap [M4]
  records. This adds a SECOND-PERSON (maker/checker) approval gate ON TOP of those
  sensitive commits: the maker STAGES the change; a DIFFERENT administrator (the
  checker, with the required role) must APPROVE it before it may commit. A
  non-sensitive authoring change is unaffected (commits as before). Self-approval
  is refused.

  REUSE (no parallel approval system)
  -----------------------------------
  This file is a thin CLASSIFIER + COMMIT GATE that sits on the EXISTING approval
  machinery in engine/_shared/PIM-ApprovalGate.ps1:
    * the maker raises an 'authoring' approval request (Add-PimApprovalRequest);
    * the checker approves/denies it (Set-PimApprovalDecision) -- maker != checker
      is enforced there (Test-PimApprovalSeparationOk);
    * the commit gate asks Test-PimApprovalApprovedFor for an Approved, in-window,
      un-executed 'authoring' request keyed to the change, and latches it once
      (Set-PimApprovalRequestExecuted) on commit. The SAME persisted store
      (SQL pim.Settings / JSON / in-mem) and the SAME audit surface are used.

  This file adds NO new request schema, NO new persistence, NO new decision logic.
  It contributes ONLY:
    * Test-PimAuthoringActionSensitive / Get-PimAuthoringSensitivity -- PURE
      classification: is THIS proposed authoring/onboarding change sensitive, and
      why (the reason list).
    * Get-PimSensitiveAuthoringTarget -- the STABLE approval key for a change, so
      the maker's request and the commit gate agree on the same target.
    * Test-PimAuthoringCommitAllowed -- the COMMIT gate: non-sensitive => allowed;
      sensitive => allowed ONLY when an Approved 'authoring' request for that key
      exists. Pure (takes the request set in), no I/O.

  PS 5.1-safe: no ?./??, no ternary operator, null-guarded, .ToArray() over
  List[object] (never @()).
#>

Set-StrictMode -Off

# ---------------------------------------------------------------------------
# Shared cell accessor (mirrors PIM-Authoring.Get-PimAuthoringCell). Defined
# only if that helper isn't already loaded, so this file is usable standalone
# (pure unit context) AND inside the Manager/engine where PIM-Authoring.ps1 is
# dot-sourced first. Never clobbers an existing definition.
# ---------------------------------------------------------------------------
if (-not (Get-Command Get-PimAuthoringCell -ErrorAction SilentlyContinue)) {
    function Get-PimAuthoringCell {
        param([AllowNull()][object]$Row, [Parameter(Mandatory)][string]$Column)
        if ($null -eq $Row) { return '' }
        if ($Row -is [System.Collections.IDictionary]) {
            if ($Row.Contains($Column)) { return "$($Row[$Column])" }
            return ''
        }
        $p = $Row.PSObject.Properties[$Column]
        if ($p) { return "$($p.Value)" }
        return ''
    }
}

# ---------------------------------------------------------------------------
# Privileged classification primitives (PURE).
# ---------------------------------------------------------------------------

# Authoring actions whose committed effect ONBOARDS/ATTACHES privileged access or
# DISABLES/OFFBOARDS an account -- the [M4] sensitive set. Bulk-attach + clone of
# role/azure rows ATTACH role/scope to a group; admin import + move ONBOARD/REPOINT
# an admin into delegation groups; delete of privileged rows + the
# disable/offboard control-plane actions are destructive. The action alone does
# not make a change sensitive -- the PRIVILEGE of the affected rows does (below);
# this set is just which actions CAN be sensitive.
$script:PimSensitiveAuthoringActions = @(
    'bulk-attach','clone','clone-azure-role','clone-au','au',
    'import-admins','move-admin','delete-rows','disable','offboard'
)

function Test-PimRoleNameIsPrivileged {
    # PURE: is this role / scope-permission name a WELL-KNOWN privileged role?
    # Case-insensitive substring match against the high-privilege role set. Pure.
    [CmdletBinding()] param([AllowNull()][string]$RoleName)
    $r = "$RoleName".Trim().ToLowerInvariant()
    if (-not $r) { return $false }
    $privileged = @(
        'global administrator','company administrator',
        'privileged role administrator','privileged authentication administrator',
        'security administrator','conditional access administrator',
        'application administrator','cloud application administrator',
        'user administrator','authentication administrator',
        'exchange administrator','sharepoint administrator',
        'intune administrator','hybrid identity administrator',
        'domain name administrator','partner tier2 support',
        'directory synchronization accounts',
        'owner','user access administrator','contributor'
    )
    foreach ($p in $privileged) { if ($r -eq $p -or $r.Contains($p)) { return $true } }
    return $false
}

function Test-PimRowIsPrivileged {
    # PURE: does this proposed row attach/define PRIVILEGED access? A row is
    # privileged when ANY of:
    #   * it is Control-Plane / Management-Plane (Plane = CP/MP, or a control-plane
    #     CPPlatform marker), OR
    #   * its tier is Tier-0 / Tier-1 (TierLevel/Tier/Level carries 0 or 1, or a
    #     T0/T1/L0/L1 marker), OR
    #   * it names a role/scope from the well-known privileged set
    #     (Global Administrator, Privileged Role Administrator, Owner at a broad
    #     Azure scope, etc.), OR
    #   * the GroupTag/Name carries a privileged marker (L0/L1/T0/T1/PRIV/ADMIN).
    # Conservative-by-design: when in doubt about tier (blank), a privileged role
    # NAME or plane still flags it. Pure; PS 5.1-safe.
    [CmdletBinding()] param([AllowNull()][object]$Row)
    if ($null -eq $Row) { return $false }
    $g = { param($n) (Get-PimAuthoringCell $Row $n) }

    # 1. Plane -- control / management plane is privileged.
    $plane = "$(& $g 'Plane')".Trim().ToUpperInvariant()
    if ($plane -in @('CP','MP','CONTROLPLANE','CONTROL-PLANE','MANAGEMENTPLANE','MANAGEMENT-PLANE')) { return $true }
    $cpp = "$(& $g 'CPPlatform')".Trim().ToUpperInvariant()
    if ($cpp -in @('CP','MP','CONTROLPLANE','MANAGEMENTPLANE')) { return $true }

    # 2. Tier 0/1 (from TierLevel / Tier / Level). Accept a bare 0/1 or a T0/T1/L0/L1 marker.
    foreach ($col in 'TierLevel','Tier','Level') {
        $t = "$(& $g $col)".Trim().ToUpperInvariant()
        if (-not $t) { continue }
        if ($t -match '^(T|L)?\s*[01]$') { return $true }
        if ($t -match '\b(T0|T1|L0|L1|TIER\s*0|TIER\s*1)\b') { return $true }
    }

    # 3. Privileged role / scope NAME.
    $role = "$(& $g 'RoleDefinitionName')".Trim()
    if (-not $role) { $role = "$(& $g 'AzScopePermission')".Trim() }
    if (Test-PimRoleNameIsPrivileged -RoleName $role) { return $true }

    # 4. Privileged marker in the GroupTag / GroupName.
    foreach ($col in 'GroupTag','GroupName','TargetGroupTag','SourceGroupTag') {
        $v = "$(& $g $col)".Trim().ToUpperInvariant()
        if (-not $v) { continue }
        if ($v -match '(^|[^A-Z0-9])(L0|L1|T0|T1|PRIV|PRIVILEGED|GLOBALADMIN|GA)([^A-Z0-9]|$)') { return $true }
    }

    return $false
}

function Test-PimRowIsGuest {
    # PURE: is this onboarding/admin row a GUEST / EXTERNAL account? TRUE when
    # UserType = Guest/External, OR the UPN/UserName carries an external-tenant
    # marker (#EXT#) or a B2B invited-domain shape. Pure; PS 5.1-safe.
    [CmdletBinding()] param([AllowNull()][object]$Row)
    if ($null -eq $Row) { return $false }
    $g = { param($n) (Get-PimAuthoringCell $Row $n) }
    $ut = "$(& $g 'UserType')".Trim().ToLowerInvariant()
    if ($ut -in @('guest','external','b2b')) { return $true }
    foreach ($col in 'UserPrincipalName','UserName','Username','principalUpn','principal') {
        $v = "$(& $g $col)".Trim().ToLowerInvariant()
        if ($v -and $v.Contains('#ext#')) { return $true }
    }
    return $false
}

# ---------------------------------------------------------------------------
# Sensitivity classification (PURE).
# ---------------------------------------------------------------------------
function Get-PimAuthoringSensitivity {
    # PURE: classify a proposed authoring/onboarding change as SENSITIVE [M4] or
    # not, with the reason list. Inputs (any subset):
    #   $Action  -- the authoring action token (bulk-attach / move-admin / clone /
    #               clone-azure-role / clone-au / au / import-admins / delete-rows /
    #               disable / offboard).
    #   $Base    -- the entity the rows belong to (for context).
    #   $Rows    -- the PROPOSED rows the action computed (the 'after'/added set),
    #               OR the rows being removed/onboarded -- whatever the action acts on.
    #   $Preview -- (optional) a Get-PimAuthoringPreview result; when supplied its
    #               adds/modifies/removes rows are ALSO classified, and a destructive
    #               (removes>0) preview is itself a sensitivity trigger when those
    #               removed rows are privileged.
    #
    # Sensitive when ANY of the [M4] conditions hold:
    #   (a) PRIVILEGED-ROLE ATTACH      -- a privileged role/scope row is added to a group;
    #   (b) GUEST-INTO-PRIVILEGED-GROUP -- a guest/external account row targets a privileged group;
    #   (c) DISABLE / OFFBOARD          -- the action disables/offboards an account.
    # Returns @{ sensitive; reasons[]; action; base; privilegedRowCount; guestRowCount;
    #            isDisableOrOffboard }. Never throws.
    [CmdletBinding()]
    param(
        [string]$Action = '',
        [string]$Base = '',
        [AllowNull()][AllowEmptyCollection()][object[]]$Rows = @(),
        [AllowNull()][object]$Preview = $null
    )
    $act = "$Action".Trim().ToLowerInvariant()
    $reasons = New-Object System.Collections.ArrayList

    # Gather every row the action touches: the explicit Rows + any preview rows.
    $touched = New-Object System.Collections.ArrayList
    foreach ($r in @($Rows)) { if ($null -ne $r) { [void]$touched.Add($r) } }
    if ($null -ne $Preview) {
        foreach ($bucket in 'adds','modifies','removes') {
            $items = $null
            if ($Preview -is [System.Collections.IDictionary]) { if ($Preview.Contains($bucket)) { $items = $Preview[$bucket] } }
            else { $pp = $Preview.PSObject.Properties[$bucket]; if ($pp) { $items = $pp.Value } }
            foreach ($it in @($items)) {
                if ($null -eq $it) { continue }
                # preview items are { key; row } or { key; before; after; diffCols }
                $row = $null
                if ($it -is [System.Collections.IDictionary]) {
                    if ($it.Contains('after')) { $row = $it['after'] } elseif ($it.Contains('row')) { $row = $it['row'] }
                } else {
                    $ap = $it.PSObject.Properties['after']; if ($ap) { $row = $ap.Value }
                    if ($null -eq $row) { $rp = $it.PSObject.Properties['row']; if ($rp) { $row = $rp.Value } }
                }
                if ($null -ne $row) { [void]$touched.Add($row) }
            }
        }
    }

    # (c) DISABLE / OFFBOARD -- the action itself is destructive to an account.
    $isDisableOrOffboard = ($act -in @('disable','offboard'))
    if ($isDisableOrOffboard) {
        [void]$reasons.Add("account $act is a sensitive offboarding action requiring a second approver")
    }

    # (a) + (b) -- scan the touched rows.
    $privCount = 0; $guestCount = 0
    foreach ($r in $touched) {
        $isPriv  = (Test-PimRowIsPrivileged -Row $r)
        $isGuest = (Test-PimRowIsGuest -Row $r)
        if ($isPriv)  { $privCount++ }
        if ($isGuest) { $guestCount++ }
    }
    if ($privCount -gt 0) {
        [void]$reasons.Add("attaches/defines $privCount privileged (Tier-0/1 or control-plane) role/scope row(s)")
    }
    if ($guestCount -gt 0) {
        # A guest into a PRIVILEGED group is the [M4] condition; a guest into a
        # NON-privileged group is not flagged here (it is ordinary onboarding).
        $guestPriv = 0
        foreach ($r in $touched) { if ((Test-PimRowIsGuest -Row $r) -and (Test-PimRowIsPrivileged -Row $r)) { $guestPriv++ } }
        if ($guestPriv -gt 0) {
            [void]$reasons.Add("onboards $guestPriv guest/external account row(s) INTO a privileged group")
        }
    }

    $sensitive = ($reasons.Count -gt 0)
    return [ordered]@{
        sensitive           = $sensitive
        reasons             = $reasons.ToArray()
        action              = $act
        base                = "$Base"
        privilegedRowCount  = $privCount
        guestRowCount       = $guestCount
        isDisableOrOffboard = $isDisableOrOffboard
    }
}

function Test-PimAuthoringActionSensitive {
    # PURE convenience predicate: TRUE when the change is sensitive [M4]. Same
    # inputs as Get-PimAuthoringSensitivity.
    [CmdletBinding()]
    param(
        [string]$Action = '',
        [string]$Base = '',
        [AllowNull()][AllowEmptyCollection()][object[]]$Rows = @(),
        [AllowNull()][object]$Preview = $null
    )
    return [bool]((Get-PimAuthoringSensitivity -Action $Action -Base $Base -Rows $Rows -Preview $Preview).sensitive)
}

function Get-PimSensitiveAuthoringTarget {
    # PURE: the STABLE approval-request target key for a sensitive authoring change,
    # so the maker's raised request and the commit gate agree on the SAME identity.
    # Shape: "authoring:<action>:<base>" -- the action + entity the commit affects.
    # (A per-row key would force one approval per row; the operator approves the
    # STAGED change set for an action+base, which is what the GUI confirms.)
    [CmdletBinding()] param([Parameter(Mandatory)][string]$Action, [string]$Base = '')
    $a = "$Action".Trim().ToLowerInvariant()
    $b = "$Base".Trim()
    return ("authoring:" + $a + ":" + $b)
}

# ---------------------------------------------------------------------------
# COMMIT GATE (PURE -- reuses the existing approval machinery).
# ---------------------------------------------------------------------------
function Test-PimAuthoringCommitAllowed {
    # THE GATE the authoring/onboarding COMMIT path calls before it writes the
    # staged change to the desired store. Decision:
    #   * NON-SENSITIVE change      -> allowed (gate='not-sensitive'); commits as before.
    #   * SENSITIVE change [M4]      -> allowed ONLY when an Approved (in-window,
    #     un-executed) 'authoring' approval request for THIS change's target key
    #     exists in the supplied request set (Test-PimApprovalApprovedFor). Maker !=
    #     checker is already enforced when that request was approved -- a request a
    #     person self-approved never reaches Approved unless self-approve is opted in.
    #     No such request -> blocked (gate='needs-approval'), with the target key the
    #     maker must raise an approval for.
    #
    # Inputs:
    #   $Action / $Base / $Rows / $Preview -- the change (classified via
    #                                         Get-PimAuthoringSensitivity).
    #   $Requests -- the current approval request set (Get-PimApprovalRequests).
    #   $NowUtc   -- clock (for in-window check); defaults to UtcNow.
    #
    # Returns @{ allowed; gate; reason; sensitive; reasons[]; target; approval }.
    # PURE -- no persistence; the caller latches the approval (Set-PimApprovalRequestExecuted)
    # AFTER a successful commit so it can never drive a second commit.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Action,
        [string]$Base = '',
        [AllowNull()][AllowEmptyCollection()][object[]]$Rows = @(),
        [AllowNull()][object]$Preview = $null,
        [AllowNull()][AllowEmptyCollection()][object[]]$Requests = @(),
        [datetime]$NowUtc = [datetime]::UtcNow
    )
    $cls = Get-PimAuthoringSensitivity -Action $Action -Base $Base -Rows $Rows -Preview $Preview
    $target = Get-PimSensitiveAuthoringTarget -Action $Action -Base $Base
    if (-not $cls.sensitive) {
        return [pscustomobject]@{
            allowed = $true; gate = 'not-sensitive'
            reason = 'change is not in the sensitive authoring/onboarding set -- no second approver required'
            sensitive = $false; reasons = @(); target = $target; approval = $null
        }
    }
    # SENSITIVE -- an Approved 'authoring' request for this target is required.
    $appr = $null
    if (Get-Command Test-PimApprovalApprovedFor -ErrorAction SilentlyContinue) {
        $appr = Test-PimApprovalApprovedFor -Requests @($Requests) -Action 'authoring' -Target $target -NowUtc $NowUtc
    }
    if (-not $appr) {
        return [pscustomobject]@{
            allowed = $false; gate = 'needs-approval'
            reason = ("this is a sensitive change (" + ($cls.reasons -join '; ') + ") -- a SECOND administrator must approve it before commit. Raise an 'authoring' approval request for target '" + $target + "'.")
            sensitive = $true; reasons = @($cls.reasons); target = $target; approval = $null
        }
    }
    return [pscustomobject]@{
        allowed = $true; gate = 'approved'
        reason = ("sensitive change approved by " + "$($appr.approver)")
        sensitive = $true; reasons = @($cls.reasons); target = $target; approval = $appr
    }
}
