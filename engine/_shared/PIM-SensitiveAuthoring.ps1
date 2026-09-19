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
# BUG-190 -- "WOULD THIS WRITE DISABLE AN ADMIN ON THE NEXT ENGINE RUN?" (PURE).
# The ONE rule the Manager's two admin write paths share (POST /api/admin-accounts/modify and the
# Review & Save PUT of Account-Definitions-Admins), and the classifier below. It mirrors what the
# engine acts on (PIM-EngineProviders.ps1 Get-PimAdminStatusDecision / Test-PimAdminOffboarded):
#   AccountStatus = Disabled | Revoked            -> disabled (Revoked also revokes sessions)
#   Lifecycle     = Retire*                       -> offboarded (disable, sessions, memberships)
#   AutoDisableDate / OffboardDate (legacy name) at or before NOW -> offboarded
# Operator decision (2026-09-18): such a write IS an offboard, so it goes through the offboard
# approval (a second administrator), never straight into the desired state.
# ---------------------------------------------------------------------------
$script:PimAdminDisablingColumns = @('AccountStatus', 'Lifecycle', 'AutoDisableDate', 'OffboardDate')

function Test-PimAdminDisablingValue {
    # PURE. Does this ONE admin-row cell, on its own, make the engine disable the account on its
    # next run? Blank = no. An UNREADABLE date is treated as immediate (fail closed: an odd value
    # must not slip past the approval gate); the Manager's own validation refuses such a value
    # before it is ever stored, so this only decides which way an unreadable value falls.
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Column, [AllowNull()][AllowEmptyString()][string]$Value, [datetime]$NowUtc = [datetime]::UtcNow)
    $v = "$Value".Trim()
    if (-not $v) { return $false }
    $c = "$Column".Trim()
    if ($c -ieq 'AccountStatus') { return ($v -match '(?i)^(disabled|revoked)$') }
    if ($c -ieq 'Lifecycle')     { return ($v -match '(?i)^retire') }
    if ($c -ieq 'AutoDisableDate' -or $c -ieq 'OffboardDate') {
        $parsed = $null
        if (Get-Command Resolve-PimDateExpression -ErrorAction SilentlyContinue) { try { $parsed = Resolve-PimDateExpression -Expression $v } catch { $parsed = $null } }
        if (-not $parsed -and (Get-Command Get-PimUtcStamp -ErrorAction SilentlyContinue)) { try { $parsed = Get-PimUtcStamp $v } catch { $parsed = $null } }
        if (-not $parsed) {
            $d = [datetime]::MinValue
            $styles = [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal
            if ([datetime]::TryParse($v, [System.Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$d)) { $parsed = $d }
        }
        if (-not $parsed) { return $true }
        return (([datetime]$parsed).ToUniversalTime() -le $NowUtc.ToUniversalTime())
    }
    return $false
}

function Get-PimAdminDisableHolds {
    # PURE. Given the STORED admin rows and the rows a commit would store, find every change that
    # would disable an admin on the next engine run, and HOLD it:
    #   * a MODIFIED row: each disabling column that CHANGED to a disabling value (and was not
    #     already disabling) is put back to its stored value -- every other column of the row, and
    #     every other row, is kept;
    #   * an ADDED row that carries a disabling value is held WHOLE. There is no stored value to put
    #     back, and writing it without that column would ask the engine to CREATE an enabled admin
    #     the operator marked for disabling. (An offboard approval needs an existing row, so the
    #     operator adds the admin first and offboards it through the approval.)
    # Rows are matched by the store's natural key (Get-PimStoreRowKey). Returns
    #   @{ rows = <the rows to store>; holds = @( @{ key; upn; kind = modify|add; fields = @{ col = held value };
    #      restored = @{ col = stored value } } ) }
    [CmdletBinding()]
    param(
        [AllowNull()][AllowEmptyCollection()][object[]]$Before = @(),
        [AllowNull()][AllowEmptyCollection()][object[]]$After = @(),
        [string]$Base = 'Account-Definitions-Admins',
        [datetime]$NowUtc = [datetime]::UtcNow
    )
    $keyOf = {
        param($r)
        $k = ''
        if (Get-Command Get-PimStoreRowKey -ErrorAction SilentlyContinue) { try { $k = "$(Get-PimStoreRowKey -Base $Base -Row $r)" } catch { $k = '' } }
        if (-not "$k".Trim()) {
            $k = "$(Get-PimAuthoringCell $r 'UserPrincipalName')".Trim()
            if (-not $k) { $k = "$(Get-PimAuthoringCell $r 'UserName')".Trim() }
        }
        return "$k".Trim().ToLowerInvariant()
    }
    $byKey = @{}
    foreach ($b in @($Before)) {
        if ($null -eq $b) { continue }
        $k = & $keyOf $b
        if ($k -and -not $byKey.ContainsKey($k)) { $byKey[$k] = $b }
    }
    $rows  = New-Object System.Collections.Generic.List[object]
    $holds = New-Object System.Collections.Generic.List[object]
    foreach ($a in @($After)) {
        if ($null -eq $a) { continue }
        $k = & $keyOf $a
        $old = $null
        if ($k -and $byKey.ContainsKey($k)) { $old = $byKey[$k] }
        $held = [ordered]@{}; $restored = [ordered]@{}
        foreach ($col in $script:PimAdminDisablingColumns) {
            $nv = "$(Get-PimAuthoringCell $a $col)".Trim()
            $ov = ''
            if ($null -ne $old) { $ov = "$(Get-PimAuthoringCell $old $col)".Trim() }
            if ($nv -ieq $ov) { continue }                                          # not changed
            if (-not (Test-PimAdminDisablingValue -Column $col -Value $nv -NowUtc $NowUtc)) { continue }
            # Already disabling before (a past date moved to another past date, Disabled -> Disabled):
            # the account is already off; this write does not disable anybody. Disabled -> Revoked
            # DOES escalate (sessions + memberships), so AccountStatus compares the value itself.
            $wasOff = Test-PimAdminDisablingValue -Column $col -Value $ov -NowUtc $NowUtc
            if ($wasOff -and ($col -ine 'AccountStatus' -or $nv -ieq 'Disabled')) { continue }
            $held[$col] = $nv; $restored[$col] = $ov
        }
        $upn = "$(Get-PimAuthoringCell $a 'UserPrincipalName')".Trim()
        if (-not $upn) { $upn = "$(Get-PimAuthoringCell $a 'UserName')".Trim() }
        if ($held.Count -eq 0) { $rows.Add($a); continue }
        if ($null -eq $old) {
            $holds.Add([pscustomobject]@{ key = $k; upn = $upn; kind = 'add'; fields = $held; restored = $restored })
            continue                                                                # the added row is held whole
        }
        # Put the held columns back to their STORED values on a copy (the caller's row is not mutated).
        $copy = [ordered]@{}
        if ($a -is [System.Collections.IDictionary]) { foreach ($kk in @($a.Keys)) { $copy[$kk] = $a[$kk] } }
        else { foreach ($p in $a.PSObject.Properties) { $copy[$p.Name] = $p.Value } }
        foreach ($col in @($held.Keys)) {
            $orig = $null
            if ($old -is [System.Collections.IDictionary]) { if ($old.Contains($col)) { $orig = $old[$col] } }
            else { $op = $old.PSObject.Properties[$col]; if ($op) { $orig = $op.Value } }
            if ($null -eq $orig) { $orig = '' }
            $copy[$col] = $orig
        }
        $rows.Add($copy)
        $holds.Add([pscustomobject]@{ key = $k; upn = $upn; kind = 'modify'; fields = $held; restored = $restored })
    }
    return [pscustomobject]@{ rows = $rows.ToArray(); holds = $holds.ToArray() }
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

    # (d) BUG-190 -- an ADMIN ROW that would disable the account on the next engine run (AccountStatus
    #     Disabled/Revoked, Lifecycle Retire, an AutoDisableDate/OffboardDate at or before now) is an
    #     offboard whatever action wrote it. A preview MODIFY counts only when it CHANGES a column into a
    #     disabling value (Get-PimAdminDisableHolds), so editing the department of an admin who is already
    #     disabled is not flagged; a preview ADD counts when it carries one; a REMOVE never does (removing
    #     a row disables nothing -- 71.22). The plain $Rows are the action's proposed rows, except for
    #     'review-save', whose rows mix adds with removes and whose PUT already HOLDS every disabling
    #     change for the offboard approval before this gate runs.
    $isAdminBase = ("$Base".Trim() -ieq 'Account-Definitions-Admins')
    if ($isAdminBase) {
        $disablingUpns = New-Object System.Collections.ArrayList
        $noteUpn = {
            param($r)
            $u = "$(Get-PimAuthoringCell $r 'UserPrincipalName')".Trim()
            if (-not $u) { $u = "$(Get-PimAuthoringCell $r 'UserName')".Trim() }
            if (-not $u) { $u = '(unnamed row)' }
            if (-not $disablingUpns.Contains($u)) { [void]$disablingUpns.Add($u) }
        }
        $rowDisables = {
            param($r)
            foreach ($col in $script:PimAdminDisablingColumns) {
                if (Test-PimAdminDisablingValue -Column $col -Value "$(Get-PimAuthoringCell $r $col)") { return $true }
            }
            return $false
        }
        if ($act -ne 'review-save') {
            foreach ($r in @($Rows)) { if ($null -ne $r -and (& $rowDisables $r)) { & $noteUpn $r } }
        }
        if ($null -ne $Preview) {
            $pv = { param($name) if ($Preview -is [System.Collections.IDictionary]) { if ($Preview.Contains($name)) { return $Preview[$name] } } else { $pp = $Preview.PSObject.Properties[$name]; if ($pp) { return $pp.Value } }; return $null }
            foreach ($it in @(& $pv 'adds')) {
                if ($null -eq $it) { continue }
                $row = $it
                if ($it -is [System.Collections.IDictionary] -and $it.Contains('row')) { $row = $it['row'] }
                elseif ($it -isnot [System.Collections.IDictionary] -and $it.PSObject.Properties['row']) { $row = $it.row }
                if (& $rowDisables $row) { & $noteUpn $row }
            }
            foreach ($it in @(& $pv 'modifies')) {
                if ($null -eq $it) { continue }
                $bf = $null; $af = $null
                if ($it -is [System.Collections.IDictionary]) { $bf = $it['before']; $af = $it['after'] }
                else { if ($it.PSObject.Properties['before']) { $bf = $it.before }; if ($it.PSObject.Properties['after']) { $af = $it.after } }
                if ($null -eq $af) { continue }
                $bset = @(); if ($null -ne $bf) { $bset = @($bf) }
                $h = Get-PimAdminDisableHolds -Before $bset -After @($af) -Base 'Account-Definitions-Admins'
                if (@($h.holds).Count -gt 0) { & $noteUpn $af }
            }
        }
        if ($disablingUpns.Count -gt 0) {
            [void]$reasons.Add("disables $($disablingUpns.Count) admin account(s) on the next engine run (" + ((@($disablingUpns) | Select-Object -First 5) -join ', ') + ") -- an offboard, requiring a second approver")
            $isDisableOrOffboard = $true
        }
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

    # 🔴 BUG-107 -- THE OPT-IN. Maker/checker is a POLICY CHOICE, not a default.
    # This gate shipped unconditionally, so a single-administrator deployment could not commit
    # any privileged change at all: the 409 asks for a SECOND administrator, self-approval is
    # refused by design, and in that tenant no second administrator exists. The operator hit it
    # after clearing every other blocker -- "i have not enabled this feature ... that should not
    # be standard".
    # 🔑 Enforced in the LIBRARY, not at the four call sites, so no future caller can reintroduce
    # the unconditional behaviour by forgetting the check. Absent flag machinery => OFF, because
    # the failure mode of defaulting ON is a deployment nobody can use, while defaulting OFF
    # merely restores the behaviour every other advanced surface already ships with.
    $mcOn = $false
    if (Get-Command Test-PimFeatureAvailable -ErrorAction SilentlyContinue) {
        try { $mcOn = [bool](Test-PimFeatureAvailable -Key 'makerchecker' -Quiet) } catch { $mcOn = $false }
    }
    if (-not $mcOn) {
        return [pscustomobject]@{
            allowed = $true; gate = 'makerchecker-disabled'
            reason = ("second-approver policy is OFF for this deployment (Settings -> features -> " +
                      "'Second-approver on sensitive changes'); the change is still classified, audited and validated" +
                      $(if ($cls.sensitive) { " -- flagged sensitive: " + ($cls.reasons -join '; ') } else { '' }))
            sensitive = [bool]$cls.sensitive; reasons = @($cls.reasons); target = $target; approval = $null
        }
    }

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
            # BUG-107: this text is what an admin reads at the moment they are stopped, so it
            # says WHO must act, WHAT to do, and HOW TO TURN THE POLICY OFF -- the original
            # named an internal request target and left the reader with no route at all
            # ("and this is not user friendly").
            reason = ("Another administrator needs to approve this before it can be committed, " +
                      "because it changes privileged access (" + ($cls.reasons -join '; ') + "). " +
                      "Ask a second administrator to approve it on the Approvals page. " +
                      "If this deployment has only one administrator, turn the second-approver " +
                      "policy off in Settings -> features -> 'Second-approver on sensitive changes'. " +
                      "(Approval reference: " + $target + ")")
            sensitive = $true; reasons = @($cls.reasons); target = $target; approval = $null
        }
    }
    return [pscustomobject]@{
        allowed = $true; gate = 'approved'
        reason = ("sensitive change approved by " + "$($appr.approver)")
        sensitive = $true; reasons = @($cls.reasons); target = $target; approval = $appr
    }
}
