<#
  _revaudit.ps1 -- WHO MAY REVOKE WHAT (REQ 100.122 F4; owner decisions (15), (30), (34), (35), (36) of 2026-10-13).
  Dot-sourced by Open-PimManager.ps1. Called by POST /api/revoke (staging: preview and commit of the batch) and by
  POST /api/queue/commit (the commit of a staged revoke), with the SAME rule both times, for the person who makes the call.

  THE RULE, decided on the server from STORED rows (never from what the page sent beyond the ids that address the row):
    * a SuperAdmin revokes anything: managed or not, any scope, any level. Always a person's own action.
    * an assignment PIM Manager does NOT manage (an old manual assignment, an old-design leftover, a Drift "extra"):
      a SuperAdmin only -- at staging AND at commit. An Admin is refused, with the reason.
    * an assignment PIM Manager MANAGES: the person who has permission over the target, without a SuperAdmin:
        - inside his scope: his portal profile's ceiling (service / tier / level / Azure scope / departments / managed
          admins), judged on the STORED definition rows of the groups involved and the stored admin row;
        - and the target is not an admin at a MORE privileged level than the caller (level 0 = most privileged;
          a level-4 admin never revokes a level-0 or level-1 admin; the same level or a less privileged one is allowed).
    * a refused revoke is refused WHOLE, with the reason per row, whoever staged it.

  MANAGED / NOT MANAGED / NOT KNOWN -- three answers, never two:
    MANAGED      the row's identity (Get-PimActiveRowIdentity) is in the engine's 'managed-live' list. That alone is
                 enough: a row that is missing from the stored read, or a stored read that is older, never turns a
                 managed assignment into a not-managed one.
    NOT MANAGED  only on positive evidence: the list is complete, the row IS in the stored read, the list is at least
                 as new as that read, and the identity is not in the list.
    NOT KNOWN    everything else (no list yet, an incomplete list, a row that is not in the stored read, a list older
                 than the read, a row without the ids that identify it). It is refused for everybody but a SuperAdmin
                 and the refusal SAYS that the mark could not be established -- it is never reported as "not managed".
  An ACTIVE Azure assignment is removed by its roleAssignmentId, which is not part of the identity: the id the request
  carries must be the id of the stored row with that identity, or the request is refused.

  PURE functions take everything as parameters (tests/Test-PimRevokeRule.ps1); the readers at the end fetch the stored rows.
  No $script: defaults (a $script: default read from a child scope is $null): every constant is a function or a literal.
#>
Set-StrictMode -Off

function Get-PimRevauditDefinitionEntities {
    # The entities whose rows DEFINE a group (the same eight the delegated model reads).
    return @('PIM-Definitions-Roles', 'PIM-Definitions-Services', 'PIM-Definitions-Organization', 'PIM-Definitions-Tasks',
             'PIM-Definitions-Projects', 'PIM-Definitions-Processes', 'PIM-Definitions-CrossOrg', 'PIM-Definitions-Resources')
}

function Get-PimRevauditRowValue {
    # PURE. One field of a row (IDictionary or object), by name, case-insensitive, trimmed; '' when absent.
    param([AllowNull()][object]$Row, [string[]]$Names)
    if ($null -eq $Row) { return '' }
    foreach ($n in @($Names)) {
        if ($Row -is [System.Collections.IDictionary]) {
            foreach ($k in @($Row.Keys)) { if ("$k" -ieq $n -and "$($Row[$k])".Trim()) { return "$($Row[$k])".Trim() } }
        } else {
            $p = $Row.PSObject.Properties | Where-Object { "$($_.Name)" -ieq $n } | Select-Object -First 1
            if ($p -and "$($p.Value)".Trim()) { return "$($p.Value)".Trim() }
        }
    }
    return ''
}

function ConvertTo-PimRevauditUtc {
    # PURE. A stored time (text, or the [datetime] pwsh 7 makes of ISO text in JSON) -> a UTC [datetime], or $null.
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [datetime]) {
        if ($Value.Kind -eq [DateTimeKind]::Local) { return $Value.ToUniversalTime() }
        return [datetime]::SpecifyKind($Value, [DateTimeKind]::Utc)
    }
    $s = "$Value".Trim(); if (-not $s) { return $null }
    $d = [datetime]::MinValue
    $styles = [Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal
    if ([datetime]::TryParse($s, [Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$d)) { return $d }
    return $null
}

function ConvertTo-PimRevauditRoleAssignmentId {
    # PURE. The Azure role-assignment id a revoke row addresses, normalised for comparison ('' when it names none).
    param([AllowNull()][object]$Row)
    $ra = Get-PimRevauditRowValue $Row @('roleAssignmentId')
    if (-not $ra) {
        $sc = (Get-PimRevauditRowValue $Row @('scope')).TrimEnd('/'); $nm = Get-PimRevauditRowValue $Row @('roleAssignmentName')
        if ($sc -and $nm) { $ra = "$sc/providers/Microsoft.Authorization/roleAssignments/$nm" }
    }
    return "$ra".Trim().TrimEnd('/').ToLowerInvariant()
}

function Test-PimRevauditRowEligible {
    # PURE. Does the row name an ELIGIBLE assignment (the engine then removes by principal + role + scope, not by an id)?
    param([AllowNull()][object]$Row)
    $t = Get-PimRevauditRowValue $Row @('assignmentType'); if (-not $t) { $t = Get-PimRevauditRowValue $Row @('memberType') }
    return [bool]($t -match '^(?i)elig')
}

function ConvertTo-PimRevauditRowFromQueueEntry {
    <#
      PURE. A pending queue entry of entity 'PIM-Action-Revoke' -> the revoke row it was staged from (the fields the rule
      reads), or $null when the entry is not a revoke / carries no readable payload.
    #>
    param([AllowNull()][object]$Entry)
    if ($null -eq $Entry -or "$($Entry.entity)" -ne 'PIM-Action-Revoke') { return $null }
    $p = $Entry.payload
    if ($p -is [string]) { try { $p = $p | ConvertFrom-Json } catch { $p = $null } }
    if ($null -eq $p) { return $null }
    $map = @{ 'entra-role-revoke' = 'entra-role'; 'azure-rbac-revoke' = 'azure-rbac'; 'group-assignment-revoke' = 'pim-for-groups' }
    $pt = (Get-PimRevauditRowValue $p @('type')).ToLowerInvariant()
    $row = [ordered]@{ id = "$($Entry.id)"; type = $(if ($map.ContainsKey($pt)) { $map[$pt] } else { '' }) }
    foreach ($f in @('principal', 'principalId', 'roleDefinitionId', 'directoryScopeId', 'roleAssignmentId', 'scope', 'groupId', 'accessId', 'assignmentType')) {
        $v = Get-PimRevauditRowValue $p @($f); if ($v) { $row[$f] = $v }
    }
    return $row
}

function Get-PimRevauditManagedMark {
    <#
      PURE. MANAGED / NOT MANAGED / NOT KNOWN for one revoke row (the file header says when which).
        -ManagedLive  @{ known; complete; computedUtc; set = HashSet[string] of lower-case identities; error }
        -Snapshot     @{ known; refreshedUtc; error; byIdentity = @{ identity -> @(stored rows) } }
      Returns @{ state = 'managed' | 'not-managed' | 'unknown' | 'mismatch'; why; identity; stored (the stored row or $null) }.
      'mismatch' = an active Azure assignment whose roleAssignmentId is not the stored row's.
    #>
    param([AllowNull()][object]$Row, [AllowNull()][hashtable]$ManagedLive, [AllowNull()][hashtable]$Snapshot)
    $out = @{ state = 'unknown'; why = ''; identity = ''; stored = $null }
    $id = ''
    if (Get-Command Get-PimActiveRowIdentity -ErrorAction SilentlyContinue) { try { $id = "$(Get-PimActiveRowIdentity -Row $Row)" } catch { $id = '' } }
    $id = $id.Trim().ToLowerInvariant()
    $out.identity = $id
    if (-not $id) { $out.why = 'the row does not carry the ids that identify an assignment (principal, role or group, scope)'; return $out }
    $snapKnown = [bool]($Snapshot -and $Snapshot.known)
    $storedList = @()
    if ($snapKnown -and $Snapshot.byIdentity -and $Snapshot.byIdentity.ContainsKey($id)) { $storedList = @($Snapshot.byIdentity[$id]) }
    $stored = if ($storedList.Count) { $storedList[0] } else { $null }
    # An ACTIVE Azure assignment is deleted by its roleAssignmentId: it must be the stored row's.
    $type = (Get-PimRevauditRowValue $Row @('type')).ToLowerInvariant()
    if ($type -eq 'azure-rbac' -and -not (Test-PimRevauditRowEligible -Row $Row)) {
        $want = ConvertTo-PimRevauditRoleAssignmentId -Row $Row
        if (-not $want) { $out.why = 'the row names no Azure role-assignment id'; return $out }
        if (-not $snapKnown) { $out.why = "the stored read of the tenant could not be used to check the Azure role-assignment id ($(if ($Snapshot) { $Snapshot.error } else { 'not read' }))"; return $out }
        if (-not $storedList.Count) { $out.why = 'the stored read of the tenant does not hold this Azure assignment, so its role-assignment id cannot be checked'; return $out }
        $hit = $null
        foreach ($s in $storedList) { if ((ConvertTo-PimRevauditRoleAssignmentId -Row $s) -eq $want) { $hit = $s; break } }
        if ($null -eq $hit) { $out.state = 'mismatch'; $out.why = 'the Azure role-assignment id in the request is not the one of the stored assignment for this principal, role and scope'; return $out }
        $stored = $hit
    }
    $out.stored = $stored
    if (-not $ManagedLive -or -not $ManagedLive.known) {
        $out.why = "the engine's list of the assignments PIM Manager manages is not available ($(if ($ManagedLive -and $ManagedLive.error) { $ManagedLive.error } else { 'not stored yet' }))"
        return $out
    }
    if ($ManagedLive.set -and $ManagedLive.set.Contains($id)) { $out.state = 'managed'; $out.why = "in the engine's list of managed assignments"; return $out }
    # Not in the list. NOT MANAGED only on positive evidence; any doubt = NOT KNOWN.
    if (-not [bool]$ManagedLive.complete) { $out.why = "the engine's last list of managed assignments is not complete, so a row that is missing from it proves nothing"; return $out }
    if (-not $snapKnown) { $out.why = "the stored read of the tenant is not available ($(if ($Snapshot) { $Snapshot.error } else { 'not read' }))"; return $out }
    if ($null -eq $stored) { $out.why = 'the assignment is not in the stored read of the tenant'; return $out }
    $mlAt = ConvertTo-PimRevauditUtc $ManagedLive.computedUtc; $snAt = ConvertTo-PimRevauditUtc $Snapshot.refreshedUtc
    if ($null -eq $mlAt -or $null -eq $snAt) { $out.why = 'the time of the list of managed assignments or of the stored read cannot be read'; return $out }
    if ($mlAt -lt $snAt) {
        $out.why = ("the list of managed assignments (as of {0:u}) is older than the stored read of the tenant (as of {1:u}), so a new managed assignment may not be in it yet" -f $mlAt, $snAt)
        return $out
    }
    $out.state = 'not-managed'; $out.why = "in the stored read of the tenant and not in the engine's complete list of managed assignments"
    return $out
}

function Get-PimRevauditEntraRoleFacets {
    # PURE. The facets of an Entra directory role (tier 0; privileged = L0, AU-scoped = L2, any other = L1).
    param([string]$RoleName, [bool]$AuScoped = $false)
    if (Get-Command Get-PimDelegatedEntraRoleFacets -ErrorAction SilentlyContinue) { return (Get-PimDelegatedEntraRoleFacets -RoleName $RoleName -AuScoped:$AuScoped -GroupTag '') }
    $priv = @('global administrator', 'privileged role administrator', 'privileged authentication administrator')
    $lvl = if ($priv -contains "$RoleName".Trim().ToLowerInvariant()) { 0 } elseif ($AuScoped) { 2 } else { 1 }
    return @{ service = 'entra'; workload = 'Entra-ID'; tier = 0; level = $lvl; plane = 'CP'; scope = ''; au = ''; groupTag = ''; name = "Entra role '$RoleName'"; kind = 'indirect' }
}

function Find-PimRevauditAdminRow {
    # PURE. The Account-Definitions-Admins row of a person named by UPN / user name ($null when none). A bare user name
    # matches UserName or the local part of UserPrincipalName.
    param([object[]]$Admins = @(), [string[]]$Names = @())
    $want = @(@($Names) | ForEach-Object { "$_".Trim().ToLowerInvariant() } | Where-Object { $_ } | Select-Object -Unique)
    if (-not $want.Count) { return $null }
    foreach ($a in @($Admins)) {
        if ($null -eq $a) { continue }
        $upn = (Get-PimRevauditRowValue $a @('UserPrincipalName')).ToLowerInvariant(); $un = (Get-PimRevauditRowValue $a @('UserName')).ToLowerInvariant()
        foreach ($w in $want) {
            if (($upn -and $w -eq $upn) -or ($un -and $w -eq $un)) { return $a }
            if ($un -and $w.Contains('@') -and ($w -split '@')[0] -eq $un -and -not $upn) { return $a }
        }
    }
    return $null
}

function Get-PimRevauditAdminLevel {
    # PURE. The level of an admin row (0 = most privileged), or $null when it cannot be read.
    param([AllowNull()][object]$AdminRow)
    if ($null -eq $AdminRow) { return $null }
    if (Get-Command Get-PimAdminPrivilegeLevel -ErrorAction SilentlyContinue) { return (Get-PimAdminPrivilegeLevel -Row $AdminRow).level }
    $l = Get-PimRevauditRowValue $AdminRow @('Level')
    if ($l -match '^(?i)L?(\d+)$') { return [int]$Matches[1] }
    return $null
}

function Get-PimRevauditCallerLevel {
    <#
      PURE. The caller's own level (0 = most privileged), or $null when he has none: the MORE restrictive (the higher
      number) of his portal profile's levelMax and the level of his own admin row. Neither known = no level ceiling (an
      administrator of the whole tenant, as Test-PimPortalCanDeleteAdmin reads an Admin without a profile).
    #>
    param([AllowNull()][object]$Profile, [string]$Identity = '', [object[]]$Admins = @())
    $levels = New-Object System.Collections.Generic.List[int]
    if ($null -ne $Profile) {
        $lm = Get-PimRevauditRowValue $Profile @('levelMax'); $n = 0
        if ($lm -and [int]::TryParse($lm, [ref]$n)) { $levels.Add($n) }
    }
    $own = Find-PimRevauditAdminRow -Admins $Admins -Names @($Identity)
    $ol = Get-PimRevauditAdminLevel -AdminRow $own
    if ($null -ne $ol) { $levels.Add([int]$ol) }
    if (-not $levels.Count) { return $null }
    return [int](($levels | Measure-Object -Maximum).Maximum)
}

function Get-PimRevauditTargetFacts {
    <#
      PURE. What a revoke row is about, read from STORED rows:
        -Row          the STORED snapshot row (names, kinds) -- $null = nothing stored for it
        -Definitions  @{ lower group name -> definition row } of every defined group
        -Admins       the Account-Definitions-Admins rows
      Returns @{ known; type; principal; principalKind; adminRow; adminLevel; adminLevelUnreadable; principalGroup (def row);
                 containerGroup (def row, PIM for Groups); facets = @(hashtable); missing = @(texts); departments = @(lower);
                 adminDepartment (lower); groupDepartments = @(lower); targetLevel }.
    #>
    param([AllowNull()][object]$Row, [hashtable]$Definitions = @{}, [object[]]$Admins = @())
    $o = @{ known = $false; type = ''; principal = ''; principalKind = ''; adminRow = $null; adminLevel = $null; adminLevelUnreadable = $false
            principalGroup = $null; containerGroup = $null; facets = @(); missing = @(); departments = @(); targetLevel = $null
            adminDepartment = ''; groupDepartments = @() }
    if ($null -eq $Row) { return $o }
    $o.known = $true
    $o.type = (Get-PimRevauditRowValue $Row @('type')).ToLowerInvariant()
    $o.principal = Get-PimRevauditRowValue $Row @('principal')
    $o.principalKind = (Get-PimRevauditRowValue $Row @('principalKind')).ToLowerInvariant()
    $upn = Get-PimRevauditRowValue $Row @('principalUpn')
    $facets = New-Object System.Collections.Generic.List[hashtable]
    $missing = New-Object System.Collections.Generic.List[string]
    $deps = New-Object System.Collections.Generic.List[string]
    $haveFacets = [bool](Get-Command Get-PimGroupFacets -ErrorAction SilentlyContinue)
    $defOf = { param($name) $k = "$name".Trim().ToLowerInvariant(); if ($k -and $Definitions.ContainsKey($k)) { $Definitions[$k] } else { $null } }
    # the principal: a defined admin (a person), or a defined group
    if ($o.principalKind -eq 'group') {
        $o.principalGroup = & $defOf $o.principal
    } else {
        $o.adminRow = Find-PimRevauditAdminRow -Admins $Admins -Names @($upn, $o.principal)
        if ($o.adminRow) {
            $o.adminLevel = Get-PimRevauditAdminLevel -AdminRow $o.adminRow
            if ($null -eq $o.adminLevel) { $o.adminLevelUnreadable = $true }
            $d = Get-PimRevauditRowValue $o.adminRow @('Department'); if ($d) { $deps.Add($d.ToLowerInvariant()) }
        }
    }
    if ($o.principalGroup) { $d = Get-PimRevauditRowValue $o.principalGroup @('Department'); if ($d) { $deps.Add($d.ToLowerInvariant()) } }
    $scope = Get-PimRevauditRowValue $Row @('scope')
    switch ($o.type) {
        'pim-for-groups' {
            $o.containerGroup = & $defOf $scope
            if (-not $o.containerGroup) { $missing.Add("the group '$scope' has no stored definition, so its scope and level cannot be checked") }
            elseif ($haveFacets) { $facets.Add((Get-PimGroupFacets -Row $o.containerGroup -Base '')) }
            if ($o.containerGroup) { $d = Get-PimRevauditRowValue $o.containerGroup @('Department'); if ($d) { $deps.Add($d.ToLowerInvariant()) } }
            if ($o.principalGroup -and $haveFacets) { $facets.Add((Get-PimGroupFacets -Row $o.principalGroup -Base '')) }
        }
        'entra-role' {
            $ds = Get-PimRevauditRowValue $Row @('directoryScopeId')
            $facets.Add((Get-PimRevauditEntraRoleFacets -RoleName (Get-PimRevauditRowValue $Row @('role')) -AuScoped ([bool]($ds -and $ds -ne '/'))))
            if ($o.principalKind -eq 'group') {
                if (-not $o.principalGroup) { $missing.Add("the group '$($o.principal)' has no stored definition, so its scope and level cannot be checked") }
                elseif ($haveFacets) { $facets.Add((Get-PimGroupFacets -Row $o.principalGroup -Base '')) }
            }
        }
        'azure-rbac' {
            if ($o.principalKind -eq 'group' -and -not $o.principalGroup) { $missing.Add("the group '$($o.principal)' has no stored definition, so its scope and level cannot be checked") }
            $f = $null
            if ($o.principalGroup -and $haveFacets) { $f = Get-PimGroupFacets -Row $o.principalGroup -Base '' }
            if ($null -eq $f) { $f = @{ service = 'azure'; workload = 'Azure'; tier = $null; level = $null; plane = ''; scope = ''; au = ''; groupTag = ''; name = "Azure role at '$scope'"; kind = 'indirect' } }
            else { $f = $f.Clone(); $f.service = 'azure' }
            $f.scope = $scope      # where the role is held: the STORED assignment's own scope
            $facets.Add($f)
        }
        default { $missing.Add("the stored row has an unknown type '$($o.type)'") }
    }
    if (-not $haveFacets) { $missing.Add('the scope library is not loaded') }
    $o.facets = @($facets.ToArray()); $o.missing = @($missing.ToArray()); $o.departments = @($deps | Select-Object -Unique)
    $o.adminDepartment = $(if ($o.adminRow) { (Get-PimRevauditRowValue $o.adminRow @('Department')).ToLowerInvariant() } else { '' })
    $o.groupDepartments = @(@($o.containerGroup, $o.principalGroup) | Where-Object { $null -ne $_ } | ForEach-Object { (Get-PimRevauditRowValue $_ @('Department')).ToLowerInvariant() } | Where-Object { $_ } | Select-Object -Unique)
    # the level the caller is compared with: the admin's own; for a group principal the group's own
    if ($o.adminRow) { $o.targetLevel = $o.adminLevel }
    elseif ($o.principalGroup -and $haveFacets) { $o.targetLevel = (Get-PimGroupFacets -Row $o.principalGroup -Base '').level }
    return $o
}

function Test-PimRevauditScope {
    # PURE. Is a managed row inside the caller's portal profile? Returns '' (in scope) or the reason it is not.
    param([AllowNull()][object]$Profile, [hashtable]$Facts)
    if ($null -eq $Profile) { return '' }     # no portal profile = the scope is not narrowed (the flat role gate applies)
    if (-not $Facts -or -not $Facts.known) { return 'it is not in the stored read of the tenant, so it cannot be placed inside your scope' }
    if (@($Facts.missing).Count) { return (@($Facts.missing) -join '; ') }
    if (-not (Get-Command Test-PimPortalCanManageGroup -ErrorAction SilentlyContinue)) { return 'the scope library is not loaded' }
    foreach ($f in @($Facts.facets)) {
        if (-not (Test-PimPortalCanManageGroup -Profile $Profile -Facets $f)) {
            return ("{0} (service {1}, T{2}, L{3}{4}) is outside your scope" -f $(if ("$($f.name)".Trim()) { $f.name } else { 'the assignment' }), $f.service, $f.tier, $f.level, $(if ("$($f.service)" -eq 'azure') { ", scope $($f.scope)" } else { '' }))
        }
    }
    # A profile that is limited to departments (a department owner's): EVERY group the assignment involves must belong
    # to one of them; when no group carries a department, the person must. (The delegated model's rule for a write.)
    $pd = @(@($Profile.departments) | ForEach-Object { "$_".Trim().ToLowerInvariant() } | Where-Object { $_ })
    if ($pd.Count) {
        $gd = @(@($Facts.groupDepartments) | Where-Object { "$_" })
        if ($gd.Count) {
            $other = @($gd | Where-Object { $pd -notcontains "$_" })
            if ($other.Count) { return "the group belongs to department '$($other[0])', which is not one of your departments" }
        } else {
            $ad = "$($Facts.adminDepartment)"
            if (-not $ad -or $pd -notcontains $ad) { return 'neither the group nor the person belongs to one of your departments' }
        }
        return ''
    }
    # A profile that names the admins it manages (and is not limited to departments): the person must be one of them.
    $ma = @(@($Profile.managedAdmins) | ForEach-Object { "$_".Trim().ToLowerInvariant() } | Where-Object { $_ })
    if ($Facts.adminRow -and $ma.Count -and $ma -notcontains '*') {
        $names = @(@((Get-PimRevauditRowValue $Facts.adminRow @('UserPrincipalName')), (Get-PimRevauditRowValue $Facts.adminRow @('UserName'))) | Where-Object { $_ } | ForEach-Object { $_.ToLowerInvariant() })
        if (-not @($names | Where-Object { $ma -contains $_ }).Count) { return "'$($Facts.principal)' is not one of the admins you manage" }
    }
    return ''
}

function Test-PimRevauditRevoke {
    <#
      PURE. THE VERDICT for a batch of revoke rows (the file header states the rule).
        -Caller  @{ role; isSuperAdmin; identity; profile; level (int or $null) }
        -Items   @( @{ row (as requested); mark (Get-PimRevauditManagedMark); facts (Get-PimRevauditTargetFacts of mark.stored) } )
        -ManagedOnly  the request came from a view that shows managed assignments only: a row that is not established as
                      managed is refused for everybody, a SuperAdmin included.
      Returns @{ allowed; reason; refused = @( @{ id; principal; type; code; reason } ); checked; needsSuperAdmin }.
      Codes: not-managed | managed-unknown | stored-row-mismatch | out-of-scope | more-privileged | level-unknown | role.
    #>
    param([hashtable]$Caller, [object[]]$Items = @(), [bool]$ManagedOnly = $false)
    $refused = New-Object System.Collections.Generic.List[object]
    $role = "$($Caller.role)"; $isSuper = [bool]$Caller.isSuperAdmin
    $needsSuper = $false
    $add = {
        param($it, $code, $text)
        $r = $it.row
        $refused.Add([ordered]@{ id = (Get-PimRevauditRowValue $r @('id')); principal = (Get-PimRevauditRowValue $r @('principal', 'principalId')); type = (Get-PimRevauditRowValue $r @('type')); code = $code; reason = $text })
    }
    foreach ($it in @($Items)) {
        if ($null -eq $it) { continue }
        $m = $it.mark; $f = $it.facts
        $who = Get-PimRevauditRowValue $it.row @('principal', 'principalId'); if (-not $who) { $who = '(unknown principal)' }
        $what = Get-PimRevauditRowValue $it.row @('role', 'roleDefinitionId', 'groupId'); if ($m -and $m.stored) { $sw = Get-PimRevauditRowValue $m.stored @('role'); if ($sw) { $what = $sw } }
        $label = "$who -> $what"
        if ($isSuper) {
            if ($ManagedOnly -and (-not $m -or "$($m.state)" -ne 'managed')) { & $add $it 'not-managed' "${label}: this view revokes only what PIM Manager manages, and this assignment is not established as managed -- revoke it from Delegation overview (All privileged permissions)" }
            continue
        }
        if ($role -ne 'Admin') { & $add $it 'role' "${label}: an Admin or a SuperAdmin is needed to revoke"; continue }
        $state = if ($m) { "$($m.state)" } else { 'unknown' }
        if ($state -eq 'mismatch') { & $add $it 'stored-row-mismatch' "${label}: $($m.why) -- nothing was staged for it; refresh the page and select the row again"; continue }
        if ($state -eq 'not-managed') {
            $needsSuper = $true
            & $add $it 'not-managed' "${label}: PIM Manager does not manage this assignment (an old manual assignment or a leftover), so only a SuperAdmin can revoke it -- you are signed in as $role"
            continue
        }
        if ($state -ne 'managed') {
            $needsSuper = $true
            & $add $it 'managed-unknown' "${label}: PIM Manager cannot establish right now whether it manages this assignment ($(if ($m) { $m.why } else { 'not checked' })). It is NOT counted as not managed. A SuperAdmin can revoke it now; for everybody else it works again after the next engine read"
            continue
        }
        # MANAGED: the caller's own permission over the target -- scope, then level. No SuperAdmin is asked for.
        $needFacts = ($null -ne $Caller.profile) -or ($null -ne $Caller.level)
        if ($needFacts -and (-not $f -or -not $f.known)) {
            & $add $it 'managed-unknown' "${label}: PIM Manager manages this assignment, but it is not in the stored read of the tenant, so your scope and level cannot be checked against it. It works again after the next read of the tenant (a SuperAdmin can revoke it now)"
            continue
        }
        $why = Test-PimRevauditScope -Profile $Caller.profile -Facts $f
        if ($why) { & $add $it 'out-of-scope' "${label}: outside your scope -- $why"; continue }
        if ($null -ne $Caller.level -and $f) {
            if ($f.adminRow -and $f.adminLevelUnreadable) { & $add $it 'level-unknown' "${label}: the level of '$who' cannot be read from the admin's row, so it cannot be compared with your level L$($Caller.level) -- not revoked (set Level on the admin, or ask a SuperAdmin)"; continue }
            if ($null -ne $f.targetLevel -and [int]$f.targetLevel -lt [int]$Caller.level) {
                & $add $it 'more-privileged' "${label}: '$who' is level L$($f.targetLevel), more privileged than your level L$($Caller.level) -- a level-$($Caller.level) admin cannot revoke it (ask an admin at level $($f.targetLevel) or above, or a SuperAdmin)"
                continue
            }
        }
    }
    $n = $refused.Count
    $reason = ''
    if ($n) {
        $first = @($refused | Select-Object -First 5 | ForEach-Object { "$($_.reason)" })
        $reason = ("Nothing was {0}: {1} of {2} selected assignment(s) may not be revoked by you. " -f 'staged or committed', $n, @($Items).Count) + ($first -join ' | ') + $(if ($n -gt 5) { " | ... and $($n - 5) more" } else { '' })
    }
    return [pscustomobject]@{ allowed = ($n -eq 0); reason = $reason; refused = @($refused.ToArray()); checked = @($Items).Count; needsSuperAdmin = $needsSuper }
}

# ----------------------------------------------------------------------------------------------------------------------
# The readers (stored rows only: pim.TenantCache, pim.ActiveAssignmentRows, pim.Rows). Never the tenant.
# ----------------------------------------------------------------------------------------------------------------------
function Get-PimRevauditManagedLive {
    # The engine's list of managed assignments (pim.TenantCache 'managed-live'): @{ known; complete; computedUtc; set; error }.
    $o = @{ known = $false; complete = $false; computedUtc = $null; set = (New-Object 'System.Collections.Generic.HashSet[string]'); error = '' }
    if (-not (Get-Command Get-PimTenantCacheEntry -ErrorAction SilentlyContinue)) { $o.error = 'the cache reader is not loaded'; return $o }
    $ml = $null
    try { $ml = Get-PimTenantCacheEntry -Kind 'managed-live' } catch { $o.error = "$($_.Exception.Message)"; return $o }
    if ($null -eq $ml) {
        $e = ''; if (Get-Command Get-PimTenantCacheReadError -ErrorAction SilentlyContinue) { $e = "$(Get-PimTenantCacheReadError -Kind 'managed-live')" }
        $o.error = $(if ($e) { "it could not be read: $e" } else { 'not stored yet -- the engine writes it with its drift read' })
        return $o
    }
    foreach ($i in @($ml.identities)) { if ("$i".Trim()) { [void]$o.set.Add("$i".Trim().ToLowerInvariant()) } }
    $o.complete = [bool]$ml.complete; $o.computedUtc = $ml.computedUtc; $o.known = $true
    return $o
}

function Get-PimRevauditSnapshotRows {
    <#
      The STORED rows of the last read of the tenant for these principals, by identity:
      @{ known; refreshedUtc; error; byIdentity = @{ identity -> @(rows) } }. Table form: one indexed query per 200
      principal ids (never the whole generation); one-document form: the document's rows.
    #>
    param([string[]]$PrincipalIds = @())
    $o = @{ known = $false; refreshedUtc = $null; error = ''; byIdentity = @{} }
    if (-not (Get-Command Get-PimTenantCacheEntry -ErrorAction SilentlyContinue)) { $o.error = 'the cache reader is not loaded'; return $o }
    $hdr = $null
    try { $hdr = Get-PimTenantCacheEntry -Kind 'active-assignments' -HeaderOnly } catch { $o.error = "$($_.Exception.Message)"; return $o }
    if ($null -eq $hdr) {
        $e = ''; if (Get-Command Get-PimTenantCacheReadError -ErrorAction SilentlyContinue) { $e = "$(Get-PimTenantCacheReadError -Kind 'active-assignments')" }
        $o.error = $(if ($e) { "it could not be loaded: $e" } else { 'no read of the tenant is stored yet' })
        return $o
    }
    $o.refreshedUtc = $hdr.refreshedUtc
    $ids = @(@($PrincipalIds) | ForEach-Object { "$_".Trim() } | Where-Object { $_ } | Select-Object -Unique)
    $rows = New-Object System.Collections.Generic.List[object]
    $isTable = [bool]($hdr.PSObject.Properties['rowStore'] -and "$($hdr.rowStore)" -eq 'table')
    try {
        if ($isTable) {
            $cs = "$(Get-PimTenantCacheStoreCs)"
            $sid = [long]0; [void][long]::TryParse("$($hdr.snapshotId)", [ref]$sid)
            if (-not $cs.Trim() -or $sid -le 0 -or -not (Get-Command Invoke-PimSqlQuery -ErrorAction SilentlyContinue)) { throw 'the stored rows cannot be read (no store or no generation)' }
            for ($i = 0; $i -lt $ids.Count; $i += 200) {
                $chunk = @($ids[$i..([Math]::Min($i + 199, $ids.Count - 1))])
                $p = @{ s = $sid }; $names = New-Object System.Collections.Generic.List[string]
                for ($j = 0; $j -lt $chunk.Count; $j++) { $p["p$j"] = "$($chunk[$j])"; $names.Add("@p$j") }
                $sql = 'SELECT RowJson FROM pim.ActiveAssignmentRows WHERE SnapshotId = @s AND PrincipalId IN (' + ($names -join ',') + ')'
                foreach ($r in @(Invoke-PimSqlQuery -ConnectionString $cs -Sql $sql -Parameters $p)) {
                    $j2 = "$($r.RowJson)"; if ($j2.Trim()) { $rows.Add(($j2 | ConvertFrom-Json)) }
                }
            }
        } else {
            $set = @{}; foreach ($x in $ids) { $set[$x.ToLowerInvariant()] = $true }
            foreach ($r in @($hdr.rows)) { if ($null -ne $r -and $set.ContainsKey((Get-PimRevauditRowValue $r @('principalId')).ToLowerInvariant())) { $rows.Add($r) } }
        }
    } catch { $o.error = "the stored rows could not be read: $($_.Exception.Message)"; return $o }
    foreach ($r in $rows) {
        $k = ''; try { $k = "$(Get-PimActiveRowIdentity -Row $r)".Trim().ToLowerInvariant() } catch { $k = '' }
        if (-not $k) { continue }
        # plain ARRAYS as values (pwsh 7 throws on @() over a generic list read back out of a hashtable)
        if ($o.byIdentity.ContainsKey($k)) { $o.byIdentity[$k] = [object[]]($o.byIdentity[$k] + @($r)) } else { $o.byIdentity[$k] = [object[]]@($r) }
    }
    $o.known = $true
    return $o
}

function Get-PimRevauditDirectory {
    # The stored definitions the rule reads: @{ ok; error; definitions = @{ lower group name -> row }; admins = @(rows) }.
    # A read that fails is an ERROR (fail closed), never an empty set.
    $o = @{ ok = $false; error = ''; definitions = @{}; admins = @() }
    try {
        foreach ($e in (Get-PimRevauditDefinitionEntities)) {
            foreach ($x in @((Read-PimRows -BaseName $e -NoScope).rows)) {
                $n = Get-PimRevauditRowValue $x @('GroupName'); if ($n -and -not $o.definitions.ContainsKey($n.ToLowerInvariant())) { $o.definitions[$n.ToLowerInvariant()] = $x }
            }
        }
        $o.admins = @((Read-PimRows -BaseName 'Account-Definitions-Admins' -NoScope).rows)
        $o.ok = $true
    } catch { $o.error = "$($_.Exception.Message)" }
    return $o
}

function Test-PimRevauditRequest {
    <#
      The verdict for the rows of ONE request, for the person who makes it (POST /api/revoke: preview and commit;
      Test-PimRevauditQueueCommit for the commit of staged entries). A SuperAdmin without -ManagedOnly is allowed without
      a single read. Anything that cannot be read refuses (fail closed) and says what could not be read.
    #>
    param([object[]]$Rows = @(), [bool]$ManagedOnly = $false)
    $rows = @(@($Rows) | Where-Object { $null -ne $_ })
    $role = $null; try { $role = Get-PimManagerRole } catch { $role = $null }
    $scope = $null; try { $scope = Get-PimManagerCallerScope } catch { $scope = $null }
    $caller = @{ role = "$(if ($role) { $role.role })"; identity = "$(if ($role) { $role.identity })"; isSuperAdmin = [bool]($scope -and $scope.isSuperAdmin); profile = $(if ($scope) { $scope.profile } else { $null }); level = $null }
    if ($caller.isSuperAdmin -and -not $ManagedOnly) { return [pscustomobject]@{ allowed = $true; reason = 'SuperAdmin'; refused = @(); checked = $rows.Count; needsSuperAdmin = $false; caller = $caller } }
    if (-not $rows.Count) { return [pscustomobject]@{ allowed = $true; reason = 'no rows'; refused = @(); checked = 0; needsSuperAdmin = $false; caller = $caller } }
    $ml = Get-PimRevauditManagedLive
    $snap = Get-PimRevauditSnapshotRows -PrincipalIds @($rows | ForEach-Object { Get-PimRevauditRowValue $_ @('principalId') })
    $dir = @{ ok = $true; error = ''; definitions = @{}; admins = @() }
    if (-not $caller.isSuperAdmin) {
        $dir = Get-PimRevauditDirectory
        if (-not $dir.ok) {
            $msg = "Nothing was staged or committed: the stored definitions could not be read ($($dir.error)), so who may revoke these assignments cannot be decided. Try again; a SuperAdmin is not limited by this."
            return [pscustomobject]@{ allowed = $false; reason = $msg; refused = @([ordered]@{ id = ''; principal = ''; type = ''; code = 'definitions-unreadable'; reason = $msg }); checked = $rows.Count; needsSuperAdmin = $false; caller = $caller }
        }
        $caller.level = Get-PimRevauditCallerLevel -Profile $caller.profile -Identity $caller.identity -Admins @($dir.admins)
    }
    $items = New-Object System.Collections.Generic.List[object]
    foreach ($r in $rows) {
        $mark = Get-PimRevauditManagedMark -Row $r -ManagedLive $ml -Snapshot $snap
        $facts = Get-PimRevauditTargetFacts -Row $mark.stored -Definitions $dir.definitions -Admins @($dir.admins)
        $items.Add(@{ row = $r; mark = $mark; facts = $facts })
    }
    $v = Test-PimRevauditRevoke -Caller $caller -Items @($items.ToArray()) -ManagedOnly $ManagedOnly
    $v | Add-Member -NotePropertyName caller -NotePropertyValue $caller -Force
    return $v
}

function Test-PimRevauditQueueEntryIsGroupDelete {
    # PURE. Is this queue entry the Drift page's DELETE of a whole extra group (entity PIM-Action-GroupDelete / type group-delete)?
    param([AllowNull()][object]$Entry)
    if ($null -eq $Entry) { return $false }
    if ("$($Entry.entity)" -eq 'PIM-Action-GroupDelete') { return $true }
    $p = $Entry.payload
    if ($p -is [string]) { try { $p = $p | ConvertFrom-Json } catch { $p = $null } }
    return ((Get-PimRevauditRowValue $p @('type')) -eq 'group-delete')
}

function Get-PimRevauditGroupDeleteReason {
    # PURE. Decision (30): a whole group that is an EXTRA is not managed by PIM Manager -- deleting it is a SuperAdmin's,
    # at staging and at commit. '' = allowed; otherwise the reason.
    param([bool]$IsSuperAdmin, [string]$Role = '', [string]$Stage = 'stage')
    if ($IsSuperAdmin) { return '' }
    $r = if ("$Role".Trim()) { "$Role".Trim() } else { 'Reader' }
    if ($Stage -eq 'commit') { return "Nothing was committed: the deletion of a group PIM Manager does not manage (an extra on the Drift page) is committed by a SuperAdmin only -- you are signed in as $r." }
    return "Nothing was queued: a group PIM Manager does not manage (an extra on the Drift page) is deleted by a SuperAdmin only -- you are signed in as $r. Ask a SuperAdmin, or choose Import into PIM or Ignore."
}

function Get-PimRevauditGroupDeleteRefusal {
    # The same, for the person who makes this request.
    param([string]$Stage = 'stage')
    $role = $null; try { $role = Get-PimManagerRole } catch { $role = $null }
    $isSuper = $false; try { $isSuper = [bool](Test-PimManagerRoleAtLeast -Minimum 'SuperAdmin') } catch { $isSuper = $false }
    return (Get-PimRevauditGroupDeleteReason -IsSuperAdmin $isSuper -Role "$(if ($role) { $role.role })" -Stage $Stage)
}

function Test-PimRevauditQueueCommit {
    <#
      Decisions (34)-(36): the commit of a STAGED revoke is checked again, for the person who commits, from the stored
      rows as they are NOW. -Ids = the ids this commit would move; -Entries = the pending queue entries. Entries that are
      not a revoke are not this rule's. Returns the verdict; refused[].id is the QUEUE id.
    #>
    param([string[]]$Ids = @(), [object[]]$Entries = @())
    $want = @{}; foreach ($i in @($Ids)) { if ("$i".Trim()) { $want["$i".Trim().ToLowerInvariant()] = $true } }
    $rows = New-Object System.Collections.Generic.List[object]
    $unreadable = New-Object System.Collections.Generic.List[object]
    # Decision (30): the DELETE of a whole extra group is a SuperAdmin's at commit too (its own commit stays as it is).
    $gd = @(@($Entries) | Where-Object { $null -ne $_ -and $want.ContainsKey("$($_.id)".Trim().ToLowerInvariant()) -and (Test-PimRevauditQueueEntryIsGroupDelete -Entry $_) })
    if ($gd.Count) {
        $why = Get-PimRevauditGroupDeleteRefusal -Stage 'commit'
        if ($why) {
            $ref = @($gd | ForEach-Object { [ordered]@{ id = "$($_.id)"; principal = "$(Get-PimRevauditRowValue $_.payload @('groupName'))"; type = 'group-delete'; code = 'not-managed'; reason = $why } })
            return [pscustomobject]@{ allowed = $false; reason = $why; refused = $ref; checked = $gd.Count; needsSuperAdmin = $true }
        }
    }
    foreach ($e in @($Entries)) {
        if ($null -eq $e -or -not $want.ContainsKey("$($e.id)".Trim().ToLowerInvariant())) { continue }
        if ("$($e.entity)" -ne 'PIM-Action-Revoke') { continue }
        $row = ConvertTo-PimRevauditRowFromQueueEntry -Entry $e
        if ($null -eq $row -or -not "$($row.type)") { $unreadable.Add($e); continue }
        $rows.Add($row)
    }
    if (-not $rows.Count -and -not $unreadable.Count) { return [pscustomobject]@{ allowed = $true; reason = 'no staged revoke in this commit'; refused = @(); checked = 0; needsSuperAdmin = $false } }
    $v = Test-PimRevauditRequest -Rows @($rows.ToArray())
    if ($unreadable.Count -and -not ($v.caller -and $v.caller.isSuperAdmin)) {
        $extra = @($unreadable | ForEach-Object { [ordered]@{ id = "$($_.id)"; principal = ''; type = ''; code = 'managed-unknown'; reason = "queue entry $($_.id): the staged revoke cannot be read, so it cannot be checked -- a SuperAdmin commits it, or discard it and stage it again" } })
        $all = @(@($v.refused) + $extra)
        $v = [pscustomobject]@{ allowed = $false; reason = ("Nothing was committed: {0} staged revoke(s) may not be committed by you. " -f $all.Count) + ((@($all | Select-Object -First 5 | ForEach-Object { "$($_.reason)" })) -join ' | '); refused = $all; checked = $v.checked + $unreadable.Count; needsSuperAdmin = $true; caller = $v.caller }
    }
    return $v
}

function Get-PimRevauditRefusalBody {
    # PURE. The JSON body of a refusal (HTTP 403): the reason in words, and one entry per refused row.
    param([Parameter(Mandatory)][object]$Verdict, [string]$Stage = 'stage')
    $msg = "$($Verdict.reason)"
    if ($Stage -eq 'commit') { $msg = $msg -replace '^Nothing was staged or committed:', 'Nothing was committed:' } else { $msg = $msg -replace '^Nothing was staged or committed:', 'Nothing was staged:' }
    return [ordered]@{ ok = $false; error = $msg; revokeRefused = $true; stage = $Stage; needsSuperAdmin = [bool]$Verdict.needsSuperAdmin; refused = @($Verdict.refused); denied = @($Verdict.refused) }
}

function Write-PimRevauditRefusalAudit {
    # One audit event per refused row (who tried, what, why). Never throws: the refusal itself must reach the caller.
    param([Parameter(Mandatory)][object]$Verdict, [string]$Stage = 'stage')
    if (-not (Get-Command Write-PimManagerAuditEvent -ErrorAction SilentlyContinue)) { return }
    foreach ($r in @($Verdict.refused)) {
        try {
            Write-PimManagerAuditEvent -Action "revoke.refused.$Stage" -Target ("{0} | {1}" -f "$($r.principal)", "$($r.type)") -Result 'refused' `
                -After ([ordered]@{ id = "$($r.id)"; code = "$($r.code)"; reason = "$($r.reason)"; stage = $Stage })
        } catch { Write-Warning "[revoke] the refusal could not be audited: $($_.Exception.Message)" }
    }
}
