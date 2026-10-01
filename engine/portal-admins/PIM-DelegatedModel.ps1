<#
  PIM-DelegatedModel.ps1 -- §79.9 THE DELEGATED MODEL, write side (operator 2026-09-25: "a dept owner whose Azure subscription
  sits at management-group level 6 logs in to the portal as a delegated admin and (a) delegates permissions on the resources
  linked to the dept, (b) manages the admins linked to the dept" ... "it is the whole delegated model"; decision: DERIVED from
  department ownership, CAPPED at level 3 and below).

  The READ side existed: a 'Delegated' Manager user sees only the groups they own (Owners / SponsorUpn, or through the
  group's Department) and a commit keeps every row they cannot see (BUG-198). The Delegated role was read-only for writes.
  This file is the write side:
    * WHO is delegated: ManagerAccess role 'Delegated', or -- derived -- a Reader who is an OWNER of at least one department
      (PIM-Definitions-Departments.Owners). Pro ('access.delegated'): without the licence the role is capped at Reader.
    * THE PROFILE they write under: an explicit portal profile (pim.Settings['PortalAdmins']) when one exists; else the
      DERIVED one -- levelMax 3, tierMax 1 (never L0-L2, never T0), Azure only under the departments' AzureScopes (a
      department with no AzureScopes grants NO Azure scope -- an empty scope list must never mean "anywhere"), manage +
      assign, and account operations on the admins of their departments.
    * THE WRITE RULE: every row a write affects must be (1) OWNED by the caller and (2) inside the profile's ceiling.
      Ownership: a definition row whose Owners/SponsorUpn names them or whose Department they own; an assignment row that
      references (GroupTag / TargetGroupTag / SourceGroupTag) a group they own; an admin row whose Department they own.
  PURE. The Manager (Open-PimManager.ps1) resolves the rows and applies the verdict.
#>
Set-StrictMode -Off

$script:PimDelegatedNoAzureScope = '/__pim-delegated-no-azure-scope__'   # a scope nothing is under

function Get-PimDelegatedRowValue {
    param([AllowNull()][object]$Row, [string[]]$Names)
    if ($null -eq $Row) { return '' }
    foreach ($n in $Names) {
        if ($Row -is [System.Collections.IDictionary]) { foreach ($k in @($Row.Keys)) { if ("$k" -ieq $n -and "$($Row[$k])".Trim()) { return "$($Row[$k])".Trim() } } }
        else { $p = $Row.PSObject.Properties | Where-Object { "$($_.Name)" -ieq $n } | Select-Object -First 1; if ($p -and "$($p.Value)".Trim()) { return "$($p.Value)".Trim() } }
    }
    return ''
}

function Split-PimDelegatedList {
    param([AllowNull()][string]$Value)
    @("$Value" -split '[|;,\s]+' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
}

function Get-PimDelegatedOwnership {
    <#
      PURE. What -Identity owns: @{ departments (lower); groupTags (lower); groupNames (lower); admins (lower usernames + upns) }.
      -Departments: PIM-Definitions-Departments rows; -Definitions: every definition row (Roles/Services/Organization/Tasks...);
      -Admins: Account-Definitions-Admins rows.
    #>
    param([string]$Identity, [object[]]$Departments = @(), [object[]]$Definitions = @(), [object[]]$Admins = @(), [object[]]$AzureBindings = @(),
          [object[]]$AdminAssignments = @())
    $id = "$Identity".Trim().ToLowerInvariant()
    # R25-03: definitions = EVERY stored definition row by GroupTag (owned or not), adminIndex = every stored admin by
    # UserName and UPN, groupAzScopes = the AzScope of every stored PIM-Assignments-Azure-Resources binding per group.
    # The write ceiling of an assignment is read from THESE, never from the submitted row.
    $out = @{ departments = @{}; groupTags = @{}; groupNames = @{}; admins = @{}; azureScopes = New-Object System.Collections.Generic.List[string]
              definitions = @{}; adminIndex = @{}; groupAzScopes = @{}; adminGroups = @{} }
    # R25-04: the groups every admin is in (PIM-Assignments-Admins, by Username -- a bare name or a UPN).
    foreach ($m in @($AdminAssignments)) {
        $u = Get-PimDelegatedRowValue $m @('Username', 'UserName'); $t = Get-PimDelegatedRowValue $m @('GroupTag'); if (-not $u -or -not $t) { continue }
        $k = $u.ToLowerInvariant(); if (-not $out.adminGroups.ContainsKey($k)) { $out.adminGroups[$k] = New-Object System.Collections.Generic.List[string] }
        $out.adminGroups[$k].Add($t) | Out-Null
    }
    foreach ($b in @($AzureBindings)) {
        $t = Get-PimDelegatedRowValue $b @('GroupTag'); $s = Get-PimDelegatedRowValue $b @('AzScope'); if (-not $t) { continue }
        $k = $t.ToLowerInvariant(); if (-not $out.groupAzScopes.ContainsKey($k)) { $out.groupAzScopes[$k] = New-Object System.Collections.Generic.List[string] }
        $out.groupAzScopes[$k].Add($(if ($s) { $s } else { '/' })) | Out-Null   # a binding with no scope is read as the root
    }
    foreach ($r in @(@($Definitions) + @($Departments))) {
        $t = Get-PimDelegatedRowValue $r @('GroupTag'); if ($t -and -not $out.definitions.ContainsKey($t.ToLowerInvariant())) { $out.definitions[$t.ToLowerInvariant()] = $r }
    }
    foreach ($a in @($Admins)) {
        $un = Get-PimDelegatedRowValue $a @('UserName'); $upn = Get-PimDelegatedRowValue $a @('UserPrincipalName')
        $keys = @(@($un, $upn) | Where-Object { $_ } | ForEach-Object { $_.ToLowerInvariant() })
        foreach ($k in $keys) { $out.adminIndex[$k] = $keys }
    }
    if (-not $id) { return $out }
    foreach ($d in @($Departments)) {
        $n = Get-PimDelegatedRowValue $d @('Department', 'DepartmentName'); if (-not $n) { continue }
        $own = @(Split-PimDelegatedList (Get-PimDelegatedRowValue $d @('Owners', 'DeptOwner', 'DepartmentOwner', 'ManagerEmail')) | ForEach-Object { $_.ToLowerInvariant() })
        if ($own -contains $id) {
            $out.departments[$n.ToLowerInvariant()] = $true
            foreach ($s in (Split-PimDelegatedList (Get-PimDelegatedRowValue $d @('AzureScopes', 'AzureScope')))) { if ($s -match '^/') { $out.azureScopes.Add($s) | Out-Null } }
        }
    }
    foreach ($r in @($Definitions)) {
        if (Test-PimDelegatedDefinitionOwned -Row $r -Identity $id -OwnedDepartments $out.departments) {
            $t = Get-PimDelegatedRowValue $r @('GroupTag'); if ($t) { $out.groupTags[$t.ToLowerInvariant()] = $true }
            $g = Get-PimDelegatedRowValue $r @('GroupName'); if ($g) { $out.groupNames[$g.ToLowerInvariant()] = $true }
        }
    }
    foreach ($a in @($Admins)) {
        $dep = Get-PimDelegatedRowValue $a @('Department')
        if ($dep -and $out.departments.ContainsKey($dep.ToLowerInvariant())) {
            foreach ($k in @('UserName', 'UserPrincipalName')) { $v = Get-PimDelegatedRowValue $a @($k); if ($v) { $out.admins[$v.ToLowerInvariant()] = $true } }
        }
    }
    return $out
}

function Test-PimDelegatedDefinitionOwned {
    param([AllowNull()][object]$Row, [string]$Identity, [hashtable]$OwnedDepartments = @{})
    $id = "$Identity".Trim().ToLowerInvariant(); if (-not $id -or $null -eq $Row) { return $false }
    $names = @(Split-PimDelegatedList ((Get-PimDelegatedRowValue $Row @('Owners')) + ';' + (Get-PimDelegatedRowValue $Row @('SponsorUpn'))) | ForEach-Object { $_.ToLowerInvariant() })
    if ($names -contains $id) { return $true }
    $dep = Get-PimDelegatedRowValue $Row @('Department')
    return [bool]($dep -and $OwnedDepartments.ContainsKey($dep.ToLowerInvariant()))
}

function Get-PimDelegatedDerivedProfile {
    <#
      PURE. The profile a delegated caller writes under. -Explicit (their pim.Settings['PortalAdmins'] profile) wins as is.
      Otherwise derived from -Ownership (Get-PimDelegatedOwnership): $null when they own no department and no group.
    #>
    param([string]$Identity, [AllowNull()][object]$Explicit, [hashtable]$Ownership)
    if ($Explicit) { return $Explicit }
    if (-not $Ownership -or (-not $Ownership.departments.Count -and -not $Ownership.groupTags.Count)) { return $null }
    $scopes = @($Ownership.azureScopes | Sort-Object -Unique)
    if (-not $scopes.Count) { $scopes = @($script:PimDelegatedNoAzureScope) }
    [pscustomobject]@{
        identity      = "$Identity"
        source        = 'derived:department-owner'
        departments   = @($Ownership.departments.Keys | Sort-Object)
        services      = @('*')
        tierMax       = 1
        levelMax      = 3
        scopes        = $scopes
        capabilities  = @('manage-direct', 'manage-indirect', 'assign', 'assign-admin', 'manage-account')
        managedAdmins = @($Ownership.admins.Keys | Sort-Object)
    }
}

function Test-PimDelegatedRowOwned {
    # PURE. Is this row the caller's to change? (definition / assignment / admin -- see the file header)
    param([AllowNull()][object]$Row, [string]$Base, [string]$Identity, [hashtable]$Ownership)
    if ($null -eq $Row -or -not $Ownership) { return $false }
    if ("$Base" -like 'Account-Definitions-Admins*') {
        $dep = Get-PimDelegatedRowValue $Row @('Department')
        return [bool]($dep -and $Ownership.departments.ContainsKey($dep.ToLowerInvariant()))
    }
    if ("$Base" -like 'PIM-Definitions-*') {
        if ("$Base" -eq 'PIM-Definitions-Departments') { return $false }   # the departments themselves (owners!) stay with an administrator
        return (Test-PimDelegatedDefinitionOwned -Row $Row -Identity $Identity -OwnedDepartments $Ownership.departments)
    }
    foreach ($c in @('GroupTag', 'TargetGroupTag', 'SourceGroupTag')) {
        $v = Get-PimDelegatedRowValue $Row @($c)
        if ($v -and -not $Ownership.groupTags.ContainsKey($v.ToLowerInvariant())) { return $false }   # EVERY referenced group must be theirs
    }
    return [bool](@('GroupTag', 'TargetGroupTag', 'SourceGroupTag') | Where-Object { Get-PimDelegatedRowValue $Row @($_) }).Count
}

function Get-PimDelegatedRowColumns {
    # The columns of a row that carry a value (IDictionary or PSObject).
    param([AllowNull()][object]$Row)
    if ($null -eq $Row) { return @() }
    if ($Row -is [System.Collections.IDictionary]) { return @(@($Row.Keys) | Where-Object { "$($Row[$_])".Trim() } | ForEach-Object { "$_" }) }
    return @($Row.PSObject.Properties | Where-Object { "$($_.Value)".Trim() } | ForEach-Object { "$($_.Name)" })
}

function Get-PimDelegatedEntraRoleFacets {
    # R25-03: an Entra DIRECTORY role is tier 0 (Get-PimEntraDerivation: "entra permission groups are tier 0"); the
    # privileged set is L0, an AU-scoped role L2, every other role L1. Read from the ROLE, never from the row's columns.
    param([string]$RoleName, [switch]$AuScoped, [string]$GroupTag)
    $priv = if (Get-Command Get-PimPrivilegedEntraRoles -ErrorAction SilentlyContinue) { @(Get-PimPrivilegedEntraRoles) } else { @('Global Administrator', 'Privileged Role Administrator', 'Privileged Authentication Administrator') }
    $isPriv = @($priv | ForEach-Object { "$_".Trim().ToLowerInvariant() }) -contains "$RoleName".Trim().ToLowerInvariant()
    $lvl = if ($isPriv) { 0 } elseif ($AuScoped) { 2 } else { 1 }
    return @{ service = 'entra'; workload = 'Entra-ID'; tier = 0; level = $lvl; plane = 'CP'; scope = ''; au = ''; groupTag = "$GroupTag"; name = "Entra role '$RoleName'"; kind = 'indirect' }
}

function Test-PimDelegatedFacetsManageable {
    # Test-PimPortalCanManageGroup, except that an AZURE GROUP WITH NO SCOPE (a definition: the scope lives on its
    # PIM-Assignments-Azure-Resources binding, which is checked there on its AzScope) is judged on everything but the
    # scope gate. Every other facet -- service, tier, level, capability, managedGroupTags -- still applies.
    param([AllowNull()][object]$Profile, [hashtable]$Facets)
    if ($null -eq $Profile) { return $false }
    if ($Facets.service -eq 'azure' -and -not "$($Facets.scope)".Trim()) {
        if ($Profile -is [System.Collections.IDictionary]) { $p2 = $Profile.Clone(); $p2['scopes'] = @() }
        else {
            $p2 = $Profile.PSObject.Copy()
            if ($p2.PSObject.Properties['scopes']) { $p2.scopes = @() } else { $p2 | Add-Member -NotePropertyName scopes -NotePropertyValue @() }
        }
        return [bool](Test-PimPortalCanManageGroup -Profile $p2 -Facets $Facets)
    }
    return [bool](Test-PimPortalCanManageGroup -Profile $Profile -Facets $Facets)
}

function Test-PimDelegatedAssignmentCeiling {
    <#
      PURE. R25-03 -- the ceiling of ONE assignment row, taken from what the row GRANTS, never from what it claims:
        * every referenced group (GroupTag / TargetGroupTag / SourceGroupTag) through its STORED definition row
          (-Ownership.definitions); a group with no stored definition is refused;
        * the role or scope itself: an Entra directory role (Roles-Groups / Roles-AUs) is T0 at L0/L1/L2; an Azure
          assignment's AzScope, a workload binding's Workload + Scope;
        * the capability to assign at all, and for PIM-Assignments-Admins the assigned admin must be one the profile manages.
      The submitted TierLevel / Level / Plane / PermissionScope columns are ignored. Returns @(denial texts) (empty = ok).
    #>
    param([AllowNull()][object]$Profile, [AllowNull()][object]$Row, [string]$Base, [hashtable]$Ownership)
    $den = New-Object System.Collections.Generic.List[string]
    if ($null -eq $Row) { return @() }
    $label = Get-PimDelegatedRowValue $Row @('GroupTag', 'TargetGroupTag', 'Username', 'UserName')
    if (-not $label) { $label = '(unnamed row)' }
    if (-not (Test-PimPortalCanAssign -Profile $Profile)) { $den.Add("${label}: your profile may not make assignments") | Out-Null; return @($den) }
    $defs = if ($Ownership -and $Ownership.definitions) { $Ownership.definitions } else { @{} }
    $checks = New-Object System.Collections.Generic.List[hashtable]
    $storedFacets = $null
    foreach ($c in @('GroupTag', 'TargetGroupTag', 'SourceGroupTag')) {
        $t = Get-PimDelegatedRowValue $Row @($c); if (-not $t) { continue }
        if (-not $defs.ContainsKey($t.ToLowerInvariant())) { $den.Add("${label}: group '$t' has no stored definition, so its level cannot be checked") | Out-Null; continue }
        $f = Get-PimGroupFacets -Row $defs[$t.ToLowerInvariant()] -Base ''
        if ($c -ne 'SourceGroupTag' -and $null -eq $storedFacets) { $storedFacets = $f }
        # An Azure group's scope is where it is BOUND: check every stored binding's scope (none = it grants no scope yet).
        if ($f.service -eq 'azure' -and -not "$($f.scope)".Trim()) {
            $bound = if ($Ownership -and $Ownership.groupAzScopes -and $Ownership.groupAzScopes.ContainsKey($t.ToLowerInvariant())) { @($Ownership.groupAzScopes[$t.ToLowerInvariant()]) } else { @() }
            if ($bound.Count) { foreach ($s in $bound) { $fb = $f.Clone(); $fb.scope = $s; $fb.name = "$($f.name) bound at $s"; $checks.Add($fb) | Out-Null }; continue }
        }
        $checks.Add($f) | Out-Null
    }
    switch -Wildcard ("$Base") {
        'PIM-Assignments-Roles-Groups' {
            $rn = Get-PimDelegatedRowValue $Row @('RoleDefinitionName')
            if (-not $rn) { $den.Add("${label}: no RoleDefinitionName") | Out-Null } else { $checks.Add((Get-PimDelegatedEntraRoleFacets -RoleName $rn -GroupTag $label)) | Out-Null }
        }
        'PIM-Assignments-Roles-AUs' {
            $rn = Get-PimDelegatedRowValue $Row @('RoleDefinitionName')
            if (-not $rn) { $den.Add("${label}: no RoleDefinitionName") | Out-Null } else { $checks.Add((Get-PimDelegatedEntraRoleFacets -RoleName $rn -AuScoped -GroupTag $label)) | Out-Null }
        }
        'PIM-Assignments-Azure-Resources' {
            $sc = Get-PimDelegatedRowValue $Row @('AzScope')
            if (-not $sc -or $sc.Trim().TrimEnd('/') -eq '') { $den.Add("${label}: no AzScope (or the tenant root)") | Out-Null }
            else {
                $lv = if ($storedFacets) { $storedFacets.level } else { $null }
                $tr = if ($storedFacets -and $null -ne $storedFacets.tier) { [Math]::Max(1, [int]$storedFacets.tier) } else { $null }
                $checks.Add(@{ service = 'azure'; workload = 'Azure'; tier = $tr; level = $lv; plane = ''; scope = $sc; au = ''; groupTag = $label; name = "Azure scope '$sc'"; kind = 'indirect' }) | Out-Null
            }
        }
        'PIM-Assignments-Workloads' {
            $wl = Get-PimDelegatedRowValue $Row @('Workload')
            if (-not $wl) { $den.Add("${label}: no Workload") | Out-Null }
            else {
                $svc = Resolve-PimServiceType -Workload $wl
                $lv = if ($storedFacets) { $storedFacets.level } else { $null }
                $tr = if ($svc -eq 'entra') { 0 } elseif ($storedFacets) { $storedFacets.tier } else { $null }
                $checks.Add(@{ service = $svc; workload = $wl; tier = $tr; level = $lv; plane = ''; scope = (Get-PimDelegatedRowValue $Row @('Scope')); au = ''; groupTag = $label; name = "$wl role '$(Get-PimDelegatedRowValue $Row @('RoleName'))'"; kind = 'indirect' }) | Out-Null
            }
        }
        'PIM-Assignments-Admins' {
            $who = Get-PimDelegatedRowValue $Row @('Username', 'UserName', 'UserPrincipalName')
            $names = @($who.ToLowerInvariant())
            if ($Ownership -and $Ownership.adminIndex -and $Ownership.adminIndex.ContainsKey($who.ToLowerInvariant())) { $names = @($Ownership.adminIndex[$who.ToLowerInvariant()]) }
            $ok = $false
            if ($who) { foreach ($n in $names) { if (Test-PimPortalCanAssignAdmin -Profile $Profile -AdminName $n) { $ok = $true; break } } }
            if (-not $ok) { $den.Add("${label}: '$who' is not an admin you manage") | Out-Null }
        }
    }
    foreach ($f in $checks) {
        if (-not (Test-PimDelegatedFacetsManageable -Profile $Profile -Facets $f)) {
            $den.Add(("{0}: {1} (service {2}, T{3}, L{4}{5}) is above your delegated ceiling" -f $label, $(if ($f.name) { $f.name } else { $f.groupTag }), $f.service, $f.tier, $f.level, $(if ($f.service -eq 'azure') { ", scope $($f.scope)" }))) | Out-Null
        }
    }
    return @($den)
}

# R25-04: what a delegated caller may set on an admin row. A MODIFY may only touch the descriptive columns, move the admin
# between departments (ownership of the after side decides which) and EXTEND AutoDisableDate under the owner-extend rules.
# Identity, mail routing, TAP issuing, account status and replication stay with a PIM administrator.
# An ADD (a new admin of their department) may carry the onboarding columns, but never mail redirection or replication,
# and its AutoDisableDate must be within the owner-extend window. (The two lists are literals in the function.)

function Test-PimDelegatedAdminWrite {
    <#
      PURE. R25-04 -- a delegated write to Account-Definitions-Admins, judged on the DIFF (never "the admin is in my
      department, so anything goes"): removes refused (Remove on My people raises an offboard approval instead); a modify
      only in the allow-list, AutoDisableDate only LATER, in the future and at most -MaxDays ahead (Test-PimOwnerExtendRequest);
      an add without the denied columns; and every group the admin is already in must sit inside the caller's ceiling.
      Returns @(denial texts) (empty = ok).
    #>
    param([AllowNull()][object]$Profile, [AllowNull()][object]$Diff, [hashtable]$Ownership, [int]$MaxDays = 0, [datetime]$NowUtc = [datetime]::UtcNow)
    # Literals, not $script: -- a $script: default read from a child scope can be $null, and a null deny-list fails OPEN.
    $modifyCols = @('FirstName', 'LastName', 'Initials', 'DisplayName', 'Purpose', 'UsageLocation', 'Company', 'Department', 'AutoDisableDate')
    $addDenied = @('ManagerEmail', 'ForwardMailsToContact', 'MailForwardAddress', 'AccountStatus', 'ManagementMode', 'Ring', 'Target', 'Replicate', 'OffboardDate')
    $den = New-Object System.Collections.Generic.List[string]
    if ($null -eq $Diff) { $den.Add('an admin write must be judged on its diff -- refusing (fail closed)') | Out-Null; return @($den) }
    $caps = @(@($Profile.capabilities) | ForEach-Object { "$_".ToLowerInvariant() })
    $name = { param($r) $n = Get-PimDelegatedRowValue $r @('UserName', 'UserPrincipalName'); if ($n) { $n } else { '(unnamed admin)' } }
    $memberships = {
        param($r)
        foreach ($k in @(@((Get-PimDelegatedRowValue $r @('UserName')), (Get-PimDelegatedRowValue $r @('UserPrincipalName'))) | Where-Object { $_ } | ForEach-Object { $_.ToLowerInvariant() })) {
            if ($Ownership -and $Ownership.adminGroups -and $Ownership.adminGroups.ContainsKey($k)) {
                foreach ($t in @($Ownership.adminGroups[$k])) {
                    foreach ($d in @(Test-PimDelegatedAssignmentCeiling -Profile $Profile -Row ([pscustomobject]@{ Username = $k; GroupTag = $t }) -Base 'PIM-Assignments-Admins' -Ownership $Ownership)) {
                        $den.Add("$(& $name $r) is in a group above your ceiling -- $d") | Out-Null
                    }
                }
            }
        }
    }
    foreach ($r in @($Diff.removes)) { if ($null -ne $r) { $den.Add("$(& $name $r): removing an admin is an offboard -- use Remove on My people (a PIM administrator approves it)") | Out-Null } }
    foreach ($m in @($Diff.modifies)) {
        if ($null -eq $m) { continue }
        $b = if ($m -is [System.Collections.IDictionary]) { $m['before'] } else { $m.before }
        $a = if ($m -is [System.Collections.IDictionary]) { $m['after'] } else { $m.after }
        $cols = @($(if ($m -is [System.Collections.IDictionary]) { $m['diffCols'] } else { $m.diffCols }) | Where-Object { "$_".Trim() })
        $who = & $name $b
        if (-not (Test-PimPortalCanManageAdmin -Profile $Profile -AdminName (Get-PimDelegatedRowValue $b @('UserName', 'UserPrincipalName')))) { $den.Add("${who}: not an admin whose account you manage") | Out-Null; continue }
        $bad = @($cols | Where-Object { $modifyCols -notcontains "$_" })
        if ($bad.Count) { $den.Add(("{0}: {1} may only be changed by a PIM administrator" -f $who, ($bad -join ', '))) | Out-Null }
        if ($cols -contains 'AutoDisableDate') {
            if (-not (Get-Command Test-PimOwnerExtendRequest -ErrorAction SilentlyContinue)) { $den.Add("${who}: the owner-extend rules are not loaded -- refusing (fail closed)") | Out-Null }
            else {
                $x = Test-PimOwnerExtendRequest -Row $b -NewDate (Get-PimDelegatedRowValue $a @('AutoDisableDate')) -MaxDays $MaxDays -NowUtc $NowUtc
                if (-not $x.ok) { $den.Add("${who}: AutoDisableDate -- $($x.reason)") | Out-Null }
            }
        }
        & $memberships $b
    }
    foreach ($r in @($Diff.adds)) {
        if ($null -eq $r) { continue }
        $who = & $name $r
        if ($caps -notcontains 'manage-account') { $den.Add("${who}: your profile may not create admin accounts (manage-account)") | Out-Null; continue }
        $bad = @(Get-PimDelegatedRowColumns $r | Where-Object { $addDenied -contains "$_" })
        if ($bad.Count) { $den.Add(("{0}: {1} may only be set by a PIM administrator" -f $who, ($bad -join ', '))) | Out-Null }
        $ad = Get-PimDelegatedRowValue $r @('AutoDisableDate')
        if (-not $ad) { $den.Add("${who}: a new admin needs an AutoDisableDate (at most $(if ($MaxDays -gt 0) { $MaxDays } else { 365 }) days ahead)") | Out-Null }
        elseif (Get-Command Test-PimOwnerExtendRequest -ErrorAction SilentlyContinue) {
            # the window rule without the "later than the current one" part: judged against a row that has no date yet
            $x = Test-PimOwnerExtendRequest -Row ([pscustomobject]@{ UserName = $who; AutoDisableDate = $NowUtc.ToUniversalTime().ToString('yyyy-MM-dd') }) -NewDate $ad -MaxDays $MaxDays -NowUtc $NowUtc
            if (-not $x.ok) { $den.Add("${who}: AutoDisableDate -- $($x.reason)") | Out-Null }
        } else { $den.Add("${who}: the owner-extend rules are not loaded -- refusing (fail closed)") | Out-Null }
        & $memberships $r
    }
    return @($den)
}

function Test-PimDelegatedWrite {
    <#
      PURE (given Test-PimPortalRowsInScope). The verdict for one entity write by a delegated caller: every affected row
      OWNED and inside the profile. Returns @{ allowed; reason; denied = @(names) }.
      -AllowedColumns (R25-03): the entity's columns. -WrittenColumns: the columns this write sets (every valued column of
      an add + the changed columns of a modify; default = every valued column of -Rows). One outside the entity is refused.
    #>
    param([AllowNull()][object]$Profile, [object[]]$Rows = @(), [string]$Base, [string]$Identity, [hashtable]$Ownership, [string[]]$AllowedColumns = @(),
          [AllowNull()][string[]]$WrittenColumns = $null, [AllowNull()][object]$Diff = $null, [int]$OwnerExtendMaxDays = 0, [datetime]$NowUtc = [datetime]::UtcNow)
    if ($null -eq $Profile) { return [pscustomobject]@{ allowed = $false; reason = 'you own no department and no group, so there is nothing you may change here'; denied = @() } }
    $notOwned = New-Object System.Collections.Generic.List[string]
    foreach ($r in @($Rows)) {
        if ($null -eq $r) { continue }
        if (-not (Test-PimDelegatedRowOwned -Row $r -Base $Base -Identity $Identity -Ownership $Ownership)) {
            $nm = Get-PimDelegatedRowValue $r @('GroupName', 'GroupTag', 'TargetGroupTag', 'UserName', 'Username', 'Department')
            $notOwned.Add($(if ($nm) { $nm } else { '(unnamed row)' })) | Out-Null
        }
    }
    if ($notOwned.Count) {
        return [pscustomobject]@{ allowed = $false; reason = ("{0} row(s) are not yours to change (you are not their owner, nor an owner of their department): {1}" -f $notOwned.Count, ((@($notOwned) | Select-Object -First 10) -join ', ')); denied = @($notOwned) }
    }
    # (after ownership: a row that is not theirs is refused as 'not yours' first -- the clearer answer)
    if (@($AllowedColumns).Count) {
        $allow = @{}; foreach ($c in $AllowedColumns) { $allow["$c".ToLowerInvariant()] = $true }
        # + the columns THIS model decides ownership by (a grid header may not show them, e.g. Department on Services);
        # what they may say is governed by the ownership check on the after side of every row.
        foreach ($c in @('Department', 'Owners', 'SponsorUpn')) { $allow[$c.ToLowerInvariant()] = $true }
        $cols = if ($null -ne $WrittenColumns) { @($WrittenColumns) } else { @(foreach ($r in @($Rows)) { Get-PimDelegatedRowColumns $r }) }
        $unknown = @(foreach ($c in $cols) { if ("$c".Trim() -and -not $allow.ContainsKey("$c".ToLowerInvariant())) { "$c" } }) | Sort-Object -Unique
        if (@($unknown).Count) { return [pscustomobject]@{ allowed = $false; reason = ("column(s) {0} are not part of {1} -- refused" -f (@($unknown) -join ', '), $Base); denied = @($unknown) } }
    }
    if ("$Base" -like 'Account-Definitions-Admins*') {
        # R25-04: ownership (their department) is necessary, never sufficient -- the diff decides (Test-PimDelegatedAdminWrite).
        $ad = @(Test-PimDelegatedAdminWrite -Profile $Profile -Diff $Diff -Ownership $Ownership -MaxDays $OwnerExtendMaxDays -NowUtc $NowUtc)
        if ($ad.Count) { return [pscustomobject]@{ allowed = $false; reason = ("{0} admin change(s) refused: {1}" -f $ad.Count, ((@($ad) | Select-Object -First 10) -join '; ')); denied = @($ad) } }
        return [pscustomobject]@{ allowed = $true; reason = 'admins of your departments, inside the owner rules'; denied = @() }
    }
    if (-not (Get-Command Get-PimGroupFacets -ErrorAction SilentlyContinue)) { return [pscustomobject]@{ allowed = $false; reason = 'the scope library is not loaded -- refusing (fail-closed)'; denied = @() } }
    if ("$Base" -notlike 'PIM-Definitions-*') {
        # R25-03: an ASSIGNMENT's ceiling comes from the stored groups and the role / scope it grants, not its columns.
        $den = New-Object System.Collections.Generic.List[string]
        foreach ($r in @($Rows)) { foreach ($d in @(Test-PimDelegatedAssignmentCeiling -Profile $Profile -Row $r -Base $Base -Ownership $Ownership)) { $den.Add($d) | Out-Null } }
        if ($den.Count) { return [pscustomobject]@{ allowed = $false; reason = ("{0} assignment check(s) failed: {1}" -f $den.Count, ((@($den) | Select-Object -First 10) -join '; ')); denied = @($den) } }
        return [pscustomobject]@{ allowed = $true; reason = 'owned and inside your delegated ceiling'; denied = @() }
    }
    # A DEFINITION row is checked on its columns AND on what its tag / name says (the columns cannot claim T1 L3 for a
    # group whose tag reads L0-T0).
    $gramRows = @(foreach ($r in @($Rows)) {
        if ($null -eq $r) { continue }
        $g = [ordered]@{ GroupTag = (Get-PimDelegatedRowValue $r @('GroupTag')); GroupName = (Get-PimDelegatedRowValue $r @('GroupName')) }
        $gf = Get-PimGroupFacets -Row $g -Base $Base
        if ($null -ne $gf.tier -or $null -ne $gf.level) {
            foreach ($k in @('PermissionScope', 'AzScope', 'Scope', 'AdministrativeUnitTag')) { $v = Get-PimDelegatedRowValue $r @($k); if ($v) { $g[$k] = $v } }
            [pscustomobject]$g
        }
    })
    $outside = New-Object System.Collections.Generic.List[string]
    foreach ($r in @(@($Rows) + @($gramRows))) {
        if ($null -eq $r) { continue }
        $f = Get-PimGroupFacets -Row $r -Base $Base
        if (-not (Test-PimDelegatedFacetsManageable -Profile $Profile -Facets $f)) { $outside.Add($(if ("$($f.name)".Trim()) { "$($f.name)" } elseif ("$($f.groupTag)".Trim()) { "$($f.groupTag)" } else { '(unnamed row)' })) | Out-Null }
    }
    if ($outside.Count) {
        $u = @($outside | Select-Object -Unique)
        return [pscustomobject]@{ allowed = $false; reason = ("{0} affected row(s) are outside your delegated scope (tier/level/service/scope) and cannot be created, changed, or removed by you: {1}" -f $u.Count, ((@($u) | Select-Object -First 10) -join ', ')); denied = @($u) }
    }
    return [pscustomobject]@{ allowed = $true; reason = 'owned and inside your delegated ceiling'; denied = @() }
}
