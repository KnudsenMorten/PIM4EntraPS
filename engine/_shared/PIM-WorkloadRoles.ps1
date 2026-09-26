<#
  PIM4EntraPS -- WORKLOAD ROLES: the group + its workload role as ONE unit (REQ-U wave 2, 2026-09-19).

  Operator: "otherwise we will end with orphaned permission groups that are not connected with the actual workload" /
  "you must have a warning if that is the case, can be checked against api" / "we need to include this role in the
  template for defender xdr. maybe you can verify the automatic discovery of defender xdr api works".

  What lives here (loaded by PIM-EngineProviders.ps1 next to PIM-WorkloadConnectors.ps1, so the engine, the
  scheduler tick and every host that loads the providers has it):

    [1] Defender XDR ROLE SPEC (design point 3) -- a Defender binding row may carry `Permissions` (the role's
        allowedResourceActions, ';'-separated) and `DataSources` (the assignment's appScopeIds, ';'-separated,
        blank = '/'). With a spec, the DefenderXdrRoles provider OWNS the custom role named like the group: it
        creates it (POST) when missing, PATCHes its actions when they differ, and assigns it with the spec's data
        sources. Without a spec a row binds an EXISTING role by name, exactly as before. A spec row in
        PIM-Assignments-Workloads is therefore served by DefenderXdrRoles, not by the generic connector dispatcher.
        A role NAME that two live roles share is ambiguous and is refused, never resolved to one of them.
    [2] REQ-W (2.4.380) the ASSIGNMENT HOLD -- a workload group is ALWAYS created (the wave-2 group create hold is
        gone); a NEW workload role assignment waits while its workload's prerequisites are not green
        (Get-PimWorkloadAssignmentHold, pim.Settings 'WorkloadPrereqs' read once per run).
    [3] LIVE ORPHAN WARNINGS (design point 8) -- from the providers' own live reads: a PIM workload group holding NO
        live workload role; a live workload role held by a principal PIM does not define; for Defender a role whose
        live actions / data sources differ from its spec ("wrong permissions").
    [4] WORKLOAD ROLE DISCOVERY (design point 6) -- the 'discovery-defender' / 'discovery-intune' jobs read the live
        role catalog, store pim.TenantCache kind 'workload-roles:<service>' as
          { read:bool, reason, readUtc, roles:[{ name, id, isBuiltIn, actions? }] }
        (the Coverage page reads exactly that), and report roles no pack knows plus -- for Defender -- action
        namespaces no pack knows. A catalog that could NOT be read is stored as read=false and FAILS the job.

  PURE unless the name or the comment says otherwise. Runs on pwsh 7 and Windows PowerShell 5.1.
#>
Set-StrictMode -Off

# The token a pack binding row carries instead of a literal role name: "the custom role named like this group".
$script:PimWorkloadGroupNameToken = '{GroupName}'

function Get-PimWlRoleField {
    # First NON-BLANK value among -Names (trimmed), '' when none. Dictionary or object.
    param([AllowNull()][object]$Row, [string[]]$Names)
    if ($null -eq $Row) { return '' }
    foreach ($n in $Names) {
        if ($Row -is [System.Collections.IDictionary]) { if ($Row.Contains($n) -and "$($Row[$n])".Trim()) { return "$($Row[$n])".Trim() } }
        else { $p = $Row.PSObject.Properties[$n]; if ($p -and "$($p.Value)".Trim()) { return "$($p.Value)".Trim() } }
    }
    return ''
}

function Get-PimWlBindingKind {
    # A Workload value -> 'intune' | 'defender' | a connector id | ''. Delegates to the one mapping
    # (ConvertTo-PimWorkloadBindingKind, PIM-WorkloadConnectors.ps1) when it is loaded.
    param([AllowNull()][string]$Workload)
    if (Get-Command ConvertTo-PimWorkloadBindingKind -ErrorAction SilentlyContinue) { return (ConvertTo-PimWorkloadBindingKind -Workload $Workload) }
    $w = ("$Workload".Trim().ToLowerInvariant()) -replace '[^a-z0-9]', ''
    if ($w -in @('intune', 'microsoftintune', 'endpointmanager', 'mem', 'intunerbac')) { return 'intune' }
    if ($w -in @('defender', 'defenderxdr', 'microsoftdefender', 'microsoftdefenderxdr', 'm365defender', 'microsoft365defender', 'mde', 'defenderforendpoint')) { return 'defender' }
    return ''
}

# ===========================================================================
# [1] Defender XDR role spec -- PURE helpers
# ===========================================================================
function Split-PimWorkloadRoleList {
    # PURE. 'a; b,c|d' -> @('a','b','c','d'): trimmed, blanks dropped, de-duplicated case-insensitively (first
    # spelling kept, order kept).
    param([AllowNull()][string]$Raw)
    $out = New-Object System.Collections.Generic.List[string]
    $seen = New-Object System.Collections.Generic.HashSet[string] ([StringComparer]::OrdinalIgnoreCase)
    foreach ($s in @("$Raw" -split '[;,|\r\n]+')) {
        $t = "$s".Trim()
        if ($t -and $seen.Add($t)) { $out.Add($t) }
    }
    return @($out.ToArray())
}

function ConvertTo-PimDefenderDataSourceList {
    # PURE. The assignment's appScopeIds from a DataSources cell: blank = '/' (all and future data sources).
    param([AllowNull()][string]$Raw)
    $l = @(Split-PimWorkloadRoleList -Raw $Raw)
    if (-not $l.Count) { return @('/') }
    return $l
}

function Test-PimWorkloadStringSetEqual {
    # PURE. Same members, ignoring order, case and duplicates.
    param([AllowNull()][object[]]$A, [AllowNull()][object[]]$B)
    $sa = New-Object System.Collections.Generic.HashSet[string] ([StringComparer]::OrdinalIgnoreCase)
    $sb = New-Object System.Collections.Generic.HashSet[string] ([StringComparer]::OrdinalIgnoreCase)
    foreach ($x in @($A)) { if ("$x".Trim()) { [void]$sa.Add("$x".Trim()) } }
    foreach ($x in @($B)) { if ("$x".Trim()) { [void]$sb.Add("$x".Trim()) } }
    return $sa.SetEquals($sb)
}

function Get-PimDefenderRoleSpec {
    # PURE. A binding row's role spec, or $null when it carries no Permissions (= "bind an existing role by name").
    #   { actions = @(allowedResourceActions); dataSources = @(appScopeIds, '/' when blank) }
    param([AllowNull()][object]$Row)
    $perm = Get-PimWlRoleField -Row $Row -Names @('Permissions', 'AllowedResourceActions')
    if (-not $perm) { return $null }
    $acts = @(Split-PimWorkloadRoleList -Raw $perm)
    if (-not $acts.Count) { return $null }
    return [pscustomobject]@{ actions = $acts; dataSources = @(ConvertTo-PimDefenderDataSourceList -Raw (Get-PimWlRoleField -Row $Row -Names @('DataSources', 'AppScopeIds'))) }
}

function Test-PimDefenderSpecBindingRow {
    # PURE. Is this a PIM-Assignments-Workloads row the DefenderXdrRoles provider owns? A Defender workload, a
    # Permissions spec, and an Assign action (blank = Assign). A Remove row stays with the connector dispatcher
    # (its targeted removal); a row without Permissions keeps binding an existing role through the connector.
    param([AllowNull()][object]$Row)
    if ($null -eq $Row) { return $false }
    if ((Get-PimWlBindingKind -Workload (Get-PimWlRoleField -Row $Row -Names @('Workload'))) -ne 'defender') { return $false }
    if (-not (Get-PimWlRoleField -Row $Row -Names @('Permissions', 'AllowedResourceActions'))) { return $false }
    $act = Get-PimWlRoleField -Row $Row -Names @('Action')
    return (-not $act -or $act -ieq 'Assign')
}

function Resolve-PimWorkloadBindingRoleName {
    # PURE-ish. The role a binding row names. '{GroupName}' (or a blank role on a spec row) = the custom role named
    # EXACTLY like the row's group: the definition's GroupName for the tag (-TagToName), else the tag under the
    # tenant's own naming pattern (Resolve-PimGroupNameFromTag) -- never a generic 'PIM-' + tag.
    param([AllowNull()][object]$Row, [hashtable]$TagToName = @{})
    $rn = Get-PimWlRoleField -Row $Row -Names @('RoleDefinitionName', 'RoleName')
    if ($rn -and $rn -ne $script:PimWorkloadGroupNameToken) {
        if ($rn.IndexOf($script:PimWorkloadGroupNameToken, [System.StringComparison]::OrdinalIgnoreCase) -lt 0) { return $rn }
    }
    $gt = Get-PimWlRoleField -Row $Row -Names @('GroupTag')
    if (-not $gt) { return $rn }
    $gn = ''
    if ($TagToName -and $TagToName.ContainsKey($gt.ToLowerInvariant())) { $gn = "$($TagToName[$gt.ToLowerInvariant()])".Trim() }
    if (-not $gn -and (Get-Command Resolve-PimGroupNameFromTag -ErrorAction SilentlyContinue)) { $gn = "$(Resolve-PimGroupNameFromTag -Tag $gt)".Trim() }
    if (-not $gn) { $gn = $gt }
    if ($rn -and $rn -ne $script:PimWorkloadGroupNameToken) { return ($rn -replace [regex]::Escape($script:PimWorkloadGroupNameToken), $gn) }
    return $gn
}

function ConvertTo-PimDefenderDesiredBinding {
    # PURE-ish. One desired Defender binding from a PIM-Assignments-Defender row or a PIM-Assignments-Workloads spec
    # row -- a NEW object (the store's row is never mutated), carrying the resolved role name, the spec and the
    # group's name (so a drift / failure label reads "group X -> Defender XDR role 'Y'").
    param([Parameter(Mandatory)][object]$Row, [hashtable]$TagToName = @{}, [string]$SourceEntity = 'PIM-Assignments-Defender')
    $gt = Get-PimWlRoleField -Row $Row -Names @('GroupTag')
    $gn = ''
    if ($gt -and $TagToName -and $TagToName.ContainsKey($gt.ToLowerInvariant())) { $gn = "$($TagToName[$gt.ToLowerInvariant()])" }
    return [pscustomobject]@{
        GroupTag           = $gt
        GroupName          = $gn
        RoleDefinitionName = (Resolve-PimWorkloadBindingRoleName -Row $Row -TagToName $TagToName)
        Workload           = 'Defender XDR'
        Permissions        = (Get-PimWlRoleField -Row $Row -Names @('Permissions', 'AllowedResourceActions'))
        DataSources        = (Get-PimWlRoleField -Row $Row -Names @('DataSources', 'AppScopeIds'))
        AssignmentName     = (Get-PimWlRoleField -Row $Row -Names @('AssignmentName'))
        Action             = 'Assign'
        SourceEntity       = $SourceEntity
    }
}

function Get-PimDefenderDesiredBindings {
    # The DefenderXdrRoles desired set: every PIM-Assignments-Defender row (Action != Remove, a group, a role -- or a
    # spec, which names its own role) plus every PIM-Assignments-Workloads SPEC row (Test-PimDefenderSpecBindingRow).
    param([hashtable]$TagToName = @{})
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($r in @(Get-PimDesiredRows -Entity 'PIM-Assignments-Defender')) {
        if ($null -eq $r) { continue }
        if ((Get-PimWlRoleField -Row $r -Names @('Action')) -ieq 'Remove') { continue }
        if (-not (Get-PimWlRoleField -Row $r -Names @('GroupTag'))) { continue }
        $hasRole = [bool](Get-PimWlRoleField -Row $r -Names @('RoleDefinitionName', 'RoleName'))
        if (-not $hasRole -and -not (Get-PimDefenderRoleSpec -Row $r)) { continue }
        $out.Add((ConvertTo-PimDefenderDesiredBinding -Row $r -TagToName $TagToName -SourceEntity 'PIM-Assignments-Defender'))
    }
    foreach ($r in @(Get-PimDesiredRows -Entity 'PIM-Assignments-Workloads')) {
        if (-not (Test-PimDefenderSpecBindingRow -Row $r)) { continue }
        if (-not (Get-PimWlRoleField -Row $r -Names @('GroupTag'))) { continue }
        $out.Add((ConvertTo-PimDefenderDesiredBinding -Row $r -TagToName $TagToName -SourceEntity 'PIM-Assignments-Workloads'))
    }
    return @($out.ToArray())
}

function Get-PimWorkloadConnectorDesiredRows {
    # The PIM-Assignments-Workloads rows the generic connector dispatcher (WorkloadConnectors) serves: all of them
    # EXCEPT the Defender spec rows, which DefenderXdrRoles owns (it creates the custom role the connector cannot).
    # REQ-Y (2026-09-19): and a Pro connector's rows (app-role, Azure DevOps, Dataverse, Business Central, Power
    # Platform, Power BI) only with a Pro licence -- Select-PimWorkloadRowsLicensed (PIM-FeatureCatalog.ps1) holds the
    # rest, both ways, with a scope warning. Intune / Defender XDR / Azure RBAC / Entra roles are free.
    param([object]$Warnings)
    $rows = @(Get-PimDesiredRows -Entity 'PIM-Assignments-Workloads' | Where-Object { -not (Test-PimDefenderSpecBindingRow -Row $_) })
    if (Get-Command Select-PimWorkloadRowsLicensed -ErrorAction SilentlyContinue) { $rows = @(Select-PimWorkloadRowsLicensed -Rows $rows -Warnings $Warnings) }
    return $rows
}

function Get-PimWorkloadRoleBindingKey {
    # PURE. Desired and live Defender / Intune rows share ONE key: 'tag:<GroupTag>|<role>' (lower-case). A live row
    # is stamped with the GroupTag(s) of its group, so desired meets live. (The old keys put the group id on the
    # live side and the tag on the desired side, so a bound role never matched: every run planned a CREATE.)
    # A row with no GroupTag falls back to '<principalId>|<role>'.
    param([AllowNull()][object]$Row)
    $role = Get-PimWlRoleField -Row $Row -Names @('RoleDefinitionName', 'RoleName', 'RoleDefinitionId', 'roleDefinitionId')
    $gt = Get-PimWlRoleField -Row $Row -Names @('GroupTag')
    if ($gt) { return ("tag:$gt|$role").ToLowerInvariant() }
    $gid = Get-PimWlRoleField -Row $Row -Names @('principalId')
    return ("$gid|$role").ToLowerInvariant()
}

function Test-PimDefenderActionCovers {
    # PURE. Does Defender action $By already grant $Action? '<ns>/<path...>/<verb>'. A '*' path segment matches ONE OR
    # MORE segments; the verb must match, or $By's verb is 'manage' (manage includes read) or '*'.
    param([string]$By, [string]$Action)
    $b = "$By".Trim().ToLowerInvariant(); $a = "$Action".Trim().ToLowerInvariant()
    if (-not $b -or -not $a -or $b -eq $a) { return $false }
    $bs = $b -split '/'; $as = $a -split '/'
    if ($bs.Count -lt 2 -or $as.Count -lt 2) { return $false }
    $bv = $bs[-1]; $av = $as[-1]
    if (-not ($bv -eq $av -or $bv -eq '*' -or ($bv -eq 'manage' -and $av -eq 'read'))) { return $false }
    $bp = @($bs[0..($bs.Count - 2)]) | ForEach-Object { if ($_ -eq '*') { '[^/]+(?:/[^/]+)*' } else { [regex]::Escape($_) } }
    $ap = ($as[0..($as.Count - 2)]) -join '/'
    return ($ap -match ('^' + ($bp -join '/') + '$'))
}

function Get-PimDefenderEffectiveActions {
    # PURE. The spec's actions as Defender STORES them: an action another spec action already grants is dropped.
    # 2026-09-21 (operator: "bug: looks wrong" -- four "wrong permissions" warnings + "changed" every run): the pack lists
    # 'microsoft.xdr/secops/*/manage;microsoft.xdr/secops/rawdata/quarantineemailcontent/read'; Defender keeps only the
    # wildcard (it covers the read), so live never equalled the spec and the engine re-planned an UPDATE forever.
    param([AllowNull()][object[]]$Actions)
    $all = @($Actions | Where-Object { "$_".Trim() } | ForEach-Object { "$_".Trim() })
    return @($all | Where-Object { $x = $_; -not @($all | Where-Object { Test-PimDefenderActionCovers -By $_ -Action $x }).Count })
}

function Get-PimDefenderSpecDifference {
    # PURE. How a live Defender binding differs from its spec: '' when it matches (or the row has no spec).
    #   -Desired: a desired binding (Permissions / DataSources); -LiveActions: the role's live allowedResourceActions;
    #   -LiveDataSources: the assignment's live appScopeIds ($null = no assignment to compare).
    param([AllowNull()][object]$Desired, [AllowNull()][object[]]$LiveActions, [AllowNull()][object[]]$LiveDataSources)
    $spec = Get-PimDefenderRoleSpec -Row $Desired
    if (-not $spec) { return '' }
    $parts = New-Object System.Collections.Generic.List[string]
    if (-not (Test-PimWorkloadStringSetEqual -A @(Get-PimDefenderEffectiveActions -Actions @($LiveActions)) -B @(Get-PimDefenderEffectiveActions -Actions @($spec.actions)))) {
        $parts.Add(("actions: live [{0}], spec [{1}]" -f (@($LiveActions) -join '; '), (@($spec.actions) -join '; ')))
    }
    if ($null -ne $LiveDataSources -and -not (Test-PimWorkloadStringSetEqual -A @($LiveDataSources) -B @($spec.dataSources))) {
        $parts.Add(("data sources: live [{0}], spec [{1}]" -f (@($LiveDataSources) -join '; '), (@($spec.dataSources) -join '; ')))
    }
    return ($parts.ToArray() -join '; ')
}

function Test-PimDefenderBindingEqual {
    # PURE. The DefenderXdrRoles Equal: a row WITHOUT a spec is existence-based (as before); a row WITH one also
    # compares the role's actions AND the assignment's data sources -- a difference is an UPDATE.
    param([AllowNull()][object]$Desired, [AllowNull()][object]$Live)
    if (-not (Get-PimDefenderRoleSpec -Row $Desired)) { return $true }
    $la = @(); $ld = @()
    if ($null -ne $Live) {
        $p = $Live.PSObject.Properties['roleActions']; if ($p) { $la = @($p.Value) }
        $q = $Live.PSObject.Properties['appScopeIds']; if ($q) { $ld = @($q.Value) }
    }
    return (-not (Get-PimDefenderSpecDifference -Desired $Desired -LiveActions $la -LiveDataSources $ld))
}

# ===========================================================================
# [1] Defender XDR role catalog + assignments -- LIVE reads (Graph BETA)
# ===========================================================================
function Get-PimDefenderRoleCatalog {
    <#
      The live Defender XDR role definitions, ONE read per run (cached; a FAILED read is never cached):
        { ok; error; roles=@({ id; name; isBuiltIn; actions }); byName=@{ lower name -> @(roles) }; byId=@{ lower id -> role } }
      Graph BETA /roleManagement/defender/roleDefinitions (v1.0 answers 400). byName keeps EVERY role of a name, so
      two roles sharing a display name are visible as ambiguous instead of one silently shadowing the other
      (internal carries two "Microsoft Defender for Identity Administrator").
    #>
    [CmdletBinding()] param([switch]$Force)
    if (-not $Force -and $script:PimDefenderRoleCatalog) { return $script:PimDefenderRoleCatalog }
    $roles = New-Object System.Collections.Generic.List[object]
    try {
        foreach ($r in @(Invoke-PimGraph -Beta -All -Path '/roleManagement/defender/roleDefinitions')) {
            if ($null -eq $r) { continue }
            $id = "$($r.id)"; $n = "$($r.displayName)"
            if (-not $id -and -not $n) { continue }
            $acts = New-Object System.Collections.Generic.List[string]
            foreach ($rp in @($r.rolePermissions)) { foreach ($a in @($rp.allowedResourceActions)) { if ("$a".Trim()) { $acts.Add("$a".Trim()) } } }
            $bi = $false; if ($r.PSObject.Properties['isBuiltIn'] -and $null -ne $r.isBuiltIn) { $bi = [bool]$r.isBuiltIn }
            $roles.Add([pscustomobject]@{ id = $id; name = $n; isBuiltIn = $bi; actions = @($acts.ToArray()); description = "$($r.description)" })
        }
    } catch {
        $msg = "$($_.Exception.Message)"
        return [pscustomobject]@{ ok = $false; error = $msg; roles = @(); byName = @{}; byId = @{} }
    }
    $cat = New-PimDefenderRoleCatalogObject -Roles @($roles.ToArray())
    $script:PimDefenderRoleCatalog = $cat
    return $cat
}

function New-PimDefenderRoleCatalogObject {
    # PURE. Index a role list (see Get-PimDefenderRoleCatalog).
    # byName values are plain ARRAYS: pwsh 7 throws "Argument types do not match" on @() over a List[object] read back
    # out of a hashtable.
    param([object[]]$Roles = @())
    $byName = @{}; $byId = @{}
    foreach ($r in @($Roles)) {
        if ($null -eq $r) { continue }
        $k = "$($r.name)".ToLowerInvariant()
        if ($k) { if ($byName.ContainsKey($k)) { $byName[$k] = [object[]]($byName[$k] + @($r)) } else { $byName[$k] = [object[]]@($r) } }
        if ("$($r.id)") { $byId["$($r.id)".ToLowerInvariant()] = $r }
    }
    return [pscustomobject]@{ ok = $true; error = ''; roles = @($Roles); byName = $byName; byId = $byId }
}

function Add-PimDefenderRoleToCatalog {
    # Keep the run's cached catalog honest after the provider CREATED a role (a second binding to it in the same run
    # must find it, not create it again).
    param([Parameter(Mandatory)][object]$Role)
    $cat = $script:PimDefenderRoleCatalog
    if (-not $cat) { return }
    $k = "$($Role.name)".ToLowerInvariant()
    if ($k) { if ($cat.byName.ContainsKey($k)) { $cat.byName[$k] = [object[]]($cat.byName[$k] + @($Role)) } else { $cat.byName[$k] = [object[]]@($Role) } }
    if ("$($Role.id)") { $cat.byId["$($Role.id)".ToLowerInvariant()] = $Role }
    $cat.roles = @(@($cat.roles) + $Role)
}

function Get-PimDefenderAmbiguousRoleNames {
    # PURE over a catalog. lower name -> @(ids) for every name two or more live roles share.
    param([AllowNull()][object]$Catalog)
    $h = @{}
    if (-not $Catalog -or -not $Catalog.byName) { return $h }
    foreach ($k in @($Catalog.byName.Keys)) { $l = @($Catalog.byName[$k]); if ($l.Count -gt 1) { $h[$k] = @($l | ForEach-Object { "$($_.id)" }) } }
    return $h
}

function Get-PimDefenderLiveAssignments {
    # LIVE. Every Defender XDR role assignment: { ok; error; items=@({ id; displayName; roleDefinitionId; principals; appScopeIds }) }.
    $items = New-Object System.Collections.Generic.List[object]
    try {
        foreach ($a in @(Invoke-PimGraph -Beta -All -Path '/roleManagement/defender/roleAssignments')) {
            if ($null -eq $a) { continue }
            $items.Add([pscustomobject]@{
                id = "$($a.id)"; displayName = "$($a.displayName)"; roleDefinitionId = "$($a.roleDefinitionId)"
                principals = @(@($a.principalIds) | ForEach-Object { "$_" } | Where-Object { $_ })
                appScopeIds = @(@($a.appScopeIds) | ForEach-Object { "$_" } | Where-Object { $_ })
            })
        }
    } catch { return [pscustomobject]@{ ok = $false; error = "$($_.Exception.Message)"; items = @() } }
    return [pscustomobject]@{ ok = $true; error = ''; items = @($items.ToArray()) }
}

function Get-PimDefenderRoleWriteErrorText {
    <#
      PURE. The error a failed role create / PATCH is reported with. Measured on internal (2026-09-19, lead): a role
      carrying microsoft.xdr/dataops/*/read is REFUSED with "... not a valid permission for storage" because its
      prerequisite (a Microsoft Sentinel workspace onboarded to Defender XDR / the Sentinel data lake) is missing. That
      400 alone tells an operator nothing, so it becomes DEFENDER-PERMISSION-PREREQUISITE naming the prerequisite and the
      prerequisite script. Any other error is passed through with the role named.
    #>
    param([string]$Name, [string[]]$Actions = @(), [string]$Message, [string]$Verb = 'create')
    if ("$Message" -match '(?i)not a valid permission for storage|valid permission.{0,40}storage') {
        $dataOps = @(@($Actions) | Where-Object { "$_" -match '(?i)^microsoft\.xdr/dataops/' })
        $what = if ($dataOps.Count) { "the Data Operations permission(s) [$($dataOps -join '; ')] need a Microsoft Sentinel workspace onboarded to Defender XDR (the Sentinel data lake)" } else { "a permission in [$(@($Actions) -join '; ')] needs a prerequisite that is not in place" }
        return ("DEFENDER-PERMISSION-PREREQUISITE: Defender XDR refused to {0} the custom role '{1}' -- {2}. Run tools\setup\Initialize-PimWorkloadPrereqs.ps1 -Workload DefenderXdr to check and fix the prerequisite; the next run creates the role and its assignment. (Graph: {3})" -f $Verb, $Name, $what, "$Message".Trim())
    }
    return ("DefenderXdrRoles: could not {0} the custom role '{1}' with [{2}]: {3}" -f $Verb, $Name, (@($Actions) -join '; '), "$Message".Trim())
}

function New-PimDefenderAssignmentBody {
    <#
      PURE. The POST body of /beta/roleManagement/defender/roleAssignments (a unifiedRoleAssignmentMultiple).
      🔴 NO '@odata.type'. PROVEN LIVE 2026-09-19 ~20:40Z on internal (operator-approved probe, one group): the SAME body
      WITH "@odata.type": "#microsoft.graph.unifiedRoleAssignmentMultiple" -> 400 "The input was not valid.
      roleAssignment: The roleAssignment field is required." (every Defender create on RIDE / EFIF / internal, 2.4.379 and
      2.4.380); WITHOUT it -> the assignment is created (then the insecure redirect, see
      Invoke-PimDefenderAssignmentCreate). The Graph beta example carries the annotation; the service refuses it.
      The shipped connector body (workloads\connectors\defender-xdr.connector.json 'assign') never had one.
      directoryScopeIds ['/'] as every portal-made assignment carries (read on internal, 16 of 16); the data sources
      (Mde, Mdo, Mdi, Mdc, ...) in appScopeIds. Blank data sources = '/'.
    #>
    param([Parameter(Mandatory)][string]$DisplayName, [Parameter(Mandatory)][string]$RoleDefinitionId, [Parameter(Mandatory)][string]$PrincipalId, [string[]]$AppScopeIds = @())
    $apps = @($AppScopeIds | Where-Object { "$_".Trim() } | ForEach-Object { "$_".Trim() })
    if (-not $apps.Count) { $apps = @('/') }
    return @{
        displayName       = $DisplayName
        roleDefinitionId  = "$RoleDefinitionId"
        principalIds      = @("$PrincipalId")
        directoryScopeIds = @('/')
        appScopeIds       = @($apps)
    }
}

function Invoke-PimDefenderAssignmentCreate {
    <#
      WRITES. POST one Defender XDR role assignment (the body from New-PimDefenderAssignmentBody) and return it.
      🔴 LIVE 2026-09-19 (internal): like the role POST, Graph answers a SUCCESSFUL assignment POST with a redirect to an
      http:// location, which pwsh 7 refuses to follow ("Cannot follow an insecure redirection") -- the assignment IS
      created (read back: the group held it, dir '/', app '/'). So the insecure hop is never followed: the assignment is
      READ BACK by group + role, and only a read-back that finds nothing is a failure.
    #>
    param([Parameter(Mandatory)][hashtable]$Body)
    $redirected = $false; $res = $null
    try { $res = Invoke-PimGraph -Beta -Method POST -Path '/roleManagement/defender/roleAssignments' -Body $Body }
    catch {
        $m = "$($_.Exception.Message)$(if ($_.ErrorDetails) { ' ' + $_.ErrorDetails.Message })"
        if ($m -match '(?i)insecure redirection') { $redirected = $true } else { throw }
    }
    if (-not $redirected) { return $res }
    $gid = "$(@($Body.principalIds)[0])"; $rid = "$($Body.roleDefinitionId)"
    for ($i = 0; $i -lt 4; $i++) {
        if ($i) { Start-Sleep -Seconds 3 }
        $hit = $null
        try {
            $hit = @(Invoke-PimGraph -Beta -All -Path '/roleManagement/defender/roleAssignments') |
                Where-Object { "$($_.roleDefinitionId)" -ieq $rid -and (@($_.principalIds) | Where-Object { "$_" -ieq $gid }) } | Select-Object -First 1
        } catch { $hit = $null }
        if ($hit) { return $hit }
    }
    throw "DefenderXdrRoles: the assignment of role $rid to group $gid was answered with a redirect Graph does not allow to follow, and it could not be read back -- the next run retries"
}

function Find-PimDefenderRoleIdByName {
    # Re-read the live Defender role definitions and return the id of the ONE role named -Name ('' when none / several).
    param([Parameter(Mandatory)][string]$Name)
    $all = @(Invoke-PimGraph -Beta -All -Path '/roleManagement/defender/roleDefinitions')
    $hits = @($all | Where-Object { "$($_.displayName)" -ieq $Name })
    if ($hits.Count -eq 1) { return "$($hits[0].id)" }
    return ''
}

if (-not (Get-Command Get-PimUtcStamp -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot 'PIM-DateSafe.ps1') }   # IMP-02 reader (the create-pending marker)
$script:PimDefenderManagedRoleDescription = 'Managed by PIM4EntraPS: the custom Defender XDR role of the permission group of the same name.'

function Get-PimDefenderDuplicateRolePlan {
    <#
      PURE. Two or more live roles share a name. They are healed ONLY when every one is PIM's OWN custom role (not built-in,
      PIM's description) and at most ONE carries an assignment: keep that one (or the first when none is assigned), delete
      the rest. Anything else returns $null and stays DEFENDER-ROLE-AMBIGUOUS -- PIM never deletes a role it did not make or
      one somebody assigned.
      Measured 2026-09-26 on RIDE: 2x 'PIM-Defender-XDR-DataOperations-Operator-L3-T1-MP-ID' and 2x '...-Reader-L4-T1-MP-ID',
      mailed as a drift warning every 4 hours -- the create was redirected, not read back in time, and POSTed again.
    #>
    param([Parameter(Mandatory)][object[]]$Hits, [AllowEmptyCollection()][string[]]$AssignedRoleIds = @())
    $hs = @($Hits | Where-Object { $_ })
    if ($hs.Count -lt 2) { return $null }
    foreach ($h in $hs) {
        if ($h.isBuiltIn) { return $null }
        if ("$($h.description)".Trim() -ne $script:PimDefenderManagedRoleDescription) { return $null }
    }
    $asg = @{}; foreach ($a in @($AssignedRoleIds)) { if ("$a".Trim()) { $asg["$a".Trim().ToLowerInvariant()] = $true } }
    $assigned = @($hs | Where-Object { $asg.ContainsKey("$($_.id)".ToLowerInvariant()) })
    if ($assigned.Count -gt 1) { return $null }
    $keep = if ($assigned.Count -eq 1) { $assigned[0] } else { $hs[0] }
    return [pscustomobject]@{ keep = "$($keep.id)"; delete = @($hs | Where-Object { "$($_.id)" -ne "$($keep.id)" } | ForEach-Object { "$($_.id)" }) }
}

function Get-PimDefenderCreatePending {
    # The names whose create was ANSWERED (redirect) but not yet listed, with when: pim.Settings['DefenderRoleCreatePending'].
    $h = @{}
    try { $raw = Get-PimSetting -Name 'DefenderRoleCreatePending'; if ($raw) { $o = if ($raw -is [string]) { $raw | ConvertFrom-Json } else { $raw }; foreach ($p in $o.PSObject.Properties) { $h[$p.Name] = $p.Value } } } catch { }   # the RAW value: pwsh 7 made a [datetime] of the ISO text, and "$dt" loses its UTC kind
    return $h
}
function Set-PimDefenderCreatePending {
    param([Parameter(Mandatory)][string]$Name, [switch]$Clear)
    try {
        $h = Get-PimDefenderCreatePending; $k = $Name.ToLowerInvariant()
        if ($Clear) { if (-not $h.ContainsKey($k)) { return }; $h.Remove($k) } else { $h[$k] = [datetime]::UtcNow.ToString('o') }
        foreach ($kk in @($h.Keys)) { if ($h[$kk] -is [datetime]) { $h[$kk] = ([datetime]$h[$kk]).ToUniversalTime().ToString('o') } }
        Set-PimSetting -Name 'DefenderRoleCreatePending' -Value ([pscustomobject]$h | ConvertTo-Json -Compress)
    } catch { Write-Warning "DefenderXdrRoles: the create-pending marker for '$Name' could not be saved ($($_.Exception.Message)) -- a slow create may be posted again" }
}

function Resolve-PimDefenderSpecRole {
    <#
      WRITES. The custom role a spec binding needs, made to match the spec: POST it when no live role has the name,
      PATCH its rolePermissions when the actions differ, nothing when it matches. Returns the role id.
      🔒 A name two live roles share is REFUSED (DEFENDER-ROLE-AMBIGUOUS) -- PIM never guesses which one is meant.
    #>
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][string[]]$Actions, [AllowNull()][object]$Catalog)
    $cat = if ($Catalog) { $Catalog } else { Get-PimDefenderRoleCatalog }
    if (-not $cat.ok) { throw "DefenderXdrRoles: the Defender XDR role catalog could not be read -- the role '$Name' was not created or checked: $($cat.error)" }
    $hits = @(); if ($cat.byName.ContainsKey($Name.ToLowerInvariant())) { $hits = @($cat.byName[$Name.ToLowerInvariant()]) }
    if ($hits.Count -gt 1) {
        # SELF-HEAL (2026-09-26): duplicates PIM itself made (see Get-PimDefenderDuplicateRolePlan) are reduced to one.
        $assignedIds = @()
        try { $assignedIds = @(@(Invoke-PimGraph -Beta -All -Path '/roleManagement/defender/roleAssignments') | ForEach-Object { "$($_.roleDefinitionId)" }) } catch { $assignedIds = $null }
        $plan = if ($null -ne $assignedIds) { Get-PimDefenderDuplicateRolePlan -Hits $hits -AssignedRoleIds $assignedIds } else { $null }
        if ($plan) {
            foreach ($did in @($plan.delete)) {
                Invoke-PimGraph -Beta -Method DELETE -Path "/roleManagement/defender/roleDefinitions/$did" | Out-Null
                Write-Host ("    [-] Defender XDR role '{0}': deleted the duplicate {1} PIM created (kept {2})" -f $Name, $did, $plan.keep) -ForegroundColor Yellow
            }
            $hits = @($hits | Where-Object { "$($_.id)" -eq $plan.keep })
            $cat.byName[$Name.ToLowerInvariant()] = @($hits)
        }
    }
    if ($hits.Count -gt 1) {
        throw ("DEFENDER-ROLE-AMBIGUOUS: {0} live Defender XDR roles are named '{1}' (ids {2}) -- PIM will not pick one. Rename or delete the extra role in the Defender portal (Settings > Permissions > Roles), then the next run binds the one that is left." -f $hits.Count, $Name, (@($hits | ForEach-Object { $_.id }) -join ', '))
    }
    if ($hits.Count -eq 1) {
        $role = $hits[0]
        Set-PimDefenderCreatePending -Name $Name -Clear
        if (-not (Test-PimWorkloadStringSetEqual -A @($role.actions) -B @($Actions))) {
            try { Invoke-PimGraph -Beta -Method PATCH -Path "/roleManagement/defender/roleDefinitions/$($role.id)" -Body @{ rolePermissions = @(@{ allowedResourceActions = @($Actions) }) } | Out-Null }
            catch { throw (Get-PimDefenderRoleWriteErrorText -Name $Name -Actions $Actions -Message "$($_.Exception.Message)$(if ($_.ErrorDetails) { ' ' + $_.ErrorDetails.Message })" -Verb 'update') }
            Write-Host ("    [~] Defender XDR role '{0}': permissions set to the spec ({1})" -f $Name, (@($Actions) -join '; ')) -ForegroundColor Green
            $role.actions = @($Actions)
        }
        return "$($role.id)"
    }
    # PREVENT (2026-09-26): a create that was redirected and not yet listed is NOT posted again for 30 minutes -- the second
    # POST is exactly how RIDE got two roles of one name.
    $pend = Get-PimDefenderCreatePending
    $pk = $Name.ToLowerInvariant()
    if ($pend.ContainsKey($pk)) {
        $at = $null; try { $at = Get-PimUtcStamp $pend[$pk] } catch { }   # IMP-02: locale- and kind-safe (a culture round trip read a 5-minute-old marker as 2 h old on a UTC+2 host)
        if ($at -and $at -gt [datetime]::UtcNow.AddMinutes(-30)) {
            throw "DEFENDER-ROLE-CREATE-PENDING: the custom role '$Name' was created at $($at.ToString('u')) and Defender does not list it yet -- not created again; the next run binds it once it is listed"
        }
    }
    $body = @{
        displayName     = $Name
        description     = $script:PimDefenderManagedRoleDescription
        rolePermissions = @(@{ allowedResourceActions = @($Actions) })
    }
    $new = $null; $redirected = $false
    try { $new = Invoke-PimGraph -Beta -Method POST -Path '/roleManagement/defender/roleDefinitions' -Body $body }
    catch {
        $m = "$($_.Exception.Message)$(if ($_.ErrorDetails) { ' ' + $_.ErrorDetails.Message })"
        # 🔴 LIVE 2026-09-19 (RIDE / EFIF / internal): Graph answers this POST with a redirect to an http:// location, and
        # PowerShell 7 refuses to follow HTTPS -> HTTP ("Cannot follow an insecure redirection"). The role IS created (the
        # next run found it and went on to assign). So: never follow the insecure hop -- READ THE ROLE BACK by name.
        if ($m -match '(?i)insecure redirection') { $redirected = $true }
        else { throw (Get-PimDefenderRoleWriteErrorText -Name $Name -Actions $Actions -Message $m -Verb 'create') }
    }
    $nid = "$($new.id)"
    if (-not $nid -and $redirected) {
        for ($i = 0; $i -lt 4 -and -not $nid; $i++) {
            if ($i) { Start-Sleep -Seconds 3 }
            try { $nid = Find-PimDefenderRoleIdByName -Name $Name } catch { $nid = '' }
        }
        if (-not $nid) {
            Set-PimDefenderCreatePending -Name $Name
            throw "DEFENDER-ROLE-CREATE-PENDING: the custom role '$Name' was created (answered with a redirect) and Defender does not list it yet -- it is not created again; the next run binds it once it is listed"
        }
    }
    if (-not $nid) { throw "DefenderXdrRoles: creating the custom role '$Name' returned no id" }
    Write-Host ("    [+] Defender XDR role '{0}' created ({1})" -f $Name, (@($Actions) -join '; ')) -ForegroundColor Green
    Add-PimDefenderRoleToCatalog -Role ([pscustomobject]@{ id = $nid; name = $Name; isBuiltIn = $false; actions = @($Actions) })
    return $nid
}

# ===========================================================================
# [2] REQ-W -- groups are always created; a workload ROLE ASSIGNMENT waits for its prerequisites
# ===========================================================================
function Get-PimWorkloadGateState {
    # { available; reason } for the workload binding providers' feature gate (connectors.workload).
    $key = 'connectors.workload'
    $avail = $true; $reason = ''
    if (Get-Command Test-PimFeatureAvailable -ErrorAction SilentlyContinue) {
        try { $avail = [bool](Test-PimFeatureAvailable -Key $key -Quiet) } catch { $avail = $false }
        if (-not $avail) {
            $reason = if (Get-Command Get-PimFeatureSkipReason -ErrorAction SilentlyContinue) { Get-PimFeatureSkipReason -Key $key } else { "the feature '$key' is not available" }
        }
    }
    return [pscustomobject]@{ available = $avail; reason = $reason }
}

# 🔴 REQ-W (operator 2026-09-19: "it should be possible to deploy groups"). The wave-2 GROUP CREATE HOLD
# (Get-PimWorkloadGroupCreateHold) is GONE: a group definition is ALWAYS created, whatever the state of its binding --
# gated off, no binding row, prerequisites not green, or a binding read refused. Measured on internal (tick 17:01Z,
# 2.4.378/379): 0 binding rows -> connectors.workload stayed off (autoEnableWhenData) -> 140 workload groups were
# warned about AND not created. What waits now is only the workload ROLE ASSIGNMENT (Get-PimWorkloadAssignmentHold
# below); the Groups provider warns (Get-PimWorkloadGateWarnings) and the orphan / coverage warnings show the missing role.

function Get-PimWorkloadBoundTags {
    # tag(lower) -> $true for every group that has a non-Remove binding row in an entity that can bind -Kind
    # (Get-PimWorkloadBindingEntities). A binding row in PIM-Assignments-Workloads counts only when its Workload is -Kind.
    param([Parameter(Mandatory)][string]$Kind)
    $h = @{}
    if (-not (Get-Command Get-PimWorkloadBindingEntities -ErrorAction SilentlyContinue) -or -not (Get-Command Get-PimDesiredRows -ErrorAction SilentlyContinue)) { return $h }
    foreach ($e in @(Get-PimWorkloadBindingEntities -Kind $Kind)) {
        foreach ($r in @(Get-PimDesiredRows -Entity $e)) {
            if ($null -eq $r) { continue }
            if ((Get-PimWlRoleField -Row $r -Names @('Action')) -ieq 'Remove') { continue }
            if ($e -eq 'PIM-Assignments-Workloads' -and (Get-PimWlBindingKind -Workload (Get-PimWlRoleField -Row $r -Names @('Workload'))) -ne $Kind) { continue }
            $t = Get-PimWlRoleField -Row $r -Names @('GroupTag'); if ($t) { $h[$t.ToLowerInvariant()] = $true }
        }
    }
    return $h
}

# ---------------------------------------------------------------------------
# REQ-W -- THE ASSIGNMENT HOLD. pim.Settings 'WorkloadPrereqs' (written by tools\setup\Initialize-PimWorkloadPrereqs.ps1)
# is read ONCE per run and judged by the one rule, Get-PimWorkloadAssignmentGate (PIM-WorkloadPrereqs.ps1). A provider
# asks Get-PimWorkloadAssignmentHold before it CREATES an assignment; a held one is reported, never written.
# 🔒 Only a CREATE waits. Removals, updates (Defender spec PATCH / re-assign, Azure extend / renew) and a TYPE CHANGE's
#    re-create proceed as before -- the gate never takes away or changes an assignment that exists.
# 🔒 Fail closed for creates only: no store / a setting that cannot be read holds every gated workload (never Entra).
# ---------------------------------------------------------------------------
function Read-PimEngineWorkloadPrereqsSetting {
    <#
      The stored pim.Settings 'WorkloadPrereqs' through the engine's channels, in the order the feature-gate reader uses
      (Get-PimFeatureStoreValue): the hydrated in-process bag (Import-PimSettingsFromStore), then the Get-PimSetting
      bridge (Manager / scheduler), then a direct SQL read. Returns @{ ok; stored; error } -- ok=$false = NOT readable
      (never "nothing stored"); ok=$true with stored=$null = the script has never run.
    #>
    $name = 'WorkloadPrereqs'
    $raw = $null; $ok = $false; $err = ''
    try {
        if ($global:PIM_NamingConventions -is [System.Collections.IDictionary] -and $global:PIM_NamingConventions.Contains($name)) { $raw = $global:PIM_NamingConventions[$name]; $ok = $true }
        elseif (Get-Command Get-PimSetting -ErrorAction SilentlyContinue) { $raw = Get-PimSetting -Name $name; $ok = $true }
        else {
            $cs = if (Get-Command Get-PimAdminLifecycleStoreCs -ErrorAction SilentlyContinue) { Get-PimAdminLifecycleStoreCs } else { $null }
            if ($cs -and (Get-Command Get-PimSqlSetting -ErrorAction SilentlyContinue)) { $raw = Get-PimSqlSetting -ConnectionString $cs -Name $name; $ok = $true }
            else { $err = 'no SQL settings store is wired in this process' }
        }
    } catch { $ok = $false; $err = "reading pim.Settings['$name'] failed: $($_.Exception.Message)" }
    if ($ok -and $raw -is [string]) {
        if ("$raw".Trim()) { try { $raw = $raw | ConvertFrom-Json } catch { return [pscustomobject]@{ ok = $false; stored = $null; error = "pim.Settings['$name'] is not readable JSON: $($_.Exception.Message)" } } }
        else { $raw = $null }
    }
    return [pscustomobject]@{ ok = $ok; stored = $raw; error = $err }
}

function Get-PimEngineWorkloadPrereqState {
    # The judged per-workload view (Get-PimWorkloadPrereqView) + the store error, read ONCE per run (a tick is a fresh
    # process; a long-lived host drops it with Clear-PimWorkloadRoleCaches). -Force re-reads.
    [CmdletBinding()] param([switch]$Force)
    if (-not $Force -and $script:PimEngineWorkloadPrereqs) { return $script:PimEngineWorkloadPrereqs }
    $st = [pscustomobject]@{ view = @(); storeError = '' }
    if (-not (Get-Command Get-PimWorkloadPrereqView -ErrorAction SilentlyContinue)) {
        $st.storeError = 'the prerequisite library (PIM-WorkloadPrereqs.ps1) is not loaded'
    } else {
        $r = Read-PimEngineWorkloadPrereqsSetting
        if (-not $r.ok) { $st.storeError = "$($r.error)" }
        else {
            try { $st.view = @(Get-PimWorkloadPrereqView -Stored $r.stored -NowUtc ([datetime]::UtcNow) -StaleDays (Get-PimWorkloadPrereqStaleDays)) }
            catch { $st.storeError = "pim.Settings['WorkloadPrereqs'] could not be judged: $($_.Exception.Message)" }
        }
    }
    $script:PimEngineWorkloadPrereqs = $st
    return $st
}

function Get-PimEngineWorkloadAssignmentGate {
    # Get-PimWorkloadAssignmentGate over this run's stored state. EntraRoles and '' are never held (not even unreadable).
    param([AllowEmptyString()][string]$Workload)
    if (-not "$Workload".Trim() -or -not (Get-Command Get-PimWorkloadAssignmentGate -ErrorAction SilentlyContinue)) {
        if ("$Workload".Trim() -and "$Workload".Trim() -ne 'EntraRoles') {
            # The rule itself is missing: fail closed, the same as an unreadable store.
            return [pscustomobject]@{ workload = "$Workload"; held = $true; state = 'unreadable'; reason = "$Workload prerequisites not green (unreadable): the prerequisite library is not loaded"; reasons = @('the prerequisite library is not loaded'); command = "tools\setup\Initialize-PimWorkloadPrereqs.ps1 -Workload $Workload" }
        }
        return [pscustomobject]@{ workload = "$Workload"; held = $false; state = ''; reason = ''; reasons = @(); command = '' }
    }
    $s = Get-PimEngineWorkloadPrereqState
    return [pscustomobject](Get-PimWorkloadAssignmentGate -Workload $Workload -View @($s.view) -StoreError "$($s.storeError)")
}

function Get-PimWorkloadAssignmentHold {
    <#
      Called by a provider's ApplyCreate BEFORE any write. $null = create it; else the gate verdict has been reported
      (Write-Warning -> the job log; the scope result's `warnings` -> the run summary) and the caller returns the object
      it gets back: { pimApplied = $false; held = $true; reason } -- the engine core counts it as NOT applied (skipped),
      never as created, and the scope does not fail.
      -Item: a TYPE CHANGE (typeChange) is never held -- its removal already ran, so holding the re-create would take
      away an assignment that existed.
    #>
    param([AllowEmptyString()][string]$Workload, [hashtable]$Context, [string]$What = '', [object]$Item, [string]$Scope = 'engine')
    if ($null -ne $Item -and $Item.PSObject -and $Item.PSObject.Properties['typeChange'] -and $Item.typeChange) { return $null }
    $g = Get-PimEngineWorkloadAssignmentGate -Workload $Workload
    if (-not $g.held) { return $null }
    $msg = ("HELD: {0} is NOT assigned -- held: {1} prerequisites not green ({2}) -- run Initialize-PimWorkloadPrereqs.ps1 -Workload {1}. {3}. The group itself is created; the assignment is made on the first run after the prerequisites are green." -f $What, $g.workload, $g.state, (@($g.reasons) -join '; '))
    Write-Warning "  [$Scope] $msg"
    if ($Context -and $Context['__pimScopeWarnings'] -is [System.Collections.Generic.List[string]]) { $Context['__pimScopeWarnings'].Add($msg) }
    return [pscustomobject]@{ pimApplied = $false; held = $true; workload = "$($g.workload)"; state = "$($g.state)"; reason = $msg }
}

function Get-PimWorkloadPrereqHeldReasons {
    # kind (intune | defender | a connector id) -> the held gate for a workload group's warning, $null when not held.
    param([Parameter(Mandatory)][string]$Kind)
    $w = if (Get-Command Get-PimWorkloadPrereqForConnector -ErrorAction SilentlyContinue) { Get-PimWorkloadPrereqForConnector -Connector $Kind } else { '' }
    if (-not $w) { return $null }
    $g = Get-PimEngineWorkloadAssignmentGate -Workload $w
    if ($g.held) { return $g }
    return $null
}

# ===========================================================================
# [3] LIVE ORPHAN WARNINGS -- PURE over the providers' live reads
# ===========================================================================
function Get-PimWorkloadDefinitionsOfKind {
    # The group definitions (Get-PimGroupDefinitionRows) whose Workload has the binding kind -Kind.
    param([Parameter(Mandatory)][string]$Kind, [object[]]$Definitions)
    $defs = if ($PSBoundParameters.ContainsKey('Definitions')) { @($Definitions) } elseif (Get-Command Get-PimGroupDefinitionRows -ErrorAction SilentlyContinue) { @(Get-PimGroupDefinitionRows) } else { @() }
    return @($defs | Where-Object { $null -ne $_ -and (Get-PimWlBindingKind -Workload (Get-PimWlRoleField -Row $_ -Names @('Workload'))) -eq $Kind })
}

function Get-PimWorkloadLiveOrphanFindings {
    <#
      PURE. The live orphan warnings of ONE workload area. Every finding:
        { type='warning'; kind; key; label; group; role; relatedKeys=@() }
      kind:
        orphan-group       -- a PIM group whose Workload is -Kind holds NO live role of that workload.
        unmanaged-binding  -- a live role of that workload held by a principal no PIM definition defines.
        wrong-permissions  -- (Defender) a spec'd role whose live actions / data sources differ from the spec. Its key
                              IS the binding's plan key, so the drift snapshot counts it once with the plan's update.
        ambiguous-role     -- (Defender) a spec'd role name two live roles share (PIM refuses to bind it).
        held-prerequisites -- REQ-W: what would be an orphan-group, but the group HAS a binding row and its workload's
                              assignment is held (-HeldGate): "waiting for <workload> prerequisites", not "orphan".
      relatedKeys: plan keys in the same area; a warning whose related key is already a plan item is shown but not
      counted a second time.
      Inputs:
        -Definitions   group definition rows (GroupName; GroupTag; Workload)
        -OwnedById     gid -> { id; name; tag } for EVERY live PIM-defined group (any workload)
        -Assignments   live assignments { id; displayName; roleName; roleDefinitionId; principals; appScopeIds }
        -SpecBindings  (Defender) desired bindings WITH a spec; -SpecGidByTag tag(lower) -> gid; -Catalog the role catalog
        -NameById      optional gid -> display name for principals PIM does not own
    #>
    param(
        [Parameter(Mandatory)][ValidateSet('intune', 'defender')][string]$Kind,
        [object[]]$Definitions = @(),
        [hashtable]$OwnedById = @{},
        [object[]]$Assignments = @(),
        [object[]]$SpecBindings = @(),
        [hashtable]$SpecGidByTag = @{},
        [AllowNull()][object]$Catalog,
        [hashtable]$NameById = @{},
        [hashtable]$RelatedKeysByTag = @{},
        # REQ-W: this area's assignment gate (Get-PimEngineWorkloadAssignmentGate). When it HOLDS, a group that has a
        # binding row (-BoundTags, tag(lower) -> $true) and no live role is not an orphan: its assignment is waiting.
        [AllowNull()][object]$HeldGate,
        [hashtable]$BoundTags = @{}
    )
    $area = if ($Kind -eq 'intune') { 'Intune' } else { 'Defender XDR' }
    $out = New-Object System.Collections.Generic.List[object]
    $heldBy = @{}
    foreach ($a in @($Assignments)) {
        if ($null -eq $a) { continue }
        foreach ($p in @($a.principals)) { $pp = "$p".ToLowerInvariant(); if ($pp) { if (-not $heldBy.ContainsKey($pp)) { $heldBy[$pp] = New-Object System.Collections.Generic.List[string] }; $heldBy[$pp].Add("$($a.roleName)") } }
    }
    $owned = @{}; $ownedTag = @{}
    foreach ($k in @($OwnedById.Keys)) {
        $o = $OwnedById[$k]; $owned["$k".ToLowerInvariant()] = $o
        $t = "$($o.tag)".Trim(); if ($t) { $ownedTag[$t.ToLowerInvariant()] = "$k".ToLowerInvariant() }
    }
    # (1) orphan groups
    foreach ($d in @(Get-PimWorkloadDefinitionsOfKind -Kind $Kind -Definitions @($Definitions))) {
        $tag = Get-PimWlRoleField -Row $d -Names @('GroupTag'); $gn = Get-PimWlRoleField -Row $d -Names @('GroupName')
        $gid = ''
        if ($tag -and $ownedTag.ContainsKey($tag.ToLowerInvariant())) { $gid = $ownedTag[$tag.ToLowerInvariant()] }
        if (-not $gid) {
            foreach ($k in @($owned.Keys)) { if ("$($owned[$k].name)" -and "$($owned[$k].name)" -ieq $gn) { $gid = $k; break } }
        }
        if (-not $gid) { continue }   # not created yet -- the Groups area reports a missing group, not an orphan
        if ($heldBy.ContainsKey($gid)) { continue }
        $rk = @(); if ($tag -and $RelatedKeysByTag.ContainsKey($tag.ToLowerInvariant())) { $rk = @($RelatedKeysByTag[$tag.ToLowerInvariant()]) }
        if ($HeldGate -and $HeldGate.held -and $tag -and $BoundTags -and $BoundTags.ContainsKey($tag.ToLowerInvariant())) {
            $out.Add([pscustomobject]@{
                type = 'warning'; kind = 'held-prerequisites'; key = ("held-prerequisites|$tag").ToLowerInvariant(); group = $gn; role = ''
                label = ("waiting for {0} prerequisites: '{1}' (tag '{2}') holds no live {3} role yet -- its assignment is HELD until the {0} prerequisites are green ({4}); run Initialize-PimWorkloadPrereqs.ps1 -Workload {0}" -f $HeldGate.workload, $gn, $tag, $area, $HeldGate.state)
                relatedKeys = $rk
            })
            continue
        }
        $out.Add([pscustomobject]@{
            type = 'warning'; kind = 'orphan-group'; key = ("orphan-group|$tag").ToLowerInvariant(); group = $gn; role = ''
            label = ("orphan group: '{0}' (tag '{1}', workload {2}) holds NO live {3} role -- add its binding, or remove the definition" -f $gn, $tag, (Get-PimWlRoleField -Row $d -Names @('Workload')), $area)
            relatedKeys = $rk
        })
    }
    # (2) unmanaged bindings -- a live workload role on a principal no PIM definition defines
    foreach ($a in @($Assignments)) {
        if ($null -eq $a) { continue }
        foreach ($p in @($a.principals)) {
            $pp = "$p".ToLowerInvariant(); if (-not $pp) { continue }
            if ($owned.ContainsKey($pp)) { continue }
            $who = if ($NameById -and $NameById.ContainsKey($pp) -and "$($NameById[$pp])".Trim()) { "'$($NameById[$pp])' ($p)" } else { "principal $p" }
            $out.Add([pscustomobject]@{
                type = 'warning'; kind = 'unmanaged-binding'; key = ("unmanaged-binding|$($a.id)|$pp").ToLowerInvariant(); group = "$p"; role = "$($a.roleName)"
                label = ("unmanaged binding: {0} role '{1}'{2} is held by {3}, which no PIM definition defines" -f $area, $a.roleName, $(if ("$($a.displayName)".Trim() -and "$($a.displayName)" -ne "$($a.roleName)") { " (assignment '$($a.displayName)')" } else { '' }), $who)
                relatedKeys = @()
            })
        }
    }
    # (3) Defender: wrong permissions / ambiguous role names on spec'd bindings
    if ($Kind -eq 'defender' -and $Catalog -and $Catalog.byName) {
        foreach ($s in @($SpecBindings)) {
            $spec = Get-PimDefenderRoleSpec -Row $s; if (-not $spec) { continue }
            $rn = Get-PimWlRoleField -Row $s -Names @('RoleDefinitionName', 'RoleName'); if (-not $rn) { continue }
            $tag = Get-PimWlRoleField -Row $s -Names @('GroupTag')
            $gn = Get-PimWlRoleField -Row $s -Names @('GroupName'); if (-not $gn) { $gn = $tag }
            $bk = Get-PimWorkloadRoleBindingKey -Row $s
            $hits = @(); if ($Catalog.byName.ContainsKey($rn.ToLowerInvariant())) { $hits = @($Catalog.byName[$rn.ToLowerInvariant()]) }
            if ($hits.Count -gt 1) {
                $out.Add([pscustomobject]@{ type = 'warning'; kind = 'ambiguous-role'; key = ("ambiguous-role|$rn").ToLowerInvariant(); group = $gn; role = $rn
                    label = ("ambiguous role: {0} live Defender XDR roles are named '{1}' -- PIM refuses to bind group '{2}' to either; rename or delete the extra role" -f $hits.Count, $rn, $gn)
                    relatedKeys = @($bk) })
                continue
            }
            if ($hits.Count -ne 1) { continue }   # no role yet: the plan creates it (a 'missing' item)
            $role = $hits[0]
            $gid = if ($tag -and $SpecGidByTag.ContainsKey($tag.ToLowerInvariant())) { "$($SpecGidByTag[$tag.ToLowerInvariant()])".ToLowerInvariant() } else { '' }
            $ds = $null
            if ($gid) {
                $mine = @(@($Assignments) | Where-Object { $_ -and "$($_.roleDefinitionId)" -ieq "$($role.id)" -and (@($_.principals) | Where-Object { "$_" -ieq $gid }) })
                if ($mine.Count) {
                    $ds = @($mine[0].appScopeIds)
                    foreach ($m in $mine) { if (Test-PimWorkloadStringSetEqual -A @($m.appScopeIds) -B @($spec.dataSources)) { $ds = @($m.appScopeIds); break } }
                }
            }
            $diff = Get-PimDefenderSpecDifference -Desired $s -LiveActions @($role.actions) -LiveDataSources $ds
            if (-not $diff) { continue }
            $out.Add([pscustomobject]@{
                type = 'warning'; kind = 'wrong-permissions'; key = $bk; group = $gn; role = $rn
                label = ("wrong permissions: Defender XDR role '{0}' (group '{1}') differs from its spec -- {2}" -f $rn, $gn, $diff)
                relatedKeys = @($bk)
            })
        }
    }
    return @($out.ToArray())
}

function Add-PimWorkloadLiveFindings {
    # Hand an area's live findings to the engine: the scope result's `findings` (the drift snapshot lists and counts
    # them) and its `warnings` (the run summary). One job-log line per area, not one per finding.
    param([hashtable]$Context, [object[]]$Findings = @(), [string]$Scope = '')
    $f = @($Findings | Where-Object { $null -ne $_ })
    if (-not $f.Count) { return }
    if ($Context) {
        if ($Context['__pimLiveFindings'] -is [System.Collections.Generic.List[object]]) { foreach ($x in $f) { $Context['__pimLiveFindings'].Add($x) } }
        if ($Context['__pimScopeWarnings'] -is [System.Collections.Generic.List[string]]) { foreach ($x in $f) { $Context['__pimScopeWarnings'].Add("$($x.label)") } }
    }
    $byKind = @($f | Group-Object kind | ForEach-Object { "$($_.Count) $($_.Name)" }) -join ', '
    Write-Warning ("  [{0}] {1} live workload warning(s): {2} -- {3}" -f $Scope, $f.Count, $byKind, ((@($f | Select-Object -First 3 | ForEach-Object { $_.label })) -join ' | '))
}

# ===========================================================================
# [4] WORKLOAD ROLE DISCOVERY -- 'discovery-defender' / 'discovery-intune'
# ===========================================================================
function Get-PimWorkloadTemplatesDir {
    if ("$($global:PIM_TemplatesDir)".Trim()) { return "$($global:PIM_TemplatesDir)".Trim() }
    $solutionRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    return (Join-Path $solutionRoot 'templates')
}

function Get-PimWorkloadPackKnowledge {
    <#
      What the shipped delegation pack(s) of a workload KNOW: the role names their binding rows bind (a '{GroupName}'
      role resolved to the group's name under the TENANT pattern) and -- Defender -- `knownActionPrefixes`.
        { service; packs=@(ids); roleNames=@(lower); actionPrefixes=@(lower); read; reason }
      Reads templates/*.template.json (shipped with the image; code, not state).
    #>
    param([Parameter(Mandatory)][ValidateSet('defender', 'intune')][string]$Service, [string]$Directory, [string]$TenantPattern)
    $dir = if ("$Directory".Trim()) { "$Directory".Trim() } else { Get-PimWorkloadTemplatesDir }
    $names = New-Object System.Collections.Generic.HashSet[string] ([StringComparer]::OrdinalIgnoreCase)
    $prefixes = New-Object System.Collections.Generic.List[string]
    $packs = New-Object System.Collections.Generic.List[string]
    if (-not (Test-Path -LiteralPath $dir)) { return [pscustomobject]@{ service = $Service; packs = @(); roleNames = @(); actionPrefixes = @(); read = $false; reason = "no templates directory at $dir" } }
    foreach ($f in @(Get-ChildItem -LiteralPath $dir -Filter '*.template.json' -File -ErrorAction SilentlyContinue | Sort-Object Name)) {
        $tpl = $null
        try {
            $raw = [System.IO.File]::ReadAllText($f.FullName, (New-Object System.Text.UTF8Encoding($false)))
            if ($raw.Length -gt 0 -and [int][char]$raw[0] -eq 0xFEFF) { $raw = $raw.Substring(1) }
            $tpl = $raw | ConvertFrom-Json
        } catch { Write-Warning ("  [discovery] pack {0} could not be parsed: {1}" -f $f.Name, $_.Exception.Message); continue }
        if (-not $tpl -or -not $tpl.rows) { continue }
        $packPat = if ("$($tpl.groupNamePattern)".Trim()) { "$($tpl.groupNamePattern)" } else { 'PIM-{Role}' }
        # the pack's definitions: tag -> the group NAME under this tenant's pattern
        $tagToName = @{}
        foreach ($bp in $tpl.rows.PSObject.Properties) {
            if ($bp.Name -notlike 'PIM-Definitions-*') { continue }
            foreach ($d in @($bp.Value)) {
                $t = Get-PimWlRoleField -Row $d -Names @('GroupTag'); $n = Get-PimWlRoleField -Row $d -Names @('GroupName')
                if (-not $t) { continue }
                if ($n -and (Get-Command ConvertTo-PimTenantGroupName -ErrorAction SilentlyContinue)) {
                    $a = @{ Name = $n; FromPattern = $packPat }; if ("$TenantPattern".Trim()) { $a['ToPattern'] = $TenantPattern }
                    $n = ConvertTo-PimTenantGroupName @a
                }
                $tagToName[$t.ToLowerInvariant()] = $n
            }
        }
        $hit = $false
        foreach ($bp in $tpl.rows.PSObject.Properties) {
            if ($bp.Name -notin @('PIM-Assignments-Workloads', 'PIM-Assignments-Intune', 'PIM-Assignments-Defender')) { continue }
            foreach ($b in @($bp.Value)) {
                $kind = switch ($bp.Name) { 'PIM-Assignments-Intune' { 'intune' } 'PIM-Assignments-Defender' { 'defender' } default { Get-PimWlBindingKind -Workload (Get-PimWlRoleField -Row $b -Names @('Workload')) } }
                if ($kind -ne $Service) { continue }
                $rn = Resolve-PimWorkloadBindingRoleName -Row $b -TagToName $tagToName
                if ($rn) { [void]$names.Add($rn); $hit = $true }
            }
        }
        if ($Service -eq 'defender' -and $tpl.PSObject.Properties['knownActionPrefixes']) {
            foreach ($p in @($tpl.knownActionPrefixes)) { if ("$p".Trim()) { $prefixes.Add("$p".Trim().ToLowerInvariant()); $hit = $true } }
        }
        if ($hit) { $packs.Add("$($tpl.id)") }
    }
    return [pscustomobject]@{ service = $Service; packs = @($packs.ToArray()); roleNames = @($names | ForEach-Object { $_.ToLowerInvariant() }); actionPrefixes = @($prefixes.ToArray()); read = $true; reason = '' }
}

function Get-PimDefenderActionNamespace {
    # PURE. 'microsoft.xdr/secops/securitydata/alerts/manage' -> 'microsoft.xdr/secops'.
    param([AllowNull()][string]$Action)
    $parts = @("$Action".Trim().ToLowerInvariant() -split '/' | Where-Object { $_ })
    if ($parts.Count -ge 2) { return ($parts[0] + '/' + $parts[1]) }
    return ($parts -join '/')
}

function Read-PimWorkloadRoleCatalog {
    <#
      LIVE. One workload's role catalog as the stored record:
        { read:bool; reason; readUtc; roles:[{ name; id; isBuiltIn; actions? }] }
      Defender: Graph BETA roleManagement/defender/roleDefinitions -- EVERY role with its full action strings (the
      Data Operations actions are unpublished; this is how they become known). Intune: v1.0
      deviceManagement/roleDefinitions, built-in and custom. A failed read is read=false with the reason -- never an
      empty role list.
    #>
    param([Parameter(Mandatory)][ValidateSet('defender', 'intune')][string]$Service, [datetime]$NowUtc = [datetime]::UtcNow)
    $stamp = $NowUtc.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ', [System.Globalization.CultureInfo]::InvariantCulture)
    $roles = New-Object System.Collections.Generic.List[object]
    if ($Service -eq 'defender') {
        $cat = Get-PimDefenderRoleCatalog -Force
        if (-not $cat.ok) { return [ordered]@{ read = $false; reason = "Graph beta /roleManagement/defender/roleDefinitions: $($cat.error)"; readUtc = $stamp; roles = @() } }
        foreach ($r in @($cat.roles)) { $roles.Add([ordered]@{ name = "$($r.name)"; id = "$($r.id)"; isBuiltIn = [bool]$r.isBuiltIn; actions = @($r.actions) }) }
    } else {
        try {
            foreach ($r in @(Invoke-PimGraph -All -Path '/deviceManagement/roleDefinitions?$select=id,displayName,isBuiltIn')) {
                if ($null -eq $r -or (-not "$($r.id)" -and -not "$($r.displayName)")) { continue }
                $bi = $false; if ($r.PSObject.Properties['isBuiltIn'] -and $null -ne $r.isBuiltIn) { $bi = [bool]$r.isBuiltIn }
                $roles.Add([ordered]@{ name = "$($r.displayName)"; id = "$($r.id)"; isBuiltIn = $bi })
            }
        } catch {
            return [ordered]@{ read = $false; reason = "Graph v1.0 /deviceManagement/roleDefinitions: $($_.Exception.Message)"; readUtc = $stamp; roles = @() }
        }
    }
    return [ordered]@{ read = $true; reason = ''; readUtc = $stamp; roles = @($roles.ToArray()) }
}

function Read-PimDefenderPermissionCatalog {
    <#
      LIVE. The Defender XDR Unified RBAC PERMISSION catalog -- every action Microsoft offers, whether or not a role uses it:
        { read:bool; reason; readUtc; actions:[{ id; name; description }] }
      Graph BETA /roleManagement/defender/resourceNamespaces?$expand=resourceActions (measured on internal 2026-09-19 by
      the lead: 200, 77 actions in 5 permission groups -- secops, securityposture, configuration, dataops, aicodesecurity).
      NB: .../resourceNamespaces/microsoft.xdr/resourceActions answers 404; the $expand is the working read.
    #>
    param([datetime]$NowUtc = [datetime]::UtcNow)
    $stamp = $NowUtc.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ', [System.Globalization.CultureInfo]::InvariantCulture)
    $acts = New-Object System.Collections.Generic.List[object]
    $seen = New-Object System.Collections.Generic.HashSet[string] ([StringComparer]::OrdinalIgnoreCase)
    $add = {
        param($a)
        if ($null -eq $a) { return }
        $id = "$($a.id)"; $nm = "$($a.name)"
        $act = if ($id -match '/') { $id } elseif ($nm -match '^[a-z0-9.]+/') { $nm } else { '' }
        if (-not $act -or -not $seen.Add($act)) { return }
        $label = if ($act -ne $nm) { $nm } else { '' }
        $acts.Add([ordered]@{ id = $act; name = $label; description = "$($a.description)" })
    }
    try {
        foreach ($ns in @(Invoke-PimGraph -Beta -All -Path '/roleManagement/defender/resourceNamespaces?$expand=resourceActions')) {
            if ($null -eq $ns) { continue }
            if ($ns.PSObject.Properties['resourceActions']) { foreach ($a in @($ns.resourceActions)) { & $add $a } }
            else { & $add $ns }   # a flattened answer: the items ARE the actions
        }
    } catch {
        return [ordered]@{ read = $false; reason = "Graph beta /roleManagement/defender/resourceNamespaces?`$expand=resourceActions: $($_.Exception.Message)"; readUtc = $stamp; actions = @() }
    }
    return [ordered]@{ read = $true; reason = ''; readUtc = $stamp; actions = @($acts.ToArray()) }
}

function Test-PimWlRecordRead {
    # PURE. Was this stored record (dictionary or object) a GOOD read?
    param([AllowNull()][object]$Record)
    if ($null -eq $Record) { return $false }
    if ($Record -is [System.Collections.IDictionary]) { return ($Record.Contains('read') -and [bool]$Record['read']) }
    $p = $Record.PSObject.Properties['read']
    return ($null -ne $p -and [bool]$p.Value)
}

function Get-PimWorkloadRoleDiscoveryDelta {
    <#
      PURE. What discovery found that the packs do not know:
        newRoles            -- live roles whose name no pack binding names
        unknownNamespaces   -- (Defender) permission groups ('microsoft.xdr/<group>') USED by live roles that no pack's
                               knownActionPrefixes covers, each { namespace; actions; roles }
        newPermissionGroups -- (Defender) permission groups in Microsoft's permission CATALOG (-PermissionCatalog) no pack
                               covers, each { namespace; actions=@({ id; name }) } -- a new group Microsoft added (Data
                               Operations was one) shows here even before any role uses it
        freshRoles / freshNamespaces / freshPermissionGroups -- the part NOT in the previous good records (what to mail)
    #>
    param([Parameter(Mandatory)][string]$Service, [object]$Record, [object]$Knowledge, [AllowNull()][object]$Previous,
          [AllowNull()][object]$PermissionCatalog, [AllowNull()][object]$PreviousPermissionCatalog)
    $known = New-Object System.Collections.Generic.HashSet[string] ([StringComparer]::OrdinalIgnoreCase)
    foreach ($n in @($Knowledge.roleNames)) { if ("$n") { [void]$known.Add("$n") } }
    $prefixes = @(@($Knowledge.actionPrefixes) | ForEach-Object { "$_".ToLowerInvariant() } | Where-Object { $_ })
    $prevNames = New-Object System.Collections.Generic.HashSet[string] ([StringComparer]::OrdinalIgnoreCase)
    $prevNs = New-Object System.Collections.Generic.HashSet[string] ([StringComparer]::OrdinalIgnoreCase)
    $prevRead = Test-PimWlRecordRead -Record $Previous
    if ($prevRead) {
        foreach ($r in @($Previous.roles)) {
            if ("$($r.name)") { [void]$prevNames.Add("$($r.name)") }
            foreach ($a in @($r.actions)) { if ("$a".Trim()) { [void]$prevNs.Add((Get-PimDefenderActionNamespace -Action "$a")) } }
        }
    }
    $newRoles = New-Object System.Collections.Generic.List[object]
    $ns = [ordered]@{}
    foreach ($r in @($Record.roles)) {
        $n = "$($r.name)"
        if ($n -and -not $known.Contains($n)) { $newRoles.Add([pscustomobject]@{ name = $n; id = "$($r.id)"; isBuiltIn = [bool]$r.isBuiltIn; fresh = (-not $prevRead -or -not $prevNames.Contains($n)) }) }
        if ($Service -ne 'defender') { continue }
        foreach ($a in @($r.actions)) {
            $al = "$a".Trim().ToLowerInvariant(); if (-not $al) { continue }
            $covered = $false
            foreach ($p in $prefixes) { if ($al.StartsWith($p)) { $covered = $true; break } }
            if ($covered) { continue }
            $nsk = Get-PimDefenderActionNamespace -Action $al
            if (-not $ns.Contains($nsk)) { $ns[$nsk] = [pscustomobject]@{ namespace = $nsk; actions = (New-Object System.Collections.Generic.List[string]); roles = (New-Object System.Collections.Generic.List[string]); fresh = (-not $prevRead -or -not $prevNs.Contains($nsk)) } }
            if (-not $ns[$nsk].actions.Contains("$a".Trim())) { $ns[$nsk].actions.Add("$a".Trim()) }
            if ($n -and -not $ns[$nsk].roles.Contains($n)) { $ns[$nsk].roles.Add($n) }
        }
    }
    $nsList = @(foreach ($k in $ns.Keys) { [pscustomobject]@{ namespace = $ns[$k].namespace; actions = @($ns[$k].actions.ToArray()); roles = @($ns[$k].roles.ToArray()); fresh = [bool]$ns[$k].fresh } })
    # The permission CATALOG (Defender): a permission group no pack covers = a new permission group found.
    $pg = [ordered]@{}
    if ($Service -eq 'defender' -and (Test-PimWlRecordRead -Record $PermissionCatalog)) {
        $prevCat = New-Object System.Collections.Generic.HashSet[string] ([StringComparer]::OrdinalIgnoreCase)
        $prevCatRead = Test-PimWlRecordRead -Record $PreviousPermissionCatalog
        if ($prevCatRead) { foreach ($a in @($PreviousPermissionCatalog.actions)) { if ("$($a.id)") { [void]$prevCat.Add((Get-PimDefenderActionNamespace -Action "$($a.id)")) } } }
        foreach ($a in @($PermissionCatalog.actions)) {
            $al = "$($a.id)".Trim().ToLowerInvariant(); if (-not $al) { continue }
            $covered = $false
            foreach ($p in $prefixes) { if ($al.StartsWith($p)) { $covered = $true; break } }
            if ($covered) { continue }
            $nsk = Get-PimDefenderActionNamespace -Action $al
            if (-not $pg.Contains($nsk)) { $pg[$nsk] = [pscustomobject]@{ namespace = $nsk; actions = (New-Object System.Collections.Generic.List[object]); fresh = (-not $prevCatRead -or -not $prevCat.Contains($nsk)) } }
            $pg[$nsk].actions.Add([pscustomobject]@{ id = "$($a.id)"; name = "$($a.name)" })
        }
    }
    $pgList = @(foreach ($k in $pg.Keys) { [pscustomobject]@{ namespace = $pg[$k].namespace; actions = @($pg[$k].actions.ToArray()); fresh = [bool]$pg[$k].fresh } })
    return [pscustomobject]@{
        service               = $Service
        newRoles              = @($newRoles.ToArray())
        unknownNamespaces     = @($nsList)
        newPermissionGroups   = @($pgList)
        freshRoles            = @($newRoles.ToArray() | Where-Object { $_.fresh })
        freshNamespaces       = @($nsList | Where-Object { $_.fresh })
        freshPermissionGroups = @($pgList | Where-Object { $_.fresh })
    }
}

function Get-PimWorkloadRoleCacheKind {
    param([Parameter(Mandatory)][ValidateSet('defender', 'intune')][string]$Service)
    return "workload-roles:$Service"
}

function Invoke-PimWorkloadRoleDiscoveryJob {
    <#
      The 'discovery-defender' / 'discovery-intune' job body (the scheduler's discovery handler routes a job whose
      service -- or scope -- is Defender / Intune here). Reads the live catalog, stores it in pim.TenantCache kind
      'workload-roles:<service>' EXACTLY as { read, reason, readUtc, roles }, computes what no pack knows and mails
      the FRESH part through the existing discovery-notice mail (opt-in recipients, Send-PimDiscoveryNotices).
      It replaces the PIM-Catalog-ServiceRoles queueing for these services: nothing ever consumed that queue entity.
      🔒 -WhatIf reads nothing and writes nothing.
      🔒 No tenant-cache store -> REFUSED (unimplemented), never a record only this process could see.
      🔴 A catalog that could NOT be read is STORED (read=false + reason, so the Coverage page says "not checked") and
         the job FAILS (throws) -- never an empty "0 new roles" success.
    #>
    param([Parameter(Mandatory)][ValidateSet('defender', 'intune')][string]$Service, [datetime]$NowUtc = [datetime]::UtcNow, [switch]$WhatIf, [string]$NotifyRecipient, [switch]$NoNotify)
    $kind = Get-PimWorkloadRoleCacheKind -Service $Service
    if ($WhatIf) {
        return [pscustomobject]@{ ran = $false; whatIf = $true; read = $true; service = $Service
            detail = "whatif:discovery-$Service -- would read the $Service role catalog and write pim.TenantCache/$kind (nothing read, nothing written)" }
    }
    if (-not (Get-Command Set-PimTenantCacheEntry -ErrorAction SilentlyContinue) -or -not (Get-Command Get-PimTenantCacheStoreCs -ErrorAction SilentlyContinue)) {
        return [pscustomobject]@{ ran = $false; unimplemented = $true; whatIf = $false; read = $true; service = $Service
            detail = "unimplemented:discovery-$Service (tools/pim-manager/_tenantSync.ps1 is not loaded on this worker -- no tenant-cache store to write to)" }
    }
    if (-not (Get-PimTenantCacheStoreCs)) {
        return [pscustomobject]@{ ran = $false; unimplemented = $true; whatIf = $false; read = $true; service = $Service
            detail = "unimplemented:discovery-$Service -- no SQL store in this process, so the $Service role catalog could only live in memory where the Manager can never read it" }
    }
    $prev = $null
    try { $prev = Get-PimTenantCacheEntry -Kind $kind } catch { $prev = $null }
    $rec = Read-PimWorkloadRoleCatalog -Service $Service -NowUtc $NowUtc
    $where = Set-PimTenantCacheEntry -Kind $kind -Value $rec
    if (-not [bool]$rec.read) {
        return [pscustomobject]@{ ran = $true; read = $false; notRead = $true; service = $Service; reason = "$($rec.reason)"; where = $where
            detail = ("discovery[{0}]: NOT READ -- {1} (stored as not checked -> {2})" -f $Service, $rec.reason, $where) }
    }
    # Defender: Microsoft's PERMISSION catalog too (every action, used or not), stored as 'workload-actions:defender'
    # { read, reason, readUtc, actions:[{ id, name, description }] } -- the source a new permission group's rows are
    # authored from, and the baseline for "fresh" next run.
    $perm = $null; $prevPerm = $null; $permWhere = ''
    if ($Service -eq 'defender') {
        try { $prevPerm = Get-PimTenantCacheEntry -Kind 'workload-actions:defender' } catch { $prevPerm = $null }
        $perm = Read-PimDefenderPermissionCatalog -NowUtc $NowUtc
        try { $permWhere = Set-PimTenantCacheEntry -Kind 'workload-actions:defender' -Value $perm } catch { Write-Warning "[discovery] the Defender XDR permission catalog could not be stored: $($_.Exception.Message)" }
    }
    $tenantPat = ''
    try { if (Get-Command Get-PimNamingConvention -ErrorAction SilentlyContinue) { $tenantPat = "$(Get-PimNamingConvention -Key 'PimGroupPattern')" } } catch { $tenantPat = '' }
    $know = Get-PimWorkloadPackKnowledge -Service $Service -TenantPattern $tenantPat
    $delta = Get-PimWorkloadRoleDiscoveryDelta -Service $Service -Record ([pscustomobject]$rec) -Knowledge $know -Previous $prev -PermissionCatalog $perm -PreviousPermissionCatalog $prevPerm
    $items = New-Object System.Collections.Generic.List[object]
    foreach ($r in @($delta.freshRoles)) { $items.Add([pscustomobject]@{ action = 'create'; resourceType = "WorkloadRole:$Service"; key = "$Service|role|$($r.name)".ToLowerInvariant(); name = "$($r.name)$(if ($r.isBuiltIn) { ' (built-in)' } else { ' (custom)' })" }) }
    $mailedNs = New-Object System.Collections.Generic.HashSet[string] ([StringComparer]::OrdinalIgnoreCase)
    foreach ($g in @($delta.freshPermissionGroups)) {
        [void]$mailedNs.Add("$($g.namespace)")
        $items.Add([pscustomobject]@{ action = 'create'; resourceType = "PermissionGroup:$Service"; key = "$Service|namespace|$($g.namespace)"; name = ("new permission group {0}: {1}" -f $g.namespace, (@($g.actions | ForEach-Object { if ("$($_.name)") { "$($_.id) ($($_.name))" } else { "$($_.id)" } }) -join ', ')) })
    }
    foreach ($n in @($delta.freshNamespaces)) {
        if ($mailedNs.Contains("$($n.namespace)")) { continue }
        $items.Add([pscustomobject]@{ action = 'create'; resourceType = "ActionNamespace:$Service"; key = "$Service|namespace|$($n.namespace)"; name = ("{0} -- {1} (used by {2})" -f $n.namespace, (@($n.actions) -join ', '), (@($n.roles) -join ', ')) })
    }
    $notice = $null
    if ($items.Count -and (Get-Command Send-PimDiscoveryNotices -ErrorAction SilentlyContinue)) {
        $na = @{ Items = @($items.ToArray()); Scope = $(if ($Service -eq 'defender') { 'Defender XDR roles' } else { 'Intune roles' }) }
        if ($PSBoundParameters.ContainsKey('NotifyRecipient')) { $na['Recipient'] = $NotifyRecipient }
        if ($NoNotify) { $na['NoMail'] = $true }
        try { $notice = Send-PimDiscoveryNotices @na } catch { $notice = $null }
    }
    $nsTxt = ''
    if ($Service -eq 'defender') {
        $nsTxt = " unknownNamespaces=$(@($delta.unknownNamespaces).Count)$(if (@($delta.unknownNamespaces).Count) { ' (' + ((@($delta.unknownNamespaces) | ForEach-Object { $_.namespace }) -join ', ') + ')' })"
        $nsTxt += if (Test-PimWlRecordRead -Record $perm) { " permissions=$(@($perm.actions).Count) newPermissionGroups=$(@($delta.newPermissionGroups).Count)$(if (@($delta.newPermissionGroups).Count) { ' (' + ((@($delta.newPermissionGroups) | ForEach-Object { $_.namespace }) -join ', ') + ')' })" } else { ' permission catalog NOT READ' }
    }
    $out = [pscustomobject]@{
        ran = $true; read = $true; service = $Service; where = $where
        roles = @($rec.roles).Count; packs = @($know.packs)
        newRoles = @($delta.newRoles); unknownNamespaces = @($delta.unknownNamespaces); newPermissionGroups = @($delta.newPermissionGroups)
        freshRoles = @($delta.freshRoles).Count; freshNamespaces = @($delta.freshNamespaces).Count; freshPermissionGroups = @($delta.freshPermissionGroups).Count
        permissionCatalog = $(if ($null -ne $perm) { [pscustomobject]@{ read = (Test-PimWlRecordRead -Record $perm); actions = @($perm.actions).Count; where = $permWhere } } else { $null })
        notified = $(if ($notice) { [bool]$notice.notified } else { $false }); notice = $notice
        detail = ("discovery[{0}]: roles={1} newRoles={2} (fresh {3}){4} -> {5}{6}" -f $Service, @($rec.roles).Count, @($delta.newRoles).Count, @($delta.freshRoles).Count, $nsTxt, $where, $(if ($notice -and $notice.notified) { '; mailed' } else { '' }))
    }
    # 🔴 The permission catalog is part of this job's answer ("is there a new permission group?"). Roles read but the
    # catalog NOT read is a FAILED run too -- stored and reported, never a quiet "nothing new".
    if ($null -ne $perm -and -not (Test-PimWlRecordRead -Record $perm)) {
        Add-Member -InputObject $out -NotePropertyName notRead -NotePropertyValue $true -Force
        Add-Member -InputObject $out -NotePropertyName notReadWhat -NotePropertyValue 'permission catalog' -Force
        Add-Member -InputObject $out -NotePropertyName reason -NotePropertyValue "$($perm.reason)" -Force
    }
    return $out
}

function Clear-PimWorkloadRoleCaches {
    # Drop the per-run Defender catalog and the stored prerequisite state (a long-lived host before a fresh check; a tick
    # is a fresh process).
    $script:PimDefenderRoleCatalog = $null
    $script:PimEngineWorkloadPrereqs = $null
}
