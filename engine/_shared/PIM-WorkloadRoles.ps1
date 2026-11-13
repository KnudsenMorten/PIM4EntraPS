<#
  PIM4EntraPS -- WORKLOAD ROLES: the group + its workload role as ONE unit (REQ-U wave 2, 2026-09-19).

  Operator: "otherwise we will end with orphaned permission groups that are not connected with the actual workload" /
  "you must have a warning if that is the case, can be checked against api" / "we need to include this role in the
  template for defender xdr. maybe you can verify the automatic discovery of defender xdr api works".

  What lives here (loaded by PIM-EngineProviders.ps1 next to PIM-WorkloadConnectors.ps1, so the engine, the
  scheduler tick and every host that loads the providers has it):

    [1] Defender XDR ROLE SPEC (design point 3) -- a Defender binding row may carry `Permissions` (the role's
        allowedResourceActions, ';'-separated) and `DataSources` (the assignment's appScopeIds, ';'-separated,
        blank = '/'). OWNER 2026-11-13 (3.1.21): PIM never creates, changes or deletes a Defender role. With a spec,
        the DefenderXdrRoles provider looks the role up by name and COMPARES it (Get-PimDefenderRoleVerdict): equal or
        narrower = the group is assigned (a narrower role is reported); wider / unknown = not assigned, reported;
        missing = held, reported. Without a spec a row binds an EXISTING role by name, exactly as before. A spec row in
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
    # 2026-11-13 (review): the ONE spec test (Get-PimDefenderRoleSpec) -- a Permissions value of only separators (';')
    # is NO spec here too, so such a row stays a by-name bind, consistently.
    if (-not (Get-PimDefenderRoleSpec -Row $Row)) { return $false }
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
    # EXCEPT the Defender spec rows, which DefenderXdrRoles serves (it compares the role's permissions, which the connector cannot).
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
    # ASSUMPTIONS (2026-11-13): "manage covers read" and "'*' matches 1+ segments". The live evidence: on 2026-11-12
    # Microsoft dropped 'microsoft.xdr/secops/rawdata/quarantineemailcontent/read' from a role that also holds
    # 'microsoft.xdr/secops/*/manage' -- it treats the wildcard as granting it (several segments, a read under a manage).
    param([string]$By, [string]$Action)
    $b = "$By".Trim().ToLowerInvariant(); $a = "$Action".Trim().ToLowerInvariant()
    if (-not $b -or -not $a -or $b -eq $a) { return $false }
    $bs = $b -split '/'; $as = $a -split '/'
    if ($bs.Count -lt 2 -or $as.Count -lt 2) { return $false }
    # 2026-11-13 (review, safe side): a LIVE action that itself has a '*' path segment is covered only by an action of the
    # SAME segment count (a wildcard is never assumed to fit inside a deeper or shallower pattern).
    if (@($as[0..($as.Count - 2)] | Where-Object { $_ -eq '*' }).Count -and $bs.Count -ne $as.Count) { return $false }
    $bv = $bs[-1]; $av = $as[-1]
    # 2026-11-13 (review): a trailing '*' VERB with nothing after it (e.g. 'microsoft.xdr/*') covers every DEEPER action under
    # its path too -- the '*' then stands for one or more segments, verb included.
    if ($bv -eq '*') {
        $bpx = @($bs[0..($bs.Count - 2)]) | ForEach-Object { if ($_ -eq '*') { '[^/]+(?:/[^/]+)*' } else { [regex]::Escape($_) } }
        if ($a -match ('^' + ($bpx -join '/') + '(?:/[^/]+)+$')) { return $true }
    }
    if (-not ($bv -eq $av -or $bv -eq '*' -or ($bv -eq 'manage' -and $av -eq 'read'))) { return $false }
    $bp = @($bs[0..($bs.Count - 2)]) | ForEach-Object { if ($_ -eq '*') { '[^/]+(?:/[^/]+)*' } else { [regex]::Escape($_) } }
    $ap = ($as[0..($as.Count - 2)]) -join '/'
    return ($ap -match ('^' + ($bp -join '/') + '$'))
}

function Get-PimDefenderEffectiveActions {
    # test/compat only (2026-11-13: no engine caller left -- the compare is Test-PimDefenderActionSetEquivalent).
    # PURE. The spec's actions as Defender STORES them: an action another spec action already grants is dropped.
    # 2026-09-21 (operator: "bug: looks wrong" -- four "wrong permissions" warnings + "changed" every run): the pack lists
    # 'microsoft.xdr/secops/*/manage;microsoft.xdr/secops/rawdata/quarantineemailcontent/read'; Defender keeps only the
    # wildcard (it covers the read), so live never equalled the spec and the engine re-planned an UPDATE forever.
    param([AllowNull()][object[]]$Actions)
    $all = @($Actions | Where-Object { "$_".Trim() } | ForEach-Object { "$_".Trim() })
    return @($all | Where-Object { $x = $_; -not @($all | Where-Object { Test-PimDefenderActionCovers -By $_ -Action $x }).Count })
}

function Test-PimDefenderActionSetEquivalent {
    # PURE. Do two Defender action sets grant the SAME access? Every action of A is in B (case-insensitive) or granted by
    # an action of B (Test-PimDefenderActionCovers), AND every action of B likewise by A. 2026-11-13 (a customer, every
    # delta-workloads run red): Microsoft stopped returning 'microsoft.xdr/secops/rawdata/quarantineemailcontent/read' next
    # to 'microsoft.xdr/secops/*/manage' (the wildcard grants it), so a strict compare called the role "different" and the
    # update path threw DEFENDER-ROLE-NOT-OWN on a role whose access was exactly the template's. Compare only: what PIM
    # WRITES is always the spec's own action list.
    param([AllowNull()][object[]]$A, [AllowNull()][object[]]$B)
    $la = @(@($A) | Where-Object { "$_".Trim() } | ForEach-Object { "$_".Trim() })
    $lb = @(@($B) | Where-Object { "$_".Trim() } | ForEach-Object { "$_".Trim() })
    foreach ($pair in @(@{ x = $la; y = $lb }, @{ x = $lb; y = $la })) {
        foreach ($act in @($pair.x)) {
            $hit = $false
            foreach ($by in @($pair.y)) { if ($by -ieq $act -or (Test-PimDefenderActionCovers -By $by -Action $act)) { $hit = $true; break } }
            if (-not $hit) { return $false }
        }
    }
    return $true
}

function Test-PimDefenderRoleRestricted {
    # PURE. Does a live Defender role (a catalog entry) carry excludedResourceActions or a condition? A spec has neither, so
    # such a role is never "equal" to one (the safe direction: an exclusion PIM did not ask for is a difference).
    param([AllowNull()][object]$Role)
    if ($null -eq $Role) { return $false }
    $e = $Role.PSObject.Properties['excludedActions']; $c = $Role.PSObject.Properties['hasCondition']
    return ([bool]($e -and @(@($e.Value) | Where-Object { "$_".Trim() }).Count) -or [bool]($c -and $c.Value))
}

function Get-PimDefenderRoleVerdict {
    # PURE. OWNER 2026-11-13 (wizard, with examples): how a live role's ACTIONS relate to the definition's, own or not:
    #   equal    -- each side covers the other (Test-PimDefenderActionSetEquivalent)
    #   narrower -- every live action is equal to / covered by a spec action, but not equal: the group gets LESS -> assign + report
    #   wider    -- some live action is NOT covered by the spec (manage instead of read, another area, a wildcard the
    #               definition lacks): the group would get MORE -> never assigned, report
    #   unknown  -- the live role carries excluded actions or a condition: the direction cannot be told -> the safe side (= wider)
    # { dir; extra = live actions the spec does not cover; missing = spec actions the live role does not cover }
    param([AllowNull()][object]$Role, [AllowNull()][object[]]$Actions)
    $la = @(@($(if ($Role) { $Role.actions })) | Where-Object { "$_".Trim() } | ForEach-Object { "$_".Trim() })
    $sa = @(@($Actions) | Where-Object { "$_".Trim() } | ForEach-Object { "$_".Trim() })
    $covered = { param($act, $set) foreach ($by in @($set)) { if ($by -ieq $act -or (Test-PimDefenderActionCovers -By $by -Action $act)) { return $true } }; return $false }
    $extra = @($la | Where-Object { -not (& $covered $_ $sa) })
    $missing = @($sa | Where-Object { -not (& $covered $_ $la) })
    # 2026-11-13 (review, dangerous direction): a live role with ZERO actions (rolePermissions missing, an odd Microsoft
    # shape during an outage) is UNKNOWN, never "narrower" -- PIM could not read its permissions, so it is not assigned.
    $why = ''
    $dir = if (Test-PimDefenderRoleRestricted -Role $Role) { $why = 'restricted'; 'unknown' } elseif (-not $la.Count) { $why = 'unreadable'; 'unknown' } elseif ($extra.Count) { 'wider' } elseif ($missing.Count) { 'narrower' } else { 'equal' }
    return [pscustomobject]@{ dir = $dir; extra = $extra; missing = $missing; why = $why }
}

function Get-PimDefenderRoleVerdictText {
    # PURE. The ONE wording of a role-permission difference (engine warning, drift finding, catalogue): '' for equal.
    #   -Assigned: the group already holds the role (the update path) -- a wider role is then reported, never removed.
    param([string]$Name, [string]$RoleId, [object]$Verdict, [string[]]$Actions = @(), [switch]$Assigned, [string]$Detail = '')
    $id = if ("$RoleId".Trim()) { " (id $RoleId)" } else { '' }
    switch ("$($Verdict.dir)") {
        'narrower' {
            return ("DEFENDER-ROLE-DIFFERS: the Defender XDR role '{0}'{1} has fewer permissions than its definition (missing: [{2}]). PIM Manager never changes a Defender role; the group's assignment is {3}. If that is not intended, change the role in the Defender portal (Settings > Permissions > Roles) or the definition. Report only.{4}" -f $Name, $id, (@($Verdict.missing) -join '; '), $(if ($Assigned) { 'kept' } else { 'added' }), $Detail)
        }
        'wider' {
            if ($Assigned) { return ("DEFENDER-ROLE-WIDER: the Defender role '{0}'{1} grants more than its definition ([{2}]); the group already holds it and PIM never removes it (removing it is yours). Change the role in the Defender portal or the definition.{3}" -f $Name, $id, (@($Verdict.extra) -join '; '), $Detail) }
            return ("DEFENDER-ROLE-WIDER: the Defender role '{0}'{1} grants more than its definition ([{2}]); PIM did not assign it to the group. Change the role in the Defender portal or the definition.{3}" -f $Name, $id, (@($Verdict.extra) -join '; '), $Detail)
        }
        'unknown' {
            $tail = if ($Assigned) { 'the group already holds it and PIM never removes it (removing it is yours)' } else { 'PIM did not assign it to the group' }
            if ("$($Verdict.why)" -eq 'unreadable') {
                return ("DEFENDER-ROLE-WIDER: PIM could not read the role's permissions -- the Defender role '{0}'{1} lists no actions, so PIM cannot tell whether it grants more than its definition; {2}. Check the role in the Defender portal or the definition.{3}" -f $Name, $id, $tail, $Detail)
            }
            return ("DEFENDER-ROLE-WIDER: the Defender role '{0}'{1} carries excluded actions or a condition, so PIM cannot tell whether it grants more than its definition; {2}. Change the role in the Defender portal or the definition.{3}" -f $Name, $id, $tail, $Detail)
        }
    }
    return ''
}

function Get-PimDefenderDataSourceDirection {
    # PURE. How the LIVE assignment's data sources relate to the spec's: 'equal' | 'narrower' | 'wider'.
    # '/' or a blank list = ALL (and future) data sources. live all vs spec explicit = wider; live explicit vs spec all =
    # narrower; both explicit: live a subset of the spec = narrower, a source the spec lacks = wider (also a partial
    # overlap). 2026-11-13 (review): only 'wider' means the group holds MORE access than its definition.
    param([AllowNull()][object[]]$Live, [AllowNull()][object[]]$Spec)
    $l = @(@($Live) | Where-Object { "$_".Trim() } | ForEach-Object { "$_".Trim() })
    $s = @(@($Spec) | Where-Object { "$_".Trim() } | ForEach-Object { "$_".Trim() })
    $lAll = (-not $l.Count) -or (@($l | Where-Object { $_ -eq '/' }).Count -gt 0)
    $sAll = (-not $s.Count) -or (@($s | Where-Object { $_ -eq '/' }).Count -gt 0)
    if ($lAll -and $sAll) { return 'equal' }
    if ($lAll) { return 'wider' }
    if ($sAll) { return 'narrower' }
    if (Test-PimWorkloadStringSetEqual -A $l -B $s) { return 'equal' }
    if (@($l | Where-Object { $x = $_; -not @($s | Where-Object { $_ -ieq $x }).Count }).Count) { return 'wider' }
    return 'narrower'
}

function Get-PimDefenderSpecDifference {
    # PURE. How a live Defender binding differs from its spec: '' when it matches (or the row has no spec).
    #   -Desired: a desired binding (Permissions / DataSources); -LiveActions: the role's live allowedResourceActions;
    #   -LiveDataSources: the assignment's live appScopeIds ($null = no assignment to compare).
    #   -LiveRestricted: the live role carries excludedResourceActions or a condition (always a difference).
    param([AllowNull()][object]$Desired, [AllowNull()][object[]]$LiveActions, [AllowNull()][object[]]$LiveDataSources, [switch]$LiveRestricted)
    $spec = Get-PimDefenderRoleSpec -Row $Desired
    if (-not $spec) { return '' }
    $parts = New-Object System.Collections.Generic.List[string]
    if ($LiveRestricted) { $parts.Add('actions: the live role carries excluded actions or a condition, the spec has none') }
    elseif (-not (Test-PimDefenderActionSetEquivalent -A @($LiveActions) -B @($spec.actions))) {
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
    $la = @(); $ld = @(); $lr = $false
    if ($null -ne $Live) {
        $p = $Live.PSObject.Properties['roleActions']; if ($p) { $la = @($p.Value) }
        $q = $Live.PSObject.Properties['appScopeIds']; if ($q) { $ld = @($q.Value) }
        $r = $Live.PSObject.Properties['roleRestricted']; if ($r) { $lr = [bool]$r.Value }
    }
    return (-not (Get-PimDefenderSpecDifference -Desired $Desired -LiveActions $la -LiveDataSources $ld -LiveRestricted:$lr))
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
            # 2026-11-13: excludedResourceActions and a condition are read too -- a live role that carries either is never
            # "equal" to a spec (which has neither); see Test-PimDefenderRoleRestricted.
            $excl = New-Object System.Collections.Generic.List[string]; $cond = $false
            foreach ($rp in @($r.rolePermissions)) {
                if ($null -eq $rp) { continue }
                foreach ($a in @($rp.allowedResourceActions)) { if ("$a".Trim()) { $acts.Add("$a".Trim()) } }
                if ($rp.PSObject.Properties['excludedResourceActions']) { foreach ($x in @($rp.excludedResourceActions)) { if ("$x".Trim()) { $excl.Add("$x".Trim()) } } }
                if ($rp.PSObject.Properties['condition'] -and "$($rp.condition)".Trim()) { $cond = $true }
            }
            $bi = $false; if ($r.PSObject.Properties['isBuiltIn'] -and $null -ne $r.isBuiltIn) { $bi = [bool]$r.isBuiltIn }
            $roles.Add([pscustomobject]@{ id = $id; name = $n; isBuiltIn = $bi; actions = @($acts.ToArray()); description = "$($r.description)"; excludedActions = @($excl.ToArray()); hasCondition = $cond })
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
    # DEAD HELPER: no engine caller since 3.1.21 (owner 2026-11-13: PIM never creates, changes or deletes a Defender role). Kept for its tests only.
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
    # DEAD HELPER: no engine caller since 3.1.21 (owner 2026-11-13: PIM never creates, changes or deletes a Defender role). Kept for its tests only.
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
      roleAssignment: The roleAssignment field is required." (every Defender create on both test tenants and internal, 2.4.379 and
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
    # DEAD HELPER: no engine caller since 3.1.21 (owner 2026-11-13: PIM never creates, changes or deletes a Defender role). Kept for its tests only.
    # Re-read the live Defender role definitions and return the id of the ONE role named -Name ('' when none / several).
    param([Parameter(Mandatory)][string]$Name)
    $all = @(Invoke-PimGraph -Beta -All -Path '/roleManagement/defender/roleDefinitions')
    $hits = @($all | Where-Object { "$($_.displayName)" -ieq $Name })
    if ($hits.Count -eq 1) { return "$($hits[0].id)" }
    return ''
}

if (-not (Get-Command Get-PimUtcStamp -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot 'PIM-DateSafe.ps1') }   # IMP-02 reader (the create-pending marker)
$script:PimDefenderManagedRoleDescription = 'Managed by PIM4EntraPS: the custom Defender XDR role of the permission group of the same name.'

function Get-PimDefenderManagedRoleDescription {
    # The marker every role PIM Manager creates carries, as a LITERAL (a $script: value read from a child scope can be
    # $null; a null marker must never read as "every role is ours" -- nor as "no role is ours" without saying so).
    return 'Managed by PIM4EntraPS: the custom Defender XDR role of the permission group of the same name.'
}

function Test-PimDefenderRoleIsOwn {
    <#
      PURE. 100.122 F5. Is this live Defender XDR role PIM Manager's OWN -- a custom role (not built-in) that carries the
      description PIM Manager writes when it creates one? The same test the duplicate clean-up applies before a DELETE.
      Anything else ($null, a built-in role, another description, no description) is NOT own.
    #>
    param([AllowNull()][object]$Role)
    if ($null -eq $Role) { return $false }
    if ($Role.isBuiltIn) { return $false }
    return ("$($Role.description)".Trim() -ceq (Get-PimDefenderManagedRoleDescription))
}

function Get-PimDefenderDuplicateRolePlan {
    # DEAD HELPER: no engine caller since 3.1.21 (owner 2026-11-13: PIM never creates, changes or deletes a Defender role). Kept for its tests only.
    <#
      PURE. Two or more live roles share a name. They are healed ONLY when every one is PIM's OWN custom role (not built-in,
      PIM's description) and at most ONE carries an assignment: keep that one (or the first when none is assigned), delete
      the rest. Anything else returns $null and stays DEFENDER-ROLE-AMBIGUOUS -- PIM never deletes a role it did not make or
      one somebody assigned.
      Measured 2026-09-26 on a test tenant: 2x 'PIM-Defender-XDR-DataOperations-Operator-L3-T1-MP-ID' and 2x '...-Reader-L4-T1-MP-ID',
      mailed as a drift warning every 4 hours -- the create was redirected, not read back in time, and POSTed again.
    #>
    param([Parameter(Mandatory)][object[]]$Hits, [AllowEmptyCollection()][string[]]$AssignedRoleIds = @())
    $hs = @($Hits | Where-Object { $_ })
    if ($hs.Count -lt 2) { return $null }
    # OWNER RULE (2026-11-13: "never ever touch builtin"): the ONE own-role test gates every delete -- built-in, or not
    # PIM's exact description (case-sensitive, as Test-PimDefenderRoleIsOwn), = no plan.
    foreach ($h in $hs) {
        if ($h.isBuiltIn) { return $null }
        if (-not (Test-PimDefenderRoleIsOwn -Role $h)) { return $null }
    }
    $asg = @{}; foreach ($a in @($AssignedRoleIds)) { if ("$a".Trim()) { $asg["$a".Trim().ToLowerInvariant()] = $true } }
    $assigned = @($hs | Where-Object { $asg.ContainsKey("$($_.id)".ToLowerInvariant()) })
    if ($assigned.Count -gt 1) { return $null }
    $keep = if ($assigned.Count -eq 1) { $assigned[0] } else { $hs[0] }
    return [pscustomobject]@{ keep = "$($keep.id)"; delete = @($hs | Where-Object { "$($_.id)" -ne "$($keep.id)" } | ForEach-Object { "$($_.id)" }) }
}

function Repair-PimDefenderDuplicateRoles {
    <#
      RETIRED (OWNER 2026-11-13: "we dont own perm in any system"). It used to DELETE duplicate Defender XDR roles PIM had
      made. PIM never deletes a Defender role definition now: a name two live roles share stays DEFENDER-ROLE-AMBIGUOUS (a
      refusal; the customer renames or deletes the extra role in the Defender portal). Kept as a no-op for its callers.
    #>
    param([Parameter(Mandatory)]$Catalog, [string[]]$Names = @())
    return @()
}

function Get-PimDefenderCreatePending {
    # DEAD HELPER: no engine caller since 3.1.21 (owner 2026-11-13: PIM never creates, changes or deletes a Defender role). Kept for its tests only.
    # The names whose create was ANSWERED (redirect) but not yet listed, with when: pim.Settings['DefenderRoleCreatePending'].
    $h = @{}
    try { $raw = Get-PimSetting -Name 'DefenderRoleCreatePending'; if ($raw) { $o = if ($raw -is [string]) { $raw | ConvertFrom-Json } else { $raw }; foreach ($p in $o.PSObject.Properties) { $h[$p.Name] = $p.Value } } } catch { }   # the RAW value: pwsh 7 made a [datetime] of the ISO text, and "$dt" loses its UTC kind
    return $h
}
function Set-PimDefenderCreatePending {
    # DEAD HELPER: no engine caller since 3.1.21 (owner 2026-11-13: PIM never creates, changes or deletes a Defender role). Kept for its tests only.
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
      READ-ONLY (OWNER 2026-11-13: "we dont own perm in any system" / wizard "Only add assignments", and the wizard
      decision with examples: own or not makes no difference). The live Defender XDR role a spec binding names, found by
      NAME. PIM NEVER creates, patches or deletes a Defender role definition; the spec's Permissions are only COMPARED
      (Get-PimDefenderRoleVerdict) and reported -- the job never fails on a difference:
        no live role of the name -> DEFENDER-ROLE-MISSING (pim-def-0108) warning, returns $null: the caller HOLDS the assignment
        two or more              -> DEFENDER-ROLE-AMBIGUOUS (thrown: a refusal, as before) -- no duplicate heal
        one, equal               -> its id
        one, NARROWER            -> DEFENDER-ROLE-DIFFERS (pim-def-0109) warning, returns its id: the group IS assigned
        one, WIDER / unknown     -> DEFENDER-ROLE-WIDER (pim-def-0110) warning, returns $null: never assigned; with
                                    -Assigned (the group already holds it) reported only, never removed
      DEFENDER-ROLE-NOT-OWN (pim-def-0104) is no longer raised (kept as a pinned key).
    #>
    #   -DataSources / -LiveDataSources (optional): the spec's and the live assignment's appScopeIds -- only printed.
    #   -Warnings (optional): a list the report-only lines are added to (the scope's warnings).
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][string[]]$Actions, [AllowNull()][object]$Catalog,
          [AllowNull()][object[]]$DataSources, [AllowNull()][object[]]$LiveDataSources, [AllowNull()][System.Collections.IList]$Warnings,
          [switch]$Assigned)
    $cat = if ($Catalog) { $Catalog } else { Get-PimDefenderRoleCatalog }
    if (-not $cat.ok) { throw "DefenderXdrRoles: the Defender XDR role catalog could not be read -- the role '$Name' was not checked: $($cat.error)" }
    $hits = @(); if ($cat.byName.ContainsKey($Name.ToLowerInvariant())) { $hits = @($cat.byName[$Name.ToLowerInvariant()]) }
    $__say = { param($m) Write-Warning "  [DefenderXdrRoles] $m"; if ($null -ne $Warnings) { [void]$Warnings.Add($m) } }
    if ($hits.Count -gt 1) {
        throw ("DEFENDER-ROLE-AMBIGUOUS: {0} live Defender XDR roles are named '{1}' (ids {2}) -- PIM will not pick one. Rename or delete the extra role in the Defender portal (Settings > Permissions > Roles), then the next run binds the one that is left." -f $hits.Count, $Name, (@($hits | ForEach-Object { $_.id }) -join ', '))
    }
    if ($hits.Count -eq 1) {
        $role = $hits[0]
        $v = Get-PimDefenderRoleVerdict -Role $role -Actions @($Actions)
        if ($v.dir -eq 'equal') { return "$($role.id)" }
        $__lsl = @(@($LiveDataSources) | Where-Object { "$_".Trim() }); $__ssl = @(@($DataSources) | Where-Object { "$_".Trim() })
        $__ls = if ($__lsl.Count) { $__lsl -join '; ' } else { 'none (no assignment)' }
        $__ss = if ($__ssl.Count) { $__ssl -join '; ' } else { 'none (no assignment)' }
        $__la = @(@($role.actions) | Where-Object { "$_".Trim() }) -join '; '
        if (Test-PimDefenderRoleRestricted -Role $role) { $__la += ' (plus excluded actions or a condition)' }
        $__detail = (" Live actions: [{0}]. Spec actions: [{1}]. Live data sources: [{2}]. Spec data sources: [{3}]." -f $__la, (@($Actions) -join '; '), $__ls, $__ss)
        & $__say (Get-PimDefenderRoleVerdictText -Name $Name -RoleId "$($role.id)" -Verdict $v -Actions @($Actions) -Assigned:$Assigned -Detail $__detail)
        if ($v.dir -eq 'narrower') { return "$($role.id)" }
        return $null
    }
    # No live role of that name: PIM never CREATES a Defender role -- reported, and the caller HOLDS the assignment.
    & $__say (Get-PimDefenderRoleMissingText -Name $Name -Actions @($Actions))
    return $null
}

function Get-PimDefenderRoleMissingText {
    # PURE. The ONE wording of DEFENDER-ROLE-MISSING (engine warning + drift finding). -Actions empty = a binding without a
    # spec (no permissions list: the role is named, not described).
    param([string]$Name, [string[]]$Actions = @())
    $a = @(@($Actions) | Where-Object { "$_".Trim() })
    $what = if ($a.Count) { "create it in the Defender portal (Settings > Permissions > Roles) with these permissions: [$($a -join '; ')]" } else { 'create it in the Defender portal (Settings > Permissions > Roles), or correct the role name in the binding' }
    return ("DEFENDER-ROLE-MISSING: the Defender XDR role '{0}' does not exist -- {1}. PIM Manager never creates a Defender role; the group's assignment is held (not created) until the role exists, and the next run assigns it." -f $Name, $what)
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
        role-missing       -- (Defender, 2026-11-13) a spec'd role that does not exist: the DEFENDER-ROLE-MISSING text (PIM
                              never creates it); its group is then NOT an orphan-group. wrong-permissions carries `code`
                              DEFENDER-ROLE-DIFFERS (narrower) / DEFENDER-ROLE-WIDER (wider / unknown) for an action difference.
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
    # 2026-11-13: a spec'd tag whose role is NOT in the catalogue is a role-missing finding (section 3, the
    # DEFENDER-ROLE-MISSING text), never an orphan group.
    $roleMissingTags = @{}
    if ($Kind -eq 'defender' -and $Catalog -and $Catalog.byName) {
        foreach ($s in @($SpecBindings)) {
            $rn0 = Get-PimWlRoleField -Row $s -Names @('RoleDefinitionName', 'RoleName'); $t0 = Get-PimWlRoleField -Row $s -Names @('GroupTag')
            if ($rn0 -and $t0 -and (Get-PimDefenderRoleSpec -Row $s) -and -not $Catalog.byName.ContainsKey($rn0.ToLowerInvariant())) { $roleMissingTags[$t0.ToLowerInvariant()] = $true }
        }
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
        if ($tag -and $roleMissingTags.ContainsKey($tag.ToLowerInvariant())) { continue }   # role-missing (section 3), not an orphan
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
            if ($hits.Count -eq 0) {
                # 2026-11-13: PIM never creates the role -- a role-missing finding with the DEFENDER-ROLE-MISSING text (name +
                # permissions), keyed to the binding so the drift snapshot counts it once with the plan's create.
                $out.Add([pscustomobject]@{ type = 'warning'; kind = 'role-missing'; code = 'DEFENDER-ROLE-MISSING'; key = $bk; group = $gn; role = $rn
                    label = (Get-PimDefenderRoleMissingText -Name $rn -Actions @($spec.actions)); relatedKeys = @($bk) })
                continue
            }
            $role = $hits[0]
            $gid = if ($tag -and $SpecGidByTag.ContainsKey($tag.ToLowerInvariant())) { "$($SpecGidByTag[$tag.ToLowerInvariant()])".ToLowerInvariant() } else { '' }
            # 2026-11-13 (review): the group id not resolved for the spec -> the PIM-owned group carrying the tag, so the text
            # never says "PIM did not assign it" while the group holds the role.
            if (-not $gid -and $tag -and $ownedTag.ContainsKey($tag.ToLowerInvariant())) { $gid = "$($ownedTag[$tag.ToLowerInvariant()])" }
            $ds = $null
            if ($gid) {
                $mine = @(@($Assignments) | Where-Object { $_ -and "$($_.roleDefinitionId)" -ieq "$($role.id)" -and (@($_.principals) | Where-Object { "$_" -ieq $gid }) })
                if ($mine.Count) {
                    $ds = @($mine[0].appScopeIds)
                    foreach ($m in $mine) { if (Test-PimWorkloadStringSetEqual -A @($m.appScopeIds) -B @($spec.dataSources)) { $ds = @($m.appScopeIds); break } }
                }
            }
            # 2026-11-13: the same restriction rule as the plan's Equal (an exclusion / condition is a difference), so the
            # drift page and the plan agree.
            $diff = Get-PimDefenderSpecDifference -Desired $s -LiveActions @($role.actions) -LiveDataSources $ds -LiveRestricted:(Test-PimDefenderRoleRestricted -Role $role)
            if (-not $diff) { continue }
            # 2026-11-13: an ACTION difference carries its code + the engine's own wording (narrower = DEFENDER-ROLE-DIFFERS,
            # wider / unknown = DEFENDER-ROLE-WIDER), so the Manager shows the customer step; a data-source-only one keeps the old label.
            $v = Get-PimDefenderRoleVerdict -Role $role -Actions @($spec.actions)
            $vt = Get-PimDefenderRoleVerdictText -Name $rn -RoleId "$($role.id)" -Verdict $v -Actions @($spec.actions) -Assigned:([bool]($null -ne $ds))
            $code = if ("$vt" -match '^(DEFENDER-ROLE-(DIFFERS|WIDER)):') { $Matches[1] } else { '' }
            $out.Add([pscustomobject]@{
                type = 'warning'; kind = 'wrong-permissions'; code = $code; key = $bk; group = $gn; role = $rn
                label = $(if ($vt) { "$vt -- group '$gn'; $diff" } else { "wrong permissions: Defender XDR role '{0}' (group '{1}') differs from its spec -- {2}" -f $rn, $gn, $diff })
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
