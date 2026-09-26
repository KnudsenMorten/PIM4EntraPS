#Requires -Version 5.1
<#
.SYNOPSIS
    REQ-O -- the REPLICATION OVERVIEW: every replicable row on the MSP master, grouped by kind, with its effective
    Replicate / Ring / Target in plain words and the managed tenants it reaches.

.DESCRIPTION
    Operator 2026-09-19: "i also need a wizard to list all direct and indirect delegations and roles that should be
    replicated downlinks to which". The Managed tenants page's "reach by group tag" covers admin memberships only; this
    covers everything the bundle can carry: admins, memberships, direct groups, permission groups, nestings, Entra role
    bindings and resource bindings.

    🔒 THE REACH IS THE PLAN'S OWN ANSWER, NEVER A SECOND OPINION. Get-PimReplicationOverview composes
    Get-PimReplicationPreview (PIM-DownlinkManager.ps1): the producer's own selection, signed with a throwaway key, run
    through the SAME Get-PimDownlinkPlan every managed tenant runs, once per registered tenant. Nothing here decides
    whether a row reaches a tenant; it only lays the preview's answer out per row. The browser only filters what the
    server computed.

    🔒 BUG-175 -- EVERY RING IS LOCAL IN THE MANAGED TENANT. The preview plans each tenant with the MASTER'S COPY of its
    ring (platform.Tenants.Ring); the tenant's own ring gates its real pull. The result says so (ringSource/ringNote).

    🔒 NOT CHECKED IS NOT "REACHES NONE". A tenant whose plan failed is listed in notChecked, and a row is only called
    "reaches no tenant" when every tenant was actually planned.

    PS 5.1 COMPATIBLE: no ?. / ??, no ternary, null-guarded.
#>

Set-StrictMode -Off

if ($PSScriptRoot -and -not (Get-Command Get-PimReplicationPreview -ErrorAction SilentlyContinue)) {
    $__dm = Join-Path $PSScriptRoot 'PIM-DownlinkManager.ps1'
    if (Test-Path -LiteralPath $__dm) { . $__dm }
}

# The kinds, in the order the page shows them. entities = the pim.Rows entities whose rows belong to the group.
$script:PimReplOverviewGroups = @(
    [ordered]@{ key = 'admins';           label = 'Admins';                                                         kind = 'admin';      entities = @('Account-Definitions-Admins') }
    [ordered]@{ key = 'memberships';      label = 'Admin memberships (admin -> direct group)';                      kind = 'membership'; entities = @('PIM-Assignments-Admins') }
    [ordered]@{ key = 'directGroups';     label = 'Direct groups (role, organisation, department, project, cross-org)'; kind = 'group';   entities = @('PIM-Definitions-Roles', 'PIM-Definitions-Organization', 'PIM-Definitions-Departments', 'PIM-Definitions-Projects', 'PIM-Definitions-CrossOrg') }
    [ordered]@{ key = 'permissionGroups'; label = 'Permission groups (tasks, services, processes)';                  kind = 'group';      entities = @('PIM-Definitions-Tasks', 'PIM-Definitions-Services', 'PIM-Definitions-Processes') }
    [ordered]@{ key = 'nestings';         label = 'Nestings (direct group -> permission group)';                     kind = 'nesting';    entities = @('PIM-Assignments-Groups') }
    [ordered]@{ key = 'roleBindings';     label = 'Entra role bindings';                                             kind = 'binding';    entities = @('PIM-Assignments-Roles-Groups') }
    [ordered]@{ key = 'resourceBindings'; label = 'Resource bindings (AU-scoped roles, Azure resources, workloads)'; kind = 'resource';   entities = @('PIM-Assignments-Roles-AUs', 'PIM-Assignments-Azure-Resources', 'PIM-Assignments-Workloads') }
)

function Get-PimReplicationOverviewGroups {
    # PURE. A copy of the kind catalog (key, label, kind, entities).
    return @($script:PimReplOverviewGroups | ForEach-Object { [ordered]@{ key = $_.key; label = $_.label; kind = $_.kind; entities = @($_.entities) } })
}

function Get-PimReplicationWording {
    <#
      PURE. One row's effective Replicate / Ring / Target in the REQ-M plain words -- the same words the grid and the
      wizards use (replModeOptions / replRingLabel in the Manager). Returns
      @{ replicate = @{ mode; text; reason; valid; explicit }; ring = @{ value; text }; target = @{ value; text } }.
      -TenantNames: tenant id (lowercase) -> name, so a tenant:<id> term reads as the tenant's name.
    #>
    param(
        [object]$Row,
        [Parameter(Mandatory)][ValidateSet('admin', 'membership', 'group', 'nesting', 'binding', 'resource')][string]$Kind,
        [ValidateSet('Definition', 'Registry')][string]$AdminSource = 'Definition',
        [hashtable]$TenantNames = @{}
    )
    $m = if ($Kind -eq 'admin') { Get-PimReplicateMode -Row $Row -Kind $Kind -AdminSource $AdminSource } else { Get-PimReplicateMode -Row $Row -Kind $Kind }
    $rtext = switch ("$($m.mode)") {
        'Yes'    { 'Replicate to managed tenants' }
        'Follow' { 'Follow (default) -- sent only when a replicated row needs it' }
        default  {
            if (-not $m.valid) { 'No replication -- the value is refused (treated as master tenant only)' }
            elseif ($Kind -eq 'admin') { 'Master tenant only -- no replication to managed tenants' }
            elseif ($Kind -eq 'resource' -and -not $m.explicit) { 'Master tenant only (default) -- a tenant-specific resource is not replicated' }
            else { 'No replication to managed tenants -- master tenant only' }
        }
    }
    $ringRaw = "$(Get-PimDownlinkValue -Object $Row -Key 'Ring')".Trim()
    $ringText = ''
    if (-not $ringRaw) { $ringText = if ($Kind -eq 'admin') { 'No ring -- an admin without a ring reaches no managed tenant' } else { 'Any ring -- not narrowed by ring' } }
    elseif ($ringRaw -notmatch '^[0-2]$') { $ringText = "Ring '$ringRaw' is not a ring (0 dev, 1 test, 2 broad) -- reaches no managed tenant" }
    elseif ($ringRaw -eq '0') { $ringText = 'Ring 0 (dev) -- dev tenants only' }
    elseif ($ringRaw -eq '1') { $ringText = 'Ring 1 (test) -- dev + test tenants' }
    elseif ($ringRaw -eq '2') { $ringText = 'Ring 2 (broad) -- every managed tenant' }
    else { $ringText = "Ring $ringRaw -- not a ring" }

    $tgtRaw = "$(Get-PimDownlinkValue -Object $Row -Key 'Target')".Trim()
    $tgtText = 'Every tenant the ring admits'
    if ($tgtRaw) {
        $parts = New-Object System.Collections.Generic.List[string]
        $none = $false
        foreach ($tok in @($tgtRaw -split '[;,]' | ForEach-Object { "$_".Trim() } | Where-Object { $_ })) {
            $l = $tok.ToLowerInvariant()
            if ($l -eq 'none') { $none = $true; continue }
            if ($l -in @('*', 'all')) { $parts.Add('every tenant the ring admits') | Out-Null; continue }
            if ($l -like 'tenant:*') {
                $id = $l.Substring(7).Trim()
                $nm = if ($TenantNames.ContainsKey($id)) { "$($TenantNames[$id])" } else { '' }
                $parts.Add($(if ($nm) { "tenant $nm" } else { "tenant $id (not registered)" })) | Out-Null
                continue
            }
            $tag = if ($l -like 'tag:*') { $tok.Substring(4).Trim() } else { $tok }
            $ps = @($tag -split '\+' | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
            if ($ps.Count -gt 1) { $parts.Add("tenants tagged $($ps -join ' AND ')") | Out-Null } else { $parts.Add("tenants tagged $tag") | Out-Null }
        }
        if ($none) { $tgtText = 'none -- master tenant only (never replicated)' }
        elseif ($parts.Count) { $tgtText = ($parts.ToArray() -join ' OR ') }
    }
    return [ordered]@{
        replicate = [ordered]@{ mode = "$($m.mode)"; text = $rtext; reason = "$($m.reason)"; valid = [bool]$m.valid; explicit = [bool]$m.explicit }
        ring      = [ordered]@{ value = $ringRaw; text = $ringText }
        target    = [ordered]@{ value = $tgtRaw; text = $tgtText }
    }
}

function Get-PimReplicationRowOwnReach {
    # PURE. Would this row's OWN fields admit the tenant (Replicate + Ring + Target, the rule Test-PimReplicationReach
    # applies)? Used only to EXPLAIN a row that reaches no tenant -- never to decide reach. Returns @{ reach; reason }.
    param([object]$Row, [Parameter(Mandatory)][string]$Kind, [string]$AdminSource = 'Definition', [Parameter(Mandatory)][object]$Tenant, [object[]]$DeploymentRings = @())
    $tid = "$($Tenant.tenantId)"; $ring = [int]$Tenant.ring; $tags = @($Tenant.tags)
    if ($Kind -eq 'admin') {
        $m = Get-PimReplicateMode -Row $Row -Kind 'admin' -AdminSource $AdminSource
        if ($m.mode -eq 'No') { return @{ reach = $false; reason = "$($m.reason)" } }
        $rg = Test-PimReplicationRingAdmits -Row $Row -Kind 'admin' -TenantRing $ring
        if (-not $rg.admits) { return @{ reach = $false; reason = "$($rg.reason)" } }
        if (@($DeploymentRings).Count) {
            $mem = Test-PimDeploymentRingMember -Rings @($DeploymentRings) -SlaveRing $ring -TenantId $tid -TenantTags $tags
            if (-not $mem.member) { return @{ reach = $false; reason = "$($mem.reason)" } }
        }
        $tv = Test-PimArtifactTarget -Target "$(Get-PimDownlinkValue -Object $Row -Key 'Target')" -TenantId $tid -TenantTags $tags
        if (-not $tv.match) { return @{ reach = $false; reason = "$($tv.reason)" } }
        return @{ reach = $true; reason = '' }
    }
    $r = Test-PimReplicationReach -Row $Row -Kind $Kind -TenantId $tid -TenantRing $ring -TenantTags $tags -DeploymentRings @($DeploymentRings)
    return @{ reach = [bool]$r.reach; reason = "$($r.reason)" }
}

function Get-PimReplicationRowTitle {
    # PURE. What the page shows as the row's name, per kind.
    param([Parameter(Mandatory)][string]$Kind, [string]$Entity, [object]$Row)
    $v = { param($k) "$(Get-PimDownlinkValue -Object $Row -Key $k)".Trim() }
    switch ($Kind) {
        'admin'      { $u = & $v 'UserName'; if (-not $u) { $u = & $v 'UserPrincipalName' }; $d = & $v 'DisplayName'; if ($d -and $d -ne $u) { return "$u ($d)" }; return $u }
        'membership' { $u = & $v 'Username'; if (-not $u) { $u = & $v 'UserName' }; return "$u -> $(& $v 'GroupTag')" }
        'group'      { $n = & $v 'GroupName'; $t = & $v 'GroupTag'; if ($n -and $n -ne $t) { return "$t ($n)" }; return $t }
        'nesting'    { return "$(& $v 'SourceGroupTag') -> $(& $v 'TargetGroupTag')" }
        'binding'    { return "$(& $v 'GroupTag') -> $(& $v 'RoleDefinitionName')" }
        'resource'   {
            $what = @('RoleDefinitionName', 'AdministrativeUnitTag', 'Scope', 'Workload', 'Role') | ForEach-Object { & $v $_ } | Where-Object { $_ } | Select-Object -First 2
            $short = "$Entity" -replace '^PIM-Assignments-', ''
            return ("{0}: {1}{2}" -f $short, (& $v 'GroupTag'), $(if (@($what).Count) { ' -> ' + (@($what) -join ' @ ') } else { '' }))
        }
    }
    return ''
}

function Get-PimReplicationOverview {
    <#
      PURE except for the clock and the preview's throwaway key. -Model is Get-PimReplicationMasterModel's result
      (RegistryRows, RegistryReplicate, Entities, Tenants, ProjectionPolicy). -Preview may be passed (a test, or a caller
      that already has one); otherwise it is computed here with the same inputs.
      Returns @{ master; computedUtc; tenants; tenantCount; groups = @( @{ key; label; kind; rows = @(...) } ); totals;
                 notPublished; dependencyIncluded; warnings; errors; notChecked; ringSource; ringNote }.
      Each row: id, kind, entity, source (definition|registry), title, replicate/ring/target (plain words), reaches
      (tenant names), reachIds, count, tenantCount, reachesNone, autoIncluded (tenant, dependent, reason), whyNone.
    #>
    [CmdletBinding()] param([Parameter(Mandatory)][hashtable]$Model, [object]$Preview)
    $prev = $Preview
    if ($null -eq $prev) {
        $prev = Get-PimReplicationPreview -RegistryRows @($Model.RegistryRows) -RegistryReplicate $(if ($Model.RegistryReplicate) { $Model.RegistryReplicate } else { @{} }) `
                    -Entities $(if ($Model.Entities) { $Model.Entities } else { @{} }) -Tenants @($Model.Tenants) -ProjectionPolicy $(if ($null -ne $Model.ProjectionPolicy) { $Model.ProjectionPolicy } else { [ordered]@{} }) -DeploymentRings @($Model.DeploymentRings)
    }
    $tenants = @($prev.tenants)
    $names = @{}; $idsByName = @{}
    foreach ($t in $tenants) { $names["$($t.tenantId)".ToLowerInvariant()] = "$($t.name)"; $idsByName["$($t.name)"] = "$($t.tenantId)".ToLowerInvariant() }
    # a tenant whose plan FAILED was not checked: its name is the prefix of its error line ("<name>: <reason>")
    $notChecked = @(@($prev.errors) | ForEach-Object { $s = "$_"; $i = $s.IndexOf(': '); if ($i -gt 0) { $s.Substring(0, $i) } else { $s } } | Where-Object { $_ } | Sort-Object -Unique)
    $checked = @($tenants | Where-Object { $notChecked -notcontains "$($_.name)" })
    $warnByTag = @{}
    foreach ($w in @($prev.warnings)) {
        $k = "$($w.GroupTag)".Trim().ToLowerInvariant(); if (-not $k) { continue }
        if (-not $warnByTag.ContainsKey($k)) { $warnByTag[$k] = New-Object System.Collections.Generic.List[object] }
        $warnByTag[$k].Add([ordered]@{ tenant = "$($w.tenant)"; tenantId = "$($w.tenantId)"; dependent = "$($w.dependent)"; reason = "$($w.reason)" }) | Out-Null
    }
    $regRep = if ($Model.RegistryReplicate) { $Model.RegistryReplicate } else { @{} }
    $ents = if ($Model.Entities) { $Model.Entities } else { @{} }

    $mkRow = {
        param($grp, $entity, $row, $source)
        $kind = $grp.kind
        $adminSrc = if ($source -eq 'registry') { 'Registry' } else { 'Definition' }
        $rowForWords = $row
        if ($source -eq 'registry') {
            # the registry's Replicate lives beside the row (pim.CentralAdmins.Replicate, read separately)
            $o = [ordered]@{}
            if ($row -is [System.Collections.IDictionary]) { foreach ($k in @($row.Keys)) { $o["$k"] = $row[$k] } }
            else { foreach ($p in $row.PSObject.Properties) { $o[$p.Name] = $p.Value } }
            $rk = "$(Get-PimDownlinkValue -Object $row -Key 'UserName')".Trim().ToLowerInvariant()
            if ($regRep.ContainsKey($rk)) { $o['Replicate'] = $regRep[$rk] }
            $rowForWords = [pscustomobject]$o
        }
        $id = Get-PimReplicationRowId -Entity $entity -Row $row
        $reach = @(); if ($id -and $prev.reach.ContainsKey($id)) { $reach = @($prev.reach[$id]) }
        $words = Get-PimReplicationWording -Row $rowForWords -Kind $kind -AdminSource $adminSrc -TenantNames $names
        $auto = @()
        if ($kind -eq 'group') { $gt = "$(Get-PimDownlinkValue -Object $row -Key 'GroupTag')".Trim().ToLowerInvariant(); if ($gt -and $warnByTag.ContainsKey($gt)) { $auto = @($warnByTag[$gt].ToArray()) } }
        $why = ''
        if (-not $reach.Count) {
            if (-not $tenants.Count) { $why = 'No managed tenant is registered (Managed tenant registry).' }
            elseif ($words.replicate.mode -eq 'No') { $why = "$($words.replicate.text). $($words.replicate.reason)" }
            else {
                $own = @($checked | ForEach-Object { $x = Get-PimReplicationRowOwnReach -Row $rowForWords -Kind $kind -AdminSource $adminSrc -Tenant $_ -DeploymentRings @($Model.DeploymentRings); if (-not $x.reach) { "$($_.name): $($x.reason)" } })
                if ($checked.Count -and $own.Count -eq $checked.Count) { $why = "Its own Ring / Target admit no tenant -- " + ($own -join '; ') }
                elseif ($words.replicate.mode -eq 'Follow') { $why = 'Follow -- no replicated row needs it in any managed tenant.' }
                else { $why = 'The plan sent it to no tenant: a row it depends on is not replicated, or the per-tenant projection policy on Managed tenants holds it back.' }
            }
        }
        return [ordered]@{
            id          = $id
            kind        = $kind
            group       = $grp.key
            entity      = $entity
            source      = $source
            title       = Get-PimReplicationRowTitle -Kind $kind -Entity $entity -Row $row
            replicate   = $words.replicate
            ring        = $words.ring
            target      = $words.target
            reaches     = @($reach)
            reachIds    = @(@($reach) | ForEach-Object { if ($idsByName.ContainsKey("$_")) { $idsByName["$_"] } } | Where-Object { $_ })
            count       = $reach.Count
            tenantCount = [int]$prev.tenantCount
            # "reaches none" only when every tenant was actually planned; otherwise it is NOT CHECKED for the others
            reachesNone = ($reach.Count -eq 0 -and $notChecked.Count -eq 0 -and $tenants.Count -gt 0)
            notChecked  = @($notChecked)
            autoIncluded = @($auto)
            whyNone     = $why
        }
    }

    $groupsOut = New-Object System.Collections.Generic.List[object]
    $total = 0; $none = 0
    foreach ($g in (Get-PimReplicationOverviewGroups)) {
        $rows = New-Object System.Collections.Generic.List[object]
        if ($g.kind -eq 'admin') {
            foreach ($r in @($Model.RegistryRows)) { if ($null -ne $r) { $rows.Add((& $mkRow $g 'Account-Definitions-Admins' $r 'registry')) | Out-Null } }
        }
        foreach ($e in @($g.entities)) {
            foreach ($r in @($ents[$e])) { if ($null -ne $r) { $rows.Add((& $mkRow $g $e $r 'definition')) | Out-Null } }
        }
        $arr = @($rows.ToArray() | Sort-Object -Property @{ Expression = { "$($_.title)" } })
        $total += $arr.Count; $none += @($arr | Where-Object { $_.reachesNone }).Count
        $groupsOut.Add([ordered]@{ key = $g.key; label = $g.label; kind = $g.kind; rows = @($arr) }) | Out-Null
    }
    return [ordered]@{
        master             = $true
        computedUtc        = [datetime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
        tenants            = @($tenants | ForEach-Object { [ordered]@{ tenantId = "$($_.tenantId)"; name = "$($_.name)"; ring = $_.ring; ringKnown = [bool]$_.ringKnown; ringSource = 'master-copy'; tags = @($_.tags) } })
        tenantCount        = [int]$prev.tenantCount
        groups             = @($groupsOut.ToArray())
        totals             = [ordered]@{ rows = $total; reachesNone = $none }
        notPublished       = @($prev.notPublished)
        dependencyIncluded = @($prev.dependencyIncluded)
        warnings           = @($prev.warnings)
        errors             = @($prev.errors)
        notChecked         = @($notChecked)
        ringSource         = 'master-copy'
        ringNote           = "Computed with the master's copy of each tenant's ring (platform.Tenants.Ring). Each managed tenant's own ring is set locally and gates its real pull, so a tenant whose ring differs from the master's copy receives what ITS ring admits."
    }
}

# --- the short-TTL cache (the preview plans once per tenant; the page re-opens and re-filters) ---------------------
$script:PimReplOverviewCache = $null

function Get-PimReplicationOverviewCached {
    <#
      The overview for GET /api/msp/replication/overview, cached for -TtlSeconds (default 30) per store. -Refresh
      recomputes. -Loader: { param() <returns the overview> } -- the endpoint passes the model read + compute, a test
      passes a counter. The cached copy is returned with cached = $true and its age, so the page can say it.
    #>
    [CmdletBinding()] param([Parameter(Mandatory)][string]$CacheKey, [Parameter(Mandatory)][scriptblock]$Loader, [int]$TtlSeconds = 30, [switch]$Refresh, [datetime]$NowUtc = ([datetime]::UtcNow))
    $c = $script:PimReplOverviewCache
    if (-not $Refresh -and $c -and "$($c.key)" -eq $CacheKey -and ($NowUtc - $c.at).TotalSeconds -lt $TtlSeconds -and ($NowUtc - $c.at).TotalSeconds -ge 0) {
        # a shallow COPY carries the cache marks -- the stored answer (and whoever already holds it) is never changed
        $v = [ordered]@{}
        foreach ($k in @($c.value.Keys)) { $v[$k] = $c.value[$k] }
        $v['cached'] = $true; $v['cacheAgeSeconds'] = [int]($NowUtc - $c.at).TotalSeconds; $v['ttlSeconds'] = $TtlSeconds
        return $v
    }
    $val = & $Loader
    if ($val -is [System.Collections.IDictionary]) {
        $val['cached'] = $false; $val['cacheAgeSeconds'] = 0; $val['ttlSeconds'] = $TtlSeconds
        # only a complete answer is cached -- a failed tenant plan is recomputed on the next request
        if (-not @($val['errors']).Count) { $script:PimReplOverviewCache = @{ key = $CacheKey; at = $NowUtc; value = $val } } else { $script:PimReplOverviewCache = $null }
    }
    return $val
}

function Clear-PimReplicationOverviewCache {
    # A registry or replication edit makes the cached overview stale at once.
    $script:PimReplOverviewCache = $null
}
