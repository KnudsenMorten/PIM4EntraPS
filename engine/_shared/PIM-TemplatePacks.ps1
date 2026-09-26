#Requires -Version 5.1
<#
  REQ-U (IaC import) -- PERMISSION TEMPLATE PACKS: the planning logic of GET /api/templates, as a shared library.

  Operator, 2026-09-19: "can you import with script. we need to be able to do this via script" / "iac" / "so 25 tenants
  can be prepped".

  WHAT THIS FILE IS. The PURE half of a template import: given a pack (templates\<id>.template.json), the environment's
  CURRENT rows per entity and the tenant's group pattern, which rows the environment does not have yet -- re-expressed
  in the tenant's own naming -- and which of them belong together as one unit. No SQL, no Graph, no clock: every
  caller reads the store itself and hands the rows in.
    * tools\setup\Import-PimPermissionTemplate.ps1 -- plans with Get-PimTemplatePackPlan, then commits through the same
      snapshot -> transactional apply -> restore-on-failure -> prune path the Manager's Review & Save uses.
    * tools\pim-manager\Open-PimManager.ps1 GET /api/templates -- dot-sources this file and plans every pack with
      Get-PimTemplatePackPlan, passing every group definition entity so the GUI ADOPTS exactly as the script does
      (2.4.381; the route's own copy of these functions is gone). tests\Test-PimTemplateImport.ps1 B2 proves route ==
      script for every shipped pack, B4 the adoption through the route.

  Moved here from the route, unchanged in behaviour:
    Get-PimTemplateRowKey          the key a pack row is matched on, per entity (binding entities keyed on role too)
    Get-PimTemplateImportUnits     a group definition + its workload binding row(s) = ONE unit (never half a unit)
    ConvertTo-PimTemplatePackRow   tenant naming: GroupName re-expressed under the tenant's PimGroupPattern (pack
                                   authored in groupNamePattern, default 'PIM-{Role}'); a binding role '{GroupName}'
                                   resolved to the group's tenant name
    REQ 70.13                      a row carrying the all-zero subscription is a placeholder, never offered
  New (the script's needs; the route can use them too):
    Get-PimTemplatePackKnownBases      the entities a pack may carry (the Manager's grid list)
    Read-PimTemplatePack               BOM-safe read of one pack
    Get-PimTemplatePackBases           which known entities a pack touches (= what the caller must read)
    Get-PimTemplatePackPlan            the plan: @{ id; name; version; missing; missingCount; units; placeholderSkipped }
    Select-PimTemplatePackPlanSubset   -Only: narrow a plan to some groups, WIDENED to whole units
    Get-PimTemplateTenantGroupPattern  the tenant's PimGroupPattern: shipped defaults < locked file < pim.Settings

  Requires engine\_shared\PIM-Naming.ps1 (loaded below when the caller has not).
  PS 5.1-safe (setup scripts run on Windows PowerShell 5.1): no ?. / ?? / ternary. ASCII only.
#>

Set-StrictMode -Off
if (-not (Get-Command ConvertTo-PimTenantGroupName -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot 'PIM-Naming.ps1') }

function Get-PimTemplatePackKnownBases {
    # The entities a pack row may land in: the Manager's grid list ($script:PimCsvBases in Open-PimManager.ps1, which the
    # route checks with Get-PimCsvSpec). A pack entity outside it is skipped, exactly as the route skips it.
    # DUPLICATED on purpose (the Manager is not a library); tests\Test-PimTemplateImport.ps1 fails when the two drift.
    @(
        'Account-Definitions-Admins',
        'PIM-Definitions-Roles', 'PIM-Definitions-Tasks', 'PIM-Definitions-Services', 'PIM-Definitions-Processes',
        'PIM-Definitions-Resources', 'PIM-Definitions-Departments', 'PIM-Definitions-Organization', 'PIM-Definitions-Projects',
        'PIM-Definitions-CrossOrg', 'PIM-Definitions-AU',
        'PIM-Assignments-Admins', 'PIM-Assignments-Groups', 'PIM-Assignments-Roles-Groups', 'PIM-Assignments-Roles-AUs',
        'PIM-Assignments-Azure-Resources', 'PIM-Assignments-Workloads'
    )
}

function Read-PimTemplatePack {
    # One pack, parsed. The route reads UTF-8 and drops a BOM by hand (a BOM makes ConvertFrom-Json fail on 5.1).
    param([Parameter(Mandatory)][string]$Path)
    $raw = [System.IO.File]::ReadAllText($Path, (New-Object System.Text.UTF8Encoding($false)))
    if ($raw.Length -gt 0 -and [int][char]$raw[0] -eq 0xFEFF) { $raw = $raw.Substring(1) }
    return ($raw | ConvertFrom-Json)
}

function Get-PimTemplateRowKey {
    param([string]$Base, [object]$Row)
    $g = { param($p) $x = $Row.PSObject.Properties[$p]; if ($x -and $x.Value) { "$($x.Value)" } else { '' } }
    switch -Wildcard ($Base) {
        'PIM-Definitions-AU'              { return (& $g 'AdministrativeUnitTag') }
        'PIM-Definitions-*'               { return (& $g 'GroupTag') }
        'Account-Definitions-Admins'      { return (& $g 'UserName') }
        'PIM-Assignments-Admins'          { return ((& $g 'Username') + '|' + (& $g 'GroupTag')) }
        'PIM-Assignments-Groups'          { return ((& $g 'TargetGroupTag') + '|' + (& $g 'SourceGroupTag')) }
        'PIM-Assignments-Roles-Groups'    { return ((& $g 'GroupTag') + '|' + (& $g 'RoleDefinitionName')) }
        'PIM-Assignments-Roles-AUs'       { return ((& $g 'GroupTag') + '|' + (& $g 'AdministrativeUnitTag') + '|' + (& $g 'RoleDefinitionName')) }
        'PIM-Assignments-Azure-Resources' { return ((& $g 'GroupTag') + '|' + (& $g 'AzScope') + '|' + (& $g 'AzScopePermission')) }
        # REQ-U (2026-09-19): the WORKLOAD BINDING entities, so a pack can carry a group AND its workload role as one
        # unit. Keyed by what makes one binding distinct (Get-PimStoreRowKey keys these on GroupTag alone, which would
        # hide a second role for the same group).
        'PIM-Assignments-Intune'          { return ((& $g 'GroupTag') + '|' + (& $g 'RoleDefinitionName')) }
        'PIM-Assignments-Defender'        { return ((& $g 'GroupTag') + '|' + (& $g 'RoleDefinitionName')) }
        'PIM-Assignments-Workloads'       { return ((& $g 'Workload') + '|' + (& $g 'GroupTag') + '|' + (& $g 'RoleName')) }
        default { return '' }
    }
}

function Get-PimTemplateImportUnits {
    # REQ-U wave 2 (design point 1) -- A GROUP AND ITS WORKLOAD ROLE ARE ONE UNIT. Operator: "otherwise we will end with
    # orphaned permission groups that are not connected with the actual workload". PURE over the offered rows: every
    # offered definition (PIM-Definitions-*, not AU) paired with the offered binding rows (PIM-Assignments-Workloads /
    # -Intune / -Defender) of the SAME GroupTag:
    #   @( @{ tag; groupName; definition = @{ base; i }; bindings = @( @{ base; i } ) } )
    # i = the row's index in missing[base]. The GUI ticks / unticks a unit together and refuses to import half of one;
    # the script's -Only widens to whole units. A definition whose binding is already in the store (or a binding whose
    # group is) is no unit.
    param([System.Collections.IDictionary]$Missing)
    $out = New-Object System.Collections.ArrayList
    if (-not $Missing) { return @() }
    $bindBases = @('PIM-Assignments-Workloads', 'PIM-Assignments-Intune', 'PIM-Assignments-Defender')
    foreach ($db in @($Missing.Keys)) {
        if ("$db" -notlike 'PIM-Definitions-*' -or "$db" -eq 'PIM-Definitions-AU') { continue }
        $drows = @($Missing[$db])
        for ($i = 0; $i -lt $drows.Count; $i++) {
            $tag = "$($drows[$i].GroupTag)".Trim(); if (-not $tag) { continue }
            $binds = New-Object System.Collections.ArrayList
            foreach ($bb in $bindBases) {
                if (-not $Missing.Contains($bb)) { continue }
                $brows = @($Missing[$bb])
                for ($j = 0; $j -lt $brows.Count; $j++) {
                    if ("$($brows[$j].GroupTag)".Trim() -ieq $tag -and "$($brows[$j].Action)".Trim() -ine 'Remove') { [void]$binds.Add([ordered]@{ base = $bb; i = $j }) }
                }
            }
            if ($binds.Count) { [void]$out.Add([ordered]@{ tag = $tag; groupName = "$($drows[$i].GroupName)"; definition = [ordered]@{ base = "$db"; i = $i }; bindings = @($binds.ToArray()) }) }
        }
    }
    return @($out.ToArray())
}

function ConvertTo-PimTemplatePackRow {
    # REQ-U (2026-09-19) -- names from the TENANT, never the pack's generic 'PIM-'. Operator: "customer can have
    # different naming convention so you must make sure code uses the actual naming per tenant and not generic". A pack
    # is authored in the shipped convention (-PackPattern, default 'PIM-{Role}'); a definition row's GroupName is
    # re-expressed under this tenant's PimGroupPattern (ConvertTo-PimTenantGroupName), and a row that carries only a
    # GroupTag gets its name from the tag (Resolve-PimGroupNameFromTag). Returns a COPY; any other row is returned as it is.
    param([string]$Base, [object]$Row, [string]$PackPattern = 'PIM-{Role}', [string]$TenantPattern, [hashtable]$PackGroupNameByTag = @{})
    # REQ-U wave 2: a pack BINDING row may name its role '{GroupName}' -- "the custom role named exactly like this group"
    # (Defender XDR). It is offered with the group's name under THIS tenant's pattern: the pack definition's GroupName
    # for the tag re-expressed (ConvertTo-PimTenantGroupName), else the tag under the tenant pattern. The row key is taken
    # from the converted row, so an imported binding reads as present.
    if ($Base -in @('PIM-Assignments-Workloads', 'PIM-Assignments-Intune', 'PIM-Assignments-Defender')) {
        $rp = if ($Base -eq 'PIM-Assignments-Workloads') { 'RoleName' } else { 'RoleDefinitionName' }
        $rpv = $Row.PSObject.Properties[$rp]; $rv = if ($rpv) { "$($rpv.Value)" } else { '' }
        if ($rv.IndexOf('{GroupName}', [System.StringComparison]::OrdinalIgnoreCase) -lt 0) { return $Row }
        $bgt = "$($Row.GroupTag)".Trim(); $bgn = ''
        if ($bgt -and $PackGroupNameByTag -and $PackGroupNameByTag.ContainsKey($bgt.ToLowerInvariant())) {
            $bgn = "$($PackGroupNameByTag[$bgt.ToLowerInvariant()])"
            if (Get-Command ConvertTo-PimTenantGroupName -ErrorAction SilentlyContinue) { $bgn = ConvertTo-PimTenantGroupName -Name $bgn -FromPattern $PackPattern -ToPattern $TenantPattern }
        } elseif ($bgt -and (Get-Command Resolve-PimGroupNameFromTag -ErrorAction SilentlyContinue)) { $bgn = Resolve-PimGroupNameFromTag -Tag $bgt -Pattern $TenantPattern }
        if (-not "$bgn".Trim()) { return $Row }
        $bcopy = [ordered]@{}
        foreach ($p in $Row.PSObject.Properties) { $bcopy[$p.Name] = $p.Value }
        $bcopy[$rp] = [regex]::Replace($rv, '\{GroupName\}', { param($m) "$bgn" }, 'IgnoreCase')
        return [pscustomobject]$bcopy
    }
    if ($Base -notlike 'PIM-Definitions-*' -or $Base -eq 'PIM-Definitions-AU') { return $Row }
    if (-not (Get-Command Resolve-PimGroupNameFromTag -ErrorAction SilentlyContinue)) { return $Row }
    $copy = [ordered]@{}
    foreach ($p in $Row.PSObject.Properties) { $copy[$p.Name] = $p.Value }
    $gn = "$($copy['GroupName'])".Trim(); $gt = "$($copy['GroupTag'])".Trim()
    if ($gn) { $copy['GroupName'] = ConvertTo-PimTenantGroupName -Name $gn -FromPattern $PackPattern -ToPattern $TenantPattern }
    elseif ($gt) { $copy['GroupName'] = Resolve-PimGroupNameFromTag -Tag $gt -Pattern $TenantPattern }
    return [pscustomobject]$copy
}

function Test-PimTemplatePlaceholderRow {
    # PURE. REQ 70.13 (operator 2026-09-13: "it makes no sense to have a sub with all 00000000", "why are they there"):
    # azure-rbac.template.json ships rows with the all-zero subscription for the operator to fill in; offering them as
    # "missing" imported them unchanged, and 4 such rows blocked every commit on internal. Any column counts.
    param([Parameter(Mandatory)][object]$Row)
    return ((@($Row.PSObject.Properties | ForEach-Object { "$($_.Value)" }) -join '|') -match '(?i)/subscriptions/0{8}-0{4}-0{4}-0{4}-0{12}')
}

function Get-PimTemplatePackBases {
    # The known entities (Get-PimTemplatePackKnownBases, or -KnownBases) this pack carries rows for, in pack order --
    # exactly the entities a caller must read before planning.
    param([Parameter(Mandatory)][object]$Pack, [string[]]$KnownBases)
    $known = if ($PSBoundParameters.ContainsKey('KnownBases')) { @($KnownBases) } else { @(Get-PimTemplatePackKnownBases) }
    $out = New-Object System.Collections.Generic.List[string]
    if ($null -eq $Pack.rows) { return @() }
    foreach ($bp in $Pack.rows.PSObject.Properties) { if ($known -contains $bp.Name) { $out.Add($bp.Name) } }
    return @($out.ToArray())
}

function Get-PimTemplatePackPlan {
    <#
      PURE. What GET /api/templates computes for ONE pack against ONE environment:
        -TemplatePath        templates\<id>.template.json (or -Pack, already parsed)
        -CurrentRowsByBase   hashtable base -> the entity's CURRENT rows. Every base the pack carries
                             (Get-PimTemplatePackBases) MUST be present -- an absent base is refused, because
                             "not read" planned as "empty" re-offers rows the store already holds, and the importer
                             would then overwrite them. An empty array is a legitimately empty entity.
        -TenantGroupPattern  the tenant's PimGroupPattern (Get-PimTemplateTenantGroupPattern)
        -KnownBases          optional override of Get-PimTemplatePackKnownBases (the route passes its grid list)
      Returns [ordered]@{ id; name; version; description; totalRows; missing = [ordered] base -> rows (tenant-named copies);
                          missingCount; units (Get-PimTemplateImportUnits); placeholderSkipped }.
    #>
    param(
        [string]$TemplatePath,
        [object]$Pack,
        [Parameter(Mandatory)][hashtable]$CurrentRowsByBase,
        [AllowEmptyString()][string]$TenantGroupPattern = '',
        [string[]]$KnownBases,
        # Every CURRENT group definition row (all PIM-Definitions-* except AU), when the caller read them. Used to ADOPT
        # a pack group that the store already defines -- under the same tag in ANOTHER definition entity, or under the
        # same (tenant) GroupName with a different tag. Without it only the pack's own definition bases are consulted.
        [object[]]$ExistingDefinitionRows
    )
    $tpl = $Pack
    if ($null -eq $tpl) {
        if (-not "$TemplatePath".Trim()) { throw 'Get-PimTemplatePackPlan: give -TemplatePath or -Pack.' }
        $tpl = Read-PimTemplatePack -Path $TemplatePath
    }
    $known = if ($PSBoundParameters.ContainsKey('KnownBases')) { @($KnownBases) } else { @(Get-PimTemplatePackKnownBases) }
    # 🔴 ADOPTION (measured on internal 2026-09-19, before anything was written): the intune pack names its groups
    # 'PIM-Intune-HelpDeskOperator-L4-T1-WDP-ID' with tag 'Intune-HelpDeskOperator-L4-T1-WDP-ID'; internal already
    # defined the SAME group under its v1 tag 'Intune-HelpdeskOperator-L4'. Keyed by tag alone, the plan offered a second
    # definition of one group (9 of 10 Intune groups). A pack group whose tag, or whose tenant GroupName, the store
    # already defines is ADOPTED: no definition is added, and the pack's rows that point at it (bindings, nestings) are
    # re-tagged to the STORE's tag, so they bind to the group that exists.
    $defRows = New-Object System.Collections.Generic.List[object]
    if ($PSBoundParameters.ContainsKey('ExistingDefinitionRows')) { foreach ($r in @($ExistingDefinitionRows)) { if ($null -ne $r) { $defRows.Add($r) } } }
    else {
        foreach ($b0 in @($CurrentRowsByBase.Keys)) {
            if ("$b0" -notlike 'PIM-Definitions-*' -or "$b0" -eq 'PIM-Definitions-AU') { continue }
            foreach ($r in @($CurrentRowsByBase[$b0])) { if ($null -ne $r) { $defRows.Add($r) } }
        }
    }
    $storeTags = @{}; $storeNameToTag = @{}
    foreach ($r in $defRows) {
        $rt = "$(([pscustomobject]$r).GroupTag)".Trim(); $rn = "$(([pscustomobject]$r).GroupName)".Trim()
        if ($rt) { $storeTags[$rt.ToLowerInvariant()] = $rt }
        if ($rn -and $rt -and -not $storeNameToTag.ContainsKey($rn.ToLowerInvariant())) { $storeNameToTag[$rn.ToLowerInvariant()] = $rt }
    }
    $retag = @{}                                   # pack tag (lower) -> the store's tag
    $adopted = New-Object System.Collections.Generic.List[object]
    $missing = [ordered]@{}
    $missingCount = 0
    $totalCount = 0
    $placeholderSkipped = 0
    # REQ-U wave 2: the pack's own tag -> GroupName, for a binding row whose role is '{GroupName}'.
    $packTagToName = @{}
    foreach ($bp0 in $tpl.rows.PSObject.Properties) {
        if ($bp0.Name -notlike 'PIM-Definitions-*' -or $bp0.Name -eq 'PIM-Definitions-AU') { continue }
        foreach ($d0 in @($bp0.Value)) { $t0 = "$($d0.GroupTag)".Trim(); if ($t0 -and "$($d0.GroupName)".Trim()) { $packTagToName[$t0.ToLowerInvariant()] = "$($d0.GroupName)".Trim() } }
    }
    $packPat = if ("$($tpl.groupNamePattern)".Trim()) { "$($tpl.groupNamePattern)" } else { 'PIM-{Role}' }
    foreach ($bp1 in $tpl.rows.PSObject.Properties) {
        if ($bp1.Name -notlike 'PIM-Definitions-*' -or $bp1.Name -eq 'PIM-Definitions-AU' -or $known -notcontains $bp1.Name) { continue }
        foreach ($d1 in @($bp1.Value)) {
            $pt = "$($d1.GroupTag)".Trim(); if (-not $pt) { continue }
            $c1 = ConvertTo-PimTemplatePackRow -Base $bp1.Name -Row $d1 -PackPattern $packPat -TenantPattern $TenantGroupPattern -PackGroupNameByTag $packTagToName
            $pn = "$($c1.GroupName)".Trim()
            if ($storeTags.ContainsKey($pt.ToLowerInvariant())) {
                # Same tag already defined (possibly in another definition entity): present, nothing to re-tag.
                $st = $storeTags[$pt.ToLowerInvariant()]
                if ($st -cne $pt) { $retag[$pt.ToLowerInvariant()] = $st }
                $adopted.Add([ordered]@{ groupName = $pn; packTag = $pt; storeTag = $st; by = 'tag' })
            } elseif ($pn -and $storeNameToTag.ContainsKey($pn.ToLowerInvariant())) {
                $st = $storeNameToTag[$pn.ToLowerInvariant()]
                $retag[$pt.ToLowerInvariant()] = $st
                $adopted.Add([ordered]@{ groupName = $pn; packTag = $pt; storeTag = $st; by = 'name' })
            }
        }
    }
    $adoptedTags = @{}; foreach ($a in $adopted) { $adoptedTags["$($a.packTag)".ToLowerInvariant()] = $true }
    $keyTaken = New-Object System.Collections.Generic.List[object]
    $retagRow = {
        param($Row)
        $cols = @('GroupTag', 'SourceGroupTag', 'TargetGroupTag')
        $hit = $false
        foreach ($c in $cols) { $p = $Row.PSObject.Properties[$c]; if ($p -and $retag.ContainsKey("$($p.Value)".Trim().ToLowerInvariant())) { $hit = $true } }
        if (-not $hit) { return $Row }
        $copy = [ordered]@{}
        foreach ($p in $Row.PSObject.Properties) {
            $v = $p.Value
            if ($cols -contains $p.Name -and $retag.ContainsKey("$v".Trim().ToLowerInvariant())) { $v = $retag["$v".Trim().ToLowerInvariant()] }
            $copy[$p.Name] = $v
        }
        return [pscustomobject]$copy
    }
    foreach ($baseProp in $tpl.rows.PSObject.Properties) {
        $base = $baseProp.Name
        if ($known -notcontains $base) { continue }
        if (-not $CurrentRowsByBase.ContainsKey($base)) { throw "Get-PimTemplatePackPlan: no current rows were given for '$base' (pack '$($tpl.id)') -- read the entity first; an unread entity is not an empty one." }
        $existing = @{}
        # 🔴 §77.24 (EFIF 2026-09-21: "14 store key(s) of PIM-Assignments-Workloads are used by more than one row"): the
        # pack is diffed on its own finer key (Workloads: Workload|GroupTag|RoleName) but the STORE keeps one row per
        # Get-PimStoreRowKey (Workloads: GroupTag alone). A pack row whose store key an existing row already holds can
        # never be added -- offering it staged a second row for the group and the commit was refused. Such rows are
        # reported in keyTaken, not offered.
        $storeKeyed = [bool](Get-Command Get-PimStoreRowKey -ErrorAction SilentlyContinue)
        $storeKeys = @{}
        foreach ($r in @($CurrentRowsByBase[$base])) {
            if ($null -eq $r) { continue }
            $k = Get-PimTemplateRowKey -Base $base -Row ([pscustomobject]$r)
            if ($k -and $k -ne '|' ) { $existing[$k.ToLowerInvariant()] = $true }
            if ($storeKeyed) { $sk = Get-PimStoreRowKey -Base $base -Row ([pscustomobject]$r); if ($sk) { $storeKeys[$sk.ToLowerInvariant()] = $true } }
        }
        $miss = New-Object System.Collections.ArrayList
        foreach ($tr in @($baseProp.Value)) {
            $totalCount++
            if (Test-PimTemplatePlaceholderRow -Row $tr) { $placeholderSkipped++; continue }
            # REQ-U wave 2: keyed on the row as it would be IMPORTED (a '{GroupName}' role resolved), so a binding already
            # in the store is not offered again.
            $conv = ConvertTo-PimTemplatePackRow -Base $base -Row $tr -PackPattern $packPat -TenantPattern $TenantGroupPattern -PackGroupNameByTag $packTagToName
            # ADOPTION: a definition the store already has is never offered; rows pointing at it take the store's tag.
            if ($base -like 'PIM-Definitions-*' -and $base -ne 'PIM-Definitions-AU' -and $adoptedTags.ContainsKey("$($conv.GroupTag)".Trim().ToLowerInvariant())) { continue }
            $conv = & $retagRow $conv
            $k = Get-PimTemplateRowKey -Base $base -Row $conv
            if ($k -and -not $existing.ContainsKey($k.ToLowerInvariant())) {
                $sk = if ($storeKeyed) { "$(Get-PimStoreRowKey -Base $base -Row $conv)".ToLowerInvariant() } else { '' }
                if ($sk -and $storeKeys.ContainsKey($sk)) { $keyTaken.Add([ordered]@{ base = $base; storeKey = $sk; groupTag = "$($conv.GroupTag)" }); continue }
                if ($sk) { $storeKeys[$sk] = $true }   # two pack rows sharing one store key: only the first is offered
                [void]$miss.Add($conv)
            }
        }
        if ($miss.Count -gt 0) { $missing[$base] = $miss.ToArray(); $missingCount += $miss.Count }
    }
    # §77.24: a unit is never offered half -- when a group's workload BINDING was withheld (its store key taken), its
    # DEFINITION is withheld too, or the import would create a group with no workload role (an orphan).
    $takenBindTags = @{}
    foreach ($kt in $keyTaken) { if (@('PIM-Assignments-Workloads', 'PIM-Assignments-Intune', 'PIM-Assignments-Defender') -contains $kt.base -and "$($kt.groupTag)".Trim()) { $takenBindTags["$($kt.groupTag)".Trim().ToLowerInvariant()] = $true } }
    if ($takenBindTags.Count) {
        foreach ($mb in @($missing.Keys)) {
            if ("$mb" -notlike 'PIM-Definitions-*' -or "$mb" -eq 'PIM-Definitions-AU') { continue }
            $keepRows = New-Object System.Collections.ArrayList
            foreach ($dr in @($missing[$mb])) {
                if ($takenBindTags.ContainsKey("$($dr.GroupTag)".Trim().ToLowerInvariant())) {
                    $keyTaken.Add([ordered]@{ base = "$mb"; storeKey = "$($dr.GroupTag)".ToLowerInvariant(); groupTag = "$($dr.GroupTag)"; reason = 'its workload binding cannot be added (store key taken)' })
                    $missingCount--
                } else { [void]$keepRows.Add($dr) }
            }
            if ($keepRows.Count) { $missing[$mb] = $keepRows.ToArray() } else { $missing.Remove($mb) }
        }
    }
    return [ordered]@{
        id = "$($tpl.id)"; name = "$($tpl.name)"; version = $tpl.version
        description = "$($tpl.description)"
        totalRows = $totalCount; missingCount = $missingCount; missing = $missing
        units = @(Get-PimTemplateImportUnits -Missing $missing)
        placeholderSkipped = $placeholderSkipped
        # §77.24: pack rows NOT offered because an existing row already holds their store key (one row per store key).
        keyTaken = @($keyTaken.ToArray())
        # Pack groups the store already defines (by tag, or by tenant GroupName under another tag): not re-defined; the
        # pack's rows for them were re-tagged to storeTag.
        adopted = @($adopted.ToArray())
    }
}

function Get-PimTemplatePlanRowTags {
    # PURE. The group identifiers a planned row answers to for -Only: its tag(s) and, for a definition, its (tenant)
    # GroupName. Lower-cased.
    param([Parameter(Mandatory)][string]$Base, [Parameter(Mandatory)][object]$Row)
    $out = New-Object System.Collections.Generic.List[string]
    $cols = if ($Base -eq 'PIM-Definitions-AU') { @('AdministrativeUnitTag', 'AUDisplayName') }
            elseif ($Base -eq 'PIM-Assignments-Groups') { @('TargetGroupTag', 'SourceGroupTag') }
            else { @('GroupTag', 'GroupName') }
    foreach ($c in $cols) { $p = $Row.PSObject.Properties[$c]; if ($p -and "$($p.Value)".Trim()) { $out.Add("$($p.Value)".Trim().ToLowerInvariant()) } }
    return @($out.ToArray())
}

function Select-PimTemplatePackPlanSubset {
    <#
      PURE. -Only for the importer: narrow a plan (Get-PimTemplatePackPlan) to the rows of some groups, named by GroupTag
      or by (tenant) GroupName, case-insensitive. ALWAYS WIDENED TO WHOLE UNITS: when any row of a unit is selected, the
      unit's definition and every binding come with it -- a group without its workload role (or a role without its group)
      is the orphan the operator ruled out ("otherwise we will end with orphaned permission groups ...").
      Returns the narrowed plan (missing / missingCount / units recomputed, everything else copied) plus
        selectedTags  -- the tags that were matched
        widenedTags   -- units that were completed by widening (a name matched only part of the unit)
        unmatched     -- -Only entries that matched no planned row
    #>
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Plan, [Parameter(Mandatory)][string[]]$Only)
    $want = @{}
    foreach ($o in @($Only)) { $t = "$o".Trim(); if ($t) { $want[$t.ToLowerInvariant()] = $true } }
    $hit = @{}                                   # "$base|$i" -> $true
    $matchedEntries = @{}
    foreach ($b in @($Plan.missing.Keys)) {
        $rows = @($Plan.missing[$b])
        for ($i = 0; $i -lt $rows.Count; $i++) {
            foreach ($t in @(Get-PimTemplatePlanRowTags -Base "$b" -Row $rows[$i])) {
                if ($want.ContainsKey($t)) { $hit["$b|$i"] = $true; $matchedEntries[$t] = $true }
            }
        }
    }
    # WIDEN: a unit is all-or-nothing.
    $widened = New-Object System.Collections.Generic.List[string]
    foreach ($u in @($Plan.units)) {
        $members = @("$($u.definition.base)|$($u.definition.i)") + @(@($u.bindings) | ForEach-Object { "$($_.base)|$($_.i)" })
        $anyHit = @($members | Where-Object { $hit.ContainsKey($_) }).Count
        if ($anyHit -gt 0 -and $anyHit -lt $members.Count) {
            foreach ($m in $members) { $hit[$m] = $true }
            $widened.Add("$($u.tag)")
        }
    }
    $missing = [ordered]@{}; $count = 0
    $tags = New-Object System.Collections.Generic.List[string]
    foreach ($b in @($Plan.missing.Keys)) {
        $rows = @($Plan.missing[$b]); $keep = New-Object System.Collections.ArrayList
        for ($i = 0; $i -lt $rows.Count; $i++) {
            if (-not $hit.ContainsKey("$b|$i")) { continue }
            [void]$keep.Add($rows[$i])
            $gt = "$($rows[$i].GroupTag)".Trim(); if ($gt -and -not $tags.Contains($gt)) { $tags.Add($gt) }
        }
        if ($keep.Count) { $missing["$b"] = $keep.ToArray(); $count += $keep.Count }
    }
    $out = [ordered]@{}
    foreach ($k in @($Plan.Keys)) { $out[$k] = $Plan[$k] }
    $out['missing'] = $missing
    $out['missingCount'] = $count
    $out['units'] = @(Get-PimTemplateImportUnits -Missing $missing)
    $out['selectedTags'] = @($tags.ToArray())
    $out['widenedTags'] = @($widened.ToArray())
    $out['unmatched'] = @(@($want.Keys) | Where-Object { -not $matchedEntries.ContainsKey($_) } | Sort-Object)
    return $out
}

function Get-PimTemplateTenantGroupPattern {
    <#
      The tenant's PimGroupPattern exactly as the Manager's Get-PimNamingConventions resolves it: the shipped defaults
      (Get-PimShippedNamingConventions -- IN CODE), overlaid by the store's pim.Settings['NamingConventions'] (-Stored,
      parsed; an object or a map -- anything else is ignored, as ConvertTo-PimPlainHashtable does). No SQL here: the
      caller reads the setting.
      🔴 2026-09-20: -LockedConfigPath is GONE. It sourced config\PIM4EntraPS.NamingConventions.locked.ps1, a
      hand-synced duplicate of the very defaults this function already falls back to. The parameter is still ACCEPTED
      and IGNORED so an older caller keeps working; nothing reads a config file for naming any more.
    #>
    param([AllowNull()][object]$Stored, [string]$LockedConfigPath)
    $pattern = 'PIM-{Role}-{Department}'
    if (Get-Command Get-PimShippedNamingConventions -ErrorAction SilentlyContinue) {
        try {
            $shipped = Get-PimShippedNamingConventions
            if ($shipped -is [System.Collections.IDictionary] -and $shipped.Contains('PimGroupPattern') -and "$($shipped['PimGroupPattern'])".Trim()) {
                $pattern = "$($shipped['PimGroupPattern'])"
            }
        } catch { }
    }
    if ($Stored -is [System.Collections.IDictionary]) { if ($Stored.Contains('PimGroupPattern')) { $pattern = $Stored['PimGroupPattern'] } }
    elseif ($Stored -is [System.Management.Automation.PSCustomObject]) { $p = $Stored.PSObject.Properties['PimGroupPattern']; if ($p) { $pattern = $p.Value } }
    return "$pattern"
}
