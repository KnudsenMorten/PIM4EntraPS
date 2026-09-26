#Requires -Version 5.1
<#
.SYNOPSIS
    Discovery inbox (REQ-DISC-2, operator 2026-09-26): ONE list of what is new in the tenant, each item with Create and
    Ignore -- "i feel the discovery solution is not working. i need a way to see them, and either ignore them or approve
    them (create)" / "must be fast and easy".

.DESCRIPTION
    Before this, the Discovery page and the discovery jobs never met: the page diffed the tenant cache against an
    all-or-nothing baseline (no per-item action), and the jobs marked anything they did not auto-import as "seen" in a
    container-local file, after which it was never shown again.

    Now:
      * SOURCES -- the tenant cache the Manager already reads: 'azure-scopes' (management groups + subscriptions),
        'entra-roles', 'workload-roles:defender' / 'workload-roles:intune', and 'powerbi-workspaces' (written by the
        discovery-powerbi job).
      * KNOWN -- an Azure scope / Power BI workspace is known when a definition already names it (its proposed group name
        or tag is defined, or a stored row references its scope / workspace id). A ROLE kind is known when it was in the
        tenant the first time the inbox read that kind (the baseline -- so only roles Microsoft ADDS later are new), or
        when it was accepted.
      * DECISIONS -- pim.Settings 'DiscoveryDecisions' { key -> { state = ignored | accepted | staged; by; atUtc } }.
        Ignore needs no reason (operator: "just ignore, no need to provide reason") and is reversible.
      * CREATE -- an Azure management group / subscription or a Power BI workspace becomes a PERMISSION GROUP definition
        (PIM-Definitions-Services, the v1 model the Create wizard uses), named by the naming convention at the CAF level
        of its place in the management-group tree (the Create wizard's §79.17 rule). The page STAGES it; Commit applies
        it. Discovery never grants access: roles are linked in Create access. A ROLE kind is ACCEPTED into the catalog.
    PURE functions here; the Manager does the I/O. PS 5.1-safe.
#>
Set-StrictMode -Off

$script:PimDiscoveryKinds = [ordered]@{
    'azure-mg'      = 'Azure management group'
    'azure-sub'     = 'Azure subscription'
    'powerbi-ws'    = 'Power BI workspace'
    'entra-role'    = 'Entra ID role'
    'defender-role' = 'Defender XDR role'
    'intune-role'   = 'Intune role'
}
$script:PimDiscoveryRoleKinds = @('entra-role', 'defender-role', 'intune-role')

function Get-PimDiscoveryField {
    param($Item, [string]$Name)
    if ($null -eq $Item) { return '' }
    if ($Item -is [System.Collections.IDictionary]) { return "$($Item[$Name])".Trim() }
    $p = $Item.PSObject.Properties[$Name]; if ($p) { return "$($p.Value)".Trim() }
    return ''
}

function Get-PimAzureCafLevel {
    <#
      PURE -- the PowerShell twin of the page's pimAzureScopeLevel (§79.17, CAF layers): the Tenant Root Group is L3, every
      layer below it one more, a subscription one below its management group, capped at L9. -Scopes = the cached
      azure-scopes items (parentId '' = the root). $null when the chain to the root is not known.
    #>
    param([string]$ScopePath, [object[]]$Scopes = @())
    $p = "$ScopePath".Trim().TrimEnd('/')
    if (-not $p) { return $null }
    $byPath = @{}
    foreach ($x in @($Scopes)) { $k = (Get-PimDiscoveryField $x 'scopePath'); if (-not $k) { $k = Get-PimDiscoveryField $x 'id' }; if ($k) { $byPath[$k.ToLowerInvariant()] = $x } }
    $key = $p.ToLowerInvariant(); $below = 0
    $m = [regex]::Match($p, '(?i)^(/subscriptions/[^/]+)(/resourceGroups/[^/]+)?(/providers/.+)?$')
    if ($m.Success) { $key = $m.Groups[1].Value.ToLowerInvariant(); $below = [int]$m.Groups[2].Success + [int]$m.Groups[3].Success }
    $cur = $byPath[$key]; $depth = 0
    if ($null -eq $cur) { return $null }
    $pp = if ($cur -is [System.Collections.IDictionary]) { $cur.Contains('parentId') } else { [bool]$cur.PSObject.Properties['parentId'] }
    if (-not $pp) { return $null }
    while ((Get-PimDiscoveryField $cur 'parentId') -ne '') {
        if (++$depth -gt 20) { return $null }
        $cur = $byPath[(Get-PimDiscoveryField $cur 'parentId').ToLowerInvariant()]
        if ($null -eq $cur) { return $null }
    }
    return [math]::Min(9, 3 + $depth + $below)
}

function ConvertTo-PimDiscoveryItems {
    <# PURE. The cached sources -> one flat list of { key; kind; kindLabel; id; name; path }. #>
    param([object[]]$AzureScopes = @(), [object[]]$EntraRoles = @(), [object[]]$DefenderRoles = @(), [object[]]$IntuneRoles = @(), [object[]]$PowerBiWorkspaces = @())
    $out = New-Object System.Collections.Generic.List[object]
    $add = { param($kind, $id, $name, $path) if ("$id".Trim()) { $out.Add([pscustomobject]@{ key = "${kind}:$("$id".Trim().ToLowerInvariant())"; kind = $kind; kindLabel = $script:PimDiscoveryKinds[$kind]; id = "$id".Trim(); name = "$name".Trim(); path = "$path".Trim() }) } }
    foreach ($s in @($AzureScopes)) {
        $t = Get-PimDiscoveryField $s 'type'
        if ((Get-PimDiscoveryField $s 'isRoot') -eq 'True') { continue }   # the Tenant Root Group is the platform's own, never "new"
        if ($t -eq 'managementGroup') { & $add 'azure-mg' (Get-PimDiscoveryField $s 'scopePath') (Get-PimDiscoveryField $s 'displayName') (Get-PimDiscoveryField $s 'scopePath') }
        elseif ($t -eq 'subscription') { & $add 'azure-sub' (Get-PimDiscoveryField $s 'scopePath') (Get-PimDiscoveryField $s 'displayName') (Get-PimDiscoveryField $s 'scopePath') }
    }
    foreach ($r in @($EntraRoles)) { $tid = Get-PimDiscoveryField $r 'templateId'; if (-not $tid) { $tid = Get-PimDiscoveryField $r 'id' }; & $add 'entra-role' $tid (Get-PimDiscoveryField $r 'displayName') '' }
    foreach ($r in @($DefenderRoles)) { & $add 'defender-role' (Get-PimDiscoveryField $r 'id') (Get-PimDiscoveryField $r 'name') '' }
    foreach ($r in @($IntuneRoles)) { & $add 'intune-role' (Get-PimDiscoveryField $r 'id') (Get-PimDiscoveryField $r 'name') '' }
    foreach ($w in @($PowerBiWorkspaces)) { & $add 'powerbi-ws' (Get-PimDiscoveryField $w 'workspaceId') (Get-PimDiscoveryField $w 'workspaceName') '' }
    return $out.ToArray()
}

function Get-PimDiscoveryProposal {
    <#
      PURE (uses the naming convention). The permission-group definition an Azure scope / Power BI workspace becomes on
      Create: { base; groupName; groupTag; level; row }. $null for a role kind (accepted, nothing created).
    #>
    param([Parameter(Mandatory)]$Item, [object[]]$Scopes = @())
    if ($Item.kind -in $script:PimDiscoveryRoleKinds) { return $null }
    if ($Item.kind -eq 'powerbi-ws') {
        $seg = ConvertTo-PimNameSegment $Item.name
        $svc = 'PowerBI'
        $name = New-PimPermissionGroupName -Service $svc -Name $seg -Level 4 -Tier 1 -Code 'WDP' -Domain 'DAT' -ScopeSegment $seg
        $tag = New-PimPermissionGroupTag -Service $svc -Name $seg -Level 4 -Tier 1 -Code 'WDP' -Domain 'DAT'
        return [pscustomobject]@{ base = 'PIM-Definitions-Services'; groupName = $name; groupTag = $tag; level = 4
            row = [ordered]@{ GroupName = $name; GroupDescription = "Power BI workspace $($Item.name) ($($Item.id)) -- created from Discovery"; GroupTag = $tag
                              AdministrativeUnitTag = ''; IsRoleAssignable = 'FALSE'; Workload = 'PowerBI'; Level = 'L4'; TierLevel = 'T1'; Plane = 'WDP'; CPPlatform = 'DAT'; Owners = ''; PolicyTemplate = '' } }
    }
    $scopeType = if ($Item.kind -eq 'azure-mg') { 'managementGroup' } else { 'subscription' }
    $d = Get-PimAzureScopeDerivation -ScopeType $scopeType -ScopePath $Item.path -ScopeName $Item.name
    $lvl = Get-PimAzureCafLevel -ScopePath $Item.path -Scopes $Scopes
    $level = if ($null -ne $lvl) { [int]$lvl } else { [int]$d.level }
    $seg = if ($Item.name) { ConvertTo-PimNameSegment $Item.name } else { ConvertTo-PimNameSegment $scopeType }
    $svc = Get-PimServiceName 'azure'
    $name = New-PimPermissionGroupName -Service $svc -Name $seg -Level $level -Tier $d.tier -Code $d.plane -Domain $d.domain -ScopeSegment $seg
    $tag = New-PimPermissionGroupTag -Service $svc -Name $seg -Level $level -Tier $d.tier -Code $d.plane -Domain $d.domain
    return [pscustomobject]@{ base = 'PIM-Definitions-Services'; groupName = $name; groupTag = $tag; level = $level
        row = [ordered]@{ GroupName = $name; GroupDescription = "Azure $($script:PimDiscoveryKinds[$Item.kind].ToLowerInvariant()) $($Item.name) ($($Item.path)) -- created from Discovery"; GroupTag = $tag
                          AdministrativeUnitTag = ''; IsRoleAssignable = 'FALSE'; Workload = 'Azure'; Level = "L$level"; TierLevel = "T$($d.tier)"; Plane = $d.plane; CPPlatform = $d.domain; Owners = ''; PolicyTemplate = '' } }
}

function Get-PimDiscoveryInbox {
    <#
      PURE. Items + decisions + baseline + what the store already defines -> every item with its state:
        new | ignored | staged | accepted | known   (+ proposal for the creatable kinds).
      -Defined: @{ names = @(lower group names); tags = @(lower tags); refs = @(lower scope paths / workspace ids) }.
      -Baseline: @{ '<role kind>' = @(lower ids) } -- a role kind with no baseline yet is reported in 'baselineNeeded'
      and none of its items is new (the caller records the baseline from this read).
    #>
    param([object[]]$Items = @(), [hashtable]$Decisions = @{}, [hashtable]$Baseline = @{}, [hashtable]$Defined = @{}, [object[]]$Scopes = @())
    $names = @{}; foreach ($n in @($Defined['names'])) { if ("$n".Trim()) { $names["$n".Trim().ToLowerInvariant()] = $true } }
    $tags = @{}; foreach ($n in @($Defined['tags'])) { if ("$n".Trim()) { $tags["$n".Trim().ToLowerInvariant()] = $true } }
    $refs = @{}; foreach ($n in @($Defined['refs'])) { if ("$n".Trim()) { $refs["$n".Trim().TrimEnd('/').ToLowerInvariant()] = $true } }
    $needBaseline = New-Object System.Collections.Generic.List[string]
    foreach ($k in $script:PimDiscoveryRoleKinds) { if (@($Items | Where-Object { $_.kind -eq $k }).Count -and -not $Baseline.ContainsKey($k)) { $needBaseline.Add($k) } }
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($it in @($Items)) {
        $dec = $Decisions[$it.key]
        $proposal = $null; $state = 'new'
        if ($it.kind -in $script:PimDiscoveryRoleKinds) {
            $base = @($Baseline[$it.kind])
            if ($needBaseline -contains $it.kind -or ($base -contains $it.id.ToLowerInvariant())) { $state = 'known' }
        } else {
            try { $proposal = Get-PimDiscoveryProposal -Item $it -Scopes $Scopes } catch { $proposal = $null }
            $ref = $it.id.TrimEnd('/').ToLowerInvariant()
            if ($refs.ContainsKey($ref) -or ($proposal -and ($names.ContainsKey($proposal.groupName.ToLowerInvariant()) -or $tags.ContainsKey($proposal.groupTag.ToLowerInvariant())))) { $state = 'known' }
        }
        if ($state -eq 'new' -and $dec) {
            $ds = Get-PimDiscoveryField $dec 'state'
            if ($ds -in @('ignored', 'accepted', 'staged')) { $state = $ds }
        }
        $out.Add([pscustomobject]@{ key = $it.key; kind = $it.kind; kindLabel = $it.kindLabel; id = $it.id; name = $it.name; path = $it.path
            state = $state; decidedBy = (Get-PimDiscoveryField $dec 'by'); decidedUtc = (Get-PimDiscoveryField $dec 'atUtc')
            groupName = $(if ($proposal) { $proposal.groupName } else { '' }); level = $(if ($proposal) { $proposal.level } else { $null }) })
    }
    $all = $out.ToArray()
    return [pscustomobject]@{
        items          = @($all | Where-Object { $_.state -notin @('known', 'accepted') })   # accepted = in the catalog now, like known
        counts         = [ordered]@{ new = @($all | Where-Object { $_.state -eq 'new' }).Count; ignored = @($all | Where-Object { $_.state -eq 'ignored' }).Count
                                     staged = @($all | Where-Object { $_.state -eq 'staged' }).Count; accepted = @($all | Where-Object { $_.state -eq 'accepted' }).Count
                                     known = @($all | Where-Object { $_.state -eq 'known' }).Count }
        baselineNeeded = @($needBaseline.ToArray())
    }
}

function Set-PimDiscoveryDecision {
    <#
      PURE. Apply one action to a decisions map and return the new map. Actions: ignore | unignore | accept | stage.
      'unignore' removes the decision (the item is new again). accept is for role kinds, stage for the creatable ones.
    #>
    param([hashtable]$Decisions = @{}, [Parameter(Mandatory)][string]$Key, [Parameter(Mandatory)][ValidateSet('ignore', 'unignore', 'accept', 'stage')][string]$Action, [string]$By = '', [datetime]$NowUtc = [datetime]::UtcNow)
    $d = @{}; foreach ($k in @($Decisions.Keys)) { $d[$k] = $Decisions[$k] }
    if ($Action -eq 'unignore') { $d.Remove($Key); return $d }
    $state = @{ ignore = 'ignored'; accept = 'accepted'; stage = 'staged' }[$Action]
    $d[$Key] = [ordered]@{ state = $state; by = $By; atUtc = $NowUtc.ToUniversalTime().ToString('o') }
    return $d
}
