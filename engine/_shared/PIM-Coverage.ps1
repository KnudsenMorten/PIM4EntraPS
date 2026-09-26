<#
  PIM4EntraPS -- COVERAGE / GAPS REPORT (REQ-I + REQ-U design point 7), built by the SCHEDULER, served by the Manager.

  WHY THIS FILE EXISTS. REQ-I (operator): "see the difference between existing permission groups fx. against entra
  roles and then any new roles that exist which has NOT been created ... show gaps/missing roles ... create fast ...
  prestage all so i can multiselect". REQ-U extends the same gap pattern to every workload -- Intune and Defender
  roles, Power BI workspaces ("show any power bi workspace which is not delegated with pim"), Azure subscriptions and
  management groups ("same for azure subscriptions not delegated") -- and adds review-only findings for PIM for Groups
  groups PIM4EntraPS does not manage ("it can be any application, like hr app, so we gotta point those out").

  THE SAME DESIGN AS THE DRIFT SNAPSHOT (PIM-DriftSnapshot.ps1):
    * the scheduler job 'coverage' (default every 720 min) reads the tenant caches + pim.Rows, computes the report and
      stores ONE document in SQL pim.TenantCache kind 'coverage-report' (with computedUtc);
    * the Manager only READS that row (ConvertTo-PimCoverageView) and asks for a refresh by queueing a trigger
      (Request-PimCoverageRefresh). The job handler is registered only by tools/pim-scheduler/Start-PimScheduler.ps1;
      the default handler in PIM-Scheduler.ps1 declares the job unimplemented, so the Manager never computes it.

  ROW SHAPE: { key; workload; item; itemId; coveredBy[]; status; reason; proposal; detail }
    status is one of $script:PimCoverageStatuses. proposal = $null or { units:[ { id; label; groupName; groupTag;
    level; rows:[ { entity; row } ] } ] } -- a UNIT is one group plus its binding, staged whole or not at all.

  RULES (operator):
    * NOT CHECKED IS NEVER CLEAN. A source that cannot be read (cache absent, 401/403, feature off) is ONE row with
      status 'Not checked' and its reason -- never an empty list that reads as "no gaps".
    * "IS IT OURS" is decided by the definition rows / GroupTag and the TENANT's naming pattern, never by a prefix.
    * Group names come from the tenant's pattern (Resolve-PimGroupNameFromTag / New-PimPermissionGroupName).
    * Level rule: L2 only for tenant-wide Entra roles scoped to an AU. Workload RBAC: managers / admins L3,
      operators L4, readers L5; readers stay "as today" (Defender readers L4, Intune readers L5). The Entra and
      Azure proposals mirror their shipped packs (templates\entra-roles / azure-rbac .template.json).
    * Unmanaged privileged groups and orphans are REVIEW-ONLY: shown, never proposed, never adopted.

  Dependencies (all optional at load, checked where used): PIM-Naming.ps1 + PIM-PermissionWizard.ps1 (loaded on demand
  for names), tools/pim-manager/_tenantSync.ps1 (Get-/Set-PimTenantCacheEntry, Get-PimTenantSyncRows), PIM-Rest.ps1
  (Invoke-PimGraph / Invoke-PimPowerBI, scheduler only), PIM-Scheduler.ps1 (Add-PimJobTrigger), PIM-JobAlert.ps1
  (Send-PimJobAlertViaNotify). PS 5.1 compatible; pure ASCII.
#>

Set-StrictMode -Off

$script:PimCoverageJobType   = 'coverage'
$script:PimCoverageCacheKind = 'coverage-report'
$script:PimCoverageAlertEvent = 'coverage'
$script:PimCoverageDefaultCadenceMinutes = 720
$script:PimCoverageStatuses = @('Covered', 'Gap', 'Orphan group', 'Unmanaged binding', 'Wrong permissions', 'Unmanaged privileged group', 'Not checked')
# The statuses a NEW occurrence of which is mailed (Covered / Not checked never are).
$script:PimCoverageAlertStatuses = @('Gap', 'Orphan group', 'Unmanaged binding', 'Wrong permissions', 'Unmanaged privileged group')
# Graph reads per unmanaged privileged group (what it grants) are bounded; the rest are listed without grants.
$script:PimCoverageGrantsCap = 50
# Entra roles Microsoft does not allow on a (role-assignable) group -- listed as gaps, never pre-staged.
$script:PimCoverageEntraNotGroupAssignable = @('Directory Synchronization Accounts', 'On Premises Directory Sync Account',
    'Partner Tier1 Support', 'Partner Tier2 Support', 'Guest User', 'Restricted Guest User', 'User', 'Device Users',
    'Device Join', 'Workplace Device Join', 'Device Managers')

# Entities read from pim.Rows. Definitions decide "is it ours"; bindings decide "is it covered".
$script:PimCoverageDefinitionEntities = @('PIM-Definitions-Roles', 'PIM-Definitions-Services', 'PIM-Definitions-Organization',
    'PIM-Definitions-Tasks', 'PIM-Definitions-Departments', 'PIM-Definitions-Processes', 'PIM-Definitions-Projects',
    'PIM-Definitions-CrossOrg', 'PIM-Definitions-Resources')
# Permission-group entities (a group that exists to carry a binding). Direct-group entities (Roles / Organization /
# Departments / Projects / CrossOrg) nest INTO permission groups and are never "orphans" for want of a role.
$script:PimCoveragePermissionEntities = @('PIM-Definitions-Services', 'PIM-Definitions-Tasks', 'PIM-Definitions-Processes')
$script:PimCoverageBindingEntities = @('PIM-Assignments-Roles-Groups', 'PIM-Assignments-Roles-AUs', 'PIM-Assignments-Roles-Direct',
    'PIM-Assignments-Workloads', 'PIM-Assignments-Intune', 'PIM-Assignments-Defender', 'PIM-Assignments-Azure-Resources')

# ===========================================================================
# small PURE helpers
# ===========================================================================
function Get-PimCoverageField {
    param([AllowNull()][object]$Item, [string]$Name)
    if ($null -eq $Item) { return $null }
    if ($Item -is [System.Collections.IDictionary]) { if ($Item.Contains($Name)) { return $Item[$Name] }; return $null }
    $p = $Item.PSObject.Properties[$Name]
    if ($p) { return $p.Value }
    return $null
}

function Get-PimCoverageText {
    # The first non-blank of several column names, trimmed ('' when none).
    param([AllowNull()][object]$Row, [string[]]$Names)
    foreach ($n in @($Names)) { $v = "$(Get-PimCoverageField $Row $n)".Trim(); if ($v) { return $v } }
    return ''
}

function Test-PimCoverageRemovalRow {
    # A row whose Action asks for REMOVAL describes access that should NOT exist -- it covers nothing.
    param([AllowNull()][object]$Row)
    return ((Get-PimCoverageText $Row @('Action')) -match '^(?i)(remove|delete|revoke)')
}

function ConvertTo-PimCoverageWorkloadKind {
    # A Workload value -> 'entra' | 'intune' | 'defender' | 'powerbi' | 'azure' | ''. The Intune / Defender / Power BI
    # spellings are ConvertTo-PimWorkloadBindingKind's (PIM-WorkloadConnectors.ps1), duplicated here so the Manager
    # (which does not load the connectors) and the tick agree.
    param([AllowNull()][string]$Workload)
    $w = ("$Workload".Trim().ToLowerInvariant()) -replace '[^a-z0-9]', ''
    if (-not $w) { return '' }
    if ($w -in @('entraid', 'entra', 'azuread', 'aad', 'entraidroles', 'entraroles')) { return 'entra' }
    if ($w -in @('intune', 'microsoftintune', 'endpointmanager', 'mem', 'intunerbac')) { return 'intune' }
    if ($w -in @('defender', 'defenderxdr', 'microsoftdefender', 'microsoftdefenderxdr', 'm365defender', 'microsoft365defender', 'mde', 'defenderforendpoint')) { return 'defender' }
    if ($w -in @('powerbi', 'fabric', 'powerbifabric')) { return 'powerbi' }
    if ($w -in @('azure', 'azurerbac', 'azres', 'azureresources')) { return 'azure' }
    return ''
}

function Initialize-PimCoverageNaming {
    # The naming + derivation helpers (tenant pattern). Loaded on demand so the Manager, which only reads the stored
    # report, does not have to carry them.
    if (-not (Get-Command Resolve-PimGroupNameFromTag -ErrorAction SilentlyContinue)) {
        $n = Join-Path $PSScriptRoot 'PIM-Naming.ps1'; if (Test-Path -LiteralPath $n) { . $n }
    }
    if (-not (Get-Command Get-PimEntraDerivation -ErrorAction SilentlyContinue)) {
        $w = Join-Path $PSScriptRoot 'PIM-PermissionWizard.ps1'; if (Test-Path -LiteralPath $w) { . $w }
    }
}

function ConvertTo-PimCoverageSegment {
    # A label -> a CamelCase name segment (ConvertTo-PimNameSegment's rule, with a local fallback).
    param([AllowNull()][string]$Text)
    if (Get-Command ConvertTo-PimNameSegment -ErrorAction SilentlyContinue) { return (ConvertTo-PimNameSegment $Text) }
    $t = ("$Text".Trim() -replace '[^A-Za-z0-9 ]', ' ')
    return ((@($t -split '\s+' | Where-Object { $_ }) | ForEach-Object { if ($_.Length -gt 1) { $_.Substring(0, 1).ToUpper() + $_.Substring(1) } else { $_.ToUpper() } }) -join '')
}

function Resolve-PimCoverageNameFromTag {
    # GroupTag -> group NAME: the definition row's GroupName when one exists, else the tenant's pattern around the tag.
    param([string]$Tag, [hashtable]$TagToName = @{})
    $t = "$Tag".Trim(); if (-not $t) { return '' }
    $k = $t.ToLowerInvariant()
    if ($TagToName -and $TagToName.ContainsKey($k) -and "$($TagToName[$k])".Trim()) { return "$($TagToName[$k])".Trim() }
    if (Get-Command Resolve-PimGroupNameFromTag -ErrorAction SilentlyContinue) { return "$(Resolve-PimGroupNameFromTag -Tag $t)" }
    return $t
}

function Get-PimCoverageRoleLevel {
    # PURE. The operator's level rule for a WORKLOAD RBAC role (never L2): managers / administrators L3, operators L4,
    # readers L5 -- except that readers stay "as today", one level below their operator (Defender: operators L3,
    # readers L4).
    param([ValidateSet('intune', 'defender', 'powerbi', 'generic')][string]$Kind = 'generic', [AllowNull()][string]$RoleName)
    $n = "$RoleName"
    $isReader = ($n -match '(?i)read\s*-?\s*only|reader|viewer|\bread\b')
    $isManager = ($n -match '(?i)manager|admin')
    $isOperator = ($n -match '(?i)operator|operations|contributor')
    if ($Kind -eq 'defender') { if ($isReader) { return 4 }; return 3 }
    if ($isReader) { return 5 }
    if ($isManager) { return 3 }
    if ($isOperator) { return 4 }
    return 3
}

function New-PimCoverageRow {
    param([string]$Workload, [string]$Item, [string]$ItemId = '', [string[]]$CoveredBy = @(), [string]$Status, [string]$Reason = '',
          [AllowNull()][object]$Proposal = $null, [AllowNull()][object]$Detail = $null)
    $idPart = if ("$ItemId".Trim()) { "$ItemId".Trim() } else { "$Item".Trim() }
    return [ordered]@{
        key       = ("{0}|{1}|{2}" -f $Workload, $Status, $idPart).ToLowerInvariant()
        workload  = $Workload
        item      = $Item
        itemId    = "$ItemId"
        coveredBy = @(@($CoveredBy) | Where-Object { "$_".Trim() } | Select-Object -Unique)
        status    = $Status
        reason    = $Reason
        proposal  = $Proposal
        detail    = $Detail
    }
}

function New-PimCoverageSource {
    param([string]$Workload, [string]$Source, [bool]$Read, [string]$Reason = '', [AllowNull()][object]$ReadUtc = $null, [int]$Items = 0, [string]$Note = '')
    return [ordered]@{ workload = $Workload; source = $Source; read = $Read; reason = $Reason; readUtc = $(if ($null -ne $ReadUtc) { "$ReadUtc" } else { '' }); items = $Items; note = $Note }
}

function New-PimCoverageUnit {
    param([string]$Id, [string]$Label, [string]$GroupName, [string]$GroupTag, [string]$Level, [object[]]$Rows)
    return [ordered]@{ id = $Id; label = $Label; groupName = $GroupName; groupTag = $GroupTag; level = $Level; rows = @($Rows) }
}

# ===========================================================================
# THE MODEL -- pim.Rows, indexed once
# ===========================================================================
function New-PimCoverageModel {
    <#
      PURE. -Rows: @{ '<entity>' = @(rows) }. Returns the indexes every source evaluator uses:
        definitions (all), tagToName, definedTags, ownedNames (definition GroupNames + every binding tag under the tenant
        pattern + the tag itself, which v1 rows used as the group name), and the raw rows per entity.
    #>
    param([hashtable]$Rows = @{})
    $get = { param($e) if ($Rows.ContainsKey($e)) { @(@($Rows[$e]) | Where-Object { $null -ne $_ }) } else { @() } }
    $defs = New-Object System.Collections.Generic.List[object]
    $tagToName = @{}; $definedTags = @{}; $definedNames = @{}; $owned = @{}
    foreach ($e in $script:PimCoverageDefinitionEntities) {
        foreach ($r in (& $get $e)) {
            $gn = Get-PimCoverageText $r @('GroupName'); if (-not $gn) { continue }   # Department owner rows are not groups
            $tag = Get-PimCoverageText $r @('GroupTag')
            $defs.Add([pscustomobject]@{ entity = $e; GroupName = $gn; GroupTag = $tag
                Workload = (Get-PimCoverageText $r @('Workload')); IsRoleAssignable = (Get-PimCoverageText $r @('IsRoleAssignable'))
                Lifecycle = (Get-PimCoverageText $r @('Lifecycle')) })
            $definedNames[$gn.ToLowerInvariant()] = $true; $owned[$gn.ToLowerInvariant()] = $true
            if ($tag) { $definedTags[$tag.ToLowerInvariant()] = $e; if (-not $tagToName.ContainsKey($tag.ToLowerInvariant())) { $tagToName[$tag.ToLowerInvariant()] = $gn } }
        }
    }
    foreach ($e in $script:PimCoverageBindingEntities) {
        foreach ($r in (& $get $e)) {
            $tag = Get-PimCoverageText $r @('GroupTag'); if (-not $tag) { continue }
            $owned[$tag.ToLowerInvariant()] = $true
            $nm = Resolve-PimCoverageNameFromTag -Tag $tag -TagToName $tagToName
            if ($nm) { $owned[$nm.ToLowerInvariant()] = $true }
        }
    }
    return [pscustomobject]@{
        rows = $Rows; definitions = @($defs.ToArray()); tagToName = $tagToName; definedTags = $definedTags
        definedNames = $definedNames; ownedNames = $owned
    }
}

function Test-PimCoverageTagDefined {
    param([object]$Model, [string]$Tag)
    $t = "$Tag".Trim(); if (-not $t) { return $false }
    if ($Model.definedTags.ContainsKey($t.ToLowerInvariant())) { return $true }
    # v1 rows used the full group NAME as the tag.
    return [bool]$Model.definedNames.ContainsKey($t.ToLowerInvariant())
}

function Get-PimCoverageEntityRows {
    param([object]$Model, [string]$Entity)
    if ($Model.rows.ContainsKey($Entity)) { return @(@($Model.rows[$Entity]) | Where-Object { $null -ne $_ }) }
    return @()
}

function Test-PimCoverageNameMatchesPattern {
    # "Is this ours" by the TENANT's pattern: the name carries the pattern's literal prefix/suffix around a tag.
    param([string]$Name)
    if (-not (Get-Command ConvertFrom-PimGroupNameToTag -ErrorAction SilentlyContinue)) { return $false }
    return [bool]("$(ConvertFrom-PimGroupNameToTag -Name $Name)".Trim())
}

# ===========================================================================
# PROPOSALS (PURE) -- one UNIT = one group + its binding
# ===========================================================================
function New-PimCoverageEntraProposal {
    <#
      A gap Entra directory role -> the Entra pack's shape (templates\entra-roles.template.json): a role-assignable
      PIM-Definitions-Services group 'Entra-ID-<Role>-L<n>' (T0, CP, ID; L0 for the privileged roles, L1 otherwise --
      Get-PimEntraDerivation, the target-first wizard's own brain) plus its PIM-Assignments-Roles-Groups Eligible
      binding. The NAME is the tenant's pattern around '<tag>-T0-CP-ID'. A group already defined under that tag or name
      gets the binding only.
    #>
    param([Parameter(Mandatory)][string]$RoleName, [object]$Model)
    Initialize-PimCoverageNaming
    $level = 1; $seg = ConvertTo-PimCoverageSegment $RoleName; $name = ''
    if (Get-Command Get-PimEntraDerivation -ErrorAction SilentlyContinue) {
        $d = Get-PimEntraDerivation -Roles @($RoleName)
        $level = [int]$d.level; $seg = "$($d.nameSegment)"; $name = "$($d.groupName)"
    }
    if (-not $name) { $name = Resolve-PimCoverageNameFromTag -Tag ("Entra-ID-{0}-L{1}-T0-CP-ID" -f $seg, $level) }
    $tag = "Entra-ID-{0}-L{1}" -f $seg, $level
    $rows = New-Object System.Collections.Generic.List[object]
    $existing = $Model -and ((Test-PimCoverageTagDefined -Model $Model -Tag $tag) -or $Model.definedNames.ContainsKey($name.ToLowerInvariant()))
    if ($existing -and $Model.definedNames.ContainsKey($name.ToLowerInvariant()) -and -not (Test-PimCoverageTagDefined -Model $Model -Tag $tag)) {
        $hit = @($Model.definitions | Where-Object { "$($_.GroupName)" -ieq $name } | Select-Object -First 1)
        if ($hit.Count -and "$($hit[0].GroupTag)".Trim()) { $tag = "$($hit[0].GroupTag)".Trim() }
    }
    if (-not $existing) {
        $rows.Add([ordered]@{ entity = 'PIM-Definitions-Services'; row = [ordered]@{
            GroupName = $name; GroupDescription = "Entra ID - $RoleName"; GroupTag = $tag; AdministrativeUnitTag = "PIM-L$level"
            IsRoleAssignable = 'TRUE'; Workload = 'Entra-ID'; Level = "L$level"; TierLevel = 'T0'; Plane = 'CP'; CPPlatform = 'ID'; Owners = '' } })
    }
    $rows.Add([ordered]@{ entity = 'PIM-Assignments-Roles-Groups'; row = [ordered]@{
        GroupTag = $tag; RoleDefinitionName = $RoleName; AssignmentType = 'Eligible'; Action = 'Assign'; UpdateExisting = 'FALSE'
        AutoExtend = 'TRUE'; NumOfDaysWhenExpire = '90'; Permanent = 'FALSE'; CPPlatform = 'ID'; Plane = 'CP'; TierLevel = 'T0'
        PermissionScope = 'Global'; SyncPlatform = '' } })
    $label = if ($existing) { "Bind '$RoleName' to the existing group $name" } else { "New group $name with '$RoleName' (Eligible, L$level)" }
    return [ordered]@{ units = @(New-PimCoverageUnit -Id ("entra|" + $RoleName.ToLowerInvariant()) -Label $label -GroupName $name -GroupTag $tag -Level "L$level" -Rows @($rows.ToArray())) }
}

function New-PimCoverageWorkloadProposal {
    <#
      A gap Intune / Defender role -> the pack v2 shape: a PIM-Definitions-Services group + its PIM-Assignments-Workloads
      binding (one unit). Intune: tag 'Intune-<Role>-L<n>-T1-WDP-ID' (pack v2, WDP by operator decision). Defender:
      tag 'Defender-XDR-<Role>-L<n>', name '<tag>-T1-MP-ID' under the tenant pattern -- or, when the Defender custom role
      is itself named in the tenant's pattern (the production convention: role named like its group), that name.
    #>
    param([Parameter(Mandatory)][ValidateSet('intune', 'defender')][string]$Kind, [Parameter(Mandatory)][string]$RoleName,
          [bool]$IsBuiltIn = $true, [object]$Model)
    Initialize-PimCoverageNaming
    $level = Get-PimCoverageRoleLevel -Kind $Kind -RoleName $RoleName
    $seg = ConvertTo-PimCoverageSegment $RoleName
    if ($Kind -eq 'intune') {
        $tag = "Intune-{0}-L{1}-T1-WDP-ID" -f $seg, $level
        $name = Resolve-PimCoverageNameFromTag -Tag $tag
        $wl = 'Intune'; $plane = 'WDP'; $connector = 'intune'; $scope = ''; $label0 = 'Intune'
        $notes = $(if ($IsBuiltIn) { 'built-in Intune role' } else { 'custom Intune role' })
    } else {
        $asTag = ''
        if (Get-Command ConvertFrom-PimGroupNameToTag -ErrorAction SilentlyContinue) { $asTag = "$(ConvertFrom-PimGroupNameToTag -Name $RoleName)".Trim() }
        if ($asTag) {
            $name = $RoleName.Trim()
            $tag = ($asTag -replace '(?i)-T\d-(CP|MP|WDP|DP|APP|USER)-(ID|RES|DAT)$', '')
            if ($tag -match '(?i)-L(\d)$') { $level = [int]$Matches[1] }
        } else {
            $tag = "Defender-XDR-{0}-L{1}" -f $seg, $level
            $name = Resolve-PimCoverageNameFromTag -Tag ("{0}-T1-MP-ID" -f $tag)
        }
        $wl = 'Defender-XDR'; $plane = 'MP'; $connector = 'defender-xdr'; $scope = '/'; $label0 = 'Defender XDR'
        $notes = $(if ($IsBuiltIn) { 'built-in Defender XDR role' } else { 'Defender XDR custom role' })
    }
    $rows = New-Object System.Collections.Generic.List[object]
    $existing = $Model -and ((Test-PimCoverageTagDefined -Model $Model -Tag $tag) -or $Model.definedNames.ContainsKey($name.ToLowerInvariant()))
    if (-not $existing) {
        $rows.Add([ordered]@{ entity = 'PIM-Definitions-Services'; row = [ordered]@{
            GroupName = $name; GroupDescription = "$label0 - $RoleName"; GroupTag = $tag; AdministrativeUnitTag = $(if (Get-Command Get-PimPermissionGroupAdminUnit -ErrorAction SilentlyContinue) { Get-PimPermissionGroupAdminUnit 'L1' } else { 'PIM-L1' })
            IsRoleAssignable = 'FALSE'; Workload = $wl; Level = "L$level"; TierLevel = 'T1'; Plane = $plane; CPPlatform = 'ID'; Owners = '' } })
    }
    $rows.Add([ordered]@{ entity = 'PIM-Assignments-Workloads'; row = [ordered]@{
        Workload = $connector; RoleName = $RoleName; GroupTag = $tag; Scope = $scope; Action = 'Assign'; Notes = $notes } })
    $label = if ($existing) { "Bind '$RoleName' to the existing group $name" } else { "New group $name with the $label0 role '$RoleName' (L$level)" }
    return [ordered]@{ units = @(New-PimCoverageUnit -Id ("{0}|{1}" -f $Kind, $RoleName.ToLowerInvariant()) -Label $label -GroupName $name -GroupTag $tag -Level "L$level" -Rows @($rows.ToArray())) }
}

function New-PimCoverageAzureProposal {
    <#
      A gap Azure scope -> the Azure pack's convention (templates\azure-rbac.template.json): Reader L4 Active 365 days and
      Contributor L3 Eligible 90 days, each its OWN group (tag 'AzRes-<Scope>-<Role>-L<n>') -- ONE unit per group: the
      PIM-Definitions-Services row that DEFINES it + its PIM-Assignments-Azure-Resources binding at that scope.
      AZURE GROUP DEFINITION (lead-verified bug, 2026-09-19): this used to propose the binding ALONE ("an Azure group has
      no definition row -- the engine creates it from the assignment"). It does not: the engine creates groups only from
      definition rows (Get-PimGroupDefinitionRows) and the AzRes provider resolves the GroupTag through them, so the
      staged unit was PIM-FK-001 and a group that was never created. The v1 model -- every Azure group a Services row
      (Workload 'Azure'), the Azure-Resources row only binding it -- is what the pack and the wizards now stage. A tag the
      model already defines gets the binding only.
    #>
    param([Parameter(Mandatory)][string]$ScopePath, [string]$ScopeName, [string]$ScopeType = 'subscription', [object]$Model)
    Initialize-PimCoverageNaming
    $alias = ConvertTo-PimCoverageSegment $(if ("$ScopeName".Trim()) { $ScopeName } else { ($ScopePath -split '/')[-1] })
    if (-not $alias) { $alias = 'Scope' }
    $scopeLabel = if ("$ScopeName".Trim()) { "$ScopeName".Trim() } else { $ScopePath }
    $units = New-Object System.Collections.Generic.List[object]
    foreach ($spec in @(@{ role = 'Reader'; level = 4; type = 'Active'; days = '365' }, @{ role = 'Contributor'; level = 3; type = 'Eligible'; days = '90' })) {
        $tag = "AzRes-{0}-{1}-L{2}" -f $alias, $spec.role, $spec.level
        $name = Resolve-PimCoverageNameFromTag -Tag $tag
        $rows = New-Object System.Collections.Generic.List[object]
        $existing = $Model -and (Test-PimCoverageTagDefined -Model $Model -Tag $tag)
        if (-not $existing) {
            $rows.Add([ordered]@{ entity = 'PIM-Definitions-Services'; row = [ordered]@{
                GroupName = $name; GroupDescription = ("Azure - {0} at {1} {2}" -f $spec.role, $ScopeType, $scopeLabel); GroupTag = $tag; AdministrativeUnitTag = ''
                IsRoleAssignable = 'FALSE'; Workload = 'Azure'; Level = ("L{0}" -f $spec.level); TierLevel = 'T1'; Plane = 'MP'; CPPlatform = 'ID'; Owners = ''; PolicyTemplate = '' } })
        }
        $rows.Add([ordered]@{ entity = 'PIM-Assignments-Azure-Resources'; row = [ordered]@{ GroupTag = $tag; AzScope = $ScopePath; AzScopePermission = $spec.role; AssignmentType = $spec.type; Action = 'Assign'
            UpdateExisting = 'FALSE'; AutoExtend = 'TRUE'; NumOfDaysWhenExpire = $spec.days; Permanent = 'FALSE'; CPPlatform = 'ID'; Plane = 'MP'
            TierLevel = 'T1'; PermissionScope = 'Scoped'; SyncPlatform = '' } })
        $label = if ($existing) { "Bind the existing group {0}: {1} at this {2} ({3}, L{4})" -f $name, $spec.role, $ScopeType, $spec.type, $spec.level }
                 else { "New group {0}: {1} at this {2} ({3}, L{4})" -f $name, $spec.role, $ScopeType, $spec.type, $spec.level }
        $units.Add((New-PimCoverageUnit -Id ("azure|{0}|{1}" -f $ScopePath.ToLowerInvariant(), $spec.role.ToLowerInvariant()) `
            -Label $label -GroupName $name -GroupTag $tag -Level ("L{0}" -f $spec.level) -Rows @($rows.ToArray())))
    }
    return [ordered]@{ units = @($units.ToArray()) }
}

function New-PimCoveragePowerBiProposal {
    # A gap Power BI workspace -> Contributor (L4) and Viewer (L5) groups, each a definition + its Workloads binding
    # (connector 'powerbi', Scope = the workspace id), named 'PowerBI-WS-<Workspace>-<Role>-L<n>-T1-WDP-DAT'.
    param([Parameter(Mandatory)][string]$WorkspaceId, [string]$WorkspaceName, [object]$Model)
    Initialize-PimCoverageNaming
    $ws = ConvertTo-PimCoverageSegment $(if ("$WorkspaceName".Trim()) { $WorkspaceName } else { $WorkspaceId })
    if (-not $ws) { $ws = 'Workspace' }
    $units = New-Object System.Collections.Generic.List[object]
    foreach ($role in @('Contributor', 'Viewer')) {
        $level = Get-PimCoverageRoleLevel -Kind 'powerbi' -RoleName $role
        $tag = "PowerBI-WS-{0}-{1}-L{2}-T1-WDP-DAT" -f $ws, $role, $level
        $name = Resolve-PimCoverageNameFromTag -Tag $tag
        $rows = New-Object System.Collections.Generic.List[object]
        if (-not ($Model -and (Test-PimCoverageTagDefined -Model $Model -Tag $tag))) {
            $rows.Add([ordered]@{ entity = 'PIM-Definitions-Services'; row = [ordered]@{
                GroupName = $name; GroupDescription = "Power BI - $role of workspace $WorkspaceName"; GroupTag = $tag; AdministrativeUnitTag = 'PIM-L1'
                IsRoleAssignable = 'FALSE'; Workload = 'PowerBI'; Level = "L$level"; TierLevel = 'T1'; Plane = 'WDP'; CPPlatform = 'DAT'; Owners = '' } })
        }
        $rows.Add([ordered]@{ entity = 'PIM-Assignments-Workloads'; row = [ordered]@{
            Workload = 'powerbi'; RoleName = $role; GroupTag = $tag; Scope = $WorkspaceId; Action = 'Assign'; Notes = "Power BI workspace $WorkspaceName" } })
        $units.Add((New-PimCoverageUnit -Id ("powerbi|{0}|{1}" -f $WorkspaceId.ToLowerInvariant(), $role.ToLowerInvariant()) `
            -Label ("New group {0}: {1} of this workspace (L{2})" -f $name, $role, $level) -GroupName $name -GroupTag $tag -Level "L$level" -Rows @($rows.ToArray())))
    }
    return [ordered]@{ units = @($units.ToArray()) }
}

# ===========================================================================
# SOURCE EVALUATORS (PURE)
# ===========================================================================
function Test-PimCoverageSourceReadable {
    # A source object { read; reason; ... } or $null -> @{ ok; reason }.
    param([AllowNull()][object]$Source, [string]$MissingReason)
    if ($null -eq $Source) { return @{ ok = $false; reason = $MissingReason } }
    $r = Get-PimCoverageField $Source 'read'
    if ($null -ne $r -and -not [bool]$r) {
        $why = "$(Get-PimCoverageField $Source 'reason')".Trim()
        return @{ ok = $false; reason = $(if ($why) { $why } else { 'the source could not be read' }) }
    }
    return @{ ok = $true; reason = '' }
}

function Get-PimCoverageEntraRows {
    param([AllowNull()][object]$Catalog, [object]$Model)
    $W = 'Entra ID'
    $out = New-Object System.Collections.Generic.List[object]
    $chk = Test-PimCoverageSourceReadable -Source $Catalog -MissingReason "the tenant cache holds no Entra role catalog yet (the 'tenant-cache' job writes it)"
    $items = @(if ($chk.ok) { @(Get-PimCoverageField $Catalog 'items') | Where-Object { $null -ne $_ -and "$(Get-PimCoverageField $_ 'displayName')".Trim() } })
    if ($chk.ok -and $items.Count -eq 0) { $chk = @{ ok = $false; reason = 'the Entra role catalog in the tenant cache is EMPTY -- that is a failed read, not a tenant without roles' } }
    $src = New-PimCoverageSource -Workload $W -Source 'tenant cache: entra-roles' -Read $chk.ok -Reason $chk.reason -ReadUtc (Get-PimCoverageField $Catalog 'refreshedUtc') -Items $items.Count
    if (-not $chk.ok) {
        $out.Add((New-PimCoverageRow -Workload $W -Item '(Entra directory role catalog)' -Status 'Not checked' -Reason $chk.reason))
        return [pscustomobject]@{ source = $src; rows = @($out.ToArray()) }
    }
    # role name -> the delegations that grant it
    $byRole = @{}
    $add = { param($role, $text) $k = "$role".Trim().ToLowerInvariant(); if (-not $k) { return }; if (-not $byRole.ContainsKey($k)) { $byRole[$k] = New-Object System.Collections.Generic.List[string] }; $byRole[$k].Add($text) }
    $boundTags = @{}
    foreach ($e in @('PIM-Assignments-Roles-Groups', 'PIM-Assignments-Roles-AUs')) {
        foreach ($r in (Get-PimCoverageEntityRows -Model $Model -Entity $e)) {
            if (Test-PimCoverageRemovalRow $r) { continue }
            $role = Get-PimCoverageText $r @('RoleDefinitionName', 'RoleName'); $tag = Get-PimCoverageText $r @('GroupTag')
            if (-not $role) { continue }
            $gname = Resolve-PimCoverageNameFromTag -Tag $tag -TagToName $Model.tagToName
            $au = Get-PimCoverageText $r @('AdministrativeUnitTag')
            & $add $role $(if ($au) { "$gname (AU $au)" } else { $gname })
            if ($tag) { $boundTags[$tag.ToLowerInvariant()] = $true }
            if ($tag -and -not (Test-PimCoverageTagDefined -Model $Model -Tag $tag)) {
                $out.Add((New-PimCoverageRow -Workload $W -Item ("{0} -> {1}" -f $role, $tag) -ItemId ("binding|{0}|{1}" -f $e, "$tag|$role") -CoveredBy @($gname) -Status 'Unmanaged binding' `
                    -Reason ("a {0} row binds '{1}' to the group tag '{2}', but no PIM4EntraPS definition row defines that group -- the engine cannot resolve it" -f $e, $role, $tag)))
            }
        }
    }
    foreach ($r in (Get-PimCoverageEntityRows -Model $Model -Entity 'PIM-Assignments-Roles-Direct')) {
        if (Test-PimCoverageRemovalRow $r) { continue }
        $role = Get-PimCoverageText $r @('RoleDefinitionName', 'RoleName')
        $who = Get-PimCoverageText $r @('UserPrincipalName', 'Username', 'UPN', 'upn')
        if ($role) { & $add $role ("direct: {0}" -f $(if ($who) { $who } else { '(an admin)' })) }
    }
    $catalogNames = @{}
    $notAssignable = @($script:PimCoverageEntraNotGroupAssignable | ForEach-Object { "$_".ToLowerInvariant() })
    foreach ($it in @($items | Sort-Object { "$(Get-PimCoverageField $_ 'displayName')" })) {
        $name = "$(Get-PimCoverageField $it 'displayName')".Trim(); $id = "$(Get-PimCoverageField $it 'id')".Trim()
        $k = $name.ToLowerInvariant(); $catalogNames[$k] = $true
        $builtIn = Get-PimCoverageField $it 'isBuiltIn'
        $kindTxt = if ($null -ne $builtIn -and -not [bool]$builtIn) { 'custom role' } else { 'built-in role' }
        if ($byRole.ContainsKey($k)) {
            $out.Add((New-PimCoverageRow -Workload $W -Item $name -ItemId $id -CoveredBy @($byRole[$k].ToArray()) -Status 'Covered' -Reason ("delegated ({0})" -f $kindTxt)))
        } elseif ($notAssignable -contains $k) {
            $out.Add((New-PimCoverageRow -Workload $W -Item $name -ItemId $id -Status 'Gap' `
                -Reason ("no permission group grants this {0} -- Microsoft does not allow it to be assigned to a group, so nothing is pre-staged" -f $kindTxt)))
        } else {
            $out.Add((New-PimCoverageRow -Workload $W -Item $name -ItemId $id -Status 'Gap' -Reason ("no permission group grants this {0}" -f $kindTxt) `
                -Proposal (New-PimCoverageEntraProposal -RoleName $name -Model $Model)))
        }
    }
    # A binding to a role the tenant does not have: the group holds no role.
    foreach ($k in @($byRole.Keys)) {
        if ($catalogNames.ContainsKey($k)) { continue }
        foreach ($via in @($byRole[$k].ToArray() | Where-Object { $_ -notmatch '^direct:' })) {
            $out.Add((New-PimCoverageRow -Workload $W -Item $via -ItemId ("unknown-role|{0}|{1}" -f $k, $via) -CoveredBy @($via) -Status 'Orphan group' `
                -Reason ("bound to the Entra role '{0}', which the tenant's role catalog does not contain -- the group holds no role" -f $k)))
        }
    }
    # A role-assignable Entra permission group with no role binding at all.
    foreach ($d in @($Model.definitions)) {
        if ($script:PimCoveragePermissionEntities -notcontains $d.entity) { continue }
        if ((ConvertTo-PimCoverageWorkloadKind $d.Workload) -ne 'entra') { continue }
        if ("$($d.IsRoleAssignable)" -notmatch '^(?i)(true|yes|1)$') { continue }
        if ("$($d.Lifecycle)" -match '^(?i)retire') { continue }
        $t = "$($d.GroupTag)".Trim()
        if (($t -and $boundTags.ContainsKey($t.ToLowerInvariant())) -or $boundTags.ContainsKey("$($d.GroupName)".ToLowerInvariant())) { continue }
        $out.Add((New-PimCoverageRow -Workload $W -Item $d.GroupName -ItemId ("def|{0}" -f $d.GroupName) -CoveredBy @($d.GroupName) -Status 'Orphan group' `
            -Reason ("a role-assignable Entra ID permission group ({0}, tag '{1}') with no PIM-Assignments-Roles-Groups / -Roles-AUs row -- it grants no role" -f $d.entity, $t)))
    }
    return [pscustomobject]@{ source = $src; rows = @($out.ToArray()) }
}

function Get-PimCoverageExpectedActions {
    # The expected permission list a binding / definition row carries (Permissions / Actions / RolePermissions,
    # separated by ; , or |), or $null when none is stated.
    param([object[]]$Rows)
    foreach ($r in @($Rows)) {
        $v = Get-PimCoverageText $r @('Permissions', 'AllowedResourceActions', 'Actions', 'RolePermissions', 'AllowedActions')
        if ($v) { return @($v -split '[;,|]' | ForEach-Object { "$_".Trim() } | Where-Object { $_ }) }
    }
    return $null
}

function Get-PimCoverageWorkloadRows {
    <#
      Intune / Defender. -Source = pim.TenantCache kind 'workload-roles:<service>' { read; reason; readUtc;
      roles:[{ name; id; isBuiltIn; actions?; assignments? }] } written by the discovery job.
    #>
    param([Parameter(Mandatory)][ValidateSet('intune', 'defender')][string]$Kind, [AllowNull()][object]$Source, [object]$Model)
    $W = if ($Kind -eq 'intune') { 'Intune' } else { 'Defender XDR' }
    $out = New-Object System.Collections.Generic.List[object]
    $chk = Test-PimCoverageSourceReadable -Source $Source -MissingReason ("discovery has not run yet -- no {0} role catalog is cached (pim.TenantCache 'workload-roles:{1}')" -f $W, $Kind)
    $roles = @(if ($chk.ok) { @(Get-PimCoverageField $Source 'roles') | Where-Object { $null -ne $_ -and "$(Get-PimCoverageField $_ 'name')".Trim() } })
    if ($chk.ok -and $roles.Count -eq 0) { $chk = @{ ok = $false; reason = "the cached $W role catalog is EMPTY -- that is a failed read, not a tenant without roles" } }
    $src = New-PimCoverageSource -Workload $W -Source ("tenant cache: workload-roles:{0}" -f $Kind) -Read $chk.ok -Reason $chk.reason -ReadUtc (Get-PimCoverageField $Source 'readUtc') -Items $roles.Count
    # Bindings in pim.Rows (desired): PIM-Assignments-Workloads (connector kind) + the per-workload entity.
    $bindEnt = if ($Kind -eq 'intune') { 'PIM-Assignments-Intune' } else { 'PIM-Assignments-Defender' }
    $bindings = New-Object System.Collections.Generic.List[object]
    foreach ($r in (Get-PimCoverageEntityRows -Model $Model -Entity 'PIM-Assignments-Workloads')) {
        if ((ConvertTo-PimCoverageWorkloadKind (Get-PimCoverageText $r @('Workload'))) -ne $Kind) { continue }
        if (Test-PimCoverageRemovalRow $r) { continue }
        $bindings.Add([pscustomobject]@{ entity = 'PIM-Assignments-Workloads'; role = (Get-PimCoverageText $r @('RoleName', 'RoleDefinitionName')); tag = (Get-PimCoverageText $r @('GroupTag')); row = $r })
    }
    foreach ($r in (Get-PimCoverageEntityRows -Model $Model -Entity $bindEnt)) {
        if (Test-PimCoverageRemovalRow $r) { continue }
        $bindings.Add([pscustomobject]@{ entity = $bindEnt; role = (Get-PimCoverageText $r @('RoleDefinitionName', 'RoleName')); tag = (Get-PimCoverageText $r @('GroupTag')); row = $r })
    }
    $boundTags = @{}
    foreach ($b in $bindings) {
        if ($b.tag) { $boundTags[$b.tag.ToLowerInvariant()] = $true }
        if ($b.tag -and -not (Test-PimCoverageTagDefined -Model $Model -Tag $b.tag)) {
            $out.Add((New-PimCoverageRow -Workload $W -Item ("{0} -> {1}" -f $b.role, $b.tag) -ItemId ("binding|{0}|{1}|{2}" -f $b.entity, $b.tag, $b.role) -CoveredBy @($b.tag) -Status 'Unmanaged binding' `
                -Reason ("a {0} row binds the {1} role '{2}' to '{3}', which no PIM4EntraPS definition row defines" -f $b.entity, $W, $b.role, $b.tag)))
        }
    }
    # A definition with this workload and no binding row: the group exists with no workload role (REQ-U orphan).
    foreach ($d in @($Model.definitions)) {
        if ((ConvertTo-PimCoverageWorkloadKind $d.Workload) -ne $Kind) { continue }
        if ("$($d.Lifecycle)" -match '^(?i)retire') { continue }
        $t = "$($d.GroupTag)".Trim()
        if (($t -and $boundTags.ContainsKey($t.ToLowerInvariant())) -or $boundTags.ContainsKey("$($d.GroupName)".ToLowerInvariant())) { continue }
        $out.Add((New-PimCoverageRow -Workload $W -Item $d.GroupName -ItemId ("def|{0}" -f $d.GroupName) -CoveredBy @($d.GroupName) -Status 'Orphan group' `
            -Reason ("the group is defined for {0} (tag '{1}') but has no binding row ({2} / PIM-Assignments-Workloads) -- it holds no {0} role" -f $W, $t, $bindEnt)))
    }
    if (-not $chk.ok) {
        $out.Insert(0, (New-PimCoverageRow -Workload $W -Item ("({0} role catalog)" -f $W) -Status 'Not checked' -Reason $chk.reason))
        return [pscustomobject]@{ source = $src; rows = @($out.ToArray()) }
    }
    $byRole = @{}
    foreach ($b in $bindings) { $k = "$($b.role)".Trim().ToLowerInvariant(); if (-not $k) { continue }; if (-not $byRole.ContainsKey($k)) { $byRole[$k] = New-Object System.Collections.Generic.List[object] }; $byRole[$k].Add($b) }
    $catalog = @{}
    foreach ($ro in @($roles | Sort-Object { "$(Get-PimCoverageField $_ 'name')" })) {
        $name = "$(Get-PimCoverageField $ro 'name')".Trim(); $id = "$(Get-PimCoverageField $ro 'id')".Trim(); $k = $name.ToLowerInvariant()
        $catalog[$k] = $true
        $bi = Get-PimCoverageField $ro 'isBuiltIn'; $isBuiltIn = ($null -eq $bi -or [bool]$bi)
        if ($byRole.ContainsKey($k)) {
            $bs = @($byRole[$k].ToArray())
            $names = @($bs | ForEach-Object { Resolve-PimCoverageNameFromTag -Tag $_.tag -TagToName $Model.tagToName })
            $status = 'Covered'; $why = 'delegated'
            $expected = Get-PimCoverageExpectedActions -Rows @($bs | ForEach-Object { $_.row })
            $live = @(Get-PimCoverageField $ro 'actions') | Where-Object { "$_".Trim() }
            if ($Kind -eq 'defender' -and $null -ne $expected -and @($live).Count -and (Get-Command Get-PimDefenderSpecDifference -ErrorAction SilentlyContinue)) {
                # The Defender role spec's own comparison (PIM-WorkloadRoles.ps1) -- one answer for the engine and this page.
                $diffs = @($bs | ForEach-Object { "$(Get-PimDefenderSpecDifference -Desired $_.row -LiveActions @($live) -LiveDataSources $null)" } | Where-Object { $_.Trim() })
                if ($diffs.Count) { $status = 'Wrong permissions'; $why = "the live role's permissions differ from the stated ones -- " + ($diffs[0]) }
            } elseif ($null -ne $expected -and @($live).Count) {
                $e = @($expected | ForEach-Object { "$_".ToLowerInvariant() }); $l = @($live | ForEach-Object { "$_".Trim().ToLowerInvariant() })
                $missing = @($e | Where-Object { $l -notcontains $_ }); $extra = @($l | Where-Object { $e -notcontains $_ })
                if ($missing.Count -or $extra.Count) {
                    $status = 'Wrong permissions'
                    $why = "the live role's permissions differ from the stated ones" +
                        $(if ($missing.Count) { "; missing: " + (@($missing | Select-Object -First 5) -join ', ') }) +
                        $(if ($extra.Count) { "; extra: " + (@($extra | Select-Object -First 5) -join ', ') })
                }
            }
            $out.Add((New-PimCoverageRow -Workload $W -Item $name -ItemId $id -CoveredBy $names -Status $status -Reason $why))
        } else {
            $out.Add((New-PimCoverageRow -Workload $W -Item $name -ItemId $id -Status 'Gap' `
                -Reason ("no PIM group is bound to this {0} role ({1})" -f $W, $(if ($isBuiltIn) { 'built-in' } else { 'custom' })) `
                -Proposal (New-PimCoverageWorkloadProposal -Kind $Kind -RoleName $name -IsBuiltIn $isBuiltIn -Model $Model)))
        }
        # Live assignments, when the discovery job cached them: a role on a group PIM4EntraPS does not define.
        foreach ($a in @(@(Get-PimCoverageField $ro 'assignments') | Where-Object { $null -ne $_ })) {
            $gn = Get-PimCoverageText $a @('groupName', 'principalName', 'displayName')
            $gid = Get-PimCoverageText $a @('groupId', 'principalId', 'id')
            if (-not $gn -and -not $gid) { continue }
            if ($gn -and $Model.ownedNames.ContainsKey($gn.ToLowerInvariant())) { continue }
            $out.Add((New-PimCoverageRow -Workload $W -Item ("{0} -> {1}" -f $name, $(if ($gn) { $gn } else { $gid })) -ItemId ("live|{0}|{1}" -f $id, $(if ($gid) { $gid } else { $gn })) -Status 'Unmanaged binding' `
                -Reason ("the tenant assigns the {0} role '{1}' to '{2}', which PIM4EntraPS does not define -- review it" -f $W, $name, $(if ($gn) { $gn } else { $gid }))))
        }
    }
    foreach ($k in @($byRole.Keys)) {
        if ($catalog.ContainsKey($k)) { continue }
        foreach ($b in @($byRole[$k].ToArray())) {
            $gn = Resolve-PimCoverageNameFromTag -Tag $b.tag -TagToName $Model.tagToName
            $out.Add((New-PimCoverageRow -Workload $W -Item $gn -ItemId ("unknown-role|{0}|{1}" -f $k, $b.tag) -CoveredBy @($gn) -Status 'Orphan group' `
                -Reason ("bound to the {0} role '{1}', which the tenant does not have -- the group holds no {0} role" -f $W, $b.role)))
        }
    }
    return [pscustomobject]@{ source = $src; rows = @($out.ToArray()) }
}

function ConvertTo-PimCoverageScopeKey {
    param([AllowNull()][string]$Scope)
    $s = "$Scope".Trim().TrimEnd('/')
    return $s.ToLowerInvariant()
}

function Get-PimCoverageAzureRows {
    # Azure subscriptions + management groups (pim.TenantCache 'azure-scopes') vs PIM-Assignments-Azure-Resources.
    param([AllowNull()][object]$Scopes, [object]$Model)
    $W = 'Azure'
    $out = New-Object System.Collections.Generic.List[object]
    $chk = Test-PimCoverageSourceReadable -Source $Scopes -MissingReason "the tenant cache holds no Azure scope list yet (the 'tenant-cache' job writes it)"
    $items = @(if ($chk.ok) { @(Get-PimCoverageField $Scopes 'items') | Where-Object { $null -ne $_ -and "$(Get-PimCoverageField $_ 'scopePath')".Trim() -and "$(Get-PimCoverageField $_ 'type')" -in @('subscription', 'managementGroup') } })
    if ($chk.ok -and $items.Count -eq 0) { $chk = @{ ok = $false; reason = 'the cached Azure scope list is EMPTY -- the engine identity may have no ARM read access, so this is not proof that the tenant has no subscriptions' } }
    $src = New-PimCoverageSource -Workload $W -Source 'tenant cache: azure-scopes' -Read $chk.ok -Reason $chk.reason -ReadUtc (Get-PimCoverageField $Scopes 'refreshedUtc') -Items $items.Count
    if (-not $chk.ok) {
        $out.Add((New-PimCoverageRow -Workload $W -Item '(Azure subscriptions and management groups)' -Status 'Not checked' -Reason $chk.reason))
        return [pscustomobject]@{ source = $src; rows = @($out.ToArray()) }
    }
    $az = @(Get-PimCoverageEntityRows -Model $Model -Entity 'PIM-Assignments-Azure-Resources' | Where-Object { -not (Test-PimCoverageRemovalRow $_) -and (Get-PimCoverageText $_ @('AzScope')) })
    $live = @{}
    foreach ($it in $items) { $live[(ConvertTo-PimCoverageScopeKey (Get-PimCoverageField $it 'scopePath'))] = $it }
    foreach ($it in @($items | Sort-Object { "$(Get-PimCoverageField $_ 'type')" }, { "$(Get-PimCoverageField $_ 'displayName')" })) {
        $path = "$(Get-PimCoverageField $it 'scopePath')".Trim(); $key = ConvertTo-PimCoverageScopeKey $path
        $type = "$(Get-PimCoverageField $it 'type')"; $disp = "$(Get-PimCoverageField $it 'displayName')".Trim(); if (-not $disp) { $disp = $path }
        $typeTxt = if ($type -eq 'managementGroup') { 'management group' } else { 'subscription' }
        $exact = @($az | Where-Object { (ConvertTo-PimCoverageScopeKey (Get-PimCoverageText $_ @('AzScope'))) -eq $key })
        $below = @($az | Where-Object { (ConvertTo-PimCoverageScopeKey (Get-PimCoverageText $_ @('AzScope'))).StartsWith($key + '/') })
        $label = "{0} ({1})" -f $disp, $typeTxt
        if ($exact.Count) {
            $by = @($exact | ForEach-Object { "{0} ({1})" -f (Resolve-PimCoverageNameFromTag -Tag (Get-PimCoverageText $_ @('GroupTag')) -TagToName $Model.tagToName), (Get-PimCoverageText $_ @('AzScopePermission')) })
            $out.Add((New-PimCoverageRow -Workload $W -Item $label -ItemId $path -CoveredBy $by -Status 'Covered' -Reason ("{0} delegation(s) at this scope" -f $exact.Count)))
        } elseif ($below.Count -and $type -eq 'subscription') {
            $by = @($below | ForEach-Object { "{0} ({1} at {2})" -f (Resolve-PimCoverageNameFromTag -Tag (Get-PimCoverageText $_ @('GroupTag')) -TagToName $Model.tagToName), (Get-PimCoverageText $_ @('AzScopePermission')), (Get-PimCoverageText $_ @('AzScope')) })
            $out.Add((New-PimCoverageRow -Workload $W -Item $label -ItemId $path -CoveredBy $by -Status 'Covered' -Reason ("delegated below this subscription ({0} resource group / resource delegation(s)), none at the subscription itself" -f $below.Count)))
        } else {
            $out.Add((New-PimCoverageRow -Workload $W -Item $label -ItemId $path -Status 'Gap' -Reason ("no PIM delegation at this {0}" -f $typeTxt) `
                -Proposal (New-PimCoverageAzureProposal -ScopePath $path -ScopeName $disp -ScopeType $typeTxt -Model $Model)))
        }
    }
    # A delegation whose scope the tenant does not list: the group holds no role assignment there.
    foreach ($r in $az) {
        $scope = Get-PimCoverageText $r @('AzScope'); $sk = ConvertTo-PimCoverageScopeKey $scope
        $anchor = ''
        if ($sk -match '^(/subscriptions/[^/]+)') { $anchor = $Matches[1] }
        elseif ($sk -match '^(/providers/microsoft\.management/managementgroups/[^/]+)') { $anchor = $Matches[1] }
        if (-not $anchor -or $live.ContainsKey($anchor)) { continue }
        $gn = Resolve-PimCoverageNameFromTag -Tag (Get-PimCoverageText $r @('GroupTag')) -TagToName $Model.tagToName
        $out.Add((New-PimCoverageRow -Workload $W -Item ("{0} ({1} at {2})" -f $gn, (Get-PimCoverageText $r @('AzScopePermission')), $scope) -ItemId ("orphan|{0}|{1}" -f $scope, (Get-PimCoverageText $r @('GroupTag'))) -CoveredBy @($gn) -Status 'Orphan group' `
            -Reason ("its scope is not in the Azure scope list the engine identity can see (deleted, moved, or no read access) -- the group may hold no role assignment there")))
    }
    return [pscustomobject]@{ source = $src; rows = @($out.ToArray()) }
}

function Get-PimCoveragePowerBiRows {
    # Power BI workspaces { read; reason; readUtc; workspaces:[{ id; name }] } vs PIM-Assignments-Workloads (powerbi).
    param([AllowNull()][object]$Source, [object]$Model)
    $W = 'Power BI'
    $out = New-Object System.Collections.Generic.List[object]
    $chk = Test-PimCoverageSourceReadable -Source $Source -MissingReason 'no Power BI workspace list was read (the coverage job reads it through the Power BI admin API)'
    $ws = @(if ($chk.ok) { @(Get-PimCoverageField $Source 'workspaces') | Where-Object { $null -ne $_ -and "$(Get-PimCoverageField $_ 'id')".Trim() } })
    $src = New-PimCoverageSource -Workload $W -Source 'Power BI admin API: workspaces' -Read $chk.ok -Reason $chk.reason -ReadUtc (Get-PimCoverageField $Source 'readUtc') -Items $ws.Count
    $bind = @(Get-PimCoverageEntityRows -Model $Model -Entity 'PIM-Assignments-Workloads' | Where-Object { (ConvertTo-PimCoverageWorkloadKind (Get-PimCoverageText $_ @('Workload'))) -eq 'powerbi' -and -not (Test-PimCoverageRemovalRow $_) })
    if (-not $chk.ok) {
        $out.Add((New-PimCoverageRow -Workload $W -Item '(Power BI workspaces)' -Status 'Not checked' -Reason $chk.reason))
        return [pscustomobject]@{ source = $src; rows = @($out.ToArray()) }
    }
    $liveIds = @{}
    foreach ($wsItem in @($ws | Sort-Object { "$(Get-PimCoverageField $_ 'name')" })) {
        $id = "$(Get-PimCoverageField $wsItem 'id')".Trim(); $nm = "$(Get-PimCoverageField $wsItem 'name')".Trim(); if (-not $nm) { $nm = $id }
        $liveIds[$id.ToLowerInvariant()] = $true
        $hits = @($bind | Where-Object { (Get-PimCoverageText $_ @('Scope', 'Resource')) -ieq $id })
        if ($hits.Count) {
            $by = @($hits | ForEach-Object { "{0} ({1})" -f (Resolve-PimCoverageNameFromTag -Tag (Get-PimCoverageText $_ @('GroupTag')) -TagToName $Model.tagToName), (Get-PimCoverageText $_ @('RoleName')) })
            $out.Add((New-PimCoverageRow -Workload $W -Item $nm -ItemId $id -CoveredBy $by -Status 'Covered' -Reason 'delegated'))
        } else {
            $out.Add((New-PimCoverageRow -Workload $W -Item $nm -ItemId $id -Status 'Gap' -Reason 'no PIM delegation on this workspace' `
                -Proposal (New-PimCoveragePowerBiProposal -WorkspaceId $id -WorkspaceName $nm -Model $Model)))
        }
    }
    foreach ($b in $bind) {
        $sc = Get-PimCoverageText $b @('Scope', 'Resource'); if (-not $sc -or $liveIds.ContainsKey($sc.ToLowerInvariant())) { continue }
        $gn = Resolve-PimCoverageNameFromTag -Tag (Get-PimCoverageText $b @('GroupTag')) -TagToName $Model.tagToName
        $out.Add((New-PimCoverageRow -Workload $W -Item $gn -ItemId ("orphan|{0}|{1}" -f $sc, (Get-PimCoverageText $b @('GroupTag'))) -CoveredBy @($gn) -Status 'Orphan group' `
            -Reason ("bound to the Power BI workspace '{0}', which the workspace list does not contain -- the group holds no workspace role" -f $sc)))
    }
    return [pscustomobject]@{ source = $src; rows = @($out.ToArray()) }
}

function Get-PimCoveragePimForGroupsRows {
    <#
      REVIEW-ONLY. -Snapshot = pim.TenantCache 'active-assignments' (the active-assignments snapshot job):
      { refreshedUtc; rows; surfaceErrors; ok }. -Grants = @{ groupId -> { appRoles[]; licences[]; errors[] } } (the job's
      bounded Graph reads). A group holding PIM-for-Groups assignments that no definition / tag / binding covers is an
      'Unmanaged privileged group' -- or an 'Orphan group' when it carries the tenant's naming pattern (named like ours,
      defined nowhere). Never proposed, never adopted.
    #>
    param([AllowNull()][object]$Snapshot, [hashtable]$Grants = @{}, [object]$Model, [int]$GrantsCap = $script:PimCoverageGrantsCap)
    $W = 'PIM for Groups'
    $out = New-Object System.Collections.Generic.List[object]
    $chk = Test-PimCoverageSourceReadable -Source $Snapshot -MissingReason "the active-assignments snapshot has not run yet (job 'active-assignments-snapshot')"
    $note = 'from ACTIVE PIM-for-Groups assignment schedules (the active-assignments snapshot); a group whose members are only ELIGIBLE is not detected here'
    if ($chk.ok) {
        $okV = Get-PimCoverageField $Snapshot 'ok'
        $pfgErr = @(@(Get-PimCoverageField $Snapshot 'surfaceErrors') | Where-Object { "$(Get-PimCoverageField $_ 'surface')" -eq 'pim-for-groups' } | Select-Object -First 1)
        if ($pfgErr.Count) { $chk = @{ ok = $false; reason = ("the PIM-for-Groups read failed in the active-assignments snapshot: {0}" -f "$(Get-PimCoverageField $pfgErr[0] 'error')") } }
        elseif ($null -ne $okV -and -not [bool]$okV) { $chk = @{ ok = $false; reason = ("the active-assignments snapshot failed: {0}" -f "$(Get-PimCoverageField $Snapshot 'error')") } }
    }
    $allRows = @(if ($chk.ok) { @(Get-PimCoverageField $Snapshot 'rows') | Where-Object { $null -ne $_ } })
    $pfg = @($allRows | Where-Object { "$(Get-PimCoverageField $_ 'type')" -eq 'pim-for-groups' -and "$(Get-PimCoverageField $_ 'groupId')".Trim() })
    $byGroup = [ordered]@{}
    foreach ($r in $pfg) { $g = "$(Get-PimCoverageField $r 'groupId')".Trim(); if (-not $byGroup.Contains($g)) { $byGroup[$g] = New-Object System.Collections.Generic.List[object] }; $byGroup[$g].Add($r) }
    $src = New-PimCoverageSource -Workload $W -Source 'tenant cache: active-assignments' -Read $chk.ok -Reason $chk.reason -ReadUtc (Get-PimCoverageField $Snapshot 'refreshedUtc') -Items $byGroup.Count -Note $note
    if (-not $chk.ok) {
        $out.Add((New-PimCoverageRow -Workload $W -Item '(groups onboarded to PIM for Groups)' -Status 'Not checked' -Reason $chk.reason))
        return [pscustomobject]@{ source = $src; rows = @($out.ToArray()) }
    }
    $entraByPrincipal = @{}
    foreach ($r in @($allRows | Where-Object { "$(Get-PimCoverageField $_ 'type')" -eq 'entra-role' })) {
        $p = "$(Get-PimCoverageField $r 'principalId')".Trim().ToLowerInvariant(); if (-not $p) { continue }
        if (-not $entraByPrincipal.ContainsKey($p)) { $entraByPrincipal[$p] = New-Object System.Collections.Generic.List[string] }
        $sc = "$(Get-PimCoverageField $r 'scope')".Trim()
        $entraByPrincipal[$p].Add(("{0}{1}" -f "$(Get-PimCoverageField $r 'role')", $(if ($sc -and $sc -ne '/' -and $sc -notmatch '^(?i)directory$|^tenant') { " ($sc)" } else { '' })))
    }
    $n = 0
    foreach ($gid in @($byGroup.Keys)) {
        $rs = @($byGroup[$gid].ToArray())
        $gname = "$(Get-PimCoverageField $rs[0] 'scope')".Trim(); if (-not $gname -or $gname -eq $gid) { $gname = $gid }
        if ($Model.ownedNames.ContainsKey($gname.ToLowerInvariant())) { continue }   # ours: a definition, a tag or a binding names it
        $members = @($rs | Where-Object { "$(Get-PimCoverageField $_ 'accessId')" -ne 'owner' })
        $owners  = @($rs | Where-Object { "$(Get-PimCoverageField $_ 'accessId')" -eq 'owner' })
        $who = @($rs | ForEach-Object { "$(Get-PimCoverageField $_ 'principal')" } | Where-Object { $_ } | Select-Object -Unique -First 5)
        $gr = $null; if ($Grants -and $Grants.ContainsKey($gid)) { $gr = $Grants[$gid] }
        $detail = [ordered]@{
            groupId = $gid; activeMembers = $members.Count; activeOwners = $owners.Count; principals = @($who)
            entraRoles = @(if ($entraByPrincipal.ContainsKey($gid.ToLowerInvariant())) { $entraByPrincipal[$gid.ToLowerInvariant()].ToArray() | Select-Object -Unique })
            appRoles   = @(if ($gr) { @(Get-PimCoverageField $gr 'appRoles') | Where-Object { $_ } })
            licences   = @(if ($gr) { @(Get-PimCoverageField $gr 'licences') | Where-Object { $_ } })
            grantsRead = [bool]$gr
            grantsNote = $(if ($gr) { (@(Get-PimCoverageField $gr 'errors') | Where-Object { $_ }) -join '; ' } elseif ($n -ge $GrantsCap) { "app roles and licences not read: only the first $GrantsCap groups are read per run" } else { 'app roles and licences were not read in this run' })
        }
        $n++
        $grantsTxt = @()
        if ($detail.entraRoles.Count) { $grantsTxt += ("Entra roles: " + ($detail.entraRoles -join ', ')) }
        if ($detail.appRoles.Count)   { $grantsTxt += ("apps: " + (@($detail.appRoles | Select-Object -First 5) -join ', ')) }
        if ($detail.licences.Count)   { $grantsTxt += ("licences: " + (@($detail.licences | Select-Object -First 5) -join ', ')) }
        $grantsLine = if ($grantsTxt.Count) { ' Grants ' + ($grantsTxt -join '; ') + '.' } else { '' }
        $status = 'Unmanaged privileged group'
        $why = ("onboarded to PIM for Groups ({0} active member(s), {1} owner(s)) and no PIM4EntraPS definition covers it -- review what it gates.{2}" -f $members.Count, $owners.Count, $grantsLine)
        if (Test-PimCoverageNameMatchesPattern -Name $gname) {
            $status = 'Orphan group'
            $why = ("named in the tenant's PIM group pattern and onboarded to PIM for Groups ({0} active member(s)), but no PIM4EntraPS definition row covers it -- a leftover of a removed definition?{1}" -f $members.Count, $grantsLine)
        }
        $out.Add((New-PimCoverageRow -Workload $W -Item $gname -ItemId $gid -Status $status -Reason $why -Detail $detail))
    }
    return [pscustomobject]@{ source = $src; rows = @($out.ToArray()) }
}

# ===========================================================================
# THE REPORT (PURE)
# ===========================================================================
function Get-PimCoverageReport {
    <#
      PURE over -Inputs (gathered by Get-PimCoverageInputs in the scheduler, stubbed in tests):
        @{ rows = @{ '<entity>' = @(rows) }; rowsErrors = @{ '<entity>' = 'why' };
           entraRoles; workloadRoles = @{ intune; defender }; azureScopes; powerBi; pimForGroups; grants = @{ gid -> {...} } }
      Returns { computedUtc; ok; counts; countsByWorkload; sources[]; rows[]; statuses[]; pattern }.
      A source whose inputs cannot be read is ONE 'Not checked' row with the reason (never an empty list).
    #>
    param([hashtable]$Inputs = @{}, [datetime]$NowUtc = [datetime]::UtcNow)
    Initialize-PimCoverageNaming
    $rows = if ($Inputs.ContainsKey('rows') -and $Inputs['rows'] -is [hashtable]) { $Inputs['rows'] } else { @{} }
    $rowsErr = if ($Inputs.ContainsKey('rowsErrors') -and $Inputs['rowsErrors'] -is [hashtable]) { $Inputs['rowsErrors'] } else { @{} }
    $model = New-PimCoverageModel -Rows $rows
    $wr = if ($Inputs.ContainsKey('workloadRoles') -and $Inputs['workloadRoles'] -is [hashtable]) { $Inputs['workloadRoles'] } else { @{} }
    $grants = if ($Inputs.ContainsKey('grants') -and $Inputs['grants'] -is [hashtable]) { $Inputs['grants'] } else { @{} }

    $defErr = @($script:PimCoverageDefinitionEntities | Where-Object { $rowsErr.ContainsKey($_) })
    $blocked = {
        param([string[]]$Needs)
        $bad = @($defErr) + @(@($Needs) | Where-Object { $rowsErr.ContainsKey($_) })
        if (-not $bad.Count) { return '' }
        return ("the desired state could not be read ({0}: {1})" -f $bad[0], "$($rowsErr[$bad[0]])")
    }
    $plan = @(
        @{ workload = 'Entra ID';       needs = @('PIM-Assignments-Roles-Groups', 'PIM-Assignments-Roles-AUs', 'PIM-Assignments-Roles-Direct'); run = { Get-PimCoverageEntraRows -Catalog $Inputs['entraRoles'] -Model $model } }
        @{ workload = 'Intune';         needs = @('PIM-Assignments-Workloads', 'PIM-Assignments-Intune');   run = { Get-PimCoverageWorkloadRows -Kind 'intune' -Source $wr['intune'] -Model $model } }
        @{ workload = 'Defender XDR';   needs = @('PIM-Assignments-Workloads', 'PIM-Assignments-Defender'); run = { Get-PimCoverageWorkloadRows -Kind 'defender' -Source $wr['defender'] -Model $model } }
        @{ workload = 'Power BI';       needs = @('PIM-Assignments-Workloads');                             run = { Get-PimCoveragePowerBiRows -Source $Inputs['powerBi'] -Model $model } }
        @{ workload = 'Azure';          needs = @('PIM-Assignments-Azure-Resources');                       run = { Get-PimCoverageAzureRows -Scopes $Inputs['azureScopes'] -Model $model } }
        @{ workload = 'PIM for Groups'; needs = @($script:PimCoverageBindingEntities);                      run = { Get-PimCoveragePimForGroupsRows -Snapshot $Inputs['pimForGroups'] -Grants $grants -Model $model } }
    )
    $sources = New-Object System.Collections.Generic.List[object]
    $all = New-Object System.Collections.Generic.List[object]
    foreach ($p in $plan) {
        $why = & $blocked $p.needs
        if ($why) {
            $sources.Add((New-PimCoverageSource -Workload $p.workload -Source 'pim.Rows' -Read $false -Reason $why))
            $all.Add((New-PimCoverageRow -Workload $p.workload -Item "($($p.workload))" -Status 'Not checked' -Reason $why))
            continue
        }
        try {
            $res = & $p.run
            $sources.Add($res.source)
            foreach ($r in @($res.rows)) { $all.Add($r) }
        } catch {
            $m = "the coverage check itself failed for this source: $($_.Exception.Message)"
            $sources.Add((New-PimCoverageSource -Workload $p.workload -Source 'coverage' -Read $false -Reason $m))
            $all.Add((New-PimCoverageRow -Workload $p.workload -Item "($($p.workload))" -Status 'Not checked' -Reason $m))
        }
    }
    $counts = [ordered]@{}; foreach ($s in $script:PimCoverageStatuses) { $counts[$s] = 0 }
    $byW = [ordered]@{}
    foreach ($r in $all) {
        $counts[$r.status] = [int]$counts[$r.status] + 1
        if (-not $byW.Contains($r.workload)) { $byW[$r.workload] = [ordered]@{}; foreach ($s in $script:PimCoverageStatuses) { $byW[$r.workload][$s] = 0 } }
        $byW[$r.workload][$r.status] = [int]$byW[$r.workload][$r.status] + 1
    }
    $pattern = ''
    if (Get-Command Get-PimNamingConvention -ErrorAction SilentlyContinue) { try { $pattern = "$(Get-PimNamingConvention -Key 'PimGroupPattern')" } catch { $pattern = '' } }
    return [ordered]@{
        computedUtc      = $NowUtc.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ', [System.Globalization.CultureInfo]::InvariantCulture)
        # ok = every source was read (NOT "no gaps"). A partly-read report is ok=$false.
        ok               = (@($sources | Where-Object { -not $_.read }).Count -eq 0)
        counts           = $counts
        countsByWorkload = $byW
        sourcesNotChecked = @($sources | Where-Object { -not $_.read }).Count
        sources          = @($sources.ToArray())
        rows             = @($all.ToArray())
        statuses         = @($script:PimCoverageStatuses)
        pattern          = $pattern
    }
}

function Get-PimCoverageNewFindings {
    # PURE. Rows of -Current whose key (workload|status|item) was not in -Previous and whose status is mailed.
    param([AllowNull()][object]$Previous, [AllowNull()][object]$Current)
    $seen = @{}
    foreach ($r in @(@(Get-PimCoverageField $Previous 'rows') | Where-Object { $null -ne $_ })) { $k = "$(Get-PimCoverageField $r 'key')"; if ($k) { $seen[$k] = $true } }
    return @(@(Get-PimCoverageField $Current 'rows') | Where-Object {
        $null -ne $_ -and ($script:PimCoverageAlertStatuses -contains "$(Get-PimCoverageField $_ 'status')") -and -not $seen.ContainsKey("$(Get-PimCoverageField $_ 'key')") })
}

# ===========================================================================
# GATHER -- the scheduler reads caches, rows and (bounded) Graph; tests stub these
# ===========================================================================
function Get-PimCoverageCacheEntry {
    # One pim.TenantCache kind, parsed, or $null. Kinds outside _tenantSync's list ('workload-roles:<service>', written
    # by the discovery jobs) are read from the SQL store directly -- never an error that would hide the source.
    param([Parameter(Mandatory)][string]$Kind)
    if ($script:PimTenantCacheKinds -and ($script:PimTenantCacheKinds -contains $Kind) -and (Get-Command Get-PimTenantCacheEntry -ErrorAction SilentlyContinue)) {
        return (Get-PimTenantCacheEntry -Kind $Kind)
    }
    $cs = $null
    if (Get-Command Get-PimTenantCacheStoreCs -ErrorAction SilentlyContinue) { $cs = Get-PimTenantCacheStoreCs }
    if ($cs -and (Get-Command Get-PimSqlTenantCache -ErrorAction SilentlyContinue)) {
        try { return (Get-PimSqlTenantCache -ConnectionString $cs -Kind $Kind) } catch { Write-Warning ("  [coverage] SQL read of '{0}' failed: {1}" -f $Kind, $_.Exception.Message); return $null }
    }
    if ($script:PimTenantCacheMem -and $script:PimTenantCacheMem.ContainsKey($Kind)) { try { return ($script:PimTenantCacheMem[$Kind] | ConvertFrom-Json) } catch { return $null } }
    return $null
}

function Get-PimCoverageRowsFromStore {
    # Every entity the report needs -> @{ rows; rowsErrors }. A failed read is recorded, never an empty list.
    $rows = @{}; $errs = @{}
    foreach ($e in @($script:PimCoverageDefinitionEntities + $script:PimCoverageBindingEntities)) {
        try {
            if (Get-Command Get-PimTenantSyncRows -ErrorAction SilentlyContinue) { $rows[$e] = @(Get-PimTenantSyncRows -Entity $e) }
            elseif (Get-Command Get-PimDesiredRows -ErrorAction SilentlyContinue) { $rows[$e] = @(Get-PimDesiredRows -Entity $e) }
            else { throw 'no desired-state reader is loaded in this process' }
        } catch { $errs[$e] = "$($_.Exception.Message)" }
    }
    return @{ rows = $rows; rowsErrors = $errs }
}

function Read-PimCoveragePowerBiWorkspaces {
    # The tenant's Power BI workspaces through the ADMIN API -> { read; reason; readUtc; workspaces }. The per-identity
    # /groups list is NOT a fallback: it shows only workspaces the engine identity belongs to, which would read as
    # "everything else is covered". A refused read (401/403: no Power BI admin API grant) is NOT CHECKED with its reason.
    $now = [datetime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ', [System.Globalization.CultureInfo]::InvariantCulture)
    if (-not (Get-Command Invoke-PimPowerBI -ErrorAction SilentlyContinue)) {
        return [ordered]@{ read = $false; reason = 'the Power BI REST client (PIM-Rest.ps1) is not loaded on this worker'; readUtc = $now; workspaces = @() }
    }
    try {
        $ws = @(Invoke-PimPowerBI -Path "/admin/groups?`$top=5000&`$filter=type eq 'Workspace'" -All)
        return [ordered]@{ read = $true; reason = ''; readUtc = $now; workspaces = @($ws | Where-Object { $_ -and "$($_.id)" } | ForEach-Object { [ordered]@{ id = "$($_.id)"; name = "$($_.name)" } }) }
    } catch {
        $m = "$($_.Exception.Message)"
        $why = if ($m -match '(?i)\b401\b|unauthori[sz]ed') { "the engine identity has no Power BI admin API grant (401): $m" }
               elseif ($m -match '(?i)\b403\b|forbidden') { "the Power BI admin API refused the engine identity (403 -- 'Allow service principals to use read-only admin APIs' is off or the identity is not in its group): $m" }
               else { "the Power BI workspace read failed: $m" }
        return [ordered]@{ read = $false; reason = $why; readUtc = $now; workspaces = @() }
    }
}

function Read-PimCoverageGroupGrants {
    # What each unmanaged PIM-for-Groups group grants, where Graph can tell: app role assignments and group-assigned
    # licences (Entra roles come from the active-assignments snapshot itself). Bounded to -Cap groups; every failure is
    # recorded on that group, never thrown.
    param([string[]]$GroupIds = @(), [int]$Cap = $script:PimCoverageGrantsCap)
    $out = @{}
    if (-not (Get-Command Invoke-PimGraph -ErrorAction SilentlyContinue)) { return $out }
    $skuNames = @{}; $skuErr = ''
    try { foreach ($s in @(Invoke-PimGraph -Path "/subscribedSkus?`$select=skuId,skuPartNumber" -All)) { if ($s.skuId) { $skuNames["$($s.skuId)".ToLowerInvariant()] = "$($s.skuPartNumber)" } } }
    catch { $skuErr = "licence names could not be read: $($_.Exception.Message)" }
    foreach ($gid in @($GroupIds | Select-Object -First $Cap)) {
        $g = [ordered]@{ appRoles = @(); licences = @(); errors = @() }
        $errs = New-Object System.Collections.Generic.List[string]
        if ($skuErr) { $errs.Add($skuErr) }
        try {
            $ara = @(Invoke-PimGraph -Path ("/groups/{0}/appRoleAssignments?`$select=resourceDisplayName,appRoleId" -f [uri]::EscapeDataString($gid)) -All)
            $g.appRoles = @($ara | ForEach-Object { "$($_.resourceDisplayName)" } | Where-Object { $_ } | Select-Object -Unique)
        } catch { $errs.Add("app role assignments: $($_.Exception.Message)") }
        try {
            $go = Invoke-PimGraph -Path ("/groups/{0}?`$select=id,assignedLicenses" -f [uri]::EscapeDataString($gid))
            $g.licences = @(@($go.assignedLicenses) | Where-Object { $_ -and $_.skuId } | ForEach-Object { $k = "$($_.skuId)".ToLowerInvariant(); if ($skuNames.ContainsKey($k)) { $skuNames[$k] } else { "$($_.skuId)" } })
        } catch { $errs.Add("licences: $($_.Exception.Message)") }
        $g.errors = @($errs.ToArray())
        $out[$gid] = $g
    }
    return $out
}

function Get-PimCoverageInputs {
    # The scheduler's gather. -SkipLive: caches + rows only (no Power BI / Graph reads).
    param([switch]$SkipLive)
    $st = Get-PimCoverageRowsFromStore
    $inp = @{
        rows = $st.rows; rowsErrors = $st.rowsErrors
        entraRoles   = (Get-PimCoverageCacheEntry -Kind 'entra-roles')
        azureScopes  = (Get-PimCoverageCacheEntry -Kind 'azure-scopes')
        pimForGroups = (Get-PimCoverageCacheEntry -Kind 'active-assignments')
        workloadRoles = @{ intune = (Get-PimCoverageCacheEntry -Kind 'workload-roles:intune'); defender = (Get-PimCoverageCacheEntry -Kind 'workload-roles:defender') }
        powerBi = $null; grants = @{}
    }
    if ($SkipLive) {
        $inp.powerBi = [ordered]@{ read = $false; reason = 'not read in this run (-SkipLive)'; workspaces = @() }
        return $inp
    }
    $inp.powerBi = Read-PimCoveragePowerBiWorkspaces
    # Candidate unmanaged groups: in the snapshot, not owned. The pure evaluator decides; this only bounds the reads.
    try {
        $model = New-PimCoverageModel -Rows $st.rows
        $cand = @(@(Get-PimCoverageField $inp.pimForGroups 'rows') | Where-Object { $_ -and "$(Get-PimCoverageField $_ 'type')" -eq 'pim-for-groups' -and
            -not $model.ownedNames.ContainsKey("$(Get-PimCoverageField $_ 'scope')".Trim().ToLowerInvariant()) } |
            ForEach-Object { "$(Get-PimCoverageField $_ 'groupId')".Trim() } | Where-Object { $_ } | Select-Object -Unique)
        if ($cand.Count) { $inp.grants = Read-PimCoverageGroupGrants -GroupIds $cand }
    } catch { Write-Warning "[coverage] what the unmanaged groups grant could not be read: $($_.Exception.Message)" }
    return $inp
}

# ===========================================================================
# THE SCHEDULER JOB -- 'coverage'
# ===========================================================================
function Invoke-PimCoverageJob {
    <#
      Compute the coverage report and persist it as pim.TenantCache kind 'coverage-report'.
      -WhatIf reads and writes NOTHING. No SQL store -> REFUSED (unimplemented), never a memory-only write the Manager
      could never read. The desired state unreadable -> the report is STORED (the page shows why) and the job THROWS.
      NEW gaps / orphans / unmanaged groups since the previous report -> the 'coverage' alert (the first run is the
      baseline and mails nothing).
    #>
    param([object]$Job, [datetime]$NowUtc = [datetime]::UtcNow, [switch]$WhatIf, [hashtable]$Inputs)
    $type = $script:PimCoverageJobType
    $kind = $script:PimCoverageCacheKind
    if ($WhatIf) {
        return [pscustomobject]@{ ran = $false; whatIf = $true
            detail = "whatif:$type -- would compare the tenant caches (Entra roles, workload roles, Azure scopes, Power BI, PIM for Groups) with pim.Rows and write pim.TenantCache/$kind (nothing read, nothing written)" }
    }
    if (-not (Get-Command Set-PimTenantCacheEntry -ErrorAction SilentlyContinue) -or -not (Get-Command Get-PimTenantCacheStoreCs -ErrorAction SilentlyContinue)) {
        return [pscustomobject]@{ ran = $false; unimplemented = $true; whatIf = $false
            detail = "unimplemented:$type (tools/pim-manager/_tenantSync.ps1 is not loaded on this worker -- no tenant-cache store to write to)" }
    }
    if (-not (Get-PimTenantCacheStoreCs)) {
        return [pscustomobject]@{ ran = $false; unimplemented = $true; whatIf = $false
            detail = "unimplemented:$type -- no SQL store in this process, so the report could only live in memory where the Manager can never read it" }
    }
    if (Get-Command Import-PimSchedulerSettingsFromStore -ErrorAction SilentlyContinue) { try { [void](Import-PimSchedulerSettingsFromStore) } catch { } }   # the tenant's naming pattern
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $previous = $null
    try { $previous = Get-PimCoverageCacheEntry -Kind $kind } catch { $previous = $null }
    if (-not $PSBoundParameters.ContainsKey('Inputs') -or $null -eq $Inputs) { $Inputs = Get-PimCoverageInputs }
    $doc = Get-PimCoverageReport -Inputs $Inputs -NowUtc $NowUtc
    $sw.Stop()
    $doc['durationSeconds'] = [math]::Round($sw.Elapsed.TotalSeconds, 1)
    $doc['source'] = 'scheduler'
    $doc['correlationId'] = "$($global:PIM_JobCorrelationId)"
    $new = @()
    if ($null -ne $previous -and "$(Get-PimCoverageField $previous 'computedUtc')".Trim()) { $new = @(Get-PimCoverageNewFindings -Previous $previous -Current $doc) }
    $doc['newSinceLast'] = @($new | ForEach-Object { $_.key })
    $doc['baseline'] = ($null -eq $previous)
    $where = Set-PimTenantCacheEntry -Kind $kind -Value $doc

    $c = $doc.counts
    $sum = "covered={0} gap={1} orphan={2} unmanaged-binding={3} wrong-permissions={4} unmanaged-privileged-group={5} not-checked={6} in {7}s -> {8}" -f `
        $c['Covered'], $c['Gap'], $c['Orphan group'], $c['Unmanaged binding'], $c['Wrong permissions'], $c['Unmanaged privileged group'], $c['Not checked'], $doc.durationSeconds, $where
    if ($new.Count) {
        $byS = @($new | Group-Object { "$($_.status)" } | ForEach-Object { "{0} {1}" -f $_.Count, $_.Name.ToLowerInvariant() }) -join ', '
        $title = "Coverage: $($new.Count) new finding(s) -- $byS"
        $detail = (@($new | Select-Object -First 10 | ForEach-Object { "[{0}] {1}: {2}" -f $_.status, $_.workload, $_.item }) -join '; ') + $(if ($new.Count -gt 10) { "; +$($new.Count - 10) more on the Coverage & gaps page" } else { '' })
        try {
            if (Get-Command Send-PimManagerAlert -ErrorAction SilentlyContinue) {
                [void](Send-PimManagerAlert -Event $script:PimCoverageAlertEvent -Title $title -Detail $detail -LinkTab 'coverage')
            } elseif (Get-Command Send-PimJobAlertViaNotify -ErrorAction SilentlyContinue) {
                [void](Send-PimJobAlertViaNotify -Event $script:PimCoverageAlertEvent -Title $title -Detail $detail -LinkTab 'coverage')
            }
        } catch { Write-Warning "[$type] the coverage alert could not be raised: $($_.Exception.Message)" }
    }
    $defFail = @($script:PimCoverageDefinitionEntities | Where-Object { $Inputs['rowsErrors'] -is [hashtable] -and $Inputs['rowsErrors'].ContainsKey($_) })
    if ($defFail.Count) {
        throw ("[$type] the definitions could not be read, so nothing could be checked; the report was stored so the Coverage & gaps page shows why. " + "$($defFail[0]): $($Inputs['rowsErrors'][$defFail[0]])")
    }
    $nc = @($doc.sources | Where-Object { -not $_.read })
    $tail = if ($nc.Count) { " | NOT CHECKED: " + (@($nc | ForEach-Object { "$($_.workload) ($($_.reason))" }) -join '; ') } else { '' }
    $tail += $(if ($null -eq $previous) { ' | baseline run (nothing mailed)' } elseif ($new.Count) { " | $($new.Count) new finding(s) alerted" } else { ' | no new findings' })
    return [pscustomobject]@{ ran = $true; whatIf = $false; newFindings = $new.Count; notChecked = $nc.Count; detail = "$type`: $sum$tail" }
}

# ===========================================================================
# THE MANAGER'S SIDE -- read the stored report, ask for a refresh. Never computes.
# ===========================================================================
function Request-PimCoverageRefresh {
    # Queue an on-demand 'coverage' run (deduped by type+scope inside Add-PimJobTrigger). Never throws.
    param([string]$Reason = 'manager')
    if (-not (Get-Command Add-PimJobTrigger -ErrorAction SilentlyContinue)) {
        return [pscustomobject]@{ queued = $false; error = 'the scheduler trigger queue (PIM-Scheduler.ps1) is not loaded in this process' }
    }
    try {
        [void](Add-PimJobTrigger -Type $script:PimCoverageJobType -Scope 'All' -Reason $Reason)
        $still = @()
        if (Get-Command Get-PimPendingTriggers -ErrorAction SilentlyContinue) { $still = @(Get-PimPendingTriggers | Where-Object { "$($_.type)" -eq $script:PimCoverageJobType }) }
        if (-not $still.Count) { return [pscustomobject]@{ queued = $false; error = 'the trigger was written but could not be read back from the scheduler queue' } }
        return [pscustomobject]@{ queued = $true; error = '' }
    } catch {
        return [pscustomobject]@{ queued = $false; error = "$($_.Exception.Message)" }
    }
}

function ConvertTo-PimCoverageIsoStamp {
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [DateTimeOffset]) { return $Value.UtcDateTime.ToString('yyyy-MM-ddTHH:mm:ssZ', [System.Globalization.CultureInfo]::InvariantCulture) }
    if ($Value -is [datetime]) {
        $d = if ($Value.Kind -eq [DateTimeKind]::Unspecified) { [datetime]::SpecifyKind($Value, [DateTimeKind]::Utc) } else { $Value.ToUniversalTime() }
        return $d.ToString('yyyy-MM-ddTHH:mm:ssZ', [System.Globalization.CultureInfo]::InvariantCulture)
    }
    $s = "$Value".Trim(); if (-not $s) { return $null }
    return $s
}

function ConvertTo-PimCoverageView {
    <#
      PURE. A stored report (or $null) -> the GET /api/coverage response:
        { ok; supported; snapshotMissing; computedUtc; ageSeconds; cadenceMinutes; stale; hint; counts; countsByWorkload;
          sources; rows; statuses; refreshQueued; refreshError; newSinceLast; pattern }
    #>
    param([AllowNull()][object]$Entry, [datetime]$NowUtc = [datetime]::UtcNow, [int]$CadenceMinutes = 0,
          [bool]$RefreshQueued = $false, [string]$QueueError = '')
    if ($CadenceMinutes -le 0) { $CadenceMinutes = $script:PimCoverageDefaultCadenceMinutes }
    $zero = [ordered]@{}; foreach ($s in $script:PimCoverageStatuses) { $zero[$s] = 0 }
    $computed = if ($null -ne $Entry) { ConvertTo-PimCoverageIsoStamp -Value (Get-PimCoverageField $Entry 'computedUtc') } else { $null }
    if ($null -eq $Entry -or -not "$computed".Trim()) {
        $hint = if ($RefreshQueued) { 'No coverage check has run yet -- one is queued. The scheduler runs it within a few minutes.' }
                elseif ("$QueueError".Trim()) { "No coverage check has run yet, and one could NOT be queued ($QueueError). The scheduler job 'coverage' runs it every $CadenceMinutes min." }
                else { "No coverage check has run yet. The scheduler job 'coverage' runs it every $CadenceMinutes min; Check now queues one." }
        return [ordered]@{ ok = $true; supported = $true; snapshotMissing = $true; computedUtc = $null; ageSeconds = $null; cadenceMinutes = $CadenceMinutes
            stale = $false; hint = $hint; counts = $zero; countsByWorkload = [ordered]@{}; sources = @(); rows = @(); statuses = @($script:PimCoverageStatuses)
            refreshQueued = [bool]$RefreshQueued; refreshError = "$QueueError"; newSinceLast = @(); pattern = '' }
    }
    $c = $null
    try { $c = [datetime]::Parse($computed, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]'AdjustToUniversal,AssumeUniversal') } catch { $c = $null }
    $age = if ($c) { [int64][math]::Max(0, [math]::Round(($NowUtc.ToUniversalTime() - $c).TotalSeconds, 0)) } else { $null }
    $stale = ($null -ne $age) -and ($age -gt (2 * $CadenceMinutes * 60))
    $asOf = if ($c) { $c.ToString('yyyy-MM-dd HH:mm', [System.Globalization.CultureInfo]::InvariantCulture) + ' UTC' } else { "$computed" }
    $hint = "as of $asOf (checked every $CadenceMinutes min)"
    if ($RefreshQueued) { $hint += '; a new check is queued -- results in a few minutes' }
    elseif ("$QueueError".Trim()) { $hint += "; a new check could NOT be queued ($QueueError)" }
    if ($stale) { $hint += "; STALE -- older than two cadences, check the 'coverage' job on the Jobs page" }
    $counts = Get-PimCoverageField $Entry 'counts'; if ($null -eq $counts) { $counts = $zero }
    $okV = Get-PimCoverageField $Entry 'ok'
    return [ordered]@{
        ok = $(if ($null -ne $okV) { [bool]$okV } else { $true }); supported = $true; snapshotMissing = $false
        computedUtc = $computed; ageSeconds = $age; cadenceMinutes = $CadenceMinutes; stale = [bool]$stale; hint = $hint
        counts = $counts; countsByWorkload = (Get-PimCoverageField $Entry 'countsByWorkload')
        sources = @(@(Get-PimCoverageField $Entry 'sources') | Where-Object { $null -ne $_ })
        rows = @(@(Get-PimCoverageField $Entry 'rows') | Where-Object { $null -ne $_ })
        statuses = @($script:PimCoverageStatuses)
        refreshQueued = [bool]$RefreshQueued; refreshError = "$QueueError"
        newSinceLast = @(@(Get-PimCoverageField $Entry 'newSinceLast') | Where-Object { $_ })
        pattern = "$(Get-PimCoverageField $Entry 'pattern')"
        durationSeconds = (Get-PimCoverageField $Entry 'durationSeconds')
    }
}
