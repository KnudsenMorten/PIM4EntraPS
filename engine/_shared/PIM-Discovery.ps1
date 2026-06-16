# PIM4EntraPS -- discovery layer (REST-only, module-free) for the NEW engine.
#
# Three discovery jobs (DESIGN §17.13 / scheduler "Discovery = 3 jobs"):
#   * Entra  -- new built-in directory roles (-> catalog for the import planner)
#   * Azure  -- new management groups / subscriptions (-> Azure reconcile planner)
#   * PowerBI-- new workspaces (-> propose PIM groups; NEVER auto-map to anyone)
#
# This file supplies:
#   1. LIVE enumerators over PIM-Rest (ARM + Graph + Power BI) -- the only side-
#      effecting parts; each is best-effort + returns @() on failure so a missing
#      permission/adapter never crashes a run.
#   2. PURE planners (testable offline, no Graph): Power BI workspace derivation +
#      reconcile (create/rename/orphan/unchanged, same shape as PIM-AzureDiscovery),
#      a service/role catalog folder, an auto-map gate (discovered -> desired rows),
#      and delta refinement (surface ONLY not-yet-handled items so handled items
#      never reappear -- the "array-index delta" pattern from REQUIREMENTS §8).
#
# Constraints honoured: REST-only (no Az/Graph modules), cert app-only auth via
# PIM-Rest, PS 5.1 (no ?./??/RSA.ImportFromPem; @() wraps WHOLE pipelines), group-
# centric (every proposal is a PIM group), and NEVER auto-map a discovered scope to
# a principal by default (auto-import only CREATEs the empty permission-group
# container; assigning admins stays a human decision).
#
# Dot-sourced alongside PIM-AzureDiscovery.ps1 / PIM-PermissionWizard.ps1, which
# provide ConvertTo-PimNameSegment / New-PimPermissionGroupName / the Azure planner.

Set-StrictMode -Off

# ===========================================================================
# Power BI workspace discovery -- PURE derivation + reconcile
# ===========================================================================

function Get-PimPowerBiWorkspaceDerivation {
    # Scope-only permission-group derivation for a Power BI workspace. Mirrors
    # Get-PimAzureScopeDerivation: returns the CONTAINER group the business later
    # links workspace roles to. Power BI is a workload/data plane -> WDP, T1, DAT;
    # level fixed at 3 (service-admin rung, per DESIGN's L3-T1 service-admin band).
    #   Name: PIM-PowerBI-WS-{Workspace}-L3-T1-WDP-DAT
    param(
        [Parameter(Mandatory)][string]$WorkspaceName,
        [string]$WorkspaceId,
        [int]$Level = 3
    )
    $seg  = if ("$WorkspaceName".Trim()) { ConvertTo-PimNameSegment $WorkspaceName } else { ConvertTo-PimNameSegment $WorkspaceId }
    if (-not $seg) { $seg = 'Workspace' }
    $name = New-PimPermissionGroupName -Service 'PowerBI' -Name ("WS-" + $seg) -Level $Level -Tier 1 -Code 'WDP' -Domain 'DAT'
    return [pscustomobject]@{ level = $Level; tier = 1; plane = 'WDP'; domain = 'DAT'; workspaceId = "$WorkspaceId"; groupName = $name }
}

function Get-PimPowerBiStableKey {
    # Stable identity of a workspace across renames: the workspace GUID. A renamed
    # workspace keeps its id -> detected as a rename, not an orphan + duplicate.
    param([Parameter(Mandatory)][string]$WorkspaceId)
    return ("pbiws:" + ("$WorkspaceId".Trim())).ToLowerInvariant()
}

function Get-PimPowerBiReconcilePlan {
    # Discovered workspaces vs existing PIM definitions -> create / rename / orphan /
    # unchanged (identical contract + output shape to Get-PimAzureReconcilePlan, so the
    # Manager/queue treat both discoveries the same).
    #   Discovered item: @{ workspaceId; workspaceName }
    #   Existing item:   @{ workspaceId; workspaceName; groupName(current) }
    # AutoImport: a discovered workspace becomes a CREATE with autoImport=$true only when
    # $AutoImport is set (Power BI proposals default to a human decision -- never auto-map).
    param(
        [object[]]$Discovered = @(),
        [object[]]$Existing = @(),
        [switch]$AutoImport
    )
    $exIndex = @{}
    foreach ($e in @($Existing)) {
        $id = "$($e.workspaceId)"; if (-not $id) { continue }
        $exIndex[(Get-PimPowerBiStableKey -WorkspaceId $id)] = $e
    }
    $create    = New-Object System.Collections.Generic.List[object]
    $rename    = New-Object System.Collections.Generic.List[object]
    $unchanged = New-Object System.Collections.Generic.List[object]
    $seen = @{}
    foreach ($d in @($Discovered)) {
        $id = "$($d.workspaceId)"; if (-not $id) { continue }
        $k = Get-PimPowerBiStableKey -WorkspaceId $id
        $seen[$k] = $true
        $exp = Get-PimPowerBiWorkspaceDerivation -WorkspaceName "$($d.workspaceName)" -WorkspaceId $id
        if ($exIndex.ContainsKey($k)) {
            $cur = $exIndex[$k]
            if ("$($cur.groupName)" -ne "$($exp.groupName)") {
                $rename.Add([pscustomobject]@{ stableKey=$k; workspaceId=$id; from="$($cur.groupName)"; to="$($exp.groupName)"; expected=$exp })
            } else {
                $unchanged.Add([pscustomobject]@{ stableKey=$k; workspaceId=$id; groupName="$($exp.groupName)" })
            }
        } else {
            $create.Add([pscustomobject]@{ stableKey=$k; workspaceId=$id; workspaceName="$($d.workspaceName)"; expected=$exp; autoImport=[bool]$AutoImport })
        }
    }
    $orphan = New-Object System.Collections.Generic.List[object]
    foreach ($e in @($Existing)) {
        $id = "$($e.workspaceId)"; if (-not $id) { continue }
        $k = Get-PimPowerBiStableKey -WorkspaceId $id
        if (-not $seen.ContainsKey($k)) { $orphan.Add([pscustomobject]@{ stableKey=$k; workspaceId=$id; groupName="$($e.groupName)" }) }
    }
    return [pscustomobject]@{
        create=$create.ToArray(); rename=$rename.ToArray(); orphan=$orphan.ToArray(); unchanged=$unchanged.ToArray()
        summary=[ordered]@{ create=$create.Count; rename=$rename.Count; orphan=$orphan.Count; unchanged=$unchanged.Count
                            autoCreate=@($create | Where-Object { $_.autoImport }).Count }
    }
}

function ConvertTo-PimPowerBiQueueChanges {
    # Power BI reconcile plan -> change-queue records (same as ConvertTo-PimReconcileQueueChanges):
    # auto-imports -> Create; renames -> Update (carry from/to); orphans -> Remove ONLY when
    # -IncludeOrphanRemovals (deletion is destructive). Non-auto creates need a human decision.
    param(
        [Parameter(Mandatory)][object]$Plan,
        [string]$Entity = 'PIM-Definitions-Services',
        [switch]$IncludeOrphanRemovals,
        [string]$By = 'powerbi-discovery'
    )
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($c in @($Plan.create)) {
        if (-not $c.autoImport) { continue }
        $out.Add((New-PimChange -Entity $Entity -Key "$($c.expected.groupName)" -Op Create -Payload $c.expected -By $By))
    }
    foreach ($r in @($Plan.rename)) {
        $out.Add((New-PimChange -Entity $Entity -Key "$($r.to)" -Op Update -Payload ([pscustomobject]@{ rename=$true; from="$($r.from)"; to="$($r.to)"; expected=$r.expected }) -By $By))
    }
    if ($IncludeOrphanRemovals) {
        foreach ($o in @($Plan.orphan)) { $out.Add((New-PimChange -Entity $Entity -Key "$($o.groupName)" -Op Remove -By $By)) }
    }
    return $out.ToArray()
}

# ===========================================================================
# Service / role catalog -- PURE folder of discovered built-in roles per service
# ===========================================================================

function Get-PimDiscoveredRoleKey {
    # Stable identity for a discovered service role across runs: "<service>|<roleId-or-name>".
    param([Parameter(Mandatory)][string]$Service, [string]$RoleId, [string]$RoleName)
    $rid = if ("$RoleId".Trim()) { "$RoleId".Trim() } else { "$RoleName".Trim() }
    return ("$Service|$rid").ToLowerInvariant()
}

function Get-PimRoleCatalogDelta {
    # Catalog new built-in roles for a service (Entra / Defender XDR / Intune / ...):
    # which discovered roles are NOT yet in the catalog. PURE -- $Live + $Known are
    # plain role objects; $Known is the previously-catalogued set.
    #   role object: @{ id; name } (either field optional; key uses id then name)
    # Returns the rows to ADD to the catalog (the not-yet-known ones), each carrying a
    # stable key so a second run with the same $Known surfaces nothing (no churn).
    param(
        [Parameter(Mandatory)][string]$Service,
        [object[]]$Live = @(),
        [object[]]$Known = @()
    )
    $knownKeys = @{}
    foreach ($k in @($Known)) {
        $kid = "$($k.id)"; $knm = "$($k.name)"
        if (-not $kid -and -not $knm) { $knm = "$k" }
        $knownKeys[(Get-PimDiscoveredRoleKey -Service $Service -RoleId $kid -RoleName $knm)] = $true
    }
    $new = New-Object System.Collections.Generic.List[object]
    foreach ($r in @($Live)) {
        $rid = "$($r.id)"; $rnm = "$($r.name)"
        if (-not $rid -and -not $rnm) { $rnm = "$r" }
        $key = Get-PimDiscoveredRoleKey -Service $Service -RoleId $rid -RoleName $rnm
        if ($knownKeys.ContainsKey($key)) { continue }
        $knownKeys[$key] = $true   # de-dup within $Live too
        $new.Add([pscustomobject]@{ service=$Service; roleId=$rid; roleName=$rnm; key=$key })
    }
    return $new.ToArray()
}

# ===========================================================================
# Reconcile auto-map gate (discovered -> desired)
# ===========================================================================

function Resolve-PimDiscoveryAutoMap {
    # Decide what a reconcile plan's CREATE candidates become in the desired store:
    # auto-imported scopes are CREATEd as empty permission-group CONTAINERS; everything
    # else is staged PENDING for a human. This is the single chokepoint that enforces
    # "auto-detect new subs/MGs/workspaces, but NEVER auto-map them to a principal":
    # the function returns definition (container) rows + assignment rows SEPARATELY,
    # and the assignment list is ALWAYS empty (no auto-map). PURE.
    #   $Plan = a reconcile plan ({ create[]; rename[]; orphan[]; unchanged[] }) from
    #           Get-PimAzureReconcilePlan or Get-PimPowerBiReconcilePlan.
    param(
        [Parameter(Mandatory)][object]$Plan,
        [string]$DefinitionEntity = 'PIM-Definitions-Resources'
    )
    $definitions = New-Object System.Collections.Generic.List[object]
    $pending     = New-Object System.Collections.Generic.List[object]
    foreach ($c in @($Plan.create)) {
        $row = [pscustomobject]@{ entity=$DefinitionEntity; key="$($c.expected.groupName)"; payload=$c.expected }
        if ($c.autoImport) { $definitions.Add($row) } else { $pending.Add($row) }
    }
    return [pscustomobject]@{
        definitions   = $definitions.ToArray()   # CREATE now (empty containers; no members)
        pending       = $pending.ToArray()        # await a human decision in the Manager
        assignments   = @()                        # ALWAYS empty -- discovery never auto-maps a principal
        renames       = @($Plan.rename)
        orphans       = @($Plan.orphan)
    }
}

# ===========================================================================
# Per-resource-type AUTO-CREATE policy for DISCOVERED resources (REQUIREMENTS §8)
# ===========================================================================
# Today discovery FLAGS a newly-found resource (resource.discovered) but the
# operator has no way to say "auto-create the delegation for new resources of
# THIS type." This layer adds a config-driven per-type policy:
#   $global:PIM_DiscoveryAutoCreate = @{ AzureSubscription='flag'|'pending'|'auto'
#                                        PowerBIWorkspace ='flag'|'pending'|'auto'
#                                        ... }
# Semantics (DEFAULT = 'flag' for EVERY type -- safe; matches read-only-by-default
# + no-scaffolding-defaults):
#   flag    -> current behaviour: only log/audit the discovery (resource.discovered).
#              Nothing is staged or created.
#   pending -> generate the desired delegation row(s) into the normal PENDING/desired
#              set for a human to review + commit. Does NOT bypass governance.
#   auto    -> generate + commit through the NORMAL engine create flow (the change
#              queue -> Create), still honouring approval/prune opt-in rules. NEVER a
#              destructive bypass (this path only ever CREATEs; it never removes/prunes).
# Group NAMES come from the EXISTING naming resolver (the reconcile planners already
# call New-PimPermissionGroupName via Get-PimAzureScopeDerivation /
# Get-PimPowerBiWorkspaceDerivation), so this layer never duplicates naming logic and
# stays correct after the concurrent PIM-Naming rework.

function Get-PimDiscoveryAutoCreatePolicy {
    # Resolve the configured auto-create policy for a resource TYPE. PURE.
    # Reads the per-type map ($Map, default $global:PIM_DiscoveryAutoCreate); an
    # unknown type, an empty/missing map, or an unrecognised value all fall back to
    # 'flag' (the safe default -- never silently auto-create). Case-insensitive on
    # both the type key and the value.
    param(
        [Parameter(Mandatory)][string]$ResourceType,
        [object]$Map
    )
    if ($null -eq $Map) { $Map = $global:PIM_DiscoveryAutoCreate }
    $valid = @('flag','pending','auto')
    $val = ''
    if ($null -ne $Map) {
        $rt = "$ResourceType".Trim()
        if ($Map -is [System.Collections.IDictionary]) {
            foreach ($k in @($Map.Keys)) { if ("$k".Trim().ToLowerInvariant() -eq $rt.ToLowerInvariant()) { $val = "$($Map[$k])"; break } }
        } else {
            $p = $Map.PSObject.Properties | Where-Object { "$($_.Name)".Trim().ToLowerInvariant() -eq $rt.ToLowerInvariant() } | Select-Object -First 1
            if ($p) { $val = "$($p.Value)" }
        }
    }
    $val = "$val".Trim().ToLowerInvariant()
    if ($valid -contains $val) { return $val }
    return 'flag'
}

function Resolve-PimDiscoveryResourceType {
    # Normalise a reconcile create-row to a canonical resource-type key the policy
    # map uses. PURE. Azure reconcile create rows (Get-PimAzureReconcilePlan) carry
    # .scopePath (and optionally .scopeType); Power BI rows carry .workspaceId. New
    # types are added here (Entra role scope, etc.) without touching callers.
    param([Parameter(Mandatory)][object]$Create)
    # Power BI workspaces are unambiguous.
    if ("$($Create.workspaceId)".Trim()) { return 'PowerBIWorkspace' }
    if ("$($Create.roleScope)".Trim() -or "$($Create.entraRoleId)".Trim()) { return 'EntraRoleScope' }
    # Prefer an explicit scopeType when present (discovered shape), else parse scopePath
    # (the reconcile create-row shape, which only carries the path).
    $st = "$($Create.scopeType)".Trim().ToLowerInvariant()
    if (-not $st) {
        $p = "$($Create.scopePath)".Trim().TrimEnd('/')
        if ($p -match '(?i)/resourceGroups/[^/]+/providers/') { $st = 'resource' }
        elseif ($p -match '(?i)/resourceGroups/[^/]+') { $st = 'resourcegroup' }
        elseif ($p -match '(?i)/subscriptions/[^/]+') { $st = 'subscription' }
        elseif ($p -match '(?i)/managementGroups/[^/]+') { $st = 'managementgroup' }
        elseif ($p -eq '' -or $p -eq '/') { $st = 'tenantroot' }
    }
    switch ($st) {
        'subscription'    { return 'AzureSubscription' }
        'managementgroup' { return 'ManagementGroup' }
        'resourcegroup'   { return 'ResourceGroup' }
        'resource'        { return 'AzureResource' }
        'tenantroot'      { return 'ManagementGroup' }
        default           { return 'Unknown' }
    }
}

function Resolve-PimDiscoveryPolicyPlan {
    # PURE policy chokepoint: given a reconcile plan ({ create[]; rename[]; orphan[];
    # unchanged[] } from Get-PimAzureReconcilePlan / Get-PimPowerBiReconcilePlan) and
    # the per-type policy map, bucket each CREATE candidate into:
    #   flagged -> log only (policy 'flag', the safe default; also the fallback for an
    #              Unknown/unrecognised type)
    #   pending -> a desired DEFINITION row staged for human review (policy 'pending')
    #   auto    -> a desired DEFINITION row to commit via the normal create flow ('auto')
    # Each bucketed row carries the resolver-produced group name
    # ($create.expected.groupName) -- this layer NEVER names groups itself. Definition
    # rows are empty permission-group CONTAINERS; assignments are NEVER generated here
    # (a principal is never auto-mapped, exactly as Resolve-PimDiscoveryAutoMap).
    #   $ResourceType (optional) pins the type for the whole plan; otherwise each create
    #   row is classified individually via Resolve-PimDiscoveryResourceType.
    param(
        [Parameter(Mandatory)][object]$Plan,
        [object]$PolicyMap,
        [string]$ResourceType,
        [string]$DefinitionEntity = 'PIM-Definitions-Resources'
    )
    if ($null -eq $PolicyMap) { $PolicyMap = $global:PIM_DiscoveryAutoCreate }
    $flagged = New-Object System.Collections.Generic.List[object]
    $pending = New-Object System.Collections.Generic.List[object]
    $auto    = New-Object System.Collections.Generic.List[object]
    foreach ($c in @($Plan.create)) {
        $type   = if ("$ResourceType".Trim()) { "$ResourceType".Trim() } else { Resolve-PimDiscoveryResourceType -Create $c }
        $policy = Get-PimDiscoveryAutoCreatePolicy -ResourceType $type -Map $PolicyMap
        $name   = "$($c.expected.groupName)"
        $row = [pscustomobject]@{
            entity     = $DefinitionEntity
            key        = $name
            payload    = $c.expected
            stableKey  = "$($c.stableKey)"
            resourceType = $type
            policy     = $policy
        }
        switch ($policy) {
            'auto'    { $auto.Add($row) }
            'pending' { $pending.Add($row) }
            default   { $flagged.Add($row) }   # 'flag' (and any unknown -> flag)
        }
    }
    return [pscustomobject]@{
        flagged     = $flagged.ToArray()   # log only -- nothing staged/created
        pending     = $pending.ToArray()   # staged desired rows; await human commit
        auto        = $auto.ToArray()      # commit now via the normal create flow
        assignments = @()                  # ALWAYS empty -- discovery never auto-maps a principal
        renames     = @($Plan.rename)
        orphans     = @($Plan.orphan)
        summary     = [ordered]@{ flagged=$flagged.Count; pending=$pending.Count; auto=$auto.Count }
    }
}

function Invoke-PimDiscoveryAutoCreate {
    # ENGINE WIRING (side-effecting): run a reconcile plan through the per-type policy
    # and act on each bucket. Emits clear run-log lines:
    #   resource.discovered  <type> <name>  policy=<flag|pending|auto>   (every create)
    #   resource.autocreate  <type> <name>  -> pending|auto              (staged/committed)
    # For 'pending' it UPSERTs the desired definition row (Set-PimSqlRow) so it shows up
    # in the normal pending/desired set for review. For 'auto' it ENQUEUEs a Create
    # change (Add-PimSqlQueueChange) -- the SAME change-queue the GUI commit uses, so the
    # normal engine create flow (and its approval/prune opt-in rules) applies; no row is
    # ever pruned/removed from this path. WhatIf logs the decisions without writing.
    # Returns a summary { flagged; pending; auto; committed[] } for the caller/run log.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Plan,
        [object]$PolicyMap,
        [string]$ResourceType,
        [string]$DefinitionEntity = 'PIM-Definitions-Resources',
        [string]$ConnectionString,
        [switch]$WhatIf
    )
    $resolved = Resolve-PimDiscoveryPolicyPlan -Plan $Plan -PolicyMap $PolicyMap -ResourceType $ResourceType -DefinitionEntity $DefinitionEntity
    $cs = if ("$ConnectionString".Trim()) { $ConnectionString }
          elseif ($global:PIM_EngineSqlCs) { $global:PIM_EngineSqlCs }
          elseif ($global:PIM_SqlConnectionString) { $global:PIM_SqlConnectionString }
          else { $null }
    $committed = New-Object System.Collections.Generic.List[object]
    foreach ($f in @($resolved.flagged)) {
        Write-Host ("    resource.discovered  {0,-18} {1}  policy=flag" -f $f.resourceType, $f.key) -ForegroundColor Yellow
        if (Get-Command Write-PimAuditEvent -ErrorAction SilentlyContinue) {
            try { Write-PimAuditEvent -Action 'resource.discovered' -Target "$($f.key)" -After @{ resourceType=$f.resourceType; policy='flag' } } catch {}
        }
    }
    foreach ($row in @($resolved.pending) + @($resolved.auto)) {
        $policy = "$($row.policy)"
        Write-Host ("    resource.discovered  {0,-18} {1}  policy={2}" -f $row.resourceType, $row.key, $policy) -ForegroundColor Cyan
        if (Get-Command Write-PimAuditEvent -ErrorAction SilentlyContinue) {
            try { Write-PimAuditEvent -Action 'resource.discovered' -Target "$($row.key)" -After @{ resourceType=$row.resourceType; policy=$policy } } catch {}
        }
        if ($WhatIf) {
            Write-Host ("    resource.autocreate  {0,-18} {1}  -> {2} (plan)" -f $row.resourceType, $row.key, $policy) -ForegroundColor DarkGray
            continue
        }
        if (-not $cs) { Write-Host ("    resource.autocreate  {0,-18} {1}  SKIPPED (no SQL store)" -f $row.resourceType, $row.key) -ForegroundColor DarkYellow; continue }
        try {
            if ($policy -eq 'pending') {
                # Stage the desired DEFINITION row -- it now shows in the normal desired
                # set for a human to review + commit (no auto-commit).
                Set-PimSqlRow -ConnectionString $cs -Entity $row.entity -Key $row.key -Data $row.payload
                Write-Host ("    resource.autocreate  {0,-18} {1}  -> pending (staged for review)" -f $row.resourceType, $row.key) -ForegroundColor Green
                [void]$committed.Add([pscustomobject]@{ resourceType=$row.resourceType; key=$row.key; policy='pending' })
            } else {
                # AUTO: enqueue a Create on the SAME change queue the GUI commit uses, so the
                # normal create flow (approval/prune opt-in honoured; never a destructive
                # bypass) applies. Containers only -- no assignment is ever generated.
                $change = New-PimChange -Entity $row.entity -Key $row.key -Op Create -Payload $row.payload -By 'discovery-autocreate'
                Add-PimSqlQueueChange -ConnectionString $cs -Change $change
                Write-Host ("    resource.autocreate  {0,-18} {1}  -> auto (enqueued Create)" -f $row.resourceType, $row.key) -ForegroundColor Green
                [void]$committed.Add([pscustomobject]@{ resourceType=$row.resourceType; key=$row.key; policy='auto' })
            }
        } catch {
            Write-Host ("    resource.autocreate  {0,-18} {1}  FAILED: {2}" -f $row.resourceType, $row.key, $_.Exception.Message) -ForegroundColor Red
        }
    }
    return [pscustomobject]@{
        flagged   = @($resolved.flagged).Count
        pending   = @($resolved.pending).Count
        auto      = @($resolved.auto).Count
        committed = $committed.ToArray()
    }
}

# ===========================================================================
# Delta refinement -- surface ONLY not-yet-handled items (the array-index pattern)
# ===========================================================================

function Get-PimDiscoveryDelta {
    # Given a current discovery snapshot ($Current) and the previously-handled set
    # ($Handled, the stable keys we've already proposed/handled), return ONLY the
    # items NOT yet handled -- so a handled item never reappears on the next run, AND
    # roll the handled set forward. PURE; storage-agnostic (the caller persists
    # $rolled to output/state/discovery-handled-<scope>.json).
    #   $Current item must expose a .stableKey (reconcile-plan create/rename rows do).
    param(
        [object[]]$Current = @(),
        [string[]]$Handled = @()
    )
    $handledSet = @{}
    foreach ($h in @($Handled)) { if ("$h") { $handledSet["$h".ToLowerInvariant()] = $true } }
    $fresh  = New-Object System.Collections.Generic.List[object]
    $rolled = New-Object System.Collections.Generic.List[string]
    foreach ($h in @($Handled)) { if ("$h") { [void]$rolled.Add("$h") } }
    foreach ($c in @($Current)) {
        $k = "$($c.stableKey)"
        if (-not $k) { continue }
        $lk = $k.ToLowerInvariant()
        if ($handledSet.ContainsKey($lk)) { continue }
        $handledSet[$lk] = $true
        $fresh.Add($c)
        [void]$rolled.Add($k)
    }
    return [pscustomobject]@{ fresh=$fresh.ToArray(); handled=$rolled.ToArray() }
}

# ===========================================================================
# LIVE enumerators (REST; best-effort; @() on failure). Side-effecting, untested
# offline -- the planners above carry the unit coverage.
# ===========================================================================

function Get-PimLivePowerBiWorkspaces {
    # All Power BI workspaces the engine SPN can see, normalised to { workspaceId;
    # workspaceName }. Uses the admin groups API first (full-tenant; needs Tenant.Read.All)
    # and falls back to the per-SP /myorg/groups list. REST-only via Invoke-PimPowerBI.
    [CmdletBinding()] param()
    $out = New-Object System.Collections.Generic.List[object]
    $ws = @()
    try { $ws = @(Invoke-PimPowerBI -Path '/admin/groups?$top=5000&$filter=type eq ''Workspace''' -All) } catch { Write-Verbose "PowerBI admin groups: $($_.Exception.Message)" }
    if (-not @($ws).Count) {
        try { $ws = @(Invoke-PimPowerBI -Path '/groups' -All) } catch { Write-Verbose "PowerBI groups: $($_.Exception.Message)" }
    }
    foreach ($w in @($ws)) {
        $id = "$($w.id)"; if (-not $id) { continue }
        $out.Add([pscustomobject]@{ workspaceId=$id; workspaceName="$($w.name)" })
    }
    return $out.ToArray()
}

function Get-PimLiveAzureScopes {
    # Discovered ARM scopes (management groups + subscriptions), normalised to the
    # shape Get-PimAzureReconcilePlan consumes: { scopeType; scopePath; scopeName;
    # mgmtGroupDepth }. REST-only via Invoke-PimArm. Best-effort per source.
    [CmdletBinding()] param([switch]$IncludeManagementGroups)
    $out = New-Object System.Collections.Generic.List[object]
    if ($IncludeManagementGroups) {
        try {
            foreach ($mg in @(Invoke-PimArm -Path '/providers/Microsoft.Management/managementGroups' -ApiVersion '2021-04-01' -All)) {
                $name = "$($mg.name)"; if (-not $name) { continue }
                $disp = if ("$($mg.properties.displayName)") { "$($mg.properties.displayName)" } else { $name }
                $out.Add([pscustomobject]@{ scopeType='managementGroup'; scopePath="/providers/Microsoft.Management/managementGroups/$name"; scopeName=$disp; mgmtGroupDepth=1 })
            }
        } catch { Write-Verbose "ARM management groups: $($_.Exception.Message)" }
    }
    try {
        foreach ($sub in @(Invoke-PimArm -Path '/subscriptions' -ApiVersion '2020-01-01' -All)) {
            $sid = "$($sub.subscriptionId)"; if (-not $sid) { continue }
            $out.Add([pscustomobject]@{ scopeType='subscription'; scopePath="/subscriptions/$sid"; scopeName="$($sub.displayName)"; mgmtGroupDepth=1 })
        }
    } catch { Write-Verbose "ARM subscriptions: $($_.Exception.Message)" }
    return $out.ToArray()
}

function Get-PimLiveServiceRoles {
    # Built-in role definitions for a discoverable service, normalised to { id; name }.
    # Supports the Graph-native services the engine already has scopes/connectors for.
    # REST-only via Invoke-PimGraph. Best-effort -> @() on failure.
    [CmdletBinding()] param([Parameter(Mandatory)][ValidateSet('entra','defender','intune')][string]$Service)
    $out = New-Object System.Collections.Generic.List[object]
    try {
        switch ($Service) {
            'entra'    { foreach ($r in @(Invoke-PimGraph -Path '/roleManagement/directory/roleDefinitions?$select=id,displayName,isBuiltIn' -All)) { if ("$($r.id)") { $out.Add([pscustomobject]@{ id="$($r.id)"; name="$($r.displayName)" }) } } }
            'defender' { foreach ($r in @(Invoke-PimGraph -Path '/roleManagement/defender/roleDefinitions?$select=id,displayName' -All)) { if ("$($r.id)") { $out.Add([pscustomobject]@{ id="$($r.id)"; name="$($r.displayName)" }) } } }
            'intune'   { foreach ($r in @(Invoke-PimGraph -Path '/deviceManagement/roleDefinitions?$select=id,displayName' -All)) { if ("$($r.id)") { $out.Add([pscustomobject]@{ id="$($r.id)"; name="$($r.displayName)" }) } } }
        }
    } catch { Write-Verbose "service roles ($Service): $($_.Exception.Message)" }
    return $out.ToArray()
}

# ===========================================================================
# Department import from Entra (REQUIREMENTS §8 / §11) -- pull Entra groups
# matching a configurable name pattern (default ORG-*) into the PIM
# *departments* used for delegation-approval routing (dept -> owner).
#   * PURE pattern parse + map + idempotent-upsert planner (offline-tested).
#   * LIVE enumerator over Invoke-PimGraph (server-side $filter startswith,
#     never bulk-list; owners pulled via $expand=owners).
# The pattern is a glob with a leading literal prefix and a trailing '*',
# e.g. 'ORG-*' -> prefix 'ORG-' (the GUI/settings DepartmentImportPattern).
# Each matched group becomes a department record { name; owners[]; contact;
# notes; source='entra-import'; sourceId=<groupId> }. Re-import UPDATES an
# existing dept (matched by name, case-insensitive) and NEVER deletes a
# manually-added dept -- manual depts are carried through untouched.
# ===========================================================================

function ConvertTo-PimDepartmentImportPrefix {
    # Parse the configured department-import pattern into the literal prefix the
    # server-side Graph $filter startswith() uses. PURE.
    #   'ORG-*' -> 'ORG-'   'DEPT-' -> 'DEPT-'   '*' / '' -> '' (match all)
    # A pattern with no '*' is treated as a literal prefix. Anything before the
    # FIRST '*' is the prefix; a leading '*' (or empty) means no prefix filter.
    param([AllowNull()][string]$Pattern)
    $p = "$Pattern".Trim()
    if (-not $p) { return '' }
    $star = $p.IndexOf('*')
    if ($star -lt 0) { return $p }       # no wildcard -> whole thing is the prefix
    return $p.Substring(0, $star)        # text before the first '*'
}

function Test-PimDepartmentImportMatch {
    # Does a group display name match the configured import pattern? PURE.
    # Prefix match, case-insensitive; empty prefix matches every non-blank name.
    param([AllowNull()][string]$Name, [AllowNull()][string]$Pattern)
    $n = "$Name".Trim()
    if (-not $n) { return $false }
    $prefix = ConvertTo-PimDepartmentImportPrefix $Pattern
    if (-not $prefix) { return $true }
    return $n.ToLowerInvariant().StartsWith($prefix.ToLowerInvariant())
}

function ConvertTo-PimDepartmentName {
    # Derive the department NAME from a matched group's display name. The pattern's
    # literal prefix is stripped so 'ORG-Finance' becomes 'Finance' (a friendlier
    # dept label); a name that doesn't carry the prefix is kept verbatim. PURE.
    param([Parameter(Mandatory)][string]$GroupName, [AllowNull()][string]$Pattern)
    $n = "$GroupName".Trim()
    $prefix = ConvertTo-PimDepartmentImportPrefix $Pattern
    if ($prefix -and $n.ToLowerInvariant().StartsWith($prefix.ToLowerInvariant())) {
        $stripped = $n.Substring($prefix.Length).Trim()
        if ($stripped) { return $stripped }
    }
    return $n
}

function Get-PimEntraDepartmentImportPlan {
    # PURE idempotent-upsert planner: given the Entra groups discovered for the
    # pattern ($Discovered: @{ id; displayName; owners[] }) and the CURRENT
    # department list ($Existing: @{ name; owners[]; contact; notes; source; sourceId }),
    # compute created / updated / skipped (unchanged) and the MERGED department
    # list to persist. Upsert key = department name (case-insensitive). Manual
    # departments (no matching imported group) are PRESERVED untouched -- import
    # never deletes a dept. Owners are normalised to a sorted, de-duplicated
    # string[]; an imported dept whose owners + sourceId already equal the stored
    # values is 'skipped' (no churn on re-import).
    param(
        [object[]]$Discovered = @(),
        [object[]]$Existing   = @(),
        [string]$Pattern = 'ORG-*'
    )
    function _normOwners($val) {
        $list = @()
        if ($null -eq $val) { return @() }
        if ($val -is [string]) { $list = @($val -split '[|;,]') } else { $list = @($val) }
        $clean = @($list | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
        return @($clean | Sort-Object -Unique)
    }
    # Index existing depts by lower(name) -- preserve original order for the merge.
    $byName = @{}
    $order  = New-Object System.Collections.Generic.List[string]
    foreach ($e in @($Existing)) {
        $nm = "$($e.name)".Trim(); if (-not $nm) { continue }
        $lk = $nm.ToLowerInvariant()
        if (-not $byName.ContainsKey($lk)) { [void]$order.Add($lk) }
        $byName[$lk] = [pscustomobject]@{
            name    = $nm
            owners  = (_normOwners $e.owners)
            contact = "$($e.contact)"
            notes   = "$($e.notes)"
            source  = "$($e.source)"
            sourceId= "$($e.sourceId)"
        }
    }
    $created = New-Object System.Collections.Generic.List[object]
    $updated = New-Object System.Collections.Generic.List[object]
    $skipped = New-Object System.Collections.Generic.List[object]
    $seen    = @{}
    foreach ($g in @($Discovered)) {
        $gid = "$($g.id)"
        $gn  = "$($g.displayName)".Trim(); if (-not $gn) { continue }
        $deptName = ConvertTo-PimDepartmentName -GroupName $gn -Pattern $Pattern
        $lk = $deptName.ToLowerInvariant()
        if ($seen.ContainsKey($lk)) { continue }    # de-dup within the discovered set
        $seen[$lk] = $true
        $owners = (_normOwners $g.owners)
        if ($byName.ContainsKey($lk)) {
            $cur = $byName[$lk]
            $sameOwners = (@($cur.owners) -join '|') -ieq (@($owners) -join '|')
            $sameSource = "$($cur.sourceId)" -eq $gid -and "$($cur.source)" -eq 'entra-import'
            if ($sameOwners -and $sameSource) {
                $skipped.Add([pscustomobject]@{ name=$deptName; groupName=$gn; sourceId=$gid })
            } else {
                # update IN PLACE: refresh owners + source linkage, keep manual contact/notes.
                $byName[$lk] = [pscustomobject]@{
                    name=$cur.name; owners=$owners; contact=$cur.contact; notes=$cur.notes
                    source='entra-import'; sourceId=$gid
                }
                $updated.Add([pscustomobject]@{ name=$deptName; groupName=$gn; sourceId=$gid; owners=$owners })
            }
        } else {
            $byName[$lk] = [pscustomobject]@{ name=$deptName; owners=$owners; contact=''; notes=''; source='entra-import'; sourceId=$gid }
            [void]$order.Add($lk)
            $created.Add([pscustomobject]@{ name=$deptName; groupName=$gn; sourceId=$gid; owners=$owners })
        }
    }
    $merged = New-Object System.Collections.Generic.List[object]
    foreach ($lk in $order) { $merged.Add($byName[$lk]) }
    return [pscustomobject]@{
        created = $created.ToArray()
        updated = $updated.ToArray()
        skipped = $skipped.ToArray()
        departments = $merged.ToArray()    # the full list to persist (manual depts preserved)
        summary = [ordered]@{ created=$created.Count; updated=$updated.Count; skipped=$skipped.Count; total=$merged.Count; pattern="$Pattern" }
    }
}

function Resolve-PimGroupOwnerUpn {
    # Map a Graph owner directoryObject to its best display identity:
    # UPN -> mail -> displayName -> id. PURE. Returns '' for an empty owner.
    param([AllowNull()][object]$Owner)
    if ($null -eq $Owner) { return '' }
    $u = if ("$($Owner.userPrincipalName)".Trim()) { "$($Owner.userPrincipalName)".Trim() }
         elseif ("$($Owner.mail)".Trim())          { "$($Owner.mail)".Trim() }
         elseif ("$($Owner.displayName)".Trim())   { "$($Owner.displayName)".Trim() }
         else                                       { "$($Owner.id)".Trim() }
    return "$u"
}

function Get-PimLiveEntraDepartmentGroups {
    # LIVE: Entra groups matching the import pattern, normalised to
    # { id; displayName; owners[] } with owners resolved to UPN (fallback mail /
    # displayName / id).
    #
    # TWO-PHASE (the fix): Graph REJECTS $count=true together with $expand on
    # /groups (HTTP 400 "Query parameter 'count' ... not ... with 'expand'"),
    # and the startsWith() $filter on displayName is an ADVANCED query that
    # REQUIRES $count=true + ConsistencyLevel:eventual. The old single call
    # combined startsWith+$count+$expand=owners, so it always 400'd, the catch
    # swallowed it to Verbose, and NO groups (ORG-* or otherwise) were ever
    # imported. We now (1) list groups server-side filtered (startsWith + $count
    # + eventual, NO $expand) so we never bulk-list, then (2) pull owners per
    # matched group in a separate call (no advanced params needed). When no
    # prefix is given we page all groups (no advanced params, no $expand).
    # REST-only via Invoke-PimGraph; best-effort -> @() on failure.
    [CmdletBinding()] param([string]$Pattern = 'ORG-*')
    $prefix = ConvertTo-PimDepartmentImportPrefix $Pattern
    $out = New-Object System.Collections.Generic.List[object]
    # ---- Phase 1: list matching groups (id + displayName only) -------------
    $groups = @()
    try {
        if ($prefix) {
            $esc = $prefix.Replace("'", "''")
            # startsWith on displayName is an advanced query -> $count=true + eventual REQUIRED.
            $groups = @(Invoke-PimGraph -Headers @{ ConsistencyLevel = 'eventual' } -All -Path "/groups?`$filter=startswith(displayName,'$esc')&`$count=true&`$select=id,displayName&`$top=999")
        } else {
            $groups = @(Invoke-PimGraph -All -Path "/groups?`$select=id,displayName&`$top=999")
        }
    } catch { Write-Verbose "department-import groups ('$prefix'): $($_.Exception.Message)" }
    # ---- Phase 2: resolve owners per matched group (separate call) ---------
    foreach ($g in @($groups)) {
        $gn = "$($g.displayName)".Trim(); if (-not $gn) { continue }
        $gid = "$($g.id)".Trim()
        $owners = New-Object System.Collections.Generic.List[string]
        # A pre-expanded owners collection (test fixtures / future callers) is honoured
        # first; otherwise fetch /groups/{id}/owners. Best-effort -- a group with no
        # readable owners is STILL emitted (operator can fill owners in manually).
        $ownerObjs = @()
        if ($g.PSObject.Properties['owners'] -and $g.owners) {
            $ownerObjs = @($g.owners)
        } elseif ($gid) {
            try { $ownerObjs = @(Invoke-PimGraph -All -Path "/groups/$gid/owners?`$select=id,displayName,userPrincipalName,mail&`$top=999") }
            catch { Write-Verbose "department-import owners ('$gn'): $($_.Exception.Message)" }
        }
        foreach ($o in @($ownerObjs)) {
            $u = Resolve-PimGroupOwnerUpn -Owner $o
            if ("$u".Trim()) { [void]$owners.Add("$u".Trim()) }
        }
        $out.Add([pscustomobject]@{ id=$gid; displayName=$gn; owners=@($owners | Sort-Object -Unique) })
    }
    return $out.ToArray()
}

function Import-PimEntraDepartments {
    # End-to-end import: discover Entra groups for the pattern (LIVE) and run the
    # PURE upsert planner against the supplied current department list. Returns the
    # plan (created/updated/skipped + merged 'departments' list + summary). The
    # CALLER persists $plan.departments through the settings store (engine stays the
    # writer; this function does no I/O beyond the Graph read). REST/cert, PS 5.1.
    [CmdletBinding()] param(
        [object[]]$Existing = @(),
        [string]$Pattern = 'ORG-*'
    )
    if (-not "$Pattern".Trim()) { $Pattern = 'ORG-*' }
    $discovered = @(Get-PimLiveEntraDepartmentGroups -Pattern $Pattern)
    return (Get-PimEntraDepartmentImportPlan -Discovered $discovered -Existing $Existing -Pattern $Pattern)
}

# ===========================================================================
# Approver/owner import from CSV (REQUIREMENTS §11) -- bulk-assign approvers /
# owners to departments from an uploaded CSV, with an optional RENAME of the
# department. PURE planner (offline-tested) -- the CALLER persists the merged
# department list through the settings store (engine stays the writer).
#
# CSV is delimiter-flexible: header row OR headerless. Recognised columns
# (case-insensitive) are Department, GroupName, NewName/RenameTo and Approvers/
# Owners. The minimal contract from the task is:
#     Department;GroupName;approver1,approver2,...
# i.e. col0 = department (match key), col1 = group name, col2 = owners list
# (comma/pipe/semicolon-within-the-cell separated). A 'NewName' column (or a 4th
# positional column) renames the department.
# ===========================================================================

function ConvertFrom-PimApproverCsv {
    # PURE: parse approver/owner CSV TEXT into rows
    # @{ department; groupName; newName; approvers[] }. Delimiter auto-detected
    # (';' preferred, then ',' then tab). A first row whose first cell is literally
    # 'Department' (any case) is treated as a header and skipped. Owners inside a
    # single cell may themselves be comma/pipe/semicolon separated. PS 5.1 safe.
    param([AllowNull()][string]$Text)
    $rows = New-Object System.Collections.Generic.List[object]
    $t = "$Text"
    if (-not $t.Trim()) { return $rows.ToArray() }
    $lines = @($t -split "(`r`n|`n|`r)" | Where-Object { $_ -and ($_ -notmatch '^(`r`n|`n|`r)$') })
    # Pick the delimiter from the first non-empty line.
    $first = ($lines | Where-Object { "$_".Trim() } | Select-Object -First 1)
    $delim = ';'
    if ($first) {
        if    ($first.Contains(';')) { $delim = ';' }
        elseif ($first.Contains("`t")) { $delim = "`t" }
        elseif ($first.Contains(',')) { $delim = ',' }
    }
    $idx = 0
    foreach ($lnRaw in $lines) {
        $ln = "$lnRaw"
        if (-not $ln.Trim()) { continue }
        $cells = @($ln.Split($delim))
        $c0 = if ($cells.Count -ge 1) { "$($cells[0])".Trim() } else { '' }
        # header detection (only on the very first data-bearing line)
        if ($idx -eq 0 -and $c0 -match '^(?i)department$') { $idx++; continue }
        $idx++
        if (-not $c0) { continue }
        $dept    = $c0
        $group   = if ($cells.Count -ge 2) { "$($cells[1])".Trim() } else { '' }
        $apprRaw = if ($cells.Count -ge 3) { "$($cells[2])".Trim() } else { '' }
        $newName = if ($cells.Count -ge 4) { "$($cells[3])".Trim() } else { '' }
        $approvers = @($apprRaw -split '[|,;]' | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
        $rows.Add([pscustomobject]@{ department=$dept; groupName=$group; newName=$newName; approvers=@($approvers) })
    }
    return $rows.ToArray()
}

function Get-PimApproverImportPlan {
    # PURE idempotent planner: apply parsed CSV rows ($Rows from
    # ConvertFrom-PimApproverCsv) onto the CURRENT department list ($Existing:
    # @{ name; owners[]; contact; notes; source; sourceId }). For each row:
    #   * match the department by name (case-insensitive); if a 'newName' is given
    #     and the department exists, RENAME it (collisions are merged into the
    #     target). A row whose department doesn't exist is CREATED.
    #   * REPLACE the department's owners/approvers with the CSV's list (the CSV is
    #     authoritative for the rows it carries). Departments NOT named in the CSV
    #     are PRESERVED untouched. Returns created/updated/renamed + the merged
    #     'departments' list to persist + a summary.
    param(
        [object[]]$Rows     = @(),
        [object[]]$Existing = @()
    )
    function _normOwners($val) {
        if ($null -eq $val) { return @() }
        $list = if ($val -is [string]) { @($val -split '[|;,]') } else { @($val) }
        return @($list | ForEach-Object { "$_".Trim() } | Where-Object { $_ } | Sort-Object -Unique)
    }
    $byName = @{}
    $order  = New-Object System.Collections.Generic.List[string]
    foreach ($e in @($Existing)) {
        $nm = "$($e.name)".Trim(); if (-not $nm) { continue }
        $lk = $nm.ToLowerInvariant()
        if (-not $byName.ContainsKey($lk)) { [void]$order.Add($lk) }
        $byName[$lk] = [pscustomobject]@{
            name=$nm; owners=(_normOwners $e.owners); contact="$($e.contact)"
            notes="$($e.notes)"; source="$($e.source)"; sourceId="$($e.sourceId)"
        }
    }
    $created = New-Object System.Collections.Generic.List[object]
    $updated = New-Object System.Collections.Generic.List[object]
    $renamed = New-Object System.Collections.Generic.List[object]
    foreach ($r in @($Rows)) {
        $dept = "$($r.department)".Trim(); if (-not $dept) { continue }
        $lk   = $dept.ToLowerInvariant()
        $owners = _normOwners $r.approvers
        $new  = "$($r.newName)".Trim()
        if ($byName.ContainsKey($lk)) {
            $cur = $byName[$lk]
            $targetName = if ($new) { $new } else { $cur.name }
            $targetLk   = $targetName.ToLowerInvariant()
            $merged = [pscustomobject]@{
                name=$targetName; owners=$owners; contact=$cur.contact; notes=$cur.notes
                source=$cur.source; sourceId=$cur.sourceId
            }
            if ($new -and $targetLk -ne $lk) {
                # RENAME (and merge if the target already exists).
                $byName.Remove($lk)
                $order.Remove($lk) | Out-Null
                if (-not $byName.ContainsKey($targetLk)) { [void]$order.Add($targetLk) }
                $byName[$targetLk] = $merged
                $renamed.Add([pscustomobject]@{ from=$cur.name; to=$targetName; owners=$owners })
            } else {
                $byName[$lk] = $merged
                $updated.Add([pscustomobject]@{ name=$cur.name; owners=$owners })
            }
        } else {
            $name = if ($new) { $new } else { $dept }
            $nlk  = $name.ToLowerInvariant()
            if (-not $byName.ContainsKey($nlk)) { [void]$order.Add($nlk) }
            $byName[$nlk] = [pscustomobject]@{ name=$name; owners=$owners; contact=''; notes=''; source='csv-import'; sourceId='' }
            $created.Add([pscustomobject]@{ name=$name; owners=$owners })
        }
    }
    $mergedList = New-Object System.Collections.Generic.List[object]
    foreach ($lk in $order) { if ($byName.ContainsKey($lk)) { $mergedList.Add($byName[$lk]) } }
    return [pscustomobject]@{
        created     = $created.ToArray()
        updated     = $updated.ToArray()
        renamed     = $renamed.ToArray()
        departments = $mergedList.ToArray()
        summary     = [ordered]@{ created=$created.Count; updated=$updated.Count; renamed=$renamed.Count; total=$mergedList.Count }
    }
}

function Import-PimApproversFromCsv {
    # End-to-end approver/owner CSV import: parse the CSV TEXT and run the PURE
    # planner against the supplied current department list. The CALLER persists
    # $plan.departments through the settings store. No I/O. PS 5.1.
    [CmdletBinding()] param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Csv,
        [object[]]$Existing = @()
    )
    $rows = @(ConvertFrom-PimApproverCsv -Text $Csv)
    return (Get-PimApproverImportPlan -Rows $rows -Existing $Existing)
}
