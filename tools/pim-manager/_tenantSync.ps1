#Requires -Version 5.1
<#
.SYNOPSIS
    Tenant-list cache builder for PIM Manager.

.DESCRIPTION
    Dot-sourced from Open-PimManager.ps1. Provides:

      Invoke-PimTenantListRefresh   -> connects to the tenant via the engine
                                       SPN, queries Graph + Resource Graph,
                                       writes the caches to SQL
                                       pim.TenantCache (one row per kind).

      Read-PimTenantListCache       -> returns hashtable of the 4 cached
                                       lists for the UI (no live calls).

    Cache document format is stable:

        { "refreshedUtc": "<iso>", "items": [ ... ] }

    The cache kinds:

      entra-roles          items: { id, displayName, description, isBuiltIn,
                                    rolePermissions: [
                                        { allowedResourceActions, excludedResourceActions,
                                          allowedDataActions,    excludedDataActions } ] }
      aus                  items: { id, displayName, description }
      pim-groups           items: { id, displayName, description }
      azure-scopes         items: { id, displayName, type, scopePath }

    The entra-roles `rolePermissions` field powers the per-role permission
    drill-down in the Manager Graph tab (Roadmap #2 / #25 -- v2.2.0). It is
    persisted as-is from Graph; field-shape per Graph docs for the
    `unifiedRoleDefinition` resource type.

    Connection contract: reuses the engine globals so no browser auth flow
    is ever triggered. Required globals (populated by
    Initialize-PlatformAutomationFramework or the customer's own bootstrap):

      $global:HighPriv_Modern_ApplicationID_Azure
      $global:HighPriv_Modern_CertificateThumbprint_Azure
      $global:AzureTenantID   (or $global:AzureTenantId)

    Refuses with a clear error if any of those is missing. Never falls back
    to interactive Connect-MgGraph / Connect-AzAccount -- this is an
    admin-side automation tool, not an interactive sign-in surface.

.NOTES
    Solution     : PIM4EntraPS
    Developed by : Morten Knudsen, Microsoft MVP
#>

# ---------------------------------------------------------------------------
# Cache store -- SQL pim.TenantCache (one row per kind)
# ---------------------------------------------------------------------------
# PIM v2 is SQL-only (2026-09-13). The caches used to be JSON files under
# tools/pim-manager/cache/<instance>/<kind>.json -- lost on every hosted revision roll and
# invisible to a scheduler running in another container. They are now rows in pim.TenantCache
# (Set-/Get-PimSqlTenantCache, PIM-SqlStore.ps1). The database IS the instance, so per-tenant
# isolation holds without an instance folder.
# Without a store (offline tests, a bare dot-source) the entries live in this process's memory
# only, and a write SAYS so -- it is never presented as persistence.
# 'active-assignments' (§70.1b option 2): { refreshedUtc; rows; counts; surfaceErrors; partial; ok; error; durationMs;
# source; correlationId } -- written by the scheduler job 'active-assignments-snapshot', read by the Manager's
# GET /api/active-assignments. See engine/_shared/PIM-ActiveAssignments.ps1.
# 'drift' (Drift page, 2026-09-14): { refreshedUtc; durationSeconds; total; counts; scopesFailed; ok; scopes[...] } -- written
# by the scheduler job 'drift-snapshot', read by GET /api/drift. See engine/_shared/PIM-DriftSnapshot.ps1.
# 'coverage-report' (REQ-I + REQ-U, Coverage & gaps page): { computedUtc; ok; counts; sources[]; rows[]; ... } -- written by the
# scheduler job 'coverage', read by GET /api/coverage. See engine/coverage/PIM-Coverage.ps1.
# 'workload-roles:defender' / 'workload-roles:intune' (REQ-U wave 2): { read; reason; readUtc; roles:[{ name; id; isBuiltIn; actions? }] }
# -- written by the scheduler jobs 'discovery-defender' / 'discovery-intune' (engine/_shared/PIM-WorkloadRoles.ps1), read by
# the Coverage page. read=false = NOT CHECKED (with its reason), never an empty catalog.
# 'workload-actions:defender' (REQ-U wave 2): { read; reason; readUtc; actions:[{ id; name; description }] } -- Microsoft's Defender
# XDR permission catalog (beta resourceNamespaces?$expand=resourceActions), written by 'discovery-defender'.
# 'tenant-domains' (REQ-T): { refreshedUtc; domains:[{ id; isDefault; isInitial }] } -- this tenant's verified domains,
# written/read by Get-PimManagerTenantDomains for the "Admin account domain" setting.
# 🪤 THIS LIST IS AN ALLOW-LIST, AND AN UNLISTED KIND FAILS SILENTLY. Set-/Get-PimTenantCacheEntry validate
#    -Kind against it, so a kind that is missing here makes BOTH calls throw -- and every caller wraps them in a
#    best-effort try/catch, because a cache is a convenience. Measured 2026-09-20: 'tenant-domains' was never
#    added when REQ-T shipped, so the domain cache was dead in both directions and the Settings dropdown had
#    nothing to offer whenever the live Graph read was unavailable. ADD THE KIND IN THE SAME EDIT AS THE CACHE CALL.
$script:PimTenantCacheKinds = @('entra-roles','aus','pim-groups','azure-scopes','azure-rbac-roles','auth-methods','pim-activity','tenant-org','active-assignments','drift','coverage-report','target-check','workload-roles:defender','workload-roles:intune','workload-actions:defender','tenant-domains','powerbi-workspaces','ad-servers','managed-live')   # managed-live: the live assignments the engine matched to a definition (drift read; Review current delegations, 2026-10-07); powerbi-workspaces: REQ-DISC-2 (the discovery-powerbi job); ad-servers: §80.2 server onboarding (written by the hybrid worker)
$script:PimTenantCacheMem   = @{}

function Get-PimTenantCacheStoreCs {
    # The store connection string, or $null when this process has no store.
    if ("$($script:PimSqlCs)".Trim()) { return "$($script:PimSqlCs)" }
    if ("$($global:PIM_SqlConnectionString)".Trim()) { return "$($global:PIM_SqlConnectionString)" }
    if (Get-Command Get-PimSqlSettingsConnectionString -ErrorAction SilentlyContinue) {
        try { $cs = Get-PimSqlSettingsConnectionString; if ("$cs".Trim()) { return "$cs" } } catch { }
    }
    return $null
}

function Set-PimTenantCacheEntry {
    # Persist one cache kind (the whole document). Returns 'sql:pim.TenantCache/<kind>' or 'memory:<kind>'.
    param(
        [Parameter(Mandatory)][ValidateScript({ $script:PimTenantCacheKinds -contains $_ })][string]$Kind,
        [AllowNull()][object]$Value,
        # 100.31 SNAPSHOT-OOM: a document the caller already serialised (one compact string) -- stored as is.
        [AllowNull()][string]$ValueJson = $null
    )
    $hasJson = $PSBoundParameters.ContainsKey('ValueJson')
    if (-not $hasJson -and -not $PSBoundParameters.ContainsKey('Value')) { throw 'Set-PimTenantCacheEntry: pass -Value or -ValueJson' }
    $cs = Get-PimTenantCacheStoreCs
    if ($cs -and (Get-Command Set-PimSqlTenantCache -ErrorAction SilentlyContinue)) {
        if ($hasJson) {
            if ((Get-Command Set-PimSqlTenantCache).Parameters.ContainsKey('ValueJson')) { Set-PimSqlTenantCache -ConnectionString $cs -Kind $Kind -ValueJson $ValueJson }
            else { Set-PimSqlTenantCache -ConnectionString $cs -Kind $Kind -Value $(if ("$ValueJson" -ne '') { $ValueJson | ConvertFrom-Json } else { $null }) }
        } else {
            Set-PimSqlTenantCache -ConnectionString $cs -Kind $Kind -Value $Value
        }
        return "sql:pim.TenantCache/$Kind"
    }
    $script:PimTenantCacheMem[$Kind] = $(if ($hasJson) { $ValueJson } else { ($Value | ConvertTo-Json -Depth 12 -Compress) })
    Write-Warning ("  [tenant-cache] '{0}' kept in this process only -- no SQL store is configured (PIM v2 is SQL-only)" -f $Kind)
    return "memory:$Kind"
}

function Get-PimTenantCacheEntry {
    # One cache kind, parsed; $null when absent. Never throws (a cache is a convenience, not a gate).
    param([Parameter(Mandatory)][ValidateScript({ $script:PimTenantCacheKinds -contains $_ })][string]$Kind)
    $cs = Get-PimTenantCacheStoreCs
    if ($cs -and (Get-Command Get-PimSqlTenantCache -ErrorAction SilentlyContinue)) {
        try { return (Get-PimSqlTenantCache -ConnectionString $cs -Kind $Kind) }
        catch { Write-Warning ("  [tenant-cache] SQL read of '{0}' failed: {1}" -f $Kind, $_.Exception.Message); return $null }
    }
    if ($script:PimTenantCacheMem.ContainsKey($Kind)) {
        try { return ($script:PimTenantCacheMem[$Kind] | ConvertFrom-Json) } catch { return $null }
    }
    return $null
}

function Write-PimTenantCache {
    param(
        [Parameter(Mandatory)][string]$Kind,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Items
    )
    $body = [ordered]@{
        refreshedUtc = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        items        = @($Items)
    }
    return (Set-PimTenantCacheEntry -Kind $Kind -Value $body)
}

function Read-PimTenantListCache {
    # Returns hashtable: @{ entraRoles=@{refreshedUtc;items}; aus=@{...}; pimGroups=@{...}; azureScopes=@{...} }
    # A kind never written yields a $null entry -- UI must tolerate.
    $out = [ordered]@{}
    $kinds = @(
        @{ kind = 'entra-roles';      key = 'entraRoles' },
        @{ kind = 'aus';              key = 'aus' },
        @{ kind = 'pim-groups';       key = 'pimGroups' },
        @{ kind = 'azure-scopes';     key = 'azureScopes' },
        @{ kind = 'azure-rbac-roles'; key = 'azureRbacRoles' }
    )
    foreach ($k in $kinds) {
        $parsed = $null
        try { $parsed = Get-PimTenantCacheEntry -Kind $k.kind } catch { $parsed = $null }
        if ($null -ne $parsed) {
            $out[$k.key] = @{
                refreshedUtc = $parsed.refreshedUtc
                items        = @($parsed.items)
            }
        } else {
            $out[$k.key] = $null
        }
    }
    return $out
}

# ---------------------------------------------------------------------------
# Connection / dependency helpers
# ---------------------------------------------------------------------------

function Test-PimRestTenantAuthAvailable {
    # True when PIM-Rest.ps1 can mint an app-only token with NO PowerShell module:
    #   * a managed identity is present (App Service / Functions / IMDS), OR
    #   * the engine SPN client id + (cert thumbprint | secret) are configured.
    # This is the hosted-container path (no Graph/Az SDK).
    if (-not (Get-Command Get-PimRestToken -ErrorAction SilentlyContinue)) { return $false }
    if ($env:IDENTITY_ENDPOINT -or $env:MSI_ENDPOINT -or $global:PIM_UseManagedIdentity) { return $true }
    $cid = if ($global:PIM_ClientId) { $global:PIM_ClientId } else { $global:HighPriv_Modern_ApplicationID_Azure }
    if (-not $cid) { return $false }
    $hasCred = $global:PIM_CertThumbprint -or $global:PIM_ClientSecret -or
               $global:HighPriv_Modern_CertificateThumbprint_Azure -or $global:HighPriv_Modern_Secret_Azure
    return [bool]$hasCred
}

function Assert-PimTenantConnectionContext {
    # Verify a usable tenant connection context. §100.42 (owner 2026-10-09: "modern single connect only"): the ONE
    # connect path is PIM-Rest.ps1's token client -- a managed identity, or the engine SPN client id + certificate
    # (secret only where PIM-Rest itself still accepts one). No Graph/Az SDK context is consulted any more.
    # Never falls back to interactive sign-in.
    $tenantId = $null
    if     ($global:AzureTenantID) { $tenantId = $global:AzureTenantID }
    elseif ($global:AzureTenantId) { $tenantId = $global:AzureTenantId }
    elseif ($global:PIM_TenantId)  { $tenantId = $global:PIM_TenantId }
    elseif ($env:PIM_TenantId)     { $tenantId = $env:PIM_TenantId }

    # REST app-only (hosted container / module-less). A managed identity
    # supplies its own tenant in the token, so PIM_TenantId is optional with MI.
    if (Test-PimRestTenantAuthAvailable) {
        if ($tenantId) { return $tenantId }
        if ($env:IDENTITY_ENDPOINT -or $env:MSI_ENDPOINT -or $global:PIM_UseManagedIdentity) { return '' }  # MI: token carries the tenant
        throw "PIM Manager tenant access (REST): a credential is present but the tenant id is not. Set PIM_TenantId (app setting / `$global:PIM_TenantId)."
    }

    $missing = New-Object System.Collections.ArrayList
    if (-not $global:HighPriv_Modern_ApplicationID_Azure) { [void]$missing.Add('$global:HighPriv_Modern_ApplicationID_Azure (or PIM_ClientId)') }
    if (-not $global:HighPriv_Modern_CertificateThumbprint_Azure -and -not $global:HighPriv_Modern_Secret_Azure) {
        [void]$missing.Add('$global:HighPriv_Modern_CertificateThumbprint_Azure (or PIM_CertThumbprint / a client secret / a managed identity)')
    }
    if (-not $tenantId) { [void]$missing.Add('$global:AzureTenantID (or PIM_TenantId)') }
    if ($missing.Count -gt 0) {
        $missingList = $missing -join ', '
        throw "PIM Manager tenant access requires the engine SPN context (or a managed identity). Missing: $missingList. Hosted: set PIM_ClientId + PIM_CertThumbprint + PIM_TenantId app settings, or assign the container a managed identity with the needed Graph/ARM permissions. Local: set the same PIM_* globals (PIM-Rest.ps1 is the only connect path)."
    }
    return $tenantId
}

# ---------------------------------------------------------------------------
# Graph paging helper (REST, PIM-Rest.ps1)
# ---------------------------------------------------------------------------

function Invoke-PimGraphGetAll {
    # Pages through a Graph collection URL through PIM-Rest.ps1's Invoke-PimGraph (it mints the app-only token from
    # PIM_* / MI and aggregates @odata.nextLink). §100.42: REST is the only path -- no Invoke-MgGraphRequest fallback.
    param([Parameter(Mandatory)][string]$Uri)
    if (-not (Get-Command Invoke-PimGraph -ErrorAction SilentlyContinue)) { throw 'Invoke-PimGraphGetAll: Invoke-PimGraph (PIM-Rest.ps1) is not loaded.' }
    return ,@(Invoke-PimGraph -Path $Uri -All)
}

# ---------------------------------------------------------------------------
# Per-list fetchers
# ---------------------------------------------------------------------------

function Get-PimEntraRolesFromTenant {
    # rolePermissions is required by the Manager's per-role permission drill-down
    # (Roadmap #2 / #25). Graph returns it by default on roleDefinitions, but we
    # ask for it explicitly so the $select projection doesn't strip it.
    $rows = Invoke-PimGraphGetAll -Uri 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions?$select=id,displayName,description,isBuiltIn,rolePermissions'
    $items = foreach ($r in $rows) {
        # Normalize rolePermissions into a plain array of ordered hashtables so
        # ConvertTo-Json -Depth 10 produces stable, friendly JSON regardless of
        # whether Graph returned PSCustomObject or hashtable.
        $perms = New-Object System.Collections.ArrayList
        if ($r.rolePermissions) {
            foreach ($p in @($r.rolePermissions)) {
                [void]$perms.Add([ordered]@{
                    allowedResourceActions  = @(if ($p.allowedResourceActions)  { $p.allowedResourceActions  } else { @() })
                    excludedResourceActions = @(if ($p.excludedResourceActions) { $p.excludedResourceActions } else { @() })
                    allowedDataActions      = @(if ($p.allowedDataActions)      { $p.allowedDataActions      } else { @() })
                    excludedDataActions     = @(if ($p.excludedDataActions)     { $p.excludedDataActions     } else { @() })
                })
            }
        }
        [ordered]@{
            id              = "$($r.id)"
            displayName     = "$($r.displayName)"
            description     = "$($r.description)"
            isBuiltIn       = [bool]$r.isBuiltIn
            rolePermissions = @($perms)
        }
    }
    return ,@($items | Sort-Object { $_.displayName })
}

function Get-PimAdministrativeUnitsFromTenant {
    $rows = Invoke-PimGraphGetAll -Uri 'https://graph.microsoft.com/v1.0/directory/administrativeUnits?$select=id,displayName,description'
    $items = foreach ($r in $rows) {
        [ordered]@{
            id          = "$($r.id)"
            displayName = "$($r.displayName)"
            description = "$($r.description)"
        }
    }
    return ,@($items | Sort-Object { $_.displayName })
}

function Get-PimTenantSyncGroupPrefix {
    # BUG-209 (ss33.28): the PIM-group prefix comes from the naming convention (PimGroupPattern, the literal
    # text before the first {Token}), not a hard-coded 'PIM-' -- a tenant whose convention names groups
    # 'GRP-PIM-{Role}' had an EMPTY group cache. Same rule as Get-PimActiveAssignmentsGroupPrefix / the
    # engine; a prefix shorter than 3 characters is ignored (it would list the whole directory).
    $pfx = 'PIM-'
    try {
        $pat = $null
        if ($global:PIM_NamingConventions -and $global:PIM_NamingConventions.PimGroupPattern) { $pat = "$($global:PIM_NamingConventions.PimGroupPattern)" }
        elseif (Get-Command Get-PimNamingConvention -ErrorAction SilentlyContinue) { $c = Get-PimNamingConvention; if ($c -and $c.PimGroupPattern) { $pat = "$($c.PimGroupPattern)" } }
        if ($pat) {
            $p = if (Get-Command Get-PimNamePrefix -ErrorAction SilentlyContinue) { Get-PimNamePrefix -Pattern $pat }
                 else { $i = $pat.IndexOf('{'); if ($i -lt 0) { $pat } else { $pat.Substring(0, $i) } }
            if ($p -and "$p".Length -ge 3) { $pfx = "$p" }
        }
    } catch { }
    return $pfx
}

function Get-PimGroupsFromTenant {
    # Graph filter syntax for startswith requires the property to be filterable;
    # displayName is. Top 999 is the API max per page; paging handles the rest.
    $pfx = (Get-PimTenantSyncGroupPrefix) -replace "'", "''"
    $uri = 'https://graph.microsoft.com/v1.0/groups?$filter=' +
           [uri]::EscapeDataString("startswith(displayName,'$pfx')") +
           '&$select=id,displayName,description&$top=999'
    $rows = Invoke-PimGraphGetAll -Uri $uri
    $items = foreach ($r in $rows) {
        [ordered]@{
            id          = "$($r.id)"
            displayName = "$($r.displayName)"
            description = "$($r.description)"
        }
    }
    return ,@($items | Sort-Object { $_.displayName })
}

# §79.17 -- the management-group TREE, so the Create wizard can derive the level Lx from the CAF layer a scope sits in
# (Tenant Root Group = L3, one level per layer below it). PURE: walks the answer of
#   GET /providers/Microsoft.Management/managementGroups/{root}?$expand=children&$recurse=true
# and returns @{ '<scope path, lower case>' = '<parent scope path>' } for every management group and subscription in
# it; the root itself maps to ''.
function ConvertFrom-PimMgTree {
    param([object]$Root)
    $map = @{}
    if (-not $Root -or -not "$($Root.id)".Trim()) { return $map }
    $map["$($Root.id)".ToLowerInvariant()] = ''
    $stack = New-Object System.Collections.Stack
    $stack.Push($Root)
    while ($stack.Count) {
        $n = $stack.Pop()
        $kids = if ($n.PSObject.Properties['properties'] -and $n.properties -and $n.properties.PSObject.Properties['children']) { @($n.properties.children) } else { @() }
        foreach ($c in $kids) {
            if (-not $c -or -not "$($c.id)".Trim()) { continue }
            $map["$($c.id)".ToLowerInvariant()] = "$($n.id)"
            # a child of the recursive expand carries its own children directly (no nested 'properties')
            $cc = if ($c.PSObject.Properties['children']) { @($c.children) } else { @() }
            if ($cc.Count) { $stack.Push([pscustomobject]@{ id = "$($c.id)"; properties = [pscustomobject]@{ children = $cc } }) }
        }
    }
    $map
}

# Stamps parentId on each azure-scopes item from the tree ('' = the Tenant Root Group). A tree that cannot be read
# (no read on the root management group) leaves the items as they were: the wizard then falls back to the role rule
# and says so.
function Add-PimAzureScopeParents {
    param([System.Collections.IList]$Items)
    if (-not $Items -or -not (Get-Command Invoke-PimArm -ErrorAction SilentlyContinue)) { return }
    $root = $null
    foreach ($i in $Items) { if ("$($i.type)" -eq 'managementGroup' -and $i.Contains('isRoot') -and $i.isRoot) { $root = $i; break } }
    if (-not $root) { return }
    try {
        $tree = Invoke-PimArm -Method GET -Path ("$($root.id)" + '?$expand=children&$recurse=true') -ApiVersion '2020-05-01'
        $map = ConvertFrom-PimMgTree -Root $tree
    } catch { Write-Warning ("  ARM management-group tree read failed (levels fall back to the role rule): {0}" -f $_.Exception.Message); return }
    foreach ($i in $Items) {
        $k = "$($i.scopePath)".ToLowerInvariant()
        if ($map.ContainsKey($k)) { $i['parentId'] = $map[$k] }
    }
}

function Get-PimAzureScopesFromTenant {
    # Returns subscriptions + management groups + their full ARM scope paths, over ARM REST (PIM-Rest.ps1's
    # Invoke-PimArm). §100.42: REST is the only path -- the Az-module fallbacks (Get-AzManagementGroup, Search-AzGraph,
    # Get-AzSubscription) are gone.
    $items = New-Object System.Collections.ArrayList
    if (-not (Get-Command Invoke-PimArm -ErrorAction SilentlyContinue)) {
        Write-Warning '  Azure scopes: the ARM REST client (Invoke-PimArm, PIM-Rest.ps1) is not loaded -- no scopes listed.'
        Add-PimAzureScopeParents -Items $items   # §79.17
        return ,@($items)
    }
    # Management groups: GET /providers/Microsoft.Management/managementGroups
    try {
        foreach ($m in @(Invoke-PimArm -Path '/providers/Microsoft.Management/managementGroups' -ApiVersion '2020-05-01' -All)) {
            [void]$items.Add([ordered]@{
                id          = "$($m.id)"
                displayName = "$($m.properties.displayName)"
                type        = 'managementGroup'
                scopePath   = "$($m.id)"
                isRoot      = ("$($m.name)" -and "$($m.name)" -eq "$($m.properties.tenantId)")   # §79.17 the Tenant Root Group
            })
        }
    } catch { Write-Warning ("  ARM managementGroups list failed: {0}" -f $_.Exception.Message) }
    # Subscriptions: GET /subscriptions
    try {
        foreach ($s in @(Invoke-PimArm -Path '/subscriptions' -ApiVersion '2020-01-01' -All)) {
            [void]$items.Add([ordered]@{
                id          = "$($s.subscriptionId)"
                displayName = "$($s.displayName)"
                type        = 'subscription'
                scopePath   = "/subscriptions/$($s.subscriptionId)"
            })
        }
    } catch { Write-Warning ("  ARM subscriptions list failed: {0}" -f $_.Exception.Message) }
    Add-PimAzureScopeParents -Items $items   # §79.17
    return ,@($items)
}

function Get-PimAzureRbacRolesFromTenant {
    # Azure RBAC role DEFINITIONS (Owner, Contributor, Reader, custom roles...)
    # for the Azure permission-group pickers -- so operators select role names
    # instead of typing them (spelling errors in AzScopePermission silently
    # break the engine's role assignment).
    $items = New-Object System.Collections.ArrayList
    # §100.42: ARM REST only (the Az.Resources Get-AzRoleDefinition fallback is gone).
    if (-not (Get-Command Invoke-PimArm -ErrorAction SilentlyContinue)) {
        Write-Warning '  Azure RBAC roles: the ARM REST client (Invoke-PimArm, PIM-Rest.ps1) is not loaded -- no roles listed.'
        return ,@($items)
    }
    # ARM REST: roleDefinitions are queried at a scope; built-in roles are
    # identical tenant-wide, so list them at the first subscription scope.
    # Custom roles are scope-specific -- a full per-scope sweep is a later
    # increment; built-ins cover the common-role pickers the GUI needs.
    try {
        $sub = @(Invoke-PimArm -Path '/subscriptions' -ApiVersion '2020-01-01' -All | Select-Object -First 1)
        if ($sub.Count -gt 0) {
            $scope = "/subscriptions/$($sub[0].subscriptionId)"
            foreach ($d in @(Invoke-PimArm -Path "$scope/providers/Microsoft.Authorization/roleDefinitions" -ApiVersion '2022-04-01' -All)) {
                [void]$items.Add([ordered]@{
                    id          = "$($d.name)"
                    displayName = "$($d.properties.roleName)"
                    description = "$($d.properties.description)"
                    isCustom    = ("$($d.properties.type)" -ne 'BuiltInRole')
                })
            }
        } else {
            Write-Warning '  ARM roleDefinitions: no subscription reachable to scope the query.'
        }
    } catch { Write-Warning ("  ARM roleDefinitions list failed: {0}" -f $_.Exception.Message) }
    return ,@($items | Sort-Object { $_.displayName })
}


# ---------------------------------------------------------------------------
# BUG-192 (ss33.28) -- the two caches the validator reads and nothing WROTE.
# PIM-AUTH-001/002 read kind 'auth-methods' and PIM-STALE-003 reads 'pim-activity'; both kinds were only LISTED,
# so every environment showed a permanent "skipped" info. Both are written here now, by the tick's tenant-cache
# job. Each is OPTIONAL: a permission the engine identity does not hold (403) SKIPS the step and writes nothing,
# so the validator's own "skipped (needs <permission>)" info stays true -- it is never reported as a failure.
# Both caches are a MAP (not the { refreshedUtc; items } list shape), exactly as the validator reads them.
# ---------------------------------------------------------------------------
function Get-PimTenantSyncRows {
    # Desired rows of one entity from the store: the engine reader in the tick, the SQL reader in the Manager.
    param([Parameter(Mandatory)][string]$Entity)
    if (Get-Command Get-PimDesiredRows -ErrorAction SilentlyContinue) {
        $rows = @(Get-PimDesiredRows -Entity $Entity)
        # An unresolved read is NOT "no rows": writing an empty map would make every admin read as "no methods".
        if (($global:PIM_DesiredResolved -is [hashtable]) -and $global:PIM_DesiredResolved.ContainsKey($Entity) -and -not [bool]$global:PIM_DesiredResolved[$Entity]) {
            throw "'$Entity' could not be read from the store -- nothing is cached rather than an empty list"
        }
        return $rows
    }
    $cs = Get-PimTenantCacheStoreCs
    if ($cs -and (Get-Command Get-PimSqlRows -ErrorAction SilentlyContinue)) { return @(Get-PimSqlRows -ConnectionString $cs -Entity $Entity) }
    throw "no desired-state reader is loaded -- '$Entity' cannot be read"
}

function Test-PimTenantSyncPermissionError {
    param([string]$Message)
    return ("$Message" -match '(?i)\b403\b|Forbidden|Authorization_RequestDenied|Insufficient privileges|PermissionScopeNotGranted')
}

function ConvertTo-PimAuthMethodName {
    # PURE. A Graph authentication method @odata.type -> the short name the validator's required/weak sets use.
    # '' for the password (it is not a second factor and would hide an sms-only admin from PIM-AUTH-002).
    param([string]$ODataType)
    switch -Regex ("$ODataType") {
        'microsoftAuthenticatorAuthenticationMethod' { return 'microsoftAuthenticator' }
        'fido2AuthenticationMethod'                  { return 'fido2' }
        'platformCredentialAuthenticationMethod'     { return 'passkey' }
        'windowsHelloForBusinessAuthenticationMethod' { return 'windowsHelloForBusiness' }
        'x509CertificateAuthenticationMethod'        { return 'certificate' }
        'phoneAuthenticationMethod'                  { return 'phone' }
        'emailAuthenticationMethod'                  { return 'email' }
        'softwareOathAuthenticationMethod'           { return 'softwareOath' }
        'temporaryAccessPassAuthenticationMethod'    { return 'temporaryAccessPass' }
        'passwordAuthenticationMethod'               { return '' }
        default { $n = ("$ODataType" -replace '^#microsoft\.graph\.', '' -replace 'AuthenticationMethod$', ''); return $n }
    }
}

function Get-PimAdminAuthMethodsFromTenant {
    # upn-lower -> @(method names) for every Entra admin row (TargetPlatform AD has no Entra methods).
    # Needs UserAuthenticationMethod.Read.All. Returns [pscustomobject] map.
    $map = [ordered]@{}
    foreach ($r in @(Get-PimTenantSyncRows -Entity 'Account-Definitions-Admins')) {
        if ($null -eq $r) { continue }
        $upn = "$($r.UserPrincipalName)".Trim(); if (-not $upn) { $upn = "$($r.UserName)".Trim() }
        if (-not $upn -or "$($r.TargetPlatform)".Trim() -ieq 'AD') { continue }
        try {
            $methods = Invoke-PimGraphGetAll -Uri ("https://graph.microsoft.com/v1.0/users/{0}/authentication/methods" -f [uri]::EscapeDataString($upn))   # returns ,@(...) -- not wrapped (would nest)
        } catch {
            if (Test-PimTenantSyncPermissionError -Message "$($_.Exception.Message)") { throw "PERMISSION: UserAuthenticationMethod.Read.All is not granted to the engine identity ($($_.Exception.Message))" }
            if ("$($_.Exception.Message)" -match '(?i)\b404\b|Request_ResourceNotFound|does not exist') { continue }   # not created yet -- nothing to check
            throw
        }
        $names = @($methods | ForEach-Object { ConvertTo-PimAuthMethodName -ODataType "$($_.'@odata.type')" } | Where-Object { $_ } | Sort-Object -Unique)
        $map[$upn.ToLowerInvariant()] = $names
    }
    return [pscustomobject]$map
}

# The entities that DEFINE a group -- the same list as Get-PimGroupDefinitionRows (PIM-EngineProviders.ps1). Keep in step.
$script:PimTenantSyncGroupDefinitionEntities = @('PIM-Definitions-Roles', 'PIM-Definitions-Services', 'PIM-Definitions-Organization', 'PIM-Definitions-Tasks',
                                                  'PIM-Definitions-Departments', 'PIM-Definitions-Processes', 'PIM-Definitions-Projects', 'PIM-Definitions-CrossOrg')

function Get-PimTenantSyncOwnedGroups {
    <#
      BUG-192 follow-up (2.4.371). The solution-owned groups resolved to live ids, in EITHER host:
        * the tick (engine providers loaded)  -> Get-PimSolutionOwnedGroups, the engine's own resolver;
        * the Manager (no engine providers)   -> the group DEFINITION rows from the store, matched by displayName
          against the tenant's groups: one paged prefix list (the same read as the 'pim-groups' cache), then a
          direct displayName lookup for each defined group the prefix list did not contain (Department/Project/
          Cross-org groups can carry another prefix). A defined group with no live object is not created yet and
          is simply not in the set -- exactly as the engine resolver treats it.
      2.4.370 threw "the engine providers are not loaded" here, so every Manager-side refresh reported
      "1 of 7 list(s) FAILED". Returns @{ byId = @{ gid -> @{ id; name; tag } }; byTag = @{ tag -> gid }; source }.
    #>
    [CmdletBinding()] param()
    if (Get-Command Get-PimSolutionOwnedGroups -ErrorAction SilentlyContinue) {
        $o = Get-PimSolutionOwnedGroups
        return [pscustomobject]@{ byId = $o.byId; byTag = $o.byTag; source = 'engine' }
    }
    $defs = [ordered]@{}   # name-lower -> @{ name; tag }
    foreach ($e in $script:PimTenantSyncGroupDefinitionEntities) {
        foreach ($r in @(Get-PimTenantSyncRows -Entity $e)) {
            if ($null -eq $r) { continue }
            $gn = "$($r.GroupName)".Trim(); if (-not $gn) { continue }   # Department OWNER rows carry no GroupName -- not groups
            $k = $gn.ToLowerInvariant(); if (-not $defs.Contains($k)) { $defs[$k] = @{ name = $gn; tag = "$($r.GroupTag)".Trim() } }
        }
    }
    $live = @{}   # name-lower -> id
    if ($defs.Count) {
        $glist = Get-PimGroupsFromTenant   # returns ,@(...) -- assign, never wrap in @() (it would NEST the list)
        foreach ($g in $glist) { $n = "$($g.displayName)".Trim().ToLowerInvariant(); if ($n -and -not $live.ContainsKey($n)) { $live[$n] = "$($g.id)" } }
    }
    $byId = @{}; $byTag = @{}
    foreach ($k in @($defs.Keys)) {
        $d = $defs[$k]; $gid = $live[$k]
        if (-not $gid) {
            $flt = [uri]::EscapeDataString(("displayName eq '{0}'" -f ($d.name -replace "'", "''")))
            $hit = Invoke-PimGraphGetAll -Uri ("https://graph.microsoft.com/v1.0/groups?`$filter={0}&`$select=id,displayName" -f $flt)   # assigned, not wrapped (see above)
            if (@($hit).Count) { $gid = "$(@($hit)[0].id)" }
        }
        if (-not $gid) { continue }   # not created yet -- nothing live to read activity for
        $byId[$gid] = [pscustomobject]@{ id = $gid; name = $d.name; tag = $d.tag }
        if ($d.tag) { $byTag[$d.tag.ToLowerInvariant()] = $gid }
    }
    return [pscustomobject]@{ byId = $byId; byTag = $byTag; source = 'store+graph' }
}

function Get-PimGroupActivityFromTenant {
    # groupTag-lower -> the latest SELF-ACTIVATION (ISO UTC) of each solution-owned PIM group. Groups never activated
    # are simply absent (PIM-STALE-003 then reports "never activated"). One request per group
    # (GET .../group/assignmentScheduleRequests?$filter=groupId eq '<id>' -- the API REQUIRES a groupId or
    # principalId filter). Needs PrivilegedAssignmentSchedule.ReadWrite.AzureADGroup (the engine already holds it).
    # 2.4.371: the owned-group set resolves in the Manager too (Get-PimTenantSyncOwnedGroups) -- no engine dependency.
    $owned = Get-PimTenantSyncOwnedGroups
    $map = [ordered]@{}
    # 2.4.540 (internal 2026-10-09, mail "too many requests"): ~377 single GETs one after another were throttled (429)
    # right after an update queued tenant-cache + drift on top of the normal jobs. Read them through /$batch (20 per
    # round-trip, paced on Retry-After, the throttled items retried as a batch) -- the active-assignments snapshot's path.
    $tagged = @($owned.byId.Keys | Where-Object { "$($owned.byId[$_].tag)".Trim() })
    $batched = @{}
    if ($tagged.Count -and (Get-Command Invoke-PimGraphBatchGet -ErrorAction SilentlyContinue)) {
        $res = Invoke-PimGraphBatchGet -Paths @($tagged | ForEach-Object { "/identityGovernance/privilegedAccess/group/assignmentScheduleRequests?`$filter=groupId eq '$_'&`$select=action,status,createdDateTime" })   # 2.4.542: NOT @(...) -- the function returns ,$results (one array); @() nested it so only slot 0 held an answer and every other group read "no answer"
        $bad = @(); $transient = 0
        for ($i = 0; $i -lt $tagged.Count; $i++) {
            $r = $res[$i]
            if ($r -and $r.ok) { $batched[$tagged[$i]] = @($r.items); continue }
            $msg = if ($r) { "$($r.error)" } else { 'no answer' }
            if (Test-PimTenantSyncPermissionError -Message $msg) { throw "PERMISSION: PrivilegedAssignmentSchedule.ReadWrite.AzureADGroup is not granted to the engine identity ($msg)" }
            # 2.4.541 (internal 2026-10-09 20:37): after the batch's retries a throttled read comes back with NO answer (or
            # status 429/5xx). That is still throttling -- say so, so the refresh keeps the last list (stale) instead of failing.
            $code = if ($r) { [int]"0$($r.status)" } else { 0 }
            if (-not $r -or $msg -match '(?i)no answer' -or $code -eq 429 -or $code -ge 500) { $transient++ }
            $bad += "$($tagged[$i]): $msg"
        }
        $unanswered = @{}
        if ($bad.Count) {
            $what = if ($transient -eq $bad.Count) { 'THROTTLED (HTTP 429) -- ' } else { '' }
            # 2.4.543 (internal 2026-10-09, §100.44): on a busy big tenant SOME groups always stay throttled, so an
            # all-or-nothing read never refreshed. When every failure is throttling and at least one group answered: keep
            # the answered groups, and carry each unanswered group's PREVIOUS value from the cache -- the list converges a
            # little more on every run instead of never. Nothing answered, or a real error = throw as before.
            if ($transient -eq $bad.Count -and $batched.Count -gt 0) {
                foreach ($gid in $tagged) { if (-not $batched.ContainsKey($gid)) { $unanswered[$gid] = $true } }
                $script:PimActivityPartial = "{0} of {1} groups read; {2} throttled kept their previous value" -f $batched.Count, $tagged.Count, $unanswered.Count
            } else {
                throw ("{0}{1} of {2} group activity read(s) failed: {3}" -f $what, $bad.Count, $tagged.Count, (@($bad | Select-Object -First 3) -join '; '))
            }
        } else { $script:PimActivityPartial = $null }
        if ($unanswered.Count) {
            $prev = $null; try { $prev = Get-PimTenantCacheEntry -Kind 'pim-activity' } catch { $prev = $null }
            if ($prev -is [string]) { try { $prev = $prev | ConvertFrom-Json } catch { $prev = $null } }
            foreach ($gid in @($unanswered.Keys)) {
                $k = "$($owned.byId[$gid].tag)".Trim().ToLowerInvariant()
                $pv = $null
                if ($prev -is [System.Collections.IDictionary]) { if ($prev.Contains($k)) { $pv = $prev[$k] } }
                elseif ($prev -and $prev.PSObject.Properties[$k]) { $pv = $prev.$k }
                if ("$pv") { $map[$k] = "$pv" }
            }
        }
    }
    foreach ($gid in @($owned.byId.Keys)) {
        $tag = "$($owned.byId[$gid].tag)".Trim(); if (-not $tag) { continue }
        if ($unanswered -and $unanswered.ContainsKey($gid)) { continue }   # 2.4.543: carried from the cache above, never re-read one by one
        $reqs = @()
        if ($batched.ContainsKey($gid)) { $reqs = $batched[$gid] }
        else {
            try {
                $reqs = Invoke-PimGraphGetAll -Uri ("https://graph.microsoft.com/v1.0/identityGovernance/privilegedAccess/group/assignmentScheduleRequests?`$filter=groupId eq '{0}'&`$select=action,status,createdDateTime" -f $gid)   # returns ,@(...) -- wrapping it in @() would NEST the list
            } catch {
                if (Test-PimTenantSyncPermissionError -Message "$($_.Exception.Message)") { throw "PERMISSION: PrivilegedAssignmentSchedule.ReadWrite.AzureADGroup is not granted to the engine identity ($($_.Exception.Message))" }
                throw
            }
        }
        $last = $null
        foreach ($q in @($reqs)) {
            if ("$($q.action)" -ine 'selfActivate') { continue }
            if ("$($q.status)" -notmatch '(?i)^(Provisioned|Granted|ScheduleCreated|PendingProvisioning)$') { continue }
            $t = $null; try { $t = ([datetime]"$($q.createdDateTime)").ToUniversalTime() } catch { $t = $null }
            if ($null -ne $t -and ($null -eq $last -or $t -gt $last)) { $last = $t }
        }
        if ($null -ne $last) {
            $k = $tag.ToLowerInvariant()
            if (-not $map.Contains($k) -or ([datetime]$map[$k]) -lt $last) { $map[$k] = $last.ToString('o') }
        }
    }
    return [pscustomobject]$map
}
# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

# §100.45: when the group-activity list ('pim-activity') was last READ from Graph. Kept in pim.Settings
# 'PimActivityReadUtc' (and in this process), not inside the cache document: its keys are group tags.
$script:PimActivityRefreshHours = 24
$script:PimActivityLastReadMem = $null
function Test-PimActivityReadDue {
    # PURE. Due when never read, unreadable, or at least -Hours ago (a stamp in the future counts as due).
    param([AllowNull()][object]$LastReadUtc, [datetime]$NowUtc = [datetime]::UtcNow, [double]$Hours = $script:PimActivityRefreshHours)
    if ($null -eq $LastReadUtc) { return $true }
    $t = $null; try { $t = ([datetime]$LastReadUtc).ToUniversalTime() } catch { return $true }
    $age = ($NowUtc.ToUniversalTime() - $t).TotalHours
    return ($age -lt 0 -or $age -ge $Hours)
}
function Get-PimActivityLastReadUtc {
    # [datetime] UTC of the last group-activity read, or $null. Never throws.
    if ($script:PimActivityLastReadMem -is [datetime]) { return $script:PimActivityLastReadMem }
    $cs = Get-PimTenantCacheStoreCs
    if ($cs -and (Get-Command Get-PimSqlSetting -ErrorAction SilentlyContinue)) {
        try {
            $v = Get-PimSqlSetting -ConnectionString $cs -Name 'PimActivityReadUtc'
            if ($v -is [datetime]) { return $v.ToUniversalTime() }
            $d = [datetime]::MinValue
            if ("$v".Trim() -and [datetime]::TryParse("$v".Trim('"'), [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]'AdjustToUniversal,AssumeUniversal', [ref]$d)) { return $d }
        } catch { }
    }
    return $null
}
function Set-PimActivityLastReadUtc {
    param([Parameter(Mandatory)][datetime]$WhenUtc)
    $script:PimActivityLastReadMem = $WhenUtc.ToUniversalTime()
    $cs = Get-PimTenantCacheStoreCs
    if ($cs -and (Get-Command Set-PimSqlSetting -ErrorAction SilentlyContinue)) {
        # A failed write is reported, never swallowed: the in-memory value still holds for this process, so the only cost is
        # one extra activity read after a restart.
        try { Set-PimSqlSetting -ConnectionString $cs -Name 'PimActivityReadUtc' -Value $WhenUtc.ToUniversalTime().ToString('o') | Out-Null }
        catch { Write-Warning "[tenant-sync] pim-activity: the last-read time was not saved ($($_.Exception.Message)) -- the next restart reads the activity list again." }
    }
}

# Single-flight lock so concurrent UI refresh requests don't hammer Graph.
$script:PimTenantRefreshInProgress = $false

function Invoke-PimTenantListRefresh {
    [CmdletBinding()]
    param(
        [switch]$Quiet
    )

    if ($script:PimTenantRefreshInProgress) {
        if (-not $Quiet) { Write-Host "  tenant refresh already in progress -- skipping." -ForegroundColor Yellow }
        return [ordered]@{ ok = $false; reason = 'in-progress' }
    }
    $script:PimTenantRefreshInProgress = $true
    try {
        $tenantId = Assert-PimTenantConnectionContext

        if (-not $Quiet) {
            Write-Host "  refreshing tenant lists (tenant $tenantId) ..." -ForegroundColor Cyan
        }

        # §100.42: nothing to connect -- every read below mints its token through PIM-Rest.ps1 (the one connect path).

        $results = [ordered]@{}

        foreach ($step in @(
            @{ kind = 'entra-roles';      label = 'Entra ID roles';        fn = { Get-PimEntraRolesFromTenant } },
            @{ kind = 'aus';              label = 'Administrative Units';  fn = { Get-PimAdministrativeUnitsFromTenant } },
            @{ kind = 'pim-groups';       label = 'PIM-* groups';          fn = { Get-PimGroupsFromTenant } },
            @{ kind = 'azure-scopes';     label = 'Azure scopes';          fn = { Get-PimAzureScopesFromTenant } },
            @{ kind = 'azure-rbac-roles'; label = 'Azure RBAC roles';      fn = { Get-PimAzureRbacRolesFromTenant } },
            # BUG-192: the two validator caches nothing wrote. MAP-shaped, OPTIONAL (a missing permission skips).
            @{ kind = 'auth-methods';     label = 'Admin auth methods';    fn = { Get-PimAdminAuthMethodsFromTenant }; map = $true; optional = $true },
            @{ kind = 'pim-activity';     label = 'PIM group activity';    fn = { Get-PimGroupActivityFromTenant };    map = $true; optional = $true }
        )) {
            $kind  = $step.kind
            $label = $step.label
            # §100.45: the group-activity read (one request per owned group, ~366 on internal) runs at most once per
            # $script:PimActivityRefreshHours -- run on every refresh it overlapped the policy / drift reads and multiplied
            # the 429s. In between the last value is kept and its age reported.
            if ($kind -eq 'pim-activity') {
                $lastAct = Get-PimActivityLastReadUtc
                if (-not (Test-PimActivityReadDue -LastReadUtc $lastAct)) {
                    $ageH = [Math]::Round(((Get-Date).ToUniversalTime() - $lastAct).TotalHours, 1)
                    if (-not $Quiet) { Write-Host ("    {0,-22} KEPT -- read {1} h ago (refreshed every {2} h)" -f $label, $ageH, $script:PimActivityRefreshHours) -ForegroundColor DarkGray }
                    $results[$kind] = @{ ok = $true; kept = $true; count = 0; ageHours = $ageH; lastReadUtc = $lastAct.ToString('o'); reason = "kept: read $ageH h ago, refreshed every $($script:PimActivityRefreshHours) h" }
                    continue
                }
            }
            try {
                $items = & $step.fn
                if ($kind -eq 'pim-activity') { Set-PimActivityLastReadUtc -WhenUtc (Get-Date).ToUniversalTime() }
                if ($step.map) {
                    $path  = Set-PimTenantCacheEntry -Kind $kind -Value $items
                    $count = @($items.PSObject.Properties).Count
                } else {
                    $path  = Write-PimTenantCache -Kind $kind -Items $items
                    $count = @($items).Count
                }
                if (-not $Quiet) {
                    Write-Host ("    {0,-22} {1,5} items -> {2}" -f $label, $count, $path) -ForegroundColor DarkGray
                }
                $results[$kind] = @{ ok = $true; count = $count; path = $path }
            } catch {
                if ($step.optional -and "$($_.Exception.Message)" -like 'PERMISSION:*') {
                    # Not a failure: the permission is a deployment choice, and the validator already says the check
                    # is skipped and why. Reported so it is visible, never counted against the refresh.
                    if (-not $Quiet) { Write-Host ("    {0,-22} SKIPPED -- {1}" -f $label, $_.Exception.Message) -ForegroundColor DarkYellow }
                    $results[$kind] = @{ ok = $true; skipped = $true; count = 0; reason = "$($_.Exception.Message)" }
                    continue
                }
                # 2.4.540: an OPTIONAL list that failed for a TRANSIENT reason (Graph throttling 429, a 5xx, a timeout) keeps its
                # last good cache (nothing was written) and is reported STALE -- not a failed refresh, not an alert mail. It
                # refreshes on the next run. A required list, or a real error, still fails the refresh.
                if ($step.optional -and "$($_.Exception.Message)" -match '(?i)\b429\b|too many requests|throttl|\b50[0-4]\b|timed out|service unavailable') {
                    if (-not $Quiet) { Write-Host ("    {0,-22} STALE -- kept the last refresh, transient: {1}" -f $label, $_.Exception.Message) -ForegroundColor DarkYellow }
                    $results[$kind] = @{ ok = $true; stale = $true; count = 0; reason = "$($_.Exception.Message)" }
                    continue
                }
                if (-not $Quiet) {
                    Write-Warning ("    {0} FAILED: {1}" -f $label, $_.Exception.Message)
                }
                $results[$kind] = @{ ok = $false; error = "$($_.Exception.Message)" }
            }
        }

        # 2.4.544 (framework 12.15 "else what the last collection recorded"): the UPDATER's identity may not $count tenant
        # objects (Graph 403 on every environment, 2026-10-09), so the tick -- which holds the Graph read rights -- records
        # users / groups / service principals here; the updater's sizing reads pim.Settings 'TenantObjectCounts' on a 403.
        # Best effort: never fails or slows the refresh beyond three $count calls.
        try {
            $csC = Get-PimTenantCacheStoreCs
            if (-not (Get-Command Get-PimTenantObjectCounts -ErrorAction SilentlyContinue)) {
                $tsz = Join-Path $PSScriptRoot '..\..\engine\_shared\PIM-TenantSizing.ps1'   # the tick does not load it otherwise
                if (Test-Path -LiteralPath $tsz) { . $tsz }
            }
            if ($csC -and (Get-Command Get-PimTenantObjectCounts -ErrorAction SilentlyContinue) -and (Get-Command Invoke-PimGraph -ErrorAction SilentlyContinue) -and (Get-Command Set-PimSqlSetting -ErrorAction SilentlyContinue)) {
                $oc = Get-PimTenantObjectCounts -GraphGet { param($p) Invoke-PimGraph -Path $p -Headers @{ ConsistencyLevel = 'eventual' } }
                if ($oc.ok) {
                    # framework 8.11 ASSET-COUNTS: enabled MEMBER users and guests too (two more $count calls); a count that
                    # cannot be read is left out (null), never 0.
                    $cnt1 = { param($p) $n = 0L; try { $raw = Invoke-PimGraph -Path $p -Headers @{ ConsistencyLevel = 'eventual' }; if ([long]::TryParse(("$raw".Trim().Trim([char]0xFEFF)), [ref]$n)) { return $n } } catch { }; return $null }
                    $members = & $cnt1 "/users/`$count?`$filter=userType eq 'Member' and accountEnabled eq true"
                    $guests = & $cnt1 "/users/`$count?`$filter=userType eq 'Guest'"
                    Set-PimSqlSetting -ConnectionString $csC -Name 'TenantObjectCounts' -Value ([ordered]@{ Users = $oc.Users; Groups = $oc.Groups; ServicePrincipals = $oc.ServicePrincipals; Members = $members; Guests = $guests; recordedUtc = (Get-Date).ToUniversalTime().ToString('o') }) | Out-Null
                }
            }
        } catch { if (-not $Quiet) { Write-Host "    tenant object counts not recorded: $($_.Exception.Message)" -ForegroundColor DarkYellow } }

        # IMP-49 b (ss33.28): this returned ok=$true even when EVERY step had failed, so the tenant-cache job read green
        # over an empty refresh. ok is now true only when no REQUIRED step failed; an optional step that is skipped
        # (permission not granted) is reported, not failed.
        $failedKinds = @($results.Keys | Where-Object { -not $results[$_].ok })
        $okKinds     = @($results.Keys | Where-Object { $results[$_].ok })
        $reason = if ($failedKinds.Count) {
            ("{0} of {1} list(s) FAILED to refresh: {2}" -f $failedKinds.Count, @($results.Keys).Count,
                ((@($failedKinds) | ForEach-Object { "$_ ($($results[$_].error))" }) -join '; '))
        } else { '' }
        return [ordered]@{
            ok       = ($failedKinds.Count -eq 0)
            partial  = ($failedKinds.Count -gt 0 -and $okKinds.Count -gt 0)
            reason   = $reason
            failed   = $failedKinds
            tenantId = $tenantId
            results  = $results
            refreshedUtc = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        }
    } finally {
        $script:PimTenantRefreshInProgress = $false
    }
}
