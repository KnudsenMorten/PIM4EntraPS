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
# scheduler job 'coverage', read by GET /api/coverage. See engine/_shared/PIM-Coverage.ps1.
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
$script:PimTenantCacheKinds = @('entra-roles','aus','pim-groups','azure-scopes','azure-rbac-roles','auth-methods','pim-activity','tenant-org','active-assignments','drift','coverage-report','target-check','workload-roles:defender','workload-roles:intune','workload-actions:defender','tenant-domains')
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
        [Parameter(Mandatory)][AllowNull()][object]$Value
    )
    $cs = Get-PimTenantCacheStoreCs
    if ($cs -and (Get-Command Set-PimSqlTenantCache -ErrorAction SilentlyContinue)) {
        Set-PimSqlTenantCache -ConnectionString $cs -Kind $Kind -Value $Value
        return "sql:pim.TenantCache/$Kind"
    }
    $script:PimTenantCacheMem[$Kind] = ($Value | ConvertTo-Json -Depth 12 -Compress)
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
    # Verify a usable tenant connection context. Accepted, in order:
    #   1. An ALREADY-CONNECTED app-only Graph context (Connect-Platform did the
    #      work in this process -- e.g. launched via -ConnectPlatform). Tenant
    #      comes from the live context. (Graph SDK only.)
    #   2. REST app-only auth (PIM-Rest.ps1): a managed identity, or the engine
    #      SPN client id + cert/secret. This is the HOSTED container path -- no
    #      Graph/Az PowerShell module is present, so tokens are minted over REST.
    #   3. Engine SPN globals with a certificate thumbprint (cert auth).
    #   4. Engine SPN globals with a client secret (secret auth).
    # Never falls back to interactive sign-in.
    $tenantId = $null
    if     ($global:AzureTenantID) { $tenantId = $global:AzureTenantID }
    elseif ($global:AzureTenantId) { $tenantId = $global:AzureTenantId }
    elseif ($global:PIM_TenantId)  { $tenantId = $global:PIM_TenantId }
    elseif ($env:PIM_TenantId)     { $tenantId = $env:PIM_TenantId }

    # (1) live SDK app-only context (only meaningful when the SDK is loaded).
    if (Get-Command Get-MgContext -ErrorAction SilentlyContinue) {
        try {
            $mg = Get-MgContext -ErrorAction SilentlyContinue
            if ($mg -and $mg.AuthType -eq 'AppOnly' -and (-not $tenantId -or $mg.TenantId -eq $tenantId)) {
                return $(if ($tenantId) { $tenantId } else { $mg.TenantId })
            }
        } catch { }
    }

    # (2) REST app-only (hosted container / module-less). A managed identity
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
        throw "PIM Manager tenant access requires the engine SPN context (or a managed identity). Missing: $missingList. Hosted: set PIM_ClientId + PIM_CertThumbprint + PIM_TenantId app settings, or assign the container a managed identity with the needed Graph/ARM permissions. Local: launch with -ConnectPlatform, or run any baseline engine first."
    }
    return $tenantId
}

function Connect-PimManagerGraph {
    # Reuses an existing matching app-only context when present; otherwise
    # connects via cert thumbprint, else via client secret. Always app-only.
    # REST-only (hosted container, no Graph SDK): no-op -- Invoke-PimGraph mints
    # its own app-only token per call from PIM_* / MI via PIM-Rest.ps1.
    param([Parameter(Mandatory)][AllowEmptyString()][string]$TenantId)
    if (-not (Get-Command Connect-MgGraph -ErrorAction SilentlyContinue)) { return }
    $appId  = $global:HighPriv_Modern_ApplicationID_Azure
    $thumb  = $global:HighPriv_Modern_CertificateThumbprint_Azure
    $secret = $global:HighPriv_Modern_Secret_Azure

    try {
        $mg = Get-MgContext -ErrorAction SilentlyContinue
        if ($mg -and $mg.AuthType -eq 'AppOnly' -and $mg.TenantId -eq $TenantId) { return }
    } catch { }

    if (-not $appId) { throw "Connect-PimManagerGraph: no existing Graph context and `$global:HighPriv_Modern_ApplicationID_Azure is not set." }
    try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch { }

    if ($thumb) {
        $hasModule = Get-Module -ListAvailable -Name MicrosoftGraphPS | Select-Object -First 1
        if ($hasModule) {
            Import-Module MicrosoftGraphPS -Global -Force -WarningAction SilentlyContinue
            Connect-MicrosoftGraphPS `
                -AppId $appId `
                -CertificateThumbprint $thumb `
                -TenantId $TenantId `
                -ErrorAction Stop | Out-Null
        } else {
            Import-Module Microsoft.Graph.Authentication -Force -WarningAction SilentlyContinue
            Connect-MgGraph `
                -ClientId $appId `
                -CertificateThumbprint $thumb `
                -TenantId $TenantId `
                -NoWelcome `
                -ErrorAction Stop | Out-Null
        }
        return
    }
    if ($secret) {
        Import-Module Microsoft.Graph.Authentication -Force -WarningAction SilentlyContinue
        $sec  = ConvertTo-SecureString -String ([string]$secret) -AsPlainText -Force
        $cred = New-Object System.Management.Automation.PSCredential($appId, $sec)
        Connect-MgGraph `
            -TenantId $TenantId `
            -ClientSecretCredential $cred `
            -NoWelcome `
            -ErrorAction Stop | Out-Null
        return
    }
    throw "Connect-PimManagerGraph: neither a certificate thumbprint nor a client secret is available for app $appId."
}

function Connect-PimManagerAz {
    # REST-only (hosted container, no Az SDK): no-op -- Invoke-PimArm mints its
    # own app-only token per call from PIM_* / MI via PIM-Rest.ps1.
    param([Parameter(Mandatory)][AllowEmptyString()][string]$TenantId)
    if (-not (Get-Command Connect-AzAccount -ErrorAction SilentlyContinue)) { return }
    $appId  = $global:HighPriv_Modern_ApplicationID_Azure
    $thumb  = $global:HighPriv_Modern_CertificateThumbprint_Azure
    $secret = $global:HighPriv_Modern_Secret_Azure

    # Reuse an existing matching context if present (engines / Connect-Platform
    # may already be connected -- account match on appId, or any app-only
    # context in the right tenant when appId is unknown).
    try {
        $ctx = Get-AzContext -ErrorAction SilentlyContinue
        if ($ctx -and $ctx.Tenant.Id -eq $TenantId -and (-not $appId -or $ctx.Account.Id -eq $appId)) { return }
    } catch { }

    if (-not $appId) { throw "Connect-PimManagerAz: no existing Az context for tenant $TenantId and `$global:HighPriv_Modern_ApplicationID_Azure is not set." }
    Import-Module Az.Accounts -Force -WarningAction SilentlyContinue
    if ($thumb) {
        Connect-AzAccount `
            -ServicePrincipal `
            -ApplicationId $appId `
            -CertificateThumbprint $thumb `
            -TenantId $TenantId `
            -ErrorAction Stop | Out-Null
        return
    }
    if ($secret) {
        $sec  = ConvertTo-SecureString -String ([string]$secret) -AsPlainText -Force
        $cred = New-Object System.Management.Automation.PSCredential($appId, $sec)
        Connect-AzAccount `
            -ServicePrincipal `
            -Credential $cred `
            -TenantId $TenantId `
            -ErrorAction Stop | Out-Null
        return
    }
    throw "Connect-PimManagerAz: neither a certificate thumbprint nor a client secret is available for app $appId."
}

# ---------------------------------------------------------------------------
# Graph paging helper (works for both MicrosoftGraphPS and native cmdlets)
# ---------------------------------------------------------------------------

function Invoke-PimGraphGetAll {
    # Pages through a Graph collection URL. REST-first: when PIM-Rest.ps1's
    # Invoke-PimGraph is available (always, in the hosted container) it mints an
    # app-only token from PIM_* / MI -- no Graph SDK module required. Falls back
    # to Invoke-MgGraphRequest only when the SDK is loaded and REST is not.
    param([Parameter(Mandatory)][string]$Uri)
    if ((Get-Command Invoke-PimGraph -ErrorAction SilentlyContinue) -and
        (-not (Get-Command Invoke-MgGraphRequest -ErrorAction SilentlyContinue))) {
        # REST path (module-less): Invoke-PimGraph -All aggregates @odata.nextLink.
        return ,@(Invoke-PimGraph -Path $Uri -All)
    }
    if (Get-Command Invoke-MgGraphRequest -ErrorAction SilentlyContinue) {
        $all = New-Object System.Collections.ArrayList
        $next = $Uri
        while ($next) {
            $resp = Invoke-MgGraphRequest -Method GET -Uri $next -ErrorAction Stop
            if ($resp.value) { foreach ($v in $resp.value) { [void]$all.Add($v) } }
            $next = $resp.'@odata.nextLink'
        }
        return ,$all.ToArray()
    }
    # Last resort: REST even if the SDK is partially present.
    if (Get-Command Invoke-PimGraph -ErrorAction SilentlyContinue) {
        return ,@(Invoke-PimGraph -Path $Uri -All)
    }
    throw "Invoke-PimGraphGetAll: neither Invoke-PimGraph (REST) nor Invoke-MgGraphRequest (SDK) is available."
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
    # Returns subscriptions + management groups + their full ARM scope paths.
    # REST-first (hosted container, no Az module): the ARM REST API lists both
    # without any PowerShell module. Falls back to Az cmdlets when present.
    $items = New-Object System.Collections.ArrayList
    $restArm = (Get-Command Invoke-PimArm -ErrorAction SilentlyContinue) -and -not (Get-Command Get-AzManagementGroup -ErrorAction SilentlyContinue)

    if ($restArm) {
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

    # Management groups -- PURE ARM REST.
    #
    # 🔴 THIS RAN `Get-AzManagementGroup` UNCONDITIONALLY, and the container has no Az modules
    # (§19: the engine is REST-only). Unlike the subscription and roleDefinition blocks around it,
    # which already try ARM REST first and return, this one had NO REST path at all -- so in the
    # hosted Manager it always threw "not recognized", was caught, warned, and the Azure scope list
    # silently lost every management group.
    # 🔑 The ARM endpoint returns the same ids, including the tenants/ boundary the old comment
    # valued, so nothing downstream changes shape.
    $mgDone = $false
    if (Get-Command Invoke-PimArm -ErrorAction SilentlyContinue) {
        try {
            $resp = Invoke-PimArm -Method GET -Path '/providers/Microsoft.Management/managementGroups' -ApiVersion '2020-05-01' -All
            foreach ($m in @($resp)) {
                if (-not "$($m.id)".Trim()) { continue }
                [void]$items.Add([ordered]@{
                    id          = "$($m.id)"
                    displayName = $(if ("$($m.properties.displayName)".Trim()) { "$($m.properties.displayName)" } else { "$($m.name)" })
                    type        = 'managementGroup'
                    scopePath   = "$($m.id)"
                    isRoot      = ("$($m.name)" -and "$($m.name)" -eq "$($m.properties.tenantId)")   # §79.17 the Tenant Root Group
                })
            }
            $mgDone = $true
        } catch {
            Write-Warning ("  ARM managementGroups list failed: {0}" -f $_.Exception.Message)
        }
    }
    if (-not $mgDone) {
        # Host/dev convenience only -- never reachable in the container.
        try {
            $mgs = Get-AzManagementGroup -ErrorAction SilentlyContinue
            foreach ($m in $mgs) {
                [void]$items.Add([ordered]@{
                    id          = "$($m.Id)"
                    displayName = "$($m.DisplayName)"
                    type        = 'managementGroup'
                    scopePath   = "$($m.Id)"
                })
            }
        } catch {
            Write-Warning ("  Get-AzManagementGroup failed: {0}" -f $_.Exception.Message)
        }
    }

    # Subscriptions via Resource Graph -- PURE ARM REST.
    #
    # 🔴 THIS USED `Search-AzGraph`, AN Az MODULE CMDLET, AND THE CONTAINER HAS NO Az MODULES.
    # The engine is REST-only by design (§19), so in the hosted Manager the cmdlet was never found,
    # the fast path was skipped every time, and the fallback below ran instead -- which is why the
    # GUI sat on "Loading..." for ~51s and logged
    #     Get-AzActiveRoleAssignmentsViaArg: Search-AzGraph ... is not recognized
    # A capability that is ABSENT rather than broken, degrading silently into a slow path: the same
    # shape as BUG-134, measured here as a hang rather than a wrong answer.
    # 🔑 Resource Graph has a plain REST endpoint. Invoke-PimArm is the engine's own ARM client and
    # is always present, so there is no module to install and no fallback to be slow in.
    $argOk = $false
    if (Get-Command Invoke-PimArm -ErrorAction SilentlyContinue) {
        try {
            $kql  = "resourcecontainers | where type =~ 'microsoft.resources/subscriptions' | project subscriptionId, name, tenantId | order by name asc"
            $skip = 0
            do {
                $body = @{ query = $kql; options = @{ '$top' = 1000; '$skip' = $skip } }
                $resp = Invoke-PimArm -Method POST -Path '/providers/Microsoft.ResourceGraph/resources' `
                            -ApiVersion '2021-03-01' -Body $body
                $rows = @($resp.data)
                foreach ($s in $rows) {
                    [void]$items.Add([ordered]@{
                        id          = "$($s.subscriptionId)"
                        displayName = "$($s.name)"
                        type        = 'subscription'
                        scopePath   = "/subscriptions/$($s.subscriptionId)"
                    })
                }
                $skip += $rows.Count
                $argOk = $true
            } while ($rows.Count -ge 1000)
        } catch {
            # 🪤 Say it, do not swallow it into the slow path silently -- that is what hid this for
            # months. The fallback still runs, but the reason is on the record.
            Write-Warning ("  Resource Graph REST query failed ({0}) -- falling back to a slower enumeration." -f $_.Exception.Message)
            $argOk = $false
        }
    }
    if ($argOk) { }
    elseif (Get-Command Search-AzGraph -ErrorAction SilentlyContinue) {
        # Host/dev convenience only. Never reached in the container, which has no Az modules.
        try {
            $batch = $null
            $skip = 0
            do {
                $kql = "resourcecontainers | where type =~ 'microsoft.resources/subscriptions' | project subscriptionId, name, tenantId | order by name asc"
                $batch = Search-AzGraph -Query $kql -First 1000 -Skip $skip -ErrorAction Stop
                foreach ($s in $batch) {
                    [void]$items.Add([ordered]@{
                        id          = "$($s.subscriptionId)"
                        displayName = "$($s.name)"
                        type        = 'subscription'
                        scopePath   = "/subscriptions/$($s.subscriptionId)"
                    })
                }
                $skip += $batch.Count
            } while ($batch -and $batch.Count -ge 1000)
        } catch {
            Write-Warning ("  Search-AzGraph subscriptions query failed: {0}" -f $_.Exception.Message)
        }
    } else {
        # Fallback: Get-AzSubscription. Slower but doesn't need ARG module.
        try {
            $subs = Get-AzSubscription -ErrorAction SilentlyContinue
            foreach ($s in $subs) {
                [void]$items.Add([ordered]@{
                    id          = "$($s.Id)"
                    displayName = "$($s.Name)"
                    type        = 'subscription'
                    scopePath   = "/subscriptions/$($s.Id)"
                })
            }
        } catch {
            Write-Warning ("  Get-AzSubscription failed: {0}" -f $_.Exception.Message)
        }
    }

    Add-PimAzureScopeParents -Items $items   # §79.17
    return ,@($items)
}

function Get-PimAzureRbacRolesFromTenant {
    # Azure RBAC role DEFINITIONS (Owner, Contributor, Reader, custom roles...)
    # for the Azure permission-group pickers -- so operators select role names
    # instead of typing them (spelling errors in AzScopePermission silently
    # break the engine's role assignment).
    $items = New-Object System.Collections.ArrayList
    $restArm = (Get-Command Invoke-PimArm -ErrorAction SilentlyContinue) -and -not (Get-Command Get-AzRoleDefinition -ErrorAction SilentlyContinue)
    if ($restArm) {
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
    try {
        Import-Module Az.Resources -ErrorAction SilentlyContinue | Out-Null
        $defs = Get-AzRoleDefinition -ErrorAction Stop
        foreach ($d in $defs) {
            [void]$items.Add([ordered]@{
                id          = "$($d.Id)"
                displayName = "$($d.Name)"
                description = "$($d.Description)"
                isCustom    = [bool]$d.IsCustom
            })
        }
    } catch {
        Write-Warning ("  Get-AzRoleDefinition failed: {0}" -f $_.Exception.Message)
    }
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
    foreach ($gid in @($owned.byId.Keys)) {
        $tag = "$($owned.byId[$gid].tag)".Trim(); if (-not $tag) { continue }
        $reqs = @()
        try {
            $reqs = Invoke-PimGraphGetAll -Uri ("https://graph.microsoft.com/v1.0/identityGovernance/privilegedAccess/group/assignmentScheduleRequests?`$filter=groupId eq '{0}'&`$select=action,status,createdDateTime" -f $gid)   # returns ,@(...) -- wrapping it in @() would NEST the list
        } catch {
            if (Test-PimTenantSyncPermissionError -Message "$($_.Exception.Message)") { throw "PERMISSION: PrivilegedAssignmentSchedule.ReadWrite.AzureADGroup is not granted to the engine identity ($($_.Exception.Message))" }
            throw
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

        Connect-PimManagerGraph -TenantId $tenantId
        Connect-PimManagerAz    -TenantId $tenantId

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
            try {
                $items = & $step.fn
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
                if (-not $Quiet) {
                    Write-Warning ("    {0} FAILED: {1}" -f $label, $_.Exception.Message)
                }
                $results[$kind] = @{ ok = $false; error = "$($_.Exception.Message)" }
            }
        }

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
