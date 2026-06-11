#Requires -Version 5.1
<#
.SYNOPSIS
    Tenant-list cache builder for PIM Manager.

.DESCRIPTION
    Dot-sourced from Open-PimManager.ps1. Provides:

      Invoke-PimTenantListRefresh   -> connects to the tenant via the engine
                                       SPN, queries Graph + Resource Graph,
                                       writes JSON cache files under
                                       tools/pim-manager/cache/.

      Read-PimTenantListCache       -> returns hashtable of the 4 cached
                                       lists for the UI (no live calls).

    Cache file format is stable:

        { "refreshedUtc": "<iso>", "items": [ ... ] }

    The four cache files:

      entra-roles.json     items: { id, displayName, description, isBuiltIn,
                                    rolePermissions: [
                                        { allowedResourceActions, excludedResourceActions,
                                          allowedDataActions,    excludedDataActions } ] }
      aus.json             items: { id, displayName, description }
      pim-groups.json      items: { id, displayName, description }
      azure-scopes.json    items: { id, displayName, type, scopePath }

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
# Cache path helpers
# ---------------------------------------------------------------------------

function Get-PimTenantCacheRoot {
    if (-not $script:PimManagerRoot) {
        # _tenantSync.ps1 sits next to Open-PimManager.ps1; PSScriptRoot here is the dot-sourcer's path,
        # so derive from $PSCommandPath instead.
        $script:PimManagerRoot = Split-Path -Parent $PSCommandPath
    }
    $cacheRoot = Join-Path $script:PimManagerRoot 'cache'
    # MSP multi-instance: each instance is a different tenant, so role names /
    # AU ids / subscription ids must never bleed across customers. 'local'
    # keeps the flat cache/ folder for back-compat with existing installs.
    if ($script:PimInstanceName -and $script:PimInstanceName -ne 'local') {
        $cacheRoot = Join-Path $cacheRoot $script:PimInstanceName
    }
    if (-not (Test-Path -LiteralPath $cacheRoot)) {
        New-Item -ItemType Directory -Path $cacheRoot -Force | Out-Null
    }
    return $cacheRoot
}

function Get-PimTenantCacheFile {
    param([Parameter(Mandatory)][ValidateSet('entra-roles','aus','pim-groups','azure-scopes')][string]$Kind)
    Join-Path (Get-PimTenantCacheRoot) ("{0}.json" -f $Kind)
}

function Write-PimTenantCache {
    param(
        [Parameter(Mandatory)][string]$Kind,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Items
    )
    $file = Get-PimTenantCacheFile -Kind $Kind
    $body = [ordered]@{
        refreshedUtc = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        items        = @($Items)
    }
    $json = $body | ConvertTo-Json -Depth 10 -Compress
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    $tmp = "$file.tmp"
    [System.IO.File]::WriteAllText($tmp, $json, $utf8NoBom)
    Move-Item -LiteralPath $tmp -Destination $file -Force
    return $file
}

function Read-PimTenantListCache {
    # Returns hashtable: @{ entraRoles=@{refreshedUtc;items}; aus=@{...}; pimGroups=@{...}; azureScopes=@{...} }
    # Missing files yield $null entries -- UI must tolerate.
    $out = [ordered]@{}
    $kinds = @(
        @{ kind = 'entra-roles';  key = 'entraRoles' },
        @{ kind = 'aus';          key = 'aus' },
        @{ kind = 'pim-groups';   key = 'pimGroups' },
        @{ kind = 'azure-scopes'; key = 'azureScopes' }
    )
    foreach ($k in $kinds) {
        $f = Get-PimTenantCacheFile -Kind $k.kind
        if (Test-Path -LiteralPath $f) {
            try {
                $raw = [System.IO.File]::ReadAllText($f, [System.Text.UTF8Encoding]::new($false))
                if ($raw.Length -gt 0 -and [int][char]$raw[0] -eq 0xFEFF) { $raw = $raw.Substring(1) }
                $parsed = $raw | ConvertFrom-Json
                $out[$k.key] = @{
                    refreshedUtc = $parsed.refreshedUtc
                    items        = @($parsed.items)
                }
            } catch {
                $out[$k.key] = @{ refreshedUtc = $null; items = @(); error = "$($_.Exception.Message)" }
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

function Assert-PimTenantConnectionContext {
    # Verify a usable tenant connection context. Accepted, in order:
    #   1. An ALREADY-CONNECTED app-only Graph context (Connect-Platform did the
    #      work in this process -- e.g. launched via -ConnectPlatform). Tenant
    #      comes from the live context.
    #   2. Engine SPN globals with a certificate thumbprint (cert auth).
    #   3. Engine SPN globals with a client secret (secret auth -- what
    #      Connect-PlatformModern populates on tenants without a Modern cert).
    # Never falls back to interactive sign-in.
    $tenantId = $null
    if     ($global:AzureTenantID) { $tenantId = $global:AzureTenantID }
    elseif ($global:AzureTenantId) { $tenantId = $global:AzureTenantId }

    try {
        $mg = Get-MgContext -ErrorAction SilentlyContinue
        if ($mg -and $mg.AuthType -eq 'AppOnly' -and (-not $tenantId -or $mg.TenantId -eq $tenantId)) {
            return $(if ($tenantId) { $tenantId } else { $mg.TenantId })
        }
    } catch { }

    $missing = New-Object System.Collections.ArrayList
    if (-not $global:HighPriv_Modern_ApplicationID_Azure) { [void]$missing.Add('$global:HighPriv_Modern_ApplicationID_Azure') }
    if (-not $global:HighPriv_Modern_CertificateThumbprint_Azure -and -not $global:HighPriv_Modern_Secret_Azure) {
        [void]$missing.Add('$global:HighPriv_Modern_CertificateThumbprint_Azure (or $global:HighPriv_Modern_Secret_Azure)')
    }
    if (-not $tenantId) { [void]$missing.Add('$global:AzureTenantID') }
    if ($missing.Count -gt 0) {
        $missingList = $missing -join ', '
        throw "PIM Manager tenant access requires the engine SPN context. Missing: $missingList. Launch with Open-PimManager.ps1 -ConnectPlatform (recommended), or run any baseline engine first, or source your bootstrap manually."
    }
    return $tenantId
}

function Connect-PimManagerGraph {
    # Reuses an existing matching app-only context when present; otherwise
    # connects via cert thumbprint, else via client secret. Always app-only.
    param([Parameter(Mandatory)][string]$TenantId)
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
    param([Parameter(Mandatory)][string]$TenantId)
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
    # Pages through a Graph collection URL. Uses Invoke-MgGraphRequest under
    # the hood so we don't depend on the SDK resource cmdlets being present.
    param([Parameter(Mandatory)][string]$Uri)
    $all = New-Object System.Collections.ArrayList
    $next = $Uri
    while ($next) {
        $resp = Invoke-MgGraphRequest -Method GET -Uri $next -ErrorAction Stop
        if ($resp.value) {
            foreach ($v in $resp.value) { [void]$all.Add($v) }
        }
        $next = $resp.'@odata.nextLink'
    }
    return ,$all.ToArray()
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

function Get-PimGroupsFromTenant {
    # Graph filter syntax for startswith requires the property to be filterable;
    # displayName is. Top 999 is the API max per page; paging handles the rest.
    $uri = 'https://graph.microsoft.com/v1.0/groups?$filter=' +
           [uri]::EscapeDataString("startswith(displayName,'PIM-')") +
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

function Get-PimAzureScopesFromTenant {
    # Returns subscriptions + management groups + their full ARM scope paths.
    # Resource Graph is faster + paginates server-side. We deliberately do not
    # enumerate resource groups here -- assignments are typically at sub/mg.
    $items = New-Object System.Collections.ArrayList

    # Management groups via Az cmdlet (Resource Graph has them too, but the
    # Az cmdlet returns the full id including 'tenants/' boundary nicely).
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

    # Subscriptions via Resource Graph.
    $hasArg = Get-Command Search-AzGraph -ErrorAction SilentlyContinue
    if ($hasArg) {
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

    return ,@($items)
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
            @{ kind = 'entra-roles';  label = 'Entra ID roles';        fn = { Get-PimEntraRolesFromTenant } },
            @{ kind = 'aus';          label = 'Administrative Units';  fn = { Get-PimAdministrativeUnitsFromTenant } },
            @{ kind = 'pim-groups';   label = 'PIM-* groups';          fn = { Get-PimGroupsFromTenant } },
            @{ kind = 'azure-scopes'; label = 'Azure scopes';          fn = { Get-PimAzureScopesFromTenant } }
        )) {
            $kind  = $step.kind
            $label = $step.label
            try {
                $items = & $step.fn
                $path  = Write-PimTenantCache -Kind $kind -Items $items
                if (-not $Quiet) {
                    Write-Host ("    {0,-22} {1,5} items -> {2}" -f $label, @($items).Count, (Split-Path -Leaf $path)) -ForegroundColor DarkGray
                }
                $results[$kind] = @{ ok = $true; count = @($items).Count; path = $path }
            } catch {
                if (-not $Quiet) {
                    Write-Warning ("    {0} FAILED: {1}" -f $label, $_.Exception.Message)
                }
                $results[$kind] = @{ ok = $false; error = "$($_.Exception.Message)" }
            }
        }

        return [ordered]@{
            ok       = $true
            tenantId = $tenantId
            results  = $results
            refreshedUtc = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        }
    } finally {
        $script:PimTenantRefreshInProgress = $false
    }
}
