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

      entra-roles.json     items: { id, displayName, description }
      aus.json             items: { id, displayName, description }
      pim-groups.json      items: { id, displayName, description }
      azure-scopes.json    items: { id, displayName, type, scopePath }

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
    # Verify the engine SPN globals are present. Throw with an actionable error
    # if not. We deliberately do NOT auto-bootstrap the AutomateITPS framework
    # here -- the caller (Open-PimManager.ps1) does that before dot-sourcing us.
    $missing = New-Object System.Collections.ArrayList
    if (-not $global:HighPriv_Modern_ApplicationID_Azure)        { [void]$missing.Add('$global:HighPriv_Modern_ApplicationID_Azure') }
    if (-not $global:HighPriv_Modern_CertificateThumbprint_Azure) { [void]$missing.Add('$global:HighPriv_Modern_CertificateThumbprint_Azure') }
    $tenantId = $null
    if     ($global:AzureTenantID) { $tenantId = $global:AzureTenantID }
    elseif ($global:AzureTenantId) { $tenantId = $global:AzureTenantId }
    if (-not $tenantId) { [void]$missing.Add('$global:AzureTenantID') }
    if ($missing.Count -gt 0) {
        $missingList = $missing -join ', '
        throw "PIM Manager tenant refresh requires the engine SPN context. Missing: $missingList. Run any baseline engine first (which calls Initialize-PlatformAutomationFramework), or source your bootstrap manually before -RefreshTenantLists."
    }
    return $tenantId
}

function Connect-PimManagerGraph {
    # Uses MicrosoftGraphPS if available (matches engines), else falls back to
    # native Connect-MgGraph with certificate auth. Either way: app-only.
    param([Parameter(Mandatory)][string]$TenantId)
    $appId = $global:HighPriv_Modern_ApplicationID_Azure
    $thumb = $global:HighPriv_Modern_CertificateThumbprint_Azure

    try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch { }

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
}

function Connect-PimManagerAz {
    param([Parameter(Mandatory)][string]$TenantId)
    $appId = $global:HighPriv_Modern_ApplicationID_Azure
    $thumb = $global:HighPriv_Modern_CertificateThumbprint_Azure

    # Reuse an existing matching context if present (engines may already be connected).
    try {
        $ctx = Get-AzContext -ErrorAction SilentlyContinue
        if ($ctx -and $ctx.Tenant.Id -eq $TenantId -and $ctx.Account.Id -eq $appId) { return }
    } catch { }

    Import-Module Az.Accounts -Force -WarningAction SilentlyContinue
    Connect-AzAccount `
        -ServicePrincipal `
        -ApplicationId $appId `
        -CertificateThumbprint $thumb `
        -TenantId $TenantId `
        -ErrorAction Stop | Out-Null
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
    $rows = Invoke-PimGraphGetAll -Uri 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions?$select=id,displayName,description,isBuiltIn'
    $items = foreach ($r in $rows) {
        [ordered]@{
            id          = "$($r.id)"
            displayName = "$($r.displayName)"
            description = "$($r.description)"
            isBuiltIn   = [bool]$r.isBuiltIn
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
