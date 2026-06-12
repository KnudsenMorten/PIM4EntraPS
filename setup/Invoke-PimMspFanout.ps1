#Requires -Version 5.1
<#
.SYNOPSIS
    MSP fan-out: deploy central IT admin accounts from the platform registry
    (SQL) to every registered tenant their ring reaches.

.DESCRIPTION
    Phase 12a (docs/LIFECYCLE-GOVERNANCE.md § 16) -- the first registry-driven
    multi-tenant pass. For each tenant in platform.Tenants that has a PIM app
    in platform.TenantApps AND whose certificate is present in the local
    machine store (fictional demo tenants drop out of scope automatically):

      1. Connect-MgGraph app-only (per-tenant AppId + the shared mgmt-host
         certificate from Cert:\LocalMachine\My).
      2. Resolve the tenant's default domain -> $global:DefaultDomainUPN
         (each central admin gets a tenant-local UPN: <UserName>@<domain>).
      3. Build a temp Account-Definitions CSV from pim.CentralAdmins, ring-
         filtered by pim.vw_AdminTenantTargets (admin.Ring <= tenant.Ring).
      4. -WhatIfMode (default ON): print the plan only.
         Live: run the engine's CreateUpdate-Accounts-From-file-CSV -OnlyID.

    Ring semantics match the engine: a ring-0 admin reaches every tenant; a
    ring-2 consultant only reaches ring-2 (test) tenants.

.PARAMETER ServerInstance
    SQL instance holding the platform registry. Default: localhost\SQLEXPRESS.

.PARAMETER Database
    Default: PimPlatform.

.PARAMETER UseAzureSql
    Connect to Azure SQL with an Entra access token from the current Az
    context instead of Windows auth. -ServerInstance must then be the
    full FQDN (xxx.database.windows.net).

.PARAMETER WhatIfMode
    Default ON: connect + plan, change nothing. -WhatIfMode:$false applies.

.EXAMPLE
    .\Invoke-PimMspFanout.ps1                       # plan, local registry
    .\Invoke-PimMspFanout.ps1 -WhatIfMode:$false    # apply
#>
[CmdletBinding()]
param(
    [string]$ServerInstance = 'localhost\SQLEXPRESS',
    [string]$Database = 'PimPlatform',
    [switch]$UseAzureSql,
    [switch]$WhatIfMode = $true
)

$ErrorActionPreference = 'Stop'

# CRITICAL process-hygiene rule: the SqlServer module (and Az.Accounts) bundle
# an OLDER Azure.Core than the Microsoft Graph SDK -- loading them into the
# same process before Connect-MgGraph breaks app-only auth with
# "Method not found: Azure.Core.TokenRequestContext..ctor". All SQL access
# therefore runs in a CHILD process; this process only ever loads Graph (+ the
# engine module, after Graph, in live mode).
function Get-PimRegistryRows {
    param([Parameter(Mandatory)][string]$Query)
    $child = @"
`$ErrorActionPreference = 'Stop'
Import-Module SqlServer
`$sqlArgs = @{ ServerInstance = '$ServerInstance'; Database = '$Database' }
if ('$UseAzureSql' -eq 'True') {
    `$tok = (Get-AzAccessToken -ResourceUrl 'https://database.windows.net/').Token
    if (`$tok -is [securestring]) { `$tok = [System.Net.NetworkCredential]::new('', `$tok).Password }
    `$sqlArgs['AccessToken'] = `$tok
} else {
    `$sqlArgs['TrustServerCertificate'] = `$true
}
`$rows = Invoke-Sqlcmd @sqlArgs -Query @'
$Query
'@
`$rows | Select-Object * -ExcludeProperty ItemArray, Table, RowError, RowState, HasErrors | ConvertTo-Json -Depth 4 -Compress
"@
    $tmp = Join-Path $env:TEMP ("pim-sqlchild-" + [guid]::NewGuid().ToString('N') + '.ps1')
    Set-Content -Path $tmp -Value $child -Encoding UTF8
    try {
        $out = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $tmp 2>&1
        if ($LASTEXITCODE -ne 0) { throw "registry query child process failed: $($out -join "`n")" }
        $json = ($out | Where-Object { "$_".TrimStart().StartsWith('[') -or "$_".TrimStart().StartsWith('{') } | Select-Object -Last 1)
        if (-not $json) { return @() }
        @($json | ConvertFrom-Json)
    } finally { Remove-Item $tmp -Force -ErrorAction SilentlyContinue }
}

Write-Host ""
Write-Host "==========================================================================" -ForegroundColor Cyan
Write-Host " PIM4EntraPS MSP fan-out $(if ($WhatIfMode) { '(WHATIF -- plan only)' } else { '(LIVE)' })" -ForegroundColor Cyan
Write-Host "==========================================================================" -ForegroundColor Cyan
Write-Host "  registry: $ServerInstance / $Database"

$targets = Get-PimRegistryRows -Query @"
SELECT v.TenantId, v.TenantName, v.TenantRing, v.UserName, v.AdminRing,
       a.AppId, a.CertificateThumbprint,
       c.DisplayName, c.FirstName, c.LastName, c.Initials, c.Purpose, c.UsageLocation, c.Ring
FROM pim.vw_AdminTenantTargets v
JOIN platform.TenantApps a ON a.TenantId = v.TenantId AND a.Product = 'PIM'
JOIN pim.CentralAdmins c   ON c.UserName = v.UserName
ORDER BY v.TenantRing, v.TenantName, v.AdminRing
"@
if (-not $targets) { Write-Host "  nothing to deploy (no tenants with PIM apps + admins in ring reach)." -ForegroundColor Yellow; return }

$byTenant = $targets | Group-Object TenantId
$results = @()

foreach ($grp in $byTenant) {
    $t = $grp.Group[0]
    Write-Host ""
    Write-Host "--- Tenant: $($t.TenantName) (ring $($t.TenantRing), $($t.TenantId)) ---" -ForegroundColor Cyan

    # Fictional/demo tenants register fake thumbprints -- the cert check
    # scopes the run to tenants this host can actually authenticate to.
    $cert = Get-Item "Cert:\LocalMachine\My\$($t.CertificateThumbprint)" -ErrorAction SilentlyContinue
    if (-not $cert) {
        Write-Host "  [skip] certificate $($t.CertificateThumbprint) not in Cert:\LocalMachine\My (demo tenant or not enrolled on this host)." -ForegroundColor DarkGray
        continue
    }

    try {
        Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
        Connect-MgGraph -ClientId $t.AppId -TenantId $t.TenantId -CertificateThumbprint $t.CertificateThumbprint -NoWelcome -ErrorAction Stop
        $ctx = Get-MgContext
        Write-Host "  connected app-only as $($ctx.AppName) ($($ctx.ClientId))" -ForegroundColor Green
    } catch {
        Write-Host "  [fail] app-only connect failed: $($_.Exception.Message)" -ForegroundColor Red
        $results += [pscustomobject]@{ Tenant = $t.TenantName; Status = 'connect-failed'; Admins = 0 }
        continue
    }

    $defaultDomain = $null
    try {
        $defaultDomain = (Get-MgDomain -All -ErrorAction Stop | Where-Object { $_.IsDefault }).Id
    } catch { Write-Host "  [warn] default-domain lookup failed: $($_.Exception.Message)" -ForegroundColor Yellow }
    if (-not $defaultDomain) {
        Write-Host "  [fail] cannot resolve the tenant default domain -- skipping tenant." -ForegroundColor Red
        $results += [pscustomobject]@{ Tenant = $t.TenantName; Status = 'no-default-domain'; Admins = 0 }
        continue
    }
    Write-Host "  default domain: $defaultDomain (admin UPNs become <UserName>@$defaultDomain)"

    # Build the per-tenant Account-Definitions CSV from the registry rows.
    $rows = foreach ($a in $grp.Group) {
        [pscustomobject]@{
            FirstName             = "$($a.FirstName)"
            LastName              = "$($a.LastName)"
            Initials              = "$($a.Initials)"
            Purpose               = "$($a.Purpose)"
            TargetUsage           = 'Cloud'
            TargetPlatform        = 'ID'
            UserType              = 'External'
            UserName              = "$($a.UserName)"
            DisplayName           = "$($a.DisplayName)"
            UserPrincipalName     = "$($a.UserName)@$defaultDomain"
            UsageLocation         = "$($a.UsageLocation)"
            ForwardMailsToContact = 'FALSE'
            MailForwardAddress    = ''
            Company               = ''
            Notes                 = "MSP fan-out (central admin ring $($a.AdminRing) -> tenant ring $($t.TenantRing))"
            ManagerEmail          = ''
            StartDate             = ''
            ProvisionDate         = ''
            CreateTAP             = 'FALSE'
            TAPStartDate          = ''
            TAPLifetimeHours      = ''
            AccountStatus         = 'Enabled'
            StatusChangeCode      = ''
            Ring                  = "$($a.AdminRing)"
            Template              = ''
            OffboardDate          = ''
            DeleteAfterDays       = ''
        }
    }
    foreach ($r in $rows) {
        Write-Host ("  plan: {0,-22} ring {1} -> {2}" -f $r.UserName, $r.Ring, $r.UserPrincipalName) -ForegroundColor $(if ($WhatIfMode) { 'Yellow' } else { 'Gray' })
    }

    if ($WhatIfMode) {
        $results += [pscustomobject]@{ Tenant = $t.TenantName; Status = 'planned (whatif)'; Admins = @($rows).Count }
        continue
    }

    # LIVE: hand the rows to the engine's account function.
    $tmpCsv = Join-Path $env:TEMP ("pim-fanout-{0}.csv" -f $t.TenantId)
    $rows | Export-Csv -Path $tmpCsv -Delimiter ';' -Encoding UTF8 -NoTypeInformation
    try {
        if (-not (Get-Command CreateUpdate-Accounts-From-file-CSV -ErrorAction SilentlyContinue)) {
            Import-Module (Join-Path (Split-Path -Parent $PSScriptRoot) 'engine\_shared\PIM-Functions.psm1') -Force -DisableNameChecking
        }
        # ring gate inside the engine compares admin.Ring <= PIM_TenantRing
        $global:PIM_TenantRing   = [int]$t.TenantRing
        $global:DefaultDomainUPN = $defaultDomain
        $global:WhatIfMode       = $false
        CreateUpdate-Accounts-From-file-CSV -AccountsDefinitionFile $tmpCsv -OnlyID
        $results += [pscustomobject]@{ Tenant = $t.TenantName; Status = 'applied'; Admins = @($rows).Count }
        if (Get-Command Write-PimAuditEvent -ErrorAction SilentlyContinue) {
            Write-PimAuditEvent -Action 'msp.fanout.apply' -Target $t.TenantName -After @{ tenantId = "$($t.TenantId)"; admins = @($rows | ForEach-Object { $_.UserPrincipalName }) }
        }
    } catch {
        Write-Host "  [fail] engine pass failed: $($_.Exception.Message)" -ForegroundColor Red
        $results += [pscustomobject]@{ Tenant = $t.TenantName; Status = "failed: $($_.Exception.Message)"; Admins = 0 }
    } finally {
        Remove-Item $tmpCsv -Force -ErrorAction SilentlyContinue
        $global:DefaultDomainUPN = $null
    }
}

Write-Host ""
Write-Host "==========================================================================" -ForegroundColor Cyan
Write-Host " Fan-out summary" -ForegroundColor Cyan
Write-Host "==========================================================================" -ForegroundColor Cyan
$results | Format-Table -AutoSize
$results
