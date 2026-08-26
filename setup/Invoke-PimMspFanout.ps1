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

      1. Authenticate per-tenant app-only over PURE REST (per-tenant AppId +
         the per-tenant certificate from Cert:\LocalMachine\My) -- no
         Microsoft.Graph module, no Connect-MgGraph. Auth + the default-domain
         lookup run through PIM-Rest (Invoke-PimGraph). PS 5.1-safe.
      2. Resolve the tenant's default domain -> $global:DefaultDomainUPN
         (each central admin gets a tenant-local UPN: <UserName>@<domain>).
      3. Build a temp Account-Definitions CSV from pim.CentralAdmins, ring-
         filtered by pim.vw_AdminTenantTargets (admin.Ring <= tenant.Ring).
      4. -WhatIfMode (default ON): print the plan only.
         Live: provision the ID accounts over PURE REST
         (Invoke-PimRestAccountApply -> New-PimRestAdminAccount, Graph
         /users create+update). Set $global:PIM_UseGraphSdk = $true to fall
         back to the legacy Graph-SDK engine path
         (CreateUpdate-Accounts-From-file-CSV -OnlyID) instead.

    The whole fan-out path -- auth, directory reads AND the live account
    write -- is now pure REST (no Microsoft.Graph module). REQUIREMENTS.md §19
    write-path migration item closed for this launcher.

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

# Pure-REST auth + directory reads + account write (no Microsoft.Graph module).
# PIM-Rest gives us Get-PimRestToken / Invoke-PimGraph against a per-tenant SPN +
# certificate; PIM-AccountRest gives us the REST account create/update writer.
$shared = Join-Path (Split-Path -Parent $PSScriptRoot) 'engine\_shared'
. (Join-Path $shared 'PIM-Rest.ps1')
. (Join-Path $shared 'PIM-AccountRest.ps1')

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

# MSP fan-out is a Pro feature (offline .pimlicense in config\; Core is free).
. (Join-Path (Split-Path -Parent $PSScriptRoot) 'engine\_shared\PIM-License.ps1')
Write-Host "  license : $(Get-PimLicenseStatusText)"
if (-not (Test-PimProFeature 'MspFanout')) { return }

# The TAP columns (operator decision 2026-08-13, see platform-schema.sql) are selected with the
# same defensive fallback the bundle producer uses: a registry that predates them still fans out,
# and the row build below then applies the default (TAP ON) rather than the old hardcoded FALSE.
$fanoutSelect = @"
SELECT v.TenantId, v.TenantName, v.TenantRing, v.UserName, v.AdminRing,
       a.AppId, a.CertificateThumbprint,
       c.DisplayName, c.FirstName, c.LastName, c.Initials, c.Purpose, c.UsageLocation, c.Ring,
       c.Template{0}
FROM pim.vw_AdminTenantTargets v
JOIN platform.TenantApps a ON a.TenantId = v.TenantId AND a.Product = 'PIM'
JOIN pim.CentralAdmins c   ON c.UserName = v.UserName
ORDER BY v.TenantRing, v.TenantName, v.AdminRing
"@
$targets = $null
try { $targets = Get-PimRegistryRows -Query ($fanoutSelect -f ', c.CreateTap, c.TapLifetimeHours, c.ManagerEmail') }
catch {
    Write-Host "  (no CreateTap/TapLifetimeHours/ManagerEmail in pim.CentralAdmins -- applying the fan-out defaults)" -ForegroundColor DarkGray
    $targets = Get-PimRegistryRows -Query ($fanoutSelect -f '')
}
if (-not $targets) { Write-Host "  nothing to deploy (no tenants with PIM apps + admins in ring reach)." -ForegroundColor Yellow; return }

$byTenant = $targets | Group-Object TenantId
$results = @()

# BUG-23: this loop REPOINTS the ambient identity ($global:PIM_TenantId / _ClientId /
# _CertThumbprint) at each customer tenant in turn, and used to leave it wherever the last
# iteration landed. Anything the caller did afterwards in the same process therefore ran
# against THE LAST TENANT THE FANOUT HAPPENED TO TOUCH, not the tenant it meant.
# Observed live 2026-08-06: in the TEST-12 S6 scenario the downlink fanned out (local slave,
# then central slave) and the engine apply that followed authenticated as the CENTRAL
# tenant's SPN and reconciled that tenant's estate -- for a run whose target was the local
# slave. Read-shaped there; a write-shaped one is a cross-tenant write.
# The identity is captured here and restored in the finally below, so the fanout is
# transparent to its caller. (Cf. BUG-22: the token cache is now keyed by identity, so a
# restored ambient context also gets the RIGHT token again.)
$__prevTenantId   = $global:PIM_TenantId
$__prevClientId   = $global:PIM_ClientId
$__prevThumbprint = $global:PIM_CertThumbprint
$__prevUseMi      = $global:PIM_UseManagedIdentity
$__prevInteractive= $global:PIM_Interactive

try {

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

    # Tenant-bound licensing: a tenant outside the license's tenantIds is
    # skipped, not failed -- the rest of the fleet still deploys.
    if (-not (Test-PimProFeature 'MspFanout' -TenantId "$($t.TenantId)")) {
        $results += [pscustomobject]@{ Tenant = $t.TenantName; Status = 'skipped (not licensed)'; Admins = 0 }
        continue
    }

    # Pure-REST app-only auth: point PIM-Rest at THIS tenant's SPN + cert and
    # force a fresh token (the resource cache is keyed by audience only, so it
    # must be cleared between tenants). No Connect-MgGraph / Microsoft.Graph.
    try {
        $global:PIM_UseGraphSdk      = $false
        $global:PIM_TenantId         = "$($t.TenantId)"
        $global:PIM_ClientId         = "$($t.AppId)"
        $global:PIM_CertThumbprint   = "$($t.CertificateThumbprint)"
        $global:PIM_UseManagedIdentity = $false
        $global:PIM_Interactive        = $false
        # mint (and prove) the token for this tenant before doing any read
        $null = Get-PimRestToken -Resource graph -TenantId "$($t.TenantId)" -ClientId "$($t.AppId)" -CertThumbprint "$($t.CertificateThumbprint)" -Force
        Write-Host "  authenticated app-only over REST (clientId $($t.AppId))" -ForegroundColor Green
    } catch {
        Write-Host "  [fail] app-only REST auth failed: $($_.Exception.Message)" -ForegroundColor Red
        $results += [pscustomobject]@{ Tenant = $t.TenantName; Status = 'connect-failed'; Admins = 0 }
        continue
    }

    $defaultDomain = $null
    try {
        $defaultDomain = Get-PimRestDefaultDomain
    } catch { Write-Host "  [warn] default-domain lookup failed: $($_.Exception.Message)" -ForegroundColor Yellow }
    if (-not $defaultDomain) {
        Write-Host "  [fail] cannot resolve the tenant default domain -- skipping tenant." -ForegroundColor Red
        $results += [pscustomobject]@{ Tenant = $t.TenantName; Status = 'no-default-domain'; Admins = 0 }
        continue
    }
    Write-Host "  default domain: $defaultDomain (admin UPNs become <UserName>@$defaultDomain)"

    # Build the per-tenant Account-Definitions CSV from the registry rows.
    $rows = foreach ($a in $grp.Group) {
        # TAP intent -- ON unless the registry says otherwise (operator decision 2026-08-13).
        # Kept byte-for-byte equivalent to the S6 downlink's resolution so the two topologies
        # cannot drift: a customer must not get a different admin depending on how we reached it.
        $tapRaw = "$($a.CreateTap)".Trim()
        $createTap = if ($tapRaw) { if ($tapRaw -match '(?i)^(true|1|yes)$') { 'TRUE' } else { 'FALSE' } } else { 'TRUE' }
        $life = 0; [void][int]::TryParse("$($a.TapLifetimeHours)".Trim(), [ref]$life)
        if ($life -le 0) { $life = 8 }
        $mgr = "$($a.ManagerEmail)".Trim()
        if ($createTap -eq 'TRUE' -and -not $mgr) {
            Write-Host "  [warn] $($a.UserName): CreateTAP is ON but the registry carries no ManagerEmail -- the TAP will be minted and delivered NOWHERE (the code is readable only at creation)." -ForegroundColor Yellow
        }
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
            ManagerEmail          = $mgr
            StartDate             = ''
            ProvisionDate         = ''
            CreateTAP             = $createTap
            TAPStartDate          = ''
            TAPLifetimeHours      = "$life"
            AccountStatus         = 'Enabled'
            StatusChangeCode      = ''
            Ring                  = "$($a.AdminRing)"
            # MSP-2: this used to be hardcoded ''. The baseline bundle goes to the trouble of
            # carrying + SIGNING Template (New-PimBaselineBundle selects it, the downlink stages
            # it), and the fan-out then threw it away on arrival -- so the value could never
            # reach the slave no matter what the master published.
            Template              = "$($a.Template)"
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

    # LIVE: provision the ID accounts. Default = pure REST writer
    # (New-PimRestAdminAccount over Invoke-PimGraph). Opt INTO the legacy
    # Graph-SDK engine (CreateUpdate-Accounts-From-file-CSV) only when the
    # caller sets $global:PIM_UseGraphSdk = $true (e.g. to use the EXO
    # Set-Mailbox forwarding path or the AD/hybrid branch).
    try {
        if ($global:PIM_UseGraphSdk) {
            Write-Host "  [legacy] PIM_UseGraphSdk=$true -- using the Graph-SDK engine path." -ForegroundColor DarkYellow
            $tmpCsv = Join-Path $env:TEMP ("pim-fanout-{0}.csv" -f $t.TenantId)
            $rows | Export-Csv -Path $tmpCsv -Delimiter ';' -Encoding UTF8 -NoTypeInformation
            try {
                if (-not (Get-Command CreateUpdate-Accounts-From-file-CSV -ErrorAction SilentlyContinue)) {
                    Import-Module (Join-Path $shared 'PIM-Functions.psm1') -Force -DisableNameChecking
                }
                $global:PIM_TenantRing   = [int]$t.TenantRing
                $global:DefaultDomainUPN = $defaultDomain
                $global:WhatIfMode       = $false
                CreateUpdate-Accounts-From-file-CSV -AccountsDefinitionFile $tmpCsv -OnlyID
            } finally {
                Remove-Item $tmpCsv -Force -ErrorAction SilentlyContinue
                $global:DefaultDomainUPN = $null
            }
        } else {
            # pure REST: the UPNs are already resolved on each row above.
            $applied = @(Invoke-PimRestAccountApply -Rows $rows)
            $bad = @($applied | Where-Object { "$($_.Action)" -like 'failed:*' })
            if ($bad.Count) { throw ("{0} of {1} account(s) failed: {2}" -f $bad.Count, $applied.Count, (($bad | ForEach-Object { "$($_.Upn) ($($_.Action))" }) -join '; ')) }
        }
        $results += [pscustomobject]@{ Tenant = $t.TenantName; Status = 'applied'; Admins = @($rows).Count }
        if (Get-Command Write-PimAuditEvent -ErrorAction SilentlyContinue) {
            Write-PimAuditEvent -Action 'msp.fanout.apply' -Target $t.TenantName -After @{ tenantId = "$($t.TenantId)"; admins = @($rows | ForEach-Object { $_.UserPrincipalName }) }
        }
    } catch {
        Write-Host "  [fail] account provisioning failed: $($_.Exception.Message)" -ForegroundColor Red
        $results += [pscustomobject]@{ Tenant = $t.TenantName; Status = "failed: $($_.Exception.Message)"; Admins = 0 }
    }
}

}
finally {
    # BUG-23: hand the caller's ambient identity back exactly as we found it, on every
    # exit path including a throw. Restoring only on success would leave a failed fanout
    # pointing at a customer tenant, which is the worse half of the bug.
    $global:PIM_TenantId           = $__prevTenantId
    $global:PIM_ClientId           = $__prevClientId
    $global:PIM_CertThumbprint     = $__prevThumbprint
    $global:PIM_UseManagedIdentity = $__prevUseMi
    $global:PIM_Interactive        = $__prevInteractive
}

Write-Host ""
Write-Host "==========================================================================" -ForegroundColor Cyan
Write-Host " Fan-out summary" -ForegroundColor Cyan
Write-Host "==========================================================================" -ForegroundColor Cyan
$results | Format-Table -AutoSize
$results
