#Requires -Version 5.1
<#
.SYNOPSIS
    Local-plane engine apply (LIFECYCLE-GOVERNANCE § 19): read the customer's
    OWN local store (Owner=Local admins) and provision those accounts INTO the
    customer tenant, with the tenant's own credential. The real local engine
    run -- not a simulation.

.DESCRIPTION
    Runs for ONE tenant, using that tenant's per-tenant engine SPN (cert auth):
      1. Read pim.LocalAdmins from the tenant's local SQL store. SQL access
         runs in a CHILD powershell.exe (the SqlServer module's bundled
         Azure.Core breaks Connect-MgGraph app-only if loaded in-process --
         same isolation Invoke-PimMspFanout uses).
      2. Connect-MgGraph app-only with the engine SPN + certificate.
      3. Resolve the tenant default domain -> per-tenant UPNs.
      4. Build an Account-Definitions CSV from the local rows and run the real
         engine (CreateUpdate-Accounts-From-file-CSV -OnlyID).

    Local IT is autonomous: every Owner=Local row provisions, any Purpose
    (incl. HighPriv) -- no MSP request. The MSP baseline is a separate apply
    (the fan-out / pulled bundle); this script is the LOCAL half.

.PARAMETER WhatIfMode
    Default ON: connect + plan only. -WhatIfMode:$false provisions for real.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$TenantId,
    [Parameter(Mandatory)][string]$AppId,
    [string]$CertificateThumbprint = '50F3106D437C87374CACB28D47E8DEADB9BC0FE1',
    [string]$LocalSqlServer,
    [string]$LocalSqlDatabase = 'PimLocal',
    [switch]$WhatIfMode = $true
)

$ErrorActionPreference = 'Stop'

# Read the local SQL store in a CHILD process (Azure.Core isolation), as the
# tenant SPN (Entra-only DB auth).
function Get-PimLocalAdmins {
    param([string]$Server, [string]$Database, [string]$Tid, [string]$App, [string]$Thumb)
    $child = @"
`$ErrorActionPreference='Stop'
Connect-AzAccount -ServicePrincipal -ApplicationId '$App' -CertificateThumbprint '$Thumb' -Tenant '$Tid' -ErrorAction Stop | Out-Null
if (-not '$Server') { `$srv = (Get-AzSqlServer -ResourceGroupName 'rg-pim-local' | Select-Object -First 1).ServerName + '.database.windows.net' } else { `$srv = '$Server' }
Import-Module SqlServer
`$tok = (Get-AzAccessToken -ResourceUrl 'https://database.windows.net/').Token
if (`$tok -is [securestring]) { `$tok = [System.Net.NetworkCredential]::new('', `$tok).Password }
`$rows = Invoke-Sqlcmd -ServerInstance `$srv -Database '$Database' -AccessToken `$tok -Encrypt Mandatory -Query 'SELECT UserName,DisplayName,FirstName,LastName,Initials,UsageLocation,Purpose FROM pim.LocalAdmins WHERE Enabled=1 ORDER BY UserName'
@{ server = `$srv; rows = @(`$rows | Select-Object UserName,DisplayName,FirstName,LastName,Initials,UsageLocation,Purpose) } | ConvertTo-Json -Depth 5 -Compress
"@
    $tmp = Join-Path $env:TEMP ("pim-localsql-" + [guid]::NewGuid().ToString('N') + '.ps1')
    Set-Content -Path $tmp -Value $child -Encoding UTF8
    try {
        $out = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $tmp 2>&1
        if ($LASTEXITCODE -ne 0) { throw "local-store read child failed: $($out -join "`n")" }
        $json = ($out | Where-Object { "$_".TrimStart().StartsWith('{') } | Select-Object -Last 1)
        if (-not $json) { throw "local-store read returned no JSON: $($out -join "`n")" }
        $json | ConvertFrom-Json
    } finally { Remove-Item $tmp -Force -ErrorAction SilentlyContinue }
}

Write-Host ""
Write-Host "==========================================================================" -ForegroundColor Cyan
Write-Host " PIM4EntraPS LOCAL apply $(if ($WhatIfMode) { '(WHATIF -- plan only)' } else { '(LIVE)' })" -ForegroundColor Cyan
Write-Host "==========================================================================" -ForegroundColor Cyan
Write-Host "  tenant: $TenantId   app: $AppId"

$store = Get-PimLocalAdmins -Server $LocalSqlServer -Database $LocalSqlDatabase -Tid $TenantId -App $AppId -Thumb $CertificateThumbprint
$rows = @($store.rows)
Write-Host "  local store: $($store.server) / $LocalSqlDatabase  ($($rows.Count) Owner=Local admin(s))"
if ($rows.Count -eq 0) { Write-Host "  nothing to apply."; return }

Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
Connect-MgGraph -ClientId $AppId -TenantId $TenantId -CertificateThumbprint $CertificateThumbprint -NoWelcome -ErrorAction Stop
$domain = (Get-MgDomain -All | Where-Object { $_.IsDefault }).Id
Write-Host "  default domain: $domain"

$csvRows = foreach ($a in $rows) {
    [pscustomobject]@{
        FirstName='' + $a.FirstName; LastName='' + $a.LastName; Initials='' + $a.Initials
        Purpose='' + $a.Purpose; TargetUsage='Cloud'; TargetPlatform='ID'; UserType='Member'
        UserName='' + $a.UserName; DisplayName='' + $a.DisplayName
        UserPrincipalName=('' + $a.UserName) + '@' + $domain; UsageLocation='' + $a.UsageLocation
        ForwardMailsToContact='FALSE'; MailForwardAddress=''; Company=''; Notes='local-plane apply (Owner=Local)'
        ManagerEmail=''; StartDate=''; ProvisionDate=''; CreateTAP='FALSE'; TAPStartDate=''; TAPLifetimeHours=''
        AccountStatus='Enabled'; StatusChangeCode=''; Ring='2'; Template=''; OffboardDate=''; DeleteAfterDays=''
    }
}
foreach ($r in $csvRows) { Write-Host ("  plan: {0,-22} {1,-9} -> {2}" -f $r.UserName, $r.Purpose, $r.UserPrincipalName) -ForegroundColor $(if ($WhatIfMode){'Yellow'}else{'Gray'}) }

if ($WhatIfMode) { Write-Host "`n  (WhatIf) no changes made." -ForegroundColor Yellow; return }

$tmpCsv = Join-Path $env:TEMP ("pim-localapply-$TenantId.csv")
$csvRows | Export-Csv -Path $tmpCsv -Delimiter ';' -Encoding UTF8 -NoTypeInformation
try {
    if (-not (Get-Command CreateUpdate-Accounts-From-file-CSV -ErrorAction SilentlyContinue)) {
        Import-Module (Join-Path (Split-Path -Parent $PSScriptRoot) 'engine\_shared\PIM-Functions.psm1') -Force -DisableNameChecking
    }
    $global:PIM_TenantRing = 2
    $global:DefaultDomainUPN = $domain
    $global:WhatIfMode = $false
    CreateUpdate-Accounts-From-file-CSV -AccountsDefinitionFile $tmpCsv -OnlyID
    if (Get-Command Write-PimAuditEvent -ErrorAction SilentlyContinue) {
        Write-PimAuditEvent -Action 'local.apply' -Target $TenantId -After @{ admins = @($csvRows | ForEach-Object { $_.UserPrincipalName }) }
    }
    Write-Host "`n  LIVE local apply done ($($csvRows.Count) account(s))." -ForegroundColor Green
} finally {
    Remove-Item $tmpCsv -Force -ErrorAction SilentlyContinue
    $global:DefaultDomainUPN = $null
}
