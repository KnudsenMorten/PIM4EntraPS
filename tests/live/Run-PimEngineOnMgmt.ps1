<#
.SYNOPSIS
  Fast MGMT1 harness for the NEW REST+SQL engine — load it exactly as the scheduler
  does, point it at the live PimPlatform SQL DB, and run scopes WhatIf/live without a
  container rebuild. Tokens come from the ambient `az login` session (Get-PimRestToken
  falls back to `az account get-access-token` for graph / database / arm).

.DESCRIPTION
  This is the inner-loop dev/test rig the user asked for ("start the pim coreengine on
  mgmt1 and fix — that is faster"). It is NOT a product entrypoint; the product
  entrypoint is Start-PimScheduler.ps1 (which loads the identical module chain).

.EXAMPLE
  .\Run-PimEngineOnMgmt.ps1 -Inspect                 # dump live SQL row shapes
  .\Run-PimEngineOnMgmt.ps1 -Scope Groups -WhatIf    # plan one scope, no writes
  .\Run-PimEngineOnMgmt.ps1 -Scope All -WhatIf
  .\Run-PimEngineOnMgmt.ps1 -Scope Groups            # LIVE apply (real test)
#>
[CmdletBinding()]
param(
    [string]$Scope = 'All',
    [ValidateSet('Full','Delta')][string]$Mode = 'Delta',
    [switch]$WhatIf,
    [switch]$Inspect,
    [string[]]$InspectEntities = @('Account-Definitions-Admins','PIM-Assignments-Admins','Groups','PIM-Definitions-Roles','PIM-Assignments-Roles-Groups','Azure-Resources','Definitions-AU','Roles-AUs','Definitions-Services','Definitions-Tasks'),
    # All environment-specific values come from env / params -- never hardcoded here.
    [string]$SqlServer   = $env:PIM_SqlServer,
    [string]$SqlDatabase = $env:PIM_SqlDatabase,
    # MGMT1 dev identity (an AAD principal that is a DB user). Product uses MI; this is
    # only the dev box. Pass the secret at call time (never stored here).
    [string]$ClientId    = $env:PIM_ClientId,
    [string]$ClientSecret= $env:PIM_ClientSecret,
    [string]$CertThumbprint = $env:PIM_CertThumbprint,
    [string]$TenantId    = $env:PIM_TenantId
)
$ErrorActionPreference = 'Stop'
$here   = Split-Path -Parent $MyInvocation.MyCommand.Path
$shared = Resolve-Path "$here\..\..\engine\_shared"
if (-not $SqlServer)   { throw "Set -SqlServer or `$env:PIM_SqlServer (the Azure SQL FQDN)." }
if (-not $SqlDatabase) { throw "Set -SqlDatabase or `$env:PIM_SqlDatabase." }

$global:PIM_UseGraphSdk = $false
$global:PIM_SqlServer   = $SqlServer
$global:PIM_SqlDatabase = $SqlDatabase
if ($ClientId)       { $global:PIM_ClientId = $ClientId }
if ($ClientSecret)   { $global:PIM_ClientSecret = $ClientSecret }
if ($CertThumbprint) { $global:PIM_CertThumbprint = $CertThumbprint }
if ($TenantId)       { $global:PIM_TenantId = $TenantId }

. "$shared\PIM-Rest.ps1"
. "$shared\PIM-SqlStore.ps1"
. "$shared\PIM-ChangeQueue.ps1"
. "$shared\PIM-ContextBuilder.ps1"
. "$shared\PIM-EngineCore.ps1"
. "$shared\PIM-EngineProviders.ps1"
# Build-PimContext requires $global:PIM_Filters (include/exclude candidate filters).
$config = Resolve-Path "$here\..\..\config"
. "$config\PIM4EntraPS.Filters.locked.ps1"
Register-PimDefaultEngineProviders

# engine reads DESIRED from this CS (used by Get-PimDesiredRows)
$global:PIM_EngineSqlCs = Get-PimSqlConnectionString
Write-Host "SQL: $SqlServer / $SqlDatabase" -ForegroundColor Cyan
Write-Host "Scopes registered: $((Get-PimEngineScopes) -join ', ')" -ForegroundColor Cyan

if ($Inspect) {
    foreach ($e in $InspectEntities) {
        $rows = @(Get-PimSqlRows -ConnectionString $global:PIM_EngineSqlCs -Entity $e)
        Write-Host ("`n== {0}  ({1} rows) ==" -f $e, $rows.Count) -ForegroundColor Yellow
        if ($rows.Count) {
            $cols = @($rows[0].PSObject.Properties.Name)
            Write-Host ("   columns: " + ($cols -join ', '))
            Write-Host  "   sample : "
            $rows[0].PSObject.Properties | ForEach-Object { Write-Host ("      {0,-28}= {1}" -f $_.Name, $_.Value) }
        }
    }
    return
}

$res = Invoke-PimEngine -Scope $Scope -Mode $Mode -WhatIf:$WhatIf
foreach ($r in @($res)) {
    Write-Host ("[{0}] create={1} update={2} remove={3} nochange={4} applied={5} errors={6} ok={7}" -f `
        $r.scope, $r.create, $r.update, $r.remove, $r.nochange, $r.applied, $r.errors, $r.ok) -ForegroundColor $(if ($r.ok) {'Green'} else {'Red'})
    if ($r.plan) { $r.plan | Select-Object -First 8 | ForEach-Object { Write-Host ("    {0,-7} {1}" -f $_.op, $_.key) } }
}
