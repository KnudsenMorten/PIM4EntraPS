#requires -Version 5.1
<#
.SYNOPSIS
    PIM4EntraPS Manager -- EMERGENCY / break-glass edition (runs on a client PC).

.DESCRIPTION
    Failover for when the hosted Manager (native Azure App Service) is
    unreachable -- outage, network/GSA disruption, Easy Auth/identity problem,
    or a Sev-1 where the operator must drive PIM from their own workstation.

    Runs the SAME Open-PimManager.ps1 in LOCAL loopback mode (127.0.0.1, no
    public surface) and talks to the SAME Azure SQL database the hosted app
    uses -- so there is ONE source of truth, never a divergent local copy.
    No CSV fallback.

    Auth is INTERACTIVE: the operator signs in as THEMSELVES (PKCE loopback,
    pure REST -- no MSAL / Graph / Az modules). The SQL action is therefore
    audited under the human identity, not a shared app/MI. The operator must be
    a contained DB user (directly or via an Entra group) on the database.

    Network reach to the private SQL endpoint:
      * On the corporate network  -> private DNS resolves the privatelink FQDN.
      * Cloud-only / non-AD PC     -> Entra Private Access (GSA) tunnels it; the
                                      GSA private network must publish
                                      <server>.database.windows.net:1433.

.PARAMETER SqlServer
    Azure SQL logical server FQDN. Taken from $env:PIM_SqlServer when not passed.
    REQUIRED -- there is no built-in default (SEC-05): this is break-glass against
    live data, so the script refuses to start rather than guess a server.

.PARAMETER SqlDatabase
    Database name. Defaults to $env:PIM_SqlDatabase or 'PimPlatform'.

.PARAMETER TenantId
    Entra tenant for the interactive sign-in. Defaults to the internal tenant.

.EXAMPLE
    .\Start-PimEmergency.ps1
    Sign in interactively, open the loopback Manager against the live SQL DB.

.NOTES
    This is the sanctioned failover that lets us run the hosted edition
    SQL-only / MI-only with confidence: if the platform is down, this brings
    the console back on any workstation in minutes, against the same data.
#>
[CmdletBinding()]
param(
    # SEC-05: NO built-in server default. This shipped with the author's own platform
    # server baked in, which both leaked a real infra name into published source and
    # meant a customer running the break-glass console pointed at someone else's
    # database unless they happened to override it. Supply it, or set PIM_SqlServer.
    [string]$SqlServer  = "$env:PIM_SqlServer",
    [string]$SqlDatabase = $(if ($env:PIM_SqlDatabase) { $env:PIM_SqlDatabase } else { 'PimPlatform' }),
    [string]$TenantId   = $(if ($env:PIM_TenantId)    { $env:PIM_TenantId }    else { 'organizations' }),
    [int]$Port = 0
)

$ErrorActionPreference = 'Stop'
$here = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }

Write-Host ''
Write-Host '  ====================================================================' -ForegroundColor Red
Write-Host '   PIM4EntraPS -- EMERGENCY / BREAK-GLASS console (loopback, client PC)' -ForegroundColor Red
Write-Host '  ====================================================================' -ForegroundColor Red
Write-Host ''
if (-not "$SqlServer".Trim()) {
    Write-Host ''
    Write-Host '   NO SQL SERVER SPECIFIED.' -ForegroundColor Red
    Write-Host '   This is break-glass against LIVE data, so there is deliberately no' -ForegroundColor Red
    Write-Host '   built-in default -- pointing at the wrong database in an emergency is' -ForegroundColor Red
    Write-Host '   worse than not starting. Supply your own platform server:' -ForegroundColor Red
    Write-Host ''
    Write-Host '     .\Start-PimEmergency.ps1 -SqlServer <your-server>.database.windows.net' -ForegroundColor Yellow
    Write-Host '     (or set $env:PIM_SqlServer)' -ForegroundColor Yellow
    Write-Host ''
    exit 2
}
Write-Host "   SQL   : $SqlServer / $SqlDatabase" -ForegroundColor Yellow
Write-Host  '   Auth  : INTERACTIVE -- you sign in as yourself (action audited under you).' -ForegroundColor Yellow
Write-Host  '   Data  : live Azure SQL (same DB as the hosted app; no local copy, no CSV).' -ForegroundColor Yellow
Write-Host ''

# Point the Manager at the live database, force interactive SQL auth, and force
# SQL-only mode. These globals are read by the storage block + PIM-SqlStore.
$global:PIM_SqlServer     = $SqlServer
$global:PIM_SqlDatabase   = $SqlDatabase
$global:PIM_TenantId      = $TenantId
$global:PIM_Interactive   = $true          # PKCE loopback sign-in for any resource
$global:PIM_SqlInteractive = $true         # SQL token via the human, not MI/SPN
$global:PIM_SqlAccessToken = $null         # never reuse a stale token

# Preflight: prove we can reach SQL + mint a token BEFORE opening the browser UI,
# so a network/permission problem surfaces as a clear console error.
$sqlLib = Join-Path (Split-Path -Parent (Split-Path -Parent $here)) 'engine\_shared\PIM-SqlStore.ps1'
$restLib = Join-Path (Split-Path -Parent (Split-Path -Parent $here)) 'engine\_shared\PIM-Rest.ps1'
if (Test-Path $restLib) { . $restLib }
if (Test-Path $sqlLib)  { . $sqlLib }
if (Get-Command Get-PimSqlConnectionString -ErrorAction SilentlyContinue) {
    Write-Host '   [preflight] acquiring SQL access token + testing connection ...' -ForegroundColor Cyan
    $cs = Get-PimSqlConnectionString
    $tc = New-PimSqlConnection -ConnectionString $cs
    $tc.Open(); $tc.Close()
    Write-Host '   [preflight] SQL reachable + authenticated OK' -ForegroundColor Green
    Write-Host ''
}

# Launch the loopback Manager (NOT -Hosted: emergency runs on 127.0.0.1 only).
& (Join-Path $here 'Open-PimManager.ps1') -DesiredPort $Port
