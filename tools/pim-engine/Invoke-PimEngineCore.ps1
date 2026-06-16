<#
.SYNOPSIS
  PIM4EntraPS engine entrypoint -- runs the NEW REST + SQL engine (PIM-EngineCore +
  providers). This IS the engine the scheduler, container worker and VM call; it is not
  a test harness. It reads DESIRED state from SQL, the LIVE tenant over Graph/ARM REST
  (no modules), diffs, and applies via the engine SPN (app-only, certificate auth).

.DESCRIPTION
  Identity + targets come from configuration (env vars / launcher globals / the
  AutomateIT framework), never hardcoded:
     PIM_ClientId           engine SPN appId            (or $global:PIM_ClientId)
     PIM_CertThumbprint     engine SPN cert thumbprint  (or $global:PIM_CertThumbprint)
     PIM_TenantId           tenant id                   (or $global:PIM_TenantId)
     PIM_SqlServer          Azure SQL FQDN              (or $global:PIM_SqlServer)
     PIM_SqlDatabase        database name               (or $global:PIM_SqlDatabase)
  When no client id is present and a managed identity is available (container / VM),
  authentication falls back to MI automatically.

  Modes (see PIM-EngineCore):
     -Mode Full              whole-scope reconcile (create/update + prune removals)
     -Mode Delta             create/update everything that differs (no prune)
     -Mode Delta -FromQueue  apply ONLY the pending commit-queue (entity,key) changes

.EXAMPLE
  .\Invoke-PimEngineCore.ps1 -Scope All -Mode Delta
.EXAMPLE
  .\Invoke-PimEngineCore.ps1 -Scope Groups -WhatIf          # plan only
.EXAMPLE
  .\Invoke-PimEngineCore.ps1 -Mode Delta -FromQueue          # commit-triggered run
#>
[CmdletBinding()]
param(
    [string]$Scope = 'All',
    [ValidateSet('Full','Delta')][string]$Mode = 'Delta',
    [switch]$WhatIf,
    [switch]$Prune,            # destructive prune of live-not-in-desired (Full only; opt-in)
    [switch]$FromQueue,
    [string]$LogDir
)
$ErrorActionPreference = 'Stop'
$here   = Split-Path -Parent $MyInvocation.MyCommand.Path
$shared = Resolve-Path "$here\..\..\engine\_shared"
$config = Resolve-Path "$here\..\..\config"

# --- log output to a timestamped file (engine run log) -------------------------
if (-not $LogDir) { $LogDir = if ($env:PIM_LogDir) { $env:PIM_LogDir } else { Join-Path $here '..\..\output\engine-logs' } }
try { if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null } } catch {}
$stamp = (Get-Date).ToString('yyyyMMdd-HHmmss')
$logFile = Join-Path $LogDir "pim-engine-$Scope-$Mode-$stamp.log"
try { Start-Transcript -Path $logFile -Force | Out-Null; $script:__transcript = $true } catch { $script:__transcript = $false }

# --- configuration (env -> existing globals; nothing hardcoded) ----------------
$global:PIM_UseGraphSdk = $false   # REST-only, no Graph/Az modules
function Use-Cfg($globalName, $envName) {
    $cur = Get-Variable -Name $globalName -Scope Global -ValueOnly -ErrorAction SilentlyContinue
    if (-not $cur -and (Test-Path "Env:\$envName")) { Set-Variable -Name $globalName -Scope Global -Value (Get-Item "Env:\$envName").Value }
}
Use-Cfg 'PIM_ClientId'       'PIM_ClientId'
Use-Cfg 'PIM_CertThumbprint' 'PIM_CertThumbprint'
Use-Cfg 'PIM_TenantId'       'PIM_TenantId'
Use-Cfg 'PIM_SqlServer'      'PIM_SqlServer'
Use-Cfg 'PIM_SqlDatabase'    'PIM_SqlDatabase'
# DESIRED store: the engine reads pim.Rows from SQL. Two first-class stores are supported
# (Get-PimSqlConnectionString resolves either):
#   * Azure SQL  -- $global:PIM_SqlServer is an FQDN (...database.windows.net); auth = MI /
#                   SPN AccessToken. The HOSTED product path.
#   * Local SQL  -- $global:PIM_SqlServer is a local instance (e.g. .\SQLEXPRESS) reached
#                   with Integrated auth. The MGMT1 / on-prem / dev + emergency path: the
#                   running identity is itself a DB user, so there is no cross-tenant token
#                   or MI-not-a-DB-user blocker. This is the default when no server is set.
# Only the DATABASE NAME is mandatory; the server defaults to .\SQLEXPRESS (local store).
if (-not $global:PIM_SqlServer) {
    $global:PIM_SqlServer = if ($env:PIM_SqlServer) { $env:PIM_SqlServer } else { '.\SQLEXPRESS' }
    Write-Host "    Note   : PIM_SqlServer not set -- using local store '$($global:PIM_SqlServer)' (Integrated auth)." -ForegroundColor DarkYellow
}
if (-not $global:PIM_SqlDatabase) { throw "Engine config missing: set PIM_SqlDatabase (the desired-store database name, e.g. PimPlatform)." }

# --- load the engine (identical chain to the scheduler) ------------------------
. "$shared\PIM-Rest.ps1"
. "$shared\PIM-SqlStore.ps1"
. "$shared\PIM-ChangeQueue.ps1"
. "$shared\PIM-PermissionWizard.ps1"      # naming helpers (ConvertTo-PimNameSegment / New-PimPermissionGroupName / scope-depth+plane) for discovery
. "$shared\PIM-AzureDiscovery.ps1"        # Azure scope reconcile planner (Power BI discovery mirrors its shape)
. "$shared\PIM-Discovery.ps1"             # Power BI / service-role / auto-map / delta discovery layer (REST-only)
. "$shared\PIM-ContextBuilder.ps1"
. "$shared\PIM-EngineCore.ps1"
. "$shared\PIM-DisableGuard.ps1"                # account-disable circuit breaker (incident 2026-06-15)
. "$shared\PIM-Notify.ps1"                      # mail notifications (REST sendMail)
. "$shared\PIM-HybridAd.ps1"                    # on-prem AD/gMSA-sMSA PLANNER + hybrid-worker seam (on-prem write is worker-only)
. "$shared\PIM-EngineProviders.ps1"
. "$config\PIM4EntraPS.Filters.locked.ps1"     # $global:PIM_Filters (candidate filters)
Register-PimDefaultEngineProviders
$global:PIM_EngineSqlCs = Get-PimSqlConnectionString

$idLabel = if ($global:PIM_ClientId) { "SPN $($global:PIM_ClientId)" + $(if ($global:PIM_CertThumbprint) { " (cert $($global:PIM_CertThumbprint.Substring(0,8))...)" } else { '' }) } else { 'managed identity / ambient' }
Write-Host "==> PIM4EntraPS engine" -ForegroundColor Cyan
Write-Host "    SQL    : $($global:PIM_SqlServer) / $($global:PIM_SqlDatabase)"
Write-Host "    Auth   : $idLabel"
Write-Host "    Run    : scope=$Scope mode=$Mode whatIf=$([bool]$WhatIf) fromQueue=$([bool]$FromQueue)"
Write-Host "    Scopes : $((Get-PimEngineScopes) -join ', ')"

if ($Prune -and $Mode -ne 'Full') { Write-Host "    Note   : -Prune is only honoured with -Mode Full; ignoring." -ForegroundColor DarkYellow }

# --- PRECONDITION GUARD -------------------------------------------------------
# Fail HARD before touching the tenant if the expected inputs aren't there, instead of
# silently producing empty scopes (which on a wrong/un-provisioned target could mass-create
# from scratch or, in Full+Prune, mass-delete). Each check throws a clear, actionable error.
# Opt out only deliberately with -SkipPreflight (set $env:PIM_SkipPreflight=1).
if (-not $env:PIM_SkipPreflight) {
    Write-Host "    Preflight..." -ForegroundColor DarkCyan
    # 1) DESIRED store reachable + non-empty. An empty desired set against a live tenant is the
    #    classic "pointed at the wrong/empty store" mistake -- never silently proceed.
    try { if (-not (Test-PimSqlConnectivity -ConnectionString $global:PIM_EngineSqlCs)) { throw 'no SELECT 1' } }
    catch { throw "Preflight FAILED: cannot reach the desired store ($($global:PIM_SqlServer)/$($global:PIM_SqlDatabase)): $($_.Exception.Message)" }
    $desiredTotal = 0
    foreach ($e in @('PIM-Definitions-AU','PIM-Definitions-Roles','PIM-Definitions-Services','PIM-Definitions-Organization','PIM-Definitions-Tasks','Account-Definitions-Admins')) {
        $desiredTotal += @(Get-PimSqlRows -ConnectionString $global:PIM_EngineSqlCs -Entity $e).Count
    }
    if ($desiredTotal -eq 0) { throw "Preflight FAILED: the desired store ($($global:PIM_SqlServer)/$($global:PIM_SqlDatabase)) has NO definition/admin rows. Refusing to run against a live tenant with an empty desired set (seed the store, or check PIM_SqlServer/PIM_SqlDatabase)." }
    # 2) Tenant identity actually works -- mint a Graph token + resolve the org, so a wrong/missing
    #    credential is caught here, not after a half-applied run.
    try {
        $tok = Get-PimRestToken -Resource 'graph'
        if (-not $tok) { throw 'no token' }
        $org = Invoke-PimGraph -Path "/organization?`$select=displayName,id"
        $orgName = if ($org.value) { $org.value[0].displayName } else { $org.displayName }
        Write-Host "    Tenant : $orgName ($($global:PIM_TenantId))  desired rows=$desiredTotal" -ForegroundColor DarkCyan
    } catch { throw "Preflight FAILED: could not authenticate to the tenant / resolve the organization (check PIM_TenantId / PIM_ClientId / PIM_CertThumbprint or MI): $($_.Exception.Message)" }
}

$res = Invoke-PimEngine -Scope $Scope -Mode $Mode -WhatIf:$WhatIf -Prune:$Prune -FromQueue:$FromQueue

# --- discovery sweep + per-type auto-create policy (REQUIREMENTS §8) ------------
# Run on a normal full/delta sweep (NOT a commit-triggered -FromQueue run, which only
# drains the queue). New resources of a type whose policy = 'auto' are enqueued as a
# Create on the SAME change queue (applied by the next/commit run); 'pending' stages a
# desired row for review; 'flag' (the default for every type) only logs the discovery.
# Best-effort: a discovery failure never fails the engine run.
if (-not $FromQueue) {
    try { [void](Invoke-PimEngineDiscoverySweep -WhatIf:$WhatIf -ConnectionString $global:PIM_EngineSqlCs) }
    catch { Write-Warning "  [discovery] sweep failed (non-fatal): $($_.Exception.Message)" }
}

$tot = [pscustomobject]@{ create=0; update=0; remove=0; applied=0; skipped=0; errors=0 }
foreach ($r in @($res)) { $tot.create+=$r.create; $tot.update+=$r.update; $tot.remove+=$r.remove; $tot.applied+=$r.applied; $tot.skipped+=([int]$r.skipped); $tot.errors+=$r.errors }
Write-Host ("==> Done. create={0} update={1} remove={2} applied={3} skipped={4} errors={5}" -f $tot.create,$tot.update,$tot.remove,$tot.applied,$tot.skipped,$tot.errors) -ForegroundColor $(if ($tot.errors) {'Yellow'} else {'Green'})
Write-Host "    Log    : $logFile"
if ($script:__transcript) { try { Stop-Transcript | Out-Null } catch {} }
if ($tot.errors) { exit 1 }
