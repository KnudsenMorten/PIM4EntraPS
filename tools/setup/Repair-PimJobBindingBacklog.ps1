<#
.SYNOPSIS
  BUG-134/117 REMEDIATION -- find and clear the backlog left by scheduled jobs that were bound to
  engine scopes no provider serves, and repair the stored schedule that kept them that way.

.DESCRIPTION
  🔴 WHAT WENT WRONG, so an operator running this knows exactly what they are repairing.

  The shipped job schedule carried v1 CSV-engine scope names the REST engine never registered:
    delta-groups-assign  -> 'GroupsAssignment'          (nests a PIM-ROLE group into its permission groups)
    delta-groups-deploy  -> 'GroupsCreateModifyPolicy'  (creates the group, its owners, its AU membership)
    delta-workloads      -> 'Workloads'                 (Defender XDR / Intune / enterprise-app roles)
  An unserved scope returned "no provider" with NO counts, and the scheduler recorded the tick as
  SUCCEEDED. So those jobs did nothing, on every tick, while reporting success.

  The user-visible effect is the one that matters: a DELEGATION authored in the Manager was
  validated, committed to pim.Rows, and rendered correctly on the Access map -- and was never
  applied to Entra. The only thing that ever picked it up was the daily `full-reconcile`
  (scope All), so the symptom was "my delegation took a day", or, if full-reconcile was disabled
  or failing, "my delegation never happened".

  Separately (BUG-136), Get-PimJobSchedule took a STORED 'JobSchedule' wholesale instead of
  merging the operator's enabled/cadence choices onto the shipped catalog. Any environment whose
  cadences were ever touched in the GUI froze its own copy of the broken scope names, so a
  corrected default could never reach it. Both are fixed in the engine; this script reports and
  clears what the outage already left behind.

  WHAT THIS SCRIPT DOES
    1. Reports the binding verdict for THIS environment's resolved schedule -- which jobs, if any,
       still point at a scope no provider serves.
    2. Optionally rewrites the stored 'JobSchedule' to the merged/corrected form (-RepairSchedule),
       so the GUI and the scheduler agree immediately.
    3. Runs a FULL reconcile over exactly the affected scopes to quantify (and, with -Apply, clear)
       the backlog. Full is required: a Delta only looks at what changed recently, and the backlog
       is by definition everything that was never applied at all.

  SAFE BY DEFAULT: reports only. -Apply performs the reconcile. -Prune is deliberately NOT offered
  -- this repair only ever CREATES the assignments that should already exist; nothing is removed.

.EXAMPLE
  # 1) See what was never applied in this environment (no writes):
  .\Repair-PimJobBindingBacklog.ps1 -TenantId <t> -ClientId <c> -CertThumbprint <th> `
      -SqlServer <srv> -SqlDatabase <db>

.EXAMPLE
  # 2) Repair the stored schedule and clear the backlog:
  .\Repair-PimJobBindingBacklog.ps1 -TenantId <t> -ClientId <c> -CertThumbprint <th> `
      -SqlServer <srv> -SqlDatabase <db> -RepairSchedule -Apply
#>
[CmdletBinding()]
param(
    [string]$TenantId,
    [string]$ClientId,
    [string]$CertThumbprint,
    [string]$SqlServer,
    [string]$SqlDatabase,
    [string]$Label,                 # friendly name for the report header (e.g. the customer/env)
    [switch]$RepairSchedule,        # rewrite the stored 'JobSchedule' to the merged/corrected form
    [switch]$Apply,                 # actually apply the backlog (default = report only)
    # The scopes the broken jobs were supposed to drive. Override only to narrow the repair.
    [string[]]$Scope = @('GroupsCreateModifyPolicy','GroupMembers','AdminAccounts','EntraRoleAssignments','Workloads')
)
$ErrorActionPreference = 'Stop'
$here   = Split-Path -Parent $MyInvocation.MyCommand.Path
$sol    = Resolve-Path "$here\..\.."
$engine = Join-Path $sol 'tools\pim-engine\Invoke-PimEngineCore.ps1'
if (-not (Test-Path -LiteralPath $engine)) { throw "engine entry point not found at $engine" }

$hdr = if ("$Label".Trim()) { "$Label" } else { "$SqlServer/$SqlDatabase" }
Write-Host ""
Write-Host "=== PIM job-binding backlog repair -- $hdr ===" -ForegroundColor Cyan
Write-Host ("    mode: {0}" -f $(if ($Apply) { 'APPLY (writes to the tenant)' } else { 'REPORT ONLY (no writes)' })) `
    -ForegroundColor $(if ($Apply) { 'Yellow' } else { 'DarkGray' })

# --- 1. binding verdict for this environment's resolved schedule ---------------
# Loaded in THIS process only to read the schedule + registry; no tenant calls here.
$shared = Join-Path $sol 'engine\_shared'
. "$shared\PIM-ChangeQueue.ps1"
. "$shared\PIM-EngineCore.ps1"
. "$shared\PIM-EngineProviders.ps1"
# 🪤 PIM-PortalAccess.ps1 defines Get-PimPolicySetting, which this script uses to read the STORED
# JobSchedule. Without it the call is skipped by its own `Get-Command` guard and the report says
# "no stored JobSchedule" for an environment that has one -- i.e. it would clear the environment of
# the very defect it exists to find. Caught by Test-PimCodeAudit's INERT-CAPABILITY class, which
# checks that every capability an entry point relies on is actually loaded by that entry point.
. "$shared\PIM-PortalAccess.ps1"
. "$shared\PIM-Scheduler.ps1"
Register-PimDefaultEngineProviders

if ("$SqlServer".Trim())   { $global:PIM_SqlServer   = $SqlServer.Trim();   $env:PIM_SqlServer   = $SqlServer.Trim() }
if ("$SqlDatabase".Trim()) { $global:PIM_SqlDatabase = $SqlDatabase.Trim(); $env:PIM_SqlDatabase = $SqlDatabase.Trim() }

$storedRaw = $null
try {
    . "$shared\PIM-SqlStore.ps1"
    if (Get-Command Import-PimSettingsFromStore -ErrorAction SilentlyContinue) { [void](Import-PimSettingsFromStore) }
    if (Get-Command Get-PimPolicySetting -ErrorAction SilentlyContinue) { $storedRaw = Get-PimPolicySetting -Name 'JobSchedule' -Default $null }
} catch { Write-Warning "could not read the stored JobSchedule ($($_.Exception.Message)); reporting against the shipped catalog instead." }

$storedCount = @($storedRaw).Count
Write-Host ("    stored JobSchedule: {0}" -f $(if ($storedCount) { "$storedCount job(s) -- this environment has its own snapshot" } else { 'none (uses the shipped catalog)' }))

# What the environment WOULD have run before the fix (the raw snapshot, taken wholesale)...
if ($storedCount) {
    $before = Test-PimJobScopeBinding -Schedule @($storedRaw)
    if (-not $before.ok) {
        Write-Host "    [!] the stored snapshot contains $(@($before.unbound).Count) job(s) bound to NOTHING:" -ForegroundColor Red
        foreach ($u in $before.unbound) { Write-Host "         - $($u.name)  scope '$($u.scope)'" -ForegroundColor Red }
        Write-Host "       These reported SUCCESS on every tick while doing nothing." -ForegroundColor Red
    } else {
        Write-Host "    stored snapshot: all engine jobs already bind to a provider." -ForegroundColor DarkGray
    }
}
# ...and what it runs NOW, after the merge fix.
$effective = @(Get-PimJobSchedule)
$after = Test-PimJobScopeBinding -Schedule $effective
if ($after.ok) {
    Write-Host "    [OK] effective schedule: all $($after.checked) engine job(s) bind to a provider." -ForegroundColor Green
} else {
    Write-Host "    [!] effective schedule STILL has unbound jobs -- fix these before relying on the repair:" -ForegroundColor Red
    foreach ($u in $after.unbound) { Write-Host "         - $($u.name)  scope '$($u.scope)'  $($u.detail)" -ForegroundColor Red }
}

# --- 2. optionally rewrite the stored schedule --------------------------------
if ($RepairSchedule) {
    if (-not $storedCount) {
        Write-Host "    -RepairSchedule: nothing stored; the catalog is already in use. Skipped." -ForegroundColor DarkGray
    } elseif (-not (Get-Command Set-PimSqlSetting -ErrorAction SilentlyContinue)) {
        Write-Warning "    -RepairSchedule: Set-PimSqlSetting not available; skipped."
    } else {
        # Write back the SAME merge the engine now performs, so the persisted snapshot stops
        # carrying stale scopes and the GUI's Jobs tab matches what the scheduler runs.
        $merged = @(Merge-PimJobSchedule -Stored @($storedRaw) -Catalog (Get-PimDefaultJobSchedule))
        if ($Apply) {
            Set-PimSqlSetting -ConnectionString (Get-PimSqlConnectionString) -Name 'JobSchedule' -Value $merged
            Write-Host "    [OK] stored JobSchedule rewritten ($(@($merged).Count) jobs, operator cadences preserved)." -ForegroundColor Green
        } else {
            Write-Host "    would rewrite the stored JobSchedule to $(@($merged).Count) merged job(s) (re-run with -Apply)." -ForegroundColor Yellow
        }
    }
}

# --- 3. quantify / clear the backlog ------------------------------------------
# Delegated to the real engine entry point so auth, preflight and logging are IDENTICAL to a
# normal run -- a repair must not be a second, differently-behaving code path.
Write-Host ""
Write-Host "--- backlog over scopes: $($Scope -join ', ') ---" -ForegroundColor Cyan
$results = @()
foreach ($s in $Scope) {
    $engArgs = @{ Scope = $s; Mode = 'Full' }
    if ("$TenantId".Trim())       { $engArgs['TenantId']       = $TenantId }
    if ("$ClientId".Trim())       { $engArgs['ClientId']       = $ClientId }
    if ("$CertThumbprint".Trim()) { $engArgs['CertThumbprint'] = $CertThumbprint }
    if ("$SqlServer".Trim())      { $engArgs['SqlServer']      = $SqlServer }
    if ("$SqlDatabase".Trim())    { $engArgs['SqlDatabase']    = $SqlDatabase }
    if (-not $Apply)              { $engArgs['WhatIf']         = $true }
    # NB: -Prune is never passed. This repair only creates what should already exist.
    try {
        $r = & $engine @engArgs
        $sum = @($r) | Where-Object { $_.kind -eq 'pim-engine-summary' } | Select-Object -First 1
        if (-not $sum) { $sum = @($r) | Select-Object -Last 1 }
        $results += [pscustomobject]@{ scope=$s; create=[int]$sum.create; update=[int]$sum.update; applied=[int]$sum.applied; errors=[int]$sum.errors }
    } catch {
        Write-Warning "  scope '$s' FAILED: $($_.Exception.Message)"
        $results += [pscustomobject]@{ scope=$s; create=-1; update=-1; applied=-1; errors=1 }
    }
}

Write-Host ""
Write-Host "=== BACKLOG SUMMARY -- $hdr ===" -ForegroundColor Cyan
$results | Format-Table -AutoSize | Out-String | Write-Host
$missing = (@($results | Where-Object { $_.create -gt 0 }) | Measure-Object -Property create -Sum).Sum
if (-not $Apply) {
    if ($missing) {
        Write-Host "[!] $missing assignment(s) exist in the desired store but NOT in the tenant -- this is the backlog the broken jobs left." -ForegroundColor Red
        Write-Host "   Re-run with -Apply to create them." -ForegroundColor Yellow
    } else {
        Write-Host "[OK] no backlog: every desired assignment in these scopes is already present in the tenant." -ForegroundColor Green
    }
} else {
    $applied = (@($results) | Measure-Object -Property applied -Sum).Sum
    $errs    = (@($results) | Measure-Object -Property errors  -Sum).Sum
    Write-Host ("{0} applied={1} errors={2}" -f $(if ($errs) { '[WARN]' } else { '[OK]' }), $applied, $errs) -ForegroundColor $(if ($errs) { 'Yellow' } else { 'Green' })
    Write-Host "   Re-run WITHOUT -Apply to confirm the backlog is now zero." -ForegroundColor DarkGray
}
@($results)
