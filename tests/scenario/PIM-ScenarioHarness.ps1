<#
.SYNOPSIS
  Shared harness for the PIM4EntraPS engine+GUI SCENARIO SIMULATION suite
  (REQUIREMENTS.md §20 "engine+GUI scenario sim"). Dot-source it from a scenario script.

  It wires the three layers a scenario needs:

    1. SQL desired store   -- a throwaway local SQLEXPRESS database holds pim.Rows, the
                              SINGLE source of truth the real engine reads AND the Manager
                              renders in SQL mode. The rich scenario seed populates it.
    2. The REAL engine     -- Invoke-PimEngine + the real providers, loaded exactly as the
                              entrypoint loads them, run against (1) for desired and the
                              FAKE TENANT (PIM-FakeTenant.ps1) for live -> genuine
                              create/diff/idempotency without a tenant or network.
    3. Assertions          -- 3-level critical eval (system / UX / use-case) helpers:
                              Assert-Plan, Assert-Idempotent, Assert-FakeState.

  PS 5.1, REST-only, no Graph/Az modules, no secrets/IDs/customer names.

  SELF-SKIP: Test-PimScenarioPrereq returns $false (with a reason) when SQLEXPRESS is not
  reachable, so a scenario script can exit 0 (clean skip) rather than fail.
#>

$script:PimScenarioRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path   # solution root

# ---------------------------------------------------------------------------
# Pretty assert plumbing (shared counters the scenario script reads).
# ---------------------------------------------------------------------------
function New-PimScenarioContext { [pscustomobject]@{ pass=0; fail=0; name='' } }
function Set-PimScenarioName { param($Ctx,[string]$Name) $Ctx.name=$Name; Write-Host "`n== SCENARIO: $Name ==" -ForegroundColor Cyan }
function Assert-PimScenario {
    param($Ctx,[string]$What,[bool]$Cond,[string]$Detail='')
    if ($Cond) { $Ctx.pass++; Write-Host "  PASS  $What" -ForegroundColor Green }
    else       { $Ctx.fail++; Write-Host "  FAIL  $What $(if($Detail){"-- $Detail"})" -ForegroundColor Red }
}

# ---------------------------------------------------------------------------
# Prereqs.
# ---------------------------------------------------------------------------
function Test-PimScenarioPrereq {
    param([string]$SqlServer = '.\SQLEXPRESS')
    try {
        $cs = "Server=$SqlServer;Database=master;Integrated Security=SSPI;TrustServerCertificate=True;Connect Timeout=4"
        $c = New-Object System.Data.SqlClient.SqlConnection $cs
        $c.Open(); $c.Close()
        return [pscustomobject]@{ ok=$true; reason='' }
    } catch {
        return [pscustomobject]@{ ok=$false; reason="SQLEXPRESS not reachable at $SqlServer ($($_.Exception.Message.Split([char]10)[0]))" }
    }
}

# ---------------------------------------------------------------------------
# Load the engine + fake tenant. Mirrors Invoke-PimEngineCore.ps1's load chain
# but stops short of the live preflight (the fake tenant replaces live).
# ---------------------------------------------------------------------------
function Get-PimScenarioEngineFiles {
    # The ordered file list a scenario script DOT-SOURCES at its top level (so every engine
    # function lands in the scenario's scope, visible to the harness functions). Returns
    # absolute paths. Set $global:PIM_SqlServer/Database before dot-sourcing them.
    $shared = Join-Path $script:PimScenarioRoot 'engine\_shared'
    $config = Join-Path $script:PimScenarioRoot 'config'
    $files = @(
        "$shared\PIM-Rest.ps1","$shared\PIM-SqlStore.ps1","$shared\PIM-ChangeQueue.ps1",
        "$shared\PIM-PermissionWizard.ps1","$shared\PIM-AzureDiscovery.ps1","$shared\PIM-Discovery.ps1",
        "$shared\PIM-ContextBuilder.ps1","$shared\PIM-EngineCore.ps1","$shared\PIM-Notify.ps1",
        "$shared\PIM-EngineProviders.ps1"
    )
    if (Test-Path "$config\PIM4EntraPS.Filters.locked.ps1") { $files += "$config\PIM4EntraPS.Filters.locked.ps1" }
    # NB: load the PARAMLESS seed-spec (not Seed-PimScenarioDataset.ps1, whose param() block
    # would clobber same-named caller variables when dot-sourced at the scenario top level).
    $files += @((Join-Path $PSScriptRoot 'PIM-FakeTenant.ps1'),(Join-Path $PSScriptRoot 'PIM-ScenarioSeedSpec.ps1'))
    return $files
}

# ---------------------------------------------------------------------------
# Provision a clean throwaway SQL desired store and load it with the rich seed.
# Returns the connection string; the engine reads desired from it.
# ---------------------------------------------------------------------------
function Initialize-PimScenarioStore {
    param(
        [Parameter(Mandatory)][string]$SqlServer,
        [Parameter(Mandatory)][string]$SqlDatabase,
        [Parameter(Mandatory)][string]$OwnerUpn,
        [Parameter(Mandatory)][string]$DefaultDomain,
        [string]$Marker='PIMSCENARIO-'
    )
    Initialize-PimSqlDatabase -Server $SqlServer -Database $SqlDatabase
    $cs = Get-PimSqlConnectionString
    Initialize-PimSqlStore -ConnectionString $cs
    # wipe any prior rows so each run is deterministic
    Invoke-PimSqlNonQuery -ConnectionString $cs -Sql "DELETE FROM pim.Rows" | Out-Null
    $global:PIM_EngineSqlCs = $cs

    $spec = Get-PimScenarioSeedSpec -OwnerUpn $OwnerUpn -DefaultDomain $DefaultDomain -Marker $Marker
    foreach ($entity in $spec.Keys) {
        foreach ($r in @($spec[$entity])) {
            $key = if ($entity -eq 'PIM-Definitions-Departments') { "$($r.Department)" } else { Get-PimStoreRowKey -Base $entity -Row $r }
            if (-not $key) { continue }
            Set-PimSqlRow -ConnectionString $cs -Entity $entity -Key $key -Data $r
        }
    }
    return $cs
}

function Remove-PimScenarioStore {
    param([Parameter(Mandatory)][string]$SqlServer,[Parameter(Mandatory)][string]$SqlDatabase)
    try {
        $cs = "Server=$SqlServer;Database=master;Integrated Security=SSPI;TrustServerCertificate=True;Connect Timeout=8"
        $sql = "IF DB_ID('$SqlDatabase') IS NOT NULL BEGIN ALTER DATABASE [$SqlDatabase] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE [$SqlDatabase]; END"
        $c = New-Object System.Data.SqlClient.SqlConnection $cs; $c.Open()
        $cmd = $c.CreateCommand(); $cmd.CommandText=$sql; $cmd.ExecuteNonQuery() | Out-Null; $c.Close()
    } catch { Write-Warning "scenario store cleanup: $($_.Exception.Message)" }
}

# ---------------------------------------------------------------------------
# Run the real engine against the fake tenant. -Mode + -Prune passthrough.
# Returns the aggregated plan ([create/update/remove/applied/skipped/errors] + the
# per-scope results) so a scenario can assert exactly what happened.
# ---------------------------------------------------------------------------
# A real deploy runs -Mode Full and -Mode Delta in SEPARATE engine PROCESSES; each starts
# with empty per-run caches. The scenario sim runs both passes in ONE process, so the
# provider schedule-preload caches ($script:PimDirSchedAt / PimGrpSchedAt / PimGrpMemCache
# etc., dot-sourced into the SCENARIO scope) would survive and serve STALE (pre-create)
# live state -> a false "Delta still creates" result. Clearing them before the Delta pass
# faithfully simulates a fresh process. The names are dot-sourced into the global session
# state by Get-PimScenarioEngineFiles, so clear them there.
$script:PimEngineRunCacheVars = @(
    'PimDirSchedAt','PimDirElig','PimDirAct','PimGrpSchedAt','PimGrpElig','PimGrpAct',
    'PimGrpMemCache'
)
function Reset-PimEngineRunCaches {
    # Clear in BOTH the global scope and the caller's scope so it works whether the engine
    # was dot-sourced globally or at the scenario top level.
    foreach ($v in $script:PimEngineRunCacheVars) {
        Set-Variable -Name $v -Value $null -Scope Global -ErrorAction SilentlyContinue
        Set-Variable -Name $v -Value $null -Scope Script -ErrorAction SilentlyContinue
    }
    # also drop the directory-context built marker so a refreshBefore scope rebuilds from
    # the (now fuller) fake store rather than a stale snapshot.
    Set-Variable -Name 'PimContextBuiltAt' -Value $null -Scope Global -ErrorAction SilentlyContinue
}

function Invoke-PimScenarioEngine {
    param([string]$Scope='All',[ValidateSet('Full','Delta')][string]$Mode='Delta',[switch]$WhatIf,[switch]$Prune,[switch]$FreshProcess)
    if ($FreshProcess) { Reset-PimEngineRunCaches }
    # the engine reads desired from $global:PIM_EngineSqlCs (set by Initialize-PimScenarioStore)
    $res = @(Invoke-PimEngine -Scope $Scope -Mode $Mode -WhatIf:$WhatIf -Prune:$Prune)
    $tot = [pscustomobject]@{ create=0; update=0; remove=0; applied=0; skipped=0; errors=0; scopes=$res }
    foreach ($r in $res) { $tot.create+=[int]$r.create; $tot.update+=[int]$r.update; $tot.remove+=[int]$r.remove; $tot.applied+=[int]$r.applied; $tot.skipped+=[int]$r.skipped; $tot.errors+=[int]$r.errors }
    return $tot
}

function Get-PimScenarioScope { param($Result,[string]$Scope) @($Result.scopes | Where-Object { $_.scope -eq $Scope }) | Select-Object -First 1 }
