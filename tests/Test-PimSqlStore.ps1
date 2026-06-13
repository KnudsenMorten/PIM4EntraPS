#Requires -Version 5.1
<#
.SYNOPSIS
    LIVE integration test for the SQL-only data layer (engine/_shared/PIM-SqlStore.ps1)
    against a real SQL Server instance. Creates a throwaway database, runs the
    schema, round-trips rows + the change-queue delta commit, then DROPS the
    database. Skips cleanly if no SQL instance is reachable.

        powershell -NoProfile -File .\tests\Test-PimSqlStore.ps1 [-Server .\SQLEXPRESS]
#>
[CmdletBinding()] param([string]$Server = '.\SQLEXPRESS')
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
. (Join-Path $root 'engine\_shared\PIM-ChangeQueue.ps1')
. (Join-Path $root 'engine\_shared\PIM-SqlStore.ps1')

$fail = New-Object System.Collections.Generic.List[string]; $pass = 0
function A($cond, $name) { if ($cond) { $script:pass++; Write-Host "  [PASS] $name" -ForegroundColor Green } else { $script:fail.Add($name); Write-Host "  [FAIL] $name" -ForegroundColor Red } }

# Reachable?
$masterCs = Get-PimSqlConnectionString -Server $Server -Database 'master'
if (-not (Test-PimSqlConnectivity -ConnectionString $masterCs)) {
    Write-Host "SQL instance '$Server' not reachable -- SKIPPING SQL store integration test." -ForegroundColor Yellow
    exit 0
}

$db = "pimtest_" + [guid]::NewGuid().ToString('N').Substring(0,12)
$cs = Get-PimSqlConnectionString -Server $Server -Database $db
try {
    Write-Host "Creating throwaway DB $db ..." -ForegroundColor Cyan
    Initialize-PimSqlDatabase -Server $Server -Database $db
    Initialize-PimSqlStore -ConnectionString $cs
    A ($true) 'database + schema created (pim.Rows + pim.ChangeQueue)'

    Write-Host "Row CRUD" -ForegroundColor Cyan
    Set-PimSqlRow -ConnectionString $cs -Entity 'PIM-Definitions-Tasks' -Key 'Entra-ID-UserAdmin-L1' -Data ([pscustomobject]@{ GroupName='PIM-Entra-ID-UserAdmin-L1-T0-CP-ID'; Workload='Entra-ID'; Level='L1'; TierLevel='T0'; Plane='CP' })
    $r = Get-PimSqlRow -ConnectionString $cs -Entity 'PIM-Definitions-Tasks' -Key 'Entra-ID-UserAdmin-L1'
    A ("$($r.Workload)" -eq 'Entra-ID' -and "$($r.Level)" -eq 'L1') 'insert + read round-trips the JSON row'
    Set-PimSqlRow -ConnectionString $cs -Entity 'PIM-Definitions-Tasks' -Key 'Entra-ID-UserAdmin-L1' -Data ([pscustomobject]@{ GroupName='x'; Workload='Entra-ID'; Level='L2' })
    A ((Get-PimSqlRow -ConnectionString $cs -Entity 'PIM-Definitions-Tasks' -Key 'Entra-ID-UserAdmin-L1').Level -eq 'L2') 'upsert updates in place (MERGE)'
    A (@(Get-PimSqlRows -ConnectionString $cs -Entity 'PIM-Definitions-Tasks').Count -eq 1) 'one row for the entity (no duplicate)'
    Remove-PimSqlRow -ConnectionString $cs -Entity 'PIM-Definitions-Tasks' -Key 'Entra-ID-UserAdmin-L1'
    A (@(Get-PimSqlRows -ConnectionString $cs -Entity 'PIM-Definitions-Tasks').Count -eq 0) 'remove deletes the row'

    Write-Host "Change queue + fast delta commit" -ForegroundColor Cyan
    Add-PimSqlQueueChange -ConnectionString $cs -Change (New-PimChange -Entity 'PIM-Definitions-Tasks' -Key 'k-new' -Op Create -Payload ([pscustomobject]@{ GroupName='New'; Workload='Azure' }))
    A (@(Get-PimSqlQueue -ConnectionString $cs).Count -eq 1) 'change enqueued (pending)'
    $commit = Invoke-PimSqlCommit -ConnectionString $cs
    A ($commit.applied -ge 1) 'commit drained the queue'
    A ((Get-PimSqlRow -ConnectionString $cs -Entity 'PIM-Definitions-Tasks' -Key 'k-new').Workload -eq 'Azure') 'committed change landed in pim.Rows'
    A (@(Get-PimSqlQueue -ConnectionString $cs).Count -eq 0) 'queue empty after commit (marked applied)'

    Write-Host "Delta correctness: enqueue Create then Remove same key -> net no-op" -ForegroundColor Cyan
    Add-PimSqlQueueChange -ConnectionString $cs -Change (New-PimChange -Entity 'PIM-Definitions-Tasks' -Key 'k-cancel' -Op Create -Payload ([pscustomobject]@{ x=1 }) -EnqueuedUtc '2026-06-13T10:00:00Z')
    Add-PimSqlQueueChange -ConnectionString $cs -Change (New-PimChange -Entity 'PIM-Definitions-Tasks' -Key 'k-cancel' -Op Remove -EnqueuedUtc '2026-06-13T10:05:00Z')
    [void](Invoke-PimSqlCommit -ConnectionString $cs)
    A ($null -eq (Get-PimSqlRow -ConnectionString $cs -Entity 'PIM-Definitions-Tasks' -Key 'k-cancel')) 'create+remove in one commit cancels (no row created)'

    Write-Host "Entity row-set replace (the manager PUT semantics)" -ForegroundColor Cyan
    $e = 'PIM-Assignments-Roles-Groups'
    A ((Get-PimStoreRowKey -Base $e -Row ([pscustomobject]@{ GroupTag='G1'; RoleDefinitionName='Reader' })) -eq 'G1|Reader') 'natural key composes per base'
    Set-PimSqlEntityRows -ConnectionString $cs -Entity $e -Base $e -Rows @(
        [pscustomobject]@{ GroupTag='G1'; RoleDefinitionName='Reader' }
        [pscustomobject]@{ GroupTag='G2'; RoleDefinitionName='Owner' }
    ) | Out-Null
    A (@(Get-PimSqlRows -ConnectionString $cs -Entity $e).Count -eq 2) 'row-set write inserts both rows'
    $r2 = Set-PimSqlEntityRows -ConnectionString $cs -Entity $e -Base $e -Rows @([pscustomobject]@{ GroupTag='G1'; RoleDefinitionName='Reader' })
    A (@(Get-PimSqlRows -ConnectionString $cs -Entity $e).Count -eq 1 -and $r2.removed -eq 1) 'row-set replace deletes the dropped row (full-set semantics)'

    Write-Host "Settings live in SQL (file is seed only)" -ForegroundColor Cyan
    Set-PimSqlSetting -ConnectionString $cs -Name 'PawEnforcement' -Value $true
    A ((Get-PimSqlSetting -ConnectionString $cs -Name 'PawEnforcement') -eq $true) 'setting round-trips through pim.Settings'
    $added = Import-PimSettingsSeed -ConnectionString $cs -Seed @{ PawEnforcement = $false; NewKey = 'x' }
    A ($added -eq 1) 'seed adds only missing keys (never overwrites managed settings)'
    A ((Get-PimSqlSetting -ConnectionString $cs -Name 'PawEnforcement') -eq $true) 'existing managed setting NOT overwritten by seed'
    A ((Get-PimAllSqlSettings -ConnectionString $cs)['NewKey'] -eq 'x') 'all-settings load returns seeded key'
} finally {
    Write-Host "Dropping $db ..." -ForegroundColor Cyan
    try { [void](Invoke-PimSqlNonQuery -ConnectionString $masterCs -Sql "IF DB_ID('$db') IS NOT NULL BEGIN ALTER DATABASE [$db] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE [$db]; END") } catch { Write-Warning "cleanup failed: $($_.Exception.Message)" }
}

Write-Host ('=' * 70)
if ($fail.Count -eq 0) { Write-Host ("ALL {0} ASSERTIONS PASSED." -f $pass) -ForegroundColor Green; exit 0 }
else { Write-Host ("{0} passed, {1} FAILED:" -f $pass, $fail.Count) -ForegroundColor Red; $fail | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }; exit 1 }
