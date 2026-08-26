#Requires -Version 5.1
<#
.SYNOPSIS
    TEST-12 / §33.7.f criterion 6 + §33.7.e-2 rule 5 -- prove that `-Cleanup` ALONE returns
    every tenant to its pre-run baseline, and that it touches nothing else.

.DESCRIPTION
    Two claims, and the second is the one that makes the first safe:

      COMPLETE  -- after the sweep, NO object carrying the marker remains in any tenant,
                   and no marked row remains in the scratch store.
      CONTAINED -- every UNMARKED object that existed before the sweep still exists after
                   it, with the same name. A cleanup that removed the customer's real
                   groups would satisfy "complete" perfectly.

    So this takes a full inventory of all three object classes in every tenant plus the
    scratch store's registry tables, runs the real sweep, re-inventories, and diffs the two
    by NAME -- not by count, because a count survives a swap.

    It is deliberately a LIVE test with no mocks: the thing being verified is that the real
    sweep, against real directories, is both sufficient and bounded. Run it AFTER a
    scenario run, while there is a seeded estate to remove -- that is when the claim means
    something. With nothing seeded it still passes (and asserts that a no-op sweep changes
    nothing), which is a useful regression in its own right.

.PARAMETER TenantJson
    Same file the sweep uses: [{ name; tenantId; clientId; certThumbprint; subscriptionId }]

.EXAMPLE
    .\Test-PimScenarioCleanupComplete.ps1 -TenantJson .\scenario-tenants.custom.json
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$TenantJson,
    [string]$SqlServer   = $(if ($env:PIM_ScenarioSqlServer)   { $env:PIM_ScenarioSqlServer }   else { '.\SQLEXPRESS' }),
    [string]$SqlDatabase = $(if ($env:PIM_ScenarioSqlDatabase) { $env:PIM_ScenarioSqlDatabase } else { 'PimScenarioTest' }),
    [string]$Marker      = 'PIMSCEN'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Off

$pass = 0; $fail = 0
function Assert($n, $c) { if ($c) { Write-Host "  PASS  $n" -ForegroundColor Green; $script:pass++ } else { Write-Host "  FAIL  $n" -ForegroundColor Red; $script:fail++ } }

$here   = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $here) { $here = (Get-Location).Path }
$shared = Resolve-Path (Join-Path $here '..\..\engine\_shared')
. (Join-Path $shared 'PIM-Rest.ps1')
. (Join-Path $shared 'PIM-ChangeQueue.ps1')
. (Join-Path $shared 'PIM-SqlStore.ps1')
. (Join-Path $here '_PimScenarioMarker.ps1')
. (Join-Path $here '_PimScenarioTenants.ps1')
Set-PimScenarioMarker -Marker $Marker

Write-Host "=== TEST-12: -Cleanup alone restores the pre-run baseline (§33.7.f-6) ===" -ForegroundColor Cyan

# BUG-26: this half failed CLOSED (the concatenated tenantId could not bind to [string], so
# it threw) -- loud, therefore safe, but still broken under 5.1. Same shared parse as the
# sweep, so the two can never drift on what a tenant file means.
$tenants = @(Import-PimScenarioTenantJson -Path $TenantJson)

function Get-TenantInventory {
    param($T)
    $tok = Get-PimRestToken -Resource graph -TenantId $T.tenantId -ClientId $T.clientId -CertThumbprint $T.certThumbprint -Force
    $h = @{ Authorization = "Bearer $tok"; ConsistencyLevel = 'eventual' }
    $inv = [ordered]@{}
    foreach ($kind in @(
        @{ k = 'users';  u = 'https://graph.microsoft.com/v1.0/users?$select=userPrincipalName&$top=999' ; p = 'userPrincipalName' }
        @{ k = 'groups'; u = 'https://graph.microsoft.com/v1.0/groups?$select=displayName&$top=999'      ; p = 'displayName' }
        @{ k = 'aus';    u = 'https://graph.microsoft.com/v1.0/directory/administrativeUnits?$select=displayName' ; p = 'displayName' }
    )) {
        $names = New-Object System.Collections.Generic.List[string]
        $url = $kind.u
        while ($url) {
            $r = Invoke-RestMethod -Uri $url -Headers $h
            foreach ($o in @($r.value)) { $names.Add("$($o.$($kind.p))") }
            $url = $r.'@odata.nextLink'
        }
        $inv[$kind.k] = @($names | Sort-Object -Unique)
    }
    $inv
}

function Get-StoreInventory {
    # Ownership for a STORE ROW has to be judged the way the SWEEP judges it, or this test
    # reports phantom failures:
    #   * pim.Rows -- the sweep matches the key OR the DataJson, so a row whose key carries
    #     no marker but whose payload does IS owned. Judging on the key alone made such a
    #     row look like an unmarked row the sweep had wrongly deleted.
    #   * platform.TenantApps -- keyed by TenantId, a GUID that can never carry a marker. It
    #     is owned via its PARENT platform.Tenants row, which is exactly how the sweep
    #     deletes it. So the marker is carried here on the parent's DisplayName.
    $global:PIM_SqlServer = $SqlServer; $global:PIM_SqlDatabase = $SqlDatabase
    $cs = Get-PimSqlConnectionString
    $out = [ordered]@{}
    if (-not (Test-PimSqlConnectivity -ConnectionString $cs)) { return $out }
    foreach ($q in @(
        @{ k = 'pim.Rows';            sql = "SELECT Entity + '|' + [Key] + '|' + ISNULL(CAST(DataJson AS NVARCHAR(MAX)),'') AS n FROM pim.Rows" }
        @{ k = 'pim.CentralAdmins';   sql = "SELECT UserName AS n FROM pim.CentralAdmins" }
        @{ k = 'platform.Tenants';    sql = "SELECT DisplayName AS n FROM platform.Tenants" }
        @{ k = 'platform.TenantApps'; sql = "SELECT CAST(a.TenantId AS NVARCHAR(50)) + '|' + ISNULL(t.DisplayName,'') AS n FROM platform.TenantApps a LEFT JOIN platform.Tenants t ON t.TenantId = a.TenantId" }
    )) {
        try { $out[$q.k] = @(@(Invoke-PimSqlQuery -ConnectionString $cs -Sql $q.sql) | ForEach-Object { "$($_.n)" } | Sort-Object -Unique) }
        catch { $out[$q.k] = @() }   # table absent in this store
    }
    $out
}

# ---------------------------------------------------------------------------
Write-Host "`n[1] inventory BEFORE the sweep" -ForegroundColor Cyan
$before = [ordered]@{}
foreach ($t in $tenants) {
    $before[$t.tenantId] = Get-TenantInventory -T $t
    $m = @($before[$t.tenantId].GetEnumerator() | ForEach-Object { @($_.Value) | Where-Object { Test-PimScenarioOwnedName -Name $_ } })
    Write-Host ("  {0,-46} users={1,-4} groups={2,-4} aus={3,-3} marked={4}" -f $t.name, @($before[$t.tenantId].users).Count, @($before[$t.tenantId].groups).Count, @($before[$t.tenantId].aus).Count, @($m).Count)
}
$storeBefore = Get-StoreInventory
$markedStoreBefore = @($storeBefore.GetEnumerator() | ForEach-Object { @($_.Value) | Where-Object { Test-PimScenarioOwnedName -Name $_ } })
Write-Host ("  scratch store marked rows: {0}" -f @($markedStoreBefore).Count)

# ---------------------------------------------------------------------------
Write-Host "`n[2] the real sweep" -ForegroundColor Cyan
& (Join-Path $here 'Clear-PimScenarioEstate.ps1') -TenantJson $TenantJson -SqlServer $SqlServer -SqlDatabase $SqlDatabase -Marker $Marker | Out-Null
$sweepExit = $LASTEXITCODE

# ---------------------------------------------------------------------------
Write-Host "`n[3] inventory AFTER the sweep" -ForegroundColor Cyan
# Entra does not stop listing a deleted object the instant the DELETE returns 204. The
# first run of this test read the last-swept tenant immediately and saw objects the sweep
# had just, verifiably, removed. The claim being made is about the SETTLED state, so
# re-read until the marked set is empty or the budget runs out -- and then report whatever
# is really left. This waits only while something marked is still visible, so a genuinely
# incomplete sweep still fails, just ~a minute later.
$after = [ordered]@{}
$deadline = (Get-Date).AddSeconds(90)
do {
    $stillMarked = 0
    foreach ($t in $tenants) {
        $after[$t.tenantId] = Get-TenantInventory -T $t
        foreach ($kind in @('users', 'groups', 'aus')) {
            $stillMarked += @(@($after[$t.tenantId].$kind) | Where-Object { Test-PimScenarioOwnedName -Name $_ }).Count
        }
    }
    if ($stillMarked -eq 0) { break }
    if ((Get-Date) -ge $deadline) { Write-Host "  (still $stillMarked marked object(s) visible after the settle budget -- reporting as-is)" -ForegroundColor DarkYellow; break }
    Write-Host "  $stillMarked marked object(s) still listed -- waiting for the delete to settle..." -ForegroundColor DarkGray
    Start-Sleep -Seconds 10
} while ($true)
$storeAfter = Get-StoreInventory

Write-Host "`n-- COMPLETE: nothing marked survives --" -ForegroundColor Yellow
foreach ($t in $tenants) {
    foreach ($kind in @('users', 'groups', 'aus')) {
        $left = @(@($after[$t.tenantId].$kind) | Where-Object { Test-PimScenarioOwnedName -Name $_ })
        Assert ("{0}: no marked {1} remain{2}" -f $t.name, $kind, $(if (@($left).Count) { " (left: $($left -join ', '))" } else { '' })) (@($left).Count -eq 0)
    }
}
$leftStore = @($storeAfter.GetEnumerator() | ForEach-Object { @($_.Value) | Where-Object { Test-PimScenarioOwnedName -Name $_ } })
Assert ("scratch store: no marked rows remain{0}" -f $(if (@($leftStore).Count) { " (left: $($leftStore -join ', '))" } else { '' })) (@($leftStore).Count -eq 0)
Assert "the sweep reported success (exit 0, nothing stranded)" ($sweepExit -eq 0 -or $null -eq $sweepExit)

Write-Host "`n-- CONTAINED: every UNMARKED object is still there --" -ForegroundColor Yellow
foreach ($t in $tenants) {
    foreach ($kind in @('users', 'groups', 'aus')) {
        $keepBefore = @(@($before[$t.tenantId].$kind) | Where-Object { -not (Test-PimScenarioOwnedName -Name $_) })
        $nowSet = @{}; foreach ($n in @($after[$t.tenantId].$kind)) { $nowSet["$n"] = $true }
        $missing = @($keepBefore | Where-Object { -not $nowSet.ContainsKey("$_") })
        Assert ("{0}: no unmarked {1} was removed{2}" -f $t.name, $kind, $(if (@($missing).Count) { " (MISSING: $($missing -join ', '))" } else { '' })) (@($missing).Count -eq 0)
    }
}
foreach ($k in @($storeBefore.Keys)) {
    $keepBefore = @(@($storeBefore[$k]) | Where-Object { -not (Test-PimScenarioOwnedName -Name $_) })
    $nowSet = @{}; foreach ($n in @($storeAfter[$k])) { $nowSet["$n"] = $true }
    $missing = @($keepBefore | Where-Object { -not $nowSet.ContainsKey("$_") })
    Assert ("store {0}: no unmarked row was removed" -f $k) (@($missing).Count -eq 0)
}

Write-Host "`n=== $pass passed / $fail failed ===" -ForegroundColor $(if ($fail) { 'Red' } else { 'Green' })
if ($fail) { exit 1 }
exit 0
