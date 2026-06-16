#Requires -Version 5.1
<#
.SYNOPSIS
    Migrate a PIM4EntraPS instance's CSV config into the SQL store (the SQL-only
    data layer). NON-DESTRUCTIVE: the CSV files are read, never modified. Same
    code targets Azure SQL (prod, via -ConnectionString) or local SQL Express
    (dev). Idempotent -- re-running re-syncs each entity (full-set replace).

.DESCRIPTION
    For each <base>.custom.csv in -ConfigDir: parse rows -> pim.Rows (entity =
    base, key = the base's natural key). Then seed pim.Settings from the naming-
    convention config (file is the seed; SQL becomes authoritative afterwards).
    Connection auth is passwordless: Managed Identity (Azure SQL, via
    $global:PIM_SqlAccessToken) or Integrated (Express). No secret in any file.

    REST-migration note (REQUIREMENTS.md §19): this script is already pure
    SQL-data-plane -- it makes NO Microsoft.Graph or Az.* SDK calls. It uses
    SqlServer/ADO.NET via PIM-SqlStore.ps1 (Initialize-PimSqlStore /
    Set-PimSqlEntityRows / Import-PimSettingsSeed). The only Az touch anywhere
    underneath is an OPTIONAL Get-AzAccessToken fallback for a Key Vault secret
    read inside PIM-SqlStore; the primary path is the launcher-minted token. No
    conversion needed.

.PARAMETER ConfigDir
    The instance config folder (holds <base>.custom.csv + NamingConventions ps1).

.PARAMETER ConnectionString
    Target SQL connection string. Omit to build from -Server/-Database.

.PARAMETER WhatIf
    Report what would migrate without writing.

.EXAMPLE
    # dev (Express)
    .\Migrate-PimToSql.ps1 -ConfigDir ..\config -Server .\SQLEXPRESS -Database PIM4EntraPS
.EXAMPLE
    # prod (Azure SQL; launcher pre-minted the MI token into $global:PIM_SqlAccessToken)
    .\Migrate-PimToSql.ps1 -ConfigDir E:\cust\config -ConnectionString $cs
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$ConfigDir,
    [string]$ConnectionString,
    [string]$Server,
    [string]$Database = 'PIM4EntraPS',
    [switch]$SeedSettings = $true
)
$ErrorActionPreference = 'Stop'
$shared = Join-Path (Split-Path -Parent $PSScriptRoot) 'engine\_shared'
. (Join-Path $shared 'PIM-ChangeQueue.ps1')
. (Join-Path $shared 'PIM-SqlStore.ps1')

if (-not $ConnectionString) { $ConnectionString = Get-PimSqlConnectionString -Server $Server -Database $Database }
if (-not (Test-PimSqlConnectivity -ConnectionString $ConnectionString)) { throw "SQL not reachable with the supplied connection." }

Write-Host "Initializing SQL store (idempotent) ..." -ForegroundColor Cyan
if ($PSCmdlet.ShouldProcess($Database, 'Initialize-PimSqlStore')) { Initialize-PimSqlStore -ConnectionString $ConnectionString }

$report = New-Object System.Collections.Generic.List[object]
foreach ($f in Get-ChildItem -LiteralPath $ConfigDir -Filter '*.custom.csv' -File | Sort-Object Name) {
    $base = $f.BaseName -replace '\.custom$', ''
    try {
        $rows = @(Import-Csv -Path $f.FullName -Delimiter ';' -Encoding UTF8)
        if ($PSCmdlet.ShouldProcess("$base ($($rows.Count) rows)", 'migrate -> pim.Rows')) {
            $res = Set-PimSqlEntityRows -ConnectionString $ConnectionString -Entity $base -Base $base -Rows $rows
            Write-Host ("  [migrate] {0}: {1} rows -> SQL" -f $base, $res.rowCount) -ForegroundColor Green
            $report.Add([pscustomobject]@{ entity = $base; rows = $res.rowCount; removed = $res.removed })
        } else {
            Write-Host ("  [migrate][WhatIf] {0}: {1} rows" -f $base, $rows.Count) -ForegroundColor Yellow
            $report.Add([pscustomobject]@{ entity = $base; rows = $rows.Count; removed = 0 })
        }
    } catch { Write-Warning "  [migrate] $base skipped: $($_.Exception.Message)" }
}

if ($SeedSettings) {
    # Seed pim.Settings from the naming-convention config (file = seed; SQL wins after).
    foreach ($cfg in 'PIM4EntraPS.NamingConventions.locked.ps1','PIM4EntraPS.NamingConventions.custom.ps1') {
        $p = Join-Path $ConfigDir $cfg; if (Test-Path -LiteralPath $p) { try { . $p } catch { Write-Warning "could not load $cfg : $($_.Exception.Message)" } }
    }
    if ($global:PIM_NamingConventions -is [hashtable] -and $PSCmdlet.ShouldProcess('pim.Settings', 'seed from NamingConventions')) {
        $added = Import-PimSettingsSeed -ConnectionString $ConnectionString -Seed $global:PIM_NamingConventions
        Write-Host ("  [migrate] seeded {0} setting(s) into pim.Settings" -f $added) -ForegroundColor Green
    }
}

Write-Host ("`nMigration complete: {0} entities. The CSV files were NOT modified." -f $report.Count) -ForegroundColor Cyan
Write-Host "Next: set StorageBackend=sql (or supply the connection) so the Manager runs in SQL mode." -ForegroundColor Cyan
return $report.ToArray()
