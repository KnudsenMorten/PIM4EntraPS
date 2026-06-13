# PIM4EntraPS -- locked-schema + data conformance (preflight migrator).
# Dot-sourced by PIM-Functions.psm1 (and standalone by the pim-manager).
#
# Problem: a customer migrates an OLD data set (CSV files or a SQL store) whose
# shape predates the current contract -- e.g. it still carries a `TierLevel`
# column that we no longer use (routing is name-marker + Purpose driven now).
# This preflight brings BOTH schema AND data to the LOCKED structure:
#   - add required columns that are missing (blank)
#   - DROP deprecated columns (TierLevel, ...)
#   - MIGRATE data first where a deprecated column has a replacement
#     (TierLevel -> Purpose), so intent is preserved before the column is dropped
#
# Same discipline as the rest of the engine: a LOCKED spec is the single source
# of truth; a PURE planner + pure row/DDL appliers (testable offline, no DB); a
# thin preflight orchestrator that rewrites CSV files / emits idempotent T-SQL.

Set-StrictMode -Off

# --- TierLevel -> Purpose: the one semantic data migration. Tier 0 / L0 / T0
#     markers mean a privileged account (HighPriv); everything else is Day2Day.
function ConvertTo-PimPurposeFromTier {
    param([AllowNull()][string]$TierLevel)
    if ("$TierLevel" -match '(?i)(^|[^a-z0-9])(t0|l0|tier\s*0|tier0)([^a-z0-9]|$)') { return 'HighPriv' }
    return 'Day2Day'
}

# --- THE LOCKED SCHEMA (single source of truth) ---------------------------------
# Per base/table:
#   deprecated : columns to DROP (no longer part of the contract)
#   required   : columns that MUST exist (added blank if missing). For SQL the
#                value is the column's T-SQL type; for CSV any non-empty marker.
#   migrations : data moves applied BEFORE a deprecated column is dropped
#                @{ from; to; whenTargetBlank; map=<scriptblock> }
#   key        : natural key (informational / dedup)
function Get-PimLockedSchema {
    $dropTier = @('TierLevel')
    $genericDef = @{ deprecated = $dropTier; required = @(); migrations = @() }
    return @{
        'Account-Definitions-Admins' = @{
            key = 'UserName'
            deprecated = @('TierLevel')
            required   = @('Purpose','ProvisionDate','TAPLifetimeHours','Template','OffboardDate','DeleteAfterDays')
            migrations = @(@{ from = 'TierLevel'; to = 'Purpose'; whenTargetBlank = $true; map = { param($v) ConvertTo-PimPurposeFromTier -TierLevel "$v" } })
        }
        'PIM-Definitions-Roles'        = $genericDef
        'PIM-Definitions-Tasks'        = $genericDef
        'PIM-Definitions-Services'     = $genericDef
        'PIM-Definitions-Processes'    = $genericDef
        'PIM-Definitions-Resources'    = $genericDef
        'PIM-Definitions-Departments'  = $genericDef
        'PIM-Definitions-Organization' = $genericDef
        'PIM-Definitions-AU'           = $genericDef
        'PIM-Assignments-Admins'          = $genericDef
        'PIM-Assignments-Groups'          = $genericDef
        'PIM-Assignments-Roles-Groups'    = $genericDef
        'PIM-Assignments-Roles-AUs'       = $genericDef
        'PIM-Assignments-Azure-Resources' = $genericDef
    }
}

# SQL table locked spec (the LOCAL store). Same shape; required carries T-SQL types.
function Get-PimLockedSqlSchema {
    return @{
        'pim.LocalAdmins' = @{
            deprecated = @('TierLevel')
            required   = @{ Purpose = "NVARCHAR(20) NOT NULL CONSTRAINT DF_LocalAdmins_Purpose DEFAULT 'Day2Day'" }
            migrations = @(@{ from = 'TierLevel'; to = 'Purpose'; whenTargetBlank = $true; sqlCase = "CASE WHEN [TierLevel] LIKE '%T0%' OR [TierLevel] LIKE '%L0%' OR [TierLevel] LIKE '%Tier0%' THEN 'HighPriv' ELSE 'Day2Day' END" })
        }
    }
}

# --- PURE PLANNER ---------------------------------------------------------------
function Get-PimSchemaConformancePlan {
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$ActualColumns,
        [Parameter(Mandatory)][hashtable]$Spec
    )
    $actual = @{}; foreach ($c in @($ActualColumns)) { $actual["$c".ToLowerInvariant()] = "$c" }
    $reqNames = @()
    if ($Spec.required -is [hashtable]) { $reqNames = @($Spec.required.Keys) } else { $reqNames = @($Spec.required) }
    $toDrop = @(@($Spec.deprecated) | Where-Object { $_ -and $actual.ContainsKey("$_".ToLowerInvariant()) })
    $toAdd  = @($reqNames | Where-Object { $_ -and -not $actual.ContainsKey("$_".ToLowerInvariant()) })
    $toMigrate = @(@($Spec.migrations) | Where-Object { $_ -and $actual.ContainsKey("$($_.from)".ToLowerInvariant()) })
    return [pscustomobject]@{
        ToDrop = $toDrop; ToAdd = $toAdd; ToMigrate = $toMigrate
        Conformant = (($toDrop.Count -eq 0) -and ($toAdd.Count -eq 0) -and ($toMigrate.Count -eq 0))
    }
}

# --- PURE CSV/ROW APPLIER -------------------------------------------------------
# Returns @{ rows = <repaired>; changed = [bool]; plan = <plan> }. Migrates first,
# adds missing (blank), drops deprecated, preserves column order (minus dropped,
# plus appended new). Never mutates the input rows.
function Repair-PimRowsToSchema {
    param(
        [AllowNull()][object[]]$Rows,
        [Parameter(Mandatory)][hashtable]$Spec,
        [string[]]$Columns   # explicit header (so an all-empty file still conforms its header)
    )
    $rows = @($Rows)
    $cols = @()
    if ($Columns) { $cols = @($Columns) }
    elseif ($rows.Count -gt 0) { $cols = @($rows[0].PSObject.Properties.Name) }
    $plan = Get-PimSchemaConformancePlan -ActualColumns $cols -Spec $Spec
    $reqNames = @()
    if ($Spec.required -is [hashtable]) { $reqNames = @($Spec.required.Keys) } else { $reqNames = @($Spec.required) }

    # Final column order: existing minus dropped, then any missing required.
    $dropLc = @{}; foreach ($d in @($plan.ToDrop)) { $dropLc["$d".ToLowerInvariant()] = $true }
    $finalCols = New-Object System.Collections.Generic.List[string]
    foreach ($c in $cols) { if (-not $dropLc.ContainsKey("$c".ToLowerInvariant())) { $finalCols.Add("$c") } }
    foreach ($a in @($plan.ToAdd)) { if (-not ($finalCols | Where-Object { $_ -ieq "$a" })) { $finalCols.Add("$a") } }

    $out = New-Object System.Collections.Generic.List[object]
    foreach ($r in $rows) {
        $get = { param($n) $p = $r.PSObject.Properties["$n"]; if ($p) { $p.Value } else { $null } }
        # data migrations FIRST (read the soon-to-be-dropped source)
        $migrated = @{}
        foreach ($m in @($Spec.migrations)) {
            $srcVal = & $get $m.from
            if ($null -eq $srcVal -or "$srcVal".Trim() -eq '') { continue }
            $tgtVal = & $get $m.to
            if ($m.whenTargetBlank -and "$tgtVal".Trim() -ne '') { continue }   # don't clobber an explicit value
            $migrated[$m.to] = (& $m.map $srcVal)
        }
        $obj = [ordered]@{}
        foreach ($c in $finalCols) {
            if ($migrated.ContainsKey($c)) { $obj[$c] = $migrated[$c] }
            else {
                $v = & $get $c
                $obj[$c] = if ($null -eq $v) { '' } else { $v }
            }
        }
        $out.Add([pscustomobject]$obj)
    }
    return @{ rows = $out.ToArray(); changed = (-not $plan.Conformant); plan = $plan; columns = $finalCols.ToArray() }
}

# --- PURE SQL DDL GENERATOR (idempotent) ----------------------------------------
# Given a table's ACTUAL columns, emit guarded T-SQL that migrates data, drops
# deprecated columns (dropping their default constraints first), and adds missing
# required columns. Every statement is guarded so re-running is a no-op.
function New-PimSqlConformanceDdl {
    param(
        [Parameter(Mandatory)][string]$Table,
        [Parameter(Mandatory)][hashtable]$Spec,
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$ActualColumns
    )
    $plan = Get-PimSchemaConformancePlan -ActualColumns $ActualColumns -Spec $Spec
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine("-- PIM schema conformance for $Table (idempotent; safe to re-run)")
    # 1. data migrations (before drops)
    foreach ($m in @($plan.ToMigrate)) {
        if (-not $m.sqlCase) { continue }
        [void]$sb.AppendLine("IF COL_LENGTH('$Table','$($m.from)') IS NOT NULL AND COL_LENGTH('$Table','$($m.to)') IS NOT NULL")
        $blank = if ($m.whenTargetBlank) { "WHERE ([$($m.to)] IS NULL OR LTRIM(RTRIM([$($m.to)])) = '' OR [$($m.to)] = 'Day2Day') AND [$($m.from)] IS NOT NULL" } else { "WHERE [$($m.from)] IS NOT NULL" }
        [void]$sb.AppendLine("    UPDATE [$($Table.Replace('.','].['))] SET [$($m.to)] = $($m.sqlCase) $blank;")
    }
    # 2. add missing required columns
    if ($Spec.required -is [hashtable]) {
        foreach ($col in @($plan.ToAdd)) {
            $type = "$($Spec.required[$col])"
            if (-not $type) { $type = 'NVARCHAR(200) NULL' }
            [void]$sb.AppendLine("IF COL_LENGTH('$Table','$col') IS NULL ALTER TABLE [$($Table.Replace('.','].['))] ADD [$col] $type;")
        }
    }
    # 3. drop deprecated columns (drop bound default constraint first)
    foreach ($col in @($plan.ToDrop)) {
        [void]$sb.AppendLine("IF COL_LENGTH('$Table','$col') IS NOT NULL")
        [void]$sb.AppendLine("BEGIN")
        [void]$sb.AppendLine("    DECLARE @df_$col SYSNAME = (SELECT dc.name FROM sys.default_constraints dc JOIN sys.columns c ON c.default_object_id = dc.object_id WHERE dc.parent_object_id = OBJECT_ID('$Table') AND c.name = '$col');")
        [void]$sb.AppendLine("    IF @df_$col IS NOT NULL EXEC('ALTER TABLE [$($Table.Replace('.','].['))] DROP CONSTRAINT [' + @df_$col + ']');")
        [void]$sb.AppendLine("    ALTER TABLE [$($Table.Replace('.','].['))] DROP COLUMN [$col];")
        [void]$sb.AppendLine("END")
    }
    return @{ ddl = $sb.ToString(); plan = $plan }
}

# --- THIN PREFLIGHT ORCHESTRATOR (CSV) ------------------------------------------
# Brings every present <base>.custom.csv in $ConfigDir to the locked structure.
# -WhatIfMode reports without writing. Returns a per-base report.
function Invoke-PimSchemaConformancePreflight {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ConfigDir, [switch]$WhatIfMode)
    $schema = Get-PimLockedSchema
    $report = New-Object System.Collections.Generic.List[object]
    foreach ($base in @($schema.Keys)) {
        $path = Join-Path $ConfigDir "$base.custom.csv"
        if (-not (Test-Path -LiteralPath $path)) { continue }
        try {
            $lines = @(Get-Content -LiteralPath $path -Encoding UTF8)
            if ($lines.Count -eq 0) { continue }
            $header = @($lines[0] -split ';' | ForEach-Object { $_.Trim().Trim('"') })
            $rows = @(Import-Csv -Path $path -Delimiter ';' -Encoding UTF8)
            $res = Repair-PimRowsToSchema -Rows $rows -Spec $schema[$base] -Columns $header
            $entry = [ordered]@{ base = $base; changed = $res.changed; dropped = @($res.plan.ToDrop); added = @($res.plan.ToAdd); migrated = @(@($res.plan.ToMigrate) | ForEach-Object { "$($_.from)->$($_.to)" }) }
            if ($res.changed -and -not $WhatIfMode) {
                if (@($res.rows).Count -gt 0) {
                    $res.rows | Select-Object -Property $res.columns | Export-Csv -Path $path -Delimiter ';' -Encoding UTF8 -NoTypeInformation
                } else {
                    # header-only conform (no data rows): rewrite the header line.
                    Set-Content -LiteralPath $path -Value (($res.columns -join ';')) -Encoding UTF8
                }
                $entry['applied'] = $true
                Write-Host ("  [SchemaConf] {0}: dropped[{1}] added[{2}] migrated[{3}]" -f $base, ($res.plan.ToDrop -join ','), ($res.plan.ToAdd -join ','), (@($res.plan.ToMigrate | ForEach-Object { $_.from }) -join ',')) -ForegroundColor Cyan
            } else { $entry['applied'] = $false }
            $report.Add([pscustomobject]$entry)
        } catch {
            Write-Warning ("  [SchemaConf] {0} skipped (left untouched): {1}" -f $base, $_.Exception.Message)
            $report.Add([pscustomobject]@{ base = $base; error = "$($_.Exception.Message)" })
        }
    }
    return $report.ToArray()
}
