#Requires -Version 5.1
<#
  PIM4EntraPS -- NO-PERSON-DB-ADMIN part D2 (framework 12.23 / SEC-08): the database job's SCHEMA UPGRADE step.
  Dot-sourced by tools/pim-engine/dbinit-job-entry.ps1; offline-tested by tests/Test-PimDbAdminWindow.ps1 (section F).

  WHY IT EXISTS
    On an EXISTING install the deploy's 'schema' step used to connect AS THE SIGNED-IN PERSON (Invoke-PimUpdate -SchemaOnly
    -InstallSqlAccessModel), so the person had to be made a database admin for that run. The deploy now starts ONE execution
    of the install's own database job (ca-pim-dbinit / caj-pim-dbinit, its own identity) with the EMPTY body (Invardia decision
    A: nothing written on the job) when the job's own image is the deploy's version; the job's own definition (PIM_DBINIT_SCHEMA)
    runs this step on an existing store (PIM_DBINIT_SCHEMA_UPGRADE=1 asks it explicitly), doing the same work from inside:
      1. the store's core tables (Initialize-PimSqlStore -- idempotent)
      2. the shipped schema file(s) behind the SAME store-aware guard the updater uses (Get-PimSchemaFileApplyPlan: no DROP
         TABLE / TRUNCATE / DELETE / UPDATE, a DROP COLUMN only when guarded AND the column is absent here) -- every file is
         checked BEFORE any of them runs
      3. CREATE before ALTER: the conformance DDL of every existing, non-conformant locked table (New-PimSqlConformanceDdl);
         a plan that would DROP a column REFUSES (an unattended step never destroys data)
      4. re-preflight against what is now really in the database; drift left = failed
    The base-schema step of the job still only CREATES an empty store; this step is the upgrade.

  RULES (Test-PimDbAdminWindow F): ASCII only; PS 5.1 + 7; no az, no modules; no SQL of its own except the column reads --
  every statement it runs is a shipped schema file or the conformance builder's DDL; never throws (returns ok / reason).
#>
Set-StrictMode -Off

function Get-PimDbInitSchemaUpgradeSetting { <# PURE. LITERAL. The per-execution setting that asks for this step. #> return 'PIM_DBINIT_SCHEMA_UPGRADE' }
function Get-PimDbInitSchemaUpgradeStepId { <# PURE. LITERAL. The step id (Get-PimDbInitStepIds; class 'schema': never beside a run). #> return 'schema-upgrade' }
function Get-PimDbInitSchemaUpgradeFiles { <# PURE. LITERAL. The shipped base-schema file(s), relative to the solution root. #> return @('sql/platform-schema.sql') }

function Test-PimDbInitSchemaUpgradeAsked {
    <# PURE. Is the step asked for by its setting's value? Only an explicit yes ('1' / 'true' / 'yes', any case). #>
    param([AllowNull()][AllowEmptyString()][string]$Value)
    return ("$Value".Trim().ToLowerInvariant() -in @('1', 'true', 'yes'))
}

function Split-PimDbInitSqlBatches {
    <# PURE. A shipped .sql text split on GO (a client-side batch separator, never sent to the server). #>
    param([AllowEmptyString()][string]$Sql)
    return @(("$Sql" -split '(?im)^\s*GO\s*$') | Where-Object { "$_".Trim() })
}

function Invoke-PimDbInitSchemaUpgrade {
    <#
      The schema upgrade of an EXISTING (or new) store, from inside, as the database job's own identity.
        -Query       : param([string]$Sql, [hashtable]$Parameters) -> rows (objects with named columns); throws on an error
        -Exec        : param([string]$Sql) -> runs ONE batch; throws on an error
        -InitStore   : param() -> the store's core tables (Initialize-PimSqlStore over the job's connection); throws on an error
        -SolutionRoot: where sql/platform-schema.sql is (the image's own copy -- the deploy started the job on ITS image)
        -LockedSchema: Get-PimLockedSqlSchema's answer (passed in: tests give a small one)
      Returns @{ ok; reason; applied = @(files); altered = @(tables); lines = @() }. Never throws.
    #>
    param([Parameter(Mandatory)][scriptblock]$Query, [Parameter(Mandatory)][scriptblock]$Exec, [scriptblock]$InitStore,
          [Parameter(Mandatory)][string]$SolutionRoot, [Parameter(Mandatory)][hashtable]$LockedSchema, [string]$Version = '')
    $o = [ordered]@{ ok = $false; reason = ''; applied = @(); altered = @(); lines = @() }
    $lines = New-Object System.Collections.Generic.List[string]
    $readCols = {
        $cols = @{}
        foreach ($t in @($LockedSchema.Keys)) {
            $p = "$t" -split '\.'
            $rows = @(& $Query 'SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA=@s AND TABLE_NAME=@t' @{ s = $p[0]; t = $p[-1] })
            if ($rows.Count) { $cols["$t"] = @($rows | ForEach-Object { "$($_.COLUMN_NAME)" }) }
        }
        return $cols
    }
    try {
        # 1. the core tables (idempotent: every object IF OBJECT_ID ... IS NULL)
        if ($InitStore) { & $InitStore; $lines.Add('core tables present (pim.Rows / pim.Settings / pim.AuditEvents)') }
        # 2. the shipped file(s): ALL checked before ANY runs (a refusal applies nothing)
        $colProbe = {
            param([string]$Table, [string]$Column)
            $r = @(& $Query 'SELECT CASE WHEN COL_LENGTH(@t, @c) IS NULL THEN 0 ELSE 1 END AS e' @{ t = $Table; c = $Column })
            if (-not $r.Count) { throw "no answer for COL_LENGTH($Table, $Column)" }
            ([int]"$($r[0].e)") -eq 1
        }   # a PLAIN scriptblock (never .GetNewClosure(): a closure is bound to a new module and cannot see the store functions $Query calls)
        $files = @()
        foreach ($rel in @(Get-PimDbInitSchemaUpgradeFiles)) {
            $f = Join-Path $SolutionRoot $rel
            if (-not (Test-Path -LiteralPath $f)) { $o.reason = "the shipped schema file '$rel' is missing from this image -- nothing applied"; $o.lines = @($lines.ToArray()); return [pscustomobject]$o }
            $txt = [IO.File]::ReadAllText($f)
            $fp = Get-PimSchemaFileApplyPlan -Sql $txt -Name $rel -ColumnExists $colProbe
            if (-not $fp.ok) { $o.reason = "the shipped schema file '$rel' is REFUSED for an unattended apply: $(@($fp.violations) -join '; ') -- nothing applied"; $o.lines = @($lines.ToArray()); return [pscustomobject]$o }
            $files += @{ rel = $rel; sql = $txt }
        }
        foreach ($s in $files) {
            $n = 0
            foreach ($b in @(Split-PimDbInitSqlBatches -Sql $s.sql)) { & $Exec $b; $n++ }
            $o.applied += $s.rel
            $lines.Add("applied $($s.rel) ($n batch(es); idempotent, guarded additions reach an existing store)")
        }
        # 3. CREATE before ALTER: plan against what is NOW really there
        $cols = & $readCols
        $plan = Get-PimSqlUpdatePlan -DeployedColumns $cols -LockedSqlSchema $LockedSchema -PulledSchemaVersion $Version -DeployedSchemaVersion $Version
        $absent = @($plan.tables | Where-Object { $_.exists -eq $false } | ForEach-Object { "$($_.table)" })
        if ($absent.Count) { $o.reason = "the shipped schema was applied but these table(s) are still absent: $($absent -join ', ')"; $o.lines = @($lines.ToArray()); return [pscustomobject]$o }
        $ddls = @()
        foreach ($tp in @($plan.tables | Where-Object { $_.exists -and -not $_.conformant })) {
            $act = @(if ($cols.ContainsKey("$($tp.table)")) { $cols["$($tp.table)"] } else { @() })
            $d = New-PimSqlConformanceDdl -Table "$($tp.table)" -Spec $LockedSchema["$($tp.table)"] -ActualColumns $act
            if (@($d.plan.ToDrop).Count) { $o.reason = "the upgrade of $($tp.table) would DROP column(s) $(@($d.plan.ToDrop) -join ', ') -- REFUSED (an unattended step never destroys data; nothing altered)"; $o.lines = @($lines.ToArray()); return [pscustomobject]$o }
            $ddls += @{ table = "$($tp.table)"; ddl = "$($d.ddl)" }
        }
        foreach ($d in $ddls) {
            foreach ($b in @(Split-PimDbInitSqlBatches -Sql $d.ddl)) { & $Exec $b }
            $o.altered += $d.table
            $lines.Add("altered $($d.table) (conformance DDL, additive)")
        }
        # 4. re-preflight
        $re = Get-PimSqlUpdatePlan -DeployedColumns (& $readCols) -LockedSqlSchema $LockedSchema -PulledSchemaVersion $Version -DeployedSchemaVersion $Version
        if ($re.SqlUpdateRequired) { $o.reason = "the re-preflight still reports drift: $($re.reason)"; $o.lines = @($lines.ToArray()); return [pscustomobject]$o }
        $o.ok = $true
        $o.reason = "schema up to date ($(@($o.applied).Count) file(s) applied, $(@($o.altered).Count) table(s) altered) -- as the database job's own identity"
    } catch { $o.ok = $false; $o.reason = "the schema upgrade stopped: $($_.Exception.Message)" }
    $o.lines = @($lines.ToArray())
    return [pscustomobject]$o
}
