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
    [switch]$SeedSettings = $true,
    # Report which files WOULD be imported, and which are ignored, without touching SQL at all.
    # Answering "will this pick up my data?" should not require a database.
    [switch]$ListOnly,
    # 2026-09-13 (SQL-only): where the pre-v2 instance kept its runtime files (alerts, scheduler
    # state, template-state, audit). Defaults to the 'output' folder next to -ConfigDir.
    [string]$OutputDir,
    # The folder holding <type>.mailtemplate.custom.html overrides. Defaults to the solution's templates\mail.
    [string]$MailTemplateDir
)
$ErrorActionPreference = 'Stop'
$shared = Join-Path (Split-Path -Parent $PSScriptRoot) 'engine\_shared'

function Import-PimMigrateWorkloadExemptions {
    # Import a v1 PIM-WorkloadExemptions.custom.json into pim.Settings['WorkloadExemptions'] via
    # Save-PimWorkloadExemptions. Returns @{ imported; kept; dropped; existing; message; error }.
    # Never overwrites a store that already holds exemptions.
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Shared)
    if (-not (Get-Command Save-PimWorkloadExemptions -ErrorAction SilentlyContinue)) { . (Join-Path $Shared 'PIM-WorkloadMap.ps1') }
    $prevCs = $global:PIM_SqlConnectionString
    $global:PIM_SqlConnectionString = $ConnectionString   # the WorkloadMap store seam writes through this when no Set-PimSetting bridge exists
    try {
        $doc = $null
        try { $doc = (Get-Content -LiteralPath $Path -Raw -Encoding UTF8) | ConvertFrom-Json } catch {
            return [pscustomobject]@{ imported = 0; kept = 0; dropped = 0; existing = 0; message = ''; error = "PIM-WorkloadExemptions.custom.json is not valid JSON: $($_.Exception.Message)" }
        }
        $all = @(Read-PimWorkloadExemptions -Config $doc)
        $existing = @(Read-PimWorkloadExemptions)
        if ($existing.Count) {
            return [pscustomobject]@{ imported = 0; kept = $existing.Count; dropped = 0; existing = $existing.Count
                message = ("store already holds {0} exemption(s) -- KEPT; the file's {1} entr(ies) were not imported" -f $existing.Count, $all.Count); error = '' }
        }
        $saved = @(Save-PimWorkloadExemptions -Exemptions $all)
        $dropped = $all.Count - $saved.Count
        $msg = "{0} imported into pim.Settings['WorkloadExemptions']" -f $saved.Count
        if ($dropped) { $msg += ("; {0} malformed entr(ies) DROPPED (each needs a reason and an expiresOn, or noExpiry)" -f $dropped) }
        return [pscustomobject]@{ imported = $saved.Count; kept = 0; dropped = $dropped; existing = 0; message = $msg; error = '' }
    } catch {
        return [pscustomobject]@{ imported = 0; kept = 0; dropped = 0; existing = 0; message = ''; error = "workload exemptions import failed: $($_.Exception.Message)" }
    } finally {
        $global:PIM_SqlConnectionString = $prevCs
    }
}
function Import-PimMigrateFileStores {
    <#
      2026-09-13 (SQL-only): carry a pre-v2 instance's remaining FILE stores into SQL ONCE. The
      runtime no longer reads any of them. Each is imported only when the target store is still
      EMPTY -- a re-run never overwrites what an operator has since changed in the Manager -- and
      every file is left untouched. Returns one report row per store found:
        @{ store; file; imported; kept; message; error }
        config/PIM-WarningOverrides.custom.json        -> pim.Settings['WarningOverrides']
        config/exemptions.json                         -> pim.Settings['ConformanceExemptions']
        config/PIM4EntraPS.NamingConventions.custom.ps1 -> pim.Settings (one row per key it changes
                                                          from the shipped default; a key already
                                                          edited in SQL is kept)
        output/alerts/pim-alerts.jsonl                 -> pim.Settings['AlertFeed']
        output/scheduler/pim-scheduler-state.json      -> pim.Settings['SchedulerState']
        output/scheduler/pim-scheduler-runs.json       -> pim.Settings['JobRunHistory']
        output/scheduler/pim-scheduler-acks.json       -> pim.Settings['JobAcknowledgements']
        output/state/template-state.json               -> pim.Settings['ConformanceTemplateState']
        templates/mail/<type>.mailtemplate.custom.html -> pim.Settings['MailTemplates'] (edited entry)
      Reported, not imported: output/audit/pim-audit-*.jsonl (use Import-PimAuditFileTrail.ps1) and
      the tenant-list caches (rebuilt by the tenant-cache job into pim.TenantCache).
    #>
    param(
        [Parameter(Mandatory)][string]$ConnectionString,
        [Parameter(Mandatory)][string]$ConfigDir,
        [string]$OutputDir,
        [string]$MailTemplateDir,
        [Parameter(Mandatory)][string]$Shared
    )
    $rows = New-Object System.Collections.Generic.List[object]
    $readText = { param($p) $x = [System.IO.File]::ReadAllText($p, (New-Object System.Text.UTF8Encoding($false))); if ($x.Length -gt 0 -and [int][char]$x[0] -eq 0xFEFF) { $x = $x.Substring(1) }; $x }
    $isEmpty = {
        param($name)
        $v = Get-PimSqlSetting -ConnectionString $ConnectionString -Name $name
        if ($null -eq $v) { return $true }
        if ($v -is [string] -and -not "$v".Trim()) { return $true }
        return $false
    }
    $importDoc = {
        param([string]$Store, [string]$File, [scriptblock]$Parse)
        if (-not (Test-Path -LiteralPath $File)) { return }
        $row = [ordered]@{ store = $Store; file = $File; imported = $false; kept = $false; message = ''; error = '' }
        try {
            if (-not (& $isEmpty $Store)) { $row.kept = $true; $row.message = "pim.Settings['$Store'] already holds a value -- KEPT; the file was not imported" }
            else {
                $value = & $Parse $File
                Set-PimSqlSetting -ConnectionString $ConnectionString -Name $Store -Value $value
                $row.imported = $true; $row.message = "imported into pim.Settings['$Store']"
            }
        } catch { $row.error = "$Store import failed: $($_.Exception.Message)" }
        $rows.Add([pscustomobject]$row)
    }

    # --- config/ -------------------------------------------------------------------------------
    & $importDoc 'WarningOverrides' (Join-Path $ConfigDir 'PIM-WarningOverrides.custom.json') { param($f) (& $readText $f) | ConvertFrom-Json }
    & $importDoc 'ConformanceExemptions' (Join-Path $ConfigDir 'exemptions.json') { param($f) $d = (& $readText $f) | ConvertFrom-Json; @{ exemptions = @($d.exemptions) } }

    $ncCustom = Join-Path $ConfigDir 'PIM4EntraPS.NamingConventions.custom.ps1'
    if (Test-Path -LiteralPath $ncCustom) {
        $row = [ordered]@{ store = 'NamingConventions (per key)'; file = $ncCustom; imported = $false; kept = $false; message = ''; error = '' }
        $prevNc = $global:PIM_NamingConventions
        try {
            $locked = @{}
            $lockedFile = Join-Path $ConfigDir 'PIM4EntraPS.NamingConventions.locked.ps1'
            if (-not (Test-Path -LiteralPath $lockedFile)) { $lockedFile = Join-Path (Split-Path -Parent $Shared) '..\config\PIM4EntraPS.NamingConventions.locked.ps1' }
            $global:PIM_NamingConventions = @{}
            if (Test-Path -LiteralPath $lockedFile) { . $lockedFile }
            if ($global:PIM_NamingConventions -is [System.Collections.IDictionary]) { foreach ($k in @($global:PIM_NamingConventions.Keys)) { $locked[$k] = $global:PIM_NamingConventions[$k] } }
            $global:PIM_NamingConventions = @{}
            foreach ($k in @($locked.Keys)) { $global:PIM_NamingConventions[$k] = $locked[$k] }
            . $ncCustom
            $custom = $global:PIM_NamingConventions
            $stored = Get-PimAllSqlSettings -ConnectionString $ConnectionString
            $set = 0; $keptKeys = @()
            foreach ($k in @($custom.Keys)) {
                $cj = ConvertTo-Json -InputObject $custom[$k] -Depth 8 -Compress
                $lj = if ($locked.ContainsKey($k)) { ConvertTo-Json -InputObject $locked[$k] -Depth 8 -Compress } else { $null }
                if ($cj -eq $lj) { continue }                                     # not a customisation
                if ($stored.ContainsKey($k)) {
                    $sj = ConvertTo-Json -InputObject $stored[$k] -Depth 8 -Compress
                    if ($sj -eq $cj) { continue }                                  # already imported
                    if ($null -ne $lj -and $sj -ne $lj) { $keptKeys += $k; continue } # edited in SQL since: keep
                }
                Set-PimSqlSetting -ConnectionString $ConnectionString -Name $k -Value $custom[$k]
                $set++
            }
            $row.imported = ($set -gt 0); $row.kept = ($keptKeys.Count -gt 0)
            $row.message = "{0} customised key(s) imported into pim.Settings" -f $set
            if ($keptKeys.Count) { $row.message += ("; {0} key(s) already changed in SQL were KEPT: {1}" -f $keptKeys.Count, ($keptKeys -join ', ')) }
        } catch { $row.error = "NamingConventions.custom.ps1 import failed: $($_.Exception.Message)" }
        finally { $global:PIM_NamingConventions = $prevNc }
        $rows.Add([pscustomobject]$row)
    }

    # --- output/ -------------------------------------------------------------------------------
    if ("$OutputDir".Trim() -and (Test-Path -LiteralPath $OutputDir)) {
        & $importDoc 'AlertFeed' (Join-Path $OutputDir 'alerts\pim-alerts.jsonl') {
            param($f)
            if (-not (Get-Command Select-PimAlertFeed -ErrorAction SilentlyContinue)) { . (Join-Path $Shared 'PIM-AlertFeed.ps1') }
            $list = New-Object System.Collections.Generic.List[object]
            foreach ($line in ((& $readText $f) -split "`r?`n")) { if ("$line".Trim()) { try { $list.Add(("$line" | ConvertFrom-Json)) } catch { } } }
            @{ alerts = @(Select-PimAlertFeed -Feed $list.ToArray() -Take 500) }
        }
        # The scheduler documents are stored as JSON TEXT, exactly as Save-PimSchedulerState writes them.
        & $importDoc 'SchedulerState'      (Join-Path $OutputDir 'scheduler\pim-scheduler-state.json') { param($f) (& $readText $f) }
        & $importDoc 'JobRunHistory'       (Join-Path $OutputDir 'scheduler\pim-scheduler-runs.json')  { param($f) (& $readText $f) }
        & $importDoc 'JobAcknowledgements' (Join-Path $OutputDir 'scheduler\pim-scheduler-acks.json')  { param($f) (& $readText $f) }
        & $importDoc 'ConformanceTemplateState' (Join-Path $OutputDir 'state\template-state.json')          { param($f) ((& $readText $f) | ConvertFrom-Json | ConvertTo-Json -Depth 8 -Compress) }
        $auditFiles = @(Get-ChildItem -LiteralPath (Join-Path $OutputDir 'audit') -Filter 'pim-audit-*.jsonl' -File -ErrorAction SilentlyContinue)
        if ($auditFiles.Count) {
            $rows.Add([pscustomobject]@{ store = 'AuditEvents'; file = (Join-Path $OutputDir 'audit'); imported = $false; kept = $false
                message = ("{0} pre-v2 audit file(s) found -- NOT imported here; carry them into pim.AuditEvents with tools/pim-manager/Import-PimAuditFileTrail.ps1" -f $auditFiles.Count); error = '' })
        }
    }

    # --- templates/mail/*.mailtemplate.custom.html -> the ONE mail template store -------------------
    if ("$MailTemplateDir".Trim() -and (Test-Path -LiteralPath $MailTemplateDir)) {
        $customs = @(Get-ChildItem -LiteralPath $MailTemplateDir -Filter '*.mailtemplate.custom.html' -File -ErrorAction SilentlyContinue)
        if ($customs.Count) {
            if (-not (Get-Command Update-PimMailTemplateStore -ErrorAction SilentlyContinue)) { . (Join-Path $Shared 'PIM-MailTemplateStore.ps1') }
            [void](Update-PimMailTemplateStore -ConnectionString $ConnectionString -TemplateDir $MailTemplateDir -Actor 'migrate')
            foreach ($cf in $customs) {
                $type = $cf.Name -replace '\.mailtemplate\.custom\.html$', ''
                $row = [ordered]@{ store = "MailTemplates[$type]"; file = $cf.FullName; imported = $false; kept = $false; message = ''; error = '' }
                try {
                    $doc = Get-PimMailTemplateStoreDocument -ConnectionString $ConnectionString
                    if ($null -ne $doc.templates[$type] -and $doc.templates[$type].source -eq 'edited') { $row.kept = $true; $row.message = 'the store already holds an edited template -- KEPT' }
                    else {
                        Set-PimMailTemplateStoreEntry -ConnectionString $ConnectionString -Type $type -Body (& $readText $cf.FullName) -By 'migrated from .mailtemplate.custom.html' -TemplateDir $MailTemplateDir
                        $row.imported = $true; $row.message = "imported into pim.Settings['MailTemplates'] as an edited template"
                    }
                } catch { $row.error = "mail template '$type' import failed: $($_.Exception.Message)" }
                $rows.Add([pscustomobject]$row)
            }
        }
    }
    return $rows.ToArray()
}
. (Join-Path $shared 'PIM-ChangeQueue.ps1')
. (Join-Path $shared 'PIM-Rest.ps1')
. (Join-Path $shared 'PIM-SqlStore.ps1')
# Default only for the solution layout (<root>\config next to <root>\output): an arbitrary data folder
# must not pick up whatever 'output' folder happens to sit beside it.
if (-not "$OutputDir".Trim() -and (Split-Path -Leaf $ConfigDir) -like 'config*') { $OutputDir = Join-Path (Split-Path -Parent $ConfigDir) 'output' }
if (-not "$MailTemplateDir".Trim()) { $MailTemplateDir = Join-Path (Split-Path -Parent $PSScriptRoot) 'templates\mail' }

if (-not $ListOnly) {
    if (-not $ConnectionString) { $ConnectionString = Get-PimSqlConnectionString -Server $Server -Database $Database }
    if (-not (Test-PimSqlConnectivity -ConnectionString $ConnectionString)) { throw "SQL not reachable with the supplied connection." }

    Write-Host "Initializing SQL store (idempotent) ..." -ForegroundColor Cyan
    if ($PSCmdlet.ShouldProcess($Database, 'Initialize-PimSqlStore')) { Initialize-PimSqlStore -ConnectionString $ConnectionString }
}

# 🔴 TAKE THE FILES AS THE CUSTOMER HAS THEM. This used to match ONLY '*.custom.csv', so a v1
# data folder -- where the files are plainly 'PIM-Definitions-Roles.csv' -- imported NOTHING and
# said nothing: `Get-ChildItem -Filter` simply returned no matches, the loop body never ran, and
# the script reported "Migration complete: 0 entities". An import that silently does nothing is
# indistinguishable from one that worked, until somebody opens the Manager and finds it empty.
# Renaming a customer's data files to suit our filter is not their job.
#
# Accepted, in precedence order per entity: <base>.custom.csv, then <base>.csv, then
# <base>.locked.csv. The FIRST one found wins, and the others are reported as ignored rather than
# quietly dropped.
$PimEntityBases = @(
    'Account-Definitions-Admins','PIM-Definitions-Roles','PIM-Definitions-Tasks',
    'PIM-Definitions-Services','PIM-Definitions-Processes','PIM-Definitions-Resources',
    'PIM-Definitions-Departments','PIM-Definitions-Organization','PIM-Definitions-AU',
    'PIM-Assignments-Admins','PIM-Assignments-Groups','PIM-Assignments-Roles-Groups',
    'PIM-Assignments-Roles-AUs','PIM-Assignments-Azure-Resources','PIM-Assignments-Workloads'
)
# 🪤 A v1 data folder holds much more than PIM's own entities -- CMDB, Device_Tagging,
# Identity_Tagging, Onboarding-Groups, Azure-Tags-*, plus the engine's own _Delta and _LastApplied
# working files. Importing those would create entities the Manager never reads; importing a
# _LastApplied as if it were desired state would be worse. Only the known bases are taken, and
# everything else is LISTED as skipped so the operator can see the decision rather than trust it.
$byBase = [ordered]@{}
$ignored = New-Object System.Collections.Generic.List[string]
foreach ($f in (Get-ChildItem -LiteralPath $ConfigDir -Filter '*.csv' -File | Sort-Object Name)) {
    $b = $f.BaseName -replace '\.(custom|locked)$', ''
    $match = @($PimEntityBases | Where-Object { $_ -eq $b }) | Select-Object -First 1
    if (-not $match) { [void]$ignored.Add($f.Name); continue }
    $rank = if ($f.BaseName -match '\.custom$') { 0 } elseif ($f.BaseName -match '\.locked$') { 2 } else { 1 }
    if (-not $byBase.Contains($match) -or $rank -lt $byBase[$match].rank) {
        $byBase[$match] = @{ file = $f; rank = $rank }
    } elseif ($byBase.Contains($match)) { [void]$ignored.Add("$($f.Name) (superseded by $($byBase[$match].file.Name))") }
}
if ($ignored.Count) {
    Write-Host ("  [migrate] ignored {0} file(s) that are not PIM entity data:" -f $ignored.Count) -ForegroundColor DarkGray
    $ignored | ForEach-Object { Write-Host "      $_" -ForegroundColor DarkGray }
}
if (-not $byBase.Count) {
    throw ("No PIM entity CSVs found in '$ConfigDir'. Expected one or more of: " + ($PimEntityBases -join ', ') +
           " (as <name>.csv or <name>.custom.csv). Refusing to report a migration that moved nothing.")
}

if ($ListOnly) {
    Write-Host ''
    Write-Host ("  WOULD IMPORT {0} entit(ies) from '{1}':" -f $byBase.Count, $ConfigDir) -ForegroundColor Cyan
    foreach ($b in $byBase.Keys) { Write-Host ("      {0,-34} <- {1}" -f $b, $byBase[$b].file.Name) -ForegroundColor Green }
    $missing = @($PimEntityBases | Where-Object { -not $byBase.Contains($_) })
    if ($missing.Count) {
        Write-Host ("  NOT PRESENT ({0}) -- these entities keep whatever the store already holds:" -f $missing.Count) -ForegroundColor DarkGray
        $missing | ForEach-Object { Write-Host "      $_" -ForegroundColor DarkGray }
    }
    Write-Host ''
    return ,@($byBase.Keys)
}

$report = New-Object System.Collections.Generic.List[object]
$failedEntities = New-Object System.Collections.Generic.List[object]
foreach ($base in $byBase.Keys) {
    $f = $byBase[$base].file
    try {
        # 🪤 DETECT THE DELIMITER, do not assume ';'. A comma-separated export parsed with ';'
        # yields ONE column per row -- no error, no warning, and every field lost. The header line
        # answers the question, so ask it.
        $head = (Get-Content -LiteralPath $f.FullName -TotalCount 1)
        $delim = if ("$head".Split(';').Count -ge "$head".Split(',').Count) { ';' } else { ',' }
        $rows = @(Import-Csv -Path $f.FullName -Delimiter $delim -Encoding UTF8)
        Write-Host ("  [migrate] {0}  <- {1} (delimiter '{2}')" -f $base, $f.Name, $delim) -ForegroundColor DarkGray
        if ($PSCmdlet.ShouldProcess("$base ($($rows.Count) rows)", 'migrate -> pim.Rows')) {
            # 🔴 §52.18b -- ONE CONNECTION PER ENTITY, NOT ONE PER ROW.
            # Set-PimSqlEntityRows calls Set-PimSqlRow once per row, and each of those opens and
            # closes its own connection. Disposing them (the §52.18 fix) returns each to its pool,
            # but a connection carrying an Entra ACCESS TOKEN cannot share a pool with one carrying
            # a different token -- so every freshly-minted token is a NEW pool holding a NEW
            # physical session, and the sessions sit there idle rather than closing.
            # Measured at a live customer 2026-09-10, on a database already raised to 900 sessions:
            #     PIM-Definitions-Tasks skipped: ... The session limit for the database is 900 and
            #     has been reached.
            # after twelve entities and ~565 rows had gone through. Raising the tier moved the
            # number the import dies at; it did not change the shape.
            # 🔑 The transactional variant has IDENTICAL semantics -- upsert by natural key, delete
            # keys no longer submitted -- on ONE connection inside ONE transaction. Fifteen entities
            # therefore cost fifteen sessions instead of six hundred, and an entity that fails
            # part-way rolls back instead of leaving half its rows applied, which is what a re-run
            # then has to reason about.
            $res = Set-PimSqlEntityRowsTransactional -ConnectionString $ConnectionString -Entity $base -Base $base -Rows $rows
            Write-Host ("  [migrate] {0}: {1} rows -> SQL" -f $base, $res.rowCount) -ForegroundColor Green
            $report.Add([pscustomobject]@{ entity = $base; rows = $res.rowCount; removed = $res.removed })
        } else {
            Write-Host ("  [migrate][WhatIf] {0}: {1} rows" -f $base, $rows.Count) -ForegroundColor Yellow
            $report.Add([pscustomobject]@{ entity = $base; rows = $rows.Count; removed = 0 })
        }
    } catch {
        # 🔴 A SKIPPED ENTITY IS A FAILED MIGRATION, NOT A WARNING.
        # This printed a warning, kept going, and then announced "Migration complete: 12 entities"
        # with exit 0 -- so the operator's own report of the run above said COMPLETE over a
        # database that had rejected an entity. Recorded and made fatal at the end, so the exit
        # code and the last line agree with what actually happened.
        Write-Warning "  [migrate] $base FAILED: $($_.Exception.Message)"
        [void]$failedEntities.Add([pscustomobject]@{ entity = $base; error = "$($_.Exception.Message)" })
    }
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
    # PIM policy templates live in SQL too (2026-09-12): seed the SHIPPED templates on a fresh store, upgrade
    # unmodified ones, keep + flag customised ones (Update-PimPolicyTemplateStore). v1
    # *.policytemplate.custom.json overrides are NOT imported -- only shipped templates apply.
    if ($PSCmdlet.ShouldProcess('pim.Settings', 'seed PolicyTemplates from the shipped templates')) {
        . (Join-Path $shared 'PIM-PolicyBaseline.ps1')
        . (Join-Path $shared 'PIM-PolicyTemplateStore.ps1')
        $pt = Initialize-PimPolicyTemplateStore -ConnectionString $ConnectionString -TemplateDir (Join-Path (Split-Path -Parent $PSScriptRoot) 'templates\policy')
        Write-Host ("  [migrate] policy templates: {0} in SQL -- {1}" -f $pt.count, $pt.reason) -ForegroundColor Green
    }
    # Workload exemptions live in pim.Settings['WorkloadExemptions'] (2026-09-12). A v1 folder keeps them
    # in PIM-WorkloadExemptions.custom.json: import it ONCE, through Save-PimWorkloadExemptions so a
    # malformed entry (no reason, no expiry) is refused at the door exactly as the Manager refuses it.
    # A store that already holds exemptions is KEPT -- a re-run must not overwrite what an operator has
    # since edited in the Manager.
    $wexFile = Join-Path $ConfigDir 'PIM-WorkloadExemptions.custom.json'
    if ((Test-Path -LiteralPath $wexFile) -and $PSCmdlet.ShouldProcess('pim.Settings', 'import WorkloadExemptions from PIM-WorkloadExemptions.custom.json')) {
        $wexResult = Import-PimMigrateWorkloadExemptions -ConnectionString $ConnectionString -Path $wexFile -Shared $shared
        $wexColor = if ($wexResult.imported) { 'Green' } elseif ($wexResult.error) { 'Red' } else { 'Yellow' }
        Write-Host ("  [migrate] workload exemptions: {0}" -f $wexResult.message) -ForegroundColor $wexColor
        if ($wexResult.error) { [void]$failedEntities.Add([pscustomobject]@{ entity = 'WorkloadExemptions'; error = "$($wexResult.error)" }) }
    }
    # The remaining v2 FILE stores (2026-09-13: "PIM v2 is SQL-only, no files"): imported ONCE, each
    # only into an EMPTY store, files untouched. The runtime reads none of these files any more.
    if ($PSCmdlet.ShouldProcess('pim.Settings', 'import the remaining file stores (overrides, exemptions, naming, alert feed, scheduler state, template-state, mail templates)')) {
        $fsRows = @(Import-PimMigrateFileStores -ConnectionString $ConnectionString -ConfigDir $ConfigDir -OutputDir $OutputDir -MailTemplateDir $MailTemplateDir -Shared $shared)
        foreach ($fr in $fsRows) {
            $color = if ($fr.error) { 'Red' } elseif ($fr.imported) { 'Green' } else { 'Yellow' }
            Write-Host ("  [migrate] {0}: {1}" -f $fr.store, $(if ($fr.error) { $fr.error } else { $fr.message })) -ForegroundColor $color
            if ($fr.error) { [void]$failedEntities.Add([pscustomobject]@{ entity = "$($fr.store)"; error = "$($fr.error)" }) }
        }
        $script:PimMigrateFileStoreReport = $fsRows
    }
}

if ($failedEntities.Count) {
    # 🔴 THE LAST LINE MUST AGREE WITH WHAT HAPPENED. This used to print "Migration complete: 12
    # entities" and exit 0 after an entity had been rejected by the database -- so the operator's
    # own transcript said COMPLETE over an import that was not. Every later question ("is the data
    # there?", "why are the mappings missing?") then starts from a false premise.
    Write-Host ''
    Write-Host ("MIGRATION INCOMPLETE -- {0} of {1} entit(ies) FAILED:" -f $failedEntities.Count, ($report.Count + $failedEntities.Count)) -ForegroundColor Red
    foreach ($fe in $failedEntities) { Write-Host ("    {0}: {1}" -f $fe.entity, $fe.error) -ForegroundColor Red }
    Write-Host ("  {0} entit(ies) DID import and are in SQL; each failed entity was rolled back whole, so re-running is safe." -f $report.Count) -ForegroundColor Yellow
    Write-Host '  The CSV files were NOT modified.' -ForegroundColor Yellow
    throw ("Migrate-PimToSql: {0} entit(ies) failed to import -- see above. Refusing to report a completed migration." -f $failedEntities.Count)
}

Write-Host ("`nMigration complete: {0} entities. The CSV files were NOT modified." -f $report.Count) -ForegroundColor Cyan
Write-Host "Next: set StorageBackend=sql (or supply the connection) so the Manager runs in SQL mode." -ForegroundColor Cyan
return $report.ToArray()
