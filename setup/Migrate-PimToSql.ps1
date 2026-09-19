#Requires -Version 5.1
<#
.SYNOPSIS
    Migrate a PIM4EntraPS instance's CSV config into the SQL store (the SQL-only
    data layer). NON-DESTRUCTIVE: the CSV files are read, never modified. Same
    code targets Azure SQL (prod, via -ConnectionString) or local SQL Express
    (dev).

    REQ-G (2026-09-19) -- VALIDATE FIRST, THEN ADD BY KEY, NEVER DELETE:
      * Before ANYTHING is written (before SQL is even contacted) every file is checked by
        engine/_shared/PIM-CsvImportCheck.ps1 -- the same check setup/Invoke-PimCsvImportCheck.ps1 runs:
        encoding, delimiter, header vs the entity schema, keys, duplicate keys, the Manager's own
        validator rules over the rows, and the replication each row would get on an MSP master.
        Any ERROR refuses the import unless -AllowValidationErrors is passed. -ValidateOnly runs the
        check and stops: no SQL, nothing written.
      * The engine's STATE files (*_Delta.csv, *_LastApplied.csv) are never imported.
      * Rows are ADDED by natural key. A key already in the store with the SAME content is left
        alone; a key with DIFFERENT content is a collision and is reported -- by default the import
        REFUSES, before writing any row (-OnKeyConflict KeepExisting keeps the store's row and imports
        the rest; -OnKeyConflict Overwrite updates it from the file). Nothing is ever deleted.
      * -ForceLocal: imported rows stay on the master (Replicate=No; admins ManagementMode=local)
        unless the file sets the value explicitly.
    (BUG-201 kept a whole entity out when the store already held rows for it -- so a store holding
    the SAMPLE rows imported NOTHING for that entity, and said only "KEPT". Adding by key keeps what
    BUG-201 protected -- Manager rows are never deleted or overwritten silently -- without that.)
    -ReplaceExistingEntityRows remains the explicit, named full-set replace (it DELETES).

.DESCRIPTION
    For each <base>.custom.csv in -ConfigDir: parse rows -> pim.Rows (entity =
    base, key = the base's natural key). Then seed pim.Settings from the naming-
    convention config (file is the seed; SQL becomes authoritative afterwards).
    Connection auth is passwordless: Managed Identity (Azure SQL, via
    $global:PIM_SqlAccessToken) or Integrated (Express). No secret in any file.

    REST-migration note (REQUIREMENTS.md §19): this script is already pure
    SQL-data-plane -- it makes NO Microsoft.Graph or Az.* SDK calls. It uses
    SqlServer/ADO.NET via PIM-SqlStore.ps1 (Initialize-PimSqlStore /
    Merge-PimSqlEntityRows -- add/update by key -- / Set-PimSqlEntityRowsTransactional
    for -ReplaceExistingEntityRows / Import-PimSettingsSeed). The only Az touch anywhere
    underneath is an OPTIONAL Get-AzAccessToken fallback for a Key Vault secret
    read inside PIM-SqlStore; the primary path is the launcher-minted token. No
    conversion needed.

.PARAMETER ConfigDir
    The instance config folder (holds <base>.custom.csv + NamingConventions ps1).

.PARAMETER ConnectionString
    Target SQL connection string. Omit to build from -Server/-Database.

.PARAMETER WhatIf
    Report what would migrate without writing.

.PARAMETER ReplaceExistingEntityRows
    BUG-201 override. A FULL-SET REPLACE of every imported entity: every row of that entity that is
    NOT in the CSV -- including rows added or edited in the Manager since go-live -- is DELETED.
    Only for a deliberate re-seed. Without it the import adds by key and never deletes.

.PARAMETER ValidateOnly
    Run the pre-import check and stop. No SQL connection, nothing written. Returns the check result.

.PARAMETER AllowValidationErrors
    The explicit, named override for importing files the check found ERRORS in. Warnings never block.

.PARAMETER OnKeyConflict
    A row whose key is already in the store with DIFFERENT content: Refuse (default -- nothing is
    written), KeepExisting (the store's row wins, reported), or Overwrite (the file's row wins).

.PARAMETER ForceLocal
    Imported rows get Replicate=No (admins: ManagementMode=local) unless the file sets it explicitly,
    so nothing imported onto an MSP master is published to managed tenants by default.

.EXAMPLE
    # dev (Express)
    .\Migrate-PimToSql.ps1 -ConfigDir ..\config -Server .\SQLEXPRESS -Database PimPlatform
.EXAMPLE
    # prod (Azure SQL; launcher pre-minted the MI token into $global:PIM_SqlAccessToken)
    .\Migrate-PimToSql.ps1 -ConfigDir E:\cust\config -ConnectionString $cs
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$ConfigDir,
    [string]$ConnectionString,
    [string]$Server,
    # BUG-201: the v2 store's database is PimPlatform everywhere else (Setup-PimContainers, Invoke-PimDeployAll, every
    # job); 'PIM4EntraPS' here imported into a database nothing reads.
    [string]$Database = 'PimPlatform',
    [switch]$SeedSettings = $true,
    # BUG-201: the explicit, NAMED override for re-importing an entity whose store already holds rows (see .PARAMETER).
    [switch]$ReplaceExistingEntityRows,
    # Report which files WOULD be imported, and which are ignored, without touching SQL at all.
    # Answering "will this pick up my data?" should not require a database.
    [switch]$ListOnly,
    # 2026-09-13 (SQL-only): where the pre-v2 instance kept its runtime files (alerts, scheduler
    # state, template-state, audit). Defaults to the 'output' folder next to -ConfigDir.
    [string]$OutputDir,
    # The folder holding <type>.mailtemplate.custom.html overrides. Defaults to the solution's templates\mail.
    [string]$MailTemplateDir,
    # REQ-G: run the pre-import check only -- no SQL, nothing written (see .PARAMETER).
    [switch]$ValidateOnly,
    # REQ-G: the explicit, NAMED override for importing files the check found errors in.
    [switch]$AllowValidationErrors,
    # REQ-G: a key already in the store with different content. Refuse = write nothing (default).
    [ValidateSet('Refuse','KeepExisting','Overwrite')][string]$OnKeyConflict = 'Refuse',
    # REQ-G: imported rows stay on the master unless the file sets Replicate / ManagementMode.
    [switch]$ForceLocal,
    # REQ-G: the target is a single or managed tenant, not an MSP master (passed to the check).
    [switch]$NotMspMaster,
    # REQ-G: the target's default UPN domain, for admin rows without a UserPrincipalName (passed to the check).
    [string]$DefaultDomain
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

function Read-PimMigrateStoreRows {
    # REQ-G: the rows the store ALREADY holds for one entity, WITH their stored [Key] -- read-only, before
    # anything is written, so a key collision is found while it can still refuse cleanly. A store without
    # pim.Rows yet (a fresh database) holds nothing. A read that FAILS throws; it is never "empty".
    # Returns @( @{ key; row } ).
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][string]$Entity)
    $has = [int](Invoke-PimSqlScalar -ConnectionString $ConnectionString -Sql "SELECT CASE WHEN OBJECT_ID('pim.Rows') IS NULL THEN 0 ELSE 1 END")
    if (-not $has) { return @() }
    $raw = @(Invoke-PimSqlQuery -ConnectionString $ConnectionString -Sql "SELECT [Key], DataJson FROM pim.Rows WHERE Entity = @e" -Parameters @{ e = $Entity })
    return @($raw | ForEach-Object { @{ key = "$($_.Key)"; row = $(if ("$($_.DataJson)".Trim()) { $_.DataJson | ConvertFrom-Json } else { [pscustomobject]@{} }) } })
}

# REQ-G: the WRITE (add / update by key, never delete, one transaction per entity) and the row COMPARE are the
# store's own -- Merge-PimSqlEntityRows and Compare-PimSqlRowContent in engine/_shared/PIM-SqlStore.ps1. This
# script carried a private MERGE copy (Invoke-PimMigrateUpsertRows) until the store had an upsert-only mode.

. (Join-Path $shared 'PIM-ChangeQueue.ps1')
. (Join-Path $shared 'PIM-Rest.ps1')
. (Join-Path $shared 'PIM-SqlStore.ps1')
. (Join-Path $shared 'PIM-CsvImportCheck.ps1')
# 🧪 TEST SEAM ONLY. The dot-sources above (re)define the store functions in THIS script's scope, so a stub
# a test defines beforehand would be shadowed. $global:PIM_MigrateStoreStub = @{ <function name> = <scriptblock> }
# replaces those functions for this run (tests/Test-PimCsvImportCheck.ps1 drives the refuse / validate-only /
# upsert paths offline with it). Announced every time, so it can never be active unnoticed.
if ($global:PIM_MigrateStoreStub -is [hashtable] -and $global:PIM_MigrateStoreStub.Count) {
    # A stub written for the removed private writer would stub NOTHING and let the real store write -- refuse it.
    if ($global:PIM_MigrateStoreStub.ContainsKey('Invoke-PimMigrateUpsertRows') -and -not $global:PIM_MigrateStoreStub.ContainsKey('Merge-PimSqlEntityRows')) {
        throw "Migrate-PimToSql TEST SEAM: 'Invoke-PimMigrateUpsertRows' no longer exists -- stub 'Merge-PimSqlEntityRows' (the store's upsert-only writer) instead. Refusing to run with the real writer unstubbed."
    }
    Write-Warning ("  [migrate] TEST SEAM ACTIVE -- store function(s) stubbed: {0}" -f (@($global:PIM_MigrateStoreStub.Keys) -join ', '))
    foreach ($__n in @($global:PIM_MigrateStoreStub.Keys)) { Set-Item -Path "function:script:$__n" -Value $global:PIM_MigrateStoreStub[$__n] }
}
# Default only for the solution layout (<root>\config next to <root>\output): an arbitrary data folder
# must not pick up whatever 'output' folder happens to sit beside it.
if (-not "$OutputDir".Trim() -and (Split-Path -Leaf $ConfigDir) -like 'config*') { $OutputDir = Join-Path (Split-Path -Parent $ConfigDir) 'output' }
if (-not "$MailTemplateDir".Trim()) { $MailTemplateDir = Join-Path (Split-Path -Parent $PSScriptRoot) 'templates\mail' }
# REQ-G: SQL is contacted only AFTER the files have been validated (below) -- a folder the check refuses
# never opens a connection, and -ValidateOnly / -ListOnly never do.

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
    'PIM-Assignments-Roles-AUs','PIM-Assignments-Azure-Resources','PIM-Assignments-Workloads',
    # REQ-G: the two direct-group types the Manager, validator and engine already support (2026-09-12).
    'PIM-Definitions-Projects','PIM-Definitions-CrossOrg'
)
# 🪤 A v1 data folder holds much more than PIM's own entities -- CMDB, Device_Tagging,
# Identity_Tagging, Onboarding-Groups, Azure-Tags-*, plus the engine's own _Delta and _LastApplied
# working files. Importing those would create entities the Manager never reads; importing a
# _LastApplied as if it were desired state would be worse. Only the known bases are taken, and
# everything else is LISTED as skipped so the operator can see the decision rather than trust it.
# REQ-G: ONE classifier (Get-PimCsvImportFileSet) for this import and for the pre-import check, so the
# files that are validated are exactly the files that are imported.
$fileSet = Get-PimCsvImportFileSet -Path $ConfigDir -Entities $PimEntityBases
$byBase = [ordered]@{}
foreach ($b in $fileSet.entities.Keys) { $byBase[$b] = @{ file = $fileSet.entities[$b] } }
if (@($fileSet.skipped).Count) {
    Write-Host ("  [migrate] ignored {0} file(s) that are not PIM entity data:" -f @($fileSet.skipped).Count) -ForegroundColor DarkGray
    foreach ($s in @($fileSet.skipped)) {
        $why = switch ($s.status) { 'state' { 'state file, not imported' } 'superseded' { "$($s.reason)" } default { 'not a PIM entity' } }
        Write-Host ("      {0} ({1})" -f $s.file, $why) -ForegroundColor DarkGray
    }
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

# =====================================================================================================
# REQ-G 1) VALIDATE THE FILES -- before SQL is contacted, before anything is written.
# The rows imported below are the rows validated here (the check's parse: headers cleaned, trailing empty
# columns and blank separator rows dropped, -ForceLocal applied) -- one parse, not a second Import-Csv that
# could read the file differently (Import-Csv names an empty header column 'H<n>' and stores it).
# =====================================================================================================
$check = Invoke-PimCsvImportCheck -Path $ConfigDir -Entities $PimEntityBases -ForceLocal:$ForceLocal -NotMspMaster:$NotMspMaster -DefaultDomain $DefaultDomain
Write-PimCsvImportReport -Result $check
$script:PimMigrateValidation = $check
if ($ValidateOnly) {
    Write-Host ("VALIDATE ONLY -- {0}. SQL was not contacted and nothing was written." -f $(if ($check.errors) { "$($check.errors) error(s): an import would be REFUSED" } else { 'no errors: an import would proceed' })) -ForegroundColor Cyan
    return $check
}
if ($check.errors -gt 0) {
    if (-not $AllowValidationErrors) {
        throw ("Migrate-PimToSql: the pre-import check found {0} error(s) (listed above) -- REFUSING to import. Nothing was written and SQL was not contacted. Fix the files, or pass -AllowValidationErrors to import them as they are." -f $check.errors)
    }
    Write-Warning ("  [migrate] -AllowValidationErrors: importing DESPITE {0} validation error(s) listed above." -f $check.errors)
}

# =====================================================================================================
# REQ-G 2) READ WHAT THE STORE ALREADY HOLDS, for every entity, before ANY write -- so a key collision can
# still refuse the whole import cleanly instead of after half of it has landed.
# 🔴 BUG-201 still holds: a re-run must never delete what the Manager owns, nor silently revert its edits.
# BUG-201's guard kept a whole ENTITY out once the store held rows for it; that also imported NOTHING into a
# store holding sample rows (EFIF). Adding BY KEY keeps both promises: new keys are added, identical keys are
# left alone, a key with DIFFERENT content is a collision (reported; refused by default), nothing is deleted.
# A read that fails is a failed entity, never "assume empty".
# =====================================================================================================
if (-not $ConnectionString) { $ConnectionString = Get-PimSqlConnectionString -Server $Server -Database $Database }
if (-not (Test-PimSqlConnectivity -ConnectionString $ConnectionString)) { throw "SQL not reachable with the supplied connection." }

$report = New-Object System.Collections.Generic.List[object]
$failedEntities = New-Object System.Collections.Generic.List[object]
$keptEntities = New-Object System.Collections.Generic.List[object]
$plans = [ordered]@{}
$collisions = New-Object System.Collections.Generic.List[object]
foreach ($base in $byBase.Keys) {
    $im = $check.import[$base]
    try { $stored = @(Read-PimMigrateStoreRows -ConnectionString $ConnectionString -Entity $base) } catch {
        Write-Warning "  [migrate] $base FAILED: could not read the rows the store already holds, so cannot tell what importing would change -- refusing it: $($_.Exception.Message)"
        [void]$failedEntities.Add([pscustomobject]@{ entity = $base; error = "could not read the existing rows: $($_.Exception.Message)" })
        continue
    }
    $byKey = @{}
    foreach ($s in $stored) { if ("$($s.key)") { $byKey["$($s.key)".ToLowerInvariant()] = $s } }
    $plan = @{ add = New-Object System.Collections.Generic.List[object]; update = New-Object System.Collections.Generic.List[object]
               same = 0; collide = New-Object System.Collections.Generic.List[object]; existing = $stored.Count; file = $im.file; rows = @($im.rows) }
    # The LAST row per key, as the store itself would keep it (two rows with one key are a CSVIMP-KEY-002 error).
    $taken = [ordered]@{}
    for ($i = 0; $i -lt @($im.rows).Count; $i++) { $k = "$($im.keys[$i])"; if ($k) { $taken[$k.ToLowerInvariant()] = $i } }
    foreach ($lk in @($taken.Keys)) {
        $i = $taken[$lk]
        if (-not $byKey.ContainsKey($lk)) { $plan.add.Add(@{ key = "$($im.keys[$i])"; row = $im.rows[$i] }) | Out-Null; continue }
        # Compared with the row AS THE FILE HAS IT (before -ForceLocal): an unchanged row is left alone.
        $d = @(Compare-PimSqlRowContent -FileRow $im.rawRows[$i] -StoreRow $byKey[$lk].row)
        if (-not $d.Count) { $plan.same++; continue }
        $col = [pscustomobject]@{ entity = $base; key = "$($byKey[$lk].key)"; file = $im.file; row = $im.rowNumbers[$i]; line = $im.lines[$i]; columns = $d }
        $plan.collide.Add($col) | Out-Null; $collisions.Add($col) | Out-Null
        if ($OnKeyConflict -eq 'Overwrite') { $plan.update.Add(@{ key = "$($byKey[$lk].key)"; row = $im.rows[$i] }) | Out-Null }
    }
    $plans[$base] = $plan
}
$script:PimMigrateCollisions = $collisions.ToArray()
if ($collisions.Count) {
    Write-Host ''
    Write-Host ("KEY COLLISIONS ({0}) -- the store already holds these keys with DIFFERENT content:" -f $collisions.Count) -ForegroundColor $(if ($OnKeyConflict -eq 'Refuse' -and -not $ReplaceExistingEntityRows) { 'Red' } else { 'Yellow' })
    foreach ($c in $collisions) {
        $what = @($c.columns | Select-Object -First 4 | ForEach-Object { "$($_.column): store '$($_.store)' / file '$($_.file)'" }) -join '; '
        if (@($c.columns).Count -gt 4) { $what += " (+$(@($c.columns).Count - 4) more column(s))" }
        Write-Host ("    {0} '{1}' ({2} row {3}, line {4}) -- {5}" -f $c.entity, $c.key, $c.file, $c.row, $c.line, $what) -ForegroundColor Yellow
    }
    if (-not $ReplaceExistingEntityRows) {
        if ($OnKeyConflict -eq 'Refuse') {
            throw ("Migrate-PimToSql: {0} key collision(s) with DIFFERENT content (listed above) -- REFUSING before writing anything. " -f $collisions.Count +
                   "-OnKeyConflict KeepExisting keeps the store's rows and imports the rest; -OnKeyConflict Overwrite updates them from the files. Nothing is deleted either way.")
        }
        Write-Host ("  -OnKeyConflict {0}: {1}" -f $OnKeyConflict, $(if ($OnKeyConflict -eq 'Overwrite') { 'those rows are UPDATED from the files.' } else { "the store's rows are KEPT; the files' versions are NOT imported." })) -ForegroundColor Yellow
    }
}

# =====================================================================================================
# REQ-G 3) WRITE: add (and, only with -OnKeyConflict Overwrite, update) BY KEY. Never a delete.
# =====================================================================================================
Write-Host "Initializing SQL store (idempotent) ..." -ForegroundColor Cyan
if ($PSCmdlet.ShouldProcess($Database, 'Initialize-PimSqlStore')) { Initialize-PimSqlStore -ConnectionString $ConnectionString }
foreach ($base in $plans.Keys) {
    $p = $plans[$base]
    try {
        # 🔴 §52.18b -- ONE CONNECTION PER ENTITY, NOT ONE PER ROW. Set-PimSqlRow opens a connection per
        # row, and a connection carrying an Entra ACCESS TOKEN cannot share a pool with one carrying a
        # different token -- measured at a live customer 2026-09-10: "The session limit for the database
        # is 900 and has been reached" after twelve entities and ~565 rows. Both writers below run ONE
        # connection inside ONE transaction per entity, so an entity that fails rolls back whole.
        if ($ReplaceExistingEntityRows) {
            if ($p.existing -gt 0) { Write-Host ("  [migrate] {0}: -ReplaceExistingEntityRows -- REPLACING {1} existing row(s); rows not in {2} will be DELETED" -f $base, $p.existing, $p.file) -ForegroundColor Red }
            if ($PSCmdlet.ShouldProcess("$base ($(@($p.rows).Count) rows)", 'REPLACE -> pim.Rows')) {
                $res = Set-PimSqlEntityRowsTransactional -ConnectionString $ConnectionString -Entity $base -Base $base -Rows @($p.rows)
                Write-Host ("  [migrate] {0}: {1} rows -> SQL (full-set replace, {2} removed)" -f $base, $res.rowCount, $res.removed) -ForegroundColor Green
                $report.Add([pscustomobject]@{ entity = $base; rows = $res.rowCount; added = $null; updated = $null; unchanged = $null; kept = 0; removed = $res.removed })
            } else {
                Write-Host ("  [migrate][WhatIf] {0}: {1} rows (full-set replace)" -f $base, @($p.rows).Count) -ForegroundColor Yellow
                $report.Add([pscustomobject]@{ entity = $base; rows = @($p.rows).Count; added = $null; updated = $null; unchanged = $null; kept = 0; removed = 0 })
            }
            continue
        }
        $items = @($p.add.ToArray()) + @($p.update.ToArray())
        $kept = if ($OnKeyConflict -eq 'KeepExisting') { $p.collide.Count } else { 0 }
        if ($kept) { [void]$keptEntities.Add([pscustomobject]@{ entity = $base; existing = $kept; file = $p.file }) }
        if (-not $items.Count) {
            Write-Host ("  [migrate] {0}: nothing to add -- {1} row(s) already in the store unchanged{2}" -f $base, $p.same, $(if ($kept) { ", $kept collision(s) KEPT" } else { '' })) -ForegroundColor DarkGray
            continue
        }
        if ($PSCmdlet.ShouldProcess("$base ($($items.Count) rows)", 'add/update by key -> pim.Rows')) {
            # The store's upsert-only writer: ONE transaction for the entity, never a delete. It applies the plan above
            # under the SAME -OnKeyConflict, so a row the Manager changed between that read and this write is judged by
            # the operator's own policy (Refuse throws and rolls this entity back -> reported as FAILED below).
            $mr = Merge-PimSqlEntityRows -ConnectionString $ConnectionString -Entity $base -Items $items -OnKeyConflict $OnKeyConflict
            $n = [int]$mr.submitted
            Write-Host ("  [migrate] {0} <- {1}: {2} added, {3} updated, {4} unchanged{5} (nothing deleted)" -f $base, $p.file, $p.add.Count, $p.update.Count, $p.same, $(if ($kept) { ", $kept collision(s) KEPT" } else { '' })) -ForegroundColor Green
            $report.Add([pscustomobject]@{ entity = $base; rows = $n; added = $p.add.Count; updated = $p.update.Count; unchanged = $p.same; kept = $kept; removed = 0 })
        } else {
            Write-Host ("  [migrate][WhatIf] {0}: {1} to add, {2} to update, {3} unchanged" -f $base, $p.add.Count, $p.update.Count, $p.same) -ForegroundColor Yellow
            $report.Add([pscustomobject]@{ entity = $base; rows = $items.Count; added = $p.add.Count; updated = $p.update.Count; unchanged = $p.same; kept = $kept; removed = 0 })
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

$nAdded = 0; $nUpdated = 0; $nSame = 0; $nKept = 0
foreach ($r in $report) { if ($null -ne $r.added) { $nAdded += [int]$r.added }; if ($null -ne $r.updated) { $nUpdated += [int]$r.updated } }
foreach ($p in @($plans.Values)) { $nSame += [int]$p.same }
foreach ($k in $keptEntities) { $nKept += [int]$k.existing }
$delNote = if ($ReplaceExistingEntityRows) { 'FULL-SET REPLACE (-ReplaceExistingEntityRows): rows not in the files were deleted.' } else { 'Nothing was deleted.' }
Write-Host ("`nMigration complete: {0} entit(ies) written -- {1} row(s) added, {2} updated, {3} already in the store unchanged; {4} collision(s) KEPT. {5} The CSV files were NOT modified." -f $report.Count, $nAdded, $nUpdated, $nSame, $nKept, $delNote) -ForegroundColor Cyan
if ($keptEntities.Count) {
    Write-Host ("  KEPT (the store's row differs from the file's and was not overwritten): {0}. Re-run with -OnKeyConflict Overwrite to take the files' versions." -f (($keptEntities | ForEach-Object { "$($_.entity) ($($_.existing) row(s))" }) -join ', ')) -ForegroundColor Yellow
}
$script:PimMigrateKeptEntities = $keptEntities.ToArray()
Write-Host "Next: point the Manager and the engine at this database (the v2 store is SQL-only)." -ForegroundColor Cyan
return $report.ToArray()
