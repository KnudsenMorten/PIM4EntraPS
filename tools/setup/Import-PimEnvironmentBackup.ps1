#Requires -Version 5.1
<#
.SYNOPSIS
    Bring an environment's PIM configuration back from its backup into ANOTHER running environment: definitions
    (pim.Rows), settings (pim.Settings), the audit trail (pim.AuditEvents) and the commit undo snapshots (pim.Backups).

.DESCRIPTION
    Use it when an environment is replaced, rebuilt or lost and its configuration must continue in another one. Operator
    2026-10-04, after the internal environment was deleted without an export: "everything into r1-pro-ca, keep the audit
    trail too".

    1. Restore the backup's BACPAC into a scratch database the operator can read, e.g.
         SqlPackage /a:Import /sf:PimPlatform.bacpac /tsn:.\SQLEXPRESS /tdn:PimRestore_old /ttsc:true
       and pass it as -SourceConnectionString.
    2. Run WITHOUT -Apply. You get the plan: rows to insert / already present per entity, every setting's action, the
       audit rows and snapshots to append, the change-queue items NOT carried over. The rules are in
       _PimEnvironmentImport.ps1 (tested offline by tests/Test-PimEnvironmentImport.ps1).
    3. Run with -Apply. In order:
       a. every target setting this run will touch is written to -BackupDir FIRST;
       b. 🔒 the engine is PAUSED (FeatureGates.gates.'scheduler.jobs' = false), so no tick applies half an import;
       c. settings, rows, snapshots, audit rows, then one 'environment.import' audit row (with the source range);
       d. the engine stays PAUSED. You review the result (Manager: the Access / Delegations pages), then switch it back
          on yourself: Settings > Features > Scheduled jobs, or -ResumeEngine. The first runs after that are the
          engine taking over what the old environment managed.
    A row the target already has is never overwritten. A re-run inserts nothing twice: rows by key, snapshots by id, the
    audit trail by the import marker.

.PARAMETER SourceConnectionString
    The restored backup database (read only).
.PARAMETER TargetServer / -TargetDatabase / -TargetTenantId / -AzureConfigDir
    The running environment's store. Signed in with an Entra token for Azure SQL from az, in that tenant (use the az
    profile of an identity that is a member of the store's SQL admin group). Windows PowerShell 5.1 is recommended for
    the SQL login: pwsh 7 dropped the same login twice on mgmt1.
.PARAMETER SourceLabel
    Names the source in the audit marker (e.g. 'mfnpr 2026-10-02 19:01 BACPAC').
.PARAMETER Apply / -ResumeEngine
    -Apply writes (and pauses the engine). -ResumeEngine only switches the scheduled jobs back on.
.EXAMPLE
    .\Import-PimEnvironmentBackup.ps1 -SourceConnectionString 'Server=.\SQLEXPRESS;Database=PimRestore_old;Integrated Security=True;TrustServerCertificate=True' `
        -TargetServer sql-x.database.windows.net -TargetTenantId <tenant> -AzureConfigDir C:\az-profile -SourceLabel 'old env 2026-10-02'
#>
[CmdletBinding()]
param(
    [string]$SourceConnectionString = '',
    [Parameter(Mandatory)][string]$TargetServer,
    [string]$TargetDatabase = 'PimPlatform',
    [Parameter(Mandatory)][string]$TargetTenantId,
    [string]$AzureConfigDir = '',
    [string]$SourceLabel = 'backup',
    [string]$BackupDir = (Join-Path ([IO.Path]::GetTempPath()) 'pim-import-backup'),
    [switch]$Apply,
    [switch]$ResumeEngine
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '_PimEnvironmentImport.ps1')
function Say($m, $c = 'Gray') { Write-Host "[import] $m" -ForegroundColor $c }

# ---- connections -------------------------------------------------------------------------------------------------
if ($AzureConfigDir) { $env:AZURE_CONFIG_DIR = $AzureConfigDir }
$prevEap = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
$tok = "$(az account get-access-token --resource https://database.windows.net/ --tenant $TargetTenantId --query accessToken -o tsv 2>$null)".Trim()
$ErrorActionPreference = $prevEap
if (-not $tok) { throw "no Azure SQL token for tenant $TargetTenantId (az login with an identity in the store's SQL admin group; -AzureConfigDir)" }
$tgt = New-Object System.Data.SqlClient.SqlConnection "Server=tcp:$TargetServer,1433;Database=$TargetDatabase;Encrypt=True;TrustServerCertificate=False;Connection Timeout=30"
$tgt.AccessToken = $tok; $tgt.Open()
function Invoke-Sql {
    param([System.Data.SqlClient.SqlConnection]$Conn, [string]$Sql, [hashtable]$P = @{}, [System.Data.SqlClient.SqlTransaction]$Tx = $null, [switch]$NonQuery)
    $cmd = $Conn.CreateCommand(); $cmd.CommandText = $Sql; $cmd.CommandTimeout = 300; if ($Tx) { $cmd.Transaction = $Tx }
    foreach ($k in $P.Keys) { $v = $P[$k]; [void]$cmd.Parameters.AddWithValue("@$k", $(if ($null -eq $v) { [DBNull]::Value } else { $v })) }
    if ($NonQuery) { return $cmd.ExecuteNonQuery() }
    $t = New-Object System.Data.DataTable; $t.Load($cmd.ExecuteReader()); return ,$t
}
$me = (Invoke-Sql $tgt 'SELECT USER_NAME() u').Rows[0].u
Say "target $TargetServer/$TargetDatabase as $me" 'Cyan'

function Set-EngineJobs([bool]$On) {
    $cur = "$((Invoke-Sql $tgt "SELECT ValueJson FROM pim.Settings WHERE Name='FeatureGates'").Rows | ForEach-Object { $_.ValueJson })"
    $o = if ($cur.Trim()) { $cur | ConvertFrom-Json } else { [pscustomobject]@{ gates = [pscustomobject]@{} } }
    if (-not $o.PSObject.Properties['gates']) { $o | Add-Member -NotePropertyName gates -NotePropertyValue ([pscustomobject]@{}) }
    $o.gates | Add-Member -NotePropertyName 'scheduler.jobs' -NotePropertyValue $On -Force
    $j = $o | ConvertTo-Json -Depth 10 -Compress
    [void](Invoke-Sql $tgt "MERGE pim.Settings AS t USING (SELECT @n AS Name) s ON t.Name=s.Name WHEN MATCHED THEN UPDATE SET ValueJson=@v, UpdatedUtc=SYSUTCDATETIME() WHEN NOT MATCHED THEN INSERT (Name, ValueJson, UpdatedUtc) VALUES (@n, @v, SYSUTCDATETIME());" @{ n = 'FeatureGates'; v = $j } -NonQuery)
    $back = "$((Invoke-Sql $tgt "SELECT ValueJson FROM pim.Settings WHERE Name='FeatureGates'").Rows[0].ValueJson)" | ConvertFrom-Json
    if ([bool]$back.gates.'scheduler.jobs' -ne $On) { throw "the engine switch did not read back as $On" }
}

if ($ResumeEngine) {
    Set-EngineJobs $true
    [void](Invoke-Sql $tgt "INSERT pim.AuditEvents (Actor, ActorSource, Action, Target, AfterJson, Result) VALUES (@a, 'setup', 'environment.import.resume', 'FeatureGates scheduler.jobs', @j, 'ok')" @{ a = "$me"; j = '{"scheduler.jobs":true}' } -NonQuery)
    Say "scheduled jobs are ON again -- the engine takes over on its next tick" 'Green'
    $tgt.Close(); return
}
if (-not $SourceConnectionString) { throw '-SourceConnectionString is required (the restored backup database)' }
$src = New-Object System.Data.SqlClient.SqlConnection $SourceConnectionString; $src.Open()

# ---- read both sides ---------------------------------------------------------------------------------------------
$sRows = @((Invoke-Sql $src 'SELECT Entity, [Key], DataJson, UpdatedUtc FROM pim.Rows').Rows)
$tRows = @((Invoke-Sql $tgt 'SELECT Entity, [Key] FROM pim.Rows').Rows)
$rowPlan = Get-PimImportRowPlan -Source $sRows -Target $tRows
$sSet = @{}; foreach ($r in (Invoke-Sql $src 'SELECT Name, ValueJson FROM pim.Settings').Rows) { $sSet["$($r.Name)"] = "$($r.ValueJson)" }
$tSet = @{}; foreach ($r in (Invoke-Sql $tgt 'SELECT Name, ValueJson FROM pim.Settings').Rows) { $tSet["$($r.Name)"] = "$($r.ValueJson)" }
$setPlan = @(foreach ($n in @($sSet.Keys | Sort-Object)) { Get-PimImportSettingAction -Name $n -SourceJson $sSet[$n] -TargetJson $(if ($tSet.ContainsKey($n)) { $tSet[$n] } else { '' }) })
$audit = (Invoke-Sql $src 'SELECT COUNT(*) c, MIN(Ts) mn, MAX(Ts) mx, MIN(Id) idmin, MAX(Id) idmax FROM pim.AuditEvents').Rows[0]
$marker = "import:$SourceLabel|audit:$($audit.idmin)-$($audit.idmax)"
$already = [int](Invoke-Sql $tgt "SELECT COUNT(*) c FROM pim.AuditEvents WHERE Action='environment.import' AND Target=@t" @{ t = $marker }).Rows[0].c
$hasBackups = [bool](Invoke-Sql $tgt "SELECT CASE WHEN OBJECT_ID('pim.Backups') IS NULL THEN 0 ELSE 1 END b").Rows[0].b
$sSnap = @((Invoke-Sql $src 'SELECT Id, Entity, TakenUtc, [By], Reason, RowCount2, BodyJson FROM pim.Backups').Rows)
$tSnapIds = @{}; if ($hasBackups) { foreach ($r in (Invoke-Sql $tgt 'SELECT Id FROM pim.Backups').Rows) { $tSnapIds["$($r.Id)"] = $true } }
$newSnap = @($sSnap | Where-Object { -not $tSnapIds.ContainsKey("$($_.Id)") })
$queue = @((Invoke-Sql $src 'SELECT Status, COUNT(*) c FROM pim.ChangeQueue GROUP BY Status').Rows)

# ---- the plan ------------------------------------------------------------------------------------------------------
Say "=== PLAN: $SourceLabel -> $TargetServer ===" 'Cyan'
Say ("rows: {0} to insert, {1} already in the target (left alone)" -f $rowPlan.insert.Count, $rowPlan.conflict.Count)
foreach ($e in @($rowPlan.perEntity.Keys | Sort-Object)) { Say ("  {0,-40} insert {1,4}  present {2,4}" -f $e, $rowPlan.perEntity[$e].insert, $rowPlan.perEntity[$e].conflict) }
foreach ($a in 'copy', 'merge', 'union', 'replace', 'skip') {
    $l = @($setPlan | Where-Object { $_.action -eq $a })
    if ($l.Count) { Say ("settings {0,-8} {1,3}: {2}" -f $a, $l.Count, (($l | ForEach-Object { if ($_.note -and $a -eq 'union') { "$($_.name) ($($_.note))" } else { $_.name } }) -join ', ')) }
}
Say ("settings same      {0,3}" -f @($setPlan | Where-Object { $_.action -eq 'same' }).Count)
Say ("audit: {0} rows {1} .. {2} -- {3}" -f $audit.c, $audit.mn, $audit.mx, $(if ($already) { 'ALREADY IMPORTED (marker found) -- skipped' } else { 'appended as they are, plus one environment.import row' }))
Say ("undo snapshots: {0} new of {1}{2}" -f $newSnap.Count, $sSnap.Count, $(if (-not $hasBackups) { ' (the target has no pim.Backups table yet -- it is created with the Manager''s own definition)' }))
Say ("change queue NOT carried over: {0}" -f (($queue | ForEach-Object { "$($_.Status) $($_.c)" }) -join ', '))
if (-not $Apply) { Say 'plan only -- run again with -Apply to write (it pauses the engine first)' 'Yellow'; $src.Close(); $tgt.Close(); return }

# ---- apply ---------------------------------------------------------------------------------------------------------
New-Item -ItemType Directory -Force -Path $BackupDir | Out-Null
$stamp = [datetime]::UtcNow.ToString('yyyyMMddTHHmmssZ')
$bk = Join-Path $BackupDir "pim-settings-before-import-$stamp.json"
$touched = @($setPlan | Where-Object { $_.action -in 'copy', 'merge', 'union', 'replace' } | ForEach-Object { $_.name }) + 'FeatureGates'
$before = [ordered]@{}; foreach ($n in $touched) { $before[$n] = $(if ($tSet.ContainsKey($n)) { $tSet[$n] } else { $null }) }
($before | ConvertTo-Json -Depth 4) | Set-Content -LiteralPath $bk -Encoding UTF8
Say "target settings before the import: $bk" 'DarkGray'

Set-EngineJobs $false
Say 'engine PAUSED (FeatureGates scheduler.jobs = false) -- it stays paused until you resume it' 'Yellow'

if (-not $hasBackups -and $newSnap.Count) {
    # The Manager creates pim.Backups on first use; a target that never used it has none. SAME DDL as
    # engine/_shared/PIM-CommitBackup.ps1 Initialize-PimBackupStore (Test-PimEnvironmentImport pins the two together).
    [void](Invoke-Sql $tgt @"
IF SCHEMA_ID('pim') IS NULL EXEC ('CREATE SCHEMA pim');
IF OBJECT_ID('pim.Backups') IS NULL
CREATE TABLE pim.Backups (
    Id        NVARCHAR(200) NOT NULL PRIMARY KEY,
    Entity    NVARCHAR(100) NOT NULL,
    TakenUtc  DATETIME2     NOT NULL CONSTRAINT DF_Backups_Taken DEFAULT SYSUTCDATETIME(),
    [By]      NVARCHAR(256) NULL,
    Reason    NVARCHAR(400) NULL,
    RowCount2 INT           NOT NULL CONSTRAINT DF_Backups_RowCount DEFAULT 0,
    BodyJson  NVARCHAR(MAX) NULL
);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_pim_Backups_Entity_Taken' AND object_id = OBJECT_ID('pim.Backups'))
CREATE INDEX IX_pim_Backups_Entity_Taken ON pim.Backups (Entity, TakenUtc);
"@ -NonQuery)
    $hasBackups = $true
    Say 'created pim.Backups (the Manager''s own definition) for the undo snapshots' 'DarkGray'
}

$tx = $tgt.BeginTransaction()
try {
    foreach ($s in @($setPlan | Where-Object { $_.action -in 'copy', 'merge', 'union', 'replace' })) {
        if ($s.name -eq 'FeatureGates') {
            # keep the pause: the imported gates are merged, but scheduler.jobs stays false until -ResumeEngine
            $fo = $s.valueJson | ConvertFrom-Json; if ($fo.PSObject.Properties['gates']) { $fo.gates | Add-Member -NotePropertyName 'scheduler.jobs' -NotePropertyValue $false -Force }
            $s.valueJson = $fo | ConvertTo-Json -Depth 10 -Compress
        }
        [void](Invoke-Sql $tgt "MERGE pim.Settings AS t USING (SELECT @n AS Name) s ON t.Name=s.Name WHEN MATCHED THEN UPDATE SET ValueJson=@v, UpdatedUtc=SYSUTCDATETIME() WHEN NOT MATCHED THEN INSERT (Name, ValueJson, UpdatedUtc) VALUES (@n, @v, SYSUTCDATETIME());" @{ n = $s.name; v = $s.valueJson } -Tx $tx -NonQuery)
    }
    foreach ($r in $rowPlan.insert) {
        [void](Invoke-Sql $tgt "IF NOT EXISTS (SELECT 1 FROM pim.Rows WHERE Entity=@e AND [Key]=@k) INSERT pim.Rows (Entity, [Key], DataJson, UpdatedUtc) VALUES (@e, @k, @d, SYSUTCDATETIME())" @{ e = "$($r.Entity)"; k = "$($r.Key)"; d = "$($r.DataJson)" } -Tx $tx -NonQuery)
    }
    if ($hasBackups) {
        foreach ($b in $newSnap) {
            [void](Invoke-Sql $tgt "IF NOT EXISTS (SELECT 1 FROM pim.Backups WHERE Id=@i) INSERT pim.Backups (Id, Entity, TakenUtc, [By], Reason, RowCount2, BodyJson) VALUES (@i, @e, @t, @b, @r, @c, @j)" @{ i = "$($b.Id)"; e = "$($b.Entity)"; t = $b.TakenUtc; b = "$($b.By)"; r = "$($b.Reason)"; c = $b.RowCount2; j = "$($b.BodyJson)" } -Tx $tx -NonQuery)
        }
    }
    $nAudit = 0
    if (-not $already) {
        foreach ($a in (Invoke-Sql $src 'SELECT Ts, RunId, CorrelationId, Actor, ActorSource, Action, Target, BeforeJson, AfterJson, Result, WhatIf FROM pim.AuditEvents ORDER BY Id').Rows) {
            [void](Invoke-Sql $tgt "INSERT pim.AuditEvents (Ts, RunId, CorrelationId, Actor, ActorSource, Action, Target, BeforeJson, AfterJson, Result, WhatIf) VALUES (@ts, @ri, @ci, @ac, @as, @an, @tg, @bj, @aj, @rs, @wi)" @{
                ts = $a.Ts; ri = $a.RunId; ci = $a.CorrelationId; ac = $a.Actor; as = $a.ActorSource; an = $a.Action; tg = $a.Target; bj = $a.BeforeJson; aj = $a.AfterJson; rs = $a.Result; wi = $a.WhatIf } -Tx $tx -NonQuery)
            $nAudit++
        }
        $after = [ordered]@{ source = $SourceLabel; rowsInserted = $rowPlan.insert.Count; rowsPresent = $rowPlan.conflict.Count; auditAppended = $nAudit; auditRange = "$($audit.mn) .. $($audit.mx)"; snapshots = $newSnap.Count
                             settings = [ordered]@{ copy = @($setPlan | ? { $_.action -eq 'copy' } | % { $_.name }); merge = @($setPlan | ? { $_.action -eq 'merge' } | % { $_.name }); union = @($setPlan | ? { $_.action -eq 'union' } | % { $_.name }); replace = @($setPlan | ? { $_.action -eq 'replace' } | % { $_.name }); skip = @($setPlan | ? { $_.action -eq 'skip' } | % { $_.name }) }
                             settingsBackupFile = $bk; enginePaused = $true }
        [void](Invoke-Sql $tgt "INSERT pim.AuditEvents (Actor, ActorSource, Action, Target, AfterJson, Result) VALUES (@a, 'setup', 'environment.import', @t, @j, 'ok')" @{ a = "$me"; t = $marker; j = ($after | ConvertTo-Json -Depth 6 -Compress) } -Tx $tx -NonQuery)
    }
    $tx.Commit()
} catch { try { $tx.Rollback() } catch { }; Say "FAILED -- rolled back, the target is as before (the engine stays PAUSED): $($_.Exception.Message)" 'Red'; throw }

# ---- verify --------------------------------------------------------------------------------------------------------
$miss = 0; $tKeys = @{}; foreach ($r in (Invoke-Sql $tgt 'SELECT Entity, [Key] FROM pim.Rows').Rows) { $tKeys["$($r.Entity)|$($r.Key)".ToLowerInvariant()] = $true }
foreach ($r in $sRows) { if (-not $tKeys.ContainsKey("$($r.Entity)|$($r.Key)".ToLowerInvariant())) { $miss++ } }
$imp = [int](Invoke-Sql $tgt "SELECT COUNT(*) c FROM pim.AuditEvents WHERE Action='environment.import' AND Target=@t" @{ t = $marker }).Rows[0].c
Say ("verified: every source row is in the target ({0} missing), import marker {1}, engine paused" -f $miss, $(if ($imp) { 'present' } else { 'MISSING' })) $(if ($miss -or -not $imp) { 'Red' } else { 'Green' })
Say 'NEXT: review in the Manager, then resume the engine: Settings > Features > Scheduled jobs, or this script -ResumeEngine' 'Yellow'
$src.Close(); $tgt.Close()
if ($miss -or -not $imp) { exit 1 }
