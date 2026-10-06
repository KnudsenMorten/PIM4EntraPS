<#
  CONFIG-1.1 (framework DOCS/REQUIREMENTS.md) / PIM §96.1 -- THE CHANGE JOURNAL (the transaction log).

  Operator 2026-10-06: "any commit must have a transaction log, which can be used for the later pruning (extra validation)"
  and "people make mistakes, so we need a way to undo a commit". Decision: the journal is written in the SAME database
  transaction as the change -- both land or neither does.

  * pim.CommitJournal: one row per changed pim.Rows record per commit -- CommitId, CommittedUtc, Entity, Key, Op
    (Add / Modify / Remove), BeforeJson + AfterJson (the FULL stored row), InitiatedBy, ApprovedBy, Source, UndoOf.
  * Append-only in the database (the AUDIT-1.3 trigger model): UPDATE and DELETE are always refused. Retention = keep
    (CONFIG-1.1: never shorter than the backup retention; no retention job yet, so nothing ever deletes).
  * WHERE it is written: in the store's own write functions (PIM-SqlStore.ps1 -- Set-PimSqlRow, Remove-PimSqlRow,
    Set-PimSqlEntityRowsTransactional, Merge-PimSqlEntityRows, the queue drain), on the connection + transaction of the
    write. So EVERY write through the store is journaled, whichever caller made it; a caller that knows who and why sets
    the CONTEXT (commit id, initiator, approver, source, per-key attribution). A write with no context is still journaled:
    Source 'system', its own commit id. A row written with byte-identical JSON is no change and leaves no journal row.
  * If the journal row cannot be written (no table, no rights) the write FAILS and rolls back -- a change without its
    journal row cannot exist (operator decision).
#>

function Get-PimCommitJournalDdl {
    @"
IF OBJECT_ID('pim.CommitJournal') IS NULL
CREATE TABLE pim.CommitJournal (
    Id            BIGINT IDENTITY(1,1) NOT NULL CONSTRAINT PK_pim_CommitJournal PRIMARY KEY,
    CommitId      NVARCHAR(64)  NOT NULL,
    CommittedUtc  DATETIME2     NOT NULL CONSTRAINT DF_CommitJournal_Ts DEFAULT SYSUTCDATETIME(),
    Entity        NVARCHAR(100) NOT NULL,
    [Key]         NVARCHAR(400) NOT NULL,
    Op            NVARCHAR(10)  NOT NULL,
    BeforeJson    NVARCHAR(MAX) NULL,
    AfterJson     NVARCHAR(MAX) NULL,
    InitiatedBy   NVARCHAR(200) NOT NULL,
    ApprovedBy    NVARCHAR(200) NULL,
    Source        NVARCHAR(40)  NOT NULL,
    UndoOf        NVARCHAR(64)  NULL
);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_pim_CommitJournal_Commit')
CREATE INDEX IX_pim_CommitJournal_Commit ON pim.CommitJournal (CommitId);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_pim_CommitJournal_Key')
CREATE INDEX IX_pim_CommitJournal_Key ON pim.CommitJournal (Entity, [Key], CommittedUtc);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_pim_CommitJournal_Who')
CREATE INDEX IX_pim_CommitJournal_Who ON pim.CommitJournal (InitiatedBy, CommittedUtc);
"@
}

function Get-PimCommitJournalTriggerSql {
    # CREATE OR ALTER keeps it idempotent; it must be the only statement in its batch. No retention marker: nothing deletes.
    @"
CREATE OR ALTER TRIGGER pim.TR_CommitJournal_AppendOnly ON pim.CommitJournal
INSTEAD OF UPDATE, DELETE
AS
BEGIN
    SET NOCOUNT ON;
    THROW 51010, 'pim.CommitJournal is append-only: a journal row is never changed or deleted (CONFIG-1.1).', 1;
END
"@
}

function Initialize-PimCommitJournal {
    <# Creates the table + the append-only trigger. Never throws (a store must still open); a store without the journal
       then refuses every write, which is the decided failure direction. Returns @{ ok; detail }. #>
    param([Parameter(Mandatory)][string]$ConnectionString)
    try {
        [void](Invoke-PimSqlNonQuery -ConnectionString $ConnectionString -Sql (Get-PimCommitJournalDdl))
        [void](Invoke-PimSqlNonQuery -ConnectionString $ConnectionString -Sql (Get-PimCommitJournalTriggerSql))
        return [pscustomobject]@{ ok = $true; detail = 'journal + append-only trigger in place' }
    } catch {
        $m = "$($_.Exception.Message)"
        Write-Warning "[journal] pim.CommitJournal could not be created -- every store write will be refused until it exists: $m"
        return [pscustomobject]@{ ok = $false; detail = "journal NOT in place: $m" }
    }
}

function New-PimCommitJournalContext {
    <#
      PURE. Who and why for the writes that follow. -Attribution: @{ '<key lower>' = @{ initiatedBy; approvedBy } } -- a
      commit that carries colleagues' staged changes names each row's own initiator (ConvertTo-PimCommitAttributionEntries).
    #>
    param([string]$CommitId = '', [string]$Source = 'system', [string]$InitiatedBy = '', [string]$ApprovedBy = '',
          [string]$UndoOf = '', [hashtable]$Attribution = @{})
    $id = if ("$CommitId".Trim()) { "$CommitId".Trim() } else { [guid]::NewGuid().ToString('N') }
    $ini = if ("$InitiatedBy".Trim()) { "$InitiatedBy".Trim() } else { Get-PimCommitJournalSystemActor }
    return [pscustomobject]@{ commitId = $id; source = $(if ("$Source".Trim()) { "$Source".Trim() } else { 'system' }); initiatedBy = $ini
                              approvedBy = "$ApprovedBy".Trim(); undoOf = "$UndoOf".Trim(); attribution = $Attribution }
}

function Get-PimCommitJournalSystemActor {
    # A write no person asked for (a job, a sync, a migration) names the process that made it.
    $job = "$env:PIM_JOB_NAME".Trim(); if (-not $job) { $job = "$env:CONTAINER_APP_JOB_NAME".Trim() }
    if ($job) { return "system:$job" }
    return 'system'
}

function Set-PimCommitJournalContext {
    <# Sets the ambient context for the store writes that follow; returns the previous one (restore it in a finally). #>
    param([AllowNull()][object]$Context)
    $prev = $global:PIM_CommitJournalContext
    $global:PIM_CommitJournalContext = $Context
    return $prev
}

function Get-PimCommitJournalContext {
    <# The ambient context, or a fresh 'system' one (its own commit id) when no caller set one. #>
    if ($global:PIM_CommitJournalContext) { return $global:PIM_CommitJournalContext }
    return (New-PimCommitJournalContext -Source 'system')
}

function Resolve-PimCommitJournalActor {
    <# PURE. @{ initiatedBy; approvedBy } for one key: the context's per-key attribution, else the context's own. #>
    param([Parameter(Mandatory)][object]$Context, [string]$Key)
    $a = $null
    if ($Context.attribution -and "$Key".Trim()) { $a = $Context.attribution["$Key".Trim().ToLowerInvariant()] }
    $ini = if ($a -and "$($a.initiatedBy)".Trim()) { "$($a.initiatedBy)".Trim() } else { "$($Context.initiatedBy)" }
    $apv = if ($a -and $a.Contains('approvedBy')) { "$($a.approvedBy)".Trim() } else { "$($Context.approvedBy)" }
    return @{ initiatedBy = $ini; approvedBy = $apv }
}

$script:PimCommitJournalInsertSql = @"
INSERT INTO pim.CommitJournal (CommitId, Entity, [Key], Op, BeforeJson, AfterJson, InitiatedBy, ApprovedBy, Source, UndoOf)
VALUES (@jc, @je, @jk, @jo, @jb, @ja, @ji, @jp, @js, @ju);
"@

function Add-PimCommitJournalRowTx {
    <#
      Writes ONE journal row on the caller's connection + transaction, so it commits or rolls back with the change.
      -Op Add | Modify | Remove. Throws on failure (the caller's transaction then rolls back).
    #>
    param([Parameter(Mandatory)][object]$Connection, [AllowNull()][object]$Transaction, [Parameter(Mandatory)][string]$Entity,
          [Parameter(Mandatory)][string]$Key, [Parameter(Mandatory)][ValidateSet('Add','Modify','Remove')][string]$Op,
          [AllowNull()][string]$BeforeJson, [AllowNull()][string]$AfterJson, [object]$Context)
    if (-not $Context) { $Context = Get-PimCommitJournalContext }
    $who = Resolve-PimCommitJournalActor -Context $Context -Key $Key
    $cmd = $Connection.CreateCommand(); if ($Transaction) { $cmd.Transaction = $Transaction }
    $cmd.CommandText = $script:PimCommitJournalInsertSql
    $p = [ordered]@{ jc = "$($Context.commitId)"; je = $Entity; jk = $Key; jo = $Op
                     jb = $(if ("$BeforeJson" -ne '') { $BeforeJson } else { $null }); ja = $(if ("$AfterJson" -ne '') { $AfterJson } else { $null })
                     ji = $(if ("$($who.initiatedBy)".Trim()) { "$($who.initiatedBy)" } else { 'system' }); jp = $(if ("$($who.approvedBy)".Trim()) { "$($who.approvedBy)" } else { $null })
                     js = "$($Context.source)"; ju = $(if ("$($Context.undoOf)".Trim()) { "$($Context.undoOf)" } else { $null }) }
    foreach ($k in $p.Keys) { [void]$cmd.Parameters.AddWithValue("@$k", $(if ($null -eq $p[$k]) { [DBNull]::Value } else { $p[$k] })) }
    [void]$cmd.ExecuteNonQuery()
}

function Get-PimRowJsonTx {
    <# The stored JSON of one row, read on the caller's transaction with UPDLOCK (nobody changes it until we commit). $null = absent. #>
    param([Parameter(Mandatory)][object]$Connection, [AllowNull()][object]$Transaction, [Parameter(Mandatory)][string]$Entity, [Parameter(Mandatory)][string]$Key)
    $cmd = $Connection.CreateCommand(); if ($Transaction) { $cmd.Transaction = $Transaction }
    $cmd.CommandText = 'SELECT DataJson FROM pim.Rows WITH (UPDLOCK, HOLDLOCK) WHERE Entity=@e AND [Key]=@k'
    [void]$cmd.Parameters.AddWithValue('@e', $Entity); [void]$cmd.Parameters.AddWithValue('@k', $Key)
    $v = $cmd.ExecuteScalar()
    if ($null -eq $v -or $v -is [DBNull]) { return $null }
    return "$v"
}

function Get-PimCommitJournalEntries {
    <# One commit's journal rows (oldest first). #>
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][string]$CommitId)
    return @(Invoke-PimSqlQuery -ConnectionString $ConnectionString -Parameters @{ c = $CommitId } -Sql @"
SELECT Id, CommitId, CommittedUtc, Entity, [Key], Op, BeforeJson, AfterJson, InitiatedBy, ApprovedBy, Source, UndoOf
FROM pim.CommitJournal WHERE CommitId = @c ORDER BY Id
"@)
}

function Get-PimCommitJournalCommits {
    <#
      The commit list (newest first): CommitId, CommittedUtc, InitiatedBy (the first row's), Source, UndoOf, Rows, Entities.
      -InitiatedBy: only commits that person initiated (CONFIG-1.2: an Admin sees only their own).
    #>
    param([Parameter(Mandatory)][string]$ConnectionString, [string]$InitiatedBy = '', [int]$Top = 200, [int]$Days = 90)
    $where = 'CommittedUtc >= DATEADD(DAY, -@d, SYSUTCDATETIME())'
    $p = @{ d = $Days; t = $Top }
    if ("$InitiatedBy".Trim()) { $where += ' AND InitiatedBy = @i'; $p['i'] = "$InitiatedBy".Trim() }
    return @(Invoke-PimSqlQuery -ConnectionString $ConnectionString -Parameters $p -Sql @"
SELECT TOP (@t) CommitId, MIN(CommittedUtc) AS CommittedUtc, MIN(InitiatedBy) AS InitiatedBy, MIN(Source) AS Source,
       MIN(UndoOf) AS UndoOf, COUNT(*) AS [Rows], COUNT(DISTINCT Entity) AS Entities
FROM pim.CommitJournal WHERE $where
GROUP BY CommitId ORDER BY MIN(Id) DESC
"@)
}

# =====================================================================================================================
# CONFIG-1.1 "what was applied there" / PIM 96.1 -- THE APPLIED OUTCOME PER ROW (the engine side of the journal).
#
# The journal says what a commit STORED. pim.CommitApplied says what the engine then DID in the tenant for it: per key,
# the commit it came from, the store row (Entity + Key, as in the journal), the live key, the operation and the result --
# created / updated / removed / already present / failed (+ the error). Written by the engine once per scope pass, only
# for items a commit names (a change no commit names -- an expiry, a catch-up of a row from before the journal -- has no
# commit to answer for). Never fails the run. Created at store open (Initialize-PimSqlStore), never failing the open.
#
# BUG-294: the engine used pim.ChangeAttribution (latest-wins per key) to name the commit. When two commits touched one
# key before the engine applied, both applies were credited to the later person. The journal keeps EVERY commit per key,
# so the commit is now resolved per key AND per operation (Resolve-PimJournalCommitForKey): a create credits the commit
# that ADDED the row, an update / remove the latest commit that changed it. ChangeAttribution stays the fallback (the
# definitions family's 'name:<GroupName>' alias, rows from before the journal).
# =====================================================================================================================

function Get-PimCommitAppliedDdl {
    @"
IF OBJECT_ID('pim.CommitApplied') IS NULL
CREATE TABLE pim.CommitApplied (
    Id          BIGINT IDENTITY(1,1) NOT NULL CONSTRAINT PK_pim_CommitApplied PRIMARY KEY,
    AppliedUtc  DATETIME2      NOT NULL CONSTRAINT DF_CommitApplied_Ts DEFAULT SYSUTCDATETIME(),
    CommitId    NVARCHAR(64)   NOT NULL,
    Entity      NVARCHAR(100)  NOT NULL,
    [Key]       NVARCHAR(400)  NOT NULL,
    Scope       NVARCHAR(50)   NOT NULL,
    LiveKey     NVARCHAR(400)  NOT NULL,
    Op          NVARCHAR(10)   NOT NULL,
    Result      NVARCHAR(20)   NOT NULL,
    Error       NVARCHAR(2000) NULL,
    JobRun      NVARCHAR(64)   NULL
);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_pim_CommitApplied_Commit')
CREATE INDEX IX_pim_CommitApplied_Commit ON pim.CommitApplied (CommitId);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_pim_CommitApplied_Live')
CREATE INDEX IX_pim_CommitApplied_Live ON pim.CommitApplied (Scope, LiveKey);
"@
}

function Initialize-PimCommitApplied {
    <# Creates pim.CommitApplied. Never throws (a store must still open); without it the engine records no outcome. #>
    param([Parameter(Mandatory)][string]$ConnectionString)
    try { [void](Invoke-PimSqlNonQuery -ConnectionString $ConnectionString -Sql (Get-PimCommitAppliedDdl)); return [pscustomobject]@{ ok = $true; detail = 'applied-outcome table in place' } }
    catch {
        Write-Warning "[journal] pim.CommitApplied could not be created -- the engine records no applied outcome until it exists: $($_.Exception.Message)"
        return [pscustomobject]@{ ok = $false; detail = "applied-outcome table NOT in place: $($_.Exception.Message)" }
    }
}

function ConvertTo-PimCommitAppliedResult {
    <# PURE. The engine's outcome of one item -> the CONFIG-1.1 result word. -Outcome ok | exists | error. #>
    param([Parameter(Mandatory)][string]$Op, [Parameter(Mandatory)][ValidateSet('ok','exists','error')][string]$Outcome)
    if ($Outcome -eq 'error') { return 'failed' }
    if ($Outcome -eq 'exists') { return 'already present' }
    switch -Regex ("$Op") { '^(?i)create$' { return 'created' } '^(?i)update$' { return 'updated' } '^(?i)remove$' { return 'removed' } default { return 'already present' } }
}

function New-PimCommitAppliedRecord {
    <# PURE. One outcome row. -Commit: the resolved commit (Resolve-PimEngineChangeCommit: CommitId, Entity, Key). $null without one. #>
    param([AllowNull()][object]$Commit, [Parameter(Mandatory)][string]$Scope, [string]$LiveKey = '', [Parameter(Mandatory)][string]$Op,
          [Parameter(Mandatory)][ValidateSet('ok','exists','error')][string]$Outcome, [string]$ErrorMessage = '', [string]$JobRun = '')
    if ($null -eq $Commit -or -not "$($Commit.CommitId)".Trim()) { return $null }
    $err = "$ErrorMessage"; if ($err.Length -gt 2000) { $err = $err.Substring(0, 1997) + '...' }
    $lk = "$LiveKey"; if ($lk.Length -gt 400) { $lk = $lk.Substring(0, 400) }
    return [pscustomobject]@{ commitId = "$($Commit.CommitId)".Trim(); entity = "$($Commit.Entity)"; key = "$($Commit.Key)"; scope = "$Scope"
                              liveKey = $lk; op = "$Op"; result = (ConvertTo-PimCommitAppliedResult -Op $Op -Outcome $Outcome)
                              error = $(if ($Outcome -eq 'error') { $err } else { '' }); jobRun = "$JobRun" }
}

function Save-PimCommitAppliedOutcomes {
    <#
      Writes the outcome rows in ONE round trip. Test seam: $global:PIM_CommitAppliedStore (a List[object]) collects them in
      memory. Returns the number written. Throws on a store error (the engine warns and carries on).
    #>
    param([string]$ConnectionString, [object[]]$Items = @())
    $rows = @(@($Items) | Where-Object { $null -ne $_ -and "$($_.commitId)".Trim() -and "$($_.entity)".Trim() -and "$($_.key)".Trim() })
    if (-not $rows.Count) { return 0 }
    if ($global:PIM_CommitAppliedStore -is [System.Collections.Generic.List[object]]) {
        foreach ($r in $rows) { $global:PIM_CommitAppliedStore.Add([pscustomobject]@{ AppliedUtc = [datetime]::UtcNow; CommitId = $r.commitId; Entity = $r.entity; Key = $r.key; Scope = $r.scope; LiveKey = $r.liveKey; Op = $r.op; Result = $r.result; Error = $r.error; JobRun = $r.jobRun }) }
        return $rows.Count
    }
    if (-not "$ConnectionString".Trim()) { return 0 }
    $json = ConvertTo-Json -InputObject @($rows | ForEach-Object { [ordered]@{ c = $_.commitId; e = $_.entity; k = $_.key; s = $_.scope; l = $_.liveKey; o = $_.op; r = $_.result; x = $_.error; j = $_.jobRun } }) -Compress -Depth 4
    [void](Invoke-PimSqlNonQuery -ConnectionString $ConnectionString -Parameters @{ j = $json } -Sql @"
INSERT INTO pim.CommitApplied (CommitId, Entity, [Key], Scope, LiveKey, Op, Result, Error, JobRun)
SELECT c, e, k, s, ISNULL(l, ''), o, r, NULLIF(x, ''), NULLIF(j, '')
FROM OPENJSON(@j) WITH (c NVARCHAR(64) '$.c', e NVARCHAR(100) '$.e', k NVARCHAR(400) '$.k', s NVARCHAR(50) '$.s', l NVARCHAR(400) '$.l',
                        o NVARCHAR(10) '$.o', r NVARCHAR(20) '$.r', x NVARCHAR(2000) '$.x', j NVARCHAR(64) '$.j');
"@)
    return $rows.Count
}

function Get-PimCommitAppliedOutcomes {
    <# What the engine did for one commit (oldest first). #>
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][string]$CommitId)
    if ($global:PIM_CommitAppliedStore -is [System.Collections.Generic.List[object]]) { return @($global:PIM_CommitAppliedStore | Where-Object { "$($_.CommitId)" -eq $CommitId }) }
    return @(Invoke-PimSqlQuery -ConnectionString $ConnectionString -Parameters @{ c = $CommitId } -Sql @"
IF OBJECT_ID('pim.CommitApplied') IS NOT NULL
SELECT Id, AppliedUtc, CommitId, Entity, [Key], Scope, LiveKey, Op, Result, Error, JobRun FROM pim.CommitApplied WHERE CommitId = @c ORDER BY Id
"@)
}

function Get-PimCommitAppliedFailedCreates {
    <#
      D2 (b): the live keys of one scope whose CREATE by a commit FAILED (the call errored) -- if a later full live read sees
      such a key live, the platform took PIM's request after all, so the key is confirmed. -LiveKeys narrows the read. Returns
      @{ liveKey(lower) -> @{ commitId; sourceEntity; sourceKey } } (the latest per key). Never throws (an empty answer
      confirms nothing).
    #>
    param([string]$ConnectionString, [Parameter(Mandatory)][string]$Scope, [string[]]$LiveKeys = @())
    $out = @{}
    $want = @{}; foreach ($k in @($LiveKeys)) { if ("$k".Trim()) { $want["$k".Trim().ToLowerInvariant()] = $true } }
    if (-not $want.Count) { return $out }
    try {
        $rows = @()
        if ($global:PIM_CommitAppliedStore -is [System.Collections.Generic.List[object]]) {
            $rows = @($global:PIM_CommitAppliedStore | Where-Object { "$($_.Scope)" -eq $Scope -and "$($_.Op)" -eq 'Create' -and "$($_.Result)" -eq 'failed' })
        } elseif ("$ConnectionString".Trim()) {
            $json = ConvertTo-Json -InputObject @($want.Keys) -Compress
            $rows = @(Invoke-PimSqlQuery -ConnectionString $ConnectionString -Parameters @{ s = $Scope; j = $json } -Sql @"
IF OBJECT_ID('pim.CommitApplied') IS NOT NULL
SELECT Id, CommitId, Entity, [Key], LiveKey FROM pim.CommitApplied
WHERE Scope = @s AND Op = 'Create' AND Result = 'failed' AND LiveKey IN (SELECT [value] FROM OPENJSON(@j)) ORDER BY Id
"@)
        }
        foreach ($r in $rows) {
            $lk = "$($r.LiveKey)".Trim().ToLowerInvariant()
            if ($want.ContainsKey($lk)) { $out[$lk] = @{ commitId = "$($r.CommitId)"; sourceEntity = "$($r.Entity)"; sourceKey = "$($r.Key)" } }
        }
    } catch { Write-Warning "[journal] failed creates of $Scope could not be read (nothing is confirmed from them this run): $($_.Exception.Message)" }
    return $out
}

function Get-PimCommitJournalKeyIndex {
    <#
      The recent journal (no row JSON), as a lookup: 'entity|key' (lower) -> rows oldest first (Id, CommitId, CommittedUtc,
      Entity, Key, Op, InitiatedBy, ApprovedBy, Source). Read once per engine run. Never throws (an empty index resolves
      nothing; the attribution then answers).
    #>
    param([Parameter(Mandatory)][string]$ConnectionString, [int]$Days = 30)
    $ix = @{}
    try {
        $rows = @(Invoke-PimSqlQuery -ConnectionString $ConnectionString -Parameters @{ d = $Days } -Sql @"
IF OBJECT_ID('pim.CommitJournal') IS NOT NULL
SELECT Id, CommitId, CommittedUtc, Entity, [Key], Op, InitiatedBy, ApprovedBy, Source FROM pim.CommitJournal
WHERE CommittedUtc >= DATEADD(DAY, -@d, SYSUTCDATETIME()) ORDER BY Id
"@)
        foreach ($r in $rows) {
            $k = ("{0}|{1}" -f "$($r.Entity)", "$($r.Key)").ToLowerInvariant()
            if (-not $ix.ContainsKey($k)) { $ix[$k] = New-Object System.Collections.Generic.List[object] }
            $ix[$k].Add($r)
        }
    } catch { Write-Warning "[journal] the change journal could not be read (the latest-commit attribution names the commits): $($_.Exception.Message)" }
    return $ix
}

function Get-PimCommitJournalKeyHistory {
    <#
      The FULL journal history (no time window, no row JSON) of the given store rows: -Refs @(@{ entity; key }). Returns
      'entity|key' (lower) -> rows oldest first. Test seam: $global:PIM_CommitJournalHistoryStore (the same shape). THROWS when
      the journal cannot be read (the reconcile then removes nothing: a missing history is never "no history").
    #>
    param([string]$ConnectionString, [object[]]$Refs = @())
    $f = { param($o, $n) if ($o -is [System.Collections.IDictionary]) { "$($o[$n])" } elseif ($null -ne $o -and $o.PSObject.Properties[$n]) { "$($o.$n)" } else { '' } }
    $want = @{}
    foreach ($r in @($Refs)) { $e = (& $f $r 'entity').Trim(); $k = (& $f $r 'key').Trim(); if ($e -and $k) { $want[("{0}|{1}" -f $e, $k).ToLowerInvariant()] = [ordered]@{ e = $e; k = $k } } }
    $out = @{}
    if (-not $want.Count) { return $out }
    if ($global:PIM_CommitJournalHistoryStore -is [hashtable]) {
        foreach ($wk in @($want.Keys)) { if ($global:PIM_CommitJournalHistoryStore.ContainsKey($wk)) { $out[$wk] = @($global:PIM_CommitJournalHistoryStore[$wk]) } }
        return $out
    }
    if (-not "$ConnectionString".Trim()) { throw 'no SQL store to read the change journal from' }
    $json = ConvertTo-Json -InputObject @($want.Values) -Compress -Depth 3
    $rows = @(Invoke-PimSqlQuery -ConnectionString $ConnectionString -Parameters @{ j = $json } -Sql @"
SELECT c.Id, c.CommitId, c.CommittedUtc, c.Entity, c.[Key], c.Op, c.InitiatedBy, c.ApprovedBy, c.Source
FROM pim.CommitJournal c
JOIN OPENJSON(@j) WITH (e NVARCHAR(100) '$.e', k NVARCHAR(400) '$.k') w ON c.Entity = w.e AND c.[Key] = w.k
ORDER BY c.Id
"@)
    foreach ($r in $rows) {
        $k = ("{0}|{1}" -f "$($r.Entity)", "$($r.Key)").ToLowerInvariant()
        if (-not $out.ContainsKey($k)) { $out[$k] = New-Object System.Collections.Generic.List[object] }
        $out[$k].Add($r)
    }
    $res = @{}; foreach ($k in @($out.Keys)) { $res[$k] = @($out[$k].ToArray()) }
    return $res
}

function Test-PimCommitJournalIsPimCommit {
    <# PURE. A journal row made by a PIM COMMIT (a person, the API, an import, a restore, an undo, the queue, an MSP pull) --
       not a 'system' write no one asked for (a job's bookkeeping, a migration). #>
    param([AllowNull()][object]$Row)
    if ($null -eq $Row) { return $false }
    $s = "$($Row.Source)".Trim().ToLowerInvariant()
    return ($s -and $s -ne 'system')
}

function Resolve-PimJournalCommitForKey {
    <#
      PURE (BUG-294). Which commit asked for this operation on this store row? -History: the row's journal rows, oldest first.
        Create -> the latest commit that ADDED the row (a later edit before the apply does not take the creation's credit);
        Update / Remove / anything else -> the latest commit that touched it.
      'system' writes never answer (nobody asked for them). Returns the journal row, or $null.
    #>
    param([object[]]$History = @(), [string]$Op = '')
    $h = @(@($History) | Where-Object { Test-PimCommitJournalIsPimCommit -Row $_ })
    if (-not $h.Count) { return $null }
    if ("$Op" -match '^(?i)create$') {
        $adds = @($h | Where-Object { "$($_.Op)" -eq 'Add' })
        if ($adds.Count) { return $adds[-1] }
    }
    return $h[-1]
}
