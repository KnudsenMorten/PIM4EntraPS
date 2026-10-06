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
