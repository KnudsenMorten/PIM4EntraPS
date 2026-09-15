# PIM4EntraPS -- change queue + full/delta run modes.
# Dot-sourced by PIM-Functions.psm1 and standalone by the pim-manager.
#
# Problem: today a run reconciles EVERYTHING (1-2 hours before a single change
# shows up). Fix: the GUI "commit" ENQUEUES only the changed items; the engine
# drains the queue fast (DELTA), instead of a full sweep (FULL).
#
# Pure, storage-agnostic core (change records + net-fold + ordered apply plan),
# fully testable offline. Persistence is a thin adapter (JSON file now; the SQL
# queue table lands with the SQL-only data layer -- Get-PimChangeQueueDdl below).
#
# A change record:
#   @{ id; entity; key; op(Create|Update|Remove); payload; enqueuedUtc; by; status }
# entity = a definitions/assignments base (e.g. PIM-Definitions-Tasks); key = the
# row's natural key within that base.

Set-StrictMode -Off

# Apply ORDER: definitions before the assignments that reference them; within a
# pass, creates/updates before removes; assignment removes before definition
# removes (so you never orphan a binding). Lower rank applies first.
function Get-PimEntityOrderRank {
    param([string]$Entity)
    $e = "$Entity".ToLowerInvariant()
    if ($e -like '*definitions*') { return 0 }
    if ($e -like '*assignments*') { return 1 }
    return 2
}

function New-PimChange {
    <#
      §65 -- Kind/Origin default to the ORIGINAL behaviour (DesiredState + Proposal) so every
      existing caller keeps its exact semantics without being touched. A caller that means
      something else must say so, which is the point: an imperative action or an operator-authorised
      entry is never produced by accident.

      🔒 status ALWAYS starts 'pending'. Nothing here can mint a pre-committed entry -- committing
      is an operator act on a stored row (§65.7), not a property of construction. If this ever grows
      a -Status parameter, the commit gate has been bypassed.
    #>
    param(
        [Parameter(Mandatory)][string]$Entity,
        [Parameter(Mandatory)][string]$Key,
        [Parameter(Mandatory)][ValidateSet('Create','Update','Remove')][string]$Op,
        [object]$Payload,
        [string]$By = "$env:USERNAME",
        [string]$EnqueuedUtc,
        [ValidateSet('DesiredState','Action')][string]$Kind = 'DesiredState',
        [ValidateSet('Proposal','Authorised')][string]$Origin = 'Proposal',
        # Why the operator asked for it. Carried for revokes because the Graph call already demands
        # one, and an audit trail that loses it is worse than the synchronous call it replaced.
        [string]$Justification = ''
    )
    if (-not $EnqueuedUtc) { $EnqueuedUtc = ([datetime]::UtcNow).ToString('o') }
    return [pscustomobject]@{
        id = [guid]::NewGuid().ToString(); entity = "$Entity"; key = "$Key"; op = "$Op"
        payload = $Payload; enqueuedUtc = "$EnqueuedUtc"; by = "$By"; status = 'pending'
        kind = "$Kind"; origin = "$Origin"; justification = "$Justification"
        committedBy = ''; committedUtc = ''; attempts = 0; lastError = ''; appliedUtc = ''
    }
}

# Fold a chronological list of changes on the SAME (entity,key) to its NET op:
#   Create then Remove   -> (none, cancelled)
#   Create then Update   -> Create (payload from the update)
#   Update then Remove   -> Remove
#   Remove then Create   -> Update (re-add)
#   last write wins for payload otherwise
function Resolve-PimNetChange {
    param([Parameter(Mandatory)][object[]]$Changes)
    $ordered = @($Changes | Sort-Object { $_.enqueuedUtc })
    $netOp = $null; $payload = $null; $first = $ordered[0]
    foreach ($c in $ordered) {
        switch ("$($c.op)") {
            'Create' { if ($netOp -eq 'Remove') { $netOp = 'Update' } else { $netOp = 'Create' }; $payload = $c.payload }
            'Update' { if ($netOp -eq 'Create') { $netOp = 'Create' } elseif ($netOp -eq 'Remove') { $netOp = 'Update' } else { $netOp = 'Update' }; $payload = $c.payload }
            'Remove' { if ($netOp -eq 'Create') { $netOp = $null; $payload = $null } else { $netOp = 'Remove'; $payload = $c.payload } }
        }
    }
    if (-not $netOp) { return $null }   # cancelled out
    return [pscustomobject]@{
        entity = "$($first.entity)"; key = "$($first.key)"; op = $netOp; payload = $payload
        by = "$($ordered[-1].by)"; enqueuedUtc = "$($ordered[-1].enqueuedUtc)"
    }
}

# Collapse a raw queue to net changes (dedup per entity|key, cancellations dropped).
function Get-PimQueueNetChanges {
    param([object[]]$Queue = @())
    $groups = @{}
    foreach ($c in @($Queue)) {
        $k = ("$($c.entity)|$($c.key)").ToLowerInvariant()
        if (-not $groups.ContainsKey($k)) { $groups[$k] = New-Object System.Collections.Generic.List[object] }
        $groups[$k].Add($c)
    }
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($k in $groups.Keys) {
        $net = Resolve-PimNetChange -Changes $groups[$k].ToArray()
        if ($net) { $out.Add($net) }
    }
    return $out.ToArray()
}

# Ordered apply plan from a queue: net changes sorted by entity rank then op
# (Create/Update before Remove within definitions; for removes, assignments before
# definitions via descending entity rank).
function Get-PimQueueApplyPlan {
    param([object[]]$Queue = @())
    $net = @(Get-PimQueueNetChanges -Queue $Queue)
    $opRank = @{ Create = 0; Update = 0; Remove = 1 }
    $creates = @($net | Where-Object { $_.op -ne 'Remove' } | Sort-Object { Get-PimEntityOrderRank $_.entity }, { "$($_.key)" })
    # removes apply in REVERSE entity order (assignments before definitions)
    $removes = @($net | Where-Object { $_.op -eq 'Remove' } | Sort-Object { - (Get-PimEntityOrderRank $_.entity) }, { "$($_.key)" })
    return @($creates + $removes)
}

# Run set for the engine: DELTA = just the queue's net plan; FULL = upsert
# (Create/Update) changes for EVERY desired item (full reconcile). $DesiredItems
# rows are objects with .entity + .key (+ payload = the row).
function Get-PimRunSet {
    param(
        [Parameter(Mandatory)][ValidateSet('Full','Delta')][string]$Mode,
        [object[]]$Queue = @(),
        [object[]]$DesiredItems = @()
    )
    if ($Mode -eq 'Delta') { return @(Get-PimQueueApplyPlan -Queue $Queue) }
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($d in @($DesiredItems)) {
        $out.Add([pscustomobject]@{ entity = "$($d.entity)"; key = "$($d.key)"; op = 'Update'; payload = $d.payload; by = 'full-run'; enqueuedUtc = ([datetime]::UtcNow).ToString('o') })
    }
    return @($out.ToArray() | Sort-Object { Get-PimEntityOrderRank $_.entity }, { "$($_.key)" })
}

# --- persistence adapter (JSON now; SQL via the Phase-6 data layer) -------------
function Read-PimChangeQueue {
    param([Parameter(Mandatory)][string]$QueueFile)
    if (-not (Test-Path -LiteralPath $QueueFile)) { return @() }
    try { return @((Get-Content -LiteralPath $QueueFile -Raw -Encoding UTF8 | ConvertFrom-Json).changes) } catch { return @() }
}

function Add-PimChangeToQueue {
    param([Parameter(Mandatory)][string]$QueueFile, [Parameter(Mandatory)][object]$Change)
    $dir = Split-Path -Parent $QueueFile
    if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $list = New-Object System.Collections.Generic.List[object]
    foreach ($c in (Read-PimChangeQueue -QueueFile $QueueFile)) { $list.Add($c) }
    $list.Add($Change)
    @{ changes = $list.ToArray() } | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $QueueFile -Encoding UTF8
    return $list.Count
}

function Clear-PimChangeQueue {
    # Drop the (applied) changes; optionally keep a specified set of ids pending.
    param([Parameter(Mandatory)][string]$QueueFile, [string[]]$KeepIds = @())
    $keep = @{}; foreach ($i in @($KeepIds)) { $keep["$i"] = $true }
    $remaining = @(Read-PimChangeQueue -QueueFile $QueueFile | Where-Object { $keep.ContainsKey("$($_.id)") })
    @{ changes = $remaining } | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $QueueFile -Encoding UTF8
    return $remaining.Count
}

# SQL queue table DDL (Phase-6 SQL-only data layer will create this).
function Get-PimChangeQueueDdl {
    <#
      §65 -- THE QUEUE IS A SHARED REVIEW SURFACE, not an internal staging buffer.

      Two dimensions the original table could not express, and one lifecycle:

        Kind   DesiredState : Payload IS a pim.Rows row (today's behaviour)
               Action       : Payload is an imperative directory operation (revoke, TAP reset,
                              session revoke) that is NEVER written to pim.Rows
        Origin Proposal     : discovery proposed it
               Authorised   : an operator action in the GUI created it

      🔒 ORIGIN DOES NOT GRANT THE RIGHT TO APPLY -- THE COMMIT DOES (§65.7). Only Status='committed'
      is drained, which is what keeps BUG-135's "propose-don't-auto-map" rule intact: a discovery
      proposal is never applied because nobody committed it, not because the queue refuses its kind.

      🔒 EVERY DEFAULT PRESERVES TODAY'S BEHAVIOUR. An existing row backfills to
      DesiredState + Proposal + pending, so nothing already queued starts draining because this
      shipped. Asserted in tests/Test-PimChangeQueue.ps1, not reasoned about.

      🪤 THE COLUMNS BELOW ARE WHY BUG-152 WAS UNFIXABLE IN PLACE. With one Status for the whole
      batch and no per-entry outcome, "retry what failed" had nothing to retry FROM -- see
      Invoke-PimSqlCommit's old blanket `UPDATE ... WHERE Status='pending'`.
    #>
    return @"
IF SCHEMA_ID('pim') IS NULL EXEC ('CREATE SCHEMA pim');
IF OBJECT_ID('pim.ChangeQueue') IS NULL
CREATE TABLE pim.ChangeQueue (
    Id           UNIQUEIDENTIFIER NOT NULL PRIMARY KEY DEFAULT NEWID(),
    Entity       NVARCHAR(100)  NOT NULL,
    [Key]        NVARCHAR(400)  NOT NULL,
    Op           NVARCHAR(10)   NOT NULL CONSTRAINT CK_ChangeQueue_Op CHECK (Op IN ('Create','Update','Remove')),
    Payload      NVARCHAR(MAX)  NULL,         -- JSON
    EnqueuedUtc  DATETIME2      NOT NULL CONSTRAINT DF_ChangeQueue_Enq DEFAULT SYSUTCDATETIME(),
    [By]         NVARCHAR(200)  NULL,
    Status       NVARCHAR(20)   NOT NULL CONSTRAINT DF_ChangeQueue_Status DEFAULT 'pending'
);
-- §65 columns, added idempotently so an EXISTING store (internal already has this table) migrates
-- in place. A NOT NULL column with a DEFAULT backfills every existing row, which is what makes the
-- "nothing already queued starts draining" guarantee true rather than aspirational.
IF COL_LENGTH('pim.ChangeQueue','Kind') IS NULL
    ALTER TABLE pim.ChangeQueue ADD Kind NVARCHAR(20) NOT NULL
        CONSTRAINT DF_ChangeQueue_Kind DEFAULT 'DesiredState';
IF COL_LENGTH('pim.ChangeQueue','Origin') IS NULL
    ALTER TABLE pim.ChangeQueue ADD Origin NVARCHAR(20) NOT NULL
        CONSTRAINT DF_ChangeQueue_Origin DEFAULT 'Proposal';
IF COL_LENGTH('pim.ChangeQueue','Justification') IS NULL
    ALTER TABLE pim.ChangeQueue ADD Justification NVARCHAR(1000) NULL;
IF COL_LENGTH('pim.ChangeQueue','CommittedBy') IS NULL
    ALTER TABLE pim.ChangeQueue ADD CommittedBy NVARCHAR(200) NULL;
IF COL_LENGTH('pim.ChangeQueue','CommittedUtc') IS NULL
    ALTER TABLE pim.ChangeQueue ADD CommittedUtc DATETIME2 NULL;
IF COL_LENGTH('pim.ChangeQueue','Attempts') IS NULL
    ALTER TABLE pim.ChangeQueue ADD Attempts INT NOT NULL
        CONSTRAINT DF_ChangeQueue_Attempts DEFAULT 0;
IF COL_LENGTH('pim.ChangeQueue','LastAttemptUtc') IS NULL
    ALTER TABLE pim.ChangeQueue ADD LastAttemptUtc DATETIME2 NULL;
IF COL_LENGTH('pim.ChangeQueue','LastError') IS NULL
    ALTER TABLE pim.ChangeQueue ADD LastError NVARCHAR(MAX) NULL;
IF COL_LENGTH('pim.ChangeQueue','AppliedUtc') IS NULL
    ALTER TABLE pim.ChangeQueue ADD AppliedUtc DATETIME2 NULL;
-- The applying identity, so a drain can be attributed to ca-pim-tick vs a host run (§64.7 trap 1:
-- the runtime identity is the one fact every wrong diagnosis this month started by assuming).
IF COL_LENGTH('pim.ChangeQueue','AppliedBy') IS NULL
    ALTER TABLE pim.ChangeQueue ADD AppliedBy NVARCHAR(200) NULL;
-- DISCARD (2026-09-12): an operator removes a stale pending/failed entry from the open work WITHOUT
-- deleting it (section 65.8 retains history). Additive + nullable, so an unmigrated store is unaffected.
IF COL_LENGTH('pim.ChangeQueue','DiscardedBy') IS NULL
    ALTER TABLE pim.ChangeQueue ADD DiscardedBy NVARCHAR(200) NULL;
IF COL_LENGTH('pim.ChangeQueue','DiscardedUtc') IS NULL
    ALTER TABLE pim.ChangeQueue ADD DiscardedUtc DATETIME2 NULL;
IF COL_LENGTH('pim.ChangeQueue','DiscardReason') IS NULL
    ALTER TABLE pim.ChangeQueue ADD DiscardReason NVARCHAR(1000) NULL;

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name='IX_ChangeQueue_Pending' AND object_id=OBJECT_ID('pim.ChangeQueue'))
    CREATE INDEX IX_ChangeQueue_Pending ON pim.ChangeQueue (Status, EnqueuedUtc);
-- The drain's own predicate (Status + Kind), so claiming work does not scan the whole queue.
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name='IX_ChangeQueue_Drain' AND object_id=OBJECT_ID('pim.ChangeQueue'))
    CREATE INDEX IX_ChangeQueue_Drain ON pim.ChangeQueue (Status, Kind, EnqueuedUtc);
"@
}

# The queue's vocabulary, in ONE place so a typo cannot invent a state. Every consumer -- the GUI,
# the drain, the gates -- validates against these rather than matching strings inline.
function Get-PimQueueVocabulary {
    return [pscustomobject]@{
        Kinds    = @('DesiredState','Action')
        Origins  = @('Proposal','Authorised')
        # pending   -> nobody has committed it yet; NEVER drained (this is BUG-135's rule)
        # committed -> an operator selected it; the drain will claim it
        # applying  -> CLAIMED by a drain and in flight. Only ACTIONS reach this state: a directory
        #              call cannot be rolled back the way a pim.Rows write can, so the claim happens
        #              BEFORE the effect. A row stuck here means a drain died mid-action -- which is
        #              exactly what you want to be able to see, rather than having a second drain
        #              silently re-issue the same revoke.
        # applied   -> the effect was re-read and CONFIRMED (§65.8: not "the POST returned 200")
        # failed    -> attempts exhausted, or terminal; RETAINED and surfaced, never deleted
        # discarded -> an operator took a pending/failed entry OUT of the open work, with a reason;
        #              RETAINED (never deleted) and never drained -- the drain only claims 'committed'
        Statuses = @('pending','committed','applying','applied','failed','discarded')
        Terminal = @('applied','failed','discarded')
    }
}
