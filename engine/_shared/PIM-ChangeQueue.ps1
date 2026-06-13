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
    param(
        [Parameter(Mandatory)][string]$Entity,
        [Parameter(Mandatory)][string]$Key,
        [Parameter(Mandatory)][ValidateSet('Create','Update','Remove')][string]$Op,
        [object]$Payload,
        [string]$By = "$env:USERNAME",
        [string]$EnqueuedUtc
    )
    if (-not $EnqueuedUtc) { $EnqueuedUtc = ([datetime]::UtcNow).ToString('o') }
    return [pscustomobject]@{
        id = [guid]::NewGuid().ToString(); entity = "$Entity"; key = "$Key"; op = "$Op"
        payload = $Payload; enqueuedUtc = "$EnqueuedUtc"; by = "$By"; status = 'pending'
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
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name='IX_ChangeQueue_Pending' AND object_id=OBJECT_ID('pim.ChangeQueue'))
    CREATE INDEX IX_ChangeQueue_Pending ON pim.ChangeQueue (Status, EnqueuedUtc);
"@
}
