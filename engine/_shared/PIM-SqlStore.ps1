# PIM4EntraPS -- SQL data store (the SQL-only data layer).
# Dot-sourced by PIM-Functions.psm1 (uses PIM-ChangeQueue.ps1 for the commit
# plan) and the pim-manager.
#
# The new solution is SQL-only -- no CSV. Storage-neutral naming throughout
# (entity / row / store, never "csv"). Access is RAW ADO.NET (System.Data.
# SqlClient) -- NOT the SqlServer PowerShell module -- so there is no module
# dependency, it is PS 5.1-safe, and it never drags Azure.Core into a Graph
# process (the SqlServer-module-poisons-Connect-MgGraph trap).
#
# Row store: pim.Rows(Entity, [Key], DataJson, UpdatedUtc) -- one JSON row per
# (entity, key). The locked column structure is enforced at the app layer
# (PIM-SchemaConformance.ps1); typed per-entity tables can be layered on later.
# Commit drains the queue (pim.ChangeQueue) as a DELTA against pim.Rows.

Set-StrictMode -Off
Add-Type -AssemblyName System.Data -ErrorAction SilentlyContinue

function Get-PimSqlConnectionString {
    # Prod: $global:PIM_SqlConnectionString. Otherwise build from server+db
    # (dev default server .\SQLEXPRESS, integrated auth).
    param([string]$Server, [string]$Database = 'PIM4EntraPS')
    if ($global:PIM_SqlConnectionString -and -not $Server) { return $global:PIM_SqlConnectionString }
    $srv = if ($Server) { $Server } elseif ($global:PIM_SqlServer) { $global:PIM_SqlServer } else { '.\SQLEXPRESS' }
    return "Server=$srv;Database=$Database;Integrated Security=SSPI;Encrypt=False;TrustServerCertificate=True;Connection Timeout=15"
}

function Assert-PimSqlIdentifier {
    # Guard a DB/object name we must string-build (CREATE DATABASE can't bind it).
    param([Parameter(Mandatory)][string]$Name)
    if ($Name -notmatch '^[A-Za-z0-9_]+$') { throw "Unsafe SQL identifier '$Name' (allowed: A-Z a-z 0-9 _)." }
    return $Name
}

function Invoke-PimSqlQuery {
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][string]$Sql, [hashtable]$Parameters = @{})
    $c = New-Object System.Data.SqlClient.SqlConnection $ConnectionString
    try {
        $c.Open(); $cmd = $c.CreateCommand(); $cmd.CommandText = $Sql
        foreach ($k in $Parameters.Keys) { [void]$cmd.Parameters.AddWithValue("@$k", $(if ($null -eq $Parameters[$k]) { [DBNull]::Value } else { $Parameters[$k] })) }
        $rd = $cmd.ExecuteReader(); $rows = New-Object System.Collections.Generic.List[object]
        while ($rd.Read()) { $o = [ordered]@{}; for ($i = 0; $i -lt $rd.FieldCount; $i++) { $o[$rd.GetName($i)] = $(if ($rd.IsDBNull($i)) { $null } else { $rd.GetValue($i) }) }; $rows.Add([pscustomobject]$o) }
        $rd.Close(); return $rows.ToArray()
    } finally { $c.Close() }
}

function Invoke-PimSqlNonQuery {
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][string]$Sql, [hashtable]$Parameters = @{})
    $c = New-Object System.Data.SqlClient.SqlConnection $ConnectionString
    try {
        $c.Open(); $cmd = $c.CreateCommand(); $cmd.CommandText = $Sql
        foreach ($k in $Parameters.Keys) { [void]$cmd.Parameters.AddWithValue("@$k", $(if ($null -eq $Parameters[$k]) { [DBNull]::Value } else { $Parameters[$k] })) }
        return $cmd.ExecuteNonQuery()
    } finally { $c.Close() }
}

function Invoke-PimSqlScalar {
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][string]$Sql, [hashtable]$Parameters = @{})
    $c = New-Object System.Data.SqlClient.SqlConnection $ConnectionString
    try {
        $c.Open(); $cmd = $c.CreateCommand(); $cmd.CommandText = $Sql
        foreach ($k in $Parameters.Keys) { [void]$cmd.Parameters.AddWithValue("@$k", $(if ($null -eq $Parameters[$k]) { [DBNull]::Value } else { $Parameters[$k] })) }
        return $cmd.ExecuteScalar()
    } finally { $c.Close() }
}

function Initialize-PimSqlDatabase {
    # Create the database if missing (connects to master). Idempotent.
    param([string]$Server, [Parameter(Mandatory)][string]$Database)
    [void](Assert-PimSqlIdentifier -Name $Database)
    $masterCs = Get-PimSqlConnectionString -Server $Server -Database 'master'
    [void](Invoke-PimSqlNonQuery -ConnectionString $masterCs -Sql "IF DB_ID('$Database') IS NULL CREATE DATABASE [$Database];")
}

function Initialize-PimSqlStore {
    # Create the pim schema + tables (pim.Rows + pim.ChangeQueue). Idempotent.
    param([Parameter(Mandatory)][string]$ConnectionString)
    $ddl = @"
IF SCHEMA_ID('pim') IS NULL EXEC ('CREATE SCHEMA pim');
IF OBJECT_ID('pim.Rows') IS NULL
CREATE TABLE pim.Rows (
    Entity      NVARCHAR(100) NOT NULL,
    [Key]       NVARCHAR(400) NOT NULL,
    DataJson    NVARCHAR(MAX) NULL,
    UpdatedUtc  DATETIME2     NOT NULL CONSTRAINT DF_Rows_Updated DEFAULT SYSUTCDATETIME(),
    CONSTRAINT PK_pim_Rows PRIMARY KEY (Entity, [Key])
);
"@
    [void](Invoke-PimSqlNonQuery -ConnectionString $ConnectionString -Sql $ddl)
    [void](Invoke-PimSqlNonQuery -ConnectionString $ConnectionString -Sql (Get-PimChangeQueueDdl))
}

# --- row CRUD -------------------------------------------------------------------
function Get-PimSqlRows {
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][string]$Entity)
    $raw = Invoke-PimSqlQuery -ConnectionString $ConnectionString -Sql "SELECT [Key], DataJson FROM pim.Rows WHERE Entity = @e ORDER BY [Key]" -Parameters @{ e = $Entity }
    return @($raw | ForEach-Object { if ("$($_.DataJson)".Trim()) { $_.DataJson | ConvertFrom-Json } })
}

function Get-PimSqlRow {
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][string]$Entity, [Parameter(Mandatory)][string]$Key)
    $j = Invoke-PimSqlScalar -ConnectionString $ConnectionString -Sql "SELECT DataJson FROM pim.Rows WHERE Entity=@e AND [Key]=@k" -Parameters @{ e = $Entity; k = $Key }
    if ($null -eq $j -or "$j".Trim() -eq '') { return $null }
    return ($j | ConvertFrom-Json)
}

function Set-PimSqlRow {
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][string]$Entity, [Parameter(Mandatory)][string]$Key, [object]$Data)
    $json = if ($null -ne $Data) { $Data | ConvertTo-Json -Depth 12 -Compress } else { '{}' }
    $sql = @"
MERGE pim.Rows AS t USING (SELECT @e AS Entity, @k AS [Key]) AS s
  ON t.Entity = s.Entity AND t.[Key] = s.[Key]
WHEN MATCHED THEN UPDATE SET DataJson = @d, UpdatedUtc = SYSUTCDATETIME()
WHEN NOT MATCHED THEN INSERT (Entity, [Key], DataJson, UpdatedUtc) VALUES (@e, @k, @d, SYSUTCDATETIME());
"@
    [void](Invoke-PimSqlNonQuery -ConnectionString $ConnectionString -Sql $sql -Parameters @{ e = $Entity; k = $Key; d = $json })
}

function Remove-PimSqlRow {
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][string]$Entity, [Parameter(Mandatory)][string]$Key)
    [void](Invoke-PimSqlNonQuery -ConnectionString $ConnectionString -Sql "DELETE FROM pim.Rows WHERE Entity=@e AND [Key]=@k" -Parameters @{ e = $Entity; k = $Key })
}

# --- SQL-backed change queue (mirrors the JSON adapter) -------------------------
function Add-PimSqlQueueChange {
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][object]$Change)
    $payload = if ($null -ne $Change.payload) { $Change.payload | ConvertTo-Json -Depth 12 -Compress } else { $null }
    [void](Invoke-PimSqlNonQuery -ConnectionString $ConnectionString -Sql @"
INSERT INTO pim.ChangeQueue (Id, Entity, [Key], Op, Payload, EnqueuedUtc, [By], Status)
VALUES (@id, @e, @k, @op, @p, @enq, @by, 'pending');
"@ -Parameters @{ id = [guid]$Change.id; e = "$($Change.entity)"; k = "$($Change.key)"; op = "$($Change.op)"; p = $payload; enq = [datetime]$Change.enqueuedUtc; by = "$($Change.by)" })
}

function Get-PimSqlQueue {
    param([Parameter(Mandatory)][string]$ConnectionString, [string]$Status = 'pending')
    $raw = Invoke-PimSqlQuery -ConnectionString $ConnectionString -Sql "SELECT Id, Entity, [Key], Op, Payload, EnqueuedUtc, [By], Status FROM pim.ChangeQueue WHERE Status=@s ORDER BY EnqueuedUtc" -Parameters @{ s = $Status }
    return @($raw | ForEach-Object {
        [pscustomobject]@{ id = "$($_.Id)"; entity = "$($_.Entity)"; key = "$($_.Key)"; op = "$($_.Op)"
            payload = $(if ("$($_.Payload)".Trim()) { $_.Payload | ConvertFrom-Json } else { $null })
            enqueuedUtc = ([datetime]$_.EnqueuedUtc).ToString('o'); by = "$($_.By)"; status = "$($_.Status)" }
    })
}

# --- the fast commit: drain the queue as a DELTA against pim.Rows ----------------
function Invoke-PimSqlCommit {
    # Apply the pending queue's NET plan to pim.Rows, then mark the changes applied.
    # This is the "hit commit -> change populates fast" path (no full sweep).
    param([Parameter(Mandatory)][string]$ConnectionString)
    $pending = @(Get-PimSqlQueue -ConnectionString $ConnectionString -Status 'pending')
    if ($pending.Count -eq 0) { return [pscustomobject]@{ applied = 0; rowsAffected = 0 } }
    $plan = @(Get-PimQueueApplyPlan -Queue $pending)   # pure fold + ordering (PIM-ChangeQueue.ps1)
    $affected = 0
    foreach ($ch in $plan) {
        if ($ch.op -eq 'Remove') { Remove-PimSqlRow -ConnectionString $ConnectionString -Entity "$($ch.entity)" -Key "$($ch.key)" }
        else { Set-PimSqlRow -ConnectionString $ConnectionString -Entity "$($ch.entity)" -Key "$($ch.key)" -Data $ch.payload }
        $affected++
    }
    [void](Invoke-PimSqlNonQuery -ConnectionString $ConnectionString -Sql "UPDATE pim.ChangeQueue SET Status='applied' WHERE Status='pending'")
    return [pscustomobject]@{ applied = $pending.Count; netChanges = $plan.Count; rowsAffected = $affected }
}

function Test-PimSqlConnectivity {
    param([Parameter(Mandatory)][string]$ConnectionString)
    try { return ((Invoke-PimSqlScalar -ConnectionString $ConnectionString -Sql 'SELECT 1') -eq 1) } catch { return $false }
}
