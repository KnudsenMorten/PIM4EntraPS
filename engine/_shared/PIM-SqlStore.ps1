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

function New-PimSqlConnection {
    # Single place connections are created, so MANAGED IDENTITY (the chosen auth
    # for Azure SQL) works passwordless: the launcher mints an MI access token for
    # https://database.windows.net/ into $global:PIM_SqlAccessToken; we set it on
    # the connection (System.Data.SqlClient supports .AccessToken). No password in
    # the connection string. Skipped when the CS uses Integrated auth (dev/on-prem)
    # -- the two are mutually exclusive.
    param([Parameter(Mandatory)][string]$ConnectionString)
    $c = New-Object System.Data.SqlClient.SqlConnection $ConnectionString
    if ($global:PIM_SqlAccessToken -and $ConnectionString -notmatch '(?i)Integrated\s*Security') {
        try { $c.AccessToken = "$($global:PIM_SqlAccessToken)" } catch {}
    }
    return $c
}

function Get-PimAzureSqlConnectionString {
    # Passwordless Azure SQL connection string (no credentials) -- auth is the MI
    # AccessToken set by New-PimSqlConnection. Launcher builds this + mints the token.
    param([Parameter(Mandatory)][string]$Fqdn, [string]$Database = 'PIM4EntraPS')
    return "Server=tcp:$Fqdn,1433;Database=$Database;Encrypt=True;TrustServerCertificate=False;Connection Timeout=30"
}

function Get-PimSqlSecretFromKeyVault {
    # Fetch a secret (the connection string, or a password) from Key Vault via the
    # KV REST API with a Bearer token. Prefers a launcher-pre-minted token
    # ($global:PIM_KeyVaultToken) to avoid pulling the Az module into a Graph
    # process; falls back to Get-AzAccessToken only if available. NEVER cached to disk.
    param([Parameter(Mandatory)][string]$VaultName, [Parameter(Mandatory)][string]$SecretName, [string]$ApiVersion = '7.4')
    $token = $global:PIM_KeyVaultToken
    if (-not $token) {
        $t = (Get-AzAccessToken -ResourceUrl 'https://vault.azure.net' -ErrorAction Stop).Token
        $token = if ($t -is [securestring]) { [System.Net.NetworkCredential]::new('', $t).Password } else { $t }
    }
    $uri = "https://$VaultName.vault.azure.net/secrets/$SecretName" + "?api-version=$ApiVersion"
    return (Invoke-RestMethod -Method GET -Uri $uri -Headers @{ Authorization = "Bearer $token" } -ErrorAction Stop).value
}

function Get-PimSqlConnectionString {
    # Resolve the connection string WITHOUT persisting any secret to a file.
    # Priority:
    #   1. explicit -Server         -> build passwordless (Integrated) [dev/test]
    #   2. $global:PIM_SqlConnectionString  -> in-memory (launcher-set from KV)
    #   3. KV pointer ($global:PIM_SqlConnStringVault + ...Secret) -> fetch from KV
    #   4. passwordless build from $global:PIM_SqlServer + db (Integrated / AAD-MI)
    # The connection string / secret is NEVER read from a JSON/config file.
    param([string]$Server, [string]$Database = 'PIM4EntraPS')
    if ($Server) { return "Server=$Server;Database=$Database;Integrated Security=SSPI;Encrypt=False;TrustServerCertificate=True;Connection Timeout=15" }
    if ($global:PIM_SqlConnectionString) { return $global:PIM_SqlConnectionString }
    if ($global:PIM_SqlConnStringVault -and $global:PIM_SqlConnStringSecret) {
        return (Get-PimSqlSecretFromKeyVault -VaultName "$($global:PIM_SqlConnStringVault)" -SecretName "$($global:PIM_SqlConnStringSecret)")
    }
    $srv = if ($global:PIM_SqlServer) { $global:PIM_SqlServer } else { '.\SQLEXPRESS' }
    # Passwordless: Integrated (on-prem/Express) or, for Azure SQL, the launcher
    # sets a token-based CS in $global:PIM_SqlConnectionString instead.
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
    $c = New-PimSqlConnection -ConnectionString $ConnectionString
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
    $c = New-PimSqlConnection -ConnectionString $ConnectionString
    try {
        $c.Open(); $cmd = $c.CreateCommand(); $cmd.CommandText = $Sql
        foreach ($k in $Parameters.Keys) { [void]$cmd.Parameters.AddWithValue("@$k", $(if ($null -eq $Parameters[$k]) { [DBNull]::Value } else { $Parameters[$k] })) }
        return $cmd.ExecuteNonQuery()
    } finally { $c.Close() }
}

function Invoke-PimSqlScalar {
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][string]$Sql, [hashtable]$Parameters = @{})
    $c = New-PimSqlConnection -ConnectionString $ConnectionString
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
IF OBJECT_ID('pim.Settings') IS NULL
CREATE TABLE pim.Settings (
    Name        NVARCHAR(200) NOT NULL PRIMARY KEY,
    ValueJson   NVARCHAR(MAX) NULL,
    UpdatedUtc  DATETIME2     NOT NULL CONSTRAINT DF_Settings_Updated DEFAULT SYSUTCDATETIME()
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

function Get-PimStoreRowKey {
    # Natural key per entity/base (matches the manager's row-key convention) so a
    # row maps to a stable pim.Rows [Key]. Returns '' when no key can be derived.
    param([Parameter(Mandatory)][string]$Base, [Parameter(Mandatory)][object]$Row)
    $g = {
        param($n)
        if ($Row -is [System.Collections.IDictionary]) { if ($Row.Contains($n)) { "$($Row[$n])" } else { '' } }
        else { $p = $Row.PSObject.Properties[$n]; if ($p -and $null -ne $p.Value) { "$($p.Value)" } else { '' } }
    }
    $k = switch -Wildcard ($Base) {
        'PIM-Definitions-AU'              { (& $g 'AdministrativeUnitTag') }
        'PIM-Definitions-*'              { (& $g 'GroupTag') }
        'Account-Definitions-Admins'     { (& $g 'UserName') }
        'PIM-Assignments-Admins'         { ((& $g 'Username') + '|' + (& $g 'GroupTag')) }
        'PIM-Assignments-Groups'         { ((& $g 'TargetGroupTag') + '|' + (& $g 'SourceGroupTag')) }
        'PIM-Assignments-Roles-Groups'   { ((& $g 'GroupTag') + '|' + (& $g 'RoleDefinitionName')) }
        'PIM-Assignments-Roles-AUs'      { ((& $g 'GroupTag') + '|' + (& $g 'AdministrativeUnitTag') + '|' + (& $g 'RoleDefinitionName')) }
        'PIM-Assignments-Azure-Resources'{ ((& $g 'GroupTag') + '|' + (& $g 'AzScope') + '|' + (& $g 'AzScopePermission')) }
        default                          { $x = (& $g 'GroupTag'); if (-not "$x".Trim()) { $x = (& $g 'GroupName') }; $x }
    }
    $k = "$k".Trim()
    if ($k -eq '' -or $k -eq '|' -or $k -match '^\|+$') { return '' }
    return $k
}

function Set-PimSqlEntityRows {
    # Full-set replace of an entity's rows (matches CSV file-write semantics):
    # upsert every submitted row by its natural key, delete current keys that are
    # no longer present. Returns @{ rowCount; removed }.
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][string]$Entity, [object[]]$Rows = @(), [string]$Base)
    $base = if ("$Base".Trim()) { $Base } else { $Entity }
    $submitted = @{}
    foreach ($r in @($Rows)) {
        $k = Get-PimStoreRowKey -Base $base -Row $r
        if (-not $k) { continue }
        $submitted[$k] = $true
        Set-PimSqlRow -ConnectionString $ConnectionString -Entity $Entity -Key $k -Data $r
    }
    $removed = 0
    $currentKeys = @(Invoke-PimSqlQuery -ConnectionString $ConnectionString -Sql "SELECT [Key] FROM pim.Rows WHERE Entity=@e" -Parameters @{ e = $Entity } | ForEach-Object { "$($_.Key)" })
    foreach ($ck in $currentKeys) { if (-not $submitted.ContainsKey($ck)) { Remove-PimSqlRow -ConnectionString $ConnectionString -Entity $Entity -Key $ck; $removed++ } }
    return @{ rowCount = $submitted.Count; removed = $removed }
}

# --- settings live in SQL (protected), not a readable JSON file -----------------
# A hacker reading the JSON must not learn/modify the naming convention or policy.
# The file is only an INITIAL SEED; ongoing management is in pim.Settings.
function Get-PimSqlSetting {
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][string]$Name)
    $j = Invoke-PimSqlScalar -ConnectionString $ConnectionString -Sql "SELECT ValueJson FROM pim.Settings WHERE Name=@n" -Parameters @{ n = $Name }
    if ($null -eq $j -or "$j".Trim() -eq '') { return $null }
    try { return ($j | ConvertFrom-Json) } catch { return "$j" }
}

function Set-PimSqlSetting {
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][string]$Name, [object]$Value)
    $json = if ($null -ne $Value) { $Value | ConvertTo-Json -Depth 12 -Compress } else { $null }
    [void](Invoke-PimSqlNonQuery -ConnectionString $ConnectionString -Sql @"
MERGE pim.Settings AS t USING (SELECT @n AS Name) AS s ON t.Name = s.Name
WHEN MATCHED THEN UPDATE SET ValueJson=@v, UpdatedUtc=SYSUTCDATETIME()
WHEN NOT MATCHED THEN INSERT (Name, ValueJson, UpdatedUtc) VALUES (@n, @v, SYSUTCDATETIME());
"@ -Parameters @{ n = $Name; v = $json })
}

function Get-PimAllSqlSettings {
    # All settings as a hashtable Name -> value (JSON-parsed). For loading over the
    # file seed into $global:PIM_NamingConventions at boot.
    param([Parameter(Mandatory)][string]$ConnectionString)
    $out = @{}
    foreach ($r in @(Invoke-PimSqlQuery -ConnectionString $ConnectionString -Sql "SELECT Name, ValueJson FROM pim.Settings")) {
        $v = if ("$($r.ValueJson)".Trim()) { try { $r.ValueJson | ConvertFrom-Json } catch { "$($r.ValueJson)" } } else { $null }
        $out["$($r.Name)"] = $v
    }
    return $out
}

function Import-PimSettingsSeed {
    # Seed pim.Settings from a setup-file default hashtable -- ONLY keys not already
    # present (so the SQL store, once managed, is never overwritten by the seed).
    param([Parameter(Mandatory)][string]$ConnectionString, [hashtable]$Seed = @{})
    $existing = Get-PimAllSqlSettings -ConnectionString $ConnectionString
    $added = 0
    foreach ($k in @($Seed.Keys)) { if (-not $existing.ContainsKey("$k")) { Set-PimSqlSetting -ConnectionString $ConnectionString -Name "$k" -Value $Seed[$k]; $added++ } }
    return $added
}

function Test-PimSqlConnectivity {
    param([Parameter(Mandatory)][string]$ConnectionString)
    try { return ((Invoke-PimSqlScalar -ConnectionString $ConnectionString -Sql 'SELECT 1') -eq 1) } catch { return $false }
}
