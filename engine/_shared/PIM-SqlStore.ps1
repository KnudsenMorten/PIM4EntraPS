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

function Resolve-PimSqlClientType {
    # The SQL driver is the one unavoidable non-REST dependency. Prefer
    # Microsoft.Data.SqlClient (cross-platform: Linux/PS7 container) and fall back to
    # the in-box System.Data.SqlClient (Windows PowerShell 5.1). Order:
    #   1. Microsoft.Data.SqlClient (already loaded)
    #   2. System.Data.SqlClient    (in-box on Windows 5.1; null on .NET Core/Linux)
    #   3. an explicit DLL via $env:PIM_SQLCLIENT_DLL
    #   4. the SqlServer module (bundles Microsoft.Data.SqlClient w/ managed SNI on Linux)
    if ($script:PimSqlClientType) { return $script:PimSqlClientType }
    $t = ('Microsoft.Data.SqlClient.SqlConnection' -as [type])
    if (-not $t) { $t = ('System.Data.SqlClient.SqlConnection' -as [type]) }   # in-box on Windows PS 5.1
    # Pinned, BUNDLED assembly (no PowerShell module): $env:PIM_SQLCLIENT_DLL points at
    # the Microsoft.Data.SqlClient.dll (or its folder). Probe the same folder for the
    # dependency closure on demand, so we Add-Type one DLL and deps resolve locally.
    if (-not $t -and $env:PIM_SQLCLIENT_DLL) {
        $p = $env:PIM_SQLCLIENT_DLL
        $script:PimSqlDllDir = if (Test-Path -LiteralPath $p -PathType Container) { $p } else { Split-Path -Parent $p }
        $main = if (Test-Path -LiteralPath $p -PathType Leaf) { $p } else { Join-Path $script:PimSqlDllDir 'Microsoft.Data.SqlClient.dll' }
        if (Test-Path -LiteralPath $main) {
            $resolver = [System.ResolveEventHandler]{
                param($s, $e)
                $n = ($e.Name -split ',')[0]
                $cand = Join-Path $script:PimSqlDllDir "$n.dll"
                if (Test-Path -LiteralPath $cand) { return [System.Reflection.Assembly]::LoadFrom($cand) }
                return $null
            }
            try {
                [System.AppDomain]::CurrentDomain.add_AssemblyResolve($resolver)
                Add-Type -Path $main -ErrorAction Stop
                $t = ('Microsoft.Data.SqlClient.SqlConnection' -as [type])
            } catch { Write-Verbose "PIM-SqlStore: Add-Type $main failed: $($_.Exception.Message)" }
        }
    }
    if (-not $t) { throw 'No SQL client available. Windows PS 5.1 has System.Data.SqlClient in-box; on Linux/PS7 bundle Microsoft.Data.SqlClient and point $env:PIM_SQLCLIENT_DLL at it (the container image does this).' }
    $script:PimSqlClientType = $t
    return $t
}

function New-PimSqlConnection {
    # Single place connections are created, so MANAGED IDENTITY (the chosen auth for
    # Azure SQL) works passwordless: an MI access token for https://database.windows.net/
    # is set on the connection (.AccessToken). If one isn't pre-minted, mint it via
    # PIM-Rest (MI / SPN / az) here. No password in the connection string. Skipped when
    # the CS uses Integrated auth (dev/on-prem) -- the two are mutually exclusive.
    param([Parameter(Mandatory)][string]$ConnectionString)
    $type = Resolve-PimSqlClientType
    $c = $type::new($ConnectionString)
    if ($ConnectionString -notmatch '(?i)Integrated\s*Security') {
        if (-not $global:PIM_SqlAccessToken -and (Get-Command Get-PimRestToken -ErrorAction SilentlyContinue)) {
            # 0) BREAK-GLASS / emergency edition on a client PC: no MI, no SPN -- the
            #    operator signs in interactively as THEMSELVES (audited under the human).
            #    Opt in with $global:PIM_SqlInteractive or $global:PIM_Interactive.
            if ($global:PIM_SqlInteractive -or $global:PIM_Interactive) {
                try { $global:PIM_SqlAccessToken = Get-PimRestToken -Resource 'https://database.windows.net' -Interactive } catch { Write-Warning "  [sql] interactive token failed: $($_.Exception.Message)" }
            }
            # 1) Managed Identity (App Service $IDENTITY_ENDPOINT / IMDS) when present.
            if (-not $global:PIM_SqlAccessToken -and ($env:IDENTITY_ENDPOINT -or $global:PIM_UseManagedIdentity)) {
                try { $global:PIM_SqlAccessToken = Get-PimRestToken -Resource 'https://database.windows.net' -UseManagedIdentity } catch { Write-Warning "  [sql] MI token failed: $($_.Exception.Message)" }
            }
            # 2) Fall back to an SPN (PIM_SqlClientId/Secret or PIM_ClientId/Secret, cert, or az)
            #    -- e.g. when MI isn't wired into the container. Get-PimRestToken resolves the
            #    configured client-credentials for the database resource.
            if (-not $global:PIM_SqlAccessToken) {
                $sqlCid = if ($global:PIM_SqlClientId) { $global:PIM_SqlClientId } else { $global:PIM_ClientId }
                $sqlSec = if ($global:PIM_SqlClientSecret) { $global:PIM_SqlClientSecret } else { $global:PIM_ClientSecret }
                try { $global:PIM_SqlAccessToken = Get-PimRestToken -Resource 'https://database.windows.net' -ClientId $sqlCid -ClientSecret $sqlSec } catch { Write-Warning "  [sql] SPN token failed: $($_.Exception.Message)" }
            }
        }
        if ($global:PIM_SqlAccessToken) { try { $c.AccessToken = "$($global:PIM_SqlAccessToken)" } catch { Write-Warning "  [sql] set AccessToken failed: $($_.Exception.Message)" } }
        else { Write-Warning "  [sql] NO SQL access token acquired (connection would present no credential)" }
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
    param([string]$Server, [string]$Database)
    if (-not $Database) { $Database = if ($global:PIM_SqlDatabase) { "$($global:PIM_SqlDatabase)" } else { 'PIM4EntraPS' } }
    if ($Server) { return "Server=$Server;Database=$Database;Integrated Security=SSPI;Encrypt=False;TrustServerCertificate=True;Connection Timeout=15" }
    if ($global:PIM_SqlConnectionString) { return $global:PIM_SqlConnectionString }
    if ($global:PIM_SqlConnStringVault -and $global:PIM_SqlConnStringSecret) {
        return (Get-PimSqlSecretFromKeyVault -VaultName "$($global:PIM_SqlConnStringVault)" -SecretName "$($global:PIM_SqlConnStringSecret)")
    }
    $srv = if ($global:PIM_SqlServer) { "$($global:PIM_SqlServer)" } else { '.\SQLEXPRESS' }
    # Azure SQL (FQDN) -> passwordless token-based CS (MI AccessToken set by
    # New-PimSqlConnection). On-prem / Express -> Integrated.
    if ($srv -match '(?i)database\.windows\.net') { return (Get-PimAzureSqlConnectionString -Fqdn $srv -Database $Database) }
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
    # NB: 'switch -Wildcard' evaluates EVERY matching clause unless 'break' stops it.
    # The exact 'PIM-Definitions-AU'/'-Departments' patterns ALSO match the generic
    # 'PIM-Definitions-*' below, so without 'break' both clauses ran and their outputs
    # concatenated (e.g. 'AU1 GT1'). 'break' makes the specific clause win.
    $k = switch -Wildcard ($Base) {
        'PIM-Definitions-AU'              { (& $g 'AdministrativeUnitTag'); break }
        # Departments are a people/owner-routing entity: rows are identified by the
        # department NAME, not a GroupTag (the §11 Departments grid + the scenario
        # seed write { Department; Owners; ... } with NO GroupTag). The generic
        # 'PIM-Definitions-*' branch below keys on GroupTag -> blank key -> the row
        # is silently dropped on save. Key on Department/DepartmentName first, then
        # fall back to GroupTag/GroupName for the shipped-sample shape that carries one.
        'PIM-Definitions-Departments'    {
            $d = (& $g 'Department'); if (-not "$d".Trim()) { $d = (& $g 'DepartmentName') }
            if (-not "$d".Trim()) { $d = (& $g 'GroupTag') }
            if (-not "$d".Trim()) { $d = (& $g 'GroupName') }
            $d; break
        }
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

function Set-PimSqlEntityRowsTransactional {
    # TRANSACTIONAL full-set replace of an entity's rows (REQUIREMENTS.md s28 [M1]).
    # Identical SEMANTICS to Set-PimSqlEntityRows -- upsert every submitted row by
    # its natural key, delete current keys no longer present -- but every upsert AND
    # delete runs inside ONE SqlTransaction on ONE connection. A failure mid-loop
    # rolls the WHOLE batch back, so the store is left exactly as before (never a
    # half-applied row-set, the [M1] defect). Returns @{ rowCount; removed }.
    #
    # -FailAfter is a TEST seam only: throw deliberately after applying N statements
    # to prove the rollback leaves pim.Rows unchanged (the offline tests use it; it
    # is never set in production).
    param(
        [Parameter(Mandatory)][string]$ConnectionString,
        [Parameter(Mandatory)][string]$Entity,
        [object[]]$Rows = @(),
        [string]$Base,
        [int]$FailAfter = -1
    )
    $base = if ("$Base".Trim()) { $Base } else { $Entity }
    $c = New-PimSqlConnection -ConnectionString $ConnectionString
    $tx = $null
    try {
        $c.Open()
        $tx = $c.BeginTransaction()
        $stmts = 0

        $exec = {
            param($sql, $params)
            $cmd = $c.CreateCommand()
            $cmd.Transaction = $tx
            $cmd.CommandText = $sql
            foreach ($k in $params.Keys) { [void]$cmd.Parameters.AddWithValue("@$k", $(if ($null -eq $params[$k]) { [DBNull]::Value } else { $params[$k] })) }
            [void]$cmd.ExecuteNonQuery()
        }

        $mergeSql = @"
MERGE pim.Rows AS t USING (SELECT @e AS Entity, @k AS [Key]) AS s
  ON t.Entity = s.Entity AND t.[Key] = s.[Key]
WHEN MATCHED THEN UPDATE SET DataJson = @d, UpdatedUtc = SYSUTCDATETIME()
WHEN NOT MATCHED THEN INSERT (Entity, [Key], DataJson, UpdatedUtc) VALUES (@e, @k, @d, SYSUTCDATETIME());
"@

        # 1) read current keys (inside the tx for a consistent snapshot).
        $curCmd = $c.CreateCommand(); $curCmd.Transaction = $tx
        $curCmd.CommandText = "SELECT [Key] FROM pim.Rows WHERE Entity=@e"
        [void]$curCmd.Parameters.AddWithValue('@e', $Entity)
        $rd = $curCmd.ExecuteReader(); $currentKeys = New-Object System.Collections.Generic.List[string]
        while ($rd.Read()) { $currentKeys.Add("$($rd.GetValue(0))") }
        $rd.Close()

        # 2) upsert every submitted row.
        $submitted = @{}
        foreach ($r in @($Rows)) {
            $k = Get-PimStoreRowKey -Base $base -Row $r
            if (-not $k) { continue }
            $submitted[$k] = $true
            $json = if ($null -ne $r) { $r | ConvertTo-Json -Depth 12 -Compress } else { '{}' }
            & $exec $mergeSql @{ e = $Entity; k = $k; d = $json }
            $stmts++
            if ($FailAfter -ge 0 -and $stmts -ge $FailAfter) { throw "injected mid-commit failure after $stmts statement(s) (test seam)" }
        }

        # 3) delete dropped keys.
        $removed = 0
        foreach ($ck in $currentKeys) {
            if (-not $submitted.ContainsKey($ck)) {
                & $exec "DELETE FROM pim.Rows WHERE Entity=@e AND [Key]=@k" @{ e = $Entity; k = $ck }
                $removed++; $stmts++
                if ($FailAfter -ge 0 -and $stmts -ge $FailAfter) { throw "injected mid-commit failure after $stmts statement(s) (test seam)" }
            }
        }

        $tx.Commit()
        return @{ rowCount = $submitted.Count; removed = $removed }
    } catch {
        if ($tx) { try { $tx.Rollback() } catch { Write-Warning "  [sql] transaction rollback failed: $($_.Exception.Message)" } }
        throw
    } finally {
        $c.Close()
    }
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
