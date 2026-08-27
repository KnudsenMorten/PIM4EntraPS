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

function Test-PimManagedIdentityAvailable {
    # Is a managed identity reachable from THIS process? Answers once and caches, because
    # the IMDS probe costs a real timeout when there is no MI and connections are frequent.
    # Order matters: the env-var forms (App Service / Functions) are free to check, so they
    # answer before anything touches the network. $global:PIM_UseManagedIdentity forces yes.
    # Set $global:PIM_NoManagedIdentity to force no (offline tests must never probe IMDS).
    [CmdletBinding()] param([switch]$Force)
    if ($global:PIM_NoManagedIdentity) { return $false }
    if ($global:PIM_UseManagedIdentity) { return $true }
    if ($env:IDENTITY_ENDPOINT -and $env:IDENTITY_HEADER) { return $true }
    if ($env:MSI_ENDPOINT -and $env:MSI_SECRET) { return $true }
    if (-not $Force -and $null -ne $script:PimMiAvailable) { return $script:PimMiAvailable }
    $ok = $false
    try {
        $null = Invoke-RestMethod -Method GET -TimeoutSec 3 -Headers @{ Metadata = 'true' } `
                  -Uri 'http://169.254.169.254/metadata/instance?api-version=2021-02-01'
        $ok = $true
    } catch { $ok = $false }
    $script:PimMiAvailable = $ok
    return $ok
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
        # Acquire a FRESH token on EVERY connection. Get-PimRestToken caches per
        # resource with an expiry and auto-refreshes when near expiry, so this is
        # cheap (returns the still-valid cached token) AND it never hands SQL an
        # expired token. Previously the token was minted once into
        # $global:PIM_SqlAccessToken and reused forever, so a long-running Manager
        # (hosted 24/7) failed with "Login failed ... Token is expired" ~1h after
        # start. Do NOT gate acquisition on the global being empty. (Fix 2026-06-17.)
        $tok = $null
        if (Get-Command Get-PimRestToken -ErrorAction SilentlyContinue) {
            # 0) BREAK-GLASS / emergency edition on a client PC: no MI, no SPN -- the
            #    operator signs in interactively as THEMSELVES (audited under the human).
            #    Opt in with $global:PIM_SqlInteractive or $global:PIM_Interactive.
            if ($global:PIM_SqlInteractive -or $global:PIM_Interactive) {
                try { $tok = Get-PimRestToken -Resource 'https://database.windows.net' -Interactive } catch { Write-Warning "  [sql] interactive token failed: $($_.Exception.Message)" }
            }
            # 1) MANAGED IDENTITY IS PLAN A (operator directive 2026-08-08: "use MI as plan A
            #    to connect with managed identity"), but ONLY when no SPN is explicitly
            #    configured. MI was previously gated on $env:IDENTITY_ENDPOINT -- an App
            #    Service/Functions variable NEVER set on an Azure VM -- so on a VM (mgmt1
            #    included) MI was silently skipped even though Get-PimManagedIdentityToken had
            #    handled IMDS all along. The gate, not the capability, was missing.
            #
            #    BUG-34: making MI unconditional then broke the CROSS-TENANT case, which is the
            #    normal one for the test estate. A managed identity can only mint tokens for
            #    ITS OWN tenant, and MI acquisition SUCCEEDS -- so a valid-but-wrong-tenant
            #    token was taken and the explicitly configured SPN never got a turn. Azure SQL
            #    then answers "Login failed for user '<token-identified principal>'. The server
            #    is not currently configured to accept this token", which reads like a
            #    permissions problem rather than "you authenticated to the wrong directory".
            #    Precedence is therefore: an EXPLICIT credential wins over ambient MI. MI stays
            #    plan A for the in-tenant/hosted case it was asked for (engine in ACA with no
            #    SPN configured), which is where it is genuinely correct.
            #    Test-PimManagedIdentityAvailable probes IMDS ONCE per process and caches the
            #    answer, so a machine with no MI does not pay a timeout on every connection.
            $sqlCid = if ($global:PIM_SqlClientId)     { $global:PIM_SqlClientId }     else { $global:PIM_ClientId }
            $sqlSec = if ($global:PIM_SqlClientSecret) { $global:PIM_SqlClientSecret } else { $global:PIM_ClientSecret }
            $sqlThumb = if ($global:PIM_SqlCertThumbprint) { $global:PIM_SqlCertThumbprint } else { $global:PIM_CertThumbprint }
            $explicitSpn = [bool]("$sqlCid".Trim()) -and ([bool]("$sqlSec".Trim()) -or [bool]("$sqlThumb".Trim()))

            # 🔴 BUG-77 -- SAY WHICH BRANCH RAN AND WHICH IDENTITY IT ASKED FOR, ONCE PER PROCESS.
            # Every branch below was silent on success and the MI branch is a plain `if`, so being
            # SKIPPED produced no output at all. The result: "no [mi] line, no [sql] warning, and a
            # login failure" was equally consistent with MI-skipped, MI-returned-the-wrong-identity,
            # and SPN-token-minted-from-$env:AZURE_CLIENT_SECRET (which Get-PimRestToken reads on its
            # own, so the SPN can be used even when $explicitSpn is $false). Those cannot be told
            # apart from outside, and each guess costs a rebuild. One line ends that.
            $miAvail = Test-PimManagedIdentityAvailable
            if (-not $script:PimSqlAuthLogged) {
                $script:PimSqlAuthLogged = $true
                $miIdLabel = if ($global:PIM_ManagedIdentityClientId) { "user-assigned $($global:PIM_ManagedIdentityClientId)" }
                             elseif ($env:PIM_ManagedIdentityClientId) { "user-assigned $($env:PIM_ManagedIdentityClientId)" } else { 'default (system, or the only one attached)' }
                $credKind = if ("$sqlSec".Trim()) { 'secret' } elseif ("$sqlThumb".Trim()) { "cert $sqlThumb" }
                            elseif ($env:AZURE_CLIENT_SECRET) { 'secret via $env:AZURE_CLIENT_SECRET (NOT counted by $explicitSpn)' } else { 'none' }
                Write-Warning ("  [sql] auth plan: explicitSpn={0} sqlClientId='{1}' credential={2} | MI available={3} identity={4}" -f `
                                $explicitSpn, "$sqlCid", $credKind, $miAvail, $miIdLabel)
            }
            # 🪤 ONCE PER PROCESS, NOT ONCE PER CONNECTION. The first version of this logged the
            # winning branch on EVERY connection: a single downlink run emitted ~80 identical
            # "token source: MANAGED IDENTITY" warnings, which is how a diagnostic stops being one.
            # Noise that drowns the next real warning costs more than the silence it replaced.
            # The FAILURE paths stay unconditional -- those are rare and each one matters.
            if (-not $tok -and $explicitSpn) {
                try { $tok = Get-PimRestToken -Resource 'https://database.windows.net' -ClientId $sqlCid -ClientSecret $sqlSec -CertThumbprint $sqlThumb
                      if ($tok -and -not $script:PimSqlSourceLogged) { $script:PimSqlSourceLogged = $true; Write-Warning "  [sql] token source: EXPLICIT SPN $sqlCid" } }
                catch { Write-Warning "  [sql] SPN token failed: $($_.Exception.Message)" }
            }
            if (-not $tok -and $miAvail) {
                try { $tok = Get-PimRestToken -Resource 'https://database.windows.net' -UseManagedIdentity
                      if ($tok -and -not $script:PimSqlSourceLogged) { $script:PimSqlSourceLogged = $true; Write-Warning '  [sql] token source: MANAGED IDENTITY' } }
                catch { Write-Warning "  [sql] MI token failed: $($_.Exception.Message)" }
            }
            elseif (-not $tok -and -not $miAvail -and -not $script:PimSqlSourceLogged) {
                $script:PimSqlSourceLogged = $true
                Write-Warning '  [sql] MI branch SKIPPED (no managed identity detected in this process)'
            }
            # Last resort: an SPN that was not "explicit" by the test above (e.g. client id
            # present but credential resolved from the ambient cert store).
            if (-not $tok -and -not $explicitSpn) {
                # 🪤 This branch can still authenticate as the SPN even though $explicitSpn said
                # there was no explicit credential: Get-PimRestToken reads $env:AZURE_CLIENT_SECRET
                # itself. That is exactly how a container ends up presenting the ENGINE SPN to SQL
                # while every log line suggests managed identity -- so it names the source too.
                try { $tok = Get-PimRestToken -Resource 'https://database.windows.net' -ClientId $sqlCid -ClientSecret $sqlSec -CertThumbprint $sqlThumb
                      if ($tok -and -not $script:PimSqlSourceLogged) { $script:PimSqlSourceLogged = $true; Write-Warning "  [sql] token source: FALLBACK SPN $sqlCid (credential resolved inside Get-PimRestToken, e.g. \$env:AZURE_CLIENT_SECRET)" } }
                catch { Write-Warning "  [sql] SPN token failed: $($_.Exception.Message)" }
            }
            if (-not $tok) { Write-Warning '  [sql] NO TOKEN was obtained by any branch -- the connection will present no credential.' }
        }
        # Last-resort: an explicitly pre-pinned token (e.g. a caller that minted its own).
        if (-not $tok -and $global:PIM_SqlAccessToken) { $tok = $global:PIM_SqlAccessToken }
        if ($tok) {
            try { $c.AccessToken = "$tok" } catch { Write-Warning "  [sql] set AccessToken failed: $($_.Exception.Message)" }
            $global:PIM_SqlAccessToken = $tok   # keep the freshest token visible for diagnostics/last-resort
        }
        else {
            # BUG-33: name the CAUSE. The common one is not "auth failed" but "the token provider
            # was never loaded" -- a caller that dot-sources PIM-SqlStore without PIM-Rest skips
            # the whole block above, presents no credential, and Azure SQL reports
            # "Login failed for user ''", which points at permissions and wastes the search there.
            if (-not (Get-Command Get-PimRestToken -ErrorAction SilentlyContinue)) {
                Write-Warning "  [sql] NO SQL access token: Get-PimRestToken is NOT LOADED -- dot-source engine/_shared/PIM-Rest.ps1 BEFORE PIM-SqlStore.ps1. (Azure SQL will report: Login failed for user '')"
            } else {
                Write-Warning "  [sql] NO SQL access token acquired (MI and SPN both failed; connection would present no credential)"
            }
        }
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
    #
    # SEC-03: every local/on-prem path below uses `Encrypt=True;TrustServerCertificate=True`.
    # It previously used `Encrypt=False`, which put privileged desired-state data and the SQL
    # session on the wire in CLEAR TEXT. §31 accepts `TrustServerCertificate` "until a real
    # cert" for hybrid -- but that concession is about not VALIDATING the certificate, not
    # about dropping encryption entirely. `Encrypt=True;TrustServerCertificate=True` keeps the
    # wire encrypted while still tolerating a self-signed cert, which is what that note
    # actually intended. The Azure SQL path (above) stays fully strict:
    # `Encrypt=True;TrustServerCertificate=False`.
    param([string]$Server, [string]$Database)
    if (-not $Database) { $Database = if ($global:PIM_SqlDatabase) { "$($global:PIM_SqlDatabase)" } else { 'PIM4EntraPS' } }
    # BUG-30 (2026-08-08): an explicit -Server naming AZURE SQL must get the passwordless
    # token connection string, exactly like the ambient path below (:170) and the scenario
    # path (:159) already do. This branch used to return the Integrated string
    # unconditionally, which cannot work against Azure SQL -- PaaS has no Windows auth, and
    # New-PimSqlConnection SKIPS token acquisition entirely when the CS matches
    # /Integrated\s*Security/, so no AAD token was ever minted either. It also silently
    # downgraded TrustServerCertificate from False to True. Since -Server is the parameter
    # every harness and PIM-SqlStore.ps1:217 itself use, the ONLY supported store (Azure SQL
    # PaaS) was unreachable from the explicit path -- which is why every live scenario matrix
    # so far ran against .\SQLEXPRESS, a store the product does not ship. Test the FQDN first.
    if ($Server) {
        if ($Server -match '(?i)database\.windows\.net') { return (Get-PimAzureSqlConnectionString -Fqdn $Server -Database $Database) }
        return "Server=$Server;Database=$Database;Integrated Security=SSPI;Encrypt=True;TrustServerCertificate=True;Connection Timeout=15"
    }
    if ($global:PIM_SqlConnectionString) { return $global:PIM_SqlConnectionString }
    # §31.3 HOSTING RESOLUTION (opt-in by scenario). When a deployment scenario is
    # active AND its resolved hostingLocation names a concrete store (central MSP
    # Azure SQL for S5 / local SQL for S6), pick that server here instead of relying
    # only on the ambient $global:PIM_SqlServer. in-tenant (S1-S4) and the
    # no-scenario case return server='' so the existing ambient logic below wins.
    # Lowest precedence after the explicit overrides above so nothing already wired
    # changes; default behaviour is identical when no scenario is set.
    if ($global:PIM_ActiveScenario -and (Get-Command Resolve-PimScenarioHostingStore -ErrorAction SilentlyContinue)) {
        try {
            $hostStore = Resolve-PimScenarioHostingStore -Scenario "$($global:PIM_ActiveScenario)"
            if ($hostStore -and "$($hostStore.server)".Trim()) {
                $ssrv2 = "$($hostStore.server)".Trim()
                if ($ssrv2 -match '(?i)database\.windows\.net') { return (Get-PimAzureSqlConnectionString -Fqdn $ssrv2 -Database $Database) }
                return "Server=$ssrv2;Database=$Database;Integrated Security=SSPI;Encrypt=True;TrustServerCertificate=True;Connection Timeout=15"
            }
        } catch { Write-Verbose "PIM-SqlStore: scenario hosting resolution skipped: $($_.Exception.Message)" }
    }
    if ($global:PIM_SqlConnStringVault -and $global:PIM_SqlConnStringSecret) {
        return (Get-PimSqlSecretFromKeyVault -VaultName "$($global:PIM_SqlConnStringVault)" -SecretName "$($global:PIM_SqlConnStringSecret)")
    }
    $srv = if ($global:PIM_SqlServer) { "$($global:PIM_SqlServer)" } else { '.\SQLEXPRESS' }
    # Azure SQL (FQDN) -> passwordless token-based CS (MI AccessToken set by
    # New-PimSqlConnection). On-prem / Express -> Integrated.
    if ($srv -match '(?i)database\.windows\.net') { return (Get-PimAzureSqlConnectionString -Fqdn $srv -Database $Database) }
    return "Server=$srv;Database=$Database;Integrated Security=SSPI;Encrypt=True;TrustServerCertificate=True;Connection Timeout=15"
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
    # BUG-32 (2026-08-08): the guard was `IF DB_ID('<db>') IS NULL`, which is NOT idempotent on
    # Azure SQL -- the store we actually support. Measured from master as the managed identity:
    #     DB_ID('PimScenarioTest')            -> NULL
    #     EXISTS (sys.databases WHERE name=..) -> YES
    # On Azure SQL, DB_ID() resolves only databases the principal owns/created (metadata
    # visibility), so for a PRE-PROVISIONED database -- the normal PaaS case, where the DB is
    # created by IaC and the app is only granted into it -- the guard reads "missing", runs
    # CREATE DATABASE, and throws "Database '<db>' already exists." Every caller therefore fails
    # on an existing Azure database, i.e. on every run after the first.
    # sys.databases lists every database on the logical server and is the correct existence test.
    param([string]$Server, [Parameter(Mandatory)][string]$Database)
    [void](Assert-PimSqlIdentifier -Name $Database)
    $masterCs = Get-PimSqlConnectionString -Server $Server -Database 'master'
    [void](Invoke-PimSqlNonQuery -ConnectionString $masterCs -Sql "IF NOT EXISTS (SELECT 1 FROM sys.databases WHERE name = N'$Database') CREATE DATABASE [$Database];")
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
        # TEST-13: neither of these carries a GroupTag/GroupName, so both fell through to
        # the generic 'default' branch, derived a BLANK key, and every row was dropped on
        # save with a warning that scrolls past. An offboarding row is identified by the
        # ACCOUNT it offboards; a discovery row by its tag. Found because the scenario
        # seeder reported "seeded PIM-Offboarding 0 rows" while TESTS.md said it plants one
        # -- so every assertion that depended on either entity was passing vacuously.
        'PIM-Offboarding'                {
            $o = (& $g 'Username'); if (-not "$o".Trim()) { $o = (& $g 'UserName') }
            if (-not "$o".Trim()) { $o = (& $g 'UserPrincipalName') }
            if (-not "$o".Trim()) { $o = (& $g 'Upn') }
            $o; break
        }
        'PIM-Discovery'                  {
            $d = (& $g 'DiscoveryTag'); if (-not "$d".Trim()) { $d = (& $g 'Tag') }
            if (-not "$d".Trim()) { $d = (& $g 'GroupTag') }
            $d; break
        }
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

# --- atomic compare-and-set, for the scheduler's single-runner lease (BUG-36) ----
# Set-PimSqlSetting above is an unconditional MERGE: read-then-write with it is NOT atomic, so
# two runners can both read "lease free" and both write, which is the exact double-apply the
# lease exists to prevent. These two give a real CAS.
function Get-PimSqlSettingRaw {
    # The value EXACTLY as stored, unparsed. CAS compares bytes, so it must not round-trip
    # through ConvertFrom-Json/ConvertTo-Json -- that can change formatting and break the compare.
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][string]$Name)
    $j = Invoke-PimSqlScalar -ConnectionString $ConnectionString -Sql "SELECT ValueJson FROM pim.Settings WHERE Name=@n" -Parameters @{ n = $Name }
    if ($null -eq $j -or $j -is [DBNull]) { return $null }
    return "$j"
}

function Set-PimSqlSettingIfUnchanged {
    <#
      Write $NewValueJson to $Name ONLY IF the stored value is still $ExpectedValueJson
      (pass $null to mean "expected absent-or-null"). Returns the number of rows written:
      1 = we won, 0 = someone else got there first.

      The row is PRIMARY KEY on Name, so two racers taking the insert path collide on the key --
      that duplicate-key failure IS the correct answer (we lost) and is caught, not thrown.

      🪤 BUG-41 -- READ THIS BEFORE CHANGING THE NULL HANDLING BELOW.
      These parameters are typed [string], and PowerShell coerces a $null argument to
      [string]::Empty at the parameter boundary. So `-ExpectedValueJson $null` -- which every
      caller uses to mean "expected absent" -- arrived here as '', the function's own
      `$null -ne $ExpectedValueJson` test read TRUE, and it bound @e='' instead of DBNull.
      `IF @e IS NULL` was then FALSE, so the batch took the ELSE branch and ran
      `UPDATE ... WHERE ValueJson=@e`, which matches nothing when the row is absent. The INSERT
      branch -- the ONLY one that can create the row -- was unreachable, so the function returned
      0 forever and the scheduler lease could never be acquired on a fresh store. Measured live
      2026-08-09: two ticks 'Succeeded', both logged "another runner holds the lease", and
      pim.Settings held 0 rows. Nullness is therefore decided with IsNullOrEmpty, NOT with
      `-ne $null`, and that is not a style choice -- `-ne $null` cannot work through a [string]
      parameter. (An empty string is not a meaningful stored value here either: a real value is
      JSON, and Get-PimSqlSettingRaw already returns $null for a NULL column.)
    #>
    param(
        [Parameter(Mandatory)][string]$ConnectionString,
        [Parameter(Mandatory)][string]$Name,
        [string]$NewValueJson,
        [string]$ExpectedValueJson
    )
    $sql = @"
SET NOCOUNT ON;
DECLARE @affected INT = 0;
IF @e IS NULL
BEGIN
    UPDATE pim.Settings SET ValueJson=@v, UpdatedUtc=SYSUTCDATETIME()
      WHERE Name=@n AND ValueJson IS NULL;
    SET @affected = @@ROWCOUNT;
    IF @affected = 0
    BEGIN
        INSERT INTO pim.Settings (Name, ValueJson, UpdatedUtc)
        SELECT @n, @v, SYSUTCDATETIME()
          WHERE NOT EXISTS (SELECT 1 FROM pim.Settings WHERE Name=@n);
        SET @affected = @@ROWCOUNT;
    END
END
ELSE
BEGIN
    UPDATE pim.Settings SET ValueJson=@v, UpdatedUtc=SYSUTCDATETIME()
      WHERE Name=@n AND ValueJson=@e;
    SET @affected = @@ROWCOUNT;
END
SELECT @affected;
"@
    try {
        $r = Invoke-PimSqlScalar -ConnectionString $ConnectionString -Sql $sql -Parameters @{
            n = $Name
            # IsNullOrEmpty, not `-ne $null` -- see BUG-41 in the comment block above. `v` gets the
            # same treatment because Remove-PimSchedulerLease releases by passing -NewValueJson
            # $null, which by the identical coercion was storing '' instead of NULL.
            v = $(if ([string]::IsNullOrEmpty($NewValueJson))      { [DBNull]::Value } else { $NewValueJson })
            e = $(if ([string]::IsNullOrEmpty($ExpectedValueJson)) { [DBNull]::Value } else { $ExpectedValueJson })
        }
        if ($null -eq $r -or $r -is [DBNull]) { return 0 }
        return [int]$r
    } catch {
        # Duplicate key = another runner inserted first. That is a LOST RACE, not an error.
        if ("$($_.Exception.Message)" -match '(?i)duplicate key|PRIMARY KEY') { return 0 }
        throw
    }
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
    # 🔴 BUG-77 -- THIS USED TO BE `catch { return $false }`, WHICH DISCARDED THE ONLY SENTENCE THAT
    # SAYS WHAT WENT WRONG. Its caller then reports `Preflight FAILED: cannot reach the desired
    # store: no SELECT 1` -- a message that is true of a firewall block, an expired token, a missing
    # contained user, a wrong tenant and an unreachable server alike. Three rebuild/redeploy/run
    # cycles were spent guessing between those on the greenfield slave, because the process was
    # telling us "no" and refusing to say why. A probe that hides the reason is not a probe.
    try { return ((Invoke-PimSqlScalar -ConnectionString $ConnectionString -Sql 'SELECT 1') -eq 1) }
    catch {
        $script:PimSqlLastError = "$($_.Exception.Message)"
        Write-Warning "  [sql] connectivity probe FAILED: $($_.Exception.Message)"
        return $false
    }
}

# --- cold-process settings hydration (the GUI-state == actual-behavior fix) -----
# The Manager hydrates pim.Settings into $global:PIM_NamingConventions at boot, so its
# OWN process honours GUI-saved EmailControls / JobSchedule. But a COLD-booted scheduler
# or a one-shot engine/job run never ran that boot path -- so a kill switch set in the
# GUI would NOT stop a cold scheduled send, and a freshly-booted scheduler would NOT see
# a changed cadence. Get-PimSqlSettingsConnectionString resolves the store CS the same
# way the scheduler tick already does (ambient globals only -- never builds a credential
# out of thin air), and Import-PimSettingsFromStore loads ALL pim.Settings into
# $global:PIM_NamingConventions so Get-PimPolicySetting (engine/scheduler reader) resolves
# the persisted values in ANY process. FAIL-SAFE: a read failure leaves whatever was
# already configured untouched (it never CLEARS an existing kill switch and never
# fails-open to sending more than configured). REQUIREMENTS s29.
function Get-PimSqlSettingsConnectionString {
    # Best-effort store CS for a cold process. Mirrors Invoke-PimSchedulerTick's resolver:
    # an explicit in-memory CS wins; else build from ambient SQL globals ONLY when one is
    # actually configured (so a bare default never fabricates a connection). Returns $null
    # when no store is configured -- the caller then leaves settings as-is (fail-safe).
    if ("$($global:PIM_SqlConnectionString)".Trim()) { return "$($global:PIM_SqlConnectionString)" }
    $hasSig = ("$($global:PIM_SqlServer)".Trim() -or "$($global:PIM_SqlConnStringVault)".Trim() -or "$($global:PIM_SqlDatabase)".Trim())
    if ($hasSig -and (Get-Command Get-PimSqlConnectionString -ErrorAction SilentlyContinue)) {
        try { return (Get-PimSqlConnectionString) } catch { return $null }
    }
    return $null
}

function Import-PimSettingsFromStore {
    # Load pim.Settings into $global:PIM_NamingConventions (the engine/scheduler reader
    # source -- Get-PimPolicySetting reads it first). Additive: existing keys are
    # overwritten with the persisted value, other globals untouched. Returns the number
    # of settings loaded, or -1 when no store was reachable (so the caller can tell
    # "nothing to load" from "couldn't read" -- both are non-fatal / fail-safe).
    # -ConnectionString overrides the resolver (tests / an already-open CS).
    param([string]$ConnectionString)
    $cs = if ("$ConnectionString".Trim()) { $ConnectionString } else { Get-PimSqlSettingsConnectionString }
    if (-not "$cs".Trim()) { return -1 }
    $loaded = $null
    try { $loaded = Get-PimAllSqlSettings -ConnectionString $cs } catch { Write-Warning "  [settings] hydrate from store failed (leaving current settings unchanged): $($_.Exception.Message)"; return -1 }
    if ($null -eq $loaded) { return -1 }
    if (-not ($global:PIM_NamingConventions -is [hashtable])) { $global:PIM_NamingConventions = @{} }
    $n = 0
    foreach ($k in @($loaded.Keys)) { $global:PIM_NamingConventions[$k] = $loaded[$k]; $n++ }
    # Apply the EmailControls record to the email globals the notify path reads (the
    # Manager does this in its PUT handler; do it here too so a cold process is covered).
    if ((Get-Command Set-PimEmailControlsGlobals -ErrorAction SilentlyContinue) -and $global:PIM_NamingConventions.ContainsKey('EmailControls')) {
        [void](Set-PimEmailControlsGlobals -EmailControls $global:PIM_NamingConventions['EmailControls'])
    }
    # IMP-06a: the SENDER is not part of the EmailControls record, so the projection above could
    # never carry it -- which is why $global:PIM_MailSender had no persisted path at all and every
    # hosted environment was mail-mute no matter what onboarding did. Project it here so the
    # Manager can change the sender without a container redeploy and a cold-booted tick Job still
    # honours it, overriding the deploy-time env var Invoke-PimEngineCore reads.
    # 🔒 FAIL-SAFE DIRECTION, and it is the opposite of the kill switch's. A missing or BLANK
    # stored value must LEAVE an existing sender alone: clearing it would silently mute a working
    # environment, and muting is the exact failure IMP-06 exists to stop. Only a non-blank value
    # ever writes here. (The kill switch is fail-safe by staying ON; the sender is fail-safe by
    # staying SET.)
    if ($global:PIM_NamingConventions.ContainsKey('MailSender')) {
        $__sender = "$($global:PIM_NamingConventions['MailSender'])".Trim()
        if ($__sender) { $global:PIM_MailSender = $__sender }
    }
    return $n
}
