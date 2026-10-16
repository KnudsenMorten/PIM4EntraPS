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
    # §100.63(b) an Azure Arc-enabled server (the on-premises hybrid worker): its agent serves the identity on localhost,
    # never on 169.254.169.254, so the IMDS probe below would answer "no" there.
    if ((Get-Command Get-PimArcIdentityEndpoint -ErrorAction SilentlyContinue) -and (Get-PimArcIdentityEndpoint)) { return $true }
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

# REQ 100.76: forget the cached SQL token, so the next connection mints one (a setup run that has just made the signed-in
# person the server's admin must not present the token it held from before).
function Reset-PimSqlTokenCache { $script:PimSqlTokenCache = $null }

function New-PimSqlConnection {
    # Single place connections are created, so MANAGED IDENTITY (the chosen auth for
    # Azure SQL) works passwordless: an MI access token for https://database.windows.net/
    # is set on the connection (.AccessToken). If one isn't pre-minted, mint it via
    # PIM-Rest (MI / SPN / signed-in source) here. No password in the connection string. Skipped when
    # the CS uses Integrated auth (dev/on-prem) -- the two are mutually exclusive.
    param([Parameter(Mandatory)][string]$ConnectionString)
    $type = Resolve-PimSqlClientType
    $c = $type::new($ConnectionString)
    # §97.1: every connection is counted, so a commit can say how many it opened ([commit-timing]) and a test can prove a
    # bulk write does not open one per row.
    $global:PIM_SqlConnectionCount = 1 + [int]$global:PIM_SqlConnectionCount
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

            # 🔴 §52.18 -- REUSE THE TOKEN, OR EVERY CONNECTION GETS ITS OWN POOL.
            # ADO.NET pools physical sessions per connection string AND per access token. Minting a
            # FRESH token for every connection therefore fragments the pool: each token opens its
            # own set of sessions instead of reusing the ones already there, and they are held for
            # the pool's lifetime. Against a Basic-tier database (300 sessions) that is a ceiling a
            # normal import can actually reach -- measured at a live customer 2026-09-09, where a
            # CSV migration failed halfway with "The session limit for the database is 300 and has
            # been reached", after the morning's deploys, the Manager and the tick job had each
            # contributed their own pools.
            # 🪤 The mint is also not free: every connection paid a token round-trip.
            # Cached per (identity, resource) for slightly less than the token's own lifetime, so a
            # long run still refreshes before expiry rather than failing mid-way.
            $tokKey = "sql|$sqlCid|$($sqlThumb)|$([bool]$sqlSec)"
            if ($script:PimSqlTokenCache -and
                $script:PimSqlTokenCache.key -eq $tokKey -and
                $script:PimSqlTokenCache.expires -gt (Get-Date).ToUniversalTime()) {
                $tok = $script:PimSqlTokenCache.token
            }

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
                $__sap = ("  [sql] auth plan: explicitSpn={0} sqlClientId='{1}' credential={2} | MI available={3} identity={4}" -f `
                                $explicitSpn, "$sqlCid", $credKind, $miAvail, $miIdLabel)
                # §100.46: in the tick a start-up diagnostic (printed on change / first of the day / PIM_LOG_VERBOSE=1)
                if (Get-Command Write-PimStartupLine -ErrorAction SilentlyContinue) { Write-PimStartupLine -Message $__sap -ForegroundColor DarkGray } else { Write-Host $__sap -ForegroundColor DarkGray }
            }
            # 🪤 ONCE PER PROCESS, NOT ONCE PER CONNECTION. The first version of this logged the
            # winning branch on EVERY connection: a single downlink run emitted ~80 identical
            # "token source: MANAGED IDENTITY" warnings, which is how a diagnostic stops being one.
            # Noise that drowns the next real warning costs more than the silence it replaced.
            # The FAILURE paths stay unconditional -- those are rare and each one matters.
            if (-not $tok -and $explicitSpn) {
                $spnErr = $null
                try { $tok = Get-PimRestToken -Resource 'https://database.windows.net' -ClientId $sqlCid -ClientSecret $sqlSec -CertThumbprint $sqlThumb
                      if ($tok -and -not $script:PimSqlSourceLogged) { $script:PimSqlSourceLogged = $true; if (Get-Command Write-PimStartupLine -ErrorAction SilentlyContinue) { Write-PimStartupLine -Message "  [sql] token source: EXPLICIT SPN $sqlCid" -ForegroundColor DarkGray } else { Write-Host -ForegroundColor DarkGray "  [sql] token source: EXPLICIT SPN $sqlCid" } } }
                catch { $spnErr = "$($_.Exception.Message)"; Write-Warning "  [sql] SPN token failed: $spnErr" }
                # =============================================================================
                # 🔴 SEC-12b -- SAME DEFECT AS SEC-12, ONE LAYER DOWN, AND IT WAS STILL LIVE.
                # BUG-34 fixed the PRECEDENCE (an explicit SPN is tried before ambient MI). It did
                # not fix the FAILURE path: when the explicit SPN's token could not be acquired,
                # control simply carried on to the MI branch below, and then to a pre-pinned
                # $global:PIM_SqlAccessToken -- either of which is a DIFFERENT PRINCIPAL.
                # 🪤 OBSERVED IN THIS SESSION'S OWN LOG, against the live store:
                #       [sql] SPN token failed: ...
                #       [sql] token source: MANAGED IDENTITY
                #    ...followed by "The SELECT permission was denied on the object 'Tenants'".
                #    That reads as an RBAC problem and is not one: the connection had silently
                #    authenticated as the machine's managed identity instead of the SPN that was
                #    explicitly configured. Every minute spent on the permission is wasted.
                # 🔑 A caller that configured an SPN has said who it wants to be. Presenting a
                # different identity SUCCEEDS at the connection and fails later, somewhere else,
                # wearing the wrong error's clothes. Refuse instead -- the failure is then one
                # line from its cause.
                # =============================================================================
                if (-not $tok) {
                    throw ("PIM store auth REFUSED: an explicit SPN ($sqlCid) is configured for SQL and its token " +
                           "could not be acquired$(if ($spnErr) { ": $spnErr" } else { '.' }) " +
                           'Refusing to fall back to the machine managed identity or a pre-pinned token -- that would ' +
                           'connect as a DIFFERENT principal and surface later as a permissions error. Fix the ' +
                           'credential, or clear $global:PIM_SqlClientId/$global:PIM_ClientId to use ambient auth on purpose.')
                }
            }
            if (-not $tok -and $miAvail) {
                try { $tok = Get-PimRestToken -Resource 'https://database.windows.net' -UseManagedIdentity
                      if ($tok -and -not $script:PimSqlSourceLogged) { $script:PimSqlSourceLogged = $true; if (Get-Command Write-PimStartupLine -ErrorAction SilentlyContinue) { Write-PimStartupLine -Message '  [sql] token source: MANAGED IDENTITY' -ForegroundColor DarkGray } else { Write-Host '  [sql] token source: MANAGED IDENTITY' -ForegroundColor DarkGray } } }
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
                      if ($tok -and -not $script:PimSqlSourceLogged) { $script:PimSqlSourceLogged = $true; Write-Host -ForegroundColor DarkGray "  [sql] token source: FALLBACK SPN $sqlCid (credential resolved inside Get-PimRestToken, e.g. \$env:AZURE_CLIENT_SECRET)" } }
                catch { Write-Warning "  [sql] SPN token failed: $($_.Exception.Message)" }
            }
            if (-not $tok) { Write-Warning '  [sql] NO TOKEN was obtained by any branch -- the connection will present no credential.' }
        }
        # Last-resort: an explicitly pre-pinned token (e.g. a caller that minted its own).
        if (-not $tok -and $global:PIM_SqlAccessToken) { $tok = $global:PIM_SqlAccessToken }
        if ($tok) {
            # 🔴 §70 (2026-09-13) -- THE POOL IS KEYED ON THE TOKEN *OBJECT*, NOT ITS TEXT.
            # This line used to be `$c.AccessToken = "$tok"`. The quotes build a NEW string on every
            # call, and System.Data.SqlClient then gives every connection its OWN pool -- so §52.18's
            # token cache (below) never actually shared a session. MEASURED against internal's store,
            # same token value, 10 open/close each: assigning the cached object -> 1 session; assigning
            # "$tok" -> 10 sessions. Live effect: the Manager held 223 sleeping sessions after one page
            # load, the Basic database hit "The session limit for the database is 300", and every query
            # paid a full TLS + Entra login, which is why Home/Admins took ~3 minutes.
            # 🔑 So: ONE string instance per token, stored once, and that same instance is assigned
            # to every connection. Never interpolate, concatenate or re-cast it on the way in.
            $cacheHit = $script:PimSqlTokenCache -and "$($script:PimSqlTokenCache.key)" -eq "$tokKey" -and
                        [object]::ReferenceEquals($script:PimSqlTokenCache.token, $tok)
            if (-not $cacheHit) {
                # A freshly acquired token: store it ONCE. The expiry is stamped only here -- it used to
                # be re-stamped on every cache hit, so under steady use the 45-minute refresh never came
                # and a long-running Manager would eventually present an expired token.
                # 45 minutes is comfortably inside an Entra token's hour.
                $script:PimSqlTokenCache = @{ key = "$tokKey"; token = $tok
                                              expires = (Get-Date).ToUniversalTime().AddMinutes(45) }
            }
            try { $c.AccessToken = $script:PimSqlTokenCache.token } catch { Write-Warning "  [sql] set AccessToken failed: $($_.Exception.Message)" }
            $global:PIM_SqlAccessToken = $script:PimSqlTokenCache.token   # freshest token, for diagnostics/last-resort
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
    param([Parameter(Mandatory)][string]$Fqdn, [string]$Database = 'PimPlatform')   # the v2 platform database (lead, 2026-09-18: PimPlatform is the default everywhere else)
    return "Server=tcp:$Fqdn,1433;Database=$Database;Encrypt=True;TrustServerCertificate=False;Connection Timeout=30"
}

function Get-PimSqlSecretFromKeyVault {
    # Fetch a secret (the connection string, or a password) from Key Vault via the
    # KV REST API with a Bearer token. Prefers a launcher-pre-minted token
    # ($global:PIM_KeyVaultToken); otherwise PIM-Rest mints it (§100.42: the ONE connect path -- no Az module
    # fallback). NEVER cached to disk.
    param([Parameter(Mandatory)][string]$VaultName, [Parameter(Mandatory)][string]$SecretName, [string]$ApiVersion = '7.4')
    $token = $global:PIM_KeyVaultToken
    if (-not $token) {
        if (Get-Command Get-PimRestToken -ErrorAction SilentlyContinue) {
            # 🔴 REQ-F (2026-09-19): the hosted containers ship NO Az module, so Get-AzAccessToken does not exist
            # there and every vault read through this function failed -- the emergency passphrase in particular
            # (Resolve-PimEmergencyExpectedHash), which made break-glass activation impossible on every hosted
            # Manager. PIM-Rest mints the vault token from the same identity the container already uses for
            # Graph/ARM (its managed identity, or the engine SPN certificate).
            $token = Get-PimRestToken -Resource 'https://vault.azure.net'
        } else {
            throw 'no way to obtain a Key Vault token in this runtime (PIM-Rest.ps1 is not loaded -- dot-source it first)'
        }
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
    if (-not $Database) { $Database = if ($global:PIM_SqlDatabase) { "$($global:PIM_SqlDatabase)" } else { 'PimPlatform' } }   # v2 platform database name (was the v1 'PIM4EntraPS')
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
    # 🔴 NO `.\SQLEXPRESS` FALLBACK. **SQL Express is not used by this product, anywhere**
    # (operator, 2026-08-28). It was never a supported store -- the BUG-30 note four lines up
    # already called it "a store the product does not ship" -- and leaving it as the DEFAULT
    # meant an unconfigured caller did not fail: it quietly connected to whatever local
    # database happened to exist, with Integrated auth, and read desired state out of it.
    # 🪤 THAT IS NOT HYPOTHETICAL, AND IT HAS ALREADY COST THIS PROJECT A FALSE GREEN TWICE:
    #   * BUG-78 -- a `.\SQLEXPRESS` default OVERRODE a correct Azure SQL FQDN, so the live
    #     scenario matrix had been running against a local database nobody deployed;
    #   * TEST-32 -- a torn-down tenant could not make the estate matrix fail, because the
    #     local SQL Express desired state OUTLIVED the teardown. The run was green about a
    #     directory and false about the claim.
    # Both are the same shape: a default that cannot fail is a default that cannot be trusted.
    # An unset store is a CONFIGURATION ERROR, and it must be loud -- "no store" and "a store
    # with stale rows in it" are the two readings, and only the first is ever right here.
    $srv = "$($global:PIM_SqlServer)".Trim()
    if (-not $srv) {
        # 🪤 ASCII ONLY in this message. The first version used a Unicode ellipsis and Windows
        # PowerShell 5.1's console rendered it as mojibake, which makes an actionable error look
        # like an encoding fault and sends the reader hunting the wrong problem.
        throw ('PIM store is not configured: $global:PIM_SqlServer is empty. Set it to the Azure SQL ' +
               'server FQDN (<name>.database.windows.net) -- or set $global:PIM_SqlConnectionString / the ' +
               'KV pointer ($global:PIM_SqlConnStringVault + $global:PIM_SqlConnStringSecret). ' +
               'There is deliberately NO local default: SQL Express is not a store this product uses, ' +
               'and defaulting to one turns a missing configuration into a silent read of the wrong data.')
    }
    # Azure SQL (FQDN) -> passwordless token-based CS (MI AccessToken set by New-PimSqlConnection).
    # A non-FQDN server is still buildable (a named on-prem/hybrid instance per §31), but it is
    # never REACHED BY DEFAULT any more -- somebody has to have named it.
    if ($srv -match '(?i)database\.windows\.net') { return (Get-PimAzureSqlConnectionString -Fqdn $srv -Database $Database) }
    return "Server=$srv;Database=$Database;Integrated Security=SSPI;Encrypt=True;TrustServerCertificate=True;Connection Timeout=15"
}

function Assert-PimSqlIdentifier {
    # Guard a DB/object name we must string-build (CREATE DATABASE can't bind it).
    param([Parameter(Mandatory)][string]$Name)
    if ($Name -notmatch '^[A-Za-z0-9_]+$') { throw "Unsafe SQL identifier '$Name' (allowed: A-Z a-z 0-9 _)." }
    return $Name
}

function Assert-PimSqlDemoScope {
    <#
      100.68 (b): the DEMO dataset lives in its own schema (pimdemo) and NOTHING but the demo module may touch it -- the
      engine reads pim.Rows only, so demo data can never reach a tenant. Any statement naming pimdemo outside the demo
      module's scope ($global:PIM_DemoSqlScope, set only by Invoke-PimDemoSql in engine/_shared/PIM-DemoData.ps1, which no
      engine entry loads) is REFUSED before it is sent.
    #>
    param([AllowEmptyString()][string]$Sql)
    if ("$Sql" -match '(?i)\[?\bpimdemo\b\]?\s*\.' -and -not $global:PIM_DemoSqlScope) {
        throw 'REFUSED: this statement names the demo schema (pimdemo) outside the demo-data module -- demo data is never read or applied by the engine.'
    }
}

function Invoke-PimSqlQuery {
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][string]$Sql, [hashtable]$Parameters = @{})
    Assert-PimSqlDemoScope -Sql $Sql
    $c = New-PimSqlConnection -ConnectionString $ConnectionString
    try {
        $c.Open(); $cmd = $c.CreateCommand(); $cmd.CommandText = $Sql
        foreach ($k in $Parameters.Keys) { [void]$cmd.Parameters.AddWithValue("@$k", $(if ($null -eq $Parameters[$k]) { [DBNull]::Value } else { $Parameters[$k] })) }
        $rd = $cmd.ExecuteReader(); $rows = New-Object System.Collections.Generic.List[object]
        while ($rd.Read()) { $o = [ordered]@{}; for ($i = 0; $i -lt $rd.FieldCount; $i++) { $o[$rd.GetName($i)] = $(if ($rd.IsDBNull($i)) { $null } else { $rd.GetValue($i) }) }; $rows.Add([pscustomobject]$o) }
        $rd.Close(); return $rows.ToArray()
    } finally { if ($c) { $c.Close(); $c.Dispose() } }   # §52.18: Dispose, not just Close -- see Set-PimSqlEntityRows
}

function Invoke-PimSqlNonQuery {
    # -CommandTimeoutSec: 0 = the provider default (30 s). Large single-row writes (the tenant cache) pass more.
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][string]$Sql, [hashtable]$Parameters = @{}, [int]$CommandTimeoutSec = 0)
    Assert-PimSqlDemoScope -Sql $Sql
    $c = New-PimSqlConnection -ConnectionString $ConnectionString
    try {
        $c.Open(); $cmd = $c.CreateCommand(); $cmd.CommandText = $Sql
        if ($CommandTimeoutSec -gt 0) { $cmd.CommandTimeout = $CommandTimeoutSec }
        foreach ($k in $Parameters.Keys) { [void]$cmd.Parameters.AddWithValue("@$k", $(if ($null -eq $Parameters[$k]) { [DBNull]::Value } else { $Parameters[$k] })) }
        return $cmd.ExecuteNonQuery()
    } finally { if ($c) { $c.Close(); $c.Dispose() } }
}

function Invoke-PimSqlScalar {
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][string]$Sql, [hashtable]$Parameters = @{})
    Assert-PimSqlDemoScope -Sql $Sql
    $c = New-PimSqlConnection -ConnectionString $ConnectionString
    try {
        $c.Open(); $cmd = $c.CreateCommand(); $cmd.CommandText = $Sql
        foreach ($k in $Parameters.Keys) { [void]$cmd.Parameters.AddWithValue("@$k", $(if ($null -eq $Parameters[$k]) { [DBNull]::Value } else { $Parameters[$k] })) }
        return $cmd.ExecuteScalar()
    } finally { if ($c) { $c.Close(); $c.Dispose() } }
}

function Initialize-PimSqlDatabase {
    # Create the database if missing (connects to managing tenant). Idempotent.
    # BUG-32 (2026-08-08): the guard was `IF DB_ID('<db>') IS NULL`, which is NOT idempotent on
    # Azure SQL -- the store we actually support. Measured from managing tenant as the managed identity:
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
-- SEC-16 (§36.2). The Manager's audit trail. It used to be appended to
-- output/audit/pim-audit-YYYYMM.jsonl on the container filesystem, and the hosted app mounts
-- NO persistent volume (measured 2026-08-31: volumes=null, mounts=null) -- so every revision
-- roll destroyed the entire trail. The audit is the one record that must OUTLIVE the thing it
-- audits: desired state is already in SQL, the tenant cache rebuilds, engine logs are copied to
-- Log Analytics. "Who granted privileged access" was the only thing with no second home.
-- ActorSource is here because of the second half of SEC-16: the writer recorded the CONTAINER's
-- process identity, so every row said the same thing. Storing WHERE the actor came from makes a
-- future regression of that kind visible in the data instead of invisible.
IF OBJECT_ID('pim.AuditEvents') IS NULL
CREATE TABLE pim.AuditEvents (
    Id            BIGINT IDENTITY(1,1) PRIMARY KEY,
    Ts            DATETIME2     NOT NULL CONSTRAINT DF_PimAudit_Ts DEFAULT SYSUTCDATETIME(),
    RunId         NVARCHAR(64)  NULL,
    CorrelationId NVARCHAR(64)  NULL,
    Actor         NVARCHAR(200) NOT NULL,
    ActorSource   NVARCHAR(100) NULL,
    Action        NVARCHAR(100) NOT NULL,
    Target        NVARCHAR(400) NOT NULL,
    BeforeJson    NVARCHAR(MAX) NULL,
    AfterJson     NVARCHAR(MAX) NULL,
    Result        NVARCHAR(100) NOT NULL CONSTRAINT DF_PimAudit_Result DEFAULT 'ok',
    WhatIf        BIT           NOT NULL CONSTRAINT DF_PimAudit_WhatIf DEFAULT 0
);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_pim_AuditEvents_Ts')
CREATE INDEX IX_pim_AuditEvents_Ts ON pim.AuditEvents (Ts DESC);
-- 2026-09-13 (SQL-only). The Manager's tenant-list caches (entra-roles, aus, pim-groups,
-- azure-scopes, azure-rbac-roles, auth-methods, pim-activity, tenant-org) used to be JSON files
-- under tools/pim-manager/cache/<instance>/. One row per kind; the database IS the instance, so
-- there is no instance column. RefreshedUtc is the freshness stamp the validator reads.
IF OBJECT_ID('pim.TenantCache') IS NULL
CREATE TABLE pim.TenantCache (
    Kind          NVARCHAR(64)  NOT NULL CONSTRAINT PK_pim_TenantCache PRIMARY KEY,
    ValueJson     NVARCHAR(MAX) NULL,
    RefreshedUtc  DATETIME2     NULL,
    UpdatedUtc    DATETIME2     NOT NULL CONSTRAINT DF_TenantCache_Updated DEFAULT SYSUTCDATETIME()
);
-- Schema conformance for a table created by an earlier build: add any column it lacks (additive only).
IF COL_LENGTH('pim.TenantCache','ValueJson') IS NULL ALTER TABLE pim.TenantCache ADD ValueJson NVARCHAR(MAX) NULL;
IF COL_LENGTH('pim.TenantCache','RefreshedUtc') IS NULL ALTER TABLE pim.TenantCache ADD RefreshedUtc DATETIME2 NULL;
IF COL_LENGTH('pim.TenantCache','UpdatedUtc') IS NULL ALTER TABLE pim.TenantCache ADD UpdatedUtc DATETIME2 NOT NULL CONSTRAINT DF_TenantCache_Updated2 DEFAULT SYSUTCDATETIME();
"@
    [void](Invoke-PimSqlNonQuery -ConnectionString $ConnectionString -Sql $ddl)
    [void](Invoke-PimSqlNonQuery -ConnectionString $ConnectionString -Sql (Get-PimChangeQueueDdl))
    [void](Initialize-PimNamingConventionSeed -ConnectionString $ConnectionString)
    [void](Invoke-PimRingOrderMigration -ConnectionString $ConnectionString)
    [void](Invoke-PimDepartmentRowKeyMigration -ConnectionString $ConnectionString)
    # AUDIT-1.3: pim.AuditEvents is append-only IN THE DATABASE (trigger; PIM-AuditRetention.ps1). Never throws: a store
    # that cannot take the guard still opens, and says so.
    if (Get-Command Initialize-PimAuditAppendOnly -ErrorAction SilentlyContinue) { [void](Initialize-PimAuditAppendOnly -ConnectionString $ConnectionString) }
    # AUDIT-1 actor: who initiated / approved each committed row (PIM-ChangeAttribution.ps1). Never fails the store open.
    if (Get-Command Get-PimChangeAttributionDdl -ErrorAction SilentlyContinue) { try { [void](Invoke-PimSqlNonQuery -ConnectionString $ConnectionString -Sql (Get-PimChangeAttributionDdl)) } catch { Write-Warning "[audit] pim.ChangeAttribution could not be created: $($_.Exception.Message)" } }
    # SEC-80: the ledger of live items PIM manages (PIM-ManagedKeys.ps1) -- a prune removes only these. Never fails the open
    # (a store without it reads as an empty ledger: nothing prunable).
    if (Get-Command Get-PimManagedKeysDdl -ErrorAction SilentlyContinue) { try { [void](Invoke-PimSqlNonQuery -ConnectionString $ConnectionString -Sql (Get-PimManagedKeysDdl)) } catch { Write-Warning "[engine] pim.ManagedKeys could not be created: $($_.Exception.Message)" } }
    # CONFIG-1.1: the change journal (PIM-CommitJournal.ps1). Never fails the open -- without it every write is refused.
    if (Get-Command Initialize-PimCommitJournal -ErrorAction SilentlyContinue) { [void](Initialize-PimCommitJournal -ConnectionString $ConnectionString) }
    # CONFIG-1.1 / 96.1: the engine's applied outcome per row (PIM-CommitJournal.ps1). Never fails the open.
    if (Get-Command Initialize-PimCommitApplied -ErrorAction SilentlyContinue) { [void](Initialize-PimCommitApplied -ConnectionString $ConnectionString) }
    # CONFIG-1.3: the configuration backup tables (PIM-ConfigBackup.ps1). Never fails the open.
    if (Get-Command Initialize-PimConfigBackupStore -ErrorAction SilentlyContinue) { [void](Initialize-PimConfigBackupStore -ConnectionString $ConnectionString) }
    # CR8 item 1 (PIM 100.152): the commit snapshot table (pim.Backups) is created HERE too -- the Manager used to create it
    # on first use, and after the cut-over it has no right to change the schema (the updater runs this before every roll).
    if (Get-Command Initialize-PimBackupStore -ErrorAction SilentlyContinue) { [void](Initialize-PimBackupStore -ConnectionString $ConnectionString) }
    # Framework §12.23 / PIM 100.156: the activation ledger (pim.ImpactActivations) was created ONLY by the engine's
    # snapshot job, right before its first insert -- the one engine DDL the updater did not already create. Created here
    # too, so the engine can lose db_ddladmin (run 2) without that job failing. Never fails the open.
    if (Get-Command Get-PimImpactActivationLedgerDdl -ErrorAction SilentlyContinue) { try { [void](Invoke-PimSqlNonQuery -ConnectionString $ConnectionString -Sql (Get-PimImpactActivationLedgerDdl)) } catch { Write-Warning "[store] pim.ImpactActivations could not be created: $($_.Exception.Message)" } }
    # REQ 100.114 (2): the active-assignment rows (pim.ActiveAssignmentRows + pim.ActiveAssignmentSnapshots, below in this
    # file). Never fails the open: a store that cannot take the tables keeps the one-document snapshot, and says so.
    $aaDdl = Initialize-PimSqlActiveAssignmentRows -ConnectionString $ConnectionString
    if (-not $aaDdl.ok) { Write-Warning "[store] pim.ActiveAssignmentRows could not be created: $($aaDdl.error) -- the active-assignments snapshot stays one document in pim.TenantCache" }
    # Framework §12.23 run 2 prerequisite (PIM 100.156): the publish job's control view (REQ-Y licence row) was refreshed
    # by the MANAGER at every start -- a CREATE OR ALTER VIEW the web app may not run once it has no DDL right. The schema
    # step (the updater, before every roll) refreshes it now; a store without the view is left alone (the refresh SQL
    # itself checks). Never fails the open.
    if (Get-Command Get-PimPublishJobControlViewRefreshSql -ErrorAction SilentlyContinue) {
        try { [void](Invoke-PimSqlNonQuery -ConnectionString $ConnectionString -Sql (Get-PimPublishJobControlViewRefreshSql)) }
        catch { Write-Warning "[store] the publish job's control view could not be refreshed: $($_.Exception.Message)" }
    }
}

# ---- Framework §12.23 run 2 prerequisite (PIM 100.156): the RUNTIME never needs a DDL right ----------------------------
# Every table / column / view is created by the schema step (Initialize-PimSqlStore, run by the updater before every roll
# and by setup). A runtime path (the engine, the Manager) only CHECKS that what it is about to use is there -- read-only,
# OBJECT_ID / COL_LENGTH -- once per process and store. When something is missing (an install whose updater has not run
# since the object was added, a developer store), ONE -Fallback try of the old create is made: it works only where the
# identity still holds the right (a developer box, an install before run 2) and is refused harmlessly afterwards; still
# missing = a plain message naming the updater, never a DDL error from deep inside a job.
$script:PimSchemaReadyCache = @{}

function Get-PimSqlSchemaMissing {
    <#
      READ-ONLY. The -Objects (schema.object) and -Columns (@{ 'schema.table' = @('Col', ...) }) that are NOT in this
      store. Returns string[] ('pim.X' / 'pim.X.Col'); empty = ready. THROWS when the store cannot be read.
      -Query: param($cs, $sql, $params) -> rows (test seam; default Invoke-PimSqlQuery).
    #>
    param([Parameter(Mandatory)][string]$ConnectionString, [string[]]$Objects = @(), [hashtable]$Columns = @{}, [scriptblock]$Query)
    if (-not $Query) { $Query = { param($cs, $sql, $p) Invoke-PimSqlQuery -ConnectionString $cs -Sql $sql -Parameters $p } }
    $sel = New-Object System.Collections.Generic.List[string]; $p = @{}; $names = @{}; $i = 0
    foreach ($o in @($Objects)) { if (-not "$o".Trim()) { continue }; $sel.Add("CASE WHEN OBJECT_ID(@o$i) IS NULL THEN 0 ELSE 1 END AS [k$i]"); $p["o$i"] = "$o"; $names["k$i"] = "$o"; $i++ }
    foreach ($t in @($Columns.Keys)) {
        foreach ($c in @($Columns[$t])) { if (-not "$c".Trim()) { continue }; $sel.Add("CASE WHEN COL_LENGTH(@o$i, @c$i) IS NULL THEN 0 ELSE 1 END AS [k$i]"); $p["o$i"] = "$t"; $p["c$i"] = "$c"; $names["k$i"] = "$t.$c"; $i++ }
    }
    if (-not $sel.Count) { return @() }
    $rows = @(& $Query $ConnectionString ("SELECT " + ($sel -join ', ')) $p)
    if (-not $rows.Count) { throw 'the schema check returned no row' }
    $r = $rows[0]; $miss = New-Object System.Collections.Generic.List[string]
    foreach ($k in @($names.Keys | Sort-Object { [int]("$_".Substring(1)) })) {
        $v = if ($r -is [System.Collections.IDictionary]) { $r[$k] } else { $r.$k }
        if ("$v" -ne '1') { $miss.Add("$($names[$k])") }
    }
    return @($miss.ToArray())
}

function Confirm-PimSqlSchemaObject {
    <#
      The runtime half of §12.23 run 2: is everything this path uses in the store? NEVER throws:
      @{ ok; created; missing[]; message }. ok = ready (or created by the -Fallback). Cached per process and store once
      ready (not when -Query is a test seam). -Fallback: { } -- the old create, tried ONCE only when something is missing.
    #>
    param([Parameter(Mandatory)][string]$ConnectionString, [string[]]$Objects = @(), [hashtable]$Columns = @{},
          [scriptblock]$Fallback, [scriptblock]$Query)
    $key = "$ConnectionString|$(@($Objects) -join ',')|$(@($Columns.Keys | Sort-Object | ForEach-Object { "$_=$(@($Columns[$_]) -join '+')" }) -join ';')"
    if (-not $Query -and $script:PimSchemaReadyCache.ContainsKey($key)) { return [pscustomobject]@{ ok = $true; created = $false; missing = @(); message = '' } }
    $miss = @()
    try { $miss = @(Get-PimSqlSchemaMissing -ConnectionString $ConnectionString -Objects $Objects -Columns $Columns -Query $Query) }
    catch { return [pscustomobject]@{ ok = $false; created = $false; missing = @(); message = "the store could not be checked: $($_.Exception.Message)" } }
    if (-not $miss.Count) { if (-not $Query) { $script:PimSchemaReadyCache[$key] = $true }; return [pscustomobject]@{ ok = $true; created = $false; missing = @(); message = '' } }
    $why = ''
    if ($Fallback) {
        try {
            [void](& $Fallback)
            $miss = @(Get-PimSqlSchemaMissing -ConnectionString $ConnectionString -Objects $Objects -Columns $Columns -Query $Query)
            if (-not $miss.Count) { if (-not $Query) { $script:PimSchemaReadyCache[$key] = $true }; return [pscustomobject]@{ ok = $true; created = $true; missing = @(); message = '' } }
        } catch { $why = " ($((("$($_.Exception.Message)") -split "`n")[0]))" }
    }
    return [pscustomobject]@{ ok = $false; created = $false; missing = @($miss)
        message = ("{0} {1} not in this store -- the next update creates it (the updater's schema step); this component does not create tables{2}" -f (@($miss) -join ', '), $(if (@($miss).Count -eq 1) { 'is' } else { 'are' }), $why) }
}

function Test-PimSqlCanCreateTable {
    <#
      READ-ONLY. May THIS identity create a table in this database (HAS_PERMS_BY_NAME CREATE TABLE -- db_ddladmin / db_owner
      / an explicit grant)? $false when it may not OR the store cannot be read: never throws. -Query: param($cs, $sql) -> rows.
    #>
    param([Parameter(Mandatory)][string]$ConnectionString, [scriptblock]$Query)
    if (-not $Query) { $Query = { param($cs, $sql) Invoke-PimSqlQuery -ConnectionString $cs -Sql $sql } }
    try {
        $r = @(& $Query $ConnectionString "SELECT HAS_PERMS_BY_NAME(NULL, NULL, 'CREATE TABLE') AS canCreate;")[0]
        return ($null -ne $r -and "$($r.canCreate)" -eq '1')
    } catch { return $false }
}

function Wait-PimHostedStoreSchema {
    <#
      Framework §12.23 run 2 (PIM 100.156, live 2026-10-16 on a fresh community install): a HOSTED component whose store has
      no core tables yet (the Manager's FIRST start, before the deploy's schema step ran) must not attempt DDL -- it holds no
      DDL right, and the attempt logged "CREATE TABLE permission denied" with a stack trace. Instead: ONE calm line, then the
      READ-ONLY check is repeated every -IntervalSeconds until the tables are there or -MaxWaitSeconds passed; one more line
      when they appear. NEVER throws, never runs DDL. Returns { ready; checks; waitedSeconds; missing[] }.
      -Check: param($cs, $objects) -> { ok; missing } (default Confirm-PimSqlSchemaObject, no -Fallback). -Sleep: param($s).
      -Log: param($text) (default Write-Host). All three are test seams.
    #>
    param([Parameter(Mandatory)][string]$ConnectionString, [string[]]$Objects = @(), [int]$IntervalSeconds = 30, [int]$MaxWaitSeconds = 900,
          [scriptblock]$Check, [scriptblock]$Sleep, [scriptblock]$Log)
    if (-not $Check) { $Check = { param($cs, $o) Confirm-PimSqlSchemaObject -ConnectionString $cs -Objects $o } }
    if (-not $Sleep) { $Sleep = { param($s) Start-Sleep -Seconds $s } }
    if (-not $Log) { $Log = { param($t) Write-Host $t -ForegroundColor DarkGray } }
    if ($IntervalSeconds -lt 1) { $IntervalSeconds = 1 }
    if ($MaxWaitSeconds -lt 0) { $MaxWaitSeconds = 0 }
    $waited = 0; $checks = 0; $said = $false; $miss = @()
    while ($true) {
        $checks++
        $r = $null; try { $r = & $Check $ConnectionString $Objects } catch { $r = $null }
        if ($r -and $r.ok) {
            if ($said) { & $Log ("  [store] the store's schema is there now (after {0} s) -- starting" -f $waited) }
            return [pscustomobject]@{ ready = $true; checks = $checks; waitedSeconds = $waited; missing = @() }
        }
        if ($r -and $r.PSObject.Properties['missing']) { $miss = @($r.missing) }
        if (-not $said) {
            & $Log ("  [store] waiting for the store's schema -- the install / update creates it (checking again every {0} s)" -f $IntervalSeconds)
            $said = $true
        }
        if ($waited -ge $MaxWaitSeconds) { return [pscustomobject]@{ ready = $false; checks = $checks; waitedSeconds = $waited; missing = @($miss) } }
        $step = [Math]::Min($IntervalSeconds, [Math]::Max(1, $MaxWaitSeconds - $waited))
        & $Sleep $step
        $waited += $step
    }
}

function Invoke-PimDepartmentRowKeyMigration {
    <#
      2.4.462 -- re-key PIM-Definitions-Departments to the new store key (Get-PimStoreRowKey: a department GROUP row by its
      GroupTag, an owner row by its department name). Before 2.4.462 group rows were keyed on the Department column, so a
      new group of an existing department collided with that department's owner row and its save was refused.
      A full-set save re-keys by itself, but ROW-BY-ROW writers (the MSP downlink) would add a second copy next to the old
      key -- so existing rows are moved here, once, idempotently:
        * key already right                         -> untouched
        * new key free                              -> UPDATE [Key] (the row keeps its data and timestamp)
        * new key taken by a row with the SAME data -> the old-key copy is a duplicate -> deleted
        * new key taken by DIFFERENT data           -> left alone and reported (never merged or overwritten)
      Returns @{ moved; deduplicated; conflicts[] }. Never throws: a failed migration must not stop the store from opening.
    #>
    param([Parameter(Mandatory)][string]$ConnectionString, [object[]]$Rows = $null, [scriptblock]$Exec = $null)
    $out = @{ moved = 0; deduplicated = 0; conflicts = @() }
    try {
        $e = 'PIM-Definitions-Departments'
        if ($null -eq $Rows) { $Rows = @(Invoke-PimSqlQuery -ConnectionString $ConnectionString -Sql "SELECT [Key], DataJson FROM pim.Rows WHERE Entity=@e" -Parameters @{ e = $e }) }
        if (-not $Exec) { $Exec = { param($sql, $p) [void](Invoke-PimSqlNonQuery -ConnectionString $ConnectionString -Sql $sql -Parameters $p) } }
        $byKey = @{}; foreach ($r in @($Rows)) { if ($r) { $byKey["$($r.Key)".ToLowerInvariant()] = $r } }
        foreach ($r in @($Rows)) {
            if (-not $r) { continue }
            $data = $null; try { $data = "$($r.DataJson)" | ConvertFrom-Json } catch { continue }
            $nk = "$(Get-PimStoreRowKey -Base $e -Row $data)".Trim()
            if (-not $nk -or $nk -ieq "$($r.Key)") { continue }
            $other = $byKey[$nk.ToLowerInvariant()]
            if (-not $other) {
                & $Exec 'UPDATE pim.Rows SET [Key]=@nk WHERE Entity=@e AND [Key]=@ok' @{ e = $e; nk = $nk; ok = "$($r.Key)" }
                $byKey.Remove("$($r.Key)".ToLowerInvariant()); $byKey[$nk.ToLowerInvariant()] = $r
                $out.moved++
            } elseif ("$($other.DataJson)" -eq "$($r.DataJson)") {
                & $Exec 'DELETE FROM pim.Rows WHERE Entity=@e AND [Key]=@ok' @{ e = $e; ok = "$($r.Key)" }
                $byKey.Remove("$($r.Key)".ToLowerInvariant())
                $out.deduplicated++
            } else {
                $out.conflicts += "$($r.Key) -> $nk"
            }
        }
        if ($out.moved -or $out.deduplicated) { Write-Host ("[store] Departments re-keyed to the 2.4.462 store key: moved {0}, duplicates removed {1}" -f $out.moved, $out.deduplicated) -ForegroundColor DarkCyan }
        if ($out.conflicts.Count) { Write-Warning ("[store] Departments: {0} row(s) could not be re-keyed (a different row already holds the new key): {1}" -f $out.conflicts.Count, ($out.conflicts -join '; ')) }
    } catch { Write-Warning "[store] Departments re-key migration skipped: $($_.Exception.Message)" }
    return $out
}

function Get-PimRingOrderMigrationSql {
    # §77.20 -- the ONE-TIME conversion of every stored ring to the dev-first order (new = 2 - old), in ONE transaction,
    # guarded by the pim.Settings['RingOrder'] marker read under UPDLOCK so two starts cannot both convert. Rings outside
    # 0..2 are left as they are (they reached no tenant before and reach none now). UpdatedUtc is NOT touched: the
    # conversion changes no reach, so it must not look like an edit to the change detector.
    return @"
SET XACT_ABORT ON;
BEGIN TRAN;
IF NOT EXISTS (SELECT 1 FROM pim.Settings WITH (UPDLOCK, HOLDLOCK) WHERE Name = 'RingOrder')
BEGIN
    DECLARE @rows INT = 0, @central INT = 0, @tenants INT = 0;
    UPDATE pim.Rows
       SET DataJson = JSON_MODIFY(DataJson, '$.Ring', CAST(2 - CAST(JSON_VALUE(DataJson, '$.Ring') AS INT) AS NVARCHAR(10)))
     WHERE ISJSON(DataJson) = 1 AND JSON_VALUE(DataJson, '$.Ring') IN ('0', '1', '2');
    SET @rows = @@ROWCOUNT;
    IF OBJECT_ID('pim.CentralAdmins') IS NOT NULL
    BEGIN
        EXEC sp_executesql N'UPDATE pim.CentralAdmins SET Ring = 2 - Ring WHERE Ring BETWEEN 0 AND 2; SET @n = @@ROWCOUNT;', N'@n INT OUTPUT', @n = @central OUTPUT;
    END
    IF OBJECT_ID('platform.Tenants') IS NOT NULL AND COL_LENGTH('platform.Tenants', 'Ring') IS NOT NULL
    BEGIN
        EXEC sp_executesql N'UPDATE platform.Tenants SET Ring = 2 - Ring WHERE Ring BETWEEN 0 AND 2; SET @n = @@ROWCOUNT;', N'@n INT OUTPUT', @n = @tenants OUTPUT;
    END
    INSERT pim.Settings (Name, ValueJson)
    VALUES ('RingOrder', CONCAT('{"order":"dev-first","convertedUtc":"', CONVERT(NVARCHAR(30), SYSUTCDATETIME(), 127),
                                '","rows":', @rows, ',"centralAdmins":', @central, ',"tenants":', @tenants, '}'));
    SELECT 'converted' AS Outcome, @rows AS RowsConverted, @central AS CentralAdmins, @tenants AS Tenants;
END
ELSE
    SELECT 'already' AS Outcome, 0 AS RowsConverted, 0 AS CentralAdmins, 0 AS Tenants;
COMMIT;
"@
}

function Invoke-PimRingOrderMigration {
    <#
      §77.20 (operator 2026-09-21: "ring 0 = dev, ring 1 = test, ring 2 = broad (all)" / "make it consistent"). Until
      2.4.388 ring 0 was the BROADEST reach; every stored ring is converted ONCE per store so each row keeps exactly the
      tenants it reached: pim.Rows (every entity's Ring), pim.CentralAdmins.Ring, platform.Tenants.Ring, and the
      conformance overlay's per-entry rings. Idempotent (marker pim.Settings['RingOrder']); a fresh store just gets
      the marker. Returns @{ outcome = converted|already|failed; rows; centralAdmins; tenants; overlay; error }.
      A failure is REPORTED, never thrown: the store keeps working, and the next start tries again.
    #>
    param([Parameter(Mandatory)][string]$ConnectionString)
    $res = [ordered]@{ outcome = 'failed'; rows = 0; centralAdmins = 0; tenants = 0; overlay = 0; error = '' }
    try {
        # The conformance overlay first: it carries its own done-flag, so a retry after a failed SQL step never
        # converts it twice.
        $ov = $null
        try { $ov = Get-PimSqlSetting -ConnectionString $ConnectionString -Name 'ConformanceTemplateOverlay' } catch { $ov = $null }
        $marker = $null
        try { $marker = Get-PimSqlSetting -ConnectionString $ConnectionString -Name 'RingOrder' } catch { $marker = $null }
        if ($null -eq $marker -and $null -ne $ov) {
            if ($ov -is [string]) { try { $ov = $ov | ConvertFrom-Json } catch { $ov = $null } }
            if ($null -ne $ov -and -not $ov.PSObject.Properties['__ringOrder']) {
                $n = 0
                foreach ($tp in @($ov.PSObject.Properties)) {
                    $entry = $tp.Value
                    if ($null -eq $entry -or -not $entry.PSObject -or -not $entry.PSObject.Properties['rings'] -or $null -eq $entry.rings) { continue }
                    foreach ($rp in @($entry.rings.PSObject.Properties)) {
                        if ("$($rp.Value)".Trim() -match '^[0-2]$') { $rp.Value = 2 - [int]"$($rp.Value)".Trim(); $n++ }
                    }
                }
                $ov | Add-Member -NotePropertyName '__ringOrder' -NotePropertyValue 'dev-first' -Force
                Set-PimSqlSetting -ConnectionString $ConnectionString -Name 'ConformanceTemplateOverlay' -ValueJson ($ov | ConvertTo-Json -Depth 10 -Compress) | Out-Null
                $res.overlay = $n
            }
        }
        $out = @(Invoke-PimSqlQuery -ConnectionString $ConnectionString -Sql (Get-PimRingOrderMigrationSql))
        $row = $out | Select-Object -Last 1
        $res.outcome = "$($row.Outcome)"
        $res.rows = [int]$row.RowsConverted; $res.centralAdmins = [int]$row.CentralAdmins; $res.tenants = [int]$row.Tenants
        if ($res.outcome -eq 'converted') {
            Write-Host ("  [store] ring order converted to dev-first (0 dev, 1 test, 2 broad): {0} row(s), {1} central admin(s), {2} tenant(s), {3} conformance ring(s) -- every row keeps the tenants it reached" -f $res.rows, $res.centralAdmins, $res.tenants, $res.overlay) -ForegroundColor Yellow
        }
    } catch {
        $res.error = "$($_.Exception.Message)"
        Write-Warning ("  [store] the ring-order conversion (0 dev, 1 test, 2 broad) did NOT run: {0} -- rings are still in the OLD order in this store; it is retried on the next start." -f $res.error)
    }
    return $res
}

function Initialize-PimNamingConventionSeed {
    <#
      🔴 DEPLOY THE DEFAULT NAMING TEMPLATE INTO THE STORE (operator, 2026-09-20: *"naming convention are
      always per customer. if this are samples or default or initial, then we should incude that in the
      deployment instead"* / *"remember to add it to setup script also so we can deploy default naming
      template"*).

      Naming used to have THREE homes: the shipped defaults in code (PIM-Naming.ps1), a hand-synced copy in
      config\PIM4EntraPS.NamingConventions.locked.ps1, and pim.Settings. The file is gone; this is what
      replaces it -- every path that creates or opens a store (Initialize-PimTenantStore, the Manager's
      boot, the updater's schema step, Invoke-PimUpdate) now SEEDS the shipped defaults into
      pim.Settings['NamingConventions'], so a fresh environment has a complete, editable naming template on
      day one and nothing has to read a file.

      🔒 SEED, NEVER OVERWRITE. Naming is per customer: if the setting already exists -- even empty-ish --
      it is left exactly as it is. Writing defaults over a customer's conventions would silently rename
      every group and admin account the next run computes. Best-effort: a store that cannot take the seed
      is not a reason to fail store initialisation, so this never throws.
    #>
    [CmdletBinding()] param([Parameter(Mandatory)][string]$ConnectionString)
    try {
        if (-not (Get-Command Get-PimShippedNamingConventions -ErrorAction SilentlyContinue)) { return $false }
        $existing = $null
        try { $existing = Get-PimSqlSetting -ConnectionString $ConnectionString -Name 'NamingConventions' } catch { return $false }
        if ($null -ne $existing) { return $false }          # already the customer's -- untouched
        # 🔴 SEED A *NEW* STORE ONLY -- NEVER AN ESTABLISHED ONE.
        # Absent is not the same as new. An environment that already holds admins and groups was named by
        # SOME convention; if its setting is missing, writing the SHIPPED default here would declare the
        # wrong convention and the engine would then happily run on it. MSP-SETUP-GUIDE §5 / IMP-13:
        # EFIF's admins are 'admin-efif-{Initial}', so the shipped 'Admin-{Initial}' would make every one
        # of them invisible to the Admins provider's prefix match -- re-created every tick, accumulating
        # unmanaged privileged accounts. Seeding the wrong convention is WORSE than not seeding: on a
        # populated store we leave it absent so the engine's preflight REFUSES and a human decides.
        $populated = $true
        try {
            $rows = @(Invoke-PimSqlQuery -ConnectionString $ConnectionString -Sql 'SELECT TOP 1 1 AS x FROM pim.Rows')
            $populated = [bool](@($rows).Count)
        } catch { $populated = $true }                      # cannot tell => treat as established, do not seed
        if ($populated) {
            Write-Warning ("  [store] pim.Settings['NamingConventions'] is NOT set and this store already holds rows -- " +
                           "NOT seeding the shipped default (it would declare the wrong convention for an estate that is already named). " +
                           "Set this tenant's convention in the Manager (Settings > Naming); the engine refuses to run until it is there.")
            return $false
        }
        $shipped = Get-PimShippedNamingConventions
        if ($shipped -isnot [System.Collections.IDictionary] -or -not $shipped.Keys.Count) { return $false }
        Set-PimSqlSetting -ConnectionString $ConnectionString -Name 'NamingConventions' `
            -ValueJson (ConvertTo-Json -InputObject $shipped -Depth 12 -Compress)
        $back = Get-PimSqlSetting -ConnectionString $ConnectionString -Name 'NamingConventions'
        if ($null -eq $back) { Write-Warning '  [store] the default naming template was written but did not read back.'; return $false }
        Write-Host ("  [store] seeded the default naming template into pim.Settings['NamingConventions'] ({0} keys) -- edit it per customer in the Manager." -f $shipped.Keys.Count) -ForegroundColor DarkGray
        return $true
    } catch {
        Write-Warning "  [store] could not seed the default naming template (the environment keeps the in-code defaults): $($_.Exception.Message)"
        return $false
    }
}

# --- tenant-list cache (pim.TenantCache) -------------------------------------------
function Set-PimSqlTenantCache {
    # Upsert one cache kind. -Value is the whole document (e.g. @{ refreshedUtc; items }).
    # -ValueJson (100.31 SNAPSHOT-OOM): the document ALREADY serialised by the caller (the active-assignments snapshot
    # writes its rows one at a time into one compact string); stored as given, never parsed or re-serialised here.
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][string]$Kind, [object]$Value, [datetime]$RefreshedUtc = [datetime]::UtcNow,
          [AllowNull()][string]$ValueJson = $null)
    $json = if ($PSBoundParameters.ContainsKey('ValueJson')) { $(if ("$ValueJson" -ne '') { $ValueJson } else { $null }) }
            elseif ($null -ne $Value) { $Value | ConvertTo-Json -Depth 12 -Compress } else { $null }
    [void](Invoke-PimSqlNonQuery -ConnectionString $ConnectionString -Sql @"
MERGE pim.TenantCache AS t USING (SELECT @k AS Kind) AS s ON t.Kind = s.Kind
WHEN MATCHED THEN UPDATE SET ValueJson=@v, RefreshedUtc=@r, UpdatedUtc=SYSUTCDATETIME()
WHEN NOT MATCHED THEN INSERT (Kind, ValueJson, RefreshedUtc, UpdatedUtc) VALUES (@k, @v, @r, SYSUTCDATETIME());
"@ -Parameters @{ k = $Kind; v = $json; r = $RefreshedUtc.ToUniversalTime() } -CommandTimeoutSec 180)   # a large tenant's snapshot is one multi-MB row: 30 s timed out on a busy S0 (2026-10-08)
}

function Get-PimSqlTenantCache {
    # One cache kind, parsed; $null when the kind has never been written.
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][string]$Kind)
    $j = Invoke-PimSqlScalar -ConnectionString $ConnectionString -Sql "SELECT ValueJson FROM pim.TenantCache WHERE Kind=@k" -Parameters @{ k = $Kind }
    if ($null -eq $j -or $j -is [System.DBNull] -or "$j".Trim() -eq '') { return $null }
    return ($j | ConvertFrom-Json)
}

function Get-PimSqlTenantCacheStamps {
    # REQ 100.112: WHEN each kind was last written -- Kind + RefreshedUtc only, NEVER the document (one kind's document can
    # be tens of MB, and reading it is what made a "is there a snapshot?" question cost 25 s). Returns a hashtable
    # kind -> round-trip UTC text ('' when the column is NULL); a kind with no row is ABSENT from it. Throws on a failed read.
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][string[]]$Kinds)
    $out = @{}
    $ks = @($Kinds | Where-Object { "$_".Trim() })
    if ($ks.Count -eq 0) { return $out }
    $p = @{}; $names = New-Object System.Collections.Generic.List[string]
    for ($i = 0; $i -lt $ks.Count; $i++) { $p["k$i"] = "$($ks[$i])"; $names.Add("@k$i") }
    $rows = @(Invoke-PimSqlQuery -ConnectionString $ConnectionString -Sql ("SELECT Kind, RefreshedUtc FROM pim.TenantCache WHERE Kind IN (" + ($names -join ', ') + ")") -Parameters $p)
    foreach ($r in $rows) {
        if ($null -eq $r) { continue }
        $v = $r.RefreshedUtc; $txt = ''
        if ($v -is [datetime]) { $txt = [datetime]::SpecifyKind($v, [DateTimeKind]::Utc).ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ', [System.Globalization.CultureInfo]::InvariantCulture) }
        elseif ($null -ne $v) { $txt = "$v" }
        $out["$($r.Kind)"] = $txt
    }
    return $out
}

# --- active-assignment rows (pim.ActiveAssignmentRows) -- REQ 100.114 (2) / 100.110 ---------------------------------
# The active-assignments snapshot used to be ONE document in pim.TenantCache (22 MB at 38,000 assignments): written as
# one row (the write timed out, 100.110) and read + parsed whole for every request (25-63 s, 100.114). The ROWS now live
# in pim.ActiveAssignmentRows, one row per assignment, indexed for what the page filters and sorts on; the
# pim.TenantCache row 'active-assignments' keeps only the small header and names the generation (snapshotId) its rows
# are in. Writing = a new generation, batch by batch; the header is switched to it in ONE transaction after the row
# count was verified, so a reader sees the previous complete generation or the new complete one, never a part.
# A store where the table cannot be created keeps the one-document form (the caller falls back to it).
# Every default / limit is a FUNCTION returning a literal: a $script: variable is $null in a child scope behind a
# Get-Command load guard, and `-gt $null` is TRUE.
function Get-PimActiveAssignmentRowsBatchSize         { return 500 }    # rows per write batch (one transaction each)
function Get-PimActiveAssignmentRowsCommandTimeoutSec { return 120 }    # per batch / per statement of the snapshot write
function Get-PimActiveAssignmentRowsWriteAttempts     { return 4 }      # tries per batch on a transient error
function Get-PimActiveAssignmentRowsRetryDelayMs      { return 1500 }   # first wait; doubled per further try
function Get-PimActiveAssignmentsPageSizeDefault      { return 200 }
function Get-PimActiveAssignmentsPageSizeMax          { return 2000 }
function Get-PimActiveAssignmentsQueryTimeoutSec      { return 60 }
function Get-PimActiveAssignmentsAliasMax             { return 60 }     # exact-name alternatives per text search
function Get-PimActiveAssignmentsTableFormName        { return 'table' }

function Get-PimActiveAssignmentRowsDdl {
    <# PURE. The two tables + the indexes. Idempotent (every object guarded); additive only. #>
@'
IF OBJECT_ID('pim.ActiveAssignmentSnapshots') IS NULL
CREATE TABLE pim.ActiveAssignmentSnapshots (
    SnapshotId    BIGINT        NOT NULL CONSTRAINT PK_pim_ActiveAssignmentSnapshots PRIMARY KEY,
    State         NVARCHAR(20)  NOT NULL,
    StartedUtc    DATETIME2     NOT NULL CONSTRAINT DF_pim_AaSnapshots_Started DEFAULT SYSUTCDATETIME(),
    CompletedUtc  DATETIME2     NULL,
    RowsExpected  INT           NOT NULL CONSTRAINT DF_pim_AaSnapshots_Rows DEFAULT 0,
    MarksKey      NVARCHAR(100) NULL,
    MarksUtc      DATETIME2     NULL
);
IF OBJECT_ID('pim.ActiveAssignmentRows') IS NULL
CREATE TABLE pim.ActiveAssignmentRows (
    SnapshotId    BIGINT         NOT NULL,
    Seq           INT            NOT NULL,
    RowId         NVARCHAR(900)  NULL,
    Kind          NVARCHAR(40)   NOT NULL,
    Principal     NVARCHAR(400)  NULL,
    PrincipalId   NVARCHAR(100)  NULL,
    PrincipalKind NVARCHAR(40)   NULL,
    PrincipalUpn  NVARCHAR(400)  NULL,
    Role          NVARCHAR(400)  NULL,
    Scope         NVARCHAR(400)  NULL,
    GroupId       NVARCHAR(100)  NULL,
    StartUtc      DATETIME2      NULL,
    EndUtc        DATETIME2      NULL,
    Justification NVARCHAR(400)  NULL,
    IdentityKey   NVARCHAR(450)  NULL,
    Managed       BIT            NOT NULL CONSTRAINT DF_pim_AaRows_Managed DEFAULT 0,
    OwnKind       NVARCHAR(20)   NOT NULL CONSTRAINT DF_pim_AaRows_OwnKind DEFAULT N'',
    SearchText    NVARCHAR(4000) NULL,
    RowJson       NVARCHAR(MAX)  NOT NULL,
    CONSTRAINT PK_pim_ActiveAssignmentRows PRIMARY KEY CLUSTERED (SnapshotId, Seq)
);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_pim_AaRows_Kind' AND object_id = OBJECT_ID('pim.ActiveAssignmentRows'))
CREATE INDEX IX_pim_AaRows_Kind ON pim.ActiveAssignmentRows (SnapshotId, Kind, PrincipalKind, Managed, OwnKind) INCLUDE (PrincipalId);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_pim_AaRows_Principal' AND object_id = OBJECT_ID('pim.ActiveAssignmentRows'))
CREATE INDEX IX_pim_AaRows_Principal ON pim.ActiveAssignmentRows (SnapshotId, Principal, Seq) INCLUDE (Kind, PrincipalKind, Managed, OwnKind);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_pim_AaRows_Role' AND object_id = OBJECT_ID('pim.ActiveAssignmentRows'))
CREATE INDEX IX_pim_AaRows_Role ON pim.ActiveAssignmentRows (SnapshotId, Role, Seq) INCLUDE (Kind, PrincipalKind, Managed, OwnKind);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_pim_AaRows_Scope' AND object_id = OBJECT_ID('pim.ActiveAssignmentRows'))
CREATE INDEX IX_pim_AaRows_Scope ON pim.ActiveAssignmentRows (SnapshotId, Scope, Seq) INCLUDE (Kind, PrincipalKind, Managed, OwnKind);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_pim_AaRows_EndUtc' AND object_id = OBJECT_ID('pim.ActiveAssignmentRows'))
CREATE INDEX IX_pim_AaRows_EndUtc ON pim.ActiveAssignmentRows (SnapshotId, EndUtc, Seq) INCLUDE (Kind, PrincipalKind, Managed, OwnKind);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_pim_AaRows_PrincipalId' AND object_id = OBJECT_ID('pim.ActiveAssignmentRows'))
CREATE INDEX IX_pim_AaRows_PrincipalId ON pim.ActiveAssignmentRows (SnapshotId, PrincipalId);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_pim_AaRows_GroupId' AND object_id = OBJECT_ID('pim.ActiveAssignmentRows'))
CREATE INDEX IX_pim_AaRows_GroupId ON pim.ActiveAssignmentRows (SnapshotId, GroupId);
'@
}

function Initialize-PimSqlActiveAssignmentRows {
    # Create the tables + indexes when they are not there. NEVER throws: returns @{ ok; error }. ok=$false = this store
    # keeps the one-document snapshot (the identity may lack CREATE TABLE); the writer and the readers both handle that.
    param([Parameter(Mandatory)][string]$ConnectionString)
    try {
        [void](Invoke-PimSqlNonQuery -ConnectionString $ConnectionString -Sql (Get-PimActiveAssignmentRowsDdl) -CommandTimeoutSec (Get-PimActiveAssignmentRowsCommandTimeoutSec))
        return [pscustomobject]@{ ok = $true; error = '' }
    } catch {
        return [pscustomobject]@{ ok = $false; error = "$($_.Exception.Message)" }
    }
}

function Confirm-PimSqlActiveAssignmentRowsReady {
    # Framework §12.23 run 2 prerequisite (PIM 100.156): the RUNTIME half (the snapshot job). Read-only check that the two
    # tables are there; the create (Initialize-PimSqlActiveAssignmentRows) is only a one-time fallback -- the schema step
    # creates them. Same answer shape as Initialize-PimSqlActiveAssignmentRows: @{ ok; error }. NEVER throws.
    param([Parameter(Mandatory)][string]$ConnectionString)
    $r = Confirm-PimSqlSchemaObject -ConnectionString $ConnectionString -Objects @('pim.ActiveAssignmentSnapshots', 'pim.ActiveAssignmentRows') `
            -Fallback { $i = Initialize-PimSqlActiveAssignmentRows -ConnectionString $ConnectionString; if (-not $i.ok) { throw "$($i.error)" } }
    return [pscustomobject]@{ ok = [bool]$r.ok; error = "$($r.message)" }
}

function Test-PimSqlTransientError {
    <#
      PURE. Is this failure worth one more try of the SAME statement? A command / connection timeout, a deadlock victim,
      a dropped connection, Azure SQL "busy / reconfiguring / resource limit". Walks the inner exceptions. Anything else
      (a constraint, a missing object, a permission) is not transient: it fails at once.
    #>
    param([AllowNull()][object]$Exception)
    $numbers = @(-2, 53, 64, 121, 233, 1205, 4060, 10053, 10054, 10060, 10928, 10929, 40143, 40197, 40501, 40540, 40613, 49918, 49919, 49920)
    $e = $Exception
    if ($e -is [System.Management.Automation.ErrorRecord]) { $e = $e.Exception }
    $depth = 0
    while ($null -ne $e -and $depth -lt 8) {
        if ($e -is [System.TimeoutException]) { return $true }
        $n = $null
        try { if ($e.PSObject.Properties['Number']) { $n = $e.Number } } catch { $n = $null }
        if ($null -ne $n -and ($numbers -contains [int]$n)) { return $true }
        if ("$($e.Message)" -match '(?i)timeout expired|timed out|transport-level error|deadlocked|connection was (forcibly )?closed|not currently available|service is busy') { return $true }
        $e = $e.InnerException; $depth++
    }
    return $false
}

function New-PimSqlActiveAssignmentRowTable {
    <# The batch buffer: a DataTable with the table's WRITTEN columns (Managed / OwnKind keep their defaults). #>
    $t = New-Object System.Data.DataTable 'ActiveAssignmentRows'
    [void]$t.Columns.Add('SnapshotId', [long])
    [void]$t.Columns.Add('Seq', [int])
    foreach ($c in 'RowId', 'Kind', 'Principal', 'PrincipalId', 'PrincipalKind', 'PrincipalUpn', 'Role', 'Scope', 'GroupId') { [void]$t.Columns.Add($c, [string]) }
    [void]$t.Columns.Add('StartUtc', [datetime])
    [void]$t.Columns.Add('EndUtc', [datetime])
    foreach ($c in 'Justification', 'IdentityKey', 'SearchText', 'RowJson') { [void]$t.Columns.Add($c, [string]) }
    return ,$t
}

function Write-PimSqlActiveAssignmentRowBatch {
    <#
      ONE batch of rows into pim.ActiveAssignmentRows: one bulk insert in ONE transaction of its own, with the snapshot
      write's command timeout. -Attempt > 1 = a retry: whatever an earlier try may have left of exactly this batch
      (SnapshotId + its Seq range) is removed first, so a retry can never double a row. Throws on failure.
    #>
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][long]$SnapshotId, [Parameter(Mandatory)][System.Data.DataTable]$Table, [int]$Attempt = 1)
    if ($Table.Rows.Count -eq 0) { return 0 }
    $timeout = Get-PimActiveAssignmentRowsCommandTimeoutSec
    $first = [int]$Table.Rows[0]['Seq']; $last = [int]$Table.Rows[$Table.Rows.Count - 1]['Seq']
    $c = New-PimSqlConnection -ConnectionString $ConnectionString
    try {
        $c.Open()
        if ($Attempt -gt 1) {
            $cmd = $c.CreateCommand(); $cmd.CommandTimeout = $timeout
            $cmd.CommandText = 'DELETE FROM pim.ActiveAssignmentRows WHERE SnapshotId = @s AND Seq BETWEEN @a AND @b'
            [void]$cmd.Parameters.AddWithValue('@s', $SnapshotId); [void]$cmd.Parameters.AddWithValue('@a', $first); [void]$cmd.Parameters.AddWithValue('@b', $last)
            [void]$cmd.ExecuteNonQuery()
        }
        $ct = $c.GetType(); $asm = $ct.Assembly; $ns = $ct.Namespace
        $bcType  = $asm.GetType("$ns.SqlBulkCopy", $true)
        $optType = $asm.GetType("$ns.SqlBulkCopyOptions", $true)
        $txType  = $asm.GetType("$ns.SqlTransaction", $true)
        $opt = [Enum]::Parse($optType, 'UseInternalTransaction')
        $bc = $bcType.GetConstructor([type[]]@($ct, $optType, $txType)).Invoke(@($c, $opt, $null))
        try {
            $bc.DestinationTableName = 'pim.ActiveAssignmentRows'
            $bc.BulkCopyTimeout = $timeout
            $bc.BatchSize = $Table.Rows.Count          # the whole batch = one internal transaction
            foreach ($col in $Table.Columns) { [void]$bc.ColumnMappings.Add($col.ColumnName, $col.ColumnName) }
            $bc.WriteToServer($Table)
        } finally { try { $bc.Close() } catch { } }
        return $Table.Rows.Count
    } finally { if ($c) { $c.Close(); $c.Dispose() } }
}

function Invoke-PimSqlActiveAssignmentBatchWrite {
    <#
      One batch with the retry: up to Get-PimActiveAssignmentRowsWriteAttempts tries, a growing wait between them, and only
      for a TRANSIENT failure (Test-PimSqlTransientError). Returns @{ rows; attempts }. Throws the last error.
      -Writer / -Sleep are the test seams (default: Write-PimSqlActiveAssignmentRowBatch / Start-Sleep).
    #>
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][long]$SnapshotId, [Parameter(Mandatory)][System.Data.DataTable]$Table,
          [scriptblock]$Writer = $null, [scriptblock]$Sleep = $null)
    if (-not $Writer) { $Writer = { param($cs, $sid, $tbl, $attempt) Write-PimSqlActiveAssignmentRowBatch -ConnectionString $cs -SnapshotId $sid -Table $tbl -Attempt $attempt } }
    if (-not $Sleep) { $Sleep = { param($ms) Start-Sleep -Milliseconds $ms } }
    $max = Get-PimActiveAssignmentRowsWriteAttempts
    $delay = Get-PimActiveAssignmentRowsRetryDelayMs
    for ($attempt = 1; $attempt -le $max; $attempt++) {
        try {
            $n = & $Writer $ConnectionString $SnapshotId $Table $attempt
            return [pscustomobject]@{ rows = [int]$Table.Rows.Count; attempts = $attempt; written = $n }
        } catch {
            $transient = Test-PimSqlTransientError -Exception $_.Exception
            if (-not $transient -or $attempt -ge $max) { throw }
            Write-Warning ("  [active-assignments] a batch write did not complete (try {0} of {1}): {2} -- trying again" -f $attempt, $max, $_.Exception.Message)
            & $Sleep $delay
            $delay = $delay * 2
        }
    }
}

function Get-PimSqlActiveAssignmentsForm {
    <#
      Which form the stored snapshot has, read CHEAPLY (the first characters of the row, never the document):
      'none' (no row) | 'table' (the header of a table-form snapshot) | 'document' (the one-document form of 2.4.611 and
      before). Throws on a failed read.
    #>
    param([Parameter(Mandatory)][string]$ConnectionString)
    $rows = @(Invoke-PimSqlQuery -ConnectionString $ConnectionString -Sql "SELECT LEFT(ValueJson, 40) AS Head FROM pim.TenantCache WHERE Kind = @k" -Parameters @{ k = 'active-assignments' })
    if ($rows.Count -eq 0) { return 'none' }
    $head = "$($rows[0].Head)"
    if (-not $head.Trim()) { return 'none' }
    if ($head -match '^\s*\{\s*"rowStore"\s*:\s*"table"') { return 'table' }
    return 'document'
}

function Test-PimActiveAssignmentsTableEntry {
    <# PURE. Is this parsed pim.TenantCache 'active-assignments' entry the header of a table-form snapshot? #>
    param([AllowNull()][object]$Entry)
    if ($null -eq $Entry) { return $false }
    $v = $null
    if ($Entry -is [System.Collections.IDictionary]) { if ($Entry.Contains('rowStore')) { $v = $Entry['rowStore'] } }
    elseif ($Entry.PSObject.Properties['rowStore']) { $v = $Entry.rowStore }
    return ("$v" -eq (Get-PimActiveAssignmentsTableFormName))
}

function Get-PimSqlActiveAssignmentsCurrentSnapshotId {
    # The generation the stored header points at; 0 when there is none / it is the one-document form. Throws on a failed read.
    param([Parameter(Mandatory)][string]$ConnectionString)
    # The writer puts rowStore and snapshotId FIRST in the header, so the first characters answer this (no JSON function,
    # no document).
    $v = Invoke-PimSqlScalar -ConnectionString $ConnectionString -Sql 'SELECT LEFT(ValueJson, 120) FROM pim.TenantCache WHERE Kind = @k' -Parameters @{ k = 'active-assignments' }
    if ($null -eq $v -or $v -is [System.DBNull] -or -not "$v".Trim()) { return [long]0 }
    $m = [regex]::Match("$v", '^\s*\{\s*"rowStore"\s*:\s*"table"\s*,\s*"snapshotId"\s*:\s*(\d{1,18})')
    if (-not $m.Success) { return [long]0 }
    return [long]$m.Groups[1].Value
}

function Start-PimSqlActiveAssignmentSnapshot {
    <#
      Open a NEW generation for the snapshot write and return its id (greater than every id in the store). Removes what
      no reader can need any more: every generation that is neither the one the header points at nor this new one -- the
      leftovers of a failed write and generations before the current one -- in bounded deletes. The CURRENT generation is
      never touched here: it stays complete and readable until the header is switched (Complete-...), and after the switch
      it stays as the previous generation until the NEXT write starts, so a reader that read the header just before the
      switch still finds its rows.
    #>
    param([Parameter(Mandatory)][string]$ConnectionString, [int]$ExpectedRows = 0, [datetime]$NowUtc = [datetime]::UtcNow)
    $timeout = Get-PimActiveAssignmentRowsCommandTimeoutSec
    $current = Get-PimSqlActiveAssignmentsCurrentSnapshotId -ConnectionString $ConnectionString
    $max = Invoke-PimSqlScalar -ConnectionString $ConnectionString -Sql 'SELECT ISNULL(MAX(SnapshotId), 0) FROM pim.ActiveAssignmentSnapshots'
    $maxId = [long]0; if ($null -ne $max -and $max -isnot [System.DBNull]) { $maxId = [long]$max }
    $epoch = [datetime]::SpecifyKind([datetime]'1970-01-01T00:00:00', [DateTimeKind]::Utc)
    $id = [long][math]::Floor(($NowUtc.ToUniversalTime() - $epoch).TotalMilliseconds)
    if ($id -le $maxId) { $id = $maxId + 1 }
    if ($id -le $current) { $id = $current + 1 }
    [void](Invoke-PimSqlNonQuery -ConnectionString $ConnectionString -Sql "INSERT INTO pim.ActiveAssignmentSnapshots (SnapshotId, State, RowsExpected) VALUES (@s, N'writing', @n)" -Parameters @{ s = $id; n = $ExpectedRows } -CommandTimeoutSec $timeout)
    $removed = 0
    for ($i = 0; $i -lt 100000; $i++) {
        $n = Invoke-PimSqlNonQuery -ConnectionString $ConnectionString -Sql 'DELETE TOP (5000) FROM pim.ActiveAssignmentRows WHERE SnapshotId <> @keep AND SnapshotId <> @new' -Parameters @{ keep = $current; new = $id } -CommandTimeoutSec $timeout
        if ([int]$n -le 0) { break }
        $removed += [int]$n
    }
    [void](Invoke-PimSqlNonQuery -ConnectionString $ConnectionString -Sql 'DELETE FROM pim.ActiveAssignmentSnapshots WHERE SnapshotId <> @keep AND SnapshotId <> @new' -Parameters @{ keep = $current; new = $id } -CommandTimeoutSec $timeout)
    return [pscustomobject]@{ snapshotId = $id; previousSnapshotId = $current; removedRows = $removed }
}

function Complete-PimSqlActiveAssignmentSnapshot {
    <#
      THE SWITCH. One transaction: the generation's row count is checked against what was written, the generation is
      marked complete and the pim.TenantCache header is replaced by -HeaderJson (which names this generation). A count
      that does not match rolls everything back and throws -- the header keeps pointing at the previous generation.
    #>
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][long]$SnapshotId, [Parameter(Mandatory)][int]$ExpectedRows,
          [Parameter(Mandatory)][string]$HeaderJson, [datetime]$RefreshedUtc = [datetime]::UtcNow)
    $sql = @'
SET XACT_ABORT ON;
BEGIN TRAN;
DECLARE @have BIGINT = (SELECT COUNT_BIG(*) FROM pim.ActiveAssignmentRows WHERE SnapshotId = @s);
IF @have <> @n
BEGIN
    ROLLBACK;
    DECLARE @msg NVARCHAR(300) = CONCAT(N'active-assignment rows incomplete: ', @have, N' of ', @n, N' stored for generation ', @s, N' -- the previous snapshot stays in place');
    THROW 51114, @msg, 1;
END
UPDATE pim.ActiveAssignmentSnapshots SET State = N'complete', CompletedUtc = SYSUTCDATETIME(), RowsExpected = @n WHERE SnapshotId = @s;
MERGE pim.TenantCache AS t USING (SELECT @k AS Kind) AS src ON t.Kind = src.Kind
WHEN MATCHED THEN UPDATE SET ValueJson = @v, RefreshedUtc = @r, UpdatedUtc = SYSUTCDATETIME()
WHEN NOT MATCHED THEN INSERT (Kind, ValueJson, RefreshedUtc, UpdatedUtc) VALUES (@k, @v, @r, SYSUTCDATETIME());
COMMIT;
'@
    [void](Invoke-PimSqlNonQuery -ConnectionString $ConnectionString -Sql $sql -Parameters @{ s = $SnapshotId; n = $ExpectedRows; k = 'active-assignments'; v = $HeaderJson; r = $RefreshedUtc.ToUniversalTime() } -CommandTimeoutSec (Get-PimActiveAssignmentRowsCommandTimeoutSec))
}

function Get-PimSqlActiveAssignmentRowsJson {
    <#
      Every stored row of one generation as ONE JSON array string ('[{...},{...}]'), in snapshot order -- for the readers
      that still need the whole set (the coverage report, the Home tile, a delegated caller's filtered answer). The stored
      row JSON is passed through, never parsed here. -Kind = only that assignment type. -ExpectedRows (when no -Kind): a
      generation that holds another number of rows throws -- a part of a snapshot is never returned as the snapshot.
    #>
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][long]$SnapshotId, [string]$Kind = '', [int]$ExpectedRows = -1)
    $sb = New-Object System.Text.StringBuilder 65536
    [void]$sb.Append('[')
    $n = 0
    $c = New-PimSqlConnection -ConnectionString $ConnectionString
    try {
        $c.Open(); $cmd = $c.CreateCommand(); $cmd.CommandTimeout = Get-PimActiveAssignmentsQueryTimeoutSec
        if ("$Kind".Trim()) {
            $cmd.CommandText = 'SELECT RowJson FROM pim.ActiveAssignmentRows WHERE SnapshotId = @s AND Kind = @k ORDER BY Seq'
            [void]$cmd.Parameters.AddWithValue('@k', "$Kind".Trim())
        } else { $cmd.CommandText = 'SELECT RowJson FROM pim.ActiveAssignmentRows WHERE SnapshotId = @s ORDER BY Seq' }
        [void]$cmd.Parameters.AddWithValue('@s', $SnapshotId)
        $rd = $cmd.ExecuteReader()
        try {
            while ($rd.Read()) {
                if ($n -gt 0) { [void]$sb.Append(',') }
                [void]$sb.Append($rd.GetString(0))
                $n++
            }
        } finally { $rd.Close() }
    } finally { if ($c) { $c.Close(); $c.Dispose() } }
    if ($ExpectedRows -ge 0 -and -not "$Kind".Trim() -and $n -ne $ExpectedRows) {
        throw "the stored active-assignment rows are incomplete ($n of $ExpectedRows for generation $SnapshotId)"
    }
    [void]$sb.Append(']')
    return $sb.ToString()
}

function Expand-PimSqlActiveAssignmentsEntry {
    <#
      A table-form header (parsed) -> the SAME shape the one-document form had: the header's fields plus 'rows' (every
      row, parsed). For the readers that work on the whole set. Throws when the rows cannot be read or are incomplete.
    #>
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][object]$Entry)
    $sid = [long]0; [void][long]::TryParse("$($Entry.snapshotId)", [ref]$sid)
    $exp = -1; if ("$($Entry.rowCount)".Trim() -match '^\d+$') { $exp = [int]"$($Entry.rowCount)" }
    $json = Get-PimSqlActiveAssignmentRowsJson -ConnectionString $ConnectionString -SnapshotId $sid -ExpectedRows $exp
    $rows = @()
    if ($json.Length -gt 2) {
        # Windows PowerShell 5.1 hands a JSON array back as ONE object, pwsh 7 enumerates it: foreach covers both.
        $parsed = $json | ConvertFrom-Json
        $rows = @(foreach ($x in $parsed) { $x })
        $parsed = $null
    }
    $json = $null
    $out = [ordered]@{}
    foreach ($p in @($Entry.PSObject.Properties)) { $out[$p.Name] = $p.Value }
    $out['rows'] = $rows
    return [pscustomobject]$out
}

function Get-PimSqlActiveAssignmentServicePrincipalIds {
    # The distinct principal ids of kind servicePrincipal in one generation (index-only). For the "own identities" marks.
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][long]$SnapshotId)
    $rows = @(Invoke-PimSqlQuery -ConnectionString $ConnectionString -Sql "SELECT DISTINCT PrincipalId FROM pim.ActiveAssignmentRows WHERE SnapshotId = @s AND PrincipalKind = N'servicePrincipal' AND PrincipalId IS NOT NULL AND PrincipalId <> N''" -Parameters @{ s = $SnapshotId })
    return @($rows | ForEach-Object { "$($_.PrincipalId)" } | Where-Object { $_ })
}

function ConvertTo-PimSqlJsonStringArray {
    <# PURE. A string list -> a compact JSON array of strings ('[]' for none); trimmed, empty values dropped, lower-cased. #>
    param([AllowNull()][string[]]$Values)
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('[')
    $first = $true
    foreach ($v in @($Values)) {
        $s = "$v".Trim().ToLowerInvariant()
        if (-not $s) { continue }
        if (-not $first) { [void]$sb.Append(',') }
        $first = $false
        [void]$sb.Append('"')
        foreach ($ch in $s.ToCharArray()) {
            if ($ch -eq '"') { [void]$sb.Append('\"') }
            elseif ($ch -eq '\') { [void]$sb.Append('\\') }
            elseif ([int]$ch -lt 0x20) { [void]$sb.Append(('\u{0:x4}' -f [int]$ch)) }
            else { [void]$sb.Append($ch) }
        }
        [void]$sb.Append('"')
    }
    [void]$sb.Append(']')
    return $sb.ToString()
}

function Get-PimActiveAssignmentMarksKey {
    <# PURE. One key for everything the MANAGED / own-identity marks of a generation are computed from. #>
    param([string]$ManagedStamp = '', [bool]$ManagedKnown = $false, [string[]]$Product = @(), [string[]]$Support = @(), [string[]]$BreakGlass = @())
    $norm = { param($a) (@(@($a) | ForEach-Object { "$_".Trim().ToLowerInvariant() } | Where-Object { $_ } | Sort-Object -Unique) -join ',') }
    $text = @("m=$ManagedKnown", "ml=$ManagedStamp", "p=$(& $norm $Product)", "s=$(& $norm $Support)", "b=$(& $norm $BreakGlass)") -join '|'
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { $h = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($text)) } finally { $sha.Dispose() }
    return (-join ($h | ForEach-Object { $_.ToString('x2') }))
}

function Sync-PimSqlActiveAssignmentMarks {
    <#
      Bring the stored marks of one generation up to date, in SQL, set-based, ONLY when what they are computed from changed
      (-MarksKey differs from the one recorded for the generation):
        Managed  = the row's identity is in the engine's 'managed-live' list (pim.TenantCache, read inside SQL -- the list
                   never travels to this process)
        OwnKind  = breakglass | support | product | '' (that order of precedence) from the three small lists
      Returns @{ updated; changed }. Throws on failure (the caller reports it; rows are then served with the marks they have).
    #>
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][long]$SnapshotId, [Parameter(Mandatory)][string]$MarksKey,
          [bool]$ManagedKnown = $false, [string[]]$Product = @(), [string[]]$Support = @(), [string[]]$BreakGlass = @())
    $sql = @'
SET NOCOUNT ON; SET XACT_ABORT ON;
IF EXISTS (SELECT 1 FROM pim.ActiveAssignmentSnapshots WHERE SnapshotId = @s AND MarksKey = @mk)
BEGIN
    SELECT 0 AS Updated, 0 AS Changed;
    RETURN;
END
DECLARE @bg TABLE (v NVARCHAR(400) NOT NULL PRIMARY KEY);
DECLARE @sup TABLE (v NVARCHAR(400) NOT NULL PRIMARY KEY);
DECLARE @prod TABLE (v NVARCHAR(400) NOT NULL PRIMARY KEY);
DECLARE @m TABLE (v NVARCHAR(450) NOT NULL PRIMARY KEY);
INSERT @bg (v) SELECT DISTINCT LOWER(LEFT(CAST(j.[value] AS NVARCHAR(MAX)), 400)) FROM OPENJSON(@bgJson) j WHERE j.[value] IS NOT NULL AND j.[value] <> N'';
INSERT @sup (v) SELECT DISTINCT LOWER(LEFT(CAST(j.[value] AS NVARCHAR(MAX)), 400)) FROM OPENJSON(@supJson) j WHERE j.[value] IS NOT NULL AND j.[value] <> N'';
INSERT @prod (v) SELECT DISTINCT LOWER(LEFT(CAST(j.[value] AS NVARCHAR(MAX)), 400)) FROM OPENJSON(@prodJson) j WHERE j.[value] IS NOT NULL AND j.[value] <> N'';
IF @useManaged = 1
BEGIN
    INSERT @m (v)
    SELECT DISTINCT LOWER(LEFT(CAST(j.[value] AS NVARCHAR(MAX)), 450))
    FROM pim.TenantCache t CROSS APPLY OPENJSON(t.ValueJson, '$.identities') j
    WHERE t.Kind = N'managed-live' AND ISJSON(t.ValueJson) = 1 AND j.[value] IS NOT NULL AND j.[value] <> N'';
    IF NOT EXISTS (SELECT 1 FROM @m)
        INSERT @m (v)
        SELECT LOWER(LEFT(JSON_VALUE(t.ValueJson, '$.identities'), 450)) FROM pim.TenantCache t
        WHERE t.Kind = N'managed-live' AND ISJSON(t.ValueJson) = 1 AND JSON_VALUE(t.ValueJson, '$.identities') IS NOT NULL AND JSON_VALUE(t.ValueJson, '$.identities') <> N'';
END
BEGIN TRAN;
UPDATE a SET Managed = n.Managed, OwnKind = n.OwnKind
FROM pim.ActiveAssignmentRows a
CROSS APPLY (SELECT
    CAST(CASE WHEN a.IdentityKey IS NOT NULL AND a.IdentityKey <> N'' AND EXISTS (SELECT 1 FROM @m m WHERE m.v = LOWER(a.IdentityKey)) THEN 1 ELSE 0 END AS BIT) AS Managed,
    CASE WHEN EXISTS (SELECT 1 FROM @bg b WHERE b.v IN (LOWER(a.PrincipalId), LOWER(LTRIM(RTRIM(a.Principal))), LOWER(LTRIM(RTRIM(a.PrincipalUpn))))) THEN N'breakglass'
         WHEN EXISTS (SELECT 1 FROM @sup s WHERE s.v = LOWER(a.PrincipalId)) THEN N'support'
         WHEN EXISTS (SELECT 1 FROM @prod p WHERE p.v = LOWER(a.PrincipalId)) THEN N'product'
         ELSE N'' END AS OwnKind) n
WHERE a.SnapshotId = @s AND (a.Managed <> n.Managed OR a.OwnKind <> n.OwnKind);
DECLARE @chg INT = @@ROWCOUNT;
UPDATE pim.ActiveAssignmentSnapshots SET MarksKey = @mk, MarksUtc = SYSUTCDATETIME() WHERE SnapshotId = @s;
COMMIT;
SELECT 1 AS Updated, @chg AS Changed;
'@
    $p = @{ s = $SnapshotId; mk = $MarksKey; useManaged = [bool]$ManagedKnown
            bgJson   = (ConvertTo-PimSqlJsonStringArray -Values @($BreakGlass | Where-Object { "$_" -notmatch '^\s*<' }))
            supJson  = (ConvertTo-PimSqlJsonStringArray -Values $Support)
            prodJson = (ConvertTo-PimSqlJsonStringArray -Values $Product) }
    $sets = Invoke-PimSqlQuerySets -ConnectionString $ConnectionString -Sql $sql -Parameters $p -CommandTimeoutSec (Get-PimActiveAssignmentRowsCommandTimeoutSec)
    $row = $null
    for ($i = 0; $i -lt $sets.Count; $i++) { foreach ($r in $sets[$i]) { if ($null -ne $r -and $r.PSObject.Properties['Updated']) { $row = $r } } }
    if ($null -eq $row) { return [pscustomobject]@{ updated = $false; changed = 0 } }
    return [pscustomobject]@{ updated = ([int]$row.Updated -eq 1); changed = [int]$row.Changed }
}

function Invoke-PimSqlQuerySets {
    <# Like Invoke-PimSqlQuery, for a batch that answers SEVERAL result sets: returns a list, one object[] per set. #>
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][string]$Sql, [hashtable]$Parameters = @{}, [int]$CommandTimeoutSec = 0)
    Assert-PimSqlDemoScope -Sql $Sql
    $sets = New-Object System.Collections.Generic.List[object]
    $c = New-PimSqlConnection -ConnectionString $ConnectionString
    try {
        $c.Open(); $cmd = $c.CreateCommand(); $cmd.CommandText = $Sql
        if ($CommandTimeoutSec -gt 0) { $cmd.CommandTimeout = $CommandTimeoutSec }
        foreach ($k in $Parameters.Keys) { [void]$cmd.Parameters.AddWithValue("@$k", $(if ($null -eq $Parameters[$k]) { [DBNull]::Value } else { $Parameters[$k] })) }
        $rd = $cmd.ExecuteReader()
        try {
            do {
                $rows = New-Object System.Collections.Generic.List[object]
                while ($rd.Read()) { $o = [ordered]@{}; for ($i = 0; $i -lt $rd.FieldCount; $i++) { $o[$rd.GetName($i)] = $(if ($rd.IsDBNull($i)) { $null } else { $rd.GetValue($i) }) }; $rows.Add([pscustomobject]$o) }
                $sets.Add($rows.ToArray())
            } while ($rd.NextResult())
        } finally { $rd.Close() }
    } finally { if ($c) { $c.Close(); $c.Dispose() } }
    # an ARRAY of the sets (index it; Windows PowerShell 5.1 cannot wrap a generic list in @() -- "Argument types do not match")
    return ,($sets.ToArray())
}

function Get-PimActiveAssignmentsSortColumn {
    <#
      PURE. The page's sort key -> the column it sorts on. A CLOSED list: the ORDER BY text is built from these literals
      only, never from what the request sent. An unknown key = the default (principal).
    #>
    param([string]$Key = '')
    switch ("$Key".Trim().ToLowerInvariant()) {
        'principal'     { return 'a.Principal' }
        'role'          { return 'a.Role' }
        'scope'         { return 'a.Scope' }
        'type'          { return 'a.Kind' }
        'start'         { return 'a.StartUtc' }
        'end'           { return 'a.EndUtc' }
        'justification' { return 'a.Justification' }
    }
    return 'a.Principal'
}

function ConvertTo-PimSqlLikeContains {
    <# PURE. A search text -> the LIKE pattern for "contains" with ESCAPE '\' (the text's own % _ [ \ are literals). #>
    param([AllowNull()][string]$Text)
    $t = "$Text"
    $t = $t.Replace('\', '\\').Replace('%', '\%').Replace('_', '\_').Replace('[', '\[')
    return '%' + $t + '%'
}

function Get-PimActiveAssignmentsConditionColumn {
    <#
      PURE. PIM 100.120. A list-menu condition's column name -> the SQL expression it compares. A CLOSED list: the text
      of a condition is built from these literals only, never from what the request sent. Unknown = '' (the caller
      refuses). -Exact: "is" / "starts with" / "any of" compare the name itself; "contains" on principal also reads the
      sign-in name, as the page shows both.
    #>
    param([string]$Key = '', [switch]$Exact)
    switch -CaseSensitive ("$Key") {
        'principal'     { if ($Exact) { return "ISNULL(a.Principal, N'')" } else { return "CONCAT(ISNULL(a.Principal, N''), N' ', ISNULL(a.PrincipalUpn, N''))" } }
        'role'          { return "ISNULL(a.Role, N'')" }
        'scope'         { return "ISNULL(a.Scope, N'')" }
        'type'          { return "ISNULL(a.Kind, N'')" }
        'justification' { return "ISNULL(a.Justification, N'')" }
        '*'             { return "ISNULL(a.SearchText, N'')" }
    }
    return ''
}

function Get-PimActiveAssignmentsConditionSql {
    <#
      PURE. PIM 100.120. The list menu's conditions (already checked: ConvertTo-PimListQuery) -> the text added to the
      WHERE of the paged query, and its parameters: @{ sql; parameters; count }. Every VALUE is a parameter (@lmc0,
      @lmc1, ... -- the names come from a counter here, @lmq for the search); the only text that varies is a column
      expression from the closed list above and one of five fixed comparisons. No condition and no search = '' and no
      parameter, so the statement is what it was. A column or an operator outside the lists THROWS (fail closed).
    #>
    param([AllowNull()][object[]]$Conditions, [AllowNull()][string]$Search = '')
    $sb = New-Object System.Text.StringBuilder
    $p = @{}
    $n = 0
    foreach ($c in @($Conditions)) {
        if ($null -eq $c) { continue }
        if ($n -ge 10) { throw 'more than 10 list conditions' }
        $op = "$($c.op)"
        $exact = (@('equals', 'startsWith', 'anyOf') -ccontains $op)
        $col = Get-PimActiveAssignmentsConditionColumn -Key "$($c.col)" -Exact:$exact
        if (-not $col) { throw 'a list condition names a column that is not in the list of known columns' }
        $name = 'lmc' + $n
        $text = "$($c.value)".Trim().ToLowerInvariant()
        if ($text.Length -gt 200) { $text = $text.Substring(0, 200) }
        if ($op -ceq 'contains') {
            [void]$sb.Append("`n  AND LOWER($col) LIKE @$name ESCAPE N'\'")
            $p[$name] = (ConvertTo-PimSqlLikeContains -Text $text)
        } elseif ($op -ceq 'notContains') {
            [void]$sb.Append("`n  AND LOWER($col) NOT LIKE @$name ESCAPE N'\'")
            $p[$name] = (ConvertTo-PimSqlLikeContains -Text $text)
        } elseif ($op -ceq 'startsWith') {
            [void]$sb.Append("`n  AND LOWER(LTRIM($col)) LIKE @$name ESCAPE N'\'")
            $p[$name] = (ConvertTo-PimSqlLikeContains -Text $text).Substring(1)
        } elseif ($op -ceq 'equals') {
            [void]$sb.Append("`n  AND LOWER(LTRIM(RTRIM($col))) = @$name")
            $p[$name] = $text
        } elseif ($op -ceq 'anyOf') {
            $vals = @(@($c.values) | ForEach-Object { "$_" })
            $hasEmpty = (@($vals | Where-Object { -not "$_".Trim() }).Count -gt 0)
            [void]$sb.Append("`n  AND (LOWER(LTRIM(RTRIM($col))) IN (SELECT CAST(j.[value] AS NVARCHAR(400)) FROM OPENJSON(@$name) j)")
            if ($hasEmpty) { [void]$sb.Append(" OR LTRIM(RTRIM($col)) = N''") }
            [void]$sb.Append(')')
            $p[$name] = (ConvertTo-PimSqlJsonStringArray -Values @($vals | Select-Object -First 50))
        } else { throw 'a list condition has an operator that is not one of the five known ones' }
        $n++
    }
    $s = "$Search".Trim().ToLowerInvariant()
    if ($s.Length -gt 200) { $s = $s.Substring(0, 200) }
    if ($s) {
        [void]$sb.Append("`n  AND a.SearchText LIKE @lmq ESCAPE N'\'")
        $p['lmq'] = (ConvertTo-PimSqlLikeContains -Text $s)
    }
    return @{ sql = $sb.ToString(); parameters = $p; count = $n }
}

function Get-PimActiveAssignmentsViewCounts {
    <#
      PURE. The page's counters from the grouped counts of a whole generation (-Groups: Kind, IsDeleted, Managed, OwnKind,
      N) and the five "show" ticks -- the SAME rule the page applies to a row (deleted first, then its own kind, then
      managed): total, deleted, managed, own{product,support,breakglass}, hidden, hiddenBy{...}, and the per-type counts of
      what is not hidden.
    #>
    param([AllowNull()][object[]]$Groups, [bool]$ShowDeleted = $false, [bool]$ShowManaged = $false, [bool]$ShowProduct = $false, [bool]$ShowSupport = $false, [bool]$ShowBreakGlass = $false)
    $own = [ordered]@{ product = 0; support = 0; breakglass = 0 }
    $hiddenBy = [ordered]@{ product = 0; support = 0; breakglass = 0; managed = 0; deleted = 0 }
    $visible = [ordered]@{ all = 0; 'entra-role' = 0; 'azure-rbac' = 0; 'pim-for-groups' = 0 }
    $byType = [ordered]@{ total = 0; 'entra-role' = 0; 'azure-rbac' = 0; 'pim-for-groups' = 0 }
    $total = [long]0; $deleted = [long]0; $managed = [long]0; $hidden = [long]0
    $showOwn = @{ product = $ShowProduct; support = $ShowSupport; breakglass = $ShowBreakGlass }
    foreach ($g in @($Groups)) {
        if ($null -eq $g) { continue }
        $n = [long]$g.N; $kind = "$($g.Kind)"; $ok = "$($g.OwnKind)"
        $isDel = ([int]$g.IsDeleted -eq 1); $isMan = [bool]$g.Managed
        $total += $n; $byType['total'] += $n
        if ($byType.Contains($kind)) { $byType[$kind] += $n }
        if ($isDel) { $deleted += $n }
        if ($isMan) { $managed += $n }
        if ($own.Contains($ok)) { $own[$ok] += $n }
        $why = ''
        if (-not $ShowDeleted -and $isDel) { $why = 'deleted' }
        elseif ($own.Contains($ok) -and -not $showOwn[$ok]) { $why = $ok }
        elseif (-not $ShowManaged -and $isMan) { $why = 'managed' }
        if ($why) { $hidden += $n; $hiddenBy[$why] += $n; continue }
        $visible['all'] += $n
        if ($visible.Contains($kind)) { $visible[$kind] += $n }
    }
    return [ordered]@{ total = $total; deleted = $deleted; managed = $managed; own = $own; hidden = $hidden; hiddenBy = $hiddenBy; visible = $visible; byType = $byType }
}

function Invoke-PimSqlActiveAssignmentsQuery {
    <#
      COUNTS + ONE PAGE of one generation, filter, sort and paging IN SQL. Every value of the request is a PARAMETER; the
      only text that varies is the ORDER BY column and direction, taken from a closed list in this file
      (Get-PimActiveAssignmentsSortColumn). Returns:
        @{ groups   = the grouped counts of the whole generation (for Get-PimActiveAssignmentsViewCounts)
           filtered = how many rows match the filter (all pages)
           rows     = this page: @{ seq; json (the stored row, as written); managed; ownKind }
           page; pageSize }
      -Type all | entra-role | azure-rbac | pim-for-groups | deleted. -Search = "contains", over principal id, principal,
      role, scope and justification (lower-cased both sides). -Aliases = exact names (principal / role / scope) that also
      match the search (the page's tag <-> display-name pairs). -ScopeIs = exact scope names (the group-delete check).
    #>
    param(
        [Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][long]$SnapshotId,
        [string]$Type = 'all', [string]$Search = '', [string[]]$Aliases = @(), [string[]]$ScopeIs = @(),
        [string]$Sort = 'principal', [switch]$Descending, [int]$Page = 1, [int]$PageSize = 0,
        [bool]$ShowDeleted = $false, [bool]$ShowManaged = $false, [bool]$ShowProduct = $false, [bool]$ShowSupport = $false, [bool]$ShowBreakGlass = $false,
        # PIM 100.120: the list menu's conditions and search (checked by the caller), added to the filter of the COUNT and
        # of the page -- so "filtered" is the number of matching rows of the whole list. None = the statement as it was.
        [AllowNull()][object[]]$Conditions = @(), [AllowNull()][string]$ListSearch = ''
    )
    $max = Get-PimActiveAssignmentsPageSizeMax
    if ($PageSize -le 0) { $PageSize = Get-PimActiveAssignmentsPageSizeDefault }
    if ($PageSize -gt $max) { $PageSize = $max }
    if ($Page -lt 1) { $Page = 1 }
    $typeV = "$Type".Trim().ToLowerInvariant()
    if (@('all', 'entra-role', 'azure-rbac', 'pim-for-groups', 'deleted') -notcontains $typeV) { $typeV = 'all' }
    $q = "$Search".Trim().ToLowerInvariant()
    if ($q.Length -gt 200) { $q = $q.Substring(0, 200) }
    $aliasMax = Get-PimActiveAssignmentsAliasMax
    $al = @(@($Aliases) | Where-Object { "$_".Trim() } | Select-Object -First $aliasMax)
    $sc = @(@($ScopeIs) | Where-Object { "$_".Trim() } | Select-Object -First $aliasMax)
    $col = Get-PimActiveAssignmentsSortColumn -Key $Sort
    $dir = if ($Descending) { 'DESC' } else { 'ASC' }
    $where = @'
a.SnapshotId = @sid
  AND (@showDeleted = 1 OR a.PrincipalKind IS NULL OR a.PrincipalKind <> N'deleted')
  AND (a.OwnKind = N'' OR (a.OwnKind = N'product' AND @showProduct = 1) OR (a.OwnKind = N'support' AND @showSupport = 1) OR (a.OwnKind = N'breakglass' AND @showBreakGlass = 1))
  AND (@showManaged = 1 OR a.Managed = 0)
  AND (@type = N'all' OR (@type = N'deleted' AND a.PrincipalKind = N'deleted') OR (@type <> N'deleted' AND a.Kind = @type))
  AND (@q = N'' OR a.SearchText LIKE @qLike ESCAPE N'\' OR (@hasAl = 1 AND EXISTS (SELECT 1 FROM @al x WHERE x.v IN (LOWER(LTRIM(RTRIM(a.Scope))), LOWER(LTRIM(RTRIM(a.Role))), LOWER(LTRIM(RTRIM(a.Principal)))))))
  AND (@hasSc = 0 OR EXISTS (SELECT 1 FROM @sc y WHERE y.v = LOWER(LTRIM(RTRIM(a.Scope)))))
'@
    $lmSql = Get-PimActiveAssignmentsConditionSql -Conditions $Conditions -Search $ListSearch
    if ("$($lmSql.sql)") { $where = $where + "$($lmSql.sql)" }
    $sql = @"
SET NOCOUNT ON;
DECLARE @al TABLE (v NVARCHAR(400) NOT NULL PRIMARY KEY);
DECLARE @sc TABLE (v NVARCHAR(400) NOT NULL PRIMARY KEY);
INSERT @al (v) SELECT DISTINCT LOWER(LEFT(CAST(j.[value] AS NVARCHAR(MAX)), 400)) FROM OPENJSON(@aliasJson) j WHERE j.[value] IS NOT NULL AND j.[value] <> N'';
INSERT @sc (v) SELECT DISTINCT LOWER(LEFT(CAST(j.[value] AS NVARCHAR(MAX)), 400)) FROM OPENJSON(@scopeJson) j WHERE j.[value] IS NOT NULL AND j.[value] <> N'';
DECLARE @hasAl BIT = CASE WHEN EXISTS (SELECT 1 FROM @al) THEN 1 ELSE 0 END;
DECLARE @hasSc BIT = CASE WHEN EXISTS (SELECT 1 FROM @sc) THEN 1 ELSE 0 END;
SELECT a.Kind, CASE WHEN a.PrincipalKind = N'deleted' THEN 1 ELSE 0 END AS IsDeleted, a.Managed, a.OwnKind, COUNT_BIG(*) AS N
FROM pim.ActiveAssignmentRows a WHERE a.SnapshotId = @sid
GROUP BY a.Kind, CASE WHEN a.PrincipalKind = N'deleted' THEN 1 ELSE 0 END, a.Managed, a.OwnKind;
SELECT COUNT_BIG(*) AS N FROM pim.ActiveAssignmentRows a WHERE $where OPTION (RECOMPILE);
SELECT a.Seq, a.RowJson, a.Managed, a.OwnKind FROM pim.ActiveAssignmentRows a WHERE $where
ORDER BY $col $dir, a.Seq ASC OFFSET @off ROWS FETCH NEXT @take ROWS ONLY OPTION (RECOMPILE);
"@
    $p = @{ sid = $SnapshotId; type = $typeV; q = $q; qLike = (ConvertTo-PimSqlLikeContains -Text $q)
            aliasJson = (ConvertTo-PimSqlJsonStringArray -Values $al); scopeJson = (ConvertTo-PimSqlJsonStringArray -Values $sc)
            showDeleted = [bool]$ShowDeleted; showManaged = [bool]$ShowManaged; showProduct = [bool]$ShowProduct; showSupport = [bool]$ShowSupport; showBreakGlass = [bool]$ShowBreakGlass
            off = [int](($Page - 1) * $PageSize); take = [int]$PageSize }
    foreach ($lmKey in @($lmSql.parameters.Keys)) { $p["$lmKey"] = $lmSql.parameters[$lmKey] }
    $sets = Invoke-PimSqlQuerySets -ConnectionString $ConnectionString -Sql $sql -Parameters $p -CommandTimeoutSec (Get-PimActiveAssignmentsQueryTimeoutSec)
    if ($sets.Count -lt 3) { throw "the active-assignments query answered $($sets.Count) of 3 result sets" }
    $filtered = [long]0
    foreach ($r in $sets[1]) { if ($null -ne $r) { $filtered = [long]$r.N } }
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($r in $sets[2]) {
        if ($null -eq $r) { continue }
        $rows.Add([pscustomobject]@{ seq = [int]$r.Seq; json = "$($r.RowJson)"; managed = [bool]$r.Managed; ownKind = "$($r.OwnKind)" })
    }
    return [pscustomobject]@{ groups = @($sets[0]); filtered = $filtered; rows = $rows.ToArray(); page = $Page; pageSize = $PageSize; sort = $col; descending = [bool]$Descending }
}

# --- row CRUD -------------------------------------------------------------------
function Get-PimSqlRows {
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][string]$Entity)
    $raw = Invoke-PimSqlQuery -ConnectionString $ConnectionString -Sql "SELECT [Key], DataJson FROM pim.Rows WHERE Entity = @e ORDER BY [Key]" -Parameters @{ e = $Entity }
    # §97.1: parsed 200 rows per ConvertFrom-Json call, not one call per row (a 400-row entity was ~1 s of parser start-up,
    # read twice per commit). Same objects, same order; a row whose JSON does not parse alone still fails the read.
    $js = @($raw | Where-Object { "$($_.DataJson)".Trim() } | ForEach-Object { "$($_.DataJson)" })
    $out = New-Object System.Collections.Generic.List[object]
    for ($at = 0; $at -lt $js.Count; $at += 200) {
        $chunk = $js[$at..([Math]::Min($js.Count, $at + 200) - 1)]
        $parsed = ConvertFrom-Json -InputObject ('[' + ($chunk -join ',') + ']')   # assigned first: PS 5.1 emits the array as ONE object
        foreach ($o in @($parsed)) { $out.Add($o) }
    }
    return @($out.ToArray())
}

function Get-PimSqlRow {
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][string]$Entity, [Parameter(Mandatory)][string]$Key)
    $j = Invoke-PimSqlScalar -ConnectionString $ConnectionString -Sql "SELECT DataJson FROM pim.Rows WHERE Entity=@e AND [Key]=@k" -Parameters @{ e = $Entity; k = $Key }
    if ($null -eq $j -or "$j".Trim() -eq '') { return $null }
    return ($j | ConvertFrom-Json)
}

function Invoke-PimSqlJournaledRowWrite {
    <#
      CONFIG-1.1: ONE row written (upsert, or delete with -Remove) together with its journal row, in ONE transaction:
      read the stored JSON (UPDLOCK), write, and journal Add / Modify / Remove when the content changed. A byte-identical
      upsert still stamps UpdatedUtc (unchanged behaviour) and leaves no journal row. Throws (rolled back) on any failure.
    #>
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][string]$Entity, [Parameter(Mandatory)][string]$Key,
          [AllowNull()][string]$Json, [switch]$Remove)
    $c = New-PimSqlConnection -ConnectionString $ConnectionString
    $tx = $null
    try {
        $c.Open(); $tx = $c.BeginTransaction()
        $before = Get-PimRowJsonTx -Connection $c -Transaction $tx -Entity $Entity -Key $Key
        $cmd = $c.CreateCommand(); $cmd.Transaction = $tx
        [void]$cmd.Parameters.AddWithValue('@e', $Entity); [void]$cmd.Parameters.AddWithValue('@k', $Key)
        if ($Remove) {
            $cmd.CommandText = 'DELETE FROM pim.Rows WHERE Entity=@e AND [Key]=@k'
            [void]$cmd.ExecuteNonQuery()
            if ($null -ne $before) { Add-PimCommitJournalRowTx -Connection $c -Transaction $tx -Entity $Entity -Key $Key -Op Remove -BeforeJson $before -AfterJson $null }
        } else {
            $cmd.CommandText = @"
MERGE pim.Rows AS t USING (SELECT @e AS Entity, @k AS [Key]) AS s
  ON t.Entity = s.Entity AND t.[Key] = s.[Key]
WHEN MATCHED THEN UPDATE SET DataJson = @d, UpdatedUtc = SYSUTCDATETIME()
WHEN NOT MATCHED THEN INSERT (Entity, [Key], DataJson, UpdatedUtc) VALUES (@e, @k, @d, SYSUTCDATETIME());
"@
            [void]$cmd.Parameters.AddWithValue('@d', $Json)
            [void]$cmd.ExecuteNonQuery()
            if ($null -eq $before) { Add-PimCommitJournalRowTx -Connection $c -Transaction $tx -Entity $Entity -Key $Key -Op Add -BeforeJson $null -AfterJson $Json }
            elseif (-not [string]::Equals($before, $Json, [StringComparison]::Ordinal)) { Add-PimCommitJournalRowTx -Connection $c -Transaction $tx -Entity $Entity -Key $Key -Op Modify -BeforeJson $before -AfterJson $Json }
        }
        $tx.Commit(); $tx = $null
    } catch {
        if ($tx) { try { $tx.Rollback() } catch { Write-Warning "  [sql] transaction rollback failed: $($_.Exception.Message)" } }
        throw
    } finally {
        if ($c) { $c.Close(); $c.Dispose() }
    }
}

function Set-PimSqlRow {
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][string]$Entity, [Parameter(Mandatory)][string]$Key, [object]$Data)
    $json = if ($null -ne $Data) { $Data | ConvertTo-Json -Depth 12 -Compress } else { '{}' }
    Invoke-PimSqlJournaledRowWrite -ConnectionString $ConnectionString -Entity $Entity -Key $Key -Json $json
}

function Remove-PimSqlRow {
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][string]$Entity, [Parameter(Mandatory)][string]$Key)
    Invoke-PimSqlJournaledRowWrite -ConnectionString $ConnectionString -Entity $Entity -Key $Key -Remove
}

# --- SQL-backed change queue (mirrors the JSON adapter) -------------------------
function ConvertTo-PimSqlUtcDateTime {
    <#
      BUG-251 (§78 live GUI sweep, 2026-09-24): `[datetime]'2026-09-24T04:06:10Z'` converts to the MACHINE'S LOCAL time,
      and that local value was written into pim.ChangeQueue.EnqueuedUtc. In the hosted container local IS UTC, so it hid;
      a Manager or tool on a UTC+2 host stored every enqueue two hours ahead, and Pending changes then showed an entry
      "applied" two hours before it was requested. Always hand SQL a real UTC value:
        * a [datetime]: Local -> converted; Utc -> as is; Unspecified -> taken AS UTC (it came from a ...Utc column)
        * a string: parsed invariant, assumed UTC when it carries no offset, adjusted to UTC when it does
      Empty -> now (UTC), matching the old behaviour of an enqueue without a timestamp.
    #>
    param($Value)
    if ($null -eq $Value -or "$Value".Trim() -eq '') { return [datetime]::UtcNow }
    if ($Value -is [datetime]) {
        if ($Value.Kind -eq [DateTimeKind]::Local) { return $Value.ToUniversalTime() }
        return [datetime]::SpecifyKind($Value, [DateTimeKind]::Utc)
    }
    $styles = [Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal
    return [datetime]::Parse("$Value", [Globalization.CultureInfo]::InvariantCulture, $styles)
}

function Add-PimSqlQueueChange {
    # §65 -- carries Kind/Origin/Justification. Both dimensions default at the DDL level to
    # DesiredState/Proposal, so a caller built before §65 (or one that passes a bare change record)
    # enqueues exactly what it always did.
    # 🔒 Status is hard-coded 'pending'. There is deliberately NO way to enqueue something already
    # committed -- committing is an operator act on a stored row (§65.7), never a property of the
    # insert. A caller that could mint a committed entry would bypass the whole review surface.
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][object]$Change)
    $payload = if ($null -ne $Change.payload) { $Change.payload | ConvertTo-Json -Depth 12 -Compress } else { $null }
    $kind    = if ("$($Change.kind)".Trim())   { "$($Change.kind)" }   else { 'DesiredState' }
    $origin  = if ("$($Change.origin)".Trim()) { "$($Change.origin)" } else { 'Proposal' }
    $just    = if ("$($Change.justification)".Trim()) { "$($Change.justification)" } else { $null }
    $enq     = ConvertTo-PimSqlUtcDateTime $Change.enqueuedUtc
    [void](Invoke-PimSqlNonQuery -ConnectionString $ConnectionString -Sql @"
INSERT INTO pim.ChangeQueue (Id, Entity, [Key], Op, Payload, EnqueuedUtc, [By], Status, Kind, Origin, Justification)
VALUES (@id, @e, @k, @op, @p, @enq, @by, 'pending', @kind, @origin, @just);
"@ -Parameters @{ id = [guid]$Change.id; e = "$($Change.entity)"; k = "$($Change.key)"; op = "$($Change.op)"; p = $payload; enq = $enq; by = "$($Change.by)"; kind = $kind; origin = $origin; just = $just })
}

function Add-PimSqlQueueChangeIfAbsent {
    <#
      🔴 BUG-212 (§33.28) -- DE-DUPLICATED ENQUEUE. Discovery proposes the same items every day (discovery-entra
      runs daily with -GetLiveRoles and proposed ~130 Creates each run); only COMMITTED rows are drained, so every
      un-reviewed proposal was added again the next day and pending rows piled up. This inserts ONLY when no
      OPEN entry (pending / committed / applying / failed -- anything not applied or discarded) exists for the same
      Entity + Key + Op, in ONE statement (INSERT ... WHERE NOT EXISTS), so two runners cannot both insert it.
      Returns $true when a row was added, $false when an open duplicate already exists. THROWS on a store error.
    #>
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][object]$Change)
    $payload = if ($null -ne $Change.payload) { $Change.payload | ConvertTo-Json -Depth 12 -Compress } else { $null }
    $kind    = if ("$($Change.kind)".Trim())   { "$($Change.kind)" }   else { 'DesiredState' }
    $origin  = if ("$($Change.origin)".Trim()) { "$($Change.origin)" } else { 'Proposal' }
    $just    = if ("$($Change.justification)".Trim()) { "$($Change.justification)" } else { $null }
    $n = Invoke-PimSqlNonQuery -ConnectionString $ConnectionString -Sql @"
INSERT INTO pim.ChangeQueue (Id, Entity, [Key], Op, Payload, EnqueuedUtc, [By], Status, Kind, Origin, Justification)
SELECT @id, @e, @k, @op, @p, @enq, @by, 'pending', @kind, @origin, @just
WHERE NOT EXISTS (SELECT 1 FROM pim.ChangeQueue WITH (UPDLOCK, HOLDLOCK)
                  WHERE Entity=@e AND [Key]=@k AND Op=@op AND Status IN ('pending','committed','applying','failed'));
"@ -Parameters @{ id = [guid]$Change.id; e = "$($Change.entity)"; k = "$($Change.key)"; op = "$($Change.op)"; p = $payload; enq = (ConvertTo-PimSqlUtcDateTime $Change.enqueuedUtc); by = "$($Change.by)"; kind = $kind; origin = $origin; just = $just }
    return ([int]$n -gt 0)
}

function Add-PimSqlQueueChangeUnlessPending {
    <#
      §33.0a -- REVOKE DE-DUPE (operator 2026-10-07: three identical revokes were queued by three Delete clicks).
      Inserts the change ONLY when no PENDING entry exists for the same Entity + Key + Op, in ONE statement
      (INSERT ... WHERE NOT EXISTS under UPDLOCK/HOLDLOCK), so two admins clicking at once cannot both insert it.
      🔒 PENDING ONLY, deliberately narrower than Add-PimSqlQueueChangeIfAbsent: an entry that is already
      committed / applying / applied / failed is a decision (or an outcome) of its own, so a new revoke of the same
      target is a new request and is queued -- the de-dupe never hides a request behind an older one.
      Returns @{ added = $true|$false; existingId = '<id of the pending entry>' | '' }. THROWS on a store error.
    #>
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][object]$Change)
    $payload = if ($null -ne $Change.payload) { $Change.payload | ConvertTo-Json -Depth 12 -Compress } else { $null }
    $kind    = if ("$($Change.kind)".Trim())   { "$($Change.kind)" }   else { 'DesiredState' }
    $origin  = if ("$($Change.origin)".Trim()) { "$($Change.origin)" } else { 'Proposal' }
    $just    = if ("$($Change.justification)".Trim()) { "$($Change.justification)" } else { $null }
    $n = Invoke-PimSqlNonQuery -ConnectionString $ConnectionString -Sql @"
INSERT INTO pim.ChangeQueue (Id, Entity, [Key], Op, Payload, EnqueuedUtc, [By], Status, Kind, Origin, Justification)
SELECT @id, @e, @k, @op, @p, @enq, @by, 'pending', @kind, @origin, @just
WHERE NOT EXISTS (SELECT 1 FROM pim.ChangeQueue WITH (UPDLOCK, HOLDLOCK)
                  WHERE Entity=@e AND [Key]=@k AND Op=@op AND Status='pending');
"@ -Parameters @{ id = [guid]$Change.id; e = "$($Change.entity)"; k = "$($Change.key)"; op = "$($Change.op)"; p = $payload; enq = (ConvertTo-PimSqlUtcDateTime $Change.enqueuedUtc); by = "$($Change.by)"; kind = $kind; origin = $origin; just = $just }
    if ([int]$n -gt 0) { return [pscustomobject]@{ added = $true; existingId = '' } }
    $ex = @(Invoke-PimSqlQuery -ConnectionString $ConnectionString -Sql "SELECT TOP 1 Id FROM pim.ChangeQueue WHERE Entity=@e AND [Key]=@k AND Op=@op AND Status='pending' ORDER BY EnqueuedUtc" -Parameters @{ e = "$($Change.entity)"; k = "$($Change.key)"; op = "$($Change.op)" })
    return [pscustomobject]@{ added = $false; existingId = $(if ($ex.Count) { "$($ex[0].Id)" } else { '' }) }
}

function Set-PimSqlQueueCommitted {
    <#
      §65.7 -- COMMIT THE ENTRIES THE OPERATOR SELECTED. Per-id, never "everything pending".

      🔒 THE TRANSITION IS CONDITIONAL (`WHERE Id=@id AND Status='pending'`), which is what makes
      this safe with several admins working at once. Two people committing the same entry: the
      first moves it, the second's UPDATE affects 0 rows and is reported back as 'skipped' with the
      state it is actually in. The loser is TOLD, never silently ignored -- a commit that appears to
      succeed twice is how a revoke gets applied twice.

      Returns one record per requested id: @{ id; committed; state; reason }.
    #>
    param(
        [Parameter(Mandatory)][string]$ConnectionString,
        [Parameter(Mandatory)][string[]]$Ids,
        [Parameter(Mandatory)][string]$By
    )
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($raw in @($Ids)) {
        $id = "$raw".Trim()
        if (-not $id) { continue }
        $g = [guid]::Empty
        if (-not [guid]::TryParse($id, [ref]$g)) {
            $out.Add([pscustomobject]@{ id = $id; committed = $false; state = 'invalid'; reason = 'not a GUID' }); continue
        }
        $n = Invoke-PimSqlNonQuery -ConnectionString $ConnectionString -Sql @"
UPDATE pim.ChangeQueue
   SET Status='committed', CommittedBy=@by, CommittedUtc=SYSUTCDATETIME()
 WHERE Id=@id AND Status='pending';
"@ -Parameters @{ id = $g; by = "$By" }
        if ([int]$n -eq 1) {
            $out.Add([pscustomobject]@{ id = $id; committed = $true; state = 'committed'; reason = '' })
        } else {
            # Say WHAT it is now. "0 rows" alone cannot distinguish "already committed by a
            # colleague" from "this id does not exist", and those need different responses.
            $cur = @(Invoke-PimSqlQuery -ConnectionString $ConnectionString -Sql "SELECT Status FROM pim.ChangeQueue WHERE Id=@id" -Parameters @{ id = $g })
            $state = if ($cur.Count) { "$($cur[0].Status)" } else { 'missing' }
            $reason = if ($state -eq 'missing') { 'no such queue entry' } else { "already '$state' -- only a pending entry can be committed" }
            $out.Add([pscustomobject]@{ id = $id; committed = $false; state = $state; reason = $reason })
        }
    }
    return @($out.ToArray())
}

function Get-PimDesiredStateSignature {
    <#
      A CHEAP change-detector for one entity's desired state, used to invalidate the
      convergence-verification cache (Get-PimConvergenceScopePlan) without re-reading rows.

      COUNT(*) + MAX(UpdatedUtc) over pim.Rows for the entity: an insert or delete moves the
      count, any edit moves the timestamp (Set-PimSqlRow stamps UpdatedUtc=SYSUTCDATETIME() on
      both the MATCHED and NOT MATCHED branch). So any Manager commit touching this entity
      changes the signature and forces a fresh verification -- which is the property that makes
      caching safe: a newly-authored delegation is re-verified at once, not on a slow cycle.

      Returns '' when the signature cannot be read. 🪤 The CALLER MUST treat '' as "unknown, so
      verify" and never as "unchanged" -- reading an error as a negative result is the exact
      mistake that let BUG-134 hide.
    #>
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][string]$Entity)
    try {
        $r = @(Invoke-PimSqlQuery -ConnectionString $ConnectionString `
                -Sql "SELECT COUNT(*) AS N, MAX(UpdatedUtc) AS M FROM pim.Rows WHERE Entity=@e" `
                -Parameters @{ e = $Entity })
        if (-not $r.Count) { return '' }
        $n = "$($r[0].N)"
        $m = if ($null -ne $r[0].M -and "$($r[0].M)".Trim()) { ([datetime]$r[0].M).ToString('o') } else { 'none' }
        return "$Entity|$n|$m"
    } catch { return '' }
}

function Get-PimSqlQueue {
    <#
      §65.7 -- THIS IS THE SHARED REVIEW SURFACE, so it returns everything a reviewer needs to judge
      an entry: who enqueued it, why, who committed it, and what happened on the last attempt.
      -Status '' returns ALL states (the GUI's default view: a queue that hides its failures is not
      a review surface).
    #>
    param(
        [Parameter(Mandatory)][string]$ConnectionString,
        [string]$Status = 'pending',
        [ValidateSet('','DesiredState','Action')][string]$Kind = '',
        # 🔴 READ WHAT WILL BE LOOKED AT (operator, 2026-09-22: "loading queue is taking too long").
        # Every row carries its PAYLOAD -- for a configuration commit that is the whole row set it
        # wrote (one live queue held 151 discarded entries and a Services commit of 67 rows) -- and
        # the page was reading, parsing, describing and shipping all of it to render 36 rows.
        # -ExcludeStatus drops states nobody is looking at; -Limit keeps the NEWEST n.
        # Neither may be used to hide a failure: the caller still counts every state separately
        # (Get-PimSqlQueueCounts), so what is not read is still REPORTED.
        [string[]]$ExcludeStatus = @(),
        [int]$Limit = 0
    )
    $where = New-Object System.Collections.Generic.List[string]
    $p = @{}
    if ("$Status".Trim()) { $where.Add('Status=@s'); $p['s'] = $Status }
    if ("$Kind".Trim())   { $where.Add('Kind=@kd');  $p['kd'] = $Kind }
    $ex = @($ExcludeStatus | Where-Object { "$_".Trim() })
    if ($ex.Count) {
        $names = @()
        for ($i = 0; $i -lt $ex.Count; $i++) { $names += "@x$i"; $p["x$i"] = "$($ex[$i])" }
        $where.Add('Status NOT IN (' + ($names -join ',') + ')')
    }
    # The discard columns are ADDITIVE (2026-09-12). Select them only when the store has them, so an
    # engine/drain running against a store the Manager has not migrated yet keeps working unchanged.
    $hasDiscard = $false
    try {
        $colLen = Invoke-PimSqlScalar -ConnectionString $ConnectionString -Sql "SELECT COL_LENGTH('pim.ChangeQueue','DiscardedBy')"
        $hasDiscard = ($null -ne $colLen -and -not ($colLen -is [System.DBNull]) -and "$colLen".Trim() -ne '')
    } catch { $hasDiscard = $false }
    $discardCols = if ($hasDiscard) { ', DiscardedBy, DiscardedUtc, DiscardReason' } else { '' }
    $top = if ($Limit -gt 0) { "TOP ($([int]$Limit)) " } else { '' }
    $sql = "SELECT ${top}Id, Entity, [Key], Op, Payload, EnqueuedUtc, [By], Status, Kind, Origin, Justification, CommittedBy, CommittedUtc, Attempts, LastAttemptUtc, LastError, AppliedUtc, AppliedBy$discardCols FROM pim.ChangeQueue"
    if ($where.Count) { $sql += ' WHERE ' + ($where -join ' AND ') }
    # With a limit the NEWEST rows are the ones worth reading, so the cut is taken from the top and
    # the result is turned back into the ascending order every caller expects.
    $sql += $(if ($Limit -gt 0) { ' ORDER BY EnqueuedUtc DESC' } else { ' ORDER BY EnqueuedUtc' })
    $raw = Invoke-PimSqlQuery -ConnectionString $ConnectionString -Sql $sql -Parameters $p
    if ($Limit -gt 0) { $raw = @($raw) ; [array]::Reverse($raw) }
    $iso = { param($v) if ($null -ne $v -and "$v".Trim()) { ([datetime]$v).ToString('o') } else { '' } }
    return @($raw | ForEach-Object {
        [pscustomobject]@{ id = "$($_.Id)"; entity = "$($_.Entity)"; key = "$($_.Key)"; op = "$($_.Op)"
            payload = $(if ("$($_.Payload)".Trim()) { $_.Payload | ConvertFrom-Json } else { $null })
            enqueuedUtc = (& $iso $_.EnqueuedUtc); by = "$($_.By)"; status = "$($_.Status)"
            kind = "$($_.Kind)"; origin = "$($_.Origin)"; justification = "$($_.Justification)"
            committedBy = "$($_.CommittedBy)"; committedUtc = (& $iso $_.CommittedUtc)
            attempts = [int]"$(if ($null -ne $_.Attempts) { $_.Attempts } else { 0 })"
            lastAttemptUtc = (& $iso $_.LastAttemptUtc); lastError = "$($_.LastError)"
            appliedUtc = (& $iso $_.AppliedUtc); appliedBy = "$($_.AppliedBy)"
            discardedBy = $(if ($hasDiscard) { "$($_.DiscardedBy)" } else { '' })
            discardedUtc = $(if ($hasDiscard) { (& $iso $_.DiscardedUtc) } else { '' })
            discardReason = $(if ($hasDiscard) { "$($_.DiscardReason)" } else { '' }) }
    })
}

function Get-PimSqlQueueCounts {
    <#
      How many entries are in each state, as ONE aggregate -- no payloads, no rows.
      The queue list may legitimately read a subset (see -ExcludeStatus / -Limit on Get-PimSqlQueue),
      and this is what keeps the page HONEST about what it is not showing: "151 discarded hidden" is
      a fact read from the store, not a count of rows that happened to be fetched.
      Returns @{ pending = n; applied = n; ... } -- states with no rows are simply absent.
    #>
    param([Parameter(Mandatory)][string]$ConnectionString)
    $out = @{}
    $raw = Invoke-PimSqlQuery -ConnectionString $ConnectionString -Sql 'SELECT Status, COUNT(*) AS N FROM pim.ChangeQueue GROUP BY Status'
    foreach ($r in @($raw)) {
        $s = "$($r.Status)".Trim()
        if ($s) { $out[$s] = [int]"$($r.N)" }
    }
    return $out
}

function Set-PimSqlQueueDiscarded {
    <#
      DISCARD selected queue entries (2026-09-12). Operator: a failed test row "cannot be removed".

      🔒 ONLY 'pending' OR 'failed' may be discarded -- never 'committed', 'applying' or 'applied'.
      A committed entry is authorised work the drain may claim at any moment, and an applying or
      applied one has (or is having) a real directory effect; hiding those would falsify the record.
      The transition is CONDITIONAL in SQL (`WHERE Status IN ('pending','failed')`) so a drain that
      claims the row first wins, and the loser is TOLD the state it is really in.

      🔒 THE ROW IS KEPT (section 65.8 retains history): Status='discarded' + DiscardedBy/Utc/Reason.
      The drain only ever claims Status='committed', so a discarded entry can never be applied.

      Returns one record per id: @{ id; discarded; state; reason }.
    #>
    param(
        [Parameter(Mandatory)][string]$ConnectionString,
        [Parameter(Mandatory)][string[]]$Ids,
        [Parameter(Mandatory)][string]$By,
        [Parameter(Mandatory)][string]$Reason
    )
    if (-not "$Reason".Trim()) { throw 'a discard needs a reason' }
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($raw in @($Ids)) {
        $id = "$raw".Trim()
        if (-not $id) { continue }
        $g = [guid]::Empty
        if (-not [guid]::TryParse($id, [ref]$g)) {
            $out.Add([pscustomobject]@{ id = $id; discarded = $false; state = 'invalid'; reason = 'not a GUID' }); continue
        }
        $n = Invoke-PimSqlNonQuery -ConnectionString $ConnectionString -Sql @"
UPDATE pim.ChangeQueue
   SET Status='discarded', DiscardedBy=@by, DiscardedUtc=SYSUTCDATETIME(), DiscardReason=@r
 WHERE Id=@id AND Status IN ('pending','failed');
"@ -Parameters @{ id = $g; by = "$By"; r = "$Reason" }
        if ([int]$n -eq 1) {
            $out.Add([pscustomobject]@{ id = $id; discarded = $true; state = 'discarded'; reason = '' })
        } else {
            $cur = @(Invoke-PimSqlQuery -ConnectionString $ConnectionString -Sql "SELECT Status FROM pim.ChangeQueue WHERE Id=@id" -Parameters @{ id = $g })
            $state = if ($cur.Count) { "$($cur[0].Status)" } else { 'missing' }
            $why = if ($state -eq 'missing') { 'no such queue entry' } else { "'$state' -- only a pending or failed entry can be discarded" }
            $out.Add([pscustomobject]@{ id = $id; discarded = $false; state = $state; reason = $why })
        }
    }
    return @($out.ToArray())
}

# --- the drain: apply COMMITTED desired-state entries to pim.Rows ----------------
function Invoke-PimSqlCommit {
    <#
      🔴 BUG-152 -- REWRITTEN. The previous version ended with:

          UPDATE pim.ChangeQueue SET Status='applied' WHERE Status='pending'

      Unbounded by id, so it marked every row that was pending AT THE END OF THE DRAIN -- not the
      rows it planned. Three defects, all of which §65.8 forbids:
        1. THE READ->UPDATE RACE. Anything enqueued while the loop ran was marked applied without
           ever being applied. Silent loss, and the slower the drain the wider the window.
        2. NO TRANSACTION. The pim.Rows write and the status change were separate statements.
        3. NO PER-ENTRY OUTCOME, so a failure could not be attributed -- and therefore not retried.
      It never damaged a customer only because nothing called it (BUG-135).

      🔑 ONLY 'committed' ENTRIES ARE DRAINED. 'pending' means nobody has selected it yet, which is
      what preserves BUG-135's "propose-don't-auto-map": a discovery proposal sits here forever
      until an operator commits it.

      🪤 PER-ENTRY, NOT NET-FOLDED -- a DELIBERATE trade. Get-PimQueueApplyPlan folds several
      changes on one (entity,key) into a single net op, which is faster but destroys attribution:
      if three entries fold into one write and it fails, no entry can be marked failed and none can
      be retried. §65.8 requires per-entry outcome, so entries are applied in order instead. The
      final state is identical (Create-then-Update applied in sequence == the folded result).

      -MaxAttempts: after this many failed attempts an entry becomes 'failed' -- RETAINED and
      surfaced, never deleted. Without a cap a permanently-broken entry retries every tick forever
      and stays invisible.
      -FailAfter: TEST SEAM ONLY (mirrors Set-PimSqlEntityRowsTransactional) -- throw after N
      applies to prove the per-entry transaction rolls back and the entry stays retryable.
    #>
    param(
        [Parameter(Mandatory)][string]$ConnectionString,
        [int]$MaxAttempts = 3,
        [string]$AppliedBy = '',
        [int]$FailAfter = -1
    )
    $committed = @(Get-PimSqlQueue -ConnectionString $ConnectionString -Status 'committed' -Kind 'DesiredState')
    if ($committed.Count -eq 0) {
        return [pscustomobject]@{ applied = 0; failed = 0; retrying = 0; rowsAffected = 0; results = @() }
    }
    # Definitions before assignments, then enqueue order -- the same ordering the fold used, so a
    # binding is never applied before the thing it references.
    $ordered = @($committed | Sort-Object { Get-PimEntityOrderRank $_.entity }, { "$($_.enqueuedUtc)" })

    $who = if ("$AppliedBy".Trim()) { "$AppliedBy" } else { "$env:COMPUTERNAME" }
    $results = New-Object System.Collections.Generic.List[object]
    $applied = 0; $failedN = 0; $retrying = 0; $affected = 0; $done = 0; $unrecorded = 0

    foreach ($ch in $ordered) {
        $id = [guid]"$($ch.id)"
        $err = ''
        $c = New-PimSqlConnection -ConnectionString $ConnectionString
        $tx = $null
        try {
            $c.Open()
            $tx = $c.BeginTransaction()
            $exec = {
                param($sql, $params)
                $cmd = $c.CreateCommand(); $cmd.Transaction = $tx; $cmd.CommandText = $sql
                foreach ($k in $params.Keys) { [void]$cmd.Parameters.AddWithValue("@$k", $(if ($null -eq $params[$k]) { [DBNull]::Value } else { $params[$k] })) }
                return $cmd.ExecuteNonQuery()
            }
            # 🔒 THE EFFECT AND THE STATUS CHANGE ARE ONE TRANSACTION (§65.8). A crash between them
            # leaves the entry 'committed' and therefore replayed -- never applied-but-not-done.
            # CONFIG-1.1: the journal row joins that transaction; the entry's id is its commit id, its submitter and committer
            # are the initiator and approver.
            $qCtx = New-PimCommitJournalContext -CommitId "$($ch.id)".Replace('-', '') -Source 'queue' `
                        -InitiatedBy $(if ("$($ch.by)".Trim()) { "$($ch.by)" } else { $who }) `
                        -ApprovedBy $(if ("$($ch.committedBy)".Trim() -and "$($ch.committedBy)" -ne "$($ch.by)") { "$($ch.committedBy)" } else { '' })
            $qBefore = Get-PimRowJsonTx -Connection $c -Transaction $tx -Entity "$($ch.entity)" -Key "$($ch.key)"
            if ("$($ch.op)" -eq 'Remove') {
                [void](& $exec "DELETE FROM pim.Rows WHERE Entity=@e AND [Key]=@k" @{ e = "$($ch.entity)"; k = "$($ch.key)" })
                if ($null -ne $qBefore) { Add-PimCommitJournalRowTx -Connection $c -Transaction $tx -Entity "$($ch.entity)" -Key "$($ch.key)" -Op Remove -BeforeJson $qBefore -AfterJson $null -Context $qCtx }
            } else {
                $json = if ($null -ne $ch.payload) { $ch.payload | ConvertTo-Json -Depth 12 -Compress } else { '{}' }
                [void](& $exec @"
MERGE pim.Rows AS t USING (SELECT @e AS Entity, @k AS [Key]) AS s
  ON t.Entity = s.Entity AND t.[Key] = s.[Key]
WHEN MATCHED THEN UPDATE SET DataJson = @d, UpdatedUtc = SYSUTCDATETIME()
WHEN NOT MATCHED THEN INSERT (Entity, [Key], DataJson, UpdatedUtc) VALUES (@e, @k, @d, SYSUTCDATETIME());
"@ @{ e = "$($ch.entity)"; k = "$($ch.key)"; d = $json })
                if ($null -eq $qBefore) { Add-PimCommitJournalRowTx -Connection $c -Transaction $tx -Entity "$($ch.entity)" -Key "$($ch.key)" -Op Add -BeforeJson $null -AfterJson $json -Context $qCtx }
                elseif (-not [string]::Equals($qBefore, $json, [StringComparison]::Ordinal)) { Add-PimCommitJournalRowTx -Connection $c -Transaction $tx -Entity "$($ch.entity)" -Key "$($ch.key)" -Op Modify -BeforeJson $qBefore -AfterJson $json -Context $qCtx }
            }
            $done++
            if ($FailAfter -ge 0 -and $done -gt $FailAfter) { throw "FailAfter=$FailAfter test seam" }

            # Conditional on Status='committed' so a concurrent drain cannot apply the same entry
            # twice -- the second one's UPDATE affects 0 rows and it rolls back.
            $n = & $exec @"
UPDATE pim.ChangeQueue
   SET Status='applied', AppliedUtc=SYSUTCDATETIME(), AppliedBy=@who,
       Attempts=Attempts+1, LastAttemptUtc=SYSUTCDATETIME(), LastError=NULL
 WHERE Id=@id AND Status='committed';
"@ @{ id = $id; who = $who }
            if ([int]$n -ne 1) { throw "entry was claimed by another drain (status changed under us)" }
            $tx.Commit(); $tx = $null
            $applied++; $affected++
            $results.Add([pscustomobject]@{ id = "$($ch.id)"; entity = "$($ch.entity)"; key = "$($ch.key)"; outcome = 'applied'; error = '' })
        } catch {
            $err = "$($_.Exception.Message)"
            if ($tx) { try { $tx.Rollback() } catch { } }
        } finally {
            if ($c) { $c.Close(); $c.Dispose() }
        }

        if ($err) {
            # The row write rolled back, so record the ATTEMPT separately. An entry that has burnt
            # its attempts becomes 'failed' and is kept; anything else returns to 'committed' and is
            # retried on the next tick (§65.8 -- "goes into the queue again").
            $attempts = [int]$ch.attempts + 1
            $next = if ($attempts -ge $MaxAttempts) { 'failed' } else { 'committed' }
            # 🔴 THIS BOOKKEEPING WRITE IS NOT OPTIONAL, AND ITS FAILURE IS NOT COSMETIC.
            # It was first written as `try { ... } catch { }` -- and Test-PimCodeAudit's
            # SWALLOWED-MUTATION class caught it, correctly: if this UPDATE fails, the entry keeps
            # its OLD attempt count and NO error text, so it retries forever with nothing on it
            # explaining why. A drain that reports 'retrying' while failing to record the attempt is
            # the same "a failed write reports success" shape this whole chapter exists to remove.
            $bookkept = $false
            $bookErr = ''
            try {
                [void](Invoke-PimSqlNonQuery -ConnectionString $ConnectionString -Sql @"
UPDATE pim.ChangeQueue
   SET Status=@st, Attempts=@n, LastAttemptUtc=SYSUTCDATETIME(), LastError=@e
 WHERE Id=@id;
"@ -Parameters @{ st = $next; n = $attempts; e = $err; id = $id })
                $bookkept = $true
            } catch {
                $bookErr = "$($_.Exception.Message)"
            }
            if (-not $bookkept) {
                # Counted separately: the action did not apply AND its state could not be recorded,
                # so the caller must not read this as a clean retry.
                $unrecorded++
                $results.Add([pscustomobject]@{ id = "$($ch.id)"; entity = "$($ch.entity)"; key = "$($ch.key)"
                    outcome = 'unrecorded'
                    error = "$err -- AND the queue state could not be updated: $bookErr" })
                continue
            }
            if ($next -eq 'failed') { $failedN++ } else { $retrying++ }
            $results.Add([pscustomobject]@{ id = "$($ch.id)"; entity = "$($ch.entity)"; key = "$($ch.key)"; outcome = $next; error = $err })
        }
    }

    return [pscustomobject]@{ applied = $applied; failed = $failedN; retrying = $retrying
        unrecorded = $unrecorded; rowsAffected = $affected; results = @($results.ToArray()) }
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
        # 🔴 2.4.462 (demo on internal 2026-09-29): a department GROUP row carries BOTH its business department (Department =
        # FINANCE) and its own GroupTag (DEPT-deptsimon). Keyed on Department, a NEW group of an existing department took the
        # key of that department's owner row -> "duplicate store key" -> the definition save was refused (400) AFTER the
        # assignments naming it had been written. One department can own several DEPT- groups: a row with a GroupTag is
        # keyed on the tag; an owner row (no tag) on the department name.
        'PIM-Definitions-Departments'    {
            $d = (& $g 'GroupTag')
            if (-not "$d".Trim()) { $d = (& $g 'Department') }
            if (-not "$d".Trim()) { $d = (& $g 'DepartmentName') }
            if (-not "$d".Trim()) { $d = (& $g 'GroupName') }
            $d; break
        }
        'PIM-Definitions-*'              { (& $g 'GroupTag') }
        'Account-Definitions-Admins'     { (& $g 'UserName') }
        # 68.6 row 35: central admins imported from a managing tenant (PIM-Downlink.ps1 Invoke-PimDownlinkAdminApply).
        'Account-Definitions-Admins-Central' { (& $g 'UserName') }
        # §82 consultant lifecycle: an external company, keyed on its name. Deliberately NOT a PIM-Definitions-* entity --
        # every PIM-Definitions-* base is treated as an Entra GROUP definition (template packs, cutover, policy catalog).
        'Account-Definitions-Companies'  { (& $g 'Company'); break }
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
        # 2026-09-21 (operator: "assign permanent ga to ..."): a DIRECT Entra role row names a user, not a group, so it
        # fell through to 'default' (GroupTag / GroupName), got a BLANK key and was dropped on every save. Keyed like the
        # engine's Get-PimDirectRoleKey: the user, the role and the assignment type.
        'PIM-Assignments-Roles-Direct'   {
            $u = (& $g 'UserPrincipalName'); if (-not "$u".Trim()) { $u = (& $g 'Username') }; if (-not "$u".Trim()) { $u = (& $g 'UserName') }
            $r = (& $g 'RoleDefinitionName'); if (-not "$r".Trim()) { $r = (& $g 'RoleName') }
            if (-not "$u".Trim() -or -not "$r".Trim()) { ''; break }
            ("$u".Trim() + '|' + "$r".Trim() + '|' + (& $g 'AssignmentType')); break
        }
        'PIM-Assignments-Roles-Groups'   { ((& $g 'GroupTag') + '|' + (& $g 'RoleDefinitionName')) }
        'PIM-Assignments-Roles-AUs'      { ((& $g 'GroupTag') + '|' + (& $g 'AdministrativeUnitTag') + '|' + (& $g 'RoleDefinitionName')) }
        'PIM-Assignments-Azure-Resources'{ ((& $g 'GroupTag') + '|' + (& $g 'AzScope') + '|' + (& $g 'AzScopePermission')) }
        default                          { $x = (& $g 'GroupTag'); if (-not "$x".Trim()) { $x = (& $g 'GroupName') }; $x }
    }
    $k = "$k".Trim()
    if ($k -eq '' -or $k -eq '|' -or $k -match '^\|+$') { return '' }
    return $k
}

function Get-PimDuplicateStoreKeys {
    # PURE (BUG-204, 2.4.371). The store keys that two or more of $Rows share for $Base. The full-set replace below
    # upserts row by row into a case-insensitive map, so rows that share a key COLLAPSE: the last one wins and the
    # others are silently dropped (a 2-role workload delegation kept only its last role -- the Workloads key is
    # GroupTag alone). Returns @( @{ key; count; rows = @(1-based positions) } ), empty when every key is unique.
    # Rows with no derivable key are not reported here (they are skipped by the store, a separate concern).
    param([Parameter(Mandatory)][string]$Base, [AllowEmptyCollection()][object[]]$Rows = @())
    $seen = @{}; $order = New-Object System.Collections.Generic.List[string]
    $i = 0
    foreach ($r in @($Rows)) {
        $i++
        if ($null -eq $r) { continue }
        $k = Get-PimStoreRowKey -Base $Base -Row $r
        if (-not $k) { continue }
        if (-not $seen.ContainsKey($k)) { $seen[$k] = New-Object System.Collections.Generic.List[int]; $order.Add($k) }
        $seen[$k].Add($i)
    }
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($k in $order) { if ($seen[$k].Count -gt 1) { $out.Add([pscustomobject]@{ key = $k; count = $seen[$k].Count; rows = @($seen[$k].ToArray()) }) } }
    return @($out.ToArray())
}

function Set-PimSqlEntityRows {
    # Full-set replace of an entity's rows (matches CSV file-write semantics):
    # upsert every submitted row by its natural key, delete current keys that are
    # no longer present. Returns @{ rowCount; removed }.
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][string]$Entity, [object[]]$Rows = @(), [string]$Base,
          [switch]$AllowEmpty)
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
    # 🔴 Same empty-set wipe as the transactional twin, and MORE dangerous here: there is no
    # transaction, so a refusal after the deletes had started could not be rolled back. Guard
    # BEFORE the delete loop. See the long note in Set-PimSqlEntityRowsTransactional.
    if (-not $submitted.Count -and $currentKeys.Count -and -not $AllowEmpty) {
        throw ("Set-PimSqlEntityRows: refusing to delete all $($currentKeys.Count) row(s) of '$Entity' " +
               'because NO rows were submitted -- that is almost always a failed upstream read. ' +
               'Pass -AllowEmpty if you genuinely mean to empty it.')
    }
    foreach ($ck in $currentKeys) { if (-not $submitted.ContainsKey($ck)) { Remove-PimSqlRow -ConnectionString $ConnectionString -Entity $Entity -Key $ck; $removed++ } }
    return @{ rowCount = $submitted.Count; removed = $removed }
}

# §97.1: rows per set-based statement batch. One batch is one round trip; the JSON it carries stays far below any limit.
$script:PimSqlRowBatchSize = 500

function Invoke-PimSqlEntityRowBatchTx {
    <#
      §97.1 -- SET-BASED row writes on the caller's connection + transaction. -Items, in order: @{ k; op = Add|Modify|Remove;
      d = the row JSON (Add/Modify); b = the stored JSON it replaces (Modify/Remove) }. Each batch of <= $script:PimSqlRowBatchSize
      items is ONE statement batch (one round trip): the upserts (MERGE), the deletes, and one journal row per item in
      the given order (CONFIG-1.1: the same rows Add-PimCommitJournalRowTx wrote one by one, with the per-key initiator /
      approver of the ambient journal context). Returns the number of batches sent. Throws on failure (the caller's
      transaction then rolls back). -FailAfter: test seam -- throw once that many items have been written.
    #>
    param([Parameter(Mandatory)][object]$Connection, [AllowNull()][object]$Transaction, [Parameter(Mandatory)][string]$Entity,
          [AllowEmptyCollection()][object[]]$Items = @(), [int]$FailAfter = -1)
    $sql = @'
SET NOCOUNT ON;
DECLARE @in TABLE (o INT NOT NULL, k NVARCHAR(400) COLLATE DATABASE_DEFAULT NOT NULL, op NVARCHAR(10) NOT NULL, d NVARCHAR(MAX) NULL,
                   b NVARCHAR(MAX) NULL, i NVARCHAR(200) NOT NULL, a NVARCHAR(200) NULL);
INSERT INTO @in (o, k, op, d, b, i, a)
SELECT o, k, op, d, b, i, a FROM OPENJSON(@j) WITH (o INT '$.o', k NVARCHAR(400) '$.k', op NVARCHAR(10) '$.op', d NVARCHAR(MAX) '$.d',
                                                   b NVARCHAR(MAX) '$.b', i NVARCHAR(200) '$.i', a NVARCHAR(200) '$.a');
MERGE pim.Rows WITH (HOLDLOCK) AS t
USING (SELECT k, d FROM @in WHERE op <> 'Remove') AS s ON t.Entity = @e AND t.[Key] = s.k
WHEN MATCHED THEN UPDATE SET DataJson = s.d, UpdatedUtc = SYSUTCDATETIME()
WHEN NOT MATCHED THEN INSERT (Entity, [Key], DataJson, UpdatedUtc) VALUES (@e, s.k, s.d, SYSUTCDATETIME());
DELETE t FROM pim.Rows AS t JOIN @in AS x ON t.Entity = @e AND t.[Key] = x.k WHERE x.op = 'Remove';
INSERT INTO pim.CommitJournal (CommitId, Entity, [Key], Op, BeforeJson, AfterJson, InitiatedBy, ApprovedBy, Source, UndoOf)
SELECT @jc, @e, k, op, b, CASE WHEN op = 'Remove' THEN NULL ELSE d END, i, a, @js, @ju FROM @in ORDER BY o;
'@
    $all = @($Items | Where-Object { $null -ne $_ })
    if (-not $all.Count) { return 0 }
    $ctx = Get-PimCommitJournalContext
    $size = [Math]::Max(1, [int]$script:PimSqlRowBatchSize)
    $batches = 0; $done = 0
    for ($at = 0; $at -lt $all.Count; $at += $size) {
        $chunk = @($all[$at..([Math]::Min($all.Count, $at + $size) - 1)])
        $payload = New-Object System.Collections.Generic.List[object]
        $o = 0
        foreach ($x in $chunk) {
            $who = Resolve-PimCommitJournalActor -Context $ctx -Key "$($x.k)"
            $payload.Add([ordered]@{
                o = $o; k = "$($x.k)"; op = "$($x.op)"
                d = $(if ("$($x.d)" -ne '') { "$($x.d)" } else { $null })
                b = $(if ("$($x.b)" -ne '') { "$($x.b)" } else { $null })
                i = $(if ("$($who.initiatedBy)".Trim()) { "$($who.initiatedBy)" } else { 'system' })
                a = $(if ("$($who.approvedBy)".Trim()) { "$($who.approvedBy)" } else { $null })
            })
            $o++
        }
        $cmd = $Connection.CreateCommand(); if ($Transaction) { $cmd.Transaction = $Transaction }
        $cmd.CommandText = $sql
        try { $cmd.CommandTimeout = 180 } catch { }
        $p = [ordered]@{ e = $Entity; j = (ConvertTo-Json -InputObject @($payload.ToArray()) -Depth 3 -Compress)
                         jc = "$($ctx.commitId)"; js = "$($ctx.source)"; ju = $(if ("$($ctx.undoOf)".Trim()) { "$($ctx.undoOf)" } else { $null }) }
        foreach ($k in $p.Keys) { [void]$cmd.Parameters.AddWithValue("@$k", $(if ($null -eq $p[$k]) { [DBNull]::Value } else { $p[$k] })) }
        [void]$cmd.ExecuteNonQuery()
        $batches++; $done += $chunk.Count
        if ($FailAfter -ge 0 -and $done -ge $FailAfter) { throw "injected mid-commit failure after $done statement(s) (test seam)" }
    }
    return $batches
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
        [int]$FailAfter = -1,
        # 🔴 See the empty-set guard below. Deliberately clearing an entity is legitimate; doing it
        # BY ACCIDENT is a production data wipe, and the two look identical from in here.
        [switch]$AllowEmpty
    )
    $base = if ("$Base".Trim()) { $Base } else { $Entity }
    $c = New-PimSqlConnection -ConnectionString $ConnectionString
    $tx = $null
    try {
        $c.Open()
        $tx = $c.BeginTransaction()
        $stmts = 0

        # §97.1: the round trips this replace made (SqlConnection statistics; a fake connection has none -> -1).
        $statsErr = ''; try { $c.StatisticsEnabled = $true } catch { $statsErr = "$($_.Exception.Message)" }

        # 1) read current keys AND their stored JSON (inside the tx for a consistent snapshot).
        $curCmd = $c.CreateCommand(); $curCmd.Transaction = $tx
        $curCmd.CommandText = "SELECT [Key], DataJson FROM pim.Rows WHERE Entity=@e"
        [void]$curCmd.Parameters.AddWithValue('@e', $Entity)
        $rd = $curCmd.ExecuteReader(); $currentKeys = New-Object System.Collections.Generic.List[string]
        # The key match is case-insensitive, like pim.Rows' own key (and the $submitted map below): a submitted 'A' IS the
        # stored 'a' -- an update, journaled as a Modify of that row (never an Add plus a kept duplicate).
        $currentJson = New-Object 'System.Collections.Generic.Dictionary[string,string]' ([StringComparer]::OrdinalIgnoreCase)
        while ($rd.Read()) { $ck0 = "$($rd.GetValue(0))"; $currentKeys.Add($ck0); $dj = $rd.GetValue(1); $currentJson[$ck0] = $(if ($null -eq $dj -or $dj -is [DBNull]) { '' } else { "$dj" }) }
        $rd.Close()

        # 2) the submitted rows that CHANGED -- planned here, written SET-BASED below.
        # §88 (operator 2026-10-02: "why is the commit so slow into the sql"): this used to MERGE EVERY submitted row --
        # the Manager submits the whole entity, so one changed admin on internal (659 rows) was 659 round trips to Azure
        # SQL inside the commit. A row whose JSON is byte-identical to what is stored is skipped: same data, and its
        # UpdatedUtc stays honest (the change detector still sees the rows that did change).
        # 🔴 §97.1 (EFIF 2026-10-08, 168 template rows, 132 s): every CHANGED row was still TWO round trips (its MERGE +
        # its journal INSERT) inside the transaction. The plan is now built in memory and written in ONE statement batch
        # per <= $script:PimSqlRowBatchSize rows (Invoke-PimSqlEntityRowBatchTx): same rows, same journal rows, same
        # single transaction, a constant number of round trips. Two rows with one key: the LAST wins (as before).
        $submitted = @{}; $written = 0
        $plan = New-Object 'System.Collections.Specialized.OrderedDictionary' ([StringComparer]::OrdinalIgnoreCase)
        foreach ($r in @($Rows)) {
            $k = Get-PimStoreRowKey -Base $base -Row $r
            if (-not $k) { continue }
            $submitted[$k] = $true
            $json = if ($null -ne $r) { $r | ConvertTo-Json -Depth 12 -Compress } else { '{}' }
            if ($currentJson.ContainsKey($k) -and [string]::Equals($currentJson[$k], $json, [StringComparison]::Ordinal)) { if ($plan.Contains($k)) { $plan.Remove($k) }; continue }
            # CONFIG-1.1: every written row gets its journal row in the same transaction (a failure rolls the whole set back).
            $item = [ordered]@{ k = $k; op = $(if ($currentJson.ContainsKey($k)) { 'Modify' } else { 'Add' }); d = $json; b = $(if ($currentJson.ContainsKey($k)) { $currentJson[$k] } else { $null }) }
            if ($plan.Contains($k)) { $plan[$k] = $item } else { $plan.Add($k, $item) }
        }
        $written = $plan.Count

        # 🔴 AN EMPTY SUBMISSION AGAINST A NON-EMPTY ENTITY IS A WIPE, AND IT ARRIVES BY ACCIDENT.
        # -Rows defaults to @(). This is a FULL-SET REPLACE, so "no rows submitted" means "delete
        # every row of this entity" -- and it would do so transactionally, then return
        # @{ rowCount = 0; removed = <all of them> } as a SUCCESS.
        # 🪤 The way that happens is never someone typing "delete everything": it is an upstream
        # read that failed and returned nothing (a Graph throttle, an empty CSV, a caught exception
        # yielding @()). Set-PimManagerAccess.ps1 already carries this exact lesson for the access
        # model -- "A read failure is FATAL, never 'nothing was stored'" -- but the general row
        # store, which holds every assignment and definition in the product, had no such guard.
        # 🔒 So: submitting NOTHING while the store holds SOMETHING is refused unless the caller
        # says it means it. Rolls back, changes nothing, and names the entity. (R8: "dont delete
        # sql ... this is production".)
        if (-not $submitted.Count -and $currentKeys.Count -and -not $AllowEmpty) {
            throw ("Set-PimSqlEntityRowsTransactional: refusing to delete all $($currentKeys.Count) row(s) of " +
                   "'$Entity' because NO rows were submitted. A full-set replace with an empty set is " +
                   "almost always a failed upstream read, not an intent to clear the entity. " +
                   'Pass -AllowEmpty if you genuinely mean to empty it.')
        }
        # 3) delete dropped keys (after the upserts, journaled in that order -- as before).
        $removed = 0
        $items = New-Object System.Collections.Generic.List[object]
        foreach ($v in $plan.Values) { $items.Add($v) }
        foreach ($ck in $currentKeys) {
            if (-not $submitted.ContainsKey($ck)) { $items.Add([ordered]@{ k = $ck; op = 'Remove'; d = $null; b = $currentJson[$ck] }); $removed++ }
        }
        $batches = Invoke-PimSqlEntityRowBatchTx -Connection $c -Transaction $tx -Entity $Entity -Items @($items.ToArray()) -FailAfter $FailAfter

        $tx.Commit()
        $rt = -1; $rtWhy = ''
        try {
            $st = $c.RetrieveStatistics()
            $rtv = $null; foreach ($sk in @($st.Keys)) { if ("$sk" -eq 'ServerRoundtrips') { $rtv = $st[$sk] } }
            if ($null -ne $rtv) { $rt = [int]$rtv } else { $rtWhy = "no ServerRoundtrips in the statistics ($(@($st.Keys) -join ','))" }
        } catch { $rt = -1; $rtWhy = "$($_.Exception.Message)" }
        if ($statsErr) { $rtWhy = "statistics could not be enabled: $statsErr; $rtWhy" }
        # commands = statements sent on this connection after the open: the read + one per batch (+ begin/commit by the driver)
        return @{ rowCount = $submitted.Count; removed = $removed; written = $written; batches = [int]$batches; commands = 1 + [int]$batches; roundTrips = $rt; roundTripsNote = $rtWhy }
    } catch {
        if ($tx) { try { $tx.Rollback() } catch { Write-Warning "  [sql] transaction rollback failed: $($_.Exception.Message)" } }
        throw
    } finally {
        # 🔴 §52.18 -- DISPOSE, NOT JUST CLOSE. `Close()` returns the connection to the pool;
        # `Dispose()` is what releases it deterministically instead of waiting for a finalizer.
        # Across this file there were 8 opens, 6 closes and ZERO disposes, so a run that threw --
        # or simply ran long -- accumulated sessions. Measured at a live customer 2026-09-09: a
        # CSV import died halfway with "The session limit for the database is 300 and has been
        # reached" on a Basic-tier database, after that morning's deploys, the Manager and the
        # tick job had each left sessions behind.
        if ($c) { $c.Close(); $c.Dispose() }
    }
}

# --- UPSERT-ONLY: add or update by key, NEVER delete (REQ-G) --------------------
# The full-set replace above is right for a grid save (the grid IS the whole set). An IMPORT is not the whole
# set: a row the Manager added after go-live is not in the file, and must survive. These three are the store's
# upsert-only path, so an importer does not have to carry a private MERGE of its own (Migrate-PimToSql did).

function Compare-PimSqlRowContent {
    # PURE. Does row A say exactly what row B says? Every column of either side is compared as text (a column one
    # side lacks reads as blank), so a value the store holds that the new row does not carry is a DIFFERENCE --
    # overwriting would drop it. pwsh 7's ConvertFrom-Json turns an ISO date into a [datetime]; the two are equal
    # when they are the same instant. A dictionary is compared by its keys, like an object's properties.
    # Returns @() when equal, else @( @{ column; file; store } ) ('file' = -FileRow, 'store' = -StoreRow).
    # (The algorithm Migrate-PimToSql's REQ-G import compared rows with; it moved here with the upsert.)
    param([Parameter(Mandatory)][object]$FileRow, [Parameter(Mandatory)][object]$StoreRow)
    if ($FileRow -is [System.Collections.IDictionary]) { $FileRow = [pscustomobject]$FileRow }
    if ($StoreRow -is [System.Collections.IDictionary]) { $StoreRow = [pscustomobject]$StoreRow }
    $names = [ordered]@{}
    foreach ($p in @($FileRow.PSObject.Properties) + @($StoreRow.PSObject.Properties)) { if (-not $names.Contains($p.Name.ToLowerInvariant())) { $names[$p.Name.ToLowerInvariant()] = $p.Name } }
    $diff = New-Object System.Collections.Generic.List[object]
    foreach ($n in @($names.Values)) {
        $a = $FileRow.PSObject.Properties[$n]; $b = $StoreRow.PSObject.Properties[$n]
        $av = if ($a -and $null -ne $a.Value) { $a.Value } else { '' }
        $bv = if ($b -and $null -ne $b.Value) { $b.Value } else { '' }
        if ($bv -is [datetime] -or $av -is [datetime]) {
            $ad = $av; $bd = $bv
            try { if ($ad -isnot [datetime]) { $ad = [datetime]::Parse("$ad", [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind) } } catch { $ad = $null }
            try { if ($bd -isnot [datetime]) { $bd = [datetime]::Parse("$bd", [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind) } } catch { $bd = $null }
            if ($null -ne $ad -and $null -ne $bd -and $ad.ToUniversalTime() -eq $bd.ToUniversalTime()) { continue }
        }
        if ("$av" -cne "$bv") { $diff.Add([ordered]@{ column = $n; file = "$av"; store = "$bv" }) | Out-Null }
    }
    return @($diff.ToArray())
}

function Get-PimSqlMergePlan {
    <#
      PURE. What an upsert-only write of -Rows / -Items would do to an entity that already holds -Existing.
        -Rows      rows, keyed by Get-PimStoreRowKey -Base (a row with no derivable key is skipped + counted)
        -Items     @( @{ key; row } ), already keyed by the caller (used instead of -Rows when given)
        -Existing  @( @{ key; row } ), the entity's stored rows (row = parsed DataJson)
      Keys match case-insensitively; two submitted rows with one key COLLAPSE to the last (counted), as the store
      itself would keep them. Per key:
        not stored                        -> add
        stored, same content              -> unchanged (not written)
        stored, DIFFERENT content         -> a key CONFLICT, decided by -OnKeyConflict:
                                             Overwrite -> update (written under the STORED key's spelling)
                                             KeepExisting -> kept (the store's row stays)
                                             Refuse -> listed in conflicts; Merge-PimSqlEntityRows then writes NOTHING
      Nothing is ever planned for a stored key that was not submitted: there is no delete in this plan.
      Returns @{ add; update; unchanged; kept; conflicts; skippedNoKey; collapsed } (lists of @{ key; row [; columns] }).
    #>
    param(
        [string]$Base,
        [AllowEmptyCollection()][object[]]$Rows = @(),
        [AllowEmptyCollection()][object[]]$Items,
        [AllowEmptyCollection()][object[]]$Existing = @(),
        [ValidateSet('Refuse','KeepExisting','Overwrite')][string]$OnKeyConflict = 'Overwrite'
    )
    $skippedNoKey = 0
    $sub = [ordered]@{}; $nSub = 0
    if ($PSBoundParameters.ContainsKey('Items')) {
        foreach ($it in @($Items)) {
            if ($null -eq $it) { continue }
            $k = "$($it.key)".Trim()
            if (-not $k) { $skippedNoKey++; continue }
            $sub[$k.ToLowerInvariant()] = @{ key = "$($it.key)"; row = $it.row }; $nSub++
        }
    } else {
        if (-not "$Base".Trim()) { throw 'Get-PimSqlMergePlan: -Base is required to key -Rows (or pass -Items already keyed).' }
        foreach ($r in @($Rows)) {
            if ($null -eq $r) { continue }
            $k = Get-PimStoreRowKey -Base $Base -Row $r
            if (-not $k) { $skippedNoKey++; continue }
            $sub[$k.ToLowerInvariant()] = @{ key = $k; row = $r }; $nSub++
        }
    }
    $have = @{}
    foreach ($e in @($Existing)) { if ($null -ne $e -and "$($e.key)") { $have["$($e.key)".ToLowerInvariant()] = $e } }
    $add = New-Object System.Collections.Generic.List[object]; $upd = New-Object System.Collections.Generic.List[object]
    $same = New-Object System.Collections.Generic.List[object]; $kept = New-Object System.Collections.Generic.List[object]
    $conf = New-Object System.Collections.Generic.List[object]
    foreach ($lk in @($sub.Keys)) {
        $s = $sub[$lk]
        if (-not $have.ContainsKey($lk)) { $add.Add(@{ key = $s.key; row = $s.row }) | Out-Null; continue }
        $cur = $have[$lk]
        $rowObj = if ($null -ne $s.row) { $s.row } else { [pscustomobject]@{} }
        $curObj = if ($null -ne $cur.row) { $cur.row } else { [pscustomobject]@{} }
        $d = @(Compare-PimSqlRowContent -FileRow $rowObj -StoreRow $curObj)
        if (-not $d.Count) { $same.Add(@{ key = "$($cur.key)"; row = $s.row }) | Out-Null; continue }
        $one = @{ key = "$($cur.key)"; row = $s.row; columns = $d }
        switch ($OnKeyConflict) {
            'Overwrite'    { $upd.Add($one) | Out-Null }
            'KeepExisting' { $kept.Add($one) | Out-Null }
            default        { $conf.Add($one) | Out-Null }
        }
    }
    return @{
        add = @($add.ToArray()); update = @($upd.ToArray()); unchanged = @($same.ToArray()); kept = @($kept.ToArray())
        conflicts = @($conf.ToArray()); skippedNoKey = $skippedNoKey; collapsed = ($nSub - $sub.Count)
    }
}

function Merge-PimSqlEntityRows {
    <#
      UPSERT-ONLY, TRANSACTIONAL write of an entity's rows (REQ-G) -- Set-PimSqlEntityRowsTransactional WITHOUT
      its delete half. A stored key that is not submitted is NEVER touched, so an import cannot remove a row the
      Manager added after go-live, and there is no empty-set guard to need: submitting nothing changes nothing.
      ONE connection, ONE transaction per entity (§52.18b: one session per entity, not per row): the stored rows
      are read inside the transaction (UPDLOCK, HOLDLOCK -- nobody changes them between the compare and the
      write), classified by Get-PimSqlMergePlan, and the adds + updates are MERGEd -- the same statement the
      replace uses. A failure rolls the entity back whole.
        -OnKeyConflict  a submitted key the store already holds with DIFFERENT content:
                          Overwrite (default -- a plain upsert) = the submitted row wins;
                          KeepExisting = the store's row stays, counted as kept;
                          Refuse = THROW and roll back: nothing of this entity is written, and the keys are named.
      Returns @{ submitted; added; updated; unchanged; kept; skippedNoKey; collapsed; conflicts }.
      -FailAfter: TEST SEAM ONLY (as in the replace) -- throw after N writes to prove the rollback.
    #>
    param(
        [Parameter(Mandatory)][string]$ConnectionString,
        [Parameter(Mandatory)][string]$Entity,
        [AllowEmptyCollection()][object[]]$Rows = @(),
        [AllowEmptyCollection()][object[]]$Items,
        [string]$Base,
        [ValidateSet('Refuse','KeepExisting','Overwrite')][string]$OnKeyConflict = 'Overwrite',
        [int]$FailAfter = -1
    )
    $base = if ("$Base".Trim()) { $Base } else { $Entity }
    $hasItems = $PSBoundParameters.ContainsKey('Items')
    $nIn = if ($hasItems) { @($Items | Where-Object { $null -ne $_ }).Count } else { @($Rows | Where-Object { $null -ne $_ }).Count }
    if (-not $nIn) { return @{ submitted = 0; added = 0; updated = 0; unchanged = 0; kept = 0; skippedNoKey = 0; collapsed = 0; conflicts = @() } }
    $c = New-PimSqlConnection -ConnectionString $ConnectionString
    $tx = $null
    try {
        $c.Open()
        $tx = $c.BeginTransaction()
        $curCmd = $c.CreateCommand(); $curCmd.Transaction = $tx
        $curCmd.CommandText = "SELECT [Key], DataJson FROM pim.Rows WITH (UPDLOCK, HOLDLOCK) WHERE Entity=@e"
        [void]$curCmd.Parameters.AddWithValue('@e', $Entity)
        $rd = $curCmd.ExecuteReader(); $raw = New-Object System.Collections.Generic.List[object]
        try { while ($rd.Read()) { $raw.Add(@{ key = "$($rd.GetValue(0))"; json = $(if ($rd.IsDBNull(1)) { '' } else { "$($rd.GetValue(1))" }) }) } } finally { $rd.Close() }
        # parsed AFTER the reader is closed (one connection = one open reader); a row that will not parse THROWS --
        # an unreadable stored row is not "different", and must not be overwritten on a guess
        $existing = @($raw.ToArray() | ForEach-Object { @{ key = $_.key; row = $(if ("$($_.json)".Trim()) { $_.json | ConvertFrom-Json } else { [pscustomobject]@{} }) } })
        $planArgs = @{ Base = $base; Existing = $existing; OnKeyConflict = $OnKeyConflict }
        if ($hasItems) { $planArgs['Items'] = @($Items) } else { $planArgs['Rows'] = @($Rows) }
        $plan = Get-PimSqlMergePlan @planArgs
        if (@($plan.conflicts).Count) {
            $names = @($plan.conflicts | Select-Object -First 5 | ForEach-Object { "'$($_.key)' ($(@($_.columns | ForEach-Object { $_.column }) -join ', '))" }) -join '; '
            throw ("Merge-PimSqlEntityRows: {0} key conflict(s) in '{1}' -- the store holds these keys with DIFFERENT content: {2}{3}. -OnKeyConflict Refuse: NOTHING of this entity was written." -f `
                   @($plan.conflicts).Count, $Entity, $names, $(if (@($plan.conflicts).Count -gt 5) { ' ...' } else { '' }))
        }
        $mergeSql = @"
MERGE pim.Rows AS t USING (SELECT @e AS Entity, @k AS [Key]) AS s
  ON t.Entity = s.Entity AND t.[Key] = s.[Key]
WHEN MATCHED THEN UPDATE SET DataJson = @d, UpdatedUtc = SYSUTCDATETIME()
WHEN NOT MATCHED THEN INSERT (Entity, [Key], DataJson, UpdatedUtc) VALUES (@e, @k, @d, SYSUTCDATETIME());
"@
        $n = 0
        $beforeByKey = @{}; foreach ($x in $raw) { $beforeByKey["$($x.key)"] = "$($x.json)" }
        foreach ($it in @($plan.add) + @($plan.update)) {
            $cmd = $c.CreateCommand(); $cmd.Transaction = $tx; $cmd.CommandText = $mergeSql
            $d = if ($null -ne $it.row) { $it.row | ConvertTo-Json -Depth 12 -Compress } else { '{}' }
            [void]$cmd.Parameters.AddWithValue('@e', $Entity)
            [void]$cmd.Parameters.AddWithValue('@k', "$($it.key)")
            [void]$cmd.Parameters.AddWithValue('@d', $d)
            [void]$cmd.ExecuteNonQuery()
            # CONFIG-1.1: journaled in the same transaction.
            if ($beforeByKey.ContainsKey("$($it.key)")) { Add-PimCommitJournalRowTx -Connection $c -Transaction $tx -Entity $Entity -Key "$($it.key)" -Op Modify -BeforeJson $beforeByKey["$($it.key)"] -AfterJson $d }
            else { Add-PimCommitJournalRowTx -Connection $c -Transaction $tx -Entity $Entity -Key "$($it.key)" -Op Add -BeforeJson $null -AfterJson $d }
            $n++
            if ($FailAfter -ge 0 -and $n -ge $FailAfter) { throw "injected mid-commit failure after $n statement(s) (test seam)" }
        }
        $tx.Commit()
        return @{
            submitted = (@($plan.add).Count + @($plan.update).Count + @($plan.unchanged).Count + @($plan.kept).Count)
            added = @($plan.add).Count; updated = @($plan.update).Count; unchanged = @($plan.unchanged).Count; kept = @($plan.kept).Count
            skippedNoKey = [int]$plan.skippedNoKey; collapsed = [int]$plan.collapsed; conflicts = @()
        }
    } catch {
        if ($tx) { try { $tx.Rollback() } catch { Write-Warning "  [sql] transaction rollback failed: $($_.Exception.Message)" } }
        throw
    } finally {
        if ($c) { $c.Close(); $c.Dispose() }
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
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][string]$Name, [object]$Value,
          # IMP-39: the value ALREADY serialised. `$Value | ConvertTo-Json` UNROLLS an array through the
          # pipeline, so a one-element list was stored as a bare string and an empty list as NULL -- a
          # value that must be a JSON ARRAY (pim.Settings['BreakGlassAccounts']) needs the exact text.
          [string]$ValueJson)
    $json = if ($PSBoundParameters.ContainsKey('ValueJson')) { $ValueJson }
            elseif ($null -ne $Value) { $Value | ConvertTo-Json -Depth 12 -Compress } else { $null }
    # 🔴 §70.8 (2026-09-13) -- WRITE ONLY WHAT CHANGED. Every save rewrote the whole value, changed or not.
    # On internal's Basic database the transaction log write rate is capped, and this MERGE averaged 5.9 s
    # (max 8 s, 396 runs in ~12 h; LOG_RATE_GOVERNOR the top wait at 2,152 s) -- mostly JobRunHistory
    # (1.98 MB) plus values such as the 145 KB AzResPolicyMassHold re-saved unchanged every tick.
    # The compare is BYTE-exact (varbinary): the database collation is case-insensitive and ignores trailing
    # spaces, so a plain `<>` would silently skip a real change. An unchanged save now writes no log and does
    # not bump UpdatedUtc (so it also stops looking like a change to anything polling pim.Settings).
    [void](Invoke-PimSqlNonQuery -ConnectionString $ConnectionString -Sql @"
MERGE pim.Settings AS t USING (SELECT @n AS Name, @v AS V) AS s ON t.Name = s.Name
WHEN MATCHED AND (   (t.ValueJson IS NULL AND s.V IS NOT NULL)
                  OR (t.ValueJson IS NOT NULL AND s.V IS NULL)
                  OR CAST(t.ValueJson AS VARBINARY(MAX)) <> CAST(s.V AS VARBINARY(MAX)))
    THEN UPDATE SET ValueJson=s.V, UpdatedUtc=SYSUTCDATETIME()
WHEN NOT MATCHED THEN INSERT (Name, ValueJson, UpdatedUtc) VALUES (@n, @v, SYSUTCDATETIME());
"@ -Parameters @{ n = $Name; v = $json })
}

# --- audit trail in SQL (SEC-16 / §36.2) ----------------------------------------
# APPEND-ONLY by intent. There is deliberately no update or delete helper here: the value of an
# audit trail is that it cannot be tidied, and the easiest way to keep a capability from being
# used by accident is not to write it. Retention is a policy decision for §36.3, not an ad-hoc
# DELETE somebody reaches for at 2am.
function Write-PimSqlAuditEvent {
    param(
        [Parameter(Mandatory)][string]$ConnectionString,
        [Parameter(Mandatory)][string]$Actor,
        [Parameter(Mandatory)][string]$Action,
        [Parameter(Mandatory)][string]$Target,
        [string]$ActorSource = '',
        [string]$RunId = '',
        [string]$CorrelationId = '',
        [object]$Before = $null,
        [object]$After = $null,
        [string]$Result = 'ok',
        [bool]$WhatIf = $false,
        # §36.3 phase 1b -- an IMPORT of the retired file trail must keep each event's ORIGINAL
        # time. Left unbound, Ts stays on its DF_PimAudit_Ts default (SYSUTCDATETIME()), which is
        # what every live write wants; binding it to "now" for an import would stamp the whole
        # imported history with the minute somebody ran the importer and destroy the ordering
        # that makes the trail evidence. Only the importer passes this.
        [datetime]$Ts
    )
    $b = if ($null -ne $Before) { $Before | ConvertTo-Json -Depth 8 -Compress } else { $null }
    $a = if ($null -ne $After)  { $After  | ConvertTo-Json -Depth 8 -Compress } else { $null }
    $cols = 'RunId, CorrelationId, Actor, ActorSource, Action, Target, BeforeJson, AfterJson, Result, WhatIf'
    $vals = '@run, @corr, @actor, @asrc, @action, @target, @before, @after, @result, @whatif'
    $p = @{
        run = $RunId; corr = $CorrelationId; actor = $Actor; asrc = $ActorSource
        action = $Action; target = $Target; before = $b; after = $a
        result = $Result; whatif = [int][bool]$WhatIf
    }
    if ($PSBoundParameters.ContainsKey('Ts')) {
        $cols = 'Ts, ' + $cols; $vals = '@ts, ' + $vals; $p['ts'] = $Ts.ToUniversalTime()
    }
    [void](Invoke-PimSqlNonQuery -ConnectionString $ConnectionString -Sql @"
INSERT INTO pim.AuditEvents ($cols)
VALUES ($vals);
"@ -Parameters $p)
}

function Get-PimSqlAuditEvents {
    <#
      Read the trail newest-first, shaped EXACTLY like the jsonl reader's records so
      Select-PimAuditEvents / Get-PimAuditChangeSummary keep working unchanged -- the point of
      moving the store is not to rewrite the query layer.
    #>
    param(
        [Parameter(Mandatory)][string]$ConnectionString,
        [datetime]$FromUtc, [datetime]$ToUtc,
        [int]$Top = 5000,
        # BUG-264: -Actions narrows to exact action names IN SQL (the commit page asks for config saves only); -NoPayload
        # leaves BeforeJson/AfterJson unread and unparsed (the Audit tab fills them for the page it shows, by `id`).
        [string[]]$Actions,
        [switch]$NoPayload
    )
    $where = @(); $p = @{}
    if ($PSBoundParameters.ContainsKey('FromUtc')) { $where += 'Ts >= @f'; $p['f'] = $FromUtc }
    if ($PSBoundParameters.ContainsKey('ToUtc'))   { $where += 'Ts <= @t'; $p['t'] = $ToUtc }
    $acts = @(@($Actions) | Where-Object { "$_".Trim() } | ForEach-Object { "$_".Trim() } | Select-Object -Unique)
    if ($acts.Count) {
        $names = for ($i = 0; $i -lt $acts.Count; $i++) { $p["a$i"] = $acts[$i]; "@a$i" }
        $where += ('Action IN (' + (@($names) -join ',') + ')')
    }
    $w = if ($where.Count) { 'WHERE ' + ($where -join ' AND ') } else { '' }
    if ($Top -lt 1) { $Top = 1 }
    $payloadCols = if ($NoPayload) { '' } else { ', BeforeJson, AfterJson' }
    $rows = @(Invoke-PimSqlQuery -ConnectionString $ConnectionString -Sql @"
SELECT TOP ($Top) Id, Ts, RunId, CorrelationId, Actor, ActorSource, Action, Target$payloadCols, Result, WhatIf
FROM pim.AuditEvents $w ORDER BY Ts DESC, Id DESC;
"@ -Parameters $p)
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($r in $rows) {
        $before = $null; $after = $null
        if (-not $NoPayload) {
            if ("$($r.BeforeJson)".Trim()) { try { $before = $r.BeforeJson | ConvertFrom-Json } catch { $before = "$($r.BeforeJson)" } }
            if ("$($r.AfterJson)".Trim())  { try { $after  = $r.AfterJson  | ConvertFrom-Json } catch { $after  = "$($r.AfterJson)" } }
        }
        $out.Add([pscustomobject]@{
            id = "$($r.Id)"
            # Ts is stored UTC (SYSUTCDATETIME) but comes back Kind=Unspecified, which
            # ToUniversalTime() treats as LOCAL -- shifting every event by the host's offset.
            ts = [datetime]::SpecifyKind([datetime]$r.Ts, [System.DateTimeKind]::Utc).ToString('o')
            runId = "$($r.RunId)"; correlationId = "$($r.CorrelationId)"
            actor = "$($r.Actor)"; actorSource = "$($r.ActorSource)"
            action = "$($r.Action)"; target = "$($r.Target)"
            before = $before; after = $after
            result = "$($r.Result)"; whatIf = [bool]$r.WhatIf
        })
        # -NoPayload: no before/after AT ALL (not $null) -- "not read" must not look like "recorded as empty"
        if ($NoPayload) { $o = $out[$out.Count - 1]; [void]$o.PSObject.Properties.Remove('before'); [void]$o.PSObject.Properties.Remove('after') }
    }
    # 🪤 `.ToArray()`, NOT `@($out)`. Wrapping a System.Collections.Generic.List[object] in @()
    # throws "Argument types do not match" on BOTH Windows PowerShell 5.1 and pwsh 7, empty or
    # not (an ArrayList is unaffected). Measured 2026-08-31.
    # 🔑 CORRECTED 2026-09-12 -- this note used to say "and even for a list of plain strings",
    # which is FALSE and would send a reader to rewrite correct code. Re-measured on both hosts:
    # List[object] throws; List[string], List[int], List[psobject] and List[hashtable] do not.
    # It is the declared ELEMENT TYPE that decides, never the contents -- a List[object] holding
    # only strings still throws, and a List[string] never does.
    # 🪤 The same note also claimed "nothing else in this solution hits it". It has since been hit
    # TWICE more (/api/approvals and /api/admin-accounts, the latter a live 500 that took out the
    # whole Admin accounts screen), which is why the guard is now mechanical:
    # tests/Test-PimListWrapTrap.ps1 scans every shipped script.
    return $out.ToArray()
}

function Read-PimSqlAuditEventPayloads {
    <#
      BUG-264 -- the other half of Get-PimSqlAuditEvents -NoPayload: read BeforeJson/AfterJson for just these events (by
      their `id`) and set .before / .after on them, parsed exactly as the full read parses them. One query per call.
    #>
    param([Parameter(Mandatory)][string]$ConnectionString, [object[]]$Events = @())
    $byId = @{}
    foreach ($e in @($Events)) { if ($null -ne $e -and "$($e.id)" -match '^\d+$') { $byId["$($e.id)"] = $e } }
    if ($byId.Count -eq 0) { return }
    $p = @{}; $i = 0
    $names = foreach ($k in @($byId.Keys)) { $p["i$i"] = [long]$k; "@i$i"; $i++ }
    $rows = @(Invoke-PimSqlQuery -ConnectionString $ConnectionString -Sql ("SELECT Id, BeforeJson, AfterJson FROM pim.AuditEvents WHERE Id IN (" + (@($names) -join ',') + ");") -Parameters $p)
    foreach ($r in $rows) {
        $e = $byId["$($r.Id)"]; if ($null -eq $e) { continue }
        $before = $null; $after = $null
        if ("$($r.BeforeJson)".Trim()) { try { $before = $r.BeforeJson | ConvertFrom-Json } catch { $before = "$($r.BeforeJson)" } }
        if ("$($r.AfterJson)".Trim())  { try { $after  = $r.AfterJson  | ConvertFrom-Json } catch { $after  = "$($r.AfterJson)" } }
        $e | Add-Member -NotePropertyName before -NotePropertyValue $before -Force
        $e | Add-Member -NotePropertyName after -NotePropertyValue $after -Force
    }
}

function Get-PimSqlAuditMonthCount {
    <#
      How many distinct calendar months the trail spans. The file-based reader answered this by
      counting monthly FILES; with SQL there are no files, and "0 months of history" would make
      the Audit tab's window selector claim the trail is empty when it is not.
    #>
    param([Parameter(Mandatory)][string]$ConnectionString)
    $n = Invoke-PimSqlScalar -ConnectionString $ConnectionString -Sql @"
SELECT COUNT(*) FROM (SELECT DISTINCT YEAR(Ts) AS y, MONTH(Ts) AS m FROM pim.AuditEvents) AS x;
"@
    $i = 0; [void][int]::TryParse("$n", [ref]$i)
    return $i
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
    # 🔴 REQ-T (2.4.377): THE TENANT'S OWN NAMING NEVER REACHED THE ENGINE. The Settings page stores every naming key
    # (PimGroupPattern, AdminAccountPattern, AdminAccountUpnSuffix, …) as ONE record, pim.Settings['NamingConventions'],
    # and the loop above put that record under the key 'NamingConventions' -- where Get-PimNamingConvention, which reads
    # flat keys, never looks. So every engine-side name (discovery auto-create, hybrid AD, the admin UPN domain) used the
    # SHIPPED defaults whatever the customer had configured. The Manager flattens the same record
    # (Get-PimManagerNamingSettings); the engine now does too. A key stored as its own setting row still wins.
    $nc = $loaded['NamingConventions']
    if ($nc) {
        $pairs = if ($nc -is [System.Collections.IDictionary]) { @($nc.Keys | ForEach-Object { @{ k = "$_"; v = $nc[$_] } }) }
                 else { @($nc.PSObject.Properties | ForEach-Object { @{ k = $_.Name; v = $_.Value } }) }
        foreach ($p in $pairs) { if ($p.k -and -not $loaded.ContainsKey($p.k)) { $global:PIM_NamingConventions[$p.k] = $p.v } }
    }
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
    # MAIL-1 (framework 12.3): the TRANSPORT -- MailMode (none | sharedMailbox | smtp) and the SmtpRelay record (no
    # password: that lives in Key Vault). Same fail-safe direction as the sender: only a valid, non-blank value writes.
    if ($global:PIM_NamingConventions.ContainsKey('MailMode') -and (Get-Command ConvertTo-PimMailMode -ErrorAction SilentlyContinue)) {
        $__mode = ConvertTo-PimMailMode -Value $global:PIM_NamingConventions['MailMode']
        if ($__mode) { $global:PIM_MailMode = $__mode }
    }
    if ($global:PIM_NamingConventions.ContainsKey('SmtpRelay') -and $null -ne $global:PIM_NamingConventions['SmtpRelay']) {
        $global:PIM_SmtpRelay = $global:PIM_NamingConventions['SmtpRelay']
    }
    return $n
}

# AUDIT-1.3: the append-only guard + the retention job ride with the store, so every loader of the store has them.
$__auditRet = Join-Path $PSScriptRoot 'PIM-AuditRetention.ps1'
if (Test-Path -LiteralPath $__auditRet) { . $__auditRet }
# AUDIT-1 actor: the change attribution rides with the store too.
$__chgAttr = Join-Path $PSScriptRoot 'PIM-ChangeAttribution.ps1'
if (Test-Path -LiteralPath $__chgAttr) { . $__chgAttr }
# SEC-80: the managed-key ledger rides with the store too.
$__mgdKeys = Join-Path $PSScriptRoot 'PIM-ManagedKeys.ps1'
if (Test-Path -LiteralPath $__mgdKeys) { . $__mgdKeys }
# CONFIG-1.1: the change journal is written BY the store's write functions, so it must ride with the store.
$__cmtJrn = Join-Path $PSScriptRoot 'PIM-CommitJournal.ps1'
if (Test-Path -LiteralPath $__cmtJrn) { . $__cmtJrn }
# PIM 96.5: the daily reconcile's removal report + pause / resume ride with the store (the scheduler, the engine and the
# Manager all read them).
$__rcnRem = Join-Path $PSScriptRoot 'PIM-ReconcileRemoval.ps1'
if (Test-Path -LiteralPath $__rcnRem) { . $__rcnRem }
# CONFIG-1.3 / PIM §96.3: the configuration backup (pim.ConfigBackups) rides with the store too.
$__cfgBak = Join-Path $PSScriptRoot 'PIM-ConfigBackup.ps1'
if (Test-Path -LiteralPath $__cfgBak) { . $__cfgBak }
# CR8 item 1 (PIM 100.152): the commit snapshot table's DDL rides with the store, so the updater's schema step creates it.
if (-not (Get-Command Initialize-PimBackupStore -ErrorAction SilentlyContinue)) { $__cmtBak = Join-Path $PSScriptRoot 'PIM-CommitBackup.ps1'; if (Test-Path -LiteralPath $__cmtBak) { . $__cmtBak } }
# Framework §12.23 run 2 (PIM 100.156): the publish job's control-view refresh rides with the store, so the updater's schema
# step runs it (it was run by the Manager at every start -- a CREATE OR ALTER VIEW the web app may not run after run 2).
if (-not (Get-Command Get-PimPublishJobControlViewRefreshSql -ErrorAction SilentlyContinue)) { $__jobCad = Join-Path $PSScriptRoot 'PIM-JobCadence.ps1'; if (Test-Path -LiteralPath $__jobCad) { . $__jobCad } }
# Framework §12.23 / PIM 100.156: the activation ledger's DDL rides with the store, so the updater's schema step creates it.
if (-not (Get-Command Get-PimImpactActivationLedgerDdl -ErrorAction SilentlyContinue)) { $__impCnt = Join-Path $PSScriptRoot 'PIM-ImpactCounters.ps1'; if (Test-Path -LiteralPath $__impCnt) { . $__impCnt } }
# PIM 100.121: the feature-setting reader rides with the store -- it reads what Import-PimSettingsFromStore hydrates, so
# every process that can hold a stored setting (the engine, the scheduler, the Manager) has the reader for it.
$__featSet = Join-Path $PSScriptRoot 'PIM-FeatureSettings.ps1'
if (Test-Path -LiteralPath $__featSet) { . $__featSet }
