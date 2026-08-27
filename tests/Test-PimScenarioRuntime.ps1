#Requires -Version 5.1
<#
.SYNOPSIS
    §31.3 RUNTIME RESOLUTION wiring (the remaining ◻ items): the three pure scenario
    resolvers (hosting store / SPN model / sync-file staging root) for all six
    scenarios, the Get-PimSqlConnectionString hosting thread (default unchanged), and
    the Settings "Deployment scenario" card (GET/PUT /api/settings/scenario) round-trip
    + static GUI/server wiring.

.DESCRIPTION
    All OFFLINE (no live tenant, no az, no SQL, no server boot). Layers:

      1. PURE RESOLVERS over the REAL shared lib (engine/_shared/PIM-ScenarioProfile.ps1):
         Resolve-PimScenarioHostingStore (central-msp -> central Azure SQL; local-slave ->
         local SQL; in-tenant -> ambient/no override), Resolve-PimScenarioSpnAuth
         (multi-tenant-spn -> managed tenant; local-spn -> ambient), and
         Resolve-PimScenarioSyncRoot (central-msp/local-slave roots from env; none -> no stage)
         across all six scenarios, plus env-default + missing-input behaviour.

      2. HOSTING THREAD into Get-PimSqlConnectionString (real PIM-SqlStore.ps1): a S6
         active scenario + a local server env picks that server; default behaviour is
         IDENTICAL when no scenario is set (regression guard).

      3. GUI -> STORE -> READ round-trip through the REAL Manager wrappers
         (Get-/Set-PimScenarioConfig extracted from Open-PimManager.ps1) over the SAME
         Get-/Set-PimManagerSetting chain pim.Settings is read through: a saved scenario
         reads back identically; an unknown id is REJECTED (not silently stored).

      4. STATIC GUI / SERVER wiring (no dead view): the server dot-sources the scenario
         profile, routes GET/PUT /api/settings/scenario with a SuperAdmin gate on the
         write, and the Settings tab renders the Deployment scenario card + calls both
         endpoints.

    Run standalone (exits 0 green / 1 red) or via Run-AllPimTests.ps1 / PIM.Tests.ps1.
#>
[CmdletBinding()] param()

$ErrorActionPreference = 'Stop'
$pass = 0; $fail = 0
function T($n, $c) { if ($c) { Write-Host "  PASS $n" -ForegroundColor Green; $script:pass++ } else { Write-Host "  FAIL $n" -ForegroundColor Red; $script:fail++ } }

$root     = Split-Path -Parent $PSScriptRoot           # ...\PIM4EntraPS
$lib      = Join-Path $root 'engine\_shared\PIM-ScenarioProfile.ps1'
$sqlLib   = Join-Path $root 'engine\_shared\PIM-SqlStore.ps1'
$srvPath  = Join-Path $root 'tools\pim-manager\Open-PimManager.ps1'
$htmlPath = Join-Path $root 'tools\pim-manager\pim-manager.html'
T 'PIM-ScenarioProfile.ps1 present' (Test-Path -LiteralPath $lib)
T 'PIM-SqlStore.ps1 present'        (Test-Path -LiteralPath $sqlLib)
T 'Open-PimManager.ps1 present'     (Test-Path -LiteralPath $srvPath)
T 'pim-manager.html present'        (Test-Path -LiteralPath $htmlPath)
if ($fail) { Write-Host "`n RESULT: $pass pass, $fail fail" -ForegroundColor Red; exit 1 }

Set-StrictMode -Off
. $lib

# ===========================================================================
# Layer 1 -- PURE RESOLVERS (real shared lib), all six scenarios
# ===========================================================================
Write-Host "`n-- Layer 1: pure resolvers (hosting / SPN / sync-root) --" -ForegroundColor Cyan

# Expected per-scenario hosting kind/server + spn model + sync stage. Explicit roots
# are passed so the test does not depend on the box's environment variables.
$CENTRAL_SQL  = 'sql-central-msp.database.windows.net'
$LOCAL_SQL    = 'SLAVEHOST\SQLEXPRESS'
$MANAGED_TID  = '11111111-2222-3333-4444-555555555555'
$CENTRAL_ROOT = 'C:\msp\sync'
$LOCAL_ROOT   = 'C:\local\sync'

# --- HOSTING ---
$expHost = @(
    @{ id='S1'; src='in-tenant';   kind='ambient'; srv='' }
    @{ id='S2'; src='in-tenant';   kind='ambient'; srv='' }
    @{ id='S3'; src='in-tenant';   kind='ambient'; srv='' }
    @{ id='S4'; src='in-tenant';   kind='ambient'; srv='' }
    @{ id='S5'; src='central-msp'; kind='azure';   srv=$CENTRAL_SQL }
    @{ id='S6'; src='local-slave'; kind='local';   srv=$LOCAL_SQL }
)
foreach ($e in $expHost) {
    $h = Resolve-PimScenarioHostingStore -Scenario $e.id -CentralServer $CENTRAL_SQL -LocalServer $LOCAL_SQL
    T "$($e.id) hosting -> source=$($e.src) kind=$($e.kind) server='$($e.srv)'" (
        $h.source -eq $e.src -and $h.kind -eq $e.kind -and "$($h.server)" -eq $e.srv)
}
# in-tenant returns an EMPTY server so the ambient resolution wins (default unchanged).
T 'in-tenant (S1) hosting server is EMPTY (ambient override = none)' ("$((Resolve-PimScenarioHostingStore -Scenario 'S1').server)" -eq '')
# central-msp with NO central server supplied -> empty server (fall back to ambient), not a throw.
T 'central-msp with no central server -> empty server (fall back to ambient)' ("$((Resolve-PimScenarioHostingStore -Scenario 'S5' -CentralServer '').server)" -eq '')
# BUG-78: local-slave with NO local server -> EMPTY (fall back to ambient), exactly like
# central-msp above. This assertion used to demand '.\SQLEXPRESS' and called it "the safe
# default" -- it was neither safe nor a default: it OUTRANKED an explicitly configured
# PIM_SqlServer=<...>.database.windows.net, so a managed-tenant container silently connected to a
# SQL Express instance that does not exist in the image. The resulting Integrated-Security
# connection string also makes New-PimSqlConnection skip token acquisition, which is why the S6
# downlink produced no auth diagnostics at all and read as an identity problem for three rebuilds.
T 'local-slave with no local server -> empty server (fall back to ambient)' ("$((Resolve-PimScenarioHostingStore -Scenario 'S6' -LocalServer '').server)" -eq '')
T 'local-slave never invents a local instance that outranks ambient config' ((Resolve-PimScenarioHostingStore -Scenario 'S6' -LocalServer '').server -ne '.\SQLEXPRESS')
# An explicit AZURE local-slave server is reported as azure, not mislabelled local.
T 'local-slave with an Azure FQDN is kind=azure' ((Resolve-PimScenarioHostingStore -Scenario 'S6' -LocalServer 'sql-x.database.windows.net').kind -eq 'azure')

# --- SPN MODEL ---
foreach ($id in 'S1','S2','S3','S4','S6') {
    $a = Resolve-PimScenarioSpnAuth -Scenario $id -ManagedTenantId $MANAGED_TID
    T "$id spn -> local-spn, multiTenant=$false, no tenant override" ($a.spnModel -eq 'local-spn' -and -not $a.multiTenant -and "$($a.tenantId)" -eq '')
}
$a5 = Resolve-PimScenarioSpnAuth -Scenario 'S5' -ManagedTenantId $MANAGED_TID
T 'S5 spn -> multi-tenant-spn, multiTenant=$true, tenant=managed tenant' ($a5.spnModel -eq 'multi-tenant-spn' -and $a5.multiTenant -and "$($a5.tenantId)" -eq $MANAGED_TID)
# S5 with NO managed tenant id -> multiTenant=$true but empty tenant (fall back to ambient), not a throw.
$a5b = Resolve-PimScenarioSpnAuth -Scenario 'S5' -ManagedTenantId ''
T 'S5 spn with no managed tenant id -> multiTenant=$true, empty tenant (ambient)' ($a5b.multiTenant -and "$($a5b.tenantId)" -eq '')
# local-spn honours an explicit local tenant id.
T 'local-spn honours an explicit -LocalTenantId' ((Resolve-PimScenarioSpnAuth -Scenario 'S1' -LocalTenantId 'aaa').tenantId -eq 'aaa')

# --- SYNC-FILE ROOT ---
$expSync = @(
    @{ id='S1'; loc='none';        stage=$false; root='' }
    @{ id='S2'; loc='none';        stage=$false; root='' }
    @{ id='S3'; loc='central-msp'; stage=$true;  root=$CENTRAL_ROOT }
    @{ id='S4'; loc='central-msp'; stage=$true;  root=$CENTRAL_ROOT }
    @{ id='S5'; loc='central-msp'; stage=$true;  root=$CENTRAL_ROOT }
    @{ id='S6'; loc='local-slave'; stage=$true;  root=$LOCAL_ROOT }
)
foreach ($e in $expSync) {
    $s = Resolve-PimScenarioSyncRoot -Scenario $e.id -CentralRoot $CENTRAL_ROOT -LocalRoot $LOCAL_ROOT
    T "$($e.id) sync-root -> loc=$($e.loc) stage=$($e.stage) root='$($e.root)'" (
        $s.syncFileLocation -eq $e.loc -and [bool]$s.stage -eq $e.stage -and "$($s.root)" -eq $e.root)
}
# central-msp scenario but no root supplied -> stage=$true with an empty root + a helpful reason.
$snr = Resolve-PimScenarioSyncRoot -Scenario 'S5' -CentralRoot '' -LocalRoot ''
T 'central-msp with no root -> stage=$true, empty root, reason names the env var' ([bool]$snr.stage -and "$($snr.root)" -eq '' -and $snr.reason -match 'PIM_SyncRootCentral')
# env-var default path: set $env:PIM_SyncRootCentral and call WITHOUT -CentralRoot.
$old = $env:PIM_SyncRootCentral
try {
    $env:PIM_SyncRootCentral = 'C:\fromenv'
    T 'sync-root reads $env:PIM_SyncRootCentral when -CentralRoot omitted' ((Resolve-PimScenarioSyncRoot -Scenario 'S5').root -eq 'C:\fromenv')
} finally { $env:PIM_SyncRootCentral = $old }

# resolvers accept a descriptor object too (not only an id).
$descS5 = Get-PimScenario -Id 'S5'
T 'resolvers accept a descriptor object (not only an id)' (
    (Resolve-PimScenarioHostingStore -Scenario $descS5 -CentralServer $CENTRAL_SQL).source -eq 'central-msp' -and
    (Resolve-PimScenarioSpnAuth -Scenario $descS5 -ManagedTenantId $MANAGED_TID).multiTenant)

# ===========================================================================
# Layer 2 -- HOSTING THREAD into Get-PimSqlConnectionString (real lib)
# ===========================================================================
Write-Host "`n-- Layer 2: Get-PimSqlConnectionString hosting thread (default unchanged) --" -ForegroundColor Cyan
# Load the SQL store in a clean global state. Capture + restore the globals we touch.
$savedActive = $global:PIM_ActiveScenario
$savedServer = $global:PIM_SqlServer
$savedCs     = $global:PIM_SqlConnectionString
$savedSrvCentral = $env:PIM_SqlServerCentral
$savedSrvLocal   = $env:PIM_SqlServerLocal
try {
    $global:PIM_SqlConnectionString = $null
    . $sqlLib

    # 2a) NO scenario set -> behaviour is IDENTICAL to before (ambient default = .\SQLEXPRESS).
    $global:PIM_ActiveScenario = $null
    $global:PIM_SqlServer      = $null
    $env:PIM_SqlServerCentral  = $null
    $env:PIM_SqlServerLocal    = $null
    $csDefault = Get-PimSqlConnectionString -Database 'PimPlatform'
    T 'no scenario -> default ambient CS (.\SQLEXPRESS, Integrated)' ($csDefault -match 'Server=\.\\SQLEXPRESS;' -and $csDefault -match 'Integrated Security=SSPI')

    # 2b) explicit -Server still wins (highest precedence, untouched).
    T 'explicit -Server still wins over scenario' ((Get-PimSqlConnectionString -Server 'X\Y' -Database 'D') -match 'Server=X\\Y;')

    # 2b-BUG-30) explicit -Server naming AZURE SQL must produce the PASSWORDLESS token CS.
    # This is the assertion whose absence hid a 🔴: every existing explicit -Server test used a
    # LOCAL name (2b's 'X\Y', PIM.Features.Tests' 'localhost\SQLEXPRESS'), so nothing ever
    # passed an Azure FQDN through the one parameter all ~10 harnesses and PIM-SqlStore.ps1:217
    # actually use. It returned Integrated Security=SSPI -- unusable against PaaS, and it made
    # New-PimSqlConnection skip token acquisition altogether. Assert the NEGATIVE (no Integrated,
    # no TrustServerCertificate=True) as well as the positive, because the failure mode was a
    # connection string that looked perfectly well-formed.
    $csAz = Get-PimSqlConnectionString -Server 'sql-explicit.database.windows.net' -Database 'PimScenarioTest'
    T 'BUG-30: explicit -Server + Azure FQDN -> passwordless token CS (tcp:, port 1433)' (
        $csAz -match 'Server=tcp:sql-explicit\.database\.windows\.net,1433' -and $csAz -match 'Database=PimScenarioTest')
    T 'BUG-30: explicit -Server + Azure FQDN -> NO Integrated Security (PaaS has no Windows auth)' (
        $csAz -notmatch '(?i)Integrated\s*Security')
    T 'BUG-30: explicit -Server + Azure FQDN -> strict TLS (TrustServerCertificate=False)' (
        $csAz -match 'Encrypt=True' -and $csAz -match 'TrustServerCertificate=False')
    T 'BUG-30: the Azure FQDN test is case-insensitive' (
        (Get-PimSqlConnectionString -Server 'SQL-UPPER.DATABASE.WINDOWS.NET' -Database 'D') -notmatch '(?i)Integrated\s*Security')
    # And the regression guard in the other direction: a LOCAL explicit server is unchanged.
    T 'BUG-30: a local explicit -Server still gets the Integrated CS (unchanged)' (
        (Get-PimSqlConnectionString -Server 'localhost\SQLEXPRESS' -Database 'D') -match '(?i)Integrated Security=SSPI')

    # 2b-MI) Managed identity is PLAN A (operator 2026-08-08). The probe must be decidable
    # WITHOUT touching the network, so an offline suite never depends on IMDS being reachable.
    $savedNoMi = $global:PIM_NoManagedIdentity
    $savedUseMi = $global:PIM_UseManagedIdentity
    try {
        $global:PIM_NoManagedIdentity = $true;  $global:PIM_UseManagedIdentity = $null
        T 'MI plan A: $PIM_NoManagedIdentity forces the probe to NO (offline tests never hit IMDS)' (-not (Test-PimManagedIdentityAvailable))
        $global:PIM_NoManagedIdentity = $null;  $global:PIM_UseManagedIdentity = $true
        T 'MI plan A: $PIM_UseManagedIdentity forces the probe to YES without a network call' (Test-PimManagedIdentityAvailable)
    } finally { $global:PIM_NoManagedIdentity = $savedNoMi; $global:PIM_UseManagedIdentity = $savedUseMi }

    # 2c) S6 active + a local server env -> the connection string uses THAT server.
    $global:PIM_ActiveScenario = 'S6'
    $env:PIM_SqlServerLocal    = 'SLAVE\SQLEXPRESS'
    $csS6 = Get-PimSqlConnectionString -Database 'PimPlatform'
    T 'S6 active + local server env -> CS uses the local-slave server' ($csS6 -match 'Server=SLAVE\\SQLEXPRESS;')

    # 2d) S5 active + a central Azure SQL FQDN -> passwordless Azure CS (Encrypt=True, no Integrated).
    $global:PIM_ActiveScenario = 'S5'
    $env:PIM_SqlServerLocal    = $null
    $env:PIM_SqlServerCentral  = 'sql-central.database.windows.net'
    $csS5 = Get-PimSqlConnectionString -Database 'PimPlatform'
    T 'S5 active + central FQDN -> passwordless Azure CS (Encrypt=True, no Integrated)' ($csS5 -match 'Server=tcp:sql-central\.database\.windows\.net' -and $csS5 -match 'Encrypt=True' -and $csS5 -notmatch 'Integrated Security')

    # 2e) in-tenant scenario (S1) -> NO override; ambient default again.
    $global:PIM_ActiveScenario = 'S1'
    $env:PIM_SqlServerCentral  = $null
    $global:PIM_SqlServer      = $null
    $csS1 = Get-PimSqlConnectionString -Database 'PimPlatform'
    T 'S1 (in-tenant) active -> ambient default (no scenario override)' ($csS1 -match 'Server=\.\\SQLEXPRESS;')
} finally {
    $global:PIM_ActiveScenario      = $savedActive
    $global:PIM_SqlServer           = $savedServer
    $global:PIM_SqlConnectionString = $savedCs
    $env:PIM_SqlServerCentral       = $savedSrvCentral
    $env:PIM_SqlServerLocal         = $savedSrvLocal
}

# ===========================================================================
# Layer 3 -- GUI -> STORE -> READ round-trip through the REAL Manager wrappers
# ===========================================================================
Write-Host "`n-- Layer 3: GUI -> store -> read round-trip (real wrappers, in-proc) --" -ForegroundColor Cyan

function Get-FnBody([string]$source, [string]$name) {
    $pat = 'function ' + [regex]::Escape($name) + '\b[\s\S]*?\n\}\r?\n'
    $m = [regex]::Match($source, $pat)
    if (-not $m.Success) { return $null }
    return $m.Value
}
$srv = [System.IO.File]::ReadAllText($srvPath)
$getFn = Get-FnBody $srv 'Get-PimScenarioConfig'
$setFn = Get-FnBody $srv 'Set-PimScenarioConfig'
T 'Get-PimScenarioConfig body extracted' ([bool]$getFn)
T 'Set-PimScenarioConfig body extracted' ([bool]$setFn)

if ($getFn -and $setFn) {
    # In-memory store = the SAME Get-/Set-PimManagerSetting chain pim.Settings is read
    # through. Get-PimFeatureCatalogValue is the null-safe reader Set-PimScenarioConfig
    # uses; provide a minimal stand-in if the catalog lib isn't loaded.
    $script:__store = @{}
    function Get-PimManagerSetting { param([Parameter(Mandatory)][string]$Name) if ($script:__store.ContainsKey($Name)) { return $script:__store[$Name] } return $null }
    function Set-PimManagerSetting { param([Parameter(Mandatory)][string]$Name, [object]$Value) $script:__store[$Name] = $Value }
    if (-not (Get-Command Get-PimFeatureCatalogValue -ErrorAction SilentlyContinue)) {
        function Get-PimFeatureCatalogValue { param([object]$Object, [string]$Key) Get-PimScenarioValue -Object $Object -Key $Key }
    }

    $savedActive2 = $global:PIM_ActiveScenario
    try {
        $global:PIM_ActiveScenario = $null
        Invoke-Expression $getFn
        Invoke-Expression $setFn

        # Empty store -> safe single-tenant default surfaces (S1) via Get-PimActiveScenario.
        $r0 = Get-PimScenarioConfig
        T 'empty store reads the safe default scenario (S1)' ("$($r0.active)" -eq 'S1')
        T 'GET exposes the scenario catalog (6 entries)'     (@($r0.catalog).Count -eq 6)
        T 'GET surfaces resolved knobs for the active scenario' ($null -ne $r0.resolved -and "$($r0.resolved.spnModel)" -eq 'local-spn')

        # SAVE a switch to S5 (the shape the GUI PUTs) ...
        $saved = Set-PimScenarioConfig -Config ([ordered]@{ scenario = 'S5' })
        T 'save returns the persisted scenario (S5)' ("$($saved.active)" -eq 'S5')
        # ... and it READS BACK IDENTICALLY through a fresh Get (proves it hit the store).
        $r1 = Get-PimScenarioConfig
        T 'switch persists + reads back (S5)'        ("$($r1.active)" -eq 'S5')
        T 'resolved knobs reflect S5 (multi-tenant-spn, central-msp hosting)' (
            "$($r1.resolved.spnModel)" -eq 'multi-tenant-spn' -and "$($r1.resolved.hostingLocation)" -eq 'central-msp')
        T 'the underlying store key is Scenario'     ($script:__store.ContainsKey('Scenario'))
        T 'a bare id string is accepted too'         ((Set-PimScenarioConfig -Config 'S6').active -eq 'S6')

        # SAVE an unknown id -> REJECTED (throws), store NOT changed to garbage.
        $before = "$((Get-PimScenarioConfig).active)"
        $threw = $false
        try { [void](Set-PimScenarioConfig -Config ([ordered]@{ scenario = 'S99' })) } catch { $threw = $true }
        T 'unknown scenario id REJECTED (throws, not silently stored)' ($threw -and "$((Get-PimScenarioConfig).active)" -eq $before)
    } finally { $global:PIM_ActiveScenario = $savedActive2 }
}

# ===========================================================================
# Layer 4 -- STATIC GUI / SERVER wiring (no dead view)
# ===========================================================================
Write-Host "`n-- Layer 4: GUI + server wiring (static) --" -ForegroundColor Cyan
$html = [System.IO.File]::ReadAllText($htmlPath)
T 'server dot-sources PIM-ScenarioProfile.ps1'           ($srv -match 'PIM-ScenarioProfile\.ps1')
T 'server handles GET /api/settings/scenario'            ($srv -match "\`$path -eq '/api/settings/scenario' -and \`$method -eq 'GET'")
T 'server handles PUT /api/settings/scenario'            ($srv -match "\`$path -eq '/api/settings/scenario' -and \`$method -eq 'PUT'")
T 'PUT is SuperAdmin-gated'                               ($srv -match 'SuperAdmin role required to set the deployment scenario')
T 'GUI renders the Deployment scenario card'             ($html -match 'renderScenarioCard\(' -and $html -match 'id="setScenarioBody"')
T 'GUI GETs /api/settings/scenario'                      ($html -match "api\('GET',\s*'/api/settings/scenario'")
T 'GUI PUTs /api/settings/scenario'                      ($html -match "api\('PUT',\s*'/api/settings/scenario'")

# ===========================================================================
# TEST-17 -- the LIVE matrix must not default to a store the product does not ship.
#
# Asserted from HERE, statically, because Test-PimScenarioMatrix.ps1 is a live script excluded
# from the offline suite -- so nothing else would ever notice the default coming back. Same
# approach Test-PimUpdateContainers.ps1 uses for the roller.
#
# The defect: `if (-not $SqlServer) { $SqlServer = '.\SQLEXPRESS' }` plus an .EXAMPLE teaching
# the same. Operator, 2026-08-08: *"we dont support that [SQLEXPRESS]. it is native sql inside
# azure we support (paas)."* Every S1-S6 "VERIFIED" verdict to date was therefore measured on an
# unsupported configuration, and the FALLBACK is what made it silent -- a run with no store
# configured did not fail, it quietly pointed at a local Express instance and went green.
Write-Host "`n-- TEST-17: the live matrix refuses an unsupported store --" -ForegroundColor Cyan
$mxPath = Join-Path $script:Root 'tests\live\Test-PimScenarioMatrix.ps1'
$mx = if (Test-Path -LiteralPath $mxPath) { [System.IO.File]::ReadAllText($mxPath) } else { '' }
T 'the live matrix script is present to check'            ($mx.Length -gt 0)
# The load-bearing one: NO silent fallback. Match the ASSIGNMENT, not the word -- the phrase
# survives legitimately in the comment that explains the defect, and an assertion that fires on
# its own documentation is a false alarm waiting to happen (the lesson from BUG-09's asserts).
T 'TEST-17: no silent SQLEXPRESS fallback assignment'     ($mx -notmatch '(?m)^\s*if \(-not \$SqlServer\)\s*\{\s*\$SqlServer\s*=')
T 'TEST-17: a missing -SqlServer THROWS as required'      ($mx -match '(?m)^\s*throw \("Test-PimScenarioMatrix: -SqlServer is REQUIRED')
T 'TEST-17: a missing -SqlDatabase THROWS as required'    ($mx -match '(?m)^\s*throw "Test-PimScenarioMatrix: -SqlDatabase is REQUIRED')
T 'TEST-17: a non-Azure store is REFUSED by default'      ($mx -match 'REFUSING to run against' -and $mx -match "database\\\.windows\\\.net")
T 'TEST-17: -AllowUnsupportedStore is the explicit escape' ($mx -match '\[switch\]\$AllowUnsupportedStore')
T 'TEST-17: ...and taking it WARNS that the verdicts do not describe the shipped product' (
    $mx -match 'NOT the supported store' -and $mx -match 'product does not ship')
# ...and the docs that TEACH the wrong thing are part of the defect, not separate from it.
T 'TEST-17: the .EXAMPLE no longer teaches a SQLEXPRESS store' (
    $mx -notmatch "(?m)^\s*\`$env:PIM_SqlServer='\.\\\\SQLEXPRESS'")

# ===========================================================================
Write-Host ""
if ($fail -eq 0) { Write-Host " RESULT: $pass pass, 0 fail" -ForegroundColor Green; exit 0 }
else { Write-Host " RESULT: $pass pass, $fail fail" -ForegroundColor Red; exit 1 }
