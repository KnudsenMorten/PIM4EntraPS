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
# local-slave with no local server -> the safe .\SQLEXPRESS default.
T 'local-slave with no local server -> .\SQLEXPRESS default' ((Resolve-PimScenarioHostingStore -Scenario 'S6' -LocalServer '').server -eq '.\SQLEXPRESS')

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
Write-Host ""
if ($fail -eq 0) { Write-Host " RESULT: $pass pass, 0 fail" -ForegroundColor Green; exit 0 }
else { Write-Host " RESULT: $pass pass, $fail fail" -ForegroundColor Red; exit 1 }
