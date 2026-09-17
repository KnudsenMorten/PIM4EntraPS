#Requires -Version 5.1
<#
.SYNOPSIS
    §31.3 Phase-2 -- the SCENARIO-BOUND engine runner live wrapper. Thin
    orchestrator over the PURE core in engine/_shared/PIM-Downlink.ps1
    (Invoke-PimScenarioDeploy / Get-PimScenarioRunPlan).

.DESCRIPTION
    Resolves the active deployment scenario (S1-S6) and runs the right path for the
    topology:
      * single  (S1/S2) -> engine apply only.
      * master  (S3/S4) -> engine apply only (the master hosts its own estate).
      * managed (S5/S6) -> downlink-sync (ring pull -> verify -> master->slave admin
                           sync) THEN engine apply.

    Composes Invoke-PimEngineCore for the engine apply (which honours the
    mass-disable guard: -Prune is opt-in + Full-only, and an empty desired set
    never prunes). Composes Invoke-PimManagedDownlink for the managed path.

    This is what the live scenario matrix's `scenario-runner-triggers-engine` +
    `idempotent-second-pass` steps assert exists, runs, and is a no-op on a second
    pass. PURE decisions (the topology branch) are offline-tested in
    tests/Test-PimDownlink.ps1. PS 5.1-safe; SPN + certificate only.

.PARAMETER Scenario
    'S1'..'S6'. When omitted, resolves the active scenario from the store
    (Get-PimActiveScenario), defaulting to S1.

.PARAMETER EngineScope / EngineMode
    Forwarded to Invoke-PimEngineCore (default All / Delta).

.PARAMETER TenantId / SlaveRing / BaselineDocPath / BaselineUrl / BaselineAccessToken
    Managed (S5/S6) downlink inputs -- the signed baseline + the slave tenant/ring.

.PARAMETER CentralRoot / LocalRoot / SqlServer / SqlDatabase
    Staging roots + the platform registry (defaults from env / .\SQLEXPRESS).

.PARAMETER WhatIfMode
    Default ON: plan/preview, no live writes. -WhatIfMode:$false applies.

.EXAMPLE
    # single-tenant (S1): engine apply only.
    .\Invoke-PimScenarioRun.ps1 -Scenario S1 -WhatIfMode:$false

.EXAMPLE
    # managed local (S6): downlink-sync then engine apply.
    .\Invoke-PimScenarioRun.ps1 -Scenario S6 -TenantId <tenant-id-2linkit> -SlaveRing 2 `
        -BaselineDocPath C:\TMP\baseline-latest.json -WhatIfMode:$false
#>
[CmdletBinding()]
param(
    [ValidateSet('S1','S2','S3','S4','S5','S6')][string]$Scenario,

    [string]$EngineScope = 'All',
    [ValidateSet('Full','Delta')][string]$EngineMode = 'Delta',

    [string]$TenantId,
    [ValidateRange(0,2)][int]$SlaveRing = 2,
    [string]$BaselineDocPath,
    [string]$BaselineUrl,
    [string]$BaselineAccessToken,

    [string]$CentralRoot = $env:PIM_SyncRootCentral,
    [string]$LocalRoot   = $env:PIM_SyncRootLocal,
    [string]$SqlServer   = $env:PIM_SqlServer,
    [string]$SqlDatabase = $env:PIM_SqlDatabase,

    # (71.19: -DefaultManagerEmail / PIM_DefaultManagerEmail removed -- a synced admin's TAP goes to its SPONSOR
    # DEPARTMENT's owners, resolved in this tenant from the department rows the bundle carries.)

    # --- BUG-79: THE TWO DOWNLINK GATES, on the entry that had NEITHER ---------
    # This script reaches Invoke-PimManagedDownlink (via Invoke-PimScenarioDeploy) and for a long
    # time exposed no way to supply either gate -- so a downlink driven through the scenario runner
    # ran with NO version gate and NO customer veto, silently, while a downlink driven through
    # Invoke-PimDownlinkSync.ps1 had both. Same engine, same tenant, two different safety postures
    # depending on which entry point somebody happened to use.
    # 🔒 The resolution logic is SHARED, not copied: -LocalManifestPath goes through the same
    # Resolve-PimCustomerBlockedCapabilities the other entry uses, so the refuse-on-unparseable
    # rule cannot drift between them. Ring map inputs mirror that script's names exactly, for the
    # same reason -- an operator should not have to learn two vocabularies for one decision.
    [string]$TemplateRingMapPath,
    [string]$TemplateRingMapUrl,
    [string]$TemplateName = 'Baseline',
    [string]$TemplateChannel = 'managed',
    [string]$LocalManifestPath,
    [string[]]$BlockedCapabilities,
    # IMP-13. The SLAVE's admin naming prefixes, so this entry can supply the same gate the other
    # one resolves from the slave's own config. Absent => the plan reports admin recognisability as
    # NOT EVALUATED, which is the honest answer from a runner that may not be inside the slave.
    [string[]]$SlaveAdminPrefixes,
    # 71.14: the downlink's removal opt-in (same name as Invoke-PimDownlinkSync.ps1). Default OFF = retraction is
    # report-only ("WOULD REMOVE ..."); ON removes what no longer reaches this tenant, still within the removal budget.
    [switch]$AllowRetraction,

    [int64]$LastVersion = 0,
    [switch]$WhatIfMode = $true
)

$ErrorActionPreference = 'Stop'
$shared = Join-Path (Split-Path -Parent $PSScriptRoot) 'engine\_shared'
. (Join-Path $shared 'PIM-ScenarioProfile.ps1')   # also dot-sources PIM-Downlink.ps1
. (Join-Path $shared 'PIM-Baseline.ps1')
# BUG-79: the vendored platform ring core, for the same reason Invoke-PimDownlinkSync.ps1 loads it.
# ⚠️ Without this line Get-PimTemplateRingPlan is not merely uncalled, it is UNDEFINED in this
# process -- which is BUG-29's original shape verbatim ("the gate was not merely called by nobody,
# its functions were not even DEFINED in any runtime process"). Adding the -TemplateRingMap*
# parameters without this would have produced a NEW silent no-op while looking like a fix.
. (Join-Path $shared 'PIM-RingGate.ps1')
# 🔴 BUG-80 -- THE TOKEN PROVIDER WAS MISSING HERE, AND ITS ABSENCE IS SILENT BY DESIGN.
# New-PimSqlConnection acquires a token only `if (Get-Command Get-PimRestToken ...)`, so a caller
# that loads PIM-SqlStore (via PIM-Downlink) WITHOUT PIM-Rest skips token acquisition entirely,
# presents no credential, and Azure SQL answers `Login failed for user ''`. BUG-33 wrote that
# signature down -- "the common cause is not 'auth failed' but 'the token provider was never
# loaded'" -- and this runner was doing exactly that.
# MEASURED on the greenfield slave 2026-08-27: with the slave store finally wired (BUG-79), the
# downlink's own reads failed as
#     [downlink] roles: could not read PIM-Assignments-Admins from the slave store:
#                "Login failed for user ''."
# while the ENGINE -- a separate process that does load PIM-Rest -- reached the same database
# perfectly well in the same run. That split is the tell: same store, same identity, two processes,
# one of them missing a dot-source.
# PIM-AccountRest.ps1 provides Get-PimRestDefaultDomain, which the local-slave path needs to
# resolve the managed tenant's UPN domain (IMP-12 / BUG-81). It is loaded here rather than probed
# for, because the probe was `Get-Command ... -ErrorAction SilentlyContinue` and a missing module
# therefore SKIPPED the resolution without a word -- so the downlink kept refusing to stage admins
# and the reason ("no ambient tenant to read it from") pointed away from the real cause. That is
# the recorded trap: a Get-Command-guarded optional dependency turns a missing file into silently
# skipped behaviour, not a visible error.
foreach ($__dep in @('PIM-Rest.ps1','PIM-SqlStore.ps1','PIM-AccountRest.ps1')) {
    $__p = Join-Path $shared $__dep
    if (-not (Test-Path -LiteralPath $__p)) { throw "required by the downlink's own store reads and not found: $__p" }
    . $__p
}

# 🔴 BUG-83 -- THIS PROCESS HAD NO IDENTITY, SO IT SILENTLY BECAME THE MANAGED IDENTITY.
# Get-PimRestToken takes the MI branch when `$env:IDENTITY_ENDPOINT` is set AND there is no client
# id. This runner set neither $global:PIM_ClientId nor $global:PIM_TenantId, so every Graph call it
# makes -- including the default-domain lookup the local-slave path depends on -- authenticated as
# the container's managed identity instead of the engine SPN.
# MEASURED on the greenfield slave 2026-08-27, and the comparison is the proof: the SAME
# /domains call, with the SAME grant, succeeded from mgmt1 as the engine SPN at 15:16:12 and
# returned 403 from the container 35 seconds later. Not propagation -- a different identity. The
# MI holds ZERO Graph app-roles; the engine SPN holds 100. The ENGINE, a separate process that
# reads these from env, authenticates correctly and prints "Auth : SPN a399691f..." in the same run.
# Same family as BUG-80: the runner process lacked what the engine process had, and the gap showed
# up as a permissions error pointing at the wrong principal.
# The SECRET is deliberately not set here: Get-PimRestToken reads $env:AZURE_CLIENT_SECRET itself,
# so the credential never has to be copied into a global.
if ($env:PIM_TenantId -and -not $global:PIM_TenantId) { $global:PIM_TenantId = "$($env:PIM_TenantId)".Trim() }
if ($env:PIM_ClientId -and -not $global:PIM_ClientId) {
    $global:PIM_ClientId = "$($env:PIM_ClientId)".Trim()
    Write-Host "[scenario-run] identity: engine SPN $($global:PIM_ClientId) (Graph calls in THIS process, not the container's managed identity)" -ForegroundColor DarkGray
} elseif ($env:IDENTITY_ENDPOINT) {
    Write-Host '[scenario-run] identity: no PIM_ClientId -- Graph calls in this process will use the MANAGED IDENTITY, which may hold no app-roles.' -ForegroundColor Yellow
}

if (-not $SqlServer)   { $SqlServer = '.\SQLEXPRESS' }
if (-not $SqlDatabase) { $SqlDatabase = 'PimPlatform' }
$global:PIM_SqlServer   = $SqlServer
$global:PIM_SqlDatabase = $SqlDatabase
$global:PIM_UseGraphSdk = $false

# resolve the scenario (explicit id, else the active scenario from the store).
$sc = if ("$Scenario".Trim()) { Get-PimScenario -Id $Scenario } else { Get-PimActiveScenario }
if (-not $sc) { throw "could not resolve scenario '$Scenario'." }
$null = Set-PimScenarioContext -Scenario $sc   # apply the runtime knobs

Write-Host "==========================================================================" -ForegroundColor Cyan
Write-Host " PIM4EntraPS scenario-run ($($sc.id), $($sc.role)) $(if ($WhatIfMode) { '(WHATIF)' } else { '(LIVE)' })" -ForegroundColor Cyan
Write-Host "==========================================================================" -ForegroundColor Cyan

# managed scenarios need the signed baseline doc loaded (file or HTTPS pull).
$doc = $null
$run = Get-PimScenarioRunPlan -Scenario $sc
if ($run.runDownlink) {
    if ("$BaselineDocPath".Trim()) {
        if (-not (Test-Path -LiteralPath $BaselineDocPath)) { throw "baseline doc not found: $BaselineDocPath" }
        $raw = Get-Content -LiteralPath $BaselineDocPath -Raw
        $br = $raw.IndexOf('{'); if ($br -gt 0) { $raw = $raw.Substring($br) }
        $doc = $raw | ConvertFrom-Json
    } elseif ("$BaselineUrl".Trim()) {
        $headers = @{ 'x-ms-version' = '2021-08-06' }
        if ("$BaselineAccessToken".Trim()) { $headers['Authorization'] = "Bearer $BaselineAccessToken" }
        $raw = Invoke-RestMethod -Method GET -Uri $BaselineUrl -Headers $headers -ErrorAction Stop
        if ($raw -is [string]) { $br = $raw.IndexOf('{'); if ($br -gt 0) { $raw = $raw.Substring($br) }; $doc = $raw | ConvertFrom-Json }
        else { $doc = $raw }
    } else {
        throw "managed scenario $($sc.id) needs -BaselineDocPath or -BaselineUrl (the signed master baseline)."
    }
}

# --- BUG-79: resolve BOTH downlink gates before deploying -----------------------
# Both stay INERT when nothing is supplied, so a run that passes none of these behaves exactly as
# it did before -- the same non-breaking rule the version gate has carried since BUG-29.
$srArgs = @{}

# (a) the CUSTOMER's class veto. Explicit wins outright; otherwise the shared resolver reads the
#     customer's OWN bootstrap manifest (and REFUSES the run if it exists but cannot be parsed).
if ($PSBoundParameters.ContainsKey('SlaveAdminPrefixes') -and $null -ne $SlaveAdminPrefixes) {
    $srArgs['SlaveAdminPrefixes'] = @($SlaveAdminPrefixes)
    Write-Host ("  naming check: slave admin prefixes {0}" -f (@($SlaveAdminPrefixes) -join ', ')) -ForegroundColor Cyan
}
if ($PSBoundParameters.ContainsKey('BlockedCapabilities')) {
    $srArgs['BlockedCapabilities'] = @($BlockedCapabilities)
    Write-Host ("  customer gate: {0} (explicit -BlockedCapabilities)" -f `
        $(if (@($BlockedCapabilities).Count) { "blocks $(@($BlockedCapabilities) -join ', ')" } else { 'blocks nothing' })) -ForegroundColor Cyan
} else {
    $srBlocked = Resolve-PimCustomerBlockedCapabilities -ManifestPath $LocalManifestPath `
        -SolutionRoot (Split-Path -Parent $PSScriptRoot) -Solution 'PIM4EntraPS'
    if ($null -ne $srBlocked) { $srArgs['BlockedCapabilities'] = @($srBlocked) }
}

# (b) the OPERATOR's version gate (RING-1 plane 2). Same parameter names and same 'managed'
#     channel default as Invoke-PimDownlinkSync.ps1 -- one decision, one vocabulary.
$srRingMap = $null
if ("$TemplateRingMapPath".Trim()) {
    if (-not (Test-Path -LiteralPath $TemplateRingMapPath)) { throw "template ring map not found: $TemplateRingMapPath" }
    $srRawMap = Get-Content -LiteralPath $TemplateRingMapPath -Raw
    $srRingMap = $srRawMap | ConvertFrom-Json
} elseif ("$TemplateRingMapUrl".Trim()) {
    $srMapHeaders = @{ 'x-ms-version' = '2021-08-06' }
    if ("$BaselineAccessToken".Trim()) { $srMapHeaders['Authorization'] = "Bearer $BaselineAccessToken" }
    $srRawMap = Invoke-RestMethod -Method GET -Uri $TemplateRingMapUrl -Headers $srMapHeaders -ErrorAction Stop
    if ($srRawMap -is [string]) { $bm = $srRawMap.IndexOf('{'); if ($bm -gt 0) { $srRawMap = $srRawMap.Substring($bm) }; $srRingMap = $srRawMap | ConvertFrom-Json }
    else { $srRingMap = $srRawMap }
}
if ($srRingMap -and "$TenantId".Trim()) {
    $srPlan = Get-PimTemplateRingPlan -Template $TemplateName -TenantId $TenantId `
        -Assignments $srRingMap.assignments -Promotions $srRingMap.promotions `
        -Channel $TemplateChannel -DefaultRing $srRingMap.default
    $srArgs['RingPlan'] = $srPlan
    Write-Host ("  ring plan: {0} -> {1}{2}" -f $TemplateName, $srPlan.Action,
        $(if ("$($srPlan.Version)".Trim()) { " approves v$($srPlan.Version)" } else { '' })) -ForegroundColor Cyan
} elseif ($run.runDownlink) {
    # 🪤 `$run.runDownlink` -- NOT `$sc.topology`, which does not exist. The first draft of this
    # line tested `$sc.topology -eq 'managed'` and would have been silently FALSE on every run:
    # the descriptor's property is `role` ('msp-managed'), and the canonical "does this scenario
    # pull a downlink" predicate is `syncAdminsPermissions`, already surfaced here as
    # `$run.runDownlink`. A comparison against a property that does not exist is $null -ne
    # 'managed' -- no error, no warning, just a branch that never fires. That is the same silent
    # class as the gates this whole change is about; caught by printing a descriptor instead of
    # assuming its shape.
    # Only worth saying on a run that actually pulls -- S1..S4 never do, so "no ring map" there is
    # not a gap, and a warning on every single-tenant run would train people to ignore it.
    Write-Host "  ring map: none supplied -- version gate INERT (pulls whatever version the master published)" -ForegroundColor DarkYellow
}

if ($AllowRetraction) {
    $srArgs['AllowRetraction'] = $true
    if ($run.runDownlink) { Write-Host '  retraction: ALLOWED (-AllowRetraction) -- rows that no longer reach this tenant are removed, within the removal budget' -ForegroundColor Yellow }
} elseif ($run.runDownlink) {
    Write-Host '  retraction: report-only (default) -- pass -AllowRetraction to remove what no longer reaches this tenant' -ForegroundColor DarkGray
}

$result = Invoke-PimScenarioDeploy -Scenario $sc -EngineScope $EngineScope -EngineMode $EngineMode `
    -Doc $doc -TenantId $TenantId -SlaveRing $SlaveRing `
    -CentralRoot $CentralRoot -LocalRoot $LocalRoot -SqlServer $SqlServer -SqlDatabase $SqlDatabase `
    -LastVersion $LastVersion -WhatIfMode:$WhatIfMode @srArgs

Write-Host ""
$col = if ($result.ok) { 'Green' } else { 'Red' }
$held = [bool]($result.ok -and $result.PSObject.Properties['held'] -and $result.held)   # 71.13
if ($held) { $col = 'Yellow' }
Write-Host ("SCENARIO RUN $($result.scenarioId): {0}" -f $(if ($held) { 'OK -- HELD, NEEDS APPROVAL' } elseif ($result.ok) { 'OK' } else { 'FAILED' })) -ForegroundColor $col
foreach ($s in @($result.steps)) {
    Write-Host ("  [{0}] {1} -- {2}" -f $(if ($s.ok) { 'OK' } else { 'XX' }), $s.step, $s.detail) -ForegroundColor $(if ($s.ok) { 'DarkGray' } else { 'Red' })
}
$result
if (-not $result.ok) { exit 1 }
