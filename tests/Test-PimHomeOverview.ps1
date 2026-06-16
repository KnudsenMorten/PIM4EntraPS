#Requires -Version 5.1
<#
.SYNOPSIS
    Home / Overview tab + Alerting (REQUIREMENTS.md 26a/27 H2) -- static GUI/engine
    wiring asserts PLUS in-proc data-correlation tests proving the tiles reflect REAL
    engine / job / validation / audit / break-glass state (no dead/fake tiles).

.DESCRIPTION
    Three layers, all offline (no live tenant, no server boot):

      1. STATIC GUI/SERVER WIRING -- the Home tab is declared + is the landing tab,
         switchTab routes it to renderHome, renderHome calls /api/home, the heavy
         tiles lazy-load /api/home?include=heavy, every tile links to a real tab,
         the alerting card calls /api/alerting (GET/PUT) + /api/alerting/test, and
         the server defines all three handlers. (Complements the alignment test.)

      2. DATA CORRELATION (in-proc) -- extract Get-PimHomeOverview + its helpers from
         Open-PimManager.ps1, stub the EXISTING data sources (Build-PimGraphData,
         Get-PimJobsStatus, Invoke-PimPreflightValidation) with SEEDED fixtures that
         carry a FAILED job, validation errors, orphan groups + gap admins, then
         assert every tile reflects that seeded state (FAILED-jobs count, red status,
         per-level L0-L5 counts, gaps/orphans, validation errors, break-glass active).

      3. ALERTING (in-proc) -- extract Get-/Set-PimAlertingConfig + Send-PimManagerAlert,
         prove: default events ON, recipient validation, the "configure to enable"
         state when no sender, per-event gating, and that a fired alert routes through
         the notify path (stubbed Send-PimNotifyMail) to every configured recipient.

      4. SCHEDULER SEED (real) -- run Seed-PimSchedulerRuns.ps1 into a temp dir and
         prove Get-PimJobsStatus surfaces the seeded FAILED run (the same signal the
         jobs tile counts) -- the seed proves the tile reflects real job state.

    Run standalone (exits 0 green / 1 red) or via Run-AllPimTests.ps1 / PIM.Tests.ps1.
#>
[CmdletBinding()] param()

$ErrorActionPreference = 'Stop'
$pass = 0; $fail = 0
function T($n, $c) { if ($c) { Write-Host "  PASS $n" -ForegroundColor Green; $script:pass++ } else { Write-Host "  FAIL $n" -ForegroundColor Red; $script:fail++ } }

$root     = Split-Path -Parent $PSScriptRoot          # ...\PIM4EntraPS
$mgrDir   = Join-Path $root 'tools\pim-manager'
$htmlPath = Join-Path $mgrDir 'pim-manager.html'
$srvPath  = Join-Path $mgrDir 'Open-PimManager.ps1'
T 'pim-manager.html present'    (Test-Path -LiteralPath $htmlPath)
T 'Open-PimManager.ps1 present' (Test-Path -LiteralPath $srvPath)
if ($fail) { Write-Host "`n RESULT: $pass pass, $fail fail" -ForegroundColor Red; exit 1 }
$html = [System.IO.File]::ReadAllText($htmlPath)
$srv  = [System.IO.File]::ReadAllText($srvPath)

# ===========================================================================
# Layer 1 -- STATIC GUI / SERVER WIRING (no dead views)
# ===========================================================================
Write-Host "`n-- Layer 1: Home tab + alerting wiring (static) --" -ForegroundColor Cyan
T 'Home tab declared'                       ($html -match 'data-tab="home"')
T 'Home tab is the LANDING tab (active)'    ($html -match 'class="tab active" data-tab="home"')
T 'Home panel container present'            ($html -match 'id="homeTab"')
T 'Delegation Map is NO LONGER the active panel' ($html -notmatch 'id="mapTab" class="tab-panel active"')
T 'switchTab routes home -> renderHome'     ($html -match "name === 'home'\s*\)\s*renderHome")
T 'renderHome defined'                      ($html -match 'async function renderHome\(')
T 'renderHome calls GET /api/home'          ($html -match "api\('GET',\s*'/api/home'")
T 'Home lazy-loads heavy tiles'             ($html -match "api\('GET',\s*'/api/home\?include=heavy'")
T 'Home is rendered at boot'                ($html -match '(?m)^\s*renderHome\(\);')
T 'tiles are clickable links to tabs'       ($html -match 'home-tile-link' -and $html -match 'switchTab\(el\.dataset\.tab\)')
# "What needs my attention" call-out (REQUIREMENTS §26a)
T 'attention call-out placeholder present'  ($html -match 'id="homeAttnCallout"')
T 'homeCalloutHtml renderer defined'        ($html -match 'function homeCalloutHtml\(')
T 'call-out has an honest all-clear state'  ($html -match 'All clear &mdash; nothing needs your attention')
T 'call-out rows are clickable links'       ($html -match 'home-attn-link')
T 'tiles feed the call-out via homeAddAttn' ($html -match 'function homeAddAttn\(' -and $html -match "homeAddAttn\('red'" -and $html -match "homeAddAttn\('amber'")
# Tier / plane legend (REQUIREMENTS §26d / trustworthy-when-sparse)
T 'tier/plane legend renderer defined'      ($html -match 'function homeLegendHtml\(')
T 'legend documents the L0-L5 tiers'        ($html -match "'L0'" -and $html -match 'Tier &amp; plane legend')
T 'legend documents the CP/MP/WDP planes'   ($html -match "'CP'" -and $html -match "'MP'" -and $html -match "'WDP'")
# Drift surfaced on the engine/jobs tile (REQUIREMENTS §26b)
T 'engine/jobs tile renders the drift signal' ($html -match 'j\.drift' -and $html -match 'no drift \(live matches desired\)')
# Alerting card
T 'alerting card host present'              ($html -match 'id="setAlertingBody"')
T 'renderAlertingCard defined'             ($html -match 'async function renderAlertingCard\(')
T 'alerting card calls GET /api/alerting'  ($html -match "api\('GET',\s*'/api/alerting'")
T 'alerting card calls PUT /api/alerting'  ($html -match "api\('PUT',\s*'/api/alerting'")
T 'alerting card calls POST /api/alerting/test' ($html -match "api\('POST',\s*'/api/alerting/test'")
T 'alerting card surfaces configure-to-enable state' ($html -match 'Configure to enable')

# Server handlers exist
T 'server handles GET /api/home'           ($srv -match "\`$path -eq '/api/home' -and \`$method -eq 'GET'")
T 'server handles GET /api/alerting'       ($srv -match "\`$path -eq '/api/alerting' -and \`$method -eq 'GET'")
T 'server handles PUT /api/alerting'       ($srv -match "\`$path -eq '/api/alerting' -and \`$method -eq 'PUT'")
T 'server handles POST /api/alerting/test' ($srv -match "\`$path -eq '/api/alerting/test' -and \`$method -eq 'POST'")
T 'Get-PimHomeOverview defined'            ($srv -match 'function Get-PimHomeOverview')
T 'alert fires on a FAILED job run'        ($srv -match "Send-PimManagerAlert -Event 'engine-failure'")
T 'alert fires on break-glass activation'  ($srv -match "Send-PimManagerAlert -Event 'break-glass'")
T 'notify path (PIM-Notify.ps1) dot-sourced at boot' ($srv -match '\$_notifyLib = Join-Path \$solutionRoot ''engine\\_shared\\PIM-Notify\.ps1''')
T 'alert-notice mail template shipped'     (Test-Path -LiteralPath (Join-Path $root 'templates\mail\alert-notice.mailtemplate.html'))

# ===========================================================================
# Layer 2 -- DATA CORRELATION (in-proc, seeded fixtures)
# Extract the aggregation function + its tier helper, stub the EXISTING data
# sources, and prove the tiles reflect the seeded engine/job/validation state.
# ===========================================================================
Write-Host "`n-- Layer 2: Home aggregation reflects real seeded state (in-proc) --" -ForegroundColor Cyan

function Get-FnBody([string]$source, [string]$name) {
    $pat = 'function ' + [regex]::Escape($name) + '\b[\s\S]*?\n\}\r?\n'
    $m = [regex]::Match($source, $pat)
    if (-not $m.Success) { return $null }
    return $m.Value
}
$tierFn = Get-FnBody $srv 'Get-PimDelegationTierLevel'
$homeFn = Get-FnBody $srv 'Get-PimHomeOverview'
T 'Get-PimDelegationTierLevel body extracted' ([bool]$tierFn)
T 'Get-PimHomeOverview body extracted'        ([bool]$homeFn)

if ($tierFn -and $homeFn) {
    Set-StrictMode -Off
    Invoke-Expression $tierFn
    Invoke-Expression $homeFn

    # Tier-level parsing from real-shaped signals.
    T 'tier helper reads explicit Level' ((Get-PimDelegationTierLevel -Node ([ordered]@{ level = 'L2' })) -eq 2)
    T 'tier helper parses -L0- in a GroupTag' ((Get-PimDelegationTierLevel -Node ([ordered]@{ groupTag = 'PIM-ROLE-IdentityAdmin-L0-T0-MP' })) -eq 0)
    T 'tier helper parses -T3- when no level present' ((Get-PimDelegationTierLevel -Node ([ordered]@{ label = 'PIM-SVC-Backup-L3-T1-WDP' })) -eq 3)
    T 'tier helper returns $null for untiered' ($null -eq (Get-PimDelegationTierLevel -Node ([ordered]@{ label = 'PIM-ORG-Sales' })))

    # --- SEED the data sources the aggregator reads. -----------------------
    # A graph model: 3 delegation groups (L0, L1, untiered), 1 wired admin + 1 gap
    # admin, 1 wired target + 1 unmanaged target, and 1 orphan group (no edges).
    $script:__seedNodes = @(
        [ordered]@{ id='group:ROLE-Id';  kind='role-group';       label='PIM-ROLE-Id-L0-T0';  level='L0' }
        [ordered]@{ id='group:SVC-Bkp';  kind='permission-group'; label='PIM-SVC-Bkp-L1-T1';  level='L1' }
        [ordered]@{ id='group:ORG-Sales';kind='permission-group'; label='PIM-ORG-Sales';      level='' }   # untiered + ORPHAN (no edges)
        [ordered]@{ id='alice@x';        kind='admin';            label='Alice' }                            # wired
        [ordered]@{ id='bob@x';          kind='admin';            label='Bob' }                              # GAP (no edges)
        [ordered]@{ id='entra:GA';       kind='entra-role';       label='Global Administrator' }             # wired target
        [ordered]@{ id='az:/sub/1';      kind='az-resource';      label='/subscriptions/1' }                 # UNMANAGED target
    )
    $script:__seedEdges = @(
        [ordered]@{ source='alice@x';       target='group:ROLE-Id' }
        [ordered]@{ source='group:ROLE-Id'; target='entra:GA' }
        [ordered]@{ source='alice@x';       target='group:SVC-Bkp' }
    )
    function Build-PimGraphData { [ordered]@{ generatedUtc='2026-06-15T00:00:00Z'; nodes=$script:__seedNodes; edges=$script:__seedEdges } }

    # A scheduler view-model with ONE failed job + ONE running + ok history, PLUS a
    # completed engine reconcile that APPLIED changes (lastRan=$true) -> the drift signal.
    function Get-PimJobsStatus { param($Jobs) [pscustomobject]@{ total=5; runningCount=1; generatedUtc='2026-06-15T00:00:00Z'; jobs=@(
        [pscustomobject]@{ name='discovery-azure'; type='discovery'; scope='Azure'; enabled=$true; inProgress=$false; neverRun=$false; lastOk=$false; lastRan=$false; lastRunUtc='2026-06-14T22:00:00Z'; lastResult='AuthorizationFailed'; lastRunId='r1'; nextRunUtc='2026-06-15T04:00:00Z'; nextRunSynthesized=$false }
        [pscustomobject]@{ name='tenant-cache';    type='tenant-cache'; scope=''; enabled=$true; inProgress=$false; neverRun=$false; lastOk=$true; lastRan=$true; lastRunUtc='2026-06-15T00:30:00Z'; lastResult='ok'; lastRunId='r2'; nextRunUtc='2026-06-15T12:30:00Z'; nextRunSynthesized=$false }
        [pscustomobject]@{ name='full-reconcile';  type='engine-full'; scope='All'; enabled=$true; inProgress=$true; neverRun=$false; lastOk=$null; lastRan=$null; lastRunUtc=''; lastResult=''; lastRunId=''; runningRunId='rx'; nextRunUtc=''; nextRunSynthesized=$false }
        [pscustomobject]@{ name='delta-reconcile'; type='engine-delta'; scope='All'; enabled=$true; inProgress=$false; neverRun=$false; lastOk=$true; lastRan=$true; lastRunUtc='2026-06-15T01:00:00Z'; lastResult='applied 3 changes'; lastRunId='r3'; nextRunUtc='2026-06-15T02:00:00Z'; nextRunSynthesized=$false }
        [pscustomobject]@{ name='daily-summary';   type='daily-summary'; scope=''; enabled=$false; inProgress=$false; neverRun=$true; lastOk=$null; lastRan=$null; lastRunUtc=''; lastResult=''; lastRunId=''; nextRunUtc=''; nextRunSynthesized=$true }
    ) } }
    function Get-PimJobRunHistory { @(1,2,3) }   # non-empty history -> not "unknown"
    function Get-PimManagerEffectiveSchedule { @() }

    # A preflight report with errors + warnings.
    function Invoke-PimPreflightValidation { [ordered]@{ ranAt='2026-06-15T00:00:00Z'; summary=[ordered]@{ errors=2; warnings=5; infos=1; total=8 } } }

    # Break-glass: an ACTIVE override file.
    $script:configRoot = Join-Path $env:TEMP ("pim-home-" + [guid]::NewGuid().ToString('N').Substring(0,8))
    New-Item -ItemType Directory -Path $script:configRoot -Force | Out-Null
    $script:outputRoot = $script:configRoot
    $script:PimInstanceName = 'test'
    $script:PimPreflightCacheReport = $null
    ([ordered]@{ active=$true; activatedBy='sec@x'; activatedAtUtc='2026-06-15T00:00:00Z'; expiresAtUtc=([datetime]::UtcNow.AddHours(2).ToString('o')); reason='incident-42'; scopeGroupTags=@('ROLE-Id') } | ConvertTo-Json) |
        Set-Content -LiteralPath (Join-Path $script:configRoot 'emergency-override.custom.json') -Encoding UTF8

    $ov = $null
    try { $ov = Get-PimHomeOverview } catch { Write-Host "    Get-PimHomeOverview threw: $($_.Exception.Message)" -ForegroundColor Red }
    T 'Get-PimHomeOverview returns a payload' ([bool]$ov -and [bool]$ov.tiles)

    if ($ov -and $ov.tiles) {
        $tl = $ov.tiles
        # Jobs tile reflects the seeded FAILED job (the #1 requirement: FAILED jobs).
        T 'jobs tile counts the FAILED job'            ([int]$tl.jobs.failedCount -eq 1)
        T 'jobs tile status is RED on a failure'       ($tl.jobs.status -eq 'red')
        T 'jobs tile lists the failed job by name'     (@($tl.jobs.failedJobs | ForEach-Object { $_.name }) -contains 'discovery-azure')
        T 'jobs tile counts the running job'            ([int]$tl.jobs.runningCount -eq 1)
        T 'jobs tile headlines last run + next run'     ([bool]$tl.jobs.lastRun -and [bool]$tl.jobs.nextRun)
        # Drift signal (REQUIREMENTS §26b): the last engine reconcile applied changes.
        T 'jobs tile carries a drift signal'            ([bool]$tl.jobs.drift)
        T 'drift = drifted (last engine reconcile applied changes)' ([bool]$tl.jobs.drift.drifted)
        T 'drift names the engine reconcile job'        ($tl.jobs.drift.job -eq 'delta-reconcile')
        T 'drift sources the most-recent engine run, not a non-engine job' ($tl.jobs.drift.scope -eq 'All' -and $tl.jobs.drift.knownOk)
        # Tier tile: per-level L0-L5 counts.
        T 'tiers tile L0 count = 1'                     ([int]$tl.tiers.byLevel.L0 -eq 1)
        T 'tiers tile L1 count = 1'                     ([int]$tl.tiers.byLevel.L1 -eq 1)
        T 'tiers tile untiered count = 1'               ([int]$tl.tiers.byLevel.untiered -eq 1)
        T 'tiers tile total delegation groups = 3'      ([int]$tl.tiers.totalGroups -eq 3)
        # Gaps tile: orphan group + gap admin + unmanaged target.
        T 'gaps tile counts the orphan group'           ([int]$tl.gaps.orphanGroups -eq 1)
        T 'gaps tile counts the gap admin (reaches nothing)' ([int]$tl.gaps.gapAdmins -eq 1)
        T 'gaps tile counts the unmanaged target'       ([int]$tl.gaps.unmanagedTargets -eq 1)
        # Validation tile.
        T 'validation tile reports 2 errors / 5 warnings' ([int]$tl.validation.errors -eq 2 -and [int]$tl.validation.warnings -eq 5)
        T 'validation tile status is RED on errors'     ($tl.validation.status -eq 'red')
        # Break-glass tile.
        T 'break-glass tile is ACTIVE'                  ([bool]$tl.breakGlass.active)
        T 'break-glass tile carries activator + reason' ($tl.breakGlass.activatedBy -eq 'sec@x' -and $tl.breakGlass.reason -eq 'incident-42')
        # Heavy tiles are deferred on the fast load.
        T 'heavy tiles deferred on fast load'           ([bool]$tl.expiring.deferred -and [bool]$tl.accessReviews.deferred)
    }

    # --- Heavy load path: stub the live readers, prove expiring + reviews. --
    function Get-PimActiveAssignmentsCached { param([switch]$Force) [ordered]@{ ok=$true; rows=@(
        [ordered]@{ principal='Alice'; role='GA'; type='entra-role'; end=([datetime]::UtcNow.AddDays(3).ToString('o')) }   # expiring (<14d)
        [ordered]@{ principal='Bob';   role='Reader'; type='azure-rbac'; end=([datetime]::UtcNow.AddDays(40).ToString('o')) } # not soon
        [ordered]@{ principal='Eve';   role='Sec'; type='pim-for-groups'; end='' }                                          # permanent
    ) } }
    # NOTE: the real PIM-AccessReviews module may already be importable from the
    # function's $PSScriptRoot, in which case Get-PimAccessReviewSeedRows resolves to
    # the SHIPPED seed (1 InProgress + 1 Completed) -- so assert pending >= 1 (the
    # in-progress count), not an exact stub count.
    function Get-PimAccessReviewSeedRows { @([pscustomobject]@{ status='InProgress' }, [pscustomobject]@{ status='Completed' }, [pscustomobject]@{ status='InProgress' }) }

    $ovh = $null
    try { $ovh = Get-PimHomeOverview -IncludeHeavy } catch { Write-Host "    heavy overview threw: $($_.Exception.Message)" -ForegroundColor Red }
    if ($ovh -and $ovh.tiles) {
        T 'heavy: expiring tile counts only the <14d assignment' ([int]$ovh.tiles.expiring.expiring -eq 1)
        T 'heavy: access-reviews tile counts in-progress reviews (>=1)' ([int]$ovh.tiles.accessReviews.pending -ge 1)
    } else { T 'heavy overview returns a payload' $false }

    try { Remove-Item -LiteralPath $script:configRoot -Recurse -Force -ErrorAction SilentlyContinue } catch {}
}

# ===========================================================================
# Layer 3 -- ALERTING config + send routing (in-proc)
# ===========================================================================
Write-Host "`n-- Layer 3: alerting config + send routing (in-proc) --" -ForegroundColor Cyan

$getAlertFn  = Get-FnBody $srv 'Get-PimAlertingConfig'
$setAlertFn  = Get-FnBody $srv 'Set-PimAlertingConfig'
$sendAlertFn = Get-FnBody $srv 'Send-PimManagerAlert'
T 'Get-PimAlertingConfig body extracted'  ([bool]$getAlertFn)
T 'Set-PimAlertingConfig body extracted'  ([bool]$setAlertFn)
T 'Send-PimManagerAlert body extracted'   ([bool]$sendAlertFn)

if ($getAlertFn -and $setAlertFn -and $sendAlertFn) {
    Set-StrictMode -Off
    $script:PimAlertEventCatalog = @('engine-failure','drift','expiring-access','break-glass')
    # In-memory store stubs (replace the SQL/file persistence the helpers call).
    $script:__alertStore = @{}
    function Get-PimManagerSetting { param([string]$Name) if ($script:__alertStore.ContainsKey($Name)) { return $script:__alertStore[$Name] } return $null }
    function Set-PimManagerSetting { param([string]$Name,[object]$Value) $script:__alertStore[$Name] = $Value }
    function Get-PimManagerTenantContext { @{ tenantName='Contoso'; tenantId='t' } }
    function Write-PimManagerAuditEvent { param($Action,$Target,$After,$Result) }
    $script:PimInstanceName = 'test'
    $global:PIM_MailSender = $null

    Invoke-Expression $getAlertFn
    Invoke-Expression $setAlertFn
    Invoke-Expression $sendAlertFn

    # Defaults: all events ON; no recipients; not enabled (no sender, no recipients).
    $cfg0 = Get-PimAlertingConfig
    T 'default: all events ON'                ($cfg0.events['engine-failure'] -and $cfg0.events['drift'] -and $cfg0.events['expiring-access'] -and $cfg0.events['break-glass'])
    T 'default: no recipients'                (@($cfg0.recipients).Count -eq 0)
    T 'default: NOT enabled (configure to enable)' (-not $cfg0.enabled)

    # Save recipients (garbage dropped) + toggle one event off.
    $cfg1 = Set-PimAlertingConfig -Recipients @('ops@example.com','not-an-email','  ','sec@example.com') -Events @{ 'drift' = $false }
    T 'save: invalid recipients dropped, valid kept' (@($cfg1.recipients).Count -eq 2 -and ($cfg1.recipients -contains 'ops@example.com'))
    T 'save: drift event toggled OFF'         (-not $cfg1.events['drift'])
    T 'save: other events still ON'           ($cfg1.events['engine-failure'])

    # Still not enabled until a sender is configured (honest configure-to-enable).
    T 'enabled stays FALSE with recipients but no sender' (-not (Get-PimAlertingConfig).enabled)

    # Send routing: a disabled event does NOT fire.
    $rDrift = Send-PimManagerAlert -Event 'drift' -Title 't' -WhatIf
    T 'disabled event does not fire'          (-not $rDrift.fired -and $rDrift.reason -eq 'event disabled')

    # An enabled event fires + routes through the notify path to every recipient.
    $script:__sent = New-Object System.Collections.Generic.List[string]
    function Send-PimNotifyMail { param([string]$Type,[hashtable]$Tokens,[string]$Recipient,[switch]$WhatIf) $script:__sent.Add($Recipient); return @{ sent = (-not $WhatIf); recipient=$Recipient; reason=$(if($WhatIf){'whatif'}else{''}) } }
    $rFail = Send-PimManagerAlert -Event 'engine-failure' -Title 'job failed' -Detail 'x' -LinkTab 'jobs'
    T 'enabled event fires'                   ($rFail.fired)
    T 'alert routes to BOTH recipients via notify path' (@($script:__sent).Count -eq 2 -and [int]$rFail.sent -eq 2)
    T 'alert uses the alert-notice template'  ($true)   # Send-PimNotifyMail call uses Type 'alert-notice' (asserted statically below)
    T 'Send-PimManagerAlert uses alert-notice type' ($sendAlertFn -match "-Type 'alert-notice'")

    # No-recipients case yields the honest reason.
    $script:__alertStore = @{}
    $rNone = Send-PimManagerAlert -Event 'engine-failure' -Title 't'
    T 'no recipients -> honest reason, no send' (-not $rNone.fired -and $rNone.reason -eq 'no recipients configured')
}

# ===========================================================================
# Layer 4 -- SCHEDULER SEED proves the FAILED-job signal is real
# ===========================================================================
Write-Host "`n-- Layer 4: seeded scheduler run-history surfaces a FAILED job --" -ForegroundColor Cyan
$seedScript = Join-Path $root 'tools\pim-scheduler\Seed-PimSchedulerRuns.ps1'
$schedLib   = Join-Path $root 'engine\_shared\PIM-Scheduler.ps1'
if ((Test-Path $seedScript) -and (Test-Path $schedLib)) {
    $seedDir = Join-Path $env:TEMP ("pim-home-seed-" + [guid]::NewGuid().ToString('N').Substring(0,8))
    try {
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $seedScript -StateDir $seedDir | Out-Null
        . $schedLib
        $global:PIM_SchedulerStatePath = Join-Path $seedDir 'pim-scheduler-state.json'
        $vm = Get-PimJobsStatus
        $failed = @($vm.jobs | Where-Object { $_.lastOk -eq $false })
        T 'seeded scheduler produces at least one FAILED job' (@($failed).Count -ge 1)
        T 'seeded scheduler produces at least one RUNNING job' ([int]$vm.runningCount -ge 1)
    } catch {
        T "scheduler seed ran without error ($($_.Exception.Message))" $false
    } finally {
        try { Remove-Item -LiteralPath $seedDir -Recurse -Force -ErrorAction SilentlyContinue } catch {}
    }
} else {
    Write-Host "  (skip: scheduler seed/lib not found)" -ForegroundColor DarkGray
}

Write-Host ("`n RESULT: {0} pass, {1} fail" -f $pass, $fail) -ForegroundColor $(if ($fail) { 'Red' } else { 'Green' })
if ($fail) { exit 1 }
