#Requires -Version 7.0
<#
.SYNOPSIS
    SEC-PATCH-PIPELINE-1 (1)-(3) -- the in-container entry point of the security image job caj-pim-secupdate (cron 7,22,37,52 -- 3.1.71 I2).

.DESCRIPTION
    IMAGE-ONLY, SEPARATE FROM THE NORMAL UPDATER, NO QUIESCE, NO RUN GATE. One execution:
      0. pim.Settings 'SecUpdateJob' is read FIRST: not on (the default) -> one line, exit 0, nothing else is read or written.
      1. what runs: the web app's image (registry, repository, version); the customer freeze PIM_UPDATE_HOLD=1 on the UPDATER
         job (then: one line, exit 0); whether the normal updater runs now (fail closed: unreadable = running; then: wait).
      2. what the ring serves: the signed Invardia manifest, the SAME pull + verify code the updater uses (licence, install
         key, replay watermark read from the UPDATER job's live environment -- this job never moves the watermark).
      3. Get-PimSecUpdateDecision: none / hold / wait / leave-to-updater / build ring-image-only. ONLY a <build>.N on THIS
         install's ring is built (Invardia 2026-11-26: the former 'new-base' rebuild on a new Microsoft digest is REMOVED --
         it would skip the rings 0/1 proof).
      4. build: the signed archive AS THE RELEASE PINS IT (its own bases), ACR Tasks in the install's own registry
         (Invoke-PimAcrRestBuildWithRetry, with the install's agent pool when it has one), to the release's OWN tag
         <repository>:<build>.N -- the running tag is never overwritten.
      4b. the LAST look: the updater's executions and the web app's image read again; the updater running or the image
         changed since the start = abort, recorded, exit 0 (nothing moved).
      5. the swap, wrapped: the web app first, health-checked, rolled back on a failure; then every job and app on the same
         repository (no execution is stopped). ANY failure puts the previous image back on what was moved and records the
         failed attempt (the 60-min retry guard applies). Then PIM's own apps: Single + ONE active revision
         (Invoke-PimRevisionModeCheck, read back); this job itself last.
      6. pim.Settings 'SecUpdateState' (version, image, the attempt, revisions) and UpdateState.runningImages (the
         heartbeat's Update.runningImages).
    The job never runs a schema, data or settings step and never waits for an engine run.

.NOTES
    Inputs: the updater's environment (copied by Get-PimSecUpdateJobSpec) + PIM_SECUPDATE_UPDATER_JOB. PS 7 (the image).
#>
[CmdletBinding()] param()
$ErrorActionPreference = 'Stop'
function Say($m, $c = 'Gray') { Write-Host ("[secupdate] " + $m) -ForegroundColor $c }
$here    = Split-Path -Parent $PSCommandPath
$solRoot = Split-Path -Parent (Split-Path -Parent $here)
$shared  = Join-Path $solRoot 'engine\_shared'
if (-not (Test-Path -LiteralPath (Join-Path $shared 'PIM-SecUpdate.ps1'))) { Say "engine shared folder not found at '$shared'" 'Red'; exit 3 }
. (Join-Path $shared 'PIM-SecUpdate.ps1')
if (-not "$($env:IDENTITY_ENDPOINT)".Trim()) { Say 'REFUSED: no managed identity endpoint -- this entry runs inside a Container Apps job with its managed identity' 'Red'; exit 2 }
$miCid = "$($env:PIM_ManagedIdentityClientId)".Trim(); if ($miCid) { $global:PIM_ManagedIdentityClientId = $miCid }
$global:PIM_UseGraphSdk = $false; $global:PIM_UseManagedIdentity = $true
if ("$($env:PIM_SqlServer)".Trim()) { $global:PIM_SqlServer = "$($env:PIM_SqlServer)".Trim() }
if ("$($env:PIM_SqlDatabase)".Trim()) { $global:PIM_SqlDatabase = "$($env:PIM_SqlDatabase)".Trim() }
. (Join-Path $shared 'PIM-Rest.ps1')
. (Join-Path $shared 'PIM-SqlStore.ps1')
. (Join-Path $shared 'PIM-UpdateState.ps1')

# ---- 0. THE SETTING FIRST ----------------------------------------------------------------------------------------------
$cs = $null; try { $cs = Get-PimSqlConnectionString } catch { $cs = $null }
if (-not "$cs".Trim()) { Say 'no store -- the setting cannot be read, so the job is OFF this round' 'Yellow'; exit 0 }
$setting = $null; try { $setting = Get-PimSqlSetting -ConnectionString $cs -Name (Get-PimSecUpdateSettingName) } catch { $setting = $null }
$en = Test-PimSecUpdateEnabled -Value $setting
if (-not $en.enabled) { Say "$($en.reason) -- nothing done"; exit 0 }
Say $en.reason 'DarkGray'

. (Join-Path $shared 'PIM-ArmContainerApps.ps1')
. (Join-Path $shared 'PIM-AcrBuild.ps1')
. (Join-Path $shared 'PIM-RunningImages.ps1')
. (Join-Path $shared 'PIM-RegistryPrune.ps1')
. (Join-Path $shared 'PIM-UpdateLifecycle.ps1')   # Get-PimImageOnlyUpdateDecision (the updater's own image-only rule)
. (Join-Path $shared 'PIM-LicenceRequest.ps1')
. (Join-Path $shared 'PIM-InvardiaUpdate.ps1')

$sub = "$($env:PIM_SubscriptionId)".Trim(); $rg = "$($env:PIM_ResourceGroup)".Trim()
$managerApp = $(if ("$($env:PIM_ManagerApp)".Trim()) { "$($env:PIM_ManagerApp)".Trim() } else { 'ca-pim-manager' })
$container = "$($env:PIM_ManagerContainerName)".Trim()
$updJob = "$($env:PIM_SECUPDATE_UPDATER_JOB)".Trim()
$selfJob = $(if ("$($env:CONTAINER_APP_JOB_NAME)".Trim()) { "$($env:CONTAINER_APP_JOB_NAME)".Trim() } else { Get-PimSecUpdateJobName })
if (-not $sub -or -not $rg -or -not $updJob) { Say 'PIM_SubscriptionId / PIM_ResourceGroup / PIM_SECUPDATE_UPDATER_JOB are required -- refusing to guess' 'Red'; exit 2 }
$api = Get-PimSecUpdateAcaApiVersion
$rgPath = "/subscriptions/$sub/resourceGroups/$rg"
$prevState = $null; try { $ps0 = Get-PimSqlSetting -ConnectionString $cs -Name (Get-PimSecUpdateStateName); if ($ps0 -is [string] -and "$ps0".Trim()) { $ps0 = $ps0 | ConvertFrom-Json }; $prevState = $ps0 } catch { $prevState = $null }
function Save-SecState($rec) { try { Set-PimSqlSetting -ConnectionString $cs -Name (Get-PimSecUpdateStateName) -ValueJson ($rec | ConvertTo-Json -Depth 8 -Compress) } catch { Say "  state not recorded: $($_.Exception.Message)" 'Yellow' } }

# ---- 1. what runs, the customer freeze, and is the normal updater running? -------------------------------------------
$app = Get-PimAcaApp -SubscriptionId $sub -ResourceGroup $rg -Name $managerApp
if (-not $container -and @(@($app.properties.template.containers) | Where-Object { $_ }).Count -gt 1) { $mc = Get-PimAcaManagerContainer -App $app -ContainerName ''; if ($mc) { $container = "$($mc.name)" } }
$curImg = Get-PimAcaAppImage -App $app -ContainerName $container
$ref = Split-PimImageReference -Image "$curImg"
if (-not $ref -or -not "$($ref.tag)".Trim()) { Say "the web app's image ('$curImg') names no registry / version -- nothing built" 'Yellow'; exit 0 }
$running = "$($ref.tag)"
$updObj = Invoke-PimArm -Method GET -Path "$rgPath/providers/Microsoft.App/jobs/$updJob" -ApiVersion $api
$jobEnv = @{}; foreach ($e in @($updObj.properties.template.containers[0].env)) { if ($e -and "$($e.value)".Trim()) { $jobEnv["$($e.name)"] = "$($e.value)" } }
# 3.1.70 review F3: the customer freeze. PIM_UPDATE_HOLD is not copied into this job's spec, so it is read from the UPDATER's
# live environment: 1 = nothing built, nothing rolled.
$held = Test-PimSecUpdateHeld -JobEnv $jobEnv
if ($held.held) { Say "$($held.reason) -- nothing done" 'Yellow'; exit 0 }
# 3.1.70 review F2: the updater's executions, FAIL CLOSED (unreadable / Running with no start time = running). Read again
# immediately before the swap.
$readUpdater = {
    $ux = $null; $urd = $true
    try { $ux = @(Invoke-PimArm -Method GET -Path "$rgPath/providers/Microsoft.App/jobs/$updJob/executions" -ApiVersion $api -All) }
    catch { $urd = $false; Say "  the updater's executions could not be read ($((("$($_.Exception.Message)") -split "`n")[0])) -- treated as RUNNING" 'Yellow' }
    Test-PimSecUpdateExecutionsRunning -Executions $ux -Readable $urd
}
$updState = & $readUpdater

# ---- 2. what the ring serves (the updater's own pull; the watermark is the UPDATER job's, read live) ------------------
$ring = "$($jobEnv['PIM_UPDATE_RING'])".Trim(); $src = "$($jobEnv['PIM_UPDATE_SOURCE'])".Trim().ToLowerInvariant()
$community = ($src -eq 'invardia-community')
$invBase = ''; try { $invBase = "$(Get-PimSqlSetting -ConnectionString $cs -Name 'LicenceRequestBaseUrl')".Trim() } catch { }
$seq = Resolve-PimInvardiaAppliedSequence -JobEnv $jobEnv -Ring $ring -Kind $(if ($community) { 'community' } else { 'code' })
$pull = {
    param([string]$LastBuilt)
    if ($community) {
        return (Get-PimInvardiaCommunityTarget -BaseUrl $invBase -AppliedSequence ([int]$seq.applied) -RunningVersion $running -LastBuiltVersion $LastBuilt -Ring $ring -HighestKnownVersion $running)
    }
    $lic = ConvertTo-PimInvardiaLicenceText -Value (Get-PimSqlSetting -ConnectionString $cs -Name 'License')
    $key = Resolve-PimInvardiaInstallKey -GetSetting { param($n) Get-PimSqlSetting -ConnectionString $cs -Name $n }
    $iid = ''; if (Get-Command Resolve-PimInvardiaInstallId -ErrorAction SilentlyContinue) { $iid = Resolve-PimInvardiaInstallId -GetSetting { param($n) Get-PimSqlSetting -ConnectionString $cs -Name $n } }
    return (Get-PimInvardiaUpdateTarget -Http { param($m, $u, $b, $h) Invoke-PimLicenceHttp -Method $m -Url $u -Body $b -Headers $h } `
        -InstallKey $key -InstallId $iid -LicenceText $lic -BaseUrl $invBase -AppliedSequence ([int]$seq.applied) -RunningVersion $running `
        -LastBuiltVersion $LastBuilt -Ring $ring -UnprovenLegacySequence ([int]$seq.unprovenLegacy) -HighestKnownVersion $running)
}
$ringVer = ''; $t0 = $null
if ($src -notin @('invardia', 'invardia-community')) { Say "the updater's source is '$src' -- only a signed Invardia release is built here" 'Yellow' }
else {
    # LastBuilt = the running version: when the ring serves it, nothing is downloaded on this first read
    try { $t0 = & $pull $running; if ($t0.ok -and -not $t0.hold -and -not $t0.ahead) { $ringVer = "$($t0.version)".Trim() }; Say "ring $ring`: $($t0.reason)" 'DarkGray' }
    catch { Say "ring $ring could not be read: $($_.Exception.Message)" 'Yellow' }
}

# ---- 3. the decision (Invardia 2026-11-26: ONLY a <build>.N on this install's ring is built; no rebuild on a new Microsoft
#         base -- that would skip the rings 0/1 proof) ---------------------------------------------------------------------
$dec = Get-PimSecUpdateDecision -RunningVersion $running -RingVersion $ringVer -State $prevState -UpdaterRunning ([bool]$updState.running) -Hold ([bool]$held.held)
Say "$($dec.action)$(if ($dec.kind) { " ($($dec.kind))" }): $($dec.reason)" $(if ($dec.action -eq 'build') { 'Cyan' } else { 'DarkGray' })
if ($dec.action -ne 'build') { if ($t0 -and "$($t0.contextPath)".Trim()) { Remove-Item -LiteralPath "$($t0.contextPath)" -Force -ErrorAction SilentlyContinue }; exit 0 }
if (-not ($src -in @('invardia', 'invardia-community'))) { Say 'no signed source to build from -- nothing built' 'Yellow'; exit 0 }

# ---- 4. the source (signed archive), built AS THE RELEASE PINS IT, to the release's OWN tag, in the install registry ----
$ver = "$($dec.version)"
if (-not $ver -or $ver -ieq $running) { Say "the target '$ver' is the running tag -- the running tag is never overwritten; nothing built" 'Red'; exit 1 }
# the first read already downloaded it when the ring serves another version than the running one
$t = if ($t0 -and "$($t0.version)" -eq $ver -and "$($t0.contextPath)".Trim()) { $t0 } else { & $pull '' }
if (-not $t.ok -or "$($t.version)" -ne $ver -or -not "$($t.contextPath)".Trim()) { Save-SecState (New-PimSecUpdateStateRecord -Previous $prevState -AttemptOnly -Kind $dec.kind -Ok $false -Reason "source not fetched: $($t.reason)" -AttemptVersion $ver); Say "  source for $ver not fetched: $($t.reason)" 'Red'; exit 1 }
$ctx = "$($t.contextPath)"
$reg = $ref.registryName; $repo = $ref.repository
try {
    $pool = "$($jobEnv['PIM_ACR_AGENT_POOL'])".Trim()
    Say "building $repo`:$ver in $reg with the bases the release names$(if ($pool) { " (agent pool $pool)" })"
    $b = Invoke-PimAcrRestBuildWithRetry -SubscriptionId $sub -ResourceGroup $rg -RegistryName $reg -ContextPath $ctx -ImageNames @("$repo`:$ver") -AgentPoolName $pool -OnPoll { param($s) Say "  build $s" 'DarkGray' }
    if (-not $b.ok) { Save-SecState (New-PimSecUpdateStateRecord -Previous $prevState -AttemptOnly -Kind $dec.kind -Ok $false -Reason "build $($b.status): $($b.detail)" -AttemptVersion $ver); Say "  BUILD $($b.status) after $($b.seconds)s -- nothing rolled" 'Red'; exit 1 }
    Say "  built in $($b.seconds)s (run $($b.runId))" 'Green'
} catch {
    Save-SecState (New-PimSecUpdateStateRecord -Previous $prevState -AttemptOnly -Kind $dec.kind -Ok $false -Reason "build stopped: $((("$($_.Exception.Message)") -split "`n")[0])" -AttemptVersion $ver)
    Say "  the build stopped: $($_.Exception.Message) -- nothing rolled" 'Red'; exit 1
} finally { Remove-Item -LiteralPath $ctx -Force -ErrorAction SilentlyContinue }

# ---- 4b. 3.1.70 review F2 -- THE LAST LOOK before anything moves: the updater not running (a FRESH read, fail closed) and the
#          web app still on the image this execution started from. Otherwise abort, record it, exit 0 (nothing moved).
$img2 = ''; try { $img2 = Get-PimAcaAppImage -App (Get-PimAcaApp -SubscriptionId $sub -ResourceGroup $rg -Name $managerApp) -ContainerName $container } catch { $img2 = '' }
$pre = Get-PimSecUpdatePreSwapVerdict -StartImage $curImg -CurrentImage $img2 -Updater (& $readUpdater) -TargetVersion $ver -RunningVersion $running
if (-not $pre.go) {
    Save-SecState (New-PimSecUpdateStateRecord -Previous $prevState -AttemptOnly -Kind $dec.kind -Ok $false -Reason "aborted before the swap: $($pre.reason)" -AttemptVersion $ver)
    Say "  NOT SWAPPED: $($pre.reason)" 'Yellow'; exit 0
}

# ---- 5. the swap, WRAPPED (3.1.70 review F4): the web app (health-checked, rolled back by the roll itself), every job / app
#         on the repository (no execution is stopped). ANY failure puts the previous image back on what was moved and records
#         the failed attempt (the 60-min retry guard then applies). ----------------------------------------------------------
$target = "$($ref.loginServer)/$($ref.repository):$ver"
$health = {
    $rev = Get-PimAcaActiveRevision -SubscriptionId $sub -ResourceGroup $rg -Name $managerApp
    if (-not $rev) { return $false }
    ("$($rev.properties.runningState)" -notmatch '(?i)^(Failed|Degraded)$')
}
$failed = New-Object System.Collections.Generic.List[string]
$moved = New-Object System.Collections.Generic.List[object]   # @{ kind = 'app' | 'job'; name; from; container }
$swapErr = $null; $roll = $null
try {
    $roll = Invoke-PimAcaRoll -SubscriptionId $sub -ResourceGroup $rg -Name $managerApp -Image $target -ContainerName $container -HealthCheck $health
    if ($roll.rolled -and $roll.healthy -eq $false) { throw "the web app was UNHEALTHY on $target (the roll's own rollback: $($roll.rolledBack))" }
    if (-not $roll.rolled -and "$($roll.reason)" -notmatch 'already on this image') { throw "the web app did NOT roll: $($roll.reason)" }
    if ($roll.rolled) { $moved.Add(@{ kind = 'app'; name = $managerApp; from = $curImg; container = $container }) }
    Say "  $managerApp on $target (healthy)" 'Green'
    foreach ($kind in @('jobs', 'containerApps')) {
        try {
            $all = @(Invoke-PimArm -Method GET -Path "$rgPath/providers/Microsoft.App/$kind" -ApiVersion $api -All)
            $plan = Get-PimAcaJobRollPlan -Jobs $all -TargetImage $target -Exclude @($managerApp, $selfJob)
            foreach ($r in @($plan.roll)) {
                if (Test-PimAcaRollNoop -From "$($r.from)" -TargetImage $target) { continue }
                try {
                    if ($kind -eq 'jobs') { [void](Invoke-PimArmBusyRetry -NetworkWaits @(5, 15, 30) -Write { Set-PimAcaJobImage -SubscriptionId $sub -ResourceGroup $rg -Name $r.name -Image $target }) }
                    else { [void](Invoke-PimArmBusyRetry -NetworkWaits @(5, 15, 30) -Write { Set-PimAcaAppImage -SubscriptionId $sub -ResourceGroup $rg -Name $r.name -Image $target }) }
                    $moved.Add(@{ kind = $(if ($kind -eq 'jobs') { 'job' } else { 'app' }); name = "$($r.name)"; from = "$($r.from)"; container = '' })
                    Say "  $($r.name): on the new image (a running execution keeps its image)" 'DarkGray'
                } catch { $failed.Add($r.name); Say "  $($r.name) NOT moved: $($_.Exception.Message)" 'Yellow' }
            }
        } catch { $failed.Add("<$kind enumeration>"); Say "  could not list the $kind`: $($_.Exception.Message)" 'Yellow' }
    }
} catch { $swapErr = $_ }
if ($swapErr) {
    $why = (("$($swapErr.Exception.Message)") -split "`n")[0]
    Say "  the swap FAILED: $why -- putting the previous image back on what was moved" 'Red'
    $back = New-Object System.Collections.Generic.List[string]; $notBack = New-Object System.Collections.Generic.List[string]
    # the web app: whatever the failed step left, it ends on the image this execution started from
    if (-not @($moved | Where-Object { $_.name -ieq $managerApp }).Count) {
        $nowImg = ''; try { $nowImg = Get-PimAcaAppImage -App (Get-PimAcaApp -SubscriptionId $sub -ResourceGroup $rg -Name $managerApp) -ContainerName $container } catch { $nowImg = '' }
        if ($nowImg -and $nowImg -ine $curImg) { $moved.Insert(0, @{ kind = 'app'; name = $managerApp; from = $curImg; container = $container }) }
    }
    $mv = @($moved.ToArray()); [array]::Reverse($mv)
    foreach ($m in $mv) {
        try {
            if ($m.kind -eq 'job') { [void](Set-PimAcaJobImage -SubscriptionId $sub -ResourceGroup $rg -Name $m.name -Image $m.from) }
            elseif ($m.name -ieq $managerApp) { [void](Set-PimAcaAppImage -SubscriptionId $sub -ResourceGroup $rg -Name $m.name -Image $m.from -ContainerName $m.container) }
            else { [void](Set-PimAcaAppImage -SubscriptionId $sub -ResourceGroup $rg -Name $m.name -Image $m.from) }
            $back.Add($m.name)
        } catch { $notBack.Add($m.name); Say "  $($m.name) could NOT be put back on $($m.from): $($_.Exception.Message)" 'Red' }
    }
    Save-SecState (New-PimSecUpdateStateRecord -Previous $prevState -AttemptOnly -Kind $dec.kind -Ok $false -AttemptVersion $ver `
        -Reason ("swap failed: $why; put back: $(if ($back.Count) { $back -join ', ' } else { 'nothing was moved' })$(if ($notBack.Count) { "; NOT put back: $($notBack -join ', ')" })"))
    Say "  put back: $(if ($back.Count) { $back -join ', ' } else { 'nothing was moved' })$(if ($notBack.Count) { "; NOT put back: $($notBack -join ', ')" })" $(if ($notBack.Count) { 'Red' } else { 'Yellow' })
    exit 1
}
# Single + ONE active revision on PIM's OWN apps (framework SEC-PATCH-PIPELINE-1 item 6; 3.1.70 review F1: the Manager and an
# app on the Manager's repository -- any other app in the resource group is never read or changed, only counted). The SAME
# check as the updater's last step (engine/_shared/PIM-RevisionMode.ps1 Invoke-PimRevisionModeCheck: readiness guard, secrets
# kept by Set-PimArmAcaAppConfiguration, read back) -- one implementation, one Update.revisions shape for the heartbeat.
. (Join-Path $shared 'PIM-RevisionMode.ps1')
. (Join-Path $shared 'PIM-ArmSetup.ps1')
$revReport = $null
try {
    $rvApps = @(Invoke-PimArm -Method GET -Path "$rgPath/providers/Microsoft.App/containerApps" -ApiVersion $api -All | Where-Object { $_ })
    if ($rvApps.Count) {
        $rvFix = $null
        if ("$($env:PIM_UPDATE_NO_REVISION_FIX)".Trim() -ne '1') {
            # 3.1.71 review K1: the same write removes a stale rollback pin marker (only sent when the app carries one)
            $rvFix = { param($App) [void](Set-PimArmAcaAppConfiguration -SubscriptionId $sub -ResourceGroup $rg -Name "$($App.name)" -Mutate { param($c) Set-PimRevisionModeSingleConfig -Configuration $c } -MutateTags { param($t) Remove-PimRollbackPinTag -Tags $t }) }
        }
        $rvRes = Invoke-PimRevisionModeCheck -Apps $rvApps -ManagerApp $managerApp -ManagerImage $target `
                    -ListRevisions { param($App) @(Invoke-PimArm -Method GET -Path "$($App.id)/revisions" -ApiVersion $api -All) } `
                    -Fix $rvFix `
                    -ReadApp { param($App) Invoke-PimArm -Method GET -Path "$($App.id)" -ApiVersion $api } `
                    -Deactivate $(if ($rvFix) { { param($App, $Name) [void](Invoke-PimArm -Method POST -Path "$($App.id)/revisions/$Name/deactivate" -ApiVersion $api -Body @{}) } } else { $null }) `
                    -Log { param($l) Say "  revisions: $l" $(if ("$l" -match 'could not|reads back|not changed|not single') { 'Yellow' } else { 'DarkGray' }) }
        $revReport = $rvRes.fact
    }
} catch { Say "  revisions not checked: $((("$($_.Exception.Message)") -split "`n")[0])" 'Yellow' }
# itself LAST (its next execution runs the new image)
try { [void](Set-PimAcaJobImage -SubscriptionId $sub -ResourceGroup $rg -Name $selfJob -Image $target) }
catch { $failed.Add($selfJob); Say "  $selfJob (itself) NOT moved: $($_.Exception.Message)" 'Yellow' }

# ---- 6. record -----------------------------------------------------------------------------------------------------
Save-SecState (New-PimSecUpdateStateRecord -Previous $prevState -Version $ver -Image $target -Kind $dec.kind -Ok (-not $failed.Count) -Reason $(if ($failed.Count) { "not moved: $($failed -join ', ')" } else { 'swapped' }) -Revisions $revReport)
try {
    $us = Read-PimUpdateState -ConnectionString $cs
    if ($us -and -not ($us -is [string])) {
        $res = @(Get-PimRegistryPruneResources -SubscriptionId $sub -ResourceGroup $rg -ApiVersion $api | Where-Object { "$($_.name)" -notmatch ' revision ' })
        $ri = @(Get-PimRunningImages -Resources $res -Resolve { param($i) Resolve-PimRegistryImage -Image $i })
        if ($ri.Count -or $null -ne $revReport) {
            $h = [ordered]@{}; foreach ($p in $us.PSObject.Properties) { $h[$p.Name] = $p.Value }
            if ($ri.Count) { $h['runningImages'] = @($ri) }
            if ($null -ne $revReport) { $h['revisions'] = $revReport }   # the heartbeat's Update.revisions (same key as the updater writes)
            [void](Save-PimUpdateState -ConnectionString $cs -Record ([pscustomobject]$h))
        }
    }
} catch { Say "  running images not recorded: $($_.Exception.Message)" 'DarkGray' }
Say "done: $ver ($($dec.kind))$(if ($failed.Count) { "; NOT moved: $($failed -join ', ')" }); revisions single=$(if ($null -ne $revReport) { $revReport.single } else { 'unread' })" $(if ($failed.Count) { 'Yellow' } else { 'Green' })
exit $(if ($failed.Count) { 1 } else { 0 })
