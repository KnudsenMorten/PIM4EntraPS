#Requires -Version 5.1
<#
.SYNOPSIS
    POST-ROLL SAFETY NET (PIM REQUIREMENTS 100.20; framework DOCS/REQUIREMENTS.md 12.1 SPEED RULE item 2): after a Manager
    roll, run the hosted smoke; on RED roll the Manager back to the last-good image and report what happened.

.DESCRIPTION
    Owner 2026-10-09: the release gate is small now ("only what the change touches"), so "the safety net moves AFTER
    deploy: every ring-1 roll runs the hosted smoke test automatically and rolls back to the last-good image on red".

      1. read the Manager's live image (az containerapp show, explicit --subscription);
         -IfChanged: stop here when it is the image this script already checked (state file) -- a scheduled watcher
         therefore smokes every roll exactly once, whoever rolled it (the in-cloud updater at 03:00, Update-PimContainers,
         Release-PimFix);
      2. run tests\live\Test-PimManagerHostedSmoke.ps1 -AsReleaseGate -ExpectedVersion <the image's version> (a smoke
         that could not RUN is red here, never a pass);
      3. GREEN -> record the image as this environment's smoke-proven image; outcome 'ok', exit 0;
      4. RED -> the rollback anchor: PIM_UPDATE_LAST_GOOD on the update job (what the updater recorded as last-known-good
         before it moved), else the last image THIS script proved green here. No anchor, or the anchor IS the broken
         image -> outcome 'red-no-rollback' (say so loudly), exit 1;
      5. roll the Manager to the anchor (az containerapp update --image), read the image back, hold the updater
         (PIM_UPDATE_HOLD=1, so the next run does not re-roll the broken version; -NoHold to skip), smoke the rolled-back
         Manager once more (reported, not gating); outcome 'rolled-back', exit 1 -- the release is still RED.
    Every outcome is written as JSON (-OutcomeFile, default <StateDir>\<env>-last-outcome.json) and appended to
    <StateDir>\outcomes.jsonl; the console line starts with POST-ROLL so a log reader finds it.

    No PowerShell modules: az CLI + the smoke script. -WhatIf prints the plan (no smoke, no roll, nothing written).
    -SmokeCommand / -AzCommand are test seams (tests\Test-PimFastRelease.ps1 drives a red smoke with stubs).
.EXAMPLE
    .\tools\setup\Invoke-PimPostRollSmoke.ps1 -Environment internal -SubscriptionId <sub> -ResourceGroup <rg> -IfChanged
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$Environment = '',
    [string]$SubscriptionId = '',
    [string]$ResourceGroup = '',
    # The watcher form (Register-PimFastReleaseTasks.ps1): a JSON list of { name, subscriptionId, resourceGroup,
    # azureConfigDir?, managerApp?, updateJob?, easyAuthAud? } -- each checked in its own process, worst exit wins.
    [string]$EnvironmentsFile = '',
    [string]$ManagerApp = 'ca-pim-manager',
    [string]$UpdateJob = 'ca-pim-update',
    [string]$ExpectedVersion = '',
    [string]$EasyAuthAud = '',
    [string]$StateDir = $(Join-Path $env:ProgramData 'pim\postroll'),
    [string]$OutcomeFile = '',
    [switch]$IfChanged,
    [switch]$NoRollback,
    [switch]$NoHold,
    [scriptblock]$SmokeCommand = $null,     # test seam: param($SmokeArgs) -> exit code
    [scriptblock]$AzCommand = $null         # test seam: receives the az argument list, returns its output
)
$ErrorActionPreference = 'Stop'
if ($EnvironmentsFile) {
    $list = @(Get-Content -LiteralPath $EnvironmentsFile -Raw | ConvertFrom-Json | ForEach-Object { $_ })
    $worst = 0
    foreach ($e in $list) {
        $a = @('-NoProfile', '-File', $PSCommandPath, '-Environment', "$($e.name)", '-SubscriptionId', "$($e.subscriptionId)", '-ResourceGroup', "$($e.resourceGroup)", '-StateDir', $StateDir)
        foreach ($k in 'managerApp', 'updateJob', 'easyAuthAud') { if ("$($e.$k)".Trim()) { $a += @(('-' + $k), "$($e.$k)") } }
        if ($IfChanged) { $a += '-IfChanged' }; if ($NoHold) { $a += '-NoHold' }; if ($NoRollback) { $a += '-NoRollback' }; if ($WhatIfPreference) { $a += '-WhatIf' }
        $prev = $env:AZURE_CONFIG_DIR
        if ("$($e.azureConfigDir)".Trim()) { $env:AZURE_CONFIG_DIR = "$($e.azureConfigDir)" }
        try { & pwsh @a | Out-Host; $c = $LASTEXITCODE } finally { $env:AZURE_CONFIG_DIR = $prev }
        if ($c -gt $worst) { $worst = $c }
    }
    exit $worst
}
if (-not $Environment -or -not $SubscriptionId -or -not $ResourceGroup) { throw 'Invoke-PimPostRollSmoke: -Environment, -SubscriptionId and -ResourceGroup are required (or -EnvironmentsFile)' }
$sol = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$smokePath = Join-Path $sol 'tests\live\Test-PimManagerHostedSmoke.ps1'
$clock = [Diagnostics.Stopwatch]::StartNew()
function Invoke-PrAz {
    $a = @($args | ForEach-Object { "$_" })
    if ($AzCommand) { $o = & $AzCommand @a; $script:AzExit = 0; return $o }
    $o = & az @a 2>$null; $script:AzExit = $LASTEXITCODE; return $o
}
function Get-ImageVersion([string]$img) { if ("$img" -match ':(\d+\.\d+\.\d+)(?:[^\d]|$)') { return $Matches[1] }; return '' }
$safeEnv = ($Environment -replace '[^A-Za-z0-9_.-]', '_')
$statePath = Join-Path $StateDir "$safeEnv-state.json"
if (-not $OutcomeFile) { $OutcomeFile = Join-Path $StateDir "$safeEnv-last-outcome.json" }
$sub = @('--subscription', $SubscriptionId)
$out = [ordered]@{ environment = $Environment; utc = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'); app = $ManagerApp
                   image = ''; version = ''; smokeExit = $null; outcome = ''; rolledBackTo = ''; rollbackSmokeExit = $null; held = $false; message = '' }
function Save-Outcome {
    if ($WhatIfPreference) { return }
    $out.seconds = [Math]::Round($clock.Elapsed.TotalSeconds, 1)
    New-Item -ItemType Directory -Force -Path $StateDir | Out-Null
    $j = $out | ConvertTo-Json -Depth 4
    [IO.File]::WriteAllText($OutcomeFile, $j, [Text.UTF8Encoding]::new($false))
    [IO.File]::AppendAllText((Join-Path $StateDir 'outcomes.jsonl'), (($out | ConvertTo-Json -Depth 4 -Compress) + "`n"), [Text.UTF8Encoding]::new($false))
}
function Say([string]$m, [string]$c = 'Gray') { Write-Host "POST-ROLL [$Environment] $m" -ForegroundColor $c }

# ---- 1. the live image ----------------------------------------------------------------------------------------------
$img = "$(@(Invoke-PrAz containerapp show @sub -g $ResourceGroup -n $ManagerApp --query 'properties.template.containers[0].image' -o tsv) | Select-Object -First 1)".Trim()
if (-not $img) { $out.outcome = 'not-run'; $out.message = "could not read the image of $ManagerApp in $ResourceGroup (az context / names)"; Say $out.message 'Red'; Save-Outcome; exit 2 }
$out.image = $img
$ver = if ("$ExpectedVersion".Trim()) { "$ExpectedVersion".Trim() } else { Get-ImageVersion $img }
$out.version = $ver
$state = $null
if (Test-Path -LiteralPath $statePath) { try { $state = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json } catch { $state = $null } }
if ($IfChanged -and $state -and "$($state.lastCheckedImage)" -eq $img) {
    Say "image unchanged since the last check ($img) -- nothing to do" 'DarkGray'
    exit 0
}
Say "live image $img (version '$ver')" 'Cyan'
if (-not $PSCmdlet.ShouldProcess("$ManagerApp in $ResourceGroup", "hosted smoke; roll back to the last-good image on red")) {
    Say "plan: smoke $smokePath -AsReleaseGate -ExpectedVersion $ver; red -> roll $ManagerApp to PIM_UPDATE_LAST_GOOD of $UpdateJob (else the last smoke-proven image), hold the updater, re-smoke" 'Yellow'
    exit 0
}

# ---- 2. the hosted smoke --------------------------------------------------------------------------------------------
$smokeArgs = @{ App = $ManagerApp; ResourceGroup = $ResourceGroup; SubscriptionId = $SubscriptionId; AsReleaseGate = $true }
if ($ver) { $smokeArgs['ExpectedVersion'] = $ver }
if ("$EasyAuthAud".Trim()) { $smokeArgs['EasyAuthAud'] = "$EasyAuthAud".Trim() }
function Invoke-Smoke($a) {
    if ($SmokeCommand) { return [int](& $SmokeCommand $a) }
    if (-not (Test-Path -LiteralPath $smokePath)) { Say "the smoke is missing: $smokePath" 'Red'; return 3 }
    & $smokePath @a | Out-Host
    return [int]$LASTEXITCODE
}
$code = Invoke-Smoke $smokeArgs
$out.smokeExit = $code
$newState = [ordered]@{ lastCheckedImage = $img; lastGoodImage = $(if ($state) { "$($state.lastGoodImage)" } else { '' }); utc = $out.utc }
if ($code -eq 0) {
    $newState.lastGoodImage = $img
    New-Item -ItemType Directory -Force -Path $StateDir | Out-Null
    [IO.File]::WriteAllText($statePath, ($newState | ConvertTo-Json), [Text.UTF8Encoding]::new($false))
    $out.outcome = 'ok'; $out.message = "hosted smoke GREEN on $ver"
    Say $out.message 'Green'; Save-Outcome; exit 0
}
Say "hosted smoke RED (exit $code) on $img" 'Red'

# ---- 3. the rollback anchor -----------------------------------------------------------------------------------------
$anchor = ''; $anchorFrom = ''
try {
    $jobJson = (@(Invoke-PrAz containerapp job show @sub -g $ResourceGroup -n $UpdateJob -o json) -join "`n")
    if ("$jobJson".Trim()) {
        $job = $jobJson | ConvertFrom-Json
        foreach ($c in @($job.properties.template.containers)) { foreach ($e in @($c.env)) { if ("$($e.name)" -eq 'PIM_UPDATE_LAST_GOOD' -and "$($e.value)".Trim()) { $anchor = "$($e.value)".Trim(); $anchorFrom = "PIM_UPDATE_LAST_GOOD on $UpdateJob" } } }
    }
} catch { Say "could not read $UpdateJob ($($_.Exception.Message))" 'Yellow' }
if ((-not $anchor -or $anchor -eq $img) -and $state -and "$($state.lastGoodImage)".Trim() -and "$($state.lastGoodImage)" -ne $img) { $anchor = "$($state.lastGoodImage)".Trim(); $anchorFrom = 'the last image this check proved green here' }
New-Item -ItemType Directory -Force -Path $StateDir | Out-Null
[IO.File]::WriteAllText($statePath, ($newState | ConvertTo-Json), [Text.UTF8Encoding]::new($false))
if ($NoRollback) { $out.outcome = 'red-no-rollback'; $out.message = "smoke red; -NoRollback: left on $img"; Say $out.message 'Red'; Save-Outcome; exit 1 }
if (-not $anchor -or $anchor -eq $img) {
    $out.outcome = 'red-no-rollback'
    $out.message = "smoke red and NO rollback anchor (PIM_UPDATE_LAST_GOOD empty or the broken image itself, no smoke-proven image here) -- ROLL BACK BY HAND"
    Say $out.message 'Red'; Save-Outcome; exit 1
}

# ---- 4. roll back, read back, hold, re-smoke ------------------------------------------------------------------------
Say "rolling $ManagerApp back to $anchor ($anchorFrom)" 'Yellow'
[void](Invoke-PrAz containerapp update @sub -g $ResourceGroup -n $ManagerApp --image $anchor -o none)
$back = "$(@(Invoke-PrAz containerapp show @sub -g $ResourceGroup -n $ManagerApp --query 'properties.template.containers[0].image' -o tsv) | Select-Object -First 1)".Trim()
if ($back -ne $anchor) {
    $out.outcome = 'rollback-failed'; $out.message = "smoke red; rollback to $anchor did not take (live image now '$back') -- ROLL BACK BY HAND"
    Say $out.message 'Red'; Save-Outcome; exit 1
}
$out.rolledBackTo = $anchor
if (-not $NoHold) {
    [void](Invoke-PrAz containerapp job update @sub -g $ResourceGroup -n $UpdateJob --set-env-vars 'PIM_UPDATE_HOLD=1' -o none)
    $out.held = ($script:AzExit -eq 0)
}
$rb = @{} + $smokeArgs; $bv = Get-ImageVersion $anchor; if ($bv) { $rb['ExpectedVersion'] = $bv } else { $rb.Remove('ExpectedVersion') }
$out.rollbackSmokeExit = Invoke-Smoke $rb
$out.outcome = 'rolled-back'
$out.message = ("smoke red on {0}; Manager rolled back to {1} ({2}); smoke after rollback exit {3}; updater {4}" -f $ver, $anchor, $anchorFrom, $out.rollbackSmokeExit, $(if ($out.held) { 'HELD (PIM_UPDATE_HOLD=1 -- clear it when the fix is released)' } else { 'not held' }))
Say $out.message 'Yellow'
Save-Outcome
exit 1
