#Requires -Version 5.1
<#
.SYNOPSIS
    ONE command that takes an environment from "needs someone to build for it" to "updates itself
    every night". §55.

.DESCRIPTION
    An environment becomes self-sufficient in three moves, and doing them by hand is how one gets
    forgotten:

      1. BOOTSTRAP BUILD -- the update job's OWN image must contain the self-update code before it
         can build anything, so the very first image still comes from here. Exactly once per
         environment, ever. Skipped when that tag is already in the registry.
      2. ARM -- install/refresh `ca-pim-update` with the source URL and the approved version.
      3. RUN -- start it once and watch, because "installed" is not "working" and the difference
         only shows when it runs.

    After this, that environment fetches source, builds its own image in its own registry, and rolls
    itself -- nightly, with no build host, no `az` CLI and nobody present.

    🪤 STEP 1 IS THE ONLY THING THAT CANNOT BOOTSTRAP ITSELF. A job running last month's image runs
    last month's updater, which does not know how to build. That is why this exists as a command
    rather than a note in a runbook: the one manual step should be one command, run once.

.PARAMETER Version
    The version to become self-updating ON. Defaults to this tree's VERSION.

.PARAMETER SourceUrlTemplate
    Where this environment fetches source, with {version} in it. From Publish-PimSourceArchive.ps1.
    Falls back to $env:PIM_UPDATE_SOURCE_URL.

.EXAMPLE
    .\Enable-PimSelfUpdate.ps1 -SubscriptionId <sub> -ResourceGroup <rg> -EnvName cae-pim `
        -AcrName <acr> -SourceUrlTemplate 'https://<store>/pim-src/pim-src-{version}.tar.gz?<sas>'

.EXAMPLE
    .\Enable-PimSelfUpdate.ps1 -SubscriptionId <sub> -ResourceGroup <rg> -EnvName cae-pim `
        -AcrName <acr> -Cron '40 3 * * *' -NoRun
    Arm it for 03:40 UTC without running it now.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$SubscriptionId,
    [Parameter(Mandatory)][string]$ResourceGroup,
    [Parameter(Mandatory)][string]$EnvName,
    [Parameter(Mandatory)][string]$AcrName,
    [string]$Version,
    [string]$SourceUrlTemplate = "$($env:PIM_UPDATE_SOURCE_URL)",
    [string]$ImageRepo   = 'pim-manager',
    [string]$JobName     = 'ca-pim-update',
    [string]$ManagerApp  = 'ca-pim-manager',
    [string]$TickJobName = 'ca-pim-tick',
    [string]$Cron        = '0 3 * * *',
    [string]$RegistryIdentityResourceId,
    # 2026-09-13 -- the update ring (see Deploy-PimUpdateJob). Forwarded ONLY when passed, so arming an
    # existing environment keeps its ring; a new updater gets the default ring 2.
    [ValidateRange(0,3)][int]$UpdateRing = 2,
    [switch]$NoRun,
    [int]$RunTimeoutSeconds = 900
)
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $PSCommandPath
. (Join-Path $here '_PimAz.ps1')

function Step($m) { Write-Host "==> $m" -ForegroundColor Cyan }
function Note($m) { Write-Host "    $m" -ForegroundColor DarkGray }
function Warn($m) { Write-Host "    $m" -ForegroundColor Yellow }
function Fail($m) { Write-Host "    $m" -ForegroundColor Red }

$solRoot = (Resolve-Path (Join-Path $here '..\..')).Path
if (-not "$Version".Trim()) {
    $vf = Join-Path $solRoot 'VERSION'
    if (-not (Test-Path -LiteralPath $vf)) { throw "Enable-PimSelfUpdate: no -Version and no VERSION file at '$vf'." }
    $Version = (Get-Content -LiteralPath $vf -Raw).Trim()
}
$sub = @('--subscription', $SubscriptionId)

Write-Host "`n=== Make $ResourceGroup self-updating (on $Version) ===" -ForegroundColor Cyan
Note "registry   $AcrName"
Note "cron       $Cron (UTC)"
if ("$SourceUrlTemplate".Trim()) {
    # 🪤 NEVER PRINT THE URL. It carries a SAS -- a credential -- and this output ends up in
    # transcripts, screenshots and support threads. Say enough to confirm the right one is set.
    $shown = ("$SourceUrlTemplate".Trim() -split '\?')[0]
    Note "source     $shown?<read-sas withheld>"
} else {
    Fail 'no -SourceUrlTemplate and no $env:PIM_UPDATE_SOURCE_URL.'
    Fail 'Without a source this environment can only ROLL images somebody else builds -- which is'
    Fail 'the very thing this command exists to end. Publish one with Publish-PimSourceArchive.ps1.'
    exit 2
}

# ---- 1. bootstrap build (once per environment, ever) --------------------------------------------
# 🪤 LIST THE TAGS, never `acr repository show --image`: "not there yet" is the normal answer on a
# first run, and that form prints an ERROR for it -- teaching the reader to ignore errors on a
# command that is working correctly.
Step "is $ImageRepo`:$Version already in $AcrName?"
$tags = @(az acr repository show-tags @sub -n $AcrName --repository $ImageRepo -o tsv 2>$null) |
        ForEach-Object { "$_".Trim() } | Where-Object { $_ }
if (@($tags) -contains $Version) {
    Note 'yes -- skipping the bootstrap build'
} else {
    Step "bootstrap build $ImageRepo`:$Version (the ONE build this environment will ever need from here)"
    $bld = Join-Path $here 'Build-PimManagerImage.ps1'
    if (-not (Test-Path $bld)) { throw "Enable-PimSelfUpdate: builder not found at '$bld'." }
    if ($PSCmdlet.ShouldProcess("$ImageRepo`:$Version", 'az acr build')) {
        $global:LASTEXITCODE = 0
        & $bld -ImageTag $Version -AcrName $AcrName -ImageRepo $ImageRepo -SubscriptionId $SubscriptionId | Out-Host
        if ($LASTEXITCODE -and $LASTEXITCODE -ne 0) { throw "Enable-PimSelfUpdate: the bootstrap build FAILED (exit $LASTEXITCODE)." }
    }
    # 🔴 READ IT BACK. A build that reported success and pushed nothing leaves a job pointed at an
    # image that does not exist, whose executions then report "Unknown" and log nothing at all --
    # the §55 defect that cost two rounds of diagnosis at a live customer.
    $tags2 = @(az acr repository show-tags @sub -n $AcrName --repository $ImageRepo -o tsv 2>$null) |
             ForEach-Object { "$_".Trim() } | Where-Object { $_ }
    if (-not ($PSCmdlet.ShouldProcess($AcrName, 'verify') -eq $false) -and -not (@($tags2) -contains $Version) -and -not $WhatIfPreference) {
        throw "Enable-PimSelfUpdate: '$ImageRepo`:$Version' is STILL not in $AcrName after the build."
    }
    Note 'built + verified present'
}

# ---- 2. arm ------------------------------------------------------------------------------------
Step "arm $JobName on $Version, with a source"
$upj = Join-Path $here 'Deploy-PimUpdateJob.ps1'
if (-not (Test-Path $upj)) { throw "Enable-PimSelfUpdate: update-job deployer not found at '$upj'." }
$upArgs = @{
    SubscriptionId = $SubscriptionId; ResourceGroup = $ResourceGroup; EnvName = $EnvName
    AcrName = $AcrName; ImageRepo = $ImageRepo; ImageTag = $Version
    JobName = $JobName; ManagerApp = $ManagerApp; TickJobName = $TickJobName; Cron = $Cron
    TargetVersion = $Version; SourceUrlTemplate = "$SourceUrlTemplate".Trim()
    # The bootstrap build above guarantees $Version is in the registry, so it is what this environment
    # last built: its first run rolls instead of rebuilding.
    LastBuiltVersion = $Version
}
if ("$RegistryIdentityResourceId".Trim()) { $upArgs['RegistryIdentityResourceId'] = $RegistryIdentityResourceId }
if ($PSBoundParameters.ContainsKey('UpdateRing')) { $upArgs['UpdateRing'] = $UpdateRing }
$global:LASTEXITCODE = 0
& $upj @upArgs | Out-Host
if ($LASTEXITCODE -and $LASTEXITCODE -ne 0) { throw "Enable-PimSelfUpdate: arming '$JobName' FAILED (exit $LASTEXITCODE)." }

if ($NoRun) {
    Write-Host "`n==> Armed. It will run $Cron (UTC)." -ForegroundColor Green
    Warn 'NOT run now (-NoRun). "Installed" is not "working" -- run it once before you trust it.'
    exit 0
}
if ($WhatIfPreference) { Write-Host "`n==> -WhatIf: nothing was changed." -ForegroundColor Yellow; exit 0 }

# ---- 3. run it once, and watch -----------------------------------------------------------------
# 🔴 "INSTALLED" IS NOT "WORKING". Every defect §53/§55 has had -- a missing image, a wrong path, a
# blob-scoped SAS, a mis-called helper -- was invisible until an execution ran. An install that
# does not prove itself is a report, not a result.
Step "run $JobName once, now"
$exec = "$(az containerapp job start @sub -g $ResourceGroup -n $JobName --query name -o tsv 2>$null)".Trim()
if (-not $exec) { throw "Enable-PimSelfUpdate: could not start '$JobName'." }
Note "execution $exec"
$deadline = (Get-Date).AddSeconds($RunTimeoutSeconds)
$status = 'Unknown'
while ((Get-Date) -lt $deadline) {
    Start-Sleep -Seconds 15
    $status = "$(az containerapp job execution list @sub -g $ResourceGroup -n $JobName --query "[?name=='$exec'].properties.status" -o tsv 2>$null)".Trim()
    if (-not $status) { $status = 'Unknown' }
    Note "  $status"
    if ($status -eq 'Succeeded' -or $status -eq 'Failed') { break }
}

Write-Host ''
if ($status -eq 'Succeeded') {
    Write-Host "==> $ResourceGroup now updates itself. It builds its own images; no build host is involved." -ForegroundColor Green
    Write-Host "    Next run: $Cron (UTC). To move it to a new version, publish that version and set:" -ForegroundColor DarkGray
    Write-Host "      Enable-PimSelfUpdate.ps1 ... -Version <new>" -ForegroundColor White
    exit 0
}
Fail "the first execution ended '$status' -- this environment is NOT yet self-updating."
Fail 'Read what it actually did before changing anything:'
Write-Host "      az containerapp job logs show -g $ResourceGroup -n $JobName --subscription $SubscriptionId --container $JobName --execution $exec --tail 60" -ForegroundColor White
exit 1
