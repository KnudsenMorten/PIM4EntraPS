#requires -Version 5.1
<#
.SYNOPSIS
    TEST-09 -- does what is RUNNING match what this environment is APPROVED to run? Reports
    version drift between the deployed container images and the version the environment's
    update RING approves in channel.json.

    🔴 BUG-171 (2026-09-18): the expectation used to be the repo VERSION file. That contradicts
    the ring design: a ring-2 customer held at 2.4.324 by the operator ALWAYS read DRIFT, and the
    printed remedy was to roll it to the repo version -- exactly the release to ring 2 that only
    the operator may make. The expectation is now the environment's ring entry (Get-PimRingVersion,
    read through its own updater, the same way the in-cloud job reads it); the remedy only ever
    names that approved version; and an environment with NO ring cannot be checked (exit 2) unless
    the caller names the version with -ExpectedVersion. The defaults are v2: the resource group is
    REQUIRED (it used to default to a v1 group), and the apps and jobs are DISCOVERED (they used to
    be six v1 app names and no jobs, so every v2 environment exited 2).

.DESCRIPTION
    WHY THIS EXISTS
    ---------------
    On 2026-08-06 the hosted Manager was found serving `pim-manager:2.4.230` from a
    revision created 2026-06-19, while the repo was at 2.4.238 -- with the SEC-01
    security fix among the undeployed delta, recorded in §33 as "closed". Seven weeks
    of drift, and NOTHING said a word. It was found by hand, by accident.

    Every gate we had validates a DEPLOYMENT:
      * the hosted smoke checks the served version -- but only runs AS PART OF a deploy;
      * Test-PimSmokeVersionCheck proves that logic offline -- it tests the LOGIC;
      * Check-PublishHealth reports workflow-run conclusions -- not what runs in Azure.
    Nothing validated the ABSENCE of a deploy. That is the blind spot: the failure mode
    is not a bad deploy, it is NO deploy, and a gate that only fires on deploy is
    structurally incapable of noticing.

    So this MUST run on a SCHEDULE, never from the deploy path. Wiring it into a deploy
    would reproduce the exact blind spot it exists to close. (CLAUDE.md rule 7b puts
    Check-PublishHealth on the same footing -- run it periodically.)

    BUG-09 note: it also catches a deploy that silently rolled a SUBSET. A run that
    reports success while skipping apps leaves precisely this state.

.PARAMETER ResourceGroup
    Resource group holding the PIM container apps. REQUIRED (or $env:PIM_HOSTED_RG): there is no
    sensible default for somebody else's environment.

.PARAMETER Apps
    Container apps to check. Empty (default) = DISCOVER every ca-pim-* app in the group.

.PARAMETER Jobs
    Container Apps jobs to check. Empty (default) = DISCOVER every job that runs the Manager's
    image repository (the same rule the rollers use), except the update job, which re-stamps
    itself and legitimately lags one run.

.PARAMETER ExpectedVersion
    Check against THIS version instead of the ring's. The only way to check an environment that
    carries no ring.

.PARAMETER MaxAgeDays
    Also flag an app whose ACTIVE REVISION is older than this many days, even when the
    tag matches -- a long-lived revision is worth a look on its own. 0 disables the age
    check. Default 45.

.PARAMETER Quiet
    Suppress per-app output; print only the verdict line.

.EXAMPLE
    pwsh ./tools/setup/Test-PimDeployedVersionDrift.ps1 -ResourceGroup <rg> -SubscriptionId <sub>
    Exit 0 = everything runs what its ring approves. Exit 1 = drift. Exit 2 = COULD NOT CHECK.

.NOTES
    Exit 2 is deliberately distinct from both: "I could not determine the answer" must
    never be mistaken for "everything is fine". A checker that reports green when it
    could not look is worse than no checker (the TEST-05 lesson, applied here).
#>
[CmdletBinding()]
param(
    # BUG-171: no v1 default group, and no v1 app list. Empty = required / discovered (see .PARAMETER).
    [string]$ResourceGroup = $(if ($env:PIM_HOSTED_RG) { $env:PIM_HOSTED_RG } else { '' }),
    [string[]]$Apps = @(),
    # 🔴 EVERY az CALL BELOW USED TO RUN AGAINST THE AMBIENT DEFAULT CONTEXT, and on a machine
    # logged into more than one directory that is a coin flip. On mgmt1 it lands on a DIFFERENT
    # COMPANY'S subscription (CLAUDE.md: "often the DEFAULT context"), so this gate -- whose entire
    # job is to notice that nothing was deployed -- would query the wrong tenant, find none of the
    # apps, and report CANNOT CHECK. Right answer, wrong reason, and one `az account set` away from
    # being a confidently wrong answer instead. Measured 2026-08-30: it could not report on the
    # myfamilynetwork fleet at all.
    # Same family as SEC-12: an ambient identity silently standing in for an explicit one.
    [string]$SubscriptionId = $(if ($env:PIM_SUBSCRIPTION_ID) { $env:PIM_SUBSCRIPTION_ID } else { '' }),
    # Container APP JOBS (the tick) are deployed alongside the apps and drift identically -- a
    # fleet check that reads only the apps can report "no drift" while the job runs last month's
    # engine. Same BUG-09 shape the app list already guards against.
    [string[]]$Jobs = @(),
    # When an app is pinned BY DIGEST rather than by tag there is no tag to read, and the report
    # correctly says `unknown`. Given an ACR, the digest is resolved back to its tag so the answer
    # is a version instead of a shrug -- which is the difference between this gate answering the
    # question and merely declining to.
    # Empty = read off each image's own registry host (<acr>.azurecr.io/...), so a digest-pinned v2
    # environment (BUG-40 pins every roll by digest) still resolves to a version by default.
    [string]$AcrName = '',
    [string]$ExpectedVersion = '',
    [string]$UpdateJobName = 'ca-pim-update',
    [string]$ManagerApp = 'ca-pim-manager',
    [int]$MaxAgeDays = 45,
    [switch]$Quiet
)
$ErrorActionPreference = 'Stop'
# Guarded `az` shadow -- see _PimAz.ps1. az writes ordinary WARNINGS to stderr and PowerShell 5.1
# makes any such write terminating under $ErrorActionPreference='Stop'. A DRIFT check is the worst
# place to inherit that: it would report "cannot read the deployed image" on a host that is simply
# noisy, which reads as drift-unknown rather than as a broken probe.
# 🪤 Assign first. `Join-Path (if (...) {...} else {...}) 'x'` PARSES and then fails at RUNTIME with
# "The term 'if' is not recognized as a name of a cmdlet" -- the same shape already recorded in
# Sync-AutomateIT-Engine.ps1. An `if` is a statement, not an argument expression.
$here = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
. (Join-Path $here '_PimAz.ps1')

# ---------------------------------------------------------------------------
# PURE decision core -- no az, no network. This is what the offline suite tests.
# ---------------------------------------------------------------------------
function Get-PimImageTag {
    # 'acr.azurecr.io/pim-manager:2.4.238' -> '2.4.238'. Returns '' when unparseable.
    # Splits on the LAST ':' so a registry port (host:5000/repo:tag) cannot fool it.
    [CmdletBinding()] param([string]$Image)
    $s = "$Image".Trim()
    if (-not $s) { return '' }
    # 🔴 A DIGEST IS NOT A TAG, and splitting on the last ':' turns one into the other. An image
    # pinned as `repo@sha256:f25ba6e4...` was reported as running "tag" f25ba6e4..., i.e. a 64-char
    # hex string printed where a version belongs -- and then compared against 2.4.252 and called
    # DRIFT. The verdict happened to be right, which is exactly why nobody noticed: a gate whose
    # output is unreadable is one nobody reads, and the next digest-pinned deploy could as easily
    # have produced a confident nonsense answer. Measured on the myfamilynetwork fleet 2026-08-30.
    # Returning '' here is what lets the caller's registry lookup resolve the real tag, and what
    # keeps `unknown` reachable when it cannot -- an admitted gap beats an invented version.
    if ($s -match '@sha256:') { return '' }
    $i = $s.LastIndexOf(':')
    if ($i -lt 0) { return '' }                       # no tag at all (implicit :latest)
    $tag = $s.Substring($i + 1)
    if ($tag -match '/') { return '' }                # the ':' was a port, not a tag
    return $tag
}

function Get-PimVersionDriftReport {
    <#
      Compare deployed tags against the expected version. PURE.
      $Deployed: array of @{ app; image; revision; createdUtc } (createdUtc optional).
      Returns @{ expected; rows; drifted; stale; unknown; ok }.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Expected,
        [object[]]$Deployed = @(),
        [int]$MaxAgeDays = 45,
        [datetime]$NowUtc = ([datetime]::UtcNow)
    )
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($d in @($Deployed)) {
        if ($null -eq $d) { continue }
        $app = "$($d.app)"
        # A tag parsed from the image string wins; a digest-pinned image has none, and the caller
        # may have resolved it against the registry. Still PURE -- the lookup happened outside.
        $tag = Get-PimImageTag -Image "$($d.image)"
        if (-not $tag -and "$($d.resolvedTag)".Trim()) { $tag = "$($d.resolvedTag)".Trim() }
        $ageDays = $null
        if ("$($d.createdUtc)".Trim()) {
            $c = $null
            if (Get-Command Get-PimUtcStamp -ErrorAction SilentlyContinue) { $c = Get-PimUtcStamp $d.createdUtc }
            else { $tmp = [datetime]::MinValue; if ([datetime]::TryParse("$($d.createdUtc)", [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AdjustToUniversal -bor [Globalization.DateTimeStyles]::AssumeUniversal, [ref]$tmp)) { $c = $tmp } }
            if ($c) { $ageDays = [int][Math]::Floor(($NowUtc - $c.ToUniversalTime()).TotalDays) }
        }
        # 'unknown' is NOT 'ok'. An app whose tag we could not read is an open question.
        $status =
            if (-not $tag)               { 'unknown' }
            elseif ($tag -ne $Expected)  { 'drift'   }
            elseif ($MaxAgeDays -gt 0 -and $null -ne $ageDays -and $ageDays -gt $MaxAgeDays) { 'stale' }
            else                         { 'ok'      }
        $rows.Add([pscustomobject]@{
            app = $app; tag = $tag; expected = $Expected; revision = "$($d.revision)"
            ageDays = $ageDays; status = $status
        })
    }
    $all = @($rows.ToArray())
    $drifted = @($all | Where-Object { $_.status -eq 'drift'   })
    $stale   = @($all | Where-Object { $_.status -eq 'stale'   })
    $unknown = @($all | Where-Object { $_.status -eq 'unknown' })
    return [pscustomobject]@{
        expected = $Expected
        rows     = $all
        drifted  = $drifted
        stale    = $stale
        unknown  = $unknown
        # ok requires: at least one app examined, and nothing drifted/stale/unknown.
        # An EMPTY app list is NOT ok -- "checked nothing" is not "all good" (BUG-09).
        ok       = (($all.Count -gt 0) -and ($drifted.Count -eq 0) -and ($stale.Count -eq 0) -and ($unknown.Count -eq 0))
    }
}

# The ring helpers (ConvertTo-PimUpdateRingNumber, Get-PimUpdateRingChannelReport ->
# Get-PimRingVersion, Get-PimEnvironmentUpdaterEnv) and the rollers' same-repository job rule
# (Get-PimAcaJobRollPlan). Loaded, not copied: "what the ring approves" must be decided by the same
# code the in-cloud updater and the roll gate use. Side-effect free when loaded.
. (Join-Path $here '_PimUpdateRing.ps1')

function Resolve-PimDriftExpectedVersion {
    <#
      BUG-171. PURE (apart from the -Fetch seam). WHICH version this environment should be running.
        -ExpectedVersion given        -> that (the caller named it)
        updater unreadable            -> CANNOT CHECK (an unknown ring is not "no ring")
        ring on the updater           -> ringN.version from channel.json, read through the updater's
                                         own PIM_UPDATE_SOURCE_URL (a channel that cannot be read, or
                                         approves nothing for the ring, is CANNOT CHECK -- never a guess)
        no ring / no updater          -> CANNOT CHECK: nothing approves a version for it. Never the repo
                                         VERSION -- that is what the build tree says, not what the
                                         environment was approved for.
      Returns @{ ok; expected; ring; source; reason }.
    #>
    param(
        [AllowEmptyString()][string]$ExpectedVersion,
        [object]$Updater,             # Get-PimEnvironmentUpdaterEnv result
        [scriptblock]$Fetch
    )
    $mk = { param($ok, $exp, $ring, $src, $why) [pscustomobject]@{ ok = [bool]$ok; expected = "$exp"; ring = $ring; source = "$src"; reason = "$why" } }
    $ev = ("$ExpectedVersion".Trim() -replace '^v', '')
    if ($ev) { return (& $mk $true $ev $null 'the -ExpectedVersion parameter' '') }
    if (-not $Updater -or -not $Updater.ok) {
        return (& $mk $false '' $null '' ("the update job could not be read ($("$($Updater.reason)".Trim())) -- its ring, and so the approved version, is unknown"))
    }
    $uEnv = if ($Updater.found) { $Updater.env } else { [ordered]@{} }
    $ringRaw = if ($uEnv.Contains('PIM_UPDATE_RING')) { "$($uEnv['PIM_UPDATE_RING'])".Trim() } else { '' }
    if (-not $ringRaw) {
        $pin = if ($uEnv.Contains('PIM_UPDATE_TARGET_VERSION')) { "$($uEnv['PIM_UPDATE_TARGET_VERSION'])".Trim() } else { '' }
        $what = if ($Updater.found) { 'the updater carries no PIM_UPDATE_RING' } else { 'there is no update job' }
        $hint = if ($pin) { " (its updater is pinned to $pin -- pass -ExpectedVersion $pin to check against that pin)" } else { ' -- pass -ExpectedVersion <version> to check it against a version you name' }
        return (& $mk $false '' $null '' ("$what, so no ring approves any version for this environment$hint"))
    }
    $ring = ConvertTo-PimUpdateRingNumber $ringRaw
    if ($null -eq $ring) { return (& $mk $false '' $ringRaw '' "PIM_UPDATE_RING='$ringRaw' is not a ring") }
    $src = if ($uEnv.Contains('PIM_UPDATE_SOURCE_URL')) { "$($uEnv['PIM_UPDATE_SOURCE_URL'])".Trim() } else { '' }
    $rep = Get-PimUpdateRingChannelReport -SourceUrlTemplate $src -Ring $ring -CurrentVersion '' -Fetch $Fetch
    if (-not $rep.ok -or -not "$($rep.approved)".Trim()) { return (& $mk $false '' $ring '' $rep.message) }
    return (& $mk $true "$($rep.approved)".Trim() $ring "ring$ring in channel.json" '')
}

function Get-PimDriftRemedy {
    <#
      BUG-171. PURE. What to tell the operator about each drifted row -- and what NEVER to tell them.
      The only version ever named as a roll target is -Expected (what the ring approves). An
      environment AHEAD of its ring is not "behind the repo": on ring >= 2 it is running a version the
      operator never approved, and the advice is to stop and decide, not to roll anything.
      Returns an array of lines.
    #>
    param([object[]]$Rows = @(), [AllowEmptyString()][string]$Expected, $Ring, [string]$ResourceGroup)
    $lines = New-Object System.Collections.Generic.List[string]
    $ev = $null; [void][version]::TryParse(("$Expected" -replace '^v', ''), [ref]$ev)
    $ringTxt = if ($null -ne $Ring -and "$Ring" -ne '') { "ring $Ring" } else { 'the named version' }
    $behind = @(); $ahead = @()
    foreach ($r in @($Rows)) {
        $tv = $null
        if ($ev -and [version]::TryParse(("$($r.tag)" -replace '^v', ''), [ref]$tv) -and $tv -gt $ev) { $ahead += $r } else { $behind += $r }
    }
    if ($behind.Count) {
        [void]$lines.Add(("{0} is BEHIND what {1} approves ({2}): {3}." -f $(if ($behind.Count -eq 1) { '1 target' } else { "$($behind.Count) targets" }), $ringTxt, $Expected, (@($behind | ForEach-Object { "$($_.app)=$($_.tag)" }) -join ', ')))
        [void]$lines.Add("  The environment's own updater moves it to $Expected on its next run. To move it now (the ring gate allows exactly this version):")
        [void]$lines.Add(("    pwsh ./tools/setup/Update-PimContainers.ps1 -ImageTag {0} -ResourceGroup {1} -AcrName <acr> -SubscriptionId <sub> -SkipBuild" -f $Expected, $ResourceGroup))
    }
    if ($ahead.Count) {
        [void]$lines.Add(("{0} is AHEAD of what {1} approves ({2}): {3}." -f $(if ($ahead.Count -eq 1) { '1 target' } else { "$($ahead.Count) targets" }), $ringTxt, $Expected, (@($ahead | ForEach-Object { "$($_.app)=$($_.tag)" }) -join ', ')))
        if ($null -ne $Ring -and "$Ring" -ne '' -and [int]$Ring -ge 2) {
            [void]$lines.Add("  This environment runs a version its ring has NOT approved. Do not roll anything from here: the operator decides whether")
            [void]$lines.Add("  to approve that version for ring $Ring in channel.json, or to roll it back to $Expected deliberately.")
        } else {
            [void]$lines.Add("  The channel entry is behind the build this environment verified. Advance it forward-only (Invoke-PimUpdate does this")
            [void]$lines.Add("  after a verified roll); until then its updater will refuse to move it backward.")
        }
    }
    return @($lines.ToArray())
}

function Get-PimAcrNameFromImage {
    # PURE. 'acrx.azurecr.io/pim-manager@sha256:...' -> 'acrx'; anything else -> ''.
    param([AllowEmptyString()][string]$Image)
    if ("$Image".Trim() -match '^(?i)([a-z0-9]+)\.azurecr\.io/') { return $Matches[1].ToLowerInvariant() }
    return ''
}

# Dot-sourced for the offline test -> stop before touching az.
if ($MyInvocation.InvocationName -eq '.') { return }

# ---------------------------------------------------------------------------
# LIVE half
# ---------------------------------------------------------------------------
$solRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)     # tools/setup -> tools -> PIM4EntraPS
$dateSafe = Join-Path $solRoot 'engine\_shared\PIM-DateSafe.ps1'
if (Test-Path -LiteralPath $dateSafe) { . $dateSafe }

Write-Host "=== PIM deployed-version drift ===" -ForegroundColor Cyan

# BUG-171: the resource group is REQUIRED -- the old default was a v1 group, so an unconfigured run
# checked something that is not this environment and reported on it with confidence.
if (-not "$ResourceGroup".Trim()) {
    Write-Host "  CANNOT CHECK: no -ResourceGroup (or `$env:PIM_HOSTED_RG). There is no default environment." -ForegroundColor Red
    exit 2
}

if (-not (Get-Command az -ErrorAction SilentlyContinue)) {
    Write-Host "  CANNOT CHECK: azure CLI (az) not found." -ForegroundColor Red
    exit 2
}
$acct = & az account show -o json 2>$null
if ($LASTEXITCODE -ne 0 -or -not $acct) {
    Write-Host "  CANNOT CHECK: not logged in to az (run az login)." -ForegroundColor Red
    exit 2
}

# --- WHICH subscription, said out loud ---------------------------------------------------------
# 🔑 "Logged in" was never the question. `az account show` succeeding proves only that SOME context
# exists, and this check used to accept that as readiness -- which is how it ended up ready to
# query another company's tenant. Every az call below is scoped explicitly instead.
$subArgs = @()
if ("$SubscriptionId".Trim()) {
    $subArgs = @('--subscription', "$SubscriptionId".Trim())
    Write-Host ("  subscription: {0} (explicit)" -f $SubscriptionId) -ForegroundColor DarkGray
} else {
    $ctx = $null
    try { $ctx = $acct | ConvertFrom-Json } catch { }
    # NOT a failure -- a single-directory machine has one context and it is the right one. But it
    # is stated, because an ambient default is a fact about the machine, not about this fleet.
    Write-Host ("  subscription: AMBIENT DEFAULT '{0}' ({1}) -- pass -SubscriptionId to pin it" -f `
        "$($ctx.name)", "$($ctx.id)") -ForegroundColor Yellow
}

# --- WHAT this environment is approved to run (BUG-171) ------------------------------------------
# The ring entry in channel.json, read through the environment's OWN updater -- never the repo
# VERSION file. No ring, an unreadable updater or a channel that approves nothing => CANNOT CHECK.
$updater = Get-PimEnvironmentUpdaterEnv -ResourceGroup $ResourceGroup -SubscriptionArgs $subArgs -UpdateJobName $UpdateJobName
$exp = Resolve-PimDriftExpectedVersion -ExpectedVersion $ExpectedVersion -Updater $updater
if (-not $exp.ok) {
    Write-Host ("  CANNOT CHECK: {0}." -f $exp.reason) -ForegroundColor Red
    Write-Host " RESULT: COULD NOT CHECK -- no approved version to compare against. This is NOT a pass." -ForegroundColor Red
    exit 2
}
$expected = $exp.expected
Write-Host ("  expected: {0} (from {1})" -f $expected, $exp.source) -ForegroundColor DarkGray

$deployed = New-Object System.Collections.Generic.List[object]
$queryFailed = New-Object System.Collections.Generic.List[string]

# A digest -> tag cache, so N apps on one image cost ONE registry call.
$script:digestTag = @{}
function Resolve-PimDigestTag {
    <#
      An image pinned as repo@sha256:... carries no tag, and the report then says `unknown` --
      honest, but it declines to answer the only question being asked. Given an ACR we can look
      the digest up and say which version it actually is.
      Returns '' when it cannot be resolved -- which keeps `unknown` reachable rather than
      inventing a tag, because a guessed version is worse than an admitted gap.
    #>
    param([string]$Image, [string]$Acr, [string[]]$SubArgs)
    if (-not "$Acr".Trim()) { return '' }
    if ("$Image" -notmatch '@(sha256:[0-9a-f]+)$') { return '' }
    $digest = $Matches[1]
    if ($script:digestTag.ContainsKey($digest)) { return $script:digestTag[$digest] }
    $repo = ("$Image" -split '@')[0]; $repo = ($repo -split '/')[-1]
    $tag = ''
    try {
        $t = & az acr manifest list-metadata --registry $Acr --name $repo @SubArgs `
                --query "[?digest=='$digest'].tags[0]" -o tsv 2>$null
        if ($LASTEXITCODE -eq 0 -and "$t".Trim()) { $tag = ("$t".Trim() -split "\r?\n")[0] }
    } catch { }
    $script:digestTag[$digest] = $tag
    return $tag
}

# --- WHAT to check: discovered, v2 (BUG-171) -------------------------------------------------------
# The defaults used to be six v1 app names and no jobs, so on every v2 environment the checker could
# read nothing and exited 2. Empty -Apps = every ca-pim-* app in the group; empty -Jobs = every job
# that runs the Manager's image repository (Get-PimAcaJobRollPlan -- the rule both rollers use), the
# update job excepted (it re-stamps itself and lags one run by design). A listing that FAILS is an
# open question (exit 2), never "nothing to check".
if (-not @($Apps | Where-Object { "$_".Trim() }).Count) {
    $global:LASTEXITCODE = 0
    $appNames = @(& az containerapp list -g $ResourceGroup @subArgs --query "[].name" -o tsv 2>$null)
    if ($LASTEXITCODE -ne 0) { Write-Host "  CANNOT CHECK: could not list the container apps in $ResourceGroup." -ForegroundColor Red; exit 2 }
    $Apps = @($appNames | ForEach-Object { "$_".Trim() } | Where-Object { $_ -like 'ca-pim-*' })
    Write-Host ("  apps (discovered): {0}" -f $(if ($Apps.Count) { $Apps -join ', ' } else { '(none)' })) -ForegroundColor DarkGray
}
if (-not @($Jobs | Where-Object { "$_".Trim() }).Count) {
    $global:LASTEXITCODE = 0
    $mgrImg = "$(& az containerapp show -g $ResourceGroup -n $ManagerApp @subArgs --query "properties.template.containers[0].image" -o tsv 2>$null)".Trim()
    $global:LASTEXITCODE = 0
    $jobsJson = (@(& az containerapp job list -g $ResourceGroup @subArgs -o json 2>$null) -join "`n")
    if ($LASTEXITCODE -ne 0 -or -not $mgrImg) {
        Write-Host ("  CANNOT CHECK: could not read {0} -- the jobs that must follow it cannot be determined." -f $(if (-not $mgrImg) { "$ManagerApp's image" } else { "the jobs in $ResourceGroup" })) -ForegroundColor Red
        exit 2
    }
    $jobObjs = @(); try { $jobObjs = @((ConvertFrom-Json $jobsJson) | ForEach-Object { $_ }) } catch { }
    $jobPlan = Get-PimAcaJobRollPlan -Jobs $jobObjs -TargetImage $mgrImg -Exclude @("$UpdateJobName".Trim())
    $Jobs = @(@($jobPlan.roll) | ForEach-Object { "$($_.name)" })
    Write-Host ("  jobs (discovered, same image repository as {0}): {1}" -f $ManagerApp, $(if ($Jobs.Count) { $Jobs -join ', ' } else { '(none)' })) -ForegroundColor DarkGray
}

# Apps and JOBS both drift, and both are read here. A fleet check that covers only the apps can
# report "no drift" while the tick job runs last month's engine -- BUG-09's shape, one resource
# type over.
$targets = @()
foreach ($a in @($Apps)) { $targets += ,@{ name = $a; kind = 'app' } }
foreach ($j in @($Jobs)) { $targets += ,@{ name = $j; kind = 'job' } }

foreach ($t in $targets) {
    $app = $t.name
    if ($t.kind -eq 'job') { $json = & az containerapp job show -g $ResourceGroup -n $app @subArgs -o json 2>$null }
    else                   { $json = & az containerapp show     -g $ResourceGroup -n $app @subArgs -o json 2>$null }
    if ($LASTEXITCODE -ne 0 -or -not $json) { $queryFailed.Add($app); continue }
    $o = $null
    try { $o = $json | ConvertFrom-Json } catch { $queryFailed.Add($app); continue }
    $rev = ''; $created = ''
    if ($t.kind -eq 'app') {
        $rev = "$($o.properties.latestRevisionName)"
        $rj = & az containerapp revision show -g $ResourceGroup -n $app --revision $rev @subArgs --query "properties.createdTime" -o tsv 2>$null
        if ($LASTEXITCODE -eq 0 -and $rj) { $created = "$rj".Trim() }
    }
    $img = "$($o.properties.template.containers[0].image)"
    $deployed.Add([pscustomobject]@{
        app = $app; image = $img; revision = $rev; createdUtc = $created
        # Resolved here rather than inside the pure core, which must stay network-free.
        # No -AcrName: the image names its own registry (BUG-171 -- every v2 roll is digest-pinned).
        resolvedTag = (Resolve-PimDigestTag -Image $img -Acr $(if ("$AcrName".Trim()) { $AcrName } else { Get-PimAcrNameFromImage -Image $img }) -SubArgs $subArgs)
    })
}

# An app we could not query is an OPEN QUESTION, never a pass. Say so and exit 2 --
# reporting "no drift" while five apps went unread is the BUG-09 failure mode.
if ($queryFailed.Count -gt 0) {
    Write-Host ("  CANNOT CHECK {0} app(s): {1}" -f $queryFailed.Count, ($queryFailed -join ', ')) -ForegroundColor Red
}

$r = Get-PimVersionDriftReport -Expected $expected -Deployed $deployed.ToArray() -MaxAgeDays $MaxAgeDays

if (-not $Quiet) {
    foreach ($row in $r.rows) {
        $col = switch ($row.status) { 'ok' { 'Green' } 'drift' { 'Red' } 'stale' { 'Yellow' } default { 'Red' } }
        $age = if ($null -ne $row.ageDays) { "{0}d" -f $row.ageDays } else { '?' }
        Write-Host ("  {0,-20} {1,-10} {2,-8} rev-age {3,-6} {4}" -f $row.app, $row.tag, $row.status.ToUpperInvariant(), $age, $row.revision) -ForegroundColor $col
    }
}

Write-Host ""
if ($queryFailed.Count -gt 0) {
    Write-Host (" RESULT: COULD NOT CHECK -- {0} app(s) unreadable. This is NOT a pass." -f $queryFailed.Count) -ForegroundColor Red
    exit 2
}
if ($r.ok) {
    Write-Host (" RESULT: no drift -- all {0} app(s) on {1}." -f $r.rows.Count, $expected) -ForegroundColor Green
    exit 0
}
if ($r.rows.Count -eq 0) {
    Write-Host " RESULT: COULD NOT CHECK -- no apps were examined. 'Checked nothing' is not 'all good'." -ForegroundColor Red
    exit 2
}
foreach ($d in $r.drifted) { Write-Host ("  DRIFT   {0}: running {1}, expected {2} ({3})" -f $d.app, $d.tag, $expected, $exp.source) -ForegroundColor Red }
foreach ($s in $r.stale)   { Write-Host ("  STALE   {0}: on {1} but its revision is {2} days old" -f $s.app, $s.tag, $s.ageDays) -ForegroundColor Yellow }
foreach ($u in $r.unknown) { Write-Host ("  UNKNOWN {0}: could not parse an image tag" -f $u.app) -ForegroundColor Red }
Write-Host ""
# BUG-171: the remedy names ONLY the version the ring approves, and never tells anyone to move a
# ring-2 environment AHEAD of its ring (that was "roll it to the repo version" -- a release to ring 2).
foreach ($ln in @(Get-PimDriftRemedy -Rows @($r.drifted) -Expected $expected -Ring $exp.ring -ResourceGroup $ResourceGroup)) {
    Write-Host (" " + $ln) -ForegroundColor Yellow
}
exit 1
