#requires -Version 5.1
<#
.SYNOPSIS
    TEST-09 -- does what is RUNNING match what is MERGED? Reports version drift
    between the deployed container images and SOLUTIONS/PIM4EntraPS/VERSION.

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
    Resource group holding the PIM container apps.

.PARAMETER Apps
    Container apps to check. Defaults to the full PIM set.

.PARAMETER MaxAgeDays
    Also flag an app whose ACTIVE REVISION is older than this many days, even when the
    tag matches -- a long-lived revision is worth a look on its own. 0 disables the age
    check. Default 45.

.PARAMETER Quiet
    Suppress per-app output; print only the verdict line.

.EXAMPLE
    pwsh ./tools/setup/Test-PimDeployedVersionDrift.ps1
    Exit 0 = every app matches VERSION. Exit 1 = drift. Exit 2 = COULD NOT CHECK.

.NOTES
    Exit 2 is deliberately distinct from both: "I could not determine the answer" must
    never be mistaken for "everything is fine". A checker that reports green when it
    could not look is worse than no checker (the TEST-05 lesson, applied here).
#>
[CmdletBinding()]
param(
    [string]$ResourceGroup = $(if ($env:PIM_HOSTED_RG) { $env:PIM_HOSTED_RG } else { 'rg-pim-manager-web' }),
    [string[]]$Apps = @('ca-pim-manager','ca-pim-scheduler','ca-pim-engine','ca-pim-connector','ca-pim-deltaqueue','ca-pim-discovery'),
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
    [string]$AcrName = '',
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

# Dot-sourced for the offline test -> stop before touching az.
if ($MyInvocation.InvocationName -eq '.') { return }

# ---------------------------------------------------------------------------
# LIVE half
# ---------------------------------------------------------------------------
$solRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)     # tools/setup -> tools -> PIM4EntraPS
$dateSafe = Join-Path $solRoot 'engine\_shared\PIM-DateSafe.ps1'
if (Test-Path -LiteralPath $dateSafe) { . $dateSafe }

Write-Host "=== PIM deployed-version drift (TEST-09) ===" -ForegroundColor Cyan

$verFile = Join-Path $solRoot 'VERSION'
if (-not (Test-Path -LiteralPath $verFile)) {
    Write-Host "  CANNOT CHECK: VERSION not found at $verFile" -ForegroundColor Red
    exit 2
}
$expected = ([System.IO.File]::ReadAllText($verFile)).Trim()
Write-Host ("  expected (VERSION): {0}" -f $expected) -ForegroundColor DarkGray

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
        resolvedTag = (Resolve-PimDigestTag -Image $img -Acr $AcrName -SubArgs $subArgs)
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
foreach ($d in $r.drifted) { Write-Host ("  DRIFT   {0}: running {1}, expected {2}" -f $d.app, $d.tag, $expected) -ForegroundColor Red }
foreach ($s in $r.stale)   { Write-Host ("  STALE   {0}: on {1} but its revision is {2} days old" -f $s.app, $s.tag, $s.ageDays) -ForegroundColor Yellow }
foreach ($u in $r.unknown) { Write-Host ("  UNKNOWN {0}: could not parse an image tag" -f $u.app) -ForegroundColor Red }
Write-Host ""
Write-Host " Roll the fleet with:" -ForegroundColor Yellow
Write-Host ("   pwsh ./tools/setup/Update-PimContainers.ps1 -ImageTag {0} -ResourceGroup {1} -AcrName <acr> -SkipBuild" -f $expected, $ResourceGroup) -ForegroundColor Yellow
exit 1
