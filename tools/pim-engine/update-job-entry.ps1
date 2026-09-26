#Requires -Version 7.0
<#
.SYNOPSIS
    §53 -- the in-container entry point of the nightly PIM update job (`ca-pim-update`).

.DESCRIPTION
    Runs INSIDE the pim-manager image, on the Container Apps Job's cron cadence, and rolls the
    environment to a ring-approved image over ARM REST. No `az` CLI, no PowerShell modules -- the
    image has neither, and adding the Azure CLI to every customer's container to roll a container
    is a dependency this codebase has deliberately avoided everywhere else.

    🔑 IT ROLLS, IT DOES NOT BUILD. The target image is BUILT ELSEWHERE and named here. That is
    the whole safety property: this job needs no ACR push rights, no source tree and no git, so
    the worst it can do is move an environment between two images that already exist. Which image
    it is allowed to move to is the operator's decision (the ring), not this job's.

    ORDER MATTERS, and it is the reverse of what feels natural:
      1. the Manager app   -- the thing users see
      2. the tick job      -- so the engine matches the Manager
      3. ITSELF, last      -- a job that stamps its own image takes effect on the NEXT run, so
                              doing it first would leave the current run rolling everything else
                              with a definition it had already replaced.

    🪤 A ROLL WITHOUT A HEALTH CHECK IS NOT AN UPDATE, IT IS A CHANGE. The Manager roll is gated
    on the app reaching a healthy running revision, and rolls back on its own if it does not.

.NOTES
    Every input arrives as an environment variable, because that is what a Container Apps Job can
    be given. Nothing is read from a command line.
#>
[CmdletBinding()] param()
$ErrorActionPreference = 'Stop'

# 🔴 TWO LEVELS UP, NOT ONE. This file lives in <solution>\tools\pim-engine\, so the solution root
# is '..\..' -- exactly what both sibling job entries already do (Invoke-PimEngineCore line 66,
# downlink-job-entry line 78). One Split-Path lands on <solution>\tools, and the first thing the
# job did in its first live execution was:
#     The term '/app/PIM4EntraPS/tools/engine/_shared/PIM-Rest.ps1' is not recognized ...
# 🪤 There is no offline test that can catch this by reading the file -- the path is only wrong
# once something resolves it -- so the guard below turns "wrong path" into a message that names
# what it looked for, instead of a dot-source failure that reads like a missing cmdlet.
$here    = Split-Path -Parent $PSCommandPath
$solRoot = Split-Path -Parent (Split-Path -Parent $here)
$shared  = Join-Path $solRoot 'engine\_shared'
if (-not (Test-Path -LiteralPath (Join-Path $shared 'PIM-Rest.ps1'))) {
    throw ("update-job-entry: the engine shared folder was not found at '$shared' " +
           "(resolved from '$PSCommandPath'). The image layout is not what this job expects.")
}
. (Join-Path $solRoot 'engine\_shared\PIM-Rest.ps1')
. (Join-Path $solRoot 'engine\_shared\PIM-ArmContainerApps.ps1')
. (Join-Path $solRoot 'engine\_shared\PIM-SyncAutomateIT.ps1')   # the decision core (semver + pin gate)
. (Join-Path $solRoot 'engine\_shared\PIM-AcrBuild.ps1')         # §55 build in the registry, over ARM
. (Join-Path $solRoot 'engine\_shared\PIM-UpdateSource.ps1')     # §55 where this ring's source comes from
# 🔴 BUG-231 -- LOAD-BEARING, AND ITS ABSENCE IS SILENT. The desired-state gate below calls
# Get-PimPolicyBaselineFromArchive / Compare-PimPolicyBaseline behind a `Get-Command ... -ErrorAction
# SilentlyContinue` guard. Without this line that guard is FALSE FOREVER: the gate reports
# "SKIPPED -- the target version's policy templates could not be read" on every run and waves every
# roll through, looking correct while protecting nothing. Caught by Test-PimCodeAudit's
# INERT-CAPABILITY class, which exists because this exact shape shipped before.
. (Join-Path $solRoot 'engine\_shared\PIM-PolicyBaseline.ps1')   # BUG-231 the desired-state gate's fingerprint + verdict
# §56.4 -- the SCHEMA phase. Loaded HERE with the rest, not lazily next to the step that uses it:
# a shared file this entry point never dot-sources makes every `Get-Command` guard around it false
# forever, which is the audit's INERT-CAPABILITY class and reports "skipped" as though it were fine.
. (Join-Path $solRoot 'engine\_shared\PIM-ChangeQueue.ps1')      # Initialize-PimSqlStore CALLS Get-PimChangeQueueDdl
. (Join-Path $solRoot 'engine\_shared\PIM-SqlStore.ps1')         # connection + query/DDL, over the container's MI
. (Join-Path $solRoot 'engine\_shared\PIM-UpdateTelemetry.ps1')  # §56.6 one record per run, write-only
. (Join-Path $solRoot 'engine\_shared\PIM-UpdateState.ps1')      # §71.43 the SAME run, recorded IN the environment

function Say($m, $c = 'Gray') { Write-Host ("[update] " + $m) -ForegroundColor $c }

# 🔴 2026-09-18 (§71.43) -- THE STORE IS NEEDED BEFORE THE FIRST EXIT PATH, NOT ONLY AT THE SCHEMA STEP.
# Every refusal below (no resource group, a ring with no source, nothing approved, a refused downgrade)
# now RECORDS what it decided into pim.Settings so the Manager can show this environment's ring -- and
# those are exactly the runs an operator most needs to see. Without the store resolved here they would
# all have recorded nothing.
# 🪤 Idempotent, and deliberately called again at the schema step: neither phase may depend on the
# other's ordering. One implementation (PIM-UpdateSource.ps1), two call sites.
[void](Use-PimUpdaterStoreEnv)

$sub        = "$($env:PIM_SubscriptionId)".Trim()
$rg         = "$($env:PIM_ResourceGroup)".Trim()
$managerApp = $(if ("$($env:PIM_ManagerApp)".Trim()) { "$($env:PIM_ManagerApp)".Trim() } else { 'ca-pim-manager' })
$tickJob    = $(if ("$($env:PIM_TickJobName)".Trim()) { "$($env:PIM_TickJobName)".Trim() } else { 'ca-pim-tick' })
$selfJob    = $(if ("$($env:PIM_UpdateJobName)".Trim()) { "$($env:PIM_UpdateJobName)".Trim() } else { 'ca-pim-update' })
$targetImg  = "$($env:PIM_UPDATE_TARGET_IMAGE)".Trim()   # e.g. acr.azurecr.io/pim-manager:2.4.295
$container  = $(if ("$($env:PIM_ManagerContainerName)".Trim()) { "$($env:PIM_ManagerContainerName)".Trim() } else { '' })

Say "environment $rg (subscription $sub)" 'Cyan'

# ---- §56.6 TELEMETRY -- one record per run, on EVERY exit path ---------------------------------
# 🔑 "so i can see if customer has issues or specific build is not updating" is two queries: is THIS
# customer stuck, and is THIS BUILD failing everywhere. The second cannot be backfilled -- telemetry
# added at customer 80 says nothing about the first 79 -- which is why it ships now, at three.
# 🔴 IT MUST NEVER AFFECT THE UPDATE. Send-PimUpdateTelemetry never throws and is bounded; a
# reporting feature that could stop updates across the fleet would be strictly worse than no
# reporting at all. Silent no-op when PIM_TELEMETRY_URL is unset.
# 🪤 REPORTED FROM A trap-STYLE HELPER CALLED AT EVERY EXIT, not just the happy path. A telemetry
# record written only when the run succeeds answers neither question -- "stuck" and "failing" are
# precisely the runs that end early.
$script:PimUpdateStartedUtc = [datetime]::UtcNow
$script:PimTelemetrySent    = $false
# §71.43 -- what the ring said THIS run, and what was running when it started. Filled in as the run
# learns them; both start empty so a run that exits before reading the channel records '' rather than a
# value carried over from something else.
$script:PimRingApproved       = ''
$script:PimRingApprovedReason = ''
$script:PimRunningVersion     = ''
function Send-PimUpdateOutcome {
    param(
        [ValidateSet('none','built','rolled','schema','failed')][string]$Action = 'none',
        [ValidateSet('ok','failed','skipped')][string]$Outcome = 'ok',
        [string]$ToVersion, [string]$ErrorText
    )
    if ($script:PimTelemetrySent) { return }        # one record per run, never two
    $script:PimTelemetrySent = $true
    try {
        if (-not (Get-Command New-PimUpdateTelemetryRecord -ErrorAction SilentlyContinue)) { return }
        $rec = New-PimUpdateTelemetryRecord -Environment $rg -Ring "$($env:PIM_UPDATE_RING)" `
                    -FromVersion "$($env:PIM_UPDATE_LAST_BUILT)" -ToVersion $ToVersion `
                    -Action $Action -Outcome $Outcome -ErrorText $ErrorText `
                    -DurationSeconds ([int]([datetime]::UtcNow - $script:PimUpdateStartedUtc).TotalSeconds)
        [void](Send-PimUpdateTelemetry -Record $rec -Log { param($m) Say $m 'DarkGray' })
    } catch { }                                      # telemetry can never break the update

    # ---- §71.43 THE SAME FACTS, RECORDED IN THIS ENVIRONMENT'S OWN STORE ------------------------
    # 🔑 The blob above is WRITE-ONLY from here (PIM-UpdateTelemetry.ps1, header): the environment
    # cannot read back what it reported, so the Manager could never answer "which ring am I on?".
    # This writes the same run to pim.Settings['UpdateState'], where the Manager already reads
    # everything else -- and it is the ONLY place the ring exists inside the environment, because
    # PIM_UPDATE_RING lives on THIS job and not on ca-pim-manager.
    # 🔴 SAME FAIL-SAFE DIRECTION. Save-PimUpdateState never throws; a settings write that did not
    # land is a note in the log and nothing more. An update that succeeded is never reported as
    # failed, or refused, because a reporting write failed.
    try {
        if (-not (Get-Command New-PimUpdateStateRecord -ErrorAction SilentlyContinue)) { return }
        $csState = $null
        try { $csState = Get-PimSqlConnectionString } catch { $csState = $null }
        if (-not "$csState".Trim()) {
            # 🪤 UPD-15 AGAIN, ONE PHASE EARLIER. The store self-heal (Resolve-PimUpdaterStoreSettings)
            # runs at the SCHEMA phase, so an updater that carries no PIM_SqlServer -- the EFIF/RIDE
            # shape -- would record nothing on any run that refuses BEFORE it, which is precisely the
            # run whose ring an operator wants to see. $app is the Manager this run already read; it
            # is $null on the earliest exits and that simply yields no store, as before.
            try {
                $heal = Resolve-PimUpdaterStoreSettings -JobServer "$($global:PIM_SqlServer)" -JobDatabase "$($global:PIM_SqlDatabase)" `
                            -ManagerStore (Get-PimAcaStoreSettings -Resource $app) -ManagerApp $managerApp
                if ($heal.source -eq 'manager' -and "$($heal.server)".Trim()) {
                    Set-Variable -Name 'PIM_SqlServer' -Scope Global -Value "$($heal.server)"
                    if ("$($heal.database)".Trim()) { Set-Variable -Name 'PIM_SqlDatabase' -Scope Global -Value "$($heal.database)" }
                    try { $csState = Get-PimSqlConnectionString } catch { $csState = $null }
                }
            } catch { }
        }
        if (-not "$csState".Trim()) {
            Say 'update state: no store to record it in (the ring will show as "not recorded" in the Manager).' 'DarkGray'
            return
        }
        $prev = Read-PimUpdateState -ConnectionString $csState
        $stateRec = New-PimUpdateStateRecord -Environment $rg -Ring "$($env:PIM_UPDATE_RING)" `
                        -Hold ("$($env:PIM_UPDATE_HOLD)".Trim() -eq '1') `
                        -ApprovedVersion $script:PimRingApproved -ApprovedReason $script:PimRingApprovedReason `
                        -RunningVersion $script:PimRunningVersion `
                        -LastBuiltVersion "$($env:PIM_UPDATE_LAST_BUILT)" -TargetVersion $ToVersion `
                        -Action $Action -Outcome $Outcome -ErrorText $ErrorText -Previous $prev `
                        -DurationSeconds ([int]([datetime]::UtcNow - $script:PimUpdateStartedUtc).TotalSeconds)
        $saved = Save-PimUpdateState -ConnectionString $csState -Record $stateRec
        if ($saved.ok) { Say "update state: recorded ring '$($stateRec.ring)' / $Outcome in pim.Settings" 'DarkGray' }
        else { Say "update state: NOT recorded (the update itself is unaffected): $($saved.reason)" 'DarkGray' }
    } catch { }                                      # recording can never break the update
}

if (-not $sub -or -not $rg) {
    Say 'PIM_SubscriptionId and PIM_ResourceGroup are required -- refusing to guess which environment to roll.' 'Red'
    Send-PimUpdateOutcome -Action 'failed' -Outcome 'failed' -ErrorText 'PIM_SubscriptionId / PIM_ResourceGroup not set'
    exit 2
}
# ---- 0. §55 -- BUILD THE APPROVED VERSION IF THIS ENVIRONMENT HAS TO -----------------------------
# 🔴 THE UPDATER USED TO BE A ROLLER ONLY, AND THAT IS HALF A SOLUTION.
# It moved an environment onto an image SOMEBODY ELSE had put in its registry. For the three
# environments with a build host behind them that is a complete nightly cycle; for a customer with
# no VM, nothing ever puts an image there and the environment can never move. Framework DEPLOY-3.
#
# 🔑 `az acr build` NEVER BUILT LOCALLY -- it uploads source and the REGISTRY builds. So a
# container can do the same over four plain ARM/HTTPS calls with the identity it already has
# (PIM-AcrBuild.ps1), and each environment produces its own image in its own registry. Nothing has
# to distribute images between tenants, and no cross-tenant registry credential has to exist.
#
# 🔒 AND IT IS OFF UNTIL AN ENVIRONMENT IS GIVEN A SOURCE. With no PIM_UPDATE_SOURCE_URL this runs
# exactly as it did before -- roll to what the registry already holds. That is what lets this ship
# without touching the environments that already update themselves every night.
$srcUrlTpl   = "$($env:PIM_UPDATE_SOURCE_URL)".Trim()
$targetVer   = "$($env:PIM_UPDATE_TARGET_VERSION)".Trim()
$lastBuilt   = "$($env:PIM_UPDATE_LAST_BUILT)".Trim()
$imageRepo   = $(if ("$($env:PIM_ImageRepo)".Trim()) { "$($env:PIM_ImageRepo)".Trim() } else { 'pim-manager' })

# Self-configuring: the Manager's CURRENT image already names this environment's registry and
# repository, so nothing has to be told them -- the same trick as inheriting the registry identity.
# 🪤 Get-PimAcaAppImage takes the APP OBJECT (-App), not subscription/group/name. Calling it with
# the wrong parameters threw a binding error that the catch below swallowed into "no registry", and
# the run then failed further on with "Cannot bind argument to parameter 'RegistryName' because it
# is an empty string" -- a message about the SYMPTOM, three steps from the cause. Measured on the
# first live run of §55.
$loginServer = ''
$resolveErr  = ''
$app = $null; $ref = $null
try {
    $app = Get-PimAcaApp -SubscriptionId $sub -ResourceGroup $rg -Name $managerApp
    $cur = Get-PimAcaAppImage -App $app -ContainerName $container
    $ref = Split-PimImageReference -Image "$cur"
    if ($ref) {
        $loginServer = $ref.loginServer
        if ($ref.repository) { $imageRepo = $ref.repository }
        # §71.43 -- what this environment was RUNNING when the update run started. Recorded so a
        # failed/no-op run still says which version it was looking at.
        $script:PimRunningVersion = "$($ref.tag)"
    }
    else { $resolveErr = "the Manager's image ('$cur') names no registry" }
} catch { $resolveErr = "$($_.Exception.Message)" }
if ($resolveErr) { Say "  could not read this environment's registry from $managerApp`: $resolveErr" 'Yellow' }

# A bare version is the modern pin -- one value, identical in every environment. A full image
# reference (PIM_UPDATE_TARGET_IMAGE) is still honoured so nothing already deployed changes meaning.
if (-not $targetVer -and $targetImg) {
    $tref = Split-PimImageReference -Image $targetImg
    if ($tref -and $tref.tag) { $targetVer = $tref.tag }
}

# ---- §60 -- WHAT DOES THIS RING APPROVE? ---------------------------------------------------------
# 🔴 THERE IS NEVER A PUSH TO 1000 CUSTOMERS. The pin has always been the ring enforcement point --
# an environment moves only to the version it is pinned to -- but the pin was PUSHED, so "release
# to ring 2" meant editing every ring-2 environment. That is the same shape as rotating a shared
# credential by touching every holder, and it does not exist at fleet scale.
# 🔑 So the environment READS what its ring approves, from one file beside the source archives,
# using the credential it already holds. Releasing to a ring becomes editing that one file.
# 🔒 THE RING WINS over a locally-set version when a ring is configured -- otherwise adopting the
# channel would require first clearing a pin on every environment, which is the push we are
# removing. To freeze ONE environment, set PIM_UPDATE_HOLD=1; that is an explicit, visible decision
# rather than a stale pin nobody remembers setting.
$ring = "$($env:PIM_UPDATE_RING)".Trim()
if ("$($env:PIM_UPDATE_HOLD)".Trim() -eq '1') {
    Say "PIM_UPDATE_HOLD=1 -- this environment is frozen; the ring channel is not consulted." 'Yellow'
    # §71.43 -- a held environment has NO approved version to show, and saying so is the point: the
    # Manager must not display the last version some earlier run happened to read as if it still applied.
    $script:PimRingApprovedReason = 'this environment is HELD (PIM_UPDATE_HOLD=1) -- the ring channel was not consulted'
} elseif ($ring -and -not $srcUrlTpl) {
    # 🔴 2026-09-13 -- A RING WITH NO SOURCE USED TO BE SKIPPED IN SILENCE, AND THE PIN WON. The ring
    # branch below needs the source template to find channel.json, so `$ring -and $srcUrlTpl` was false
    # and the run carried on to the pin as if no ring existed: an environment the operator had put on
    # ring 2 would take whatever its pin said, with nothing in the log to say the ring was ignored.
    # 🔒 A ring-managed environment moves ONLY when its ring says so. No readable ring => no move, and a
    # FAILED outcome, so the fleet view shows it rather than a quiet night.
    Say "PIM_UPDATE_RING=$ring is set but PIM_UPDATE_SOURCE_URL is NOT -- the ring channel (channel.json) cannot be read." 'Red'
    Say '  REFUSING to roll: a ring-managed environment moves only when its ring approves a version, never on its pin.' 'Red'
    Say '  Fix: re-run tools/setup/Deploy-PimUpdateJob.ps1 (it writes the source with the ring), or set PIM_UPDATE_SOURCE_URL.' 'Red'
    $script:PimRingApprovedReason = 'this environment has a ring but no update source, so the ring channel cannot be read'
    Send-PimUpdateOutcome -Action 'none' -Outcome 'failed' -ErrorText "PIM_UPDATE_RING=$ring without PIM_UPDATE_SOURCE_URL -- ring not readable, nothing rolled"
    exit 1
} elseif ($ring -and $srcUrlTpl) {
    $chUrl = Get-PimUpdateChannelUrl -SourceTemplate $srcUrlTpl
    $chFile = Join-Path ([IO.Path]::GetTempPath()) ("pim-channel-{0}.json" -f ([guid]::NewGuid().ToString('N').Substring(0,6)))
    try {
        Invoke-WebRequest -Uri $chUrl -OutFile $chFile -UseBasicParsing -TimeoutSec 120
        $channel = (Get-Content -LiteralPath $chFile -Raw) | ConvertFrom-Json
        $rv = Get-PimRingVersion -Channel $channel -Ring $ring -CurrentVersion $lastBuilt
        Say "ring $ring -- $($rv.reason)" 'DarkGray'
        # §71.43 -- the ring's ANSWER, in the ring's own words, recorded for the Manager. This is the
        # only moment it exists: the channel is fetched to a temp file and deleted below.
        $script:PimRingApproved       = "$($rv.version)".Trim()
        $script:PimRingApprovedReason = "$($rv.reason)".Trim()
        # 🪤 An unreadable or empty channel must NOT silently fall back to a local pin: that would
        # let an environment keep taking a version the ring has since withdrawn. No answer means
        # no move.
        if ("$($rv.version)".Trim()) { $targetVer = "$($rv.version)".Trim() }
        else { $targetVer = '' }
    } catch {
        Say "  could not read the ring channel: $($_.Exception.Message)" 'Yellow'
        Say '  refusing to fall back to a local pin -- a ring-managed environment moves only when the ring says so.' 'Yellow'
        $targetVer = ''
        # §71.43 -- an unreadable channel is a REPORTABLE state, not a blank. Recorded with no approved
        # version (so the Manager never claims one) and the reason, redacted: the channel URL carries a SAS.
        $script:PimRingApproved       = ''
        $script:PimRingApprovedReason = 'the ring channel could not be read: ' +
            $(if (Get-Command Remove-PimTelemetrySecret -ErrorAction SilentlyContinue) { Remove-PimTelemetrySecret -Text "$($_.Exception.Message)" } else { 'see the update job log' })
    } finally { Remove-Item -LiteralPath $chFile -Force -ErrorAction SilentlyContinue }
}

$plan = Get-PimUpdateSourcePlan -TargetVersion $targetVer -SourceUrlTemplate $srcUrlTpl `
                                -LastBuiltVersion $lastBuilt -LoginServer $loginServer -Repository $imageRepo
Say "plan: $($plan.action) -- $($plan.reason)" 'DarkGray'

if ($plan.action -eq 'none') {
    # 🪤 NOT AN ERROR, AND NOT SILENCE EITHER. An environment whose ring has approved nothing new
    # is the NORMAL nightly outcome. Saying so is what makes a quiet log trustworthy.
    Say 'no approved target for this ring. Nothing to do.' 'DarkGray'
    # 🔑 A NO-OP IS A REPORT, NOT A NON-EVENT. "Nothing approved" and "this environment stopped
    # reporting" look identical from the fleet view unless the quiet nights are recorded too --
    # and telling them apart is most of "is THIS customer stuck".
    Send-PimUpdateOutcome -Action 'none' -Outcome 'ok'
    exit 0
}

# ---- 0a. BUG-162 -- NEVER ROLL BACKWARD UNATTENDED -----------------------------------------------
# Checked BEFORE the build: building an older version is the same wasted 20 minutes as rolling to it,
# and the refusal must name the two versions while nothing has changed yet. The ring still decides
# WHETHER this environment moves (Sec.60, untouched above); this decides only that it never moves
# DOWN on its own. PIM_UPDATE_ALLOW_DOWNGRADE=1 is the operator's way back, and it is stated loudly.
$runningVer = if ($ref) { "$($ref.tag)" } else { '' }
$dg = Get-PimUpdateDowngradeDecision -TargetVersion "$($plan.version)" -RunningVersion $runningVer `
          -LastBuiltVersion $lastBuilt -LastGoodImage "$($env:PIM_UPDATE_LAST_GOOD)" -Ring $ring `
          -AllowDowngrade:("$($env:PIM_UPDATE_ALLOW_DOWNGRADE)".Trim() -eq '1') -UpdateJobName $selfJob
if ($dg.note) { Say "  $($dg.note)" 'DarkGray' }
if (-not $dg.allowed) {
    Say $dg.message 'Red'
    Say "  $($dg.detail)" 'Red'
    Send-PimUpdateOutcome -Action 'none' -Outcome 'failed' -ToVersion "$($plan.version)" -ErrorText $dg.errorText
    exit 1
}
if ($dg.overridden) {
    Say $dg.message 'Yellow'
    Say "  $($dg.detail)" 'Yellow'
}

if ($plan.action -eq 'build') {
    $srcUrl = Resolve-PimUpdateSourceUrl -Template $srcUrlTpl -Version $plan.version
    $ctx    = Join-Path ([IO.Path]::GetTempPath()) ("pim-src-{0}.tar.gz" -f $plan.version)
    Say "fetching source for $($plan.version)"
    $got = Get-PimUpdateSourceArchive -Url $srcUrl -OutFile $ctx
    if (-not $got.ok) {
        Say "  source NOT fetched: $($got.reason)" 'Red'
        Say '  refusing to roll: an environment that cannot get its approved version must say so, not quietly stay behind.' 'Red'
        Send-PimUpdateOutcome -Action 'failed' -Outcome 'failed' -ToVersion "$($plan.version)" -ErrorText "source not fetched: $($got.reason)"
        exit 1
    }
    Say ("  fetched {0:N0} bytes" -f $got.bytes) 'DarkGray'
    try {
        $reg = Split-PimImageReference -Image $plan.image
        # 🔴 REFUSE EARLY, NAMING THE CAUSE. Without this the run died several lines later on
        # "Cannot bind argument to parameter 'RegistryName' because it is an empty string" -- a
        # message about the symptom that says nothing about the Manager image it failed to read.
        if (-not $reg -or -not "$($reg.registryName)".Trim()) {
            Say "  cannot tell which registry to build in (resolved image '$($plan.image)')." 'Red'
            Say "  This environment's registry is read from $managerApp's current image; that read failed above." 'Red'
            Send-PimUpdateOutcome -Action 'failed' -Outcome 'failed' -ToVersion "$($plan.version)" -ErrorText 'cannot resolve which registry to build in'
            exit 1
        }
        # 🔴 PIM_ACR_AGENT_POOL (set on this job by Deploy-PimUpdateJob -AcrAgentPoolName) was read ONLY by the
        # host-side Invoke-PimUpdate. The in-cloud build ignored it, so a registry with public access Disabled
        # refused every nightly build ("client with IP ... is not allowed access") -- measured 2026-09-23.
        $pool = "$($env:PIM_ACR_AGENT_POOL)".Trim()
        Say ("building $imageRepo`:$($plan.version) in $($reg.registryName) (the registry builds; this job only asks)" + $(if ($pool) { " on agent pool '$pool'" } else { '' }))
        $b = Invoke-PimAcrRestBuild -SubscriptionId $sub -ResourceGroup $rg -RegistryName $reg.registryName `
                -ContextPath $ctx -ImageNames @("$imageRepo`:$($plan.version)") -AgentPoolName $pool `
                -OnPoll { param($s) Say "  build $s" 'DarkGray' }
        if (-not $b.ok) {
            Say "  BUILD $($b.status) after $($b.seconds)s (run $($b.runId))" 'Red'
            Say '  not rolling -- there is no new image to roll to.' 'Red'
            # 🔑 action='built' even though it FAILED: the fleet view needs to know WHICH PHASE broke.
            # "the build failed" and "the roll failed" point at completely different causes.
            Send-PimUpdateOutcome -Action 'built' -Outcome 'failed' -ToVersion "$($plan.version)" -ErrorText "build $($b.status) after $($b.seconds)s"
            exit 1
        }
        Say "  built in $($b.seconds)s (run $($b.runId))" 'Green'
        # Remember it, so tomorrow night is a roll and not another build. Takes effect on the NEXT
        # run by the same rule the self-stamp does -- this run already knows what it built.
        try {
            [void](Set-PimAcaJobEnvValue -SubscriptionId $sub -ResourceGroup $rg -JobName $selfJob `
                     -VariableName 'PIM_UPDATE_LAST_BUILT' -Value $plan.version)
        } catch { Say "  could not record the built version (it will rebuild next run): $($_.Exception.Message)" 'Yellow' }
    } finally {
        Remove-Item -LiteralPath $ctx -Force -ErrorAction SilentlyContinue
    }
}

# From here on the image exists -- either this run built it, or the registry already held it.
if ($plan.image) { $targetImg = $plan.image }
if (-not $targetImg) {
    Say 'no target image could be resolved -- refusing to guess.' 'Red'
    Send-PimUpdateOutcome -Action 'failed' -Outcome 'failed' -ErrorText 'no target image could be resolved'
    exit 2
}

# ---- 0b. §56.4 -- THE SCHEMA, BEFORE ANY CONTAINER MOVES ---------------------------------------
# 🔴 THIS JOB BUILT AND ROLLED CONTAINERS AND NEVER TOUCHED SQL. An update carrying a schema change
# therefore reached a customer as a container expecting columns its database does not have --
# unattended, at 03:00, with nobody watching. R10 asks for "all phases including container, schema,
# sql backend"; this was the missing phase.
#
# 🔑 ORDER IS THE WHOLE SAFETY PROPERTY. Schema goes FIRST because migrations here are
# ADDITIVE-ONLY (§56.3): the OLD container keeps working against the NEW schema, so the window
# between the two steps is safe in a way the reverse order never is. Rolling first and gating the
# schema behind a health check is §52.18's first-deploy deadlock -- the smoke test could not pass
# until the schema existed, so the schema step was never reached.
#
# 🔒 AND IT NEVER DESTROYS DATA. The conformance builder emits DROP COLUMN for anything the locked
# spec marks deprecated; applying that unattended would delete a column and its data in every
# customer at once, and NO ROLLBACK COULD UNDO IT -- image rollback is safe precisely because
# schema change is additive. A destructive migration is an ATTENDED operation (the cutover
# ceremony owns it, with backups and an abort). Same refusal, same wording, as the host-side path
# in Invoke-PimUpdate.ps1: one rule, now enforced in both places rather than one.
#
# 📌 FAIL-SAFE DIRECTION: if the schema cannot be brought up to date, DO NOT ROLL. A container
# expecting columns that do not exist is a broken environment; staying on the current version is
# not. This is the one step whose failure must stop the update.
# 🪤 THESE LIBS ARE DOT-SOURCED HERE, NOT GUARDED WITH Get-Command. A `if (Get-Command X)` around a
# function this entry point never LOADS is the audit's INERT-CAPABILITY class: the step reports
# "skipped" truthfully and forever, and reads as covered. The first cut of this block did exactly
# that, and it would have shipped a schema step that could never run once.
. (Join-Path $solRoot 'engine/_shared/PIM-SchemaConformance.ps1')   # locked schema + conformance DDL
. (Join-Path $solRoot 'engine/_shared/PIM-UpdateLifecycle.ps1')     # Get-PimSqlUpdatePlan

# 🔑 DDL over the SAME connection path the rest of this container uses. The host-side deploy mints
# an Entra token from a cert/SPN because it runs on mgmt1; in here the identity is the container's
# MANAGED IDENTITY, which New-PimSqlConnection already handles. Reusing that -- rather than porting
# the host's token minting -- is both less code and more correct: there is exactly one way this
# process talks to SQL, so the schema step cannot authenticate differently from the app it is
# upgrading. GO is a client-side batch separator, so it is split here and never sent to the server.
function Invoke-PimJobSqlDdl {
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][string]$Sql)
    $c = New-PimSqlConnection -ConnectionString $ConnectionString
    $c.Open()
    try {
        foreach ($batch in ($Sql -split '(?im)^\s*GO\s*$')) {
            if (-not "$batch".Trim()) { continue }
            $cmd = $c.CreateCommand(); $cmd.CommandText = $batch; $cmd.CommandTimeout = 300
            [void]$cmd.ExecuteNonQuery()
        }
    } finally { $c.Close() }
}
# Actual columns per locked table, straight from INFORMATION_SCHEMA. A table that is absent simply
# yields no rows, which is what the planner reads as "needs CREATE".
function Get-PimJobDeployedColumns {
    param([Parameter(Mandatory)][string]$ConnectionString)
    $out = @{}
    foreach ($t in @((Get-PimLockedSqlSchema).Keys)) {
        $schemaName = ($t -split '\.')[0]; $tableName = ($t -split '\.')[1]
        $rows = @(Invoke-PimSqlQuery -ConnectionString $ConnectionString `
                    -Sql 'SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA=@s AND TABLE_NAME=@t' `
                    -Parameters @{ s = $schemaName; t = $tableName })
        if ($rows.Count) { $out[$t] = @($rows | ForEach-Object { "$($_.COLUMN_NAME)" }) }
    }
    return $out
}

# 🔴 2026-09-13 -- THE JOB'S SQL SETTINGS NEVER REACHED THE STORE LIBRARY. Get-PimSqlConnectionString
# reads $global:PIM_SqlServer / $global:PIM_SqlDatabase, and nothing in this entry point copied the
# container's env into them (Invoke-PimEngineCore does, with Use-Cfg). So even an updater that DID carry
# PIM_SqlServer resolved no connection -- and said the environment had no store.
# 📌 Also done at the TOP of this file (§71.43) so the earlier exit paths can record their state. It is
# idempotent, and it stays HERE as well so the schema phase never depends on that having happened.
[void](Use-PimUpdaterStoreEnv)   # SCHEMA-STEP STORE RESOLUTION

# 🔴 2026-09-15 (UPD-15) -- SELF-HEAL THE STORE SETTINGS FROM THE MANAGER, DO NOT ASK A HUMAN.
# EFIF and RIDE refused every release for two nights with "updater has no PIM_SqlServer ... re-run
# Deploy-PimUpdateJob" while ca-pim-manager, which this run has ALREADY read ($app, above), named the
# store. The job now takes the Manager's values for this run and records them on its own env for the
# next one. Recording is best-effort: a failed note for tomorrow never fails tonight's update.
# 🔒 Only a copyable value is copied (a server name). An unreadable Manager, or one on a secret / vault
# pointer, resolves to 'none' and the decision below keeps refusing exactly as before.
$sqlAdminGroup = $(if ("$($env:PIM_SqlAdminGroupName)".Trim()) { "$($env:PIM_SqlAdminGroupName)".Trim() } else { 'grp-pim-sql-admins' })
$storeHeal = Resolve-PimUpdaterStoreSettings -JobServer "$($global:PIM_SqlServer)" -JobDatabase "$($global:PIM_SqlDatabase)" `
                -ManagerStore (Get-PimAcaStoreSettings -Resource $app) -ManagerApp $managerApp
if ($storeHeal.source -eq 'manager') {
    Set-Variable -Name 'PIM_SqlServer' -Scope Global -Value "$($storeHeal.server)"
    if ("$($storeHeal.database)".Trim()) { Set-Variable -Name 'PIM_SqlDatabase' -Scope Global -Value "$($storeHeal.database)" }
    Say "  store self-heal: $($storeHeal.reason)" 'Yellow'
    $saved = Save-PimUpdaterStoreSettings -SubscriptionId $sub -ResourceGroup $rg -JobName $selfJob -Writes $storeHeal.persist
    if ($saved.ok) { Say "  store settings recorded on $selfJob ($(@($saved.written) -join ', ')) -- the next run needs no copy" 'DarkGray' }
    else { Say "  NOTE: could not record the store settings on $selfJob ($($saved.reason)); this run continues with the copied values and the next run copies them again." 'Yellow' }
} elseif ($storeHeal.source -eq 'job' -and "$($storeHeal.database)".Trim() -and -not "$($global:PIM_SqlDatabase)".Trim()) {
    Set-Variable -Name 'PIM_SqlDatabase' -Scope Global -Value "$($storeHeal.database)"
}

$schemaOk = $true
$schemaRefused = $null
$schemaLoginRefusal = $null
try {
    $csUpd = $null
    try { $csUpd = Get-PimSqlConnectionString } catch { $csUpd = $null }
    # Store-less must be PROVEN from the Manager's own settings, never inferred from this job's gap.
    $tgtVerForSchema = if ("$($plan.version)".Trim()) { "$($plan.version)".Trim() }
                       else { $tr = Split-PimImageReference -Image $targetImg; if ($tr) { "$($tr.tag)" } else { '' } }
    $storeDecision = Get-PimUpdateSchemaStoreDecision -UpdaterConnection "$csUpd" `
                        -ManagerStore (Get-PimAcaStoreSettings -Resource $app) `
                        -CurrentVersion $(if ($ref) { "$($ref.tag)" } else { '' }) -TargetVersion $tgtVerForSchema `
                        -UpdateJobName $selfJob -ManagerApp $managerApp
    if ($storeDecision.mode -eq 'storeless') {
        Say "  $($storeDecision.message)" 'DarkGray'
    } elseif ($storeDecision.mode -eq 'unverified') {
        Say "  $($storeDecision.message)" 'Red'
        Say "  $($storeDecision.detail)" 'Yellow'
    } elseif ($storeDecision.mode -eq 'refuse') {
        Say "  $($storeDecision.message)" 'Red'
        Say "  $($storeDecision.detail)" 'Red'
        $schemaRefused = $storeDecision
        $schemaOk = $false
    } else {
        Say 'applying schema updates BEFORE rolling any container (additive-only)'
        Initialize-PimSqlStore -ConnectionString $csUpd
        $locked  = Get-PimLockedSqlSchema
        # 🔴 2026-09-15 -- THE SHIPPED SCHEMA FILES RUN ON EVERY STORE, NOT ONLY WHEN A TABLE IS ABSENT.
        # They were gated on a LOCKED table being absent. pim.CentralAdmins is not locked, so 2.4.360's
        # guarded `ADD Replicate` never reached EFIF or RIDE -- while this step logged "schema up to date"
        # and the release rolled. Every guarded addition in these files is now applied to every existing
        # store, BEFORE the conformance plan, all files checked BEFORE any runs (a refusal applies nothing).
        # 🔒 Store-aware destructive guard (Get-PimSchemaFileApplyPlan): no DROP TABLE / TRUNCATE / DELETE /
        # UPDATE, and a DROP COLUMN only when it is guarded AND that column is absent here (inert). A file
        # that errors throws -- the schema step fails and nothing rolls.
        $colProbe = {
            param([string]$Table, [string]$Column)
            $rows = @(Invoke-PimSqlQuery -ConnectionString $csUpd -Sql 'SELECT CASE WHEN COL_LENGTH(@t, @c) IS NULL THEN 0 ELSE 1 END AS e' `
                          -Parameters @{ t = $Table; c = $Column })
            if (-not $rows.Count) { throw "no answer for COL_LENGTH($Table, $Column)" }
            ([int]"$($rows[0].e)") -eq 1
        }
        $schemaFiles = @()
        # 2026-09-18 (IMP-46): ONE shipped base-schema file. sql/local-schema.sql created only the dead
        # pim.LocalAdmins / pim.LocalResources and was retired; existing stores keep those tables (nothing
        # here drops anything). The locked schema below is now every table THIS file creates, so the
        # "still absent" check after the apply proves a first install really got its base schema.
        foreach ($rel in @('sql/platform-schema.sql')) {
            $sf = Join-Path $solRoot $rel
            if (-not (Test-Path -LiteralPath $sf)) { throw "base schema file '$rel' is missing from this payload." }
            $sqlText = [IO.File]::ReadAllText($sf)
            $fPlan = Get-PimSchemaFileApplyPlan -Sql $sqlText -Name $rel -ColumnExists $colProbe
            if (-not $fPlan.ok) {
                throw ("shipped schema file '$rel' REFUSED for unattended apply: " + (@($fPlan.violations) -join '; ') +
                       '. Nothing from the schema files was applied.')
            }
            $schemaFiles += @{ rel = $rel; sql = $sqlText; drops = @($fPlan.guardedDrops) }
        }
        foreach ($s in $schemaFiles) {
            Invoke-PimJobSqlDdl -ConnectionString $csUpd -Sql $s.sql
            $inert = @($s.drops | ForEach-Object { "$($_.table).$($_.column)" })
            Say ("  applied $($s.rel) (idempotent; guarded additions reach existing stores$(if ($inert.Count) { "; inert guarded drops: $($inert -join ', ')" }))") 'DarkGray'
        }
        # CREATE before ALTER -- planned AFTER the files, against what is now really in the database.
        $depCols = Get-PimJobDeployedColumns -ConnectionString $csUpd
        $sPlan   = Get-PimSqlUpdatePlan -DeployedColumns $depCols -LockedSqlSchema $locked `
                        -PulledSchemaVersion "$($plan.version)" -DeployedSchemaVersion "$($plan.version)"
        $absentT = @($sPlan.tables | Where-Object { $_.exists -eq $false })
        if ($absentT.Count) {
            throw ("the shipped schema was applied but these table(s) are still absent: " + (@($absentT | ForEach-Object { $_.table }) -join ', '))
        }
        foreach ($tp in @($sPlan.tables | Where-Object { $_.exists -and -not $_.conformant })) {
            $actual = @(if ($depCols.ContainsKey($tp.table)) { $depCols[$tp.table] } else { @() })
            $ddl = New-PimSqlConformanceDdl -Table $tp.table -Spec $locked[$tp.table] -ActualColumns $actual
            if (@($ddl.plan.ToDrop).Count) {
                throw ("schema upgrade for $($tp.table) would DROP column(s): " + (@($ddl.plan.ToDrop) -join ', ') +
                       '. An unattended update never destroys data -- no rollback could restore it.')
            }
            Say "  altering $($tp.table)" 'DarkGray'
            Invoke-PimJobSqlDdl -ConnectionString $csUpd -Sql $ddl.ddl
        }
        # Re-preflight against what is NOW really in the database, not against what we planned from.
        $reCols = Get-PimJobDeployedColumns -ConnectionString $csUpd
        $rePlan = Get-PimSqlUpdatePlan -DeployedColumns $reCols -LockedSqlSchema $locked `
                        -PulledSchemaVersion "$($plan.version)" -DeployedSchemaVersion "$($plan.version)"
        if ($rePlan.SqlUpdateRequired) { throw "schema re-preflight still reports drift: $($rePlan.reason)" }
        Say '  schema up to date.' 'Green'
    }
} catch {
    $schemaOk = $false
    $schemaErr = "$($_.Exception.Message)"
    Say "  SCHEMA STEP FAILED: $schemaErr" 'Red'
    # 🔑 A LOGIN FAILURE NAMES THE PRINCIPAL AND THE FIX. The token SQL refused is the one this process
    # presented, so its oid is exactly who to add; the job's own identity is the fallback.
    $who = Get-PimJwtPrincipal -Token $global:PIM_SqlAccessToken
    $whoOid = "$($who.oid)"
    if (-not $whoOid -and $schemaErr -match '(?i)Login failed|18456|token-identified') {
        try {
            $selfIdObj = Invoke-PimArm -Method GET -ApiVersion $script:PimAcaApi `
                            -Path "/subscriptions/$sub/resourceGroups/$rg/providers/Microsoft.App/jobs/$selfJob"
            $whoOid = "$($selfIdObj.identity.principalId)"
        } catch { }
    }
    $schemaLoginRefusal = Get-PimUpdateSchemaLoginRefusal -ErrorText $schemaErr -PrincipalObjectId $whoOid -PrincipalAppId "$($who.appid)" `
                              -SqlServer "$($global:PIM_SqlServer)" -GroupName $sqlAdminGroup -UpdateJobName $selfJob
    if ($schemaLoginRefusal) {
        Say "  $($schemaLoginRefusal.message)" 'Red'
        Say "  $($schemaLoginRefusal.detail)" 'Red'
    }
}
if ($schemaRefused) {
    Say 'NOT ROLLING: this release may need schema changes, and this updater cannot reach the store to' 'Red'
    Say "             verify them: $managerApp could not be read, or names its store through a secret or vault pointer." 'Red'
    Send-PimUpdateOutcome -Action 'schema' -Outcome 'failed' -ToVersion "$($plan.version)" -ErrorText "$($schemaRefused.errorText)"
    exit 1
}
if ($schemaLoginRefusal) {
    Say "NOT ROLLING: the schema could not be verified -- add the updater's identity to the SQL admin group '$sqlAdminGroup'." 'Red'
    Send-PimUpdateOutcome -Action 'schema' -Outcome 'failed' -ToVersion "$($plan.version)" -ErrorText "$($schemaLoginRefusal.errorText)"
    exit 1
}
if (-not $schemaOk) {
    Say 'NOT ROLLING: the schema could not be brought up to date, and a container expecting columns' 'Red'
    Say '             that do not exist is worse than staying on the current version.' 'Red'
    Send-PimUpdateOutcome -Action 'schema' -Outcome 'failed' -ToVersion "$($plan.version)" -ErrorText 'schema step failed; roll refused'
    exit 1
}

# ---- 0b. THE DESIRED-STATE GATE (BUG-231) -----------------------------------------------------
# 🔴 THE BUG-55 GATE EXISTED ONLY ON THE HOST-SIDE PATH, AND THAT IS THE PATH NOBODY RUNS ANY MORE.
# `Update-PimContainers` refuses to roll an image whose policy baseline differs from the one recorded
# on the app, because within one tick the engine starts converging EVERY managed scope onto the new
# baseline -- that is how 217 of 325 production group policies were rewritten overnight. This job
# rolls the same app, unattended, at 03:00, and had no such check at all.
# WHAT IS COMPARED: the templates the TARGET version ships (read out of the source archive, the only
# statement of that version's content this job ever holds) against the fingerprint recorded on the
# Manager app. Same decision function as the host-side gate -- Compare-PimPolicyBaseline -- so there
# is ONE rule, not a second copy that can drift from it.
# 🔒 A CHANGED BASELINE REFUSES. The operator's way past is PIM_UPDATE_ACCEPT_BASELINE_CHANGE=1 on
# THIS environment's update job -- deliberate, per environment, and named in the refusal. Same shape
# as PIM_UPDATE_ALLOW_DOWNGRADE=1 above, for the same reason: an unattended process must not decide
# on its own that a desired-state change is acceptable.
# 🪤 UNKNOWN IS NOT CHANGED. No recording yet (first roll, or a resource older than the gate) and an
# unreadable archive BOTH mean "cannot tell" -- they warn and PROCEED. Blocking on "cannot tell"
# would freeze a fleet at 03:00 over a failed download, and would make the gate impossible to roll
# out in the first place.
$blAccept = ("$($env:PIM_UPDATE_ACCEPT_BASELINE_CHANGE)".Trim() -eq '1')
try {
    $tgtBaseline = $null
    if ("$srcUrlTpl".Trim() -and (Get-Command Get-PimPolicyBaselineFromArchive -ErrorAction SilentlyContinue)) {
        $blCtx = Join-Path ([IO.Path]::GetTempPath()) ("pim-bl-src-{0}.tar.gz" -f $plan.version)
        try {
            $blGot = Get-PimUpdateSourceArchive -Url (Resolve-PimUpdateSourceUrl -Template $srcUrlTpl -Version $plan.version) -OutFile $blCtx
            if ($blGot.ok) { $tgtBaseline = Get-PimPolicyBaselineFromArchive -ArchivePath $blCtx }
        } finally { Remove-Item -LiteralPath $blCtx -Force -ErrorAction SilentlyContinue }
    }
    if (-not $tgtBaseline -or -not "$($tgtBaseline.hash)".Trim()) {
        Say '  desired-state check SKIPPED -- the target version''s policy templates could not be read (no source archive, or it could not be opened). Proceeding; the roll is not gated on a check that could not run.' 'Yellow'
    } else {
        $recBl = ''
        try {
            $appObj = Invoke-PimArm -Method GET -ApiVersion $script:PimAcaApi -Path "/subscriptions/$sub/resourceGroups/$rg/providers/Microsoft.App/containerApps/$managerApp"
            if ($appObj -and $appObj.tags) { $recBl = "$($appObj.tags.'pim-policy-baseline')".Trim() }
            if ($recBl -eq 'None') { $recBl = '' }
        } catch { $recBl = '' }
        $blV = Compare-PimPolicyBaseline -Current $tgtBaseline -RecordedHash $recBl -RecordedTemplates @{} -Accept:$blAccept
        Say ("desired-state check: {0} policy template(s), fingerprint {1}" -f $tgtBaseline.count, $tgtBaseline.hash) 'DarkGray'
        if ($blV.unknown) {
            Say "  $($blV.reason) -- rolling and RECORDING it, so the next run can answer this." 'Yellow'
        } elseif ($blV.changed -and -not $blV.allowed) {
            Say "NOT ROLLING: $($blV.reason)" 'Red'
            Say '  This image changes what the engine WANTS, not just how it works: within one tick it would start' 'Red'
            Say '  converging every managed scope onto the new baseline (BUG-55 -- 217 of 325 production group' 'Red'
            Say '  policies were rewritten overnight).' 'Red'
            Say "  If that is the point of this release, set PIM_UPDATE_ACCEPT_BASELINE_CHANGE=1 on $selfJob and re-run." 'Yellow'
            Send-PimUpdateOutcome -Action 'none' -Outcome 'failed' -ToVersion "$($plan.version)" `
                -ErrorText "refused: policy baseline would change ($($blV.reason)); set PIM_UPDATE_ACCEPT_BASELINE_CHANGE=1 to accept"
            exit 1
        } elseif ($blV.changed) {
            Say "  $($blV.reason) -- PROCEEDING because PIM_UPDATE_ACCEPT_BASELINE_CHANGE=1. This roll WILL change desired state." 'Yellow'
        } else {
            Say "  $($blV.reason)" 'Green'
        }
    }
} catch {
    Say "  desired-state check could not run ($($_.Exception.Message)) -- proceeding; a check that failed is not a refusal." 'Yellow'
}

# ---- 1. the Manager ---------------------------------------------------------------------------
Say "rolling $managerApp -> $targetImg"
$roll = Invoke-PimAcaRoll -SubscriptionId $sub -ResourceGroup $rg -Name $managerApp -Image $targetImg `
                          -ContainerName $container -HealthCheck {
    # Healthy = the app provisioned AND has an active revision the platform reports as running.
    $rev = Get-PimAcaActiveRevision -SubscriptionId $sub -ResourceGroup $rg -Name $managerApp
    if (-not $rev) { return $false }
    $state = "$($rev.properties.runningState)"
    # 🪤 'Running' is NOT the only healthy value: a scaled app reports RunningAtMaxScale, and an
    # app at min-replicas 0 with no traffic reports neither. Treat only the explicitly bad ones as
    # bad, or this check fails every healthy scale-to-zero environment at 03:00.
    ($state -notmatch '(?i)^(Failed|Degraded)$')
}

if ($roll.reason) { Say "  $($roll.reason)" 'DarkGray' }
if ($roll.rolled -and $roll.healthy -eq $false) {
    Say "  UNHEALTHY after the roll -- rolled back: $($roll.rolledBack)" 'Red'
    Send-PimUpdateOutcome -Action 'rolled' -Outcome 'failed' -ToVersion "$($plan.version)" -ErrorText "unhealthy after the roll; rolledBack=$($roll.rolledBack)"
    exit 1
}
if (-not $roll.rolled -and $roll.reason -notmatch 'already on this image') {
    Say "  the Manager did NOT roll: $($roll.reason)" 'Red'
    Send-PimUpdateOutcome -Action 'rolled' -Outcome 'failed' -ToVersion "$($plan.version)" -ErrorText "the Manager did not roll: $($roll.reason)"
    exit 1
}

# ---- 1b. RECORD THE DESIRED-STATE BASELINE THIS ROLL PUT IN PLACE (BUG-229) -------------------
# 🔴 THE SELF-UPDATE PATH NEVER TOUCHED THE BUG-55 RECORDING, AND THAT IS WHY THE HOST-SIDE GATE
# JAMS SHUT. `Update-PimContainers.ps1` writes the `pim-policy-baseline` tag after every verified
# roll; this job rolls the very same app through ARM and wrote nothing -- so on every environment
# that self-updates, the IMAGE moved while the TAG stayed frozen at whatever the last host-side
# roll happened to record.
# Measured 2026-09-20: internal ran 2.4.381 (templates `10b3bf2031bacf0c`) with the tag still at
# `856bb5f1b9b009ec`; EFIF and RIDE both at `ff26419374c19ebb`. None of those three values matches
# ANY released version -- the fingerprint is taken from the working tree at roll time, so a roll
# from a mid-edit tree records a number no release ever had.
# The consequence is not cosmetic: the host-side nightly then refuses every roll for the rest of
# time. Measured 2026-09-13 on internal -- "recorded ff26419374c19ebb -> current aadd78a1d9338aec",
# deployed=False -- and until BUG-228 there was no parameter with which to tell it to accept.
# ⚠️ A gate that can never go green is a gate people learn to pass reflexively. That is how BUG-55
# happened in the first place, so leaving the recording to rot is itself a safety regression.
#
# WHAT IS RECORDED: the fingerprint the NEWLY ROLLED Manager seeded into its own store
# (`pim.Settings['PolicyTemplates'].fingerprint`) -- i.e. what this environment's desired state now
# IS, which is precisely what the gate compares a tree against. Read AFTER the health check,
# because the Manager writes it while it boots; retried briefly for the same reason.
# 🔒 BEST EFFORT, ALWAYS. A recording that fails must never fail an update that already rolled and
# is healthy -- it degrades to "unknown" on the next host-side roll, which WARNS rather than blocks.
# 📌 STILL OPEN (operator decision): this records, it does not GATE. The BUG-55 refusal exists only
# on the host-side path, so an unattended 03:00 self-update still rolls a baseline change with no
# check at all. Gating here would block the fleet unattended, which is not a call to make silently.
try {
    $blFp = ''
    if ("$csUpd".Trim() -and (Get-Command Invoke-PimSqlQuery -ErrorAction SilentlyContinue)) {
        foreach ($attempt in 1..6) {
            $raw = ''
            try {
                $r = @(Invoke-PimSqlQuery -ConnectionString $csUpd -Sql "SELECT CAST(ValueJson AS nvarchar(max)) AS v FROM pim.Settings WHERE [Name]='PolicyTemplates'")
                if ($r.Count) { $raw = "$($r[0].v)" }
            } catch { $raw = '' }
            if ("$raw".Trim()) { try { $blFp = "$(($raw | ConvertFrom-Json).fingerprint)".Trim() } catch { $blFp = '' } }
            if ($blFp) { break }
            Start-Sleep -Seconds 10
        }
    }
    if (-not $blFp) {
        Say '  policy baseline NOT recorded: no template fingerprint in the store yet (the next host-side roll reports it as UNKNOWN, which warns rather than blocks).' 'Yellow'
    } else {
        $blScope = "/subscriptions/$sub/resourceGroups/$rg/providers/Microsoft.App/containerApps/$managerApp"
        # 🪤 Merge, never replace: a PATCH that sets `tags` wholesale would silently delete the
        # customer's own cost-centre/owner tags as a side effect of an update. This is the same
        # Microsoft.Resources/tags Merge operation `az tag update --operation Merge` performs.
        [void](Invoke-PimArm -Method PATCH -ApiVersion '2021-04-01' `
                 -Path "$blScope/providers/Microsoft.Resources/tags/default" `
                 -Body @{ operation = 'Merge'; properties = @{ tags = @{ 'pim-policy-baseline' = $blFp } } })
        Say "  recorded policy baseline $blFp on $managerApp" 'DarkGray'
    }
} catch { Say "  could not record the policy baseline (update unaffected): $($_.Exception.Message)" 'Yellow' }

# 🔴 A COMPONENT LEFT ON THE OLD BUILD IS A FAILED UPDATE, NOT A WARNING.
# Every job below used to swallow its own failure and let the run exit 0, so an environment could be
# reported "updated" with its engine still on the previous image -- a skew that is invisible until
# the GUI and the job that does the work behave differently. Counted here and surfaced at the end.
$jobFailed = @()
# B8: kept SEPARATE from $jobFailed on purpose. A job that is still on the previous build is a
# failed update; this job failing to re-stamp ITSELF only defers which image its NEXT run starts
# from, and must not turn a healthy, rolled environment into a red execution.
$selfStampDeferred = ''
# §71.44 -- what this run did to ITSELF, for the follow-up decision at the very end.
$selfImageBefore = ''; $selfStamped = $false

# ---- 2. the tick job --------------------------------------------------------------------------
# Named explicitly rather than left to discovery: it is the one job whose skew from the Manager
# matters most, and it must be rolled even in the odd case where it runs a different repository.
if ($tickJob) {
    try {
        Say "rolling the tick job $tickJob"
        [void](Set-PimAcaJobImage -SubscriptionId $sub -ResourceGroup $rg -Name $tickJob -Image $targetImg -ContainerName $container)
    } catch { $jobFailed += $tickJob; Say "  tick job not rolled: $($_.Exception.Message)" 'Yellow' }
}

# ---- 2b. §53.5 -- EVERY OTHER JOB IN THIS ENVIRONMENT THAT RUNS THE SAME IMAGE -----------------
# 🔴 The hardcoded three (Manager, tick, self) left everything else to drift FOREVER. Measured at an
# MSP slave: after a GREEN update execution, `ca-pim-downlink-s6` was still on a digest with NO TAG
# -- a dangling manifest from a build whose tag had since moved, so the job was running code nobody
# could name. MSP topologies are exactly where the extra jobs live, so the set the updater knows
# about by name was never going to be the set the environment actually has.
# 🔒 Same REPOSITORY only. This process holds Contributor on the whole resource group; a customer's
# own job living in it is not ours to retag, and pointing it at the Manager image would break it.
# The decision is in Get-PimAcaJobRollPlan so it is provable offline rather than trusted at 03:00.
$discovered = 0
try {
    $all  = Get-PimAcaJobs -SubscriptionId $sub -ResourceGroup $rg
    $plan = Get-PimAcaJobRollPlan -Jobs $all -TargetImage $targetImg -Exclude @($tickJob, $selfJob)
    foreach ($s in @($plan.skip)) { Say "  skipping $($s.name): $($s.reason)" 'DarkGray' }
    foreach ($r in @($plan.roll)) {
        try {
            Say "rolling $($r.name) (same image as the Manager)"
            [void](Set-PimAcaJobImage -SubscriptionId $sub -ResourceGroup $rg -Name $r.name -Image $targetImg)
            $discovered++
        } catch { $jobFailed += $r.name; Say "  $($r.name) NOT rolled: $($_.Exception.Message)" 'Yellow' }
    }
} catch {
    # 🪤 Enumeration failing is NOT "there was nothing else". Saying so is the difference between a
    # quiet log that means "nothing to do" and one that means "I could not look".
    $jobFailed += '<job enumeration>'
    Say "  could not enumerate the jobs in $rg -- only the NAMED jobs were rolled: $($_.Exception.Message)" 'Yellow'
}

# ---- 3. itself, LAST --------------------------------------------------------------------------
if ($selfJob) {
    try {
        # 🔴 §56.5 -- RECORD WHAT KNOWN-GOOD MEANS, BEFORE MOVING OFF IT.
        # The image this job is running RIGHT NOW has just carried a whole update to completion:
        # it fetched, built, rolled the Manager, and passed the health gate. That is the strongest
        # possible evidence an image can produce about itself, and it is only available here, at
        # the end of a successful run, one line before the job abandons it.
        # 🪤 The Manager health gate does NOT prove the updater works -- they are different entry
        # points in the same image (2.4.296-2.4.301 booted the Manager fine and broke the updater).
        # So the image being adopted below is UNPROVEN as an updater, and the watchdog in the tick
        # job needs somewhere to fall back to when it turns out not to run.
        $selfNow = ''
        try {
            $selfJobObj = Invoke-PimArm -Method GET -ApiVersion $script:PimAcaApi `
                            -Path "/subscriptions/$sub/resourceGroups/$rg/providers/Microsoft.App/jobs/$selfJob"
            $sc = @($selfJobObj.properties.template.containers)
            if ($sc.Count -eq 1) { $selfNow = "$($sc[0].image)" }
        } catch { }
        if ($selfNow -and $selfNow -ne $targetImg) {
            try {
                [void](Set-PimAcaJobEnvValue -SubscriptionId $sub -ResourceGroup $rg -JobName $selfJob `
                         -VariableName 'PIM_UPDATE_LAST_GOOD' -Value $selfNow)
                Say "  recorded last-known-good updater image: $selfNow" 'DarkGray'
            } catch { Say "  could not record the last-known-good image: $($_.Exception.Message)" 'Yellow' }
        }
        Say "stamping $selfJob (takes effect on the NEXT run, by design)"
        # 🔴 B8 (2026-09-10) -- AN ARM OPERATION ALREADY IN FLIGHT IS A WAIT, NOT A FAILURE.
        # A customer environment's SUCCESSFUL update ended:
        #     update job not stamped: PATCH ... -> HTTP 409 : ContainerAppsJobOperationInProgress
        #     NOT FULLY UPDATED -- these are still on the previous build: ca-pim-update
        # The Manager had already rolled and was healthy. Only this job's stamp of ITSELF lost a
        # race with another ARM operation on the same resource -- most often the roll we just did.
        # 🪤 §53.4 gave the mgmt1-side pin advance exactly this bounded backoff and this reasoning.
        # The cloud copy never got it: one defect, two implementations, one of them fixed. That is
        # the split-brain shape this audit keeps finding, so the wait lives here too rather than
        # being "the same idea" written once somewhere neither path loads.
        $stamped = $false; $lastErr = ''
        foreach ($wait in @(0, 10, 20, 40, 60)) {
            if ($wait) { Say "  an operation is still in flight -- retrying in ${wait}s" 'DarkGray'; Start-Sleep -Seconds $wait }
            try {
                [void](Set-PimAcaJobImage -SubscriptionId $sub -ResourceGroup $rg -Name $selfJob -Image $targetImg -ContainerName $container)
                $stamped = $true; break
            } catch {
                $lastErr = "$($_.Exception.Message)"
                # Only the in-flight case is worth waiting out. Anything else is a real failure and
                # retrying it just delays the report by two minutes.
                if ($lastErr -notmatch '(?i)OperationInProgress|active provisioning operation|\b409\b') { break }
            }
        }
        if (-not $stamped) { throw $lastErr }
        $selfImageBefore = $selfNow; $selfStamped = $true
    } catch {
        # 🔑 AND IT MUST NOT CALL A ROLLED ENVIRONMENT "FAILED".
        # This stamp only decides which image the NEXT run of this job starts from; the update that
        # just completed is unaffected by it. Reporting the whole execution as Failed sent an
        # operator to investigate an environment that had updated correctly and was healthy -- and
        # taught them to distrust a red result, which is the expensive part.
        # The job stays on its current image and will re-stamp on its next run, so this is
        # self-correcting; it is reported as a deferred item, loudly, and does NOT set the exit code.
        $selfStampDeferred = "$($_.Exception.Message)"
        Say "  NOTE: $selfJob could not stamp ITSELF this run: $selfStampDeferred" 'Yellow'
        Say "        The environment DID update and is healthy. This job stays on its current image" 'Yellow'
        Say "        and re-stamps on its next run -- no action needed." 'Yellow'
    }
}

Say "done: $($roll.from) -> $($roll.to) (healthy=$($roll.healthy)); jobs rolled by discovery: $discovered" 'Green'
if ($jobFailed.Count) {
    Say "NOT FULLY UPDATED -- these are still on the previous build: $($jobFailed -join ', ')" 'Red'
    Send-PimUpdateOutcome -Action 'rolled' -Outcome 'failed' -ToVersion "$($roll.to)" -ErrorText "still on the previous build: $($jobFailed -join ', ')"
    exit 1
}
# B8: a deferred SELF-stamp is reported, but it is not a failed update -- see the block above.
if ("$selfStampDeferred".Trim()) {
    Say "UPDATED. One deferred item: this job re-stamps itself on its next run." 'Yellow'
}
# 🔑 THE SUCCESS RECORD IS THE ONE THAT ANSWERS "is this customer stuck?". A fleet view built only
# from failures cannot distinguish an environment that is healthy and current from one whose job
# stopped running altogether -- both are simply absent from it. The last SUCCESS timestamp is the
# signal; that is why 'ok' is reported as loudly as 'failed'.
# 📌 A deferred self-stamp (B8) is still an OK outcome: the environment rolled and is healthy.
Send-PimUpdateOutcome -Action 'rolled' -Outcome 'ok' -ToVersion "$($roll.to)"

# ---- 4. §71.44 -- ONE FOLLOW-UP RUN ON THE NEW UPDATER -------------------------------------------
# 🔴 This run was executed by the PREVIOUS updater image, so whatever the new release changed in the
# updater has not happened yet. Measured 2026-09-18: the 2.4.367 updater rolled three environments to
# 2.4.369, whose new ring record (§71.43) therefore never got written, and every Manager said
# "update ring: not recorded" until the next scheduled run. One follow-up on the NEW image does that
# work now: it finds the version already running (no build, no roll) and records/reports as the new
# release does. It can never chain -- its own image already equals the target (see the decision).
# AFTER the outcome above on purpose: the follow-up's record is then the latest one. Never changes the
# exit code -- a follow-up that could not start costs one night's delay, not a failed update.
$fu = Get-PimUpdaterFollowUpDecision -SelfImageBefore $selfImageBefore -TargetImage $targetImg `
        -Stamped $selfStamped -Disable "$($env:PIM_UPDATE_NO_FOLLOWUP)"
if ($fu.start) {
    Say "follow-up: $($fu.reason)" 'Cyan'
    $st = Start-PimAcaJobExecution -SubscriptionId $sub -ResourceGroup $rg -Name $selfJob
    if ($st.ok) { Say "follow-up: started $selfJob execution $($st.execution) on the new updater image" 'Cyan' }
    else {
        Say "  NOTE: the follow-up run could not be started: $($st.reason)" 'Yellow'
        Say "        The environment DID update and is healthy; the new updater runs at its next schedule instead." 'Yellow'
    }
} else { Say "follow-up: none ($($fu.reason))" 'DarkGray' }
exit 0
