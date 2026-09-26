#Requires -Version 5.1
<#
.SYNOPSIS
    §31.3 CLOUD-NATIVE downlink JOB entrypoint -- the command an Azure Container
    Apps scheduled Job (Deploy-PimDownlinkJob.ps1) runs ON ITS CRON CADENCE inside
    the pim-manager container. Operator directive 2026-06-17: "all run in cloud
    only compute, in one test"; "run it through the containers in the slave".

.DESCRIPTION
    Runs ENTIRELY on cloud container compute. On each scheduled execution it:

      0. DECIDES WHETHER THE PULL IS DUE (operator 2026-09-18: the cadence is set in the Manager's Job schedule). The cron
         fires every 5 minutes; the gate reads this tenant's OWN pim.Settings (DownlinkSchedule / DownlinkRunNow /
         DownlinkLastRun) and a not-due execution logs one "[cadence] SKIPPED:" line and exits 0 before the engine is
         loaded. Nothing stored = daily, as before. See engine/_shared/PIM-JobCadence.ps1.
     0b. REQ-Y: REFUSES (exit 2, nothing pulled or applied) unless this slave holds a Pro licence that covers MSP for
         -TenantId (Invoke-PimMspLicenseGate, engine/_shared/PIM-License.ps1); in its grace window it pulls with a WARN.
      1. AUTHENTICATES the runtime identity (Managed Identity by default; an SPN
         certificate when $env:PIM_ENGINE_CERT_THUMBPRINT is set). REST-only, no
         PowerShell Az/Graph modules, never a secret, never device-code.
      2. Composes the ring-gated downlink + the engine apply for the scenario by
         INVOKING the existing live wrapper setup/Invoke-PimScenarioRun.ps1, which:
            * managed (S5/S6) -> downlink-sync (pull the SIGNED master baseline ->
              verify RSA-SHA256 -> ring-gate slave.Ring <= admin.Ring (§77.20) -> stage the
              per-tenant sync files -> APPLY into the slave via its own SPN) THEN
            * engine apply (admins + delegation groups/roles/AUs) -- which honours
              the mass-disable guard (empty desired never prunes; -Prune opt-in).
      3. Writes a structured run log to STDOUT (the container log stream) so the
         execution is observable via `az containerapp job execution` + `... logs`.

    This entrypoint INVOKES the downlink; it never edits it. The pure plan brain is
    engine/_shared/PIM-DownlinkJob.ps1 (offline-tested in tests/Test-PimDownlinkJob.ps1).

.PARAMETER Scenario
    'S5' (central-hosted managed, multi-tenant SPN) or 'S6' (local-hosted managed,
    local SPN). The cron Job's command always supplies this.

.PARAMETER TenantId / SlaveRing
    The managed/slave tenant id + the slave's OWN ring (0 = dev, 1 = test, 2 = broad; default 0). The ring
    is LOCAL: it is this job's argument, set in the slave, and it is authoritative. The
    master's platform.Tenants.Ring is only the master's copy and is never read here.

.PARAMETER BaselineUrl
    PLAIN blob URL of the master's signed baseline bundle (DESIGN 13.7: public-but-signed,
    or a private endpoint over VNet peering). No query string: the SAS transport is
    retired (SEC-27). Mutually exclusive with -BaselineDocPath. Falls back to
    $env:PIM_BaselineUrl.

.PARAMETER CentralKillUrl
    SEC-25: the master's signed central-kill manifest. Falls back to $env:PIM_CentralKillUrl,
    else the sibling of the bundle URL (<container>/central-kill.json). A 404 = no kill.

.PARAMETER BaselineDocPath
    Container path to an already-pulled / mounted signed bundle JSON (skips the pull).
    Falls back to $env:PIM_BaselineDocPath.

.PARAMETER WhatIfMode
    Default OFF (a scheduled cloud run APPLIES). Pass -WhatIfMode for a dry run.

.NOTES
    The image already carries the whole /app/PIM4EntraPS tree (see the Dockerfile),
    so this entrypoint and the wrappers it invokes are present at runtime. SQL is
    MI-only (PIM_StorageBackend=sql + PIM_SqlServer/PIM_SqlDatabase env, no password).
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('S5','S6')][string]$Scenario,
    [Parameter(Mandatory)][string]$TenantId,
    # 🔑 A RING IS A SLAVE-LOCAL SETTING, so it must be settable WITHOUT rewriting the container's
    # command line (operator, 2026-09-22: "ride must be ring 1 as today"). It was `-SlaveRing` only,
    # so changing a tenant's ring meant editing the job's args -- a riskier edit than setting an
    # environment variable, for the one value an operator is most likely to change.
    # 🪤 An env-provided ring is ALWAYS in the dev-first order (0 dev, 1 test, 2 broad): the variable
    # did not exist before that order did. It is therefore not $PSBoundParameters-bound, so the
    # legacy conversion below correctly leaves it alone. An explicit -SlaveRing still wins.
    [ValidateRange(0,2)][int]$SlaveRing = $(if ("$env:PIM_SlaveRing".Trim() -match '^[0-2]$') { [int]("$env:PIM_SlaveRing".Trim()) } else { 0 }),
    [string]$BaselineUrl     = $env:PIM_BaselineUrl,
    [string]$BaselineAccessToken = $env:PIM_BaselineAccessToken,
    [string]$BaselineDocPath = $env:PIM_BaselineDocPath,
    [string]$CentralKillUrl = $env:PIM_CentralKillUrl,
    [string]$EngineScope = 'All',
    [ValidateSet('Full','Delta')][string]$EngineMode = 'Delta',
    # IMP-13 / operator ruling 2026-09-03. Comma-separated in the env because an ACA env value is
    # one string. 🔴 Without this the scheduled Job never told the plan what the slave's admin
    # naming convention is, so Select-PimUnrecognisableAdmins returned `checked = $false` on every
    # production run -- "we did not look", which its own contract says must not be read as "they
    # are fine". The guard was correct and simply never armed on this path.
    [string[]]$SlaveAdminPrefixes = @(@("$env:PIM_SlaveAdminPrefixes" -split ',') | ForEach-Object { "$_".Trim() } | Where-Object { $_ }),
    # 71.14: the explicit, default-OFF retraction opt-in (an ACA env value is a string, so this is one too). Only an
    # explicit true turns it on -- see Resolve-PimDownlinkRetractionOptIn.
    [string]$AllowRetraction = $env:PIM_DOWNLINK_ALLOW_RETRACTION,
    [switch]$WhatIfMode
)

$ErrorActionPreference = 'Stop'
$global:PIM_UseGraphSdk = $false   # REST-only; no Az/Graph modules

function JobLog { param([string]$m,[string]$lvl='INFO') Write-Host ("[{0}] [downlink-job] [{1}] {2}" -f ([datetime]::UtcNow.ToString('o')), $lvl, $m) }

# Resolve the solution root from this script's location (tools/pim-engine -> ..\..).
$here    = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
$solRoot = (Resolve-Path (Join-Path $here '..\..')).Path
$shared  = Join-Path $solRoot 'engine\_shared'

JobLog "==== PIM4EntraPS scheduled downlink JOB starting ===="
# §77.20 -- THE RING ORDER (operator 2026-09-21: "ring 0 = dev, ring 1 = test, ring 2 = broad (all)"). A job built by
# 2.4.388+ carries PIM_RingOrder=dev-first and its -SlaveRing is in that order. A job built earlier has no such variable:
# its -SlaveRing is in the OLD order (0 = broad) and is converted here (new = 2 - old), so the tenant keeps exactly the
# reach it had. Re-running the build (or setting PIM_RingOrder=dev-first with a dev-first -SlaveRing) ends the conversion.
if ("$env:PIM_RingOrder".Trim() -ne 'dev-first' -and $PSBoundParameters.ContainsKey('SlaveRing')) {
    $legacyRing = $SlaveRing
    $SlaveRing = 2 - $legacyRing
    JobLog ("ring: this job's -SlaveRing {0} is in the pre-2.4.388 order (0 = broad) -- read as ring {1} ({2}); set PIM_RingOrder=dev-first with -SlaveRing {1} to make it explicit" -f $legacyRing, $SlaveRing, @('dev', 'test', 'broad')[$SlaveRing]) 'WARN'
}
JobLog ("scenario={0} tenant={1} ring={2} ({4}) mode={3}" -f $Scenario, $TenantId, $SlaveRing, $(if ($WhatIfMode) { 'WHATIF' } else { 'APPLY' }), @('dev', 'test', 'broad')[$SlaveRing])

# --- baseline source (a configuration check, no I/O): refuse if neither is present (fail-safe) -----------------------
if (-not "$BaselineUrl".Trim() -and -not "$BaselineDocPath".Trim()) {
    JobLog 'no baseline source: supply -BaselineUrl (private-endpoint blob) or -BaselineDocPath (mounted bundle) / set PIM_BaselineUrl|PIM_BaselineDocPath' 'ERROR'
    exit 2
}

# --- 0) THE CADENCE GATE (operator 2026-09-18: "i need to be able to control cadence" ... "gui must be made to control").
# The job's cron fires every 5 minutes; whether THIS execution pulls is decided here, from THIS tenant's own store
# (pim.Settings DownlinkSchedule / DownlinkRunNow / DownlinkLastRun -- set in the Manager's Job schedule). The cadence is
# LOCAL to the managed tenant, like its ring. engine/_shared/PIM-JobCadence.ps1 has the rules; the ones that matter here:
#   * nothing stored = the daily cadence this job always had, ENABLED;  * disabled in the GUI = no pull, and the log says so;
#   * a store that cannot be read = PULL ANYWAY, loudly (the pull is signature-verified and safe to repeat).
# 🔑 CHEAP ON PURPOSE: only the cadence core, the REST token layer and the SQL store are loaded before the decision. The
# scenario profile (which pulls in PIM-Downlink.ps1) and the engine are loaded only when the pull is due.
. (Join-Path $shared 'PIM-JobCadence.ps1')
$cadenceCs = ''; $cadenceErr = ''
try {
    if (-not "$env:PIM_SqlServer".Trim()) { throw 'PIM_SqlServer is not set on this job' }
    # BUG-80: the token provider BEFORE the store, or SQL is reached with no credential ("Login failed for user ''").
    foreach ($__dep in @('PIM-Rest.ps1', 'PIM-SqlStore.ps1')) { . (Join-Path $shared $__dep) }
    # The same identity the scenario runner uses for this store (BUG-83: never silently another one).
    if ($env:PIM_TenantId -and -not $global:PIM_TenantId) { $global:PIM_TenantId = "$($env:PIM_TenantId)".Trim() }
    if ($env:PIM_ClientId -and -not $global:PIM_ClientId) { $global:PIM_ClientId = "$($env:PIM_ClientId)".Trim() }
    $cadenceCs = Get-PimSqlConnectionString -Server "$env:PIM_SqlServer".Trim() -Database $(if ("$env:PIM_SqlDatabase".Trim()) { "$env:PIM_SqlDatabase".Trim() } else { 'PimPlatform' })
} catch { $cadenceErr = "$($_.Exception.Message)" }
$cadenceLog = { param($m, $l) JobLog $m $l }
$cadenceGate = Invoke-PimJobCadenceGate -Job 'pull' -StoreError $cadenceErr -Log $cadenceLog `
    -ExecutionName "$env:CONTAINER_APP_JOB_EXECUTION_NAME" -DeployedUtc "$env:PIM_CadenceDeployedUtc" `
    -ReadValues { param($names) Read-PimJobCadenceValues -ConnectionString $cadenceCs -Object 'pim.Settings' -Names $names } `
    -CompareAndSet { param($n, $v, $e) Set-PimJobCadenceValueIfUnchanged -ConnectionString $cadenceCs -Object 'pim.Settings' -Name $n -NewJson $v -ExpectedJson $e }
if (-not $cadenceGate.run) {
    JobLog '==== downlink JOB: nothing to do on this trigger (see the cadence line above) ===='
    exit 0
}
# Every exit after the gate records how the pull ended, so the Manager's Job schedule shows the last result.
function Stop-DownlinkJob {
    param([int]$Code, [ValidateSet('succeeded', 'failed', 'held')][string]$State, [string]$Detail)
    [void](Complete-PimJobCadenceRun -Gate $cadenceGate -State $State -Detail $Detail -Log $cadenceLog `
        -Write { param($n, $j) Write-PimJobCadenceValue -ConnectionString $cadenceCs -Object 'pim.Settings' -Name $n -Json $j })
    exit $Code
}

# --- 0b) REQ-Y: AN MSP SLAVE NEEDS A PRO LICENCE (operator 2026-09-19: "msp master slave require license pro") ---------
# After the cadence says the pull is due; BEFORE the scenario profile, the downlink and the engine are loaded -- nothing
# is pulled or applied without it. The licence is THIS tenant's pim.Settings['License'], bound to -TenantId (the tenant
# this job already pulls for). A store that cannot be read cannot prove a licence: refused, and the log says why.
# Not ok = one ERROR line naming the contact and the register command, recorded as the pull's result, exit 2.
# Grace = a WARN line, then pull. Independent of the global Pro switch, which stays off.
. (Join-Path $shared 'PIM-License.ps1')
$licText = ''; $licErr = "$cadenceErr"
if (-not $licErr) {
    try { $licText = ConvertFrom-PimLicenseSettingRaw ((Read-PimJobCadenceValues -ConnectionString $cadenceCs -Object 'pim.Settings' -Names @('License'))['License']) }
    catch { $licErr = "$($_.Exception.Message)" }
}
$mspLic = Invoke-PimMspLicenseGate -Role Slave -TenantId $TenantId -LicenseText $licText -StoreError $licErr -SqlServer "$env:PIM_SqlServer".Trim() -Log $cadenceLog
if (-not $mspLic.ok) { Stop-DownlinkJob -Code 2 -State failed -Detail "$($mspLic.message)" }

# Load the scenario + downlink + downlink-job cores (placement / verdict helpers).
. (Join-Path $shared 'PIM-ScenarioProfile.ps1')   # also dot-sources PIM-Downlink.ps1
. (Join-Path $shared 'PIM-DownlinkJob.ps1')
# §79.6: a central session revoke (signed intent) is QUEUED here as this tenant's own committed action -- New-PimChange.
. (Join-Path $shared 'PIM-ChangeQueue.ps1')

$placement = Get-PimDownlinkJobPlacement -Scenario $Scenario
JobLog ("placement: {0}" -f $placement.reason)

# --- 1) AUTHENTICATE the runtime identity (REST cert-SPN, else Managed Identity) ---
# The engine + downlink authenticate per-tenant inside the wrappers (cert-SPN via
# PIM-Rest.ps1 / PIM-ContextBuilder.ps1). The Job's runtime identity is a Managed
# Identity attached by the Job definition; for the SPN-cert model the thumbprint +
# client id are provided via env (read from the store at deploy time -- never a
# secret value). We DO NOT mint tokens here; we just record which identity model is
# in force so the run is auditable, and set the engine knobs the wrappers read.
$engineCid   = "$env:PIM_ENGINE_CLIENT_ID".Trim()
$engineThumb = "$env:PIM_ENGINE_CERT_THUMBPRINT".Trim()
if ($engineThumb) {
    JobLog ("identity model: SPN certificate (clientId={0} thumb={1}) -- {2}" -f $engineCid, $engineThumb, $placement.spnModel)
    $global:PIM_EngineClientId      = $engineCid
    $global:PIM_EngineCertThumbprint = $engineThumb
} else {
    JobLog ("identity model: Managed Identity ({0}) -- token acquired by the REST layer at call time" -f $placement.spnModel)
}

# --- baseline source resolution (private transport: a private-endpoint URL OR a mounted/pulled file). The refusal when
#     neither is present runs BEFORE the cadence gate, above. ------------------------------------------------------
# 🔴 REDACT THE QUERY STRING. This line used to log $BaselineUrl whole -- and when the cross-tenant
# path carried a SAS, its `sig=` landed in Log Analytics in cleartext (MEASURED 2026-09-03 on RIDE's
# first run). The SAS transport is retired (SEC-27: public-but-signed per DESIGN 13.7, no query string
# at all), and Deploy-PimDownlinkJob now refuses a URL that carries one -- the redaction stays so an
# older job definition still cannot print a credential.
if ("$BaselineUrl".Trim()) {
    if ("$BaselineUrl" -match '\?') { JobLog 'the baseline URL carries a QUERY STRING -- the SAS transport is retired; redeploy the job with the PLAIN blob URL (Deploy-PimDownlinkJob).' 'WARN' }
    JobLog ("baseline source: URL {0}" -f ($BaselineUrl -replace '\?.*$', '?<redacted>'))
}
else { JobLog ("baseline source: mounted/pulled file {0}" -f $BaselineDocPath) }
# 71.35: which master signing keys this tenant trusts (Test-PimBaselineDoc reads PIM_BaselineTrustedKeys from the env).
$__pins = @("$env:PIM_BaselineTrustedKeys" -split '[,;\s]+' | Where-Object { "$_".Trim() })
if ($__pins.Count) { JobLog ("trusted master signing key(s): {0} (a bundle signed by any other key is refused)" -f ($__pins -join ', ')) }
else { JobLog 'trusted master signing keys: none pinned -- only bundles signed by the embedded product certificate verify' 'WARN' }

# --- 2) COMPOSE downlink-sync THEN engine apply via the scenario runner --------
# Invoke-PimScenarioRun.ps1 is the single scenario-bound runner: for S5/S6 it runs
# the downlink (pull -> verify -> ring-gate -> stage -> apply into the slave) and
# THEN the engine apply (admins + delegation groups/roles/AUs), in that order. We
# INVOKE it (never edit it). It honours the mass-disable guard through the engine.
$runner = Join-Path $solRoot 'setup\Invoke-PimScenarioRun.ps1'
if (-not (Test-Path -LiteralPath $runner)) {
    JobLog "scenario runner not found: $runner" 'ERROR'
    Stop-DownlinkJob -Code 3 -State failed -Detail "scenario runner not found: $runner"
}

$runArgs = @{
    Scenario    = $Scenario
    TenantId    = $TenantId
    SlaveRing   = $SlaveRing
    EngineScope = $EngineScope
    EngineMode  = $EngineMode
    WhatIfMode  = [bool]$WhatIfMode
}
# IMP-13: arm the recognisability guard. Passed ONLY when known -- an empty list would look like
# an explicit "no prefixes" rather than "not supplied", and the plan distinguishes the two.
# 🔴 THE PREFIXES COME FROM THIS TENANT'S OWN SETTINGS (operator, 2026-09-22: "but why did we have an
# orphaned pim_slaveadminprefixes" -> "it should reflect the settings").
# PIM_SlaveAdminPrefixes was typed into the MSP build config at onboarding (PIM-MspBuild
# `adminPrefixes`, validated only for BEING THERE) and pinned into this job's env. The tenant's real
# admin naming lives in its own store, in `NamingConventions.AdminAccountPatterns` -- the value its
# ENGINE uses. Two copies of one fact, nothing reconciling them: measured on the live pair, the env
# said `Admin-,admin-` while the tenant's own setting said `adm-`, and the mismatch decided which
# administrators were replicated. A deploy-time copy of a runtime setting can only drift.
# 🔑 So the STORE wins, the env is a fallback for a store that has not been seeded yet, and a
# disagreement is SAID rather than silently resolved.
$__prefFromStore = @()
try {
    if (Get-Command Import-PimSettingsFromStore -ErrorAction SilentlyContinue) { [void](Import-PimSettingsFromStore) }
    if (Get-Command Get-PimAdminAccountPrefixes -ErrorAction SilentlyContinue) {
        $__prefFromStore = @(@(Get-PimAdminAccountPrefixes) | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
    }
} catch { JobLog ("could not read this tenant's admin naming from its store: {0}" -f $_.Exception.Message) 'WARN' }
$__prefFromEnv = @(@($SlaveAdminPrefixes) | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
$__prefSource = ''
if ($__prefFromStore.Count) {
    $SlaveAdminPrefixes = $__prefFromStore
    $__prefSource = "this tenant's own settings (NamingConventions.AdminAccountPatterns)"
    if ($__prefFromEnv.Count -and (($__prefFromEnv -join ',') -ne ($__prefFromStore -join ','))) {
        JobLog ("admin naming: the job's PIM_SlaveAdminPrefixes ({0}) DISAGREES with this tenant's own setting ({1}). The tenant's setting is used -- it is what its engine matches on. Remove the deploy-time value (or correct `adminPrefixes` in the build config) so there is one copy." -f ($__prefFromEnv -join ', '), ($__prefFromStore -join ', ')) 'WARN'
    }
} elseif ($__prefFromEnv.Count) {
    $SlaveAdminPrefixes = $__prefFromEnv
    $__prefSource = 'the job env (PIM_SlaveAdminPrefixes) -- this tenant has no AdminAccountPatterns in its store yet'
}
if (@($SlaveAdminPrefixes).Count) {
    $runArgs['SlaveAdminPrefixes'] = @($SlaveAdminPrefixes)
    JobLog ("slave admin prefixes: {0} (from {1}) -- used to REPORT a naming mismatch; since 2.4.412 it never withholds an admin" -f (@($SlaveAdminPrefixes) -join ', '), $__prefSource)
} else {
    JobLog 'slave admin prefixes: none known (no AdminAccountPatterns in this tenant''s store and no PIM_SlaveAdminPrefixes) -- a naming mismatch cannot be reported this run. Replication is unaffected.' 'WARN'
}
$retraction = Resolve-PimDownlinkRetractionOptIn -Value $AllowRetraction
if ($retraction.allow) { $runArgs['AllowRetraction'] = $true; JobLog $retraction.reason 'WARN' }
elseif (-not $retraction.recognised) { JobLog $retraction.reason 'WARN' }
else { JobLog $retraction.reason }
if ("$BaselineDocPath".Trim()) { $runArgs['BaselineDocPath'] = $BaselineDocPath }
elseif ("$BaselineUrl".Trim()) {
    $runArgs['BaselineUrl'] = $BaselineUrl
    if ("$BaselineAccessToken".Trim()) { $runArgs['BaselineAccessToken'] = $BaselineAccessToken }
}
# SEC-24/25: the runner reads this tenant's anti-rollback floor + revoked signers from its OWN store and checks the
# master's central kill; the kill URL defaults to the bundle's sibling, so only an explicit override is passed.
if ("$CentralKillUrl".Trim()) { $runArgs['CentralKillUrl'] = "$CentralKillUrl".Trim() }

JobLog "invoking scenario runner (downlink-sync -> engine-apply) ..."
$result = $null
try {
    $result = & $runner @runArgs
} catch {
    # 🔴 LOG WHERE IT THREW, NOT JUST WHAT IT SAID. This handler used to emit the message alone,
    # and for a generic PowerShell binding error that is not a diagnosis -- RIDE's first run
    # reported only "Cannot bind argument to parameter 'Path' because it is an empty string",
    # which names neither the script, the line, nor the call. This runs UNATTENDED in a container
    # nobody can attach a debugger to, so the one place the stack could have been captured is
    # here, and it was being discarded. Reproducing on Windows did not reproduce it (the same
    # inputs ran clean), so the trace is the only route to the cause.
    JobLog ("scenario run threw: {0}" -f $_.Exception.Message) 'ERROR'
    JobLog ("  type    : {0}" -f $_.Exception.GetType().FullName) 'ERROR'
    if ($_.InvocationInfo) {
        JobLog ("  at      : {0}:{1}" -f $_.InvocationInfo.ScriptName, $_.InvocationInfo.ScriptLineNumber) 'ERROR'
        JobLog ("  line    : {0}" -f "$($_.InvocationInfo.Line)".Trim()) 'ERROR'
    }
    foreach ($f in @("$($_.ScriptStackTrace)" -split "`r?`n")) {
        if ("$f".Trim()) { JobLog ("  stack   : {0}" -f $f.Trim()) 'ERROR' }
    }
    Stop-DownlinkJob -Code 4 -State failed -Detail ("scenario run threw: {0}" -f $_.Exception.Message)
}

# --- 3) structured run summary to the log stream (observability) ---------------
$ok = $false
if ($result) {
    $ok = [bool](Get-PimDownlinkJobValue -Object ($result | Select-Object -Last 1) -Key 'ok')
    foreach ($r in @($result)) {
        $steps = Get-PimDownlinkJobValue -Object $r -Key 'steps'
        if ($steps) {
            foreach ($s in @($steps)) {
                JobLog ("  step [{0}] {1} -- {2}" -f $(if ($s.ok) { 'OK' } else { 'XX' }), $s.step, $s.detail)
            }
        }
    }
}
$held = $false
if ($result) { $held = [bool](Get-PimDownlinkJobValue -Object ($result | Select-Object -Last 1) -Key 'held') }
if ($ok -and $held) {
    # 71.13 -- HELD is not FAILED. The pull applied; the engine's policy mass-change breaker held a change set that
    # needs an operator's approval (the plan hash + approve command are in the engine-apply step above, and the
    # breaker raised its own alert). The execution succeeds, and this line says why it still needs attention.
    JobLog ("==== downlink JOB HELD ({0}; NEEDS APPROVAL -- see the engine-apply step) ====" -f $(if ($WhatIfMode) { 'planned' } else { 'applied' })) 'WARN'
    Stop-DownlinkJob -Code 0 -State held -Detail ("{0}; a policy change set NEEDS APPROVAL (see the engine-apply step)" -f $(if ($WhatIfMode) { 'planned' } else { 'applied' }))
}
# The failing step, in the record the Manager shows (the first step that did not succeed).
$failedStep = ''
foreach ($r in @($result)) { foreach ($s in @(Get-PimDownlinkJobValue -Object $r -Key 'steps')) { if ($s -and -not $s.ok -and -not $failedStep) { $failedStep = ("{0}: {1}" -f $s.step, $s.detail) } } }
if ($ok) {
    JobLog ("==== downlink JOB SUCCEEDED ({0}) ====" -f $(if ($WhatIfMode) { 'planned' } else { 'applied' }))
    # 🔴 THE REASON HAS TO SURVIVE THE CONTAINER (operator, 2026-09-22: "where in the logs can i find
    # the reason"). The plan line -- how many admins were projected, what was excluded by policy or
    # ring, how many groups will be created, which dependencies were auto-included -- was written to
    # stdout only. A Container Apps execution keeps its replica for minutes, and this environment has
    # no Log Analytics workspace, so an hour later the one sentence that explains the run is simply
    # gone: the Manager showed "pulled, verified and applied" and nothing else. The downlink-sync
    # step's own detail is now recorded WITH the result, so the Job schedule page can show it.
    $__planDetail = ''
    foreach ($r in @($result)) {
        foreach ($s in @(Get-PimDownlinkJobValue -Object $r -Key 'steps')) {
            if ($s -and "$($s.step)" -eq 'downlink-sync' -and "$($s.detail)".Trim()) { $__planDetail = "$($s.detail)".Trim() }
        }
    }
    $__base = $(if ($WhatIfMode) { 'planned (WhatIf)' } else { 'pulled, verified and applied' })
    # Capped: this lands in a stored result the page renders, not in a log file.
    if ($__planDetail.Length -gt 900) { $__planDetail = $__planDetail.Substring(0, 897) + '...' }
    Stop-DownlinkJob -Code 0 -State succeeded -Detail $(if ($__planDetail) { "$__base -- $__planDetail" } else { $__base })
} else {
    JobLog "==== downlink JOB FAILED ====" 'ERROR'
    Stop-DownlinkJob -Code 1 -State failed -Detail $(if ($failedStep) { $failedStep } else { 'the scenario run reported failure (see the job log)' })
}
