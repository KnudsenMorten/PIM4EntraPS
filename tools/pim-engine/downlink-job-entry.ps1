#Requires -Version 5.1
<#
.SYNOPSIS
    §31.3 CLOUD-NATIVE downlink JOB entrypoint -- the command an Azure Container
    Apps scheduled Job (Deploy-PimDownlinkJob.ps1) runs ON ITS CRON CADENCE inside
    the pim-manager container. Operator directive 2026-06-17: "all run in cloud
    only compute, in one test"; "run it through the containers in the slave".

.DESCRIPTION
    Runs ENTIRELY on cloud container compute. On each scheduled execution it:

      1. AUTHENTICATES the runtime identity (Managed Identity by default; an SPN
         certificate when $env:PIM_ENGINE_CERT_THUMBPRINT is set). REST-only, no
         PowerShell Az/Graph modules, never a secret, never device-code.
      2. Composes the ring-gated downlink + the engine apply for the scenario by
         INVOKING the existing live wrapper setup/Invoke-PimScenarioRun.ps1, which:
            * managed (S5/S6) -> downlink-sync (pull the SIGNED master baseline ->
              verify RSA-SHA256 -> ring-gate admin.Ring <= slave.Ring -> stage the
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
    The managed/slave tenant id + its registry ring (default 2 = test).

.PARAMETER BaselineUrl
    Private-endpoint blob URL of the master's signed baseline bundle (HTTPS over the
    private cross-tenant VNet -- never the public internet). Mutually exclusive with
    -BaselineDocPath. Falls back to $env:PIM_BaselineUrl.

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
    [ValidateRange(0,2)][int]$SlaveRing = 2,
    [string]$BaselineUrl     = $env:PIM_BaselineUrl,
    [string]$BaselineAccessToken = $env:PIM_BaselineAccessToken,
    [string]$BaselineDocPath = $env:PIM_BaselineDocPath,
    [string]$EngineScope = 'All',
    [ValidateSet('Full','Delta')][string]$EngineMode = 'Delta',
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
JobLog ("scenario={0} tenant={1} ring={2} mode={3}" -f $Scenario, $TenantId, $SlaveRing, $(if ($WhatIfMode) { 'WHATIF' } else { 'APPLY' }))

# Load the scenario + downlink + downlink-job cores (placement / verdict helpers).
. (Join-Path $shared 'PIM-ScenarioProfile.ps1')   # also dot-sources PIM-Downlink.ps1
. (Join-Path $shared 'PIM-DownlinkJob.ps1')

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

# --- baseline source resolution (private transport: a private-endpoint URL OR a
#     mounted/pulled file). Refuse if neither is present (fail-safe). -----------
if (-not "$BaselineUrl".Trim() -and -not "$BaselineDocPath".Trim()) {
    JobLog 'no baseline source: supply -BaselineUrl (private-endpoint blob) or -BaselineDocPath (mounted bundle) / set PIM_BaselineUrl|PIM_BaselineDocPath' 'ERROR'
    exit 2
}
if ("$BaselineUrl".Trim()) { JobLog ("baseline source: private URL {0}" -f $BaselineUrl) }
else { JobLog ("baseline source: mounted/pulled file {0}" -f $BaselineDocPath) }

# --- 2) COMPOSE downlink-sync THEN engine apply via the scenario runner --------
# Invoke-PimScenarioRun.ps1 is the single scenario-bound runner: for S5/S6 it runs
# the downlink (pull -> verify -> ring-gate -> stage -> apply into the slave) and
# THEN the engine apply (admins + delegation groups/roles/AUs), in that order. We
# INVOKE it (never edit it). It honours the mass-disable guard through the engine.
$runner = Join-Path $solRoot 'setup\Invoke-PimScenarioRun.ps1'
if (-not (Test-Path -LiteralPath $runner)) {
    JobLog "scenario runner not found: $runner" 'ERROR'
    exit 3
}

$runArgs = @{
    Scenario    = $Scenario
    TenantId    = $TenantId
    SlaveRing   = $SlaveRing
    EngineScope = $EngineScope
    EngineMode  = $EngineMode
    WhatIfMode  = [bool]$WhatIfMode
}
if ("$BaselineDocPath".Trim()) { $runArgs['BaselineDocPath'] = $BaselineDocPath }
elseif ("$BaselineUrl".Trim()) {
    $runArgs['BaselineUrl'] = $BaselineUrl
    if ("$BaselineAccessToken".Trim()) { $runArgs['BaselineAccessToken'] = $BaselineAccessToken }
}

JobLog "invoking scenario runner (downlink-sync -> engine-apply) ..."
$result = $null
try {
    $result = & $runner @runArgs
} catch {
    JobLog ("scenario run threw: {0}" -f $_.Exception.Message) 'ERROR'
    exit 4
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
if ($ok) {
    JobLog ("==== downlink JOB SUCCEEDED ({0}) ====" -f $(if ($WhatIfMode) { 'planned' } else { 'applied' }))
    exit 0
} else {
    JobLog "==== downlink JOB FAILED ====" 'ERROR'
    exit 1
}
