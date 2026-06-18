#requires -Version 5.1
<#
.SYNOPSIS
    PIM4EntraPS -- FULL update-lifecycle automation: after PIM code is pulled, one coherent flow
    of detect -> build -> deploy -> verify -> notify -> ensure health monitoring.
    REQUIREMENTS.md sec.1 (Hosting/Runtime) + sec.2 (Containers) + sec.5 (SQL/Data) + sec.20.

.DESCRIPTION
    ONE script handles updates from BOTH pull paths:

      * COMMUNITY git pull (-Source git-pull): local/VM; store SQLEXPRESS or Azure SQL; local
        Manager. Build = local build/package + relaunch.
      * sync-automateit pull (-Source sync-automateit, hosted): Azure SQL + Container Apps. Build =
        az acr build; deploy = roll the ACA revision to the freshly-built image.

    The six steps (the orchestrator EXECUTES; the pure core in engine/_shared/PIM-UpdateLifecycle.ps1
    DECIDES -- every risky decision is unit-tested offline):

      1. DETECT  -- does the pulled update need a SQL/schema upgrade (vs the deployed DB, via the
                    locked-schema column audit + Test-PimBaselineDoc-style preflight) and/or a
                    Manager web-GUI update (content hash / VERSION over tools/pim-manager/* vs the
                    running image)?
      2. BUILD   -- when a GUI update is needed, rebuild the Manager image FROM THE PULLED CODE
                    (Build-PimManagerImage.ps1: az acr build hosted / local build community). This
                    is the gap: sync-automateit / Update-PimContainers -SkipBuild only ROLL a
                    pre-built image.
      3. DEPLOY  -- roll the Container App to the FRESHLY-BUILT image (Update-PimContainers.ps1, NOT
                    -SkipBuild) and/or apply the idempotent SQL schema upgrade
                    (preflight -> apply -> re-preflight; never destructive).
      4. VERIFY  -- run the hosted smoke (tests/live/Test-PimManagerHostedSmoke.ps1); AUTO-ROLLBACK
                    on failure (prior revision; SQL preflight gate before apply).
      5. NOTIFY  -- email the update outcome (success/failure, what was built/deployed/upgraded) to
                    the owner, reusing the EXISTING mailer (Send-PimNotifyMail -- the same mail path
                    as the synthetic-monitor work). Does NOT reinvent a mailer.
      6. ENSURE  -- make sure the deployable health monitor with mail-notify (the synthetic monitor:
        MONITOR   checks Manager + CEH health every ~5-15 min, emails the owner on failure,
                    debounced) is in place/refreshed after the update; deploy/refresh it if missing.
                    REUSES the synthetic monitor (feat/synthetic-monitor) -- never duplicates it.

    MODES:
      -DetectOnly (default, safe): report { SqlUpdateRequired; GuiUpdateRequired; details }, make NO
                  changes. This is the default so a bare run never mutates anything.
      -Apply    : build + deploy + schema + notify + ensure-monitor, gated, rollback on fail.

    Idempotent. PS 5.1-safe. REST/cert + MI only via az (no PowerShell modules). Azure SQL single
    store. West Europe / Denmark East only. ACA via Update-PimContainers (--yaml for workers).

    NOTE (synthetic-monitor dependency): the mailer is reused by INTERFACE (Send-PimNotifyMail). The
    monitor deploy script is reused by interface too: -MonitorDeployScript points at the
    feat/synthetic-monitor deploy entry. If that branch is not yet on main, step 6 reports the
    wire-up it WOULD run and self-skips (it never fabricates a monitor). Wire-up: once
    feat/synthetic-monitor lands, set -MonitorDeployScript to its deploy entry (default path tried:
    tools/setup/Deploy-PimSyntheticMonitor.ps1).

.PARAMETER Source
    'git-pull' (community/local/VM) or 'sync-automateit' (hosted ACA + Azure SQL).

.PARAMETER DetectOnly
    Report only; make no changes. THE DEFAULT (also implied when neither -DetectOnly nor -Apply set).

.PARAMETER Apply
    Actually build/deploy/upgrade/notify/ensure-monitor (gated). Rollback on verify failure.

.EXAMPLE
    .\Invoke-PimUpdate.ps1 -Source sync-automateit
    Detect-only (default): report whether the hosted deployment needs a GUI rebuild and/or a SQL upgrade.

.EXAMPLE
    .\Invoke-PimUpdate.ps1 -Source sync-automateit -Apply
    Hosted: build (if GUI changed) -> roll -> SQL upgrade (if needed) -> verify -> notify -> ensure monitor.

.EXAMPLE
    .\Invoke-PimUpdate.ps1 -Source git-pull -Apply
    Community: local build/package + relaunch + local SQL upgrade + notify + ensure monitor.

.NOTES
    Foldable into sync-automateit (PR #24) + a git post-merge hook. Decisions in the pure core
    (engine/_shared/PIM-UpdateLifecycle.ps1) are offline-unit-tested (tests/Test-PimUpdateLifecycle.ps1).
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [ValidateSet('git-pull','sync-automateit','from-master')][string]$Source = 'sync-automateit',
    # s31: resolve the update source + hosting from a deployment SCENARIO (S1..S6). When set, the
    # scenario's resolved updateSource (git-pull | sync-automateit | from-master) and managedHosting
    # (central|local) OVERRIDE -Source -- so one knob drives the whole update path.
    [ValidateSet('S1','S2','S3','S4','S5','S6')][string]$Scenario,
    [ValidateSet('central','local')][string]$ManagedHosting,   # only used for from-master (S5=central, S6=local); auto-set from -Scenario
    [switch]$DetectOnly,
    [switch]$Apply,
    # hosted deploy targets (passthrough to the existing roller / smoke).
    [string]$ResourceGroup = 'rg-pim-manager-web',
    [string]$AcrName       = 'acrsecurityinsight',
    [string]$ImageRepo     = 'pim-manager',
    [string]$ManagerApp    = 'ca-pim-manager',
    [string[]]$Apps        = @('ca-pim-manager','ca-pim-scheduler','ca-pim-engine','ca-pim-connector','ca-pim-deltaqueue','ca-pim-discovery'),
    [string]$ImageTag,                                    # override the build/deploy tag (default = pulled VERSION)
    # SQL detection inputs (hosted = Azure SQL; community = SQLEXPRESS/Azure SQL).
    [string]$SqlConnectionString,                         # if set, the orchestrator reads deployed columns to detect drift
    # notify + monitor reuse.
    [string]$Recipient          = 'mok@mortenknudsen.net',
    [string]$MonitorDeployScript,                         # feat/synthetic-monitor deploy entry (reused by interface)
    [int]$MonitorIntervalMinutes = 10,
    [switch]$SkipVerify,                                  # only for a registry with no live hosted Manager
    [switch]$SkipNotify
)
$ErrorActionPreference = 'Stop'
$here    = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
$solRoot = Split-Path -Parent (Split-Path -Parent $here)            # SOLUTIONS/PIM4EntraPS
function Step($m){ Write-Host "==> $m" -ForegroundColor Cyan }
function Info($m){ Write-Host "    $m" -ForegroundColor DarkGray }
function Warn($m){ Write-Host "    $m" -ForegroundColor Yellow }
function Have($cmd){ [bool](Get-Command $cmd -ErrorAction SilentlyContinue) }

# ---- load the pure decision core + dependencies (REUSE, never re-implement) ----
. (Join-Path $solRoot 'engine\_shared\PIM-SyncAutomateIT.ps1')        # semver/sync/health/rollback
. (Join-Path $solRoot 'engine\_shared\PIM-SchemaConformance.ps1')     # locked-schema + per-table plan
. (Join-Path $solRoot 'engine\_shared\PIM-UpdateLifecycle.ps1')       # detect/build/notify/monitor core
. (Join-Path $solRoot 'engine\_shared\PIM-ScenarioProfile.ps1')       # s31 scenario -> knob resolver
# the mailer (same path as the synthetic-monitor work). Loading PIM-Notify pulls in Send-PimNotifyMail.
$notifyLib = Join-Path $solRoot 'engine\_shared\PIM-Notify.ps1'
if (Test-Path $notifyLib) { . $notifyLib }

# default-safe: if neither switch is given, DetectOnly wins.
if (-not $Apply) { $DetectOnly = $true }
if ($DetectOnly -and $Apply) { throw "Pass either -DetectOnly or -Apply, not both." }

# ---- s31: a -Scenario resolves the update source + managed hosting, overriding -Source ----
# The build/roll SUB-scripts (Build-PimManagerImage / Update-PimContainers) only know git-pull |
# sync-automateit, so from-master is mapped to a build source by managed hosting: central => the
# ACR-build/ACA-roll path (sync-automateit), local => the local build/relaunch path (git-pull).
$buildSource = $Source
if ($Scenario) {
    $plan = Get-PimScenarioEntryPlan -Scenario $Scenario
    $Source = $plan.updateSource
    if (-not "$ManagedHosting".Trim() -and "$($plan.managedHosting)".Trim()) { $ManagedHosting = $plan.managedHosting }
    Write-Host ("[scenario] {0} -> updateSource={1} managedHosting={2} edition={3} hosting={4} spn={5}" -f `
        $plan.id, $plan.updateSource, $plan.managedHosting, $plan.activeEdition, $plan.hostingLocation, $plan.spnModel) -ForegroundColor Cyan
}
if (-not "$ManagedHosting".Trim()) { $ManagedHosting = 'local' }
# Resolve the build-source the sub-scripts understand.
if ($Source -eq 'from-master') { $buildSource = if ($ManagedHosting -eq 'central') { 'sync-automateit' } else { 'git-pull' } }
else { $buildSource = $Source }

$profile = Get-PimUpdateSourceProfile -Source $Source -ManagedHosting $ManagedHosting

Write-Host "=== PIM4EntraPS UPDATE-LIFECYCLE ($Source; $(if($DetectOnly){'DETECT-ONLY'}else{'APPLY'})) ===" -ForegroundColor Cyan
Info "build mode: $($profile.buildMode); deploy mode: $($profile.deployMode); hosted: $($profile.isHosted)"

# =============================================================================
# helpers to GATHER FACTS (the side-effecting reads; the decisions stay pure)
# =============================================================================
function Get-PulledVersion {
    $vf = Join-Path $solRoot 'VERSION'
    if (Test-Path $vf) { return (Get-Content -LiteralPath $vf -Raw).Trim() }
    return ''
}
function Get-PulledManagerContentHash {
    $mgrDir = Join-Path $solRoot 'tools\pim-manager'
    if (-not (Test-Path $mgrDir)) { return '' }
    $files = @(Get-ChildItem -Path $mgrDir -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -notmatch '\\cache\\' -and $_.Name -notmatch '\.custom\.' })
    $digests = foreach ($f in $files) {
        $rel = $f.FullName.Substring($mgrDir.Length).TrimStart('\','/')
        [pscustomobject]@{ path = $rel; sha256 = (Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256).Hash }
    }
    Get-PimContentHash -FileDigests @($digests)
}
function Get-RunningManagerInfo {
    # hosted: read the running image tag + its baked-in content hash label via az (best-effort).
    # community: read the local package marker if present. Blank hash => detection treats as needs-update.
    $info = @{ version = ''; contentHash = '' }
    if ($profile.isHosted -and (Have 'az')) {
        try {
            $img = az containerapp show -g $ResourceGroup -n $ManagerApp --query "properties.template.containers[0].image" -o tsv 2>$null
            if ("$img".Trim()) { $info.version = ("$img" -split ':')[-1] }
            # content hash is published as an image env/label; read the app env var if present.
            $h = az containerapp show -g $ResourceGroup -n $ManagerApp --query "properties.template.containers[0].env[?name=='PIM_MANAGER_CONTENT_HASH'].value | [0]" -o tsv 2>$null
            if ("$h".Trim()) { $info.contentHash = "$h".Trim() }
        } catch {}
    } else {
        $pkg = Join-Path $solRoot 'output\manager-package\manager-package.json'
        if (Test-Path $pkg) { try { $m = Get-Content $pkg -Raw | ConvertFrom-Json; $info.version = "$($m.imageTag)"; $info.contentHash = "$($m.contentHash)" } catch {} }
    }
    return $info
}
function Get-DeployedColumns {
    # Read each locked-SQL table's actual columns from the deployed DB to detect drift. Requires a
    # connection string + sqlcmd/Invoke-Sqlcmd; returns @{} (unknown) when neither is available
    # (then detection conservatively flags create-needed for absent tables only). REST/cert + MI.
    param([string]$ConnString)
    $cols = @{}
    if (-not "$ConnString".Trim()) { return $cols }
    $schema = Get-PimLockedSqlSchema
    $haveSqlcmd = Have 'sqlcmd'
    $haveInvoke = Have 'Invoke-Sqlcmd'
    if (-not ($haveSqlcmd -or $haveInvoke)) { Warn 'no sqlcmd / Invoke-Sqlcmd -- cannot read deployed columns (SQL drift detection limited to missing-table).'; return $cols }
    foreach ($table in @($schema.Keys)) {
        $parts = $table -split '\.'; $sch = $parts[0]; $tbl = $parts[-1]
        $q = "SET NOCOUNT ON; SELECT c.name FROM sys.columns c JOIN sys.objects o ON c.object_id=o.object_id JOIN sys.schemas s ON o.schema_id=s.schema_id WHERE s.name='$sch' AND o.name='$tbl';"
        $names = @()
        try {
            if ($haveInvoke) { $names = @(Invoke-Sqlcmd -ConnectionString $ConnString -Query $q -ErrorAction Stop | ForEach-Object { $_.name }) }
            else { $names = @(sqlcmd -C -h -1 -W -Q $q 2>$null | Where-Object { "$_".Trim() -and "$_" -notmatch '^\(' }) }
        } catch { Warn "could not read columns for $table : $($_.Exception.Message)" }
        if ($names.Count -gt 0) { $cols[$table] = $names }
    }
    return $cols
}
function Test-MonitorDeployed {
    # Is the synthetic health monitor deployed? Best-effort: hosted = an ACA job named *monitor*;
    # community = a scheduled task. Returns $false (treat as needs-deploy) when it can't tell.
    if ($profile.isHosted -and (Have 'az')) {
        try { $j = az containerapp job list -g $ResourceGroup --query "[?contains(name,'monitor')].name | [0]" -o tsv 2>$null; if ("$j".Trim()) { return $true } } catch {}
        return $false
    }
    try { $t = Get-ScheduledTask -TaskName 'PIM-SyntheticMonitor' -ErrorAction SilentlyContinue; if ($t) { return $true } } catch {}
    return $false
}

# =============================================================================
# STEP 1 -- DETECT (always runs; the only step a detect-only run performs)
# =============================================================================
Step '1. DETECT'
$pulledVersion = if ("$ImageTag".Trim()) { $ImageTag } else { Get-PulledVersion }
$pulledHash    = Get-PulledManagerContentHash
$running       = Get-RunningManagerInfo
Info "pulled VERSION: $pulledVersion; running VERSION: $($running.version)"
Info "pulled GUI content hash: $pulledHash"
Info "running GUI content hash: $($running.contentHash)"

$guiPlan = Get-PimGuiUpdatePlan -PulledContentHash $pulledHash -RunningContentHash $running.contentHash `
            -PulledVersion $pulledVersion -RunningVersion $running.version
$deployedCols = Get-DeployedColumns -ConnString $SqlConnectionString
$sqlPlan = Get-PimSqlUpdatePlan -DeployedColumns $deployedCols -LockedSqlSchema (Get-PimLockedSqlSchema) `
            -DeployedSchemaVersion $running.version -PulledSchemaVersion $pulledVersion
$detection = Get-PimUpdateDetection -GuiPlan $guiPlan -SqlPlan $sqlPlan

Write-Host ""
Write-Host "  DETECTION:" -ForegroundColor Cyan
Write-Host ("    GuiUpdateRequired = {0}  ({1})" -f $detection.GuiUpdateRequired, $guiPlan.reason)
Write-Host ("    SqlUpdateRequired = {0}  ({1})" -f $detection.SqlUpdateRequired, $sqlPlan.reason)
Write-Host ""

$buildPlan = Get-PimBuildPlan -GuiUpdateRequired $detection.GuiUpdateRequired -Source $Source -ImageTag $pulledVersion -ImageRepo $ImageRepo -ManagedHosting $ManagedHosting
$monitorInPlace = Test-MonitorDeployed
$applyPlan = Get-PimUpdateApplyPlan -Detection $detection -BuildPlan $buildPlan -Source $Source -Apply:$Apply -MonitorInPlace $monitorInPlace -ManagedHosting $ManagedHosting

Write-Host "  PLAN:" -ForegroundColor Cyan
foreach ($s in $applyPlan.steps) { Write-Host ("    {0}. {1,-15} [{2}] {3}" -f $s.step, $s.name, $s.action, $s.detail) }
Write-Host ""

if ($DetectOnly) {
    Step 'DETECT-ONLY -- no changes made. Re-run with -Apply to act on the plan above.'
    # emit the machine-readable detect payload (the documented -DetectOnly contract).
    [pscustomobject]@{ SqlUpdateRequired = $detection.SqlUpdateRequired; GuiUpdateRequired = $detection.GuiUpdateRequired; details = $detection.details }
    return
}

if (-not $detection.AnyUpdateRequired -and $monitorInPlace) {
    Step 'Nothing to do (no GUI/SQL update + monitor already in place).'
    if (-not $SkipNotify) { Step '5. NOTIFY (noop -- suppressed: nothing changed)' }
    return
}

# =============================================================================
# APPLY path -- run each 'do' step; capture rollback target; rollback + notify on failure.
# =============================================================================
$built = $false; $deployed = $false; $schemaUpgraded = $false; $verifyHealthy = $true
$prevRev = ''
$outcome = 'success'; $errDetail = ''

try {
    # ---- capture pre-update revision (rollback target) BEFORE any change -----
    if ($profile.isHosted -and (Have 'az')) {
        try { $prevRev = az containerapp revision list -g $ResourceGroup -n $ManagerApp --query "[?properties.active].name | [0]" -o tsv 2>$null } catch {}
        if (-not "$prevRev".Trim()) { try { $prevRev = az containerapp revision list -g $ResourceGroup -n $ManagerApp --query "[0].name" -o tsv 2>$null } catch {} }
        Info "pre-update revision (rollback target): $(if($prevRev){$prevRev}else{'(unknown)'})"
    }

    # ---- STEP 2 -- BUILD (only if GUI update needed) -------------------------
    if (($applyPlan.steps | Where-Object { $_.name -eq 'build' }).do) {
        Step "2. BUILD ($($buildPlan.buildMode)) -> $ImageRepo`:$($buildPlan.imageTag)"
        $builder = Join-Path $here 'Build-PimManagerImage.ps1'
        if ($PSCmdlet.ShouldProcess("$ImageRepo`:$($buildPlan.imageTag)", 'build from pulled code')) {
            & $builder -ImageTag $buildPlan.imageTag -Source $buildSource -AcrName $AcrName -ImageRepo $ImageRepo
            if ($LASTEXITCODE -and $LASTEXITCODE -ne 0) { throw "Build-PimManagerImage.ps1 failed (exit $LASTEXITCODE)." }
            $built = $true
        }
    } else { Step '2. BUILD [skip -- no GUI update]' }

    # ---- STEP 3 -- DEPLOY: roll freshly-built image AND/OR apply SQL upgrade --
    Step '3. DEPLOY'
    if ($detection.GuiUpdateRequired) {
        $roller = Join-Path $here 'Update-PimContainers.ps1'
        if ($profile.isHosted) {
            Info "roll ACA to the freshly-built image $($buildPlan.imageTag) (NOT -SkipBuild -- the image is already built this run, so roll only)"
            if ($PSCmdlet.ShouldProcess("$($Apps -join ', ')", "roll -> $($buildPlan.imageTag)")) {
                & $roller -ImageTag $buildPlan.imageTag -SkipBuild -ResourceGroup $ResourceGroup -AcrName $AcrName -ImageRepo $ImageRepo -Apps $Apps
                if ($LASTEXITCODE -and $LASTEXITCODE -ne 0) { throw "Update-PimContainers.ps1 (roll) failed (exit $LASTEXITCODE)." }
                $deployed = $true
            }
        } else {
            Info 'community: the freshly-built/packaged Manager is the local deploy (Build relaunched it).'
            $deployed = $true
        }
    } else { Info 'no GUI update -- no image roll.' }

    if ($detection.SqlUpdateRequired) {
        Step '   SQL schema upgrade (preflight -> apply -> re-preflight; idempotent, never destructive)'
        if (-not "$SqlConnectionString".Trim()) {
            Warn 'SqlUpdateRequired but no -SqlConnectionString -- emitting the guarded DDL plan only (apply it with your SQL deploy identity).'
            foreach ($tp in @($sqlPlan.tables | Where-Object { -not $_.conformant })) {
                if ($tp.exists) {
                    $cols = if ($deployedCols.ContainsKey($tp.table)) { @($deployedCols[$tp.table]) } else { @() }
                    $ddl = New-PimSqlConformanceDdl -Table $tp.table -Spec (Get-PimLockedSqlSchema)[$tp.table] -ActualColumns $cols
                    Write-Host $ddl.ddl
                } else { Info "table $($tp.table) needs CREATE (run sql/local-schema.sql or platform-schema.sql)." }
            }
            $schemaUpgraded = $false
        } elseif (Have 'Invoke-Sqlcmd') {
            if ($PSCmdlet.ShouldProcess('deployed DB', 'apply idempotent schema upgrade')) {
                foreach ($tp in @($sqlPlan.tables | Where-Object { $_.exists -and -not $_.conformant })) {
                    $cols = @($deployedCols[$tp.table])
                    $ddl = New-PimSqlConformanceDdl -Table $tp.table -Spec (Get-PimLockedSqlSchema)[$tp.table] -ActualColumns $cols
                    Invoke-Sqlcmd -ConnectionString $SqlConnectionString -Query $ddl.ddl -ErrorAction Stop
                }
                # re-preflight: re-read columns and confirm conformant.
                $reCols = Get-DeployedColumns -ConnString $SqlConnectionString
                $rePlan = Get-PimSqlUpdatePlan -DeployedColumns $reCols -LockedSqlSchema (Get-PimLockedSqlSchema) -PulledSchemaVersion $pulledVersion -DeployedSchemaVersion $pulledVersion
                if ($rePlan.SqlUpdateRequired) { throw "SQL re-preflight still reports drift after upgrade: $($rePlan.reason)" }
                $schemaUpgraded = $true
                Info 'SQL upgrade applied + re-preflight clean.'
            }
        } else {
            Warn 'SqlUpdateRequired + connection string set but no Invoke-Sqlcmd -- run the emitted DDL with your SQL deploy tooling.'
        }
    } else { Info 'no SQL update needed.' }

    # ---- STEP 4 -- VERIFY: hosted smoke; auto-rollback on failure -----------
    if ($deployed -and -not $SkipVerify) {
        Step '4. VERIFY (hosted smoke: Test-PimManagerHostedSmoke.ps1)'
        $smoke = Join-Path $solRoot 'tests\live\Test-PimManagerHostedSmoke.ps1'
        $code = 0
        if (Test-Path $smoke) {
            & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $smoke
            $code = $LASTEXITCODE
        } else { Warn "hosted smoke not found at $smoke -- treating as UNVERIFIED."; $code = 1 }
        $verdict = Get-PimVerifyVerdict -ExitCode $code -PreviousRevision $prevRev
        $verifyHealthy = $verdict.Healthy
        Info "verify healthy=$verifyHealthy (smoke exit $code)"
        if (-not $verifyHealthy) {
            $outcome = 'rolledback'; $errDetail = "post-deploy verification failed (smoke exit $code)"
            if ($verdict.rollback.action -eq 'rollback' -and $profile.isHosted) {
                Warn $verdict.rollback.reason
                Step "   AUTO-ROLLBACK -> $($verdict.rollback.revision)"
                $roller = Join-Path $here 'Update-PimContainers.ps1'
                if ($PSCmdlet.ShouldProcess($ManagerApp, "rollback to $($verdict.rollback.revision)")) {
                    & $roller -Rollback $verdict.rollback.revision -ResourceGroup $ResourceGroup -AcrName $AcrName -ImageRepo $ImageRepo -Apps $Apps
                }
            } else {
                $errDetail += " -- NO rollback target captured; MANUAL rollback required"
            }
        }
    } elseif ($SkipVerify) { Step '4. VERIFY [skip -- -SkipVerify]' }
    else { Step '4. VERIFY [skip -- nothing deployed]' }
}
catch {
    $outcome = 'failure'; $errDetail = "$($_.Exception.Message)"
    Warn "UPDATE FAILED: $errDetail"
    # best-effort auto-rollback if we had captured a revision and deployed.
    if ($deployed -and $profile.isHosted -and "$prevRev".Trim()) {
        Warn "attempting auto-rollback to $prevRev"
        try {
            $roller = Join-Path $here 'Update-PimContainers.ps1'
            & $roller -Rollback $prevRev -ResourceGroup $ResourceGroup -AcrName $AcrName -ImageRepo $ImageRepo -Apps $Apps
            $outcome = 'rolledback'
        } catch { Warn "auto-rollback also failed: $($_.Exception.Message)" }
    }
}

# =============================================================================
# STEP 5 -- NOTIFY (always email the outcome -- success OR failure -- reuse mailer)
# =============================================================================
Step "5. NOTIFY (email outcome '$outcome' to $Recipient via Send-PimNotifyMail)"
$notifyPlan = Get-PimNotifyPlan -Outcome $outcome -Source $buildSource -Detection $detection `
                -Built $built -Deployed $deployed -SchemaUpgraded $schemaUpgraded `
                -ImageTag $buildPlan.imageTag -Recipient $Recipient -ErrorDetail $errDetail
Info "subject: $($notifyPlan.subject)"
if ($SkipNotify) { Warn 'notify SKIPPED (-SkipNotify).' }
elseif (-not (Get-Command Send-PimNotifyMail -ErrorAction SilentlyContinue)) {
    Warn 'Send-PimNotifyMail not available (PIM-Notify.ps1 not loaded / no Graph context) -- outcome NOT emailed.'
    Info 'WIRE-UP: this reuses the synthetic-monitor mail path (Send-PimNotifyMail). Configure $global:PIM_MailSender + Graph app-only Mail.Send.'
} else {
    if ($PSCmdlet.ShouldProcess($notifyPlan.recipient, "send '$($notifyPlan.type)' mail")) {
        $r = Send-PimNotifyMail -Type $notifyPlan.type -Tokens $notifyPlan.tokens -Recipient $notifyPlan.recipient
        Info ("mail sent={0} recipient={1} reason={2}" -f $r.sent, $r.recipient, $r.reason)
    }
}

# =============================================================================
# STEP 6 -- ENSURE HEALTH MONITORING (reuse the synthetic monitor; refresh if stale/missing)
# =============================================================================
Step '6. ENSURE HEALTH MONITORING (synthetic monitor: Manager+CEH health, mail-notify, debounced)'
$monPlan = Get-PimMonitorEnsurePlan -MonitorDeployed $monitorInPlace -IntervalMinutes $MonitorIntervalMinutes
Info "monitor action: $($monPlan.action) -- $($monPlan.reason) (interval $($monPlan.intervalMinutes)m)"
if ($monPlan.action -eq 'noop') {
    Info 'health monitor already in place + fresh -- nothing to do.'
} else {
    # reuse the synthetic-monitor deploy entry by INTERFACE. Default path tried if not supplied.
    $monScript = if ("$MonitorDeployScript".Trim()) { $MonitorDeployScript } else { Join-Path $here 'Deploy-PimSyntheticMonitor.ps1' }
    if (Test-Path $monScript) {
        Step "   $($monPlan.action) synthetic monitor via $monScript"
        if ($PSCmdlet.ShouldProcess($monScript, $monPlan.action)) {
            & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $monScript -IntervalMinutes $monPlan.intervalMinutes -Recipient $Recipient
        }
    } else {
        Warn "synthetic-monitor deploy script not found ($monScript)."
        Info 'WIRE-UP: this REUSES feat/synthetic-monitor (do NOT duplicate the monitor). Once that branch is on main,'
        Info "         pass -MonitorDeployScript <its deploy entry> (default tried: tools/setup/Deploy-PimSyntheticMonitor.ps1)."
        Info "         It deploys the monitor that checks Manager + CEH health every 5-15m and emails $Recipient on failure (debounced)."
    }
}

Write-Host ""
Step "DONE. outcome=$outcome (built=$built deployed=$deployed schemaUpgraded=$schemaUpgraded verifyHealthy=$verifyHealthy)"
if ($outcome -eq 'failure' -or $outcome -eq 'rolledback') { exit 1 }
