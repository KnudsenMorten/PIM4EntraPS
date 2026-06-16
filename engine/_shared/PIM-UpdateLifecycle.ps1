<#
  PIM4EntraPS -- update-lifecycle core (the PURE, fully-testable decision brain behind the
  full update-lifecycle automation: detect -> build -> deploy -> verify -> notify ->
  ensure-monitor). REQUIREMENTS.md sec.1 (Hosting/Runtime) + sec.2 (Containers) + sec.5
  (SQL/Data) + sec.20 (Testing).

  This file only DECIDES + RENDERS PLANS. No az calls, no HTTP, no PowerShell modules, no
  git, no file writes. The thin orchestrator (tools/setup/Invoke-PimUpdate.ps1) gathers the
  FACTS (pulled GUI content hash vs running image, pulled SQL schema spec vs deployed DB,
  health verdicts, whether the monitor is deployed) and ACTS on the plans this returns. That
  split keeps every risky decision -- "does this pulled update need a SQL upgrade?", "does it
  need a Manager rebuild?", "did the build/deploy/verify succeed -- if not, roll back", "is
  the health monitor in place?" -- unit-testable offline.

  It REUSES the sync-automateit core (PIM-SyncAutomateIT.ps1: semver compare, sync decision,
  health verdict, rollback plan) -- this file does NOT re-implement version math or rollback;
  it dot-sources that core and layers detect/build/notify/ensure-monitor on top.

  PS 5.1-safe: no ?./??/RSA.ImportFromPem; Set-StrictMode -Off; only built-in cmdlets.

  Public functions:
    * Get-PimContentHash             -- stable SHA256 over an ordered list of file digests
    * Get-PimGuiUpdatePlan           -- does the pulled Manager web GUI differ from the running one?
    * Get-PimSqlUpdatePlan           -- does the pulled code need a SQL/schema upgrade vs the DB?
    * Get-PimUpdateDetection         -- the combined {SqlUpdateRequired; GuiUpdateRequired; details}
    * Get-PimUpdateSourceProfile     -- normalize the pull source (git-pull community vs sync-automateit hosted)
    * Get-PimBuildPlan               -- when GUI update needed, the image-build plan (tag, repo, dockerfile)
    * Get-PimUpdateApplyPlan         -- the ordered apply plan across all 6 steps (gated)
    * Get-PimVerifyVerdict           -- turn a post-deploy smoke result into pass/fail (rollback trigger)
    * Get-PimNotifyPlan             -- the update-outcome notification (subject/tokens/recipient/severity)
    * Get-PimMonitorEnsurePlan       -- is the health monitor in place? deploy/refresh it if missing/stale
#>

Set-StrictMode -Off

# Reuse the sync-automateit decision core (semver compare, sync decision, health verdict,
# rollback plan) -- never re-implement version math or rollback here. Idempotent dot-source.
if ($PSScriptRoot -and -not (Get-Command Get-PimSyncDecision -ErrorAction SilentlyContinue)) {
    $__pimSync = Join-Path $PSScriptRoot 'PIM-SyncAutomateIT.ps1'
    if (Test-Path -LiteralPath $__pimSync) { . $__pimSync }
}

# ---- content hashing (pure) -----------------------------------------------
function Get-PimContentHash {
    <#
      Stable SHA256 over an ORDERED set of per-file digests. The orchestrator feeds in a list
      of @{ path = <relative>; sha256 = <hex> } records (it computes the per-file SHA256 from
      disk with Get-FileHash); this combines them deterministically (sorted by path, so file
      enumeration order never changes the result) into ONE content hash for the GUI surface.
      An empty/null input returns a fixed sentinel so "no files" never collides with real
      content. This is what lets us detect a Manager GUI change WITHOUT a version bump: the
      content hash moves even when VERSION didn't.
    #>
    param([object[]]$FileDigests)
    $items = @($FileDigests | Where-Object { $_ -and $_.path })
    if ($items.Count -eq 0) { return 'EMPTY-0000000000000000000000000000000000000000000000000000000000000000' }
    $lines = @(
        $items |
        Sort-Object { "$($_.path)".ToLowerInvariant() } |
        ForEach-Object { ("{0}:{1}" -f "$($_.path)".ToLowerInvariant().Replace('\','/'), "$($_.sha256)".ToLowerInvariant()) }
    )
    $joined = ($lines -join "`n")
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($joined)
        $hash  = $sha.ComputeHash($bytes)
        return (($hash | ForEach-Object { $_.ToString('x2') }) -join '')
    } finally { $sha.Dispose() }
}

# ---- GUI update detection (pure) ------------------------------------------
function Get-PimGuiUpdatePlan {
    <#
      Decide whether the pulled Manager web GUI (tools/pim-manager/*) differs from the GUI in
      the RUNNING image/instance, so it needs a rebuild + roll.

      Inputs (FACTS the orchestrator gathers):
        -PulledContentHash  : Get-PimContentHash over the freshly-pulled tools/pim-manager files.
        -RunningContentHash : the content hash baked into / reported by the running image
                              (read from the deployed image label or a sidecar marker). Blank =
                              unknown (treat as needs-update so we never skip a real change).
        -PulledVersion      : optional VERSION string from the pulled code.
        -RunningVersion     : optional VERSION the running image reports.

      Rule: GUI update REQUIRED when the content hash changed (authoritative -- catches GUI
      edits with no version bump), OR when the pulled VERSION is strictly newer than the
      running one (semver, reusing the sync core), OR when the running hash is unknown.
      Returns { GuiUpdateRequired; reason; pulledContentHash; runningContentHash;
                pulledVersion; runningVersion }.
    #>
    param(
        [Parameter(Mandatory)][string]$PulledContentHash,
        [string]$RunningContentHash,
        [string]$PulledVersion,
        [string]$RunningVersion
    )
    $ph = "$PulledContentHash".Trim().ToLowerInvariant()
    $rh = "$RunningContentHash".Trim().ToLowerInvariant()

    if (-not $rh) {
        return [pscustomobject]@{ GuiUpdateRequired = $true; reason = 'running GUI content hash unknown -- cannot prove parity, rebuild to be safe';
            pulledContentHash = $ph; runningContentHash = $rh; pulledVersion = "$PulledVersion"; runningVersion = "$RunningVersion" }
    }
    if ($ph -ne $rh) {
        return [pscustomobject]@{ GuiUpdateRequired = $true; reason = 'Manager GUI content changed (content hash differs from the running image)';
            pulledContentHash = $ph; runningContentHash = $rh; pulledVersion = "$PulledVersion"; runningVersion = "$RunningVersion" }
    }
    # hashes match -- but a newer VERSION still warrants a roll (e.g. backend-only change with
    # an unchanged GUI surface shouldn't trigger here, yet if VERSION moved we honour it).
    if ("$PulledVersion".Trim() -and "$RunningVersion".Trim() -and (Get-Command Test-PimSyncUpdateNeeded -ErrorAction SilentlyContinue)) {
        if (Test-PimSyncUpdateNeeded -CurrentTag $RunningVersion -LatestTag $PulledVersion) {
            return [pscustomobject]@{ GuiUpdateRequired = $true; reason = "pulled VERSION $PulledVersion newer than running $RunningVersion (GUI content equal but version advanced)";
                pulledContentHash = $ph; runningContentHash = $rh; pulledVersion = "$PulledVersion"; runningVersion = "$RunningVersion" }
        }
    }
    return [pscustomobject]@{ GuiUpdateRequired = $false; reason = 'Manager GUI unchanged (content hash matches the running image)';
        pulledContentHash = $ph; runningContentHash = $rh; pulledVersion = "$PulledVersion"; runningVersion = "$RunningVersion" }
}

# ---- SQL / schema update detection (pure) ---------------------------------
function Get-PimSqlUpdatePlan {
    <#
      Decide whether the pulled code needs a SQL/schema upgrade against the DEPLOYED database.

      Inputs (FACTS the orchestrator gathers):
        -DeployedColumns : per-table actual columns read from the live DB, as a hashtable
                           @{ '<table>' = @('Col1','Col2',...) }. A table absent from the map
                           is treated as "not yet created" (needs create).
        -LockedSqlSchema : the pulled locked SQL spec (Get-PimLockedSqlSchema) -- the desired
                           shape. Per table: @{ required=@{col=type}; deprecated=@(); migrations=@() }.
        -DeployedSchemaVersion / -PulledSchemaVersion : optional monotonic schema markers
                           (when the code carries an explicit schema version). A strictly-newer
                           pulled version forces an upgrade even if a column scan looks clean
                           (covers data-only migrations the column audit can't see).

      It reuses Get-PimSchemaConformancePlan (per-table add/drop/migrate) when that function is
      available (loaded from PIM-SchemaConformance.ps1). Returns:
        { SqlUpdateRequired; reason; tables = @(per-table plan); missingTables = @(...);
          deployedSchemaVersion; pulledSchemaVersion }.
      Idempotent + NON-destructive by design: this only DETECTS; the orchestrator applies the
      idempotent guarded DDL (New-PimSqlConformanceDdl) which never drops data unguarded.
    #>
    param(
        [hashtable]$DeployedColumns,
        [Parameter(Mandatory)][hashtable]$LockedSqlSchema,
        [string]$DeployedSchemaVersion,
        [string]$PulledSchemaVersion
    )
    if (-not $DeployedColumns) { $DeployedColumns = @{} }
    $tablePlans = New-Object System.Collections.Generic.List[object]
    $missing = New-Object System.Collections.Generic.List[string]
    $needBecauseCols = $false

    foreach ($table in @($LockedSqlSchema.Keys)) {
        $spec = $LockedSqlSchema[$table]
        $hasTable = $DeployedColumns.ContainsKey($table)
        if (-not $hasTable) {
            $missing.Add("$table") | Out-Null
            $needBecauseCols = $true
            $tablePlans.Add([pscustomobject]@{ table = "$table"; exists = $false; conformant = $false; toAdd = @(); toDrop = @(); toMigrate = @() }) | Out-Null
            continue
        }
        $cols = @($DeployedColumns[$table])
        if (Get-Command Get-PimSchemaConformancePlan -ErrorAction SilentlyContinue) {
            $plan = Get-PimSchemaConformancePlan -ActualColumns $cols -Spec $spec
            if (-not $plan.Conformant) { $needBecauseCols = $true }
            $tablePlans.Add([pscustomobject]@{ table = "$table"; exists = $true; conformant = [bool]$plan.Conformant;
                toAdd = @($plan.ToAdd); toDrop = @($plan.ToDrop); toMigrate = @($plan.ToMigrate) }) | Out-Null
        } else {
            # fallback (no conformance helper loaded): plain required-column membership check.
            $reqNames = if ($spec.required -is [hashtable]) { @($spec.required.Keys) } else { @($spec.required) }
            $have = @{}; foreach ($c in $cols) { $have["$c".ToLowerInvariant()] = $true }
            $toAdd = @($reqNames | Where-Object { $_ -and -not $have.ContainsKey("$_".ToLowerInvariant()) })
            $conf = ($toAdd.Count -eq 0)
            if (-not $conf) { $needBecauseCols = $true }
            $tablePlans.Add([pscustomobject]@{ table = "$table"; exists = $true; conformant = $conf; toAdd = $toAdd; toDrop = @(); toMigrate = @() }) | Out-Null
        }
    }

    # schema-version marker: a strictly-newer pulled version forces an upgrade (data migrations).
    $needBecauseVersion = $false
    if ("$PulledSchemaVersion".Trim() -and (Get-Command Test-PimSyncUpdateNeeded -ErrorAction SilentlyContinue)) {
        $dep = if ("$DeployedSchemaVersion".Trim()) { $DeployedSchemaVersion } else { '0.0.0' }
        $needBecauseVersion = Test-PimSyncUpdateNeeded -CurrentTag $dep -LatestTag $PulledSchemaVersion
    }

    $required = ($needBecauseCols -or $needBecauseVersion)
    $reason =
        if ($missing.Count -gt 0 -and $needBecauseVersion) { "missing table(s): $($missing -join ', '); + schema version advanced $DeployedSchemaVersion -> $PulledSchemaVersion" }
        elseif ($missing.Count -gt 0) { "missing table(s) need create: $($missing -join ', ')" }
        elseif ($needBecauseCols -and $needBecauseVersion) { "column drift detected + schema version advanced $DeployedSchemaVersion -> $PulledSchemaVersion" }
        elseif ($needBecauseCols) { 'column drift detected vs the deployed DB (add/drop/migrate)' }
        elseif ($needBecauseVersion) { "schema version advanced $DeployedSchemaVersion -> $PulledSchemaVersion (data migration)" }
        else { 'deployed DB already conforms to the pulled schema -- no upgrade needed' }

    return [pscustomobject]@{
        SqlUpdateRequired     = [bool]$required
        reason                = $reason
        tables                = $tablePlans.ToArray()
        missingTables         = $missing.ToArray()
        deployedSchemaVersion = "$DeployedSchemaVersion"
        pulledSchemaVersion   = "$PulledSchemaVersion"
    }
}

# ---- combined detection (pure) --------------------------------------------
function Get-PimUpdateDetection {
    <#
      The combined detect result -- the -DetectOnly payload. Wraps the GUI plan + SQL plan into
      one object the orchestrator prints and (when -Apply) acts on. NO side effects.
      Returns { SqlUpdateRequired; GuiUpdateRequired; AnyUpdateRequired; details = { gui; sql } }.
    #>
    param(
        [Parameter(Mandatory)][object]$GuiPlan,
        [Parameter(Mandatory)][object]$SqlPlan
    )
    $gui = [bool]$GuiPlan.GuiUpdateRequired
    $sql = [bool]$SqlPlan.SqlUpdateRequired
    return [pscustomobject]@{
        SqlUpdateRequired = $sql
        GuiUpdateRequired = $gui
        AnyUpdateRequired = ($gui -or $sql)
        details           = [pscustomobject]@{ gui = $GuiPlan; sql = $SqlPlan }
    }
}

# ---- pull-source normalization (pure) -------------------------------------
function Get-PimUpdateSourceProfile {
    <#
      Normalize the two pull PATHS into one profile the orchestrator can branch on, so a single
      script handles BOTH:
        * 'git-pull'        : community / local / VM -- a `git pull` of the public repo. Store is
                              SQLEXPRESS or Azure SQL; the Manager runs locally. Build = local
                              build/package + relaunch (no ACR roll).
        * 'sync-automateit' : hosted -- the sync-automateit pull. Store is Azure SQL; the Manager
                              runs on Container Apps. Build = az acr build; deploy = roll the ACA
                              revision to the freshly-built image.
      Returns { source; buildMode; deployMode; isHosted } -- buildMode in {acr-build, local-build},
      deployMode in {aca-roll, local-relaunch}.
    #>
    param([Parameter(Mandatory)][ValidateSet('git-pull','sync-automateit')][string]$Source)
    if ($Source -eq 'sync-automateit') {
        return [pscustomobject]@{ source = 'sync-automateit'; buildMode = 'acr-build'; deployMode = 'aca-roll'; isHosted = $true }
    }
    return [pscustomobject]@{ source = 'git-pull'; buildMode = 'local-build'; deployMode = 'local-relaunch'; isHosted = $false }
}

# ---- build plan (pure) ----------------------------------------------------
function Get-PimBuildPlan {
    <#
      When a GUI update is needed, the plan to BUILD a fresh Manager image FROM THE PULLED CODE.
      This is the GAP the lifecycle adds: sync-automateit / Update-PimContainers -SkipBuild only
      ROLL a pre-built image; nothing built the new image from a fresh pull. Hosted => an
      `az acr build` (Build-PimManagerImage.ps1). Community => a local build/package + relaunch.

      -GuiUpdateRequired : from Get-PimGuiUpdatePlan.
      -Source            : 'git-pull' | 'sync-automateit'.
      -ImageTag          : the tag to build (the orchestrator derives it -- usually the pulled VERSION).
      Returns { BuildRequired; buildMode; imageTag; imageRepo; reason }.
    #>
    param(
        [Parameter(Mandatory)][bool]$GuiUpdateRequired,
        [Parameter(Mandatory)][ValidateSet('git-pull','sync-automateit')][string]$Source,
        [string]$ImageTag,
        [string]$ImageRepo = 'pim-manager'
    )
    $profile = Get-PimUpdateSourceProfile -Source $Source
    if (-not $GuiUpdateRequired) {
        return [pscustomobject]@{ BuildRequired = $false; buildMode = $profile.buildMode; imageTag = "$ImageTag"; imageRepo = $ImageRepo;
            reason = 'no GUI update -- nothing to build (SQL-only upgrades do not need an image)' }
    }
    return [pscustomobject]@{ BuildRequired = $true; buildMode = $profile.buildMode; imageTag = "$ImageTag"; imageRepo = $ImageRepo;
        reason = $(if ($profile.isHosted) { "GUI update -- build $ImageRepo`:$ImageTag in ACR from the pulled code (az acr build)" } else { 'GUI update -- local build/package + relaunch the local Manager' }) }
}

# ---- the ordered apply plan (pure) ----------------------------------------
function Get-PimUpdateApplyPlan {
    <#
      The whole 6-step apply plan as an ordered list of steps, GATED. With -DetectOnly the plan
      is detect-only (steps 2-6 are 'skip -- detect-only'). With the gate OPEN (-Apply) the
      steps that are actually needed are 'do', the rest 'skip'. The orchestrator walks this list
      and executes each 'do' step. NO side effects here -- just the plan.

      Inputs:
        -Detection        : Get-PimUpdateDetection result (gui/sql required + details).
        -BuildPlan        : Get-PimBuildPlan result.
        -Source           : 'git-pull' | 'sync-automateit'.
        -Apply            : the gate -- $false => detect-only (default-safe).
        -MonitorInPlace   : is the synthetic health monitor already deployed + fresh? (fact)
      Returns { detectOnly; steps = @( {step; action; do; detail} ... ) } in order:
        1 detect, 2 build, 3 deploy(gui)+schema(sql), 4 verify, 5 notify, 6 ensure-monitor.
    #>
    param(
        [Parameter(Mandatory)][object]$Detection,
        [Parameter(Mandatory)][object]$BuildPlan,
        [Parameter(Mandatory)][ValidateSet('git-pull','sync-automateit')][string]$Source,
        [switch]$Apply,
        [bool]$MonitorInPlace = $false
    )
    $profile = Get-PimUpdateSourceProfile -Source $Source
    $detectOnly = -not $Apply
    $steps = New-Object System.Collections.Generic.List[object]

    function _step([int]$n,[string]$name,[bool]$needed,[string]$detail) {
        $do = ($needed -and -not $detectOnly)
        $action = if ($detectOnly) { 'skip -- detect-only' } elseif ($needed) { 'do' } else { 'skip -- not needed' }
        [pscustomobject]@{ step = $n; name = $name; do = $do; action = $action; detail = $detail }
    }

    # 1. detect always runs (even detect-only).
    $steps.Add([pscustomobject]@{ step = 1; name = 'detect'; do = $true; action = 'do';
        detail = "GuiUpdateRequired=$($Detection.GuiUpdateRequired); SqlUpdateRequired=$($Detection.SqlUpdateRequired)" }) | Out-Null
    # 2. build (only if a GUI update is needed).
    $steps.Add((_step 2 'build' ([bool]$BuildPlan.BuildRequired) $BuildPlan.reason)) | Out-Null
    # 3. deploy: roll the freshly-built image (GUI) and/or apply the idempotent SQL upgrade.
    $deployNeeded = ([bool]$Detection.GuiUpdateRequired -or [bool]$Detection.SqlUpdateRequired)
    $deployDetail = @()
    if ($Detection.GuiUpdateRequired) { $deployDetail += $(if ($profile.isHosted) { 'roll ACA to the freshly-built image (NOT -SkipBuild path)' } else { 'relaunch the local Manager on the freshly-built package' }) }
    if ($Detection.SqlUpdateRequired) { $deployDetail += 'apply idempotent SQL schema upgrade (preflight -> apply -> re-preflight; never destructive)' }
    if (-not $deployDetail) { $deployDetail = @('nothing to deploy') }
    $steps.Add((_step 3 'deploy' $deployNeeded ($deployDetail -join ' + '))) | Out-Null
    # 4. verify: hosted smoke; auto-rollback on failure. Runs whenever we deployed.
    $steps.Add((_step 4 'verify' $deployNeeded 'run hosted smoke; auto-rollback on failure (prior revision; SQL preflight gate before apply)')) | Out-Null
    # 5. notify: always email the outcome when we applied anything (success OR failure).
    $steps.Add((_step 5 'notify' $deployNeeded 'email update outcome (built/deployed/upgraded; success or failure) to the owner')) | Out-Null
    # 6. ensure-monitor: refresh/deploy the synthetic health monitor after the update. Needed
    #    whenever it is NOT already in place (independent of whether code changed).
    $monNeeded = (-not $MonitorInPlace)
    $steps.Add((_step 6 'ensure-monitor' $monNeeded $(if ($MonitorInPlace) { 'health monitor already in place + fresh' } else { 'health monitor missing/stale -- deploy/refresh the synthetic monitor (reuse feat/synthetic-monitor)' }))) | Out-Null

    return [pscustomobject]@{ detectOnly = $detectOnly; source = $Source; steps = $steps.ToArray() }
}

# ---- verify verdict (pure) ------------------------------------------------
function Get-PimVerifyVerdict {
    <#
      Turn the post-deploy verification into a verdict + rollback plan. We reuse the hosted smoke
      (tests/live/Test-PimManagerHostedSmoke.ps1) and the sync core's health verdict + rollback
      plan -- never re-implement them. Healthy = exit 0 + zero fails. On failure, roll back to
      the captured pre-update revision.
        -ExitCode / -FailCount : the smoke result.
        -PreviousRevision      : the captured rollback target.
      Returns { Healthy; rollback = <Get-PimSyncRollbackPlan> }.
    #>
    param([int]$ExitCode = 0, [int]$FailCount = 0, [string]$PreviousRevision)
    $healthy = if (Get-Command Test-PimSyncHealthVerdict -ErrorAction SilentlyContinue) {
        Test-PimSyncHealthVerdict -ExitCode $ExitCode -FailCount $FailCount
    } else { (($ExitCode -eq 0) -and ($FailCount -le 0)) }
    $rb = if (Get-Command Get-PimSyncRollbackPlan -ErrorAction SilentlyContinue) {
        Get-PimSyncRollbackPlan -Healthy $healthy -PreviousRevision $PreviousRevision
    } else {
        if ($healthy) { [pscustomobject]@{ action='none'; revision=''; reason='healthy' } }
        elseif ("$PreviousRevision".Trim()) { [pscustomobject]@{ action='rollback'; revision="$PreviousRevision".Trim(); reason='unhealthy -- roll back' } }
        else { [pscustomobject]@{ action='none'; revision=''; reason='unhealthy, no rollback target' } }
    }
    return [pscustomobject]@{ Healthy = [bool]$healthy; rollback = $rb }
}

# ---- notify plan (pure) ---------------------------------------------------
function Get-PimNotifyPlan {
    <#
      Build the update-outcome notification -- the subject + token set + recipient + severity --
      that the orchestrator hands to the EXISTING mailer (Send-PimNotifyMail, reusing the
      synthetic-monitor mail path). This is PURE: it composes the message, it does NOT send.

      Inputs:
        -Outcome      : 'success' | 'failure' | 'rolledback' | 'noop'
        -Source       : 'git-pull' | 'sync-automateit'
        -Detection    : Get-PimUpdateDetection result (what was needed).
        -Built/-Deployed/-SchemaUpgraded : what actually happened (bools).
        -ImageTag     : the tag built/deployed (when any).
        -Recipient    : owner mailbox (default the project owner).
        -Error        : failure detail (when Outcome=failure/rolledback).
      Returns { send; type; recipient; severity; subject; tokens } -- `send` is $false for noop.
    #>
    param(
        [Parameter(Mandatory)][ValidateSet('success','failure','rolledback','noop')][string]$Outcome,
        [Parameter(Mandatory)][ValidateSet('git-pull','sync-automateit')][string]$Source,
        [object]$Detection,
        [bool]$Built,
        [bool]$Deployed,
        [bool]$SchemaUpgraded,
        [string]$ImageTag,
        [string]$Recipient = 'mok@mortenknudsen.net',
        [string]$ErrorDetail
    )
    $sev = switch ($Outcome) { 'success' { 'info' } 'noop' { 'info' } 'rolledback' { 'warning' } 'failure' { 'critical' } default { 'info' } }
    $what = @()
    if ($Built)          { $what += "built image $ImageTag" }
    if ($Deployed)       { $what += 'deployed (rolled) the Manager' }
    if ($SchemaUpgraded) { $what += 'applied SQL schema upgrade' }
    if (-not $what)      { $what = @('no changes') }
    $subjectMap = @{
        success    = "PIM update OK ($Source): $($what -join ', ')"
        failure    = "PIM update FAILED ($Source)"
        rolledback = "PIM update ROLLED BACK ($Source) -- verification failed"
        noop       = "PIM update: nothing to do ($Source)"
    }
    $tokens = @{
        Outcome        = $Outcome
        Source         = $Source
        WhatHappened   = ($what -join ', ')
        ImageTag       = "$ImageTag"
        GuiUpdate      = $(if ($Detection) { "$($Detection.GuiUpdateRequired)" } else { '' })
        SqlUpdate      = $(if ($Detection) { "$($Detection.SqlUpdateRequired)" } else { '' })
        Severity       = $sev
        ErrorDetail    = "$ErrorDetail"
        TimestampUtc   = [datetime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
    }
    return [pscustomobject]@{
        send      = ($Outcome -ne 'noop')
        type      = 'update-outcome'
        recipient = $Recipient
        severity  = $sev
        subject   = $subjectMap[$Outcome]
        tokens    = $tokens
    }
}

# ---- ensure-monitor plan (pure) -------------------------------------------
function Get-PimMonitorEnsurePlan {
    <#
      Step 6: make sure the deployable health monitor (the synthetic monitor from
      feat/synthetic-monitor: checks Manager + CEH health every ~5-15 min, emails the owner on
      failure, debounced) is IN PLACE/refreshed after the update -- deploy/refresh it if missing
      or stale. PURE: decides ensure|refresh|noop; the orchestrator runs the monitor's own
      deploy script (we REUSE it, never duplicate the monitor).

      Inputs (FACTS):
        -MonitorDeployed   : is a monitor currently deployed? (e.g. an ACA job / scheduled task exists)
        -DeployedMonitorHash : content hash of the deployed monitor (blank = unknown).
        -PulledMonitorHash   : content hash of the monitor in the freshly-pulled code (blank = no monitor in pull).
        -IntervalMinutes     : the configured cadence (validated to the 5-15 min window).
      Returns { action; reason; intervalMinutes } -- action in {ensure (deploy missing),
      refresh (redeploy stale), noop (already in place + fresh)}.
    #>
    param(
        [bool]$MonitorDeployed = $false,
        [string]$DeployedMonitorHash,
        [string]$PulledMonitorHash,
        [int]$IntervalMinutes = 10
    )
    # clamp/validate cadence into the documented 5-15 min debounced window.
    $iv = $IntervalMinutes
    if ($iv -lt 5)  { $iv = 5 }
    if ($iv -gt 15) { $iv = 15 }

    if (-not $MonitorDeployed) {
        return [pscustomobject]@{ action = 'ensure'; reason = 'health monitor not deployed -- deploy the synthetic monitor (reuse feat/synthetic-monitor)'; intervalMinutes = $iv }
    }
    $dh = "$DeployedMonitorHash".Trim().ToLowerInvariant()
    $ph = "$PulledMonitorHash".Trim().ToLowerInvariant()
    if ($ph -and $dh -and ($ph -ne $dh)) {
        return [pscustomobject]@{ action = 'refresh'; reason = 'health monitor deployed but the pulled monitor differs -- refresh it'; intervalMinutes = $iv }
    }
    if ($ph -and -not $dh) {
        return [pscustomobject]@{ action = 'refresh'; reason = 'health monitor deployed but its content hash is unknown -- refresh to a known-good version'; intervalMinutes = $iv }
    }
    return [pscustomobject]@{ action = 'noop'; reason = 'health monitor already in place + fresh'; intervalMinutes = $iv }
}
