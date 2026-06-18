# =============================================================================
# PIM-DownlinkJob.ps1 -- the PURE, offline-testable plan brain for the §31.3
# CLOUD-NATIVE master->managed (slave) downlink as an Azure Container Apps JOB
# with a CRON schedule (operator directive 2026-06-17: "all run in cloud only
# compute, in one test"; "run it through the containers in the slave").
#
# WHAT this delivers
#   The downlink (PIM-Downlink.ps1 / setup/Invoke-PimDownlinkSync.ps1) was a
#   wrapper run by-hand or by a Windows scheduled task. THIS turns it into a
#   first-class CLOUD scheduled JOB: an `az containerapp job` of trigger-type
#   Schedule that, on its cron cadence, runs the SAME pim-manager image with a
#   command/entrypoint that pulls -> verifies -> stages -> applies the ring-gated
#   downlink for ONE scenario+tenant+ring. Two placements:
#     * S5 -> the Job runs in the CENTRAL ACA env (cae-pim, MSP tenant) using the
#             MULTI-TENANT SPN (acts into the slave).
#     * S6 -> the Job runs in the SLAVE tenant's OWN ACA env using a LOCAL SPN.
#
# DESIGN TENETS (mirror the rest of PIM4EntraPS)
#   * PURE core here: NO az / Graph / SQL / HTTP / file I/O / global mutation. The
#     functions take FACTS and RETURN the `az containerapp job` argument arrays +
#     decisions. The thin live wrapper (tools/setup/Deploy-PimDownlinkJob.ps1)
#     gathers facts and INVOKES az with these arrays. That keeps every risky
#     decision -- which placement, which env, which identity, private-only, no
#     inline secret, idempotent create-vs-update -- unit-testable in real PS 5.1
#     with NO az and NO live tenant.
#   * private transport (REQUIREMENTS §31.3 hard constraint): the Job runs on the
#     INTERNAL ACA env (already private-only via Setup-PimContainers). A scheduled
#     Job has NO ingress at all (it is not an app) -- there is nothing public to
#     expose. The signed-baseline pull + sync-file staging traverse private
#     cross-tenant VNet only. The plan NEVER emits a public endpoint.
#   * no inline secret: identity is a Managed Identity (system/user-assigned) or an
#     SPN cert resolved at runtime from the store -- the plan emits identity refs /
#     secret-refs (Key Vault) ONLY, never a secret VALUE on the command line.
#   * idempotent: a re-deploy emits an `az containerapp job update` for an existing
#     Job (same name) instead of `create`; -Unregister emits `delete`.
#
# PS 5.1 COMPATIBLE: no ?. / ??, no ternary, Set-StrictMode -Off, null-guarded
#   property access, IDictionary-vs-PSCustomObject dual reads.
#
# REUSE (does not reinvent): the env/MI/registry/private pattern proven in
#   tools/setup/Setup-PimContainers.ps1 (the worker matrix); the image built by
#   tools/setup/Build-PimManagerImage.ps1; the downlink invoked by
#   setup/Invoke-PimDownlinkSync.ps1 + setup/Invoke-PimScenarioRun.ps1; scenario
#   resolution in engine/_shared/PIM-ScenarioProfile.ps1.
# =============================================================================

Set-StrictMode -Off

# ---------------------------------------------------------------------------
# Small null-safe property reader (IDictionary OR PSCustomObject). Mirrors
# Get-PimDownlinkValue so this file is self-contained.
# ---------------------------------------------------------------------------
function Get-PimDownlinkJobValue {
    param([object]$Object, [Parameter(Mandatory)][string]$Key)
    if ($null -eq $Object) { return $null }
    if ($Object -is [System.Collections.IDictionary]) {
        if ($Object.Contains($Key)) { return $Object[$Key] }
        return $null
    }
    $p = $Object.PSObject.Properties[$Key]
    if ($p) { return $p.Value }
    return $null
}

# ---------------------------------------------------------------------------
# PLACEMENT RESOLUTION (pure). Where does the cron Job live + which identity does
# it act with, for a given scenario? Mirrors the scenario descriptor (S5 central /
# S6 local) WITHOUT importing the whole resolver (so this core is standalone +
# testable). The caller may pass the resolved scenario context to override.
#   S5 -> placement=central, spnModel=multi-tenant-spn, syncFileLocation=central-msp
#   S6 -> placement=local,   spnModel=local-spn,        syncFileLocation=local-slave
# Returns @{ ok; reason; scenarioId; placement; spnModel; syncFileLocation;
#            hostingLocation; envScope }. envScope = 'central-msp' | 'local-slave'.
# ---------------------------------------------------------------------------
function Get-PimDownlinkJobPlacement {
    param(
        [Parameter(Mandatory)][ValidateSet('S5','S6')][string]$Scenario
    )
    $id = "$Scenario".Trim().ToUpperInvariant()
    if ($id -eq 'S5') {
        return @{
            ok = $true; reason = 'S5: cron Job runs in the CENTRAL ACA env (MSP tenant), multi-tenant SPN acts into the slave'
            scenarioId = 'S5'; placement = 'central'; spnModel = 'multi-tenant-spn'
            syncFileLocation = 'central-msp'; hostingLocation = 'central-msp'; envScope = 'central-msp'
        }
    }
    return @{
        ok = $true; reason = "S6: cron Job runs in the SLAVE tenant's OWN ACA env, local SPN"
        scenarioId = 'S6'; placement = 'local'; spnModel = 'local-spn'
        syncFileLocation = 'local-slave'; hostingLocation = 'local-slave'; envScope = 'local-slave'
    }
}

# ---------------------------------------------------------------------------
# CRON VALIDATION (pure). A standard 5-field cron expression (min hour dom mon dow).
# ACA Jobs use 5-field cron (UTC). Returns @{ ok; reason }. Fail-safe: blank/wrong
# field count is rejected so the deploy never silently schedules nothing.
# ---------------------------------------------------------------------------
function Test-PimDownlinkJobCron {
    param([Parameter(Mandatory)][string]$Cron)
    $c = "$Cron".Trim()
    if (-not $c) { return @{ ok = $false; reason = 'cron expression is blank' } }
    $fields = @($c -split '\s+' | Where-Object { "$_".Trim() })
    if ($fields.Count -ne 5) {
        return @{ ok = $false; reason = "cron must have 5 fields (min hour day-of-month month day-of-week); got $($fields.Count): '$c'" }
    }
    return @{ ok = $true; reason = "valid 5-field cron '$c' (UTC)" }
}

# ---------------------------------------------------------------------------
# THE CONTAINER COMMAND (pure). The command/args array the Job container runs --
# pwsh invoking the in-container downlink-job entrypoint with the scenario/tenant/
# ring + the baseline source. This is what makes a run actually pull+sync+apply.
# Returns a string[] (command + args) suitable for `--command` / YAML.
#   -EntryPath      : container path to the entrypoint (default the engine path).
#   -Scenario/-TenantId/-SlaveRing : forwarded to the entrypoint.
#   -BaselineUrl    : private-endpoint blob URL of the signed baseline (S5/S6).
#   -BaselineDocPath: mounted/local path to a pulled bundle (alt to -BaselineUrl).
# ---------------------------------------------------------------------------
function Get-PimDownlinkJobCommand {
    param(
        [string]$EntryPath = '/app/PIM4EntraPS/tools/pim-engine/downlink-job-entry.ps1',
        [Parameter(Mandatory)][ValidateSet('S5','S6')][string]$Scenario,
        [Parameter(Mandatory)][string]$TenantId,
        [ValidateRange(0,2)][int]$SlaveRing = 2,
        [string]$BaselineUrl,
        [string]$BaselineDocPath
    )
    $cmd = New-Object System.Collections.Generic.List[string]
    $cmd.Add('pwsh') | Out-Null
    $cmd.Add('-NoProfile') | Out-Null
    $cmd.Add('-ExecutionPolicy') | Out-Null
    $cmd.Add('Bypass') | Out-Null
    $cmd.Add('-File') | Out-Null
    $cmd.Add("$EntryPath") | Out-Null
    $cmd.Add('-Scenario') | Out-Null;  $cmd.Add("$Scenario") | Out-Null
    $cmd.Add('-TenantId') | Out-Null;  $cmd.Add("$TenantId") | Out-Null
    $cmd.Add('-SlaveRing') | Out-Null; $cmd.Add("$SlaveRing") | Out-Null
    if ("$BaselineUrl".Trim())     { $cmd.Add('-BaselineUrl') | Out-Null;     $cmd.Add("$BaselineUrl") | Out-Null }
    if ("$BaselineDocPath".Trim()) { $cmd.Add('-BaselineDocPath') | Out-Null; $cmd.Add("$BaselineDocPath") | Out-Null }
    return @($cmd.ToArray())
}

# ---------------------------------------------------------------------------
# ENV-VAR SET (pure). The non-secret env the Job container needs: scenario knobs,
# SQL coordinates (MI-auth, NO password), sync-file roots, REST-only flag. NEVER a
# secret value -- secrets are injected as secret-refs by Build-...JobArgs, not here.
# Returns string[] of NAME=VALUE.
# ---------------------------------------------------------------------------
function Get-PimDownlinkJobEnv {
    param(
        [Parameter(Mandatory)][ValidateSet('S5','S6')][string]$Scenario,
        [Parameter(Mandatory)][string]$TenantId,
        [string]$SqlServerFqdn,
        [string]$SqlDatabase = 'PimPlatform',
        [string]$SyncRootCentral = '/sync/central',
        [string]$SyncRootLocal   = '/sync/local'
    )
    $placement = Get-PimDownlinkJobPlacement -Scenario $Scenario
    $ev = New-Object System.Collections.Generic.List[string]
    $ev.Add('PIM_HOSTED=1') | Out-Null
    $ev.Add('PIM_UseGraphSdk=false') | Out-Null
    $ev.Add("PIM_ActiveScenario=$Scenario") | Out-Null
    $ev.Add("PIM_TenantId=$TenantId") | Out-Null
    $ev.Add('PIM_StorageBackend=sql') | Out-Null
    if ("$SqlServerFqdn".Trim()) { $ev.Add("PIM_SqlServer=$SqlServerFqdn") | Out-Null }
    $ev.Add("PIM_SqlDatabase=$SqlDatabase") | Out-Null
    # Sync-file staging root the scenario uses (central for S5, local for S6).
    if ("$($placement.envScope)" -eq 'central-msp') { $ev.Add("PIM_SyncRootCentral=$SyncRootCentral") | Out-Null }
    else { $ev.Add("PIM_SyncRootLocal=$SyncRootLocal") | Out-Null }
    return @($ev.ToArray())
}

# ---------------------------------------------------------------------------
# THE az containerapp job ARG SET (pure). Build the exact argument array for a
# create / update / delete / start of the scheduled downlink Job. This is the
# single decision the deploy wrapper executes via `& az @args`. Mirrors the proven
# Setup-PimContainers pattern (env id, workload profile, MI, registry-by-MI) but
# for a JOB (trigger-type Schedule + cron) instead of an App.
#
#   -Action          : create | update | delete | start  (idempotent: the wrapper
#                      picks create-vs-update from an existence probe; this fn just
#                      emits the requested action's args).
#   -JobName/-ResourceGroup/-EnvName : the ACA job + its env (private, internal-only).
#   -Image           : <acr>.azurecr.io/<repo>:<tag> (the pim-manager image).
#   -AcrServer       : <acr>.azurecr.io (registry pulled via MI -- no creds).
#   -Cron            : 5-field cron (UTC). Required for create/update.
#   -Command         : string[] from Get-PimDownlinkJobCommand.
#   -EnvVars         : string[] from Get-PimDownlinkJobEnv (NAME=VALUE, non-secret).
#   -IdentityResourceId : a USER-assigned MI resource id to attach (S5/S6). When
#                      blank, -SystemAssigned attaches the system MI instead.
#   -SystemAssigned  : attach a system-assigned MI (default when no user MI).
#   -RegistryIdentity: 'system' | <user-MI-resource-id> -- how the Job pulls from
#                      ACR (AcrPull on that identity). Default 'system'.
#   -Cpu/-Memory     : container resources (defaults 0.5 / 1Gi).
#   -ReplicaTimeout  : per-execution timeout seconds (default 1800).
#   -ReplicaRetryLimit : retries on failure (default 1).
#
# Returns @{ ok; reason; action; args=string[]; private=$true; hasInlineSecret=$bool }.
# hasInlineSecret is ALWAYS $false by construction -- the test asserts it; if a
# caller ever tried to pass a raw secret this fn would still not emit one (it has no
# secret parameter). private=$true documents the no-ingress invariant (a Job is not
# an app; it exposes no endpoint), reinforced by the internal-only env it targets.
# ---------------------------------------------------------------------------
function Build-PimDownlinkJobArgs {
    param(
        [Parameter(Mandatory)][ValidateSet('create','update','delete','start')][string]$Action,
        [Parameter(Mandatory)][string]$JobName,
        [Parameter(Mandatory)][string]$ResourceGroup,
        [string]$EnvName,
        [string]$Image,
        [string]$AcrServer,
        [string]$Cron,
        [string[]]$Command = @(),
        [string[]]$EnvVars = @(),
        [string]$IdentityResourceId,
        [switch]$SystemAssigned,
        [string]$RegistryIdentity = 'system',
        [double]$Cpu = 0.5,
        [string]$Memory = '1Gi',
        [int]$ReplicaTimeout = 1800,
        [int]$ReplicaRetryLimit = 1
    )
    $a = New-Object System.Collections.Generic.List[string]
    $a.Add('containerapp') | Out-Null
    $a.Add('job') | Out-Null

    # ---- delete (unregister) -------------------------------------------------
    if ($Action -eq 'delete') {
        $a.Add('delete') | Out-Null
        $a.Add('-g') | Out-Null; $a.Add("$ResourceGroup") | Out-Null
        $a.Add('-n') | Out-Null; $a.Add("$JobName") | Out-Null
        $a.Add('--yes') | Out-Null
        return @{ ok = $true; reason = "delete (unregister) job $JobName"; action = $Action; args = @($a.ToArray()); private = $true; hasInlineSecret = $false }
    }

    # ---- start (on-demand manual execution, for verification) ----------------
    if ($Action -eq 'start') {
        $a.Add('start') | Out-Null
        $a.Add('-g') | Out-Null; $a.Add("$ResourceGroup") | Out-Null
        $a.Add('-n') | Out-Null; $a.Add("$JobName") | Out-Null
        return @{ ok = $true; reason = "start one on-demand execution of job $JobName"; action = $Action; args = @($a.ToArray()); private = $true; hasInlineSecret = $false }
    }

    # ---- create / update -----------------------------------------------------
    if (-not "$EnvName".Trim() -and $Action -eq 'create') { return @{ ok = $false; reason = '-EnvName required for create'; action = $Action; args = @(); private = $true; hasInlineSecret = $false } }
    if (-not "$Image".Trim())   { return @{ ok = $false; reason = '-Image required'; action = $Action; args = @(); private = $true; hasInlineSecret = $false } }
    $cronCheck = Test-PimDownlinkJobCron -Cron $Cron
    if (-not $cronCheck.ok) { return @{ ok = $false; reason = "bad cron: $($cronCheck.reason)"; action = $Action; args = @(); private = $true; hasInlineSecret = $false } }

    $a.Add("$Action") | Out-Null
    $a.Add('-g') | Out-Null; $a.Add("$ResourceGroup") | Out-Null
    $a.Add('-n') | Out-Null; $a.Add("$JobName") | Out-Null
    if ($Action -eq 'create') {
        $a.Add('--environment') | Out-Null; $a.Add("$EnvName") | Out-Null
        # workload-profile Consumption matches the proven worker matrix.
        $a.Add('--workload-profile-name') | Out-Null; $a.Add('Consumption') | Out-Null
        # SCHEDULE trigger -- the cloud cron. This is what makes it a scheduled Job.
        $a.Add('--trigger-type') | Out-Null; $a.Add('Schedule') | Out-Null
        $a.Add('--cron-expression') | Out-Null; $a.Add("$Cron") | Out-Null
        $a.Add('--replica-timeout') | Out-Null; $a.Add("$ReplicaTimeout") | Out-Null
        $a.Add('--replica-retry-limit') | Out-Null; $a.Add("$ReplicaRetryLimit") | Out-Null
        # identity: user-assigned MI if supplied, else system-assigned. NO secret.
        if ("$IdentityResourceId".Trim()) {
            $a.Add('--mi-user-assigned') | Out-Null; $a.Add("$IdentityResourceId") | Out-Null
        } else {
            $a.Add('--mi-system-assigned') | Out-Null
        }
    } else {
        # update: keep the cron current (allows re-scheduling on re-deploy).
        $a.Add('--cron-expression') | Out-Null; $a.Add("$Cron") | Out-Null
        $a.Add('--replica-timeout') | Out-Null; $a.Add("$ReplicaTimeout") | Out-Null
        $a.Add('--replica-retry-limit') | Out-Null; $a.Add("$ReplicaRetryLimit") | Out-Null
    }
    $a.Add('--image') | Out-Null; $a.Add("$Image") | Out-Null
    # registry pulled via MANAGED IDENTITY (AcrPull) -- never registry creds inline.
    if ("$AcrServer".Trim()) {
        $a.Add('--registry-server') | Out-Null; $a.Add("$AcrServer") | Out-Null
        $a.Add('--registry-identity') | Out-Null; $a.Add("$RegistryIdentity") | Out-Null
    }
    $a.Add('--cpu') | Out-Null; $a.Add("$Cpu") | Out-Null
    $a.Add('--memory') | Out-Null; $a.Add("$Memory") | Out-Null
    if (@($EnvVars).Count -gt 0) {
        $a.Add('--env-vars') | Out-Null
        foreach ($e in @($EnvVars)) { $a.Add("$e") | Out-Null }
    }
    if (@($Command).Count -gt 0) {
        $a.Add('--command') | Out-Null
        foreach ($c in @($Command)) { $a.Add("$c") | Out-Null }
    }
    $a.Add('-o') | Out-Null; $a.Add('none') | Out-Null

    # By construction no element is a raw secret value (identity = MI ref/secret-ref,
    # registry = MI). Assert it for the test: no env entry that looks like an inline
    # secret value (PIM_*_SECRET / *PASSWORD / connection-string with Password=).
    $inline = $false
    foreach ($e in @($EnvVars)) {
        if ("$e" -match '(?i)(password=|pwd=|client[_-]?secret=|accountkey=|sharedaccesskey=)') { $inline = $true }
    }
    foreach ($x in @($a.ToArray())) {
        if ("$x" -match '(?i)(password=|pwd=|client[_-]?secret=|accountkey=|sharedaccesskey=)') { $inline = $true }
    }
    return @{ ok = $true; reason = "$Action scheduled downlink job $JobName (cron '$Cron')"; action = $Action; args = @($a.ToArray()); private = $true; hasInlineSecret = $inline }
}

# ---------------------------------------------------------------------------
# WHOLE DEPLOY PLAN (pure). Compose placement + command + env + the create/update
# arg set into ONE plan object the wrapper executes. -Exists decides create vs
# update (idempotent). PURE: no probe here -- the wrapper supplies -Exists from its
# `az containerapp job show` probe.
# Returns @{ ok; reason; placement; command; envVars; jobArgs=<Build-...> ; exists }.
# ---------------------------------------------------------------------------
function Get-PimDownlinkJobDeployPlan {
    param(
        [Parameter(Mandatory)][ValidateSet('S5','S6')][string]$Scenario,
        [Parameter(Mandatory)][string]$TenantId,
        [ValidateRange(0,2)][int]$SlaveRing = 2,
        [Parameter(Mandatory)][string]$JobName,
        [Parameter(Mandatory)][string]$ResourceGroup,
        [Parameter(Mandatory)][string]$EnvName,
        [Parameter(Mandatory)][string]$Image,
        [string]$AcrServer,
        [Parameter(Mandatory)][string]$Cron,
        [string]$EntryPath = '/app/PIM4EntraPS/tools/pim-engine/downlink-job-entry.ps1',
        [string]$BaselineUrl,
        [string]$BaselineDocPath,
        [string]$SqlServerFqdn,
        [string]$SqlDatabase = 'PimPlatform',
        [string]$SyncRootCentral = '/sync/central',
        [string]$SyncRootLocal   = '/sync/local',
        [string]$IdentityResourceId,
        [string]$RegistryIdentity = 'system',
        [bool]$Exists = $false
    )
    $placement = Get-PimDownlinkJobPlacement -Scenario $Scenario
    $command = Get-PimDownlinkJobCommand -EntryPath $EntryPath -Scenario $Scenario -TenantId $TenantId -SlaveRing $SlaveRing -BaselineUrl $BaselineUrl -BaselineDocPath $BaselineDocPath
    $envVars = Get-PimDownlinkJobEnv -Scenario $Scenario -TenantId $TenantId -SqlServerFqdn $SqlServerFqdn -SqlDatabase $SqlDatabase -SyncRootCentral $SyncRootCentral -SyncRootLocal $SyncRootLocal
    $action = if ($Exists) { 'update' } else { 'create' }
    $jobArgs = Build-PimDownlinkJobArgs -Action $action -JobName $JobName -ResourceGroup $ResourceGroup `
        -EnvName $EnvName -Image $Image -AcrServer $AcrServer -Cron $Cron `
        -Command $command -EnvVars $envVars -IdentityResourceId $IdentityResourceId -RegistryIdentity $RegistryIdentity
    return @{
        ok        = [bool]$jobArgs.ok
        reason    = "$($placement.reason); $($jobArgs.reason)"
        scenarioId = "$($placement.scenarioId)"
        placement = $placement
        command   = @($command)
        envVars   = @($envVars)
        jobArgs   = $jobArgs
        exists    = [bool]$Exists
        action    = $action
    }
}

# ---------------------------------------------------------------------------
# EXECUTION VERDICT (pure). The verification helper's decision core: given a Job's
# last-execution status (from `az containerapp job execution list`) + the execution
# LOG text (from the log stream), decide whether a REAL successful execution ran
# AND actually pulled+synced+applied -- distinguishing "the job exists" from "a run
# really did the downlink". Returns @{ ran; succeeded; pulled; synced; applied;
# verified; reason }. verified = ran AND succeeded AND (pulled & synced & applied
# evidence in the log).
#   -Status     : the execution status string ('Succeeded'|'Failed'|'Running'|'').
#   -LogText    : the captured execution log (stdout) of the run.
# Evidence markers are the entrypoint's own log lines (see downlink-job-entry.ps1):
#   pulled  : 'baseline: loaded' / 'baseline: pulled' / 'DOWNLINK PLANNED|APPLIED'
#   synced  : 'staged files:' / 'sync files:'
#   applied : 'engine-apply' / 'DOWNLINK APPLIED' / 'SCENARIO RUN'
# ---------------------------------------------------------------------------
function Get-PimDownlinkJobExecutionVerdict {
    param(
        [string]$Status,
        [string]$LogText
    )
    $st = "$Status".Trim()
    $log = "$LogText"
    $ran = [bool]$st   # any execution status means an execution exists/ran
    $succeeded = ($st -eq 'Succeeded')
    $pulled  = ($log -match '(?i)baseline:\s*(loaded|pulled)' -or $log -match '(?i)DOWNLINK\s+(PLANNED|APPLIED)')
    $synced  = ($log -match '(?i)(staged files:|sync files:)')
    $applied = ($log -match '(?i)(engine-apply|DOWNLINK APPLIED|SCENARIO RUN)')
    $verified = ($ran -and $succeeded -and $pulled -and $synced -and $applied)
    $reason =
        if (-not $ran) { 'NO execution found -- the job exists but has never run (deploy != run)' }
        elseif (-not $succeeded) { "last execution status='$st' (not Succeeded)" }
        elseif (-not ($pulled -and $synced -and $applied)) { "execution Succeeded but log lacks downlink evidence (pulled=$pulled synced=$synced applied=$applied)" }
        else { "VERIFIED: a real execution pulled + synced + applied the downlink (status=$st)" }
    return @{
        ran = $ran; succeeded = $succeeded; pulled = [bool]$pulled; synced = [bool]$synced; applied = [bool]$applied
        verified = [bool]$verified; reason = $reason
    }
}
