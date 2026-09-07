#requires -Version 5.1
<#
.SYNOPSIS
    PIM4EntraPS -- register the STANDALONE update on a VisualCron / Windows Task Scheduler
    cadence. This is the unattended host for the update mechanism. (REQUIREMENTS sec.1/sec.6;
    "Update is SEPARATE from the PIM engine + job-scheduler", operator correction 2026-06-18.)

.DESCRIPTION
    The UPDATE (code -> SQL-schema upgrade + Manager GUI build/roll) is a STANDALONE mechanism,
    NOT a PIM engine or in-container scheduler job. Customers run it from VisualCron or Windows
    Task Scheduler (the standalone host). This script registers a Windows Scheduled Task (the
    same XML VisualCron imports / mirrors) that fires the update unattended, cert-auth, no prompts.

    By DEFAULT (-UpdateMode Full) the task runs the FULL update lifecycle
    (tools/setup/Invoke-PimUpdate.ps1 -Apply): detect -> build the Manager image from the pulled
    code (when the GUI changed) -> roll -> apply the idempotent SQL schema upgrade -> verify
    (hosted smoke) -> notify -> ensure-monitor, with auto-rollback on a failed verify. This is the
    correct standalone entry because it handles the WHOLE dependency chain (schema AND GUI), for
    BOTH the VM and container editions.

    -UpdateMode RollOnly registers the lighter image-roll-only path (Invoke-PimSyncAutomateIT.ps1
    -Apply): it only rolls a strictly-newer ALREADY-BUILT released image, health-checks, and
    auto-rolls-back. Use it when you keep a separate build pipeline and just want a controlled roll.

    -Source selects the pull edition the update uses:
      * sync-automateit (default) -- INTERNAL edition: hosted ACA + Azure SQL (az acr build / ACA roll).
      * git-pull                  -- COMMUNITY edition: local/VM (local build/relaunch + local SQL upgrade).
    -ManagedHosting central|local applies to the from-master (MSP slave) downlink.

    -LocalPull (community pure-VM hosts) instead drives a customer-supplied -PullScript (e.g. a
    git/sync pull of the released code that THEN calls Invoke-PimUpdate.ps1), so the same scheduled
    cadence works for a no-ACA host. (On the internal edition the bootstrap post-sync deploy hook
    fires Invoke-PimUpdate.ps1 automatically after each sync-automateit pull; this scheduled task is
    the explicit standalone alternative / the VM-host path.)

.PARAMETER AtHour
    Hour of day (0-23, local time) to run the daily update. Default 03 (low-traffic window).

.PARAMETER AtMinute
    Minute past the hour (0-59). Default 0. Use it to STAGGER several environments that update
    from the same host -- they all pull into the same tree, so "04:00" three times over is three
    concurrent syncs of one directory. 04:00 / 04:20 / 04:40 is the shape in use here.

.PARAMETER UpdateMode
    'Full' (default) = the full update lifecycle (Invoke-PimUpdate.ps1 -Apply: schema + GUI build/roll
    + verify + rollback). 'RollOnly' = image roll only (Invoke-PimSyncAutomateIT.ps1 -Apply).

.PARAMETER Source
    Update pull edition: 'sync-automateit' (internal, default) or 'git-pull' (community). Only used
    by -UpdateMode Full (passed through to Invoke-PimUpdate.ps1 -Source).

.PARAMETER ManagedHosting
    'central'|'local' for the from-master (MSP slave) downlink; passed through to Invoke-PimUpdate.ps1.

.PARAMETER RunAsUser
    Service account the task runs as (must be able to `az login`/MI + reach the deployment).

.PARAMETER LocalPull
    Drive a local pull (-PullScript) instead of the update entry (for a no-ACA community VM host).

.PARAMETER PullScript
    Path to the local pull script invoked when -LocalPull is set.

.EXAMPLE
    .\Register-PimSyncSchedule.ps1
    Daily 03:00 standalone FULL update of the internal/hosted deployment (schema + GUI build/roll).

.EXAMPLE
    .\Register-PimSyncSchedule.ps1 -Source git-pull -AtHour 4
    Daily 04:00 standalone FULL update of a COMMUNITY (git-pull) deployment.

.EXAMPLE
    .\Register-PimSyncSchedule.ps1 -UpdateMode RollOnly
    Daily 03:00 controlled image ROLL only (no build/schema) of the hosted deployment.

.EXAMPLE
    .\Register-PimSyncSchedule.ps1 -LocalPull -PullScript C:\AutomateIT\Sync-AutomateIT.ps1 -AtHour 4
    Daily 04:00 local pull on a pure-VM community host (the pull script then runs Invoke-PimUpdate.ps1).

.NOTES
    Re-runnable (-Force overwrites the task). Mirrors Setup-PimVM.ps1's scheduled-task style. The
    task XML can be exported (`Export-ScheduledTask -TaskName <name>`) and imported into VisualCron.
    The update is unattended + cert-auth (no prompts) by design. This script NEVER wires the update
    into the engine or the in-container scheduler -- it is the standalone host.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [ValidateRange(0,23)][int]$AtHour = 3,
    # 🔴 MINUTES MATTER ON A MULTI-ENVIRONMENT HOST. One VM updates several environments, and every
    # one of them PULLS INTO THE SAME TREE before building. -AtHour alone can only express "04:00",
    # so asking for three environments "at 4am" registered three tasks that would sync into
    # C:\AutomateIT simultaneously. `-MultipleInstances IgnoreNew` does NOT help: it is per-task,
    # and these are different tasks. Stagger them (04:00 / 04:20 / 04:40) AND rely on the run lock
    # below -- the stagger is the plan, the lock is what holds when a run overruns.
    [ValidateRange(0,59)][int]$AtMinute = 0,
    # How long a run waits for the shared-tree lock before SKIPPING itself. Long enough to absorb
    # a slow neighbour (a full build+roll measures 8-10 minutes here), short enough that a wedged
    # night does not run into the working day.
    [ValidateRange(0,240)][int]$LockWaitMinutes = 45,
    [string]$TaskName  = 'PIM-Update',
    [ValidateSet('Full','RollOnly')][string]$UpdateMode = 'Full',
    [ValidateSet('sync-automateit','git-pull')][string]$Source = 'sync-automateit',
    [ValidateSet('central','local')][string]$ManagedHosting,
    [string]$RunAsUser = 'NT AUTHORITY\NETWORK SERVICE',
    [switch]$LocalPull,
    [string]$PullScript,
    # passthrough to the update / roll orchestrator
    [string]$ResourceGroup = "$($env:PIM_ResourceGroup)",
    [string]$AcrName       = "$($env:PIM_AcrName)",
    [string]$ImageRepo     = 'pim-manager',
    # 🔴 WHICH SUBSCRIPTION. Without this the update runs against the ambient az context, and in an
    # MSP estate every tenant is a different subscription -- see the block above the registration.
    [string]$SubscriptionId,
    # Where the update's failure/success mail goes. Invoke-PimUpdate deliberately has no default
    # recipient ("a default would email somebody else"), so an unset one means a silent failure.
    [string]$Recipient = "$($env:PIM_NotifyRecipient)",
    # Transcript directory. Defaults to <solution>\output\update-logs.
    [string]$LogDir,
    # A scheduled task does not inherit your az login. These are the same two hooks
    # Update-PimBaselineSas.ps1 exposes, for the same reason.
    [string]$AzureConfigDir,
    # 🪤 A PATH, not a command line -- matching Update-PimBaselineSas.ps1, which Test-Paths it.
    # Passing "script.ps1 -Arg x" here makes the wrapper run `& '<the whole string>'`, and
    # PowerShell then looks for a COMMAND whose NAME contains the arguments. Measured 2026-09-03:
    # "The term '...Connect-PimTenantAz.ps1 -TenantShortName ... -Quiet' is not recognized".
    # Arguments go in -PreAuthArgs.
    [string]$PreAuthScript,
    [string]$PreAuthArgs,
    # ---- PULL-BEFORE-UPDATE (the half that was missing entirely) -------------------------
    # 🔴 WITHOUT THIS THE NIGHTLY UPDATE REBUILDS THE SAME CODE FOREVER. Invoke-PimUpdate's own
    # synopsis says "after PIM code is pulled" -- it contains no git pull, no fetch, no sync call --
    # and Build-PimManagerImage builds from `git archive HEAD` of the LOCAL clone. So a fix pushed
    # to the private GitHub repo never reaches the image, while the run still reports "built",
    # because it DID build, just from unchanged code. Measured 2026-09-03: nothing on this host was
    # scheduled to run the sync at all.
    # 🔒 GENERIC ON PURPOSE -- nothing here knows what a solution is. -SyncScript is any puller
    # (bootstrap\Sync-AutomateIT.ps1, sync\Sync-AutomateIT.ps1, a customer's own), and -SyncArgs is
    # passed through verbatim, so the same wiring serves SecurityInsight or a v3 solution unchanged.
    # 📌 The properly shared home for this is the sync-triggered auto-deploy that solution.deploy.json
    # already declares (runWhenChanged, deploy.script) and that PLAT-02 records as NOT BUILT --
    # "NOTHING MERGES THEM YET". This is the per-task workaround until that exists, and it is
    # deliberately NOT a change to sync/, which auto-deploys to ~30 customers with no review step.
    [string]$SyncScript,
    [string]$SyncArgs,
    # A failed pull ABORTS by default rather than updating from a tree of unknown freshness: the
    # damage is not the failed pull, it is the green "updated" that follows one.
    [switch]$ContinueOnSyncFailure,
    # ---- WHERE THE PULL CREDENTIAL COMES FROM (operator, 2026-09-04: "github pat is in secret
    # inside visualcron" / "or in keybault") -----------------------------------------------------
    # 🔒 THE TOKEN IS NEVER WRITTEN INTO THE WRAPPER. This script GENERATES a .ps1 on disk that
    # anyone who can read the log directory can read, so a literal PAT there would be a plaintext
    # credential at rest with repo-wide scope. Both options below resolve the secret AT RUN TIME,
    # inside the wrapper, into a variable -- and the call site passes `-Token $tok`, never the
    # expanded value, so the running transcript does not capture it either.
    #   -SyncTokenEnvVar   : name of an env var the SCHEDULER injects (VisualCron secret).
    #   -SyncTokenKeyVault : vault + secret name, read with the Az context pre-auth just left.
    # Neither is required: sync/Sync-AutomateIT.ps1 also has a DPAPI `.automateit-pat` fallback for
    # a host that has already been enrolled by hand.
    [string]$SyncTokenEnvVar,
    [string]$SyncTokenKeyVault,
    [string]$SyncTokenSecretName,
    # platform-config.json holding BootstrapAppId / BootstrapThumbprint / TenantId for the tenant
    # the VAULT lives in. Required with -SyncTokenKeyVault on an unattended task, which inherits no
    # login: the pre-auth points at the CUSTOMER tenant, the vault is in the OPERATOR's.
    [string]$SyncTokenBootstrapConfig
)
$ErrorActionPreference = 'Stop'
$here = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
$atText = [string]::Format('{0:00}:{1:00}', $AtHour, $AtMinute)
function Step($m){ Write-Host "==> $m" -ForegroundColor Cyan }
# Same shape as the sibling setup scripts. (Setup-PimContainers.ps1 shipped without Warn and it
# killed every estate deploy that passed a certificate -- BUG-117. Defining both here, together.)
function Note($m){ Write-Host "    $m" -ForegroundColor DarkGray }
function Warn($m){ Write-Host "    $m" -ForegroundColor Yellow }

if ($LocalPull) {
    if (-not "$PullScript".Trim()) { throw "-LocalPull requires -PullScript <path to the local pull script>." }
    $exe = 'powershell.exe'
    $arg = "-NoProfile -ExecutionPolicy Bypass -File `"$PullScript`""
    Step "Scheduled Task '$TaskName' -> local pull: $PullScript (daily $($atText))"
} elseif ($UpdateMode -eq 'RollOnly') {
    # lighter path: roll a strictly-newer ALREADY-BUILT image (no build / no schema).
    $orch = Join-Path $here 'Invoke-PimSyncAutomateIT.ps1'
    if (-not (Test-Path $orch)) { throw "roll orchestrator not found: $orch" }
    $exe = 'powershell.exe'
    $arg = "-NoProfile -ExecutionPolicy Bypass -File `"$orch`" -Apply -ResourceGroup `"$ResourceGroup`" -AcrName `"$AcrName`" -ImageRepo `"$ImageRepo`""
    Step "Scheduled Task '$TaskName' -> ROLL ONLY (Invoke-PimSyncAutomateIT.ps1, daily $($atText))"
} else {
    # default FULL update lifecycle: schema upgrade + GUI build/roll + verify + rollback. This is
    # the correct STANDALONE update entry -- it handles the whole dependency chain for VM + container.
    $orch = Join-Path $here 'Invoke-PimUpdate.ps1'
    if (-not (Test-Path $orch)) { throw "update entry not found: $orch" }
    $exe = 'powershell.exe'
    $arg = "-NoProfile -ExecutionPolicy Bypass -File `"$orch`" -Apply -Source `"$Source`" -ResourceGroup `"$ResourceGroup`" -AcrName `"$AcrName`" -ImageRepo `"$ImageRepo`""
    if ("$ManagedHosting".Trim()) { $arg += " -ManagedHosting `"$ManagedHosting`"" }
    Step "Scheduled Task '$TaskName' -> FULL update (Invoke-PimUpdate.ps1 -Source $Source, daily $($atText))"
}

# 🔴 THREE THINGS THAT MADE THE ARMED TASK FAIL SILENTLY, ALL MEASURED 2026-09-03.
# The task registered fine, reported Ready, and its first real run returned LastTaskResult=1 with
# NOTHING to say why. Triggering the identical command by hand produced the cause:
#
#   ERROR: The resource 'acrpimwa678' ... could not be found in subscription
#          '<operator-subscription>'
#
# 1. NO SUBSCRIPTION TARGETING. This script took -ResourceGroup and -AcrName but never a
#    subscription, and Invoke-PimUpdate.ps1 has no -SubscriptionId either -- so the update ran
#    against whatever az context happened to be ambient. In an MSP estate, where every tenant is a
#    DIFFERENT subscription, that can only ever work by luck. 🪤 And the error names a missing
#    RESOURCE, so it reads as "the ACR is gone" rather than "you are in the wrong subscription" --
#    the same misdirection as ESTATE-14.
# 2. NO CONTEXT UNDER THE SERVICE ACCOUNT. A scheduled task does not inherit your az login, and
#    NETWORK SERVICE's profile is empty, so even the right subscription id would have had nothing
#    to authenticate with. -PreAuthScript is the hook (same shape Update-PimBaselineSas.ps1 uses,
#    and for the same reason).
# 3. NO OUTPUT ANYWHERE. No transcript, no redirect. At 03:00 the entire record of a failed fleet
#    update was a single integer. An unattended job that cannot say what it did is not operable.
# 🪤 -SubscriptionId is NOT forwarded to the orchestrator: Invoke-PimUpdate.ps1 has no such
# parameter (checked), and passing one would fail the run with "A parameter cannot be found".
# The subscription is applied to the az CONTEXT in the wrapper below, which is where it belongs --
# every az call the update makes then inherits it.
if ("$Recipient".Trim()) { $arg += " -Recipient `"$Recipient`"" }

# 🔒 A GENERATED WRAPPER SCRIPT, NOT AN INLINE -Command STRING.
# The first attempt built the wrapper as a nested `powershell -Command "..."` string. It has three
# quoting levels (this script -> Task Scheduler -> powershell) and it broke in both of the ways
# that are easy to miss and hard to read: the transcript path kept `$(Get-Date ...)` LITERALLY, so
# the log was a file actually named "PIM-Update-wa678-$(Get-Date -Format yyyyMMdd-HHmmss).log";
# and the escaped `Write-Host \"...\"` collapsed to `Write-Host \ABORT` with $ctx unexpanded.
# A file has ONE quoting level. It is also inspectable after the fact, which an inline string in a
# task definition is not.
if (-not "$LogDir".Trim()) { $LogDir = Join-Path (Split-Path -Parent (Split-Path -Parent $here)) 'output\update-logs' }
$null = New-Item -ItemType Directory -Force -Path $LogDir -ErrorAction SilentlyContinue
$wrapperPath = Join-Path $LogDir "$TaskName.run.ps1"
$w = New-Object System.Text.StringBuilder
[void]$w.AppendLine("# GENERATED by Register-PimSyncSchedule.ps1 for scheduled task '$TaskName'.")
[void]$w.AppendLine("# Regenerated on every registration -- edit the registration, not this file.")
[void]$w.AppendLine("`$ErrorActionPreference = 'Continue'")
[void]$w.AppendLine("`$log = Join-Path '$LogDir' (`"$TaskName-`" + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.log')")
[void]$w.AppendLine("Start-Transcript -Path `$log -Force | Out-Null")

# ---- RUN LOCK: two environments must never pull into the same tree at once --------------------
# 🔴 THE SHARED RESOURCE IS THE TREE, NOT THE TASK. Every environment on this host runs the same
# -SyncScript into the same destination and then builds an image FROM it. Two overlapping runs
# means one task's build reads a directory the other task is mid-way through overwriting -- and it
# would not fail cleanly, it would build and ship a half-written tree. `-MultipleInstances
# IgnoreNew` (set on the task below) cannot see this: it only stops a task overlapping ITSELF.
# 🪤 So the stagger is not the safety mechanism, it is the plan; this lock is the safety mechanism.
# An exclusive FileStream, not a mutex: it needs no privilege (a Global\ mutex needs
# SeCreateGlobalPrivilege), it works across users, and Windows releases the handle if the process
# dies -- so a killed run cannot wedge every following night.
# 🔒 WAITS, then gives up honestly. A skipped run that SAYS it skipped is recoverable; a run that
# proceeds into a tree another run is rewriting is not.
$lockKey = if ("$SyncScript".Trim()) { (Split-Path -Parent $SyncScript) } else { $LogDir }
$lockPath = Join-Path $LogDir ('.update-' + ([System.BitConverter]::ToString(
    [System.Security.Cryptography.SHA256]::Create().ComputeHash(
        [System.Text.Encoding]::UTF8.GetBytes($lockKey.ToLowerInvariant()))).Replace('-','').Substring(0,12)) + '.lock')
[void]$w.AppendLine("`$lockPath = '$lockPath'")
[void]$w.AppendLine("`$lockFs = `$null")
[void]$w.AppendLine("`$lockDeadline = (Get-Date).AddMinutes($LockWaitMinutes)")
[void]$w.AppendLine("while (-not `$lockFs -and (Get-Date) -lt `$lockDeadline) {")
[void]$w.AppendLine("    try { `$lockFs = [System.IO.File]::Open(`$lockPath, 'OpenOrCreate', 'ReadWrite', 'None') }")
[void]$w.AppendLine("    catch { Write-Host ('waiting for the update lock (another environment is updating from this tree): ' + `$lockPath); Start-Sleep -Seconds 30 }")
[void]$w.AppendLine("}")
[void]$w.AppendLine("if (-not `$lockFs) {")
[void]$w.AppendLine("    Write-Host ('ABORT: could not take the update lock within $LockWaitMinutes minute(s) -- another environment is still updating from this tree. SKIPPING this run rather than building from a tree that is being rewritten. Lock: ' + `$lockPath)")
[void]$w.AppendLine("    Stop-Transcript | Out-Null")
[void]$w.AppendLine("    exit 6")
[void]$w.AppendLine("}")
[void]$w.AppendLine("Write-Host ('update lock held: ' + `$lockPath)")

[void]$w.AppendLine("try {")
if ("$AzureConfigDir".Trim()) { [void]$w.AppendLine("    `$env:AZURE_CONFIG_DIR = '$AzureConfigDir'") }

# ---- RESOLVE THE PULL TOKEN **BEFORE** THE TENANT PRE-AUTH -------------------------------------
# 🔴 ORDER IS LOAD-BEARING, AND GETTING IT WRONG FAILS IN A WAY THAT READS AS A PERMISSION BUG.
# Measured 2026-09-04, reading the PAT after the pre-auth:
#     AKV10032: Invalid issuer. Expected one of https://sts.windows.net/<operator-tenant>/,
#     found https://sts.windows.net/<customer-tenant>/
# The pre-auth deliberately moves the Az context INTO THE CUSTOMER'S TENANT so the build can reach
# that customer's ACR. The pull credential, however, lives in the OPERATOR'S central vault, in a
# DIFFERENT tenant -- that split is the MSP model, not a misconfiguration. So the vault read has to
# happen while the operator context is still available, i.e. first.
# 🪤 It reads as "the SPN lacks Key Vault rights". It is not: the identity is fine and is simply
# being presented to the wrong directory.
if ("$SyncScript".Trim()) {
    [void]$w.AppendLine("    `$tok = `$null")
    if ("$SyncTokenEnvVar".Trim()) {
        # No tenant dependency at all -- the scheduler already holds the secret. Preferred.
        [void]$w.AppendLine("    `$tok = [Environment]::GetEnvironmentVariable('$SyncTokenEnvVar')")
        [void]$w.AppendLine("    if (`"`$tok`".Trim()) { Write-Host 'pull token: from scheduler-injected environment variable' }")
        [void]$w.AppendLine("    else { Write-Host `"WARNING: env var '$SyncTokenEnvVar' is empty in this process -- the scheduler did not inject the secret. Falling back to the puller's own credential resolution.`" }")
    } elseif ("$SyncTokenKeyVault".Trim()) {
        if (-not "$SyncTokenSecretName".Trim()) { throw "-SyncTokenKeyVault requires -SyncTokenSecretName." }
        if ("$SyncTokenBootstrapConfig".Trim()) {
            if (-not (Test-Path -LiteralPath $SyncTokenBootstrapConfig)) { throw "-SyncTokenBootstrapConfig '$SyncTokenBootstrapConfig' not found." }
            # Connect to the VAULT'S OWN tenant with the documented bootstrap cert. An unattended
            # task inherits no login, so without this there is no operator context to read with.
            [void]$w.AppendLine("    try {")
            [void]$w.AppendLine("        `$bc = Get-Content -LiteralPath '$SyncTokenBootstrapConfig' -Raw | ConvertFrom-Json")
            [void]$w.AppendLine("        Connect-AzAccount -ServicePrincipal -Tenant `$bc.TenantId -ApplicationId `$bc.BootstrapAppId -CertificateThumbprint `$bc.BootstrapThumbprint -WarningAction SilentlyContinue -ErrorAction Stop | Out-Null")
            [void]$w.AppendLine("        Write-Host `"pull token: bootstrap-connected to the vault's tenant (`$(`$bc.TenantId))`"")
            [void]$w.AppendLine("    } catch { Write-Host `"WARNING: bootstrap connect for the vault failed: `$(`$_.Exception.Message)`" }")
        }
        [void]$w.AppendLine("    try { `$tok = Get-AzKeyVaultSecret -VaultName '$SyncTokenKeyVault' -Name '$SyncTokenSecretName' -AsPlainText -ErrorAction Stop }")
        [void]$w.AppendLine("    catch { Write-Host `"WARNING: could not read '$SyncTokenSecretName' from '$SyncTokenKeyVault': `$(`$_.Exception.Message)`" }")
        [void]$w.AppendLine("    if (`"`$tok`".Trim()) { Write-Host 'pull token: from Key Vault' }")
    }
}
if ("$PreAuthScript".Trim()) {
    # validated at REGISTRATION so a bad path fails now, in front of you, rather than at 03:00.
    if (-not (Test-Path -LiteralPath $PreAuthScript)) { throw "-PreAuthScript '$PreAuthScript' not found. (It is a PATH; put arguments in -PreAuthArgs.)" }
    [void]$w.AppendLine("    & '$PreAuthScript' $PreAuthArgs")
    [void]$w.AppendLine("    if (`$LASTEXITCODE -and `$LASTEXITCODE -ne 0) { Write-Host `"ABORT: pre-auth failed (exit `$LASTEXITCODE) -- not running the update without a verified context.`"; exit 3 }")
}
if ("$SubscriptionId".Trim()) {
    # 🔴 ASSERT, never assume: `az account set` is SILENT when the subscription is not visible to
    # this login, and leaves you on the previous one. Measured 2026-09-03: the first armed run
    # built against the wrong subscription and failed as "the ACR could not be found".
    [void]$w.AppendLine("    az account set --subscription '$SubscriptionId' -o none 2>`$null")
    [void]$w.AppendLine("    `$ctx = (az account show --query id -o tsv 2>`$null)")
    [void]$w.AppendLine("    if (`"`$ctx`".Trim() -ne '$SubscriptionId') {")
    [void]$w.AppendLine("        Write-Host (`"ABORT: az context is '`" + `$ctx + `"', expected '$SubscriptionId' -- refusing to update the wrong subscription.`")")
    [void]$w.AppendLine("        exit 2")
    [void]$w.AppendLine("    }")
    [void]$w.AppendLine("    Write-Host (`"az context asserted: `" + `$ctx)")
}
# ---- THE PULL, emitted BEFORE the update ------------------------------------------------------
# 🔴 ORDER IS THE WHOLE POINT. The update builds from `git archive HEAD` of the LOCAL clone, so if
# the pull ran after it, every night would build yesterday's code and still report "built".
if ("$SyncScript".Trim()) {
    # Validated at REGISTRATION so a bad path fails in front of you now, not at 03:00 unattended.
    if (-not (Test-Path -LiteralPath $SyncScript)) {
        throw "-SyncScript '$SyncScript' not found. (It is a PATH; put arguments in -SyncArgs.)"
    }
    [void]$w.AppendLine("    Write-Host '--- PULL: refreshing the tree the image is built FROM ---'")
    # 🪤 `-Token `$tok` passes the VARIABLE. Interpolating the value here would put the PAT in the
    # generated file AND in the transcript. If no token resolved, omit the parameter entirely and
    # let the puller use its own DPAPI fallback -- an empty -Token is worse than no -Token.
    [void]$w.AppendLine("    if (`"`$tok`".Trim()) { & '$SyncScript' -Token `$tok $SyncArgs } else { & '$SyncScript' $SyncArgs }")
    [void]$w.AppendLine("    `$syncRc = `$LASTEXITCODE")
    [void]$w.AppendLine("    `$tok = `$null")
    if ($ContinueOnSyncFailure) {
        [void]$w.AppendLine("    if (`$syncRc -and `$syncRc -ne 0) { Write-Host `"WARNING: pull failed (exit `$syncRc) -- continuing on -ContinueOnSyncFailure. The build below uses the tree AS IT IS, which may be stale.`" }")
    } else {
        [void]$w.AppendLine("    if (`$syncRc -and `$syncRc -ne 0) { Write-Host `"ABORT: pull failed (exit `$syncRc) -- refusing to build from a tree of unknown freshness. An 'updated' report after a failed pull would call a central fix shipped when it was never pulled.`"; exit 4 }")
    }
    [void]$w.AppendLine("    Write-Host '--- pull OK ---'")
}
[void]$w.AppendLine("    & '$exe' $arg")
[void]$w.AppendLine("    exit `$LASTEXITCODE")
[void]$w.AppendLine("} finally { if (`$lockFs) { `$lockFs.Close(); `$lockFs.Dispose() }; Stop-Transcript | Out-Null }")
# 🪤 -WhatIf:$false ON PURPOSE. Without it, -WhatIf suppresses this Set-Content too, so a preview
# run registers nothing AND writes nothing -- leaving you unable to read the one artifact you ran
# -WhatIf to inspect. The wrapper is a regenerated scratch file in LogDir and contains NO secret
# (see the token block above), so writing it during a preview is safe; creating the TASK is the
# only thing -WhatIf must actually withhold, and that is still gated by ShouldProcess below.
Set-Content -LiteralPath $wrapperPath -Value $w.ToString() -Encoding UTF8 -WhatIf:$false
$exe = 'powershell.exe'
$arg = "-NoProfile -ExecutionPolicy Bypass -File `"$wrapperPath`""
Note "wrapper   : $wrapperPath"
Note "log       : $LogDir\$TaskName-<timestamp>.log"
if ("$SubscriptionId".Trim()) { Note "subscription: $SubscriptionId (asserted before the update runs)" }
else { Warn 'no -SubscriptionId: the update will run against whatever az context is ambient. In an MSP estate that is almost never what you want.' }
if (-not "$PreAuthScript".Trim() -and $RunAsUser -notmatch '\\\\|@') {
    Warn "no -PreAuthScript: '$RunAsUser' does not inherit your az login, so the run may have NO credential at all. Point -PreAuthScript at a script that leaves a usable az context."
}

if ($PSCmdlet.ShouldProcess($TaskName, 'register daily sync task')) {
    $a = New-ScheduledTaskAction -Execute $exe -Argument $arg
    $t = New-ScheduledTaskTrigger -Daily -At ([datetime]::Today.AddHours($AtHour).AddMinutes($AtMinute))
    $p = New-ScheduledTaskPrincipal -UserId $RunAsUser -LogonType ServiceAccount -RunLevel Highest
    # don't pile up overlapping runs; a roll can take minutes.
    $s = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Hours 1)
    Register-ScheduledTask -TaskName $TaskName -Action $a -Trigger $t -Principal $p -Settings $s -Force | Out-Null
    Write-Host "    registered: '$TaskName' runs daily at $($atText) as $RunAsUser" -ForegroundColor Green
}

Step "Done. Inspect/run on demand:  Start-ScheduledTask -TaskName '$TaskName'  |  Get-ScheduledTaskInfo -TaskName '$TaskName'"
