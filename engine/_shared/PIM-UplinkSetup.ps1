#Requires -Version 5.1
<#
.SYNOPSIS
  PIM REQUIREMENTS 100.10 -- PIM's half of framework DOCS/REQUIREMENTS.md 8.7 UPLINK-SETUP: the uplink report Kind=setup
  (Get Started steps, findings, identity permissions and the CONTROL LIST of critical parameters), plus the ring every
  heartbeat / run report carries (8.4 field 'Ring').

.DESCRIPTION
  ONE SOURCE. The control list below ($script:PimSetupControlsMinimum, + $script:PimSetupControlsExtended) is THE list:
    * the uplink job (PIM-Uplink.ps1, job 'uplink') reports EVERY control on EVERY setup report (unknown = could not
      check, never omitted);
    * Home's health notices (Open-PimManager.ps1 Get-PimManagerHealthNotices) show a missing / wrong critical control from
      the SAME evaluation (Get-PimSetupControlStates), so the GUI and the uplink cannot disagree;
    * the hand-over to Invardia (tools/setup/Build-PimSetupCatalog.ps1 -> setup-catalog.json) is built from it.
  INVARDIA'S CLOSED LISTS (data/setup/pim-manager.json, 2026-10-09): seeded with the framework MINIMUM control set only --
  the ids below exactly, 'value' only on the three enum controls. An unknown id rejects the WHOLE report, so until Invardia
  imports PIM's setup-catalog.json the report carries ONLY the minimum controls (+ permission counts / missing permission
  ids, which are shape-checked, not listed). PIM_UPLINK_SETUP_EXTENDED=1 (off by default) adds PIM's own ids: the Get Started
  steps, the findings and the extra controls (tenant-root Reader, break-glass protected, Activator apps, managing link).
  Identified mode only (an install key); anonymous Community sends nothing of this. Never: secret values, user names /
  UPNs, group names, tenant ids, error text -- ids, enums, counts and times only.
  PURE functions first (every one testable offline), then the one fact reader (Get-PimSetupFacts, through -GetSetting).
  Windows PowerShell 5.1 + pwsh 7. ASCII only.
#>
Set-StrictMode -Off

# ---------------------------------------------------------------------------------------------------------------------
# THE CONTROL LIST (framework 8.7 minimum -- ids EXACTLY as Invardia seeded them, 2026-10-09). One constant.
# ---------------------------------------------------------------------------------------------------------------------
$script:PimSetupControlsMinimum = @(
    [ordered]@{ id = 'updater-deployed'; title = 'Updater deployed'
        why = 'Without the updater job (ca-pim-update) PIM Manager never receives the fixes and security updates approved for its ring.'
        fix = 'Deploy the updater with Deploy-PimUpdateJob.ps1 (or re-run the guided install), then open Home again.' }
    [ordered]@{ id = 'updater-schedule'; title = 'Updater schedule enabled'; enum = @('enabled', 'disabled')
        why = 'A deployed updater that does not run on its nightly schedule never pulls what its ring approved, so the install falls behind.'
        fix = 'Check the updater job schedule in the resource group (it runs nightly); Jobs > Updates shows when it last ran.' }
    [ordered]@{ id = 'update-ring'; title = 'Update ring set'; enum = @('1', '2', '3')
        why = 'The ring decides which approved version this environment receives; without it the updater cannot choose a version.'
        fix = 'Set the ring with Deploy-PimUpdateJob.ps1 -Ring <1|2|3>; the deployment records it in the environment.' }
    [ordered]@{ id = 'uplink-key'; title = 'Uplink key present'
        why = 'The Invardia install key lets this environment report its health to Invardia support and take Pro updates.'
        fix = 'Keep "Pro updates from Invardia" on (it claims the key with the licence), or store the key from the customer portal as the PIM_UPLINK_KEY secret.' }
    [ordered]@{ id = 'licence-valid'; title = 'Licence valid'
        why = 'Pro features and Pro updates need a valid licence for this tenant.'
        fix = 'Load the current licence file in Settings > Licence (or let PIM request it automatically).' }
    [ordered]@{ id = 'mail-sender'; title = 'Mail sender works'
        why = 'TAP codes, approvals and alerts go out by mail; if the sender does not work nobody hears about problems.'
        fix = 'Set up the mail sender in Get Started > Mail sender and send a test mail.' }
    [ordered]@{ id = 'alert-recipients'; title = 'Alert recipients set'
        why = 'Guard holds and failing jobs are alerted by mail; without a recipient nobody receives them.'
        fix = 'Add at least one alert recipient in Settings > Alerting.' }
    [ordered]@{ id = 'identity-permissions'; title = 'Identity permissions complete'
        why = 'The engine identity needs every required Microsoft Graph permission; a missing one makes changes fail or be skipped.'
        fix = 'Open Home > Permissions (Verify permissions) and grant what it lists for the engine identity.' }
    [ordered]@{ id = 'last-run-24h'; title = 'Last successful run < 24 h'
        why = 'No successful engine run for a day means committed changes are not applied and the data shown is out of date.'
        fix = 'Open Jobs, fix the failing engine job and run it again (Run now).' }
    [ordered]@{ id = 'backup-configured'; title = 'Backup configured'
        why = 'The daily configuration backup is the restore point when a configuration is lost or broken.'
        fix = 'Keep the config-backup job on (Jobs) and check its last run in Operations > Backups & restore.' }
    [ordered]@{ id = 'update-pinned'; title = 'Update pinned on purpose'; enum = @('no', 'yes'); critical = $false
        why = 'An environment held on its version on purpose (PIM_UPDATE_HOLD=1) is shown as pinned, never as behind its ring.'
        fix = 'Remove PIM_UPDATE_HOLD from the updater job when the hold is over.' }
)
# PIM's own extras (framework 8.7 "PIM adds ..."). Sent only with PIM_UPLINK_SETUP_EXTENDED=1, after Invardia imported them.
$script:PimSetupControlsExtended = @(
    [ordered]@{ id = 'tenant-root-reader'; title = 'Reader at the tenant root'
        why = 'Discovery cannot see Azure management groups and subscriptions without Reader at the tenant root management group.'
        fix = 'Grant the engine identity Reader at the tenant root (Get Started > Engine permissions shows the exact command).' }
    [ordered]@{ id = 'breakglass-protected'; title = 'Break-glass accounts protected'
        why = 'The emergency accounts PIM must never touch have to be defined (and approved) before the engine changes access.'
        fix = 'Define the break-glass accounts in Get Started > Break-glass accounts; another SuperAdmin approves them.' }
    [ordered]@{ id = 'activator-apps'; title = 'Activator apps set up'; critical = $false
        why = 'Admins activate their access with the PIM Activator browser extension, which needs its Entra apps and settings.'
        fix = 'Do the steps in Get Started > Client onboarding (only when the Activator is used).' }
    [ordered]@{ id = 'managing-link'; title = 'Managing tenant link'
        why = 'A managed tenant takes its baseline from its managing tenant; with the link off nothing is pulled.'
        fix = 'Switch MSP downlink on in Settings > Features & edition (managed tenants only).' }
)

# The Get Started steps (pim-manager.html GET_STARTED_STEPS decides them; this is their stable id list for Invardia).
# Test-PimUplinkSetup pins that every step id on the page is here. Ids not listed are never sent.
$script:PimSetupSteps = @(
    [ordered]@{ id = 'naming'; title = 'Naming convention'; required = $true; why = 'PIM names the groups and admin accounts it creates by it; templates and wizards depend on it.' }
    [ordered]@{ id = 'envname'; title = 'Environment name'; required = $true; why = 'Tells several open PIM Managers apart (header and browser tab).' }
    [ordered]@{ id = 'licence'; title = 'Licence'; required = $true; why = 'Pro features and the updates from Invardia depend on it.' }
    [ordered]@{ id = 'permissions'; title = 'Engine permissions'; required = $true; why = 'The engine needs its Microsoft Graph and Azure rights for the workloads in use.' }
    [ordered]@{ id = 'mail'; title = 'Mail sender'; required = $true; why = 'TAP codes, approvals and alerts are sent by mail.' }
    [ordered]@{ id = 'departments'; title = 'Departments & owners'; required = $true; why = 'Departments sponsor access; their owners approve and receive the mail.' }
    [ordered]@{ id = 'roles'; title = 'Roles & templates'; required = $true; why = 'The roles people activate.' }
    [ordered]@{ id = 'admins'; title = 'Admin accounts'; required = $false; why = 'The separate admin accounts PIM manages.' }
    [ordered]@{ id = 'policies'; title = 'Policies'; required = $true; why = 'The activation policies (duration, MFA, justification, approval) PIM applies.' }
    [ordered]@{ id = 'alerts'; title = 'Alert recipients'; required = $true; why = 'Who receives the alerts when a guard holds something or a job fails.' }
    [ordered]@{ id = 'breakglass'; title = 'Break-glass accounts'; required = $true; why = 'The emergency accounts PIM must never touch.' }
    [ordered]@{ id = 'firstrun'; title = 'First run'; required = $true; why = 'The engine applies the configuration for the first time.' }
    [ordered]@{ id = 'activator'; title = 'Client onboarding'; required = $false; why = 'The browser extension admins activate with.' }
)

# The findings PIM reports (stable ids). area / severity are Invardia's closed lists (framework 8.7).
$script:PimSetupFindings = @(
    [ordered]@{ id = 'job-failing'; title = 'A scheduled job is failing'; severity = 'error'; area = 'config'; productDefect = $true
        why = 'A job whose latest run failed does not do its work (engine changes, discovery, reports ...).'
        fix = 'Open Jobs, read the failing run''s detail and fix the cause; Run now proves it.' }
    [ordered]@{ id = 'update-failing'; title = 'The last update run failed'; severity = 'error'; area = 'update'; productDefect = $true
        why = 'The environment keeps running its current version but does not receive what its ring approved.'
        fix = 'Open Jobs > Updates for the failing step; the run is retried nightly.' }
    [ordered]@{ id = 'engine-permission-denied'; title = 'The engine was refused a permission'; severity = 'error'; area = 'permissions'
        why = 'Microsoft Graph or Azure refused the engine identity; those changes are not deployed.'
        fix = 'Grant the missing permission to the engine identity (Home > Permissions); a new grant can take ~30 minutes to apply.' }
    [ordered]@{ id = 'azure-not-visible'; title = 'Discovery cannot see Azure'; severity = 'warning'; area = 'permissions'
        why = 'The engine was refused the management-group / subscription list, so Azure is not discovered.'
        fix = 'Grant the engine identity Reader at the tenant root management group.' }
)

$script:PimSetupStateSetting = 'UplinkSetupState'
$script:PimSetupPermissionSnapshotSetting = 'PermissionSnapshot'

# ---------------------------------------------------------------------------------------------------------------------
# PURE helpers
# ---------------------------------------------------------------------------------------------------------------------
function Test-PimUplinkSetupExtended {
    <# PURE. PIM_UPLINK_SETUP_EXTENDED (off by default): 1 / true / yes / on adds PIM's own ids (steps, findings, extras). #>
    param([AllowNull()][string]$Value = $env:PIM_UPLINK_SETUP_EXTENDED)
    return ("$Value".Trim().ToLowerInvariant() -in @('1', 'true', 'yes', 'on'))
}

function Get-PimSetupControlCatalog {
    <# PURE. The declared controls: the framework minimum, plus PIM's extras with -Extended. #>
    param([switch]$Extended)
    $l = @($script:PimSetupControlsMinimum)
    if ($Extended) { $l += @($script:PimSetupControlsExtended) }
    return $l
}

function Get-PimSetupField {
    # PURE. A property of a PSCustomObject or a dictionary, $null when absent.
    param([AllowNull()][object]$Object, [string]$Name)
    if ($null -eq $Object) { return $null }
    if ($Object -is [System.Collections.IDictionary]) { if ($Object.Contains($Name)) { return $Object[$Name] }; return $null }
    $p = $Object.PSObject.Properties[$Name]; if ($p) { return $p.Value }
    return $null
}

function ConvertTo-PimSetupUtc {
    # PURE. A time (text / [datetime] / [datetimeoffset]) -> UTC [datetime], or $null.
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [datetime]) { return $Value.ToUniversalTime() }
    if ($Value -is [datetimeoffset]) { return $Value.UtcDateTime }
    $s = "$Value".Trim(); if (-not $s) { return $null }
    try { return ([datetime]::Parse($s, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AdjustToUniversal -bor [Globalization.DateTimeStyles]::AssumeUniversal)) } catch { return $null }
}

function Resolve-PimUplinkRing {
    <#
      PURE. The update ring every heartbeat / run / setup report carries (framework 8.4 field 'Ring', New-AitUplinkReport -Ring).
      $env:PIM_UPDATE_RING is set on the UPDATE job only -- the uplink runs in the tick job, where it is empty -- so the
      environment's own record wins next: pim.Settings['UpdateState'] (configuredRing = what the last deployment set,
      then ring = what the last update run used). 'ring2' / 'Ring 2' / '2' are one ring. 0..3, else $null.
    #>
    param([AllowNull()][string]$EnvRing, [AllowNull()][object]$UpdateState)
    $cands = @("$EnvRing", "$(Get-PimSetupField $UpdateState 'configuredRing')", "$(Get-PimSetupField $UpdateState 'ring')")
    foreach ($c in $cands) {
        $n = ("$c".Trim() -replace '^(?i)ring[\s_-]*', '')
        $r = 0
        if ($n -and [int]::TryParse($n, [ref]$r) -and $r -ge 0 -and $r -le 3) { return $r }
    }
    return $null
}

function Resolve-PimSetupInstallKey {
    <#
      The Invardia install key, for the uplink-key control. Resolve-PimInvardiaInstallKey (PIM-InvardiaUpdate.ps1) when it is
      loaded (the scheduler); else the same rule here, because the Manager does not load the update library: the secret
      PIM_UPLINK_KEY wins, then the claimed key in pim.Settings['InvardiaInstallKey'] (shape inv-...). '' = none.
    #>
    param([scriptblock]$GetSetting)
    if (Get-Command Resolve-PimInvardiaInstallKey -ErrorAction SilentlyContinue) { return "$(Resolve-PimInvardiaInstallKey -GetSetting $GetSetting)" }
    $k = "$env:PIM_UPLINK_KEY".Trim()
    if ($k) { return $k }
    if ($GetSetting) { try { $k = "$(& $GetSetting 'InvardiaInstallKey')".Trim() } catch { $k = '' } }
    if ($k -match '^inv-[A-Za-z0-9_-]{20,100}$') { return $k }
    return ''
}

function New-PimPermissionSnapshot {
    <#
      PURE. The compact permission record the Manager stores (pim.Settings 'PermissionSnapshot') each time it really checks
      the engine identity (Get-PimManagerPermissionHealthBody) -- the job that sends the setup report cannot read another
      identity's grants itself. expected = the MANDATORY Graph permissions, missing = those not held (an altRole satisfies),
      extra = granted Graph roles PIM does not name at all. missingIds = permission values only (never a name of a person).
    #>
    param([string[]]$Granted = @(), [object[]]$Required = @(), [bool]$Readable = $true, [AllowNull()][object]$RootReader, [datetime]$NowUtc = [datetime]::UtcNow)
    $have = @{}; foreach ($g in @($Granted)) { if ("$g".Trim()) { $have["$g".Trim()] = $true } }
    $named = @{}
    $mand = @($Required | Where-Object { $_ -and "$($_.tier)" -ne 'optional' })
    foreach ($r in @($Required)) { if ("$($r.role)".Trim()) { $named["$($r.role)".Trim()] = $true }; if ("$($r.altRole)".Trim()) { $named["$($r.altRole)".Trim()] = $true } }
    $miss = @($mand | Where-Object { -not ($have.ContainsKey("$($_.role)".Trim()) -or ("$($_.altRole)".Trim() -and $have.ContainsKey("$($_.altRole)".Trim()))) } |
              ForEach-Object { "$($_.role)".Trim() } | Where-Object { $_ } | Sort-Object -Unique)
    $extra = @($have.Keys | Where-Object { -not $named.ContainsKey($_) })
    $rr = $null; if ($RootReader -is [bool]) { $rr = [bool]$RootReader }
    return [ordered]@{ checkedUtc = $NowUtc.ToUniversalTime().ToString('o'); readable = [bool]$Readable
        expected = $(if ($Readable) { $mand.Count } else { 0 }); missing = $(if ($Readable) { $miss.Count } else { 0 }); extra = $(if ($Readable) { $extra.Count } else { 0 })
        missingIds = $(if ($Readable) { @($miss) } else { @() }); rootReader = $rr }
}

function Get-PimSetupRunGroups {
    # PURE. The newest finished run per job TYPE (uplink excluded): @{ '<type>' = run }.
    param([object[]]$Runs = @())
    $by = @{}
    foreach ($r in @($Runs | Where-Object { $_ })) {
        $t = "$($r.type)".Trim().ToLowerInvariant(); if (-not $t) { $t = "$($r.name)".Trim().ToLowerInvariant() }
        if (-not $t -or $t -eq 'uplink') { continue }
        $fin = ConvertTo-PimSetupUtc $r.finishedUtc; if (-not $fin) { continue }
        if (-not $by.ContainsKey($t) -or $fin -gt $by[$t].fin) { $by[$t] = @{ run = $r; fin = $fin } }
    }
    return $by
}

function Test-PimSetupRunOk {
    # PURE. A finished run that did its work (completed / ok), not failed / held / skipped.
    param([AllowNull()][object]$Run)
    $st = "$($Run.status)".Trim().ToLowerInvariant()
    if ($st -in @('failed', 'running', 'skipped', 'unimplemented', 'held', 'interrupted', 'disabled', 'outofscope', '')) { return $false }
    if ($Run.PSObject.Properties['ok'] -and -not [bool]$Run.ok) { return $false }
    return $true
}

function Get-PimSetupControlStates {
    <#
      PURE. EVERY declared control, evaluated from -Facts (Get-PimSetupFacts). Returns @( [ordered]@{ id; state; value } ),
      state ok | missing | wrong | unknown; value only for the enum controls and only one of their declared values.
      A fact that could not be read is 'unknown' -- never 'ok', never left out.
    #>
    param([Parameter(Mandatory)][object]$Facts, [switch]$Extended)
    $now = if ($Facts.NowUtc) { ([datetime]$Facts.NowUtc).ToUniversalTime() } else { [datetime]::UtcNow }
    $out = New-Object System.Collections.Generic.List[object]
    $add = { param($id, $state, $value) $o = [ordered]@{ id = $id; state = $state }; if ($null -ne $value -and "$value" -ne '') { $o['value'] = "$value" }; [void]$out.Add($o) }
    $us = $Facts.UpdateState; $storeOk = [bool]$Facts.StoreReadable
    $runs = Get-PimSetupRunGroups -Runs @($Facts.Runs)

    # updater-deployed: the deployment records itself in UpdateState (kind 'deploy'), every update run replaces it (kind 'run').
    if ($us) { & $add 'updater-deployed' 'ok' $null } elseif ($storeOk) { & $add 'updater-deployed' 'missing' $null } else { & $add 'updater-deployed' 'unknown' $null }

    # updater-schedule: the nightly run reported within 48 h = enabled; a record older than that = disabled (wrong).
    if (-not $us) { if ($storeOk) { & $add 'updater-schedule' 'missing' $null } else { & $add 'updater-schedule' 'unknown' $null } }
    else {
        $last = ConvertTo-PimSetupUtc (Get-PimSetupField $us 'tsUtc')
        $deployed = ConvertTo-PimSetupUtc (Get-PimSetupField $us 'configuredUtc'); if (-not $deployed) { $deployed = ConvertTo-PimSetupUtc (Get-PimSetupField $us 'recordedUtc') }
        if ($last -and ($now - $last).TotalHours -le 48) { & $add 'updater-schedule' 'ok' 'enabled' }
        elseif ($last) { & $add 'updater-schedule' 'wrong' 'disabled' }
        elseif ($deployed -and ($now - $deployed).TotalHours -le 48) { & $add 'updater-schedule' 'unknown' $null }   # installed, first nightly run not due yet
        else { & $add 'updater-schedule' 'wrong' 'disabled' }
    }

    # update-ring (+ value 1|2|3; ring 0 = dev, reported ok without a value -- '0' is not in Invardia's list)
    $ring = Resolve-PimUplinkRing -EnvRing "$($Facts.EnvRing)" -UpdateState $us
    if ($null -ne $ring) { & $add 'update-ring' 'ok' $(if ($ring -ge 1) { "$ring" } else { $null }) }
    elseif ($us -or $storeOk) { & $add 'update-ring' 'missing' $null } else { & $add 'update-ring' 'unknown' $null }

    # uplink-key
    if ([bool]$Facts.KeyPresent) { & $add 'uplink-key' 'ok' $null } else { & $add 'uplink-key' 'missing' $null }

    # licence-valid: Valid / Grace for THIS tenant = ok (grace shows yellow through the heartbeat's licence state);
    # Expired, or a licence for another tenant = wrong; none = missing.
    $ls = "$(Get-PimSetupField $Facts.License 'Status')"
    if ($null -eq $Facts.License) { & $add 'licence-valid' 'missing' $null }
    elseif ($ls -in @('Valid', 'Grace')) { & $add 'licence-valid' $(if ([bool]$Facts.ProHere) { 'ok' } else { 'wrong' }) $null }
    elseif ($ls -eq 'Expired' -or $ls -eq 'Invalid') { & $add 'licence-valid' 'wrong' $null }
    else { & $add 'licence-valid' 'missing' $null }

    # mail-sender: the Get Started verdict (Get-PimMailSetupState) -- done = ok, a failed test mail = wrong, none = missing.
    $ms = $Facts.Mail
    if ($null -eq $ms) { & $add 'mail-sender' 'unknown' $null }
    elseif ((Get-PimSetupField $ms 'proven') -eq $false) { & $add 'mail-sender' 'wrong' $null }
    elseif ([bool](Get-PimSetupField $ms 'done')) { & $add 'mail-sender' 'ok' $null }
    else { & $add 'mail-sender' 'missing' $null }

    # alert-recipients
    if ($null -eq $Facts.AlertRecipients) { & $add 'alert-recipients' 'unknown' $null }
    elseif (@($Facts.AlertRecipients | Where-Object { "$_".Trim() }).Count) { & $add 'alert-recipients' 'ok' $null }
    else { & $add 'alert-recipients' 'missing' $null }

    # identity-permissions: the Manager's last real check (<= 7 days old), else unknown.
    $ps = $Facts.Permissions; $psAt = ConvertTo-PimSetupUtc (Get-PimSetupField $ps 'checkedUtc')
    $psFresh = ($ps -and $psAt -and ($now - $psAt).TotalDays -le 7 -and [bool](Get-PimSetupField $ps 'readable'))
    if (-not $psFresh) { & $add 'identity-permissions' 'unknown' $null }
    elseif ([int](Get-PimSetupField $ps 'missing') -gt 0) { & $add 'identity-permissions' 'missing' $null }
    else { & $add 'identity-permissions' 'ok' $null }

    # last-run-24h: the engine jobs (engine-* / queue-apply); without any of them in the history, any job.
    $eng = @($runs.Keys | Where-Object { $_ -match '^engine' -or $_ -eq 'queue-apply' })
    if (-not $eng.Count) { $eng = @($runs.Keys) }
    if (-not $eng.Count) { & $add 'last-run-24h' $(if ($storeOk) { 'missing' } else { 'unknown' }) $null }
    else {
        # the newest SUCCESSFUL run of those jobs, from every run (the per-type newest may have failed)
        $okRuns = @($Facts.Runs | Where-Object { $_ -and (Test-PimSetupRunOk $_) } | Where-Object {
                    $t = "$($_.type)".Trim().ToLowerInvariant(); if (-not $t) { $t = "$($_.name)".Trim().ToLowerInvariant() }; $eng -contains $t } |
                  ForEach-Object { ConvertTo-PimSetupUtc $_.finishedUtc } | Where-Object { $_ } | Sort-Object -Descending)
        if ($okRuns.Count -and ($now - $okRuns[0]).TotalHours -le 24) { & $add 'last-run-24h' 'ok' $null } else { & $add 'last-run-24h' 'wrong' $null }
    }

    # backup-configured: the daily config-backup job ran OK within 48 h.
    if (-not $runs.ContainsKey('config-backup')) { & $add 'backup-configured' $(if ($storeOk) { 'missing' } else { 'unknown' }) $null }
    else {
        $b = $runs['config-backup']
        if ((Test-PimSetupRunOk $b.run) -and ($now - $b.fin).TotalHours -le 48) { & $add 'backup-configured' 'ok' $null } else { & $add 'backup-configured' 'wrong' $null }
    }

    # update-pinned (+ value no|yes): PIM_UPDATE_HOLD=1 on the updater, recorded in UpdateState.hold.
    $hold = ("$($Facts.EnvHold)".Trim() -eq '1') -or [bool](Get-PimSetupField $us 'hold')
    if ($hold) { & $add 'update-pinned' 'ok' 'yes' } elseif ($us) { & $add 'update-pinned' 'ok' 'no' } else { & $add 'update-pinned' 'unknown' $null }

    if ($Extended) {
        $rr = Get-PimSetupField $ps 'rootReader'
        if (-not $psFresh -or -not ($rr -is [bool])) { & $add 'tenant-root-reader' 'unknown' $null } elseif ($rr) { & $add 'tenant-root-reader' 'ok' $null } else { & $add 'tenant-root-reader' 'missing' $null }
        $gs = @(Get-PimSetupField $Facts.GetStarted 'steps')
        $stepOf = { param($id) @($gs | Where-Object { $_ -and "$($_.id)" -eq $id }) | Select-Object -First 1 }
        $bg = & $stepOf 'breakglass'
        if (-not $bg) { & $add 'breakglass-protected' 'unknown' $null } elseif ([bool]$bg.done) { & $add 'breakglass-protected' 'ok' $null } else { & $add 'breakglass-protected' 'missing' $null }
        $ac = & $stepOf 'activator'
        if (-not $ac) { & $add 'activator-apps' 'unknown' $null } elseif ([bool]$ac.done) { & $add 'activator-apps' 'ok' $null } else { & $add 'activator-apps' 'missing' $null }
        if ("$($Facts.MspRole)" -ne 'Slave') { & $add 'managing-link' 'ok' $null }
        elseif ($null -eq $Facts.DownlinkOn) { & $add 'managing-link' 'unknown' $null }
        elseif ([bool]$Facts.DownlinkOn) { & $add 'managing-link' 'ok' $null } else { & $add 'managing-link' 'missing' $null }
    }
    return @($out.ToArray())
}

function Get-PimSetupStepStates {
    <#
      PURE. The recorded Get Started status (pim.Settings 'GetStartedStatus', written by the page) -> @( [ordered]@{ step;
      required; state; reasonClass } ). done -> done, a skipped required step -> skipped, a step whose control is WRONG
      (mail -> mail-sender, licence -> licence-valid, firstrun -> last-run-24h) -> failing, else open. Unknown ids dropped.
    #>
    param([AllowNull()][object]$Status, [object[]]$Controls = @())
    $known = @{}; foreach ($s in $script:PimSetupSteps) { $known[$s.id] = $s }
    $ctl = @{}; foreach ($c in @($Controls)) { if ($c) { $ctl["$($c.id)"] = "$($c.state)" } }
    $failOn = @{ mail = 'mail-sender'; licence = 'licence-valid'; firstrun = 'last-run-24h'; permissions = 'identity-permissions' }
    $steps = @()
    if (Get-Command ConvertTo-PimGetStartedStatus -ErrorAction SilentlyContinue) { $steps = @((ConvertTo-PimGetStartedStatus $Status).steps) }
    else { $steps = @(Get-PimSetupField $Status 'steps') }
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($s in @($steps | Where-Object { $_ })) {
        $id = "$($s.id)".Trim().ToLowerInvariant()
        if (-not $known.ContainsKey($id)) { continue }
        $req = [bool]$known[$id].required
        $done = ("$($s.done)".Trim().ToLowerInvariant() -in @('true', '1'))
        $def = ("$($s.deferred)".Trim().ToLowerInvariant() -in @('true', '1'))
        $state = 'open'; $rc = $null
        if ($done) { $state = 'done' }
        elseif ($def) { $state = 'skipped'; $rc = 'skipped-for-now' }
        elseif ($failOn.ContainsKey($id) -and $ctl[$failOn[$id]] -eq 'wrong') { $state = 'failing'; $rc = "control-$($failOn[$id])" }
        $o = [ordered]@{ step = $id; required = $req; state = $state }
        if ($rc) { $o['reasonClass'] = $rc }
        [void]$out.Add($o)
    }
    return @($out.ToArray())
}

function Get-PimSetupFindingStates {
    <# PURE. The findings present now: @( [ordered]@{ id; severity; area; count } ). An absent finding is not listed. #>
    param([Parameter(Mandatory)][object]$Facts)
    $def = @{}; foreach ($f in $script:PimSetupFindings) { $def[$f.id] = $f }
    $out = New-Object System.Collections.Generic.List[object]
    $add = { param($id, $n) if ($n -gt 0) { [void]$out.Add([ordered]@{ id = $id; severity = $def[$id].severity; area = $def[$id].area; count = [int]$n }) } }
    $groups = Get-PimSetupRunGroups -Runs @($Facts.Runs)
    & $add 'job-failing' @($groups.Values | Where-Object { "$($_.run.status)".Trim().ToLowerInvariant() -eq 'failed' -or ($_.run.PSObject.Properties['ok'] -and -not [bool]$_.run.ok -and "$($_.run.status)" -notin @('skipped', 'running', 'held', 'interrupted', 'unimplemented')) }).Count
    $us = $Facts.UpdateState
    & $add 'update-failing' $(if ($us -and "$(Get-PimSetupField $us 'outcome')" -eq 'failed') { 1 } else { 0 })
    $fails = @($Facts.EngineFailures | Where-Object { $_ })
    & $add 'engine-permission-denied' @($fails | Where-Object { "$($_.code)" -eq 'PERMISSION-DENIED' }).Count
    & $add 'azure-not-visible' @($fails | Where-Object { "$($_.code)" -eq 'AZURE-NOT-VISIBLE' }).Count
    return @($out.ToArray())
}

function Update-PimSetupSince {
    <#
      PURE. Adds sinceUtc to every item (when it ENTERED its current state) from the previous map, and returns the new map.
      -Items: @( @{ key; state; item } ). -Previous: @{ '<key>' = @{ state; sinceUtc } } (PSCustomObject or dictionary).
    #>
    param([object[]]$Items = @(), [AllowNull()][object]$Previous, [datetime]$NowUtc = [datetime]::UtcNow)
    $prev = @{}
    if ($Previous -is [System.Collections.IDictionary]) { foreach ($k in $Previous.Keys) { $prev["$k"] = $Previous[$k] } }
    elseif ($Previous) { foreach ($p in $Previous.PSObject.Properties) { $prev[$p.Name] = $p.Value } }
    $map = [ordered]@{}
    foreach ($i in @($Items)) {
        $p = $prev["$($i.key)"]; $since = $NowUtc.ToUniversalTime().ToString('o')
        if ($p -and "$(Get-PimSetupField $p 'state')" -eq "$($i.state)") { $t = ConvertTo-PimSetupUtc (Get-PimSetupField $p 'sinceUtc'); if ($t) { $since = $t.ToString('o') } }
        $i.item['sinceUtc'] = ([datetime]$since).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        $map["$($i.key)"] = [ordered]@{ state = "$($i.state)"; sinceUtc = $since }
    }
    return $map
}

function New-PimSetupReport {
    <#
      PURE. The Kind=setup record (framework 8.7) in the shape Invardia's validateUplinkReport accepts: top-level Schema, Kind,
      Product, Version, Ring, Edition, LastSeenUtc, GetStarted, Findings, Permissions, MissingIds, Controls -- NOTHING else
      (no tenant, no host, no install id: the key proves the environment). Every declared control on every report; ids not
      in the declared lists are dropped; value only on an enum control and only one of its values.
      Returns @{ record; fingerprint; since } -- fingerprint = the states without times (a change = send now).
    #>
    param([Parameter(Mandatory)][object]$Facts, [string]$Product = 'pim-manager', [string]$Version = '', [AllowNull()][object]$Ring,
          [string]$Edition = '', [switch]$Extended, [AllowNull()][object]$PreviousSince, [datetime]$NowUtc = [datetime]::UtcNow)
    $cat = Get-PimSetupControlCatalog -Extended:$Extended
    $byId = @{}; foreach ($c in $cat) { $byId[$c.id] = $c }
    $controls = New-Object System.Collections.Generic.List[object]
    $got = @{}; foreach ($c in @(Get-PimSetupControlStates -Facts $Facts -Extended:$Extended)) { $got["$($c.id)"] = $c }
    foreach ($c in $cat) {   # EVERY declared control, in the declared order; one the evaluation missed = unknown (never omitted)
        $e = $got[$c.id]
        $o = [ordered]@{ id = $c.id; state = $(if ($e -and "$($e.state)" -in @('ok', 'missing', 'wrong', 'unknown')) { "$($e.state)" } else { 'unknown' }) }
        if ($e -and $e.Contains('value') -and $c.Contains('enum') -and (@($c.enum) -contains "$($e.value)")) { $o['value'] = "$($e.value)" }
        [void]$controls.Add($o)
    }
    $steps = @(); $findings = @()
    if ($Extended) {
        $steps = @(Get-PimSetupStepStates -Status $Facts.GetStarted -Controls @($controls.ToArray()))
        $fdef = @{}; foreach ($f in $script:PimSetupFindings) { $fdef[$f.id] = $true }
        $findings = @(Get-PimSetupFindingStates -Facts $Facts | Where-Object { $fdef.ContainsKey("$($_.id)") })
    }
    $items = @()
    foreach ($c in $controls) { $items += @{ key = "c:$($c.id)"; state = "$($c.state)|$($c['value'])"; item = $c } }
    foreach ($s in $steps) { $items += @{ key = "s:$($s.step)"; state = "$($s.state)"; item = $s } }
    foreach ($f in $findings) { $items += @{ key = "f:$($f.id)"; state = "$($f.severity)"; item = $f } }
    $since = Update-PimSetupSince -Items $items -Previous $PreviousSince -NowUtc $NowUtc
    if ($Extended) { foreach ($s in $steps) { if (-not $s.Contains('reasonClass')) { $s['reasonClass'] = $null } } }

    $o = [ordered]@{ Schema = 2; Kind = 'setup'; Product = "$Product".Trim().ToLowerInvariant() }
    $ver = "$Version".Trim(); if ($ver -match '^[0-9A-Za-z.+-]{1,50}$') { $o['Version'] = $ver }
    $rp = 0; if ($null -ne $Ring -and "$Ring" -ne '' -and [int]::TryParse("$Ring", [ref]$rp) -and $rp -ge 0 -and $rp -le 10) { $o['Ring'] = $rp }
    $ed = "$Edition".Trim().ToLowerInvariant(); if ($ed -in @('community', 'pro', 'trial')) { $o['Edition'] = $ed }
    if ($Extended) { $o['GetStarted'] = @($steps); $o['Findings'] = @($findings) }
    $ps = $Facts.Permissions; $psAt = ConvertTo-PimSetupUtc (Get-PimSetupField $ps 'checkedUtc')
    $nowU = $NowUtc.ToUniversalTime()
    $permOut = $null
    if ($ps -and $psAt -and ($nowU - $psAt).TotalDays -le 7 -and [bool](Get-PimSetupField $ps 'readable')) {
        $nat = { param($v) $n = 0; if ([int]::TryParse("$v", [ref]$n) -and $n -ge 0 -and $n -le 10000) { $n } else { 0 } }
        $permOut = [ordered]@{ expected = (& $nat (Get-PimSetupField $ps 'expected')); missing = (& $nat (Get-PimSetupField $ps 'missing')); extra = (& $nat (Get-PimSetupField $ps 'extra')) }
        $o['Permissions'] = $permOut
        $o['MissingIds'] = @(@(Get-PimSetupField $ps 'missingIds') | ForEach-Object { "$_".Trim() } | Where-Object { $_ -match '^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$' } | Select-Object -Unique -First 200)
    }
    $o['Controls'] = @($controls.ToArray())
    $o['LastSeenUtc'] = $nowU.ToString('yyyy-MM-ddTHH:mm:ssZ')
    # the fingerprint: states, values, counts -- no times (a time alone never makes a report due)
    $fp = (@($controls | ForEach-Object { "c:$($_.id)=$($_.state)/$($_['value'])" }) + @($steps | ForEach-Object { "s:$($_.step)=$($_.state)" }) +
           @($findings | ForEach-Object { "f:$($_.id)=$($_.severity)/$($_.count)" }) + @("p:$(if ($permOut) { "$($permOut.expected)/$($permOut.missing)/$($permOut.extra)" })")) -join ';'
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { $fph = ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($fp)))).Replace('-', '').Substring(0, 16).ToLowerInvariant() } finally { $sha.Dispose() }
    return [pscustomobject]@{ record = [pscustomobject]$o; fingerprint = $fph; since = $since }
}

function Get-PimSetupReportDue {
    <# PURE. Daily, and on every change of state (a different fingerprint). #>
    param([AllowNull()][object]$State, [string]$Fingerprint, [datetime]$NowUtc = [datetime]::UtcNow)
    $last = ConvertTo-PimSetupUtc (Get-PimSetupField $State 'lastSentUtc')
    if (-not $last) { return $true }
    if ("$(Get-PimSetupField $State 'fingerprint')" -ne "$Fingerprint") { return $true }
    return (($NowUtc.ToUniversalTime() - $last).TotalHours -ge 24)
}

# ---------------------------------------------------------------------------------------------------------------------
# The facts (one reader, every read through -GetSetting; a read that throws = unknown, never ok)
# ---------------------------------------------------------------------------------------------------------------------
function Get-PimSetupFacts {
    param([Parameter(Mandatory)][scriptblock]$GetSetting, [object[]]$Runs = @(), [AllowNull()][object]$License, [bool]$ProHere = $false,
          [string]$InstallKey = '', [AllowNull()][string]$EnvRing = $env:PIM_UPDATE_RING, [AllowNull()][string]$EnvHold = $env:PIM_UPDATE_HOLD,
          [AllowNull()][string]$MspRole = '', [AllowNull()][object]$DownlinkOn = $null, [datetime]$NowUtc = [datetime]::UtcNow)
    $readOk = $true
    $rd = {
        param($n)
        try {
            $v = & $GetSetting $n
            for ($i = 0; $i -lt 2 -and $v -is [string]; $i++) { $t = "$v".Trim(); if ($t.StartsWith('{') -or $t.StartsWith('[')) { try { $v = $t | ConvertFrom-Json } catch { break } } else { break } }
            return $v
        } catch { $script:PimSetupReadFailed = $true; return $null }
    }
    $script:PimSetupReadFailed = $false
    $us = & $rd 'UpdateState'
    $alert = & $rd 'Alerting'
    $recips = $null
    if (-not $script:PimSetupReadFailed) { $recips = @(@(Get-PimSetupField $alert 'recipients') | Where-Object { "$_".Trim() }) }
    $readOk = -not $script:PimSetupReadFailed
    $mail = $null
    try {
        $mode = & $rd 'MailMode'; $sender = & $rd 'MailSender'; $relay = & $rd 'SmtpRelay'; $lt = & $rd 'MailLastTest'
        if (Get-Command Get-PimMailSetupState -ErrorAction SilentlyContinue) { $mail = Get-PimMailSetupState -Mode "$mode" -Sender "$sender" -SmtpRelay $relay -LastTest $lt }
        else { $mail = @{ done = [bool]("$sender".Trim()); proven = $(if ($lt -and "$(Get-PimSetupField $lt 'ok')" -eq 'False') { $false } else { $null }) } }
    } catch { $mail = $null }
    $fails = @(& $rd 'EngineItemFailures')
    $perm = & $rd $script:PimSetupPermissionSnapshotSetting
    $gs = & $rd 'GetStartedStatus'
    $readOk = $readOk -and -not $script:PimSetupReadFailed
    return [pscustomobject]@{
        NowUtc = $NowUtc.ToUniversalTime(); StoreReadable = $readOk; UpdateState = $us; EnvRing = "$EnvRing"; EnvHold = "$EnvHold"
        KeyPresent = [bool]("$InstallKey".Trim()); License = $License; ProHere = $ProHere; Mail = $mail; AlertRecipients = $recips
        Permissions = $perm; Runs = @($Runs); GetStarted = $gs
        EngineFailures = @($fails | Where-Object { $_ }); MspRole = "$MspRole"; DownlinkOn = $DownlinkOn
    }
}
