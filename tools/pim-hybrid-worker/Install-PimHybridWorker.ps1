#Requires -Version 5.1
<#
.SYNOPSIS
    §80.2 PIMHYBRIDWRK -- configure the worker VM itself. Run ON the worker, elevated (Azure run-command runs it as SYSTEM).

.DESCRIPTION
    SELF-CONTAINED on purpose: it runs before any PIM code is on the machine, so it carries the little it needs.

    -Phase Join       Offline domain join from the blob Initialize-PimHybridWorkerAd.ps1 -ProvisionOdj printed, then reboot.
                      The blob file is deleted before the join returns; nothing else keeps it.
    -Phase Configure  (after the reboot) RSAT-AD PowerShell; PowerShell 7 (MSI signature checked); the gMSA installed and
                      TESTED -- a worker that cannot use its gMSA fails HERE, not at 03:00; "log on as a batch job" for the
                      gMSA only; C:\PIM locked down (only SYSTEM / Administrators write the code the gMSA runs -- the default
                      C:\ ACL lets any signed-in user modify files below it, which on a Tier-0 box is an escalation path);
                      the PIM code for this environment's RING fetched with the VM's managed identity (no SAS, no PAT);
                      two scheduled tasks:
                         'PIM Hybrid Worker'        every 5 min, AS THE gMSA: Start-PimScheduler -Instance hybrid
                                                    -Jobs hybrid-ad-apply,hybrid-ad-groups,hybrid-ad-sync -UseManagedIdentity
                         'PIM Hybrid Servers'       (with -ServerGmsaName) every 5 min AS THE SERVER gMSA: -Instance
                                                    hybridsrv -Jobs hybrid-ad-servers -- the tier split: server local
                                                    admins are never written by the Tier-0 identity
                         'PIM Hybrid Worker Update' daily, as SYSTEM: this script -Phase Update
    -Phase Update     Read channel.json, fetch the version the ring approves when it differs, switch C:\PIM\app\current.
                      Never moves without a ring answer; never moves backwards.

    Identity model: AD writes = the gMSA (the scheduled task's run-as account; PIM-HybridAd.ps1 verifies it and refuses
    SYSTEM). SQL + Graph + the source store = the VM's managed identity. No password, secret or certificate is stored.

.EXAMPLE
    .\Install-PimHybridWorker.ps1 -Phase Join -OdjBlob <base64>
    .\Install-PimHybridWorker.ps1 -Phase Configure -GmsaName 'CORP\gmsa-pimhw' -SqlServer <server>.database.windows.net `
        -SqlDatabase PimPlatform -TenantId <tenant> -SourceContainerUrl https://<store>.blob.core.windows.net/pim-src -Ring 1
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('Join', 'Configure', 'Update', 'Layout')][string]$Phase,
    [string]$OdjBlob,
    [string]$GmsaName,
    # 2.4.467 tier split (operator 2026-09-30): server onboarding runs as its OWN gMSA (DOMAIN\gMSA-PIM-L2-T1), in its own
    # task 'PIM Hybrid Servers'; blank = the main gMSA also onboards servers (the pre-2.4.467 layout)
    [string]$ServerGmsaName = '',
    [string]$SqlServer,
    [string]$SqlDatabase = 'PimPlatform',
    [string]$TenantId,
    [string]$SourceContainerUrl,
    [string]$Ring = '',
    [string]$Version = '',
    [string]$AdServer = '',
    [string]$Root = 'C:\PIM',
    [int]$IntervalMinutes = 5,
    [switch]$NoReboot,
    # Every tick runs -WhatIf: the jobs PLAN and log (<Root>\logs) and change nothing in AD. Re-run -Phase Configure without it to go live.
    [switch]$PlanOnly
)
$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
function Step($m) { Write-Output "[worker] $m" }
$cfgPath = Join-Path $Root 'bin\worker.json'
# This script's own text, taken NOW: run through Azure run-command the file on disk is a temporary copy (and is deleted below).
$selfText = $MyInvocation.MyCommand.ScriptBlock.ToString()

# ------------------------------------------------------------------ Join
if ($Phase -eq 'Join') {
    if ((Get-CimInstance Win32_ComputerSystem).PartOfDomain) { Step "already joined to $((Get-CimInstance Win32_ComputerSystem).Domain) -- nothing to do"; return }
    if (-not "$OdjBlob".Trim()) { throw '-OdjBlob is required for -Phase Join' }
    $f = Join-Path $env:TEMP ("odj-{0}.txt" -f ([guid]::NewGuid().ToString('N')))
    try {
        $b = $OdjBlob.Trim()
        if ($b.StartsWith('gz:')) {       # Initialize-PimHybridWorkerAd.ps1 compresses it (run-command output is 4 KB)
            $in = New-Object IO.MemoryStream(, [Convert]::FromBase64String($b.Substring(3)))
            $gz = New-Object IO.Compression.GZipStream($in, [IO.Compression.CompressionMode]::Decompress)
            $out = New-Object IO.MemoryStream; $gz.CopyTo($out); $gz.Close()
            [IO.File]::WriteAllBytes($f, $out.ToArray())
        } else { [IO.File]::WriteAllBytes($f, [Convert]::FromBase64String($b)) }
        $out = & djoin.exe /requestODJ /loadfile $f /windowspath $env:SystemRoot /localos 2>&1
        if ($LASTEXITCODE -ne 0) { throw "djoin /requestODJ failed ($LASTEXITCODE): $($out -join ' ')" }
    } finally { if (Test-Path $f) { Remove-Item -LiteralPath $f -Force } }
    Step 'offline domain join staged -- rebooting to complete it'
    if (-not $NoReboot) { & shutdown.exe /r /t 15 /c 'PIM hybrid worker: completing the domain join' | Out-Null }
    return
}

# ------------------------------------------------------------------ shared: config, MI token, fetch
if ($Phase -eq 'Configure') {
    foreach ($p in 'GmsaName', 'SqlServer', 'TenantId', 'SourceContainerUrl') { if (-not "$((Get-Variable $p -ValueOnly))".Trim()) { throw "-$p is required for -Phase Configure" } }
    if (-not "$Ring".Trim() -and -not "$Version".Trim()) { throw '-Ring (the update ring this environment follows) or -Version is required' }
    if ($GmsaName -notmatch '^[^\\]+\\[^\\]+$') { throw "-GmsaName must be DOMAIN\name (got '$GmsaName')" }
    if ("$ServerGmsaName".Trim() -and $ServerGmsaName -notmatch '^[^\\]+\\[^\\]+$') { throw "-ServerGmsaName must be DOMAIN\name (got '$ServerGmsaName')" }
    if ("$ServerGmsaName".Trim() -and $ServerGmsaName.TrimEnd('$') -ieq $GmsaName.TrimEnd('$')) { throw '-ServerGmsaName must differ from -GmsaName (server onboarding is a separate tier)' }
    $cfg = [ordered]@{ gmsa = $GmsaName.TrimEnd('$'); serverGmsa = "$ServerGmsaName".Trim().TrimEnd('$'); sqlServer = $SqlServer; sqlDatabase = $SqlDatabase; tenantId = $TenantId
        source = $SourceContainerUrl.TrimEnd('/'); ring = "$Ring".Trim(); version = "$Version".Trim(); adServer = $AdServer; intervalMinutes = $IntervalMinutes; syncPauseSeconds = 5; planOnly = [bool]$PlanOnly }
} else {
    if (-not (Test-Path $cfgPath)) { throw "no $cfgPath -- run -Phase Configure first" }
    $cfg = Get-Content -LiteralPath $cfgPath -Raw | ConvertFrom-Json
}

function Get-MiToken([string]$Resource) {
    $r = Invoke-RestMethod -Headers @{ Metadata = 'true' } -Uri "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=$([uri]::EscapeDataString($Resource))" -TimeoutSec 30
    if (-not "$($r.access_token)") { throw "IMDS returned no token for $Resource -- does the VM have a system-assigned identity?" }
    return $r.access_token
}
function Get-Blob([string]$Name, [string]$OutFile) {
    $h = @{ Authorization = "Bearer $(Get-MiToken 'https://storage.azure.com/')"; 'x-ms-version' = '2021-08-06' }
    Invoke-WebRequest -Uri "$($cfg.source)/$Name" -Headers $h -OutFile $OutFile -UseBasicParsing -TimeoutSec 300
}
function Resolve-TargetVersion {
    if ("$($cfg.version)".Trim()) { return @{ version = "$($cfg.version)".Trim(); reason = 'pinned by -Version' } }
    $tmp = Join-Path $env:TEMP 'pim-channel.json'
    try { Get-Blob -Name 'channel.json' -OutFile $tmp; $ch = Get-Content -LiteralPath $tmp -Raw | ConvertFrom-Json } finally { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
    $r = "$($cfg.ring)".Trim(); if ($r -notmatch '^(?i)ring') { $r = "ring$r" }
    $e = $ch.PSObject.Properties | Where-Object { $_.Name -ieq $r } | Select-Object -First 1
    if (-not $e -or -not "$($e.Value.version)".Trim()) { return @{ version = ''; reason = "the channel approves nothing for '$r'" } }
    return @{ version = "$($e.Value.version)".Trim(); reason = "$r approves $($e.Value.version)" }
}
function Test-HybridCapable {
    # Does the installed PIM version carry the hybrid worker (§80.2)? Its scheduler must accept -Instance and -UseManagedIdentity;
    # an older version would fail every 5 minutes on "parameter not found". Read from the script's AST, nothing is run.
    $s = Join-Path $Root 'app\current\SOLUTIONS\PIM4EntraPS\tools\pim-scheduler\Start-PimScheduler.ps1'
    if (-not (Test-Path $s)) { return $false }
    $tk = $null; $er = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($s, [ref]$tk, [ref]$er)
    $names = @($ast.ParamBlock.Parameters | ForEach-Object { $_.Name.VariablePath.UserPath })
    return (($names -contains 'Instance') -and ($names -contains 'UseManagedIdentity') -and ($names -contains 'ContinuousJob'))
}
function Sync-WorkerTaskState {
    foreach ($n in 'PIM Hybrid Worker', 'PIM Hybrid AD Sync', 'PIM Hybrid AD Sync Servers', 'PIM Hybrid AD Changes', 'PIM Hybrid Servers') {
        $t = Get-ScheduledTask -TaskName $n -ErrorAction SilentlyContinue
        if (-not $t) { continue }
        if (Test-HybridCapable) { if ($t.State -eq 'Disabled') { Enable-ScheduledTask -TaskName $n | Out-Null; Step "'$n' ENABLED -- $(Get-CurrentVersion) carries the hybrid worker" } }
        else { if ($t.State -ne 'Disabled') { Disable-ScheduledTask -TaskName $n | Out-Null }; Step "'$n' stays DISABLED -- PIM $(Get-CurrentVersion) predates the hybrid worker (no Start-PimScheduler -Instance / -ContinuousJob); the daily update enables it when the ring approves a version that has it" }
    }
}
function Get-CurrentVersion {
    $cur = Join-Path $Root 'app\current'
    if (-not (Test-Path $cur)) { return '' }
    $t = (Get-Item $cur).Target; if ($t -is [array]) { $t = $t[0] }
    return (Split-Path "$t" -Leaf)
}
function Install-Version([string]$V) {
    if ($V -notmatch '^\d+\.\d+\.\d+$') { throw "refusing version '$V' (not N.N.N)" }
    $dest = Join-Path $Root "app\$V"
    $start = Join-Path $dest 'SOLUTIONS\PIM4EntraPS\tools\pim-scheduler\Start-PimScheduler.ps1'
    if (-not (Test-Path $start)) {
        $arc = Join-Path $env:TEMP "pim-src-$V.tar.gz"
        Get-Blob -Name "pim-src-$V.tar.gz" -OutFile $arc
        $b = [IO.File]::ReadAllBytes($arc)
        if ($b.Length -lt 1024 -or $b[0] -ne 0x1f -or $b[1] -ne 0x8b) { Remove-Item $arc -Force; throw "pim-src-$V.tar.gz is not a gzip archive ($($b.Length) bytes) -- refusing" }
        New-Item -ItemType Directory -Force $dest | Out-Null
        & tar.exe -xzf $arc -C $dest
        $rc = $LASTEXITCODE; Remove-Item $arc -Force
        if ($rc -ne 0 -or -not (Test-Path $start)) { Remove-Item -LiteralPath $dest -Recurse -Force -ErrorAction SilentlyContinue; throw "pim-src-$V.tar.gz did not extract to a PIM tree (tar rc $rc)" }
    }
    $cur = Join-Path $Root 'app\current'
    if (Test-Path $cur) { (Get-Item $cur).Delete() }
    & cmd.exe /c mklink /J "$cur" "$dest" | Out-Null
    if (-not (Test-Path $start.Replace($dest, $cur))) { throw "junction $cur -> $dest did not resolve" }
    # keep the new version and the one before it
    Get-ChildItem (Join-Path $Root 'app') -Directory | Where-Object { $_.Name -match '^\d+\.\d+\.\d+$' } |
        Sort-Object { [version]$_.Name } -Descending | Select-Object -Skip 2 | ForEach-Object { Remove-Item -LiteralPath $_.FullName -Recurse -Force }
    Step "PIM $V is current ($dest)"
}


# ------------------------------------------------------------------ the worker's LAYOUT: run wrapper + scheduled tasks
# One function, used by -Phase Configure, -Phase Layout and (through the NEW version's -Phase Layout) -Phase Update, so a
# worker always runs the task layout of the version it runs -- before 2.4.495 the nightly update swapped the code only and
# a new task (a new lane) never reached an installed worker.
# 2026-10-04 lanes (operator: "if a customer has 10000 servers + 65 critical ad groups, then it takes 1-2 hours to come to
# the critical groups" / "in case of emergency then can gain access within 20-30 sec at max"): THREE continuous processes,
# each its own task, log and liveness stamp, none waiting on another:
#   -Mode Sync         'PIM Hybrid AD Sync'           critical (non-server) groups, a pass every 5 s
#   -Mode SyncServers  'PIM Hybrid AD Sync Servers'   the per-server groups, parallel batches
#   -Mode Changes      'PIM Hybrid AD Changes'        AD accounts + AD groups the moment their definitions change
# -Mode Tick = the 5-minute scheduler (hybrid-ad-apply + hybrid-ad-groups as the SAFETY NET); -Mode Servers = onboarding.
function Register-WorkerLayout {
$run = @'
param([ValidateSet('Tick', 'Sync', 'SyncServers', 'Changes', 'Servers')][string]$Mode = 'Tick')
$ErrorActionPreference = 'Stop'
$root = Split-Path (Split-Path $MyInvocation.MyCommand.Path -Parent) -Parent
$cfg = Get-Content -LiteralPath (Join-Path $root 'bin\worker.json') -Raw | ConvertFrom-Json
$split = [bool]"$($cfg.serverGmsa)".Trim()
$log = Join-Path $root ("logs\{0}-{1:yyyyMMdd}.log" -f $(switch ($Mode) { 'Sync' { 'sync' } 'SyncServers' { 'sync-servers' } 'Changes' { 'changes' } 'Servers' { 'servers' } default { 'worker' } }), (Get-Date))
Get-ChildItem (Join-Path $root 'logs') -Filter '*.log' | Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-14) } | Remove-Item -Force -ErrorAction SilentlyContinue
$env:PIM_HybridAdCredentialMode = 'gMSA'
# the gMSA THIS task runs as -- PIM-HybridAd.ps1 refuses any other process identity
$env:PIM_HybridAdGmsaName = $(if ($Mode -eq 'Servers') { $cfg.serverGmsa } else { $cfg.gmsa })
if ("$($cfg.adServer)".Trim()) { $global:PIM_HybridAdServer = $cfg.adServer }
$common = @{ Instance = $(if ($Mode -eq 'Servers') { 'hybridsrv' } else { 'hybrid' }); SqlServer = $cfg.sqlServer; SqlDatabase = $cfg.sqlDatabase; TenantId = $cfg.tenantId; StorageBackend = 'sql'; UseManagedIdentity = $true; WhatIf = [bool]$cfg.planOnly }
$start = Join-Path $root 'app\current\SOLUTIONS\PIM4EntraPS\tools\pim-scheduler\Start-PimScheduler.ps1'
$pause = [int]$(if ($cfg.syncPauseSeconds) { $cfg.syncPauseSeconds } else { 5 })
Start-Transcript -LiteralPath $log -Append | Out-Null
try {
    switch ($Mode) {
        'Sync'        { & $start @common -Jobs 'hybrid-ad-sync' -ContinuousJob 'hybrid-ad-sync' -ContinuousPauseSeconds $pause }
        'SyncServers' { & $start @common -Jobs 'hybrid-ad-sync-servers' -ContinuousJob 'hybrid-ad-sync-servers' -ContinuousPauseSeconds $pause }
        'Changes'     { & $start @common -Jobs 'hybrid-ad-changes,hybrid-ad-apply,hybrid-ad-groups' -ContinuousJob 'hybrid-ad-changes' -ContinuousPauseSeconds $pause }
        'Servers'     { & $start @common -Once -Jobs 'hybrid-ad-servers' }
        default       { if ($split) { & $start @common -Once -Jobs 'hybrid-ad-apply,hybrid-ad-groups' } else { & $start @common -Once -Jobs 'hybrid-ad-apply,hybrid-ad-groups,hybrid-ad-servers' } }
    }
} finally { Stop-Transcript | Out-Null }
'@
Set-Content -LiteralPath (Join-Path $Root 'bin\Run-PimHybridWorker.ps1') -Value $run -Encoding UTF8

Step 'scheduled tasks'
$pwshExe = Join-Path $env:ProgramFiles 'PowerShell\7\pwsh.exe'
$exe = if (Test-Path $pwshExe) { $pwshExe } else { "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" }
$aRun = New-ScheduledTaskAction -Execute $exe -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$Root\bin\Run-PimHybridWorker.ps1`""
$tRun = New-ScheduledTaskTrigger -Once -At ((Get-Date).AddMinutes(1)) -RepetitionInterval (New-TimeSpan -Minutes $cfg.intervalMinutes)
$pRun = New-ScheduledTaskPrincipal -UserId "$($cfg.gmsa)`$" -LogonType Password -RunLevel Limited
$sRun = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Minutes 50) -StartWhenAvailable
Register-ScheduledTask -TaskName 'PIM Hybrid Worker' -Action $aRun -Trigger $tRun -Principal $pRun -Settings $sRun -Force | Out-Null
# the continuous lanes: each started at boot and re-checked EVERY MINUTE (IgnoreNew = a running loop is left alone), so a
# loop that stopped (crash, hang killed by the watchdog, a new version installed) is back within a minute; no time limit.
$sSync = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -ExecutionTimeLimit ([TimeSpan]::Zero) -StartWhenAvailable -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
foreach ($lane in @(@('PIM Hybrid AD Sync', 'Sync'), @('PIM Hybrid AD Sync Servers', 'SyncServers'), @('PIM Hybrid AD Changes', 'Changes'))) {
    $a = New-ScheduledTaskAction -Execute $exe -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$Root\bin\Run-PimHybridWorker.ps1`" -Mode $($lane[1])"
    $tr = @((New-ScheduledTaskTrigger -AtStartup), (New-ScheduledTaskTrigger -Once -At ((Get-Date).AddMinutes(1)) -RepetitionInterval (New-TimeSpan -Minutes 1)))
    Register-ScheduledTask -TaskName $lane[0] -Action $a -Trigger $tr -Principal $pRun -Settings $sSync -Force | Out-Null
}
# server onboarding AS ITS OWN gMSA (tier split): the scheduler instance 'hybridsrv' runs only hybrid-ad-servers
if ("$($cfg.serverGmsa)".Trim()) {
    $aSrv = New-ScheduledTaskAction -Execute $exe -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$Root\bin\Run-PimHybridWorker.ps1`" -Mode Servers"
    $tSrv = New-ScheduledTaskTrigger -Once -At ((Get-Date).AddMinutes(2)) -RepetitionInterval (New-TimeSpan -Minutes $cfg.intervalMinutes)
    $pSrv = New-ScheduledTaskPrincipal -UserId "$($cfg.serverGmsa)`$" -LogonType Password -RunLevel Limited
    Register-ScheduledTask -TaskName 'PIM Hybrid Servers' -Action $aSrv -Trigger $tSrv -Principal $pSrv -Settings $sRun -Force | Out-Null
} elseif (Get-ScheduledTask -TaskName 'PIM Hybrid Servers' -ErrorAction SilentlyContinue) { Unregister-ScheduledTask -TaskName 'PIM Hybrid Servers' -Confirm:$false }
$aUpd = New-ScheduledTaskAction -Execute $exe -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$Root\bin\Install-PimHybridWorker.ps1`" -Phase Update"
$tUpd = New-ScheduledTaskTrigger -Daily -At '04:30'
$pUpd = New-ScheduledTaskPrincipal -UserId 'NT AUTHORITY\SYSTEM' -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName 'PIM Hybrid Worker Update' -Action $aUpd -Trigger $tUpd -Principal $pUpd -Settings (New-ScheduledTaskSettingsSet -StartWhenAvailable) -Force | Out-Null
Sync-WorkerTaskState
# The changes lane and the server lane start at once (their 1-minute trigger would too); the running critical loop restarts
# on its own when the installed version changes.
foreach ($n in 'PIM Hybrid AD Sync Servers', 'PIM Hybrid AD Changes') { $tk = Get-ScheduledTask -TaskName $n -ErrorAction SilentlyContinue; if ($tk -and $tk.State -eq 'Ready') { Start-ScheduledTask -TaskName $n } }
Step ("done: 'PIM Hybrid Worker' every {0} min (safety net) + 'PIM Hybrid AD Sync' / 'PIM Hybrid AD Sync Servers' / 'PIM Hybrid AD Changes' continuously, as {1}`$; logs in {2}\logs{3}" -f $cfg.intervalMinutes, $cfg.gmsa, $Root, $(if ($cfg.planOnly) { ' -- PLAN ONLY (-WhatIf): nothing is written to AD until Configure is re-run without -PlanOnly' } else { '' }))
}

# Run the CURRENT version's -Phase Layout (its run wrapper + tasks), and keep its installer in bin for the next update. A
# version older than the layout phase is left alone (its own installer could not do it).
function Invoke-CurrentLayout {
    $inst = Join-Path $Root 'app\current\SOLUTIONS\PIM4EntraPS\tools\pim-hybrid-worker\Install-PimHybridWorker.ps1'
    if (-not (Test-Path $inst)) { Step 'layout: the current version carries no installer -- tasks left as they are'; return }
    if ((Get-Content -LiteralPath $inst -Raw) -notmatch "'Layout'") { Step 'layout: the current version predates -Phase Layout -- tasks left as they are'; return }
    $px = Join-Path $env:ProgramFiles 'PowerShell\7\pwsh.exe'; if (-not (Test-Path $px)) { $px = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" }
    Step 'layout: applying the current version''s run wrapper + tasks'
    & $px -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $inst -Phase Layout -Root $Root
    if ($LASTEXITCODE -ne 0) { Step "layout: FAILED (exit $LASTEXITCODE) -- the previous tasks stay" }
}
function Test-WorkerLayoutCurrent {
    foreach ($n in 'PIM Hybrid AD Sync Servers', 'PIM Hybrid AD Changes') { if (-not (Get-ScheduledTask -TaskName $n -ErrorAction SilentlyContinue)) { return $false } }
    return $true
}

# ------------------------------------------------------------------ Layout (run by Update with the NEW version's installer)
if ($Phase -eq 'Layout') {
    Register-WorkerLayout
    Set-Content -LiteralPath (Join-Path $Root 'bin\Install-PimHybridWorker.ps1') -Value $selfText -Encoding UTF8   # the daily updater runs this copy
    return
}

# ------------------------------------------------------------------ Update
if ($Phase -eq 'Update') {
    $t = Resolve-TargetVersion; $c = Get-CurrentVersion
    Step "ring: $($t.reason); running: $(if ($c) { $c } else { 'none' })"
    if (-not $t.version) { Step 'no approved version -- nothing moves'; return }
    if ($c -and ([version]$t.version -lt [version]$c)) { Step "the ring approves $($t.version), older than the running $c -- NOT rolling back unattended"; return }
    if ($t.version -eq $c) { Step 'up to date'; if (-not (Test-WorkerLayoutCurrent)) { Invoke-CurrentLayout }; Sync-WorkerTaskState; return }
    Install-Version -V $t.version
    Invoke-CurrentLayout
    Sync-WorkerTaskState
    return
}

# ------------------------------------------------------------------ Configure
if (-not (Get-CimInstance Win32_ComputerSystem).PartOfDomain) { throw 'this machine is not domain-joined -- run -Phase Join first' }
# The join blob carried the machine's INITIAL password, and Azure run-command leaves the script it ran (blob included) on
# disk. Rotate the machine password now -- the blob is worthless from here -- and delete those downloaded scripts.
# (Reset-ComputerMachinePassword needs RESET rights on the computer object; a machine may only CHANGE its own password,
# which is what netlogon does here.)
$dnsDomain = (Get-CimInstance Win32_ComputerSystem).Domain
$nl = & nltest.exe "/sc_change_pwd:$dnsDomain" 2>&1
if ($LASTEXITCODE -eq 0) { Step 'machine password changed (the join blob is worthless now)' }
else { Write-Warning "machine password change failed ($LASTEXITCODE): $($nl -join ' ') -- it changes by itself within 30 days; the blob stays valid until then" }
Get-ChildItem 'C:\Packages\Plugins\Microsoft.CPlat.Core.RunCommandWindows' -Recurse -Filter 'script*.ps1' -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
Step 'RSAT: ActiveDirectory PowerShell module'
if (-not (Get-WindowsFeature RSAT-AD-PowerShell).Installed) { Install-WindowsFeature RSAT-AD-PowerShell | Out-Null }
Import-Module ActiveDirectory

$pwsh = Join-Path $env:ProgramFiles 'PowerShell\7\pwsh.exe'
if (-not (Test-Path $pwsh)) {
    Step 'PowerShell 7 (latest stable MSI from the official release; Authenticode checked before install)'
    $rel = Invoke-RestMethod 'https://api.github.com/repos/PowerShell/PowerShell/releases/latest' -Headers @{ 'User-Agent' = 'pim-hybrid-worker' }
    $asset = $rel.assets | Where-Object { $_.name -match '^PowerShell-[\d.]+-win-x64\.msi$' } | Select-Object -First 1
    if (-not $asset) { throw 'no win-x64 MSI in the latest PowerShell release' }
    $msi = Join-Path $env:TEMP $asset.name
    Invoke-WebRequest $asset.browser_download_url -OutFile $msi -UseBasicParsing
    $sig = Get-AuthenticodeSignature $msi
    if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation') { Remove-Item $msi -Force; throw "PowerShell MSI signature not valid/Microsoft ($($sig.Status)) -- refusing" }
    $p = Start-Process msiexec.exe -ArgumentList "/i `"$msi`" /qn /norestart ADD_PATH=1 ENABLE_PSREMOTING=0 REGISTER_MANIFEST=1" -Wait -PassThru
    Remove-Item $msi -Force
    if ($p.ExitCode -ne 0 -and $p.ExitCode -ne 3010) { throw "PowerShell MSI failed ($($p.ExitCode))" }
}

& klist.exe -li 0x3e7 purge | Out-Null        # the computer's group membership (the PrincipalsAllowedAccess groups) is read at ticket time
$sids = @()
foreach ($g in @($cfg.gmsa, $cfg.serverGmsa) | Where-Object { "$_".Trim() }) {
    Step "gMSA $g`$"
    $sam = ($g -split '\\')[1]
    Install-ADServiceAccount -Identity $sam
    if (-not (Test-ADServiceAccount -Identity $sam)) { throw "Test-ADServiceAccount $sam = FALSE -- is this computer in $sam-PrincipalsAllowedAccess? (reboot after adding it)" }
    $sids += (New-Object System.Security.Principal.NTAccount("$g`$")).Translate([System.Security.Principal.SecurityIdentifier]).Value
}

Step 'log on as a batch job: the worker gMSA(s) only (appended to the existing holders)'
$inf = Join-Path $env:TEMP 'pim-secpol.inf'; $db = Join-Path $env:TEMP 'pim-secpol.sdb'
& secedit.exe /export /cfg $inf /areas USER_RIGHTS | Out-Null
$lines = Get-Content $inf
foreach ($sid in $sids) {
    $ix = [array]::FindIndex([string[]]$lines, [Predicate[string]] { param($l) $l -match '^SeBatchLogonRight\s*=' })
    if ($ix -ge 0) { if ($lines[$ix] -notmatch [regex]::Escape("*$sid")) { $lines[$ix] = $lines[$ix].TrimEnd() + ",*$sid" } }
    else { $at = [array]::IndexOf([string[]]$lines, '[Privilege Rights]'); $lines = $lines[0..$at] + "SeBatchLogonRight = *$sid" + $lines[($at + 1)..($lines.Count - 1)] }
}
Set-Content -LiteralPath $inf -Value $lines -Encoding Unicode
& secedit.exe /configure /db $db /cfg $inf /areas USER_RIGHTS | Out-Null
Remove-Item $inf, $db -Force -ErrorAction SilentlyContinue

Step "$Root locked down"
foreach ($d in 'app', 'bin', 'logs') { New-Item -ItemType Directory -Force (Join-Path $Root $d) | Out-Null }
& icacls.exe $Root /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' @($sids | ForEach-Object { "*$($_):(OI)(CI)RX" }) | Out-Null
& icacls.exe (Join-Path $Root 'logs') /grant:r @($sids | ForEach-Object { "*$($_):(OI)(CI)M" }) | Out-Null
$cfg | ConvertTo-Json | Set-Content -LiteralPath $cfgPath -Encoding UTF8
Set-Content -LiteralPath (Join-Path $Root 'bin\Install-PimHybridWorker.ps1') -Value $selfText -Encoding UTF8   # the daily updater runs this copy

Step 'PIM code for this ring'
$t = Resolve-TargetVersion
if (-not $t.version) { throw "cannot install: $($t.reason)" }
Install-Version -V $t.version

Register-WorkerLayout