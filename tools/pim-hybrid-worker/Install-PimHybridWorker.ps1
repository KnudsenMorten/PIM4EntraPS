#Requires -Version 5.1

<#
.SYNOPSIS
    §80.2 PIMHYBRIDWRK -- configure the worker machine itself: an Azure VM, or (§100.63(b)) the customer's own on-premises
    Windows server that is Azure Arc-enabled. Run ON the worker, elevated (run-command runs it as SYSTEM on both).

.DESCRIPTION
    Installs and configures the PIM for Active Directory hybrid worker on the worker machine itself (an Azure VM or an
    Azure Arc-enabled on-premises server): the gMSAs, the PIM code for its update ring and the scheduled tasks.

    SELF-CONTAINED on purpose: it runs before any PIM code is on the machine, so it carries the little it needs. No
    gallery module; the in-box Windows ScheduledTasks and CimCmdlets modules are used (owner 2026-10-10: in-box Windows
    modules approved for the hybrid worker).
    Deliver it with Invoke-PimHybridWorkerRunCommand.ps1 (run-command, nothing inbound) or run it locally, elevated.

    -HostType         Auto (default) | AzureVm | Arc. Auto = Arc when the Connected Machine agent (himds) is present.
                      AzureVm: the identity comes from IMDS (169.254.169.254). Arc: from the Arc agent on localhost:40342,
                      a 401 challenge answered by reading a key file only local Administrators and the local group
                      'Hybrid agent extension applications' may read -- Configure puts each worker gMSA into that group.
    -Phase Join       (Azure VM) Offline domain join from the blob Initialize-PimHybridWorkerAd.ps1 -ProvisionOdj printed,
                      then reboot. The blob file is deleted before the join returns; nothing else keeps it. An Arc server
                      is the customer's own, already domain-joined: no Join phase.
    -Phase Configure  (after the reboot) PowerShell 7 (MSI downloaded from github.com, signature checked); the gMSA
                      installed and TESTED -- a worker that cannot use its gMSA fails HERE, not at 03:00; "log on as a batch
                      job" for the gMSA only; C:\PIM locked down (only SYSTEM / Administrators write the code the gMSA runs
                      -- the default C:\ ACL lets any signed-in user modify files below it, which on a Tier-0 box is an
                      escalation path); the PIM code for this environment's RING fetched with the machine's managed
                      identity (no SAS, no PAT); then the six scheduled tasks below (-Phase Layout).
    -Phase Update     Read channel.json, fetch the version the ring approves when it differs, switch C:\PIM\app\current,
                      apply the NEW version's -Phase Layout. Never moves without a ring answer; never moves backwards.
    -Phase Layout     The run wrapper (C:\PIM\bin\Run-PimHybridWorker.ps1) + the scheduled tasks of THIS version.

    The scheduled tasks (each runs Start-PimScheduler -UseManagedIdentity as the account named):
       'PIM Hybrid Worker'           every 5 min AS THE gMSA, instance hybrid: hybrid-ad-apply + hybrid-ad-groups (the
                                     safety net), + hybrid-ad-servers when no -ServerGmsaName is given
       'PIM Hybrid AD Sync'          continuous AS THE gMSA (at boot + re-checked every minute, no time limit):
                                     hybrid-ad-sync, the CRITICAL (non-server) groups, a pass every 5 s
       'PIM Hybrid AD Sync Servers'  continuous AS THE gMSA: hybrid-ad-sync-servers, the per-server groups
       'PIM Hybrid AD Changes'       continuous AS THE gMSA: hybrid-ad-changes (+ apply + groups the moment a definition
                                     changes)
       'PIM Hybrid Servers'          (only with -ServerGmsaName) every 5 min AS THE SERVER gMSA, instance hybridsrv:
                                     hybrid-ad-servers -- the tier split: server local admins are never written by Tier 0
       'PIM Hybrid Worker Update'    daily 04:30 as SYSTEM: this script -Phase Update

    Identity model: AD writes = the gMSA (the scheduled task's run-as account; PIM-HybridAd.ps1 verifies it and refuses
    SYSTEM). SQL + Graph + the source store = the machine's managed identity (VM: IMDS; Arc: the Arc agent). No password,
    secret or certificate is stored.

.EXAMPLE
    .\Install-PimHybridWorker.ps1 -Phase Join -OdjBlob <base64>
    .\Install-PimHybridWorker.ps1 -Phase Configure -GmsaName 'CORP\gmsa-pimhw' -SqlServer <server>.database.windows.net `
        -SqlDatabase PimPlatform -TenantId <tenant> -SourceContainerUrl https://<store>.blob.core.windows.net/pim-src -Ring 1
    # an Azure Arc-enabled on-premises server (already domain-joined): no Join phase
    .\Install-PimHybridWorker.ps1 -Phase Configure -HostType Arc -GmsaName 'CORP\gMSA-PIM-L1-T0' -ServerGmsaName 'CORP\gMSA-PIM-L2-T1' `
        -SqlServer <server>.database.windows.net -TenantId <tenant> -SourceContainerUrl https://<store>.blob.core.windows.net/pim-src -Ring 2

.LINK
    https://invardia.com/docs/pim/scripts/Install-PimHybridWorker/
#>
[CmdletBinding(SupportsShouldProcess)]
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
    [switch]$PlanOnly,
    # §100.63(b): where the managed identity comes from. Auto = Arc when the Connected Machine agent (himds) is installed.
    [ValidateSet('Auto', 'AzureVm', 'Arc')][string]$HostType = 'Auto'
)
$ErrorActionPreference = 'Stop'

# 12.7 run frame: "<Script> version <x.y.z> - documentation: <page>" as the first line + a transcript in the temp folder.
. (Join-Path $PSScriptRoot '..\setup\_PimScriptDoc.ps1')
$null = Start-PimScriptRun -Script 'Install-PimHybridWorker'
try {

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
function Step($m) { Write-Output "[worker] $m" }
$cfgPath = Join-Path $Root 'bin\worker.json'
# This script's own text, taken NOW: run through Azure run-command the file on disk is a temporary copy (and is deleted below).
$selfText = $MyInvocation.MyCommand.ScriptBlock.ToString()
# The local group the Arc agent lets read its token key files (besides local Administrators). Created by the agent install.
$ArcKeyReaderGroup = 'Hybrid agent extension applications'

# ------------------------------------------------------------------ domain-join state
function Get-PimJoinState {
    $cs = Get-CimInstance Win32_ComputerSystem
    return [pscustomobject]@{ joined = [bool]$cs.PartOfDomain; domain = "$($cs.Domain)" }
}
function Resolve-PimHostType([string]$Requested) {
    if ($Requested -and $Requested -ne 'Auto') { return $Requested }
    if ("$env:IDENTITY_ENDPOINT".Trim() -and "$env:IMDS_ENDPOINT".Trim() -and -not "$env:IDENTITY_HEADER".Trim()) { return 'Arc' }
    if (Get-Service -Name 'himds' -ErrorAction SilentlyContinue) { return 'Arc' }
    return 'AzureVm'
}
function Get-PimSelfContainedText([string]$Text) {
    # The daily updater runs bin\Install-PimHybridWorker.ps1 ALONE: when this copy dot-sources the 12.7 run-frame helper
    # (the package / source tree), the helper is inlined into the copy. The published standalone and the run-command
    # wrapper carry it inlined already.
    $m = [regex]::Match($Text, "(?m)^\. \(Join-Path \`$PSScriptRoot '\.\.\\setup\\_PimScriptDoc\.ps1'\)[ \t]*\r?$")
    if (-not $m.Success) { return $Text }
    $h = if ("$PSScriptRoot".Trim()) { Join-Path $PSScriptRoot '..\setup\_PimScriptDoc.ps1' } else { '' }
    if (-not $h -or -not (Test-Path -LiteralPath $h)) { throw "cannot make the installer self-contained: _PimScriptDoc.ps1 not found next to it ($h)" }
    return ($Text.Substring(0, $m.Index) + [IO.File]::ReadAllText($h) + $Text.Substring($m.Index + $m.Length))
}

# ------------------------------------------------------------------ -WhatIf: the plan, nothing changed
if ($WhatIfPreference) {
    $ht = Resolve-PimHostType $HostType
    Step "PLAN (-WhatIf) -- nothing is changed: -Phase $Phase on this $(if ($ht -eq 'Arc') { 'Azure Arc-enabled server' } else { 'Azure VM' }) ($ht)"
    switch ($Phase) {
        'Join'      { Step $(if ($ht -eq 'Arc') { 'would REFUSE: an Arc server is joined by its owner (no offline-join blob)' } else { 'would load the offline domain-join blob (djoin /requestODJ), delete it, and reboot' }) }
        'Configure' {
            Step "would install PowerShell 7 (github.com, Microsoft signature checked), install + TEST gMSA $GmsaName$(if ("$ServerGmsaName".Trim()) { " and $ServerGmsaName" })"
            if ($ht -eq 'Arc') { Step "would add the gMSA(s) to the local group '$ArcKeyReaderGroup' and check that the Arc identity answers" } else { Step 'would rotate the machine password (the offline-join blob becomes worthless)' }
            Step "would grant 'log on as a batch job' to the gMSA(s) only, lock $Root down, fetch the PIM code for ring '$Ring'$(if ("$Version".Trim()) { " / version $Version" }) from $SourceContainerUrl with the machine identity"
            Step "would register: 'PIM Hybrid Worker' (every $IntervalMinutes min), 'PIM Hybrid AD Sync', 'PIM Hybrid AD Sync Servers', 'PIM Hybrid AD Changes' (continuous)$(if ("$ServerGmsaName".Trim()) { ", 'PIM Hybrid Servers'" }), 'PIM Hybrid Worker Update' (daily 04:30)$(if ($PlanOnly) { ' -- every run PLAN ONLY' })"
        }
        'Update'    { Step 'would read channel.json for the ring and move C:\PIM\app\current to the approved version (never backwards), then apply its layout' }
        'Layout'    { Step 'would write the run wrapper and re-register the scheduled tasks of this version' }
    }
    Step 'preview only (-WhatIf) -- nothing was changed'
    return
}

# ------------------------------------------------------------------ Join
if ($Phase -eq 'Join') {
    $js = Get-PimJoinState
    if ($js.joined) { Step "already joined to $($js.domain) -- nothing to do"; return }
    if ((Resolve-PimHostType $HostType) -eq 'Arc') { throw 'this is an Azure Arc-enabled server: join it to the domain the way you join any server (the offline-join blob is for the Azure VM worker)' }
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
        source = $SourceContainerUrl.TrimEnd('/'); ring = "$Ring".Trim(); version = "$Version".Trim(); adServer = $AdServer; intervalMinutes = $IntervalMinutes; syncPauseSeconds = 5; planOnly = [bool]$PlanOnly
        hostType = (Resolve-PimHostType $HostType) }
} else {
    if (-not (Test-Path $cfgPath)) { throw "no $cfgPath -- run -Phase Configure first" }
    $cfg = Get-Content -LiteralPath $cfgPath -Raw | ConvertFrom-Json
    if (-not "$($cfg.hostType)".Trim()) { $cfg | Add-Member -NotePropertyName hostType -NotePropertyValue (Resolve-PimHostType $HostType) -Force }   # a worker configured before 100.63(b)
}

# The local Arc agent: one GET that never throws on an HTTP status, no proxy (localhost must never go through one).
function Invoke-PimArcHttp([string]$Uri, [hashtable]$Headers) {
    $req = [System.Net.HttpWebRequest][System.Net.WebRequest]::Create($Uri)
    $req.Method = 'GET'; $req.Proxy = $null; $req.Timeout = 30000
    foreach ($k in $Headers.Keys) { $req.Headers[$k] = "$($Headers[$k])" }
    $resp = $null
    try { $resp = $req.GetResponse() } catch [System.Net.WebException] { $resp = $_.Exception.Response; if (-not $resp) { throw } }
    $out = $null
    try { $sr = New-Object System.IO.StreamReader($resp.GetResponseStream()); $out = [pscustomobject]@{ status = [int]$resp.StatusCode; auth = "$($resp.Headers['WWW-Authenticate'])"; body = $sr.ReadToEnd() }; $sr.Close() }
    finally { $resp.Close() }
    return $out
}
function Get-MiToken([string]$Resource) {
    if ("$($cfg.hostType)" -eq 'Arc') {
        # Azure Arc: 401 + "Basic realm=<key file>" -> read it (SYSTEM / Administrators / the Arc key-reader group may) -> retry.
        $ep = if ("$env:IDENTITY_ENDPOINT".Trim()) { "$env:IDENTITY_ENDPOINT".Trim() } else { 'http://localhost:40342/metadata/identity/oauth2/token' }
        $u = "$($ep)?resource=$([uri]::EscapeDataString($Resource))&api-version=2020-06-01"
        $r = Invoke-PimArcHttp -Uri $u -Headers @{ Metadata = 'true' }
        if ($r.status -eq 401) {
            $m = [regex]::Match($r.auth, '(?i)Basic\s+realm\s*=\s*"?([^"]+?)"?\s*$')
            if (-not $m.Success) { throw "the Arc agent answered 401 without a key-file realm ('$($r.auth)')" }
            $key = $m.Groups[1].Value
            $dir = Join-Path $env:ProgramData 'AzureConnectedMachineAgent\Tokens'
            if ($key -match '\.\.' -or $key -notmatch '(?i)\.key$' -or ([IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($key)).TrimEnd('\') -ine $dir.TrimEnd('\'))) { throw "the Arc agent named a key file outside $dir ('$key') -- refusing" }
            if ((New-Object IO.FileInfo($key)).Length -gt 4096) { throw "the Arc key file is larger than 4 KB -- refusing" }
            $r = Invoke-PimArcHttp -Uri $u -Headers @{ Metadata = 'true'; Authorization = "Basic $([IO.File]::ReadAllText($key).Trim())" }
        }
        if ($r.status -ne 200) { throw "the Arc agent answered HTTP $($r.status) for $Resource -- is the machine connected (azcmagent show)?" }
        $t = ($r.body | ConvertFrom-Json).access_token
        if (-not "$t") { throw "the Arc agent returned no token for $Resource" }
        return $t
    }
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
    Set-Content -LiteralPath (Join-Path $Root 'bin\Install-PimHybridWorker.ps1') -Value (Get-PimSelfContainedText $selfText) -Encoding UTF8   # the daily updater runs this copy
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
$join = Get-PimJoinState
if (-not $join.joined) { throw $(if ("$($cfg.hostType)" -eq 'Arc') { 'this Arc server is not domain-joined -- join it to the domain first (it is your own server; no offline-join blob)' } else { 'this machine is not domain-joined -- run -Phase Join first' }) }
Step "host: $($cfg.hostType), domain $($join.domain)"
if ("$($cfg.hostType)" -ne 'Arc') {
    # The join blob carried the machine's INITIAL password, and run-command leaves the script it ran on disk. Rotate the
    # machine password now -- the blob is worthless from here. (Reset-ComputerMachinePassword needs RESET rights on the
    # computer object; a machine may only CHANGE its own password, which is what netlogon does here.) An Arc server was
    # joined by its owner -- there is no blob, so nothing to rotate.
    $nl = & nltest.exe "/sc_change_pwd:$($join.domain)" 2>&1
    if ($LASTEXITCODE -eq 0) { Step 'machine password changed (the join blob is worthless now)' }
    else { Write-Warning "machine password change failed ($LASTEXITCODE): $($nl -join ' ') -- it changes by itself within 30 days; the blob stays valid until then" }
}
# the downloaded copies of the scripts run-command ran (action run-command v1 on a VM; managed run-command v2 on a VM and on Arc)
foreach ($rc in 'C:\Packages\Plugins\Microsoft.CPlat.Core.RunCommandWindows', 'C:\Packages\Plugins\Microsoft.CPlat.Core.RunCommandHandlerWindows') {
    Get-ChildItem $rc -Recurse -Filter '*.ps1' -ErrorAction SilentlyContinue | Where-Object { $_.Name -like 'script*.ps1' -or $_.DirectoryName -match '\\Downloads' } | Remove-Item -Force -ErrorAction SilentlyContinue
}
# REQ 100.42 (owner 2026-10-09): no ActiveDirectory module on the worker. The runtime (engine/hybrid-ad) talks LDAP through
# .NET System.DirectoryServices.Protocols, and the gMSA install + test below are logoncli.dll calls -- so RSAT-AD-PowerShell
# is no longer installed. (GroupPolicy / GPMC is needed only where Initialize-PimHybridWorkerAd creates the servers GPO.)
# Install-ADServiceAccount / Test-ADServiceAccount without the module: they are thin wrappers over the Netlogon client API
# (logoncli.dll NetAddServiceAccount / NetIsServiceAccount), called here directly through .NET P/Invoke.
function Initialize-PimMsaInterop {
    if ('PimMsaInterop' -as [type]) { return }
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class PimMsaInterop {
    [DllImport("logoncli.dll", CharSet = CharSet.Unicode)]
    public static extern int NetAddServiceAccount(string ServerName, string AccountName, string Password, int Flags);
    [DllImport("logoncli.dll", CharSet = CharSet.Unicode)]
    public static extern int NetIsServiceAccount(string ServerName, string AccountName, [MarshalAs(UnmanagedType.Bool)] out bool IsService);
}
'@
}
function Install-PimGmsaOnHost([string]$Sam) {
    # Flags 0 = a group MSA (1 would be LINK_TO_HOST_ONLY, the standalone-MSA case). Tried as given, then with the '$'.
    Initialize-PimMsaInterop
    $rc = [PimMsaInterop]::NetAddServiceAccount($null, $Sam, $null, 0)
    if ($rc -ne 0) { $rc = [PimMsaInterop]::NetAddServiceAccount($null, "$Sam`$", $null, 0) }
    if ($rc -ne 0) { throw ("NetAddServiceAccount {0} failed (NTSTATUS 0x{1:X8}) -- is this computer in {0}-PrincipalsAllowedAccess? (reboot after adding it)" -f $Sam, $rc) }
}
function Test-PimGmsaOnHost([string]$Sam) {
    Initialize-PimMsaInterop
    foreach ($n in @($Sam, "$Sam`$")) {
        $ok = $false
        $rc = [PimMsaInterop]::NetIsServiceAccount($null, $n, [ref]$ok)
        if ($rc -eq 0 -and $ok) { return $true }
    }
    return $false
}

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
    Install-PimGmsaOnHost -Sam $sam
    if (-not (Test-PimGmsaOnHost -Sam $sam)) { throw "gMSA test $sam = FALSE -- is this computer in $sam-PrincipalsAllowedAccess? (reboot after adding it). A KDS root key created less than ~10 hours ago is not usable yet either." }
    $sids += (New-Object System.Security.Principal.NTAccount("$g`$")).Translate([System.Security.Principal.SecurityIdentifier]).Value
}

if ("$($cfg.hostType)" -eq 'Arc') {
    # §100.63(b) the worker's tasks run AS the gMSAs and take SQL / Graph / blob tokens from the Arc agent, whose 401
    # challenge only local Administrators and this group can answer. The gMSAs join THIS group -- never Administrators.
    Step "Arc: the worker gMSA(s) into the local group '$ArcKeyReaderGroup' (so they may read the Arc agent's token key file)"
    $list = & net.exe localgroup "$ArcKeyReaderGroup" 2>&1
    if ($LASTEXITCODE -ne 0) { throw "local group '$ArcKeyReaderGroup' not found ($($list -join ' ')) -- is the Azure Connected Machine agent installed and connected (azcmagent show)?" }
    foreach ($g in @($cfg.gmsa, $cfg.serverGmsa) | Where-Object { "$_".Trim() }) {
        if (@($list | Where-Object { "$_".Trim() -ieq "$g`$" }).Count) { Step "  $g`$ already a member"; continue }
        $o = & net.exe localgroup "$ArcKeyReaderGroup" "$g`$" /add 2>&1
        if ($LASTEXITCODE -ne 0) { throw "could not add $g`$ to '$ArcKeyReaderGroup': $($o -join ' ')" }
        Step "  $g`$ added"
    }
    [void](Get-MiToken 'https://storage.azure.com/')
    Step 'Arc: the machine identity answers (token for the source store taken as SYSTEM)'
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
Set-Content -LiteralPath (Join-Path $Root 'bin\Install-PimHybridWorker.ps1') -Value (Get-PimSelfContainedText $selfText) -Encoding UTF8   # the daily updater runs this copy

Step 'PIM code for this ring'
$t = Resolve-TargetVersion
if (-not $t.version) { throw "cannot install: $($t.reason)" }
Install-Version -V $t.version

Register-WorkerLayout

} finally { Stop-PimScriptRun -Script 'Install-PimHybridWorker' }
