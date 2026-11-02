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
                      escalation path); the SIGNED release of this environment's RING from the Invardia update service --
                      its signature, ring and the archive's SHA-256 + size are checked before anything is unpacked, and
                      nothing is installed when a check fails (the installation's licence + install key are read from the
                      PIM database with the machine's managed identity: no SAS, no PAT); then the six scheduled tasks below
                      (-Phase Layout).
    -Phase Update     Ask for the signed release of the ring (checked the same way, by the installed version), install it
                      when it differs, switch C:\PIM\app\current, apply the NEW version's -Phase Layout. Never moves without
                      a ring answer; never moves backwards.
    -Phase Layout     The run wrapper (C:\PIM\bin\Run-PimHybridWorker.ps1) + the scheduled tasks of THIS version.
    -Phase Remove     (§100.63, Remove-PimHybridWorker.ps1 -Target Arc runs it through run-command) Unregister the six
                      tasks, take the gMSA(s) out of 'Hybrid agent extension applications' and 'log on as a batch job',
                      delete <Root>\app + <Root>\bin (the logs stay). The machine, its Arc agent, PowerShell 7 and the
                      domain membership are NOT touched. Also removes the metadata-service firewall rule below.
    -Phase MetadataAccess  (Azure VM) Re-applies only the outbound firewall rule 'PIM Hybrid Worker - metadata
                      service access': the instance metadata service (169.254.169.254, TCP 80) answers only SYSTEM
                      (the Azure VM agent and its extensions), PIM's gMSAs and the gMSA of each product registered in
                      C:\ProgramData\HybridWorkerHost\guests\<product>.json; every other account is blocked. Configure, Layout
                      and every daily Update apply it too; a product that registers or unregisters as a guest runs
                      C:\PIM\bin\Install-PimHybridWorker.ps1 -Phase MetadataAccess (as SYSTEM) right after. The step prints
                      each account with its SID and warns when one cannot be resolved. Not on an Azure Arc server (its local
                      Arc agent already limits who gets a token).

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
    SYSTEM). SQL + Graph (+ the source store with -UpdateSource Blob) = the machine's managed identity (VM: IMDS; Arc: the
    Arc agent). No password, secret or certificate is stored.

.EXAMPLE
    .\Install-PimHybridWorker.ps1 -Phase Join -OdjBlob <base64>
    .\Install-PimHybridWorker.ps1 -Phase Configure -GmsaName 'CORP\gmsa-pimhw' -SqlServer <server>.database.windows.net `
        -SqlDatabase PimPlatform -TenantId <tenant> -SourceContainerUrl https://<store>.blob.core.windows.net/pim-src -Ring 1
    # an Azure Arc-enabled on-premises server (already domain-joined): no Join phase
    .\Install-PimHybridWorker.ps1 -Phase Configure -HostType Arc -GmsaName 'CORP\gMSA-PIM-L1-T0' -ServerGmsaName 'CORP\gMSA-PIM-L2-T1' `
        -SqlServer <server>.database.windows.net -TenantId <tenant> -SourceContainerUrl https://<store>.blob.core.windows.net/pim-src -Ring 2

.NOTES
    Requirements:
      PowerShell: Windows PowerShell 5.1 (powershell.exe) -- one of PIM's three exceptions to PowerShell 7. Why: Azure
                  run-command runs it as SYSTEM in Windows PowerShell on a fresh server, before PowerShell 7 is there;
                  it installs PowerShell 7 itself, and the worker's scheduled tasks run in PowerShell 7.
      Role: local Administrator on the worker (run-command runs it as SYSTEM). No Microsoft Entra or Azure role for the
            person; the worker's machine identity reads the PIM code from the source store.
      Hosts: <store>.blob.core.windows.net (the source store), github.com / api.github.com /
             objects.githubusercontent.com (PowerShell 7, once), the machine identity endpoint on the machine itself
             (Azure VM metadata service, or the Azure Arc agent on localhost).

.LINK
    https://invardia.com/docs/pim/scripts/Install-PimHybridWorker/
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    # Guests (PIM 80.2a, framework 12.26): READ ONLY -- lists the other products registered on this host
    # MetadataAccess: re-applies only the metadata-service rule -- a guest runs it after it registers / unregisters
    [Parameter(Mandatory)][ValidateSet('Join', 'Configure', 'Update', 'Layout', 'Remove', 'Guests', 'MetadataAccess')][string]$Phase,
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
    [ValidateSet('Auto', 'AzureVm', 'Arc')][string]$HostType = 'Auto',
    # SEC-95 (SECAUDIT-1): where the worker takes its code -- the FIRST install and every daily update. Invardia (default) =
    # the signed manifest, verified by the installed version (Resolve-PimHybridWorkerUpdate.ps1) or, on a first install, by
    # this installer (Resolve-FirstInstallSignedTarget); Blob = the source container's channel.json + archive, which carry
    # NO signature -- a lab choice only. A worker configured before this setting existed counts as Invardia.
    [ValidateSet('Invardia', 'Blob')][string]$UpdateSource = 'Invardia'
)
$ErrorActionPreference = 'Stop'

# 12.7 run frame: "<Script> version <x.y.z> - documentation: <page>" as the first line + a transcript in the temp folder.
. (Join-Path $PSScriptRoot '..\setup\_PimScriptDoc.ps1')
# SEC-95: the signed-release checks -- the update-signing public keys and the manifest / archive checks the engine uses --
# for a FIRST install, which has no installed version to verify with. Inlined in every copy that runs on the worker
# (run-command, the published standalone, the daily updater's copy in bin), exactly like the run-frame helper above.
. (Join-Path $PSScriptRoot '..\..\engine\_shared\InvardiaUpdate.verify.ps1')
$null = Start-PimScriptRun -Script 'Install-PimHybridWorker'
try {

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
function Step($m) { Write-Output "[worker] $m" }
$cfgPath = Join-Path $Root 'bin\worker.json'
# This script's own text, taken NOW: run through Azure run-command the file on disk is a temporary copy (and is deleted below).
$selfText = $MyInvocation.MyCommand.ScriptBlock.ToString()
# The local group the Arc agent lets read its token key files (besides local Administrators). Created by the agent install.
$ArcKeyReaderGroup = 'Hybrid agent extension applications'
# Every scheduled task this installer registers (-Phase Remove unregisters exactly these, nothing else)
$script:PimWorkerTaskNames = @('PIM Hybrid Worker', 'PIM Hybrid AD Sync', 'PIM Hybrid AD Sync Servers', 'PIM Hybrid AD Changes', 'PIM Hybrid Servers', 'PIM Hybrid Worker Update')

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
    # The daily updater runs bin\Install-PimHybridWorker.ps1 ALONE: when this copy dot-sources its helpers -- the 12.7
    # run-frame helper and (SEC-95) the signed-release checks -- from the package / source tree, each is inlined into the
    # copy. The published standalone and the run-command wrapper carry them inlined already.
    foreach ($rel in @('..\setup\_PimScriptDoc.ps1', '..\..\engine\_shared\InvardiaUpdate.verify.ps1')) {
        $m = [regex]::Match($Text, ("(?m)^\. \(Join-Path \`$PSScriptRoot '" + [regex]::Escape($rel) + "'\)[ \t]*\r?$"))
        if (-not $m.Success) { continue }
        $h = if ("$PSScriptRoot".Trim()) { Join-Path $PSScriptRoot $rel } else { '' }
        if (-not $h -or -not (Test-Path -LiteralPath $h)) { throw "cannot make the installer self-contained: $(Split-Path $rel -Leaf) not found next to it ($h)" }
        $body = [regex]::Replace([IO.File]::ReadAllText($h), '(?m)^#Requires[^\r\n]*\r?\n', '')
        $Text = $Text.Substring(0, $m.Index) + $body + $Text.Substring($m.Index + $m.Length)
    }
    return $Text
}

# ------------------------------------------------------------------ SEC-87: who may reach the metadata service (Azure VM)
# On an Azure VM any local process can ask the instance metadata service (169.254.169.254, TCP 80) for a token of the VM's
# managed identities -- PIM's system identity and a guest's user-assigned one. ONE outbound BLOCK rule closes it for every
# account except: SYSTEM (the Azure VM agent and its extensions run as SYSTEM), PIM's own gMSAs (worker.json) and each
# registered guest's gMSA (C:\ProgramData\HybridWorkerHost\guests\*.json, its `gmsa`).
# The rule's LocalUser is a security descriptor that Windows checks against the token of the process that opens the
# connection: the rule MATCHES (blocks) when the token is granted CC. A DENY ACE per exempt SID, in canonical order before
# the one ALLOW ACE for Everyone (WD), means: a token that carries an exempt SID is denied -> the rule does not match -> the
# connection is not blocked; every other token is granted through Everyone -> blocked. (A separate ALLOW rule would not
# help: a block rule always wins over an allow rule.)
# Fail-open on doubt: if any account that must keep access cannot be resolved to a SID (or a guest file cannot be read),
# no new rule is written -- the previous rule stays only when it already names every unresolved account, otherwise it is
# taken away. Locking a guest out of its own identity is worse than leaving one host as it was before SEC-87.
# Azure Arc servers are left alone: their identity comes from the local Arc agent, whose key-file challenge already limits it.
function Get-PimImdsRuleSpec {
    [pscustomobject]@{ name = 'PIM-HybridWorker-MetadataAccess'; displayName = 'PIM Hybrid Worker - metadata service access'; group = 'PIM Hybrid Worker'
        remoteAddress = '169.254.169.254'; protocol = 'TCP'; remotePort = '80' }
}
function Resolve-PimImdsSid([string]$Name) {
    # an account name -> its SID on this host, or $null. A gMSA resolves with its '$'; the name is tried as given first.
    $n = "$Name".Trim(); if (-not $n) { return $null }
    if ($n -match '^S-1-\d+(-\d+)+$') { return $n }
    foreach ($c in @($n, $(if ($n.EndsWith('$')) { $n.TrimEnd('$') } else { "$n`$" }))) {
        try { $s = (New-Object System.Security.Principal.NTAccount($c)).Translate([System.Security.Principal.SecurityIdentifier]).Value; if ($s) { return $s } } catch { }
    }
    return $null
}
function Get-PimImdsPimGmsaNames($Cfg) {
    # every gMSA PIM's worker.json names: gmsa, serverGmsa and any later lane gMSA (a property whose name holds 'gmsa')
    $props = if ($Cfg -is [System.Collections.IDictionary]) { @($Cfg.Keys | ForEach-Object { [pscustomobject]@{ Name = "$_"; Value = $Cfg[$_] } }) } else { @($Cfg.PSObject.Properties | ForEach-Object { [pscustomobject]@{ Name = $_.Name; Value = $_.Value } }) }
    foreach ($p in $props) {
        if ($p.Name -notmatch '(?i)gmsa') { continue }
        foreach ($v in @($p.Value)) { if ("$v".Trim()) { [pscustomobject]@{ name = "$v".Trim(); source = "PIM (worker.json $($p.Name))" } } }
    }
}
function ConvertTo-PimImdsSddl([string[]]$Sids) {
    # owner LocalService (as Windows writes it), then one DENY per exempt SID, then ALLOW Everyone: "everyone except these"
    'O:LSD:' + (($Sids | ForEach-Object { "(D;;CC;;;$_)" }) -join '') + '(A;;CC;;;WD)'
}
function Get-PimImdsSddlSids([string]$Sddl) {
    # the exempt (deny) and the matched (allow) SIDs of a LocalUser string, aliases (SY, WD) resolved; $null when unreadable
    try { $sd = New-Object System.Security.AccessControl.RawSecurityDescriptor($Sddl) } catch { return $null }
    $deny = @(); $allow = @()
    foreach ($a in $sd.DiscretionaryAcl) { if ("$($a.AceQualifier)" -eq 'AccessDenied') { $deny += $a.SecurityIdentifier.Value } elseif ("$($a.AceQualifier)" -eq 'AccessAllowed') { $allow += $a.SecurityIdentifier.Value } }
    return [pscustomobject]@{ deny = @($deny | Sort-Object -Unique); allow = @($allow | Sort-Object -Unique) }
}
function Get-PimImdsRulePlan($Cfg, [string]$GuestDir = (Join-Path $env:ProgramData 'HybridWorkerHost\guests')) {
    $want = New-Object System.Collections.Generic.List[object]
    $problems = New-Object System.Collections.Generic.List[object]
    $want.Add([pscustomobject]@{ name = 'NT AUTHORITY\SYSTEM'; source = 'the Azure VM agent and its extensions'; sid = 'S-1-5-18' })
    foreach ($g in @(Get-PimImdsPimGmsaNames $Cfg)) { $want.Add([pscustomobject]@{ name = $g.name; source = $g.source; sid = '' }) }
    $gFiles = @(if ($GuestDir -and (Test-Path -LiteralPath $GuestDir)) { Get-ChildItem -LiteralPath $GuestDir -Filter '*.json' -File -ErrorAction SilentlyContinue | Sort-Object Name })
    $ignored = New-Object System.Collections.Generic.List[string]
    foreach ($gf in $gFiles) {
        # a guest is installed by SYSTEM / an administrator: a file anyone else wrote (ProgramData lets users create files)
        # neither adds an account nor changes the rule -- it is ignored and reported
        $own = Get-PimImdsGuestFileOwner $gf.FullName
        if ($own -notin @('S-1-5-18', 'S-1-5-32-544', 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')) { $ignored.Add("guests\$($gf.Name) (owner $(if ($own) { $own } else { 'unknown' }))"); continue }
        $gj = $null; try { $gj = Get-Content -LiteralPath $gf.FullName -Raw | ConvertFrom-Json } catch { }
        if (-not $gj) { $problems.Add([pscustomobject]@{ name = ''; why = "the guest file guests\$($gf.Name) cannot be read -- its account is unknown" }); continue }
        $gp = "$($gj.product)".Trim(); if (-not $gp) { $gp = $gf.BaseName }
        $gm = @(@($gj.gmsa) | Where-Object { "$_".Trim() })
        if (-not $gm.Count) { $problems.Add([pscustomobject]@{ name = ''; why = "the guest $gp (guests\$($gf.Name)) names no gMSA (field 'gmsa') -- its account is unknown" }); continue }
        foreach ($n in $gm) { $want.Add([pscustomobject]@{ name = "$n".Trim(); source = "guest $gp (guests\$($gf.Name))"; sid = '' }) }
    }
    $allowed = New-Object System.Collections.Generic.List[object]
    foreach ($w in $want) {
        $sid = if ($w.sid) { $w.sid } else { Resolve-PimImdsSid $w.name }
        if (-not $sid -or $sid -notmatch '^S-1-\d+(-\d+)+$') { $problems.Add([pscustomobject]@{ name = $w.name; why = "$($w.name) ($($w.source)) does not resolve to a SID on this host" }); continue }
        if (@($allowed | Where-Object { $_.sid -ieq $sid }).Count) { continue }
        $allowed.Add([pscustomobject]@{ name = $w.name; source = $w.source; sid = $sid })
    }
    # plain arrays (Windows PowerShell 5.1 refuses @(<generic List>) inside a hashtable literal: "Argument types do not match")
    $aArr = $allowed.ToArray(); $pArr = $problems.ToArray(); $iArr = $ignored.ToArray()
    [string[]]$sidList = @(foreach ($a in $aArr) { $a.sid })
    $sddl = ConvertTo-PimImdsSddl $sidList
    return [pscustomobject]@{ ok = ($pArr.Count -eq 0); allowed = $aArr; problems = $pArr; ignored = $iArr; sddl = $sddl }
}
function Get-PimImdsGuestFileOwner([string]$Path) {
    try { return (Get-Acl -LiteralPath $Path).GetOwner([System.Security.Principal.SecurityIdentifier]).Value } catch { return '' }
}
function Get-PimImdsRuleExisting {
    $spec = Get-PimImdsRuleSpec
    $found = @(@(Get-NetFirewallRule -Name $spec.name -ErrorAction SilentlyContinue) + @(Get-NetFirewallRule -DisplayName $spec.displayName -ErrorAction SilentlyContinue) | Where-Object { $_ })
    $seen = @{}; foreach ($r in $found) { if (-not $seen.ContainsKey("$($r.Name)")) { $seen["$($r.Name)"] = $r } }
    return @($seen.Values)
}
function Remove-PimImdsRule {
    $n = 0
    foreach ($r in @(Get-PimImdsRuleExisting)) { Remove-NetFirewallRule -Name "$($r.Name)" -ErrorAction SilentlyContinue; $n++ }
    return $n
}
function Set-PimImdsRule {
    # Configure / Update / Layout / MetadataAccess. Prints the allowed list, then applies (or, -PlanOnlyRule, only prints) it.
    param($Cfg, [string]$HostType, [string]$GuestDir = (Join-Path $env:ProgramData 'HybridWorkerHost\guests'), [switch]$PlanOnlyRule)
    $spec = Get-PimImdsRuleSpec
    if ("$HostType" -eq 'Arc') { Step "metadata service: no rule on an Azure Arc server -- its identity comes from the local Arc agent (localhost:40342), whose key-file challenge already limits who gets a token"; return }
    $plan = Get-PimImdsRulePlan -Cfg $Cfg -GuestDir $GuestDir
    Step "metadata service ($($spec.remoteAddress) TCP $($spec.remotePort)): only these accounts may reach it --"
    foreach ($a in $plan.allowed) { Step ("  {0}  {1}  ({2})" -f $a.name, $a.sid, $a.source) }
    foreach ($i in $plan.ignored) { Write-Warning "metadata service: ignored $i -- not written by SYSTEM or an administrator"; Step "  IGNORED: $i -- not written by SYSTEM or an administrator" }
    Step "  rule '$($spec.displayName)': outbound BLOCK for every other account; LocalUser $($plan.sddl)"
    if (-not $plan.ok) {
        foreach ($p in $plan.problems) { Write-Warning "metadata service: $($p.why)"; Step "  NOT RESOLVED: $($p.why)" }
        if ($PlanOnlyRule) { Step '  would NOT apply a new rule (an account that must keep access is not resolved -- no account is ever locked out on a doubt)'; return }
        $old = @(Get-PimImdsRuleExisting)
        $named = @(foreach ($r in $old) { $d = "$($r.Description)"; $ix = $d.IndexOf('Allowed: '); if ($ix -ge 0) { $d.Substring($ix + 9) -split '; ' | ForEach-Object { $_.Trim().ToLowerInvariant() } } })
        $covered = $old.Count -and -not @($plan.problems | Where-Object { -not $_.name -or ($named -notcontains $_.name.ToLowerInvariant()) }).Count
        if ($covered) { Step '  NOT applied: the previous rule stays as it was (it already lets every unresolved account through)'; return }
        if ($old.Count) { [void](Remove-PimImdsRule); Step '  NOT applied, and the previous rule is REMOVED (it would block an account that must keep access): the metadata service is open on this host until the account resolves -- re-run -Phase MetadataAccess then'; return }
        Step '  NOT applied: no rule on this host (the metadata service stays as it was) -- re-run -Phase MetadataAccess once the account resolves'
        return
    }
    if ($PlanOnlyRule) { Step '  would replace the rule (one rule, this name)'; return }
    $removed = Remove-PimImdsRule
    $desc = 'Created by Install-PimHybridWorker.ps1: only these accounts may reach the metadata service. Allowed: ' + (($plan.allowed | ForEach-Object { $_.name }) -join '; ')
    New-NetFirewallRule -Name $spec.name -DisplayName $spec.displayName -Group $spec.group -Description $desc -Direction Outbound -Action Block -Profile Any -Enabled True `
        -RemoteAddress $spec.remoteAddress -Protocol $spec.protocol -RemotePort $spec.remotePort -LocalUser $plan.sddl | Out-Null
    Step "  applied ($(if ($removed) { 'replaced the previous rule' } else { 'new' }))"
    # read back: the rule, its LocalUser (the same SIDs), that it is in force (a domain policy can keep local rules out), the profiles
    $rb = @(Get-NetFirewallRule -Name $spec.name -ErrorAction SilentlyContinue)
    $lu = if ($rb.Count) { "$((Get-NetFirewallSecurityFilter -AssociatedNetFirewallRule $rb[0]).LocalUser)" } else { '' }
    $got = Get-PimImdsSddlSids $lu; $exp = Get-PimImdsSddlSids $plan.sddl
    if ($rb.Count -eq 1 -and $got -and (($got.deny -join ',') -eq ($exp.deny -join ',')) -and (($got.allow -join ',') -eq 'S-1-1-0')) { Step "  read back: one rule, $($got.deny.Count) account(s) exempt" }
    else { Write-Warning "metadata service: the rule did not read back as written ($($rb.Count) rule(s), LocalUser '$lu')"; Step '  read back: NOT as written -- check the rule' }
    if (-not @(Get-NetFirewallRule -Name $spec.name -PolicyStore ActiveStore -ErrorAction SilentlyContinue).Count) { Write-Warning 'metadata service: the rule is not in force (ActiveStore) -- a Group Policy setting may keep local firewall rules from applying'; Step '  NOT in force: a Group Policy setting may keep local firewall rules from applying' }
    foreach ($pf in @(Get-NetFirewallProfile -ErrorAction SilentlyContinue)) { if ("$($pf.Enabled)" -eq 'False') { Write-Warning "metadata service: Windows Firewall is OFF for the $($pf.Name) profile -- the rule has no effect there"; Step "  Windows Firewall is OFF for the $($pf.Name) profile -- the rule has no effect there" } }
}
function Invoke-PimImdsRuleStep($Cfg) {
    # the rule never stops the phase that refreshes it: a failure is a warning, the worker's own steps go on
    try { Set-PimImdsRule -Cfg $Cfg -HostType "$($Cfg.hostType)" }
    catch { Write-Warning "metadata service: the metadata-service rule could not be applied: $($_.Exception.Message)"; Step "metadata service: NOT applied -- $($_.Exception.Message)" }
}

# ------------------------------------------------------------------ -WhatIf: the plan, nothing changed
if ($WhatIfPreference -and $Phase -ne 'Guests') {   # Guests only reads: it runs under -WhatIf too
    $ht = Resolve-PimHostType $HostType
    Step "PLAN (-WhatIf) -- nothing is changed: -Phase $Phase on this $(if ($ht -eq 'Arc') { 'Azure Arc-enabled server' } else { 'Azure VM' }) ($ht)"
    switch ($Phase) {
        'Join'      { Step $(if ($ht -eq 'Arc') { 'would REFUSE: an Arc server is joined by its owner (no offline-join blob)' } else { 'would load the offline domain-join blob (djoin /requestODJ), delete it, and reboot' }) }
        'Configure' {
            Step "would install PowerShell 7 (github.com, Microsoft signature checked), install + TEST gMSA $GmsaName$(if ("$ServerGmsaName".Trim()) { " and $ServerGmsaName" })"
            if ($ht -eq 'Arc') { Step "would add the gMSA(s) to the local group '$ArcKeyReaderGroup' and check that the Arc identity answers" } else { Step 'would rotate the machine password (the offline-join blob becomes worthless)' }
            Step ("would grant 'log on as a batch job' to the gMSA(s) only, lock $Root down, " + $(if ($UpdateSource -eq 'Blob') { "fetch the PIM code for ring '$Ring'$(if ("$Version".Trim()) { " / version $Version" }) from $SourceContainerUrl with the machine identity (source container: no signature)" } else { "install the SIGNED release of ring '$Ring' from the Invardia update service (this installer checks the signature, the ring and the archive's SHA-256 + size before anything is unpacked; the store's licence + install key are read with the machine identity)" }))
            Step "would register: 'PIM Hybrid Worker' (every $IntervalMinutes min), 'PIM Hybrid AD Sync', 'PIM Hybrid AD Sync Servers', 'PIM Hybrid AD Changes' (continuous)$(if ("$ServerGmsaName".Trim()) { ", 'PIM Hybrid Servers'" }), 'PIM Hybrid Worker Update' (daily 04:30)$(if ($PlanOnly) { ' -- every run PLAN ONLY' })"
        }
        'Update'    { Step 'would ask Invardia for the SIGNED manifest of the ring (verified by the installed version: signature, sequence, archive SHA-256) and move C:\PIM\app\current to the approved version (never backwards), then apply its layout -- with -UpdateSource Blob: channel.json from the source container (unsigned)' }
        'Layout'    { Step 'would write the run wrapper and re-register the scheduled tasks of this version' }
        'MetadataAccess' { Step 'would refresh the metadata-service rule from worker.json and the registered guests' }
        'Remove'    { Step "would unregister the worker's scheduled tasks ($($script:PimWorkerTaskNames -join ', ')), take the gMSA(s) out of '$ArcKeyReaderGroup' and 'log on as a batch job', delete $Root\app + $Root\bin (logs kept), remove the firewall rule '$((Get-PimImdsRuleSpec).displayName)'; the machine itself stays" }
    }
    # SEC-87: the metadata-service rule these phases (re)apply -- printed, never applied, under -WhatIf
    if ($Phase -in @('Configure', 'Update', 'Layout', 'MetadataAccess')) {
        $wcfg = if ($Phase -eq 'Configure') { [ordered]@{ gmsa = "$GmsaName".TrimEnd('$'); serverGmsa = "$ServerGmsaName".Trim().TrimEnd('$') } }
                elseif (Test-Path -LiteralPath $cfgPath) { Get-Content -LiteralPath $cfgPath -Raw | ConvertFrom-Json } else { $null }
        if ($null -ne $wcfg) { Set-PimImdsRule -Cfg $wcfg -HostType $(if ($Phase -ne 'Configure' -and "$($wcfg.hostType)".Trim()) { "$($wcfg.hostType)" } else { $ht }) -PlanOnlyRule }
        else { Step "metadata service: no $cfgPath -- the rule is planned by -Phase Configure" }
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

# ------------------------------------------------------------------ Guests (PIM 80.2a, framework 12.26 SHARED-WORKER)
if ($Phase -eq 'Guests') {
    # READ ONLY. Another product hosted on this machine registers in C:\ProgramData\HybridWorkerHost\guests\<product>.json
    # (written on its install, deleted on its remove). One line per file: "PIM-HW-GUEST <file> <product> <taskPath>", then
    # "PIM-HW-GUESTS <count>". An unreadable file still counts as a guest (the host must not delete the machine on a doubt).
    $gDir = Join-Path $env:ProgramData 'HybridWorkerHost\guests'
    $gFiles = @(if (Test-Path -LiteralPath $gDir) { Get-ChildItem -LiteralPath $gDir -Filter '*.json' -File -ErrorAction SilentlyContinue })
    foreach ($gf in $gFiles) {
        $gp = ''; $gt = ''
        try { $gj = Get-Content -LiteralPath $gf.FullName -Raw | ConvertFrom-Json; $gp = "$($gj.product)".Trim(); $gt = "$($gj.taskPath)".Trim() } catch { $gp = '(unreadable)' }
        if (-not $gp) { $gp = $gf.BaseName }
        Write-Output ("PIM-HW-GUEST {0} {1} {2}" -f $gf.Name, ($gp -replace '\s', '_'), $(if ($gt) { $gt -replace '\s', '_' } else { '-' }))
    }
    Write-Output "PIM-HW-GUESTS $($gFiles.Count)"
    return
}

# ------------------------------------------------------------------ Remove (§100.63: Remove-PimHybridWorker.ps1 -Target Arc)
if ($Phase -eq 'Remove') {
    # Only what this installer put on the machine. The machine, its Arc agent, PowerShell 7, the domain membership and the
    # logs stay; the gMSAs themselves are deleted in AD by the AD administrator (Remove-PimHybridWorker.ps1 prints how).
    $rcfg = if (Test-Path -LiteralPath $cfgPath) { Get-Content -LiteralPath $cfgPath -Raw | ConvertFrom-Json } else { $null }
    foreach ($n in $script:PimWorkerTaskNames) {
        $t = Get-ScheduledTask -TaskName $n -ErrorAction SilentlyContinue
        if (-not $t) { continue }
        Stop-ScheduledTask -TaskName $n -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $n -Confirm:$false
        Step "task '$n' removed"
    }
    $gm = @(@($rcfg.gmsa, $rcfg.serverGmsa) | Where-Object { "$_".Trim() })
    if (-not $gm.Count) { Step "no $cfgPath -- the gMSA clean-up is skipped (tasks removed)" }
    $sids = @()
    foreach ($g in $gm) { try { $sids += (New-Object System.Security.Principal.NTAccount("$g`$")).Translate([System.Security.Principal.SecurityIdentifier]).Value } catch { Step "  $g`$ does not resolve any more (deleted in AD?) -- skipped" } }
    if ($gm.Count -and "$($rcfg.hostType)" -eq 'Arc') {
        foreach ($g in $gm) {
            $o = & net.exe localgroup "$ArcKeyReaderGroup" "$g`$" /delete 2>&1
            if ($LASTEXITCODE -eq 0) { Step "  $g`$ removed from '$ArcKeyReaderGroup'" } else { Step "  $g`$ not in '$ArcKeyReaderGroup' ($(($o -join ' ').Trim()))" }
        }
    }
    if ($sids.Count) {
        $inf = Join-Path $env:TEMP 'pim-secpol.inf'; $db = Join-Path $env:TEMP 'pim-secpol.sdb'
        & secedit.exe /export /cfg $inf /areas USER_RIGHTS | Out-Null
        $lines = @(Get-Content $inf)
        for ($i = 0; $i -lt $lines.Count; $i++) {
            if ($lines[$i] -notmatch '^SeBatchLogonRight\s*=\s*(.*)$') { continue }
            $keep = @($Matches[1] -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -and ($sids -notcontains $_.TrimStart('*')) })
            $lines[$i] = 'SeBatchLogonRight = ' + ($keep -join ',')
        }
        Set-Content -LiteralPath $inf -Value $lines -Encoding Unicode
        & secedit.exe /configure /db $db /cfg $inf /areas USER_RIGHTS | Out-Null
        Remove-Item $inf, $db -Force -ErrorAction SilentlyContinue
        Step "'log on as a batch job' taken back from the worker gMSA(s)"
    }
    # SEC-87: PIM owns the metadata-service rule; with PIM gone it goes too (a guest that stays keeps its own protection)
    if ((Remove-PimImdsRule) -gt 0) { Step "firewall rule '$((Get-PimImdsRuleSpec).displayName)' removed" }
    foreach ($d in 'app', 'bin') { $p = Join-Path $Root $d; if (Test-Path -LiteralPath $p) { Remove-Item -LiteralPath $p -Recurse -Force; Step "$p deleted" } }
    Step "removed: the worker's tasks and rights on this machine ($Root\logs kept; the machine itself is untouched)"
    return
}

# ------------------------------------------------------------------ shared: config, MI token, fetch
if ($Phase -eq 'Configure') {
    # SEC-95: the source container is read only by a Blob worker; a signed (Invardia) worker needs its RING (the signed
    # release is chosen per ring; a -Version pin must then be that ring's signed version)
    foreach ($p in @('GmsaName', 'SqlServer', 'TenantId') + $(if ($UpdateSource -eq 'Blob') { @('SourceContainerUrl') } else { @() })) { if (-not "$((Get-Variable $p -ValueOnly))".Trim()) { throw "-$p is required for -Phase Configure" } }
    if (-not "$Ring".Trim() -and -not "$Version".Trim()) { throw '-Ring (the update ring this environment follows) or -Version is required' }
    if ($UpdateSource -ne 'Blob' -and -not "$Ring".Trim()) { throw '-Ring is required: the worker installs the signed release of its update ring' }
    if ($GmsaName -notmatch '^[^\\]+\\[^\\]+$') { throw "-GmsaName must be DOMAIN\name (got '$GmsaName')" }
    if ("$ServerGmsaName".Trim() -and $ServerGmsaName -notmatch '^[^\\]+\\[^\\]+$') { throw "-ServerGmsaName must be DOMAIN\name (got '$ServerGmsaName')" }
    if ("$ServerGmsaName".Trim() -and $ServerGmsaName.TrimEnd('$') -ieq $GmsaName.TrimEnd('$')) { throw '-ServerGmsaName must differ from -GmsaName (server onboarding is a separate tier)' }
    $cfg = [ordered]@{ gmsa = $GmsaName.TrimEnd('$'); serverGmsa = "$ServerGmsaName".Trim().TrimEnd('$'); sqlServer = $SqlServer; sqlDatabase = $SqlDatabase; tenantId = $TenantId
        source = "$SourceContainerUrl".Trim().TrimEnd('/'); ring = "$Ring".Trim(); version = "$Version".Trim(); adServer = $AdServer; intervalMinutes = $IntervalMinutes; syncPauseSeconds = 5; planOnly = [bool]$PlanOnly
        hostType = (Resolve-PimHostType $HostType); updateSource = $UpdateSource.ToLowerInvariant() }
} else {
    if (-not (Test-Path $cfgPath)) { throw "no $cfgPath -- run -Phase Configure first" }
    $cfg = Get-Content -LiteralPath $cfgPath -Raw | ConvertFrom-Json
    if (-not "$($cfg.hostType)".Trim()) { $cfg | Add-Member -NotePropertyName hostType -NotePropertyValue (Resolve-PimHostType $HostType) -Force }   # a worker configured before 100.63(b)
    # SEC-95: a worker configured before the setting existed takes the SIGNED path (the unsigned blob path is never the default)
    if (-not "$($cfg.updateSource)".Trim()) { $cfg | Add-Member -NotePropertyName updateSource -NotePropertyValue 'invardia' -Force }
}
$updStatePath = Join-Path $Root 'bin\update-state.json'

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
function Resolve-SignedTargetVersion {
    # SEC-95: the signed path, run by the INSTALLED version's resolver (its embedded keys verify the manifest). Never falls
    # back to the unsigned blob path: a failure keeps the running version and says why.
    if ("$($cfg.version)".Trim()) { return @{ version = "$($cfg.version)".Trim(); reason = 'pinned by -Version'; contextPath = '' } }
    $res = Join-Path $Root 'app\current\SOLUTIONS\PIM4EntraPS\tools\pim-hybrid-worker\Resolve-PimHybridWorkerUpdate.ps1'
    if (-not (Test-Path -LiteralPath $res)) { return @{ version = ''; contextPath = ''; reason = "the installed version $(Get-CurrentVersion) has no signed update resolver (it predates the signed update) -- nothing moves; install a current version once with -Phase Configure" } }
    $px = Join-Path $env:ProgramFiles 'PowerShell\7\pwsh.exe'; if (-not (Test-Path $px)) { $px = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" }
    $out = @(& $px -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $res -SqlServer $cfg.sqlServer -SqlDatabase $cfg.sqlDatabase -Ring "$($cfg.ring)" -StateFile $updStatePath -RunningVersion (Get-CurrentVersion) -WorkDir $env:TEMP 2>&1 | ForEach-Object { "$_" })
    $line = @($out | Where-Object { $_ -like 'PIM-HW-UPDATE *' } | Select-Object -Last 1)
    if (-not $line.Count) { return @{ version = ''; contextPath = ''; reason = "the signed update resolver gave no answer (exit $LASTEXITCODE): $((@($out | Select-Object -Last 2)) -join ' ')" } }
    $a = $line[0].Substring(14) | ConvertFrom-Json
    if (-not $a.ok) { return @{ version = ''; contextPath = ''; reason = "signed update refused: $($a.reason)" } }
    return @{ version = "$($a.version)".Trim(); contextPath = "$($a.contextPath)".Trim(); sequence = [int]$a.sequence; reason = "signed manifest: $($a.reason)" }
}
function Save-UpdateState([hashtable]$T) {
    # the worker's own replay watermark (per ring): a lower, validly signed manifest is never applied again
    if (-not $T.sequence) { return }
    ([pscustomobject]@{ ring = "$($cfg.ring)".Trim(); sequence = [int]$T.sequence; version = "$($T.version)"; savedUtc = [datetime]::UtcNow.ToString('o') } | ConvertTo-Json) |
        Set-Content -LiteralPath $updStatePath -Encoding UTF8
}

# ------------------------------------------------------------------ SEC-95: the FIRST install takes the signed release too
# A machine with nothing installed has no installed version whose keys could verify a manifest, so THIS installer does it:
# it was delivered from a trusted release tree (run-command, or the signed standalone) and carries the update-signing keys
# and checks inlined above (InvardiaUpdate.verify.ps1 -- the same file the engine uses). The install's own licence and
# install key are read from the PIM store with the machine identity; the manifest for the worker's ring is pulled and its
# signature, product, kind, ring and holds checked; the archive's size + SHA-256 must be the signed ones; the unpacked
# tree's VERSION must be the signed version. Any refusal installs NOTHING -- there is no fallback to the source container.
function Read-PimWorkerStoreSettings([string[]]$Names) {
    # pim.Settings values by name (ValueJson parsed like Get-PimSqlSetting), read with the machine identity over TLS.
    # .NET's in-box SQL client only (no module); one connection for all names.
    $t = ('System.Data.SqlClient.SqlConnection' -as [type]); if (-not $t) { $t = ('Microsoft.Data.SqlClient.SqlConnection' -as [type]) }
    if (-not $t) { throw 'no .NET SQL client on this machine' }
    $c = New-Object $t.FullName ("Server=tcp:$($cfg.sqlServer),1433;Database=$($cfg.sqlDatabase);Encrypt=True;TrustServerCertificate=False;Connection Timeout=30")
    $c.AccessToken = Get-MiToken 'https://database.windows.net/'
    $out = @{}
    try {
        $c.Open()
        foreach ($n in $Names) {
            $cmd = $c.CreateCommand(); $cmd.CommandText = 'SELECT ValueJson FROM pim.Settings WHERE Name=@n'; [void]$cmd.Parameters.AddWithValue('@n', $n)
            $j = $cmd.ExecuteScalar()
            if ($null -eq $j -or $j -is [DBNull] -or "$j".Trim() -eq '') { $out[$n] = $null; continue }
            try { $out[$n] = ($j | ConvertFrom-Json) } catch { $out[$n] = "$j" }
        }
    } finally { $c.Dispose() }
    return $out
}
function Invoke-PimWorkerHttp([string]$Method, [string]$Url, $Body, [hashtable]$Headers) {
    # One JSON call that never throws on an HTTP status: @{ status; body; error } (the shape the manifest pull takes).
    $a = @{ Method = $Method; Uri = $Url; Headers = $(if ($Headers) { $Headers } else { @{} }); ContentType = 'application/json'; TimeoutSec = 60; UseBasicParsing = $true }
    if ($null -ne $Body) { $a['Body'] = ($Body | ConvertTo-Json -Depth 6 -Compress) }
    try {
        $r = Invoke-WebRequest @a -ErrorAction Stop
        $b = $null; if ("$($r.Content)".Trim()) { try { $b = "$($r.Content)" | ConvertFrom-Json } catch { } }
        return @{ status = [int]$r.StatusCode; body = $b }
    } catch {
        $code = 0; try { if ($_.Exception.Response) { $code = [int]$_.Exception.Response.StatusCode } } catch { }
        return @{ status = $code; body = $null; error = ((("$($_.Exception.Message)") -split "`n")[0]) }
    }
}
function Resolve-FirstInstallSignedTarget {
    <#
      SEC-95: the signed release for the worker's ring, verified by THIS installer. Returns @{ ok; version; sequence; treePath;
      workPath; reason } -- treePath = the unpacked, verified release (repo-root shaped: SOLUTIONS\PIM4EntraPS\...), ready to be
      moved into <Root>\app\<version>; workPath = the folder to delete afterwards. ok=$false = NOTHING is installed.
      Seams (tests): -GetSetting { param($Name) }, -Http { param($Method, $Url, $Body, $Headers) }, -Download { param($Url,
      $OutFile, $Sha256, $Size) }, -TrustedKeys. The archive is checked again here whatever -Download did.
    #>
    param([scriptblock]$GetSetting, [scriptblock]$Http = { param($m, $u, $b, $h) Invoke-PimWorkerHttp -Method $m -Url $u -Body $b -Headers $h },
          [scriptblock]$Download = { param($u, $o, $s, $z) Save-InvardiaArchive -Url $u -OutFile $o -ExpectedSha256 $s -ExpectedSize $z },
          [AllowEmptyString()][string]$Ring = "$($cfg.ring)", [AllowEmptyString()][string]$PinnedVersion = "$($cfg.version)",
          [object[]]$TrustedKeys = $script:InvardiaUpdateTrustedKeys, [string]$WorkDir = (Join-Path $Root 'app'),
          # the worker's own replay watermark for this ring (bin\update-state.json; a first install has none) and the version
          # it runs ('' = nothing installed): the same version again = nothing downloaded
          [int]$AppliedSequence = -1, [AllowEmptyString()][string]$RunningVersion = '')
    $no = { param($why) @{ ok = $false; version = ''; sequence = 0; treePath = ''; workPath = ''; reason = $why } }
    if ($AppliedSequence -lt 0) {
        $AppliedSequence = 0
        try {
            if ($updStatePath -and (Test-Path -LiteralPath $updStatePath)) {
                $st = Get-Content -LiteralPath $updStatePath -Raw | ConvertFrom-Json
                if ("$($st.ring)".Trim() -eq "$Ring".Trim()) { [void][int]::TryParse("$($st.sequence)", [ref]$AppliedSequence) }
            }
        } catch { $AppliedSequence = 0 }
    }
    $ringN = -1
    if (-not [int]::TryParse(("$Ring".Trim() -replace '^(?i)ring', ''), [ref]$ringN) -or $ringN -lt 0 -or $ringN -gt 3) { return (& $no "no update ring 0-3 ('$Ring') -- the signed release is chosen per ring") }
    $names = @('License', 'InvardiaInstallKey', 'InstallId', 'LicenceRequestBaseUrl')
    $all = @{}
    try {
        if ($GetSetting) { foreach ($n in $names) { $all[$n] = & $GetSetting $n } }
        else { $all = Read-PimWorkerStoreSettings -Names $names }
    } catch { return (& $no "the PIM store could not be read with the machine identity: $((("$($_.Exception.Message)") -split "`n")[0])") }
    $licRaw = $all['License']
    $lic = if ($null -eq $licRaw) { '' } elseif ($licRaw -is [string]) { $licRaw } else { ConvertTo-Json -InputObject $licRaw -Depth 6 -Compress }
    $key = "$($all['InvardiaInstallKey'])".Trim()
    $iid = "$($all['InstallId'])".Trim().ToLowerInvariant()
    $base = "$($all['LicenceRequestBaseUrl'])".Trim()
    if (-not "$lic".Trim()) { return (& $no 'no Pro licence in the PIM store -- the hybrid worker installs only a signed Pro release') }
    if ($key -notmatch '^inv-[A-Za-z0-9_-]{20,100}$') { return (& $no 'no install key in the PIM store yet (the engine claims it once the Pro licence is in) -- run Configure again after that') }
    if ($base -and $base -notmatch '^(?i)https://') { return (& $no 'the update address in the PIM store is not https') }
    $p = Invoke-InvardiaManifestPull -Product 'pim-manager' -Http $Http -BaseUrl $base -InstallKey $key -LicenceText $lic -Kind 'code' -Ring $ringN -InstallId $iid
    if ($p.status -ne 200) { return (& $no "the signed release could not be read: $($p.reason)") }
    $v = Test-InvardiaManifest -Response $p.body -TrustedKeys $TrustedKeys -Kind 'code' -Product 'pim-manager' -Ring $ringN -AppliedSequence $AppliedSequence -RunningVersion $RunningVersion
    if (-not $v.ok) { return (& $no "the signed release was refused: $($v.reason)") }
    if ($v.hold) { return (& $no "the signed release is held: $($v.reason)") }
    if ("$PinnedVersion".Trim() -and "$PinnedVersion".Trim() -ne "$($v.version)") { return (& $no "pinned to $("$PinnedVersion".Trim()), but the signed release of ring $ringN is $($v.version) -- the worker installs only the signed release of its ring") }
    if ("$RunningVersion".Trim() -and "$RunningVersion".Trim() -eq "$($v.version)") { return @{ ok = $true; version = "$($v.version)"; sequence = [int]$v.sequence; treePath = ''; workPath = ''; contextPath = ''; reason = "$($v.reason) -- already running it" } }
    $work = Join-Path $WorkDir (".first-{0}" -f ([guid]::NewGuid().ToString('N').Substring(0, 8)))
    New-Item -ItemType Directory -Force -Path $work | Out-Null
    $ok = $false
    try {
        $zip = Join-Path $work "pim-manager-src-$($v.version).zip"
        $d = & $Download $v.downloadUrl $zip $v.sha256 $v.size
        if ($d -and -not $d.ok) { return (& $no "the release archive was refused: $($d.reason)") }
        $chk = Test-InvardiaArchiveFile -Path $zip -ExpectedSha256 $v.sha256 -ExpectedSize $v.size
        if (-not $chk.ok) { return (& $no "the release archive was refused: $($chk.reason)") }
        $x = Join-Path $work 'x'
        Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue
        try { [System.IO.Compression.ZipFile]::ExtractToDirectory($zip, $x) } catch { return (& $no "the release archive could not be unpacked: $($_.Exception.Message)") }
        Remove-Item -LiteralPath $zip -Force -ErrorAction SilentlyContinue
        $top = Join-Path $x "pim-manager-src-$($v.version)"
        $vf = Join-Path $top 'SOLUTIONS\PIM4EntraPS\VERSION'
        if (-not (Test-Path -LiteralPath $vf)) { return (& $no "the release archive has no pim-manager-src-$($v.version)\SOLUTIONS\PIM4EntraPS (not the release layout)") }
        $inside = "$(Get-Content -Raw -LiteralPath $vf)".Trim()
        if ($inside -ne "$($v.version)") { return (& $no "the release archive holds version $inside, the signed manifest says $($v.version)") }
        $ok = $true
        return @{ ok = $true; version = "$($v.version)"; sequence = [int]$v.sequence; treePath = $top; workPath = $work; contextPath = ''; reason = $v.reason }
    } finally { if (-not $ok) { Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue } }
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
function Install-Version([string]$V, [string]$ContextPath = '', [string]$TreePath = '') {
    if ($V -notmatch '^\d+\.\d+\.\d+$') { throw "refusing version '$V' (not N.N.N)" }
    $dest = Join-Path $Root "app\$V"
    $start = Join-Path $dest 'SOLUTIONS\PIM4EntraPS\tools\pim-scheduler\Start-PimScheduler.ps1'
    if (-not (Test-Path $start) -and "$TreePath".Trim()) {
        # SEC-95 first install: the release this installer verified (signature, SHA-256 + size, VERSION), already unpacked
        if (-not (Test-Path -LiteralPath (Join-Path $TreePath 'SOLUTIONS\PIM4EntraPS\tools\pim-scheduler\Start-PimScheduler.ps1'))) { throw "the verified release at $TreePath holds no PIM tree -- refusing" }
        if (Test-Path -LiteralPath $dest) { Remove-Item -LiteralPath $dest -Recurse -Force }
        Move-Item -LiteralPath $TreePath -Destination $dest
    }
    if (-not (Test-Path $start)) {
        $arc = Join-Path $env:TEMP "pim-src-$V.tar.gz"
        # SEC-95: the signed path hands over the VERIFIED archive (SHA-256 + VERSION checked); only the Blob path downloads here.
        # A signed worker never downloads an archive it has not verified (a -Version pin included): it refuses instead.
        if ("$ContextPath".Trim()) { if (-not (Test-Path -LiteralPath $ContextPath)) { throw "the verified archive $ContextPath is missing" }; Move-Item -LiteralPath $ContextPath -Destination $arc -Force }
        elseif ("$($cfg.updateSource)".Trim().ToLowerInvariant() -ne 'blob') { throw "refusing to install $V`: it is not a verified signed release (this worker installs only the signed release of its ring)" }
        else { Get-Blob -Name "pim-src-$V.tar.gz" -OutFile $arc }
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
    Invoke-PimImdsRuleStep $cfg
    return
}

# ------------------------------------------------------------------ MetadataAccess: only the metadata-service rule
# A guest product runs this after it writes / deletes its guests\<product>.json, so its gMSA is let through (or taken out)
# at once: C:\PIM\bin\Install-PimHybridWorker.ps1 -Phase MetadataAccess (as SYSTEM). The daily update refreshes it too.
if ($Phase -eq 'MetadataAccess') {
    Invoke-PimImdsRuleStep $cfg
    return
}

# ------------------------------------------------------------------ Update
if ($Phase -eq 'Update') {
    # SEC-87: the metadata-service rule is refreshed on EVERY daily run (finally: also when nothing moves or the update fails)
    try {
    $signed = ("$($cfg.updateSource)".Trim().ToLowerInvariant() -ne 'blob')
    # SEC-95: an installed version without the signed resolver (it predates it) is moved by THIS installer's own check
    $ownCheck = ($signed -and -not (Test-Path -LiteralPath (Join-Path $Root 'app\current\SOLUTIONS\PIM4EntraPS\tools\pim-hybrid-worker\Resolve-PimHybridWorkerUpdate.ps1')))
    $t = if ($ownCheck) { Resolve-FirstInstallSignedTarget -RunningVersion (Get-CurrentVersion) } elseif ($signed) { Resolve-SignedTargetVersion } else { Resolve-TargetVersion }; $c = Get-CurrentVersion
    try {
    Step "source: $(if ($signed) { 'Invardia (signed)' } else { 'source container (UNSIGNED: no signature on its archives)' }); ring: $($t.reason); running: $(if ($c) { $c } else { 'none' })"
    if (-not $t.version) { Step 'no approved version -- nothing moves'; return }
    if ($c -and ([version]$t.version -lt [version]$c)) { Step "the ring approves $($t.version), older than the running $c -- NOT rolling back unattended"; return }
    if ($t.version -eq $c) { Step 'up to date'; if ($signed) { Save-UpdateState $t }; if (-not (Test-WorkerLayoutCurrent)) { Invoke-CurrentLayout }; Sync-WorkerTaskState; return }
    Install-Version -V $t.version -ContextPath "$($t.contextPath)" -TreePath "$($t.treePath)"
    } finally { if ("$($t.workPath)".Trim()) { Remove-Item -LiteralPath "$($t.workPath)" -Recurse -Force -ErrorAction SilentlyContinue } }
    if ($signed) { Save-UpdateState $t }
    Invoke-CurrentLayout
    Sync-WorkerTaskState
    return
    } finally { Invoke-PimImdsRuleStep $cfg }
}

# ------------------------------------------------------------------ Configure
$join = Get-PimJoinState
if (-not $join.joined) { throw $(if ("$($cfg.hostType)" -eq 'Arc') { 'this Arc server is not domain-joined -- join it to the domain first (it is your own server; no offline-join blob)' } else { 'this machine is not domain-joined -- run -Phase Join first' }) }
Step "host: $($cfg.hostType), domain $($join.domain)"
if ("$($cfg.hostType)" -ne 'Arc' -and [Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne 'S-1-5-18' -and @(Get-PimImdsRuleExisting).Count) {
    # SEC-87: once the rule is in place only SYSTEM (and the gMSAs) reach the metadata service -- this run's code fetch needs it
    Write-Warning "metadata service: this run is not SYSTEM and the metadata-service rule is in place -- the code fetch below will be refused; run Configure through run-command (Invoke-PimHybridWorkerRunCommand.ps1), which runs as SYSTEM"
}
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
# SEC-95: every install takes the SIGNED release of its ring (unless the worker was configured with -UpdateSource Blob).
# A worker that already runs a version with the signed resolver is checked by that version (its embedded keys); a FIRST
# install -- nothing installed to verify with -- is checked by THIS installer (Resolve-FirstInstallSignedTarget: the same
# keys and checks, inlined). Either way a refusal stops here and installs nothing: there is no fallback to the container.
$signedCfg = ("$($cfg.updateSource)" -ne 'blob')
$signedHere = ($signedCfg -and (Test-Path -LiteralPath (Join-Path $Root 'app\current\SOLUTIONS\PIM4EntraPS\tools\pim-hybrid-worker\Resolve-PimHybridWorkerUpdate.ps1')))
if ($signedHere) {
    # a REFUSED signed answer stops here -- it never falls back to the unsigned source
    $t = Resolve-SignedTargetVersion
    if (-not $t.version) { throw "cannot install: $($t.reason)" }
} elseif ($signedCfg) {
    Step 'source: Invardia (signed) -- the first install is checked by this installer: signature, ring, archive SHA-256 + size, VERSION'
    $t = Resolve-FirstInstallSignedTarget
    if (-not $t.ok -or -not $t.version) { throw "cannot install: $($t.reason)" }
} else {
    Step 'source: the source container (UNSIGNED: channel.json and the archive carry no signature)'
    $t = Resolve-TargetVersion
}
if (-not $t.version) { throw "cannot install: $($t.reason)" }
try { Install-Version -V $t.version -ContextPath "$($t.contextPath)" -TreePath "$($t.treePath)" }
finally { if ("$($t.workPath)".Trim()) { Remove-Item -LiteralPath "$($t.workPath)" -Recurse -Force -ErrorAction SilentlyContinue } }
if ($signedCfg) { Save-UpdateState $t }

Register-WorkerLayout
Invoke-PimImdsRuleStep $cfg

} finally { Stop-PimScriptRun -Script 'Install-PimHybridWorker' }
