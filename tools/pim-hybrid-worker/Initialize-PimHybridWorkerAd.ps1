#Requires -Version 5.1
<#
.SYNOPSIS
    §80.2 PIMHYBRIDWRK -- the Active Directory half of the hybrid worker: its gMSA identities, the rights they need, the
    servers GPO, and (optionally) an offline domain-join blob for the worker VM.

.DESCRIPTION
    Run on a domain controller, or on any host with RSAT-AD + GPMC and rights to create gMSAs, groups, GPOs and OU
    permissions. Every step is read-before-write and idempotent; -WhatIf prints the plan and changes nothing.

    IDENTITY DESIGN (operator 2026-09-30 -- the pattern the domain's other automation identities already follow):
      every identity is THREE objects in -GmsaOu
        <name>                          the gMSA, named gMSA-<code>-L<level>-T<tier>
        <name>-PermissionGroup          the gMSA is its only member; EVERY right is granted to this group, never to the account
        <name>-PrincipalsAllowedAccess  the computers allowed to retrieve the gMSA's password (the worker VM)
      and ONE identity per privilege tier:
        -GmsaName        (default gMSA-PIM-L1-T0) AD groups + just-in-time membership + admin accounts. Tier 0: protected
                         groups (Domain / Enterprise / Schema Admins nesting) are reached through AdminSDHolder.
        -ServerGmsaName  (e.g.    gMSA-PIM-L2-T1) server onboarding: its PermissionGroup is put into the servers' local
                         Administrators by the -ServerOu GPO, and the worker sets each server's local Administrators as it.

      1. KDS root key       -- required for any gMSA. Refused when missing unless -CreateKdsRootKey (a forest-wide object).
      2. Worker computer    -- -ProvisionOdj: `djoin /provision` creates the computer account in -ComputerOu and prints the
                               one-time join blob between the markers ODJ-BLOB-BEGIN / ODJ-BLOB-END.
      3. Identities         -- the three objects above, for -GmsaName and (when given) -ServerGmsaName. AES256 only.
      4. Rights             -- on <GmsaName>-PermissionGroup, least privilege per OU:
                               -GroupsOu        create groups; write member / displayName / description on its groups
                               -AdminAccountsOu create users; full control of the user objects BELOW that OU
                               -GrantProtectedGroupMembership: write 'member' on AdminSDHolder (adminCount=1 groups: SDProp
                                                replaces their ACL hourly, so an OU grant never reaches them).
                                                ⚠️ Whoever controls that gMSA is then TIER 0. Treat the worker VM as a DC.
      5. Servers GPO        -- -ServerOu: a GPO (-ServerAdminGpoName) with Restricted Groups "member of": the server
                               identity's PermissionGroup joins BUILTIN\Administrators on every computer below the OU --
                               ADDED, nothing removed. Linked to each -ServerOu.

    What it deliberately does NOT do:
      * enable the AD Privileged Access Management feature -- irreversible for the forest. It is DETECTED and reported.
      * put an identity into a PIM just-in-time group: those groups' members are the people with an active elevation, and
        the PIM-for-AD sync removes anyone else (it removed the first worker gMSA from the shared server-admins group).
      * grant anything on protected USER accounts (adminCount=1).

.EXAMPLE
    .\Initialize-PimHybridWorkerAd.ps1 -WorkerComputerName PIMHYBRIDWRK -ComputerOu 'OU=Servers,DC=corp,DC=local' `
        -GmsaOu 'OU=Automation,OU=Service Accounts,DC=corp,DC=local' -GroupsOu 'OU=PIM Groups,DC=corp,DC=local' `
        -AdminAccountsOu 'OU=Admin Accounts,DC=corp,DC=local' -GrantProtectedGroupMembership `
        -ServerGmsaName gMSA-PIM-L2-T1 -ServerOu 'OU=Servers,DC=corp,DC=local' -WhatIf
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][ValidatePattern('^[A-Za-z0-9-]{1,15}$')][string]$WorkerComputerName,
    [Parameter(Mandatory)][string]$ComputerOu,
    [ValidatePattern('^[A-Za-z0-9-]{1,15}$')][string]$GmsaName = 'gMSA-PIM-L1-T0',
    [Parameter(Mandatory)][string]$GmsaOu,
    [Parameter(Mandatory)][string]$GroupsOu,
    [string[]]$AdminAccountsOu = @(),
    [switch]$GrantProtectedGroupMembership,
    # server onboarding, tier-split: its own identity + the GPO that makes its PermissionGroup local admin on -ServerOu
    [ValidatePattern('^$|^[A-Za-z0-9-]{1,15}$')][string]$ServerGmsaName = '',
    [string[]]$ServerOu = @(),
    [string]$ServerAdminGpoName = '',
    [string]$UsedBy = 'PIM4EntraPS hybrid worker',
    [switch]$ProvisionOdj,
    [switch]$ReuseComputer,
    [switch]$CreateKdsRootKey,
    [switch]$TriggerSdProp
)
$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory
function Step($m) { Write-Host "[ad] $m" -ForegroundColor Cyan }
function Info($m) { Write-Host "     $m" -ForegroundColor Gray }

$dom = Get-ADDomain
$net = $dom.NetBIOSName
Step "domain $($dom.DNSRoot) ($net), PDC $($dom.PDCEmulator)"
if ("$ServerGmsaName".Trim() -and -not @($ServerOu | Where-Object { "$_".Trim() }).Count) { throw '-ServerGmsaName needs -ServerOu: the OU(s) whose servers get its PermissionGroup as local administrator (the GPO)' }
if ("$ServerGmsaName".Trim() -ieq $GmsaName) { throw '-ServerGmsaName must differ from -GmsaName: server onboarding is a separate tier' }
foreach ($ou in @($ComputerOu, $GmsaOu, $GroupsOu) + @($AdminAccountsOu) + @($ServerOu)) {
    if (-not "$ou".Trim()) { continue }
    try { [void](Get-ADOrganizationalUnit -Identity $ou) } catch { throw "OU not found: '$ou'" }
}

# 1. KDS root key
$kds = @(Get-KdsRootKey)
if (-not $kds.Count) {
    if (-not $CreateKdsRootKey) { throw 'No KDS root key: a gMSA cannot exist without one. Re-run with -CreateKdsRootKey (forest-wide; effective after replication, ~10 h unless backdated), or create it yourself.' }
    if ($PSCmdlet.ShouldProcess('forest', 'Add-KdsRootKey (effective in 10 hours)')) { Add-KdsRootKey -EffectiveImmediately | Out-Null; Info 'KDS root key created -- gMSA password retrieval works once it has replicated.' }
} else { Info "KDS root key present ($($kds.Count))" }

# PAM feature: detect, never enable
$pam = @((Get-ADOptionalFeature -Filter "Name -eq 'Privileged Access Management Feature'").EnabledScopes).Count -gt 0
Info ("AD Privileged Access Management feature: {0}" -f $(if ($pam) { 'ENABLED -- JIT membership will carry a TTL' } else { 'not enabled -- JIT membership is plain; the sync removes it (this script never enables PAM: it is irreversible)' }))

# 2. worker computer + offline domain-join blob
$comp = Get-ADComputer -Filter "Name -eq '$WorkerComputerName'" -ErrorAction SilentlyContinue
if ($ProvisionOdj) {
    if ($comp -and -not $ReuseComputer) { throw "Computer '$WorkerComputerName' already exists ($($comp.DistinguishedName)). Pass -ReuseComputer to re-provision it (its password is reset)." }
    if ($PSCmdlet.ShouldProcess($WorkerComputerName, "djoin /provision in '$ComputerOu'")) {
        $tmp = Join-Path $env:TEMP ("odj-{0}.txt" -f ([guid]::NewGuid().ToString('N')))
        try {
            $dj = @('/provision', '/domain', $dom.DNSRoot, '/machine', $WorkerComputerName, '/machineou', $ComputerOu, '/savefile', $tmp)
            if ($comp) { $dj += '/reuse' }
            $out = & djoin.exe @dj 2>&1
            if ($LASTEXITCODE -ne 0) { throw "djoin /provision failed ($LASTEXITCODE): $($out -join ' ')" }
            # gzip + base64 ('gz:' prefix): the raw file is UTF-16 base64 text, ~4x larger, and Azure run-command returns only
            # the last 4 KB of output -- an uncompressed blob arrives truncated and the join fails far from the cause.
            $ms = New-Object IO.MemoryStream
            $gz = New-Object IO.Compression.GZipStream($ms, [IO.Compression.CompressionMode]::Compress)
            $raw = [IO.File]::ReadAllBytes($tmp); $gz.Write($raw, 0, $raw.Length); $gz.Close()
            $blob = 'gz:' + [Convert]::ToBase64String($ms.ToArray())
            Write-Output 'ODJ-BLOB-BEGIN'; Write-Output $blob; Write-Output 'ODJ-BLOB-END'
        } finally { if (Test-Path $tmp) { Remove-Item -LiteralPath $tmp -Force } }
        $comp = Get-ADComputer -Identity $WorkerComputerName
    }
} elseif (-not $comp) { Info "computer '$WorkerComputerName' does not exist yet (join it first, or use -ProvisionOdj) -- the PrincipalsAllowedAccess groups are created empty" }

# 3. identities: gMSA + <name>-PermissionGroup + <name>-PrincipalsAllowedAccess
function Get-OrNewGroup([string]$Name, [string]$Description) {
    $g = Get-ADGroup -Filter "Name -eq '$Name'" -ErrorAction SilentlyContinue
    if (-not $g -and $PSCmdlet.ShouldProcess($Name, "New-ADGroup in '$GmsaOu'")) {
        $g = New-ADGroup -Name $Name -SamAccountName $Name -GroupCategory Security -GroupScope Global -Path $GmsaOu -Description $Description -PassThru
        Info "group $Name created"
    } elseif ($g) { Info "group $Name exists" }
    return $g
}
function Add-Member([object]$Group, [object]$Member, [string]$What) {
    if (-not $Group -or -not $Member) { return }
    if (@(Get-ADGroupMember -Identity $Group | Where-Object { $_.SID -eq $Member.SID }).Count) { Info "$What already in $($Group.Name)"; return }
    if ($PSCmdlet.ShouldProcess($Group.Name, "add $What")) { Add-ADGroupMember -Identity $Group -Members $Member; Info "$What added to $($Group.Name)" }
}
function Initialize-Identity([string]$Name, [string]$Purpose) {
    $lt = if ($Name -match '-(L\d)-(T\d)$') { "$($Matches[1]), $($Matches[2])" } else { '' }
    $paa = Get-OrNewGroup -Name "$Name-PrincipalsAllowedAccess" -Description "Principals Allowed to retrieve password for $Name"
    Add-Member -Group $paa -Member $comp -What "$WorkerComputerName`$ (the worker needs a reboot or a Kerberos purge to see it)"
    $gm = Get-ADServiceAccount -Filter "Name -eq '$Name'" -ErrorAction SilentlyContinue
    if (-not $gm -and $PSCmdlet.ShouldProcess("$Name`$", "New-ADServiceAccount in '$GmsaOu'")) {
        $gm = New-ADServiceAccount -Name $Name -SamAccountName "$Name`$" -DNSHostName "$Name.$($dom.DNSRoot)" -KerberosEncryptionType AES256 `
            -PrincipalsAllowedToRetrieveManagedPassword "$Name-PrincipalsAllowedAccess" -Path $GmsaOu -Description ("{0}{1} | Used by {2}" -f $Purpose, $(if ($lt) { " ($lt)" } else { '' }), $UsedBy) -PassThru
        Info "gMSA $Name`$ created"
    } elseif ($gm) { Info "gMSA $Name`$ exists" }
    $pg = Get-OrNewGroup -Name "$Name-PermissionGroup" -Description "Permission-group for $Name"
    if ($gm) { Add-Member -Group $pg -Member (Get-ADServiceAccount -Identity $Name) -What "$Name`$" }
    return $pg
}
Step "identity $GmsaName (AD groups, JIT membership, admin accounts)"
$perm = Initialize-Identity -Name $GmsaName -Purpose 'PIM for AD: groups, just-in-time membership, admin accounts'
$srvPerm = $null
if ("$ServerGmsaName".Trim()) {
    Step "identity $ServerGmsaName (server onboarding)"
    $srvPerm = Initialize-Identity -Name $ServerGmsaName -Purpose 'PIM for AD: server local administrators / resource onboarding'
}

# 4. rights -- on the PermissionGroup (dsacls /G adds, never duplicates)
$who = "$net\$GmsaName-PermissionGroup"
function Grant-Ace([string]$Dn, [string[]]$Specs, [string]$Why) {
    foreach ($s in $Specs) {
        if ($PSCmdlet.ShouldProcess($Dn, "dsacls $s -> $who ($Why)")) {
            $a = $s -split ' ', 2
            $out = & dsacls.exe $Dn $a[0] /G "$($who):$($a[1])" 2>&1
            if ($LASTEXITCODE -ne 0) { throw "dsacls failed on '$Dn' ($s): $($out -join ' ')" }
        }
    }
    Info "$Why -> $Dn"
}
Grant-Ace -Dn $GroupsOu -Why 'PIM-for-AD groups: create + member/displayName/description' -Specs @('/I:T CC;group', '/I:S RPWP;member;group', '/I:S RPWP;displayName;group', '/I:S RPWP;description;group')
foreach ($ou in @($AdminAccountsOu | Where-Object { "$_".Trim() })) {
    Grant-Ace -Dn $ou -Why 'admin accounts: create users + full control of the users below' -Specs @('/I:T CC;user', '/I:S GA;;user')
}
if ($GrantProtectedGroupMembership) {
    $sdh = "CN=AdminSDHolder,CN=System,$($dom.DistinguishedName)"
    Write-Host "     WARNING -- AdminSDHolder: '$who' may change the members of every protected group -- it is TIER 0 from here on." -ForegroundColor Yellow
    Grant-Ace -Dn $sdh -Why 'protected groups (adminCount=1): write member' -Specs @('/I:T RPWP;member')
    if ($TriggerSdProp -and $PSCmdlet.ShouldProcess($dom.PDCEmulator, 'runProtectAdminGroupsTask (apply AdminSDHolder now, not within the hour)')) {
        $root = [ADSI]"LDAP://$($dom.PDCEmulator)/RootDSE"; $root.Put('runProtectAdminGroupsTask', 1); $root.SetInfo(); Info 'SDProp triggered on the PDC'
    }
}

# 5. servers GPO: Restricted Groups "member of" BUILTIN\Administrators for the server identity's PermissionGroup
if ($srvPerm) {
    Import-Module GroupPolicy
    $gpoName = if ("$ServerAdminGpoName".Trim()) { "$ServerAdminGpoName".Trim() } else { "PIM for AD: $ServerGmsaName-PermissionGroup is local administrator (servers)" }
    Step "servers GPO '$gpoName'"
    $gpo = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
    if (-not $gpo -and $PSCmdlet.ShouldProcess($gpoName, 'New-GPO')) { $gpo = New-GPO -Name $gpoName -Comment "Adds $net\$ServerGmsaName-PermissionGroup to BUILTIN\Administrators (nothing removed). Owned by the $UsedBy setup." }
    if ($gpo) {
        $sidTxt = (Get-ADGroup -Identity "$ServerGmsaName-PermissionGroup").SID.Value
        $line = "*$sidTxt`__Memberof = *S-1-5-32-544"
        $dir = "\\$($dom.DNSRoot)\SYSVOL\$($dom.DNSRoot)\Policies\{$($gpo.Id)}\Machine\Microsoft\Windows NT\SecEdit"
        $inf = Join-Path $dir 'GptTmpl.inf'
        $cur = if (Test-Path $inf) { Get-Content -LiteralPath $inf -Encoding Unicode } else { @() }
        $wrote = $false
        if (@($cur | Where-Object { $_ -eq $line }).Count) { Info 'Restricted Groups entry present' }
        elseif ($PSCmdlet.ShouldProcess($inf, "write '$line'")) {
            New-Item -ItemType Directory -Force $dir | Out-Null
            $body = @('[Unicode]', 'Unicode=yes', '[Version]', 'signature="$CHICAGO$"', 'Revision=1', '[Group Membership]', $line)
            Set-Content -LiteralPath $inf -Value $body -Encoding Unicode
            $wrote = $true
            Info "Restricted Groups: $net\$ServerGmsaName-PermissionGroup -> BUILTIN\Administrators"
        }
        # the security CSE + a version bump, or clients never process the settings -- checked on EVERY run on its own (a run
        # that failed after writing the file must not leave a GPO clients ignore). .Contains, never -like: the value has [ ].
        $gpoDn = "CN={$($gpo.Id)},CN=Policies,CN=System,$($dom.DistinguishedName)"
        $o = Get-ADObject -Identity $gpoDn -Properties gPCMachineExtensionNames, versionNumber
        $cse = '[{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C9055D1C}]'
        $ext = "$($o.gPCMachineExtensionNames)"
        if (($wrote -or -not $ext.Contains($cse)) -and $PSCmdlet.ShouldProcess($gpoDn, 'security CSE + version bump')) {
            if (-not $ext.Contains($cse)) { $ext = "$ext$cse" }
            $ver = [int]$o.versionNumber + 1
            Set-ADObject -Identity $gpoDn -Replace @{ gPCMachineExtensionNames = $ext; versionNumber = $ver }
            $gptIni = "\\$($dom.DNSRoot)\SYSVOL\$($dom.DNSRoot)\Policies\{$($gpo.Id)}\GPT.INI"
            Set-Content -LiteralPath $gptIni -Value @('[General]', "Version=$ver") -Encoding ASCII
            Info "GPO version $ver (security settings extension registered)"
        } else { Info 'security settings extension registered' }
        foreach ($ou in @($ServerOu | Where-Object { "$_".Trim() })) {
            $linked = @((Get-GPInheritance -Target $ou).GpoLinks | Where-Object { $_.GpoId -eq $gpo.Id }).Count
            if ($linked) { Info "linked to $ou" }
            elseif ($PSCmdlet.ShouldProcess($ou, "New-GPLink '$gpoName'")) { New-GPLink -Guid $gpo.Id -Target $ou -LinkEnabled Yes | Out-Null; Info "linked to $ou -- effective at each server's next policy refresh (gpupdate /target:computer)" }
        }
    }
}

Write-Host ''
Write-Host ("[ad] done. On the worker: Install-PimHybridWorker.ps1 -GmsaName '{0}\{1}'{2} (it installs and TESTS each gMSA)." -f $net, $GmsaName, $(if ("$ServerGmsaName".Trim()) { " -ServerGmsaName '$net\$ServerGmsaName'" } else { '' })) -ForegroundColor Green
Write-Host "     Set in Manager > Settings > Hybrid Active Directory: OU for new AD groups = '$GroupsOu'" -ForegroundColor Green
