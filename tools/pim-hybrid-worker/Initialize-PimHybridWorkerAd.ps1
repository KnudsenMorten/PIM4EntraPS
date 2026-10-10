#Requires -Version 5.1
<#
.SYNOPSIS
    §80.2 PIMHYBRIDWRK -- the Active Directory half of the hybrid worker: its gMSA identities, the rights they need, the
    servers GPO, and (optionally) an offline domain-join blob for the worker VM.

.DESCRIPTION
    Run on a domain controller, or on any domain-joined host, as an account with rights to create gMSAs, groups, GPOs
    and OU permissions. No ActiveDirectory PowerShell module: directory reads/writes are LDAP via .NET
    (System.DirectoryServices); dsacls.exe sets the OU rights. Two in-box modules remain, each behind one rare step
    (REQ 100.42, both under the owner's exception of 2026-10-09 for on-prem AD / GroupPolicy on the hybrid worker):
    GroupPolicy only to CREATE the servers GPO the first time, and Kds only behind the opt-in -CreateKdsRootKey. Every
    step is read-before-write and idempotent; -WhatIf prints the plan and changes nothing.

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
function Step($m) { Write-Host "[ad] $m" -ForegroundColor Cyan }
function Info($m) { Write-Host "     $m" -ForegroundColor Gray }

# ---------------------------------------------------------------------------------------------------------------------
# REQ 100.42 NO MODULES: every directory read/write below is plain LDAP through .NET (System.DirectoryServices) -- no
# ActiveDirectory module, no RSAT-AD-PowerShell. Each LDAP touch sits behind one small named helper so an offline test
# can stub it. Run on a domain-joined host as an account with the rights listed in the synopsis.
# ---------------------------------------------------------------------------------------------------------------------
Add-Type -AssemblyName System.DirectoryServices
function ConvertTo-PimLdapFilterValue([string]$Value) {
    # RFC 4515 escaping -- names are validated, but a filter is never built from an unescaped value.
    return ($Value -replace '\\', '\5c' -replace '\*', '\2a' -replace '\(', '\28' -replace '\)', '\29' -replace "`0", '\00')
}
function Get-PimAdEntry([string]$Dn) { return (New-Object System.DirectoryServices.DirectoryEntry("LDAP://$Dn")) }
function Test-PimAdDnExists([string]$Dn) { return [System.DirectoryServices.DirectoryEntry]::Exists("LDAP://$Dn") }
function Get-PimAdDomainInfo {
    $root = Get-PimAdEntry 'RootDSE'
    $dn = "$($root.Properties['defaultNamingContext'].Value)"
    $cfgNc = "$($root.Properties['configurationNamingContext'].Value)"
    $d = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
    $s = New-Object System.DirectoryServices.DirectorySearcher((Get-PimAdEntry "CN=Partitions,$cfgNc"), "(&(objectClass=crossRef)(nCName=$(ConvertTo-PimLdapFilterValue $dn)))", [string[]]@('nETBIOSName'))
    $x = $s.FindOne()
    $netb = if ($x) { "$($x.Properties['netbiosname'][0])" } else { (($d.Name -split '\.')[0]).ToUpperInvariant() }
    return [pscustomobject]@{ DNSRoot = $d.Name; NetBIOSName = $netb; PDCEmulator = $d.PdcRoleOwner.Name; DistinguishedName = $dn; ConfigurationNamingContext = $cfgNc }
}
function Find-PimAdObject([string]$LdapFilter, [string]$SearchBase) {
    # One object (or $null) as Name / DistinguishedName / SID -- the fields this script uses.
    $s = New-Object System.DirectoryServices.DirectorySearcher((Get-PimAdEntry $SearchBase), $LdapFilter, [string[]]@('distinguishedName', 'name', 'objectSid'))
    $s.SearchScope = [System.DirectoryServices.SearchScope]::Subtree
    $r = $s.FindOne()
    if (-not $r) { return $null }
    $sid = $null; if ($r.Properties['objectsid'].Count) { $sid = New-Object System.Security.Principal.SecurityIdentifier([byte[]]$r.Properties['objectsid'][0], 0) }
    return [pscustomobject]@{ Name = "$($r.Properties['name'][0])"; DistinguishedName = "$($r.Properties['distinguishedname'][0])"; SID = $sid }
}
function Get-PimAdObjectByDn([string]$Dn) { return (Find-PimAdObject -LdapFilter '(objectClass=*)' -SearchBase $Dn) }
function Test-PimAdKdsRootKey([object]$Domain) {
    # Get-KdsRootKey without the Kds module: the root keys are msKds-ProvRootKey objects in the configuration partition.
    $base = "CN=Master Root Keys,CN=Group Key Distribution Service,CN=Services,$($Domain.ConfigurationNamingContext)"
    if (-not (Test-PimAdDnExists $base)) { return 0 }
    $s = New-Object System.DirectoryServices.DirectorySearcher((Get-PimAdEntry $base), '(objectClass=msKds-ProvRootKey)', [string[]]@('cn'))
    $s.SearchScope = [System.DirectoryServices.SearchScope]::OneLevel
    return @($s.FindAll()).Count
}
function Test-PimAdPamFeatureEnabled([object]$Domain) {
    $dn = "CN=Privileged Access Management Feature,CN=Optional Features,CN=Directory Service,CN=Windows NT,CN=Services,$($Domain.ConfigurationNamingContext)"
    if (-not (Test-PimAdDnExists $dn)) { return $false }
    return ((Get-PimAdEntry $dn).Properties['msDS-EnabledFeatureBL'].Count -gt 0)
}
function New-PimAdGroupObject([string]$Name, [string]$Ou, [string]$Description) {
    $e = (Get-PimAdEntry $Ou).Children.Add("CN=$Name", 'group')
    [void]$e.Properties['sAMAccountName'].Add($Name)
    [void]$e.Properties['groupType'].Add([int]-2147483646)   # 0x80000002 = global security group
    if ("$Description".Trim()) { [void]$e.Properties['description'].Add($Description) }
    $e.CommitChanges()
    return (Get-PimAdObjectByDn "CN=$Name,$Ou")
}
function Test-PimAdGroupHasMember([object]$Group, [object]$Member) {
    foreach ($m in @((Get-PimAdEntry $Group.DistinguishedName).Properties['member'])) { if ("$m" -ieq "$($Member.DistinguishedName)") { return $true } }
    return $false
}
function Add-PimAdGroupMember([object]$Group, [object]$Member) {
    $e = Get-PimAdEntry $Group.DistinguishedName
    [void]$e.Properties['member'].Add("$($Member.DistinguishedName)")
    $e.CommitChanges()
}
function New-PimAdGmsaObject([string]$Name, [string]$Ou, [string]$DnsHostName, [object]$AllowedPrincipal, [string]$Description) {
    # New-ADServiceAccount without the module: an msDS-GroupManagedServiceAccount object. AES256 only (msDS-SupportedEncryptionTypes
    # 0x10), 30-day password interval, WORKSTATION_TRUST_ACCOUNT (4096), and msDS-GroupMSAMembership = the security descriptor
    # naming who may retrieve the password (owner BUILTIN\Administrators, one allow ACE for the PrincipalsAllowedAccess group).
    if (-not $AllowedPrincipal -or -not $AllowedPrincipal.SID) { throw "gMSA ${Name}: the PrincipalsAllowedAccess group must exist before the gMSA" }
    $sd = New-Object System.Security.AccessControl.RawSecurityDescriptor("O:S-1-5-32-544D:(A;;0x3;;;$($AllowedPrincipal.SID.Value))")
    $bin = New-Object byte[] $sd.BinaryLength; $sd.GetBinaryForm($bin, 0)
    $e = (Get-PimAdEntry $Ou).Children.Add("CN=$Name", 'msDS-GroupManagedServiceAccount')
    [void]$e.Properties['sAMAccountName'].Add("$Name`$")
    [void]$e.Properties['dNSHostName'].Add($DnsHostName)
    [void]$e.Properties['userAccountControl'].Add([int]4096)
    [void]$e.Properties['msDS-ManagedPasswordInterval'].Add([int]30)
    [void]$e.Properties['msDS-SupportedEncryptionTypes'].Add([int]16)
    [void]$e.Properties['msDS-GroupMSAMembership'].Add($bin)
    if ("$Description".Trim()) { [void]$e.Properties['description'].Add($Description) }
    $e.CommitChanges()
    return (Get-PimAdObjectByDn "CN=$Name,$Ou")
}
function Find-PimAdGpo([string]$DisplayName, [object]$Domain) {
    # Get-GPO -Name without the module: the groupPolicyContainer whose displayName matches; Id = its cn without braces.
    $s = New-Object System.DirectoryServices.DirectorySearcher((Get-PimAdEntry "CN=Policies,CN=System,$($Domain.DistinguishedName)"), "(&(objectClass=groupPolicyContainer)(displayName=$(ConvertTo-PimLdapFilterValue $DisplayName)))", [string[]]@('cn'))
    $s.SearchScope = [System.DirectoryServices.SearchScope]::OneLevel
    $r = $s.FindOne()
    if (-not $r) { return $null }
    return [pscustomobject]@{ Id = [guid]("$($r.Properties['cn'][0])".Trim('{', '}')); DisplayName = $DisplayName }
}
function New-PimAdGpo([string]$DisplayName, [string]$Comment) {
    # owner exception 2026-10-09, framework §12.17 -- GroupPolicy module (GPO create/link) on the hybrid worker only
    # (GroupPolicy has no .NET API). CREATING a GPO means a groupPolicyContainer plus its SYSVOL folder with matching ACLs (what GPMC does); hand-writing both is fragile, so this ONE step still uses
    # the GroupPolicy module, and only when the GPO does not exist yet. Reading, the CSE/version bump and linking are LDAP.
    Import-Module GroupPolicy
    $g = New-GPO -Name $DisplayName -Comment $Comment
    return [pscustomobject]@{ Id = [guid]$g.Id; DisplayName = $DisplayName }
}
function Test-PimAdGpoLinked([string]$Ou, [guid]$GpoId) {
    $cur = "$((Get-PimAdEntry $Ou).Properties['gPLink'].Value)"
    return $cur.ToLowerInvariant().Contains(("cn={{{0}}},cn=policies,cn=system," -f $GpoId.ToString()).ToLowerInvariant())
}
function Add-PimAdGpoLink([string]$Ou, [guid]$GpoId, [object]$Domain) {
    # New-GPLink -LinkEnabled Yes without the module: gPLink lists links lowest-precedence FIRST, so a new link (order = last,
    # like New-GPLink) is PREPENDED. Flag 0 = enabled, not enforced.
    $e = Get-PimAdEntry $Ou
    $cur = "$($e.Properties['gPLink'].Value)"
    $e.Properties['gPLink'].Value = ("[LDAP://cn={{{0}}},cn=policies,cn=system,{1};0]" -f $GpoId.ToString(), $Domain.DistinguishedName) + $cur
    $e.CommitChanges()
}
function Get-PimAdGpoVersionState([string]$GpoDn) {
    $e = Get-PimAdEntry $GpoDn
    return [pscustomobject]@{ gPCMachineExtensionNames = "$($e.Properties['gPCMachineExtensionNames'].Value)"; versionNumber = [int]"0$($e.Properties['versionNumber'].Value)" }
}
function Set-PimAdGpoVersionState([string]$GpoDn, [string]$Extensions, [int]$Version) {
    $e = Get-PimAdEntry $GpoDn
    $e.Properties['gPCMachineExtensionNames'].Value = $Extensions
    $e.Properties['versionNumber'].Value = $Version
    $e.CommitChanges()
}

$dom = Get-PimAdDomainInfo
$net = $dom.NetBIOSName
Step "domain $($dom.DNSRoot) ($net), PDC $($dom.PDCEmulator)"
if ("$ServerGmsaName".Trim() -and -not @($ServerOu | Where-Object { "$_".Trim() }).Count) { throw '-ServerGmsaName needs -ServerOu: the OU(s) whose servers get its PermissionGroup as local administrator (the GPO)' }
if ("$ServerGmsaName".Trim() -ieq $GmsaName) { throw '-ServerGmsaName must differ from -GmsaName: server onboarding is a separate tier' }
foreach ($ou in @($ComputerOu, $GmsaOu, $GroupsOu) + @($AdminAccountsOu) + @($ServerOu)) {
    if (-not "$ou".Trim()) { continue }
    if (-not (Test-PimAdDnExists $ou)) { throw "OU not found: '$ou'" }
}

# 1. KDS root key
$kdsCount = Test-PimAdKdsRootKey -Domain $dom
if (-not $kdsCount) {
    if (-not $CreateKdsRootKey) { throw 'No KDS root key: a gMSA cannot exist without one. Re-run with -CreateKdsRootKey (forest-wide; effective after replication, ~10 h unless backdated), or create it yourself.' }
    # owner exception 2026-10-09, framework §12.17 -- on-prem AD / GroupPolicy on the hybrid worker (KDS root key: opt-in, Tier-0 box)
    # The KDS root key is generated by the Key Distribution Service itself (no LDAP/.NET way to mint one), so Add-KdsRootKey
    # (the in-box Kds module) stays ONLY behind the opt-in -CreateKdsRootKey, a one-time forest operation.
    if ($PSCmdlet.ShouldProcess('forest', 'Add-KdsRootKey (effective in 10 hours)')) { Add-KdsRootKey -EffectiveImmediately | Out-Null; Info 'KDS root key created -- gMSA password retrieval works once it has replicated.' }
} else { Info "KDS root key present ($kdsCount)" }

# PAM feature: detect, never enable
$pam = Test-PimAdPamFeatureEnabled -Domain $dom
Info ("AD Privileged Access Management feature: {0}" -f $(if ($pam) { 'ENABLED -- JIT membership will carry a TTL' } else { 'not enabled -- JIT membership is plain; the sync removes it (this script never enables PAM: it is irreversible)' }))

# 2. worker computer + offline domain-join blob
$comp = Find-PimAdObject -LdapFilter "(&(objectCategory=computer)(name=$(ConvertTo-PimLdapFilterValue $WorkerComputerName)))" -SearchBase $dom.DistinguishedName
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
        $comp = Find-PimAdObject -LdapFilter "(&(objectCategory=computer)(name=$(ConvertTo-PimLdapFilterValue $WorkerComputerName)))" -SearchBase $dom.DistinguishedName
    }
} elseif (-not $comp) { Info "computer '$WorkerComputerName' does not exist yet (join it first, or use -ProvisionOdj) -- the PrincipalsAllowedAccess groups are created empty" }

# 3. identities: gMSA + <name>-PermissionGroup + <name>-PrincipalsAllowedAccess
function Get-OrNewGroup([string]$Name, [string]$Description) {
    $g = Find-PimAdObject -LdapFilter "(&(objectCategory=group)(name=$(ConvertTo-PimLdapFilterValue $Name)))" -SearchBase $dom.DistinguishedName
    if (-not $g -and $PSCmdlet.ShouldProcess($Name, "create global security group in '$GmsaOu'")) {
        $g = New-PimAdGroupObject -Name $Name -Ou $GmsaOu -Description $Description
        Info "group $Name created"
    } elseif ($g) { Info "group $Name exists" }
    return $g
}
function Add-Member([object]$Group, [object]$Member, [string]$What) {
    if (-not $Group -or -not $Member) { return }
    if (Test-PimAdGroupHasMember -Group $Group -Member $Member) { Info "$What already in $($Group.Name)"; return }
    if ($PSCmdlet.ShouldProcess($Group.Name, "add $What")) { Add-PimAdGroupMember -Group $Group -Member $Member; Info "$What added to $($Group.Name)" }
}
function Initialize-Identity([string]$Name, [string]$Purpose) {
    $lt = if ($Name -match '-(L\d)-(T\d)$') { "$($Matches[1]), $($Matches[2])" } else { '' }
    $paa = Get-OrNewGroup -Name "$Name-PrincipalsAllowedAccess" -Description "Principals Allowed to retrieve password for $Name"
    Add-Member -Group $paa -Member $comp -What "$WorkerComputerName`$ (the worker needs a reboot or a Kerberos purge to see it)"
    $gm = Find-PimAdObject -LdapFilter "(&(objectClass=msDS-GroupManagedServiceAccount)(name=$(ConvertTo-PimLdapFilterValue $Name)))" -SearchBase $dom.DistinguishedName
    if (-not $gm -and $PSCmdlet.ShouldProcess("$Name`$", "create gMSA in '$GmsaOu'")) {
        # the gMSA trusts "$Name-PrincipalsAllowedAccess" (msDS-GroupMSAMembership): only its members retrieve the password
        $gm = New-PimAdGmsaObject -Name $Name -Ou $GmsaOu -DnsHostName "$Name.$($dom.DNSRoot)" -AllowedPrincipal $paa `
            -Description ("{0}{1} | Used by {2}" -f $Purpose, $(if ($lt) { " ($lt)" } else { '' }), $UsedBy)
        Info "gMSA $Name`$ created"
    } elseif ($gm) { Info "gMSA $Name`$ exists" }
    $pg = Get-OrNewGroup -Name "$Name-PermissionGroup" -Description "Permission-group for $Name"
    if ($gm) { Add-Member -Group $pg -Member $gm -What "$Name`$" }
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
# READ on the OU itself first (2026-10-04, internal: the Delegation Groups OU had inheritance OFF, so the worker could
# not even see it and every create failed with "Cannot find an object with identity").
Grant-Ace -Dn $GroupsOu -Why 'PIM-for-AD groups: read the OU + create + member/displayName/description' -Specs @('/I:T GR', '/I:T CC;group', '/I:S RPWP;member;group', '/I:S RPWP;displayName;group', '/I:S RPWP;description;group')
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
    $gpoName = if ("$ServerAdminGpoName".Trim()) { "$ServerAdminGpoName".Trim() } else { "PIM for AD: $ServerGmsaName-PermissionGroup is local administrator (servers)" }
    Step "servers GPO '$gpoName'"
    $gpo = Find-PimAdGpo -DisplayName $gpoName -Domain $dom
    if (-not $gpo -and $PSCmdlet.ShouldProcess($gpoName, 'New-GPO')) { $gpo = New-PimAdGpo -DisplayName $gpoName -Comment "Adds $net\$ServerGmsaName-PermissionGroup to BUILTIN\Administrators (nothing removed). Owned by the $UsedBy setup." }
    if ($gpo) {
        $sidTxt = $srvPerm.SID.Value
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
        $o = Get-PimAdGpoVersionState -GpoDn $gpoDn
        $cse = '[{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C9055D1C}]'
        $ext = "$($o.gPCMachineExtensionNames)"
        if (($wrote -or -not $ext.Contains($cse)) -and $PSCmdlet.ShouldProcess($gpoDn, 'security CSE + version bump')) {
            if (-not $ext.Contains($cse)) { $ext = "$ext$cse" }
            $ver = [int]$o.versionNumber + 1
            Set-PimAdGpoVersionState -GpoDn $gpoDn -Extensions $ext -Version $ver
            $gptIni = "\\$($dom.DNSRoot)\SYSVOL\$($dom.DNSRoot)\Policies\{$($gpo.Id)}\GPT.INI"
            Set-Content -LiteralPath $gptIni -Value @('[General]', "Version=$ver") -Encoding ASCII
            Info "GPO version $ver (security settings extension registered)"
        } else { Info 'security settings extension registered' }
        foreach ($ou in @($ServerOu | Where-Object { "$_".Trim() })) {
            $linked = Test-PimAdGpoLinked -Ou $ou -GpoId $gpo.Id
            if ($linked) { Info "linked to $ou" }
            elseif ($PSCmdlet.ShouldProcess($ou, "New-GPLink '$gpoName'")) { Add-PimAdGpoLink -Ou $ou -GpoId $gpo.Id -Domain $dom; Info "linked to $ou -- effective at each server's next policy refresh (gpupdate /target:computer)" }
        }
    }
}

Write-Host ''
Write-Host ("[ad] done. On the worker: Install-PimHybridWorker.ps1 -GmsaName '{0}\{1}'{2} (it installs and TESTS each gMSA)." -f $net, $GmsaName, $(if ("$ServerGmsaName".Trim()) { " -ServerGmsaName '$net\$ServerGmsaName'" } else { '' })) -ForegroundColor Green
Write-Host "     Set in Manager > Settings > Hybrid Active Directory: OU for new AD groups = '$GroupsOu'" -ForegroundColor Green
