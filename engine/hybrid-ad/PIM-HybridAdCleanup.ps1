<#
  PIM-HybridAdCleanup.ps1 -- PIM 100.123 (a) + (b), owner 2026-10-13 (lane adclean): OLD PIM GROUPS LEFT IN ACTIVE
  DIRECTORY -- A REVIEWED CLEAN-UP, AND "DELETE IN AD TOO".

  Until now nothing in the product ever deleted an AD group: a group deleted in PIM Manager stayed in AD (and stayed local
  administrator on its server). This file is the ONLY place that deletes an AD group, and it does so only for an exact
  list a SuperAdmin approved:

    1. REPORT (every 'hybrid-ad-groups' run): the worker lists the AD groups that match the mirrored naming pattern, lie in
       the configured OUs (the OU for new AD groups + setting HybridAdCleanupOus) and have NO definition in PIM Manager,
       each with its members, the groups it is a member of, its server and its dates -> tenant cache 'ad-cleanup-candidates'.
    2. REVIEW (Manager, SuperAdmin): the page shows that list; a SuperAdmin approves an exact selection. The Manager
       writes settings row 'HybridAdCleanupApproval' from the worker's report (never from what the browser sent).
    3. DELETE (the next run): only the approved groups, each checked again -- see Get-PimHybridAdCleanupDecision for the
       conditions that must ALL hold. Anything else is skipped with the reason. Every deletion is logged three ways: a
       line in the worker log, an audit event in the store, and the result record 'AdCleanupResult' the page shows.

  The tier split is kept: the SERVER lane ('hybrid-ad-servers', the server identity) takes an approved per-server group
  out of its server's local Administrators (Invoke-PimHybridAdCleanupLocalAdminStep); the GROUPS lane ('hybrid-ad-groups')
  deletes the AD object afterwards. The group object is deleted as it is, with its members: where the forest has the AD
  recycle bin, restoring the object brings the members back.

  "Delete in AD too": a SuperAdmin can ask, for a group that is DEFINED now and is being deleted in PIM Manager, that its
  AD group goes as well ('HybridAdCleanupApproval'.alsoDelete). The worker acts on it only once the definition is gone
  AND the Entra group of that name is gone -- until then it waits.

  FAIL CLOSED everywhere: no OU configured, a pattern that is too wide, definitions not readable (or a store without any
  group definition), AD not readable, an approval that cannot be read = nothing is proposed and nothing is deleted.
  Never automatic, never by name pattern alone, nothing outside the configured OUs. No ActiveDirectory module.
  Needs PIM-HybridAd.ps1, PIM-HybridAdGroups.ps1 and PIM-HybridAdServerDiscovery.ps1 loaded first.
#>

function Get-PimHybridAdCleanupApprovalMaxHours { return 72 }      # an approval of the reviewed list is used for this long, then it is dead
function Get-PimHybridAdCleanupAlsoDeleteMaxDays { return 30 }     # a "delete in AD too" request waits this long for the definition + Entra group to go

function Get-PimHybridAdCleanupEpoch {
    param([datetime]$NowUtc = [datetime]::UtcNow)
    return [long][math]::Floor(($NowUtc.ToUniversalTime() - [datetime]::SpecifyKind([datetime]'1970-01-01', [DateTimeKind]::Utc)).TotalSeconds)
}

function Get-PimHybridAdCleanupField {
    # PURE. One field of a hashtable / parsed-JSON object; $null when absent.
    param($Object, [string]$Name)
    if ($null -eq $Object) { return $null }
    if ($Object -is [System.Collections.IDictionary]) { if ($Object.Contains($Name)) { return $Object[$Name] } else { return $null } }
    $p = $Object.PSObject.Properties[$Name]
    if ($p) { return $p.Value }
    return $null
}

function ConvertTo-PimHybridAdCleanupMap {
    # PURE. A hashtable / parsed-JSON object -> hashtable (its own property names as keys). $null -> @{}.
    param($Object)
    $h = @{}
    if ($null -eq $Object) { return $h }
    if ($Object -is [System.Collections.IDictionary]) { foreach ($k in @($Object.Keys)) { $h["$k"] = $Object[$k] }; return $h }
    foreach ($p in @($Object.PSObject.Properties)) { $h["$($p.Name)"] = $p.Value }
    return $h
}

function Get-PimHybridAdCleanupId {
    # PURE. The identity of one AD group object for an approval: where it is + when it was created. An object that was
    # moved, or deleted and created again under the same name, has another id -- an approval never follows it.
    param([string]$Dn, [string]$Created)
    return ("{0}|{1}" -f (ConvertTo-PimHybridAdDnKey $Dn), "$Created".Trim())
}

function Get-PimHybridAdCleanupScope {
    <#
      Where old PIM groups may be looked for and deleted: the OU for new AD groups (setting HybridAdGroupsOu) plus the
      OUs of setting HybridAdCleanupOus. Returns @{ ok; ous[]; reason }. No OU = not ok: the clean-up then proposes and
      deletes NOTHING (it never falls back to the whole domain). -GroupsOu / -CleanupOus are the seams for tests.
    #>
    param([AllowNull()][object]$GroupsOu = $null, [AllowNull()][object]$CleanupOus = $null)
    if ($null -eq $GroupsOu) { $GroupsOu = "$(Get-PimHybridAdDiscoveryRawSetting -Name 'HybridAdGroupsOu' -Default '')" }
    if ($null -eq $CleanupOus) { $CleanupOus = @((Get-PimHybridAdServerDiscoverySettings).cleanupOus) }
    $dnRx = '^(?i)(OU|CN)=[^,]+(,(OU|CN)=[^,]+)*,DC=[^,]+(,DC=[^,]+)*$'
    $seen = @{}; $ous = New-Object System.Collections.Generic.List[string]
    foreach ($o in @("$GroupsOu".Trim()) + @($CleanupOus)) {
        $v = "$o".Trim()
        if (-not $v -or $v -notmatch $dnRx) { continue }
        $k = ConvertTo-PimHybridAdDnKey $v
        if ($seen.ContainsKey($k)) { continue }
        $seen[$k] = $true; $ous.Add($v)
    }
    if (-not $ous.Count) { return @{ ok = $false; ous = @(); reason = 'no OU is configured (Settings > Hybrid Active Directory: OU for new AD groups, or Clean-up: also look in these OUs)' } }
    return @{ ok = $true; ous = $ous.ToArray(); reason = '' }
}

function Test-PimHybridAdCleanupPattern {
    # PURE. A mirrored pattern the clean-up may work with: it must hold at least three characters that are not wildcards.
    param([string]$Pattern)
    return ((("$Pattern" -replace '[*?\s]', '')).Length -ge 3)
}

function Get-PimHybridAdServerNameFromGroup {
    # PURE. The server a per-server group belongs to, from the customer's group format (-ServerPattern = the format with
    # {server} = *). '' when the name is not a per-server group.
    param([string]$GroupName, [string]$ServerPattern)
    $sp = "$ServerPattern".Trim()
    if (-not $sp -or $sp -notmatch '\*') { return '' }
    $rx = '^' + ([regex]::Escape($sp) -replace '\\\*', '(.+)') + '$'
    $m = [regex]::Match("$GroupName".Trim(), $rx, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    if ($m.Success) { return $m.Groups[1].Value }
    return ''
}

function Get-PimHybridAdCleanupProtectedNames {
    # The group names the clean-up never offers: the shared server-admins group of the settings (a PIM group by name, but
    # the customer's own standing group). Lower case -> $true.
    $h = @{}
    $shared = "$(Get-PimHybridAdDiscoveryRawSetting -Name 'HybridAdServerAdminsGroup' -Default '')".Trim()
    if ($shared) { $h[(($shared -split '\\')[-1]).ToLowerInvariant()] = $true }
    return $h
}

function Get-PimHybridAdCleanupProtectedReason {
    # PURE. Why this AD group is never deleted by the clean-up ('' = it may be).
    param($Group, [hashtable]$Protected = @{})
    $n = "$($Group.Name)".Trim()
    if ("$($Group.adminCount)" -eq '1') { return 'protected by Active Directory (adminCount = 1: it is, or was, nested in a protected group such as Domain Admins)' }
    if ("$($Group.critical)" -match '^(?i)true$') { return 'a critical system object of Active Directory' }
    if ($Protected.ContainsKey($n.ToLowerInvariant())) { return 'the shared server-admins group of the settings' }
    if ($n -match '(?i)-(PermissionGroup|PrincipalsAllowedAccess)$') { return 'a group of a worker identity' }
    return ''
}

function Get-PimHybridAdCleanupCandidates {
    <#
      PURE. The removal candidates: AD groups (-AdGroups: Name, DistinguishedName, Created, Changed, adminCount, critical,
      Members[] (DNs), MemberOf[] (DNs), Description) that match -Pattern, lie below one of -Ous and have NO definition
      (-DefinedNames: lower name -> $true). Returns @{ ok; reason; candidates[]; notOffered[] { name; reason } }.
      ok = $false (and no candidate at all) unless: an OU is configured, the pattern is narrow enough, the definitions were
      read AND the store holds at least one group definition (an empty store is treated like an unreadable one), and AD
      was read. Each candidate: id; name; dn; created; changed; description; memberCount; members[] (at most 200);
      membersTruncated; memberOf[]; server ('' = not a per-server group); serverInAd ($true | $false | $null = not known).
    #>
    param([object[]]$AdGroups = @(), [bool]$AdOk = $false, [bool]$ScopeOk = $false, [string[]]$Ous = @(), [string]$ScopeReason = '',
          [bool]$DefinitionsOk = $false, [int]$DefinitionCount = 0, [hashtable]$DefinedNames = @{}, [string]$DefinitionsReason = '',
          [string]$Pattern = '', [hashtable]$Protected = @{}, [string]$ServerPattern = '', [bool]$ServersOk = $false, [hashtable]$ServerNames = @{})
    $bad = { param($why) return @{ ok = $false; reason = "$why"; candidates = @(); notOffered = @() } }
    if (-not $ScopeOk -or -not @($Ous).Count) { return (& $bad $(if ($ScopeReason) { $ScopeReason } else { 'no OU is configured' })) }
    if (-not (Test-PimHybridAdCleanupPattern $Pattern)) { return (& $bad "the pattern of the groups mirrored to Active Directory ('$Pattern') is too wide to clean up by") }
    if (-not $DefinitionsOk) { return (& $bad "the group definitions could not be read$(if ($DefinitionsReason) { ": $DefinitionsReason" })") }
    if ($DefinitionCount -le 0) { return (& $bad 'the store holds no group definition at all -- an empty store is treated like an unreadable one, so nothing is proposed') }
    if (-not $AdOk) { return (& $bad 'Active Directory could not be read') }
    $cand = New-Object System.Collections.Generic.List[object]; $no = New-Object System.Collections.Generic.List[object]
    foreach ($g in @($AdGroups)) {
        if ($null -eq $g) { continue }
        $name = "$($g.Name)".Trim(); $dn = "$($g.DistinguishedName)".Trim()
        if (-not $name -or $name -notlike $Pattern) { continue }
        if ($DefinedNames.ContainsKey($name.ToLowerInvariant())) { continue }                 # defined: not ours to offer
        if (-not $dn -or -not (Test-PimHybridAdDnUnderAny -Dn $dn -Ous $Ous)) { continue }    # outside the configured OUs: never offered, never named
        $why = Get-PimHybridAdCleanupProtectedReason -Group $g -Protected $Protected
        if ($why) { $no.Add([ordered]@{ name = $name; reason = $why }); continue }
        if (-not "$($g.Created)".Trim()) { $no.Add([ordered]@{ name = $name; reason = 'its creation date could not be read, so an approval could not be tied to this exact object' }); continue }
        $members = @($g.Members | Where-Object { "$_".Trim() } | ForEach-Object { "$_".Trim() })
        $server = Get-PimHybridAdServerNameFromGroup -GroupName $name -ServerPattern $ServerPattern
        $inAd = $null
        if ($server -and $ServersOk) { $inAd = [bool]$ServerNames.ContainsKey($server.ToLowerInvariant()) }
        $cand.Add([ordered]@{
                id = (Get-PimHybridAdCleanupId -Dn $dn -Created "$($g.Created)"); name = $name; dn = $dn; created = "$($g.Created)".Trim(); changed = "$($g.Changed)".Trim()
                description = "$($g.Description)"; memberCount = $members.Count; members = @($members | Select-Object -First 200); membersTruncated = [bool]($members.Count -gt 200)
                memberOf = @($g.MemberOf | Where-Object { "$_".Trim() } | ForEach-Object { "$_".Trim() }); server = $server; serverInAd = $inAd })
    }
    return @{ ok = $true; reason = ''; candidates = @($cand.ToArray() | Sort-Object { $_.name }); notOffered = $no.ToArray() }
}

function Get-PimHybridAdCleanupDecision {
    <#
      PURE. ONE approved group -> @{ action = 'delete' | 'skip' | 'wait' | 'gone' | 'expired'; reason }.
      -Kind 'reviewed' = an item of the list a SuperAdmin approved on the review page; 'also' = a "delete in AD too" request.

      The worker deletes an AD group only when ALL of this holds in THIS run:
        1. the approval names who approved and when (a number, seconds since 1970 UTC), is not dated more than 10 minutes
           in the future and is not older than 72 hours (reviewed) / 30 days (delete in AD too);
        2. at least one OU is configured (-ScopeOk);
        3. the definitions were read in this run AND the store holds at least one group definition;
        4. Active Directory was read in this run;
        5. the group's name still matches the mirrored naming pattern;
        6. NO definition of that name exists in PIM Manager (a group that gained a definition since the review is skipped);
        7. exactly ONE AD group carries the name (none = already gone; two = skipped);
        8. that group lies below one of the configured OUs;
        9. (reviewed) it is the SAME object that was reviewed: same distinguished name, same creation date;
       10. it is not protected (adminCount = 1, critical system object, the shared server-admins group, a worker group);
       11. (reviewed) it has no member and no "member of" that the reviewer did not see;
       12. (delete in AD too) the Entra group of that name is confirmed gone (-EntraExists $false; unknown = wait);
       13. for a per-server group: its server no longer has it in local Administrators (the server lane reported
           'removed' / 'not a member'), or the server is not in Active Directory any more, or the SuperAdmin ticked
           "delete even if the server cannot be reached" (-Item.withoutServer).
    #>
    param([Parameter(Mandatory)][hashtable]$Item, [ValidateSet('reviewed', 'also')][string]$Kind = 'reviewed', [long]$NowEpoch = 0,
          [bool]$ScopeOk = $false, [string[]]$Ous = @(), [bool]$DefinitionsOk = $false, [int]$DefinitionCount = 0, [hashtable]$DefinedNames = @{},
          [string]$Pattern = '', [bool]$AdOk = $false, [hashtable]$AdGroupsByName = @{}, [hashtable]$Protected = @{},
          [string]$ServerPattern = '', [bool]$ServersOk = $false, [hashtable]$ServerNames = @{}, [hashtable]$LocalAdmin = @{}, [object]$EntraExists = $null)
    $r = { param($a, $why) return @{ action = "$a"; reason = "$why" } }
    $name = "$($Item.name)".Trim()
    if (-not $name) { return (& $r 'skip' 'the approval names no group') }
    $by = "$($Item.by)".Trim()
    if (-not $by) { return (& $r 'skip' 'the approval does not say who approved it') }
    $at = [long]0
    if ($Item.atEpoch -is [string] -or $null -eq $Item.atEpoch -or -not [long]::TryParse("$($Item.atEpoch)", [ref]$at) -or $at -le 0) { return (& $r 'skip' 'the approval carries no usable time') }
    if ($at -gt ($NowEpoch + 600)) { return (& $r 'skip' 'the approval is dated in the future') }
    $maxSec = if ($Kind -eq 'also') { [long](Get-PimHybridAdCleanupAlsoDeleteMaxDays) * 86400 } else { [long](Get-PimHybridAdCleanupApprovalMaxHours) * 3600 }
    if (($NowEpoch - $at) -gt $maxSec) { return (& $r 'expired' $(if ($Kind -eq 'also') { "the request is older than $(Get-PimHybridAdCleanupAlsoDeleteMaxDays) days" } else { "the approval is older than $(Get-PimHybridAdCleanupApprovalMaxHours) hours -- review the list again" })) }
    if (-not $ScopeOk -or -not @($Ous).Count) { return (& $r 'skip' 'no OU is configured for the clean-up') }
    if (-not $DefinitionsOk) { return (& $r 'skip' 'the group definitions could not be read in this run') }
    if ($DefinitionCount -le 0) { return (& $r 'skip' 'the store holds no group definition at all (treated like an unreadable store)') }
    if (-not $AdOk) { return (& $r 'skip' 'Active Directory could not be read in this run') }
    if (-not (Test-PimHybridAdCleanupPattern $Pattern) -or $name -notlike $Pattern) { return (& $r 'skip' "the name does not match the groups mirrored to Active Directory ('$Pattern')") }
    if ($DefinedNames.ContainsKey($name.ToLowerInvariant())) {
        if ($Kind -eq 'also') { return (& $r 'wait' 'the group is still defined in PIM Manager -- its AD group goes after the definition is deleted') }
        return (& $r 'skip' 'a definition of this name exists in PIM Manager (it gained one since the review) -- not deleted')
    }
    $found = @(); if ($AdGroupsByName.ContainsKey($name.ToLowerInvariant())) { $found = @($AdGroupsByName[$name.ToLowerInvariant()]) }
    if (-not $found.Count) { return (& $r 'gone' 'no AD group of this name exists any more') }
    if ($found.Count -gt 1) { return (& $r 'skip' "$($found.Count) AD groups carry this name -- none is deleted") }
    $g = $found[0]
    $dn = "$($g.DistinguishedName)".Trim()
    if (-not $dn -or -not (Test-PimHybridAdDnUnderAny -Dn $dn -Ous $Ous)) { return (& $r 'skip' 'the group is outside the configured OUs') }
    if ($Kind -eq 'reviewed') {
        if ((ConvertTo-PimHybridAdDnKey $dn) -ne (ConvertTo-PimHybridAdDnKey "$($Item.dn)") -or "$($g.Created)".Trim() -ne "$($Item.created)".Trim() -or -not "$($Item.created)".Trim()) {
            return (& $r 'skip' 'this is not the object that was reviewed (it was moved, or deleted and created again) -- review the list again')
        }
    }
    $why = Get-PimHybridAdCleanupProtectedReason -Group $g -Protected $Protected
    if ($why) { return (& $r 'skip' "never deleted: $why") }
    if ($Kind -eq 'reviewed') {
        $seen = @{}; foreach ($m in @($Item.members)) { if ("$m".Trim()) { $seen[(ConvertTo-PimHybridAdDnKey "$m")] = $true } }
        $now = @($g.Members | Where-Object { "$_".Trim() })
        $reviewedCount = 0; [void][int]::TryParse("$($Item.memberCount)", [ref]$reviewedCount)
        if ([bool]$Item.membersTruncated) { if ($now.Count -gt $reviewedCount) { return (& $r 'skip' 'the group has more members than when it was reviewed -- review the list again') } }
        else {
            $new = @($now | Where-Object { -not $seen.ContainsKey((ConvertTo-PimHybridAdDnKey "$_")) })
            if ($new.Count) { return (& $r 'skip' "the group gained $($new.Count) member(s) the reviewer did not see -- review the list again") }
        }
        $seenOf = @{}; foreach ($m in @($Item.memberOf)) { if ("$m".Trim()) { $seenOf[(ConvertTo-PimHybridAdDnKey "$m")] = $true } }
        $newOf = @($g.MemberOf | Where-Object { "$_".Trim() -and -not $seenOf.ContainsKey((ConvertTo-PimHybridAdDnKey "$_")) })
        if ($newOf.Count) { return (& $r 'skip' "the group became a member of $($newOf.Count) group(s) the reviewer did not see -- review the list again") }
    } else {
        if ($null -eq $EntraExists) { return (& $r 'wait' 'whether the Entra group of this name is gone could not be checked') }
        if ([bool]$EntraExists) { return (& $r 'wait' 'the Entra group of this name still exists -- the AD group goes after it') }
    }
    $server = Get-PimHybridAdServerNameFromGroup -GroupName $name -ServerPattern $ServerPattern
    if ($server -and -not [bool]$Item.withoutServer) {
        if (-not $ServersOk) { return (& $r 'wait' 'the servers of the domain could not be listed in this run') }
        if ($ServerNames.ContainsKey($server.ToLowerInvariant())) {
            $st = ''; if ($LocalAdmin.ContainsKey($name.ToLowerInvariant())) { $st = "$(Get-PimHybridAdCleanupField $LocalAdmin[$name.ToLowerInvariant()] 'status')".Trim().ToLowerInvariant() }
            if ($st -notin @('removed', 'not a member', 'server not in active directory')) {
                return (& $r 'wait' "its server $server has not confirmed that the group is out of local Administrators$(if ($st) { " ($st)" } else { ' (the server job has not run since the approval)' })")
            }
        }
    }
    return (& $r 'delete' '')
}

function Invoke-PimHybridAdLdapDeleteObject {
    # Delete ONE object by its distinguished name. Only a CN=... leaf is accepted (never an OU or a domain).
    param([Parameter(Mandatory)][string]$Dn, [string]$Server)
    if ("$Dn".Trim() -notmatch '^(?i)CN=') { throw "refusing to delete '$Dn': not a CN= object" }
    Initialize-PimHybridAdLdap
    $req = New-Object System.DirectoryServices.Protocols.DeleteRequest("$Dn".Trim())
    [void](Send-PimHybridAdLdapRequest -Request $req -Server $Server)
}

function Get-PimHybridAdLdapGroupsDetailed {
    # The groups matching -Pattern in the whole domain, with what the review shows. Created / Changed stay the directory's
    # own text (GeneralizedTime), so they compare exactly.
    param([Parameter(Mandatory)][string]$Pattern, [string]$Server)
    $rows = @(Get-PimHybridAdLdapGroups -Pattern $Pattern -Attributes @('description', 'adminCount', 'isCriticalSystemObject', 'whenCreated', 'whenChanged', 'member', 'memberOf') -Server $Server)
    return @(foreach ($r in $rows) {
            $one = { param($n) $v = @($r[$n]); if ($v.Count) { "$($v[0])" } else { '' } }
            [pscustomobject]@{ Name = (& $one 'name'); DistinguishedName = (& $one 'distinguishedname'); Description = (& $one 'description')
                adminCount = (& $one 'admincount'); critical = (& $one 'iscriticalsystemobject'); Created = (& $one 'whencreated'); Changed = (& $one 'whenchanged')
                Members = @($r['member']); MemberOf = @($r['memberof']) }
        })
}

function Get-PimHybridAdCleanupAdapter {
    <#
      [ ] HYBRID-WORKER-ONLY. The real directory calls of the clean-up -- LDAP through .NET, as the process identity (the
      gMSA). No factory locals in the blocks: they call functions only.
        GetGroups        { param($Pattern) }  the groups of that name pattern with members / member of / dates
        GetComputers     { }                  the Windows servers of the domain (to know whether a group's server exists)
        DeleteGroup      { param($Dn) }       delete that one group object
        EntraGroupExists { param($Name) }     $true | $false | $null (not known) -- only for "delete in AD too"
    #>
    if (-not (Test-PimHybridAdDirectoryAvailable)) { throw 'This host is not joined to an Active Directory domain -- the clean-up adapter is hybrid-worker-only.' }
    return @{
        GetGroups = {
            param([string]$Pattern)
            $s = Get-PimHybridAdServerSplat
            @(Get-PimHybridAdLdapGroupsDetailed -Pattern $Pattern @s)
        }
        GetComputers = {
            $s = Get-PimHybridAdServerSplat
            @(Get-PimHybridAdLdapComputersWithDn @s)
        }
        DeleteGroup = {
            param([string]$Dn)
            $s = Get-PimHybridAdServerSplat
            Invoke-PimHybridAdLdapDeleteObject -Dn $Dn @s
        }
        EntraGroupExists = {
            param([string]$Name)
            if (-not (Get-Command Invoke-PimGraph -ErrorAction SilentlyContinue)) { return $null }
            try {
                $esc = "$Name".Replace("'", "''")
                $hit = @(Invoke-PimGraph -Path "/groups?`$filter=displayName eq '$esc'&`$select=id,displayName" -All)
                return [bool]$hit.Count
            } catch { return $null }
        }
    }
}

function Get-PimHybridAdCleanupStore {
    <#
      The store seam of the clean-up: @{ Read = { param($name) -> parsed value | $null; THROWS when the store cannot be
      read }; Save = { param($name, $json) }; SaveCandidates = { param($doc) }; Audit = { param($action, $target, $after) } }
      -- or $null when this process has no store. PLAIN scriptblocks (they call functions only).
    #>
    $cs = Get-PimHybridAdStoreCs
    if (-not $cs -or -not (Get-Command Get-PimSqlSetting -ErrorAction SilentlyContinue) -or -not (Get-Command Set-PimSqlSetting -ErrorAction SilentlyContinue)) { return $null }
    return @{
        Read = { param($n) Get-PimSqlSetting -ConnectionString (Get-PimHybridAdStoreCs) -Name $n }
        Save = { param($n, $json) Set-PimSqlSetting -ConnectionString (Get-PimHybridAdStoreCs) -Name $n -ValueJson $json }
        SaveCandidates = { param($doc) Set-PimSqlTenantCache -ConnectionString (Get-PimHybridAdStoreCs) -Kind 'ad-cleanup-candidates' -Value $doc }
        Audit = {
            param($action, $target, $after)
            if (Get-Command Write-PimSqlAuditEvent -ErrorAction SilentlyContinue) {
                Write-PimSqlAuditEvent -ConnectionString (Get-PimHybridAdStoreCs) -Actor "hybrid-worker:$env:COMPUTERNAME" -ActorSource 'hybrid-ad clean-up (approved list)' -Action $action -Target $target -After $after -Result 'ok'
            }
        }
    }
}

function Read-PimHybridAdCleanupApproval {
    <#
      The approval record as the worker uses it: @{ ok; reason; reviewed[] ; also[] } -- each entry a hashtable in the
      shape Get-PimHybridAdCleanupDecision takes (name, dn, created, members, memberCount, membersTruncated, memberOf,
      withoutServer, by, atEpoch). ok = $false when the record could not be read or is not version 1: nothing is deleted.
      No record at all = ok with two empty lists.
    #>
    param([Parameter(Mandatory)][scriptblock]$Read)
    $raw = $null
    try { $raw = & $Read 'HybridAdCleanupApproval' } catch { return @{ ok = $false; reason = "the approval record could not be read: $($_.Exception.Message)"; reviewed = @(); also = @() } }
    if ($null -eq $raw) { return @{ ok = $true; reason = ''; reviewed = @(); also = @() } }
    if ($raw -is [string]) { try { $raw = $raw | ConvertFrom-Json } catch { return @{ ok = $false; reason = 'the approval record is not readable'; reviewed = @(); also = @() } } }
    if ("$(Get-PimHybridAdCleanupField $raw 'v')" -ne '1') { return @{ ok = $false; reason = 'the approval record has an unknown version'; reviewed = @(); also = @() } }
    $rev = New-Object System.Collections.Generic.List[object]; $also = New-Object System.Collections.Generic.List[object]
    $items = ConvertTo-PimHybridAdCleanupMap (Get-PimHybridAdCleanupField $raw 'items')
    foreach ($k in @($items.Keys)) {
        $x = $items[$k]; if ($null -eq $x) { continue }
        $rev.Add(@{ key = "$k"; name = "$(Get-PimHybridAdCleanupField $x 'name')"; dn = "$(Get-PimHybridAdCleanupField $x 'dn')"; created = "$(Get-PimHybridAdCleanupField $x 'created')"
                members = @(Get-PimHybridAdCleanupField $x 'members'); memberCount = (Get-PimHybridAdCleanupField $x 'memberCount'); membersTruncated = [bool](Get-PimHybridAdCleanupField $x 'membersTruncated')
                memberOf = @(Get-PimHybridAdCleanupField $x 'memberOf'); withoutServer = ((Get-PimHybridAdCleanupField $x 'withoutServer') -is [bool] -and [bool](Get-PimHybridAdCleanupField $x 'withoutServer'))
                by = "$(Get-PimHybridAdCleanupField $x 'approvedBy')"; atEpoch = (Get-PimHybridAdCleanupField $x 'approvedAtEpoch') })
    }
    $am = ConvertTo-PimHybridAdCleanupMap (Get-PimHybridAdCleanupField $raw 'alsoDelete')
    foreach ($k in @($am.Keys)) {
        $x = $am[$k]; if ($null -eq $x) { continue }
        $also.Add(@{ key = "also:$k"; name = "$(Get-PimHybridAdCleanupField $x 'name')"; withoutServer = $false
                by = "$(Get-PimHybridAdCleanupField $x 'requestedBy')"; atEpoch = (Get-PimHybridAdCleanupField $x 'requestedAtEpoch') })
    }
    return @{ ok = $true; reason = ''; reviewed = $rev.ToArray(); also = $also.ToArray() }
}

function Invoke-PimHybridAdCleanupJob {
    <#
      The clean-up half of the 'hybrid-ad-groups' run: report the candidates, then delete exactly the approved groups.
      Seams (tests): -Adapter (GetGroups, GetComputers, DeleteGroup, EntraGroupExists), -Store (Read, Save,
      SaveCandidates, Audit), -Rows (the definition rows), -GroupsOu / -CleanupOus, -Pattern, -ServerPattern.
      Returns @{ ran; detail; candidates; results[] { name; dn; status; reason } }. status: deleted | plan | skipped |
      waiting | gone | expired | failed. NEVER throws: the mirror job's own result is not affected by the clean-up.
    #>
    param([datetime]$NowUtc = [datetime]::UtcNow, [switch]$WhatIf, [hashtable]$Adapter, [hashtable]$Store, [object[]]$Rows = $null,
          [AllowNull()][object]$GroupsOu = $null, [AllowNull()][object]$CleanupOus = $null, [string]$Pattern = '', [string]$ServerPattern = '',
          [object]$AdModulePresent = $null, [scriptblock]$SecretReader)
    try {
        if (-not $Adapter) {
            $cap = Test-PimHybridAdWorkerCapability -AdModulePresent $AdModulePresent -SecretReader $SecretReader
            if (-not $cap.ok) { return [pscustomobject]@{ ran = $false; detail = ''; candidates = 0; results = @() } }
            $Adapter = Get-PimHybridAdCleanupAdapter
        }
        if (-not $Store) { $Store = Get-PimHybridAdCleanupStore }
        if (-not $Store) { return [pscustomobject]@{ ran = $false; detail = 'clean-up: this worker has no store connection -- nothing proposed, nothing deleted'; candidates = 0; results = @() } }
        $now = Get-PimHybridAdCleanupEpoch -NowUtc $NowUtc
        $scope = Get-PimHybridAdCleanupScope -GroupsOu $GroupsOu -CleanupOus $CleanupOus
        if (-not $Pattern) { $Pattern = "$(Get-PimHybridAdGroupPattern)" }
        if (-not $ServerPattern) { $ServerPattern = "$(Get-PimHybridAdServerGroupName -Server '*')" }
        $defs = Get-PimHybridAdAllGroupDefinitions -Rows $Rows
        $protected = Get-PimHybridAdCleanupProtectedNames
        $adGroups = @(); $adOk = $false; $adWhy = ''
        if ($scope.ok -and (Test-PimHybridAdCleanupPattern $Pattern)) {
            try { $adGroups = @(& $Adapter.GetGroups $Pattern); $adOk = $true } catch { $adOk = $false; $adWhy = "$($_.Exception.Message)" }
        }
        $serverNames = @{}; $serversOk = $false
        try { foreach ($c in @(& $Adapter.GetComputers)) { if ($c -and "$($c.Name)".Trim() -and [bool]$c.Enabled) { $serverNames["$($c.Name)".Trim().ToLowerInvariant()] = $true } }; $serversOk = $true } catch { $serversOk = $false }
        $byName = @{}
        foreach ($g in $adGroups) { if ($g -and "$($g.Name)".Trim()) { $k = "$($g.Name)".Trim().ToLowerInvariant(); if (-not $byName.ContainsKey($k)) { $byName[$k] = New-Object System.Collections.Generic.List[object] }; $byName[$k].Add($g) } }
        $byNameArr = @{}; foreach ($k in @($byName.Keys)) { $byNameArr[$k] = $byName[$k].ToArray() }

        # 1. the report
        $cand = Get-PimHybridAdCleanupCandidates -AdGroups $adGroups -AdOk $adOk -ScopeOk ([bool]$scope.ok) -Ous @($scope.ous) -ScopeReason "$($scope.reason)" `
            -DefinitionsOk ([bool]$defs.ok) -DefinitionCount @($defs.rows).Count -DefinedNames $defs.names -DefinitionsReason "$($defs.reason)" `
            -Pattern $Pattern -Protected $protected -ServerPattern $ServerPattern -ServersOk $serversOk -ServerNames $serverNames
        if (-not $cand.ok -and $adWhy) { $cand.reason = "$($cand.reason): $adWhy" }
        try {
            & $Store.SaveCandidates ([ordered]@{ v = 1; refreshedUtc = $NowUtc.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'); refreshedEpoch = $now; host = "$env:COMPUTERNAME"; planOnly = [bool]$WhatIf
                    ok = [bool]$cand.ok; reason = "$($cand.reason)"; ous = @($scope.ous); pattern = $Pattern; candidates = @($cand.candidates); notOffered = @($cand.notOffered) })
        } catch { Write-Warning "[hybrid-ad-cleanup] the candidate list was not saved: $($_.Exception.Message)" }

        # 2. the approved list
        $ap = Read-PimHybridAdCleanupApproval -Read $Store.Read
        $res = New-Object System.Collections.Generic.List[object]
        if (-not $ap.ok) { Write-Warning "[hybrid-ad-cleanup] nothing is deleted in this run: $($ap.reason)" }
        $la = @{}
        try { $laRaw = & $Store.Read 'AdCleanupLocalAdmin'; if ($laRaw -is [string] -and "$laRaw".Trim()) { $laRaw = $laRaw | ConvertFrom-Json }; $la = ConvertTo-PimHybridAdCleanupMap (Get-PimHybridAdCleanupField $laRaw 'groups') } catch { $la = @{} }
        $laLower = @{}; foreach ($k in @($la.Keys)) { $laLower["$k".ToLowerInvariant()] = $la[$k] }
        $work = @(); if ($ap.ok) { $work = @(@($ap.reviewed | ForEach-Object { @{ kind = 'reviewed'; item = $_ } }) + @($ap.also | ForEach-Object { @{ kind = 'also'; item = $_ } })) }
        foreach ($w in $work) {
            $it = $w.item
            $entra = $null
            if ($w.kind -eq 'also' -and $defs.ok -and -not $defs.names.ContainsKey("$($it.name)".Trim().ToLowerInvariant()) -and $Adapter.ContainsKey('EntraGroupExists')) { try { $entra = & $Adapter.EntraGroupExists "$($it.name)" } catch { $entra = $null } }
            $d = Get-PimHybridAdCleanupDecision -Item $it -Kind $w.kind -NowEpoch $now -ScopeOk ([bool]$scope.ok) -Ous @($scope.ous) -DefinitionsOk ([bool]$defs.ok) -DefinitionCount @($defs.rows).Count `
                -DefinedNames $defs.names -Pattern $Pattern -AdOk $adOk -AdGroupsByName $byNameArr -Protected $protected -ServerPattern $ServerPattern -ServersOk $serversOk -ServerNames $serverNames -LocalAdmin $laLower -EntraExists $entra
            $name = "$($it.name)".Trim()
            $dn = ''; if ($byNameArr.ContainsKey($name.ToLowerInvariant()) -and @($byNameArr[$name.ToLowerInvariant()]).Count -eq 1) { $dn = "$($byNameArr[$name.ToLowerInvariant()][0].DistinguishedName)" }
            $status = switch ("$($d.action)") { 'delete' { 'deleted' } 'wait' { 'waiting' } 'gone' { 'gone' } 'expired' { 'expired' } default { 'skipped' } }
            $reason = "$($d.reason)"
            if ($d.action -eq 'delete') {
                if ($WhatIf) { $status = 'plan'; $reason = 'plan-only: the worker would delete this group' }
                else {
                    try {
                        & $Adapter.DeleteGroup $dn | Out-Null
                        try { & $Store.Audit 'hybrid-ad.cleanup.delete' $dn ([ordered]@{ group = $name; approvedBy = "$($it.by)"; approvedAtEpoch = $it.atEpoch; kind = $w.kind; members = @($byNameArr[$name.ToLowerInvariant()][0].Members).Count }) }
                        catch { Write-Warning "[hybrid-ad-cleanup] the audit entry for $name was not written: $($_.Exception.Message)" }
                    } catch {
                        $status = 'failed'; $m = "$($_.Exception.Message)"
                        $reason = if (Test-PimHybridAdAccessDenied -Message $m) { "the worker's account may not delete groups in that OU -- grant its permission group 'Delete Group objects' there (Initialize-PimHybridWorkerAd -AllowGroupCleanup does). AD said: $m" } else { $m }
                    }
                }
            }
            $res.Add([pscustomobject]@{ key = "$($it.key)"; name = $name; dn = $dn; status = $status; reason = $reason; approvedBy = "$($it.by)"; kind = $w.kind })
        }
        if (Get-Command Write-PimHybridAdItemLines -ErrorAction SilentlyContinue) {
            Write-PimHybridAdItemLines -Job 'hybrid-ad-cleanup' -Lines @($res | Where-Object { $_.status -ne 'gone' } | ForEach-Object { "{0,-8} {1}  {2}  (approved by {3})" -f $_.status, $_.name, $_.reason, $_.approvedBy })
        }
        foreach ($x in @($res | Where-Object { $_.status -eq 'deleted' })) { Write-Host "    [hybrid-ad-cleanup] DELETED  $($x.dn)  (approved by $($x.approvedBy))" }

        # 3. the result record the page shows -- rewritten only when an item's status or reason changed
        try {
            $old = $null; try { $old = & $Store.Read 'AdCleanupResult' } catch { $old = $null }
            if ($old -is [string] -and "$old".Trim()) { try { $old = $old | ConvertFrom-Json } catch { $old = $null } }
            $items = ConvertTo-PimHybridAdCleanupMap (Get-PimHybridAdCleanupField $old 'items')
            $changed = $false
            foreach ($x in $res) {
                $prev = $items["$($x.key)"]
                $ps = "$(Get-PimHybridAdCleanupField $prev 'status')"; $pr = "$(Get-PimHybridAdCleanupField $prev 'reason')"
                if ($x.status -eq 'gone' -and $ps -eq 'deleted') { continue }   # deleted in an earlier run: the record of the deletion stays
                if ($ps -eq $x.status -and $pr -eq $x.reason) { continue }
                $items["$($x.key)"] = [ordered]@{ name = $x.name; dn = $(if ($x.dn) { $x.dn } else { "$(Get-PimHybridAdCleanupField $prev 'dn')" }); status = $x.status; reason = $x.reason; approvedBy = $x.approvedBy; kind = $x.kind; atEpoch = $now }
                $changed = $true
            }
            if ($changed) {
                $keep = [ordered]@{}
                foreach ($k in @($items.Keys | Sort-Object { $v = [long]0; [void][long]::TryParse("$(Get-PimHybridAdCleanupField $items[$_] 'atEpoch')", [ref]$v); $v } -Descending | Select-Object -First 500)) { $keep["$k"] = $items[$k] }
                & $Store.Save 'AdCleanupResult' (([ordered]@{ v = 1; updatedEpoch = $now; items = $keep }) | ConvertTo-Json -Depth 6 -Compress)
            }
        } catch { Write-Warning "[hybrid-ad-cleanup] the result record was not saved: $($_.Exception.Message)" }

        $n = { param($s) @($res | Where-Object { $_.status -eq $s }).Count }
        $detail = if (-not $cand.ok) { "clean-up: nothing proposed -- $($cand.reason)" } else { "clean-up: candidates=$(@($cand.candidates).Count)" }
        if ($res.Count) { $detail += (" approved={0} deleted={1} planned={2} waiting={3} skipped={4} failed={5}" -f $res.Count, (& $n 'deleted'), (& $n 'plan'), (& $n 'waiting'), ((& $n 'skipped') + (& $n 'expired')), (& $n 'failed')) }
        return [pscustomobject]@{ ran = $true; detail = $detail; candidates = @($cand.candidates).Count; results = $res.ToArray(); candidateList = @($cand.candidates); proposalOk = [bool]$cand.ok; proposalReason = "$($cand.reason)" }
    } catch {
        Write-Warning "[hybrid-ad-cleanup] the clean-up did not run: $($_.Exception.Message)"
        return [pscustomobject]@{ ran = $false; detail = "clean-up: did not run -- $($_.Exception.Message)"; candidates = 0; results = @() }
    }
}

function Invoke-PimHybridAdCleanupLocalAdminStep {
    <#
      The SERVER lane's half of the approved clean-up (called at the end of the 'hybrid-ad-servers' run, as the server
      identity): an approved per-server group is taken out of ITS server's local Administrators, and the outcome is
      recorded in settings row 'AdCleanupLocalAdmin' for the groups lane. It removes exactly one entry -- the member whose
      name is that group -- and only when ALL of this holds in this run: the approval record was read, the approval is
      not expired, the definitions were read (and the store is not empty), the group has NO definition, its name matches
      the mirrored pattern and the per-server format, and the server is one of the domain's enabled Windows servers
      (-Inventory). Returns @{ detail; results[] { group; server; status; reason } }. Never throws.
      status: removed | not a member | plan | unreachable | no access | failed | server not in Active Directory.
    #>
    param([Parameter(Mandatory)][hashtable]$Adapter, [string]$Netbios = '', [object[]]$Inventory = @(), [switch]$WhatIf, [datetime]$NowUtc = [datetime]::UtcNow,
          [hashtable]$Store, [object[]]$Rows = $null, [string]$Pattern = '', [string]$ServerPattern = '')
    $out = New-Object System.Collections.Generic.List[object]
    try {
        if (-not $Store) { $Store = Get-PimHybridAdCleanupStore }
        if (-not $Store) { return @{ detail = ''; results = @() } }
        $ap = Read-PimHybridAdCleanupApproval -Read $Store.Read
        if (-not $ap.ok) { return @{ detail = "clean-up (local Administrators): not run -- $($ap.reason)"; results = @() } }
        $work = @(@($ap.reviewed | ForEach-Object { @{ kind = 'reviewed'; item = $_ } }) + @($ap.also | ForEach-Object { @{ kind = 'also'; item = $_ } }))
        if (-not $work.Count) { return @{ detail = ''; results = @() } }
        if (-not $Adapter.ContainsKey('RemoveLocalAdmin')) { return @{ detail = 'clean-up (local Administrators): not run -- this worker cannot remove a local administrator'; results = @() } }
        $defs = Get-PimHybridAdAllGroupDefinitions -Rows $Rows
        if (-not $defs.ok -or -not @($defs.rows).Count) { return @{ detail = 'clean-up (local Administrators): not run -- the group definitions could not be read'; results = @() } }
        if (-not $Pattern) { $Pattern = "$(Get-PimHybridAdGroupPattern)" }
        if (-not $ServerPattern) { $ServerPattern = "$(Get-PimHybridAdServerGroupName -Server '*')" }
        if (-not (Test-PimHybridAdCleanupPattern $Pattern)) { return @{ detail = 'clean-up (local Administrators): not run -- the mirrored pattern is too wide'; results = @() } }
        $now = Get-PimHybridAdCleanupEpoch -NowUtc $NowUtc
        $inv = @{}; foreach ($s in @($Inventory)) { if ($s -and "$($s.name)".Trim()) { $inv["$($s.name)".Trim().ToLowerInvariant()] = $s } }
        $doc = $null; try { $doc = & $Store.Read 'AdCleanupLocalAdmin' } catch { return @{ detail = 'clean-up (local Administrators): not run -- its record could not be read'; results = @() } }
        if ($doc -is [string] -and "$doc".Trim()) { try { $doc = $doc | ConvertFrom-Json } catch { $doc = $null } }
        $groups = @{}; $gm = ConvertTo-PimHybridAdCleanupMap (Get-PimHybridAdCleanupField $doc 'groups'); foreach ($k in @($gm.Keys)) { $groups["$k".ToLowerInvariant()] = $gm[$k] }
        $changed = $false
        foreach ($w in $work) {
            $it = $w.item; $name = "$($it.name)".Trim(); if (-not $name) { continue }
            $at = [long]0; if (-not [long]::TryParse("$($it.atEpoch)", [ref]$at) -or $at -le 0 -or -not "$($it.by)".Trim()) { continue }
            $maxSec = if ($w.kind -eq 'also') { [long](Get-PimHybridAdCleanupAlsoDeleteMaxDays) * 86400 } else { [long](Get-PimHybridAdCleanupApprovalMaxHours) * 3600 }
            if ($at -gt ($now + 600) -or ($now - $at) -gt $maxSec) { continue }
            if ($name -notlike $Pattern -or $defs.names.ContainsKey($name.ToLowerInvariant())) { continue }
            $server = Get-PimHybridAdServerNameFromGroup -GroupName $name -ServerPattern $ServerPattern
            if (-not $server -or [bool]$it.withoutServer) { continue }
            $k = $name.ToLowerInvariant()
            $prev = "$(Get-PimHybridAdCleanupField $groups[$k] 'status')".Trim().ToLowerInvariant()
            if ($prev -in @('removed', 'not a member')) { continue }   # done in an earlier run
            $status = ''; $reason = ''
            if (-not $inv.ContainsKey($server.ToLowerInvariant())) { $status = 'server not in Active Directory' }
            else {
                $sv = $inv[$server.ToLowerInvariant()]
                $target = if ("$($sv.dnsHostName)".Trim()) { "$($sv.dnsHostName)".Trim() } else { "$($sv.name)" }
                try {
                    $live = @(& $Adapter.GetLocalAdmins $target)
                    $hit = @($live | Where-Object { "$_".Trim() -ieq $name -or "$_".Trim().ToLowerInvariant().EndsWith("\$k") } | Select-Object -First 1)
                    if (-not $hit.Count) { $status = 'not a member' }
                    elseif ($WhatIf) { $status = 'plan'; $reason = "would remove $($hit[0]) from local Administrators" }
                    else { & $Adapter.RemoveLocalAdmin $target "$($hit[0])" | Out-Null; $status = 'removed'; $reason = "$($hit[0])"; Write-Host "    [hybrid-ad-cleanup] removed  $($hit[0]) from local Administrators on $server (approved by $($it.by))" }
                } catch {
                    $m = "$($_.Exception.Message)"
                    $status = if (Test-PimHybridAdAccessDenied -Message $m) { 'no access' } else { 'unreachable' }
                    $reason = $m
                }
            }
            $out.Add([pscustomobject]@{ group = $name; server = $server; status = $status; reason = $reason })
            if ("$(Get-PimHybridAdCleanupField $groups[$k] 'status')" -ne $status) { $groups[$k] = [ordered]@{ name = $name; server = $server; status = $status; reason = $reason; atEpoch = $now }; $changed = $true }
        }
        if ($changed) {
            $keep = [ordered]@{}; foreach ($k in @($groups.Keys | Sort-Object)) { $keep["$k"] = $groups[$k] }
            try { & $Store.Save 'AdCleanupLocalAdmin' (([ordered]@{ v = 1; updatedEpoch = $now; groups = $keep }) | ConvertTo-Json -Depth 6 -Compress) } catch { Write-Warning "[hybrid-ad-cleanup] the local-Administrators record was not saved: $($_.Exception.Message)" }
        }
        if (-not $out.Count) { return @{ detail = ''; results = @() } }
        $n = { param($s) @($out | Where-Object { $_.status -eq $s }).Count }
        return @{ detail = ("clean-up (local Administrators): removed={0} not-a-member={1} planned={2} unreachable={3} no-access={4}" -f (& $n 'removed'), (& $n 'not a member'), (& $n 'plan'), (& $n 'unreachable'), (& $n 'no access')); results = $out.ToArray() }
    } catch { return @{ detail = "clean-up (local Administrators): not run -- $($_.Exception.Message)"; results = $out.ToArray() } }
}

function Invoke-PimHybridAdGroupsJobWithCleanup {
    <#
      The 'hybrid-ad-groups' job as the scheduler runs it since PIM 100.123: the ORIGINAL mirror job, then the clean-up
      (report + approved deletions). The mirror's own result is returned with the clean-up text appended to detail; an
      error of the mirror job is thrown again AFTER the clean-up ran. -Mirror / -Cleanup are the seams for tests.
    #>
    param([datetime]$NowUtc = [datetime]::UtcNow, [switch]$WhatIf,
          [scriptblock]$Mirror = { param($now, $whatIf) Invoke-PimHybridAdGroupsJob -NowUtc $now -WhatIf:$whatIf },
          [scriptblock]$Cleanup = { param($now, $whatIf) Invoke-PimHybridAdCleanupJob -NowUtc $now -WhatIf:$whatIf })
    $result = $null; $err = $null
    try { $result = & $Mirror $NowUtc ([bool]$WhatIf) } catch { $err = $_ }
    $text = ''
    # a host that is not a hybrid worker (the mirror said so) never runs the clean-up
    $notWorker = [bool]($result -and $result.PSObject.Properties['requiresHybridWorker'] -and $result.requiresHybridWorker)
    if (-not $notWorker) { try { $c = & $Cleanup $NowUtc ([bool]$WhatIf); if ($c -and "$($c.detail)") { $text = "$($c.detail)" } } catch { $text = "clean-up: did not run -- $($_.Exception.Message)" } }
    if ($err) { if ($text) { throw ("$($err.Exception.Message) | $text") } else { throw $err } }
    if ($text -and $result -and $result.PSObject.Properties['detail']) { $result.detail = "$($result.detail); $text" }
    return $result
}
