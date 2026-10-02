<#
  PIM-HybridAdGroups.ps1 -- §80.2 PIMHYBRIDWRK, goal b: REPLACE the "PIM for Active Directory" scripts
  (C:\SCRIPTS\PIM4ActiveDirectoryPS, operator 2026-09-29: "replace the pim for AD script. Not all customer run pim for AD
  scripts, but if they do it should handle this also").

  What the legacy scripts did, and where it lives now:
    AD-Groups-Management.ps1          -> Get-PimHybridAdGroupMirrorPlan / Invoke-PimHybridAdGroupMirror
        mirror every PIM group whose name matches the AD pattern (v1 'PIM-*ID-S_AD') to an AD Global Security group of the
        same name in the delegation-groups OU; DisplayName = name + ' (separate group)'; fix DisplayName/Description drift.
    PIM-Sync-ID-AD-Servers/-Services  -> Get-PimHybridAdMembershipPlan / Invoke-PimHybridAdMembershipSync
        near-real-time: the ACTIVE PIM-for-Groups members of each mirrored group become members of the AD group, the
        cloud admin mapped to its AD account (mailNickname '-ID' -> sAMAccountName '-AD'); with the AD Privileged Access
        Management feature the membership carries a TTL = the time left on the activation (v1: re-add when the TTL is off
        by > 120 s; no end time -> 1 h); members without an active assignment are removed.
    AD-AdminAccounts-Management.ps1   -> PIM-HybridAd.ps1 (Invoke-PimHybridAdWorkerJob), already in the engine.
    AD-ManageLocalAdministratorsGroupMembership.ps1 (server onboarding over WinRM) -> NOT here yet (see REQUIREMENTS §80.2).

  Deliberate differences from v1 (safety):
    * The group list comes from the DEFINED model in SQL (PIM-Definitions-*), never from a Graph name scan
      (memory: the engine touches only defined objects).
    * A removal only ever touches a USER whose sAMAccountName carries the AD-admin suffix ('-AD' by default) -- the accounts
      PIM itself put there. v1 removed ANY non-matching member (service accounts, nested groups). Other members are
      reported as 'kept (not PIM-managed)'. HybridAdProtectedMembers adds names that are never removed.
    * No plaintext gMSA password anywhere: the task runs AS the gMSA (PIM-HybridAd.ps1 Test-PimHybridAdRunAsGmsa).
    * -WhatIf / plan mode on every step; results are returned for the worker's status report.
    * The PAM feature is DETECTED, never enabled (enabling it is irreversible for the forest).
#>

function Get-PimHybridAdSetting {
    # One reader: $global:PIM_<Name> -> $env:PIM_<Name> -> hydrated pim.Settings -> default (Get-PimAdminLifecycleSetting when loaded).
    param([Parameter(Mandatory)][string]$Name, $Default = $null)
    if (Get-Command Get-PimAdminLifecycleSetting -ErrorAction SilentlyContinue) { return (Get-PimAdminLifecycleSetting -Name $Name -Default $Default) }
    $g = Get-Variable -Name "PIM_$Name" -Scope Global -ValueOnly -ErrorAction SilentlyContinue
    if ($null -ne $g -and "$g".Trim() -ne '') { return $g }
    $e = [Environment]::GetEnvironmentVariable("PIM_$Name", 'Process')
    if ($null -ne $e -and "$e".Trim() -ne '') { return $e }
    if ($global:PIM_NamingConventions -is [System.Collections.IDictionary] -and $global:PIM_NamingConventions.Contains($Name)) {
        $s = $global:PIM_NamingConventions[$Name]; if ($null -ne $s -and "$s".Trim() -ne '') { return $s }
    }
    return $Default
}

# 2.4.465 (operator 2026-09-30: "a customer must be able to define his groups naming convention for the hybrid solution"):
# every hybrid knob, in ONE catalog -- the Manager's Settings > Hybrid Active Directory card lists, validates and saves exactly
# these (each its own pim.Settings row; blank = the default, which is DERIVED from the tenant's own naming where it can be).
$script:PimHybridAdSettingCatalog = @(
    [ordered]@{ name = 'HybridAdGroupMarker'; label = 'AD group marker'; default = '-S_AD'; help = 'The end of a PIM group name that marks it as ALSO an on-premises AD group. The mirrored pattern is your group prefix + * + this marker.' }
    [ordered]@{ name = 'HybridAdGroupPattern'; label = 'Pattern override'; default = ''; help = 'Leave blank to derive it (prefix + * + marker). Set a full wildcard only when your AD groups do not follow that shape.' }
    [ordered]@{ name = 'HybridAdCloudSuffix'; label = 'Cloud admin suffix'; default = ''; help = 'The end of a cloud admin account name that is swapped for the AD suffix. Blank = the Entra suffix of your naming conventions.' }
    [ordered]@{ name = 'HybridAdAccountSuffix'; label = 'AD admin suffix'; default = ''; help = 'The end of the matching AD admin account. Blank = the AD suffix of your naming conventions. Only users carrying it are ever removed from an AD group.' }
    [ordered]@{ name = 'HybridAdGroupsOu'; label = 'OU for new AD groups'; default = ''; help = 'Distinguished name of the OU where missing AD groups are created (OU=...,DC=...). Blank = groups are never created, only kept in sync.' }
    [ordered]@{ name = 'HybridAdServerGroupFormat'; label = 'Per-server group format'; default = '{prefix}AD-SRV-{server}{cloud}{marker}'; help = 'The name of the group that becomes local administrator on one server. Tokens: {prefix} {server} {cloud} {marker}. {server} is required.' }
    [ordered]@{ name = 'HybridAdServerAdminsGroup'; label = 'Shared server-admins group'; default = ''; help = 'A group every onboarded server also gets in its local Administrators (and that the worker''s account is a member of). Blank = none.' }
    [ordered]@{ name = 'HybridAdProtectedMembers'; label = 'Never remove'; default = ''; help = 'Comma-separated account names the sync never removes from an AD group.' }
)

function Get-PimHybridAdSettingCatalog { return $script:PimHybridAdSettingCatalog }

function Test-PimHybridAdSettingsInput {
    <#
      PURE. -Values: name -> text (only catalog names). Returns @{ ok; errors[]; values (trimmed; '' = back to the default) }.
      Refuses what would make the worker touch the wrong groups or build names AD cannot hold.
    #>
    param([hashtable]$Values = @{})
    $known = @{}; foreach ($c in $script:PimHybridAdSettingCatalog) { $known[$c.name] = $true }
    $err = New-Object System.Collections.Generic.List[string]; $out = [ordered]@{}
    foreach ($k in @($Values.Keys)) {
        if (-not $known.ContainsKey("$k")) { $err.Add("unknown setting '$k'"); continue }
        $v = "$($Values[$k])".Trim()
        switch ("$k") {
            'HybridAdGroupMarker' { if ($v -match '[\s*?\\/@,;]') { $err.Add('AD group marker: no spaces, wildcards, slashes, @, commas') } elseif ($v.Length -gt 20) { $err.Add('AD group marker: at most 20 characters') } }
            'HybridAdGroupPattern' { if ($v -and $v -notmatch '\*') { $err.Add('Pattern override: must contain * (or be blank)') } elseif ($v -eq '*' -or $v -match '^\*+$') { $err.Add('Pattern override: * alone would mirror EVERY group') } elseif ($v -match '[\s\\/@,;]') { $err.Add('Pattern override: no spaces, slashes, @, commas') } }
            { $_ -in 'HybridAdCloudSuffix', 'HybridAdAccountSuffix' } { if ($v -match '[\s*?\\/@,;]') { $err.Add("${k}: no spaces, wildcards, slashes, @, commas") } elseif ($v.Length -gt 20) { $err.Add("${k}: at most 20 characters") } }
            'HybridAdGroupsOu' { if ($v -and $v -notmatch '^(?i)(OU|CN)=[^,]+(,(OU|CN)=[^,]+)*,DC=[^,]+(,DC=[^,]+)*$') { $err.Add('OU for new AD groups: a distinguished name such as OU=PIM,OU=Groups,DC=corp,DC=local') } }
            'HybridAdServerGroupFormat' { if ($v -and $v -notmatch '\{server\}') { $err.Add('Per-server group format: must contain {server}') } elseif ($v -match '[\s*?\\/@,;]') { $err.Add('Per-server group format: no spaces, wildcards, slashes, @, commas') } }
            'HybridAdServerAdminsGroup' { if ($v -match '[*?@,;]' -or $v -match '^\s|\\.*\\') { $err.Add('Shared server-admins group: one group name (optionally DOMAIN\name)') } }
            'HybridAdProtectedMembers' { if ($v -match '[*?]') { $err.Add('Never remove: account names only, no wildcards') } }
        }
        $out["$k"] = $v
    }
    return @{ ok = ($err.Count -eq 0); errors = $err.ToArray(); values = $out }
}

function Get-PimHybridAdSettingsView {
    <#
      The Settings card's data: each catalog knob with its stored value and what is EFFECTIVE now, plus a preview of the
      names the worker will use (pattern, a cloud -> AD account mapping, a per-server group) and the defined groups that
      match the pattern today. -Rows: the definition rows (the Manager reads them from pim.Rows).
    #>
    param([object[]]$Rows = @())
    $items = foreach ($c in $script:PimHybridAdSettingCatalog) {
        $stored = "$(Get-PimHybridAdSetting -Name $c.name -Default '')".Trim()
        [ordered]@{ name = $c.name; label = $c.label; help = $c.help; default = $c.default; value = $stored }
    }
    $sfx = Get-PimHybridAdSuffixes
    $pattern = Get-PimHybridAdGroupPattern
    $matched = @($Rows | ForEach-Object { "$($_.GroupName)".Trim() } | Where-Object { $_ -and $_ -like $pattern -and $_.Length -le 64 } | Select-Object -Unique | Sort-Object)
    $sample = if ($sfx.cloud) { "Admin-JDOE$($sfx.cloud)" } else { 'Admin-JDOE' }
    return [ordered]@{
        settings = @($items)
        preview = [ordered]@{
            pattern = $pattern; cloudSuffix = $sfx.cloud; adSuffix = $sfx.ad
            exampleCloudAccount = $sample; exampleAdAccount = (ConvertTo-PimHybridAdAccountName -MailNickname $sample -CloudSuffix $sfx.cloud -AdSuffix $sfx.ad)
            exampleServerGroup = (Get-PimHybridAdServerGroupName -Server 'FS01')
            matchedCount = $matched.Count; matched = @($matched | Select-Object -First 100)
        }
    }
}

function Get-PimHybridAdGroupPattern {
    <#
      The wildcard that marks a PIM group as ALSO an AD group (v1: 'PIM-*ID-S_AD'). Built from the CUSTOMER's naming -- their
      group prefix (Get-PimGroupNamePrefix) + '*' + the PIM-for-AD marker (setting HybridAdGroupMarker, default '-S_AD') --
      so a tenant whose groups start 'ACME-' mirrors 'ACME-*-S_AD'. Setting HybridAdGroupPattern overrides it whole.
    #>
    $explicit = "$(Get-PimHybridAdSetting -Name 'HybridAdGroupPattern' -Default '')".Trim()
    if ($explicit) { return $explicit }
    $marker = "$(Get-PimHybridAdSetting -Name 'HybridAdGroupMarker' -Default '-S_AD')".Trim()
    $prefix = ''
    if (Get-Command Get-PimGroupNamePrefix -ErrorAction SilentlyContinue) { try { $prefix = "$(Get-PimGroupNamePrefix)".Trim() } catch { $prefix = '' } }
    return "$prefix*$marker"
}

function Get-PimHybridAdSuffixes {
    <#
      The cloud -> AD account suffixes from the CUSTOMER's naming conventions (EnvironmentSuffixes: entra / ad -- v1 '-ID'
      / '-AD'), overridable by HybridAdCloudSuffix / HybridAdAccountSuffix. Nothing is hard-coded here: a tenant whose
      conventions name no suffix maps an admin to the same name in AD. Returns @{ cloud; ad }.
    #>
    $map = $null
    if (Get-Command Get-PimNamingConvention -ErrorAction SilentlyContinue) { try { $map = Get-PimNamingConvention -Key 'EnvironmentSuffixes' } catch { $map = $null } }
    if (-not $map -and $global:PIM_NamingConventions -is [System.Collections.IDictionary] -and $global:PIM_NamingConventions.Contains('EnvironmentSuffixes')) { $map = $global:PIM_NamingConventions['EnvironmentSuffixes'] }
    if (-not $map -and (Get-Command Get-PimShippedNamingConventions -ErrorAction SilentlyContinue)) { try { $map = (Get-PimShippedNamingConventions)['EnvironmentSuffixes'] } catch { $map = $null } }
    $get = { param($k) if ($map -is [System.Collections.IDictionary]) { "$($map[$k])" } elseif ($map) { "$($map.$k)" } else { '' } }
    $cloud = "$(Get-PimHybridAdSetting -Name 'HybridAdCloudSuffix' -Default (& $get 'entra'))".Trim()
    $ad = "$(Get-PimHybridAdSetting -Name 'HybridAdAccountSuffix' -Default (& $get 'ad'))".Trim()
    return @{ cloud = $cloud; ad = $ad }
}

function ConvertTo-PimHybridAdAccountName {
    <#
      PURE. The AD account of a cloud admin (v1: mailNickname with '-ID' replaced by '-AD'). -CloudSuffix/-AdSuffix from
      settings HybridAdCloudSuffix ('-ID') / HybridAdAccountSuffix ('-AD'); only a TRAILING suffix is swapped. A name
      without the cloud suffix maps to itself. Returns '' for a blank input.
    #>
    param([AllowEmptyString()][string]$MailNickname, [string]$CloudSuffix = '', [string]$AdSuffix = '')
    $n = "$MailNickname".Trim()
    if (-not $n) { return '' }
    if ($CloudSuffix -and $n.EndsWith($CloudSuffix, [System.StringComparison]::OrdinalIgnoreCase)) {
        return $n.Substring(0, $n.Length - $CloudSuffix.Length) + $AdSuffix
    }
    return $n
}

function Get-PimHybridAdGroupMirrorPlan {
    <#
      PURE. -Definitions: PIM definition rows (GroupName, GroupDescription). -Live: AD groups (Name, DisplayName,
      Description). Returns @{ create[]; update[]; nochange[]; skipped[] } -- each item @{ name; displayName;
      description; reason }. Only names matching -Pattern are mirrored; a name longer than 64 characters is skipped
      (AD's CN limit).
    #>
    param([object[]]$Definitions = @(), [object[]]$Live = @(), [string]$Pattern = '', [string]$DisplaySuffix = ' (separate group)')
    if (-not "$Pattern".Trim()) { $Pattern = Get-PimHybridAdGroupPattern }
    $liveBy = @{}
    foreach ($g in @($Live)) { if ($g -and "$($g.Name)".Trim()) { $liveBy["$($g.Name)".ToLowerInvariant()] = $g } }
    $out = @{ create = @(); update = @(); nochange = @(); skipped = @(); kept = @() }
    $seen = @{}
    foreach ($d in @($Definitions)) {
        if ($null -eq $d) { continue }
        $name = "$($d.GroupName)".Trim()
        if (-not $name -or $name -notlike $Pattern) { continue }
        $k = $name.ToLowerInvariant(); if ($seen.ContainsKey($k)) { continue }; $seen[$k] = $true
        $desc = "$($d.GroupDescription)".Trim(); if (-not $desc) { $desc = "PIM-managed group, mirrored from Entra ID ($name)" }
        $want = @{ name = $name; displayName = "$name$DisplaySuffix"; description = $desc; reason = '' }
        if ($name.Length -gt 64) { $want.reason = 'name longer than 64 characters (AD CN limit)'; $out.skipped += $want; continue }
        $cur = $liveBy[$k]
        if (-not $cur) { $want.reason = 'missing in AD'; $out.create += $want; continue }
        $diff = @()
        if ("$($cur.DisplayName)" -cne $want.displayName) { $diff += 'DisplayName' }
        if ("$($cur.Description)" -cne $want.description) { $diff += 'Description' }
        # 2.4.464: a group AD PROTECTS (adminCount=1 -- it is, or was, in Domain Admins / Schema Admins / ... directly or
        # nested) gets AdminSDHolder's ACL back every hour, so the OU delegation never lets the worker write its display
        # name or description ("Insufficient access rights" on 5 v1 groups, every hour, on internal). That drift is
        # cosmetic -- membership is what grants access -- so it is LEFT and reported, never retried as a red job.
        if ($diff.Count -and "$($cur.adminCount)" -eq '1') { $want.reason = "protected by AdminSDHolder (adminCount=1): cosmetic drift ($($diff -join ', ')) left as it is"; $out.kept += $want }
        elseif ($diff.Count) { $want.reason = "drift: $($diff -join ', ')"; $out.update += $want } else { $out.nochange += $want }
    }
    return $out
}

function Get-PimHybridAdMembershipPlan {
    <#
      PURE. One AD group. -Active: @{ mailNickname; endUtc ([datetime] or $null) } for every ACTIVE PIM-for-Groups member
      (users only). -LiveMembers: @{ samAccountName; objectClass; ttlSeconds ($null = permanent) }. -PamEnabled: the forest
      supports TTL membership. Returns @{ add[]; readd[]; remove[]; keep[]; kept[] } -- add/readd items carry ttlSeconds.
      Rules (v1 + safety): TTL = seconds left (min 60); no end -> -DefaultTtlSeconds (3600, v1's 1 h); re-add when the live
      TTL differs by more than -TtlToleranceSeconds (120); remove ONLY users whose name carries -AdSuffix and are not in
      -Protected; anything else stays and is reported in kept.
    #>
    param(
        [object[]]$Active = @(), [object[]]$LiveMembers = @(), [bool]$PamEnabled = $false,
        [datetime]$NowUtc = [datetime]::UtcNow,
        [string]$CloudSuffix = '', [string]$AdSuffix = '',
        [int]$DefaultTtlSeconds = 3600, [int]$TtlToleranceSeconds = 120,
        [string[]]$Protected = @()
    )
    $want = @{}
    foreach ($a in @($Active)) {
        if ($null -eq $a) { continue }
        $sam = ConvertTo-PimHybridAdAccountName -MailNickname "$($a.mailNickname)" -CloudSuffix $CloudSuffix -AdSuffix $AdSuffix
        if (-not $sam) { continue }
        $ttl = $DefaultTtlSeconds
        if ($a.endUtc) { $left = [int][math]::Floor(([datetime]$a.endUtc - $NowUtc).TotalSeconds); if ($left -le 0) { continue }; $ttl = [math]::Max(60, $left) }
        $k = $sam.ToLowerInvariant()
        if (-not $want.ContainsKey($k) -or $want[$k].ttlSeconds -lt $ttl) { $want[$k] = @{ samAccountName = $sam; ttlSeconds = $ttl } }
    }
    $prot = @{}; foreach ($p in @($Protected)) { if ("$p".Trim()) { $prot["$p".Trim().ToLowerInvariant()] = $true } }
    $out = @{ add = @(); readd = @(); remove = @(); keep = @(); kept = @() }
    $liveBy = @{}
    foreach ($m in @($LiveMembers)) {
        if ($null -eq $m) { continue }
        $sam = "$($m.samAccountName)".Trim(); if (-not $sam) { continue }
        $k = $sam.ToLowerInvariant(); $liveBy[$k] = $m
        if ($want.ContainsKey($k)) {
            $w = $want[$k]
            # liveTtlSeconds / ttlSeconds (= expected) ride along for the live view (v1 printed both + the deviation every cycle)
            if ($PamEnabled -and $null -ne $m.ttlSeconds -and [math]::Abs([int]$m.ttlSeconds - [int]$w.ttlSeconds) -gt $TtlToleranceSeconds) {
                $out.readd += @{ samAccountName = $sam; ttlSeconds = $w.ttlSeconds; liveTtlSeconds = [int]$m.ttlSeconds; reason = "TTL $($m.ttlSeconds)s -> $($w.ttlSeconds)s" }
            } elseif ($PamEnabled -and $null -eq $m.ttlSeconds) {
                $out.readd += @{ samAccountName = $sam; ttlSeconds = $w.ttlSeconds; liveTtlSeconds = $null; reason = 'permanent member -> time-limited' }
            } else { $out.keep += @{ samAccountName = $sam; ttlSeconds = $(if ($PamEnabled) { $w.ttlSeconds } else { $null }); liveTtlSeconds = $m.ttlSeconds } }
            continue
        }
        $isUser = ("$($m.objectClass)" -eq '' -or "$($m.objectClass)" -ieq 'user')
        $managed = $isUser -and $AdSuffix -and $sam.EndsWith($AdSuffix, [System.StringComparison]::OrdinalIgnoreCase)
        if ($prot.ContainsKey($k)) { $out.kept += @{ samAccountName = $sam; reason = 'protected (HybridAdProtectedMembers)' } }
        elseif (-not $managed) { $out.kept += @{ samAccountName = $sam; reason = "not PIM-managed ($(if ($isUser) { "no $AdSuffix suffix" } else { "$($m.objectClass)" }))" } }
        else { $out.remove += @{ samAccountName = $sam; reason = 'no active PIM assignment' } }
    }
    foreach ($k in $want.Keys) {
        if (-not $liveBy.ContainsKey($k)) { $w = $want[$k]; $out.add += @{ samAccountName = $w.samAccountName; ttlSeconds = $(if ($PamEnabled) { $w.ttlSeconds } else { $null }); reason = 'active PIM assignment' } }
    }
    return $out
}

function Test-PimHybridAdAccessDenied {
    # PURE. An AD / WinRM error that means "this identity has no rights there" (fixable by a grant), not "down".
    param([string]$Message)
    return ("$Message" -match '(?i)access is denied|access denied|insufficient access rights|unauthorizedaccess|0x80070005|E_ACCESSDENIED')
}

function Get-PimHybridAdServerSplat {
    # -Server for every AD cmdlet the worker calls: $global:PIM_HybridAdServer when set, else nothing (the locator picks a DC).
    $p = @{}; if ("$($global:PIM_HybridAdServer)".Trim()) { $p['Server'] = "$($global:PIM_HybridAdServer)".Trim() }; return $p
}

function Get-PimDefaultActiveDirectoryGroupAdapter {
    <#
      [ ] HYBRID-WORKER-ONLY. The real AD calls for the group mirror + membership sync. Runs as the process identity (the
      gMSA -- no -Credential); -Server from $global:PIM_HybridAdServer when set. Throws off a host without RSAT-AD.
    #>
    if (-not (Get-Command Get-ADGroup -ErrorAction SilentlyContinue)) { throw 'ActiveDirectory module not available -- the group adapter is hybrid-worker-only.' }
    # 🔴 NO CLOSURE-STYLE LOCALS in the blocks below: they run long after this function returned (dynamic scoping), so a
    # local such as the old `$srv = { ... }` is $null by then and every AD call failed with "The expression after '&' ...
    # was not valid" -- found by the first plan-only run on the internal worker 2026-09-29. They call a FUNCTION instead.
    return @{
        PamEnabled = {
            $s = Get-PimHybridAdServerSplat
            $f = Get-ADOptionalFeature -Filter "Name -eq 'Privileged Access Management Feature'" @s -ErrorAction Stop
            return [bool]($f -and @($f.EnabledScopes).Count)
        }
        GetGroups = {
            param([string]$Pattern)
            $s = Get-PimHybridAdServerSplat
            $flt = "Name -like '$("$Pattern".Replace("'", "''"))'"
            @(Get-ADGroup -Filter $flt -Properties DisplayName, Description, adminCount @s -ErrorAction Stop | ForEach-Object { [pscustomobject]@{ Name = $_.Name; DisplayName = $_.DisplayName; Description = $_.Description; adminCount = $_.adminCount } })
        }
        NewGroup = {
            param($Item, [string]$Ou)
            $s = Get-PimHybridAdServerSplat
            New-ADGroup -Name $Item.name -SamAccountName $Item.name -DisplayName $Item.displayName -Description $Item.description `
                -GroupCategory Security -GroupScope Global -Path $Ou @s -ErrorAction Stop
        }
        SetGroup = {
            param($Item)
            $s = Get-PimHybridAdServerSplat
            Set-ADGroup -Identity $Item.name -DisplayName $Item.displayName -Description $Item.description @s -ErrorAction Stop
        }
        GetMembers = {
            param([string]$Group)
            $s = Get-PimHybridAdServerSplat
            $g = Get-ADGroup -Identity $Group -Properties member -ShowMemberTimeToLive @s -ErrorAction Stop
            foreach ($entry in @($g.member)) {
                $ttl = $null; $dn = "$entry"
                if ($dn -match '^<TTL=(\d+)>,(.*)$') { $ttl = [int]$Matches[1]; $dn = $Matches[2] }
                $o = Get-ADObject -Identity $dn -Properties sAMAccountName, objectClass @s -ErrorAction Stop
                [pscustomobject]@{ samAccountName = "$($o.sAMAccountName)"; objectClass = "$($o.objectClass)"; ttlSeconds = $ttl }
            }
        }
        AddMember = {
            param([string]$Group, [string]$Sam, $TtlSeconds)
            $s = Get-PimHybridAdServerSplat
            if ($null -ne $TtlSeconds) { Add-ADGroupMember -Identity $Group -Members $Sam -MemberTimeToLive ([timespan]::FromSeconds([int]$TtlSeconds)) @s -ErrorAction Stop }
            else { Add-ADGroupMember -Identity $Group -Members $Sam @s -ErrorAction Stop }
        }
        RemoveMember = {
            param([string]$Group, [string]$Sam)
            $s = Get-PimHybridAdServerSplat
            Remove-ADGroupMember -Identity $Group -Members $Sam -Confirm:$false @s -ErrorAction Stop
        }
    }
}

function Invoke-PimHybridAdGroupMirror {
    # Plan + (with -Apply) create/fix the AD groups. Returns @{ plan; results[] { name; op; status; reason } }.
    param([object[]]$Definitions, [Parameter(Mandatory)][hashtable]$Adapter, [string]$Ou, [switch]$Apply, [string]$Pattern)
    if (-not $Pattern) { $Pattern = Get-PimHybridAdGroupPattern }
    $live = @(& $Adapter.GetGroups $Pattern)
    $plan = Get-PimHybridAdGroupMirrorPlan -Definitions $Definitions -Live $live -Pattern $Pattern
    $res = New-Object System.Collections.Generic.List[object]
    foreach ($x in $plan.skipped) { $res.Add([pscustomobject]@{ name = $x.name; op = 'skip'; status = 'skipped'; reason = $x.reason }) }
    foreach ($x in $plan.nochange) { $res.Add([pscustomobject]@{ name = $x.name; op = 'none'; status = 'nochange'; reason = '' }) }
    foreach ($x in $plan.kept) { $res.Add([pscustomobject]@{ name = $x.name; op = 'none'; status = 'kept'; reason = $x.reason }) }
    foreach ($x in $plan.create) {
        if (-not $Apply) { $res.Add([pscustomobject]@{ name = $x.name; op = 'create'; status = 'plan'; reason = $x.reason }); continue }
        if (-not "$Ou".Trim()) { $res.Add([pscustomobject]@{ name = $x.name; op = 'create'; status = 'skipped'; reason = 'no OU for AD groups (setting HybridAdGroupsOu)' }); continue }
        try { & $Adapter.NewGroup $x $Ou | Out-Null; $res.Add([pscustomobject]@{ name = $x.name; op = 'create'; status = 'created'; reason = '' }) }
        catch { $res.Add([pscustomobject]@{ name = $x.name; op = 'create'; status = 'failed'; reason = "$($_.Exception.Message)" }) }
    }
    foreach ($x in $plan.update) {
        if (-not $Apply) { $res.Add([pscustomobject]@{ name = $x.name; op = 'update'; status = 'plan'; reason = $x.reason }); continue }
        try { & $Adapter.SetGroup $x | Out-Null; $res.Add([pscustomobject]@{ name = $x.name; op = 'update'; status = 'updated'; reason = $x.reason }) }
        catch {
            # A cosmetic update the worker has no RIGHT to write (a protected group adminCount did not flag yet, or an OU
            # outside the delegation) is kept, not failed -- the group exists and its membership still syncs.
            $m = "$($_.Exception.Message)"
            if (Test-PimHybridAdAccessDenied -Message $m) { $res.Add([pscustomobject]@{ name = $x.name; op = 'update'; status = 'kept'; reason = "cosmetic drift ($($x.reason -replace '^drift: ','')) not written -- no right to change this group's attributes: $m" }) }
            else { $res.Add([pscustomobject]@{ name = $x.name; op = 'update'; status = 'failed'; reason = $m }) }
        }
    }
    return [pscustomobject]@{ plan = $plan; results = $res.ToArray() }
}

function Invoke-PimHybridAdMembershipSync {
    <#
      For each mirrored group: plan from -ActiveByGroup (groupName -> active members) and the live AD members, then (with
      -Apply) add / re-add / remove. A group that cannot be read is reported failed and the others continue.
      Returns @{ pamEnabled; results[] { group; samAccountName; op; status; reason } }.
    #>
    param(
        [Parameter(Mandatory)][string[]]$Groups, [Parameter(Mandatory)][hashtable]$ActiveByGroup, [Parameter(Mandatory)][hashtable]$Adapter,
        [switch]$Apply, [datetime]$NowUtc = [datetime]::UtcNow, [string[]]$Protected = @(), [object]$PamEnabled = $null
    )
    $pam = if ($null -ne $PamEnabled) { [bool]$PamEnabled } else { try { [bool](& $Adapter.PamEnabled) } catch { $false } }
    $sfx = Get-PimHybridAdSuffixes
    $cloudSfx = $sfx.cloud; $adSfx = $sfx.ad
    $res = New-Object System.Collections.Generic.List[object]
    foreach ($g in @($Groups)) {
        try { $live = @(& $Adapter.GetMembers $g) }
        catch { $res.Add([pscustomobject]@{ group = $g; samAccountName = ''; op = 'read'; status = 'failed'; reason = "$($_.Exception.Message)" }); continue }
        $act = @(); if ($ActiveByGroup.ContainsKey($g)) { $act = @($ActiveByGroup[$g]) }
        $plan = Get-PimHybridAdMembershipPlan -Active $act -LiveMembers $live -PamEnabled $pam -NowUtc $NowUtc -CloudSuffix $cloudSfx -AdSuffix $adSfx -Protected $Protected
        foreach ($k in $plan.kept) { $res.Add([pscustomobject]@{ group = $g; samAccountName = $k.samAccountName; op = 'none'; status = 'kept'; reason = $k.reason }) }
        # 2.4.465: members already right are reported too ('member', never counted as a change) -- the live view shows
        # them with current vs expected TTL, as v1's console did every cycle.
        foreach ($k in $plan.keep) { $res.Add([pscustomobject]@{ group = $g; samAccountName = $k.samAccountName; op = 'none'; status = 'member'; reason = ''; ttlSeconds = $k.ttlSeconds; liveTtlSeconds = $k.liveTtlSeconds }) }
        foreach ($op in @(@('remove', $plan.remove), @('readd', $plan.readd), @('add', $plan.add))) {
            foreach ($x in @($op[1])) {
                $lt = if ($x.ContainsKey('liveTtlSeconds')) { $x.liveTtlSeconds } else { $null }
                if (-not $Apply) { $res.Add([pscustomobject]@{ group = $g; samAccountName = $x.samAccountName; op = $op[0]; status = 'plan'; reason = $x.reason; ttlSeconds = $x.ttlSeconds; liveTtlSeconds = $lt }); continue }
                try {
                    switch ($op[0]) {
                        'remove' { & $Adapter.RemoveMember $g $x.samAccountName | Out-Null }
                        'readd' { & $Adapter.RemoveMember $g $x.samAccountName | Out-Null; & $Adapter.AddMember $g $x.samAccountName $x.ttlSeconds | Out-Null }
                        'add' { & $Adapter.AddMember $g $x.samAccountName $x.ttlSeconds | Out-Null }
                    }
                    $res.Add([pscustomobject]@{ group = $g; samAccountName = $x.samAccountName; op = $op[0]; status = 'done'; reason = $x.reason; ttlSeconds = $x.ttlSeconds; liveTtlSeconds = $lt })
                } catch { $res.Add([pscustomobject]@{ group = $g; samAccountName = $x.samAccountName; op = $op[0]; status = 'failed'; reason = "$($_.Exception.Message)"; ttlSeconds = $x.ttlSeconds; liveTtlSeconds = $lt }) }
            }
        }
    }
    return [pscustomobject]@{ pamEnabled = $pam; results = $res.ToArray() }
}

function Get-PimHybridAdActiveGroupMembers {
    <#
      READ-ONLY Graph (the worker's own identity -- VM managed identity or certificate): for each group name, the ACTIVE
      PIM-for-Groups MEMBER assignments -> @{ mailNickname; endUtc } (users only; a group principal is skipped, as in v1).
      Returns a hashtable groupName -> list. -Graph is the seam ( { param($path) ... } returning the aggregated items ).
      Needs Graph application permissions: Group.Read.All + PrivilegedAssignmentSchedule.Read.AzureADGroup + User.Read.All.
    #>
    param([Parameter(Mandatory)][string[]]$GroupNames, [scriptblock]$Graph)
    if (-not $Graph) { $Graph = { param($p) @(Invoke-PimGraph -Path $p -All) } }
    $out = @{}
    # group ids + users change rarely; the ACTIVE instances are read fresh on every call. With $script:PimHybridAdCacheSeconds
    # set (the continuous loop) the first two are kept that long, so a pass costs ~one Graph call per group.
    $ttl = [int]$script:PimHybridAdCacheSeconds
    if ($ttl -le 0 -or -not $script:PimHybridAdGraphCache -or ([datetime]::UtcNow - $script:PimHybridAdGraphCache.at).TotalSeconds -ge $ttl) {
        $script:PimHybridAdGraphCache = @{ at = [datetime]::UtcNow; groups = @{}; users = @{} }
    }
    $groupCache = $script:PimHybridAdGraphCache.groups
    $userCache = $script:PimHybridAdGraphCache.users
    foreach ($name in @($GroupNames)) {
        if (-not $groupCache.ContainsKey($name)) {
            $esc = $name.Replace("'", "''")
            $grp = @(& $Graph "/groups?`$filter=displayName eq '$esc'&`$select=id,displayName")
            $groupCache[$name] = if ($grp.Count) { "$($grp[0].id)" } else { '' }
        }
        $gid = $groupCache[$name]
        if (-not $gid) { $out[$name] = @(); continue }
        $inst = @(& $Graph "/identityGovernance/privilegedAccess/group/assignmentScheduleInstances?`$filter=groupId eq '$gid' and accessId eq 'member'")
        $list = New-Object System.Collections.Generic.List[object]
        foreach ($i in $inst) {
            $principal = "$($i.principalId)"; if (-not $principal) { continue }
            if (-not $userCache.ContainsKey($principal)) {
                $u = $null
                # /directoryObjects, not /users: a nested GROUP principal is normal here, and /users answered it with a 404
                # that filled the worker log every pass (seen live 2026-09-29). The type decides -- a group has a mailNickname too.
                try { $u = @(& $Graph "/directoryObjects/$($principal)?`$select=id,mailNickname,userPrincipalName")[0] } catch { $u = $null }
                if ($u -and "$($u.'@odata.type')" -and "$($u.'@odata.type')" -ne '#microsoft.graph.user') { $u = $null }
                $userCache[$principal] = $u
            }
            $u = $userCache[$principal]
            if (-not $u -or -not "$($u.mailNickname)".Trim()) { continue }   # not a user (nested group) -- skipped, as in v1
            $end = $null; if ("$($i.endDateTime)".Trim()) { $end = [datetimeoffset]::Parse("$($i.endDateTime)", [Globalization.CultureInfo]::InvariantCulture).UtcDateTime }
            $list.Add([pscustomobject]@{ mailNickname = "$($u.mailNickname)"; endUtc = $end })
        }
        $out[$name] = $list.ToArray()
    }
    return $out
}

# The group-definition entities read for the AD mirror (the same set the coverage report treats as "ours").
$script:PimHybridAdGroupEntities = @('PIM-Definitions-Roles', 'PIM-Definitions-Services', 'PIM-Definitions-Organization',
    'PIM-Definitions-Tasks', 'PIM-Definitions-Departments', 'PIM-Definitions-Processes', 'PIM-Definitions-Projects',
    'PIM-Definitions-CrossOrg', 'PIM-Definitions-Resources')

function Get-PimHybridAdMirroredDefinitions {
    <#
      The DEFINED groups (pim.Rows) whose name matches the AD pattern. Returns @{ ok; rows[]; pattern; reason }. ok=$false
      when the engine core is not loaded or an entity could not be read -- the jobs then refuse instead of treating an
      unreadable store as "no groups".
    #>
    param([object[]]$Rows = $null)
    $pattern = Get-PimHybridAdGroupPattern
    # the continuous sync loop sets $script:PimHybridAdCacheSeconds: the definitions are re-read at most that often, not
    # on every few-second pass (a definition change reaches AD within the refresh window; activations are not cached)
    $c = $script:PimHybridAdDefsCache
    if ($null -eq $Rows -and $script:PimHybridAdCacheSeconds -gt 0 -and $c -and $c.pattern -eq $pattern -and ([datetime]::UtcNow - $c.at).TotalSeconds -lt $script:PimHybridAdCacheSeconds) {
        return @{ ok = $true; rows = $c.rows; pattern = $pattern; reason = '' }
    }
    $fromStore = ($null -eq $Rows)
    if ($null -eq $Rows) {
        if (-not (Get-Command Get-PimDesiredRows -ErrorAction SilentlyContinue)) { return @{ ok = $false; rows = @(); pattern = $pattern; reason = 'the engine core (Get-PimDesiredRows) is not loaded on this worker' } }
        $all = New-Object System.Collections.Generic.List[object]
        foreach ($e in $script:PimHybridAdGroupEntities) {
            foreach ($r in @(Get-PimDesiredRows -Entity $e)) { if ($null -ne $r) { $all.Add($r) } }
            if ($global:PIM_DesiredResolved -is [hashtable] -and $global:PIM_DesiredResolved.ContainsKey($e) -and -not $global:PIM_DesiredResolved[$e]) {
                return @{ ok = $false; rows = @(); pattern = $pattern; reason = "the definitions '$e' could not be read from the desired store" }
            }
        }
        $Rows = $all.ToArray()
    }
    $m = @($Rows | Where-Object { $_ -and "$($_.GroupName)".Trim() -and "$($_.GroupName)".Trim() -like $pattern })
    if ($fromStore -and $script:PimHybridAdCacheSeconds -gt 0) { $script:PimHybridAdDefsCache = @{ at = [datetime]::UtcNow; pattern = $pattern; rows = $m } }
    return @{ ok = $true; rows = $m; pattern = $pattern; reason = '' }
}

function Resolve-PimHybridAdGroupAdapter {
    # The adapter for a group job, or @{ refuse = <handler result> } when this host is not a capable hybrid worker.
    param([string]$Job, [int]$Count, [string]$Pattern, [string]$Need, [switch]$WhatIf, [object]$AdModulePresent = $null, [scriptblock]$SecretReader)
    $cap = Test-PimHybridAdWorkerCapability -AdModulePresent $AdModulePresent -SecretReader $SecretReader
    if ($cap.ok) { return @{ adapter = (Get-PimDefaultActiveDirectoryGroupAdapter) } }
    return @{ refuse = [pscustomobject]@{ ran = $false; unimplemented = $true; requiresHybridWorker = $true; groups = $Count; whatIf = [bool]$WhatIf
        detail = ("hybrid worker required: {0} group(s) matching '{1}' {2}, and {3}. Run the scheduler on the hybrid worker (Start-PimScheduler.ps1 -Jobs {4})" -f $Count, $Pattern, $Need, $cap.reason, $Job) } }
}

function Write-PimHybridAdItemLines {
    <#
      One log line per planned / applied / kept / failed item -- what the operator reviews before leaving plan-only
      ("planned=20" alone says nothing). Printed only when the set DIFFERS from the previous call for the same job, so the
      continuous sync loop does not repeat an unchanged plan every few seconds.
    #>
    param([Parameter(Mandatory)][string]$Job, [string[]]$Lines = @())
    if (-not $script:PimHybridAdLastLines) { $script:PimHybridAdLastLines = @{} }
    $key = ($Lines -join "`n")
    if ($script:PimHybridAdLastLines.ContainsKey($Job) -and $script:PimHybridAdLastLines[$Job] -eq $key) { return }
    $script:PimHybridAdLastLines[$Job] = $key
    foreach ($l in $Lines) { Write-Host "    [$Job] $l" }
}

function Invoke-PimHybridAdGroupsJob {
    <#
      The 'hybrid-ad-groups' job (v1 AD-Groups-Management.ps1): mirror the defined AD-marked PIM groups to AD.
      Handler shape @{ ran; detail; unimplemented; requiresHybridWorker; results }. THROWS when a create/update failed.
    #>
    param([datetime]$NowUtc = [datetime]::UtcNow, [switch]$WhatIf, [object[]]$Rows = $null, [hashtable]$Adapter, [object]$AdModulePresent = $null, [scriptblock]$SecretReader)
    $defs = Get-PimHybridAdMirroredDefinitions -Rows $Rows
    if (-not $defs.ok) { return [pscustomobject]@{ ran = $false; unimplemented = $true; detail = "unimplemented:hybrid-ad-groups -- $($defs.reason)"; whatIf = [bool]$WhatIf } }
    $n = @($defs.rows).Count
    if (-not $n) { return [pscustomobject]@{ ran = $true; groups = 0; whatIf = [bool]$WhatIf; detail = "hybrid-ad-groups: no defined group matches '$($defs.pattern)' -- nothing to mirror to AD" } }
    if (-not $Adapter) {
        $a = Resolve-PimHybridAdGroupAdapter -Job 'hybrid-ad-groups' -Count $n -Pattern $defs.pattern -Need 'wait to be mirrored to AD' -WhatIf:$WhatIf -AdModulePresent $AdModulePresent -SecretReader $SecretReader
        if ($a.refuse) { return $a.refuse }
        $Adapter = $a.adapter
    }
    $ou = "$(Get-PimHybridAdSetting -Name 'HybridAdGroupsOu' -Default '')".Trim()
    $r = Invoke-PimHybridAdGroupMirror -Definitions $defs.rows -Adapter $Adapter -Ou $ou -Apply:(-not $WhatIf) -Pattern $defs.pattern
    Write-PimHybridAdItemLines -Job 'hybrid-ad-groups' -Lines @($r.results | Where-Object { $_.status -ne 'nochange' } | ForEach-Object { "{0,-8} {1,-7} {2}  {3}" -f $_.status, $_.op, $_.name, $_.reason })
    $c = { param($s) @($r.results | Where-Object { $_.status -eq $s }).Count }
    $failed = @($r.results | Where-Object { $_.status -eq 'failed' })
    $wi = if ($WhatIf) { ' (whatif)' } else { '' }
    $detail = ("hybrid-ad-groups{0}: planned={1} created={2} updated={3} nochange={4} kept={5} skipped={6} failed={7} (pattern '{8}')" -f $wi, (& $c 'plan'), (& $c 'created'), (& $c 'updated'), (& $c 'nochange'), (& $c 'kept'), (& $c 'skipped'), $failed.Count, $defs.pattern)
    if ($failed.Count) { throw ("$detail -- " + (@($failed | ForEach-Object { "$($_.name): $($_.reason)" }) -join '; ')) }
    return [pscustomobject]@{ ran = $true; whatIf = [bool]$WhatIf; groups = $n; results = $r.results; detail = $detail }
}

function Invoke-PimHybridAdSyncJob {
    <#
      The 'hybrid-ad-sync' job (v1 PIM-Sync-ID-AD-*): the ACTIVE PIM-for-Groups members of each mirrored group -> AD group
      membership (TTL when the forest has the PAM feature). Only groups that already exist in AD are synced (the mirror
      job creates them). THROWS when a membership change failed.
    #>
    param([datetime]$NowUtc = [datetime]::UtcNow, [switch]$WhatIf, [object[]]$Rows = $null, [hashtable]$Adapter, [scriptblock]$Graph, [object]$AdModulePresent = $null, [scriptblock]$SecretReader)
    $defs = Get-PimHybridAdMirroredDefinitions -Rows $Rows
    if (-not $defs.ok) { return [pscustomobject]@{ ran = $false; unimplemented = $true; detail = "unimplemented:hybrid-ad-sync -- $($defs.reason)"; whatIf = [bool]$WhatIf } }
    $n = @($defs.rows).Count
    if (-not $n) { return [pscustomobject]@{ ran = $true; groups = 0; whatIf = [bool]$WhatIf; detail = "hybrid-ad-sync: no defined group matches '$($defs.pattern)' -- nothing to sync" } }
    if (-not $Adapter) {
        $a = Resolve-PimHybridAdGroupAdapter -Job 'hybrid-ad-sync' -Count $n -Pattern $defs.pattern -Need 'need their active members synced to AD' -WhatIf:$WhatIf -AdModulePresent $AdModulePresent -SecretReader $SecretReader
        if ($a.refuse) { return $a.refuse }
        $Adapter = $a.adapter
    }
    $inAd = @{}; foreach ($g in @(& $Adapter.GetGroups $defs.pattern)) { if ($g) { $inAd["$($g.Name)".ToLowerInvariant()] = $true } }
    $names = @($defs.rows | ForEach-Object { "$($_.GroupName)".Trim() } | Select-Object -Unique)
    $present = @($names | Where-Object { $inAd.ContainsKey($_.ToLowerInvariant()) })
    $missing = @($names | Where-Object { -not $inAd.ContainsKey($_.ToLowerInvariant()) })
    $missText = if ($missing.Count) { "; not yet in AD (hybrid-ad-groups creates them): $($missing.Count)" } else { '' }
    if (-not $present.Count) { return [pscustomobject]@{ ran = $true; groups = 0; whatIf = [bool]$WhatIf; detail = "hybrid-ad-sync: none of the $($names.Count) mirrored group(s) exist in AD yet$missText" } }
    $gArgs = @{ GroupNames = $present }; if ($Graph) { $gArgs['Graph'] = $Graph }
    $active = Get-PimHybridAdActiveGroupMembers @gArgs
    $prot = @("$(Get-PimHybridAdSetting -Name 'HybridAdProtectedMembers' -Default '')" -split '[,;]' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    $r = Invoke-PimHybridAdMembershipSync -Groups $present -ActiveByGroup $active -Adapter $Adapter -Apply:(-not $WhatIf) -NowUtc $NowUtc -Protected $prot
    Write-PimHybridAdItemLines -Job 'hybrid-ad-sync' -Lines @($r.results | Where-Object { $_.status -ne 'member' } | ForEach-Object { "{0,-8} {1,-7} {2} / {3}  {4}" -f $_.status, $_.op, $_.group, $_.samAccountName, $_.reason })
    $c = { param($op) @($r.results | Where-Object { $_.op -eq $op -and ($_.status -eq 'done' -or $_.status -eq 'plan') }).Count }
    $failed = @($r.results | Where-Object { $_.status -eq 'failed' })
    $wi = if ($WhatIf) { ' (whatif)' } else { '' }
    $ttl = if ($r.pamEnabled) { 'on' } else { 'off -- the AD PAM feature is not enabled' }
    $detail = ("hybrid-ad-sync{0}: groups={1} add={2} readd={3} remove={4} kept={5} failed={6} (TTL membership: {7}){8}" -f $wi, $present.Count, (& $c 'add'), (& $c 'readd'), (& $c 'remove'), @($r.results | Where-Object { $_.status -eq 'kept' }).Count, $failed.Count, $ttl, $missText)
    if ($failed.Count) { throw ("$detail -- " + (@($failed | ForEach-Object { "$($_.group)/$($_.samAccountName) $($_.op): $($_.reason)" }) -join '; ')) }
    return [pscustomobject]@{ ran = $true; whatIf = [bool]$WhatIf; groups = $present.Count; groupNames = $present; missingGroups = $missing; pamEnabled = $r.pamEnabled; results = $r.results; detail = $detail }
}

function Format-PimHybridAdLiveLines {
    <#
      PURE. One sync pass -> the lines of the LIVE view, in v1's console shape (the operator demos PIM for AD with it):
        Validating PIM members for group <G>
          Current TTL in AD is <n> for user <U> / Expected TTL from the PIM activation is <m> / Deviation of seconds is <d>
          Deviation of seconds is acceptable | NOT acceptable (+/- 2 min)
          PIM for AD: User <U> is already member of <G> | Adding user <U> ... for <n> min | Removing user <U> from <G>
      -Result: Invoke-PimHybridAdSyncJob's result. Each line = @{ t = text; k = info|ok|bad|change|dim }. A pass the job
      refused or that threw gives its detail as one line.
    #>
    param([object]$Result, [int]$ToleranceSeconds = 120)
    $L = New-Object System.Collections.Generic.List[object]
    $add = { param($t, $k) $L.Add([ordered]@{ t = "$t"; k = "$k" }) }
    if ($null -eq $Result) { return @() }
    if (-not $Result.PSObject.Properties['results'] -or -not $Result.PSObject.Properties['groupNames']) { & $add "$($Result.detail)" $(if (($Result.PSObject.Properties['ran'] -and -not $Result.ran) -or ($Result.PSObject.Properties['ok'] -and -not $Result.ok)) { 'bad' } else { 'info' }); return $L.ToArray() }
    $pam = [bool]$Result.pamEnabled
    $wi = [bool]$Result.whatIf
    $by = @{}; foreach ($x in @($Result.results)) { $k = "$($x.group)"; if (-not $by.ContainsKey($k)) { $by[$k] = New-Object System.Collections.Generic.List[object] }; $by[$k].Add($x) }
    $min = { param($s) if ($null -eq $s) { '?' } else { [int][math]::Floor([int]$s / 60) } }
    foreach ($g in @($Result.groupNames)) {
        & $add "Validating PIM members for group $g" 'info'
        $items = if ($by.ContainsKey($g)) { $by[$g].ToArray() } else { @() }   # .ToArray(), never @() over a List from a hashtable (pwsh 7 "Argument types do not match")
        if (-not @($items | Where-Object { $_.status -ne 'kept' }).Count) { & $add '  no active PIM member' 'dim' }
        foreach ($x in $items) {
            $u = "$($x.samAccountName)"
            $want = if ($x.PSObject.Properties['ttlSeconds']) { $x.ttlSeconds } else { $null }
            $live = if ($x.PSObject.Properties['liveTtlSeconds']) { $x.liveTtlSeconds } else { $null }
            if ($pam -and $x.op -in @('none', 'readd') -and $x.status -ne 'kept' -and $null -ne $want) {
                if ($null -ne $live) {
                    $dev = [int]$live - [int]$want
                    & $add "  Current TTL in AD is $live for user $u" 'info'
                    & $add "  Expected TTL from the PIM activation is $want" 'info'
                    & $add "  Deviation of seconds is $dev" 'info'
                    if ([math]::Abs($dev) -le $ToleranceSeconds) { & $add '  Deviation of seconds is acceptable' 'ok' }
                    else { & $add ("  Deviation of seconds is NOT acceptable (+/- {0} min)" -f [int]($ToleranceSeconds / 60)) 'bad' }
                } else { & $add "  User $u is a PERMANENT member in AD -- expected a time-limited membership of $want s" 'bad' }
            }
            $pfx = if ($wi -and $x.status -eq 'plan') { '  PLAN (not applied): ' } else { '  PIM for AD: ' }
            switch ("$($x.op)") {
                'none' {
                    if ($x.status -eq 'kept') { & $add "  PIM for AD: $u stays in $g -- $($x.reason)" 'dim' }
                    else { & $add "  PIM for AD: User $u is already member of $g" 'ok' }
                }
                'add' {
                    $tail = if ($null -ne $want) { " with group membership for $(& $min $want) min" } else { '' }
                    if ($x.status -eq 'failed') { & $add "  PIM for AD: FAILED adding user $u to $g -- $($x.reason)" 'bad' }
                    else { & $add "${pfx}Adding user $u to $g$tail" 'change' }
                }
                'readd' {
                    if ($x.status -eq 'failed') { & $add "  PIM for AD: FAILED correcting user $u in $g -- $($x.reason)" 'bad' }
                    else { & $add "${pfx}Adding user $u with group membership for $(& $min $want) min (TTL corrected)" 'change' }
                }
                'remove' {
                    if ($x.status -eq 'failed') { & $add "  PIM for AD: FAILED removing user $u from $g -- $($x.reason)" 'bad' }
                    else { & $add "${pfx}Removing user $u from group $g (no active PIM assignment)" 'change' }
                }
                'read' { & $add "  PIM for AD: the members of $g could not be read -- $($x.reason)" 'bad' }
            }
        }
    }
    foreach ($m in @($Result.missingGroups)) { & $add "Group $m is not in AD yet -- hybrid-ad-groups creates it" 'dim' }
    return $L.ToArray()
}

function Get-PimHybridAdStoreConnectionString {
    $cs = "$($global:PIM_SqlConnectionString)".Trim()
    if (-not $cs -and (Get-Command Get-PimSqlConnectionString -ErrorAction SilentlyContinue)) { try { $cs = "$(Get-PimSqlConnectionString)".Trim() } catch { $cs = '' } }
    return $cs
}

function Publish-PimHybridAdSyncLive {
    <#
      The LIVE view feed -- written ONLY while somebody watches. The Manager's live page sets pim.Settings
      'HybridAdSyncLiveWatch' = { untilUtc } (renewed while the page is open); this reads it at most every -CheckSeconds and,
      while it is in the future, writes 'HybridAdSyncLive' = { updatedUtc; host; pauseSeconds; pamEnabled; passes[] (newest
      last, -KeepPasses); changes[] (the last -KeepChanges add/remove lines, also kept while nobody watches) }.
      Nobody watching = no write at all (internal's Basic database caps the log write rate -- §70.8).
      -Load / -Save / -Clock inject the store (tests). Never throws.
    #>
    param([object]$Result, [datetime]$NowUtc = [datetime]::UtcNow, [int]$PauseSeconds = 5, [int]$KeepPasses = 8, [int]$KeepChanges = 40, [int]$CheckSeconds = 10,
          [scriptblock]$Load, [scriptblock]$Save)
    try {
        if (-not $script:PimHybridAdLive) { $script:PimHybridAdLive = @{ passes = New-Object System.Collections.Generic.List[object]; changes = New-Object System.Collections.Generic.List[object]; checkedUtc = [datetime]::MinValue; watching = $false } }
        $st = $script:PimHybridAdLive
        if (-not $Load -or -not $Save) {
            $cs = Get-PimHybridAdStoreConnectionString
            if (-not $cs -or -not (Get-Command Get-PimSqlSetting -ErrorAction SilentlyContinue)) { return $false }
            # 🔴 PLAIN scriptblocks, NO .GetNewClosure(): a closure cannot see Get-PimSqlSetting dot-sourced into the
            # scheduler's SCRIPT scope -- 2.4.465 on the worker: "Get-PimSqlSetting is not recognized" every pass. They are
            # invoked inside this function, so $cs resolves by dynamic scope.
            $Load = { param($n) Get-PimSqlSetting -ConnectionString $cs -Name $n }
            $Save = { param($n, $v) Set-PimSqlSetting -ConnectionString $cs -Name $n -ValueJson ($v | ConvertTo-Json -Depth 8 -Compress) }
        }
        $inner = if ($Result -and $Result.PSObject.Properties['result'] -and $Result.result) { $Result.result } else { $Result }
        $lines = @(Format-PimHybridAdLiveLines -Result $inner)
        $stamp = $NowUtc.ToUniversalTime().ToString('HH:mm:ss')
        foreach ($l in @($lines | Where-Object { $_.k -eq 'change' -or ($_.k -eq 'bad' -and $_.t -match 'FAILED') })) { $st.changes.Add([ordered]@{ utc = $NowUtc.ToUniversalTime().ToString('o'); t = "$stamp $($l.t.Trim())"; k = $l.k }) }
        while ($st.changes.Count -gt $KeepChanges) { $st.changes.RemoveAt(0) }
        if (($NowUtc - $st.checkedUtc).TotalSeconds -ge $CheckSeconds) {
            $st.checkedUtc = $NowUtc; $w = $null
            try { $w = & $Load 'HybridAdSyncLiveWatch' } catch { $w = $null }
            $until = $null; if ($w) { $raw = if ($w.PSObject.Properties['untilUtc']) { $w.untilUtc } else { $null }; if ($raw -is [datetime]) { $until = $raw.ToUniversalTime() } elseif ($raw) { try { $until = [datetime]::Parse("$raw", [cultureinfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal) } catch { $until = $null } } }
            $st.watching = [bool]($until -and $until -gt $NowUtc)
        }
        if (-not $st.watching) { $st.passes.Clear(); return $false }
        $summary = if ($inner -and $inner.PSObject.Properties['detail']) { "$($inner.detail)" } else { '' }
        $st.passes.Add([ordered]@{ utc = $NowUtc.ToUniversalTime().ToString('o'); summary = $summary; lines = @($lines) })
        while ($st.passes.Count -gt $KeepPasses) { $st.passes.RemoveAt(0) }
        & $Save 'HybridAdSyncLive' ([ordered]@{ updatedUtc = $NowUtc.ToUniversalTime().ToString('o'); host = "$env:COMPUTERNAME"; pauseSeconds = $PauseSeconds
            pamEnabled = [bool]($inner -and $inner.PSObject.Properties['pamEnabled'] -and $inner.pamEnabled); passes = $st.passes.ToArray(); changes = $st.changes.ToArray() })
        return $true
    } catch { Write-Warning "[hybrid-ad-sync] live view not written: $($_.Exception.Message)"; return $false }
}

function Invoke-PimHybridAdSyncLoop {
    <#
      §80.2 -- hybrid-ad-sync runs CONTINUOUSLY, like v1's PIM-Sync-ID-AD-* (`Do { ... } Until ($Pos -eq -1)`: no pause at
      all). Operator 2026-09-29: "the 5 min is not good, as it must go fast ... otherwise people loose 5 min". A person who
      activates a PIM group must be in the AD group within seconds, not at the next scheduler slot.

      Each pass = Invoke-PimScheduledJob hybrid-ad-sync (so the licence + feature gates still decide), then -PauseSeconds.
      Definitions, group ids and users are cached for -RefreshSeconds; the ACTIVE assignments are read on every pass.
      Run history: a pass is RECORDED when it changed something, failed, or -RecordEverySeconds passed since the last record
      -- a record every 5 seconds would bury every other job's history. The heartbeat is refreshed on the same cadence.
      Stops when -MaxMinutes elapsed, -MaxIterations reached, or -StopWhen returns true (the entry point passes "the
      installed version changed", so a code update is picked up by the task restarting it).
      Returns @{ passes; recorded; failures; stopReason }.
    #>
    param(
        [int]$PauseSeconds = 5, [int]$RefreshSeconds = 300, [int]$RecordEverySeconds = 300, [int]$MaxMinutes = 720,
        [int]$MaxIterations = 0, [switch]$WhatIf,
        [scriptblock]$StopWhen = { $false },
        [scriptblock]$Pass = { param($now, $whatIf) Invoke-PimScheduledJob -Job ([pscustomobject]@{ name = 'hybrid-ad-sync'; type = 'hybrid-ad-sync' }) -NowUtc $now -WhatIf:$whatIf },
        [scriptblock]$Record = { param($res, $started) if (Get-Command Write-PimJobRunRecord -ErrorAction SilentlyContinue) { Write-PimJobRunRecord -Job ([pscustomobject]@{ name = 'hybrid-ad-sync'; type = 'hybrid-ad-sync' }) -Result $res -StartedUtc $started -RunId ([guid]::NewGuid().ToString('N')) | Out-Null } },
        [scriptblock]$Heartbeat = { if (Get-Command Save-PimHybridWorkerHeartbeat -ErrorAction SilentlyContinue) { Save-PimHybridWorkerHeartbeat -Scope @('hybrid-ad-sync') -PlanOnly:([bool]$WhatIf) } },   # $WhatIf: the loop's own parameter (dynamic scope)
        [scriptblock]$Sleep = { param($s) Start-Sleep -Seconds $s },
        [scriptblock]$Clock = { [datetime]::UtcNow },
        # 2.4.465: the Manager's LIVE view (written only while somebody watches -- Publish-PimHybridAdSyncLive)
        [scriptblock]$Live = { param($res, $now) [void](Publish-PimHybridAdSyncLive -Result $res -NowUtc $now -PauseSeconds $PauseSeconds) },
        # 🔴 SELF-HEALING (operator 2026-10-02: "it must be running 24x7x365"). A pass that never returns (a REST/LDAP/SQL call
        # waiting forever) froze the loop for 22 h while the task said "Running". -StallMinutes: when no iteration completes for
        # that long, the in-process watchdog KILLS this process and the task's 1-minute trigger starts a fresh loop. 0 = off.
        # -Alive is called once per iteration: it feeds the watchdog and stamps the liveness file the 5-minute tick checks
        # (Invoke-PimHybridSyncWatchdogCheck -- the second, external layer).
        [int]$StallMinutes = 10,
        [scriptblock]$Alive = { param($now) Set-PimHybridSyncAlive -NowUtc $now }
    )
    $script:PimHybridAdCacheSeconds = [math]::Max(0, $RefreshSeconds)
    $start = & $Clock; $lastRecord = [datetime]::MinValue; $lastBeat = [datetime]::MinValue
    $passes = 0; $recorded = 0; $failures = 0; $stop = ''
    if ($StallMinutes -gt 0) { try { Start-PimHybridSyncWatchdog -StallMinutes $StallMinutes } catch { Write-Warning "[hybrid-ad-sync] watchdog not started: $($_.Exception.Message)" } }
    try {
    while ($true) {
        $now = & $Clock
        try { & $Alive $now } catch { }
        if (($now - $lastBeat).TotalSeconds -ge $RecordEverySeconds) { try { & $Heartbeat } catch { }; $lastBeat = $now }
        $res = $null; $threw = $false
        try { $res = & $Pass $now ([bool]$WhatIf) }
        catch { $threw = $true; $res = [pscustomobject]@{ name = 'hybrid-ad-sync'; type = 'hybrid-ad-sync'; ok = $false; ran = $true; detail = "hybrid-ad-sync pass failed: $($_.Exception.Message)" } }
        $passes++
        try { & $Live $res $now } catch { }
        $inner = if ($res -and $res.PSObject.Properties['result']) { $res.result } else { $null }
        $acted = $inner -and $inner.PSObject.Properties['results'] -and @($inner.results | Where-Object { $_.status -eq 'done' -or $_.status -eq 'failed' }).Count -gt 0
        $bad = $threw -or ($res -and $res.PSObject.Properties['ok'] -and -not $res.ok)
        if ($bad) { $failures++ }
        if ($acted -or $bad -or ($now - $lastRecord).TotalSeconds -ge $RecordEverySeconds) {
            try { & $Record $res $now; $recorded++ } catch { Write-Warning "[hybrid-ad-sync] run record not written: $($_.Exception.Message)" }
            $lastRecord = $now
            if ($res) { Write-Host ("[hybrid-ad-sync] {0:HH:mm:ss} {1}" -f $now, "$($res.detail)") }
        }
        if ($MaxIterations -gt 0 -and $passes -ge $MaxIterations) { $stop = "max iterations ($MaxIterations)"; break }
        if (((& $Clock) - $start).TotalMinutes -ge $MaxMinutes) { $stop = "max runtime ($MaxMinutes min) -- the task restarts it"; break }
        $why = $null; try { $why = & $StopWhen } catch { $why = $null }
        if ($why) { $stop = "$why"; break }
        # a failing pass backs off (DC or Graph down must not become a tight error loop); a healthy one pauses -PauseSeconds
        & $Sleep $(if ($bad) { [math]::Min(60, $PauseSeconds * 6) } else { $PauseSeconds })
    }
    } finally { if ($StallMinutes -gt 0) { Stop-PimHybridSyncWatchdog } }
    Write-Host "[hybrid-ad-sync] loop stopped after $passes pass(es): $stop"
    return [pscustomobject]@{ passes = $passes; recorded = $recorded; failures = $failures; stopReason = $stop }
}

# ---- self-healing of the continuous sync (operator 2026-10-02: "it must be running 24x7x365") -----------------------------
# Layer 1 (in-process): a .NET timer THREAD -- not a PowerShell event, which never fires while the pipeline is blocked in a
#   call -- that kills this process when no loop iteration completed for -StallMinutes. The task restarts the loop in <= 1 min.
# Layer 2 (external, Invoke-PimHybridSyncWatchdogCheck): the 5-minute hybrid tick reads the liveness file and kills a sync
#   process whose stamp is stale -- for the case where layer 1 itself is wedged.
function Get-PimHybridSyncAlivePath {
    if ("$env:PIM_HybridSyncAliveFile".Trim()) { return "$env:PIM_HybridSyncAliveFile".Trim() }
    $base = if ($env:ProgramData) { $env:ProgramData } else { [IO.Path]::GetTempPath() }
    return (Join-Path $base 'PIM4EntraPS\hybrid-ad-sync.alive')
}
function Set-PimHybridSyncAlive {
    param([datetime]$NowUtc = [datetime]::UtcNow)
    if ('PimHybridSyncWatchdog' -as [type]) { [PimHybridSyncWatchdog]::Beat() }
    $p = Get-PimHybridSyncAlivePath
    $d = Split-Path $p -Parent
    if (-not (Test-Path -LiteralPath $d)) { New-Item -ItemType Directory -Force -Path $d | Out-Null }
    [IO.File]::WriteAllText($p, ("{0}|{1}" -f $NowUtc.ToUniversalTime().ToString('o'), $PID))
}
function Get-PimHybridSyncAlive {
    # -> @{ utc; pid } or $null (no file / unreadable)
    $p = Get-PimHybridSyncAlivePath
    if (-not (Test-Path -LiteralPath $p)) { return $null }
    try {
        $parts = ([IO.File]::ReadAllText($p)).Trim() -split '\|'
        $at = Get-PimUtcStamp $parts[0]
        if ($null -eq $at) { return $null }
        $procId = 0; if ($parts.Count -gt 1) { [void][int]::TryParse($parts[1], [ref]$procId) }
        return [pscustomobject]@{ utc = $at; pid = $procId }
    } catch { return $null }
}
function Start-PimHybridSyncWatchdog {
    param([int]$StallMinutes = 10, [int]$StallSeconds = 0)   # -StallSeconds: tests only (floor 3 s); production floor is 60 s
    if (-not ('PimHybridSyncWatchdog' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Diagnostics;
using System.IO;
using System.Threading;
public static class PimHybridSyncWatchdog {
    static long _last = DateTime.UtcNow.Ticks;
    static long _limit;
    static Timer _timer;
    static string _log;
    public static void Start(int stallSeconds, string logPath) {
        _log = logPath;
        Interlocked.Exchange(ref _limit, TimeSpan.FromSeconds(stallSeconds).Ticks);
        Beat();
        if (_timer == null) { _timer = new Timer(Check, null, 15000, 15000); }
    }
    public static void Beat() { Interlocked.Exchange(ref _last, DateTime.UtcNow.Ticks); }
    public static double IdleSeconds() { return TimeSpan.FromTicks(DateTime.UtcNow.Ticks - Interlocked.Read(ref _last)).TotalSeconds; }
    public static void Stop() { Interlocked.Exchange(ref _limit, 0); if (_timer != null) { _timer.Dispose(); _timer = null; } }
    static void Check(object state) {
        long limit = Interlocked.Read(ref _limit);
        if (limit <= 0 || DateTime.UtcNow.Ticks - Interlocked.Read(ref _last) <= limit) { return; }
        string line = DateTime.UtcNow.ToString("o") + " WATCHDOG: no hybrid-ad-sync iteration for " + ((int)IdleSeconds()) + " s -- killing process " + Process.GetCurrentProcess().Id + "; the task starts a fresh loop within a minute";
        try { if (!String.IsNullOrEmpty(_log)) { File.AppendAllText(_log, line + Environment.NewLine); } } catch { }
        try { Console.Error.WriteLine("[hybrid-ad-sync] " + line); } catch { }
        Process.GetCurrentProcess().Kill();
    }
}
'@
    }
    $log = Join-Path (Split-Path (Get-PimHybridSyncAlivePath) -Parent) 'hybrid-ad-sync-watchdog.log'
    $secs = if ($StallSeconds -gt 0) { [math]::Max(3, $StallSeconds) } else { [math]::Max(60, $StallMinutes * 60) }
    [PimHybridSyncWatchdog]::Start($secs, $log)
}
function Stop-PimHybridSyncWatchdog { if ('PimHybridSyncWatchdog' -as [type]) { [PimHybridSyncWatchdog]::Stop() } }
function Invoke-PimHybridSyncWatchdogCheck {
    <#
      Layer 2, run by the 5-minute hybrid tick: when the continuous loop's liveness stamp is older than -StaleMinutes, the
      process that wrote it (the pid in the stamp, and only if its command line is the sync loop) is killed; the sync task's
      1-minute trigger then starts a fresh one. No stamp at all = nothing to judge (older version, never started) -> no action.
      Returns @{ action = 'ok'|'none'|'killed'|'gone'; detail }.
    #>
    param([int]$StaleMinutes = 15, [datetime]$NowUtc = [datetime]::UtcNow,
        [scriptblock]$GetProcess = { param($procId) Get-CimInstance Win32_Process -Filter "ProcessId=$procId" -ErrorAction SilentlyContinue },
        [scriptblock]$Kill = { param($procId) Stop-Process -Id $procId -Force -ErrorAction Stop })
    $a = Get-PimHybridSyncAlive
    if (-not $a) { return [pscustomobject]@{ action = 'none'; detail = 'no liveness stamp yet' } }
    $age = ($NowUtc.ToUniversalTime() - $a.utc).TotalMinutes
    if ($age -le $StaleMinutes) { return [pscustomobject]@{ action = 'ok'; detail = ("sync loop alive ({0:N1} min ago, pid {1})" -f $age, $a.pid) } }
    if ($a.pid -le 0) { return [pscustomobject]@{ action = 'none'; detail = 'stale stamp without a pid' } }
    $p = & $GetProcess $a.pid
    if (-not $p) { return [pscustomobject]@{ action = 'gone'; detail = ("stale stamp ({0:N0} min) and pid {1} is gone -- the task starts a new loop" -f $age, $a.pid) } }
    if ("$($p.CommandLine)" -notmatch 'Mode Sync|ContinuousJob') { return [pscustomobject]@{ action = 'none'; detail = "pid $($a.pid) is not the sync loop (reused pid) -- left alone" } }
    & $Kill $a.pid
    return [pscustomobject]@{ action = 'killed'; detail = ("sync loop pid {0} made no progress for {1:N0} min -- killed; the task restarts it within a minute" -f $a.pid, $age) }
}

# =====================================================================================================================
# §80.2 SERVER ONBOARDING -- replaces AD-ManageLocalAdministratorsGroupMembership.ps1 + Custom-LocalGroups-*.ps1
# (operator 2026-09-29 wizard: "Server onboarding").
#   v1, per enabled Windows Server changed in the last 90 days (domain controllers skipped): created the Entra group
#   PIM-AD-SRV-<server>-ID-S_AD, onboarded it in PIM, created the AD group, and put that group + the shared "all servers"
#   group into the server's local Administrators over WinRM.
#   v2 splits it along the "engine touches only DEFINED objects" rule:
#     1. the worker LISTS the servers into the tenant cache 'ad-servers';
#     2. Discovery shows each server without a defined group as an 'ad-server' item -> Create stages the per-server
#        permission group (customer naming) -> Commit -> the cloud engine creates the Entra group, hybrid-ad-groups
#        mirrors it to AD, hybrid-ad-sync fills it just in time;
#     3. 'hybrid-ad-servers' puts the DEFINED per-server group (+ HybridAdServerAdminsGroup, v1's shared group) into the
#        server's local Administrators. ADD ONLY, as v1: it never removes a local administrator.
# =====================================================================================================================

function Get-PimHybridAdServerGroupName {
    <#
      The per-server PIM group for -Server in the CUSTOMER's naming. Default format (v1 shape, built from the customer's
      own parts): '{prefix}AD-SRV-{server}{cloud}{marker}' -> 'PIM-AD-SRV-FS01-ID-S_AD'. Setting HybridAdServerGroupFormat
      overrides the format ({prefix} {server} {cloud} {marker}).
    #>
    param([Parameter(Mandatory)][string]$Server)
    $fmt = "$(Get-PimHybridAdSetting -Name 'HybridAdServerGroupFormat' -Default '{prefix}AD-SRV-{server}{cloud}{marker}')".Trim()
    $prefix = ''
    if (Get-Command Get-PimGroupNamePrefix -ErrorAction SilentlyContinue) { try { $prefix = "$(Get-PimGroupNamePrefix)".Trim() } catch { $prefix = '' } }
    $marker = "$(Get-PimHybridAdSetting -Name 'HybridAdGroupMarker' -Default '-S_AD')".Trim()
    $sfx = Get-PimHybridAdSuffixes
    return $fmt.Replace('{prefix}', $prefix).Replace('{server}', "$Server".Trim()).Replace('{cloud}', $sfx.cloud).Replace('{marker}', $marker)
}

function Get-PimHybridAdServerCandidates {
    <#
      PURE. AD computer objects -> the servers v1 onboarded: Enabled, OperatingSystem 'Windows Server*', changed within
      -ActiveDays (90), NOT a domain controller (primaryGroupID 516 -- no local Administrators group). Returns
      @{ name; dnsHostName; os; whenChanged } sorted by name.
    #>
    param([object[]]$Computers = @(), [datetime]$NowUtc = [datetime]::UtcNow, [int]$ActiveDays = 90)
    $cut = $NowUtc.ToUniversalTime().AddDays(-$ActiveDays)
    @($Computers | Where-Object {
            $_ -and [bool]$_.Enabled -and "$($_.OperatingSystem)" -match 'Windows Server' -and "$($_.primaryGroupID)" -ne '516' -and
            $_.whenChanged -and ([datetime]$_.whenChanged).ToUniversalTime() -gt $cut
        } | ForEach-Object { [pscustomobject]@{ name = "$($_.Name)"; dnsHostName = "$($_.DNSHostName)"; os = "$($_.OperatingSystem)"; whenChanged = ([datetime]$_.whenChanged).ToUniversalTime().ToString('o') } } |
        Sort-Object name)
}

function Get-PimHybridAdLocalAdminPlan {
    <#
      PURE. One server. -Want: the accounts that must be local administrators ('DOMAIN\group'). -Live: the current members'
      names. Returns @{ add[]; present[] } -- case-insensitive. ADD ONLY (v1): an existing member is never removed.
    #>
    param([string[]]$Want = @(), [string[]]$Live = @())
    $have = @{}; foreach ($l in @($Live)) { if ("$l".Trim()) { $have["$l".Trim().ToLowerInvariant()] = $true } }
    $add = @(); $present = @()
    foreach ($w in @($Want | Where-Object { "$_".Trim() } | Select-Object -Unique)) { if ($have.ContainsKey("$w".Trim().ToLowerInvariant())) { $present += "$w".Trim() } else { $add += "$w".Trim() } }
    return @{ add = $add; present = $present }
}

function Get-PimDefaultServerAdapter {
    <#
      [ ] HYBRID-WORKER-ONLY. AD computer listing + local Administrators over WinRM, as the PROCESS identity (the gMSA --
      it needs local administrator rights on the servers, e.g. through the group your GPO makes local admin everywhere).
      🔴 No factory locals in the blocks (2.4.459): they call functions only.
    #>
    if (-not (Get-Command Get-ADComputer -ErrorAction SilentlyContinue)) { throw 'ActiveDirectory module not available -- the server adapter is hybrid-worker-only.' }
    return @{
        GetComputers = {
            $s = Get-PimHybridAdServerSplat
            @(Get-ADComputer -Filter 'OperatingSystem -like "*Windows Server*"' -Properties Name, DNSHostName, OperatingSystem, Enabled, whenChanged, primaryGroupID @s -ErrorAction Stop)
        }
        GetLocalAdmins = {
            param([string]$Computer)
            @(Invoke-Command -ComputerName $Computer -ErrorAction Stop -ScriptBlock { @(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop | ForEach-Object { "$($_.Name)" }) })
        }
        AddLocalAdmin = {
            param([string]$Computer, [string]$Member)
            Invoke-Command -ComputerName $Computer -ErrorAction Stop -ArgumentList $Member -ScriptBlock { param($m) Add-LocalGroupMember -SID 'S-1-5-32-544' -Member $m -ErrorAction Stop }
        }
    }
}

function Invoke-PimHybridAdServersJob {
    <#
      The 'hybrid-ad-servers' job. (1) lists the AD servers into the tenant cache 'ad-servers' (Discovery reads it);
      (2) for every candidate server whose per-server group is DEFINED and exists in AD, puts DOMAIN\<that group> and the
      shared HybridAdServerAdminsGroup into local Administrators (add only). A server WinRM cannot reach is reported
      'unreachable' and does not fail the job (servers are switched off, v1 ignored them silently); an ADD that fails
      (access denied) does -- it THROWS.
    #>
    param([datetime]$NowUtc = [datetime]::UtcNow, [switch]$WhatIf, [object[]]$Rows = $null, [hashtable]$Adapter, [hashtable]$GroupAdapter,
          [scriptblock]$SaveCache, [string]$Netbios = '', [object]$AdModulePresent = $null, [scriptblock]$SecretReader)
    # 2.4.463: a tenant with NO defined AD-marked group has nothing for server onboarding to do -- answer that, like
    # hybrid-ad-groups / -sync do, instead of "hybrid worker required" (which is 'not implemented' = a red job every hour for
    # every cloud-only customer; seen on ig798, EFIF and RIDE after 2.4.461). With a worker present the listing still runs.
    if (-not $Adapter -or -not $GroupAdapter) {
        $pre = Get-PimHybridAdMirroredDefinitions -Rows $Rows
        if ($pre.ok -and -not @($pre.rows).Count) {
            $capPre = Test-PimHybridAdWorkerCapability -AdModulePresent $AdModulePresent -SecretReader $SecretReader
            if (-not $capPre.ok) { return [pscustomobject]@{ ran = $true; servers = 0; whatIf = [bool]$WhatIf; detail = "hybrid-ad-servers: no defined group matches '$($pre.pattern)' and no hybrid worker runs here -- nothing to onboard" } }
        }
    }
    if (-not $Adapter -or -not $GroupAdapter) {
        $cap = Test-PimHybridAdWorkerCapability -AdModulePresent $AdModulePresent -SecretReader $SecretReader
        if (-not $cap.ok) {
            return [pscustomobject]@{ ran = $false; unimplemented = $true; requiresHybridWorker = $true; whatIf = [bool]$WhatIf
                detail = "hybrid worker required: server onboarding lists AD servers and sets their local Administrators, and $($cap.reason). Run the scheduler on the hybrid worker (Start-PimScheduler.ps1 -Jobs hybrid-ad-servers)" }
        }
        if (-not $Adapter) { $Adapter = Get-PimDefaultServerAdapter }
        if (-not $GroupAdapter) { $GroupAdapter = Get-PimDefaultActiveDirectoryGroupAdapter }
    }
    if (-not $Netbios) { try { $Netbios = "$((Get-ADDomain -ErrorAction Stop).NetBIOSName)" } catch { $Netbios = '' } }
    $servers = @(Get-PimHybridAdServerCandidates -Computers @(& $Adapter.GetComputers) -NowUtc $NowUtc)
    $defs = Get-PimHybridAdMirroredDefinitions -Rows $Rows
    if (-not $defs.ok) { return [pscustomobject]@{ ran = $false; unimplemented = $true; whatIf = [bool]$WhatIf; detail = "unimplemented:hybrid-ad-servers -- $($defs.reason)" } }
    $inAd = @{}; foreach ($g in @(& $GroupAdapter.GetGroups $defs.pattern)) { if ($g) { $inAd["$($g.Name)".ToLowerInvariant()] = $true } }
    # 2.4.464 ("hybrid must handle things in smart way"): each cached server carries its per-server group name and whether
    # that group ALREADY exists in AD (v1 made them for every server) -- Discovery then says Create ADOPTS the existing group.
    foreach ($sv in $servers) {
        $gn0 = Get-PimHybridAdServerGroupName -Server $sv.name
        $sv | Add-Member -NotePropertyName groupName -NotePropertyValue $gn0 -Force
        $sv | Add-Member -NotePropertyName groupInAd -NotePropertyValue ([bool]$inAd.ContainsKey($gn0.ToLowerInvariant())) -Force
    }
    if (-not $SaveCache) {
        $SaveCache = {
            param($items)
            if (-not (Get-Command Set-PimSqlTenantCache -ErrorAction SilentlyContinue)) { throw 'Set-PimSqlTenantCache is not loaded' }
            $cs = "$($global:PIM_SqlConnectionString)".Trim()
            if (-not $cs -and (Get-Command Get-PimSqlConnectionString -ErrorAction SilentlyContinue)) { $cs = "$(Get-PimSqlConnectionString)".Trim() }
            if (-not $cs) { throw 'no SQL store connection' }
            Set-PimSqlTenantCache -ConnectionString $cs -Kind 'ad-servers' -Value ([ordered]@{ refreshedUtc = [datetime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ'); items = @($items) })
        }
    }
    try { & $SaveCache $servers } catch { Write-Warning "[hybrid-ad-servers] the server list was not cached: $($_.Exception.Message)" }
    $defined = @{}; foreach ($d in @($defs.rows)) { $defined["$($d.GroupName)".Trim().ToLowerInvariant()] = $true }
    $shared = "$(Get-PimHybridAdSetting -Name 'HybridAdServerAdminsGroup' -Default '')".Trim()
    $qual = { param($n) if ("$n" -match '\\' -or -not $Netbios) { "$n" } else { "$Netbios\$n" } }
    $res = New-Object System.Collections.Generic.List[object]
    foreach ($sv in $servers) {
        $gn = $sv.groupName
        if (-not $defined.ContainsKey($gn.ToLowerInvariant())) {
            # v1 made a group for every server: an EXISTING one is adopted by Create (the engine matches Entra groups by
            # name), so say that instead of offering what looks like a brand-new group. Nothing on the server changes.
            if ($sv.groupInAd) { $res.Add([pscustomobject]@{ server = $sv.name; member = $gn; status = 'adopt'; reason = 'the group already exists (v1) but is not defined -- Discovery > Create adopts it; until then nothing here changes' }) }
            else { $res.Add([pscustomobject]@{ server = $sv.name; member = $gn; status = 'not defined'; reason = 'no defined group -- Discovery offers it (Create)' }) }
            continue
        }
        if (-not $sv.groupInAd) { $res.Add([pscustomobject]@{ server = $sv.name; member = $gn; status = 'waiting'; reason = 'not in AD yet -- hybrid-ad-groups creates it' }); continue }
        $want = @(& $qual $gn); if ($shared) { $want += (& $qual $shared) }
        $target = if ($sv.dnsHostName) { $sv.dnsHostName } else { $sv.name }
        try { $live = @(& $Adapter.GetLocalAdmins $target) }
        catch {
            # ACCESS DENIED (the worker identity is not a local administrator there) is a setup gap with ONE fix, not an
            # offline server -- tell them apart, so the hint is exact.
            $m = "$($_.Exception.Message)"
            if (Test-PimHybridAdAccessDenied -Message $m) { $res.Add([pscustomobject]@{ server = $sv.name; member = ''; status = 'no access'; reason = $m }) }
            else { $res.Add([pscustomobject]@{ server = $sv.name; member = ''; status = 'unreachable'; reason = $m }) }
            continue
        }
        $plan = Get-PimHybridAdLocalAdminPlan -Want $want -Live $live
        foreach ($p in $plan.present) { $res.Add([pscustomobject]@{ server = $sv.name; member = $p; status = 'present'; reason = '' }) }
        foreach ($a in $plan.add) {
            if ($WhatIf) { $res.Add([pscustomobject]@{ server = $sv.name; member = $a; status = 'plan'; reason = 'add to local Administrators' }); continue }
            try { & $Adapter.AddLocalAdmin $target $a | Out-Null; $res.Add([pscustomobject]@{ server = $sv.name; member = $a; status = 'added'; reason = '' }) }
            catch { $res.Add([pscustomobject]@{ server = $sv.name; member = $a; status = $(if (Test-PimHybridAdAccessDenied -Message "$($_.Exception.Message)") { 'no access' } else { 'failed' }); reason = "$($_.Exception.Message)" }) }
        }
    }
    Write-PimHybridAdItemLines -Job 'hybrid-ad-servers' -Lines @($res | Where-Object { $_.status -ne 'present' } | ForEach-Object { "{0,-11} {1} / {2}  {3}" -f $_.status, $_.server, $_.member, $_.reason })
    $c = { param($s) @($res | Where-Object { $_.status -eq $s }).Count }
    $failed = @($res | Where-Object { $_.status -eq 'failed' })
    $noAccess = @($res | Where-Object { $_.status -eq 'no access' } | ForEach-Object { $_.server } | Select-Object -Unique)
    $wi = if ($WhatIf) { ' (whatif)' } else { '' }
    $detail = ("hybrid-ad-servers{0}: servers={1} planned={2} added={3} present={4} adopt={5} not-defined={6} waiting={7} unreachable={8} no-access={9} failed={10}" -f $wi, $servers.Count, (& $c 'plan'), (& $c 'added'), (& $c 'present'), (& $c 'adopt'), (& $c 'not defined'), (& $c 'waiting'), (& $c 'unreachable'), $noAccess.Count, $failed.Count)
    $why = @()
    if ($noAccess.Count) {
        # ONE hint for all of them. v1 had rights everywhere because its gMSA was a Domain Admin. 2.4.467 (operator's
        # identity design): the server-onboarding gMSA's <name>-PermissionGroup is local administrator through the servers
        # GPO -- NEVER a PIM just-in-time group (the PIM-for-AD sync removes non-activated members; it removed the first one).
        $me = "$env:PIM_HybridAdGmsaName".Trim(); if (-not $me) { $me = '<server gMSA>' }
        $how = "the servers need '$me-PermissionGroup' in their local Administrators -- Initialize-PimHybridWorkerAd.ps1 -ServerGmsaName <name> -ServerOu <servers OU> creates the GPO that adds it; then gpupdate /target:computer on the server (or wait for its refresh)"
        $why += ("the worker is not a local administrator on {0}: {1}" -f ($noAccess -join ', '), $how)
    }
    if ($failed.Count) { $why += @($failed | ForEach-Object { "$($_.server)/$($_.member): $($_.reason)" }) }
    if ($why.Count) { throw ("$detail -- " + ($why -join '; ')) }
    return [pscustomobject]@{ ran = $true; whatIf = [bool]$WhatIf; servers = $servers.Count; results = $res.ToArray(); detail = $detail }
}
