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
    * 100.122 F1 (2026-10-13) -- NEVER REMOVE ON A DOUBT. The rule above is the design and stays; what is not the design is a
      failed or wrong read taken as "nobody is active". The Entra group behind an AD group has three answers (found /
      confirmed gone / not known), it is looked up by its remembered object id, and a removal is made only with the group
      found and its active list read in full: at once when the member's recorded end time has passed, otherwise when the
      next complete pass says the same. Not known = nobody is removed in that pass; confirmed gone (24 hours) = the members
      stay and wait for a SuperAdmin. See "100.122 F1" below Get-PimHybridAdMembershipPlan.
    * No plaintext gMSA password anywhere: the task runs AS the gMSA (PIM-HybridAd.ps1 Test-PimHybridAdRunAsGmsa).
    * -WhatIf / plan mode on every step; results are returned for the worker's status report.
    * The PAM feature is DETECTED, never enabled (enabling it is irreversible for the forest).
#>

function Test-PimHybridAdFunction {
    # Is this PIM function loaded? 🔴 NOT Get-Command: for a name that is NOT loaded, Get-Command searches every folder of
    # PATH for an executable -- ~55 ms a call, measured 2026-10-13. The continuous sync asks this many times per pass (the
    # setting reader asks once per setting), so a pass spent most of its time looking for files. Every name asked here is a
    # PowerShell function, so the function drive is the whole answer (it sees functions of the calling scopes too).
    param([Parameter(Mandatory)][string]$Name)
    return [bool](Test-Path -LiteralPath "Function:\$Name")
}

function Get-PimHybridAdSetting {
    # One reader: $global:PIM_<Name> -> $env:PIM_<Name> -> hydrated pim.Settings -> default (Get-PimAdminLifecycleSetting when loaded).
    param([Parameter(Mandatory)][string]$Name, $Default = $null)
    if (Test-PimHybridAdFunction 'Get-PimAdminLifecycleSetting') { return (Get-PimAdminLifecycleSetting -Name $Name -Default $Default) }
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
# GS-NAMING-ALL (owner 2026-10-09): 'naming = $true' marks a knob that NAMES something -- the Get Started Naming step shows
# exactly those (GET /api/settings/naming-catalog), with 'example' = what it renders as ({value} = the field, {=Key} =
# another field, {@groupPrefix} / {@entraSuffix} / {@adSuffix} = derived from the naming; 'exampleTokens' fills this
# knob's own tokens). A knob without the flag (batch size, parallelism, never-remove list) is not naming.
$script:PimHybridAdSettingCatalog = @(
    [ordered]@{ name = 'HybridAdGroupMarker'; label = 'AD group marker'; naming = $true; example = '{@groupPrefix}*{value}'; default = '-S_AD'; help = 'The end of a PIM group name that marks it as ALSO an on-premises AD group. The mirrored pattern is your group prefix + * + this marker.' }
    [ordered]@{ name = 'HybridAdGroupPattern'; label = 'Pattern override'; naming = $true; example = '{value}'; blankExample = '{@groupPrefix}*{=HybridAdGroupMarker}'; default = ''; help = 'Leave blank to derive it (prefix + * + marker). Set a full wildcard only when your AD groups do not follow that shape.' }
    [ordered]@{ name = 'HybridAdCloudSuffix'; label = 'Cloud admin suffix'; naming = $true; example = 'Admin-ABC{=HybridAdCloudSuffix|@entraSuffix} -> Admin-ABC{=HybridAdAccountSuffix|@adSuffix}'; default = ''; help = 'The end of a cloud admin account name that is swapped for the AD suffix. Blank = the Entra suffix of your naming conventions.' }
    [ordered]@{ name = 'HybridAdAccountSuffix'; label = 'AD admin suffix'; naming = $true; example = 'Admin-ABC{=HybridAdCloudSuffix|@entraSuffix} -> Admin-ABC{=HybridAdAccountSuffix|@adSuffix}'; default = ''; help = 'The end of the matching AD admin account. Blank = the AD suffix of your naming conventions. Only users carrying it are ever removed from an AD group.' }
    [ordered]@{ name = 'HybridAdGroupsOu'; label = 'OU for new AD groups'; naming = $true; default = ''; help = 'Distinguished name of the OU where missing AD groups are created (OU=...,DC=...). Blank = groups are never created, only kept in sync.' }
    [ordered]@{ name = 'HybridAdServerGroupFormat'; label = 'Per-server group format'; naming = $true; example = '{value}'; exampleTokens = [ordered]@{ prefix = '{@groupPrefix}'; server = 'FS01'; cloud = '{=HybridAdCloudSuffix|@entraSuffix}'; marker = '{=HybridAdGroupMarker}' }; default = '{prefix}AD-SRV-{server}{cloud}{marker}'; help = 'The name of the group that becomes local administrator on one server. Tokens: {prefix} {server} {cloud} {marker}. {server} is required.' }
    [ordered]@{ name = 'HybridAdServerAdminsGroup'; label = 'Shared server-admins group'; naming = $true; default = ''; help = 'A group every onboarded server also gets in its local Administrators (and that the worker''s account is a member of). Blank = none.' }
    [ordered]@{ name = 'HybridAdProtectedMembers'; label = 'Never remove'; naming = $false; default = ''; help = 'Comma-separated account names the sync never removes from an AD group.' }
    # 2026-10-04 scale (operator: "it could run fx 50 servers per batch"): the server lane's parallel Graph reads
    [ordered]@{ name = 'HybridAdSyncBatchSize'; label = 'Groups per batch'; naming = $false; default = '50'; help = 'How many AD groups one parallel batch reads from Graph per pass (the server lane cuts its groups into batches of this size). 1-1000.' }
    [ordered]@{ name = 'HybridAdSyncParallel'; label = 'Batches at once'; naming = $false; default = '8'; help = 'How many batches run at the same time (PowerShell 7 on the hybrid worker). Higher is faster until Graph starts throttling. 1-64.' }
    # 100.122 F1, owner's decision (29) 2026-10-13: the correct UTC reading of an activation's end time is a switch PER
    # INSTALL, off by default (an upgrade changes no membership). Read by Test-PimHybridAdEndTimeAsUtc.
    [ordered]@{ name = 'HybridAdEndTimeAsUtc'; label = 'Read activation end times as UTC'; naming = $false; default = 'off'; help = 'on = the end time of an activation is always read as UTC. off (or blank) = as before: on a hybrid worker whose clock is not set to UTC, a membership can end earlier or later by the time zone difference. Switching it re-adds every active member once with the corrected time. Type on or off.' }
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
            'HybridAdSyncBatchSize' { $i = 0; if ($v -and (-not [int]::TryParse($v, [ref]$i) -or $i -lt 1 -or $i -gt 1000)) { $err.Add('Groups per batch: a whole number 1-1000 (or blank = 50)') } }
            'HybridAdSyncParallel' { $i = 0; if ($v -and (-not [int]::TryParse($v, [ref]$i) -or $i -lt 1 -or $i -gt 64)) { $err.Add('Batches at once: a whole number 1-64 (or blank = 8)') } }
            'HybridAdEndTimeAsUtc' { if ($v -and $v -notmatch '^(?i)(on|off)$') { $err.Add('Read activation end times as UTC: on or off (or blank = off)') } else { $v = $v.ToLowerInvariant() } }
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
    if (Test-PimHybridAdFunction 'Get-PimGroupNamePrefix') { try { $prefix = "$(Get-PimGroupNamePrefix)".Trim() } catch { $prefix = '' } }
    return "$prefix*$marker"
}

function Get-PimHybridAdSuffixes {
    <#
      The cloud -> AD account suffixes from the CUSTOMER's naming conventions (EnvironmentSuffixes: entra / ad -- v1 '-ID'
      / '-AD'), overridable by HybridAdCloudSuffix / HybridAdAccountSuffix. Nothing is hard-coded here: a tenant whose
      conventions name no suffix maps an admin to the same name in AD. Returns @{ cloud; ad }.
    #>
    $map = $null
    if (Test-PimHybridAdFunction 'Get-PimNamingConvention') { try { $map = Get-PimNamingConvention -Key 'EnvironmentSuffixes' } catch { $map = $null } }
    if (-not $map -and $global:PIM_NamingConventions -is [System.Collections.IDictionary] -and $global:PIM_NamingConventions.Contains('EnvironmentSuffixes')) { $map = $global:PIM_NamingConventions['EnvironmentSuffixes'] }
    if (-not $map -and (Test-PimHybridAdFunction 'Get-PimShippedNamingConventions')) { try { $map = (Get-PimShippedNamingConventions)['EnvironmentSuffixes'] } catch { $map = $null } }
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

# ---- 100.122 F1: NEVER REMOVE ON A DOUBT ---------------------------------------------------------------------------------
# Owner 2026-10-13: "we can not have any wrongly deletions of data" / "so we dont flush a group in ad, that would be
# critically". Get-PimHybridAdMembershipPlan above stays exactly as it was (the just-in-time rule: a suffix-named user
# without an active assignment leaves the AD group). Everything below only ever takes removals OUT of that plan:
#   * the Entra group has these answers, never two -- FOUND / NOT KNOWN / GONE / REPLACED (another group carries the name) /
#     RENAMED. NOT KNOWN (a failed, throttled or partial read, a name search that came back empty, an id never seen, a
#     group that no longer carries the defined name) = nobody is removed in this pass;
#   * CONFIRMED GONE (the remembered id answers 404 and the deleted items were checked, over 24 hours), NEVER SEEN for 24
#     hours and REPLACED never empty an AD group by themselves: the members stay and the group waits for a SuperAdmin,
#     whose decision arrives as the record 'HybridAdSyncMemory.<job>.decisions' (take the replacement group as the one, or
#     remove NAMED members; valid 48 hours, used only while the group is in exactly the state it was made for). In a
#     REPLACED group a member remembered from the old group leaves when the end time recorded for them has passed;
#   * with the group FOUND and the read complete: an EXPECTED removal (the end time recorded for the member has passed) is
#     made at once, whatever the number; an UNEXPECTED one (the member left the active list before that end time, or no end
#     time was ever recorded) is made only when a second complete pass at least 5 and at most 30 minutes after the first
#     says the same. A hold is a wait state every pass decides again -- nothing here waits for a person. A recorded end
#     time is trusted while the complete passes are not more than 30 minutes apart (the owner: Entra has trouble for 30
#     minutes, the end time passes meanwhile -> removed as expected when it answers again); after a longer gap it is stale
#     and the member takes the two-pass way.
#   * a doubt is VISIBLE at once: a pass that keeps anybody returns a WARNING for the job, and a group that has kept
#     members for 30 minutes raises the guard alert, again every 4 hours until it heals.
# Windows, counts and limits come from FUNCTIONS returning a literal: a $script: variable is $null in a child script scope.
function Get-PimHybridAdGoneConfirmHours { return 24 }      # owner's decision (14): 24 hours before "gone" counts as confirmed
function Get-PimHybridAdGoneConfirmMinMarks { return 3 }    # ... seen gone in at least 3 different clock hours of that window
function Get-PimHybridAdNeverSeenHours { return 24 }        # an Entra group never seen and still not there after this = waits for a SuperAdmin
function Get-PimHybridAdConfirmMinMinutes { return 5 }      # the confirming pass is at least this long after the first sighting
function Get-PimHybridAdConfirmMaxMinutes { return 30 }     # ... and at most this long; older = the wait starts again
function Get-PimHybridAdHoldAlertMinutes { return 30 }      # a group that has kept members for this long raises the alert
function Get-PimHybridAdHoldAlertRepeatHours { return 4 }   # ... again every 4 hours until it heals
function Get-PimHybridAdWaitingAlertRepeatHours { return 24 }   # "waiting for a SuperAdmin": at once, then once a day
function Get-PimHybridAdAlertRetryMinutes { return 5 }      # an alert that was not delivered is tried again after this
function Get-PimHybridAdStaleMinutes { return 30 }          # no pass for this long = the recorded end times are stale
function Get-PimHybridAdOrphanPasses { return 3 }           # a principal that answers "not found" on this many passes ...
function Get-PimHybridAdOrphanMinutes { return 30 }         # ... over this long is an assignment for an account that no longer exists
function Get-PimHybridAdMemoryBucketCount { return 32 }     # the sync memory is kept in this many small settings (one write = one bucket)
function Get-PimHybridAdMemoryMaxMembers { return 500 }     # members remembered per AD group (active list, and the waiting ones)
function Get-PimHybridAdMemoryMaxOrphans { return 50 }      # "not found" principals tracked per AD group
function Get-PimHybridAdWaitingMaxMembers { return 200 }    # member names listed per group in the "waiting for a SuperAdmin" record
function Get-PimHybridAdDecisionMaxHours { return 48 }      # a SuperAdmin's decision in the decisions record is used for this long, then it is dead
function Get-PimHybridAdDecisionFutureMinutes { return 10 } # ... and never one dated further ahead than this (two clocks)
function Test-PimHybridAdEndTimeAsUtc {
    <#
      Owner's decision (29), 2026-10-13: is a [datetime] end time read as UTC (the correct reading) on THIS install?
      The per-install setting 'HybridAdEndTimeAsUtc' (pim.Settings, its own row; Settings > Hybrid Active Directory, a
      SuperAdmin) = 'on'. Read like every other hybrid knob (Get-PimHybridAdSetting: the global, the worker's environment
      variable PIM_HybridAdEndTimeAsUtc, then the settings hydrated from the SQL store). DEFAULT OFF, and OFF on anything
      else: not set, blank, any other text, a reader that throws -- so an upgrade, or a store that cannot be read, changes
      no membership. $false = the end time is read exactly as before this lane (see ConvertTo-PimHybridAdEndUtc).
    #>
    try { return [bool]("$(Get-PimHybridAdSetting -Name 'HybridAdEndTimeAsUtc' -Default '')".Trim() -ieq 'on') }
    catch { return $false }
}

function ConvertTo-PimHybridAdEpoch {
    # whole seconds since 1970 (UTC). The memory keeps numbers, never date text (ConvertFrom-Json turns date text into a
    # [datetime] on PowerShell 7 and leaves it a string on 5.1). Kind Unspecified is taken as UTC.
    param([datetime]$Utc)
    if ($Utc.Kind -eq [System.DateTimeKind]::Local) { $Utc = $Utc.ToUniversalTime() }
    return [long][math]::Floor(($Utc - (New-Object datetime 1970, 1, 1, 0, 0, 0, ([System.DateTimeKind]::Utc))).TotalSeconds)
}
function Format-PimHybridAdEpoch {
    param([long]$Epoch)
    return ((New-Object datetime 1970, 1, 1, 0, 0, 0, ([System.DateTimeKind]::Utc)).AddSeconds($Epoch).ToString('yyyy-MM-dd HH:mm', [cultureinfo]::InvariantCulture) + ' UTC')
}
function ConvertTo-PimHybridAdEndUtc {
    <#
      The end time of an active assignment as UTC, or $null (no end). THROWS on text that is not a time.
        text         parsed with the invariant culture; text without a zone is UTC (Graph always sends one)
        [datetime]   PowerShell 7's JSON reader hands back a [datetime] instead of the text. Until this lane the reader
                     turned it into text and parsed that as LOCAL time -- right on a worker whose clock is UTC, off by the
                     zone offset on any other. -AsUtc $true reads it correctly (Utc as it is, Local converted, Unspecified
                     = UTC). Without -AsUtc the install's setting decides (Test-PimHybridAdEndTimeAsUtc, 'HybridAdEndTimeAsUtc',
                     default OFF): off reads it EXACTLY AS BEFORE, so the first pass after an upgrade changes no
                     membership (a corrected end time re-adds every active member once in a forest with time-limited
                     membership). Owner's decision (29): on for the internal install and the test tenants first.
    #>
    param([object]$Value, [object]$AsUtc = $null)
    if ($null -eq $Value) { return $null }
    $utcMode = if ($null -ne $AsUtc) { [bool]$AsUtc } else { [bool](Test-PimHybridAdEndTimeAsUtc) }
    if ($Value -is [datetimeoffset]) { return $Value.UtcDateTime }
    if ($Value -is [datetime]) {
        if (-not $utcMode) { return [datetimeoffset]::Parse("$Value", [Globalization.CultureInfo]::InvariantCulture).UtcDateTime }   # as before this lane
        if ($Value.Kind -eq [System.DateTimeKind]::Local) { return $Value.ToUniversalTime() }
        return [datetime]::SpecifyKind($Value, [System.DateTimeKind]::Utc)
    }
    $t = "$Value".Trim()
    if (-not $t) { return $null }
    return [datetimeoffset]::Parse($t, [Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeUniversal).UtcDateTime
}

function Test-PimHybridAdNotFound {
    # "This id does not exist" is said ONLY by an HTTP 404 that the directory itself names ResourceNotFound. A timeout, a
    # 429, a 5xx, a 403 or a 404 from anything in between (a proxy) is a failed read, not an answer.
    param([string]$Message)
    return [bool]("$Message" -match 'HTTP 404\b' -and "$Message" -match '(?i)ResourceNotFound')
}
function Test-PimHybridAdSameName {
    # is the Entra group's display name the DEFINED name? (B1: a remembered id is followed only while it carries the name)
    param([string]$A, [string]$B)
    return ("$A".Trim() -ieq "$B".Trim())
}

function Test-PimHybridAdPartialItems {
    # Defence only: a read that handed back a PAGE instead of the items (it carries a next link nobody followed). The
    # product's REST client never does that -- it follows every page or throws -- so a thrown error is the real shape.
    param([object[]]$Items = @())
    foreach ($i in @($Items)) { if ($null -ne $i -and $i.PSObject -and $i.PSObject.Properties['@odata.nextLink'] -and "$($i.'@odata.nextLink')") { return $true } }
    return $false
}

function Get-PimHybridAdWhyText {
    # the reader's short code -> the words on the worker's result line (the codes are what the memory stores: stable text)
    param([string]$Code, [string]$Detail = '')
    switch ("$Code") {
        'never-seen'         { return 'it was not found by name and PIM Manager has never seen its id' }
        'name-lookup-failed' { return 'the search for the group failed' }
        'ambiguous'          { return 'more than one Entra group carries this name' }
        'exists-failed'      { return 'the lookup by its id failed' }
        'gone-unconfirmed'   { return ('its id answers "not found" -- not confirmed until that holds for {0} hours' -f (Get-PimHybridAdGoneConfirmHours)) }
        'renamed'            { return $(if ("$Detail".Trim()) { "$Detail".Trim() } else { 'the Entra group was renamed and no group carries the defined name' }) }
        'instances-failed'   { return 'the read of its active members failed' }
        'instances-partial'  { return 'the read of its active members came back partial' }
        default              { return 'Entra ID gave no answer for it in this pass' }
    }
}

function New-PimHybridAdGroupMemory {
    # What the sync remembers about ONE AD group between passes (all times = epoch seconds, 0 = not set):
    #   id   the Entra group's object id, once seen     m    sam -> end time of the activation (0 = no end) at the last complete pass
    #   p    sam -> FIRST time the member was seen without an active assignment (the hold; A2: confirmed 5 - 30 minutes later)
    #   o / on   principal id -> first time / number of passes it answered "not found" (B2)
    #   us / uw   NOT KNOWN since / why (code)          ss   no complete pass since (0 = the last pass was complete): the
    #                                                        recorded end times are stale once that lasts 30 minutes (B4)
    #   xs / xm / xh / xd / xc   the group is absent (gone, or never seen): since / clock hours seen / last hour / in deleted
    #   items (1/0) / confirmed at                      rid / rs   another group carries the name: its id / since
    #   hs / ha / ht   members held since / hold alert delivered / last alert attempt     wa   "waiting" alert delivered
    return @{ id = ''; m = @{}; p = @{}; o = @{}; on = @{}; us = [long]0; uw = ''; ss = [long]0
              xs = [long]0; xm = 0; xh = [long]-1; xd = 0; xc = [long]0; rid = ''; rs = [long]0
              hs = [long]0; ha = [long]0; ht = [long]0; wa = [long]0 }
}
function Copy-PimHybridAdGroupMemory {
    param([hashtable]$Memory)
    $n = New-PimHybridAdGroupMemory
    if (-not $Memory) { return $n }
    foreach ($k in @('id', 'uw', 'rid')) { if ($Memory.ContainsKey($k)) { $n[$k] = "$($Memory[$k])" } }
    foreach ($k in @('us', 'ss', 'xs', 'xh', 'xc', 'rs', 'hs', 'ha', 'ht', 'wa')) { if ($Memory.ContainsKey($k) -and $null -ne $Memory[$k]) { $n[$k] = [long]$Memory[$k] } }
    foreach ($k in @('xm', 'xd')) { if ($Memory.ContainsKey($k) -and $null -ne $Memory[$k]) { $n[$k] = [int]$Memory[$k] } }
    foreach ($k in @('m', 'p', 'o', 'on')) { if ($Memory[$k] -is [hashtable]) { foreach ($s in @($Memory[$k].Keys)) { $n[$k]["$s"] = [long]$Memory[$k][$s] } } }
    return $n
}
function Limit-PimHybridAdMemoryMap {
    # at most -Max entries. -Oldest: the entries with the SMALLEST value stay (B7: the oldest holds are never the ones
    # dropped); otherwise the same ones every time (ordinal name order).
    param([hashtable]$Map, [int]$Max, [switch]$Oldest)
    if (-not $Map -or $Map.Count -le $Max) { return $Map }
    $keys = [string[]]@($Map.Keys); [Array]::Sort($keys, [System.StringComparer]::Ordinal)
    if ($Oldest) { $keys = [string[]]@($keys | Sort-Object @{ Expression = { [long]$Map[$_] } }, @{ Expression = { "$_" } }) }
    $o = @{}; for ($i = 0; $i -lt $Max; $i++) { $o[$keys[$i]] = $Map[$keys[$i]] }
    return $o
}

function Get-PimHybridAdGuardedPlan {
    <#
      PURE. One AD group. Takes the plan of Get-PimHybridAdMembershipPlan (-Plan, untouched) and decides which of its
      removals are made in THIS pass. add / readd / keep / kept pass through unchanged -- adds are never delayed.
        -Answer   what Entra said for the group in this pass (the reader's -Answer entry; $null = no answer = NOT KNOWN):
                  @{ state = found|gone|replaced|renamed|unknown; complete; id; altId; why; detail; deleted;
                     principalFailed (count); principalNotFound (ids) }
        -Memory   the group's memory from the last pass (New-PimHybridAdGroupMemory). -MemoryReadable $false = the store
                  could not be read: only a member Entra ITSELF reports as ended is removed. -MemoryStale = no pass for
                  longer than Get-PimHybridAdStaleMinutes: a RECORDED end time is not trusted in this pass (B4).
        -Active   the active list the plan was made from
        -Decision a SuperAdmin's decision for THIS group from the decisions record (Read-PimHybridAdSyncMemory hands over
                  only a valid one, at most 48 hours old): @{ kind = gone|never-seen|replaced; forId (the Entra id the
                  decision was made for, '' = never seen); adoptId; remove (account names); by }. It is used only when
                  the group is in exactly that state IN THIS PASS -- same kind, same remembered id, and Entra saying so
                  again now. adoptId (replaced): that group is the one behind the AD group from here on. remove: those
                  accounts, and only those that wait for a SuperAdmin in this pass, are removed. DESIGN.md
                  "HybridAdSyncMemory decisions record".
      Returns @{ add; readd; keep; kept; remove[]; held[] { samAccountName; reason; hold }; notes[]; state =
                 known|not-known|waiting|replaced|memory; kind; reason (the group's line); detail; warning; memory (for
                 the next pass; $null = do not save) }.
      hold: confirm (waits for the second pass) | principal | not-known | replaced | superadmin | memory.
      remove[] is ALWAYS a subset of -Plan.remove (tests/Test-PimHybridAdNoDoubtRemoval.ps1).
    #>
    param([Parameter(Mandatory)][hashtable]$Plan, [object[]]$Active = @(), [hashtable]$Answer = $null, [hashtable]$Memory = $null,
          [bool]$MemoryReadable = $true, [bool]$MemoryStale = $false, [hashtable]$Decision = $null,
          [datetime]$NowUtc = [datetime]::UtcNow, [string]$CloudSuffix = '', [string]$AdSuffix = '')
    $now = ConvertTo-PimHybridAdEpoch $NowUtc
    $max = Get-PimHybridAdMemoryMaxMembers
    $out = @{ add = @($Plan.add); readd = @($Plan.readd); keep = @($Plan.keep); kept = @($Plan.kept); remove = @(); held = @(); notes = @()
              state = 'known'; kind = ''; reason = ''; detail = ''; memory = $null; warning = $false }
    $st = 'unknown'; $complete = $false; $why = ''; $ansId = ''; $altId = ''; $pFailed = 0; $pNotFound = @()
    if ($Answer) {
        $st = "$($Answer.state)"; $complete = [bool]$Answer.complete; $why = "$($Answer.why)"; $ansId = "$($Answer.id)".Trim(); $altId = "$($Answer.altId)".Trim()
        $out.detail = "$($Answer.detail)"
        if ($null -ne $Answer.principalFailed) { $pFailed = [int]$Answer.principalFailed }
        $pNotFound = @(@($Answer.principalNotFound) | ForEach-Object { "$_".Trim() } | Where-Object { $_ } | Select-Object -Unique)
    }
    # what Entra ITSELF says about the members in this pass: active (end time, 0 = none) / listed with an end time that has passed
    $activeNow = @{}; $endedNow = @{}
    foreach ($a in @($Active)) {
        if ($null -eq $a) { continue }
        $sam = ConvertTo-PimHybridAdAccountName -MailNickname "$($a.mailNickname)" -CloudSuffix $CloudSuffix -AdSuffix $AdSuffix
        if (-not $sam) { continue }
        $k = $sam.ToLowerInvariant()
        if ($a.endUtc) {
            $e = ConvertTo-PimHybridAdEpoch ([datetime]$a.endUtc)
            if ($e -le $now) { if (-not $activeNow.ContainsKey($k)) { $endedNow[$k] = [long]$e }; continue }
            if (-not $activeNow.ContainsKey($k) -or ($activeNow[$k] -ne 0 -and $activeNow[$k] -lt $e)) { $activeNow[$k] = [long]$e }
        } else { $activeNow[$k] = [long]0 }
        if ($endedNow.ContainsKey($k)) { $endedNow.Remove($k) }
    }
    if (-not $MemoryReadable) {
        # B6: no memory -- "expected" by a recorded end time and "second pass" cannot be judged
        $out.state = 'memory'
        $certain = ($st -eq 'found' -and $complete)
        foreach ($r in @($Plan.remove)) {
            $k = "$($r.samAccountName)".ToLowerInvariant()
            if ($certain -and $endedNow.ContainsKey($k)) { $out.remove += @{ samAccountName = $r.samAccountName; reason = 'no active PIM assignment (Entra ID reports the activation as ended)' } }
            else { $out.held += @{ samAccountName = $r.samAccountName; hold = 'memory'; reason = 'kept -- the sync''s own record of the last pass could not be read' } }
        }
        $out.warning = ($out.held.Count -gt 0)
        $out.reason = 'the sync''s own record of the last pass could not be read from the store -- only a member whose activation Entra ID itself reports as ended is removed'
        return $out
    }
    $mem = Copy-PimHybridAdGroupMemory -Memory $Memory
    $next = Copy-PimHybridAdGroupMemory -Memory $Memory
    # B4: the end times RECORDED for the members are trusted only while the complete passes have not been apart for longer
    # than Get-PimHybridAdStaleMinutes -- for the whole job (-MemoryStale) or for this group (ss = no complete pass since).
    # A short spell of trouble does not make them stale: the owner's "the end time has passed meanwhile -> removed as expected".
    $stale = [bool]$MemoryStale -or ([long]$mem.ss -gt 0 -and ($now - [long]$mem.ss) -gt ((Get-PimHybridAdStaleMinutes) * 60))
    # the remembered id and the id that answers differ: that is ANOTHER group (A3), whoever called
    if ($st -eq 'found' -and $mem.id -and $ansId -and $ansId -ne $mem.id) { $st = 'replaced'; $altId = $ansId; $ansId = $mem.id }
    # a SuperAdmin's decision for this group (already checked for its fields and its age by the reader of the record)
    $dec = $null
    if ($Decision -is [hashtable]) {
        $dec = @{ kind = "$($Decision.kind)".Trim().ToLowerInvariant(); forId = "$($Decision.forId)".Trim(); adoptId = "$($Decision.adoptId)".Trim(); by = "$($Decision.by)".Trim(); remove = @{} }
        foreach ($dn in @($Decision.remove)) { if ("$dn".Trim()) { $dec.remove["$dn".Trim().ToLowerInvariant()] = $true } }
        if (($dec.adoptId -and $dec.remove.Count) -or (-not $dec.adoptId -and -not $dec.remove.Count) -or -not $dec.by) {
            $out.notes += 'a SuperAdmin''s decision is on record for this group but it does not say ONE thing (take the new group, or remove named members) -- not used'
            $dec = $null
        }
    }
    $decFor = [bool]($dec -and $dec.forId -eq "$($mem.id)".Trim())   # made for the group this AD group is remembered with ('' = never seen)
    if ($st -eq 'replaced' -and $decFor -and $dec.kind -eq 'replaced' -and $dec.adoptId -and $altId -and $dec.adoptId -eq $altId) {
        # the decision says the new group is the one behind the AD group: from now on the normal rules, on ITS evidence. The
        # holds and end times remembered from the OLD group decide nothing here: no unexpected removal in this pass.
        $st = 'found'; $ansId = $altId; $mem.id = $altId; $mem.p = @{}; $next.p = @{}; $stale = $true
        $out.notes += "the Entra group $altId is taken as the group behind this AD group (decided by $($dec.by))"
    }
    $setHold = { param($any) if ($any) { if ([long]$next.hs -le 0) { $next.hs = $now } } else { $next.hs = [long]0; $next.ha = [long]0; $next.ht = [long]0 } }
    if ($st -eq 'found' -and $complete) {
        # ---- FOUND, the read of the active members complete ----
        # B2: a principal of the active list that could not be read may be ANY member -- unexpected removals wait for it
        $nextO = @{}; $nextOn = @{}; $orphans = 0; $openNotFound = 0
        $oMax = Get-PimHybridAdMemoryMaxOrphans
        foreach ($pp in $pNotFound) {
            $first = $now; if ($mem.o.ContainsKey($pp)) { $first = [long]$mem.o[$pp] }
            $cnt = 1; if ($mem.on.ContainsKey($pp)) { $cnt = [math]::Min((Get-PimHybridAdOrphanPasses), [int]$mem.on[$pp] + 1) }
            if ($nextO.Count -lt $oMax -or $mem.o.ContainsKey($pp)) { $nextO[$pp] = $first; $nextOn[$pp] = [long]$cnt }
            if ($cnt -ge (Get-PimHybridAdOrphanPasses) -and ($now - $first) -ge ((Get-PimHybridAdOrphanMinutes) * 60)) { $orphans++ } else { $openNotFound++ }
        }
        $pDoubt = ($pFailed -gt 0 -or $openNotFound -gt 0)
        if ($orphans) { $out.notes += "$orphans active assignment(s) in the Entra group are for an account that no longer exists (not found on $(Get-PimHybridAdOrphanPasses) passes over $(Get-PimHybridAdOrphanMinutes) minutes, not in the deleted items) -- ignored" }
        $minAge = (Get-PimHybridAdConfirmMinMinutes) * 60; $maxAge = (Get-PimHybridAdConfirmMaxMinutes) * 60
        $nextM = @{}; foreach ($k in @($activeNow.Keys)) { $nextM[$k] = $activeNow[$k] }
        $nextP = @{}
        foreach ($r in @($Plan.remove)) {
            $k = "$($r.samAccountName)".ToLowerInvariant()
            $rec = $null; if ($mem.m.ContainsKey($k)) { $rec = [long]$mem.m[$k] }
            # EXPECTED: Entra itself lists the member with an end time that has passed, or the end time RECORDED at the last
            # complete pass has passed (B4: not after a spell without complete passes -- it may have been extended unseen)
            $expected = $endedNow.ContainsKey($k) -or (-not $stale -and $null -ne $rec -and $rec -gt 0 -and $rec -le $now)
            if ($expected) {
                $out.remove += @{ samAccountName = $r.samAccountName; reason = 'no active PIM assignment (the activation ended)' }
            } elseif ($pDoubt) {
                $out.held += @{ samAccountName = $r.samAccountName; hold = 'principal'; reason = 'kept -- an active member of the Entra group could not be read (this account may be that member)' }
                $nextP[$k] = $(if ($mem.p.ContainsKey($k)) { [long]$mem.p[$k] } else { $now })
            } elseif ($mem.p.ContainsKey($k)) {
                $age = $now - [long]$mem.p[$k]
                if (($age -ge $minAge) -and ($age -le $maxAge)) {
                    $out.remove += @{ samAccountName = $r.samAccountName; reason = "no active PIM assignment (confirmed by a second pass $([int][math]::Floor($age / 60)) min after the first)" }
                    $nextP[$k] = [long]$mem.p[$k]
                } elseif ($age -gt $maxAge) {
                    $out.held += @{ samAccountName = $r.samAccountName; hold = 'confirm'; reason = "kept -- first seen without an active assignment more than $(Get-PimHybridAdConfirmMaxMinutes) minutes ago; the wait for a second pass starts again" }
                    $nextP[$k] = $now
                } else {
                    $out.held += @{ samAccountName = $r.samAccountName; hold = 'confirm'; reason = "kept -- waiting for a second pass at least $(Get-PimHybridAdConfirmMinMinutes) minutes after $(Format-PimHybridAdEpoch ([long]$mem.p[$k])) (no active PIM assignment)" }
                    $nextP[$k] = [long]$mem.p[$k]
                }
            } else {
                $out.held += @{ samAccountName = $r.samAccountName; hold = 'confirm'; reason = "kept -- waiting for a second pass at least $(Get-PimHybridAdConfirmMinMinutes) minutes after $(Format-PimHybridAdEpoch $now) (no active PIM assignment)" }
                $nextP[$k] = $now
            }
            # the recorded end time stays while the member is still in AD (a removal that failed, or one that waits) -- but NOT
            # a stale one: it is dropped here, or the very next pass (seconds later, no longer "stale") would take it as
            # expected. Without it the member is an unexpected removal and takes the two passes 5 - 30 minutes apart.
            if (-not $nextM.ContainsKey($k)) { if ($endedNow.ContainsKey($k)) { $nextM[$k] = [long]$endedNow[$k] } elseif ($null -ne $rec -and -not $stale) { $nextM[$k] = $rec } }
        }
        if ($nextP.Count -gt $max) {
            # B7: never dropped silently, and the OLDEST holds are the ones that stay tracked
            $out.notes += "more than $max members waiting: the rest is not tracked ($($nextP.Count - $max) member(s) stay until the tracked ones are decided)"
            $out.warning = $true
        }
        $next.m = Limit-PimHybridAdMemoryMap -Map $nextM -Max $max
        $next.p = Limit-PimHybridAdMemoryMap -Map $nextP -Max $max -Oldest
        $next.o = $nextO; $next.on = $nextOn
        if ($ansId) { $next.id = $ansId }
        $next.us = [long]0; $next.uw = ''; $next.ss = [long]0; $next.rid = ''; $next.rs = [long]0; $next.wa = [long]0
        $next.xs = [long]0; $next.xm = 0; $next.xh = [long]-1; $next.xd = 0; $next.xc = [long]0
        & $setHold ($out.held.Count -gt 0)
        # (24): a doubt is a warning at once -- somebody kept, or a member of the Entra group that could not be read
        # (that person may be missing from the adds)
        if ($out.held.Count -or $pDoubt) { $out.warning = $true }
        if ($pDoubt) { $out.reason = "$($pFailed + $openNotFound) active member(s) of the Entra group could not be read -- a member whose activation ended is removed, every other removal waits" }
        $out.memory = $next
        return $out
    }
    if ($st -eq 'replaced') {
        # ---- A3: the remembered group is gone (or renamed away) and ANOTHER group carries the name. It is not the old one:
        # its activations are added (the plan's adds), a member remembered from the old group stays until the end time
        # recorded for them has passed, and whoever is left waits for a SuperAdmin. No removal rests on the new group's word:
        # not even an activation IT lists as ended. A SuperAdmin's decision may name members of the waiting ones to remove.
        if ([long]$next.ss -le 0) { $next.ss = $now }
        $decRemove = [bool]($decFor -and $dec.kind -eq 'replaced' -and $dec.remove.Count -and $complete)
        if ($dec -and -not $decRemove -and -not ($decFor -and $dec.kind -eq 'replaced')) { $out.notes += 'a SuperAdmin''s decision is on record for this group, but it was made for another situation (another state or another Entra group) -- not used' }
        if ("$($next.rid)" -ne $altId -or [long]$next.rs -le 0) { $next.rid = $altId; $next.rs = $now }
        $next.xs = [long]0; $next.xm = 0; $next.xh = [long]-1; $next.xd = 0; $next.xc = [long]0
        if ([long]$next.us -le 0) { $next.us = $now }
        $next.uw = 'replaced'
        $nextM = @{}; foreach ($k in @($mem.m.Keys)) { $nextM[$k] = [long]$mem.m[$k] }
        if ($complete) { foreach ($k in @($activeNow.Keys)) { $nextM[$k] = $activeNow[$k] } }
        $waiting = 0
        foreach ($r in @($Plan.remove)) {
            $k = "$($r.samAccountName)".ToLowerInvariant()
            $rec = $null; if ($mem.m.ContainsKey($k)) { $rec = [long]$mem.m[$k] }
            if (-not $complete) {
                $out.held += @{ samAccountName = $r.samAccountName; hold = 'not-known'; reason = 'kept -- the Entra group was replaced by another group of the same name, and that group could not be read' }
            } elseif ($null -ne $rec -and $rec -gt 0 -and $rec -le $now) {
                $out.remove += @{ samAccountName = $r.samAccountName; reason = 'no active PIM assignment (the activation ended)' }
            } elseif ($null -ne $rec -and $rec -gt $now) {
                $out.held += @{ samAccountName = $r.samAccountName; hold = 'replaced'; reason = "kept until the recorded end time $(Format-PimHybridAdEpoch $rec) -- the Entra group was replaced by another group of the same name" }
            } elseif ($decRemove -and $dec.remove.ContainsKey($k)) {
                $out.remove += @{ samAccountName = $r.samAccountName; reason = "removed on a SuperAdmin's approval ($($dec.by)) -- the Entra group was replaced by another group of the same name" }
            } else {
                $waiting++
                $out.held += @{ samAccountName = $r.samAccountName; hold = 'superadmin'; reason = 'waiting for a SuperAdmin: the Entra group was replaced by another group of the same name' }
            }
        }
        $next.m = Limit-PimHybridAdMemoryMap -Map $nextM -Max $max
        $out.state = 'replaced'; $out.kind = 'replaced'; $out.warning = $true
        $out.reason = "the Entra group was replaced by another group of the same name (remembered id $($mem.id), now $altId) -- new activations are added, nobody is removed on the new group's word; $waiting member(s) wait for a SuperAdmin"
        & $setHold $true
        $out.memory = $next
        return $out
    }
    # ---- NOT KNOWN, RENAMED or GONE: nobody is removed. The holds keep their first sighting (A2); the recorded end times
    # go stale when this lasts (B4: ss). The ONE removal possible here: a member a SuperAdmin's decision names, in a group
    # that is CONFIRMED gone / never found and that Entra reports so again in this very pass. ----
    if ([long]$next.ss -le 0) { $next.ss = $now }
    # (24) a READ that failed is a warning at once, also when nobody is kept by it (an activation may be missing from the adds)
    $readFailed = [bool]($st -eq 'found' -or ($st -eq 'unknown' -and $why -ne 'never-seen'))
    $absent = $false
    if ($st -eq 'found') {
        # the group answers (the read of its members was not complete): it is not gone
        if ($ansId) { $next.id = $ansId }
        $next.xs = [long]0; $next.xm = 0; $next.xh = [long]-1; $next.xd = 0; $next.xc = [long]0; $next.wa = [long]0
        $next.rid = ''; $next.rs = [long]0
    } elseif ($st -eq 'renamed') {
        $next.xs = [long]0; $next.xm = 0; $next.xh = [long]-1; $next.xd = 0; $next.xc = [long]0; $next.wa = [long]0
        $next.rid = ''; $next.rs = [long]0
        $why = 'renamed'
    } elseif ($st -eq 'gone' -and ($next.id -or $ansId) -and (-not $ansId -or -not $next.id -or $ansId -eq $next.id)) {
        if (-not $next.id) { $next.id = $ansId }
        $absent = $true; $why = 'gone-unconfirmed'; $out.kind = 'gone'
    } elseif ($st -eq 'unknown' -and $why -eq 'never-seen' -and -not $next.id -and -not $ansId) {
        # B3: defined, in AD, and no Entra group of that name was ever seen
        $absent = $true; $out.kind = 'never-seen'
    }
    if ($absent -and [long]$next.xc -le 0) {
        if ([long]$next.xs -le 0) { $next.xs = $now; $next.xm = 0; $next.xh = [long]-1 }
        $hr = [long][math]::Floor($now / 3600)
        if ($hr -ne [long]$next.xh) { $next.xm = [int]$next.xm + 1; $next.xh = $hr }
        if ($out.kind -eq 'gone') { $next.xd = [int][bool]$Answer.deleted }
        $window = $(if ($out.kind -eq 'gone') { Get-PimHybridAdGoneConfirmHours } else { Get-PimHybridAdNeverSeenHours }) * 3600
        if (($now - [long]$next.xs) -ge $window -and [int]$next.xm -ge (Get-PimHybridAdGoneConfirmMinMarks)) { $next.xc = $now }
    }
    if ([long]$next.us -le 0) { $next.us = $now }
    if (-not $why) { $why = 'no-answer' }
    $next.uw = $why
    if ([long]$next.xc -gt 0) {
        if (-not $out.kind) { $out.kind = $(if ($next.id) { 'gone' } else { 'never-seen' }) }
        $out.state = 'waiting'
        $out.reason = $(if ($out.kind -eq 'gone') {
            "waiting for a SuperAdmin: the Entra group is gone (confirmed $(Format-PimHybridAdEpoch $next.xc), $(if ($next.xd) { 'it is in the deleted items' } else { 'it is not in the deleted items' })) -- the members stay until a SuperAdmin decides"
        } else {
            "waiting for a SuperAdmin: no Entra group of this name has been found for $(Get-PimHybridAdNeverSeenHours) hours (since $(Format-PimHybridAdEpoch $next.xs)) -- the members stay until a SuperAdmin decides"
        })
        $hr2 = $(if ($out.kind -eq 'gone') { 'waiting for a SuperAdmin: the Entra group is gone' } else { 'waiting for a SuperAdmin: the Entra group was never found' })
        # $absent: Entra said "gone" / "never found" again in THIS pass (a pass where the read failed applies no decision)
        $decRemove = [bool]($absent -and $decFor -and $dec.kind -eq $out.kind -and $dec.remove.Count -and ($out.kind -ne 'gone' -or $dec.forId))
        if ($dec -and -not $decRemove -and -not ($decFor -and $dec.kind -eq $out.kind)) { $out.notes += 'a SuperAdmin''s decision is on record for this group, but it was made for another situation (another state or another Entra group) -- not used' }
        foreach ($r in @($Plan.remove)) {
            if ($decRemove -and $dec.remove.ContainsKey("$($r.samAccountName)".ToLowerInvariant())) { $out.remove += @{ samAccountName = $r.samAccountName; reason = "removed on a SuperAdmin's approval ($($dec.by)) -- $($hr2 -replace '^waiting for a SuperAdmin: ', '')" } }
            else { $out.held += @{ samAccountName = $r.samAccountName; hold = 'superadmin'; reason = $hr2 } }
        }
    } else {
        $out.state = 'not-known'
        $since = Format-PimHybridAdEpoch $next.us
        $out.reason = "the Entra group could not be confirmed since $since ($(Get-PimHybridAdWhyText -Code $why -Detail $out.detail)) -- nobody is removed in this pass"
        foreach ($r in @($Plan.remove)) { $out.held += @{ samAccountName = $r.samAccountName; hold = 'not-known'; reason = "kept -- the Entra group could not be confirmed since $since" } }
    }
    $out.warning = ($out.held.Count -gt 0 -or $st -eq 'renamed' -or $readFailed)
    # the 30-minute alert counts from the first member KEPT (or from the rename: nobody is added from that group)
    & $setHold ($out.held.Count -gt 0 -or $st -eq 'renamed')
    $out.memory = $next
    return $out
}

# ---- the sync memory in the SQL store (pim.Settings 'HybridAdSyncMemory.<job>.<bucket>') ----
function Get-PimHybridAdMemoryBucket {
    # which bucket a group's memory lives in: the same answer on every host and edition (String.GetHashCode is not)
    param([string]$Name)
    $h = [long]7
    foreach ($ch in "$Name".ToLowerInvariant().ToCharArray()) { $h = ($h * 31 + [int]$ch) % 2147483647 }
    return [int]($h % (Get-PimHybridAdMemoryBucketCount))
}
function Get-PimHybridAdEmptyBucketJson { return '{"v":1,"g":{}}' }
function Get-PimHybridAdEmptyWaitingJson { return '{"v":1,"groups":[]}' }
function ConvertTo-PimHybridAdMemoryJson {
    # one bucket (group name in lower case -> memory) -> JSON text that is the SAME for the same content (ordered keys,
    # empty fields left out), so an unchanged pass writes nothing. Never '' (compare-and-set reads '' as "no value").
    param([hashtable]$Groups)
    if (-not $Groups -or -not $Groups.Count) { return (Get-PimHybridAdEmptyBucketJson) }
    $names = [string[]]@($Groups.Keys); [Array]::Sort($names, [System.StringComparer]::Ordinal)
    $g = [ordered]@{}
    foreach ($n in $names) {
        $mem = $Groups[$n]; $o = [ordered]@{}
        foreach ($f in @('id', 'rid', 'uw')) { if ("$($mem[$f])") { $o[$f] = "$($mem[$f])" } }
        foreach ($f in @('m', 'p', 'o', 'on')) {
            if ($mem[$f] -is [hashtable] -and $mem[$f].Count) {
                $ks = [string[]]@($mem[$f].Keys); [Array]::Sort($ks, [System.StringComparer]::Ordinal)
                $mo = [ordered]@{}; foreach ($k in $ks) { $mo[$k] = [long]$mem[$f][$k] }; $o[$f] = $mo
            }
        }
        foreach ($f in @('us', 'ss', 'xs', 'xc', 'rs', 'hs', 'ha', 'ht', 'wa')) { if ([long]$mem[$f] -gt 0) { $o[$f] = [long]$mem[$f] } }
        if ([long]$mem.xs -gt 0) { $o['xm'] = [int]$mem.xm; $o['xh'] = [long]$mem.xh; $o['xd'] = [int]$mem.xd }
        if ($o.Count) { $g[$n] = $o }
    }
    if (-not $g.Count) { return (Get-PimHybridAdEmptyBucketJson) }
    return ([ordered]@{ v = 1; g = $g } | ConvertTo-Json -Depth 6 -Compress)
}
function ConvertFrom-PimHybridAdMemoryJson {
    # THROWS on text that is not the memory's JSON (the caller then treats the bucket as empty: holds, never removals)
    param([string]$Json)
    $out = @{}
    if (-not "$Json".Trim()) { return $out }
    $d = $Json | ConvertFrom-Json
    if (-not $d -or -not $d.PSObject.Properties['g'] -or -not $d.g) { return $out }
    foreach ($gp in @($d.g.PSObject.Properties)) {
        $src = $gp.Value; if ($null -eq $src) { continue }
        $mem = New-PimHybridAdGroupMemory
        foreach ($f in @('id', 'uw', 'rid')) { if ($src.PSObject.Properties[$f]) { $mem[$f] = "$($src.$f)" } }
        foreach ($f in @('us', 'ss', 'xs', 'xh', 'xc', 'rs', 'hs', 'ha', 'ht', 'wa')) { if ($src.PSObject.Properties[$f] -and $null -ne $src.$f) { $mem[$f] = [long]$src.$f } }
        foreach ($f in @('xm', 'xd')) { if ($src.PSObject.Properties[$f] -and $null -ne $src.$f) { $mem[$f] = [int]$src.$f } }
        foreach ($f in @('m', 'p', 'o', 'on')) { if ($src.PSObject.Properties[$f] -and $src.$f) { foreach ($mp in @($src.$f.PSObject.Properties)) { $mem[$f]["$($mp.Name)"] = [long]$mp.Value } } }
        $out["$($gp.Name)".ToLowerInvariant()] = $mem
    }
    return $out
}
function Get-PimHybridAdMemoryStore {
    <#
      The store seam: @{ kind; LoadAll = { param($prefix) -> @{ settingName = jsonText } };
                         Save = { param($name, $json, $expected) -> $true (written) | $false (the stored value is no longer
                         $expected: somebody else wrote it) } }  -- compare-and-set, so two processes never overwrite each
      other's holds (B9). The SQL store, or $NULL when this process has none: there is NO silent fallback to a table in the
      process (B6) -- the job then runs as "memory not readable". Tests hand in New-PimHybridAdProcessStore explicitly.
      PLAIN scriptblocks, no closure -- see Publish-PimHybridAdSyncLive.
    #>
    $cs = Get-PimHybridAdStoreConnectionString
    if ($cs -and (Test-PimHybridAdFunction 'Invoke-PimSqlQuery') -and (Test-PimHybridAdFunction 'Set-PimSqlSettingIfUnchanged')) {
        return @{ kind = 'sql'
            LoadAll = { param($prefix) $h = @{}; foreach ($r in @(Invoke-PimSqlQuery -ConnectionString (Get-PimHybridAdStoreConnectionString) -Sql 'SELECT Name, ValueJson FROM pim.Settings WHERE Name LIKE @p' -Parameters @{ p = "$prefix%" })) { if ($r -and "$($r.ValueJson)") { $h["$($r.Name)"] = "$($r.ValueJson)" } }; $h }
            Save = { param($name, $json, $expected) ([int](Set-PimSqlSettingIfUnchanged -ConnectionString (Get-PimHybridAdStoreConnectionString) -Name "$name" -NewValueJson "$json" -ExpectedValueJson "$expected") -gt 0) } }
    }
    return $null
}
function New-PimHybridAdProcessStore {
    # TESTS ONLY, and only when handed in with -Store: the same seam over a table in this process, with the compare-and-set
    param([hashtable]$Table = @{})
    $script:PimHybridAdTestStoreTable = $Table
    return @{ kind = 'process'; table = $Table
        LoadAll = { param($prefix) $h = @{}; foreach ($k in @($script:PimHybridAdTestStoreTable.Keys)) { if ("$k".StartsWith("$prefix", [System.StringComparison]::OrdinalIgnoreCase) -and "$($script:PimHybridAdTestStoreTable[$k])") { $h["$k"] = "$($script:PimHybridAdTestStoreTable[$k])" } }; $h }
        Save = { param($name, $json, $expected) if ("$($script:PimHybridAdTestStoreTable["$name"])" -cne "$expected") { return $false }; $script:PimHybridAdTestStoreTable["$name"] = "$json"; return $true } }
}
function Get-PimHybridAdMemoryPrefix { param([string]$Job) return "HybridAdSyncMemory.$Job." }
function Read-PimHybridAdSyncMemory {
    <#
      The memory of one sync job. Returns @{ ok; reason; stored = @{ settingName = jsonText as the store holds it };
      groups = @{ lowerName = memory }; lastPass (epoch, 0 = none); adopt = @{ lowerName = Entra id } }.
      ok = $false: no store, or the store could not be read and this process holds no copy of its own last write -- the
      pass then removes only what Entra itself reports as ended and writes nothing (B6).
      A bucket that failed to SAVE (an error, not a lost compare-and-set) is kept in this process and laid over the store's
      copy -- only while the store still holds the value it was based on.
      '<prefix>decisions' is READ here and never written -- the record a SuperAdmin's page writes (DESIGN.md
      "HybridAdSyncMemory decisions record"): { v: 1, groups: { "<group name>": { kind; forEntraGroupId; decidedBy;
      decidedAtEpoch; adoptEntraGroupId | removeMembers[] } } }. decisions = lower-case group name -> @{ kind; forId;
      adoptId; remove; by; at } for every entry that is COMPLETE and not older than Get-PimHybridAdDecisionMaxHours (48)
      at -NowUtc; anything else is left out with a warning line -- a record that cannot be read is no decision at all.
    #>
    param([Parameter(Mandatory)][string]$Job, [hashtable]$Store = $null, [datetime]$NowUtc = [datetime]::UtcNow)
    $bad = @{ ok = $false; reason = ''; stored = @{}; groups = @{}; lastPass = [long]0; decisions = @{} }
    if (-not $Store) { $bad.reason = 'this process has no store for the sync memory'; return $bad }
    $prefix = Get-PimHybridAdMemoryPrefix -Job $Job
    $stored = $null; $liveRead = $true
    try { $stored = & $Store.LoadAll $prefix; if ($stored -isnot [hashtable]) { throw 'the store gave no table of settings' } }
    catch {
        Write-Warning "[$Job] the sync memory could not be read from the store: $($_.Exception.Message)"
        $stored = $null; $liveRead = $false
        if ($script:PimHybridAdMemoryLast -is [hashtable] -and $script:PimHybridAdMemoryLast[$Job] -is [hashtable]) { $stored = @{}; foreach ($k in @($script:PimHybridAdMemoryLast[$Job].Keys)) { $stored[$k] = $script:PimHybridAdMemoryLast[$Job][$k] } }
        if ($null -eq $stored) { $bad.reason = "the store could not be read: $($_.Exception.Message)"; return $bad }
    }
    $view = @{}; foreach ($k in @($stored.Keys)) { $view["$k"] = "$($stored[$k])" }
    if ($script:PimHybridAdMemoryDirty -is [hashtable] -and $script:PimHybridAdMemoryDirty[$Job] -is [hashtable]) {
        foreach ($k in @($script:PimHybridAdMemoryDirty[$Job].Keys)) {
            $d = $script:PimHybridAdMemoryDirty[$Job][$k]
            if ("$($stored[$k])" -ceq "$($d.base)") { $view[$k] = "$($d.json)" } else { $script:PimHybridAdMemoryDirty[$Job].Remove($k) }   # somebody else wrote it meanwhile: theirs counts
        }
    }
    $groups = @{}; $lastPass = [long]0; $decisions = @{}
    $nowE = ConvertTo-PimHybridAdEpoch $NowUtc
    foreach ($name in @($view.Keys)) {
        if ("$name" -match '\.\d+$') {
            try { $b = ConvertFrom-PimHybridAdMemoryJson -Json "$($view[$name])"; foreach ($k in @($b.Keys)) { $groups[$k] = $b[$k] } }
            catch { Write-Warning "[$Job] the sync memory '$name' is not readable and is started again (nobody is removed on an empty memory): $($_.Exception.Message)" }
        } elseif ("$name" -like '*.pass') {
            try { $pj = "$($view[$name])" | ConvertFrom-Json; if ($pj -and $pj.PSObject.Properties['lc']) { $lastPass = [long]$pj.lc } } catch { $lastPass = [long]0 }
        } elseif ("$name" -like '*.decisions' -and $liveRead) {
            # the record is used only when the store itself was read in THIS pass (never from this process's copy of an
            # earlier read: a decision that was withdrawn meanwhile must not be applied)
            $skipped = New-Object System.Collections.Generic.List[string]
            try {
                $dj = "$($stored[$name])" | ConvertFrom-Json
                if ($dj -and $dj.PSObject.Properties['groups'] -and $dj.groups) {
                    foreach ($dp in @($dj.groups.PSObject.Properties)) {
                        $dv = $dp.Value; $gk = "$($dp.Name)".Trim().ToLowerInvariant()
                        if (-not $gk -or $null -eq $dv -or -not $dv.PSObject) { continue }
                        $get = { param($f) if ($dv.PSObject.Properties[$f] -and $null -ne $dv.$f) { $dv.$f } else { $null } }
                        $kind = "$(& $get 'kind')".Trim().ToLowerInvariant(); $by = "$(& $get 'decidedBy')".Trim()
                        $atRaw = & $get 'decidedAtEpoch'; $at = [long]0
                        # a NUMBER of seconds only: date text is not accepted (it reads differently on 5.1 and 7)
                        if ($atRaw -is [int] -or $atRaw -is [long] -or $atRaw -is [double] -or $atRaw -is [decimal]) { try { $at = [long][math]::Floor([double]$atRaw) } catch { $at = [long]0 } }
                        $adoptId = "$(& $get 'adoptEntraGroupId')".Trim()
                        $rm = @(@(& $get 'removeMembers') | ForEach-Object { "$_".Trim() } | Where-Object { $_ } | Select-Object -Unique)
                        $why = ''
                        if ($kind -notin @('gone', 'never-seen', 'replaced')) { $why = 'no valid kind' }
                        elseif (-not $dv.PSObject.Properties['forEntraGroupId']) { $why = 'no forEntraGroupId' }
                        elseif (-not $by) { $why = 'no decidedBy' }
                        elseif ($at -le 0) { $why = 'no decidedAtEpoch (a number of seconds)' }
                        elseif ($at -gt ($nowE + (Get-PimHybridAdDecisionFutureMinutes) * 60)) { $why = 'dated in the future' }
                        elseif (($nowE - $at) -gt ((Get-PimHybridAdDecisionMaxHours) * 3600)) { $why = "older than $(Get-PimHybridAdDecisionMaxHours) hours" }
                        elseif ($adoptId -and $rm.Count) { $why = 'both adoptEntraGroupId and removeMembers' }
                        elseif (-not $adoptId -and -not $rm.Count) { $why = 'neither adoptEntraGroupId nor removeMembers' }
                        elseif ($adoptId -and $kind -ne 'replaced') { $why = 'adoptEntraGroupId needs kind = replaced' }
                        if ($why) { $skipped.Add("$($dp.Name) ($why)"); continue }
                        $decisions[$gk] = @{ kind = $kind; forId = "$(& $get 'forEntraGroupId')".Trim(); adoptId = $adoptId; remove = $rm; by = $by; at = $at }
                    }
                }
            } catch { $decisions = @{}; Write-PimHybridAdItemLines -Job "$Job-decisions" -Lines @("the SuperAdmin decisions record is not readable and is not used: $($_.Exception.Message)") }
            if ($skipped.Count) { Write-PimHybridAdItemLines -Job "$Job-decisions" -Lines @("SuperAdmin decision(s) not used: $($skipped.ToArray() -join '; ')") }
        }
    }
    return @{ ok = $true; reason = ''; stored = $stored; groups = $groups; lastPass = $lastPass; decisions = $decisions }
}
function Save-PimHybridAdSyncMemory {
    <#
      Writes ONLY the values whose text changed, each with compare-and-set against what Read-PimHybridAdSyncMemory saw
      (-Stored). A lost compare-and-set (another process wrote the bucket) is NOT retried and NOT kept: the next pass reads
      the newer value -- this pass's new holds in that bucket start again, nothing of the other process is overwritten.
      Never throws; returns @{ written; lost; failed }.
    #>
    param([Parameter(Mandatory)][string]$Job, [Parameter(Mandatory)][hashtable]$Groups, [hashtable]$Stored = @{}, [Parameter(Mandatory)][hashtable]$Store,
          [string]$WaitingJson = '', [string]$PassJson = '')
    $prefix = Get-PimHybridAdMemoryPrefix -Job $Job
    $n = Get-PimHybridAdMemoryBucketCount
    $empty = Get-PimHybridAdEmptyBucketJson
    $buckets = @{}
    foreach ($k in @($Groups.Keys)) { $b = Get-PimHybridAdMemoryBucket -Name "$k"; if (-not $buckets.ContainsKey($b)) { $buckets[$b] = @{} }; $buckets[$b]["$k"] = $Groups[$k] }
    $want = @{}
    for ($b = 0; $b -lt $n; $b++) { $want["$prefix$b"] = $(if ($buckets.ContainsKey($b)) { ConvertTo-PimHybridAdMemoryJson -Groups $buckets[$b] } else { $empty }) }
    if ("$WaitingJson") { $want["${prefix}waiting"] = "$WaitingJson" }
    if ("$PassJson") { $want["${prefix}pass"] = "$PassJson" }
    if ($script:PimHybridAdMemoryDirty -isnot [hashtable]) { $script:PimHybridAdMemoryDirty = @{} }
    if ($script:PimHybridAdMemoryDirty[$Job] -isnot [hashtable]) { $script:PimHybridAdMemoryDirty[$Job] = @{} }
    if ($script:PimHybridAdMemoryLast -isnot [hashtable]) { $script:PimHybridAdMemoryLast = @{} }
    $res = @{ written = 0; lost = 0; failed = 0 }
    $after = @{}; foreach ($name in @($Stored.Keys)) { $after["$name"] = "$($Stored[$name])" }
    foreach ($name in @($want.Keys)) {
        $old = ''; if ($Stored.ContainsKey($name)) { $old = "$($Stored[$name])" }
        if ($want[$name] -ceq $old) { if ($script:PimHybridAdMemoryDirty[$Job].ContainsKey($name)) { $script:PimHybridAdMemoryDirty[$Job].Remove($name) }; continue }
        if (-not $old -and ($want[$name] -ceq $empty -or $want[$name] -ceq (Get-PimHybridAdEmptyWaitingJson))) { continue }   # nothing stored, nothing to say
        try {
            if (& $Store.Save $name $want[$name] $old) { $res.written++; $after[$name] = $want[$name]; if ($script:PimHybridAdMemoryDirty[$Job].ContainsKey($name)) { $script:PimHybridAdMemoryDirty[$Job].Remove($name) } }
            else { $res.lost++; if ($script:PimHybridAdMemoryDirty[$Job].ContainsKey($name)) { $script:PimHybridAdMemoryDirty[$Job].Remove($name) }; Write-Warning "[$Job] the sync memory '$name' was changed by another process since this pass read it -- not overwritten; the next pass reads the newer value" }
        } catch { $res.failed++; $script:PimHybridAdMemoryDirty[$Job][$name] = @{ json = $want[$name]; base = $old }; Write-Warning "[$Job] the sync memory '$name' was not written (kept in this process, written at the next pass): $($_.Exception.Message)" }
    }
    $script:PimHybridAdMemoryLast[$Job] = $after
    return $res
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

function Select-PimHybridAdLaneGroups {
    <#
      PURE. The mirrored group rows one sync lane owns: 'servers' = the per-server groups (-ServerPattern, the server group
      format with {server} = *), 'critical' = all the others, 'all' = everything. 🔒 The critical lane drops the server groups
      ONLY while the server lane is alive: a worker whose task layout predates the lanes (or whose server loop died) keeps
      every group in sync -- never a gap. Returns @{ rows; note }.
    #>
    param([object[]]$Rows = @(), [ValidateSet('all', 'critical', 'servers')][string]$Lane = 'all', [string]$ServerPattern = '', [bool]$ServersLaneAlive = $true)
    $isSrv = { param($r) "$ServerPattern".Trim() -and "$($r.GroupName)".Trim() -like "$ServerPattern".Trim() }
    switch ($Lane) {
        'servers'  { return @{ rows = @($Rows | Where-Object { & $isSrv $_ }); note = '' } }
        'critical' {
            if (-not $ServersLaneAlive) { return @{ rows = @($Rows); note = 'server groups included -- the server lane is not running' } }
            return @{ rows = @($Rows | Where-Object { -not (& $isSrv $_) }); note = '' }
        }
        default    { return @{ rows = @($Rows); note = '' } }
    }
}

function Resolve-PimHybridAdMemberDn {
    <#
      One 'member' value (optionally '<TTL=n>,<dn>') -> @{ samAccountName; objectClass; ttlSeconds }. The DN -> account lookup
      is cached for $script:PimHybridAdCacheSeconds (the loop's refresh window; a member's account name does not change between
      passes), so a pass over thousands of groups costs one LDAP read for the groups, not one per member.
    #>
    param([Parameter(Mandatory)][string]$Entry, [scriptblock]$Lookup = { param($dn) $s = Get-PimHybridAdServerSplat; Get-PimHybridAdLdapObject -Dn $dn @s })
    $ttl = $null; $dn = $Entry
    if ($dn -match '^<TTL=(\d+)>,(.*)$') { $ttl = [int]$Matches[1]; $dn = $Matches[2] }
    $life = [int]$script:PimHybridAdCacheSeconds
    # Reset when there is none yet or the loop's refresh window passed. Outside the loop (no window) a process is one short tick.
    if (-not $script:PimHybridAdDnCache -or ($life -gt 0 -and ([datetime]::UtcNow - $script:PimHybridAdDnCache.at).TotalSeconds -ge $life)) {
        $script:PimHybridAdDnCache = @{ at = [datetime]::UtcNow; map = @{} }
    }
    $m = $script:PimHybridAdDnCache.map
    if (-not $m.ContainsKey($dn)) { $o = & $Lookup $dn; $m[$dn] = @{ sam = "$($o.sAMAccountName)"; cls = "$($o.objectClass)" } }
    $c = $m[$dn]
    return [pscustomobject]@{ samAccountName = $c.sam; objectClass = $c.cls; ttlSeconds = $ttl }
}

# ---------------------------------------------------------------------------------------------------------------------
# GROUP / COMPUTER LDAP HELPERS (REQ 100.42: no ActiveDirectory module). Built on the LDAP layer in PIM-HybridAd.ps1
# (Invoke-PimHybridAdLdapSearch / -Modify / -Add, Negotiate + sealed bind as the process identity, -Server = the named DC).
# The adapters below call ONLY these functions, so the suites stub them by name.
# ---------------------------------------------------------------------------------------------------------------------
function Get-PimHybridAdLdapObject {
    # Get-ADObject -Identity <dn> -Properties sAMAccountName, objectClass: objectClass = the most specific class (the last value).
    param([Parameter(Mandatory)][string]$Dn, [string]$Server)
    $r = @(Invoke-PimHybridAdLdapSearch -BaseDn $Dn -Scope Base -Filter '(objectClass=*)' -Attributes @('sAMAccountName', 'objectClass') -Server $Server)
    if (-not $r.Count) { throw "Cannot find an object with identity: '$Dn'" }
    $cls = @($r[0]['objectclass'])
    return [pscustomobject]@{ sAMAccountName = "$(@($r[0]['samaccountname'])[0])"; objectClass = $(if ($cls.Count) { "$($cls[$cls.Count - 1])" } else { '' }); DistinguishedName = $Dn }
}

function Get-PimHybridAdLdapGroups {
    # Get-ADGroup -Filter "Name -like '<pattern>'" (paged, 500) -- -WithTtl reads member values as '<TTL=n>,<dn>'.
    param([Parameter(Mandatory)][string]$Pattern, [string[]]$Attributes = @('displayName', 'description', 'adminCount'), [switch]$WithTtl, [string]$Server)
    $base = (Get-PimHybridAdLdapRootDse -Server $Server).DefaultNamingContext
    $f = "(&(objectCategory=group)(name=$(ConvertTo-PimHybridAdLdapFilterValue $Pattern -AllowWildcard)))"
    return @(Invoke-PimHybridAdLdapSearch -BaseDn $base -Filter $f -Attributes (@('name') + @($Attributes)) -WithTtl:$WithTtl -Server $Server)
}

function Find-PimHybridAdLdapDnBySam {
    # Get-ADGroup -Identity / Add-ADGroupMember -Members resolve a sAMAccountName: the one object carrying it (-Class narrows).
    param([Parameter(Mandatory)][string]$Sam, [ValidateSet('any', 'group')][string]$Class = 'any', [string]$Server)
    $base = (Get-PimHybridAdLdapRootDse -Server $Server).DefaultNamingContext
    $k = ConvertTo-PimHybridAdLdapFilterValue "$Sam".Trim()
    $f = if ($Class -eq 'group') { "(&(objectCategory=group)(sAMAccountName=$k))" } else { "(sAMAccountName=$k)" }
    $r = @(Invoke-PimHybridAdLdapSearch -BaseDn $base -Filter $f -Attributes @('sAMAccountName') -Server $Server)
    if (-not $r.Count) { throw "Cannot find an object with identity: '$Sam' under: '$base'." }
    return "$(@($r[0]['distinguishedname'])[0])"
}

function New-PimHybridAdLdapGroup {
    # New-ADGroup -GroupCategory Security -GroupScope Global: groupType 0x80000002.
    param([Parameter(Mandatory)][string]$Name, [string]$DisplayName, [string]$Description, [Parameter(Mandatory)][string]$Ou, [string]$Server)
    $attrs = [ordered]@{ objectClass = 'group'; sAMAccountName = $Name; groupType = '-2147483646'; displayName = $DisplayName; description = $Description }
    Invoke-PimHybridAdLdapAdd -Dn "CN=$(ConvertTo-PimHybridAdRdnValue $Name),$Ou" -Attributes $attrs -Server $Server
}

function Set-PimHybridAdLdapGroup {
    # Set-ADGroup -DisplayName -Description: a blank value clears the attribute (what Set-ADGroup did with $null).
    param([Parameter(Mandatory)][string]$Name, [string]$DisplayName, [string]$Description, [string]$Server)
    $dn = Find-PimHybridAdLdapDnBySam -Sam $Name -Class group -Server $Server
    $changes = @(
        $(if ("$DisplayName".Trim()) { @{ op = 'Replace'; name = 'displayName'; values = @("$DisplayName") } } else { @{ op = 'Replace'; name = 'displayName'; values = @() } }),
        $(if ("$Description".Trim()) { @{ op = 'Replace'; name = 'description'; values = @("$Description") } } else { @{ op = 'Replace'; name = 'description'; values = @() } }))
    Invoke-PimHybridAdLdapModify -Dn $dn -Changes $changes -Server $Server
}

function Test-PimHybridAdLdapBenignMemberError {
    # PURE. "already a member" (LDAP 20 attributeOrValueExists / ERROR_MEMBER_IN_GROUP) on an add, "not a member" (LDAP 16
    # noSuchAttribute / ERROR_MEMBER_NOT_IN_GROUP) on a remove: the desired state already holds -- Add-/Remove-ADGroupMember
    # did not fail on either.
    param([object]$ErrorRecord, [ValidateSet('Add', 'Remove')][string]$Op)
    $t = 'System.DirectoryServices.Protocols.DirectoryOperationException' -as [type]
    if (-not $t) { return $false }
    $ex = $ErrorRecord.Exception
    while ($ex -and -not ($ex -is $t) -and $ex.InnerException) { $ex = $ex.InnerException }
    if ($ex -is $t -and $ex.Response) {
        $rc = [int]$ex.Response.ResultCode
        if ($Op -eq 'Add' -and $rc -eq 20) { return $true }
        if ($Op -eq 'Remove' -and $rc -eq 16) { return $true }
    }
    return $false
}

function Add-PimHybridAdLdapGroupMember {
    # Add-ADGroupMember [-MemberTimeToLive]: a PAM time-bound link is written as '<TTL=seconds,dn>'.
    param([Parameter(Mandatory)][string]$Group, [Parameter(Mandatory)][string]$Member, $TtlSeconds = $null, [string]$Server)
    $gdn = Find-PimHybridAdLdapDnBySam -Sam $Group -Class group -Server $Server
    $mdn = Find-PimHybridAdLdapDnBySam -Sam $Member -Server $Server
    $val = if ($null -ne $TtlSeconds) { "<TTL=$([int]$TtlSeconds),$mdn>" } else { $mdn }
    try { Invoke-PimHybridAdLdapModify -Dn $gdn -Changes @(@{ op = 'Add'; name = 'member'; values = @($val) }) -Server $Server }
    catch { if (-not (Test-PimHybridAdLdapBenignMemberError -ErrorRecord $_ -Op Add)) { throw } }
}

function Remove-PimHybridAdLdapGroupMember {
    param([Parameter(Mandatory)][string]$Group, [Parameter(Mandatory)][string]$Member, [string]$Server)
    $gdn = Find-PimHybridAdLdapDnBySam -Sam $Group -Class group -Server $Server
    $mdn = Find-PimHybridAdLdapDnBySam -Sam $Member -Server $Server
    try { Invoke-PimHybridAdLdapModify -Dn $gdn -Changes @(@{ op = 'Delete'; name = 'member'; values = @($mdn) }) -Server $Server }
    catch { if (-not (Test-PimHybridAdLdapBenignMemberError -ErrorRecord $_ -Op Remove)) { throw } }
}

function Get-PimHybridAdLdapComputers {
    # Get-ADComputer -Filter 'OperatingSystem -like "*Windows Server*"' -Properties Name, DNSHostName, OperatingSystem, Enabled,
    # whenChanged, primaryGroupID -- the same property names, so Get-PimHybridAdServerCandidates is unchanged.
    param([string]$Server)
    $base = (Get-PimHybridAdLdapRootDse -Server $Server).DefaultNamingContext
    $rows = @(Invoke-PimHybridAdLdapSearch -BaseDn $base -Filter '(&(objectCategory=computer)(operatingSystem=*Windows Server*))' `
            -Attributes @('name', 'dNSHostName', 'operatingSystem', 'userAccountControl', 'whenChanged', 'primaryGroupID') -Server $Server)
    return @(foreach ($r in $rows) {
            $one = { param($n) $v = @($r["$n".ToLowerInvariant()]); if ($v.Count) { "$($v[0])" } else { $null } }
            $uac = 0; [void][int]::TryParse("$(& $one 'userAccountControl')", [ref]$uac)
            $wc = & $one 'whenChanged'
            [pscustomobject]@{ Name = (& $one 'name'); DNSHostName = (& $one 'dNSHostName'); OperatingSystem = (& $one 'operatingSystem'); Enabled = -not ($uac -band 2)
                whenChanged = $(if ($wc) { ConvertFrom-PimHybridAdLdapValue $wc } else { $null }); primaryGroupID = (& $one 'primaryGroupID') }
        })
}

function Get-PimDefaultActiveDirectoryGroupAdapter {
    <#
      [ ] HYBRID-WORKER-ONLY. The real AD calls for the group mirror + membership sync -- LDAP through .NET (the helpers above),
      no ActiveDirectory module. Runs as the process identity (the gMSA -- no -Credential); -Server from
      $global:PIM_HybridAdServer when set. Throws off a host that is not domain-joined.
    #>
    if (-not (Test-PimHybridAdDirectoryAvailable)) { throw 'This host is not joined to an Active Directory domain -- the group adapter is hybrid-worker-only.' }
    # 🔴 NO CLOSURE-STYLE LOCALS in the blocks below: they run long after this function returned (dynamic scoping), so a
    # local such as the old `$srv = { ... }` is $null by then and every AD call failed with "The expression after '&' ...
    # was not valid" -- found by the first plan-only run on the internal worker 2026-09-29. They call a FUNCTION instead.
    return @{
        PamEnabled = {
            $s = Get-PimHybridAdServerSplat
            return [bool](Test-PimHybridAdLdapPamEnabled @s)
        }
        GetGroups = {
            param([string]$Pattern)
            $s = Get-PimHybridAdServerSplat
            @(Get-PimHybridAdLdapGroups -Pattern $Pattern @s | ForEach-Object {
                    $g = $_; $one = { param($n) $v = @($g[$n]); if ($v.Count) { "$($v[0])" } else { $null } }
                    [pscustomobject]@{ Name = (& $one 'name'); DisplayName = (& $one 'displayname'); Description = (& $one 'description'); adminCount = (& $one 'admincount') } })
        }
        NewGroup = {
            param($Item, [string]$Ou)
            $s = Get-PimHybridAdServerSplat
            New-PimHybridAdLdapGroup -Name $Item.name -DisplayName $Item.displayName -Description $Item.description -Ou $Ou @s
        }
        SetGroup = {
            param($Item)
            $s = Get-PimHybridAdServerSplat
            Set-PimHybridAdLdapGroup -Name $Item.name -DisplayName $Item.displayName -Description $Item.description @s
        }
        GetMembers = {
            param([string]$Group)
            $s = Get-PimHybridAdServerSplat
            $dn = Find-PimHybridAdLdapDnBySam -Sam $Group -Class group @s
            $g = @(Invoke-PimHybridAdLdapSearch -BaseDn $dn -Scope Base -Filter '(objectClass=*)' -Attributes @('member') -WithTtl @s)
            foreach ($entry in @($g | ForEach-Object { @($_['member']) })) { Resolve-PimHybridAdMemberDn -Entry "$entry" }
        }
        # SCALE (2026-10-04): every group's members in ONE paged LDAP read (the pattern search, attribute member, TTL control),
        # member DNs resolved once and cached (Resolve-PimHybridAdMemberDn) -- instead of one group read + one object read per
        # member per group per pass. Returns @{ <group name> = @( @{ samAccountName; objectClass; ttlSeconds } ) }.
        GetMembersMany = {
            param([string]$Pattern)
            $s = Get-PimHybridAdServerSplat
            $map = @{}
            foreach ($g in @(Get-PimHybridAdLdapGroups -Pattern $Pattern -Attributes @('member') -WithTtl @s)) {
                $map["$(@($g['name'])[0])"] = @(foreach ($entry in @($g['member'])) { Resolve-PimHybridAdMemberDn -Entry "$entry" })
            }
            $map
        }
        AddMember = {
            param([string]$Group, [string]$Sam, $TtlSeconds)
            $s = Get-PimHybridAdServerSplat
            Add-PimHybridAdLdapGroupMember -Group $Group -Member $Sam -TtlSeconds $TtlSeconds @s
        }
        RemoveMember = {
            param([string]$Group, [string]$Sam)
            $s = Get-PimHybridAdServerSplat
            Remove-PimHybridAdLdapGroupMember -Group $Group -Member $Sam @s
        }
    }
}

function Get-PimHybridAdCreateFailureReason {
    <#
      PURE. AD's answer to a failed group create, in words that say what to fix. Measured on internal 2026-10-04: the OU for
      new groups had inheritance OFF and no read right for the worker, so New-ADGroup answered "Cannot find an object with
      identity: '<the OU>'" (and the job showed "The server is unwilling to process the request") -- neither says "grant read".
    #>
    param([string]$Message, [string]$Ou = '', [string]$GmsaName = "$(if ("$env:PIM_HybridAdGmsaName".Trim()) { $env:PIM_HybridAdGmsaName } else { $global:PIM_HybridAdGmsaName })")
    $m = "$Message".Trim()
    $grp = if ("$GmsaName".Trim()) { "$(("$GmsaName".Trim() -split '\\')[-1].TrimEnd('$'))-PermissionGroup" } else { "the worker's permission group" }
    if (($m -match '(?i)cannot find an object with identity' -and ("$Ou".Trim() -and $m.IndexOf("$Ou".Trim(), [StringComparison]::OrdinalIgnoreCase) -ge 0)) -or $m -match '(?i)unwilling to (process|perform)') {
        return "the worker's account cannot READ the OU for new groups ('$Ou') -- grant $grp Read on that OU (This object and all descendant objects; an OU with inheritance turned off hides it). AD said: $m"
    }
    if ($m -match '(?i)access is denied|insufficient access rights') {
        return "the worker's account may not create groups in '$Ou' -- grant $grp 'Create Group objects' on that OU (Initialize-PimHybridWorkerAd -GroupsOu does). AD said: $m"
    }
    return $m
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
        catch { $res.Add([pscustomobject]@{ name = $x.name; op = 'create'; status = 'failed'; reason = (Get-PimHybridAdCreateFailureReason -Message "$($_.Exception.Message)" -Ou $Ou) }) }
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
      100.122 F1 -- a REMOVAL is made only on evidence (Get-PimHybridAdGuardedPlan): -Answer is what Entra said for each
      group in this pass (the reader's -Answer table; a group without an answer is NOT KNOWN = nobody is removed), -Memory
      the sync memory (lower-case group name -> memory), -MemoryStale "no pass for a long time", -Decisions a SuperAdmin's
      decisions (lower-case group name -> decision, from Read-PimHybridAdSyncMemory). Adds and re-adds need none of them.
      Returns @{ pamEnabled; results[] { group; samAccountName; op; status; reason }; memory (for the next pass); states;
      warning }. Rows of this lane: op 'entra' (the group's own line: status not-known | waiting | replaced | memory | note)
      and status 'held' (a member kept, with the reason and hold = confirm | principal | not-known | replaced | superadmin |
      memory). warning = somebody was kept in this pass, or a group needs a look.
    #>
    param(
        [Parameter(Mandatory)][string[]]$Groups, [Parameter(Mandatory)][hashtable]$ActiveByGroup, [Parameter(Mandatory)][hashtable]$Adapter,
        [switch]$Apply, [datetime]$NowUtc = [datetime]::UtcNow, [string[]]$Protected = @(), [object]$PamEnabled = $null,
        [hashtable]$Answer = $null, [hashtable]$Memory = $null, [bool]$MemoryReadable = $true, [bool]$MemoryStale = $false, [hashtable]$Decisions = $null,
        # 2026-10-04 scale: the live members of every group, read in ONE pass (adapter GetMembersMany); a group not in it is read on its own
        [hashtable]$LiveByGroup = $null
    )
    $pam = if ($null -ne $PamEnabled) { [bool]$PamEnabled } else { try { [bool](& $Adapter.PamEnabled) } catch { $false } }
    $sfx = Get-PimHybridAdSuffixes
    $cloudSfx = $sfx.cloud; $adSfx = $sfx.ad
    $res = New-Object System.Collections.Generic.List[object]
    $nextMem = @{}; $states = @{}; $warn = $false
    foreach ($g in @($Groups)) {
        $gk = "$g".ToLowerInvariant()
        $gmem = $null; if ($Memory -and $Memory[$gk] -is [hashtable]) { $gmem = $Memory[$gk] }
        try { $live = if ($LiveByGroup -and $LiveByGroup.ContainsKey($g)) { @($LiveByGroup[$g]) } else { @(& $Adapter.GetMembers $g) } }
        catch {
            $res.Add([pscustomobject]@{ group = $g; samAccountName = ''; op = 'read'; status = 'failed'; reason = "$($_.Exception.Message)" })
            # no pass for this group: its memory stays, with "no complete pass since" (B4: once that lasts 30 minutes its
            # recorded end times are not trusted)
            if ($gmem) { $keepMem = Copy-PimHybridAdGroupMemory -Memory $gmem; if ([long]$keepMem.ss -le 0) { $keepMem.ss = ConvertTo-PimHybridAdEpoch $NowUtc }; $nextMem[$gk] = $keepMem }
            continue
        }
        $act = @(); if ($ActiveByGroup.ContainsKey($g)) { $act = @($ActiveByGroup[$g]) }
        $plan = Get-PimHybridAdMembershipPlan -Active $act -LiveMembers $live -PamEnabled $pam -NowUtc $NowUtc -CloudSuffix $cloudSfx -AdSuffix $adSfx -Protected $Protected
        # 100.122 F1: which of the plan's removals are made in THIS pass (never more than the plan has; adds untouched)
        $ans = $null; if ($Answer -and $Answer.ContainsKey($g)) { $ans = $Answer[$g] }
        $decision = $null; if ($Decisions -and $Decisions[$gk] -is [hashtable]) { $decision = $Decisions[$gk] }
        $guarded = Get-PimHybridAdGuardedPlan -Plan $plan -Active $act -Answer $ans -Memory $gmem -MemoryReadable $MemoryReadable -MemoryStale $MemoryStale -Decision $decision -NowUtc $NowUtc -CloudSuffix $cloudSfx -AdSuffix $adSfx
        if ($guarded.memory) { $nextMem[$gk] = $guarded.memory }
        $states[$g] = $guarded.state
        if ($guarded.warning) { $warn = $true }
        if ($guarded.reason -and ($guarded.state -ne 'memory' -or @($guarded.held).Count)) {
            $res.Add([pscustomobject]@{ group = $g; samAccountName = ''; op = 'entra'; status = $(if ($guarded.state -eq 'known') { 'principal' } else { $guarded.state }); kind = $guarded.kind; reason = $guarded.reason; detail = $guarded.detail })
        }
        foreach ($nt in @($guarded.notes)) { $res.Add([pscustomobject]@{ group = $g; samAccountName = ''; op = 'entra'; status = 'note'; kind = ''; reason = "$nt"; detail = '' }) }
        foreach ($k in $guarded.held) { $res.Add([pscustomobject]@{ group = $g; samAccountName = $k.samAccountName; op = 'none'; status = 'held'; reason = $k.reason; hold = $k.hold }) }
        $plan.remove = @($guarded.remove)
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
    return [pscustomobject]@{ pamEnabled = $pam; results = $res.ToArray(); memory = $nextMem; states = $states; warning = $warn }
}

function Invoke-PimHybridAdInstanceBatch {
    <#
      The active MEMBER instances of up to N groups through Graph `$batch (20 per round trip). -Items: { name; id }.
      -Post = { param($bodyJson) } sends one batch and returns the answer (or throws); 3 tries per round trip.
      Returns groupName -> the list, ONLY for a group whose sub-response is a complete answer: status 200, a body that
      carries a `value` LIST, no next link (B5: a 200 with any other body is not "nobody is active"). Every other group
      is simply not in the result -- the caller reads it again on its own.
      Self-contained (no other function of this file): the parallel reader runs this text in its own runspaces.
    #>
    param([object[]]$Items = @(), [Parameter(Mandatory)][scriptblock]$Post, [int]$RetrySeconds = 2)
    $items = @($Items); $got = @{}
    for ($k = 0; $k -lt $items.Count; $k += 20) {
        $slice = @($items[$k..([Math]::Min($k + 20, $items.Count) - 1)])
        $reqs = for ($r = 0; $r -lt $slice.Count; $r++) {
            @{ id = "$r"; method = 'GET'; url = "/identityGovernance/privilegedAccess/group/assignmentScheduleInstances?`$filter=groupId eq '$($slice[$r].id)' and accessId eq 'member'" }
        }
        $body = @{ requests = @($reqs) } | ConvertTo-Json -Depth 6
        $resp = $null
        for ($try = 1; $try -le 3; $try++) {
            try { $resp = & $Post $body; break }
            catch { $resp = $null; if ($RetrySeconds -gt 0) { Start-Sleep -Seconds ($RetrySeconds * $try) } }
        }
        if (-not $resp -or -not $resp.responses) { continue }   # not answered: every group of this slice is read again by the caller
        foreach ($rr in @($resp.responses)) {
            if ($null -eq $rr) { continue }
            $ix = -1
            if (-not [int]::TryParse("$($rr.id)", [ref]$ix) -or $ix -lt 0 -or $ix -ge $slice.Count) { continue }
            if ("$($rr.status)" -ne '200' -or $null -eq $rr.body) { continue }
            $b = $rr.body
            if (-not $b.PSObject.Properties['value'] -or $b.value -isnot [array]) { continue }
            if ($b.PSObject.Properties['@odata.nextLink'] -and "$($b.'@odata.nextLink')") { continue }
            $got["$($slice[$ix].name)"] = @($b.value)
        }
    }
    return $got
}

function Get-PimHybridAdActiveGroupMembers {
    <#
      READ-ONLY Graph (the worker's own identity -- VM managed identity or certificate): for each group name, the ACTIVE
      PIM-for-Groups MEMBER assignments -> @{ mailNickname; endUtc } (users only; a group principal is skipped, as in v1).
      Returns a hashtable groupName -> list. -Graph is the seam ( { param($path) ... } returning the aggregated items ).
      Needs Graph application permissions: Group.Read.All + PrivilegedAssignmentSchedule.Read.AzureADGroup + User.Read.All.

      SCALE (operator 2026-10-04: "if a customer has 10000 servers + 65 critical ad groups, then it takes 1-2 hours to come
      to the critical groups" / "for servers ... use batch parallels in ps7" / "it could run fx 50 servers per batch"):
        * group ids: with more than 20 unknown names and a -Prefix, ONE paged listing (displayName startswith <prefix>)
          fills the id cache instead of one lookup per group;
        * active instances: with -Parallel > 1 on PowerShell 7, the groups are cut into batches of -BatchSize (default 50);
          each batch runs in its own runspace (ForEach-Object -Parallel, at most -Parallel at once) and reads its groups
          through Graph `$batch (20 per round trip, Invoke-PimHybridAdInstanceBatch). Anything a batch could not answer
          (throttled, failed, paged, a body without a list) is read again one by one through -Graph afterwards;
        * principals: more than 20 unknown ids are resolved through /directoryObjects/getByIds (1,000 per call).
      With a custom -Graph (tests) or on Windows PowerShell 5.1 the reads stay one by one, exactly as before.

      100.122 F1 -- THE ANSWER PER GROUP (-Answer, a table this function FILLS; a caller that removes members MUST read it:
      the returned list alone cannot tell "nobody is active" from "the read failed"):
        @{ state; complete; id; altId; why (a code, Get-PimHybridAdWhyText); detail; deleted; principalFailed;
           principalNotFound }
        state found     the group answers under the DEFINED name (looked up by its remembered id, -KnownIds, or found by
                        name for the first time)
              gone      the remembered id answers 404, the deleted items answered, and no other group carries the name
              replaced  the remembered id is gone -- or carries another name now -- and exactly ONE other group carries the
                        name (altId). The returned list is THAT group's active members: adds only, see the decision.
              renamed   the remembered id answers under another name and no group carries the defined name. NOTHING is
                        read for it: nobody is added from a group that does not carry the defined name (B1).
              unknown   everything else: a failed, throttled or partial read, an empty name search, two groups with one name
        complete        the read of the active members answered in full (a failed principal read is counted apart:
                        principalFailed / principalNotFound, B2)
      A failure is NEVER kept as an answer -- not here and not in the caches.
    #>
    param([Parameter(Mandatory)][string[]]$GroupNames, [scriptblock]$Graph, [string]$Prefix = '',
          [ValidateRange(1, 1000)][int]$BatchSize = 50, [ValidateRange(1, 64)][int]$Parallel = 1,
          # -KnownIds = the Entra object ids the sync remembers (group name -> id). -GraphPost = the seam for the bulk reads
          # ( { param($path, $body) } ); -BatchPost = the seam for the `$batch round trip ( { param($bodyJson) } ): with it
          # the batch path runs (one batch after the other) on any edition -- tests drive the production path with it.
          [hashtable]$KnownIds = $null, [hashtable]$Answer = $null, [scriptblock]$GraphPost = $null, [scriptblock]$BatchPost = $null)
    $realGraph = -not $Graph
    if (-not $Graph) { $Graph = { param($p) @(Invoke-PimGraph -Path $p -All) } }
    if (-not $GraphPost -and $realGraph) { $GraphPost = { param($p, $b) Invoke-PimGraph -Method POST -Path $p -Body $b } }   # a READ: the only path sent is /directoryObjects/getByIds
    if ($null -eq $KnownIds) { $KnownIds = @{} }
    if ($null -eq $Answer) { $Answer = @{} }
    # decision (29): how a [datetime] end time is read is the install's setting, asked ONCE per pass (one pass never mixes
    # the two readings); off unless the setting says 'on'
    $endAsUtc = [bool](Test-PimHybridAdEndTimeAsUtc)
    $out = @{}
    # group ids + users change rarely; the ACTIVE instances are read fresh on every call. With $script:PimHybridAdCacheSeconds
    # set (the continuous loop) the first two are kept that long, so a pass costs ~one Graph call per group (or per batch).
    $ttl = [int]$script:PimHybridAdCacheSeconds
    if ($ttl -le 0 -or -not $script:PimHybridAdGraphCache -or ([datetime]::UtcNow - $script:PimHybridAdGraphCache.at).TotalSeconds -ge $ttl) {
        $script:PimHybridAdGraphCache = @{ at = [datetime]::UtcNow; groups = @{}; users = @{} }
    }
    $groupCache = $script:PimHybridAdGraphCache.groups
    $userCache = $script:PimHybridAdGraphCache.users
    $names = @($GroupNames | Where-Object { "$_".Trim() } | Select-Object -Unique)

    # What this pass learns per group. state: unknown (no id) | byid (an id to verify) | found | ambiguous | gone | replaced
    # | renamed. readId = the group whose active members are read ('' = none). complete = that read answered in full.
    $ev = @{}
    foreach ($n in $names) { $ev[$n] = @{ id = ''; readId = ''; altId = ''; state = 'unknown'; why = 'never-seen'; rwhy = ''; detail = ''; deleted = $false; complete = $true; pfail = 0; pnf = (New-Object System.Collections.Generic.List[string]) } }
    $doubt = { param($n, $why, $detail) $e = $ev[$n]; if ($e.complete) { $e.complete = $false; $e.rwhy = "$why"; if (-not $e.detail) { $e.detail = "$detail" } } }
    $nameSearch = {
        # the Entra groups carrying exactly this name: @{ ok; ids[]; error }
        param($n)
        $esc = "$n".Replace("'", "''")
        try {
            $grp = @(& $Graph "/groups?`$filter=displayName eq '$esc'&`$select=id,displayName")
            if (Test-PimHybridAdPartialItems -Items $grp) { return @{ ok = $false; ids = @(); error = 'the search came back partial (a next link that was not followed)' } }
            return @{ ok = $true; ids = @($grp | Where-Object { $null -ne $_ } | ForEach-Object { "$($_.id)".Trim() } | Where-Object { $_ } | Select-Object -Unique); error = '' }
        } catch { return @{ ok = $false; ids = @(); error = "$($_.Exception.Message)" } }
    }

    # (1) group ids. A remembered id wins: that group is looked up BY ID in (1b); its name is not searched.
    foreach ($n in $names) {
        $kid = ''
        if ($KnownIds.ContainsKey($n)) { $kid = "$($KnownIds[$n])".Trim() }
        if (-not $kid -and $groupCache.ContainsKey($n)) { $kid = "$($groupCache[$n])".Trim() }
        if ($kid) { $ev[$n].id = $kid; $ev[$n].state = 'byid'; $ev[$n].why = '' }
    }
    $unknown = @($names | Where-Object { -not $ev[$_].id })
    $listedMany = $false
    if ($unknown.Count -gt 20 -and "$Prefix".Trim()) {
        $pe = "$Prefix".Trim().Replace("'", "''")
        $listOk = $false; $listErr = ''
        try {
            $rows = @(& $Graph "/groups?`$filter=startswith(displayName,'$pe')&`$select=id,displayName")
            if (Test-PimHybridAdPartialItems -Items $rows) { throw 'the listing came back partial (a next link that was not followed)' }
            $byN = @{}
            foreach ($g in $rows) {
                if ($null -eq $g) { continue }
                $dn = "$($g.displayName)".Trim(); $gid = "$($g.id)".Trim()
                if (-not $dn -or -not $gid) { continue }
                if (-not $byN.ContainsKey($dn)) { $byN[$dn] = New-Object System.Collections.Generic.List[string] }
                if (-not $byN[$dn].Contains($gid)) { $byN[$dn].Add($gid) }
            }
            foreach ($n in $unknown) {
                if (-not $byN.ContainsKey($n)) { continue }
                $ev[$n].id = $byN[$n][0]; $ev[$n].readId = $ev[$n].id
                if ($byN[$n].Count -eq 1) { $ev[$n].state = 'found'; $ev[$n].why = ''; $groupCache[$n] = $ev[$n].id }
                else { $ev[$n].state = 'ambiguous'; $ev[$n].why = 'ambiguous'; $ev[$n].detail = "$($byN[$n].Count) Entra groups are named '$n'" }
            }
            $listOk = $true
        } catch { $listErr = "$($_.Exception.Message)"; Write-Warning "[hybrid-ad] group id listing failed: $listErr" }
        $unknown = @($names | Where-Object { -not $ev[$_].id })
        if ($unknown.Count -gt 20) {
            # Too many to ask one by one. Listed and not there = NOT KNOWN (never "no such group"); a failed listing too.
            $listedMany = $true
            if (-not $listOk) { foreach ($n in $unknown) { $ev[$n].why = 'name-lookup-failed'; $ev[$n].detail = $listErr } }
        }
    }
    if (-not $listedMany) {
        foreach ($name in $unknown) {
            $s = & $nameSearch $name
            if (-not $s.ok) { $ev[$name].why = 'name-lookup-failed'; $ev[$name].detail = "$($s.error)"; continue }
            if (@($s.ids).Count -eq 1) { $ev[$name].id = @($s.ids)[0]; $ev[$name].readId = $ev[$name].id; $ev[$name].state = 'found'; $ev[$name].why = ''; $groupCache[$name] = $ev[$name].id }
            elseif (@($s.ids).Count -gt 1) { $ev[$name].id = @($s.ids)[0]; $ev[$name].readId = $ev[$name].id; $ev[$name].state = 'ambiguous'; $ev[$name].why = 'ambiguous'; $ev[$name].detail = "$(@($s.ids).Count) Entra groups are named '$name'" }
            # none: stays unknown / never-seen -- an empty name search is never "gone"
        }
    }

    # (1b) a remembered id is VERIFIED in every pass: FOUND only when Entra answers for the id AND the group still carries
    # the DEFINED name (B1). "Gone" for this pass needs the id itself to answer 404 AND an answer from the deleted items (in
    # them, or 404 there too) AND no other group of that name. Another group of that name = REPLACED, never the old one (A3).
    # Anything else -- a failed, throttled or partial read -- leaves the group NOT KNOWN.
    $toCheck = @($names | Where-Object { $ev[$_].state -eq 'byid' })
    $exists = @{}; $absent = @{}
    if ($toCheck.Count -and $GraphPost) {
        $idsAll = @($toCheck | ForEach-Object { $ev[$_].id } | Select-Object -Unique)
        for ($c = 0; $c -lt $idsAll.Count; $c += 1000) {
            $ids = @($idsAll[$c..([Math]::Min($c + 1000, $idsAll.Count) - 1)])
            try {
                $r = & $GraphPost '/directoryObjects/getByIds' @{ ids = $ids; types = @('group') }
                if ($null -eq $r -or -not $r.PSObject.Properties['value']) { throw 'the answer carries no list' }
                if ($r.PSObject.Properties['@odata.nextLink'] -and "$($r.'@odata.nextLink')") { throw 'the answer came back partial (a next link that was not followed)' }
                $got = @{}; foreach ($o in @($r.value)) { if ($null -ne $o -and "$($o.id)".Trim() -and $o.PSObject.Properties['displayName']) { $got["$($o.id)".Trim()] = "$($o.displayName)" } }
                foreach ($i in $ids) { if ($got.ContainsKey($i)) { $exists[$i] = $got[$i] } else { $absent[$i] = $true } }
            } catch { Write-Warning "[hybrid-ad] the lookup of $($ids.Count) group id(s) failed -- those groups are not known in this pass: $($_.Exception.Message)" }
        }
    }
    foreach ($n in $toCheck) {
        $e = $ev[$n]; $id = $e.id
        $liveName = $null; $is404 = $false; $decided = $false
        if ($exists.ContainsKey($id)) { $liveName = "$($exists[$id])" }
        elseif ($GraphPost -and -not $absent.ContainsKey($id)) { $e.state = 'unknown'; $e.why = 'exists-failed'; $e.detail = 'the bulk lookup by id failed'; $e.readId = $id; $decided = $true }
        else {
            # no bulk seam, or the bulk answer did not carry the id (or its name): ask for the id itself
            try {
                $one = @(& $Graph "/groups/$($id)?`$select=id,displayName")[0]
                if ($one -and "$($one.id)".Trim() -eq $id -and $one.PSObject.Properties['displayName']) { $liveName = "$($one.displayName)" }
                else { $e.state = 'unknown'; $e.why = 'exists-failed'; $e.detail = 'the lookup by id gave no group with its name'; $e.readId = $id; $decided = $true }
            } catch {
                if (Test-PimHybridAdNotFound -Message "$($_.Exception.Message)") { $is404 = $true }
                else { $e.state = 'unknown'; $e.why = 'exists-failed'; $e.detail = "$($_.Exception.Message)"; $e.readId = $id; $decided = $true }
            }
        }
        if ($decided) { continue }
        if (-not $is404 -and (Test-PimHybridAdSameName -A $liveName -B $n)) { $e.state = 'found'; $e.readId = $id; continue }
        $inDeleted = $null
        if ($is404) {
            $delErr = ''
            try { $del = @(& $Graph "/directory/deletedItems/$($id)?`$select=id")[0]; if ($del -and "$($del.id)".Trim() -eq $id) { $inDeleted = $true } else { $delErr = 'the deleted items gave no answer for the id' } }
            catch { if (Test-PimHybridAdNotFound -Message "$($_.Exception.Message)") { $inDeleted = $false } else { $delErr = "$($_.Exception.Message)" } }
            if ($null -eq $inDeleted) { $e.state = 'unknown'; $e.why = 'exists-failed'; $e.detail = "the id answers 'not found', the deleted items could not be read: $delErr"; continue }
        }
        # the remembered id no longer carries the name (gone, or renamed): who carries it now?
        $s = & $nameSearch $n
        if (-not $s.ok) { $e.state = 'unknown'; $e.why = 'name-lookup-failed'; $e.detail = "$($s.error)"; continue }
        $others = @(@($s.ids) | Where-Object { $_ -ne $id })
        $what = $(if ($is404) { 'the remembered group is gone' } else { "the Entra group was renamed to '$liveName'" })
        if ($others.Count -eq 1) { $e.state = 'replaced'; $e.why = 'replaced'; $e.altId = $others[0]; $e.readId = $others[0]; $e.detail = "$what; another group carries the name"; $e.deleted = [bool]$inDeleted }
        elseif ($others.Count -gt 1) { $e.state = 'ambiguous'; $e.why = 'ambiguous'; $e.readId = $others[0]; $e.detail = "$what; $($others.Count) other Entra groups are named '$n'" }
        elseif ($is404) { $e.state = 'gone'; $e.why = 'gone-unconfirmed'; $e.deleted = [bool]$inDeleted; if ($groupCache.ContainsKey($n)) { $groupCache.Remove($n) } }
        elseif (@($s.ids) -contains $id) { $e.state = 'unknown'; $e.why = 'exists-failed'; $e.detail = "the lookup by id says the group is named '$liveName', the search by name still finds it under '$n'" }
        else { $e.state = 'renamed'; $e.why = 'renamed'; $e.detail = "the Entra group was renamed to '$liveName' and no group carries the defined name"; if ($groupCache.ContainsKey($n)) { $groupCache.Remove($n) } }
    }

    # (2) active instances -- for every group that has one to read (also a doubtful one: adds are never delayed). Not for a
    # group that is gone, and not for a RENAMED one: nobody is added from a group that does not carry the defined name.
    $withId = @($names | Where-Object { $ev[$_].readId })
    $instByGroup = @{}
    $useParallel = ($realGraph -and $Parallel -gt 1 -and $PSVersionTable.PSVersion.Major -ge 7 -and $withId.Count -gt 1)
    if ($BatchPost -or $useParallel) {
        $chunks = New-Object System.Collections.Generic.List[object]
        for ($c = 0; $c -lt $withId.Count; $c += $BatchSize) {
            $chunks.Add(@($withId[$c..([Math]::Min($c + $BatchSize, $withId.Count) - 1)] | ForEach-Object { [pscustomobject]@{ name = $_; id = $ev[$_].readId } }))
        }
        $answers = @()
        if ($BatchPost) {
            $answers = @(foreach ($ch in $chunks) { Invoke-PimHybridAdInstanceBatch -Items @($ch) -Post $BatchPost -RetrySeconds 0 })
        } else {
            $token = Get-PimRestToken -Resource 'graph'
            $timeout = 100; if (Test-PimHybridAdFunction 'Get-PimRestTimeoutSec') { $timeout = [int](Get-PimRestTimeoutSec) }
            $fnText = "${function:Invoke-PimHybridAdInstanceBatch}"
            $answers = $chunks | ForEach-Object -ThrottleLimit $Parallel -Parallel {
                $tok = $using:token; $to = $using:timeout
                $fn = [scriptblock]::Create($using:fnText)
                & $fn -Items @($_) -Post { param($body) Invoke-RestMethod -Method POST -Uri 'https://graph.microsoft.com/v1.0/$batch' -Headers @{ Authorization = "Bearer $tok" } -Body $body -ContentType 'application/json' -TimeoutSec $to }
            }
        }
        foreach ($a in @($answers)) { if ($a -is [hashtable]) { foreach ($k in @($a.Keys)) { $instByGroup[$k] = @($a[$k]) } } }
    }
    foreach ($name in $withId) {
        if ($instByGroup.ContainsKey($name)) { continue }   # answered by a batch (status 200, a value list, no next link -- anything else is read again here)
        # 100.122 F1: a failed or partial read is NOT "nobody is active" -- the group's answer is then not complete
        try {
            $items = @(& $Graph "/identityGovernance/privilegedAccess/group/assignmentScheduleInstances?`$filter=groupId eq '$($ev[$name].readId)' and accessId eq 'member'")
            if (Test-PimHybridAdPartialItems -Items $items) {
                & $doubt $name 'instances-partial' 'the read came back partial (a next link that was not followed)'
                $items = @($items | Where-Object { $null -ne $_ -and $_.PSObject.Properties['principalId'] })
            }
            $instByGroup[$name] = $items
        } catch { $instByGroup[$name] = @(); & $doubt $name 'instances-failed' "$($_.Exception.Message)" }
    }

    # (3) principals
    $newIds = @($instByGroup.Values | ForEach-Object { @($_) } | Where-Object { $null -ne $_ } | ForEach-Object { "$($_.principalId)" } | Where-Object { $_ -and -not $userCache.ContainsKey($_) } | Select-Object -Unique)
    if ($GraphPost -and $newIds.Count -gt 20) {
        for ($c = 0; $c -lt $newIds.Count; $c += 1000) {
            $ids = @($newIds[$c..([Math]::Min($c + 1000, $newIds.Count) - 1)])
            try {
                $r = & $GraphPost '/directoryObjects/getByIds' @{ ids = $ids; types = @('user', 'group') }
                # only what the answer CARRIES is kept: an id it left out is read on its own below (never "not a user")
                foreach ($o in @($r.value)) {
                    if ($null -eq $o -or -not "$($o.id)".Trim()) { continue }
                    if ("$($o.'@odata.type')" -eq '#microsoft.graph.user') { if ($o.PSObject.Properties['mailNickname']) { $userCache["$($o.id)"] = $o } }
                    elseif ("$($o.'@odata.type')") { $userCache["$($o.id)"] = $null }
                }
            } catch { Write-Warning "[hybrid-ad] bulk principal read failed, reading them one by one: $($_.Exception.Message)" }
        }
    }
    foreach ($name in $names) {
        $out[$name] = @()
        if (-not $instByGroup.ContainsKey($name)) { continue }   # nothing was read for it (no id, gone, renamed)
        $e = $ev[$name]
        $list = New-Object System.Collections.Generic.List[object]
        foreach ($i in @($instByGroup[$name])) {
            if ($null -eq $i) { & $doubt $name 'instances-partial' 'the list of active assignments carries an empty item'; continue }   # B5
            $principal = "$($i.principalId)".Trim()
            if (-not $principal) { & $doubt $name 'instances-partial' 'an active assignment came back without its principal id'; continue }
            if (-not $userCache.ContainsKey($principal)) {
                # 100.122 F1 (case 1, B2): a principal that could not be READ is not "not active", and the failure is NOT
                # cached. It is COUNTED for the group (principalFailed, or principalNotFound for a 404 the deleted items do
                # not explain): the decision then makes no unexpected removal there -- this principal may be anybody.
                # (Until 2026-10-13: `catch { $u = $null }`, cached -- the person left the AD group while the activation ran.)
                $u = $null; $answered = $false
                # /directoryObjects, not /users: a nested GROUP principal is normal here, and /users answered it with a 404
                # that filled the worker log every pass (seen live 2026-09-29). The type decides -- a group has a mailNickname too.
                try {
                    $u = @(& $Graph "/directoryObjects/$($principal)?`$select=id,mailNickname,userPrincipalName")[0]
                    if ($null -ne $u) { $answered = $true } else { $e.pfail++; if (-not $e.detail) { $e.detail = "the read of principal $principal gave nothing" } }
                } catch {
                    $pmsg = "$($_.Exception.Message)"
                    if (Test-PimHybridAdNotFound -Message $pmsg) {
                        # the id answers 404: an ANSWER only when the deleted items carry it (a deleted principal)
                        $inDel = $null
                        try { $dp = @(& $Graph "/directory/deletedItems/$($principal)?`$select=id")[0]; if ($dp -and "$($dp.id)".Trim() -eq $principal) { $inDel = $true } }
                        catch { if (Test-PimHybridAdNotFound -Message "$($_.Exception.Message)") { $inDel = $false } }
                        if ($inDel -eq $true) { $answered = $true; $u = $null }
                        elseif ($inDel -eq $false) { if (-not $e.pnf.Contains($principal)) { $e.pnf.Add($principal) } }   # not found anywhere: 3 passes over 30 minutes make it "no longer exists"
                        else { $e.pfail++ }
                    } else { $e.pfail++ }
                    if (-not $answered -and -not $e.detail) { $e.detail = $pmsg }
                }
                if (-not $answered) { continue }
                if ($u -and "$($u.'@odata.type')" -and "$($u.'@odata.type')" -ne '#microsoft.graph.user') { $u = $null }
                elseif ($u -and -not $u.PSObject.Properties['mailNickname']) { $e.pfail++; if (-not $e.detail) { $e.detail = "the read of principal $principal came back without its mail nickname" }; continue }
                $userCache[$principal] = $u
            }
            $u = $userCache[$principal]
            if (-not $u -or -not "$($u.mailNickname)".Trim()) { continue }   # an ANSWER: not a user (nested group) or deleted -- skipped, as in v1
            $end = $null
            try { $end = ConvertTo-PimHybridAdEndUtc -Value $i.endDateTime -AsUtc $endAsUtc }
            catch { & $doubt $name 'instances-partial' "an end time could not be read ('$($i.endDateTime)')"; continue }
            $list.Add([pscustomobject]@{ mailNickname = "$($u.mailNickname)"; endUtc = $end })
        }
        $out[$name] = $list.ToArray()
    }
    # the answer per group: FOUND + complete is the only one an unexpected removal may rest on
    foreach ($name in $names) {
        $e = $ev[$name]
        $state = $(if ($e.state -in @('found', 'gone', 'replaced', 'renamed')) { $e.state } else { 'unknown' })
        $why = $(if ($state -in @('found', 'replaced') -and -not $e.complete) { "$($e.rwhy)" } elseif ($state -eq 'found') { '' } else { "$($e.why)" })
        $Answer[$name] = @{ state = $state; complete = [bool]($state -in @('found', 'replaced') -and $e.complete); why = $why; detail = "$($e.detail)"
            id = $(if ($e.state -eq 'ambiguous' -and -not $KnownIds.ContainsKey($name)) { '' } else { "$($e.id)" }); altId = "$($e.altId)"; deleted = [bool]$e.deleted
            principalFailed = [int]$e.pfail; principalNotFound = @($e.pnf.ToArray()) }
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
        if (-not (Test-PimHybridAdFunction 'Get-PimDesiredRows')) { return @{ ok = $false; rows = @(); pattern = $pattern; reason = 'the engine core (Get-PimDesiredRows) is not loaded on this worker' } }
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
    param([datetime]$NowUtc = [datetime]::UtcNow, [switch]$WhatIf, [object[]]$Rows = $null, [hashtable]$Adapter, [scriptblock]$Graph, [object]$AdModulePresent = $null, [scriptblock]$SecretReader,
          # 2026-10-04 lanes: 'critical' = every mirrored group EXCEPT the per-server ones (while the server lane runs),
          # 'servers' = only the per-server groups, 'all' = everything (the original single loop).
          [ValidateSet('all', 'critical', 'servers')][string]$Lane = 'all',
          # $null = read the server lane's liveness stamp; tests pass it
          [object]$ServersLaneAlive = $null,
          # 100.122 F1 seams (tests): -Store = the sync memory's store (Get-PimHybridAdMemoryStore by default: the SQL store,
          # or none -- never a table in the process), -GraphPost / -BatchPost = the bulk-read and `$batch seams of the
          # reader, -Alert = { param($guardId, $title, $detail, $action, $count, $now) } returning $true when DELIVERED
          # (default: the guard-trip mechanism, Invoke-PimGuardTrip).
          [hashtable]$Store = $null, [scriptblock]$GraphPost = $null, [scriptblock]$BatchPost = $null, [scriptblock]$Alert = $null)
    $defs = Get-PimHybridAdMirroredDefinitions -Rows $Rows
    if (-not $defs.ok) { return [pscustomobject]@{ ran = $false; unimplemented = $true; detail = "unimplemented:hybrid-ad-sync -- $($defs.reason)"; whatIf = [bool]$WhatIf } }
    $jobName = if ($Lane -eq 'servers') { 'hybrid-ad-sync-servers' } else { 'hybrid-ad-sync' }
    $laneNote = ''
    if ($Lane -ne 'all') {
        $alive = $ServersLaneAlive
        if ($null -eq $alive) { $sa = Get-PimHybridSyncAlive -Lane 'hybrid-ad-sync-servers'; $alive = [bool]($sa -and ([datetime]::UtcNow - $sa.utc).TotalMinutes -le 15) }
        $sel = Select-PimHybridAdLaneGroups -Rows @($defs.rows) -Lane $Lane -ServerPattern (Get-PimHybridAdServerGroupName -Server '*') -ServersLaneAlive ([bool]$alive)
        $defs = @{ ok = $true; rows = @($sel.rows); pattern = $defs.pattern; reason = '' }
        $laneNote = " [$Lane lane$(if ($sel.note) { ": $($sel.note)" })]"
    }
    $n = @($defs.rows).Count
    if (-not $n) { return [pscustomobject]@{ ran = $true; groups = 0; whatIf = [bool]$WhatIf; detail = "hybrid-ad-sync: no defined group matches '$($defs.pattern)' -- nothing to sync" } }
    if (-not $Adapter) {
        $a = Resolve-PimHybridAdGroupAdapter -Job 'hybrid-ad-sync' -Count $n -Pattern $defs.pattern -Need 'need their active members synced to AD' -WhatIf:$WhatIf -AdModulePresent $AdModulePresent -SecretReader $SecretReader
        if ($a.refuse) { return $a.refuse }
        $Adapter = $a.adapter
    }
    # Which mirrored groups exist in AD. In the continuous loop this listing is kept for the refresh window (a group that
    # appears is seen within it, or at once after the delta runner created it -- it clears this cache), instead of listing
    # every mirrored group -- thousands of server groups -- on every 5-second pass of the critical lane.
    $life = [int]$script:PimHybridAdCacheSeconds
    $ck = "$($defs.pattern)"
    $ic = $script:PimHybridAdInAdCache
    if ($life -gt 0 -and $ic -and $ic.key -eq $ck -and ([datetime]::UtcNow - $ic.at).TotalSeconds -lt $life) { $inAd = $ic.map }
    else {
        $inAd = @{}; foreach ($g in @(& $Adapter.GetGroups $defs.pattern)) { if ($g) { $inAd["$($g.Name)".ToLowerInvariant()] = $true } }
        if ($life -gt 0) { $script:PimHybridAdInAdCache = @{ key = $ck; at = [datetime]::UtcNow; map = $inAd } }
    }
    $names = @($defs.rows | ForEach-Object { "$($_.GroupName)".Trim() } | Select-Object -Unique)
    $present = @($names | Where-Object { $inAd.ContainsKey($_.ToLowerInvariant()) })
    $missing = @($names | Where-Object { -not $inAd.ContainsKey($_.ToLowerInvariant()) })
    $missText = if ($missing.Count) { "; not yet in AD (hybrid-ad-groups creates them): $($missing.Count)" } else { '' }
    if (-not $present.Count) { return [pscustomobject]@{ ran = $true; groups = 0; whatIf = [bool]$WhatIf; detail = "$($jobName)$($laneNote): none of the $($names.Count) mirrored group(s) exist in AD yet$missText" } }
    # Graph: ids from ONE prefix listing, active members in parallel batches (settings HybridAdSyncBatchSize, default 50
    # groups per batch, and HybridAdSyncParallel, default 8 batches at once -- PowerShell 7).
    $bs = 50; [void][int]::TryParse("$(Get-PimHybridAdSetting -Name 'HybridAdSyncBatchSize' -Default '50')", [ref]$bs); if ($bs -lt 1) { $bs = 50 }
    $par = 8; [void][int]::TryParse("$(Get-PimHybridAdSetting -Name 'HybridAdSyncParallel' -Default '8')", [ref]$par); if ($par -lt 1) { $par = 1 }
    $prefix = (("$($defs.pattern)" -split '\*')[0]).Trim()
    # 100.122 F1: the sync memory (the Entra ids once seen, the last complete active list, who waits since when) -- from
    # the store. No store, or a store that cannot be read in a fresh process = "memory not readable" (B6): a warning, and
    # only a member whose activation Entra itself reports as ended is removed.
    if (-not $Store) { $Store = Get-PimHybridAdMemoryStore }
    $memRead = Read-PimHybridAdSyncMemory -Job $jobName -Store $Store -NowUtc $NowUtc
    $nowE = ConvertTo-PimHybridAdEpoch $NowUtc
    # B4: no pass of this job for longer than the window = every recorded end time is stale in this pass
    $memStale = [bool]($memRead.ok -and ([long]$memRead.lastPass -le 0 -or ($nowE - [long]$memRead.lastPass) -gt ((Get-PimHybridAdStaleMinutes) * 60)))
    $knownIds = @{}; foreach ($pn in $present) { $pm = $memRead.groups[$pn.ToLowerInvariant()]; if ($pm -is [hashtable] -and "$($pm.id)".Trim()) { $knownIds[$pn] = "$($pm.id)".Trim() } }
    $answer = @{}
    $gArgs = @{ GroupNames = $present; Prefix = $prefix; BatchSize = [Math]::Min(1000, $bs); Parallel = [Math]::Min(64, $par); KnownIds = $knownIds; Answer = $answer }
    if ($Graph) { $gArgs['Graph'] = $Graph }; if ($GraphPost) { $gArgs['GraphPost'] = $GraphPost }; if ($BatchPost) { $gArgs['BatchPost'] = $BatchPost }
    $active = Get-PimHybridAdActiveGroupMembers @gArgs
    # AD: the server lane reads every server group's members in ONE paged LDAP read (adapter GetMembersMany over the server
    # pattern); the critical lane reads its few groups one by one (member DNs cached either way).
    $liveMap = $null
    if ($Lane -eq 'servers' -and $Adapter.ContainsKey('GetMembersMany')) {
        try { $liveMap = & $Adapter.GetMembersMany (Get-PimHybridAdServerGroupName -Server '*') } catch { Write-Warning "[hybrid-ad] bulk member read failed, reading groups one by one: $($_.Exception.Message)"; $liveMap = $null }
    }
    $prot = @("$(Get-PimHybridAdSetting -Name 'HybridAdProtectedMembers' -Default '')" -split '[,;]' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    $r = Invoke-PimHybridAdMembershipSync -Groups $present -ActiveByGroup $active -Adapter $Adapter -Apply:(-not $WhatIf) -NowUtc $NowUtc -Protected $prot -LiveByGroup $liveMap -Answer $answer -Memory $memRead.groups -MemoryReadable ([bool]$memRead.ok) -MemoryStale $memStale -Decisions $memRead.decisions
    $heldRows = @($r.results | Where-Object { $_.status -eq 'held' })
    $groupRows = @($r.results | Where-Object { $_.op -eq 'entra' -and $_.status -ne 'note' })
    $guardNote = ''; $waitList = @()
    if ($memRead.ok) {
        if ($script:PimHybridAdMemoryDown -is [hashtable] -and $script:PimHybridAdMemoryDown.ContainsKey($jobName)) { $script:PimHybridAdMemoryDown.Remove($jobName) }
        # The memory for the next pass. A defined group that was not synced in this pass (not in AD yet) keeps what it had; a
        # group that is no longer defined in this lane is dropped -- the memory never outgrows the definitions.
        $nextAll = @{}
        foreach ($dn in $names) { $dk = $dn.ToLowerInvariant(); if ($r.memory[$dk] -is [hashtable]) { $nextAll[$dk] = $r.memory[$dk] } elseif ($memRead.groups[$dk] -is [hashtable]) { $nextAll[$dk] = $memRead.groups[$dk] } }
        try { $guardNote = Invoke-PimHybridAdGuardAlerts -Job $jobName -Groups $present -Memory $nextAll -Results $r.results -NowUtc $NowUtc -WhatIf:$WhatIf -Alert $Alert }
        catch { Write-Warning "[$jobName] the guard alert was not raised: $($_.Exception.Message)" }
        $waitList = @(Get-PimHybridAdWaitingList -Groups $present -Memory $nextAll -Results $r.results)
        $passJson = '{"v":1,"lc":' + ([long]([math]::Floor($nowE / 600)) * 600) + '}'   # the last pass, to 10 minutes: one small write per 10 minutes
        [void](Save-PimHybridAdSyncMemory -Job $jobName -Groups $nextAll -Stored $memRead.stored -Store $Store -WaitingJson (ConvertTo-PimHybridAdWaitingJson -List $waitList) -PassJson $passJson)
    } else {
        try { $guardNote = Invoke-PimHybridAdMemoryDownAlert -Job $jobName -Reason "$($memRead.reason)" -Held $heldRows.Count -NowUtc $NowUtc -WhatIf:$WhatIf -Alert $Alert }
        catch { Write-Warning "[$jobName] the guard alert was not raised: $($_.Exception.Message)" }
    }
    # the item lines: stable text only (a group's error text changes from pass to pass and would print every few seconds)
    Write-PimHybridAdItemLines -Job $jobName -Lines @($r.results | Where-Object { $_.status -ne 'member' } | ForEach-Object { "{0,-8} {1,-7} {2} / {3}  {4}" -f $_.status, $_.op, $_.group, $_.samAccountName, $_.reason })
    $c = { param($op) @($r.results | Where-Object { $_.op -eq $op -and ($_.status -eq 'done' -or $_.status -eq 'plan') }).Count }
    $failed = @($r.results | Where-Object { $_.status -eq 'failed' })
    $wi = if ($WhatIf) { ' (whatif)' } else { '' }
    $ttl = if ($r.pamEnabled) { 'on' } else { 'off -- the AD PAM feature is not enabled' }
    # A1: somebody kept, or a group that needs a look = a WARNING for the job (amber: not green, not failed)
    $warning = [bool]($r.warning -or -not $memRead.ok)
    $heldText = ''
    if ($warning -or $heldRows.Count -or $groupRows.Count) {
        $hc = { param($h) @($heldRows | Where-Object { $_.hold -eq $h }).Count }
        $gc = { param($s) @($groupRows | Where-Object { $_.status -eq $s }).Count }
        $bits = New-Object System.Collections.Generic.List[string]
        if ((& $hc 'confirm') -gt 0) { $bits.Add("waiting for a second pass to confirm: $(& $hc 'confirm')") }
        if ((& $hc 'not-known') -gt 0 -or (& $gc 'not-known') -gt 0) { $bits.Add("Entra group not confirmed: $(& $hc 'not-known') in $(& $gc 'not-known') group(s)") }
        if ((& $hc 'principal') -gt 0) { $bits.Add("an active member of the Entra group could not be read: $(& $hc 'principal')") }
        if ((& $hc 'replaced') -gt 0) { $bits.Add("kept until their recorded end time (Entra group replaced): $(& $hc 'replaced')") }
        if ((& $hc 'superadmin') -gt 0) { $bits.Add("waiting for a SuperAdmin: $(& $hc 'superadmin')") }
        if (-not $memRead.ok) { $bits.Add("the sync's own memory could not be read ($($memRead.reason)): $(& $hc 'memory') kept") }
        $heldText = "; $(if ($warning) { 'WARNING -- ' })NOT removed on a doubt: $($heldRows.Count) member(s)$(if ($bits.Count) { ' -- ' + ($bits.ToArray() -join ', ') })"
        if ($waitList.Count) {
            $heldText += "; groups waiting for a SuperAdmin: " + (@($waitList | Select-Object -First 10 | ForEach-Object { "$($_.group) ($($_.memberCount) member(s), $($_.kindText))" }) -join ', ') + $(if ($waitList.Count -gt 10) { " ... and $($waitList.Count - 10) more" } else { '' })
        }
        if ($guardNote) { $heldText += "; $guardNote" }
    }
    $detail = ("$($jobName)$($laneNote){0}: groups={1} add={2} readd={3} remove={4} kept={5} failed={6} (TTL membership: {7}){8}{9}" -f $wi, $present.Count, (& $c 'add'), (& $c 'readd'), (& $c 'remove'), @($r.results | Where-Object { $_.status -eq 'kept' }).Count, $failed.Count, $ttl, $missText, $heldText)
    if ($failed.Count) { throw ("$detail -- " + (@($failed | ForEach-Object { "$($_.group)/$($_.samAccountName) $($_.op): $($_.reason)" }) -join '; ')) }
    return [pscustomobject]@{ ran = $true; whatIf = [bool]$WhatIf; groups = $present.Count; groupNames = $present; missingGroups = $missing; pamEnabled = $r.pamEnabled; results = $r.results; detail = $detail
        # PIM 100.75 convention: warning = $true -> the run is recorded 'warning'. No warningSummary: a warning run is shown,
        # not mailed -- the mail is the guard alert after 30 minutes (Invoke-PimHybridAdGuardAlerts).
        warning = $warning; warningKind = $(if ($warning) { 'hybrid-ad-kept-on-doubt' } else { '' })
        held = $heldRows.Count; notKnownGroups = @($groupRows | Where-Object { $_.status -eq 'not-known' } | ForEach-Object { $_.group })
        waitingGroups = @($waitList | ForEach-Object { $_.group }); waiting = $waitList }
}

function Get-PimHybridAdWaitingList {
    <#
      PURE. The AD groups that wait for a SuperAdmin after this pass, each with the members that stay:
        gone        the Entra group is CONFIRMED gone (owner 2026-10-13, decision (13): "Wait for a SuperAdmin")
        never-seen  no Entra group of that name was ever seen, for 24 hours (B3)
        replaced    another Entra group carries the name now (A3) -- a SuperAdmin says whether it is the one
      Nothing removes these members automatically, also not after a wait.
    #>
    param([string[]]$Groups = @(), [hashtable]$Memory = @{}, [object[]]$Results = @())
    $iso = { param($e) if ([long]$e -le 0) { '' } else { (New-Object datetime 1970, 1, 1, 0, 0, 0, ([System.DateTimeKind]::Utc)).AddSeconds([long]$e).ToString('yyyy-MM-ddTHH:mm:ssZ', [cultureinfo]::InvariantCulture) } }
    $max = Get-PimHybridAdWaitingMaxMembers
    $list = New-Object System.Collections.Generic.List[object]
    $sorted = [string[]]@($Groups); [Array]::Sort($sorted, [System.StringComparer]::OrdinalIgnoreCase)
    foreach ($g in $sorted) {
        $m = $Memory[$g.ToLowerInvariant()]
        if ($m -isnot [hashtable]) { continue }
        $kind = ''
        if ([long]$m.xc -gt 0) { $kind = $(if ("$($m.id)") { 'gone' } else { 'never-seen' }) } elseif ("$($m.rid)") { $kind = 'replaced' }
        if (-not $kind) { continue }
        $mem = [string[]]@($Results | Where-Object { $_.group -eq $g -and $_.status -eq 'held' -and $_.hold -eq 'superadmin' } | ForEach-Object { "$($_.samAccountName)" } | Where-Object { $_ })
        [Array]::Sort($mem, [System.StringComparer]::OrdinalIgnoreCase)
        # a group that is gone / was never found and holds NOBODY has nothing for a person to decide: not listed, no alert
        if (-not $mem.Count -and $kind -ne 'replaced') { continue }
        $text = switch ($kind) { 'gone' { 'the Entra group is gone' } 'never-seen' { 'the Entra group was never found' } default { 'the Entra group was replaced by another group of the same name' } }
        $list.Add([pscustomobject][ordered]@{ group = $g; kind = $kind; kindText = $text; state = 'waiting-for-superadmin'; entraGroupId = "$($m.id)"; replacementGroupId = "$($m.rid)"
            sinceUtc = (& $iso $(if ($kind -eq 'replaced') { $m.rs } else { $m.xs })); confirmedUtc = (& $iso $m.xc); inDeletedItems = [bool]$m.xd
            memberCount = $mem.Count; members = @($mem | Select-Object -First $max) })
    }
    return $list.ToArray()
}
function ConvertTo-PimHybridAdWaitingJson {
    # the waiting list as the store value 'HybridAdSyncMemory.<job>.waiting': same content = same text (an unchanged pass writes nothing)
    param([object[]]$List = @())
    if (-not @($List).Count) { return (Get-PimHybridAdEmptyWaitingJson) }
    $rows = @(foreach ($x in @($List)) { [ordered]@{ group = $x.group; kind = $x.kind; state = $x.state; entraGroupId = $x.entraGroupId; replacementGroupId = $x.replacementGroupId; sinceUtc = $x.sinceUtc; confirmedUtc = $x.confirmedUtc; inDeletedItems = [bool]$x.inDeletedItems; memberCount = [int]$x.memberCount; members = @($x.members) } })
    return ([ordered]@{ v = 1; groups = @($rows) } | ConvertTo-Json -Depth 6 -Compress)
}
function Get-PimHybridAdWaitingGroups {
    <#
      B10 -- the READER of the waiting record: the AD groups that wait for a SuperAdmin, for a page (and for anything that
      wants to show the way out). One object per group: job; group; kind (gone | never-seen | replaced); entraGroupId;
      replacementGroupId; sinceUtc; confirmedUtc; inDeletedItems; memberCount; members. @() when nothing waits or there is
      no store. The ways out: restore the Entra group (it is found by its id again and the sync continues by itself), or
      a SuperAdmin's decision in 'HybridAdSyncMemory.<job>.decisions' (take the replacement group as the one, or remove
      named members) -- format and rules: DESIGN.md "HybridAdSyncMemory decisions record"; read by
      Read-PimHybridAdSyncMemory, applied by Get-PimHybridAdGuardedPlan. The sync never writes that record.
    #>
    param([string[]]$Job = @('hybrid-ad-sync', 'hybrid-ad-sync-servers'), [hashtable]$Store = $null)
    if (-not $Store) { $Store = Get-PimHybridAdMemoryStore }
    if (-not $Store) { return @() }
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($j in @($Job)) {
        $prefix = Get-PimHybridAdMemoryPrefix -Job $j
        $raw = $null; try { $raw = & $Store.LoadAll $prefix } catch { Write-Warning "[$j] the waiting record could not be read: $($_.Exception.Message)"; continue }
        if ($raw -isnot [hashtable] -or -not "$($raw["${prefix}waiting"])") { continue }
        try {
            $d = "$($raw["${prefix}waiting"])" | ConvertFrom-Json
            foreach ($x in @($d.groups)) {
                if ($null -eq $x) { continue }
                $out.Add([pscustomobject][ordered]@{ job = $j; group = "$($x.group)"; kind = "$($x.kind)"; entraGroupId = "$($x.entraGroupId)"; replacementGroupId = "$($x.replacementGroupId)"
                    sinceUtc = $x.sinceUtc; confirmedUtc = $x.confirmedUtc; inDeletedItems = [bool]$x.inDeletedItems; memberCount = [int]$x.memberCount; members = @($x.members) })
            }
        } catch { Write-Warning "[$j] the waiting record is not readable: $($_.Exception.Message)" }
    }
    return $out.ToArray()
}

function Get-PimHybridAdDefaultAlert {
    # The alert call: the existing guard-trip mechanism (state, audit, mail, telemetry). Returns $true when the alert was
    # DELIVERED -- mailed, or recorded with the customer's guard mail switched off (then the record is the delivery).
    # $null when the mechanism is not loaded in this process. The dedupe is this lane's own (per group), so every trip mails.
    if (-not (Test-PimHybridAdFunction 'Invoke-PimGuardTrip')) { return $null }
    return { param($guardId, $title, $detail, $action, $count, $at)
        $t = Invoke-PimGuardTrip -GuardId $guardId -Outcome held -Area 'hybrid-ad' -Job $Job -Title $title -Detail $detail -ActionText $action -HeldCount $count -NowUtc $at -MailDedupHours 0
        return [bool]($t -and ($t.mailed -or -not $t.mailDue)) }
}
function Invoke-PimHybridAdGuardAlerts {
    <#
      The alerts of 100.122 F1, through the guard-trip mechanism (-Alert = the seam: { param($guardId, $title, $detail,
      $action, $count, $at) } returning $true when DELIVERED):
        hybrid-ad.members-kept            A1: a group has kept members for Get-PimHybridAdHoldAlertMinutes (30) -- counted
                                          from the FIRST member kept in it, whatever happened in between -- again every 4
                                          hours until nobody is kept there
        hybrid-ad.waiting-for-superadmin  a group waits for a SuperAdmin (gone / never found / replaced): at once, then
                                          once a day
      "Alert sent" is STAMPED in -Memory (ha / wa) only when the call says it was delivered; a call that did not deliver is
      tried again after Get-PimHybridAdAlertRetryMinutes (ht). The caller saves -Memory. Every group is NAMED with the
      number of members it holds. Returns a short note for the job's detail line. -WhatIf = plan only: no alert, no stamp.
    #>
    param([Parameter(Mandatory)][string]$Job, [string[]]$Groups = @(), [hashtable]$Memory = @{}, [object[]]$Results = @(),
          [datetime]$NowUtc = [datetime]::UtcNow, [switch]$WhatIf, [scriptblock]$Alert = $null)
    if ($WhatIf) { return '' }
    $now = ConvertTo-PimHybridAdEpoch $NowUtc
    $retry = (Get-PimHybridAdAlertRetryMinutes) * 60
    $wait = New-Object System.Collections.Generic.List[string]; $kept = New-Object System.Collections.Generic.List[string]
    foreach ($g in @($Groups)) {
        $m = $Memory[$g.ToLowerInvariant()]; if ($m -isnot [hashtable]) { continue }
        if ([long]$m.ht -gt 0 -and ($now - [long]$m.ht) -lt $retry) { continue }
        if ([long]$m.xc -gt 0 -or "$($m.rid)") {
            # nobody waits in a gone / never-found group = nothing for a person to decide: no alert (the same rule as the waiting list)
            if (-not "$($m.rid)" -and -not @($Results | Where-Object { $_.status -eq 'held' -and $_.group -eq $g -and $_.hold -eq 'superadmin' }).Count) { continue }
            if ([long]$m.wa -le 0 -or ($now - [long]$m.wa) -ge ((Get-PimHybridAdWaitingAlertRepeatHours) * 3600)) { $wait.Add($g) }
        } elseif ([long]$m.hs -gt 0 -and ($now - [long]$m.hs) -ge ((Get-PimHybridAdHoldAlertMinutes) * 60)) {
            if ([long]$m.ha -le 0 -or ($now - [long]$m.ha) -ge ((Get-PimHybridAdHoldAlertRepeatHours) * 3600)) { $kept.Add($g) }
        }
    }
    if (-not $wait.Count -and -not $kept.Count) { return '' }
    if (-not $Alert) { $Alert = Get-PimHybridAdDefaultAlert }
    $heldIn = { param($g) @($Results | Where-Object { $_.status -eq 'held' -and $_.group -eq $g }).Count }
    $note = @()
    $send = { param($guardId, $names, $title, $lead, $todo, $stamp)
        $lines = @($names | Select-Object -First 50 | ForEach-Object {
            $gname = "$_"; $n = & $heldIn $gname
            $gwhy = "$(@($Results | Where-Object { $_.op -eq 'entra' -and $_.status -ne 'note' -and $_.group -eq $gname } | Select-Object -First 1 | ForEach-Object { $_.reason }))"
            "$gname -- $n member(s) kept$(if ($gwhy) { ": $gwhy" })" })
        $text = $lead + ($lines -join '; ') + $(if (@($names).Count -gt 50) { " ... and $(@($names).Count - 50) more" } else { '' })
        $count = 0; foreach ($g in $names) { $count += (& $heldIn $g) }
        $delivered = $false
        if ($Alert) { try { $delivered = [bool](& $Alert $guardId $title $text $todo $count $NowUtc) } catch { $delivered = $false; Write-Warning "[$Job] the alert '$guardId' failed: $($_.Exception.Message)" } }
        else { Write-PimHybridAdItemLines -Job "$Job-guard" -Lines @("the alert '$guardId' could not be raised: the guard-trip mechanism is not loaded in this process") }
        foreach ($g in $names) { $m = $Memory[$g.ToLowerInvariant()]; if ($delivered) { $m[$stamp] = $now; $m.ht = [long]0 } else { $m.ht = $now } }
        return $delivered
    }
    if ($wait.Count) {
        $names = @($wait.ToArray())
        $ok = & $send 'hybrid-ad.waiting-for-superadmin' $names "$($names.Count) Active Directory group(s) wait for a SuperAdmin: the Entra group behind them is gone, was never found or was replaced" `
            'The members of these Active Directory groups were NOT removed and stay until a SuperAdmin decides: ' `
            'Restore the Entra group from the deleted items if it was deleted by mistake -- the sync then continues by itself. If the group is meant to be gone, or another group took its name, a SuperAdmin decides about the members that remain.' 'wa'
        $note += "alert $(if ($ok) { 'sent' } else { 'NOT delivered (tried again in ' + (Get-PimHybridAdAlertRetryMinutes) + ' minutes)' }): $($names.Count) group(s) waiting for a SuperAdmin"
    }
    if ($kept.Count) {
        $names = @($kept.ToArray())
        $ok = & $send 'hybrid-ad.members-kept' $names "Members were kept in $($names.Count) Active Directory group(s) for more than $(Get-PimHybridAdHoldAlertMinutes) minutes because Entra ID could not confirm them" `
            'Access that may have ended is still in place in these Active Directory groups -- nobody is removed on a doubt: ' `
            'Check that the Entra group exists under its defined name and that the hybrid worker can read it and its members. When Entra ID answers again the sync continues by itself; nothing has to be approved.' 'ha'
        $note += "alert $(if ($ok) { 'sent' } else { 'NOT delivered (tried again in ' + (Get-PimHybridAdAlertRetryMinutes) + ' minutes)' }): $($names.Count) group(s) have kept members for more than $(Get-PimHybridAdHoldAlertMinutes) minutes"
    }
    return ($note -join '; ')
}
function Invoke-PimHybridAdMemoryDownAlert {
    # B6: the sync memory cannot be read (or this process has no store). The clock is kept in THIS process -- there is no
    # store to keep it in: an alert after 30 minutes, again every 4 hours, stamped only when delivered.
    param([Parameter(Mandatory)][string]$Job, [string]$Reason = '', [int]$Held = 0, [datetime]$NowUtc = [datetime]::UtcNow, [switch]$WhatIf, [scriptblock]$Alert = $null)
    $now = ConvertTo-PimHybridAdEpoch $NowUtc
    if ($script:PimHybridAdMemoryDown -isnot [hashtable]) { $script:PimHybridAdMemoryDown = @{} }
    if ($script:PimHybridAdMemoryDown[$Job] -isnot [hashtable]) { $script:PimHybridAdMemoryDown[$Job] = @{ since = $now; sent = [long]0; tried = [long]0 } }
    $s = $script:PimHybridAdMemoryDown[$Job]
    if ($WhatIf) { return '' }
    if (($now - [long]$s.since) -lt ((Get-PimHybridAdHoldAlertMinutes) * 60)) { return '' }
    if ([long]$s.sent -gt 0 -and ($now - [long]$s.sent) -lt ((Get-PimHybridAdHoldAlertRepeatHours) * 3600)) { return '' }
    if ([long]$s.tried -gt 0 -and ($now - [long]$s.tried) -lt ((Get-PimHybridAdAlertRetryMinutes) * 60)) { return '' }
    if (-not $Alert) { $Alert = Get-PimHybridAdDefaultAlert }
    $delivered = $false
    if ($Alert) {
        try { $delivered = [bool](& $Alert 'hybrid-ad.members-kept' "The hybrid AD sync ($Job) cannot read its own memory for more than $(Get-PimHybridAdHoldAlertMinutes) minutes" `
            "Since $(Format-PimHybridAdEpoch ([long]$s.since)): $Reason. $Held member(s) without an active assignment are kept; only a member whose activation Entra ID itself reports as ended is removed." `
            'Check that the hybrid worker can reach the PIM Manager database. When it can, the sync continues by itself; nothing has to be approved.' $Held $NowUtc) }
        catch { $delivered = $false }
    }
    if ($delivered) { $s.sent = $now; $s.tried = [long]0 } else { $s.tried = $now }
    return "alert $(if ($delivered) { 'sent' } else { 'NOT delivered' }): the sync's own memory cannot be read"
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
        # 100.122 F1: the group's own line first -- why nobody is removed from it in this pass
        foreach ($x in @($items | Where-Object { $_.op -eq 'entra' })) { & $add "  PIM for AD: $($x.reason)" $(if ("$($x.status)" -eq 'note') { 'info' } else { 'bad' }) }
        if (-not @($items | Where-Object { $_.status -ne 'kept' -and $_.status -ne 'held' -and $_.op -ne 'entra' }).Count) { & $add '  no active PIM member' 'dim' }
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
                    elseif ($x.status -eq 'held') { & $add "  PIM for AD: $u stays in $g -- $($x.reason)" $(if ("$($x.hold)" -eq 'confirm') { 'info' } else { 'bad' }) }
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
                    else { & $add "${pfx}Removing user $u from group $g ($(if ("$($x.reason)".Trim()) { "$($x.reason)" } else { 'no active PIM assignment' }))" 'change' }
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
    if (-not $cs -and (Test-PimHybridAdFunction 'Get-PimSqlConnectionString')) { try { $cs = "$(Get-PimSqlConnectionString)".Trim() } catch { $cs = '' } }
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
            if (-not $cs -or -not (Test-PimHybridAdFunction 'Get-PimSqlSetting')) { return $false }
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
        # MaxMinutes 0 = NO runtime limit (operator 2026-10-04: "in the old world it ran for 1 hr, then it restarted the job.
        # but it is not how we should do it today"). It was 720: the loop ended every 12 h and the task started a new one.
        # The loop now ends only on a new version (-StopWhen), a hang (the watchdog) or -MaxIterations (tests).
        [int]$PauseSeconds = 5, [int]$RefreshSeconds = 300, [int]$RecordEverySeconds = 300, [int]$MaxMinutes = 0,
        [int]$MaxIterations = 0, [switch]$WhatIf,
        # 2026-10-04 lanes: which continuous loop this is -- hybrid-ad-sync (critical groups), hybrid-ad-sync-servers (the
        # per-server groups) or hybrid-ad-changes (AD accounts + AD groups on change). Names the job, its run records, its
        # heartbeat and its liveness stamp. The defaults below read it (dynamic scope: they run inside this function).
        [ValidateSet('hybrid-ad-sync', 'hybrid-ad-sync-servers', 'hybrid-ad-changes')][string]$JobName = 'hybrid-ad-sync',
        [scriptblock]$StopWhen = { $false },
        [scriptblock]$Pass = { param($now, $whatIf) Invoke-PimScheduledJob -Job ([pscustomobject]@{ name = $JobName; type = $JobName }) -NowUtc $now -WhatIf:$whatIf },
        [scriptblock]$Record = { param($res, $started) if (Test-PimHybridAdFunction 'Write-PimJobRunRecord') { Write-PimJobRunRecord -Job ([pscustomobject]@{ name = $JobName; type = $JobName }) -Result $res -StartedUtc $started -RunId ([guid]::NewGuid().ToString('N')) | Out-Null } },
        [scriptblock]$Heartbeat = { if (Test-PimHybridAdFunction 'Save-PimHybridWorkerHeartbeat') { Save-PimHybridWorkerHeartbeat -Scope @($JobName) -PlanOnly:([bool]$WhatIf) } },   # $WhatIf: the loop's own parameter (dynamic scope)
        [scriptblock]$Sleep = { param($s) Start-Sleep -Seconds $s },
        [scriptblock]$Clock = { [datetime]::UtcNow },
        # 2.4.465: the Manager's LIVE view (written only while somebody watches -- Publish-PimHybridAdSyncLive)
        [scriptblock]$Live = { param($res, $now) if ($JobName -eq 'hybrid-ad-sync') { [void](Publish-PimHybridAdSyncLive -Result $res -NowUtc $now -PauseSeconds $PauseSeconds) } },
        # 🔴 SELF-HEALING (operator 2026-10-02: "it must be running 24x7x365"). A pass that never returns (a REST/LDAP/SQL call
        # waiting forever) froze the loop for 22 h while the task said "Running". -StallMinutes: when no iteration completes for
        # that long, the in-process watchdog KILLS this process and the task's 1-minute trigger starts a fresh loop. 0 = off.
        # -Alive is called once per iteration: it feeds the watchdog and stamps the liveness file the 5-minute tick checks
        # (Invoke-PimHybridSyncWatchdogCheck -- the second, external layer).
        [int]$StallMinutes = 10,
        [scriptblock]$Alive = { param($now) Set-PimHybridSyncAlive -NowUtc $now -Lane $JobName }
    )
    $script:PimHybridAdCacheSeconds = [math]::Max(0, $RefreshSeconds)
    $start = & $Clock; $lastRecord = [datetime]::MinValue; $lastBeat = [datetime]::MinValue
    $passes = 0; $recorded = 0; $failures = 0; $stop = ''; $wasWarn = $false
    if ($StallMinutes -gt 0) { try { Start-PimHybridSyncWatchdog -StallMinutes $StallMinutes } catch { Write-Warning "[$JobName] watchdog not started: $($_.Exception.Message)" } }
    try {
    while ($true) {
        $now = & $Clock
        try { & $Alive $now } catch { }
        if (($now - $lastBeat).TotalSeconds -ge $RecordEverySeconds) { try { & $Heartbeat } catch { }; $lastBeat = $now }
        $res = $null; $threw = $false
        try { $res = & $Pass $now ([bool]$WhatIf) }
        catch { $threw = $true; $res = [pscustomobject]@{ name = $JobName; type = $JobName; ok = $false; ran = $true; detail = "$JobName pass failed: $($_.Exception.Message)" } }
        $passes++
        try { & $Live $res $now } catch { }
        $inner = if ($res -and $res.PSObject.Properties['result']) { $res.result } else { $null }
        $acted = $inner -and $inner.PSObject.Properties['results'] -and @($inner.results | Where-Object { $_.status -eq 'done' -or $_.status -eq 'failed' }).Count -gt 0
        $bad = $threw -or ($res -and $res.PSObject.Properties['ok'] -and -not $res.ok)
        if ($bad) { $failures++ }
        # 100.122 F1 (A1): a pass that turns to WARNING (somebody kept on a doubt) -- or back -- is recorded AT ONCE, not at
        # the next 5-minute record: a doubt must be visible when it starts
        $warn = [bool]($inner -and $inner.PSObject.Properties['warning'] -and $inner.warning)
        $turned = ($warn -ne $wasWarn); $wasWarn = $warn
        if ($acted -or $bad -or $turned -or ($now - $lastRecord).TotalSeconds -ge $RecordEverySeconds) {
            try { & $Record $res $now; $recorded++ } catch { Write-Warning "[$JobName] run record not written: $($_.Exception.Message)" }
            $lastRecord = $now
            if ($res) { Write-Host ("[$JobName] {0:HH:mm:ss} {1}" -f $now, "$($res.detail)") }
        }
        if ($MaxIterations -gt 0 -and $passes -ge $MaxIterations) { $stop = "max iterations ($MaxIterations)"; break }
        if ($MaxMinutes -gt 0 -and ((& $Clock) - $start).TotalMinutes -ge $MaxMinutes) { $stop = "max runtime ($MaxMinutes min) -- the task restarts it"; break }
        $why = $null; try { $why = & $StopWhen } catch { $why = $null }
        if ($why) { $stop = "$why"; break }
        # a failing pass backs off (DC or Graph down must not become a tight error loop); a healthy one pauses -PauseSeconds
        & $Sleep $(if ($bad) { [math]::Min(60, $PauseSeconds * 6) } else { $PauseSeconds })
    }
    } finally { if ($StallMinutes -gt 0) { Stop-PimHybridSyncWatchdog } }
    Write-Host "[$JobName] loop stopped after $passes pass(es): $stop"
    return [pscustomobject]@{ passes = $passes; recorded = $recorded; failures = $failures; stopReason = $stop }
}

# ---- DELTA: AD accounts + AD groups run the moment their definitions change (operator 2026-10-04) --------------------------
# v1 ran "AD accounts (change detected)" and "AD groups for AD services (change detected)" in VisualCron -- a change reached
# AD at once. v2 had them on a 60-minute cadence. Now the continuous sync process reads ONE cheap change stamp per pass
# (count + checksum of the AD admin rows, of the group definitions, and of the hybrid / naming settings) and, when it moved,
# runs hybrid-ad-apply and/or hybrid-ad-groups right there. The 60-minute cadence stays as the safety net only. Both paths
# take the same machine-wide lock, so a delta run and the timed run never write AD at the same time.
$script:PimHybridAdAdminEntities = @('Account-Definitions-Admins', 'Account-Definitions-Admins-Central')
$script:PimHybridAdDeltaState = @{ stamp = $null }

function Get-PimHybridAdChangeStamp {
    <#
      One read: @{ ok; admins; groups; settings; error }. Each part is "<rows>:<checksum>" -- an add, a delete or an edit of
      any row moves it. -Query { param($sql, $params) -> first row } is the seam for tests; the default reads the desired
      store (Get-PimSqlConnectionString). A failed read is ok=$false -- the caller then runs nothing on it (never a guess).
    #>
    param([scriptblock]$Query = $null)
    $ae = @($script:PimHybridAdAdminEntities); $ge = @($script:PimHybridAdGroupEntities)
    $p = @{}; $an = @(); $gn = @()
    for ($i = 0; $i -lt $ae.Count; $i++) { $p["a$i"] = $ae[$i]; $an += "@a$i" }
    for ($i = 0; $i -lt $ge.Count; $i++) { $p["g$i"] = $ge[$i]; $gn += "@g$i" }
    $sql = "SELECT " +
        "(SELECT CONCAT(COUNT(*), ':', ISNULL(CHECKSUM_AGG(CHECKSUM([Key], DataJson)), 0)) FROM pim.Rows WHERE Entity IN ($($an -join ', '))) AS admins, " +
        "(SELECT CONCAT(COUNT(*), ':', ISNULL(CHECKSUM_AGG(CHECKSUM([Key], DataJson)), 0)) FROM pim.Rows WHERE Entity IN ($($gn -join ', '))) AS groups, " +
        "(SELECT CONCAT(COUNT(*), ':', ISNULL(CHECKSUM_AGG(CHECKSUM(Name, ValueJson)), 0)) FROM pim.Settings WHERE Name LIKE 'HybridAd%' OR Name IN ('NamingConventions', 'FeatureGates')) AS settings"
    if (-not $Query) {
        $Query = {
            param($q, $prm)
            $cs = Get-PimSqlConnectionString
            if (-not "$cs".Trim()) { throw 'no connection string for the desired store' }
            @(Invoke-PimSqlQuery -ConnectionString $cs -Sql $q -Parameters $prm)[0]
        }
    }
    try {
        $r = & $Query $sql $p
        if ($null -eq $r) { return @{ ok = $false; admins = ''; groups = ''; settings = ''; error = 'the change check returned nothing' } }
        $g = { param($o, $n) if ($o -is [System.Collections.IDictionary]) { "$($o[$n])" } else { "$($o.$n)" } }
        return @{ ok = $true; admins = (& $g $r 'admins'); groups = (& $g $r 'groups'); settings = (& $g $r 'settings'); error = '' }
    } catch { return @{ ok = $false; admins = ''; groups = ''; settings = ''; error = "$($_.Exception.Message)" } }
}

function Get-PimHybridAdDeltaDue {
    <#
      PURE. Which jobs a stamp change asks for: @{ admins; groups; reason }. No previous stamp (the process just started) =
      both, so whatever changed while it was down is caught up at once. A settings change (OUs, naming, marker, gates) = both.
    #>
    param([AllowNull()][hashtable]$Previous, [Parameter(Mandatory)][hashtable]$Current)
    if (-not $Current.ok) { return @{ admins = $false; groups = $false; reason = "change check failed: $($Current.error)" } }
    if (-not $Previous -or -not $Previous.ok) { return @{ admins = $true; groups = $true; reason = 'first check since start' } }
    $s = ($Previous.settings -ne $Current.settings)
    $a = $s -or ($Previous.admins -ne $Current.admins)
    $g = $s -or ($Previous.groups -ne $Current.groups)
    $why = @(); if ($Previous.admins -ne $Current.admins) { $why += 'admin definitions' }; if ($Previous.groups -ne $Current.groups) { $why += 'group definitions' }; if ($s) { $why += 'hybrid / naming settings' }
    return @{ admins = $a; groups = $g; reason = $(if ($why.Count) { "changed: $($why -join ', ')" } else { '' }) }
}

function Invoke-PimHybridAdWriteLocked {
    <#
      Run -Action under the machine-wide AD-write lock ('Global\PimHybridAdWrite'). The timed hybrid tick and the delta runner
      both write AD (create users / groups); without the lock the two could create the same object at the same moment and
      one would report a false failure. Waits up to -WaitSeconds, then runs anyway with a warning (never blocks the work).
    #>
    param([Parameter(Mandatory)][scriptblock]$Action, [int]$WaitSeconds = 600)
    $m = $null; $owned = $false
    try { $m = New-Object System.Threading.Mutex($false, 'Global\PimHybridAdWrite') } catch { $m = $null }
    try {
        if ($m) {
            try { $owned = $m.WaitOne([TimeSpan]::FromSeconds($WaitSeconds)) } catch [System.Threading.AbandonedMutexException] { $owned = $true }
            if (-not $owned) { Write-Warning "[hybrid-ad] the AD-write lock was not free after $WaitSeconds s -- running anyway" }
        }
        & $Action
    } finally { if ($m) { if ($owned) { try { $m.ReleaseMutex() } catch { } }; $m.Dispose() } }
}

function Invoke-PimHybridAdDeltaPass {
    <#
      One delta check (called every pass of the continuous loop). Reads the change stamp; when it moved, clears the cached
      definitions and runs hybrid-ad-groups and/or hybrid-ad-apply AT ONCE through the normal job path (licence + feature
      gates still decide), records each run, and logs it. The stamp is taken BEFORE the run, so a change made during the run
      is seen on the next pass. A failed run is not retried here every 5 s -- the timed safety net retries it.
      Returns @{ ran = @(types); reason }.
    #>
    param([hashtable]$State = $script:PimHybridAdDeltaState, [datetime]$NowUtc = [datetime]::UtcNow, [switch]$WhatIf,
          [scriptblock]$Stamp = { Get-PimHybridAdChangeStamp },
          [scriptblock]$RunJob = { param($type, $now, $whatIf) Invoke-PimScheduledJob -Job ([pscustomobject]@{ name = $type; type = $type }) -NowUtc $now -WhatIf:$whatIf },
          [scriptblock]$Record = { param($type, $res, $started) if (Test-PimHybridAdFunction 'Write-PimJobRunRecord') { Write-PimJobRunRecord -Job ([pscustomobject]@{ name = $type; type = $type }) -Result $res -StartedUtc $started -RunId ([guid]::NewGuid().ToString('N')) | Out-Null } })
    $cur = & $Stamp
    if (-not $cur.ok) { return @{ ran = @(); reason = "change check failed: $($cur.error)" } }   # keep the old stamp: retried next pass
    $due = Get-PimHybridAdDeltaDue -Previous $State.stamp -Current $cur
    $State.stamp = $cur
    $types = @(); if ($due.groups) { $types += 'hybrid-ad-groups' }; if ($due.admins) { $types += 'hybrid-ad-apply' }
    foreach ($t in $types) {
        $script:PimHybridAdDefsCache = $null   # the new definitions, not the 5-minute cache
        $res = $null
        try { $res = Invoke-PimHybridAdWriteLocked -Action { & $RunJob $t $NowUtc ([bool]$WhatIf) } }
        catch { $res = [pscustomobject]@{ name = $t; type = $t; ok = $false; ran = $true; detail = "$t (change detected) failed: $($_.Exception.Message)" } }
        try { & $Record $t $res $NowUtc } catch { Write-Warning "[hybrid-ad-delta] run record for $t not written: $($_.Exception.Message)" }
        Write-Host ("[hybrid-ad-delta] {0:HH:mm:ss} {1} (change detected -- {2}): {3}" -f $NowUtc, $t, $due.reason, "$(if ($res) { $res.detail })")
    }
    return @{ ran = $types; reason = $due.reason }
}

function Invoke-PimHybridAdChangesJob {
    <#
      The 'hybrid-ad-changes' job = one pass of the CHANGES lane (its own continuous loop, its own process): the change check,
      and -- when the AD admin rows, the AD group definitions or the hybrid / naming settings moved -- hybrid-ad-groups and/or
      hybrid-ad-apply at once. Returns the job-result shape the loop records: results[] carries one 'done' / 'failed' item
      per job it ran, so the loop records the pass that acted (and otherwise every 5 minutes).
    #>
    param([datetime]$NowUtc = [datetime]::UtcNow, [switch]$WhatIf)
    $d = Invoke-PimHybridAdDeltaPass -NowUtc $NowUtc -WhatIf:$WhatIf
    $items = @(foreach ($t in @($d.ran)) { [pscustomobject]@{ status = 'done'; op = 'run'; name = $t } })
    $detail = if (@($d.ran).Count) { "hybrid-ad-changes: ran $(@($d.ran) -join ' + ') ($($d.reason))" } elseif ("$($d.reason)" -match '^change check failed') { "hybrid-ad-changes: $($d.reason)" } else { 'hybrid-ad-changes: no change' }
    return [pscustomobject]@{ ran = $true; whatIf = [bool]$WhatIf; results = $items; detail = $detail; ok = -not ("$($d.reason)" -match '^change check failed') }
}

# ---- self-healing of the continuous sync (operator 2026-10-02: "it must be running 24x7x365") -----------------------------
# Layer 1 (in-process): a .NET timer THREAD -- not a PowerShell event, which never fires while the pipeline is blocked in a
#   call -- that kills this process when no loop iteration completed for -StallMinutes. The task restarts the loop in <= 1 min.
# Layer 2 (external, Invoke-PimHybridSyncWatchdogCheck): the 5-minute hybrid tick reads the liveness file and kills a sync
#   process whose stamp is stale -- for the case where layer 1 itself is wedged.
# Lanes (operator 2026-10-04: critical groups such as Domain Admins must reach AD within 20-30 s even with 10,000 servers):
# each continuous loop is its own process with its own liveness stamp, so the watchdog judges -- and kills -- only that one.
#   hybrid-ad-sync           critical (non-server) AD groups; the file name of the original single loop is kept
#   hybrid-ad-sync-servers   the per-server groups ({prefix}AD-SRV-{server}...), parallel batches
#   hybrid-ad-changes        AD accounts + AD groups the moment their definitions change (delta)
$script:PimHybridAdLanes = @('hybrid-ad-sync', 'hybrid-ad-sync-servers', 'hybrid-ad-changes')
function Get-PimHybridSyncAlivePath {
    param([string]$Lane = 'hybrid-ad-sync')
    $l = if ("$Lane".Trim()) { "$Lane".Trim().ToLowerInvariant() } else { 'hybrid-ad-sync' }
    if ("$env:PIM_HybridSyncAliveFile".Trim()) { $f = "$env:PIM_HybridSyncAliveFile".Trim(); return $(if ($l -eq 'hybrid-ad-sync') { $f } else { "$f.$l" }) }
    $base = if ($env:ProgramData) { $env:ProgramData } else { [IO.Path]::GetTempPath() }
    return (Join-Path $base "PIM4EntraPS\$l.alive")
}
function Set-PimHybridSyncAlive {
    param([datetime]$NowUtc = [datetime]::UtcNow, [string]$Lane = 'hybrid-ad-sync')
    if ('PimHybridSyncWatchdog' -as [type]) { [PimHybridSyncWatchdog]::Beat() }
    $p = Get-PimHybridSyncAlivePath -Lane $Lane
    $d = Split-Path $p -Parent
    if (-not (Test-Path -LiteralPath $d)) { New-Item -ItemType Directory -Force -Path $d | Out-Null }
    [IO.File]::WriteAllText($p, ("{0}|{1}" -f $NowUtc.ToUniversalTime().ToString('o'), $PID))
}
function Get-PimHybridSyncAlive {
    # -> @{ utc; pid } or $null (no file / unreadable)
    param([string]$Lane = 'hybrid-ad-sync')
    $p = Get-PimHybridSyncAlivePath -Lane $Lane
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
    param([int]$StaleMinutes = 15, [datetime]$NowUtc = [datetime]::UtcNow, [string]$Lane = 'hybrid-ad-sync',
        [scriptblock]$GetProcess = { param($procId) Get-CimInstance Win32_Process -Filter "ProcessId=$procId" -ErrorAction SilentlyContinue },
        [scriptblock]$Kill = { param($procId) Stop-Process -Id $procId -Force -ErrorAction Stop })
    $a = Get-PimHybridSyncAlive -Lane $Lane
    if (-not $a) { return [pscustomobject]@{ action = 'none'; detail = 'no liveness stamp yet' } }
    $age = ($NowUtc.ToUniversalTime() - $a.utc).TotalMinutes
    if ($age -le $StaleMinutes) { return [pscustomobject]@{ action = 'ok'; detail = ("$Lane loop alive ({0:N1} min ago, pid {1})" -f $age, $a.pid) } }
    if ($a.pid -le 0) { return [pscustomobject]@{ action = 'none'; detail = 'stale stamp without a pid' } }
    $p = & $GetProcess $a.pid
    if (-not $p) { return [pscustomobject]@{ action = 'gone'; detail = ("stale stamp ({0:N0} min) and pid {1} is gone -- the task starts a new loop" -f $age, $a.pid) } }
    if ("$($p.CommandLine)" -notmatch 'Mode (Sync[A-Za-z]*|Changes)|ContinuousJob') { return [pscustomobject]@{ action = 'none'; detail = "pid $($a.pid) is not the sync loop (reused pid) -- left alone" } }
    & $Kill $a.pid
    return [pscustomobject]@{ action = 'killed'; detail = ("$Lane loop pid {0} made no progress for {1:N0} min -- killed; the task restarts it within a minute" -f $a.pid, $age) }
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
    if (Test-PimHybridAdFunction 'Get-PimGroupNamePrefix') { try { $prefix = "$(Get-PimGroupNamePrefix)".Trim() } catch { $prefix = '' } }
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
    if (-not (Test-PimHybridAdDirectoryAvailable)) { throw 'This host is not joined to an Active Directory domain -- the server adapter is hybrid-worker-only.' }
    return @{
        GetComputers = {
            $s = Get-PimHybridAdServerSplat
            @(Get-PimHybridAdLdapComputers @s)
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
    if (-not $Netbios) { try { $nbs = Get-PimHybridAdServerSplat; $Netbios = "$(Get-PimHybridAdLdapNetbiosName @nbs)" } catch { $Netbios = '' } }
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
            if (-not (Test-PimHybridAdFunction 'Set-PimSqlTenantCache')) { throw 'Set-PimSqlTenantCache is not loaded' }
            $cs = "$($global:PIM_SqlConnectionString)".Trim()
            if (-not $cs -and (Test-PimHybridAdFunction 'Get-PimSqlConnectionString')) { $cs = "$(Get-PimSqlConnectionString)".Trim() }
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
