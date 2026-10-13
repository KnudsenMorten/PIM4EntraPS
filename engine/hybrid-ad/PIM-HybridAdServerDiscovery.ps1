<#
  PIM-HybridAdServerDiscovery.ps1 -- PIM 100.123 (d) + owner decision (12), 2026-10-13 (lane adclean).

  (d) THE CUSTOMER SETS HOW SERVERS ARE DISCOVERED. Until now the 'hybrid-ad-servers' job searched the whole domain for
      enabled Windows Server computers that are not domain controllers and whose AD object CHANGED within 90 days; none of
      it was a setting. Now, in Settings > Hybrid Active Directory (each its own settings row, read by the worker):
        HybridAdServerSearchOus          only these OUs (several; sub-OUs included). Blank = the whole domain.
        HybridAdServerExcludeOus         OUs to leave out (several; sub-OUs included).
        HybridAdServerActiveDays         "last seen" = the computer object last CHANGED within N days (default 90).
        HybridAdServerNameInclude        only server names matching one of these wildcards. Blank = every name.
        HybridAdServerNameExclude        never server names matching one of these wildcards.
      A server that falls out of the filter keeps its group and its access: it only stops being listed and proposed.

  (12) NEW SERVERS IN THE OUs A SUPERADMIN NAMES ARE OFFERED AS ONE LIST; A SUPERADMIN APPROVES IT; THE WORKER CREATES IT
       IN BATCHES. Owner 2026-10-13, his pick in the wizard: "Always approve, in batches".
        HybridAdServerAutoGroupOus       the OUs (several; sub-OUs included) whose new servers are OFFERED. Blank = none:
                                         every server is a Discovery proposal a person accepts (as before).
        HybridAdServerAutoGroupMaxPerRun how many groups of an approved list are created per run (default 50, 1-1000).
      THE RULE: NOTHING is created without a SuperAdmin's approval of the exact list -- not one server. Every run writes
      the eligible servers no approval covers as the waiting list (settings row 'AdServerAutoGroupsWaiting'); a SuperAdmin
      approves that exact list in the Manager ('HybridAdServerAutoGroupsApproval', valid 72 hours); the worker then creates
      at most the batch size per run, run after run, each server at most once, every condition checked again each run,
      and reports how far it is ('AdServerAutoGroupsProgress'). What is left when the 72 hours run out waits again.
      "Creates" = the worker writes the DEFINITION of the per-server group (the same row Discovery > Create stages)
      into the store. Everything after that is the existing, unchanged path: the engine creates the Entra group, the
      mirror job creates the AD group, this job puts it into the server's local Administrators, the sync fills it.

  How it is wired without touching PIM-HybridAdGroups.ps1 (owned by another lane): Invoke-PimHybridAdServersJobWithDiscovery
  lists the computers itself (with their distinguished names), applies the customer's filters, and hands the ORIGINAL job
  (Invoke-PimHybridAdServersJob) an adapter whose GetComputers returns exactly the selected computers and a SaveCache that
  adds each server's OU and its "automatic" mark. The original job's own fixed rule (enabled, Windows Server, not a domain
  controller, changed within 90 days) still runs on that list; for a customer window LONGER than 90 days the wrapper moves
  the reference time it hands over by the difference, so the inner 90-day rule equals the customer's N days.

  No ActiveDirectory module: LDAP through the helpers in PIM-HybridAd.ps1. Nothing here deletes or removes anything.
#>

# The catalog of the settings this file (and PIM-HybridAdCleanup.ps1) reads. kind: oulist | patterns | number.
$script:PimHybridAdDiscoverySettingCatalog = @(
    [ordered]@{ name = 'HybridAdServerSearchOus'; label = 'Server discovery: only these OUs'; kind = 'oulist'; default = ''; defaultText = 'Blank (the whole domain)'
        help = 'Distinguished names of the OUs the hybrid worker looks in for Windows servers, one per line (or separated by ;). Sub-OUs are included. Blank = the whole domain.' }
    [ordered]@{ name = 'HybridAdServerExcludeOus'; label = 'Server discovery: OUs to leave out'; kind = 'oulist'; default = ''; defaultText = 'Blank (nothing left out)'
        help = 'Distinguished names of OUs whose servers are never listed, one per line (or separated by ;). Sub-OUs are included.' }
    [ordered]@{ name = 'HybridAdServerActiveDays'; label = 'Server discovery: last changed within (days)'; kind = 'number'; default = '90'; min = 1; max = 3650; defaultText = '90 days'
        help = 'A server is listed when its computer object in Active Directory last CHANGED within this many days. This is the date the object changed, not the last sign-in of the computer.' }
    [ordered]@{ name = 'HybridAdServerNameInclude'; label = 'Server discovery: only names like'; kind = 'patterns'; default = ''; defaultText = 'Blank (every name)'
        help = 'Only servers whose name matches one of these wildcards are listed (for example SRV-*, FS??). Separate with comma, ; or a new line. Blank = every name.' }
    [ordered]@{ name = 'HybridAdServerNameExclude'; label = 'Server discovery: never names like'; kind = 'patterns'; default = ''; defaultText = 'Blank (no name left out)'
        help = 'Servers whose name matches one of these wildcards are never listed (for example TEST-*). Separate with comma, ; or a new line.' }
    [ordered]@{ name = 'HybridAdServerAutoGroupOus'; label = 'New servers in these OUs are offered for approval as one list'; kind = 'oulist'; default = ''; defaultText = 'Blank (no list: every server is a proposal)'
        help = 'Distinguished names of the OUs whose new servers are collected into ONE list that a SuperAdmin approves, one per line (or separated by ;). Sub-OUs are included. Naming an OU creates nothing: after the approval the worker creates the groups of the list in batches. Everywhere else a new server stays a proposal on Discovery and gaps.' }
    [ordered]@{ name = 'HybridAdServerAutoGroupMaxPerRun'; label = 'Server groups created per run'; kind = 'number'; default = '50'; min = 1; max = 1000; defaultText = '50 groups'
        help = 'How many groups of an approved list of new servers the worker creates per run (hourly), run after run until the list is done. Nothing is created without a SuperAdmin approving the list. A larger number finishes a long list sooner.' }
    [ordered]@{ name = 'HybridAdCleanupOus'; label = 'Clean-up: also look for old PIM groups in these OUs'; kind = 'oulist'; default = ''; defaultText = 'Blank (only the OU for new AD groups)'
        help = 'Old PIM groups are looked for in the OU for new AD groups. Name more OUs here, one per line (or separated by ;), when older groups live elsewhere. Sub-OUs are included. A group outside these OUs is never offered and never deleted.' }
)

function Get-PimHybridAdDiscoverySettingCatalog { return $script:PimHybridAdDiscoverySettingCatalog }

function Get-PimHybridAdDiscoveryRawSetting {
    # One reader. Get-PimHybridAdSetting (PIM-HybridAdGroups.ps1) when loaded; else the same order it uses.
    param([Parameter(Mandatory)][string]$Name, $Default = '')
    if (Get-Command Get-PimHybridAdSetting -ErrorAction SilentlyContinue) { return (Get-PimHybridAdSetting -Name $Name -Default $Default) }
    $g = Get-Variable -Name "PIM_$Name" -Scope Global -ValueOnly -ErrorAction SilentlyContinue
    if ($null -ne $g -and "$g".Trim() -ne '') { return $g }
    if ($global:PIM_NamingConventions -is [System.Collections.IDictionary] -and $global:PIM_NamingConventions.Contains($Name)) {
        $s = $global:PIM_NamingConventions[$Name]; if ($null -ne $s -and "$s".Trim() -ne '') { return $s }
    }
    return $Default
}

function ConvertTo-PimHybridAdDnKey {
    # PURE. A distinguished name in one comparable form: trimmed, lower case, no blanks around the commas and the = signs.
    param([AllowNull()][string]$Dn)
    $d = "$Dn".Trim()
    if (-not $d) { return '' }
    $d = [regex]::Replace($d, '\s*,\s*', ',')
    $d = [regex]::Replace($d, '(?i)(^|,)\s*(OU|CN|DC)\s*=\s*', '$1$2=')
    return $d.ToLowerInvariant()
}

function ConvertTo-PimHybridAdOuList {
    # PURE. The text of an OU-list setting -> the distinguished names (one per line or separated by ;). A DN holds commas,
    # so a comma never separates two OUs.
    param([AllowNull()][string]$Text)
    $seen = @{}
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($p in ("$Text" -split '[;\r\n]+')) {
        $v = "$p".Trim()
        if (-not $v) { continue }
        $k = ConvertTo-PimHybridAdDnKey $v
        if ($seen.ContainsKey($k)) { continue }
        $seen[$k] = $true
        $out.Add($v)
    }
    # NOT `return , $array`: every caller wraps the call in @(...), and @() over a comma-returned array gives ONE element
    # that is the whole array (fix round 1: every OU list was one "OU" and every filter matched nothing).
    return $out.ToArray()
}

function ConvertTo-PimHybridAdPatternList {
    # PURE. The text of a name-pattern setting -> the wildcards (comma, ; or new line between them).
    param([AllowNull()][string]$Text)
    $seen = @{}
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($p in ("$Text" -split '[,;\r\n]+')) {
        $v = "$p".Trim()
        if (-not $v) { continue }
        if ($seen.ContainsKey($v.ToLowerInvariant())) { continue }
        $seen[$v.ToLowerInvariant()] = $true
        $out.Add($v)
    }
    return $out.ToArray()   # callers wrap in @(...) -- see ConvertTo-PimHybridAdOuList
}

function Test-PimHybridAdDnUnder {
    # PURE. Is the object -Dn BELOW the container -Ou (at any depth)? The container itself is not "below" itself.
    param([AllowNull()][string]$Dn, [AllowNull()][string]$Ou)
    $d = ConvertTo-PimHybridAdDnKey $Dn
    $o = ConvertTo-PimHybridAdDnKey $Ou
    if (-not $d -or -not $o) { return $false }
    return $d.EndsWith(",$o", [System.StringComparison]::Ordinal)
}

function Test-PimHybridAdDnUnderAny {
    # PURE. Below one of -Ous? Returns the first OU that holds it, or ''.
    param([AllowNull()][string]$Dn, [string[]]$Ous = @())
    foreach ($o in @($Ous)) { if (Test-PimHybridAdDnUnder -Dn $Dn -Ou $o) { return "$o" } }
    return ''
}

function Get-PimHybridAdParentDn {
    # PURE. The container of an object: everything after the first comma that is not escaped.
    param([AllowNull()][string]$Dn)
    $m = [regex]::Match("$Dn", '^(?:\\.|[^,\\])*,(.*)$')
    if ($m.Success) { return $m.Groups[1].Value.Trim() }
    return ''
}

function Test-PimHybridAdDiscoverySettingsInput {
    <#
      PURE. -Values: name -> text (only names of the catalog above). -Current: the stored text of the other settings, so a
      rule that spans two settings (the automatic OUs must lie inside where the worker looks) is checked on the result.
      Returns @{ ok; errors[]; values (trimmed; '' = back to the default) }. An OU list is stored one OU per line.
    #>
    param([hashtable]$Values = @{}, [hashtable]$Current = @{})
    $cat = @{}; foreach ($c in $script:PimHybridAdDiscoverySettingCatalog) { $cat["$($c.name)"] = $c }
    $err = New-Object System.Collections.Generic.List[string]
    $out = [ordered]@{}
    $dnRx = '^(?i)(OU|CN)=[^,]+(,(OU|CN)=[^,]+)*,DC=[^,]+(,DC=[^,]+)*$'
    foreach ($k in @($Values.Keys)) {
        if (-not $cat.ContainsKey("$k")) { $err.Add("unknown setting '$k'"); continue }
        $c = $cat["$k"]
        $v = "$($Values[$k])".Trim()
        switch ("$($c.kind)") {
            'oulist' {
                $list = @(ConvertTo-PimHybridAdOuList $v)
                if ($list.Count -gt 50) { $err.Add("$($c.label): at most 50 OUs") }
                foreach ($ou in $list) { if ($ou -notmatch $dnRx) { $err.Add("$($c.label): '$ou' is not a distinguished name such as OU=Servers,DC=corp,DC=local") } }
                $v = ($list -join "`n")
            }
            'patterns' {
                $list = @(ConvertTo-PimHybridAdPatternList $v)
                if ($list.Count -gt 50) { $err.Add("$($c.label): at most 50 patterns") }
                foreach ($p in $list) {
                    if ($p -notmatch '^[A-Za-z0-9_*?-]{1,64}$') { $err.Add("$($c.label): '$p' -- letters, digits, - and _ with the wildcards * and ? only") }
                    elseif ("$k" -eq 'HybridAdServerNameExclude' -and $p -match '^[*?]+$') { $err.Add("$($c.label): '$p' would leave out every server") }
                }
                $v = ($list -join ', ')
            }
            'number' {
                if ($v) {
                    $i = 0
                    if (-not [int]::TryParse($v, [ref]$i) -or $i -lt [int]$c.min -or $i -gt [int]$c.max) { $err.Add("$($c.label): a whole number $($c.min)-$($c.max) (or blank = $($c.default))") }
                    else { $v = "$i" }
                }
            }
        }
        $out["$k"] = $v
    }
    # the rule across settings, on what the store would hold after this save
    $eff = { param($n) if ($out.Contains($n)) { "$($out[$n])" } elseif ($Current.ContainsKey($n)) { "$($Current[$n])" } else { '' } }
    $auto = @(ConvertTo-PimHybridAdOuList (& $eff 'HybridAdServerAutoGroupOus'))
    if ($auto.Count -and $err.Count -eq 0) {
        $search = @(ConvertTo-PimHybridAdOuList (& $eff 'HybridAdServerSearchOus'))
        $excl = @(ConvertTo-PimHybridAdOuList (& $eff 'HybridAdServerExcludeOus'))
        foreach ($a in $auto) {
            $ak = ConvertTo-PimHybridAdDnKey $a
            if ($search.Count) {
                $inside = $false
                foreach ($s in $search) { if ($ak -eq (ConvertTo-PimHybridAdDnKey $s) -or (Test-PimHybridAdDnUnder -Dn $a -Ou $s)) { $inside = $true; break } }
                if (-not $inside) { $err.Add("New servers get their group automatically in these OUs: '$a' is outside the OUs the worker looks in (Server discovery: only these OUs)") }
            }
            foreach ($x in $excl) { if ($ak -eq (ConvertTo-PimHybridAdDnKey $x) -or (Test-PimHybridAdDnUnder -Dn $a -Ou $x)) { $err.Add("New servers get their group automatically in these OUs: '$a' is inside an OU that is left out ('$x')") } }
        }
    }
    return @{ ok = ($err.Count -eq 0); errors = $err.ToArray(); values = $out }
}

function Get-PimHybridAdServerDiscoverySettings {
    <#
      The effective discovery settings, as the worker uses them. -Read { param($name) -> text } is the seam for tests and
      for the Manager's preview (unsaved values); default = the stored settings.
      Returns @{ searchOus[]; excludeOus[]; activeDays; nameInclude[]; nameExclude[]; autoOus[]; autoMax; cleanupOus[];
      problems[] }. FAIL CLOSED: a stored value that does not pass the same check the save uses is reported in problems,
      the filter falls back to its default for that one value, and NO server gets a group automatically while any
      problem exists (autoOus is emptied).
    #>
    param([scriptblock]$Read = $null)
    if (-not $Read) { $Read = { param($n) "$(Get-PimHybridAdDiscoveryRawSetting -Name $n -Default '')" } }
    $raw = @{}
    foreach ($c in $script:PimHybridAdDiscoverySettingCatalog) { $t = ''; try { $t = "$(& $Read $c.name)".Trim() } catch { $t = '' }; $raw["$($c.name)"] = $t }
    $problems = New-Object System.Collections.Generic.List[string]
    $clean = @{}
    foreach ($n in @($raw.Keys)) {
        $one = Test-PimHybridAdDiscoverySettingsInput -Values @{ $n = $raw[$n] } -Current @{}
        if ($one.ok) { $clean[$n] = "$($one.values[$n])" } else { $clean[$n] = ''; foreach ($e in @($one.errors)) { $problems.Add("$e") } }
    }
    $cross = Test-PimHybridAdDiscoverySettingsInput -Values @{ HybridAdServerAutoGroupOus = $clean['HybridAdServerAutoGroupOus'] } -Current $clean
    if (-not $cross.ok) { foreach ($e in @($cross.errors)) { $problems.Add("$e") } }
    $days = 90; if ($clean['HybridAdServerActiveDays']) { [void][int]::TryParse($clean['HybridAdServerActiveDays'], [ref]$days) }; if ($days -lt 1) { $days = 90 }
    $max = 50; if ($clean['HybridAdServerAutoGroupMaxPerRun']) { [void][int]::TryParse($clean['HybridAdServerAutoGroupMaxPerRun'], [ref]$max) }; if ($max -lt 1 -or $max -gt 1000) { $max = 50 }
    $auto = @(ConvertTo-PimHybridAdOuList $clean['HybridAdServerAutoGroupOus'])
    if ($problems.Count) { $auto = @() }
    return @{
        searchOus = @(ConvertTo-PimHybridAdOuList $clean['HybridAdServerSearchOus']); excludeOus = @(ConvertTo-PimHybridAdOuList $clean['HybridAdServerExcludeOus'])
        activeDays = $days
        nameInclude = @(ConvertTo-PimHybridAdPatternList $clean['HybridAdServerNameInclude']); nameExclude = @(ConvertTo-PimHybridAdPatternList $clean['HybridAdServerNameExclude'])
        autoOus = $auto; autoMax = $max
        cleanupOus = @(ConvertTo-PimHybridAdOuList $clean['HybridAdCleanupOus'])
        problems = $problems.ToArray()
    }
}

function Get-PimHybridAdServerInventory {
    <#
      PURE. AD computer objects (Name, DNSHostName, OperatingSystem, Enabled, whenChanged, primaryGroupID,
      DistinguishedName) -> every enabled Windows Server that is not a domain controller (primary group 516 / 521), BEFORE
      the customer's filters: @{ name; dnsHostName; os; whenChanged (UTC, round-trip text); dn }, sorted by name. This is
      what the Manager's preview filters ("with these settings the worker finds N servers").
    #>
    param([object[]]$Computers = @())
    @($Computers | Where-Object {
            $_ -and "$($_.Name)".Trim() -and [bool]$_.Enabled -and "$($_.OperatingSystem)" -match 'Windows Server' -and "$($_.primaryGroupID)" -notin @('516', '521') -and $_.whenChanged
        } | ForEach-Object {
            [pscustomobject]@{ name = "$($_.Name)"; dnsHostName = "$($_.DNSHostName)"; os = "$($_.OperatingSystem)"
                whenChanged = ([datetime]$_.whenChanged).ToUniversalTime().ToString('o'); dn = "$($_.DistinguishedName)" }
        } | Sort-Object name)
}

function Select-PimHybridAdServerDiscovery {
    <#
      PURE. The customer's filters over the inventory. Returns @{ servers[]; counts } -- each server is the inventory item
      plus ou (its container) and autoGroup ($true only when it lies below one of the automatic OUs). counts = @{ total;
      outsideOus; excludedOu; stale; nameFiltered; noDn; selected; auto }.
      A server without a distinguished name can only be selected when no OU rule is set, and is never automatic.
    #>
    param([object[]]$Inventory = @(), [Parameter(Mandatory)][hashtable]$Settings, [datetime]$NowUtc = [datetime]::UtcNow)
    $cut = $NowUtc.ToUniversalTime().AddDays(-[int]$Settings.activeDays)
    $counts = [ordered]@{ total = 0; outsideOus = 0; excludedOu = 0; stale = 0; nameFiltered = 0; noDn = 0; selected = 0; auto = 0 }
    $sel = New-Object System.Collections.Generic.List[object]
    $styles = [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal
    foreach ($s in @($Inventory)) {
        if ($null -eq $s) { continue }
        $counts.total++
        $name = "$($s.name)".Trim(); $dn = "$($s.dn)".Trim()
        $ouRule = [bool](@($Settings.searchOus).Count -or @($Settings.excludeOus).Count)
        if (-not $dn -and $ouRule) { $counts.noDn++; continue }
        if (@($Settings.searchOus).Count -and -not (Test-PimHybridAdDnUnderAny -Dn $dn -Ous $Settings.searchOus)) { $counts.outsideOus++; continue }
        if (@($Settings.excludeOus).Count -and (Test-PimHybridAdDnUnderAny -Dn $dn -Ous $Settings.excludeOus)) { $counts.excludedOu++; continue }
        $wc = $null
        if ($s.whenChanged -is [datetime]) { $wc = ([datetime]$s.whenChanged).ToUniversalTime() }
        else { try { $wc = [datetime]::Parse("$($s.whenChanged)", [System.Globalization.CultureInfo]::InvariantCulture, $styles) } catch { $wc = $null } }
        if ($null -eq $wc -or $wc -le $cut) { $counts.stale++; continue }
        $inc = @($Settings.nameInclude); $exc = @($Settings.nameExclude)
        if ($inc.Count -and -not @($inc | Where-Object { $name -like $_ }).Count) { $counts.nameFiltered++; continue }
        if ($exc.Count -and @($exc | Where-Object { $name -like $_ }).Count) { $counts.nameFiltered++; continue }
        $auto = [bool]($dn -and @($Settings.autoOus).Count -and (Test-PimHybridAdDnUnderAny -Dn $dn -Ous $Settings.autoOus))
        if ($auto) { $counts.auto++ }
        $counts.selected++
        $sel.Add([pscustomobject]@{ name = $name; dnsHostName = "$($s.dnsHostName)"; os = "$($s.os)"; whenChanged = $wc.ToString('o'); dn = $dn; ou = (Get-PimHybridAdParentDn $dn); autoGroup = $auto })
    }
    return @{ servers = $sel.ToArray(); counts = $counts }
}

function Get-PimHybridAdLdapComputersWithDn {
    # The same read as Get-PimHybridAdLdapComputers (PIM-HybridAdGroups.ps1), plus each computer's distinguished name.
    param([string]$Server)
    $base = (Get-PimHybridAdLdapRootDse -Server $Server).DefaultNamingContext
    $rows = @(Invoke-PimHybridAdLdapSearch -BaseDn $base -Filter '(&(objectCategory=computer)(operatingSystem=*Windows Server*))' `
            -Attributes @('name', 'dNSHostName', 'operatingSystem', 'userAccountControl', 'whenChanged', 'primaryGroupID') -Server $Server)
    return @(foreach ($r in $rows) {
            $one = { param($n) $v = @($r["$n".ToLowerInvariant()]); if ($v.Count) { "$($v[0])" } else { $null } }
            $uac = 0; [void][int]::TryParse("$(& $one 'userAccountControl')", [ref]$uac)
            $wc = & $one 'whenChanged'
            [pscustomobject]@{ Name = (& $one 'name'); DNSHostName = (& $one 'dNSHostName'); OperatingSystem = (& $one 'operatingSystem'); Enabled = -not ($uac -band 2)
                whenChanged = $(if ($wc) { ConvertFrom-PimHybridAdLdapValue $wc } else { $null }); primaryGroupID = (& $one 'primaryGroupID')
                DistinguishedName = (& $one 'distinguishedName') }
        })
}

function Get-PimHybridAdDiscoveryServerAdapter {
    <#
      [ ] HYBRID-WORKER-ONLY. The server adapter of the original job (Get-PimDefaultServerAdapter) with two additions:
      GetComputers also returns each computer's distinguished name, and RemoveLocalAdmin (used ONLY by the approved
      clean-up, PIM-HybridAdCleanup.ps1). No factory locals in the blocks: they call functions only.
    #>
    $a = Get-PimDefaultServerAdapter
    $a['GetComputers'] = {
        $s = Get-PimHybridAdServerSplat
        @(Get-PimHybridAdLdapComputersWithDn @s)
    }
    $a['RemoveLocalAdmin'] = {
        param([string]$Computer, [string]$Member)
        Invoke-Command -ComputerName $Computer -ErrorAction Stop -ArgumentList $Member -ScriptBlock { param($m) Remove-LocalGroupMember -SID 'S-1-5-32-544' -Member $m -ErrorAction Stop }
    }
    return $a
}

function Get-PimHybridAdStoreCs {
    # The store connection of this process, or '' (the same order the worker's other writers use).
    $cs = "$($global:PIM_SqlConnectionString)".Trim()
    if (-not $cs -and (Get-Command Get-PimSqlConnectionString -ErrorAction SilentlyContinue)) { try { $cs = "$(Get-PimSqlConnectionString)".Trim() } catch { $cs = '' } }
    return $cs
}

# The group-definition entities (the same set PIM-HybridAdGroups.ps1 mirrors from). A copy, used only when that file's own
# list is not loaded.
$script:PimHybridAdDiscoveryGroupEntities = @('PIM-Definitions-Roles', 'PIM-Definitions-Services', 'PIM-Definitions-Organization',
    'PIM-Definitions-Tasks', 'PIM-Definitions-Departments', 'PIM-Definitions-Processes', 'PIM-Definitions-Projects',
    'PIM-Definitions-CrossOrg', 'PIM-Definitions-Resources')

function Get-PimHybridAdAllGroupDefinitions {
    <#
      EVERY defined group row of the store, read NOW (never from a cache): @{ ok; rows[]; names (lower name -> $true);
      tags (lower tag -> $true); reason }. ok = $false when the engine core is not loaded or ANY entity could not be read
      -- the callers then do nothing (an unreadable store is never "no definitions"). -Rows is the seam for tests.
    #>
    param([object[]]$Rows = $null)
    if ($null -eq $Rows) {
        if (-not (Get-Command Get-PimDesiredRows -ErrorAction SilentlyContinue)) { return @{ ok = $false; rows = @(); names = @{}; tags = @{}; reason = 'the engine core (Get-PimDesiredRows) is not loaded on this worker' } }
        $ents = @($script:PimHybridAdGroupEntities); if (-not $ents.Count) { $ents = @($script:PimHybridAdDiscoveryGroupEntities) }
        $all = New-Object System.Collections.Generic.List[object]
        foreach ($e in $ents) {
            $got = $null
            try { $got = @(Get-PimDesiredRows -Entity $e) } catch { return @{ ok = $false; rows = @(); names = @{}; tags = @{}; reason = "the definitions '$e' could not be read: $($_.Exception.Message)" } }
            if (-not ($global:PIM_DesiredResolved -is [hashtable]) -or -not $global:PIM_DesiredResolved.ContainsKey($e) -or -not $global:PIM_DesiredResolved[$e]) {
                return @{ ok = $false; rows = @(); names = @{}; tags = @{}; reason = "the definitions '$e' could not be read from the store" }
            }
            foreach ($r in @($got)) { if ($null -ne $r) { $all.Add($r) } }
        }
        $Rows = $all.ToArray()
    }
    $names = @{}; $tags = @{}
    foreach ($r in @($Rows)) {
        if ($null -eq $r) { continue }
        $n = "$($r.GroupName)".Trim(); if ($n) { $names[$n.ToLowerInvariant()] = $true }
        $t = "$($r.GroupTag)".Trim(); if ($t) { $tags[$t.ToLowerInvariant()] = $true }
    }
    return @{ ok = $true; rows = @($Rows); names = $names; tags = $tags; reason = '' }
}

function Get-PimHybridAdServerGroupNamer {
    <#
      The per-server group name as Get-PimHybridAdServerGroupName (PIM-HybridAdGroups.ps1) builds it -- the same format,
      prefix, cloud suffix and marker, in the same replace order -- with the settings read ONCE. That function reads four
      settings and probes for absent commands (Get-Command = a PATH scan) on EVERY call; for 1,000 servers per run that was
      most of the run (fix round 2: the suite hit the gate's limit). Returns { param($server) -> name }.
    #>
    $fmt = "$(Get-PimHybridAdSetting -Name 'HybridAdServerGroupFormat' -Default '{prefix}AD-SRV-{server}{cloud}{marker}')".Trim()
    $prefix = ''
    if (Get-Command Get-PimGroupNamePrefix -ErrorAction SilentlyContinue) { try { $prefix = "$(Get-PimGroupNamePrefix)".Trim() } catch { $prefix = '' } }
    $marker = "$(Get-PimHybridAdSetting -Name 'HybridAdGroupMarker' -Default '-S_AD')".Trim()
    $cloud = "$((Get-PimHybridAdSuffixes).cloud)"
    $head = $fmt.Replace('{prefix}', $prefix)
    return { param($Server) $head.Replace('{server}', "$Server".Trim()).Replace('{cloud}', $cloud).Replace('{marker}', $marker) }.GetNewClosure()
}

function Get-PimHybridAdServerApprovalMaxHours { return 72 }   # an approval of a waiting list of new servers is used for this long, once

function Get-PimHybridAdServerListId {
    # PURE. The fingerprint of an exact list of servers and the group names they would get: SHA-256 over the sorted
    # "server|group" lines, lower case. The same list gives the same id on the worker and in the Manager; one server
    # more, one less or another group name gives another id -- so an approval is for exactly the list that was shown.
    param([object[]]$Items = @())
    $lines = New-Object System.Collections.Generic.List[string]
    foreach ($i in @($Items)) {
        if ($null -eq $i) { continue }
        $s = if ($i -is [System.Collections.IDictionary]) { "$($i['server'])" } else { "$($i.server)" }
        $g = if ($i -is [System.Collections.IDictionary]) { "$($i['groupName'])" } else { "$($i.groupName)" }
        if ($s.Trim() -and $g.Trim()) { $lines.Add(("{0}|{1}" -f $s.Trim().ToLowerInvariant(), $g.Trim().ToLowerInvariant())) }
    }
    if (-not $lines.Count) { return '' }
    $sorted = $lines.ToArray(); [array]::Sort($sorted, [System.StringComparer]::Ordinal)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { return (([System.BitConverter]::ToString($sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes(($sorted -join "`n"))))) -replace '-', '').ToLowerInvariant() }
    finally { $sha.Dispose() }
}

function Get-PimHybridAdServerAutoGroupPlan {
    <#
      PURE. Decision (12) + the owner's rule of 2026-10-13 ("Always approve, in batches"): which servers get their group
      DEFINED in this run, and which are OFFERED to a SuperAdmin.

      A server is ELIGIBLE only when ALL of this holds in this run:
        1. it passed every discovery filter and lies below one of the automatic OUs (autoGroup);
        2. the definitions were read (-DefinitionsOk), the Discovery decisions were read (-DecisionsOk) and the record of
           earlier automatic groups was read (-RecordOk) -- else NOTHING happens (refused);
        3. its name is a plain computer name (letters, digits, - and _; at most 15 characters);
        4. its group name (-NameOf) matches the mirrored pattern (-Pattern) and is at most 64 characters;
        5. no group of that name is defined yet;
        6. no person has decided on this server on Discovery and gaps -- Ignore, or Create staged for his own commit
           (-Ignored: 'ad-server:<name>');
        7. it never got a group automatically before (-Already): a group a person removed is not put back.
      Then:
        * NOTHING is created without a SuperAdmin's approval of the exact list -- not one server, not in a named OU. An
          eligible server that is not in the approved list (-Approved: server, lower case -> the approved group name) is
          put on the WAITING list (waiting[]), whatever the number.
        * The eligible servers of the approved list are created in BATCHES: at most -Max per run (create[], in name order);
          the others of the list wait for the next runs (remaining = how many).
        * Every run checks every condition again: a server of the approved list that is not eligible any more is not
          created and is reported (notCreated[] with the reason) -- unless it was created under this approval already
          (-Done) or is simply defined now.
      Returns @{ create[]; remaining; waiting[]; notCreated[]; skipped[]; refused; mode (none | waiting | approved) }.
      create[] / waiting[] items: server, groupName, ou, dn.
    #>
    param([object[]]$Servers = @(), [bool]$DefinitionsOk = $false, [hashtable]$DefinedNames = @{}, [string]$Pattern = '',
          [bool]$DecisionsOk = $false, [hashtable]$Ignored = @{}, [bool]$RecordOk = $false, [hashtable]$Already = @{},
          [int]$Max = 50, [hashtable]$Approved = @{}, [hashtable]$Done = @{}, [Parameter(Mandatory)][scriptblock]$NameOf)
    $out = @{ create = @(); remaining = 0; waiting = @(); notCreated = @(); skipped = @(); refused = ''; mode = 'none' }
    if ($Max -lt 1) { $Max = 50 }
    $cand = @($Servers | Where-Object { $_ -and $_.autoGroup })
    if (-not $cand.Count -and -not $Approved.Count) { return $out }
    if (-not $DefinitionsOk) { $out.refused = 'the group definitions could not be read'; return $out }
    if (-not $DecisionsOk) { $out.refused = 'the Discovery decisions (Ignore) could not be read'; return $out }
    if (-not $RecordOk) { $out.refused = 'the record of the groups defined automatically earlier could not be read'; return $out }
    if (-not "$Pattern".Trim()) { $out.refused = 'the pattern of the groups mirrored to Active Directory is not known'; return $out }
    $elig = New-Object System.Collections.Generic.List[object]; $sk = New-Object System.Collections.Generic.List[object]; $seen = @{}; $definedServers = @{}
    foreach ($s in $cand) {
        $name = "$($s.name)".Trim()
        $gn = ''
        if ($name -match '^[A-Za-z0-9_-]{1,15}$') { try { $gn = "$(& $NameOf $name)".Trim() } catch { $gn = '' } }
        $skip = ''
        if ($name -notmatch '^[A-Za-z0-9_-]{1,15}$') { $skip = 'the server name is not a plain computer name -- left as a proposal' }
        elseif (-not $gn) { $skip = 'no group name could be built for this server -- left as a proposal' }
        elseif ($gn -notlike $Pattern) { $skip = "the group name '$gn' does not match the groups mirrored to Active Directory ('$Pattern') -- left as a proposal" }
        elseif ($gn.Length -gt 64) { $skip = "the group name '$gn' is longer than 64 characters -- left as a proposal" }
        elseif ($DefinedNames.ContainsKey($gn.ToLowerInvariant())) { $definedServers[$name.ToLowerInvariant()] = $true; continue }   # defined already: the normal case, nothing to say
        elseif ($Ignored.ContainsKey("ad-server:$($name.ToLowerInvariant())")) { $skip = 'a person already decided on this server on Discovery and gaps (Ignore, or Create for his own commit) -- nothing is done automatically' }
        elseif ($Already.ContainsKey($name.ToLowerInvariant())) { $skip = 'its group was defined automatically before and has been removed since -- not put back; it is a proposal again' }
        elseif ($seen.ContainsKey($gn.ToLowerInvariant())) { continue }   # the same server listed twice: handled once
        if ($skip) { $sk.Add(@{ server = $name; groupName = $gn; reason = $skip }) } else { $seen[$gn.ToLowerInvariant()] = $true; $elig.Add(@{ server = $name; groupName = $gn; ou = "$($s.ou)"; dn = "$($s.dn)" }) }
    }
    $sorted = @($elig.ToArray() | Sort-Object { $_.server.ToLowerInvariant() })
    $go = New-Object System.Collections.Generic.List[object]; $wait = New-Object System.Collections.Generic.List[object]; $inList = @{}; $rest = 0
    foreach ($e in $sorted) {
        $k = $e.server.ToLowerInvariant()
        if ($Approved.ContainsKey($k) -and "$($Approved[$k])".Trim().ToLowerInvariant() -eq $e.groupName.ToLowerInvariant()) {
            $inList[$k] = $true
            if ($go.Count -lt $Max) { $go.Add($e) } else { $rest++ }
        } else { $wait.Add($e) }   # not approved (or approved under another group name): offered, never created
    }
    $no = New-Object System.Collections.Generic.List[object]
    if ($Approved.Count) {
        $why = @{}; foreach ($x in $sk) { $why["$($x.server)".ToLowerInvariant()] = "$($x.reason)" }
        foreach ($k in @($Approved.Keys | Sort-Object)) {
            if ($inList.ContainsKey($k) -or $definedServers.ContainsKey($k) -or $Done.ContainsKey($k)) { continue }
            $r = if ($why.ContainsKey($k)) { $why[$k] } else { 'not listed below an OU where new servers are offered any more (moved, filtered out, disabled or gone), or it would get another group name now' }
            $no.Add(@{ server = "$k"; groupName = "$($Approved[$k])"; reason = "approved, but not created: $r" })
        }
    }
    $out.create = $go.ToArray(); $out.remaining = $rest; $out.waiting = $wait.ToArray(); $out.notCreated = $no.ToArray(); $out.skipped = $sk.ToArray()
    $out.mode = if ($Approved.Count) { 'approved' } elseif ($wait.Count) { 'waiting' } else { 'none' }
    return $out
}

function Invoke-PimHybridAdServerAutoGroups {
    <#
      Decision (12), the side effects ("Always approve, in batches"). Reads what the plan needs ONCE per run, plans, writes
      the waiting list, and (unless -WhatIf) writes up to the batch size of approved definitions. Seams for tests:
        -Definitions   the result of Get-PimHybridAdAllGroupDefinitions (default: read now)
        -ReadSetting   { param($name) -> parsed settings value | $null; THROWS when the store cannot be read }
        -Proposal      { param($server) -> @{ base; groupTag; groupName; row } | $null } (default: Get-PimDiscoveryProposal)
        -WriteRow      { param($base, $key, $row) }      (default: Set-PimSqlRow)
        -SaveRecord    { param($json) }                  settings row 'AdServerAutoGroups'  (worker's own record)
        -SaveWaiting   { param($json) }                  settings row 'AdServerAutoGroupsWaiting' (the list offered to a SuperAdmin)
        -SaveProgress  { param($json) }                  settings row 'AdServerAutoGroupsProgress' (n of m of the approved list)
        -Audit         { param($action, $target, $after) }
      THE APPROVAL ('HybridAdServerAutoGroupsApproval', written by the Manager for a SuperAdmin; the worker only reads it)
      is used when it parses, names who and when (a number), is not dated in the future, is not older than 72 hours and its
      list id is the fingerprint of its own servers. It is consumed server by server: a server created under it carries the
      list id in the record and is never created twice; the servers of the list that are left when the 72 hours run out
      are simply not approved any more -- they go back on the waiting list.
      Returns @{ created[]; failed[]; planned[]; waiting[]; notCreated[]; skipped[]; refused; mode; batchSize; total (servers
      of the approved list); done (created under it so far); remaining (still to create in later runs); runsLeft;
      approvedBy; approvalListId; approvalExpired; approvalNote; waitingListId }. Never throws: a write that fails is an
      item in failed[] (the job reports it and goes red), the others still go, the next run tries it again.
      Store traffic per run: the definitions, the decisions, the record, the approval and the waiting list are each read
      ONCE; one definition write + one audit event per created group; the record written twice; nothing per server.
    #>
    param([object[]]$Servers = @(), [Parameter(Mandatory)][hashtable]$Settings, [switch]$WhatIf, [hashtable]$Definitions = $null,
          [scriptblock]$ReadSetting, [scriptblock]$Proposal, [scriptblock]$WriteRow, [scriptblock]$SaveRecord, [scriptblock]$SaveWaiting, [scriptblock]$SaveProgress,
          [scriptblock]$Audit, [datetime]$NowUtc = [datetime]::UtcNow)
    $res = @{ created = @(); failed = @(); skipped = @(); refused = ''; planned = @(); waiting = @(); notCreated = @(); mode = 'none'; batchSize = 50; waitingListId = ''
        total = 0; done = 0; remaining = 0; runsLeft = 0; approvedBy = ''; approvalListId = ''; approvalExpired = $false; approvalNote = '' }
    if (-not @($Settings.autoOus).Count) { return $res }
    if (-not $Definitions) { $Definitions = Get-PimHybridAdAllGroupDefinitions }
    if (-not $ReadSetting) {
        $ReadSetting = {
            param($n)
            $cs = Get-PimHybridAdStoreCs
            if (-not $cs -or -not (Get-Command Get-PimSqlSetting -ErrorAction SilentlyContinue)) { throw 'no store connection' }
            Get-PimSqlSetting -ConnectionString $cs -Name $n
        }
    }
    $g = { param($o, $n) if ($null -eq $o) { $null } elseif ($o -is [System.Collections.IDictionary]) { $o[$n] } else { $o.$n } }
    $props = { param($o) if ($null -eq $o) { @() } elseif ($o -is [System.Collections.IDictionary]) { @($o.Keys | ForEach-Object { [pscustomobject]@{ Name = "$_"; Value = $o[$_] } }) } else { @($o.PSObject.Properties) } }
    $nowEpoch = [long][math]::Floor(($NowUtc.ToUniversalTime() - [datetime]'1970-01-01').TotalSeconds)

    # (1) the Discovery decisions of people
    $ignored = @{}; $decOk = $false
    try {
        $d = & $ReadSetting 'DiscoveryDecisions'
        if ($d -is [string] -and "$d".Trim()) { $d = $d | ConvertFrom-Json }
        # ANY decision a person made for a server (Ignore, or Create = staged for his own commit) means "hands off":
        # Re-add on the Discovery page removes the decision, and the server is then eligible again.
        foreach ($p in @(& $props $d)) { if ("$($p.Name)" -like 'ad-server:*' -and $null -ne $p.Value) { $ignored["$($p.Name)".ToLowerInvariant()] = $true } }
        $decOk = $true
    } catch { $decOk = $false }

    # (2) THE RECORD of the groups defined automatically: ONE settings row, { v; servers: { <server, lower case>: { group;
    # atEpoch; list (the approval it was created under)[; state = 'pending'] } } }, read ONCE per run and written at most
    # TWICE per run (never once per group). No size limit and nothing is ever dropped from it: an entry is what keeps a
    # group a person removed from being put back. About 140 bytes per server (5,000 servers = about 0.7 MB in one row).
    # 'pending' = the run that wrote it had not finished: when the group is defined now it counts as done; when it is not,
    # the write did not happen and the server is tried again.
    $already = @{}; $byList = @{}; $recOk = $false; $recDirty = $false; $recDoc = [ordered]@{ v = 1; servers = [ordered]@{} }
    try {
        $r = & $ReadSetting 'AdServerAutoGroups'
        if ($r -is [string] -and "$r".Trim()) { $r = $r | ConvertFrom-Json }
        foreach ($p in @(& $props (& $g $r 'servers'))) {
            $k = "$($p.Name)".ToLowerInvariant(); $v = $p.Value
            $grp = "$(& $g $v 'group')"; $at = [long]0; [void][long]::TryParse("$(& $g $v 'atEpoch')", [ref]$at); $st = "$(& $g $v 'state')"; $li = "$(& $g $v 'list')"
            if ($st -eq 'pending') {
                if ($Definitions.ok -and $grp -and $Definitions.names.ContainsKey($grp.ToLowerInvariant())) { $st = ''; $recDirty = $true }   # it was written: done
                elseif ($Definitions.ok) { $recDirty = $true; continue }                                                                    # it was not: tried again below
            }
            if ($st -ne 'pending') { $already[$k] = $true; if ($li) { if (-not $byList.ContainsKey($li)) { $byList[$li] = @{} }; $byList[$li][$k] = $true } }
            $e = [ordered]@{ group = $grp; atEpoch = $at }; if ($li) { $e['list'] = $li }; if ($st) { $e['state'] = $st }
            $recDoc.servers[$k] = $e
        }
        $recOk = $true
    } catch { $recOk = $false }

    # (3) the approval
    $approved = @{}; $apprId = ''; $apprBy = ''; $apprAt = [long]0; $apprNote = ''; $apprTotal = 0; $expiredId = ''; $expiredTotal = 0
    $maxSec = [long](Get-PimHybridAdServerApprovalMaxHours) * 3600
    try {
        $a = & $ReadSetting 'HybridAdServerAutoGroupsApproval'
        if ($a -is [string] -and "$a".Trim()) { $a = $a | ConvertFrom-Json }
        if ($a) {
            $aid = "$(& $g $a 'listId')".Trim(); $aby = "$(& $g $a 'approvedBy')".Trim(); $aat = [long]0
            $rawAt = & $g $a 'approvedAtEpoch'
            $okAt = ($rawAt -isnot [string]) -and [long]::TryParse("$rawAt", [ref]$aat) -and $aat -gt 0
            $list = @{}
            foreach ($x in @(& $g $a 'servers')) { if ($null -eq $x) { continue }; $sn = "$(& $g $x 'server')".Trim(); $gn = "$(& $g $x 'groupName')".Trim(); if ($sn -and $gn) { $list[$sn.ToLowerInvariant()] = $gn } }
            if ("$(& $g $a 'v')" -ne '1' -or -not $aid -or -not $aby -or -not $okAt) { $apprNote = 'the approval on record is not complete (version, list, who, when) -- not used' }
            elseif ($aat -gt ($nowEpoch + 600)) { $apprNote = 'the approval on record is dated in the future -- not used' }
            # the list id is the fingerprint of exactly these servers and group names: a record that was edited does not match
            elseif (-not $list.Count -or (Get-PimHybridAdServerListId -Items @($list.Keys | ForEach-Object { @{ server = $_; groupName = $list[$_] } })) -ne $aid) { $apprNote = 'the approval on record does not match its own list -- not used' }
            elseif (($nowEpoch - $aat) -gt $maxSec) { $expiredId = $aid; $expiredTotal = $list.Count; $apprBy = $aby; $apprAt = $aat }   # its 72 hours are over: what is left waits as a new list
            else { $approved = $list; $apprId = $aid; $apprBy = $aby; $apprAt = $aat; $apprTotal = $list.Count }
        }
    } catch { $approved = @{}; $apprId = ''; $apprNote = "the approval record could not be read ($($_.Exception.Message)) -- not used" }
    if ($apprNote) { Write-Warning "[hybrid-ad-servers] $apprNote" }
    $doneSet = @{}; if ($apprId -and $byList.ContainsKey($apprId)) { $doneSet = $byList[$apprId] }
    $batch = 50; if ($Settings.ContainsKey('autoMax')) { [void][int]::TryParse("$($Settings.autoMax)", [ref]$batch) }; if ($batch -lt 1) { $batch = 50 }

    # (4) the plan
    $pattern = ''; if (Get-Command Get-PimHybridAdGroupPattern -ErrorAction SilentlyContinue) { try { $pattern = "$(Get-PimHybridAdGroupPattern)" } catch { $pattern = '' } }
    $plan = Get-PimHybridAdServerAutoGroupPlan -Servers $Servers -DefinitionsOk ([bool]$Definitions.ok) -DefinedNames $Definitions.names -Pattern $pattern `
        -DecisionsOk $decOk -Ignored $ignored -RecordOk $recOk -Already $already -Max $batch -Approved $approved -Done $doneSet -NameOf (Get-PimHybridAdServerGroupNamer)
    $res.refused = "$($plan.refused)"; $res.skipped = @($plan.skipped); $res.mode = "$($plan.mode)"; $res.batchSize = $batch; $res.notCreated = @($plan.notCreated); $res.waiting = @($plan.waiting)
    $res.approvalNote = $apprNote; $res.approvedBy = $apprBy; $res.approvalListId = $(if ($apprId) { $apprId } else { $expiredId }); $res.approvalExpired = [bool]$expiredId; $res.total = $(if ($apprId) { $apprTotal } else { $expiredTotal })
    if ($plan.refused) { Write-Warning "[hybrid-ad-servers] no server group is defined in this run: $($plan.refused)"; return $res }

    # (5) THE WAITING LIST (settings row 'AdServerAutoGroupsWaiting'; the worker writes it, the Manager shows it): every
    # eligible server that no approval covers -- one server or a thousand. Rewritten only when the list itself changed;
    # emptied when nothing waits. Written in plan-only mode too: it is a report, it creates nothing.
    try {
        if (-not $SaveWaiting) { $SaveWaiting = { param($json) $cs = Get-PimHybridAdStoreCs; if (-not $cs -or -not (Get-Command Set-PimSqlSetting -ErrorAction SilentlyContinue)) { throw 'no store connection' }; Set-PimSqlSetting -ConnectionString $cs -Name 'AdServerAutoGroupsWaiting' -ValueJson $json } }
        $oldW = $null; try { $oldW = & $ReadSetting 'AdServerAutoGroupsWaiting' } catch { $oldW = $null }
        if ($oldW -is [string] -and "$oldW".Trim()) { try { $oldW = $oldW | ConvertFrom-Json } catch { $oldW = $null } }
        $oldId = "$(& $g $oldW 'listId')"
        $wl = @($plan.waiting)
        $newId = if ($wl.Count) { Get-PimHybridAdServerListId -Items $wl } else { '' }
        $res.waitingListId = $newId
        if ($newId -ne $oldId) {
            & $SaveWaiting (([ordered]@{ v = 1; listId = $newId; sinceEpoch = $nowEpoch; batchSize = $batch; count = $wl.Count; host = "$env:COMPUTERNAME"
                    servers = @($wl | ForEach-Object { [ordered]@{ server = $_.server; groupName = $_.groupName; ou = "$($_.ou)"; dn = "$($_.dn)" } }) }) | ConvertTo-Json -Depth 6 -Compress)
        }
    } catch { Write-Warning "[hybrid-ad-servers] the waiting list of new servers was not saved: $($_.Exception.Message)" }
    if (@($plan.waiting).Count) { Write-Host "    [hybrid-ad-servers] waiting  $(@($plan.waiting).Count) new server(s) wait for a SuperAdmin's approval (Settings > Hybrid Active Directory) -- nothing is created without it" }
    foreach ($x in @($plan.notCreated)) { Write-Host "    [hybrid-ad-servers] approved $($x.server) -> $($x.groupName): $($x.reason)" }
    foreach ($s in @($plan.skipped)) { Write-Host "    [hybrid-ad-servers] proposal $($s.server) -> $($s.groupName): $($s.reason)" }

    # (6) create this run's batch of the approved list
    $todo = @($plan.create)
    $created = New-Object System.Collections.Generic.List[object]; $failed = New-Object System.Collections.Generic.List[object]; $left = New-Object System.Collections.Generic.List[object]
    foreach ($s in @($res.skipped)) { $left.Add($s) }
    if ($WhatIf) {
        $res.planned = $todo
        foreach ($c in $todo) { Write-Host "    [hybrid-ad-servers] plan     server group $($c.server) -> $($c.groupName) (approved by $apprBy)" }
    } elseif ($todo.Count) {
        if (-not $Proposal) {
            $Proposal = {
                param($server)
                if (-not (Get-Command Get-PimDiscoveryProposal -ErrorAction SilentlyContinue)) { return $null }
                Get-PimDiscoveryProposal -Item ([pscustomobject]@{ kind = 'ad-server'; id = "$server"; name = "$server"; path = '' })
            }
        }
        if (-not $WriteRow) {
            $WriteRow = {
                param($base, $key, $row)
                $cs = Get-PimHybridAdStoreCs
                if (-not $cs -or -not (Get-Command Set-PimSqlRow -ErrorAction SilentlyContinue)) { throw 'no store connection' }
                Set-PimSqlRow -ConnectionString $cs -Entity $base -Key $key -Data $row
            }
        }
        if (-not $SaveRecord) { $SaveRecord = { param($json) $cs = Get-PimHybridAdStoreCs; if (-not $cs -or -not (Get-Command Set-PimSqlSetting -ErrorAction SilentlyContinue)) { throw 'no store connection' }; Set-PimSqlSetting -ConnectionString $cs -Name 'AdServerAutoGroups' -ValueJson $json } }
        if (-not $Audit) {
            $Audit = {
                param($action, $target, $after)
                $cs = Get-PimHybridAdStoreCs
                if ($cs -and (Get-Command Write-PimSqlAuditEvent -ErrorAction SilentlyContinue)) {
                    Write-PimSqlAuditEvent -ConnectionString $cs -Actor "hybrid-worker:$env:COMPUTERNAME" -ActorSource 'hybrid-ad-servers (list approved by a SuperAdmin)' -Action $action -Target $target -After $after -Result 'ok'
                }
            }
        }
        # The record is written ONCE before the definitions (this batch marked 'pending') and ONCE after them -- so a group
        # is never defined without its record entry, and the store is not asked to rewrite the record once per group.
        foreach ($c in $todo) { $recDoc.servers[$c.server.ToLowerInvariant()] = [ordered]@{ group = $c.groupName; atEpoch = $nowEpoch; list = $apprId; state = 'pending' } }
        $recSaved = $false
        try { & $SaveRecord ($recDoc | ConvertTo-Json -Depth 6 -Compress); $recSaved = $true; $recDirty = $true }
        catch {
            $res.refused = "the record of automatic groups could not be written ($($_.Exception.Message)) -- without it a group a person removes later could come back, so nothing was defined"
            Write-Warning "[hybrid-ad-servers] no server group is defined in this run: $($res.refused)"
        }
        if ($recSaved) {
            foreach ($c in $todo) {
                $key = $c.server.ToLowerInvariant()
                try {
                    $pr = & $Proposal $c.server
                    if (-not $pr -or -not "$($pr.groupTag)".Trim() -or "$($pr.groupName)".Trim() -ne $c.groupName) { $recDoc.servers.Remove($key); $left.Add(@{ server = $c.server; groupName = $c.groupName; reason = 'no definition could be built for this server -- left as a proposal' }); continue }
                    if ($Definitions.tags.ContainsKey("$($pr.groupTag)".Trim().ToLowerInvariant())) { $recDoc.servers.Remove($key); $left.Add(@{ server = $c.server; groupName = $c.groupName; reason = "another definition already uses the tag '$($pr.groupTag)' -- nothing is overwritten; left as a proposal" }); continue }
                    $row = [ordered]@{}; foreach ($k in @($pr.row.Keys)) { $row["$k"] = $pr.row[$k] }
                    $row['GroupDescription'] = "PIM - Local Administrators on server $($c.server) -- defined from the list of new servers a SuperAdmin approved"
                    & $WriteRow "$($pr.base)" "$($pr.groupTag)" $row
                    $Definitions.names[$c.groupName.ToLowerInvariant()] = $true; $Definitions.tags["$($pr.groupTag)".Trim().ToLowerInvariant()] = $true
                    $recDoc.servers[$key] = [ordered]@{ group = $c.groupName; atEpoch = $nowEpoch; list = $apprId }
                    $doneSet[$key] = $true
                    try { & $Audit 'hybrid-ad.server.auto-group' "$($pr.base):$($pr.groupTag)" ([ordered]@{ server = $c.server; groupName = $c.groupName; ou = "$($c.ou)"; rule = 'HybridAdServerAutoGroupOus + the list a SuperAdmin approved'; approvedBy = $apprBy; approvalListId = $apprId }) } catch { Write-Warning "[hybrid-ad-servers] the audit entry for $($c.groupName) was not written: $($_.Exception.Message)" }
                    $created.Add($c)
                    Write-Host "    [hybrid-ad-servers] defined  server group $($c.server) -> $($c.groupName) (approved by $apprBy)"
                } catch {
                    # ONE failing write never stops the others. Its record entry goes, so the next run tries this server again.
                    $recDoc.servers.Remove($key)
                    $failed.Add(@{ server = $c.server; groupName = $c.groupName; reason = "the definition was not written: $($_.Exception.Message)" })
                    Write-Host "    [hybrid-ad-servers] FAILED   server group $($c.server) -> $($c.groupName): $($_.Exception.Message)"
                }
            }
        }
    }
    if ($recDirty -and -not $WhatIf) {
        if (-not $SaveRecord) { $SaveRecord = { param($json) $cs = Get-PimHybridAdStoreCs; if (-not $cs -or -not (Get-Command Set-PimSqlSetting -ErrorAction SilentlyContinue)) { throw 'no store connection' }; Set-PimSqlSetting -ConnectionString $cs -Name 'AdServerAutoGroups' -ValueJson $json } }
        try { & $SaveRecord ($recDoc | ConvertTo-Json -Depth 6 -Compress) }
        catch { Write-Warning "[hybrid-ad-servers] the record of automatic groups was not saved after the run (its entries stay 'pending' and are settled by the next run): $($_.Exception.Message)" }
    }
    $res.created = $created.ToArray(); $res.failed = $failed.ToArray(); $res.skipped = $left.ToArray()

    # (7) the progress of the approved list, for the page: n of m created, how many runs are left at this batch size
    $res.done = @($doneSet.Keys).Count
    $res.remaining = [int]$plan.remaining + $failed.Count + $(if ($WhatIf) { $todo.Count } else { 0 })
    $res.runsLeft = [int][math]::Ceiling($res.remaining / [double]$batch)
    if ($apprId -or $expiredId) {
        try {
            if (-not $SaveProgress) { $SaveProgress = { param($json) $cs = Get-PimHybridAdStoreCs; if (-not $cs -or -not (Get-Command Set-PimSqlSetting -ErrorAction SilentlyContinue)) { throw 'no store connection' }; Set-PimSqlSetting -ConnectionString $cs -Name 'AdServerAutoGroupsProgress' -ValueJson $json } }
            $lid = if ($apprId) { $apprId } else { $expiredId }
            $doneN = if ($apprId) { $res.done } elseif ($byList.ContainsKey($expiredId)) { @($byList[$expiredId].Keys).Count } else { 0 }
            # no time stamp in it: an unchanged state is the same text, and the store does not rewrite the same text
            & $SaveProgress (([ordered]@{ v = 1; listId = $lid; approvedBy = $apprBy; approvedAtEpoch = $apprAt; expiresEpoch = ($apprAt + $maxSec); expired = [bool]$expiredId
                    total = [int]$res.total; created = [int]$doneN; remaining = $(if ($apprId) { [int]$res.remaining } else { 0 }); notEligible = @($plan.notCreated).Count; batchSize = $batch
                    runsLeft = $(if ($apprId) { [int]$res.runsLeft } else { 0 })
                    notCreated = @($plan.notCreated | Select-Object -First 100 | ForEach-Object { [ordered]@{ server = $_.server; reason = $_.reason } }) }) | ConvertTo-Json -Depth 6 -Compress)
        } catch { Write-Warning "[hybrid-ad-servers] the progress of the approved list was not saved: $($_.Exception.Message)" }
    }
    return $res
}

function Invoke-PimHybridAdServersJobWithDiscovery {
    <#
      The 'hybrid-ad-servers' job as the scheduler runs it since PIM 100.123: the customer's discovery filters, then the
      ORIGINAL job on exactly the selected servers, then the automatic groups (decision (12)) and the approved clean-up's
      local-Administrators step (PIM-HybridAdCleanup.ps1, when loaded). Returns the original job's result with the extra
      text appended to detail; an error of the original job is thrown again AFTER the extra steps ran.
      Seams (tests): -Adapter (GetComputers, GetLocalAdmins, AddLocalAdmin[, RemoveLocalAdmin]), -GroupAdapter, -SaveCache
      { param($doc) } (the whole 'ad-servers' document), -SaveInventory { param($doc) }, -ReadSettingText { param($name) },
      -AutoGroups { param($servers, $settings, $whatIf) -> result }, -CleanupStep { param($adapter, $netbios, $inventory, $whatIf) -> text }.
    #>
    param([datetime]$NowUtc = [datetime]::UtcNow, [switch]$WhatIf, [object[]]$Rows = $null, [hashtable]$Adapter, [hashtable]$GroupAdapter,
          [scriptblock]$SaveCache, [scriptblock]$SaveInventory, [string]$Netbios = '', [object]$AdModulePresent = $null, [scriptblock]$SecretReader,
          [scriptblock]$ReadSettingText, [scriptblock]$AutoGroups, [scriptblock]$CleanupStep)
    if (-not $Adapter) {
        $cap = Test-PimHybridAdWorkerCapability -AdModulePresent $AdModulePresent -SecretReader $SecretReader
        # not a hybrid worker: the original job answers (its own texts for "nothing to onboard" / "hybrid worker required")
        if (-not $cap.ok) { return (Invoke-PimHybridAdServersJob -NowUtc $NowUtc -WhatIf:$WhatIf -Rows $Rows -AdModulePresent $AdModulePresent -SecretReader $SecretReader) }
        $Adapter = Get-PimHybridAdDiscoveryServerAdapter
        if (-not $GroupAdapter) { $GroupAdapter = Get-PimDefaultActiveDirectoryGroupAdapter }
    }
    $settings = Get-PimHybridAdServerDiscoverySettings -Read $ReadSettingText
    foreach ($p in @($settings.problems)) { Write-Warning "[hybrid-ad-servers] a stored discovery setting is not usable and its default is used (no server gets a group automatically until it is corrected): $p" }
    $raw = @(& $Adapter.GetComputers)
    $inventory = @(Get-PimHybridAdServerInventory -Computers $raw)
    $sel = Select-PimHybridAdServerDiscovery -Inventory $inventory -Settings $settings -NowUtc $NowUtc
    $stamp = [datetime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
    if (-not $SaveInventory) {
        $SaveInventory = {
            param($doc)
            $cs = Get-PimHybridAdStoreCs
            if (-not $cs -or -not (Get-Command Set-PimSqlTenantCache -ErrorAction SilentlyContinue)) { throw 'no SQL store connection' }
            Set-PimSqlTenantCache -ConnectionString $cs -Kind 'ad-servers-inventory' -Value $doc
        }
    }
    $invItems = @($inventory | Select-Object -First 20000)
    try { & $SaveInventory ([ordered]@{ refreshedUtc = $stamp; total = $inventory.Count; truncated = [bool]($inventory.Count -gt $invItems.Count); items = $invItems }) }
    catch { Write-Warning "[hybrid-ad-servers] the server inventory (for the settings preview) was not cached: $($_.Exception.Message)" }

    # what the original job sees: exactly the selected computers
    $byName = @{}; foreach ($s in @($sel.servers)) { $byName[$s.name.ToLowerInvariant()] = $s }
    $script:PimHybridAdDiscoveryPass = @{ computers = @($raw | Where-Object { $_ -and $byName.ContainsKey("$($_.Name)".ToLowerInvariant()) }); byName = $byName; settings = $settings; counts = $sel.counts; stamp = $stamp; saveCache = $SaveCache }
    $inner = @{}; foreach ($k in @($Adapter.Keys)) { $inner[$k] = $Adapter[$k] }
    $inner['GetComputers'] = { @($script:PimHybridAdDiscoveryPass.computers) }
    $save = {
        param($items)
        $p = $script:PimHybridAdDiscoveryPass
        foreach ($it in @($items)) {
            $m = $p.byName["$($it.name)".ToLowerInvariant()]
            $it | Add-Member -NotePropertyName ou -NotePropertyValue $(if ($m) { "$($m.ou)" } else { '' }) -Force
            $it | Add-Member -NotePropertyName autoGroup -NotePropertyValue ([bool]($m -and $m.autoGroup)) -Force
        }
        $doc = [ordered]@{ refreshedUtc = $p.stamp; items = @($items)
            discovery = [ordered]@{ searchOus = @($p.settings.searchOus); excludeOus = @($p.settings.excludeOus); activeDays = [int]$p.settings.activeDays
                nameInclude = @($p.settings.nameInclude); nameExclude = @($p.settings.nameExclude); autoOus = @($p.settings.autoOus); counts = $p.counts; problems = @($p.settings.problems) } }
        if ($p.saveCache) { & $p.saveCache $doc; return }
        $cs = Get-PimHybridAdStoreCs
        if (-not $cs -or -not (Get-Command Set-PimSqlTenantCache -ErrorAction SilentlyContinue)) { throw 'no SQL store connection' }
        Set-PimSqlTenantCache -ConnectionString $cs -Kind 'ad-servers' -Value $doc
    }
    # The original job keeps its own fixed "changed within 90 days" rule. The list it gets is already cut to the customer's
    # N days; for N above 90 the reference time is moved back by the difference so the inner rule does not cut it again.
    $innerNow = $NowUtc
    if ([int]$settings.activeDays -gt 90) { $innerNow = $NowUtc.AddDays( - ([int]$settings.activeDays - 90)) }
    $result = $null; $jobError = $null
    $jobArgs = @{ NowUtc = $innerNow; WhatIf = [bool]$WhatIf; Rows = $Rows; Adapter = $inner; SaveCache = $save; Netbios = $Netbios; AdModulePresent = $AdModulePresent; SecretReader = $SecretReader }
    if ($GroupAdapter) { $jobArgs['GroupAdapter'] = $GroupAdapter }
    try { $result = Invoke-PimHybridAdServersJob @jobArgs } catch { $jobError = $_ }

    $extra = New-Object System.Collections.Generic.List[string]
    $autoFailed = ''
    $c = $sel.counts
    $extra.Add(("discovery: {0} of {1} Windows servers selected (outside the OUs {2}, left-out OUs {3}, not changed within {4} days {5}, name filter {6})" -f $c.selected, $c.total, $c.outsideOus, $c.excludedOu, [int]$settings.activeDays, $c.stale, $c.nameFiltered))
    # decision (12): the automatic groups
    try {
        $ag = if ($AutoGroups) { & $AutoGroups @($sel.servers) $settings ([bool]$WhatIf) } else { Invoke-PimHybridAdServerAutoGroups -Servers @($sel.servers) -Settings $settings -WhatIf:$WhatIf -NowUtc $NowUtc }
        if ($ag) {
            # 🪤 @($null).Count is 1: a result without one of these lists would count as "1 failed" and fail the job. Every
            # list is read through this, which drops the $null (fix round 1).
            $lst = { param($n) @(@($ag[$n]) | Where-Object { $null -ne $_ }) }
            $agCreated = & $lst 'created'; $agFailed = & $lst 'failed'; $agPlanned = & $lst 'planned'; $agSkipped = & $lst 'skipped'; $agNot = & $lst 'notCreated'; $agWait = & $lst 'waiting'
            if ("$($ag.refused)") { $extra.Add("automatic groups: none -- $($ag.refused)") }
            elseif (@($settings.autoOus).Count) {
                $extra.Add(("server groups: defined={0} failed={1} planned={2} left as a proposal={3}" -f $agCreated.Count, $agFailed.Count, $agPlanned.Count, $agSkipped.Count))
                # the approved list in progress: n of m, how long it takes at this batch size
                if ("$($ag.approvalListId)" -and -not $ag.approvalExpired) {
                    $extra.Add(("approved list (by {0}): {1} of {2} created, {3} still to create = about {4} more run(s) at {5} per run{6}" -f $ag.approvedBy, [int]$ag.done, [int]$ag.total, [int]$ag.remaining, [int]$ag.runsLeft, [int]$ag.batchSize,
                            $(if ($agNot.Count) { "; $($agNot.Count) of the list not created (no longer meeting every condition)" } else { '' })))
                } elseif ($ag.approvalExpired) { $extra.Add("the approval by $($ag.approvedBy) is older than 72 hours: what was left of its list waits for a new approval") }
                # the notice for a list that waits: here (the job's detail line) and on the Hybrid Active Directory page -- nowhere else
                if ($agWait.Count) { $extra.Add("WAITING FOR A SUPERADMIN: $($agWait.Count) new server(s) -- nothing is created without an approval of the list (Settings > Hybrid Active Directory)") }
                if ("$($ag.approvalNote)") { $extra.Add("$($ag.approvalNote)") }
            }
            # a definition that could not be written is something the customer must SEE: the job fails with the servers
            # named (the first 20; all of them are in the worker log), and the next run tries them again
            if ($agFailed.Count) { $autoFailed = "automatic groups: $($agFailed.Count) definition(s) could not be written and are tried again in the next run -- " + (@($agFailed | Select-Object -First 20 | ForEach-Object { "$($_.server): $($_.reason)" }) -join '; ') }
        }
    } catch { $extra.Add("automatic groups: not run -- $($_.Exception.Message)") }
    # the approved clean-up: take the group out of its server's local Administrators (PIM-HybridAdCleanup.ps1)
    try {
        $ct = ''
        if ($CleanupStep) { $ct = "$(& $CleanupStep $Adapter $Netbios $inventory ([bool]$WhatIf))" }
        elseif (Get-Command Invoke-PimHybridAdCleanupLocalAdminStep -ErrorAction SilentlyContinue) { $ct = "$((Invoke-PimHybridAdCleanupLocalAdminStep -Adapter $Adapter -Netbios $Netbios -Inventory $inventory -WhatIf:$WhatIf).detail)" }
        if ($ct) { $extra.Add($ct) }
    } catch { $extra.Add("clean-up (local Administrators): not run -- $($_.Exception.Message)") }
    $script:PimHybridAdDiscoveryPass = $null
    $tail = ($extra -join '; ')
    if ($jobError) { throw ("$($jobError.Exception.Message) | $tail$(if ($autoFailed) { " | $autoFailed" })") }
    if ($autoFailed) { throw ("$(if ($result -and $result.PSObject.Properties['detail']) { "$($result.detail); " })$tail | $autoFailed") }
    if ($result -and $result.PSObject.Properties['detail']) { $result.detail = "$($result.detail); $tail" }
    return $result
}
