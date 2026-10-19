#Requires -Version 5.1
<#
  PIM-InstallNames.ps1 -- framework DOCS/REQUIREMENTS.md §12.11c NAMING (CR5) item 6, PIM REQUIREMENTS 100.149:
  EVERY resource / identity name of THIS installation is read from ONE place, never from a literal in code, so the old
  names (every install today) and the new ones (ca-pim-web, ca-pim-engine, ... for NEW installs, a later step) work side
  by side.

  🔒 Owner 2026-10-14: "but remember it must work for existing customers". TODAY'S NAME IS THE DEFAULT: an install with no
  record and no variable resolves exactly the names it runs with now -- no migration, no rename, nothing to set.

  Resolution, per role (first that answers):
    1. the install record: pim.Settings 'InstallNames' { web; engine; updater; asbuilt; asbuiltIdentity; sqlAdminGroup;
       publish; downlink; requests; recordedUtc } -- written by the updater (New-PimInstallNamesRecord) from what it was
       deployed with, and by setup at a new install (CR5 step 2)
    2. the environment variables an install already carries (PIM_ManagerApp, PIM_TickJobName, PIM_UpdateJobName,
       PIM_SqlAdminGroupName, PIM_ENGINE_JOB_NAME, PIM_SQL_ADMIN_GROUP, the tick's id PIM_TickJobId)
    3. today's name (Get-PimInstallNameDefaults)
  A record read that fails is never an error: the next source answers (a name is never blocked by a store read).
  Seams: -Record (a hashtable / object), $global:PIM_InstallNames (preloaded record; tests).
  ASCII only; PS 5.1-safe; pure except the one cached store read.
#>
Set-StrictMode -Off

function Get-PimInstallNameDefaults {
    # PURE. Today's names -- the names every existing install runs with. A literal table in a FUNCTION (the child-scope
    # trap: a $script: table is $null when a caller dot-sources this from another scope).
    return [ordered]@{
        web             = 'ca-pim-manager'
        engine          = 'ca-pim-tick'
        updater         = 'ca-pim-update'
        asbuilt         = 'caj-pim-asbuilt'
        asbuiltIdentity = 'id-pim-asbuilt'
        sqlAdminGroup   = 'grp-pim-sql-admins'
        publish         = 'ca-pim-publish'
        downlink        = 'ca-pim-downlink-s6'
        requests        = 'ca-pim-rfa'
    }
}

function Get-PimInstallNameRoles { return @((Get-PimInstallNameDefaults).Keys) }

# ---- CR5 STEP 2 (framework §12.11c items 2-4, PIM 100.149 step 2) -- THE NEW NAMES, NEW INSTALLS ONLY ---------------------
# Azure cannot rename a container app / job: an EXISTING install keeps today's names for good, and the record (above)
# tells every reader which names it runs with. A NEW install takes these only when setup's switch is on
# (-NewInstallNames / PIM_Setup_NewInstallNames, OFF by default -- with it off setup creates exactly today's names).
function Get-PimInstallNameNewDefaults {
    # PURE. The CR5 names (short code in Azure: ca-pim-<purpose> apps, caj-pim-<purpose> jobs, id-pim-<role> identities,
    # grp-pim-<purpose> groups). The as-built job + identity and the SQL admin group already carry them.
    return [ordered]@{
        web             = 'ca-pim-web'
        engine          = 'ca-pim-engine'
        updater         = 'caj-pim-updater'
        asbuilt         = 'caj-pim-asbuilt'
        asbuiltIdentity = 'id-pim-asbuilt'
        sqlAdminGroup   = 'grp-pim-sql-admins'
        publish         = 'caj-pim-publish'
        downlink        = 'caj-pim-downlink'
        requests        = 'ca-pim-requests'
    }
}

function Get-PimInstallNameSet {
    # PURE. The whole name table for a setup run: -New = the CR5 names, else today's.
    param([switch]$New)
    if ($New) { return (Get-PimInstallNameNewDefaults) }
    return (Get-PimInstallNameDefaults)
}

function Get-PimInstallNameCandidates {
    <#
      PURE. Every name -Role can carry at ANY install (today's first, then the CR5 name) -- for a reader that has no record
      and must FIND the resource (ops / support scripts, name-pattern discovery): an old install answers to the first, a
      new one to the second. -Preferred (a name the caller already knows) goes first.
    #>
    param([Parameter(Mandatory)][string]$Role, [AllowEmptyString()][string]$Preferred = '')
    $d = Get-PimInstallNameDefaults
    if (-not $d.Contains($Role)) { throw "Get-PimInstallNameCandidates: unknown role '$Role' (known: $((Get-PimInstallNameRoles) -join ', '))" }
    $n = Get-PimInstallNameNewDefaults
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($x in @("$Preferred".Trim(), "$($d[$Role])", "$($n[$Role])")) { if ((Test-PimInstallNameValue $x) -and -not $out.Contains($x)) { [void]$out.Add($x) } }
    return @($out.ToArray())
}

function Test-PimInstallNameIsRole {
    # PURE. Is -Name one of the names -Role carries at any install (today's or the CR5 one; case-insensitive)?
    param([Parameter(Mandatory)][string]$Role, [AllowEmptyString()][string]$Name)
    $n = "$Name".Trim(); if (-not $n) { return $false }
    return [bool](@(Get-PimInstallNameCandidates -Role $Role | Where-Object { $_ -ieq $n }).Count)
}

function Get-PimInstallIdentityNames {
    <#
      PURE. framework §12.11c item 3: one identity per role, id-pim-<role>. RECORDED for the owner's CR8 build, NOT created
      by setup: PIM's web app, engine job and updater run as their SYSTEM-assigned identities (an identity Azure names
      after the resource -- ca-pim-web, ca-pim-engine, caj-pim-updater at a new install), and moving them to user-assigned
      identities is the CR8 "one identity per role" change (token by client id, every grant on the new principal).
    #>
    return [ordered]@{ web = 'id-pim-web'; engine = 'id-pim-engine'; updater = 'id-pim-updater'; mcp = 'id-pim-mcp' }
}

function Test-PimNewInstallNamesSwitch {
    <#
      The setup switch for CR5 step 2 (OFF by default). -Explicit (a bound -NewInstallNames / a config value) wins; else
      $env:PIM_Setup_NewInstallNames, else $global:PIM_Setup_NewInstallNames: 1 / true / yes / on = on. Anything else = off.
    #>
    param([AllowNull()][object]$Explicit = $null)
    $on = { param($v) return ("$v".Trim() -match '^(?i)(1|true|yes|on)$') }
    if ($null -ne $Explicit -and "$Explicit".Trim() -ne '') { return [bool](& $on $Explicit) }
    if ("$($env:PIM_Setup_NewInstallNames)".Trim()) { return [bool](& $on $env:PIM_Setup_NewInstallNames) }
    if ($null -ne $global:PIM_Setup_NewInstallNames) { return [bool](& $on $global:PIM_Setup_NewInstallNames) }
    return $false
}

function Resolve-PimSetupInstallNameChoice {
    <#
      PURE. Which name set a setup run uses in ONE resource group, from what is already there (Azure cannot rename):
        today's web app / engine or updater job present -> today's names (an existing install; a requested switch is refused)
        a CR5 web app / engine or updater job present    -> the CR5 names (an install made with them, re-run without the switch)
        nothing of PIM present                           -> what was requested (-RequestNew)
        the resource group could not be read (-ReadOk:$false) and new names requested -> today's names (never guess "new")
      -ExistingApps / -ExistingJobs: the container app / job names in the group. Returns @{ useNew; reason; refused }.
    #>
    param([bool]$RequestNew = $false, [string[]]$ExistingApps = @(), [string[]]$ExistingJobs = @(), [bool]$ReadOk = $true)
    $d = Get-PimInstallNameDefaults; $n = Get-PimInstallNameNewDefaults
    $apps = @(@($ExistingApps) | ForEach-Object { "$_".Trim().ToLowerInvariant() } | Where-Object { $_ })
    $jobs = @(@($ExistingJobs) | ForEach-Object { "$_".Trim().ToLowerInvariant() } | Where-Object { $_ })
    $hasToday = ($apps -contains $d.web) -or ($jobs -contains $d.engine) -or ($jobs -contains $d.updater)
    $hasNew   = ($apps -contains $n.web) -or ($jobs -contains $n.engine) -or ($jobs -contains $n.updater)
    if ($hasToday) {
        if ($RequestNew) { return @{ useNew = $false; refused = $true; reason = "this resource group already runs PIM Manager under today's names ($($d.web) / $($d.engine)) -- Azure cannot rename a container app or job, so the install keeps them" } }
        return @{ useNew = $false; refused = $false; reason = "today's names (an existing install)" }
    }
    if ($hasNew) { return @{ useNew = $true; refused = $false; reason = "this install already runs with the new names ($($n.web) / $($n.engine)) -- kept" } }
    if ($RequestNew -and -not $ReadOk) { return @{ useNew = $false; refused = $true; reason = 'the resource group could not be read, so a new install cannot be proven -- today''s names are used' } }
    if ($RequestNew) { return @{ useNew = $true; refused = $false; reason = 'a new install with the new names (PIM_Setup_NewInstallNames)' } }
    return @{ useNew = $false; refused = $false; reason = "today's names (PIM_Setup_NewInstallNames is off)" }
}

# ---- CR5 ITEM 5 (framework §12.11c item 5) -- THE DISPLAY NAMES PEOPLE READ --------------------------------------------
# "Short code in Azure, full name where people read": the product is PIM Manager, never PIM4EntraPS. These helpers map a
# display name PIM gave an object in earlier releases to the name it carries now, and back -- so every FINDER can look for
# both (an object the update renamed must still be found by the setup scripts, and vice versa). Only names PIM itself gave
# are mapped: a name a customer chose is never one of them. Kept: the mailbox ADDRESS, mailNickname, the Exchange scope.
function Test-PimSenderOldDisplayName {
    # PURE. Is -Name a display name PIM gave a SENDER MAILBOX before the owner's 'PIM Manager' (2026-10-18)?
    # 'PIM4EntraPS Engine (notifications)', 'PIM4EntraPS Engine (<part>, notifications)', and the never-approved
    # 'PIM Manager (notifications)' / 'PIM Manager (<part>, notifications)' that 2.4.647-2.4.650 wrote.
    param([AllowEmptyString()][string]$Name)
    return [bool]("$Name".Trim() -match '^(?i)(PIM4EntraPS Engine|PIM Manager) \((.+, )?notifications\)$')
}

function ConvertTo-PimNewDisplayName {
    # PURE. The display name an object PIM named in an earlier release carries now ('' = not one of PIM's old names).
    param([AllowEmptyString()][string]$Name)
    $s = "$Name".Trim()
    # The SENDER MAILBOX (owner 2026-10-18 ~19:20Z): every one is 'PIM Manager' -- no '(notifications)', no install / ring
    # part; the address tells them apart.
    if (Test-PimSenderOldDisplayName $s) { return 'PIM Manager' }
    if ($s -match '^(?i)PIM4EntraPS Engine(?<r>( .*)?)$')  { return "PIM Manager Engine$($Matches['r'])" }
    if ($s -match '^(?i)PIM4EntraPS Deploy(?<r>( .*)?)$')  { return "PIM Manager Deploy$($Matches['r'])" }
    if ($s -match '^(?i)PIM4EntraPS Manager(?<r>( .*)?)$') { return "PIM Manager$($Matches['r'])" }
    return ''
}

function ConvertTo-PimOldDisplayName {
    # PURE. The earlier-release name of a display name PIM gives now ('' = not one of PIM's names).
    param([AllowEmptyString()][string]$Name)
    $s = "$Name".Trim()
    if ($s -match '^(?i)PIM Manager \(notifications\)$') { return 'PIM4EntraPS Engine (notifications)' }
    if ($s -match '^(?i)PIM Manager Engine(?<r>( .*)?)$')  { return "PIM4EntraPS Engine$($Matches['r'])" }
    if ($s -match '^(?i)PIM Manager Deploy(?<r>( .*)?)$')  { return "PIM4EntraPS Deploy$($Matches['r'])" }
    if ($s -match '^(?i)PIM Manager(?<r>( .*)?)$')         { return "PIM4EntraPS Manager$($Matches['r'])" }
    return ''
}

function Get-PimDisplayNameForms {
    # PURE. -Name and its other form (earlier / current release), -Name first: what a finder searches for.
    param([AllowEmptyString()][string]$Name)
    $s = "$Name".Trim()
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($x in @($s, (ConvertTo-PimNewDisplayName $s), (ConvertTo-PimOldDisplayName $s))) {
        if ("$x".Trim() -and -not @($out | Where-Object { $_ -ieq "$x" }).Count) { [void]$out.Add("$x") }
    }
    return @($out.ToArray())
}

function Test-PimDisplayNameIsNewerForm {
    # PURE. Is -Current the CURRENT form of -Wanted (an old name)? A setup script that still asks for the old name must
    # then leave the object alone -- never rename it back.
    param([AllowEmptyString()][string]$Current, [AllowEmptyString()][string]$Wanted)
    $nw = ConvertTo-PimNewDisplayName $Wanted
    return [bool]($nw -and "$Current".Trim() -ieq $nw)
}

function Test-PimRenameDisplayNamesSwitch {
    <#
      The update's switch for CR5 item 5 (OFF by default until the owner switches it on): -Explicit (a stored setting the
      caller read, pim.Settings 'PIM_Update_RenameDisplayNames') wins; else $env:PIM_Update_RenameDisplayNames, else
      $global:PIM_Update_RenameDisplayNames. 1 / true / yes / on = on.
    #>
    param([AllowNull()][object]$Explicit = $null)
    $on = { param($v) return ("$v".Trim() -match '^(?i)(1|true|yes|on)$') }
    if ($null -ne $Explicit -and "$Explicit".Trim() -ne '') { return [bool](& $on $Explicit) }
    if ("$($env:PIM_Update_RenameDisplayNames)".Trim()) { return [bool](& $on $env:PIM_Update_RenameDisplayNames) }
    if ($null -ne $global:PIM_Update_RenameDisplayNames) { return [bool](& $on $global:PIM_Update_RenameDisplayNames) }
    return $false
}

function Test-PimInstallNameValue {
    # PURE. An Azure resource / group name we accept from a record or a variable: 2-90 of letters, digits, '-', '_', '.'.
    param([AllowNull()][string]$Value)
    return [bool]("$Value".Trim() -match '^[A-Za-z0-9][A-Za-z0-9._-]{1,89}$')
}

function Get-PimInstallNameFromEnvironment {
    # The value an existing install carries in its environment for -Role ('' = none). The tick's id (/.../jobs/<name>)
    # names the engine too.
    param([Parameter(Mandatory)][string]$Role)
    $vars = switch ($Role) {
        'web'           { @('PIM_ManagerApp') }
        'engine'        { @('PIM_TickJobName', 'PIM_ENGINE_JOB_NAME') }
        'updater'       { @('PIM_UpdateJobName') }
        'sqlAdminGroup' { @('PIM_SqlAdminGroupName', 'PIM_SQL_ADMIN_GROUP') }
        default         { @() }
    }
    foreach ($v in $vars) { $x = "$([Environment]::GetEnvironmentVariable($v))".Trim(); if (Test-PimInstallNameValue $x) { return $x } }
    if ($Role -eq 'engine') {
        $id = "$env:PIM_TickJobId".Trim()
        $m = [regex]::Match($id, '(?i)/providers/Microsoft\.App/jobs/([^/]+)$')
        if ($m.Success -and (Test-PimInstallNameValue $m.Groups[1].Value)) { return $m.Groups[1].Value }
    }
    return ''
}

function Get-PimInstallNamesRecord {
    <#
      The stored install record (pim.Settings 'InstallNames'), read ONCE per process and cached; $null when there is none
      or it cannot be read (never throws). $global:PIM_InstallNames, when set, is the record (preloaded / tests).
      -Refresh reads again.
    #>
    param([switch]$Refresh)
    if ($null -ne $global:PIM_InstallNames) { return $global:PIM_InstallNames }
    if (-not $Refresh -and $script:PimInstallNamesRead) { return $script:PimInstallNamesCache }
    $rec = $null
    try {
        $cs = $null
        if ("$($global:PIM_EngineSqlCs)".Trim()) { $cs = "$($global:PIM_EngineSqlCs)" }
        elseif (Get-Command Get-PimSqlSettingsConnectionString -ErrorAction SilentlyContinue) { $cs = Get-PimSqlSettingsConnectionString }
        if ("$cs".Trim() -and (Get-Command Get-PimSqlSetting -ErrorAction SilentlyContinue)) {
            $rec = Get-PimSqlSetting -ConnectionString $cs -Name 'InstallNames'
            if ($rec -is [string]) { try { $rec = $rec | ConvertFrom-Json } catch { $rec = $null } }
        }
    } catch { $rec = $null }
    $script:PimInstallNamesCache = $rec
    $script:PimInstallNamesRead = $true
    return $rec
}

function Get-PimInstallName {
    <#
      THE name of one part of this installation. -Role: web | engine | updater | asbuilt | asbuiltIdentity | sqlAdminGroup |
      publish | downlink. Record -> environment -> today's name (see the header). -Record overrides the stored record
      (a caller that already holds it; tests). Never throws for a known role; an unknown role throws (a typo must not
      silently become someone else's resource).
    #>
    param([Parameter(Mandatory)][string]$Role, [AllowNull()][object]$Record = $null, [switch]$NoRecord)
    $defaults = Get-PimInstallNameDefaults
    if (-not $defaults.Contains($Role)) { throw "Get-PimInstallName: unknown role '$Role' (known: $((Get-PimInstallNameRoles) -join ', '))" }
    $rec = if ($NoRecord) { $null } elseif ($null -ne $Record) { $Record } else { Get-PimInstallNamesRecord }
    if ($null -ne $rec) {
        $v = ''
        if ($rec -is [System.Collections.IDictionary]) { if ($rec.Contains($Role)) { $v = "$($rec[$Role])".Trim() } }
        elseif ($rec.PSObject.Properties[$Role]) { $v = "$($rec.$Role)".Trim() }
        if (Test-PimInstallNameValue $v) { return $v }
    }
    $e = Get-PimInstallNameFromEnvironment -Role $Role
    if ($e) { return $e }
    return [string]$defaults[$Role]
}

function New-PimInstallNamesRecord {
    <#
      PURE. The record the updater stores: -Names (role -> name; empty / invalid left out) merged over -Current (what is
      stored). A role the caller does not know keeps its stored value. Returns @{ record; changed }.
    #>
    param([hashtable]$Names = @{}, [AllowNull()][object]$Current = $null, [datetime]$NowUtc = [datetime]::UtcNow)
    $out = [ordered]@{}
    foreach ($r in (Get-PimInstallNameRoles)) {
        $cur = ''
        if ($null -ne $Current) {
            if ($Current -is [System.Collections.IDictionary]) { if ($Current.Contains($r)) { $cur = "$($Current[$r])".Trim() } }
            elseif ($Current.PSObject.Properties[$r]) { $cur = "$($Current.$r)".Trim() }
        }
        $new = if ($Names.ContainsKey($r)) { "$($Names[$r])".Trim() } else { '' }
        if (Test-PimInstallNameValue $new) { $out[$r] = $new } elseif (Test-PimInstallNameValue $cur) { $out[$r] = $cur }
    }
    $changed = $false
    foreach ($r in @($out.Keys)) {
        $cur = ''
        if ($null -ne $Current) {
            if ($Current -is [System.Collections.IDictionary]) { if ($Current.Contains($r)) { $cur = "$($Current[$r])".Trim() } }
            elseif ($Current.PSObject.Properties[$r]) { $cur = "$($Current.$r)".Trim() }
        }
        if ($cur -ne $out[$r]) { $changed = $true }
    }
    $out['recordedUtc'] = $NowUtc.ToUniversalTime().ToString('o')
    return @{ record = $out; changed = $changed }
}
