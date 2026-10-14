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
       publish; downlink; recordedUtc } -- written by the updater (Save-PimInstallNamesRecord) from what it was deployed with
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
    }
}

function Get-PimInstallNameRoles { return @((Get-PimInstallNameDefaults).Keys) }

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
