#Requires -Version 5.1
<#
.SYNOPSIS
    Open the PIM4EntraPS graph mapper (v0.2 -- editor).

.DESCRIPTION
    Reads the 14 Definition + Assignment CSVs under SOLUTIONS/PIM4EntraPS/config/,
    transforms them into a node/edge JSON model, and serves them through a
    local HTTP API to a small single-page editor.

    Two run modes:

      -Server (default)
          Starts a localhost-only HttpListener on a random free port,
          serves the SPA, exposes REST endpoints for grid editing and
          save-back. The server lives only while the browser tab is open
          (30-second heartbeat timeout) and only accepts requests carrying
          a per-session bearer token generated at launch.

      -StaticHtml
          Preserves the v0.1 behaviour: bakes the JSON into the HTML and
          writes it to a temp file (or -OutHtml). No server, no edit
          capability, no token. Useful for archival snapshots.

    All writes go to <base>.custom.csv (the customer-override file, gitignored).
    The shipped <base>.locked.csv is never touched.

.PARAMETER Server
    Default. Start the local editor server.

.PARAMETER StaticHtml
    Render the v0.1-style static HTML and open it (read-only viewer).

.PARAMETER OutHtml
    Only honoured under -StaticHtml. Optional path for the rendered HTML.
    Defaults to a temp file.

.PARAMETER NoLaunch
    Don't open the browser. Print the URL (server mode) or path (static
    mode) to stdout. Useful for headless / smoke tests.

.PARAMETER Port
    Force a specific port instead of picking a random free one. The
    server still binds to 127.0.0.1 only. Optional.

.EXAMPLE
    .\Open-PimManager.ps1
    # Default: server mode, random port, opens browser.

.EXAMPLE
    .\Open-PimManager.ps1 -StaticHtml -NoLaunch -OutHtml C:\temp\snap.html

.NOTES
    Security model (server mode):
      * Listener binds 127.0.0.1 only -- never reachable from another host.
      * A random per-session bearer token (new GUID at every start) is
        embedded in the served HTML and required on every /api/* call.
        Without the token, the API returns 401.
      * Server self-terminates after 30 seconds without a /api/heartbeat
        ping -- closing the browser tab kills the process.
      * No third-party deps; pure .NET HttpListener + System.IO.

    PowerShell 5.1 compatible. Cytoscape + dagre are CDN-loaded by the HTML
    (same as v0.1).
#>
[CmdletBinding(DefaultParameterSetName='Server')]
param(
    [Parameter(ParameterSetName='Server')]
    [switch]$Server,

    [Parameter(ParameterSetName='Static')]
    [switch]$StaticHtml,

    [Parameter(ParameterSetName='Static')]
    [string]$OutHtml,

    [switch]$NoLaunch,

    [Parameter(ParameterSetName='Server')]
    [int]$Port = 0,

    # CLI mode: refresh the tenant-list cache (entra-roles, AUs, PIM groups,
    # azure scopes) by calling Microsoft Graph + Az with the engine SPN, then
    # exit. Does NOT start the server or open a browser. Use this in a
    # scheduled task or from a customer bootstrap before launching the UI.
    [Parameter(ParameterSetName='Refresh')]
    [switch]$RefreshTenantLists
)

$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Paths + constants
# ---------------------------------------------------------------------------

$solutionRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)  # ...\PIM4EntraPS
$configRoot   = Join-Path $solutionRoot 'config'
$outputRoot   = Join-Path $solutionRoot 'output'
$template     = Join-Path $PSScriptRoot 'pim-manager.html'
$tenantSync   = Join-Path $PSScriptRoot '_tenantSync.ps1'
$validator    = Join-Path $PSScriptRoot '_validator.ps1'
$mutationLog  = Join-Path $outputRoot 'pim-manager-mutations.log'

if (-not (Test-Path -LiteralPath $configRoot)) { throw "Config folder not found: $configRoot" }
if (-not (Test-Path -LiteralPath $template))   { throw "Template not found: $template" }
if (-not (Test-Path -LiteralPath $outputRoot)) { New-Item -ItemType Directory -Path $outputRoot -Force | Out-Null }
if (Test-Path -LiteralPath $tenantSync) { . $tenantSync }
if (Test-Path -LiteralPath $validator)  { . $validator }

# The 14 CSV bases the mapper edits, in stable UI order, with their default
# headers used when creating a brand-new .custom.csv.
$script:PimCsvBases = @(
    [ordered]@{ base = 'Account-Definitions-Admins';      group = 'Definitions';  defaultHeader = @('FirstName','LastName','Initials','TierLevel','TargetUsage','TargetPlatform','UserType','UserName','DisplayName','UserPrincipalName','UsageLocation','ForwardMailsToContact','MailForwardAddress','CreateTAP','TAPStartDate') },
    [ordered]@{ base = 'PIM-Definitions-Roles';           group = 'Definitions';  defaultHeader = @('GroupName','GroupDescription','GroupTag','AdministrativeUnitTag','CPPlatform','Plane','TierLevel','PermissionScope','SyncPlatform','IsRoleAssignable') },
    [ordered]@{ base = 'PIM-Definitions-Tasks';           group = 'Definitions';  defaultHeader = @('GroupName','GroupDescription','GroupTag','AdministrativeUnitTag','IsRoleAssignable','Workload','Level','TierLevel','Plane','CPPlatform','Owners') },
    [ordered]@{ base = 'PIM-Definitions-Services';        group = 'Definitions';  defaultHeader = @('GroupName','GroupDescription','GroupTag','AdministrativeUnitTag','IsRoleAssignable','Workload','Level','TierLevel','Plane','CPPlatform','Owners') },
    [ordered]@{ base = 'PIM-Definitions-Processes';       group = 'Definitions';  defaultHeader = @('GroupName','GroupDescription','GroupTag','AdministrativeUnitTag','IsRoleAssignable','Workload','Level','TierLevel','Plane','CPPlatform','Owners') },
    [ordered]@{ base = 'PIM-Definitions-Resources';       group = 'Definitions';  defaultHeader = @('GroupName','GroupDescription','GroupTag','AdministrativeUnitTag','IsRoleAssignable','Workload','Level','TierLevel','Plane','CPPlatform','Owners') },
    [ordered]@{ base = 'PIM-Definitions-Departments';     group = 'Definitions';  defaultHeader = @('GroupName','GroupDescription','GroupTag','AdministrativeUnitTag','IsRoleAssignable','Workload','Level','TierLevel','Plane','CPPlatform','Owners') },
    [ordered]@{ base = 'PIM-Definitions-Organization';    group = 'Definitions';  defaultHeader = @('GroupName','GroupDescription','GroupTag','AdministrativeUnitTag','IsRoleAssignable','Workload','Level','TierLevel','Plane','CPPlatform','Owners') },
    [ordered]@{ base = 'PIM-Definitions-AU';              group = 'Definitions';  defaultHeader = @('AUDisplayName','AUDescription','AdministrativeUnitTag','Workload','Level','TierLevel','Visibility') },
    [ordered]@{ base = 'PIM-Assignments-Admins';          group = 'Assignments';  defaultHeader = @('Username','GroupTag','AssignmentType','Action','UpdateExisting','AutoExtend','NumOfDaysWhenExpire','Permanent','CPPlatform','Plane','TierLevel','PermissionScope','SyncPlatform') },
    [ordered]@{ base = 'PIM-Assignments-Groups';          group = 'Assignments';  defaultHeader = @('TargetGroupTag','SourceGroupTag','AssignmentType','Action','UpdateExisting','AutoExtend','NumOfDaysWhenExpire','Permanent','CPPlatform','Plane','TierLevel','PermissionScope','SyncPlatform') },
    [ordered]@{ base = 'PIM-Assignments-Roles-Groups';    group = 'Assignments';  defaultHeader = @('GroupTag','RoleDefinitionName','AssignmentType','Action','UpdateExisting','AutoExtend','NumOfDaysWhenExpire','Permanent','CPPlatform','Plane','TierLevel','PermissionScope','SyncPlatform') },
    [ordered]@{ base = 'PIM-Assignments-Roles-AUs';       group = 'Assignments';  defaultHeader = @('GroupTag','AdministrativeUnitTag','RoleDefinitionName','AssignmentType','Action','UpdateExisting','AutoExtend','NumOfDaysWhenExpire','Permanent','CPPlatform','Plane','TierLevel','PermissionScope','SyncPlatform') },
    [ordered]@{ base = 'PIM-Assignments-Azure-Resources'; group = 'Assignments';  defaultHeader = @('GroupTag','AzScope','AzScopePermission','AssignmentType','Action','UpdateExisting','AutoExtend','NumOfDaysWhenExpire','Permanent','CPPlatform','Plane','TierLevel','PermissionScope','SyncPlatform') }
)

# ---------------------------------------------------------------------------
# CSV I/O helpers
# ---------------------------------------------------------------------------

function Get-PimCsvBases {
    return ,$script:PimCsvBases
}

function Get-PimCsvSpec {
    param([Parameter(Mandatory)][string]$BaseName)
    foreach ($spec in $script:PimCsvBases) {
        if ($spec.base -eq $BaseName) { return $spec }
    }
    return $null
}

function Resolve-PimCsvPath {
    # Customer override (.custom.csv) wins; fall back to shipped default (.locked.csv).
    param([Parameter(Mandatory)][string]$BaseName)
    $custom = Join-Path $configRoot "$BaseName.custom.csv"
    $locked = Join-Path $configRoot "$BaseName.locked.csv"
    if (Test-Path -LiteralPath $custom) { return [pscustomobject]@{ Path = $custom; Source = 'custom' } }
    if (Test-Path -LiteralPath $locked) { return [pscustomobject]@{ Path = $locked; Source = 'locked' } }
    return $null
}

function Read-PimCsvRows {
    # Returns hashtable: @{ header = string[]; rows = ordered[]; source = 'custom'|'locked'|'none'; path = string }
    param([Parameter(Mandatory)][string]$BaseName)
    $resolved = Resolve-PimCsvPath -BaseName $BaseName
    $spec = Get-PimCsvSpec -BaseName $BaseName
    if (-not $resolved) {
        $hdr = if ($spec) { $spec.defaultHeader } else { @() }
        return @{ header = $hdr; rows = @(); source = 'none'; path = (Join-Path $configRoot "$BaseName.custom.csv") }
    }
    # Read the raw file to recover the original header (Import-Csv mangles trailing empty columns).
    $raw = [System.IO.File]::ReadAllText($resolved.Path, [System.Text.UTF8Encoding]::new($true))
    # Strip BOM if present.
    if ($raw.Length -gt 0 -and [int][char]$raw[0] -eq 0xFEFF) { $raw = $raw.Substring(1) }
    $lines = $raw -split "(`r`n|`n|`r)" | Where-Object { $_ -and $_ -notmatch '^(\r\n|\n|\r)$' }
    if (-not $lines -or $lines.Count -eq 0) {
        $hdr = if ($spec) { $spec.defaultHeader } else { @() }
        return @{ header = $hdr; rows = @(); source = $resolved.Source; path = $resolved.Path }
    }
    $headerLine = $lines[0]
    $headerCols = $headerLine -split ';'
    # Drop trailing empty header columns (matches what users actually edit).
    while ($headerCols.Count -gt 0 -and [string]::IsNullOrEmpty($headerCols[$headerCols.Count - 1])) {
        $headerCols = $headerCols[0..($headerCols.Count - 2)]
    }
    if ($headerCols.Count -eq 0 -and $spec) { $headerCols = $spec.defaultHeader }

    $rows = New-Object System.Collections.ArrayList
    foreach ($r in (Import-Csv -Path $resolved.Path -Delimiter ';' -Encoding UTF8)) {
        # Drop blank rows (every column null/empty).
        $hasAny = $false
        foreach ($p in $r.PSObject.Properties) { if ($null -ne $p.Value -and "$($p.Value)".Length -gt 0) { $hasAny = $true; break } }
        if (-not $hasAny) { continue }
        $obj = [ordered]@{}
        foreach ($col in $headerCols) {
            $val = $null
            $prop = $r.PSObject.Properties[$col]
            if ($prop) { $val = $prop.Value }
            if ($null -eq $val) { $val = '' }
            $obj[$col] = "$val"
        }
        [void]$rows.Add($obj)
    }
    return @{ header = $headerCols; rows = $rows.ToArray(); source = $resolved.Source; path = $resolved.Path }
}

function Write-PimCsvCustom {
    # Atomic write to <base>.custom.csv. Preserves header order; appends new columns at end.
    # Returns hashtable with path + counts.
    param(
        [Parameter(Mandatory)][string]$BaseName,
        [Parameter(Mandatory)][object[]]$Rows
    )
    $spec = Get-PimCsvSpec -BaseName $BaseName
    if (-not $spec) { throw "Unknown CSV base name: $BaseName" }
    $current = Read-PimCsvRows -BaseName $BaseName
    $header = New-Object System.Collections.ArrayList
    foreach ($h in $current.header) { [void]$header.Add($h) }
    # Add any extra columns the client introduced, append at end (stable order from first occurrence).
    foreach ($row in $Rows) {
        if ($null -eq $row) { continue }
        $props = @()
        if ($row -is [System.Collections.IDictionary]) { $props = @($row.Keys) }
        else { $props = @($row.PSObject.Properties.Name) }
        foreach ($k in $props) {
            if (-not ($header -contains $k)) { [void]$header.Add($k) }
        }
    }

    # Build CSV text. Always ';' delimiter, UTF-8 no BOM. Quote any field
    # that contains ';', '"', CR or LF; double internal quotes.
    $sb = New-Object System.Text.StringBuilder
    $headerLine = ($header | ForEach-Object { Format-PimCsvField $_ }) -join ';'
    [void]$sb.AppendLine($headerLine)
    foreach ($row in $Rows) {
        if ($null -eq $row) { continue }
        $vals = New-Object System.Collections.ArrayList
        foreach ($col in $header) {
            $v = ''
            if ($row -is [System.Collections.IDictionary]) {
                if ($row.Contains($col)) { $v = "$($row[$col])" }
            } else {
                $p = $row.PSObject.Properties[$col]
                if ($p) { $v = "$($p.Value)" }
            }
            [void]$vals.Add((Format-PimCsvField $v))
        }
        [void]$sb.AppendLine(($vals -join ';'))
    }

    $finalPath = Join-Path $configRoot "$BaseName.custom.csv"
    $tmpPath   = "$finalPath.tmp"
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    # Strip the trailing newline AppendLine introduces, then re-add a single
    # platform newline so the file ends with exactly one EOL.
    $text = $sb.ToString().TrimEnd("`r", "`n") + "`r`n"
    [System.IO.File]::WriteAllText($tmpPath, $text, $utf8NoBom)
    Move-Item -LiteralPath $tmpPath -Destination $finalPath -Force

    return @{ path = $finalPath; rowCount = $Rows.Count; header = $header.ToArray() }
}

function Format-PimCsvField {
    param([Parameter(Mandatory=$false)][AllowNull()][AllowEmptyString()][string]$Value)
    if ($null -eq $Value) { return '' }
    if ($Value -match '[;"\r\n]') {
        return '"' + ($Value -replace '"','""') + '"'
    }
    return $Value
}

function Compare-PimRowSets {
    # Per-row diff between two row arrays. Identity = full row content (ordered dict equality).
    # Returns @{ adds = [...]; removes = [...]; modifies = [{ before, after, diffCols }] }.
    # 'modifies' is computed by aligning leftover adds + removes positionally,
    # since CSV rows have no stable primary key. Acceptable: the diff view is
    # advisory; the user's authority is the final row set, not the diff.
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Before,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$After
    )

    function _RowKey([object]$row) {
        if ($null -eq $row) { return '' }
        $kvs = @()
        if ($row -is [System.Collections.IDictionary]) {
            foreach ($k in ($row.Keys | Sort-Object)) {
                $kvs += "$k=$($row[$k])"
            }
        } else {
            foreach ($p in ($row.PSObject.Properties | Sort-Object Name)) {
                $kvs += "$($p.Name)=$($p.Value)"
            }
        }
        return ($kvs -join ([char]1))
    }

    $beforeMap = @{}
    foreach ($r in $Before) {
        $k = _RowKey $r
        if (-not $beforeMap.ContainsKey($k)) { $beforeMap[$k] = New-Object System.Collections.ArrayList }
        [void]$beforeMap[$k].Add($r)
    }
    $afterMap = @{}
    foreach ($r in $After) {
        $k = _RowKey $r
        if (-not $afterMap.ContainsKey($k)) { $afterMap[$k] = New-Object System.Collections.ArrayList }
        [void]$afterMap[$k].Add($r)
    }

    $unchanged = 0
    $adds = New-Object System.Collections.ArrayList
    $removes = New-Object System.Collections.ArrayList
    foreach ($r in $After) {
        $k = _RowKey $r
        if ($beforeMap.ContainsKey($k) -and $beforeMap[$k].Count -gt 0) {
            $beforeMap[$k].RemoveAt(0)
            $unchanged++
        } else {
            [void]$adds.Add($r)
        }
    }
    foreach ($k in $beforeMap.Keys) {
        foreach ($r in $beforeMap[$k]) { [void]$removes.Add($r) }
    }

    # Pair leftover adds + removes positionally to surface column-level modifies.
    # NOTE: avoid local variable names $before / $after -- they case-insensitively
    # shadow the typed params $Before / $After ([object[]]), and PowerShell would
    # coerce any subsequent assignment back to [object[]], wrapping an
    # OrderedDictionary into a 1-element array. Use $beforeRow / $afterRow.
    $modifies = New-Object System.Collections.ArrayList
    $pairs = [Math]::Min($adds.Count, $removes.Count)
    for ($i = 0; $i -lt $pairs; $i++) {
        $beforeRow = $removes[0]
        $afterRow  = $adds[0]
        $removes.RemoveAt(0); $adds.RemoveAt(0)
        $diffCols = New-Object System.Collections.ArrayList
        $allCols = @()
        if ($beforeRow -is [System.Collections.IDictionary]) { $allCols += @($beforeRow.Keys) } else { $allCols += @($beforeRow.PSObject.Properties.Name) }
        if ($afterRow  -is [System.Collections.IDictionary]) { $allCols += @($afterRow.Keys)  } else { $allCols += @($afterRow.PSObject.Properties.Name) }
        $allCols = $allCols | Select-Object -Unique
        foreach ($c in $allCols) {
            $bv = if ($beforeRow -is [System.Collections.IDictionary]) { "$($beforeRow[$c])" } else { "$($beforeRow.PSObject.Properties[$c].Value)" }
            $av = if ($afterRow  -is [System.Collections.IDictionary]) { "$($afterRow[$c])"  } else { "$($afterRow.PSObject.Properties[$c].Value)" }
            if ($bv -ne $av) { [void]$diffCols.Add($c) }
        }
        [void]$modifies.Add([ordered]@{ before = $beforeRow; after = $afterRow; diffCols = $diffCols.ToArray() })
    }

    return @{
        adds      = $adds.ToArray()
        removes   = $removes.ToArray()
        modifies  = $modifies.ToArray()
        unchanged = $unchanged
    }
}

function Write-PimMutationLog {
    param(
        [Parameter(Mandatory)][string]$BaseName,
        [Parameter(Mandatory)][int]$Adds,
        [Parameter(Mandatory)][int]$Removes,
        [Parameter(Mandatory)][int]$Modifies,
        [Parameter(Mandatory)][int]$NewRowCount
    )
    $ts = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    $line = "$ts`t$BaseName`t$Adds`t$Removes`t$Modifies`t$NewRowCount"
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    # AppendAllText creates the file if missing, no BOM, UTF-8.
    [System.IO.File]::AppendAllText($mutationLog, ($line + "`r`n"), $utf8NoBom)
}

# ---------------------------------------------------------------------------
# Naming conventions (read .locked then overlay .custom, so the UI sees what
# the engines would see). Best-effort: returns defaults if the files can't
# be sourced (e.g. running outside the repo layout).
# ---------------------------------------------------------------------------

function Get-PimNamingConventions {
    $defaults = @{
        AdminAccountPattern           = 'adm_{Owner}'
        AdminAccountUpnSuffix         = $null
        PimGroupPattern               = 'PIM_{Role}_{Department}'
        PimGroupAuPattern             = 'PIM_{Role}_AU_{AdminUnit}'
        ResourceGroupPattern          = 'rg-pim-{Tier}'
        AdminAccountDisplayNameSuffix = ' (Admin)'
    }
    # Source .locked then .custom into a fresh scope so we don't pollute the
    # server runspace's $global state on every call.
    $files = @(
        (Join-Path $configRoot 'PIM4EntraPS.NamingConventions.locked.ps1'),
        (Join-Path $configRoot 'PIM4EntraPS.NamingConventions.custom.ps1')
    )
    foreach ($f in $files) {
        if (Test-Path -LiteralPath $f) {
            try { . $f } catch { Write-Warning "  failed to source $f : $($_.Exception.Message)" }
        }
    }
    if ($global:PIM_NamingConventions) {
        # Overlay any keys actually set, else fall back to defaults.
        foreach ($k in @($defaults.Keys)) {
            if ($global:PIM_NamingConventions.ContainsKey($k)) {
                $defaults[$k] = $global:PIM_NamingConventions[$k]
            }
        }
        foreach ($k in $global:PIM_NamingConventions.Keys) {
            if (-not $defaults.ContainsKey($k)) { $defaults[$k] = $global:PIM_NamingConventions[$k] }
        }
    }
    return $defaults
}

# ---------------------------------------------------------------------------
# Graph builder (same shape as v0.1, freshly recomputed each call)
# ---------------------------------------------------------------------------

function Build-PimGraphData {
    $admins        = (Read-PimCsvRows 'Account-Definitions-Admins').rows

    $defRoles      = (Read-PimCsvRows 'PIM-Definitions-Roles').rows
    $defTasks      = (Read-PimCsvRows 'PIM-Definitions-Tasks').rows
    $defServices   = (Read-PimCsvRows 'PIM-Definitions-Services').rows
    $defProcesses  = (Read-PimCsvRows 'PIM-Definitions-Processes').rows
    $defResources  = (Read-PimCsvRows 'PIM-Definitions-Resources').rows
    $defDepts      = (Read-PimCsvRows 'PIM-Definitions-Departments').rows
    $defAUs        = (Read-PimCsvRows 'PIM-Definitions-AU').rows
    $defOrg        = (Read-PimCsvRows 'PIM-Definitions-Organization').rows

    $asgnAdmins    = (Read-PimCsvRows 'PIM-Assignments-Admins').rows
    $asgnGroups    = (Read-PimCsvRows 'PIM-Assignments-Groups').rows
    $asgnRolesGrp  = (Read-PimCsvRows 'PIM-Assignments-Roles-Groups').rows
    $asgnRolesAU   = (Read-PimCsvRows 'PIM-Assignments-Roles-AUs').rows
    $asgnAzRes     = (Read-PimCsvRows 'PIM-Assignments-Azure-Resources').rows

    $nodes = New-Object System.Collections.ArrayList
    $edges = New-Object System.Collections.ArrayList

    foreach ($a in $admins) {
        if (-not $a.UserPrincipalName) { continue }
        [void]$nodes.Add([ordered]@{
            id       = $a.UserPrincipalName
            label    = $a.DisplayName
            kind     = 'admin'
            tier     = $a.TierLevel
            platform = $a.TargetPlatform
            source   = 'Account-Definitions-Admins'
        })
    }

    $groupSources = @(
        @{ list = $defRoles;     kind = 'role-group';       source = 'PIM-Definitions-Roles' },
        @{ list = $defTasks;     kind = 'permission-group'; source = 'PIM-Definitions-Tasks' },
        @{ list = $defServices;  kind = 'permission-group'; source = 'PIM-Definitions-Services' },
        @{ list = $defProcesses; kind = 'permission-group'; source = 'PIM-Definitions-Processes' },
        @{ list = $defResources; kind = 'permission-group'; source = 'PIM-Definitions-Resources' },
        @{ list = $defDepts;     kind = 'permission-group'; source = 'PIM-Definitions-Departments' },
        @{ list = $defOrg;       kind = 'permission-group'; source = 'PIM-Definitions-Organization' }
    )
    foreach ($src in $groupSources) {
        foreach ($g in $src.list) {
            if (-not $g.GroupTag) { continue }
            [void]$nodes.Add([ordered]@{
                id          = "group:$($g.GroupTag)"
                label       = $g.GroupName
                kind        = $src.kind
                tier        = $g.TierLevel
                level       = $g.Level
                description = $g.GroupDescription
                source      = $src.source
                groupTag    = $g.GroupTag
            })
        }
    }

    foreach ($au in $defAUs) {
        $tag = $null
        if ($au.AdministrativeUnitTag) { $tag = $au.AdministrativeUnitTag }
        elseif ($au.AUTag) { $tag = $au.AUTag }
        elseif ($au.Tag)   { $tag = $au.Tag }
        if (-not $tag) { continue }
        [void]$nodes.Add([ordered]@{
            id          = "au:$tag"
            label       = if ($au.AUDisplayName) { $au.AUDisplayName } else { $tag }
            kind        = 'au'
            description = $au.AUDescription
            source      = 'PIM-Definitions-AU'
            auTag       = $tag
        })
    }

    $syntheticTargets = @{}
    $addSyn = {
        param($Id, $Label, $Kind, $Source)
        if ($syntheticTargets.ContainsKey($Id)) { return }
        $syntheticTargets[$Id] = [ordered]@{ id = $Id; label = $Label; kind = $Kind; source = $Source }
    }

    foreach ($r in $asgnAdmins) {
        if (-not $r.Username -or -not $r.GroupTag) { continue }
        [void]$edges.Add([ordered]@{
            source = $r.Username
            target = "group:$($r.GroupTag)"
            type   = $r.AssignmentType
            kind   = 'admin-to-group'
            source_csv = 'PIM-Assignments-Admins'
            match = [ordered]@{ Username = $r.Username; GroupTag = $r.GroupTag; AssignmentType = $r.AssignmentType }
        })
    }
    foreach ($r in $asgnGroups) {
        if (-not $r.SourceGroupTag -or -not $r.TargetGroupTag) { continue }
        [void]$edges.Add([ordered]@{
            source = "group:$($r.TargetGroupTag)"
            target = "group:$($r.SourceGroupTag)"
            type   = $r.AssignmentType
            kind   = 'group-to-group'
            source_csv = 'PIM-Assignments-Groups'
            match = [ordered]@{ TargetGroupTag = $r.TargetGroupTag; SourceGroupTag = $r.SourceGroupTag; AssignmentType = $r.AssignmentType }
        })
    }
    foreach ($r in $asgnRolesGrp) {
        if (-not $r.GroupTag -or -not $r.RoleDefinitionName) { continue }
        $targetId = "entra-role:$($r.RoleDefinitionName)"
        & $addSyn $targetId $r.RoleDefinitionName 'entra-role' 'PIM-Assignments-Roles-Groups'
        [void]$edges.Add([ordered]@{
            source = "group:$($r.GroupTag)"
            target = $targetId
            type   = $r.AssignmentType
            kind   = 'group-to-entra-role'
            source_csv = 'PIM-Assignments-Roles-Groups'
            match = [ordered]@{ GroupTag = $r.GroupTag; RoleDefinitionName = $r.RoleDefinitionName; AssignmentType = $r.AssignmentType }
        })
    }
    foreach ($r in $asgnRolesAU) {
        if (-not $r.GroupTag -or -not $r.RoleDefinitionName -or -not $r.AdministrativeUnitTag) { continue }
        $targetId = "au-role:$($r.AdministrativeUnitTag):$($r.RoleDefinitionName)"
        $label    = "$($r.RoleDefinitionName) @ AU:$($r.AdministrativeUnitTag)"
        & $addSyn $targetId $label 'au-role' 'PIM-Assignments-Roles-AUs'
        [void]$edges.Add([ordered]@{
            source = "group:$($r.GroupTag)"
            target = $targetId
            type   = $r.AssignmentType
            kind   = 'group-to-au-role'
            source_csv = 'PIM-Assignments-Roles-AUs'
            match = [ordered]@{ GroupTag = $r.GroupTag; AdministrativeUnitTag = $r.AdministrativeUnitTag; RoleDefinitionName = $r.RoleDefinitionName; AssignmentType = $r.AssignmentType }
        })
        [void]$edges.Add([ordered]@{
            source = "au:$($r.AdministrativeUnitTag)"
            target = $targetId
            type   = ''
            kind   = 'au-to-au-role'
            source_csv = 'PIM-Assignments-Roles-AUs'
            match = [ordered]@{ GroupTag = $r.GroupTag; AdministrativeUnitTag = $r.AdministrativeUnitTag; RoleDefinitionName = $r.RoleDefinitionName }
            cosmetic = $true
        })
    }
    foreach ($r in $asgnAzRes) {
        if (-not $r.GroupTag -or -not $r.AzScope -or -not $r.AzScopePermission) { continue }
        $targetId = "az-res:$($r.AzScope):$($r.AzScopePermission)"
        $shortScope = ($r.AzScope -split '/') | Select-Object -Last 1
        $label    = "$($r.AzScopePermission) @ $shortScope"
        & $addSyn $targetId $label 'az-resource' 'PIM-Assignments-Azure-Resources'
        [void]$edges.Add([ordered]@{
            source = "group:$($r.GroupTag)"
            target = $targetId
            type   = $r.AssignmentType
            kind   = 'group-to-az-resource'
            source_csv = 'PIM-Assignments-Azure-Resources'
            match = [ordered]@{ GroupTag = $r.GroupTag; AzScope = $r.AzScope; AzScopePermission = $r.AzScopePermission; AssignmentType = $r.AssignmentType }
        })
    }

    foreach ($t in $syntheticTargets.Values) { [void]$nodes.Add($t) }

    $summary = [ordered]@{
        nodes  = $nodes.Count
        edges  = $edges.Count
        admins = @($nodes | Where-Object { $_.kind -eq 'admin' }).Count
        roleGroups       = @($nodes | Where-Object { $_.kind -eq 'role-group' }).Count
        permissionGroups = @($nodes | Where-Object { $_.kind -eq 'permission-group' }).Count
        targets          = @($nodes | Where-Object { $_.kind -in @('entra-role','au-role','az-resource') }).Count
    }

    return [ordered]@{
        generatedUtc = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        sourceRoot   = $configRoot
        nodes        = $nodes.ToArray()
        edges        = $edges.ToArray()
        summary      = $summary
        csvBases     = @($script:PimCsvBases | ForEach-Object { @{ base = $_.base; group = $_.group } })
    }
}

# ---------------------------------------------------------------------------
# Static HTML (v0.1 behaviour)
# ---------------------------------------------------------------------------

function Invoke-StaticHtml {
    param([string]$OutHtml)

    Write-Host "Loading PIM4EntraPS config from $configRoot ..." -ForegroundColor Cyan
    $data = Build-PimGraphData

    Write-Host ""
    Write-Host "Graph summary:" -ForegroundColor Cyan
    $data.summary.GetEnumerator() | ForEach-Object {
        Write-Host ("  {0,-18}: {1}" -f $_.Key, $_.Value) -ForegroundColor Gray
    }
    Write-Host ""

    $json = $data | ConvertTo-Json -Depth 12 -Compress
    $naming = Get-PimNamingConventions
    $namingJson = $naming | ConvertTo-Json -Depth 4 -Compress
    $tenantLists = Read-PimTenantListCache
    $tenantJson  = $tenantLists | ConvertTo-Json -Depth 6 -Compress
    $html = [System.IO.File]::ReadAllText($template, [System.Text.UTF8Encoding]::new($true))
    $html = $html.Replace('__PIM_DATA__', $json).Replace('__PIM_TOKEN__', '').Replace('__PIM_MODE__', 'static').Replace('__PIM_NAMING__', $namingJson).Replace('__PIM_TENANT_LISTS__', $tenantJson)

    if (-not $OutHtml) {
        $OutHtml = Join-Path ([IO.Path]::GetTempPath()) ("pim-manager-{0}.html" -f ([Guid]::NewGuid().ToString('N').Substring(0,8)))
    }
    [System.IO.File]::WriteAllText($OutHtml, $html, [System.Text.UTF8Encoding]::new($false))
    Write-Host "Rendered: $OutHtml" -ForegroundColor Green
    if (-not $NoLaunch) {
        Write-Host "Launching default browser ..." -ForegroundColor Cyan
        Start-Process $OutHtml
    }
}

# ---------------------------------------------------------------------------
# HTTP server
# ---------------------------------------------------------------------------

function Get-FreeTcpPort {
    $l = New-Object System.Net.Sockets.TcpListener ([System.Net.IPAddress]::Loopback), 0
    $l.Start()
    $p = ([System.Net.IPEndPoint]$l.LocalEndpoint).Port
    $l.Stop()
    return $p
}

function Write-JsonResponse {
    param(
        [Parameter(Mandatory)][System.Net.HttpListenerResponse]$Response,
        [Parameter(Mandatory)][int]$Status,
        [Parameter(Mandatory)][object]$Body
    )
    $Response.StatusCode = $Status
    $Response.ContentType = 'application/json; charset=utf-8'
    $json = $Body | ConvertTo-Json -Depth 12 -Compress
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
    $Response.ContentLength64 = $bytes.LongLength
    $Response.OutputStream.Write($bytes, 0, $bytes.Length)
    $Response.OutputStream.Close()
}

function Write-HtmlResponse {
    param(
        [Parameter(Mandatory)][System.Net.HttpListenerResponse]$Response,
        [Parameter(Mandatory)][string]$Html
    )
    $Response.StatusCode = 200
    $Response.ContentType = 'text/html; charset=utf-8'
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Html)
    $Response.ContentLength64 = $bytes.LongLength
    $Response.OutputStream.Write($bytes, 0, $bytes.Length)
    $Response.OutputStream.Close()
}

function Read-RequestJson {
    param([Parameter(Mandatory)][System.Net.HttpListenerRequest]$Request)
    if (-not $Request.HasEntityBody) { return $null }
    $reader = New-Object System.IO.StreamReader($Request.InputStream, $Request.ContentEncoding)
    try { $text = $reader.ReadToEnd() } finally { $reader.Dispose() }
    if ([string]::IsNullOrWhiteSpace($text)) { return $null }
    return ($text | ConvertFrom-Json)
}

function ConvertTo-OrderedRow {
    # Accepts a PSCustomObject (from ConvertFrom-Json) and returns an ordered hashtable.
    param([Parameter(Mandatory)][AllowNull()][object]$Row)
    if ($null -eq $Row) { return $null }
    $d = [ordered]@{}
    if ($Row -is [System.Collections.IDictionary]) {
        foreach ($k in $Row.Keys) { $d[$k] = "$($Row[$k])" }
    } else {
        foreach ($p in $Row.PSObject.Properties) { $d[$p.Name] = "$($p.Value)" }
    }
    return $d
}

function Invoke-Server {
    param([int]$DesiredPort = 0)

    Write-Host "PIM4EntraPS Mapper -- starting local editor server ..." -ForegroundColor Cyan
    $token = [Guid]::NewGuid().ToString('N')

    # Pick a free port (try DesiredPort, fall back to random; retry up to 10x on conflict).
    $listener = $null
    $port = 0
    $maxAttempts = 10
    for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
        if ($DesiredPort -gt 0 -and $attempt -eq 1) { $candidate = $DesiredPort }
        else { $candidate = Get-FreeTcpPort }
        try {
            $l = New-Object System.Net.HttpListener
            $l.Prefixes.Add("http://127.0.0.1:$candidate/")
            $l.Start()
            $listener = $l
            $port = $candidate
            break
        } catch [System.Net.HttpListenerException] {
            Write-Warning ("  port {0} unavailable ({1}); retrying ..." -f $candidate, $_.Exception.Message)
            continue
        }
    }
    if (-not $listener) { throw "Failed to bind a localhost port after $maxAttempts attempts." }

    Write-Host ("  listening on http://127.0.0.1:{0}/" -f $port) -ForegroundColor Green
    Write-Host ("  session token: {0}" -f $token) -ForegroundColor DarkGray
    Write-Host "  press Ctrl-C to stop (or close the browser tab; server self-exits after 30s of silence)." -ForegroundColor DarkGray

    $url = "http://127.0.0.1:$port/?token=$token"
    if (-not $NoLaunch) {
        Write-Host "  launching default browser ..." -ForegroundColor Cyan
        Start-Process $url | Out-Null
    } else {
        Write-Host ("  URL: {0}" -f $url) -ForegroundColor Yellow
    }

    # Heartbeat tracker -- updated by /api/heartbeat, watched by the dispatch loop.
    $script:lastHeartbeat = Get-Date
    $heartbeatTimeoutSeconds = 30
    $heartbeatGraceSeconds   = 15  # extra grace at startup before the browser pings

    # Begin first async accept; we process synchronously then re-arm.
    $stop = $false
    $contextResult = $listener.BeginGetContext($null, $null)
    while (-not $stop -and $listener.IsListening) {
        # Wait for context with a 1-second cap so we can check heartbeat regularly.
        if ($contextResult.AsyncWaitHandle.WaitOne(1000)) {
            try { $ctx = $listener.EndGetContext($contextResult) }
            catch { break }
            # Re-arm immediately so subsequent requests don't queue forever.
            $contextResult = $listener.BeginGetContext($null, $null)

            $started = Get-Date
            $status = 500
            try {
                $status = Handle-Request -Context $ctx -ExpectedToken $token
            } catch {
                Write-Host ("  ERROR: {0}" -f $_.Exception.Message) -ForegroundColor Red
                try {
                    Write-JsonResponse -Response $ctx.Response -Status 500 -Body @{ error = "$($_.Exception.Message)" }
                } catch { }
                $status = 500
            }
            $ts = $started.ToString('HH:mm:ss')
            Write-Host ("  [{0}] {1,-6} {2,-40} -> {3}" -f $ts, $ctx.Request.HttpMethod, $ctx.Request.Url.PathAndQuery, $status) -ForegroundColor DarkGray
        }

        # Heartbeat check.
        $idleSeconds = (Get-Date) - $script:lastHeartbeat
        if ($idleSeconds.TotalSeconds -gt ($heartbeatTimeoutSeconds + $heartbeatGraceSeconds)) {
            Write-Host ("  heartbeat timeout ({0:N0}s with no client ping) -- shutting down." -f $idleSeconds.TotalSeconds) -ForegroundColor Yellow
            $stop = $true
        }
    }

    try { $listener.Stop() } catch { }
    try { $listener.Close() } catch { }
    Write-Host "  server stopped." -ForegroundColor Cyan
}

function Handle-Request {
    param(
        [Parameter(Mandatory)][System.Net.HttpListenerContext]$Context,
        [Parameter(Mandatory)][string]$ExpectedToken
    )
    $req  = $Context.Request
    $resp = $Context.Response
    $path = $req.Url.AbsolutePath
    $method = $req.HttpMethod

    # GET / -- serve the SPA. The token is embedded in a <meta> tag so the
    # JS can read it without exposing it on the URL after the first hop.
    if ($path -eq '/' -and $method -eq 'GET') {
        $data = Build-PimGraphData
        $json = $data | ConvertTo-Json -Depth 12 -Compress
        $naming = Get-PimNamingConventions
        $namingJson = $naming | ConvertTo-Json -Depth 4 -Compress
        $tenantLists = Read-PimTenantListCache
        $tenantJson  = $tenantLists | ConvertTo-Json -Depth 6 -Compress
        $html = [System.IO.File]::ReadAllText($template, [System.Text.UTF8Encoding]::new($true))
        $html = $html.Replace('__PIM_DATA__', $json).Replace('__PIM_TOKEN__', $ExpectedToken).Replace('__PIM_MODE__', 'server').Replace('__PIM_NAMING__', $namingJson).Replace('__PIM_TENANT_LISTS__', $tenantJson)
        Write-HtmlResponse -Response $resp -Html $html
        $script:lastHeartbeat = Get-Date
        return 200
    }

    if ($path -eq '/favicon.ico') {
        $resp.StatusCode = 204
        $resp.OutputStream.Close()
        return 204
    }

    # All /api/* paths require Authorization: Bearer <token>.
    if ($path -like '/api/*') {
        $authHeader = $req.Headers['Authorization']
        if (-not $authHeader -or $authHeader -ne "Bearer $ExpectedToken") {
            Write-JsonResponse -Response $resp -Status 401 -Body @{ error = 'unauthorized' }
            return 401
        }

        if ($path -eq '/api/heartbeat' -and $method -eq 'POST') {
            $script:lastHeartbeat = Get-Date
            Write-JsonResponse -Response $resp -Status 200 -Body @{ ok = $true; ts = (Get-Date).ToUniversalTime().ToString('o') }
            return 200
        }

        if ($path -eq '/api/config' -and $method -eq 'GET') {
            $script:lastHeartbeat = Get-Date
            $data = Build-PimGraphData
            Write-JsonResponse -Response $resp -Status 200 -Body $data
            return 200
        }

        if ($path -match '^/api/csv/([\w\.-]+)$') {
            $base = $Matches[1]
            $spec = Get-PimCsvSpec -BaseName $base
            if (-not $spec) {
                Write-JsonResponse -Response $resp -Status 404 -Body @{ error = "unknown csv base: $base" }
                return 404
            }
            $script:lastHeartbeat = Get-Date

            if ($method -eq 'GET') {
                $payload = Read-PimCsvRows -BaseName $base
                $body = [ordered]@{
                    base   = $base
                    path   = $payload.path
                    source = $payload.source
                    header = $payload.header
                    rows   = $payload.rows
                }
                Write-JsonResponse -Response $resp -Status 200 -Body $body
                return 200
            }
            if ($method -eq 'PUT') {
                $body = Read-RequestJson -Request $req
                $rowsRaw = @()
                if ($body -and $body.rows) { $rowsRaw = @($body.rows) }
                $rowsOrdered = @($rowsRaw | ForEach-Object { ConvertTo-OrderedRow $_ } | Where-Object { $_ -ne $null })

                # Diff against current on-disk state for the audit log.
                $current = Read-PimCsvRows -BaseName $base
                $diff = Compare-PimRowSets -Before $current.rows -After $rowsOrdered

                $written = Write-PimCsvCustom -BaseName $base -Rows $rowsOrdered
                Write-PimMutationLog -BaseName $base -Adds $diff.adds.Count -Removes $diff.removes.Count -Modifies $diff.modifies.Count -NewRowCount $rowsOrdered.Count

                Write-JsonResponse -Response $resp -Status 200 -Body ([ordered]@{
                    ok       = $true
                    base     = $base
                    path     = $written.path
                    rowCount = $rowsOrdered.Count
                    adds     = $diff.adds.Count
                    removes  = $diff.removes.Count
                    modifies = $diff.modifies.Count
                })
                return 200
            }
            if ($method -eq 'POST' -and $path -match '^/api/csv/[\w\.-]+$') {
                Write-JsonResponse -Response $resp -Status 405 -Body @{ error = 'method not allowed (did you mean /api/diff/<base>?)' }
                return 405
            }
        }

        if ($path -eq '/api/tenant-lists' -and $method -eq 'GET') {
            $script:lastHeartbeat = Get-Date
            $tenantLists = Read-PimTenantListCache
            Write-JsonResponse -Response $resp -Status 200 -Body $tenantLists
            return 200
        }

        if ($path -eq '/api/refresh-tenant-lists' -and $method -eq 'POST') {
            $script:lastHeartbeat = Get-Date
            if (-not (Get-Command Invoke-PimTenantListRefresh -ErrorAction SilentlyContinue)) {
                Write-JsonResponse -Response $resp -Status 500 -Body @{ ok = $false; error = '_tenantSync.ps1 was not loaded -- file missing next to Open-PimManager.ps1' }
                return 500
            }
            try {
                $result = Invoke-PimTenantListRefresh
                $tenantLists = Read-PimTenantListCache
                Write-JsonResponse -Response $resp -Status 200 -Body ([ordered]@{
                    ok      = $result.ok
                    reason  = $result.reason
                    results = $result.results
                    lists   = $tenantLists
                })
                return 200
            } catch {
                Write-JsonResponse -Response $resp -Status 500 -Body @{ ok = $false; error = "$($_.Exception.Message)" }
                return 500
            }
        }

        if ($path -eq '/api/naming-conventions' -and $method -eq 'GET') {
            $script:lastHeartbeat = Get-Date
            Write-JsonResponse -Response $resp -Status 200 -Body (Get-PimNamingConventions)
            return 200
        }

        if ($path -eq '/api/preflight' -and $method -eq 'GET') {
            $script:lastHeartbeat = Get-Date
            if (-not (Get-Command Invoke-PimPreflightValidation -ErrorAction SilentlyContinue)) {
                Write-JsonResponse -Response $resp -Status 500 -Body @{ error = '_validator.ps1 was not loaded -- file missing next to Open-PimManager.ps1' }
                return 500
            }
            try {
                $report = Invoke-PimPreflightValidation
                Write-JsonResponse -Response $resp -Status 200 -Body $report
                return 200
            } catch {
                Write-JsonResponse -Response $resp -Status 500 -Body @{ error = "$($_.Exception.Message)" }
                return 500
            }
        }

        if ($path -match '^/api/diff/([\w\.-]+)$' -and $method -eq 'POST') {
            $base = $Matches[1]
            $spec = Get-PimCsvSpec -BaseName $base
            if (-not $spec) {
                Write-JsonResponse -Response $resp -Status 404 -Body @{ error = "unknown csv base: $base" }
                return 404
            }
            $script:lastHeartbeat = Get-Date
            $body = Read-RequestJson -Request $req
            $rowsRaw = @()
            if ($body -and $body.rows) { $rowsRaw = @($body.rows) }
            $rowsOrdered = @($rowsRaw | ForEach-Object { ConvertTo-OrderedRow $_ } | Where-Object { $_ -ne $null })
            $current = Read-PimCsvRows -BaseName $base
            $diff = Compare-PimRowSets -Before $current.rows -After $rowsOrdered
            Write-JsonResponse -Response $resp -Status 200 -Body ([ordered]@{
                base     = $base
                source   = $current.source
                adds     = $diff.adds
                removes  = $diff.removes
                modifies = $diff.modifies
                unchanged = $diff.unchanged
            })
            return 200
        }

        Write-JsonResponse -Response $resp -Status 404 -Body @{ error = "not found: $method $path" }
        return 404
    }

    # Unknown / static path.
    Write-JsonResponse -Response $resp -Status 404 -Body @{ error = "not found: $method $path" }
    return 404
}

# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

switch ($PSCmdlet.ParameterSetName) {
    'Static'  { Invoke-StaticHtml -OutHtml $OutHtml }
    'Refresh' {
        Write-Host "PIM4EntraPS Mapper -- refreshing tenant lists ..." -ForegroundColor Cyan
        if (-not (Get-Command Invoke-PimTenantListRefresh -ErrorAction SilentlyContinue)) {
            throw "_tenantSync.ps1 was not loaded -- expected next to Open-PimManager.ps1 at: $tenantSync"
        }
        $r = Invoke-PimTenantListRefresh
        if ($r.ok) {
            Write-Host "  done." -ForegroundColor Green
        } else {
            Write-Warning ("  refresh did not complete: {0}" -f ($r.reason | Out-String))
        }
    }
    default {
        # Default = server mode (even without -Server explicitly set).
        Invoke-Server -DesiredPort $Port
    }
}
