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
    [switch]$RefreshTenantLists,

    # MSP / multi-instance support. An "instance" is one customer's PIM4EntraPS
    # data set: a config root (the 14 CSVs + NamingConventions files) and its
    # sibling output folder. Instances are declared in
    # tools/pim-manager/instances.custom.json (gitignored):
    #   { "instances": [ { "name": "customerA", "configRoot": "E:\\msp\\customerA\\PIM4EntraPS\\config" } ] }
    # The solution's own config/ folder is always available as instance 'local'.
    # -Instance picks the active instance at startup; the UI can switch at
    # runtime via the instance dropdown (server mode only).
    [string]$Instance,

    # Ad-hoc instance: point the Manager at any config folder directly without
    # declaring it in instances.custom.json. Wins over -Instance.
    [string]$ConfigRoot,

    # Bootstrap the AutomateITPS platform connection (bootstrap cert -> Key
    # Vault -> Modern SPN -> Graph + Az app-only) in THIS process before
    # starting, so the Revoke tab + tenant-list refresh work without running a
    # baseline engine first. Requires FUNCTIONS\AutomateITPS in the repo and a
    # bootstrap/platform-config.json (the standard mgmt-box setup).
    [switch]$ConnectPlatform
)

$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Paths + constants
# ---------------------------------------------------------------------------

$solutionRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)  # ...\PIM4EntraPS
$template     = Join-Path $PSScriptRoot 'pim-manager.html'
$tenantSync   = Join-Path $PSScriptRoot '_tenantSync.ps1'
$validator    = Join-Path $PSScriptRoot '_validator.ps1'
$instancesFile = Join-Path $PSScriptRoot 'instances.custom.json'

# Shared date-expression resolver (engine/_shared/PIM-DateExpression.ps1) --
# powers the /api/resolve-date live preview; the validator dot-sources the
# same file so GUI, validator and engine agree.
$_dateExprLib = Join-Path $solutionRoot 'engine\_shared\PIM-DateExpression.ps1'
if (Test-Path -LiteralPath $_dateExprLib) { . $_dateExprLib }

# ---------------------------------------------------------------------------
# Instances (MSP multi-customer support)
#
# An instance = one customer's data set. 'local' (the solution's own config/)
# always exists; more come from tools/pim-manager/instances.custom.json.
# All CSV / naming-convention / output / tenant-cache I/O resolves through
# $script:configRoot + $script:outputRoot + $script:PimInstanceName, which
# Set-PimManagerInstance swaps at runtime (UI dropdown -> POST /api/instance).
#
# SQL note: when instances move from per-customer CSV folders to per-customer
# SQL databases, Set-PimManagerInstance is the seam -- the registry entry
# grows a connection-string field and Read-PimCsvRows/Write-PimCsvCustom get
# a SQL-backed implementation; nothing above this layer changes.
# ---------------------------------------------------------------------------

function Get-PimSolutionVersion {
    # Reads SOLUTIONS/PIM4EntraPS/VERSION for the header badge (same pill the
    # PIM Activator shows). Best-effort: 'v?' when the file is missing.
    $vf = Join-Path $solutionRoot 'VERSION'
    if (Test-Path -LiteralPath $vf) {
        try { return ('v' + ([System.IO.File]::ReadAllText($vf).Trim())) } catch { }
    }
    return 'v?'
}

function Get-PimManagerInstances {
    # Returns array of @{ name; configRoot; outputRoot } -- 'local' first.
    $list = New-Object System.Collections.ArrayList
    [void]$list.Add(@{
        name       = 'local'
        configRoot = (Join-Path $solutionRoot 'config')
        outputRoot = (Join-Path $solutionRoot 'output')
    })
    if (Test-Path -LiteralPath $instancesFile) {
        try {
            $raw = [System.IO.File]::ReadAllText($instancesFile, [System.Text.UTF8Encoding]::new($false))
            if ($raw.Length -gt 0 -and [int][char]$raw[0] -eq 0xFEFF) { $raw = $raw.Substring(1) }
            $parsed = $raw | ConvertFrom-Json
            foreach ($e in @($parsed.instances)) {
                if (-not $e -or -not $e.name -or -not $e.configRoot) { continue }
                if ($e.name -eq 'local') { continue }  # reserved
                $cfg = [string]$e.configRoot
                $out = if ($e.outputRoot) { [string]$e.outputRoot } else {
                    # Default: sibling 'output' folder next to the config folder.
                    Join-Path (Split-Path -Parent $cfg) 'output'
                }
                [void]$list.Add(@{
                    name       = [string]$e.name
                    configRoot = $cfg
                    outputRoot = $out
                    # Optional per-tenant connection. Two credential shapes:
                    #   certThumbprint -- mgmt-box deployment (certs for every
                    #     tenant in the machine store).
                    #   keyVaultName + secretName -- central Key Vault holding
                    #     one client secret per tenant. This is the
                    #     cloud-portable shape: an Azure App Service port uses
                    #     Managed Identity -> the same vault -> the same
                    #     naming, with zero changes to this resolution logic.
                    # When tenantId is set, switching to this instance
                    # retargets the app-only Graph/Az connection so Active
                    # Assignments + tenant-cache refresh hit THIS tenant.
                    tenantId       = $(if ($e.tenantId)       { [string]$e.tenantId }       else { $null })
                    appId          = $(if ($e.appId)          { [string]$e.appId }          else { $null })
                    certThumbprint = $(if ($e.certThumbprint) { [string]$e.certThumbprint } else { $null })
                    keyVaultName   = $(if ($e.keyVaultName)   { [string]$e.keyVaultName }   else { $null })
                    secretName     = $(if ($e.secretName)     { [string]$e.secretName }     else { $null })
                })
            }
        } catch {
            Write-Warning "instances.custom.json could not be parsed: $($_.Exception.Message) -- only the 'local' instance is available."
        }
    }
    return ,$list.ToArray()
}

function Set-PimManagerInstance {
    # Switch the active instance. Throws if the name is unknown or the config
    # folder is missing. Clears every per-instance server-side cache.
    param([Parameter(Mandatory)][string]$Name)
    $inst = $null
    foreach ($i in (Get-PimManagerInstances)) { if ($i.name -eq $Name) { $inst = $i; break } }
    if (-not $inst) { throw "Unknown instance '$Name'. Declare it in $instancesFile." }
    if (-not (Test-Path -LiteralPath $inst.configRoot)) { throw "Instance '$Name': config folder not found: $($inst.configRoot)" }
    if (-not (Test-Path -LiteralPath $inst.outputRoot)) { New-Item -ItemType Directory -Path $inst.outputRoot -Force | Out-Null }

    $script:PimInstanceName = $inst.name
    $script:configRoot      = $inst.configRoot
    $script:outputRoot      = $inst.outputRoot
    $script:mutationLog     = Join-Path $inst.outputRoot 'pim-manager-mutations.log'

    # Per-instance state must not leak across customers.
    $script:PimActiveAssignmentsCache          = $null
    $script:PimActiveAssignmentsCacheLoadedUtc = $null
    $script:PimManager_LookupCachesLoaded      = $false

    # Per-tenant connection retargeting: when the registry entry carries
    # tenantId (+ optional appId / certThumbprint -- the mgmt box has the
    # certs for every tenant in its store), point the engine SPN globals at
    # THIS tenant and drop the current Graph session. The next Active
    # Assignments / tenant-cache call reconnects app-only to the right
    # tenant via _tenantSync's Connect-PimManagerGraph/Az.
    if ($inst.tenantId) {
        $global:AzureTenantID = $inst.tenantId
        if ($inst.appId) { $global:HighPriv_Modern_ApplicationID_Azure = $inst.appId }
        if ($inst.certThumbprint) {
            # Mgmt-box shape: per-tenant cert in the machine store.
            $global:HighPriv_Modern_CertificateThumbprint_Azure = $inst.certThumbprint
            # A secret from a previously-connected tenant must never be
            # replayed against this one.
            $global:HighPriv_Modern_Secret_Azure = $null
        } elseif ($inst.keyVaultName -and $inst.secretName) {
            # Central-Key-Vault shape (cloud-portable): one client secret per
            # tenant in one vault. Pulled with the CURRENT Az context (the
            # bootstrap connection from -ConnectPlatform on the mgmt box; a
            # Managed Identity on an Azure App Service port). Lazy failure is
            # fine -- _tenantSync throws a clear error on first tenant call.
            try {
                $sec = Get-AzKeyVaultSecret -VaultName $inst.keyVaultName -Name $inst.secretName -AsPlainText -ErrorAction Stop
                $global:HighPriv_Modern_Secret_Azure = $sec
                $global:HighPriv_Modern_CertificateThumbprint_Azure = $null
            } catch {
                Write-Warning ("instance '{0}': Key Vault secret {1}/{2} could not be read ({3}). Tenant-connected features will fail until resolved. Is the platform connected (-ConnectPlatform) and does this identity have get-secret on the vault?" -f $inst.name, $inst.keyVaultName, $inst.secretName, $_.Exception.Message)
            }
        }
        $script:PimManagerTenantConnected = $false
        try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch { }
        Write-Host ("  instance: {0}  (config: {1}, tenant: {2})" -f $inst.name, $inst.configRoot, $inst.tenantId) -ForegroundColor Cyan
    } else {
        Write-Host ("  instance: {0}  (config: {1})" -f $inst.name, $inst.configRoot) -ForegroundColor Cyan
    }
}

# Resolve the startup instance: -ConfigRoot (ad-hoc) > -Instance (registry) > 'local'.
if ($ConfigRoot) {
    if (-not (Test-Path -LiteralPath $ConfigRoot)) { throw "-ConfigRoot folder not found: $ConfigRoot" }
    $script:PimInstanceName = 'custom'
    $script:configRoot      = $ConfigRoot
    $script:outputRoot      = Join-Path (Split-Path -Parent $ConfigRoot) 'output'
    if (-not (Test-Path -LiteralPath $script:outputRoot)) { New-Item -ItemType Directory -Path $script:outputRoot -Force | Out-Null }
    $script:mutationLog     = Join-Path $script:outputRoot 'pim-manager-mutations.log'
    Write-Host ("  instance: custom (config: {0})" -f $ConfigRoot) -ForegroundColor Cyan
} else {
    Set-PimManagerInstance -Name $(if ($Instance) { $Instance } else { 'local' })
}

if (-not (Test-Path -LiteralPath $template))   { throw "Template not found: $template" }
if (Test-Path -LiteralPath $tenantSync) { . $tenantSync }
if (Test-Path -LiteralPath $validator)  { . $validator }

if ($ConnectPlatform) {
    $repoRoot = Split-Path -Parent (Split-Path -Parent $solutionRoot)   # ...\AutomateIT
    $psd1 = Join-Path $repoRoot 'FUNCTIONS\AutomateITPS\AutomateITPS.psd1'
    if (-not (Test-Path -LiteralPath $psd1)) { throw "-ConnectPlatform: AutomateITPS module not found at $psd1" }
    Write-Host "Connecting platform (AutomateITPS bootstrap -> Modern SPN, app-only) ..." -ForegroundColor Cyan
    Import-Module $psd1 -Global -Force -WarningAction SilentlyContinue
    $null = Connect-Platform
    Write-Host ("  connected: tenant {0}" -f $global:AzureTenantID) -ForegroundColor Green
}

# The 14 CSV bases the mapper edits, in stable UI order, with their default
# headers used when creating a brand-new .custom.csv.
$script:PimCsvBases = @(
    [ordered]@{ base = 'Account-Definitions-Admins';      group = 'Definitions';  defaultHeader = @('FirstName','LastName','Initials','TierLevel','TargetUsage','TargetPlatform','UserType','UserName','DisplayName','UserPrincipalName','UsageLocation','ForwardMailsToContact','MailForwardAddress','CreateTAP','TAPStartDate','Ring') },
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
    [ordered]@{ base = 'PIM-Assignments-Azure-Resources'; group = 'Assignments';  defaultHeader = @('GroupTag','AzScope','AzScopePermission','AssignmentType','Action','UpdateExisting','AutoExtend','NumOfDaysWhenExpire','Permanent','CPPlatform','Plane','TierLevel','PermissionScope','SyncPlatform') },
    [ordered]@{ base = 'PIM-Assignments-Workloads';       group = 'Assignments';  defaultHeader = @('Workload','RoleName','GroupTag','Scope','Action','Notes') }
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
        # KEEP blank rows (every column empty). Customers use ';;;;;' rows as
        # visual group separators in Excel; dropping them here meant every
        # Manager commit silently destroyed the hand-maintained layout
        # (observed: 53 raw rows -> 37 after one PUT round-trip). The engines
        # and the validator both skip blank rows themselves, and the grid
        # renders them as empty editable rows -- same as Excel does.
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

    $json = ConvertTo-PimJson -Body $data
    $naming = Get-PimNamingConventions
    $namingJson = ConvertTo-PimJson -Body $naming
    $tenantLists = Read-PimTenantListCache
    $tenantJson  = ConvertTo-PimJson -Body $tenantLists
    $instJson = ConvertTo-PimJson -Body ([ordered]@{ active = $script:PimInstanceName; instances = @() })
    $html = [System.IO.File]::ReadAllText($template, [System.Text.UTF8Encoding]::new($true))
    $html = $html.Replace('__PIM_DATA__', $json).Replace('__PIM_TOKEN__', '').Replace('__PIM_MODE__', 'static').Replace('__PIM_NAMING__', $namingJson).Replace('__PIM_TENANT_LISTS__', $tenantJson).Replace('__PIM_INSTANCES__', $instJson).Replace('__PIM_VERSION__', (Get-PimSolutionVersion))

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

# ---------------------------------------------------------------------------
# Fast JSON serializer. PS 5.1's ConvertTo-Json needs ~10s for a 300KB
# payload (measured on the /api/preflight report) and the server is
# single-threaded -- every second spent serializing blocks ALL other
# requests, and queued requests die with 'specified network name is no
# longer available'. JavaScriptSerializer does the same payload in <0.5s.
# ---------------------------------------------------------------------------

# Compiled normalizer + serializer -- Windows PowerShell 5.1 ONLY. 5.1's
# ConvertTo-Json needs seconds for 300-400KB payloads, so we compile a C#
# walk + JavaScriptSerializer (System.Web.Extensions). Both are .NET
# Framework-only: on PowerShell 7 the Add-Type fails with CS0012 (mscorlib
# not referenced) -- and pwsh's built-in ConvertTo-Json is already fast, so
# ConvertTo-PimJson simply falls back to it there.
$script:PimUseCompiledJson = ($PSVersionTable.PSEdition -eq 'Desktop')
if ($script:PimUseCompiledJson) {
Add-Type -AssemblyName System.Web.Extensions -ErrorAction SilentlyContinue

if (-not ('PimManager.Json' -as [type])) {
    Add-Type -ReferencedAssemblies @('System.Web.Extensions', [System.Management.Automation.PSObject].Assembly.Location) -TypeDefinition @'
using System;
using System.Collections;
using System.Collections.Generic;
using System.Management.Automation;
using System.Web.Script.Serialization;

namespace PimManager {
    public static class Json {
        public static string Serialize(object value) {
            var ser = new JavaScriptSerializer();
            ser.MaxJsonLength = 268435456;
            ser.RecursionLimit = 64;
            return ser.Serialize(Normalize(value, 0));
        }
        public static object Normalize(object value, int depth) {
            if (value == null || depth > 24) return null;
            var pso = value as PSObject;
            if (pso != null) {
                var baseObj = pso.BaseObject;
                if (baseObj is PSCustomObject) {
                    var d = new Dictionary<string, object>();
                    foreach (var p in pso.Properties) {
                        object pv;
                        try { pv = p.Value; } catch { pv = null; }
                        d[p.Name] = Normalize(pv, depth + 1);
                    }
                    return d;
                }
                return Normalize(baseObj, depth);
            }
            if (value is string || value is bool || value is int || value is long ||
                value is double || value is decimal || value is float ||
                value is byte || value is short || value is uint || value is ulong || value is ushort) return value;
            if (value is DateTime) return ((DateTime)value).ToUniversalTime().ToString("o");
            if (value is Guid || value is Uri || value is char || value is TimeSpan || value.GetType().IsEnum) return value.ToString();
            var dict = value as IDictionary;
            if (dict != null) {
                var d = new Dictionary<string, object>();
                foreach (DictionaryEntry e in dict) d[Convert.ToString(e.Key)] = Normalize(e.Value, depth + 1);
                return d;
            }
            var en = value as IEnumerable;
            if (en != null) {
                var list = new List<object>();
                foreach (var item in en) list.Add(Normalize(item, depth + 1));
                return list;
            }
            // Arbitrary .NET object (e.g. PSCustomObject reached without PSObject
            // wrapper): walk its PSObject properties via a fresh wrap.
            var wrapped = PSObject.AsPSObject(value);
            var dd = new Dictionary<string, object>();
            foreach (var p in wrapped.Properties) {
                object pv;
                try { pv = p.Value; } catch { pv = null; }
                dd[p.Name] = Normalize(pv, depth + 1);
            }
            if (dd.Count > 0) return dd;
            return value.ToString();
        }
    }
}
'@ -ErrorAction Stop
}
}

function ConvertTo-PimJson {
    param([Parameter(Mandatory)][AllowNull()][object]$Body)
    if ($script:PimUseCompiledJson -and ('PimManager.Json' -as [type])) {
        try {
            return [PimManager.Json]::Serialize($Body)
        } catch { }
    }
    # PowerShell 7 (fast native ConvertTo-Json), or 5.1 compile/serialize failure.
    return ($Body | ConvertTo-Json -Depth 12 -Compress)
}

function Write-JsonResponse {
    param(
        [Parameter(Mandatory)][System.Net.HttpListenerResponse]$Response,
        [Parameter(Mandatory)][int]$Status,
        [Parameter(Mandatory)][object]$Body
    )
    $json = ConvertTo-PimJson -Body $Body
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
    # Client-abort tolerance: a browser that gave up (tab closed, fetch
    # timeout) makes OutputStream.Write throw. Swallow + log instead of
    # cascading into a second Write-JsonResponse call on the same response
    # ('This operation cannot be performed after the response has been
    # submitted').
    try {
        $Response.StatusCode = $Status
        $Response.ContentType = 'application/json; charset=utf-8'
        $Response.ContentLength64 = $bytes.LongLength
        $Response.OutputStream.Write($bytes, 0, $bytes.Length)
        $Response.OutputStream.Close()
    } catch {
        Write-Host ("  [net] client gone before response could be written ({0} bytes, status {1}): {2}" -f $bytes.Length, $Status, $_.Exception.Message) -ForegroundColor DarkGray
    }
}

function Write-HtmlResponse {
    param(
        [Parameter(Mandatory)][System.Net.HttpListenerResponse]$Response,
        [Parameter(Mandatory)][string]$Html
    )
    try {
        $Response.StatusCode = 200
        $Response.ContentType = 'text/html; charset=utf-8'
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($Html)
        $Response.ContentLength64 = $bytes.LongLength
        $Response.OutputStream.Write($bytes, 0, $bytes.Length)
        $Response.OutputStream.Close()
    } catch {
        Write-Host ("  [net] client gone before HTML response could be written: {0}" -f $_.Exception.Message) -ForegroundColor DarkGray
    }
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

# ---------------------------------------------------------------------------
# v2.4.2 Revoke tab -- bulk-revoke of active PIM assignments.
#
# Server-side cache lives 60s to avoid hammering Graph + ARG when the operator
# re-opens the tab. `Get-PimActiveAssignmentsCached -Force` bypasses the cache.
# Three sources are combined into a single row set:
#
#   * Entra-role active assignments:
#       Get-MgRoleManagementDirectoryRoleAssignmentSchedule -All
#       (TODO v2.4.3 -- add Get-EntraRoleAssignmentsPreloaded helper to the
#        engine's _shared/PIM-Functions.psm1, mirroring the v2.4.0
#        Get-PimGroupSchedulesPreloaded pattern. For now we call directly.)
#
#   * Azure-RBAC active assignments:
#       Get-AzActiveRoleAssignmentsViaArg  (v2.4.0 helper, Search-AzGraph)
#
#   * PIM-for-Groups active assignments:
#       Get-PimGroupSchedulesPreloaded     (v2.4.0 helper, single Graph call)
#
# The Revoke tab in the Manager only acts on ACTIVE (Assigned) rows -- not
# Eligible -- because eligibility removal is a different operator workflow
# already handled by the Baseline engine. The engine PIM-Assignment-Revoker
# still supports both; the GUI is the bulk-revoke subset.
# ---------------------------------------------------------------------------

function Initialize-PimManagerTenantConnection {
    # Lazy-connect Graph + Az on first Revoke tab use. Reuses the
    # _tenantSync.ps1 helpers so we share the engine-SPN connection logic
    # (no interactive Connect-MgGraph / Connect-AzAccount ever).
    if ($script:PimManagerTenantConnected) { return }
    if (-not (Get-Command Assert-PimTenantConnectionContext -ErrorAction SilentlyContinue)) {
        throw "_tenantSync.ps1 helpers not loaded -- file missing next to Open-PimManager.ps1"
    }
    $tenantId = Assert-PimTenantConnectionContext
    Connect-PimManagerGraph -TenantId $tenantId
    Connect-PimManagerAz    -TenantId $tenantId
    $script:PimManagerTenantConnected = $true
}

function Get-PimManagerLookupCaches {
    # Populate $script:PimManager_Users / Groups / Roles for principal +
    # role-display-name resolution in the active-assignments row builder.
    # Pulled once per server start; refreshed only when -Force passed.
    param([switch]$Force)
    if (-not $Force -and $script:PimManager_LookupCachesLoaded) { return }

    Initialize-PimManagerTenantConnection

    Write-Host "  [revoke] loading principal + role lookup caches (one-shot per session) ..." -ForegroundColor DarkGray
    # Users (admin-only filter if naming-conventions present, else full set).
    try {
        if (Get-Command Get-PimAdminsFiltered -ErrorAction SilentlyContinue) {
            $script:PimManager_Users = @(Get-PimAdminsFiltered)
        } else {
            $script:PimManager_Users = @(Get-MgUser -All)
        }
    } catch {
        Write-Warning "  [revoke] user cache load failed: $($_.Exception.Message). Principal names may be blank."
        $script:PimManager_Users = @()
    }
    # Groups (PIM-prefix filter if naming-conventions present, else full set).
    try {
        if (Get-Command Get-PimGroupsFiltered -ErrorAction SilentlyContinue) {
            $script:PimManager_Groups = @(Get-PimGroupsFiltered)
        } else {
            $script:PimManager_Groups = @(Get-MgGroup -All)
        }
    } catch {
        Write-Warning "  [revoke] group cache load failed: $($_.Exception.Message). Group names may be blank."
        $script:PimManager_Groups = @()
    }
    # Entra role definitions (small, single call, no filtering).
    try {
        $script:PimManager_EntraRoles = @(Get-MgRoleManagementDirectoryRoleDefinition -All)
    } catch {
        Write-Warning "  [revoke] entra role-definition cache load failed: $($_.Exception.Message). Entra role names may be blank."
        $script:PimManager_EntraRoles = @()
    }
    # AU directory cache (for /administrativeUnits/<id> scope display).
    try {
        $script:PimManager_AUs = @(Get-MgDirectoryAdministrativeUnit -All)
    } catch {
        $script:PimManager_AUs = @()
    }

    # Engine helpers (Resolve-PimGroupCached etc.) read $Global:Users_All_ID /
    # $Global:Groups_All_ID. Mirror our caches there so the v2.4.0 helpers
    # stay first-class.
    $Global:Users_All_ID  = $script:PimManager_Users
    $Global:Groups_All_ID = $script:PimManager_Groups

    # Id-keyed indexes: the row builder resolves principal/role/AU labels per
    # assignment row, and a linear scan per row is O(rows x principals) --
    # measurably seconds on a 944-row tenant. Hashtables make it O(rows).
    $script:PimManager_UserById  = @{}
    foreach ($u in $script:PimManager_Users)  { if ($u -and $u.Id)  { $script:PimManager_UserById["$($u.Id)"]  = $u } }
    $script:PimManager_GroupById = @{}
    foreach ($g in $script:PimManager_Groups) { if ($g -and $g.Id)  { $script:PimManager_GroupById["$($g.Id)"] = $g } }
    $script:PimManager_RoleById  = @{}
    foreach ($r in $script:PimManager_EntraRoles) { if ($r -and $r.Id) { $script:PimManager_RoleById["$($r.Id)"] = $r } }
    $script:PimManager_AuById    = @{}
    foreach ($a in $script:PimManager_AUs) { if ($a -and $a.Id) { $script:PimManager_AuById["$($a.Id)"] = $a } }

    $script:PimManager_LookupCachesLoaded = $true
}

function Resolve-PimManagerPrincipalLabel {
    # Try user UPN first, then group DisplayName, then bare id. Hashtable
    # lookups -- called once per assignment row (944 rows on a real tenant).
    param([Parameter(Mandatory)][AllowEmptyString()][string]$PrincipalId)
    if ([string]::IsNullOrWhiteSpace($PrincipalId)) { return '' }
    if ($script:PimManager_UserById -and $script:PimManager_UserById.ContainsKey($PrincipalId)) {
        $u = $script:PimManager_UserById[$PrincipalId]
        if ($u.UserPrincipalName) { return [string]$u.UserPrincipalName }
        if ($u.DisplayName)       { return [string]$u.DisplayName }
        return $PrincipalId
    }
    if ($script:PimManager_GroupById -and $script:PimManager_GroupById.ContainsKey($PrincipalId)) {
        $g = $script:PimManager_GroupById[$PrincipalId]
        if ($g.DisplayName) { return [string]$g.DisplayName }
        return $PrincipalId
    }
    return $PrincipalId
}

function Resolve-PimManagerEntraRoleName {
    param([Parameter(Mandatory)][AllowEmptyString()][string]$RoleDefinitionId)
    if ([string]::IsNullOrWhiteSpace($RoleDefinitionId)) { return '' }
    # Trim a possible /providers/.../roleDefinitions/<guid> prefix.
    $guid = $RoleDefinitionId
    $slash = $RoleDefinitionId.LastIndexOf('/')
    if ($slash -ge 0 -and $slash -lt ($RoleDefinitionId.Length - 1)) {
        $guid = $RoleDefinitionId.Substring($slash + 1)
    }
    if ($script:PimManager_RoleById -and $script:PimManager_RoleById.ContainsKey($guid)) {
        $r = $script:PimManager_RoleById[$guid]
        if ($r.DisplayName) { return [string]$r.DisplayName }
    }
    return $guid
}

function Resolve-PimManagerDirectoryScope {
    param([Parameter(Mandatory)][AllowEmptyString()][string]$DirectoryScopeId)
    if ([string]::IsNullOrWhiteSpace($DirectoryScopeId)) { return '/ (tenant-wide)' }
    if ($DirectoryScopeId -eq '/')                       { return '/ (tenant-wide)' }
    if ($DirectoryScopeId -like '/administrativeUnits/*') {
        $auId = ($DirectoryScopeId -split '/')[-1]
        if ($script:PimManager_AuById -and $script:PimManager_AuById.ContainsKey($auId)) {
            return '/AdministrativeUnits/' + [string]$script:PimManager_AuById[$auId].DisplayName
        }
        return $DirectoryScopeId
    }
    return $DirectoryScopeId
}

function Get-PimActiveAssignmentsCached {
    # Returns hashtable: @{ ok; rows = [...]; loadedUtc; counts = @{...}; cacheHit }.
    param([switch]$Force)

    $maxAgeSeconds = 60
    if (-not $Force -and $script:PimActiveAssignmentsCache -and $script:PimActiveAssignmentsCacheLoadedUtc) {
        $age = ([DateTime]::UtcNow - $script:PimActiveAssignmentsCacheLoadedUtc).TotalSeconds
        if ($age -lt $maxAgeSeconds) {
            return [ordered]@{
                ok        = $true
                rows      = $script:PimActiveAssignmentsCache.rows
                loadedUtc = $script:PimActiveAssignmentsCache.loadedUtc
                counts    = $script:PimActiveAssignmentsCache.counts
                cacheHit  = $true
                ageSeconds = [math]::Round($age, 0)
            }
        }
    }

    # Initial connect + lookup caches (idempotent).
    Initialize-PimManagerTenantConnection
    Get-PimManagerLookupCaches

    # The v2.4.0 helpers + Entra-role-direct call all live in the engine's
    # PIM-Functions.psm1. Import lazily so the Manager works without the
    # engine being imported separately.
    $shared = Join-Path $PSScriptRoot '..\..\engine\_shared\PIM-Functions.psm1'
    if (Test-Path -LiteralPath $shared) {
        Import-Module $shared -Global -Force -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
    }

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $rows = New-Object System.Collections.ArrayList

    # ---- Entra-role active assignments -------------------------------------
    # TODO v2.4.3: replace with Get-EntraRoleAssignmentsPreloaded helper once
    # ported into engine/_shared/PIM-Functions.psm1 (mirror of the
    # Get-PimGroupSchedulesPreloaded pattern). For now: direct -All call.
    $entraRows = @()
    try {
        $entraRows = @(Get-MgRoleManagementDirectoryRoleAssignmentSchedule -All -ErrorAction Stop)
    } catch {
        Write-Warning "  [revoke] Get-MgRoleManagementDirectoryRoleAssignmentSchedule failed: $($_.Exception.Message)"
        $entraRows = @()
    }
    foreach ($e in $entraRows) {
        if (-not $e) { continue }
        $principalLabel = Resolve-PimManagerPrincipalLabel -PrincipalId ([string]$e.PrincipalId)
        $roleLabel      = Resolve-PimManagerEntraRoleName -RoleDefinitionId ([string]$e.RoleDefinitionId)
        $scopeLabel     = Resolve-PimManagerDirectoryScope -DirectoryScopeId ([string]$e.DirectoryScopeId)
        $start = $null; $end = $null
        if ($e.ScheduleInfo) {
            if ($e.ScheduleInfo.StartDateTime) { $start = ([DateTime]$e.ScheduleInfo.StartDateTime).ToUniversalTime().ToString('o') }
            if ($e.ScheduleInfo.Expiration -and $e.ScheduleInfo.Expiration.EndDateTime) {
                $end = ([DateTime]$e.ScheduleInfo.Expiration.EndDateTime).ToUniversalTime().ToString('o')
            }
        }
        [void]$rows.Add([ordered]@{
            id               = "entra-role:$($e.Id)"
            type             = 'entra-role'
            principal        = $principalLabel
            principalId      = [string]$e.PrincipalId
            role             = $roleLabel
            roleDefinitionId = [string]$e.RoleDefinitionId
            scope            = $scopeLabel
            directoryScopeId = [string]$e.DirectoryScopeId
            start            = $start
            end              = $end
            justification    = ''  # Entra role assignment schedules don't carry the original activation justification on the assignment object.
        })
    }

    # ---- Azure-RBAC active assignments (ARG) -------------------------------
    $azRows = @()
    if (Get-Command Get-AzActiveRoleAssignmentsViaArg -ErrorAction SilentlyContinue) {
        try {
            $azRows = @(Get-AzActiveRoleAssignmentsViaArg)
        } catch {
            Write-Warning "  [revoke] Get-AzActiveRoleAssignmentsViaArg failed: $($_.Exception.Message)"
            $azRows = @()
        }
    } else {
        Write-Warning "  [revoke] Get-AzActiveRoleAssignmentsViaArg not available (engine _shared/PIM-Functions.psm1 not loaded). Azure RBAC rows will be empty."
    }
    foreach ($a in $azRows) {
        if (-not $a) { continue }
        $principalLabel = Resolve-PimManagerPrincipalLabel -PrincipalId ([string]$a.PrincipalId)
        $roleName       = if ($a.RoleDefinitionName) { [string]$a.RoleDefinitionName } else { [string]$a.RoleDefinitionId }
        [void]$rows.Add([ordered]@{
            id               = "azure-rbac:$($a.Id)"
            type             = 'azure-rbac'
            principal        = $principalLabel
            principalId      = [string]$a.PrincipalId
            role             = $roleName
            roleDefinitionId = [string]$a.RoleDefinitionId
            scope            = [string]$a.Scope
            directoryScopeId = ''
            start            = ''  # ARG row doesn't carry start/end for the assignment record.
            end              = ''
            justification    = ''
        })
    }

    # ---- PIM-for-Groups active assignments ---------------------------------
    # Graph REFUSES an unfiltered list on assignmentSchedules ('MissingParameters:
    # The required parameters GroupId or PrincipalId is missing') -- both the
    # engine's bulk preload and a naive -All call get BadRequest. The supported
    # shape is one filtered query per group. Two scale guards:
    #   1. Only PIM-convention groups qualify (the lookup cache can contain the
    #      whole tenant when the naming filter is broad; dynamic groups fail
    #      with ResourceTypeNotSupported anyway).
    #   2. Queries go through /v1.0/$batch, 20 per round-trip -- a per-group
    #      sequential loop took >4 minutes on a real tenant.
    $pimGroupRows = @()
    $pimPrefix = 'PIM-'
    try {
        if ((Get-Command Get-PimNamePrefix -ErrorAction SilentlyContinue) -and $global:PIM_NamingConventions -and $global:PIM_NamingConventions.PimGroupPattern) {
            $p = Get-PimNamePrefix -Pattern $global:PIM_NamingConventions.PimGroupPattern
            if ($p -and $p.Length -ge 3) { $pimPrefix = $p }
        }
    } catch { }
    $pimGroupsToQuery = @($script:PimManager_Groups | Where-Object { $_ -and $_.Id -and $_.DisplayName -and ([string]$_.DisplayName).StartsWith($pimPrefix, [System.StringComparison]::OrdinalIgnoreCase) })
    if ($pimGroupsToQuery.Count -gt 0) {
        $gFail = 0
        for ($ofs = 0; $ofs -lt $pimGroupsToQuery.Count; $ofs += 20) {
            $slice = $pimGroupsToQuery[$ofs..([Math]::Min($ofs + 19, $pimGroupsToQuery.Count - 1))]
            $requests = New-Object System.Collections.ArrayList
            for ($i = 0; $i -lt $slice.Count; $i++) {
                [void]$requests.Add(@{
                    id     = "$i"
                    method = 'GET'
                    url    = "/identityGovernance/privilegedAccess/group/assignmentSchedules?`$filter=groupId eq '$($slice[$i].Id)'"
                })
            }
            try {
                $resp = Invoke-MgGraphRequest -Method POST -Uri 'https://graph.microsoft.com/v1.0/$batch' -Body (@{ requests = $requests.ToArray() } | ConvertTo-Json -Depth 6) -ContentType 'application/json' -ErrorAction Stop
                foreach ($br in @($resp.responses)) {
                    if ($br.status -ge 200 -and $br.status -lt 300 -and $br.body -and $br.body.value) {
                        foreach ($v in @($br.body.value)) { $pimGroupRows += $v }
                    } elseif ($br.status -ge 400) {
                        $gFail++
                        $errCode = if ($br.body -and $br.body.error) { $br.body.error.code } else { $br.status }
                        if ($gFail -le 3) { Write-Warning ("  [revoke] assignmentSchedules for group '{0}' failed: {1}" -f $slice[[int]$br.id].DisplayName, $errCode) }
                    }
                }
            } catch {
                $gFail += $slice.Count
                if ($gFail -le 25) { Write-Warning "  [revoke] `$batch round-trip failed: $($_.Exception.Message)" }
            }
        }
        if ($gFail -gt 3) { Write-Warning ("  [revoke] assignmentSchedules failed for {0} group(s) total (first 3 shown)." -f $gFail) }
        Write-Host ("  [revoke] pim-for-groups: {0} active assignment(s) across {1} PIM group(s) ({2} batch round-trips)" -f $pimGroupRows.Count, $pimGroupsToQuery.Count, [Math]::Ceiling($pimGroupsToQuery.Count / 20)) -ForegroundColor DarkGray
    } else {
        Write-Warning ("  [revoke] no '{0}'-prefixed groups in the lookup cache. PIM-for-Groups rows will be empty." -f $pimPrefix)
    }
    foreach ($p in $pimGroupRows) {
        if (-not $p) { continue }
        $principalLabel = Resolve-PimManagerPrincipalLabel -PrincipalId ([string]$p.PrincipalId)
        # Group display name from cache, fall back to embedded Group.DisplayName.
        $groupLabel = ''
        if ($script:PimManager_Groups) {
            foreach ($g in $script:PimManager_Groups) {
                if ($g -and "$($g.Id)" -eq [string]$p.GroupId) { $groupLabel = [string]$g.DisplayName; break }
            }
        }
        if (-not $groupLabel -and $p.Group -and $p.Group.DisplayName) { $groupLabel = [string]$p.Group.DisplayName }
        if (-not $groupLabel) { $groupLabel = [string]$p.GroupId }
        $start = $null; $end = $null
        if ($p.ScheduleInfo) {
            if ($p.ScheduleInfo.StartDateTime) { $start = ([DateTime]$p.ScheduleInfo.StartDateTime).ToUniversalTime().ToString('o') }
            if ($p.ScheduleInfo.Expiration -and $p.ScheduleInfo.Expiration.EndDateTime) {
                $end = ([DateTime]$p.ScheduleInfo.Expiration.EndDateTime).ToUniversalTime().ToString('o')
            }
        }
        $access = 'member'
        if ($p.AccessId) { $access = [string]$p.AccessId }
        [void]$rows.Add([ordered]@{
            id               = "pim-for-groups:$($p.Id)"
            type             = 'pim-for-groups'
            principal        = $principalLabel
            principalId      = [string]$p.PrincipalId
            role             = "$groupLabel ($access)"
            roleDefinitionId = ''
            scope            = $groupLabel
            directoryScopeId = ''
            groupId          = [string]$p.GroupId
            accessId         = $access
            start            = $start
            end              = $end
            justification    = if ($p.Justification) { [string]$p.Justification } else { '' }
        })
    }

    $sw.Stop()
    $elapsed = [math]::Round($sw.Elapsed.TotalSeconds, 2)
    $counts = [ordered]@{
        total           = $rows.Count
        'entra-role'    = @($rows | Where-Object { $_.type -eq 'entra-role' }).Count
        'azure-rbac'    = @($rows | Where-Object { $_.type -eq 'azure-rbac' }).Count
        'pim-for-groups' = @($rows | Where-Object { $_.type -eq 'pim-for-groups' }).Count
    }
    Write-Host ("  [revoke] active-assignments loaded: {0} total ({1}e + {2}a + {3}g) in {4}s" -f $counts.total, $counts['entra-role'], $counts['azure-rbac'], $counts['pim-for-groups'], $elapsed) -ForegroundColor DarkGray

    $loadedUtc = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    $payload = [ordered]@{
        ok         = $true
        rows       = $rows.ToArray()
        counts     = $counts
        loadedUtc  = $loadedUtc
        cacheHit   = $false
        elapsedSec = $elapsed
    }
    $script:PimActiveAssignmentsCache = [ordered]@{
        rows      = $payload.rows
        counts    = $payload.counts
        loadedUtc = $payload.loadedUtc
    }
    $script:PimActiveAssignmentsCacheLoadedUtc = [DateTime]::UtcNow
    return $payload
}

function Invoke-PimActiveAssignmentRevokeBatch {
    # Returns an array of per-row { id, ok, error? } in the same order as $Rows.
    param(
        [Parameter(Mandatory)][object[]]$Rows,
        [Parameter(Mandatory)][string]$Justification
    )

    Initialize-PimManagerTenantConnection

    $results = New-Object System.Collections.ArrayList
    foreach ($r in $Rows) {
        if (-not $r) {
            [void]$results.Add([ordered]@{ id = $null; ok = $false; error = 'null row' })
            continue
        }
        $rowId = if ($r.id) { [string]$r.id } else { '' }
        $type  = if ($r.type) { [string]$r.type } else { '' }
        try {
            switch ($type) {
                'entra-role' {
                    # Trim a possible roleDefinitions/<guid> prefix that the
                    # original schedule object carries -- the BodyParameter
                    # expects the bare GUID.
                    $roleDefId = [string]$r.roleDefinitionId
                    if ($roleDefId -and $roleDefId.Contains('/')) {
                        $roleDefId = $roleDefId.Substring($roleDefId.LastIndexOf('/') + 1)
                    }
                    $directoryScopeId = if ($r.directoryScopeId) { [string]$r.directoryScopeId } else { '/' }
                    $params = @{
                        action           = 'adminRemove'
                        principalId      = [string]$r.principalId
                        roleDefinitionId = $roleDefId
                        directoryScopeId = $directoryScopeId
                        justification    = $Justification
                    }
                    $resp = New-MgRoleManagementDirectoryRoleAssignmentScheduleRequest -BodyParameter $params -ErrorAction Stop
                    [void]$results.Add([ordered]@{ id = $rowId; ok = $true; requestId = "$($resp.Id)" })
                    Write-Host ("  [revoke][entra-role] OK -- principal {0} role {1}" -f $r.principalId, $roleDefId) -ForegroundColor DarkGray
                }
                'azure-rbac' {
                    $scope = [string]$r.scope
                    if ([string]::IsNullOrWhiteSpace($scope)) {
                        throw "missing scope for azure-rbac row"
                    }
                    $roleDefId = [string]$r.roleDefinitionId
                    if ($roleDefId -and $roleDefId.Contains('/')) {
                        $roleDefId = $roleDefId.Substring($roleDefId.LastIndexOf('/') + 1)
                    }
                    $newGuid = [Guid]::NewGuid().ToString()
                    $uri = $scope.TrimEnd('/') + '/providers/Microsoft.Authorization/roleAssignmentScheduleRequests/' + $newGuid + '?api-version=2020-10-01'
                    $body = @{
                        properties = @{
                            principalId      = [string]$r.principalId
                            roleDefinitionId = "$scope/providers/Microsoft.Authorization/roleDefinitions/$roleDefId"
                            requestType      = 'AdminRemove'
                            justification    = $Justification
                        }
                    }
                    $bodyJson = $body | ConvertTo-Json -Depth 10 -Compress
                    $resp = Invoke-AzRestMethod -Method PUT -Path $uri -Payload $bodyJson -ErrorAction Stop
                    if ($resp.StatusCode -ge 200 -and $resp.StatusCode -lt 300) {
                        [void]$results.Add([ordered]@{ id = $rowId; ok = $true; statusCode = $resp.StatusCode })
                        Write-Host ("  [revoke][azure-rbac] OK ({0}) -- principal {1} scope {2}" -f $resp.StatusCode, $r.principalId, $scope) -ForegroundColor DarkGray
                    } else {
                        $errText = "HTTP $($resp.StatusCode): $($resp.Content)"
                        [void]$results.Add([ordered]@{ id = $rowId; ok = $false; error = $errText })
                        Write-Warning ("  [revoke][azure-rbac] FAIL -- {0}" -f $errText)
                    }
                }
                'pim-for-groups' {
                    $accessId = if ($r.accessId) { [string]$r.accessId } else { 'member' }
                    $params = @{
                        accessId      = $accessId
                        principalId   = [string]$r.principalId
                        groupId       = [string]$r.groupId
                        action        = 'adminRemove'
                        justification = $Justification
                    }
                    $resp = New-MgIdentityGovernancePrivilegedAccessGroupAssignmentScheduleRequest -BodyParameter $params -ErrorAction Stop
                    [void]$results.Add([ordered]@{ id = $rowId; ok = $true; requestId = "$($resp.Id)" })
                    Write-Host ("  [revoke][pim-for-groups] OK -- principal {0} group {1}" -f $r.principalId, $r.groupId) -ForegroundColor DarkGray
                }
                default {
                    throw "unknown row type: '$type' (expected entra-role | azure-rbac | pim-for-groups)"
                }
            }
        } catch {
            $msg = "$($_.Exception.Message)"
            [void]$results.Add([ordered]@{ id = $rowId; ok = $false; error = $msg })
            Write-Warning ("  [revoke][{0}] FAIL -- {1}" -f $type, $msg)
        }
    }

    return $results.ToArray()
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
            # A served request IS client activity. Long-running endpoints
            # (active-assignments took 90s on a real tenant) block the
            # single-threaded loop, so the browser's 10s heartbeats queue
            # unprocessed -- without this, the server reaped itself right
            # after answering the slow request.
            $script:lastHeartbeat = Get-Date
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
        $json = ConvertTo-PimJson -Body $data
        $naming = Get-PimNamingConventions
        $namingJson = ConvertTo-PimJson -Body $naming
        $tenantLists = Read-PimTenantListCache
        $tenantJson  = ConvertTo-PimJson -Body $tenantLists
        # NB: foreach statement, not pipeline -- Get-PimManagerInstances returns a
        # comma-wrapped array, and piping that sends the WHOLE array as one item
        # (member enumeration then collapses .name into a string[]).
        $instList = New-Object System.Collections.ArrayList
        foreach ($i in (Get-PimManagerInstances)) { [void]$instList.Add([ordered]@{ name = $i.name; configRoot = $i.configRoot }) }
        $instJson = ConvertTo-PimJson -Body ([ordered]@{
            active    = $script:PimInstanceName
            instances = $instList.ToArray()
        })
        $html = [System.IO.File]::ReadAllText($template, [System.Text.UTF8Encoding]::new($true))
        $html = $html.Replace('__PIM_DATA__', $json).Replace('__PIM_TOKEN__', $ExpectedToken).Replace('__PIM_MODE__', 'server').Replace('__PIM_NAMING__', $namingJson).Replace('__PIM_TENANT_LISTS__', $tenantJson).Replace('__PIM_INSTANCES__', $instJson).Replace('__PIM_VERSION__', (Get-PimSolutionVersion))
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

        # -------------------------------------------------------------------
        # Admin templates (LIFECYCLE-GOVERNANCE phase 2) -- prestaged admin
        # settings for the onboarding wizard. Shipped *.admintemplate.json +
        # customer *.admintemplate.custom.json (additive; same id in a custom
        # file overrides the shipped one).
        # -------------------------------------------------------------------
        if ($path -eq '/api/admin-templates' -and $method -eq 'GET') {
            $script:lastHeartbeat = Get-Date
            $tplDir = Join-Path $solutionRoot 'templates\admin'
            $byId = @{}
            if (Test-Path -LiteralPath $tplDir) {
                $files = @(Get-ChildItem -LiteralPath $tplDir -Filter '*.admintemplate.json' -ErrorAction SilentlyContinue) +
                         @(Get-ChildItem -LiteralPath $tplDir -Filter '*.admintemplate.custom.json' -ErrorAction SilentlyContinue)
                foreach ($f in $files) {
                    try {
                        $tpl = Get-Content -LiteralPath $f.FullName -Raw -Encoding UTF8 | ConvertFrom-Json
                        if ($tpl.id) { $byId[$tpl.id] = $tpl }   # custom files enumerate last -> same id wins
                    } catch {
                        Write-Warning "admin template '$($f.Name)' unreadable: $($_.Exception.Message)"
                    }
                }
            }
            Write-JsonResponse -Response $resp -Status 200 -Body @{ templates = @($byId.Values | Sort-Object { $_.name }) }
            return 200
        }

        # -------------------------------------------------------------------
        # Date-expression live preview (LIFECYCLE-GOVERNANCE phase 1) --
        # the onboarding wizard previews ProvisionDate / TAPStartDate while
        # the operator types ("resolves to Mon 2026-07-01 08:00 UTC").
        # -------------------------------------------------------------------
        if ($path -eq '/api/resolve-date' -and $method -eq 'GET') {
            $script:lastHeartbeat = Get-Date
            $expr = $req.QueryString['expr']
            if (-not $expr -or -not (Get-Command Resolve-PimDateExpression -ErrorAction SilentlyContinue)) {
                Write-JsonResponse -Response $resp -Status 200 -Body @{ ok = $false; error = $(if ($expr) { 'resolver not loaded' } else { 'expr query parameter required' }) }
                return 200
            }
            try {
                $resolved = Resolve-PimDateExpression -Expression $expr
                Write-JsonResponse -Response $resp -Status 200 -Body @{
                    ok       = $true
                    utc      = $resolved.ToString('yyyy-MM-dd HH:mm')
                    display  = $resolved.ToLocalTime().ToString('ddd yyyy-MM-dd HH:mm') + ' (local)'
                }
            } catch {
                Write-JsonResponse -Response $resp -Status 200 -Body @{ ok = $false; error = "$($_.Exception.Message)" }
            }
            return 200
        }

        # -------------------------------------------------------------------
        # MSP multi-instance endpoints
        # -------------------------------------------------------------------
        # -------------------------------------------------------------------
        # Permission templates -- centrally maintained delegation packs
        # (templates/*.template.json ships with the repo; sync distributes).
        # The endpoint diffs each template against the ACTIVE instance and
        # reports the rows the instance doesn't have yet, so the UI can show
        # 'new permissions available to delegate' when a template grows.
        # -------------------------------------------------------------------
        if ($path -eq '/api/templates' -and $method -eq 'GET') {
            $script:lastHeartbeat = Get-Date
            function Get-PimTemplateRowKey {
                param([string]$Base, [object]$Row)
                $g = { param($p) $x = $Row.PSObject.Properties[$p]; if ($x -and $x.Value) { "$($x.Value)" } else { '' } }
                switch -Wildcard ($Base) {
                    'PIM-Definitions-AU'              { return (& $g 'AdministrativeUnitTag') }
                    'PIM-Definitions-*'               { return (& $g 'GroupTag') }
                    'Account-Definitions-Admins'      { return (& $g 'UserName') }
                    'PIM-Assignments-Admins'          { return ((& $g 'Username') + '|' + (& $g 'GroupTag')) }
                    'PIM-Assignments-Groups'          { return ((& $g 'TargetGroupTag') + '|' + (& $g 'SourceGroupTag')) }
                    'PIM-Assignments-Roles-Groups'    { return ((& $g 'GroupTag') + '|' + (& $g 'RoleDefinitionName')) }
                    'PIM-Assignments-Roles-AUs'       { return ((& $g 'GroupTag') + '|' + (& $g 'AdministrativeUnitTag') + '|' + (& $g 'RoleDefinitionName')) }
                    'PIM-Assignments-Azure-Resources' { return ((& $g 'GroupTag') + '|' + (& $g 'AzScope') + '|' + (& $g 'AzScopePermission')) }
                    default { return '' }
                }
            }
            $tplDir = Join-Path $solutionRoot 'templates'
            $outList = New-Object System.Collections.ArrayList
            if (Test-Path -LiteralPath $tplDir) {
                foreach ($f in (Get-ChildItem $tplDir -Filter '*.template.json' -File | Sort-Object Name)) {
                    try {
                        $raw = [System.IO.File]::ReadAllText($f.FullName, [System.Text.UTF8Encoding]::new($false))
                        if ($raw.Length -gt 0 -and [int][char]$raw[0] -eq 0xFEFF) { $raw = $raw.Substring(1) }
                        $tpl = $raw | ConvertFrom-Json
                        $missing = [ordered]@{}
                        $missingCount = 0
                        $totalCount = 0
                        foreach ($baseProp in $tpl.rows.PSObject.Properties) {
                            $base = $baseProp.Name
                            if (-not (Get-PimCsvSpec -BaseName $base)) { continue }
                            $current = Read-PimCsvRows -BaseName $base
                            $existing = @{}
                            foreach ($r in $current.rows) {
                                $k = Get-PimTemplateRowKey -Base $base -Row ([pscustomobject]$r)
                                if ($k -and $k -ne '|' ) { $existing[$k.ToLowerInvariant()] = $true }
                            }
                            $miss = New-Object System.Collections.ArrayList
                            foreach ($tr in @($baseProp.Value)) {
                                $totalCount++
                                $k = Get-PimTemplateRowKey -Base $base -Row $tr
                                if ($k -and -not $existing.ContainsKey($k.ToLowerInvariant())) { [void]$miss.Add($tr) }
                            }
                            if ($miss.Count -gt 0) { $missing[$base] = $miss.ToArray(); $missingCount += $miss.Count }
                        }
                        [void]$outList.Add([ordered]@{
                            id = "$($tpl.id)"; name = "$($tpl.name)"; version = $tpl.version
                            description = "$($tpl.description)"
                            totalRows = $totalCount; missingCount = $missingCount; missing = $missing
                        })
                    } catch {
                        [void]$outList.Add([ordered]@{ id = $f.Name; error = "$($_.Exception.Message)" })
                    }
                }
            }
            Write-JsonResponse -Response $resp -Status 200 -Body ([ordered]@{ templates = $outList.ToArray() })
            return 200
        }

        # -------------------------------------------------------------------
        # Workload connectors (docs/WORKLOAD-CONNECTORS.md)
        # -------------------------------------------------------------------
        if ($path -eq '/api/workloads' -and $method -eq 'GET') {
            $script:lastHeartbeat = Get-Date
            $shared = Join-Path $PSScriptRoot '..\..\engine\_shared\PIM-Functions.psm1'
            if (-not (Get-Command Read-PimWorkloadConnectors -ErrorAction SilentlyContinue) -and (Test-Path -LiteralPath $shared)) {
                Import-Module $shared -Global -Force -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
            }
            $dir = Join-Path $solutionRoot 'workloads\connectors'
            $list = New-Object System.Collections.ArrayList
            foreach ($c in @(Read-PimWorkloadConnectors -ConnectorsDir $dir)) {
                [void]$list.Add([ordered]@{ id = "$($c.id)"; name = "$($c.name)"; auth = "$($c.auth)"; permissionsNeeded = @($c.permissionsNeeded) })
            }
            Write-JsonResponse -Response $resp -Status 200 -Body ([ordered]@{ workloads = $list.ToArray() })
            return 200
        }

        if ($path -eq '/api/workload-roles' -and $method -eq 'GET') {
            $script:lastHeartbeat = Get-Date
            $wid = ''
            if ($req.Url.Query -match '(\?|&)id=([^&]+)') { $wid = [uri]::UnescapeDataString($Matches[2]) }
            if (-not $wid) { Write-JsonResponse -Response $resp -Status 400 -Body @{ error = 'id query parameter is required' }; return 400 }
            $shared = Join-Path $PSScriptRoot '..\..\engine\_shared\PIM-Functions.psm1'
            if (-not (Get-Command Get-PimWorkloadRoles -ErrorAction SilentlyContinue) -and (Test-Path -LiteralPath $shared)) {
                Import-Module $shared -Global -Force -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
            }
            $dir = Join-Path $solutionRoot 'workloads\connectors'
            $conn = @(Read-PimWorkloadConnectors -ConnectorsDir $dir) | Where-Object { "$($_.id)" -ieq $wid } | Select-Object -First 1
            if (-not $conn) { Write-JsonResponse -Response $resp -Status 404 -Body @{ error = "unknown workload connector: $wid" }; return 404 }
            try {
                # Live tenant call -- requires the app-only connection
                # (-ConnectPlatform / per-instance connection).
                Initialize-PimManagerTenantConnection
                $roles = @(Get-PimWorkloadRoles -Connector $conn)
                Write-JsonResponse -Response $resp -Status 200 -Body ([ordered]@{ id = $wid; roles = $roles })
                return 200
            } catch {
                Write-JsonResponse -Response $resp -Status 502 -Body @{ error = "$($_.Exception.Message)" }
                return 502
            }
        }

        if ($path -eq '/api/instances' -and $method -eq 'GET') {
            $script:lastHeartbeat = Get-Date
            # foreach statement, not pipeline -- see the GET / handler note.
            $instList = New-Object System.Collections.ArrayList
            foreach ($i in (Get-PimManagerInstances)) { [void]$instList.Add([ordered]@{ name = $i.name; configRoot = $i.configRoot }) }
            Write-JsonResponse -Response $resp -Status 200 -Body ([ordered]@{
                active    = $script:PimInstanceName
                instances = $instList.ToArray()
            })
            return 200
        }

        if ($path -eq '/api/instance' -and $method -eq 'POST') {
            $script:lastHeartbeat = Get-Date
            $body = Read-RequestJson -Request $req
            $name = if ($body -and $body.name) { "$($body.name)" } else { '' }
            if (-not $name) {
                Write-JsonResponse -Response $resp -Status 400 -Body @{ ok = $false; error = 'instance name is required' }
                return 400
            }
            try {
                Set-PimManagerInstance -Name $name
                Write-JsonResponse -Response $resp -Status 200 -Body ([ordered]@{ ok = $true; active = $script:PimInstanceName })
                return 200
            } catch {
                Write-JsonResponse -Response $resp -Status 400 -Body @{ ok = $false; error = "$($_.Exception.Message)" }
                return 400
            }
        }

        if ($path -eq '/api/preflight' -and $method -eq 'GET') {
            $script:lastHeartbeat = Get-Date
            if (-not (Get-Command Invoke-PimPreflightValidation -ErrorAction SilentlyContinue)) {
                Write-JsonResponse -Response $resp -Status 500 -Body @{ error = '_validator.ps1 was not loaded -- file missing next to Open-PimManager.ps1' }
                return 500
            }
            try {
                # Cache keyed on instance + the CSVs' LastWriteTimes: every page
                # load auto-runs preflight, and the validator costs seconds on
                # the single-threaded server. Unchanged inputs -> cached report.
                $stamp = $script:PimInstanceName
                foreach ($spec in (Get-PimCsvBases)) {
                    $resolved = Resolve-PimCsvPath -BaseName $spec.base
                    if ($resolved) { $stamp += '|' + $spec.base + ':' + ([System.IO.File]::GetLastWriteTimeUtc($resolved.Path).Ticks) }
                }
                if ($script:PimPreflightCacheStamp -eq $stamp -and $script:PimPreflightCacheReport) {
                    Write-JsonResponse -Response $resp -Status 200 -Body $script:PimPreflightCacheReport
                    return 200
                }
                $report = Invoke-PimPreflightValidation
                $script:PimPreflightCacheStamp  = $stamp
                $script:PimPreflightCacheReport = $report
                Write-JsonResponse -Response $resp -Status 200 -Body $report
                return 200
            } catch {
                Write-JsonResponse -Response $resp -Status 500 -Body @{ error = "$($_.Exception.Message)" }
                return 500
            }
        }

        # -------------------------------------------------------------------
        # v2.4.2 Revoke tab endpoints
        # -------------------------------------------------------------------
        if ($path -like '/api/active-assignments*' -and $method -eq 'GET') {
            $script:lastHeartbeat = Get-Date
            $forceRefresh = $false
            try {
                $qs = $req.Url.Query
                if ($qs -and $qs.IndexOf('refresh=1') -ge 0) { $forceRefresh = $true }
            } catch { }
            try {
                $body = Get-PimActiveAssignmentsCached -Force:$forceRefresh
                Write-JsonResponse -Response $resp -Status 200 -Body $body
                return 200
            } catch {
                Write-JsonResponse -Response $resp -Status 500 -Body @{ ok = $false; error = "$($_.Exception.Message)" }
                return 500
            }
        }

        if ($path -eq '/api/revoke' -and $method -eq 'POST') {
            $script:lastHeartbeat = Get-Date
            $body = Read-RequestJson -Request $req
            $justification = $null
            $rowsIn = @()
            if ($body) {
                if ($body.justification) { $justification = "$($body.justification)" }
                if ($body.rows)          { $rowsIn = @($body.rows) }
            }
            if (-not $justification -or [string]::IsNullOrWhiteSpace($justification)) {
                Write-JsonResponse -Response $resp -Status 400 -Body @{ ok = $false; error = 'justification is required' }
                return 400
            }
            if (-not $rowsIn -or $rowsIn.Count -eq 0) {
                Write-JsonResponse -Response $resp -Status 400 -Body @{ ok = $false; error = 'at least one row is required' }
                return 400
            }
            try {
                $results = Invoke-PimActiveAssignmentRevokeBatch -Rows $rowsIn -Justification $justification
                # Invalidate the active-assignments cache so the next GET re-fetches truth.
                $script:PimActiveAssignmentsCache          = $null
                $script:PimActiveAssignmentsCacheLoadedUtc = $null
                Write-JsonResponse -Response $resp -Status 200 -Body ([ordered]@{
                    ok       = $true
                    requested = $rowsIn.Count
                    results  = $results
                })
                return 200
            } catch {
                Write-JsonResponse -Response $resp -Status 500 -Body @{ ok = $false; error = "$($_.Exception.Message)" }
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
