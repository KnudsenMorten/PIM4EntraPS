#Requires -Version 7.0

<#
.SYNOPSIS
  Imports the data of a PIM version 1 installation (its CSV files and naming conventions) into an existing PIM Manager installation. By default it only checks and previews -- it writes nothing; -Apply adds the new rows by key, never deletes, and stops before writing anything when a row conflicts.

.DESCRIPTION
  V1-IMPORT-PUBLISHED. The person-facing wrapper around PIM Manager's own importer (Migrate-PimToSql.ps1, which runs the
  pre-import check engine\_shared\PIM-CsvImportCheck.ps1 and writes through the store's Merge-PimSqlEntityRows). Nothing
  of that logic is repeated here; this script finds the installation, signs you in, makes the network path for the run,
  and turns the importer's result into a plain list.

  What it does, in order:
    1. Signs you in through the browser (or uses the Invardia Support app's session open in this window), pinned to
       -TenantId and -SubscriptionId.
    2. Finds the PIM store over Azure Resource Manager: the SQL server in the subscription (or in -ResourceGroup) that
       holds the database -Database (PimPlatform). More than one: it lists them and asks for -ResourceGroup.
    3. Network: a machine that reaches the SQL server over the private network (its name resolves to a private address
       that answers on port 1433 -- inside the installation's network, a VPN or a peered network) goes straight on, with
       no firewall rule. Otherwise: a server with public access off stops the run (run it from a machine inside the
       installation's network, or ask Invardia support), and a server with public access but no firewall rule for this
       machine gets a TEMPORARY rule for this machine's address, removed again at the end of the run -- also when the
       run fails.
    4. Signs in to the database as you and checks your access first (a member of the installation's SQL admin group, or
       a database user; -Apply needs the database owner role, which the SQL admin group gives).
    5. Checks the files and previews the import: per file the rows to add, the rows already there (same), the
       CONFLICTS (same key, different content) and the problems the check found. Writes nothing.
    6. Only with -Apply: adds the new rows by key (never deletes), then reads the store again to prove they are there.
       A conflicting row stops the run before anything is written, unless -OnKeyConflict KeepExisting or Overwrite is
       given. The importer also brings over the naming conventions file (the values you changed from the defaults; a
       value already changed in PIM Manager is kept) and, only into a setting that is still empty, the warning
       overrides, exemptions and workload exemptions files of the folder.

  Files read from -SourcePath: the PIM entity files (<name>.custom.csv first, else <name>.csv) and
  PIM4EntraPS.NamingConventions.custom.ps1. The engine's state files (*_Delta.csv, *_LastApplied.csv) and files that are
  not PIM data are skipped and listed. The files themselves are never changed.

  The naming conventions file is a PowerShell file, and the importer loads it (dot-sources it) to read its values -- that
  is how PIM version 1 read it too. Before anything is loaded, this script parses it and REFUSES a file that contains
  commands (anything other than values assigned to $global:PIM_NamingConventions), so no code from the folder runs.

  The output is one calm line per step. The full check report and the importer's own lines are in a details file next
  to the transcript ("More: <file>"); the transcript path is printed at the start and at the end.

  -WhatIf: signs in and reads, but does not add the temporary firewall rule; when the database cannot be reached without
  one, it says so and reads no rows.

  Exit codes: 0 done (preview shown, or imported and read back); 1 stopped -- the reason and the next step are printed,
  nothing was written; 2 the temporary firewall rule could NOT be removed -- the rule name to delete by hand is printed.

.PARAMETER SourcePath
  The PIM version 1 data folder (holds the *.custom.csv files and PIM4EntraPS.NamingConventions.custom.ps1).
.PARAMETER TenantId
  The tenant of the PIM Manager installation. Every sign-in is pinned to it.
.PARAMETER SubscriptionId
  The subscription of the PIM Manager installation.
.PARAMETER ResourceGroup
  The installation's resource group. Needed only when the subscription holds more than one PIM store.
.PARAMETER SqlServerName
  The installation's SQL server. Needed only when one resource group holds more than one PIM store.
.PARAMETER Database
  The PIM database. Default PimPlatform.
.PARAMETER Apply
  Write: add the new rows by key. Without it the run only checks and previews.
.PARAMETER OnKeyConflict
  What -Apply does with a row whose key is already in PIM Manager with different content: Refuse (default -- nothing is
  written), KeepExisting (PIM Manager's row stays, the rest is imported), Overwrite (the file's row replaces it).
.PARAMETER ForceLocal
  Imported rows stay on this tenant (Replicate=No; admins ManagementMode=local) unless the file sets the value.
.PARAMETER MspMaster
  Give it when the installation is an MSP managing tenant: the check then also shows what each row would send to the
  managed tenants. Without it the installation is treated as a single tenant.
.PARAMETER NotMspMaster
  Not needed any more (single tenant is the default); still accepted so older command lines keep working.
.PARAMETER DefaultDomain
  The tenant's default sign-in domain, for admin rows that have a user name but no user principal name.
.PARAMETER AllowValidationErrors
  Import even though the check found errors in the files (they are listed). Without it -Apply refuses such files.
.PARAMETER ClientIp
  This machine's public address for the temporary firewall rule. Without it the address is read from api.ipify.org.

.EXAMPLE
  .\Import-PimV1Data.ps1 -SourcePath C:\PIM\config -TenantId <tenant id> -SubscriptionId <subscription id>
  Checks the files and previews the import. Nothing is written.
.EXAMPLE
  .\Import-PimV1Data.ps1 -SourcePath C:\PIM\config -TenantId <tenant id> -SubscriptionId <subscription id> -Apply
  Imports: adds the new rows by key, never deletes. Stops before writing anything when a row conflicts.

.NOTES
  Requirements:
    PowerShell: 7.0 or later (pwsh). Windows PowerShell 5.1 is not supported.
    Role: a member of the installation's SQL admin group (grp-pim-sql-admins) or a database user in the PIM database
          (-Apply: the database owner role, which the SQL admin group gives); Reader on the installation's subscription
          or resource group to find it; SQL Server Contributor (or Contributor) on the SQL server only when a temporary
          firewall rule is needed.
    Hosts: login.microsoftonline.com, management.azure.com, *.database.windows.net (port 1433),
           api.ipify.org (this machine's public address, unless -ClientIp is given)

.LINK
  https://invardia.com/docs/pim/scripts/Import-PimV1Data/
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$SourcePath,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$')][string]$TenantId,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$')][string]$SubscriptionId,
    [string]$ResourceGroup = '',
    [string]$SqlServerName = '',
    [string]$Database = 'PimPlatform',
    [switch]$Apply,
    [ValidateSet('Refuse', 'KeepExisting', 'Overwrite')][string]$OnKeyConflict = 'Refuse',
    [switch]$ForceLocal,
    [switch]$MspMaster,
    [switch]$NotMspMaster,
    [string]$DefaultDomain = '',
    [switch]$AllowValidationErrors,
    [ValidatePattern('^$|^\d{1,3}(\.\d{1,3}){3}$')][string]$ClientIp = '',
    # --- test seams (tests/Test-PimV1Import.ps1); omit them for a real run ---
    [scriptblock]$Arm,
    [scriptblock]$Sql,
    [scriptblock]$Sleep,
    [scriptblock]$Probe
)
$ErrorActionPreference = 'Stop'
# Published as ONE file (https://invardia.com/support/pim/Import-PimV1Data.ps1). The doc helper is inlined by
# Build-PimSupportScripts.ps1; the importer and the libraries it loads travel inside this file (BUILD-EMBED below) and are
# written to a private temporary folder for the run, so the importer runs exactly as it does from the repository.
. (Join-Path $PSScriptRoot '_PimScriptDoc.ps1')

# The files the importer needs, by name -> their folder in the solution. In the repository they are copied from there; in
# the published copy they come from the embedded table. tests/Test-PimV1Import.ps1 holds this list and the BUILD-EMBED
# line to the same set.
$script:PimV1ImportLayout = [ordered]@{
    'Migrate-PimToSql.ps1'        = 'tools\setup'
    '_PimSignedIn.ps1'            = 'tools\setup'
    'PIM-ChangeQueue.ps1'         = 'engine\_shared'
    'PIM-Rest.ps1'                = 'engine\_shared'
    'PIM-LoopbackAnswer.ps1'      = 'engine\_shared'
    'PIM-SqlStore.ps1'            = 'engine\_shared'
    'PIM-CsvImportCheck.ps1'      = 'engine\_shared'
    'PIM-DateSafe.ps1'            = 'engine\_shared'
    'PIM-Naming.ps1'              = 'engine\_shared'
    'PIM-PolicyTemplateStore.ps1' = 'engine\_shared'
    'PIM-PolicyBaseline.ps1'      = 'engine\_shared'
    'PIM-WorkloadMap.ps1'         = 'engine\_shared'
    'PIM-Rings.ps1'               = 'engine\_shared'
    'PIM-RoleAssignable.ps1'      = 'engine\_shared'
    'PIM-DateExpression.ps1'      = 'engine\_shared'
    'PIM-WarningOverrides.ps1'    = 'engine\_shared'
    'PIM-AdminExistingAccount.ps1' = 'engine\_shared'
    '_validator.ps1'              = 'tools\pim-manager'
}
# OWNER 2026-11-07 (OPEN-23, §84): the published single file carries NO Pro code -- the managing-tenant (MSP) library
# engine\msp\PIM-Downlink.ps1 is not in this list or embedded. The check then reports replication as "not computed".
$script:PimV1ImportPayload = @{}   # BUILD-EMBED: Migrate-PimToSql.ps1, _PimSignedIn.ps1, ../../engine/_shared/PIM-ChangeQueue.ps1, ../../engine/_shared/PIM-Rest.ps1, ../../engine/_shared/PIM-LoopbackAnswer.ps1, ../../engine/_shared/PIM-SqlStore.ps1, ../../engine/_shared/PIM-CsvImportCheck.ps1, ../../engine/_shared/PIM-DateSafe.ps1, ../../engine/_shared/PIM-Naming.ps1, ../../engine/_shared/PIM-PolicyTemplateStore.ps1, ../../engine/_shared/PIM-PolicyBaseline.ps1, ../../engine/_shared/PIM-WorkloadMap.ps1, ../../engine/_shared/PIM-Rings.ps1, ../../engine/_shared/PIM-RoleAssignable.ps1, ../../engine/_shared/PIM-DateExpression.ps1, ../../engine/_shared/PIM-WarningOverrides.ps1, ../../engine/_shared/PIM-AdminExistingAccount.ps1, ../pim-manager/_validator.ps1
# The entity schema the check reads (PIM Manager's own $script:PimCsvBases): only that one statement travels, not the Manager.
$script:PimV1ImportSchema = ''   # BUILD-EMBED-ASSIGNMENT: ../pim-manager/Open-PimManager.ps1 $script:PimCsvBases
$script:PimV1SqlApi = '2021-11-01'

function Get-PimV1ImportAssignmentText {
    # PURE given the file: the text of the ONE assignment to -Variable in -Path (parsed, never run). Throws when missing.
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Variable)
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$null, [ref]$null)
    $want = ("$Variable" -replace '^\$', '')
    $a = $ast.Find({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and $n.Left -is [System.Management.Automation.Language.VariableExpressionAst] -and "$($n.Left.VariablePath.UserPath)" -ieq $want }, $true)
    if (-not $a) { throw "no assignment to `$$want in $Path" }
    return $a.Extent.Text
}

function New-PimV1ImportStage {
    <#
      Writes the importer and its libraries to a new private folder in the user's temp folder, in the solution's own
      layout, and returns its path. -SolutionRoot (repository) copies the files; otherwise they come from the embedded
      table (published copy). The entity schema is written as a one-statement tools\pim-manager\Open-PimManager.ps1.
    #>
    param([string]$SolutionRoot = '')
    $stage = Join-Path ([IO.Path]::GetTempPath()) ('pim-v1import-' + [guid]::NewGuid().ToString('N').Substring(0, 12))
    [void][IO.Directory]::CreateDirectory($stage)
    $embedded = ($script:PimV1ImportPayload -is [hashtable]) -and $script:PimV1ImportPayload.Count
    foreach ($leaf in @($script:PimV1ImportLayout.Keys)) {
        $dir = Join-Path $stage $script:PimV1ImportLayout[$leaf]
        [void][IO.Directory]::CreateDirectory($dir)
        $dst = Join-Path $dir $leaf
        # §84 P6 (OPEN-23): the managing-tenant (MSP) library is Pro code and is not in the public Community release. The check
        # runs without it (PIM-CsvImportCheck.ps1 then skips the replication report), so a Community copy imports too.
        $optional = ($script:PimV1ImportLayout[$leaf] -like 'engine\msp*')
        if ($embedded) {
            if (-not $script:PimV1ImportPayload.ContainsKey($leaf)) { if ($optional) { continue }; throw "this copy of Import-PimV1Data.ps1 is incomplete ($leaf is missing) -- download it again" }
            [IO.File]::WriteAllBytes($dst, [Convert]::FromBase64String($script:PimV1ImportPayload[$leaf]))
        } else {
            $src = Join-Path (Join-Path $SolutionRoot $script:PimV1ImportLayout[$leaf]) $leaf
            if (-not (Test-Path -LiteralPath $src)) { if ($optional) { continue }; throw "the importer file $src is not there" }
            [IO.File]::WriteAllBytes($dst, [IO.File]::ReadAllBytes($src))
        }
    }
    $schema = if ("$($script:PimV1ImportSchema)".Trim()) { [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($script:PimV1ImportSchema)) }
              else { Get-PimV1ImportAssignmentText -Path (Join-Path $SolutionRoot 'tools\pim-manager\Open-PimManager.ps1') -Variable 'script:PimCsvBases' }
    [IO.File]::WriteAllText((Join-Path (Join-Path $stage 'tools\pim-manager') 'Open-PimManager.ps1'), $schema, (New-Object System.Text.UTF8Encoding($false)))
    [void][IO.Directory]::CreateDirectory((Join-Path $stage 'empty'))   # -OutputDir / -MailTemplateDir: nothing from there
    return $stage
}

function Test-PimV1NamingFileSafe {
    <#
      PURE given the file. The importer dot-sources the naming conventions file. Before it may, the file must hold values
      only: no command (a cmdlet, a function, a dot-source, a script call), no method call on a type ([IO.File]::...), no
      script block. Returns @{ ok; reason }.
    #>
    param([Parameter(Mandatory)][string]$Path)
    $perr = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$null, [ref]$perr)
    if (@($perr).Count) { return @{ ok = $false; reason = "it is not valid PowerShell (line $($perr[0].Extent.StartLineNumber): $($perr[0].Message))" } }
    $bad = $ast.Find({
        param($n)
        $n -is [System.Management.Automation.Language.CommandAst] -or
        $n -is [System.Management.Automation.Language.ScriptBlockExpressionAst] -or
        $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -or
        ($n -is [System.Management.Automation.Language.InvokeMemberExpressionAst] -and ($n.Static -or "$($n.Member.Extent.Text)" -notin @('Add', 'Remove', 'Clear', 'ContainsKey', 'ToLower', 'ToUpper', 'ToLowerInvariant', 'ToUpperInvariant', 'Trim', 'Replace', 'Split')))
    }, $true)
    if ($bad) { return @{ ok = $false; reason = "it runs a command (line $($bad.Extent.StartLineNumber): $(("$($bad.Extent.Text)" -split "`n")[0].Trim()))" } }
    return @{ ok = $true; reason = '' }
}

function Test-PimV1IpInRange {
    # PURE. Is -Ip inside start..end (IPv4)?
    param([string]$Ip, [string]$Start, [string]$End)
    $n = { param($s) $b = [System.Net.IPAddress]::Parse("$s").GetAddressBytes(); [uint32](([uint32]$b[0] -shl 24) -bor ([uint32]$b[1] -shl 16) -bor ([uint32]$b[2] -shl 8) -bor [uint32]$b[3]) }
    try { $x = & $n $Ip; return ($x -ge (& $n $Start) -and $x -le (& $n $End)) } catch { return $false }
}

function Test-PimV1PrivateAddress {
    # PURE. Is -Ip an IPv4 private address (10/8, 172.16/12, 192.168/16)?
    param([string]$Ip)
    return ((Test-PimV1IpInRange -Ip $Ip -Start '10.0.0.0' -End '10.255.255.255') -or
            (Test-PimV1IpInRange -Ip $Ip -Start '172.16.0.0' -End '172.31.255.255') -or
            (Test-PimV1IpInRange -Ip $Ip -Start '192.168.0.0' -End '192.168.255.255'))
}

function Test-PimV1PrivatePath {
    # V1-IMPORT-PRIVATE (a customer, 2026-11-11): does THIS machine reach the SQL server over the private network -- the server name
    # resolves to a private address (the private endpoint) and port 1433 answers there? Then no firewall rule is needed,
    # also when public network access is off. Returns @{ private; address; resolved }.
    param([string]$Fqdn, [int]$TimeoutMs = 5000)
    $addrs = @()
    try { $addrs = @([System.Net.Dns]::GetHostAddresses($Fqdn) | Where-Object { $_.AddressFamily -eq 'InterNetwork' } | ForEach-Object { "$_" }) } catch { $addrs = @() }
    foreach ($a in @($addrs | Where-Object { Test-PimV1PrivateAddress -Ip $_ })) {
        $c = [System.Net.Sockets.TcpClient]::new()
        try { if ($c.ConnectAsync($a, 1433).Wait($TimeoutMs) -and $c.Connected) { return @{ private = $true; address = $a; resolved = ($addrs -join ', ') } } }
        catch { } finally { $c.Dispose() }
    }
    return @{ private = $false; address = ''; resolved = ($addrs -join ', ') }
}

function Get-PimV1SqlFailureText {
    # PURE. A database sign-in failure -> the one plain line saying what is missing.
    param([string]$Message, [string]$Group, [string]$Who, [string]$Server)
    $m = "$Message"
    if ($m -match '(?i)\b40615\b|is not allowed to access the server|Client with IP address') { return "this machine is not allowed through the firewall of $Server. Run it again (the temporary rule may have needed a moment), or ask Invardia support." }
    if ($m -match '(?i)\b18456\b|Login failed|not currently configured to accept this token|token-identified principal|Cannot open database') {
        return "you ($Who) cannot sign in to the PIM database: you are not a member of the SQL admin group '$Group' and have no database user. Ask a Privileged Role Administrator to add you to '$Group', then run this again in a NEW PowerShell window."
    }
    return "the PIM database could not be reached: $(($m -replace '\s+', ' ').Trim())"
}

function Invoke-PimV1AccessQuery {
    # ONE read-only query as the signed-in person (a new token and a new connection); returns the first row as an object.
    param([Parameter(Mandatory)][string]$Query)
    $tok = "$(Get-PimRestToken -Resource 'https://database.windows.net' -TenantId $script:v1Tenant)".Trim()
    if (-not $tok) { throw "no database token in tenant $($script:v1Tenant)" }
    $c = New-Object (Resolve-PimSqlClientType).FullName $script:v1Cs
    $c.AccessToken = $tok; $c.Open()
    try {
        $cmd = $c.CreateCommand(); $cmd.CommandText = $Query; $cmd.CommandTimeout = 60
        $r = $cmd.ExecuteReader()
        try { if ($r.Read()) { $o = [ordered]@{}; for ($i = 0; $i -lt $r.FieldCount; $i++) { $o[$r.GetName($i)] = $r.GetValue($i) }; return [pscustomobject]$o }; return $null } finally { $r.Close() }
    } finally { $c.Close() }
}

$null = Start-PimScriptRun -Script 'Import-PimV1Data'
$script:v1Rc = 1
$script:v1Stage = ''
$script:v1Rule = $null
$script:v1More = New-Object System.Collections.Generic.List[string]
try {
function Say([string]$Text, [string]$Color = 'Gray') { Write-Host "  $Text" -ForegroundColor $Color }
function Stop-V1([string]$Text) { Write-Host ''; Write-Host "STOPPED: $Text" -ForegroundColor Red; Write-Host '  Nothing was written.' -ForegroundColor DarkGray; throw [System.OperationCanceledException]::new('v1-stop') }
function Add-More([string]$Title, $Lines) { $script:v1More.Add(''); $script:v1More.Add("==== $Title ===="); foreach ($l in @($Lines)) { $script:v1More.Add("$l") } }

$tid = "$TenantId".Trim().ToLowerInvariant(); $sub = "$SubscriptionId".Trim().ToLowerInvariant()
$script:v1Tenant = $tid
$writeData = [bool]$Apply -and -not $WhatIfPreference
Write-Host ('=' * 78) -ForegroundColor Cyan
Write-Host " PIM MANAGER -- IMPORT PIM VERSION 1 DATA   $(if ($writeData) { 'IMPORT (-Apply)' } elseif ($WhatIfPreference) { 'PREVIEW (-WhatIf)' } else { 'CHECK + PREVIEW (writes nothing)' })" -ForegroundColor Cyan
Write-Host ('=' * 78) -ForegroundColor Cyan

# ---- the folder ------------------------------------------------------------------------------------------------------
if (-not (Test-Path -LiteralPath $SourcePath -PathType Container)) { Stop-V1 "the folder '$SourcePath' does not exist." }
$src = (Resolve-Path -LiteralPath $SourcePath).Path
Say "folder: $src"
foreach ($nf in 'PIM4EntraPS.NamingConventions.custom.ps1', 'PIM4EntraPS.NamingConventions.locked.ps1') {
    $np = Join-Path $src $nf
    if (Test-Path -LiteralPath $np) {
        $safe = Test-PimV1NamingFileSafe -Path $np
        if (-not $safe.ok) { Stop-V1 "the naming file $nf is not loaded: $($safe.reason). It may only assign values to `$global:PIM_NamingConventions -- remove the rest, or ask Invardia support." }
    }
}

# ---- the importer, in a private temp folder -----------------------------------------------------------------------------
$solRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$script:v1Stage = New-PimV1ImportStage -SolutionRoot $solRoot
. (Join-Path $script:v1Stage 'engine\_shared\PIM-Rest.ps1')
. (Join-Path $script:v1Stage 'engine\_shared\PIM-SqlStore.ps1')
. (Join-Path $script:v1Stage 'tools\setup\_PimSignedIn.ps1')
$migrate = Join-Path $script:v1Stage 'tools\setup\Migrate-PimToSql.ps1'

# ---- sign-in (REST only: the Support app's session in this window, else your browser) -----------------------------------
$who = 'you'
if (-not $Arm) {
    $id = Get-PimSignedInIdentity -TenantId $tid -SubscriptionId $sub
    if (-not $id.ok) { Stop-V1 "$($id.reason)" }
    $who = "$($id.userName)"
    Say "$($id.reason)" 'DarkGray'
    $Arm = {
        param([string]$Method = 'GET', [string]$Path, $Body)
        $WhatIfPreference = $false   # reads are real; the one write (the firewall rule) is gated before it gets here
        $tok = "$(Get-PimRestToken -Resource 'https://management.azure.com' -TenantId $script:v1Tenant)".Trim()
        if (-not $tok) { throw "no Azure token for tenant $($script:v1Tenant)" }
        $a = @{ Method = $Method; Uri = $(if ($Path -match '^https://') { $Path } else { "https://management.azure.com$Path" }); Headers = @{ Authorization = "Bearer $tok" } }
        if ($null -ne $Body) { $a['Body'] = ($Body | ConvertTo-Json -Depth 8 -Compress); $a['ContentType'] = 'application/json' }
        try { return (Invoke-RestMethod @a) }
        catch {
            $code = 0; try { $code = [int]$_.Exception.Response.StatusCode } catch { $code = 0 }
            throw "$Method $Path -> HTTP $code : $((("$($_.ErrorDetails.Message) $($_.Exception.Message)") -replace '\s+', ' ').Trim())"
        }
    }
}
if (-not $Sleep) { $Sleep = { param([int]$Seconds) Start-Sleep -Seconds $Seconds } }

# ---- find the PIM store ----------------------------------------------------------------------------------------------
$db = "$Database".Trim()
if ($db -notmatch '^[^<>*%&:\\/?\[\]'';]{1,128}$') { Stop-V1 "'$Database' is not a database name." }
$scope = if ("$ResourceGroup".Trim()) { "/subscriptions/$sub/resourceGroups/$("$ResourceGroup".Trim())" } else { "/subscriptions/$sub" }
$servers = New-Object System.Collections.Generic.List[object]
try {
    $next = "$scope/providers/Microsoft.Sql/servers?api-version=$($script:PimV1SqlApi)"
    while ($next) {
        $page = & $Arm -Method GET -Path $next
        foreach ($s in @($page.value)) { if ($s -and "$($s.name)") { $servers.Add($s) } }
        $next = if ($page -and $page.PSObject.Properties['nextLink'] -and "$($page.nextLink)") { "$($page.nextLink)" } else { '' }
    }
} catch { Stop-V1 "the SQL servers in $scope could not be read ($($_.Exception.Message)). You need Reader on the subscription or the resource group." }
$found = New-Object System.Collections.Generic.List[object]
foreach ($s in $servers) {
    if ("$SqlServerName".Trim() -and "$($s.name)" -ine ("$SqlServerName".Trim() -split '\.')[0]) { continue }
    $d = $null
    try { $d = & $Arm -Method GET -Path "$($s.id)/databases/$($db)?api-version=$($script:PimV1SqlApi)" } catch { $d = $null }
    if ($d -and "$($d.name)" -ieq $db) {
        $rg = if ("$($s.id)" -match '(?i)/resourceGroups/([^/]+)/') { $Matches[1] } else { '' }
        $found.Add([pscustomobject]@{ name = "$($s.name)"; id = "$($s.id)"; resourceGroup = $rg; server = $s })
    }
}
if (-not $found.Count) { Stop-V1 "no PIM store (a SQL database '$db') was found in $(if ("$ResourceGroup".Trim()) { "resource group $ResourceGroup" } else { "subscription $sub" }). Check -SubscriptionId$(if ("$ResourceGroup".Trim()) { ' and -ResourceGroup' })." }
if ($found.Count -gt 1) {
    Write-Host ''
    Write-Host "  More than one PIM installation is in $(if ("$ResourceGroup".Trim()) { "resource group $ResourceGroup" } else { 'this subscription' }):" -ForegroundColor Yellow
    foreach ($f in $found) { Write-Host "    $($f.name)  (resource group $($f.resourceGroup))" -ForegroundColor Yellow }
    Stop-V1 "name the one to import into: run it again with $(if ("$ResourceGroup".Trim()) { '-SqlServerName <server>' } else { '-ResourceGroup <resource group>' })."
}
$inst = $found[0]
$srv = $inst.name
$fqdn = if ("$($inst.server.properties.fullyQualifiedDomainName)".Trim()) { "$($inst.server.properties.fullyQualifiedDomainName)".Trim() } else { "$srv.database.windows.net" }
Say "PIM store: $srv / $db (resource group $($inst.resourceGroup))"
# Owner 2026-11-03: "i feel it is stupid to have to tell i am not msp in a single domain ... i can just add msp parameter
# when i am a msp". Single tenant is the default; -MspMaster for an MSP managing tenant. (-NotMspMaster is still accepted.)
$script:v1IsMaster = [bool]$MspMaster -and -not $NotMspMaster
Say "installation: $(if ($script:v1IsMaster) { 'MSP managing tenant (-MspMaster: the check also shows what would be sent to managed tenants)' } else { 'single tenant' })" 'DarkGray'
$adm = $inst.server.properties.administrators
$group = if ($adm -and "$($adm.principalType)" -eq 'Group' -and "$($adm.login)".Trim()) { "$($adm.login)".Trim() } else { 'grp-pim-sql-admins' }

# ---- network ---------------------------------------------------------------------------------------------------------
# V1-IMPORT-PRIVATE (a customer, 2026-11-11): first ask whether this machine reaches the server over the private network (a machine
# inside the installation's network, a VPN, a peered network). It did stop on "public access off" without looking, also
# from inside the network.
$pp = $null
try { $pp = if ($Probe) { & $Probe $fqdn } else { Test-PimV1PrivatePath -Fqdn $fqdn } } catch { $pp = $null }
$viaPrivate = [bool]($pp -and $pp.private)
$reachable = $true
if ($viaPrivate) {
    Say "network: this machine reaches $srv over the private network ($($pp.address)); no firewall rule is needed" 'DarkGray'
}
elseif ("$($inst.server.properties.publicNetworkAccess)" -ieq 'Disabled') {
    if ($pp -and "$($pp.resolved)") { Say "network: from this machine $fqdn resolves to $($pp.resolved) -- not a private address that answers on port 1433" 'DarkGray' }
    Stop-V1 "the PIM database is private (public network access is off). Run this from a machine inside the installation's network, or ask Invardia support."
}
if (-not $viaPrivate) {
$ip = "$ClientIp".Trim()
if (-not $ip) {
    try { $ip = "$(Invoke-RestMethod -Uri 'https://api.ipify.org' -TimeoutSec 20)".Trim() } catch { $ip = '' }
    if ($ip -notmatch '^\d{1,3}(\.\d{1,3}){3}$') { Stop-V1 "this machine's public address could not be read (api.ipify.org). Run it again with -ClientIp <this machine's public address>." }
}
$rules = @()
try { $rules = @((& $Arm -Method GET -Path "$($inst.id)/firewallRules?api-version=$($script:PimV1SqlApi)").value) } catch { Stop-V1 "the firewall rules of $srv could not be read ($($_.Exception.Message))." }
$covered = @($rules | Where-Object { $_ -and (Test-PimV1IpInRange -Ip $ip -Start "$($_.properties.startIpAddress)" -End "$($_.properties.endIpAddress)") })
if ($covered.Count) { Say "network: this machine ($ip) is allowed by the firewall rule '$($covered[0].name)'" 'DarkGray' }
else {
    $ruleName = 'PimV1Import-' + [DateTime]::UtcNow.ToString('yyyyMMddHHmmss')
    if ($PSCmdlet.ShouldProcess("SQL server $srv", "add the temporary firewall rule '$ruleName' for $ip (removed at the end of the run)")) {
        try {
            [void](& $Arm -Method PUT -Path "$($inst.id)/firewallRules/$($ruleName)?api-version=$($script:PimV1SqlApi)" -Body @{ properties = @{ startIpAddress = $ip; endIpAddress = $ip } })
            $script:v1Rule = @{ name = $ruleName; path = "$($inst.id)/firewallRules/$($ruleName)?api-version=$($script:PimV1SqlApi)"; server = $srv }
            Say "network: temporary firewall rule '$ruleName' added for this machine ($ip); it is removed at the end" 'DarkGray'
        } catch {
            Stop-V1 "this machine ($ip) is not allowed through the firewall of $srv, and the temporary rule could not be added ($($_.Exception.Message)). You need SQL Server Contributor (or Contributor) on $srv -- or ask someone who has it to allow $ip."
        }
    } else {
        $reachable = $false
        Say "What if: would add the temporary firewall rule '$ruleName' for this machine ($ip) and remove it at the end. Without it the database cannot be read, so -WhatIf stops here; run it without -WhatIf for the preview (the preview writes no data)." 'Yellow'
    }
}
}

if ($reachable) {
    # ---- database access, as you ------------------------------------------------------------------------------------------
    $cs = "Server=tcp:$fqdn,1433;Database=$db;Encrypt=True;TrustServerCertificate=False;Connection Timeout=30"
    if (-not $Sql) {
        try { $sw = Connect-PimSignedInSql -TenantId $tid; if ("$($sw.userName)") { $who = "$($sw.userName)" } } catch { Stop-V1 "$($_.Exception.Message)" }
        $script:v1Cs = $cs
        $Sql = { param([string]$Query) Invoke-PimV1AccessQuery -Query $Query }
    }
    $q = "SELECT USER_NAME() AS userName, IS_MEMBER('db_owner') AS isOwner, CASE WHEN OBJECT_ID('pim.Rows') IS NULL THEN -1 ELSE HAS_PERMS_BY_NAME('pim.Rows', 'OBJECT', 'SELECT') END AS canRead"
    $acc = $null; $lastErr = ''
    for ($try = 1; $try -le 6; $try++) {
        try { $acc = & $Sql $q; $lastErr = ''; break }
        catch {
            $lastErr = "$($_.Exception.Message)"
            # a rule added a moment ago can take a few seconds to apply
            if ($script:v1Rule -and $lastErr -match '(?i)\b40615\b|Client with IP address' -and $try -lt 6) { & $Sleep 10; continue }
            break
        }
    }
    if ($lastErr) { Stop-V1 (Get-PimV1SqlFailureText -Message $lastErr -Group $group -Who $who -Server $srv) }
    if ("$($acc.canRead)" -eq '-1') { Stop-V1 "the database $db on $srv holds no PIM data table (pim.Rows) -- it is not a PIM Manager store, or the installation did not finish." }
    if ("$($acc.canRead)" -ne '1') { Stop-V1 "you ($who) can sign in to the PIM database but cannot read it. Ask a Privileged Role Administrator to add you to the SQL admin group '$group', then run this again in a NEW PowerShell window." }
    if ($writeData -and "$($acc.isOwner)" -ne '1') { Stop-V1 "-Apply needs the database owner role, and you ($who) do not have it. Ask a Privileged Role Administrator to add you to the SQL admin group '$group', then run this again in a NEW PowerShell window." }
    Say "database access: signed in as $who$(if ("$($acc.isOwner)" -eq '1') { ' (database owner)' } else { ' (read)' })" 'DarkGray'

    # ---- the importer: check + preview (writes nothing) ---------------------------------------------------------------------
    $common = @{ ConfigDir = $src; ConnectionString = $cs; OutputDir = (Join-Path $script:v1Stage 'empty'); MailTemplateDir = (Join-Path $script:v1Stage 'empty')
                 ForceLocal = [bool]$ForceLocal; NotMspMaster = (-not $script:v1IsMaster) }
    if ("$DefaultDomain".Trim()) { $common['DefaultDomain'] = "$DefaultDomain".Trim() }
    function Invoke-V1Migrate([hashtable]$Extra, [string]$Title) {
        $global:PIM_MigrateResultSink = @{}
        $a = @{}; foreach ($k in $common.Keys) { $a[$k] = $common[$k] }; foreach ($k in $Extra.Keys) { $a[$k] = $Extra[$k] }
        $lines = New-Object System.Collections.Generic.List[string]
        $err = ''
        try { & $migrate @a *>&1 | ForEach-Object { $lines.Add("$(if ($_ -is [System.Management.Automation.InformationRecord]) { $_.MessageData } else { $_ })") } }
        catch { $err = "$($_.Exception.Message)" }
        Add-More $Title $lines
        if ($err) { Add-More "$Title -- stopped" @($err) }
        $sink = $global:PIM_MigrateResultSink
        $global:PIM_MigrateResultSink = $null
        return @{ sink = $sink; error = $err }
    }
    $pv = Invoke-V1Migrate @{ WhatIf = $true; OnKeyConflict = 'KeepExisting'; AllowValidationErrors = $true } 'PREVIEW (the importer, -WhatIf)'
    $check = $pv.sink['check']
    if (-not $check) { Stop-V1 "the files could not be checked: $($pv.error)" }
    if (-not $pv.sink.ContainsKey('plans')) { Stop-V1 "the store could not be read for the preview: $($pv.error)" }
    $plans = $pv.sink['plans']; $conf = @($pv.sink['collisions'])
    $readFail = @($pv.sink['failed'] | Where-Object { $_ })
    if ($readFail.Count) { Stop-V1 "what PIM Manager already holds could not be read for $(@($readFail | ForEach-Object { $_.entity }) -join ', ') -- so the preview cannot say what would change. Details: $(@($readFail | ForEach-Object { $_.error })[0])" }

    # ---- the plain list -----------------------------------------------------------------------------------------------------
    Write-Host ''
    Write-Host '  PREVIEW, per file (nothing written):' -ForegroundColor Cyan
    $nAdd = 0; $nSame = 0
    foreach ($base in @($plans.Keys)) {
        $p = $plans[$base]
        $fi = @($check.files | Where-Object { $_.file -eq $p.file })[0]
        $nAdd += $p.add.Count; $nSame += [int]$p.same
        $probs = if ($fi) { [int]$fi.errors } else { 0 }
        $warns = if ($fi) { [int]$fi.warnings } else { 0 }
        $line = '{0,-46} {1,4} to add, {2,4} already there, {3,3} conflict(s){4}{5}' -f $p.file, $p.add.Count, $p.same, $p.collide.Count, $(if ($probs) { ", $probs problem(s)" } else { '' }), $(if ($warns) { ", $warns note(s)" } else { '' })
        Say $line $(if ($p.collide.Count -or $probs) { 'Yellow' } else { 'Gray' })
    }
    $skipped = @($check.files | Where-Object { $_.status -ne 'entity' })
    $state = @($skipped | Where-Object { $_.status -eq 'state' })
    if ($skipped.Count) { Say ("skipped {0} file(s): {1} engine state file(s) (_Delta / _LastApplied), {2} not PIM data or replaced by a .custom file -- names in the details" -f $skipped.Count, $state.Count, ($skipped.Count - $state.Count)) 'DarkGray' }
    Add-More 'SKIPPED FILES' @($skipped | ForEach-Object { "$($_.file) ($($_.status))" })
    if (Test-Path -LiteralPath (Join-Path $src 'PIM4EntraPS.NamingConventions.custom.ps1')) { Say 'naming conventions: PIM4EntraPS.NamingConventions.custom.ps1 -- the values you changed are imported with -Apply (a value already changed in PIM Manager is kept)' 'DarkGray' }
    $errs = @($check.findings | Where-Object { $_.severity -eq 'error' })
    if ($errs.Count) {
        Write-Host ''
        Write-Host "  PROBLEMS in the files ($($errs.Count)):" -ForegroundColor Red
        foreach ($e in @($errs | Select-Object -First 20)) { Say ("{0} row {1}: {2}" -f $e.file, $e.row, (("$($e.message)" -replace '\s+', ' ').Trim())) 'Red' }
        if ($errs.Count -gt 20) { Say "... and $($errs.Count - 20) more -- see the details" 'Red' }
    }
    if ($conf.Count) {
        Write-Host ''
        Write-Host "  CONFLICTS ($($conf.Count)) -- the key is already in PIM Manager with different content:" -ForegroundColor Yellow
        foreach ($c in @($conf | Select-Object -First 20)) {
            $what = @(@($c.columns) | Select-Object -First 3 | ForEach-Object { "$($_.column): PIM Manager '$($_.store)' / file '$($_.file)'" }) -join '; '
            Say ("{0} row {1}, key '{2}': {3}" -f $c.file, $c.row, $c.key, $what) 'Yellow'
        }
        if ($conf.Count -gt 20) { Say "... and $($conf.Count - 20) more -- see the details" 'Yellow' }
    }
    Add-More 'CONFLICTS' @($conf | ForEach-Object { $c = $_; "$($c.file) row $($c.row) line $($c.line) key '$($c.key)': " + (@($c.columns | ForEach-Object { "$($_.column): store '$($_.store)' / file '$($_.file)'" }) -join '; ') })
    Write-Host ''
    Say ("total: {0} row(s) to add, {1} already there, {2} conflict(s), {3} problem(s) in the files" -f $nAdd, $nSame, $conf.Count, $errs.Count) 'White'

    if (-not $writeData) {
        $next = if ($errs.Count -and -not $AllowValidationErrors) { 'fix the problems in the files first, then run it with -Apply' }
                elseif ($conf.Count) { 'decide about the conflicts: -Apply -OnKeyConflict KeepExisting keeps what PIM Manager has, -OnKeyConflict Overwrite takes the file''s rows' }
                elseif ($nAdd) { 'run the same command with -Apply to add them' } else { 'nothing to add' }
        Write-Host ''
        Write-Host "RESULT: preview only -- nothing was written. Next: $next." -ForegroundColor DarkYellow
        $script:v1Rc = 0
    } else {
        # ---- -Apply: the gates, then the importer for real ------------------------------------------------------------------
        if ($errs.Count -and -not $AllowValidationErrors) { Stop-V1 "the check found $($errs.Count) problem(s) in the files (listed above). Fix them, or run again with -AllowValidationErrors to import the files as they are." }
        if ($conf.Count -and -not $PSBoundParameters.ContainsKey('OnKeyConflict')) { Stop-V1 "$($conf.Count) row(s) conflict with what PIM Manager has (listed above). Run again with -OnKeyConflict KeepExisting (PIM Manager's rows stay) or -OnKeyConflict Overwrite (the file's rows replace them)." }
        $ap = Invoke-V1Migrate @{ WhatIf = $false; OnKeyConflict = $OnKeyConflict; AllowValidationErrors = [bool]$AllowValidationErrors } 'IMPORT (the importer)'
        if ($ap.error) { Stop-V1 "the import did not complete: $(("$($ap.error)" -replace '\s+', ' ').Trim()). Each entity is written in one transaction, so a failed one wrote nothing; running it again is safe." }
        $added = 0; $updated = 0
        foreach ($r in @($ap.sink['report'])) { if ($null -ne $r.added) { $added += [int]$r.added }; if ($null -ne $r.updated) { $updated += [int]$r.updated } }
        # Framework 12.27 SQL-STATS: a bulk import -> refresh the stale pim.* statistics (pim.usp_RefreshStatistics: sampled,
        # bounded, statistics only -- no data change). Best effort: one warning line, the import result stands.
        if (($added + $updated) -gt 0) {
            try {
                $st = & $Sql 'EXEC pim.usp_RefreshStatistics'
                if ($st -and $st.PSObject.Properties['refreshed']) { Say ("statistics: {0} refreshed of {1} stale" -f $st.refreshed, $st.stale) 'DarkGray' }
            } catch { Write-Warning "statistics refresh after the import skipped: $((("$($_.Exception.Message)") -split "`n")[0]) -- the import is not affected; the next PIM job refreshes them" }
        }
        # read back: the same preview again -- every row added must now be "already there"
        $rb = Invoke-V1Migrate @{ WhatIf = $true; OnKeyConflict = 'KeepExisting'; AllowValidationErrors = $true } 'READ BACK (the importer, -WhatIf)'
        $left = 0
        if ($rb.sink -and $rb.sink.ContainsKey('plans')) { foreach ($b in @($rb.sink['plans'].Keys)) { $left += $rb.sink['plans'][$b].add.Count } } else { $left = -1 }
        Write-Host ''
        if ($left -eq 0) {
            Write-Host ("RESULT: imported -- {0} row(s) added, {1} updated, nothing deleted; read back: every row is in PIM Manager." -f $added, $updated) -ForegroundColor Green
            $script:v1Rc = 0
        } else {
            Write-Host ("RESULT: imported {0} row(s), but the read-back {1} -- see the details." -f $added, $(if ($left -lt 0) { 'could not read the store' } else { "still finds $left row(s) to add" })) -ForegroundColor Red
            $script:v1Rc = 1
        }
    }
} else {
    Write-Host ''
    Write-Host 'RESULT: preview only -- nothing was changed (the database was not read; see the What if line above).' -ForegroundColor DarkYellow
    $script:v1Rc = 0
}
} catch [System.OperationCanceledException] {
    $script:v1Rc = 1
} catch {
    Write-Host ''
    Write-Host "STOPPED: $(("$($_.Exception.Message)" -replace '\s+', ' ').Trim())" -ForegroundColor Red
    $script:v1Rc = 1
} finally {
    # ALWAYS: the temporary firewall rule goes, also after a failure, and that is read back
    if ($script:v1Rule) {
        $gone = $false; $why = ''
        try { [void](& $Arm -Method DELETE -Path $script:v1Rule.path) } catch { $why = "$($_.Exception.Message)" }
        try { $left = @((& $Arm -Method GET -Path ($script:v1Rule.path -replace '/firewallRules/[^?]+\?', '/firewallRules?')).value | Where-Object { "$($_.name)" -eq $script:v1Rule.name }); $gone = ($left.Count -eq 0) } catch { $gone = $false; if (-not $why) { $why = "$($_.Exception.Message)" } }
        if ($gone) { Write-Host "  network: the temporary firewall rule '$($script:v1Rule.name)' was removed (read back)." -ForegroundColor DarkGray }
        else {
            Write-Host "  WARNING: the temporary firewall rule '$($script:v1Rule.name)' on $($script:v1Rule.server) could NOT be removed$(if ($why) { " ($why)" }). Delete it by hand: Azure portal > the SQL server > Networking > Firewall rules." -ForegroundColor Red
            $script:v1Rc = 2
        }
    }
    if ($script:v1More.Count -and "$($global:PimScriptRunLog)") {
        try {
            $mf = ("$($global:PimScriptRunLog)" -replace '\.log$', '') + '-more.txt'
            [IO.File]::WriteAllLines($mf, $script:v1More.ToArray(), (New-Object System.Text.UTF8Encoding($false)))
            Write-Host "More: $mf (the full check and the importer's own lines)" -ForegroundColor DarkGray
        } catch { }
    }
    if ($script:v1Stage -and (Test-Path -LiteralPath $script:v1Stage)) { try { [IO.Directory]::Delete($script:v1Stage, $true) } catch { } }
    Stop-PimScriptRun -Script 'Import-PimV1Data'
}
exit $script:v1Rc
