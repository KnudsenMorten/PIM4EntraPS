#Requires -Version 5.1

<#
.SYNOPSIS
    Converts a public (external) PIM Manager environment to private (internal) with one command: it runs the steps of the
    guide "Convert a public PIM Manager environment to private" in order by calling the existing setup scripts, checks
    each one before the next, and can resume after a stop or a failure.

.DESCRIPTION
    Converts a public (external) PIM Manager environment to private (internal-only) in one command. It runs the conversion guide's steps in order by calling the existing setup scripts (safety copy, private registry, remove and redeploy or rebuild, verify from inside the network, optional custom name, optional private SQL), checks each step before the next, records progress per tenant and resource group so -Resume continues after a stop or a failure, and stops with exit code 10 where your network team must act. Data is kept. It only prints the plan unless -Apply is given.

    REQUIREMENTS 100.64 (owner 2026-10-10). The internal/external setting of a Container Apps environment is fixed when
    the environment is created, so the conversion deletes and recreates the Container Apps part only. Everything that
    holds data stays (SQL, registry, VNet, identities, Log Analytics, Key Vault, storage).

    Steps (guide step in brackets; every child script is idempotent, so a step that is run again is safe):
      preflight     [0]  resolve the install's parameters (the deploy profile, else the parameters given), check them,
                         and check the sign-in, the subscription and the environment. Runs on every invocation.
      network       [1]  the hub side. -SkipPeering: STOPS (exit 10) and prints the New-PimHubPrepareScript.ps1 command
                         that writes the hub owner's script. Resume with -HubSideDone once the hub owner has run it.
      safety-copy   [2]  ALWAYS, and the run refuses to continue if it fails: a capture of the live PIM Manager, jobs and
                         keep-list (Rebuild-PimEnvInternal.ps1 in plan mode; Windows) and the SQL point-in-time restore
                         point (read over ARM).
      registry      [3]  New-PimHostingPrerequisites.ps1 with the existing names: Premium registry, private endpoint,
                         privatelink zone, build pool. No SQL private endpoint yet.
      remove-stack  [4B] (Route Redeploy) Remove-PimContainerStack.ps1 -Apply. Skipped when the environment is already
                         internal.
      redeploy      [4B] (Route Redeploy) Invoke-PimDeployAll.ps1 -Exposure internal -Apply with the install's parameters.
      rebuild       [4A] (Route Rebuild) Rebuild-PimEnvInternal.ps1 -Apply (resumes from its capture after a failure).
      verify-inside [5]  STOP POINT before any public endpoint is closed: when this machine reaches the PIM Manager's
                         private address, Confirm-PimInstall.ps1 runs here; otherwise it STOPS (exit 10) with what to check
                         from inside. Resume with -ConfirmedFromInside once that check passed.
      custom-host   [6]  -HostName: Set-PimManagerCustomHost.ps1 with your certificate and DNS choice.
      sql-endpoint  [7]  -SqlPrivate (last): New-PimHostingPrerequisites.ps1 -SqlPrivateEndpoint.
      profile       [7]  -SqlPrivate or Route Rebuild: Invoke-PimDeployAll.ps1 -Apply once with the private values, so the
                         saved deploy profile (and Update-PimCommunity.ps1) carries them.
      finish        [8]  what is left for you (old reply addresses, SQL public access, updates), and the rollback table.

    ROUTE. Default Redeploy (the guide's Route B), because it is the route that completes in ONE REST session: it grants
    the new identities their Graph permissions, Azure roles AND database users, it needs no Windows-only capture, and the
    install's parameters come from the deploy profile. Route Rebuild (the guide's Route A) keeps hand-made changes to the
    apps, but repairs the database users only with a certificate or secret identity, which this one-session command does
    not use (it says the database half is owed).

    SIGN-IN. One REST session pinned to -TenantId: the Invardia Support app's session for this tenant, else the person
    signs in in the browser. Every child script runs in this process and reuses it. A session of another tenant is refused.
    No Azure CLI, no PowerShell modules.

    STATE. %LOCALAPPDATA%\pim\convert\<tenant>-<resource group>.json records the parameters (never a secret) and each
    completed step; the captures go to the folder of the same name. -Resume continues after the last completed step.
    Exit codes: 0 done (or the plan); 10 stopped where your network team must act (state saved); 1 failed (state saved,
    rollback printed).

.EXAMPLE
    # the plan: every step with the exact child command (changes nothing, no sign-in)
    .\tools\setup\Convert-PimToPrivate.ps1 -TenantId <tenant-id> -SubscriptionId <subscription-id> -ResourceGroup rg-pim `
        -HubVnetId /subscriptions/<hub-sub>/resourceGroups/rg-connectivity/providers/Microsoft.Network/virtualNetworks/vnet-hub `
        -PrivateEndpointSubnetAddressPrefix 10.50.1.0/26

.EXAMPLE
    # convert; then resume after a stop point
    .\tools\setup\Convert-PimToPrivate.ps1 -TenantId <tenant-id> -SubscriptionId <subscription-id> -ResourceGroup rg-pim ... -Apply
    .\tools\setup\Convert-PimToPrivate.ps1 -TenantId <tenant-id> -SubscriptionId <subscription-id> -ResourceGroup rg-pim -Resume -Apply -ConfirmedFromInside

.LINK
    https://invardia.com/docs/pim/scripts/Convert-PimToPrivate/
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$TenantId,
    [Parameter(Mandatory)][string]$SubscriptionId,
    [Parameter(Mandatory)][string]$ResourceGroup,
    [ValidateSet('Redeploy', 'Rebuild')][string]$Route = 'Redeploy',
    [string]$DeployProfilePath,
    [string]$Tag,
    [string]$Location,
    [string]$VnetName,
    [string]$VnetResourceGroup,
    [string]$SubnetName,
    [string]$VnetAddressPrefix,
    [string]$SubnetAddressPrefix,
    [string]$AcrName,
    [string]$LogAnalyticsName,
    [string]$SqlServerFqdn,
    [string]$SqlDatabase,
    [string]$EnvName,
    [string]$ManagerApp,
    [string]$PrivateEndpointSubnetName,
    [string]$PrivateEndpointSubnetAddressPrefix,
    [string]$AcrAgentPoolName,
    [string[]]$HubVnetId = @(),
    [switch]$SkipPeering,
    [string]$DeployPrincipalObjectId,
    [string]$PrivateDnsResourceGroup,
    [switch]$SkipPrivateDns,
    [string[]]$EasyAuthAllowedPrincipals = @(),
    [switch]$EasyAuthAllowAllTenantUsers,
    [string]$HostName,
    [string]$KeyVaultName,
    [string]$KeyVaultCertName,
    [string]$PfxPath,
    [securestring]$PfxPassword,
    [ValidateSet('', 'Auto', 'PrivateDnsZone', 'AdDns', 'None')][string]$HostDns = '',
    [string]$HostDnsResourceGroup,
    [switch]$SqlPrivate,
    [switch]$HubSideDone,
    [switch]$ConfirmedFromInside,
    [scriptblock]$Reporter,
    [string]$InvardiaInstallToken = '',
    [switch]$Resume,
    [switch]$Apply
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '_PimScriptDoc.ps1')
$null = Start-PimScriptRun -Script 'Convert-PimToPrivate'
try {
# ONE REST layer for the whole run (framework 12.17 NO-AZ): loaded once here, so every child script finds it loaded and reuses
# its token cache (dot-sourcing PIM-Rest again would reset it and ask for a second browser sign-in).
$cvSolRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
if (-not (Get-Command Get-PimRestToken -ErrorAction SilentlyContinue)) { . (Join-Path $cvSolRoot 'engine\_shared\PIM-Rest.ps1') }
if (-not (Get-Command Invoke-PimSetupArm -ErrorAction SilentlyContinue)) { . (Join-Path $cvSolRoot 'engine\_shared\PIM-ArmSetup.ps1') }
. (Join-Path $PSScriptRoot '_PimSetupShared.ps1')        # Show-PimSetupBanner
. (Join-Path $PSScriptRoot '_PimDeployProfile.ps1')       # Get-PimDeployProfilePath / Read-PimDeployProfile
. (Join-Path $PSScriptRoot '_PimInstallTracking.ps1')     # optional Invardia install tracking (best effort)
Show-PimSetupBanner -ScriptName 'Convert-PimToPrivate'

$cvPlanOnly = (-not $Apply) -or [bool]$WhatIfPreference
if ($WhatIfPreference -and $Apply) { Write-Host '  -WhatIf: plan only -- -Apply is ignored, nothing is changed.' -ForegroundColor Yellow }
$cvTid = "$TenantId".Trim().ToLowerInvariant()
$cvSub = "$SubscriptionId".Trim()
$cvRg  = "$ResourceGroup".Trim()
$cvSep = [IO.Path]::DirectorySeparatorChar
$cmdPrefix = ".${cvSep}tools${cvSep}setup${cvSep}"

# ============================================================================================================== helpers
function Say([string]$m, [string]$c = 'Gray') { Write-Host "  $m" -ForegroundColor $c }

function Get-PimConvertStatePath {
    # PURE. %LOCALAPPDATA%\pim\convert\<tenant>-<rg>.json (temp folder when there is no LOCALAPPDATA, e.g. Linux).
    param([Parameter(Mandatory)][string]$TenantId, [Parameter(Mandatory)][string]$ResourceGroup)
    $base = if ("$env:LOCALAPPDATA".Trim()) { $env:LOCALAPPDATA } else { [IO.Path]::GetTempPath() }
    $safe = ("$TenantId-$ResourceGroup".ToLowerInvariant() -replace '[^A-Za-z0-9._-]', '_')
    return (Join-Path (Join-Path (Join-Path $base 'pim') 'convert') "$safe.json")
}

function Format-PimConvertValue($v) {
    if ($v -is [securestring]) { return '(secure string)' }
    if ($v -is [bool] -or $v -is [System.Management.Automation.SwitchParameter]) { return $(if ([bool]$v) { '$true' } else { '$false' }) }
    if ($v -is [int] -or $v -is [long]) { return "$v" }
    if ($v -is [array]) { return (@($v | ForEach-Object { "'" + ("$_" -replace "'", "''") + "'" }) -join ',') }
    return "'" + ("$v" -replace "'", "''") + "'"
}

function Format-PimConvertCommand {
    # PURE. ".\tools\setup\<Script>.ps1 -Name 'value' -Switch" -- the exact child command, in a stable order.
    param([Parameter(Mandatory)][string]$Script, [System.Collections.IDictionary]$Arguments = @{})
    $parts = @("$cmdPrefix$Script.ps1")
    foreach ($k in @($Arguments.Keys | Sort-Object)) {
        $v = $Arguments[$k]
        if ($v -is [bool] -or $v -is [System.Management.Automation.SwitchParameter]) {
            if ([bool]$v) { $parts += "-$k" } else { $parts += "-${k}:`$false" }
            continue
        }
        $parts += "-$k $(Format-PimConvertValue $v)"
    }
    return ($parts -join ' ')
}

function ConvertFrom-PimHubVnetId {
    # PURE. A VNet resource id -> @{ subscriptionId; resourceGroup; name } or $null.
    param([string]$Id)
    $m = [regex]::Match("$Id".Trim(), '(?i)^/subscriptions/([^/]+)/resourceGroups/([^/]+)/providers/Microsoft\.Network/virtualNetworks/([^/]+)$')
    if (-not $m.Success) { return $null }
    return @{ subscriptionId = $m.Groups[1].Value; resourceGroup = $m.Groups[2].Value; name = $m.Groups[3].Value }
}

function Invoke-PimConvertChild {
    # Runs ONE existing setup script in THIS process (it reuses this run's REST session) and returns its exit code.
    param([Parameter(Mandatory)][string]$Script, [Parameter(Mandatory)][hashtable]$Arguments)
    $cvPath = Join-Path $PSScriptRoot "$Script.ps1"
    if (-not (Test-Path -LiteralPath $cvPath)) { Write-Host "  child script not found: $cvPath" -ForegroundColor Red; return 1 }
    $global:LASTEXITCODE = 0
    try { & $cvPath @Arguments | Out-Host }
    catch { Write-Host "  $Script stopped: $($_.Exception.Message)" -ForegroundColor Red; return 1 }
    if ($LASTEXITCODE) { return [int]$LASTEXITCODE }
    return 0
}

function Get-PimConvertLiveState {
    # The Container Apps environment and the PIM Manager as they are now (ARM reads only).
    param([string]$SubscriptionId, [string]$ResourceGroup, [string]$EnvName, [string]$ManagerApp)
    $cvAca = Get-PimArmAcaEnv -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $EnvName -ErrorAsNull
    $app = Get-PimArmAcaApp -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $ManagerApp -ErrorAsNull
    return @{
        envExists     = [bool]$cvAca
        internal      = ($cvAca -and "$($cvAca.properties.vnetConfiguration.internal)" -eq 'True')
        staticIp      = "$($cvAca.properties.staticIp)"
        defaultDomain = "$($cvAca.properties.defaultDomain)"
        fqdn          = "$($app.properties.configuration.ingress.fqdn)"
    }
}

function Get-PimConvertRestorePoint {
    # Step 2: the SQL database's point-in-time restore window (ARM read). The restore point is NOW (UTC).
    param([string]$SubscriptionId, [string]$SqlServerName, [string]$SqlDatabase)
    $srv = @(Get-PimArmSqlServers -SubscriptionId $SubscriptionId | Where-Object { "$($_.name)" -ieq $SqlServerName }) | Select-Object -First 1
    if (-not $srv) { return @{ ok = $false; reason = "SQL server '$SqlServerName' is not visible in subscription $SubscriptionId" } }
    $db = Invoke-PimSetupArm -Path "$($srv.id)/databases/$SqlDatabase" -ApiVersion (Get-PimSetupApiVersion sql) -NotFoundOk -ErrorAsNull
    if (-not $db) { return @{ ok = $false; reason = "database '$SqlDatabase' on '$SqlServerName' could not be read" } }
    $earliest = "$($db.properties.earliestRestoreDate)".Trim()
    if (-not $earliest) { return @{ ok = $false; reason = "database '$SqlDatabase' reports no point-in-time restore window (earliestRestoreDate is empty)" } }
    return @{ ok = $true; restorePointUtc = [DateTime]::UtcNow.ToString('o'); earliestRestoreUtc = $earliest; databaseId = "$($db.id)" }
}

function Test-PimConvertInsideReach {
    # Step 5: can THIS machine reach the PIM Manager's private address? Resolves the name, wants a private address, then
    # opens TCP 443 (5 s). Read-only; nothing is sent beyond the TCP handshake.
    param([string]$Fqdn, [string]$StaticIp)
    if (-not "$Fqdn".Trim()) { return @{ ok = $false; reason = 'the PIM Manager has no address to test' } }
    $ips = @()
    try { $ips = @([System.Net.Dns]::GetHostAddresses($Fqdn) | ForEach-Object { "$_" }) } catch { return @{ ok = $false; reason = "$Fqdn does not resolve from this machine" } }
    $priv = @($ips | Where-Object { $_ -match '^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)' -or ("$StaticIp".Trim() -and $_ -eq "$StaticIp".Trim()) })
    if (-not $priv.Count) { return @{ ok = $false; reason = "$Fqdn resolves to $($ips -join ', ') here, not to the private address $StaticIp" } }
    $c = New-Object System.Net.Sockets.TcpClient
    try {
        $t = $c.BeginConnect($priv[0], 443, $null, $null)
        if (-not $t.AsyncWaitHandle.WaitOne(5000) -or -not $c.Connected) { return @{ ok = $false; reason = "$($priv[0]):443 does not answer from this machine" } }
        return @{ ok = $true; reason = "$Fqdn -> $($priv[0]):443 answers" }
    } catch { return @{ ok = $false; reason = "$($priv[0]):443: $($_.Exception.Message)" } } finally { $c.Close() }
}

# ================================================================================================================ state
$statePath = Get-PimConvertStatePath -TenantId $cvTid -ResourceGroup $cvRg
$stateDir  = $statePath -replace '\.json$', ''
$cvState = $null
if (Test-Path -LiteralPath $statePath) {
    try { $cvState = [IO.File]::ReadAllText($statePath) | ConvertFrom-Json } catch { throw "the conversion state $statePath cannot be read ($($_.Exception.Message)) -- move it away to start over." }
}
$noSave = @('Apply', 'Resume', 'WhatIf', 'Confirm', 'HubSideDone', 'ConfirmedFromInside', 'PfxPassword', 'Reporter', 'InvardiaInstallToken',
            'Verbose', 'Debug', 'ErrorAction', 'WarningAction', 'InformationAction', 'ErrorVariable', 'WarningVariable', 'InformationVariable', 'OutVariable', 'OutBuffer', 'PipelineVariable', 'ProgressAction')
if ($Resume) {
    if (-not $cvState) { Say "-Resume: there is no conversion state for this tenant and resource group ($statePath). Run without -Resume first." 'Red'; exit 1 }
    if ($PSBoundParameters.ContainsKey('Route') -and "$($cvState.route)" -and "$($cvState.route)" -ne $Route) { Say "-Resume: this conversion runs route $($cvState.route); -Route $Route does not match. Leave -Route out to resume." 'Red'; exit 1 }
    if ("$($cvState.route)") { $Route = "$($cvState.route)" }
    # the parameters of the first run fill every value not given again (explicit values win)
    foreach ($p in @($cvState.parameters.PSObject.Properties)) {
        if ($PSBoundParameters.ContainsKey($p.Name) -or $noSave -contains $p.Name) { continue }
        $v = $p.Value
        if ($v -is [array]) { $v = [string[]]@($v | ForEach-Object { "$_" }) }
        Set-Variable -Name $p.Name -Value $v -Scope Script
    }
}
function Get-StepState([string]$Id) {
    if (-not $cvState -or -not $cvState.steps) { return '' }
    $cvS = $cvState.steps.PSObject.Properties[$Id]
    if ($cvS) { return "$($cvS.Value.state)" }
    return ''
}

# ======================================================================================================= the parameters
$profPath = if ("$DeployProfilePath".Trim()) { "$DeployProfilePath".Trim() } else { Get-PimDeployProfilePath -TenantId $cvTid -ResourceGroup $cvRg }
$cvProf = $null; $profNote = ''
if (Test-Path -LiteralPath $profPath) {
    try { $cvProf = (Read-PimDeployProfile -Path $profPath).parameters; $profNote = "deploy profile $profPath" }
    catch { $profNote = "deploy profile $profPath could not be read: $($_.Exception.Message)" }
} else { $profNote = "no deploy profile at $profPath -- the parameters given are used" }
$cvBound = $PSBoundParameters
function Pick([string]$Name, [string[]]$ProfileKeys = @(), $Default = '') {
    # explicit (or resumed) value, else the deploy profile, else the default
    $v = Get-Variable -Name $Name -Scope Script -ValueOnly -ErrorAction SilentlyContinue
    if ($v -is [array]) { if (@($v | Where-Object { "$_".Trim() }).Count) { return , [string[]]@($v) } }
    elseif ("$v".Trim()) { return "$v".Trim() }
    if ($cvProf) { foreach ($k in @($ProfileKeys)) { if ($cvProf.ContainsKey($k) -and "$($cvProf[$k])".Trim()) { return $cvProf[$k] } } }
    return $Default
}
$cvR = [ordered]@{}
$cvR.Tag                 = Pick 'Tag' @('PrereqToken', 'EnvLabel') 'pim'
$cvR.Location            = Pick 'Location' @('Location')
$cvR.VnetName            = Pick 'VnetName' @('VnetName')
$cvR.VnetResourceGroup   = Pick 'VnetResourceGroup' @('VnetResourceGroup') $cvRg
$cvR.SubnetName          = Pick 'SubnetName' @('PrereqSubnetName')
$cvR.VnetAddressPrefix   = Pick 'VnetAddressPrefix' @('PrereqVnetAddressPrefix')
$cvR.SubnetAddressPrefix = Pick 'SubnetAddressPrefix' @('PrereqSubnetAddressPrefix')
$cvR.AcrName             = Pick 'AcrName' @('AcrName')
$cvR.LogAnalyticsName    = Pick 'LogAnalyticsName' @('LogAnalyticsWorkspaceName')
$cvR.SqlServerFqdn       = Pick 'SqlServerFqdn' @('SqlServerFqdn')
$cvR.SqlDatabase         = Pick 'SqlDatabase' @('SqlDatabase') 'PimPlatform'
$cvR.EnvName             = Pick 'EnvName' @('EnvName') 'cae-pim'
$cvR.ManagerApp          = Pick 'ManagerApp' @('ManagerApp') 'ca-pim-manager'
$cvR.PrivateEndpointSubnetName          = Pick 'PrivateEndpointSubnetName' @('PrivateEndpointSubnetName') 'pim-endpoints'
$cvR.PrivateEndpointSubnetAddressPrefix = Pick 'PrivateEndpointSubnetAddressPrefix' @('PrivateEndpointSubnetAddressPrefix')
$cvR.AcrAgentPoolName    = Pick 'AcrAgentPoolName' @('AcrAgentPoolName') 'pimbuild'
$cvR.PrivateDnsResourceGroup = Pick 'PrivateDnsResourceGroup' @('PrivateDnsResourceGroup')
$cvR.SqlServerName       = $(if ("$($cvR.SqlServerFqdn)".Trim()) { ("$($cvR.SqlServerFqdn)".Trim() -split '\.')[0] } else { '' })
$cvHubIds = @($HubVnetId | Where-Object { "$_".Trim() } | ForEach-Object { "$_".Trim() })
if (-not $cvHubIds.Count -and $cvProf -and "$($cvProf['HubVnetName'])".Trim()) {
    $hs = if ("$($cvProf['HubVnetSubscriptionId'])".Trim()) { "$($cvProf['HubVnetSubscriptionId'])".Trim() } else { $cvSub }
    $cvHubIds = @("/subscriptions/$hs/resourceGroups/$("$($cvProf['HubVnetResourceGroup'])".Trim())/providers/Microsoft.Network/virtualNetworks/$("$($cvProf['HubVnetName'])".Trim())")
}
$cvHub = $(if ($cvHubIds.Count) { ConvertFrom-PimHubVnetId -Id $cvHubIds[0] } else { $null })
$spokeVnetId = "/subscriptions/$cvSub/resourceGroups/$($cvR.VnetResourceGroup)/providers/Microsoft.Network/virtualNetworks/$($cvR.VnetName)"

$cvProblems = New-Object System.Collections.Generic.List[string]
foreach ($k in 'Location', 'VnetName', 'SubnetName', 'VnetAddressPrefix', 'SubnetAddressPrefix', 'AcrName', 'LogAnalyticsName', 'SqlServerFqdn', 'PrivateEndpointSubnetAddressPrefix') {
    if (-not "$($cvR[$k])".Trim()) { $cvProblems.Add("-$k is needed (not given and not in the deploy profile)") }
}
if ("$($cvR.VnetResourceGroup)" -ine $cvRg) { $cvProblems.Add("the PIM VNet is in resource group '$($cvR.VnetResourceGroup)', not '$cvRg': this one-command conversion supports the VNet in the PIM resource group only -- follow the guide's manual steps") }
foreach ($h in $cvHubIds) { if (-not (ConvertFrom-PimHubVnetId -Id $h)) { $cvProblems.Add("-HubVnetId '$h' is not a virtual network resource id") } }
if ($SkipPeering -and -not $cvHubIds.Count) { $cvProblems.Add('-SkipPeering needs -HubVnetId (the hub the hub owner peers to)') }
if ($Route -eq 'Redeploy' -and $cvHubIds.Count -gt 1) { $cvProblems.Add('route Redeploy peers to ONE hub: pass one -HubVnetId (the private DNS zone links to more hubs on route Rebuild)') }
if ("$HostName".Trim() -and -not ("$KeyVaultName".Trim() -and "$KeyVaultCertName".Trim()) -and -not "$PfxPath".Trim()) { $cvProblems.Add('-HostName on a private environment needs your certificate: -KeyVaultName + -KeyVaultCertName, or -PfxPath') }
if ($Route -eq 'Rebuild' -and -not $EasyAuthAllowAllTenantUsers -and -not @($EasyAuthAllowedPrincipals | Where-Object { "$_".Trim() }).Count) {
    Say 'route Rebuild without -EasyAuthAllowedPrincipals / -EasyAuthAllowAllTenantUsers: the rebuild keeps the existing sign-in restriction when the app is assignment-required.' 'Yellow'
}

# ---- child arguments (built once: the plan prints exactly what -Apply runs) ------------------------------------------
function Get-PrereqArgs([bool]$SqlPe) {
    $a = @{ TenantId = $cvTid; SubscriptionId = $cvSub; Token = "$($cvR.Tag)"; UseSignedInAccount = $true; Location = "$($cvR.Location)"
            ResourceGroupName = $cvRg; VnetName = "$($cvR.VnetName)"; SubnetName = "$($cvR.SubnetName)"; VnetAddressPrefix = "$($cvR.VnetAddressPrefix)"
            SubnetAddressPrefix = "$($cvR.SubnetAddressPrefix)"; AcrName = "$($cvR.AcrName)"; LogAnalyticsName = "$($cvR.LogAnalyticsName)"
            SqlServerName = "$($cvR.SqlServerName)"; AcrSku = 'Premium'; AcrPublicAccess = 'false'; AcrAgentPoolName = "$($cvR.AcrAgentPoolName)"
            PrivateEndpointSubnetName = "$($cvR.PrivateEndpointSubnetName)"; PrivateEndpointSubnetAddressPrefix = "$($cvR.PrivateEndpointSubnetAddressPrefix)" }
    if ("$($cvR.PrivateDnsResourceGroup)".Trim()) { $a['PrivateDnsResourceGroup'] = "$($cvR.PrivateDnsResourceGroup)" }
    if ($SqlPe) { $a['SqlPrivateEndpoint'] = $true }
    return $a
}
function Get-DeployArgs([bool]$SqlPe) {
    # the original install's parameters with the private-mode values changed or added (guide Step 4B / 7.4). One identity
    # per run: any saved credential parameter is dropped and the run uses this REST session (-UseSignedInAccount).
    $d = @{}
    if ($cvProf) { foreach ($k in @($cvProf.Keys)) { $d[$k] = $cvProf[$k] } }
    foreach ($k in 'AdminAppId', 'AdminSecret', 'AdminCertPem', 'SqlAdminClientId', 'SqlAdminClientSecret', 'SqlAdminCertThumbprint',
                   'InvardiaInstallToken', 'EnrollmentKey', 'ValidateOnly', 'Descriptor', 'SqlPrivateEndpoint', 'SkipPeering', 'SkipPrivateDns') { $d.Remove($k) }
    if (-not "$($d['Source'])".Trim()) { $d['Source'] = 'sync-automateit' }
    $d['TenantId'] = $cvTid; $d['SubscriptionId'] = $cvSub; $d['ResourceGroup'] = $cvRg
    $map = @{ VnetName = 'VnetName'; AcrName = 'AcrName'; SqlServerFqdn = 'SqlServerFqdn'; SqlDatabase = 'SqlDatabase'; Location = 'Location'; EnvName = 'EnvName'
              ManagerApp = 'ManagerApp'; LogAnalyticsName = 'LogAnalyticsWorkspaceName'; SubnetName = 'PrereqSubnetName'
              VnetAddressPrefix = 'PrereqVnetAddressPrefix'; SubnetAddressPrefix = 'PrereqSubnetAddressPrefix' }
    foreach ($k in $map.Keys) { if ("$($cvR[$k])".Trim()) { $d[$map[$k]] = "$($cvR[$k])" } }
    $d['Exposure'] = 'internal'; $d['AcrSku'] = 'Premium'; $d['AcrPublicAccess'] = 'false'; $d['AcrAgentPoolName'] = "$($cvR.AcrAgentPoolName)"
    $d['PrivateEndpointSubnetName'] = "$($cvR.PrivateEndpointSubnetName)"; $d['PrivateEndpointSubnetAddressPrefix'] = "$($cvR.PrivateEndpointSubnetAddressPrefix)"
    if ($SqlPe) { $d['SqlPrivateEndpoint'] = $true }
    if ($cvHub) { $d['HubVnetName'] = $cvHub.name; $d['HubVnetResourceGroup'] = $cvHub.resourceGroup; $d['HubVnetSubscriptionId'] = $cvHub.subscriptionId }
    if ($SkipPeering) { $d['SkipPeering'] = $true }
    if ($SkipPrivateDns) { $d['SkipPrivateDns'] = $true }
    if ("$($cvR.PrivateDnsResourceGroup)".Trim()) { $d['PrivateDnsResourceGroup'] = "$($cvR.PrivateDnsResourceGroup)" }
    if (@($EasyAuthAllowedPrincipals | Where-Object { "$_".Trim() }).Count) { $d['EasyAuthAllowedPrincipals'] = [string[]]@($EasyAuthAllowedPrincipals) }
    if ($EasyAuthAllowAllTenantUsers) { $d['EasyAuthAllowAllTenantUsers'] = $true }
    $d['SkipHostedSmoke'] = $true; $d['UseSignedInAccount'] = $true; $d['Apply'] = $true
    return $d
}
$captureDir = Join-Path $stateDir 'safety-copy'
$rebuildDir = Join-Path $stateDir 'rebuild'
$argCapture = @{ Tag = "$($cvR.Tag)"; SubscriptionId = $cvSub; ResourceGroup = $cvRg; EnvName = "$($cvR.EnvName)"; ManagerApp = "$($cvR.ManagerApp)"; CaptureDir = $captureDir; EasyAuthTenantId = $cvTid }
$argRemove  = @{ SubscriptionId = $cvSub; ResourceGroup = $cvRg; Apply = $true }
$argRebuild = @{ Tag = "$($cvR.Tag)"; SubscriptionId = $cvSub; ResourceGroup = $cvRg; EnvName = "$($cvR.EnvName)"; ManagerApp = "$($cvR.ManagerApp)"; CaptureDir = $rebuildDir
                 EasyAuthTenantId = $cvTid; LockRegistry = $true; SqlServer = "$($cvR.SqlServerFqdn)"; SqlDatabase = "$($cvR.SqlDatabase)"; HostingAccessTenantId = $cvTid; Apply = $true }
if ($cvHubIds.Count) { $argRebuild['HubVnetId'] = [string[]]$cvHubIds }
if ("$($cvR.PrivateDnsResourceGroup)".Trim()) { $argRebuild['PrivateDnsResourceGroup'] = "$($cvR.PrivateDnsResourceGroup)" }
if (@($EasyAuthAllowedPrincipals | Where-Object { "$_".Trim() }).Count) { $argRebuild['EasyAuthAllowedPrincipals'] = [string[]]@($EasyAuthAllowedPrincipals) }
if ($EasyAuthAllowAllTenantUsers) { $argRebuild['EasyAuthAllowAllTenantUsers'] = $true }
$argConfirm = @{ TenantId = $cvTid; SubscriptionId = $cvSub; ResourceGroup = $cvRg; SqlServerFqdn = "$($cvR.SqlServerFqdn)"; SqlDatabase = "$($cvR.SqlDatabase)"
                 EnvName = "$($cvR.EnvName)"; ManagerApp = "$($cvR.ManagerApp)"; AcrName = "$($cvR.AcrName)"; AcrAgentPoolName = "$($cvR.AcrAgentPoolName)"; UseSignedInAccount = $true }
$argHost = @{ SubscriptionId = $cvSub; TenantId = $cvTid; ResourceGroup = $cvRg; HostName = "$HostName".Trim(); ManagerApp = "$($cvR.ManagerApp)"; LinkVnetIds = [string[]](@($cvHubIds) + @($spokeVnetId)) }
if ("$KeyVaultName".Trim())     { $argHost['KeyVaultName'] = "$KeyVaultName".Trim() }
if ("$KeyVaultCertName".Trim()) { $argHost['KeyVaultCertName'] = "$KeyVaultCertName".Trim() }
if ("$PfxPath".Trim())          { $argHost['PfxPath'] = "$PfxPath".Trim() }
if ($PfxPassword)               { $argHost['PfxPassword'] = $PfxPassword }
if ("$HostDns".Trim())          { $argHost['Dns'] = "$HostDns".Trim() }
$hostDnsRg = $(if ("$HostDnsResourceGroup".Trim()) { "$HostDnsResourceGroup".Trim() } else { "$($cvR.PrivateDnsResourceGroup)".Trim() })
if ($hostDnsRg) { $argHost['PrivateDnsResourceGroup'] = $hostDnsRg }
$argHubPrep = @{ SpokeSubscriptionId = $cvSub; SpokeResourceGroup = "$($cvR.VnetResourceGroup)"; SpokeVnetName = "$($cvR.VnetName)" }
if ($cvHub) { $argHubPrep['HubSubscriptionId'] = $cvHub.subscriptionId; $argHubPrep['HubResourceGroup'] = $cvHub.resourceGroup; $argHubPrep['HubVnetName'] = $cvHub.name }
if ("$DeployPrincipalObjectId".Trim()) { $argHubPrep['DeployPrincipalObjectId'] = "$DeployPrincipalObjectId".Trim() }
if ("$($cvR.PrivateDnsResourceGroup)".Trim()) { $argHubPrep['DnsResourceGroup'] = "$($cvR.PrivateDnsResourceGroup)" }

# ---- the steps, in the guide's order ---------------------------------------------------------------------------------
$cvSteps = New-Object System.Collections.Generic.List[object]
function AddStep([string]$Id, [string]$Guide, [string]$Title, [string]$Child = '', $ChildArgs = $null, [string]$Skip = '') {
    $cvSteps.Add([pscustomobject]@{ id = $Id; guide = $Guide; title = $Title; child = $Child; args = $ChildArgs; skip = $Skip })
}
AddStep 'preflight' '0' 'prerequisites: the install parameters, the sign-in, the subscription and the environment'
AddStep 'network' '1' $(if ($SkipPeering) { 'the hub side of the peering and the DNS links -- YOUR NETWORK TEAM (stop point 1)' } else { 'the network: this run creates the peering and the DNS links (Network Contributor on the hub)' }) `
        $(if ($SkipPeering) { 'New-PimHubPrepareScript' } else { '' }) $(if ($SkipPeering) { $argHubPrep } else { $null })
AddStep 'safety-copy' '2' 'safety copy: capture of the live apps + keep-list, and the SQL point-in-time restore point' 'Rebuild-PimEnvInternal' $argCapture
AddStep 'registry' '3' 'make the registry private (Premium, private endpoint, privatelink zone, build pool)' 'New-PimHostingPrerequisites' (Get-PrereqArgs $false)
if ($Route -eq 'Redeploy') {
    AddStep 'remove-stack' '4B' 'remove the Container Apps stack (data is kept)' 'Remove-PimContainerStack' $argRemove
    AddStep 'redeploy' '4B' 'redeploy internal-only with the install parameters' 'Invoke-PimDeployAll' (Get-DeployArgs $false)
} else {
    AddStep 'rebuild' '4A' 'rebuild the environment internal-only from the live capture' 'Rebuild-PimEnvInternal' $argRebuild
}
AddStep 'verify-inside' '5' 'verify from inside the network before any public endpoint is closed (stop point 2)' 'Confirm-PimInstall' $argConfirm
AddStep 'custom-host' '6' 'a stable custom name for the PIM Manager' 'Set-PimManagerCustomHost' $argHost $(if (-not "$HostName".Trim()) { 'no -HostName' } else { '' })
AddStep 'sql-endpoint' '7' 'the SQL private endpoint (last)' 'New-PimHostingPrerequisites' (Get-PrereqArgs $true) $(if (-not $SqlPrivate) { 'no -SqlPrivate' } else { '' })
$profSkip = ''
if (-not $SqlPrivate -and $Route -eq 'Redeploy') { $profSkip = 'the redeploy already saved the private parameters' }
elseif ($Route -eq 'Rebuild' -and -not $cvProf -and -not $SqlPrivate) { $profSkip = 'no deploy profile to correct' }
AddStep 'profile' '7' 'save the private values in the deploy profile (one deploy with them)' 'Invoke-PimDeployAll' (Get-DeployArgs ([bool]$SqlPrivate)) $profSkip
AddStep 'finish' '8' 'what is left for you, updates after the conversion'

# ================================================================================================================ events
$cvTracker = New-PimInstallTracker -Token "$InvardiaInstallToken"
function Send-ConvertEvent([string]$Id, [string]$Title, [string]$State, [string]$Message = '') {
    $colour = switch ($State) { 'failed' { 'Red' } 'waiting' { 'Yellow' } 'warning' { 'Yellow' } 'ok' { 'Green' } 'completed' { 'Green' } default { 'Gray' } }
    Write-Host ("  [{0,-9}] {1,-14} {2}" -f $State, $Id, $Message) -ForegroundColor $colour
    if ($Reporter) { try { & $Reporter ([pscustomobject]@{ step = [pscustomobject]@{ id = $Id; title = $Title }; state = $State; message = $Message }) | Out-Null } catch { Write-Verbose "reporter failed: $($_.Exception.Message)" } }
    [void](Send-PimInstallTrackEvent -Tracker $cvTracker -StepId $Id -Title $Title -State $State -Message $Message)
}

$resumeBase = "${cmdPrefix}Convert-PimToPrivate.ps1 -TenantId '$cvTid' -SubscriptionId '$cvSub' -ResourceGroup '$cvRg' -Resume -Apply"
function Show-Rollback([string]$FailedStep) {
    Write-Host ''
    Write-Host '  ROLLBACK / WHAT NOW' -ForegroundColor Yellow
    Say "Resume after fixing the cause: $resumeBase" 'White'
    switch -Regex ($FailedStep) {
        '^(preflight|network|safety-copy|registry)$' { Say 'Nothing in the Container Apps part has changed. A registry already upgraded to Premium with a private endpoint is harmless: pulls keep working.' }
        '^(remove-stack|redeploy)$' { Say 'The Container Apps part is removed or partly rebuilt; the data is untouched. Resuming re-runs the deploy (idempotent).'
                                      Say 'Back to public instead: run Invoke-PimDeployAll.ps1 with the original deploy profile (exposure external) and -Apply.' }
        '^rebuild$' { Say "Resuming passes -ResumeFromCapture -CaptureDir '$rebuildDir' to the rebuild. KEEP THAT FOLDER until the run completes: once the apps are deleted it is the only copy of their definitions."
                      Say "Back to public instead: ${cmdPrefix}Rebuild-PimEnvExternal.ps1 -Tag '$($cvR.Tag)' -SubscriptionId '$cvSub' -ResourceGroup '$cvRg' -EasyAuthTenantId '$cvTid' -Apply" }
        default { Say 'The environment is private and running. Registry locked too early: turn its public network access back on (portal). SQL public access off too early: turn it back on, then work through the private endpoint.' }
    }
    $cvRp = if ($cvState -and "$($cvState.restorePointUtc)") { "$($cvState.restorePointUtc)" } else { '' }
    Say ("Data is not touched by any step." + $(if ($cvRp) { " Point-in-time restore point: $cvRp (Azure SQL automatic backups)." } else { '' }))
}

# ================================================================================================================= PLAN
Write-Host ''
Write-Host "==> Convert $cvRg to PRIVATE (internal-only) -- route $Route -- $(if ($cvPlanOnly) { 'PLAN ONLY' } else { 'APPLY' })" -ForegroundColor Cyan
Say "tenant $cvTid  subscription $cvSub  resource group $cvRg"
Say "parameters : $profNote"
Say "state      : $statePath$(if ($cvState) { ' (exists)' } else { '' })"
Say ("route      : " + $(if ($Route -eq 'Redeploy') { "Redeploy (guide Route B, the default): one REST session grants the new identities' Graph permissions, Azure roles and database users; no Windows-only capture" } else { "Rebuild (guide Route A): keeps hand-made app changes; the database users of the new identities need a certificate identity, so their repair is owed after this run" }))
if ($cvProblems.Count) {
    Write-Host ''
    foreach ($p in $cvProblems) { Say "MISSING / REFUSED: $p" 'Red' }
}
Write-Host ''
$cvI = 0
foreach ($cvS in $cvSteps) {
    $cvI++
    $st = Get-StepState $cvS.id
    $cvMark = if ($cvS.skip) { "skipped ($($cvS.skip))" } elseif ($st -eq 'ok') { 'done' } elseif ($st) { $st } else { '' }
    Write-Host ("  {0,2}. [{1,-14}] guide step {2,-3} {3}{4}" -f $cvI, $cvS.id, $cvS.guide, $cvS.title, $(if ($cvMark) { "  -- $cvMark" } else { '' })) -ForegroundColor $(if ($st -eq 'ok' -or $cvS.skip) { 'DarkGray' } else { 'White' })
    if ($cvS.child -and $cvS.args -and -not $cvS.skip) {
        $cvVerb = if ($cvS.id -eq 'network') { 'hub owner script ' } elseif ($cvS.id -eq 'safety-copy') { 'capture (plan)  ' } else { 'runs            ' }
        Write-Host "        $cvVerb $(Format-PimConvertCommand -Script $cvS.child -Arguments $cvS.args)" -ForegroundColor DarkGray
    }
    if ($cvS.id -eq 'safety-copy') { Write-Host '        + reads the SQL database''s point-in-time restore window (ARM); the run REFUSES to continue without a safety copy' -ForegroundColor DarkGray }
    if ($cvS.id -eq 'verify-inside') { Write-Host '        runs Confirm-PimInstall here when this machine reaches the private address; otherwise STOPS (exit 10) until -ConfirmedFromInside' -ForegroundColor DarkGray }
    if ($cvS.id -eq 'network' -and $SkipPeering) { Write-Host '        STOPS (exit 10) until the hub owner has run that script; resume with -HubSideDone' -ForegroundColor DarkGray }
}
Write-Host ''
if ($cvPlanOnly) {
    if ($cvProblems.Count) { Say 'PLAN ONLY -- -Apply would refuse until the values above are given.' 'Red'; exit 1 }
    if ($cvState -and -not $Resume) { Say "A conversion state exists for this environment: continue it with $resumeBase" 'Yellow' }
    Say 'PLAN ONLY -- nothing was signed in to and nothing was changed. Re-run with -Apply.' 'Yellow'
    exit 0
}
if ($cvProblems.Count) { Say 'REFUSED -- give the values above, then run again.' 'Red'; exit 1 }
if ($cvState -and -not $Resume) {
    Say "REFUSED -- a conversion of this environment is already recorded in $statePath. Continue it with: $resumeBase" 'Red'
    Say '(Running the steps from the start again would remove the private environment the earlier run built.)' 'Red'
    exit 1
}

# ================================================================================================================ APPLY
if (-not $cvState) {
    $cvParams = [ordered]@{}
    foreach ($k in @($cvBound.Keys | Sort-Object)) {
        if ($noSave -contains $k) { continue }
        $v = $cvBound[$k]
        if ($v -is [System.Management.Automation.SwitchParameter]) { $v = [bool]$v.IsPresent }
        $cvParams[$k] = $(if ($v -is [array]) { @($v | ForEach-Object { "$_" }) } else { $v })
    }
    $cvState = [pscustomobject]@{ schema = 1; tenantId = $cvTid; subscriptionId = $cvSub; resourceGroup = $cvRg; route = $Route
                                startedUtc = [DateTime]::UtcNow.ToString('o'); updatedUtc = ''; completedUtc = ''; restorePointUtc = ''
                                captureDir = $captureDir; parameters = [pscustomobject]$cvParams; steps = [pscustomobject]@{} }
}
function Save-ConvertState {
    $cvState.updatedUtc = [DateTime]::UtcNow.ToString('o')
    $dir = Split-Path -Parent $statePath
    if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
    [IO.File]::WriteAllText($statePath, ($cvState | ConvertTo-Json -Depth 8), (New-Object Text.UTF8Encoding $false))
}
function Set-StepState([string]$Id, [string]$St, [string]$Detail = '') {
    $v = [pscustomobject]@{ state = $St; atUtc = [DateTime]::UtcNow.ToString('o'); detail = $Detail }
    if ($cvState.steps.PSObject.Properties[$Id]) { $cvState.steps.$Id = $v } else { $cvState.steps | Add-Member -NotePropertyName $Id -NotePropertyValue $v }
    Save-ConvertState
}

# ---- ONE REST session pinned to -TenantId ----------------------------------------------------------------------------
$cvCurMode = "$($global:PIM_SetupRestMode)".Trim(); $cvCurTid = "$($global:PIM_TenantId)".Trim().ToLowerInvariant()
if ($cvCurMode -and $cvCurTid -and $cvCurTid -ne $cvTid) {
    Say "REFUSED -- this shell's REST session is for tenant $cvCurTid, not $cvTid. Open a new PowerShell window (or the Invardia support session for $cvTid) and run again." 'Red'
    exit 1
}
$cvSup = $global:InvardiaSupportState
if (-not $cvCurMode -and ($cvSup -is [hashtable]) -and "$($cvSup.TenantId)".Trim() -and "$($cvSup.TenantId)".Trim().ToLowerInvariant() -ne $cvTid) {
    Say "REFUSED -- the Invardia support session in this shell is for tenant $("$($cvSup.TenantId)".Trim()), not $cvTid. Connect the support session for $cvTid, or use a new window to sign in in the browser." 'Red'
    exit 1
}
if (-not $cvCurMode) {
    try { $cvConn = Connect-PimSetupRest -TenantId $cvTid -SubscriptionId $cvSub }
    catch { Say "REFUSED -- no REST session for tenant ${cvTid}: $($_.Exception.Message)" 'Red'; exit 1 }
    if ("$($cvConn.tenantId)".Trim().ToLowerInvariant() -ne $cvTid) { Say "REFUSED -- the session is pinned to tenant $($cvConn.tenantId), not $cvTid." 'Red'; exit 1 }
    $cvCurMode = "$($global:PIM_SetupRestMode)"
}
$cvSubObj = Get-PimArmSubscription -SubscriptionId $cvSub -ErrorAsNull
if (-not $cvSubObj -or "$($cvSubObj.subscriptionId)".Trim() -ne $cvSub) { Say "REFUSED -- this sign-in cannot see subscription $cvSub." 'Red'; exit 1 }
if ("$($cvSubObj.tenantId)".Trim() -and "$($cvSubObj.tenantId)".Trim().ToLowerInvariant() -ne $cvTid) { Say "REFUSED -- subscription $cvSub belongs to tenant $($cvSubObj.tenantId), not $cvTid." 'Red'; exit 1 }
Say "REST session: $cvCurMode, tenant $cvTid (every step below reuses it; no Azure CLI, no modules)" 'Green'
Save-ConvertState

# ---- run the steps ---------------------------------------------------------------------------------------------------
$cvI = 0
foreach ($cvS in $cvSteps) {
    $cvI++
    $cvPrev = Get-StepState $cvS.id
    if ($cvS.id -ne 'preflight' -and ($cvPrev -eq 'ok' -or $cvPrev -eq 'skipped')) { Send-ConvertEvent $cvS.id $cvS.title 'skipped' 'done in an earlier run'; continue }
    if ($cvS.skip) { Set-StepState $cvS.id 'skipped' $cvS.skip; Send-ConvertEvent $cvS.id $cvS.title 'skipped' $cvS.skip; continue }
    Write-Host ''
    Write-Host ("==> {0}. {1} (guide step {2})" -f $cvI, $cvS.title, $cvS.guide) -ForegroundColor Cyan
    Send-ConvertEvent $cvS.id $cvS.title 'started'
    $cvResult = 'ok'; $cvDetail = ''
    switch ($cvS.id) {
        'preflight' {
            $cvLive = Get-PimConvertLiveState -SubscriptionId $cvSub -ResourceGroup $cvRg -EnvName "$($cvR.EnvName)" -ManagerApp "$($cvR.ManagerApp)"
            if ($cvLive.envExists) { $cvDetail = "environment $($cvR.EnvName): $(if ($cvLive.internal) { 'already INTERNAL' } else { 'external (public)' }), domain $($cvLive.defaultDomain)" }
            else { $cvDetail = "environment $($cvR.EnvName) does not exist (an earlier run removed it, or it has another name)" }
            if (-not $cvLive.envExists -and -not $Resume) { $cvResult = 'failed'; $cvDetail += ' -- nothing to convert; pass -EnvName, or -Resume to continue an earlier conversion' }
        }
        'network' {
            if ($SkipPeering -and -not $HubSideDone) {
                $cvResult = 'waiting'
                $cvDetail = 'the hub side of the peering and the DNS links are made by the hub network owner'
            } elseif ($SkipPeering) { $cvDetail = 'the hub owner confirmed the hub side (-HubSideDone)' }
            elseif ($cvHubIds.Count) { $cvDetail = "this run creates the peering to $($cvHub.name) and links the private DNS zone (needs Network Contributor on the hub)" }
            else { $cvDetail = 'no hub VNet given: only the PIM VNet will resolve and reach the PIM Manager' }
        }
        'safety-copy' {
            $cvRp = Get-PimConvertRestorePoint -SubscriptionId $cvSub -SqlServerName "$($cvR.SqlServerName)" -SqlDatabase "$($cvR.SqlDatabase)"
            if (-not $cvRp.ok) { $cvResult = 'failed'; $cvDetail = "no SQL restore point: $($cvRp.reason)"; break }
            $cvState.restorePointUtc = $cvRp.restorePointUtc
            $cvOnWindows = ($env:OS -eq 'Windows_NT')
            if ($cvOnWindows) {
                $cvCode = Invoke-PimConvertChild -Script $cvS.child -Arguments $cvS.args
                $cvEnvCap = Join-Path $captureDir "$($cvR.Tag)-env.json"
                if ($cvCode -ne 0 -or -not (Test-Path -LiteralPath $cvEnvCap)) { $cvResult = 'failed'; $cvDetail = "the capture failed (exit $cvCode; $cvEnvCap $(if (Test-Path -LiteralPath $cvEnvCap) { 'exists' } else { 'missing' }))"; break }
                $cvDetail = "capture in $captureDir; restore point $($cvRp.restorePointUtc) (earliest $($cvRp.earliestRestoreUtc))"
            } else {
                $cvDetail = "restore point $($cvRp.restorePointUtc) (earliest $($cvRp.earliestRestoreUtc)); the app capture needs Windows (DPAPI) and was skipped"
            }
            Say 'Optional: also export a BACPAC of the database from the Azure portal (SQL database > Export) to a storage account you own.'
        }
        'remove-stack' {
            $cvLive = Get-PimConvertLiveState -SubscriptionId $cvSub -ResourceGroup $cvRg -EnvName "$($cvR.EnvName)" -ManagerApp "$($cvR.ManagerApp)"
            if ($cvLive.envExists -and $cvLive.internal) { $cvDetail = 'the environment is already internal -- nothing removed'; break }
            $cvCode = Invoke-PimConvertChild -Script $cvS.child -Arguments $cvS.args
            if ($cvCode -ne 0) { $cvResult = 'failed'; $cvDetail = "Remove-PimContainerStack exit $cvCode" } else { $cvDetail = 'Container Apps stack removed; data kept' }
        }
        'rebuild' {
            $a = @{} + $cvS.args
            if ($cvPrev -eq 'failed' -and (Test-Path -LiteralPath (Join-Path $rebuildDir "$($cvR.Tag)-env.json"))) { $a['ResumeFromCapture'] = $true; Say "resuming the rebuild from its capture in $rebuildDir" 'Yellow' }
            $cvCode = Invoke-PimConvertChild -Script $cvS.child -Arguments $a
            if ($cvCode -ne 0) { $cvResult = 'failed'; $cvDetail = "Rebuild-PimEnvInternal exit $cvCode" }
            else { $cvDetail = 'rebuilt internal-only'; Say 'If the rebuild said the database half of the identity repair is owed: open the PIM Manager > Overview > permission check (from inside the network).' 'Yellow' }
        }
        'verify-inside' {
            $cvLive = Get-PimConvertLiveState -SubscriptionId $cvSub -ResourceGroup $cvRg -EnvName "$($cvR.EnvName)" -ManagerApp "$($cvR.ManagerApp)"
            if (-not $cvLive.internal) { $cvResult = 'failed'; $cvDetail = "the environment is not internal after the conversion (exists=$($cvLive.envExists))"; break }
            $cvReach = Test-PimConvertInsideReach -Fqdn $cvLive.fqdn -StaticIp $cvLive.staticIp
            if ($cvReach.ok) {
                Say "this machine reaches the private address ($($cvReach.reason)) -- running the install check here"
                $cvCode = Invoke-PimConvertChild -Script $cvS.child -Arguments $cvS.args
                if ($cvCode -ne 0) { $cvResult = 'failed'; $cvDetail = "Confirm-PimInstall exit $cvCode (the table above says which line and how to fix it)" } else { $cvDetail = "verified from this machine: $($cvReach.reason)" }
            } elseif ($ConfirmedFromInside) {
                $cvDetail = "confirmed from inside the network by the operator (-ConfirmedFromInside); this machine: $($cvReach.reason)"
            } else {
                $cvResult = 'waiting'
                $cvDetail = "this machine cannot reach the private address ($($cvReach.reason)); verify from inside the network"
                $cvState | Add-Member -NotePropertyName newAddress -NotePropertyValue "$($cvLive.fqdn) -> $($cvLive.staticIp)" -Force
            }
        }
        'finish' {
            $cvDetail = 'converted'
        }
        default {
            $cvCode = Invoke-PimConvertChild -Script $cvS.child -Arguments $cvS.args
            if ($cvCode -ne 0) { $cvResult = 'failed'; $cvDetail = "$($cvS.child) exit $cvCode" } else { $cvDetail = "$($cvS.child) ok" }
        }
    }
    Set-StepState $cvS.id $cvResult $cvDetail
    Send-ConvertEvent $cvS.id $cvS.title $cvResult $cvDetail
    if ($cvResult -eq 'failed') {
        Show-Rollback $cvS.id
        Write-Host ''
        Say "FAILED at step '$($cvS.id)'. The state is saved in $statePath." 'Red'
        exit 1
    }
    if ($cvResult -eq 'waiting') {
        Write-Host ''
        Write-Host '  STOPPED -- your network team acts now (state saved; exit code 10)' -ForegroundColor Yellow
        if ($cvS.id -eq 'network') {
            Say 'Give the hub owner the script this command writes (it only writes a file; nothing in Azure is touched):' 'White'
            Say (Format-PimConvertCommand -Script 'New-PimHubPrepareScript' -Arguments $argHubPrep) 'White'
            Say 'They run it on the hub (it creates the hub side of the peering with the name PIM setup looks for, and the rights'
            Say 'when -DeployPrincipalObjectId is given), add gateway transit / forwarded traffic if admins come through the hub, and'
            Say 'forward DNS for the new default domain and the privatelink zones to your resolver (network-options.md).'
            Say "Then resume: $resumeBase -HubSideDone" 'White'
        } else {
            Say "From a machine INSIDE the network (hub, VPN or Private Access client), check: the new name $("$($cvState.newAddress)") resolves to the static IP;" 'White'
            Say 'the PIM Manager answers 302 to login.microsoftonline.com (never 200); from the internet it does not resolve; one engine tick'
            Say 'completes (Overview), Settings > Jobs shows the engine and the updater. The install check, run from inside:'
            Say (Format-PimConvertCommand -Script 'Confirm-PimInstall' -Arguments $argConfirm) 'White'
            Say "Then resume: $resumeBase -ConfirmedFromInside" 'White'
        }
        exit 10
    }
}

# ---- done ------------------------------------------------------------------------------------------------------------
$cvState.completedUtc = [DateTime]::UtcNow.ToString('o'); Save-ConvertState
[void](Complete-PimInstallTracker -Tracker $cvTracker -Outputs @{ route = $Route; resourceGroup = $cvRg })
Write-Host ''
Write-Host '  CONVERSION COMPLETE -- left for you (the scripts cannot see these):' -ForegroundColor Green
Say "- remove the old reply addresses (*.<old domain>) on the PIM Manager's sign-in app registration in Entra ID, and any DNS record you made for the old address"
if (-not $SqlPrivate) { Say '- make SQL private later: run again with -Resume -Apply -SqlPrivate (adds the SQL private endpoint)' }
else { Say '- turn the SQL server''s public network access OFF (portal, or your Azure Policy) once the private endpoint resolves from inside (not yet automated)' }
if ($Route -eq 'Redeploy') { Say '- the registry''s public network access is still on (route Redeploy does not lock it): turn it off in the portal once pulls go through the private endpoint' }
Say '- updates: outbound invardia.com must be allowed (Pro); the updater job carries PIM_ACR_AGENT_POOL. Community: Update-PimCommunity.ps1 -Apply from the deploy host.'
Say "- from now on Confirm-PimInstall.ps1 and Set-PimLicense.ps1 run from inside the network. State: $statePath"
exit 0
} finally { Stop-PimScriptRun -Script 'Convert-PimToPrivate' }
