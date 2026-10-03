#Requires -Version 5.1
<#
.SYNOPSIS
  §95.2 -- the GUIDED INSTALL of the PIM Manager: the one command Invardia's bootstrap calls (GUIDED-INSTALL §4.2).

.DESCRIPTION
  Install-PimManager -ConfigPath <config.json> -LicencePath <file> -Reporter <scriptblock> [-StatePath <dir>] [-Resume] [-PreflightOnly]

  Runs in Azure Cloud Shell (PowerShell 7, Linux) or PowerShell 7 / Windows PowerShell 5.1 on Windows, as the SIGNED-IN
  account -- never a secret. It:
    1. checks the answers (config.json, keys as in install-parameters.json) and the licence file      -> exit 3 when bad
    2. preflight: sign-in, tenant + subscription, rights, providers, names, SQL in the region          -> exit 2 when failed
       (-PreflightOnly stops here, exit 0)
    3. deploys with Invoke-PimDeployAll (the external, signed-in Container Apps shape; the public release), reporting
       every step                                                                                        -> exit 1 when failed
    4. registers the licence (the Pro features switch on at once), grants the Invardia Support app its access when
       config.json names one, checks health, and reports 'completed' with the outputs Invardia's support needs -> exit 0
  A step that needs a higher role than the installer holds ends as a WARNING with the command for the right person; the
  install continues. -Resume re-runs from where it stopped: completed preflight / licence / support steps are skipped,
  and the deploy itself is idempotent (each of its steps checks what exists first).

  Reporter events: @{ installId; step = @{ id; title }; state = started|ok|warning|failed|skipped|completed; message;
  action = @{ text; command }; detail; outputs }. The bootstrap adds seq and at. This script never calls invardia.com.

.EXAMPLE
  ./Install-PimManager.ps1 -ConfigPath ~/clouddrive/invardia/ab12/config.json -LicencePath ~/clouddrive/invardia/ab12/Contoso.pimlicense `
      -Reporter { param($e) "$($e.step.id) $($e.state) $($e.message)" | Write-Host }
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$ConfigPath,
    [Parameter(Mandatory)][string]$LicencePath,
    [scriptblock]$Reporter,
    [string]$StatePath = '',
    [switch]$Resume,
    [switch]$PreflightOnly,
    # --- test seams (offline tests/Test-PimGuidedInstall.ps1); omit them for a real install ---
    [scriptblock]$Az,
    [scriptblock]$Deploy,
    [scriptblock]$InstallLicence,
    [scriptblock]$GrantSupport,
    [scriptblock]$ResolveHost,
    [string]$TestLicenceCertB64,
    [scriptblock]$Http
)
$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
$sol = Split-Path -Parent (Split-Path -Parent $here)
. (Join-Path $here '_PimGuidedInstall.ps1')
. (Join-Path $here '_PimSignedIn.ps1')
. (Join-Path $sol 'engine\_shared\PIM-License.ps1')

if (-not $Az) { $Az = { param([string[]]$AzArgs) $ErrorActionPreference = 'Continue'; & az @AzArgs 2>$null } }
if (-not $ResolveHost) { $ResolveHost = { param([string]$HostName) try { @([System.Net.Dns]::GetHostAddresses($HostName)).Count -gt 0 } catch { $false } } }

$events = New-Object System.Collections.Generic.List[object]
$installId = ''
function Send-Event([System.Collections.IDictionary]$Event) {
    if (-not $Event) { return }
    if ($installId -and -not "$($Event['installId'])") { $Event['installId'] = $installId }
    $events.Add($Event) | Out-Null
    $colour = switch ("$($Event.state)") { 'failed' { 'Red' } 'warning' { 'Yellow' } 'ok' { 'Green' } 'completed' { 'Green' } default { 'Gray' } }
    Write-Host ("[{0,-9}] {1,-22} {2}" -f $Event.state, $Event.step.id, $Event.message) -ForegroundColor $colour
    if ($Event.action -and "$($Event.action.command)") { Write-Host "            -> $($Event.action.text) $($Event.action.command)" -ForegroundColor Yellow }
    if ($Reporter) { try { & $Reporter $Event | Out-Null } catch { Write-Verbose "reporter failed: $($_.Exception.Message)" } }
}
function Emit([string]$Id, [string]$State, [string]$Message = '', [string]$ActionText = '', [string]$ActionCommand = '', [System.Collections.IDictionary]$Detail, [System.Collections.IDictionary]$Outputs) {
    $a = @{ StepId = $Id; State = $State; Message = $Message; ActionText = $ActionText; ActionCommand = $ActionCommand; InstallId = $installId }
    if ($Detail) { $a['Detail'] = $Detail }
    if ($Outputs) { $a['Outputs'] = $Outputs }
    Send-Event (New-PimInstallEvent @a)
}
function Az-Text([string[]]$AzArgs) { "$(@(& $Az $AzArgs) -join "`n")".Trim() }
function Az-Json([string[]]$AzArgs) { $t = Az-Text ($AzArgs + @('-o', 'json')); if ($t) { try { return ($t | ConvertFrom-Json) } catch { } }; return $null }
# A REST read with a token taken FOR THE TARGET SUBSCRIPTION (its tenant). Never `az rest`: it has no --subscription and
# uses the default account's tenant -- on a machine holding several logins that is another directory.
if (-not $Http) { $Http = { param([string]$Url, [string]$Token) Invoke-RestMethod -Method GET -Uri $Url -Headers @{ Authorization = "Bearer $Token" } -TimeoutSec 60 } }
function Get-InstallRest([string]$Url, [string]$Resource) {
    $t = Az-Json @('account', 'get-access-token', '--subscription', $cfg.subscriptionId, '--resource', $Resource)
    if (-not "$($t.accessToken)") { return $null }
    try { return (& $Http $Url "$($t.accessToken)") } catch { return $null }
}
function Finish([int]$Code) { $global:LASTEXITCODE = $Code; exit $Code }

# ================================================================== 1. config + licence
Emit 'config' 'started'
$raw = $null
try { $raw = Get-Content -Raw -LiteralPath $ConfigPath -ErrorAction Stop | ConvertFrom-Json } catch { $raw = $null }
$chk = Test-PimInstallConfig -Config $raw
if (-not $chk.ok) { Emit 'config' 'failed' ("the answers cannot be used: " + (@($chk.errors) -join '; ')) 'Correct the answers in the wizard and download the command again.'; Finish 3 }
$cfg = $chk.config
$installId = $cfg.installId
if (-not "$StatePath".Trim()) {
    $homeDir = if ($env:HOME) { $env:HOME } else { $env:USERPROFILE }
    $base = if (Test-Path -LiteralPath (Join-Path $homeDir 'clouddrive')) { Join-Path $homeDir 'clouddrive' } else { $homeDir }
    $StatePath = Join-Path (Join-Path $base 'invardia') $installId
}
$state = Read-PimInstallState -StatePath $StatePath
$done = New-Object System.Collections.Generic.List[string]
if ($Resume -and $state.installId -eq $installId) { foreach ($c in $state.completed) { $done.Add("$c") | Out-Null } }
function Mark([string]$Id) { if (-not $done.Contains($Id)) { $done.Add($Id) | Out-Null }; Save-PimInstallState -StatePath $StatePath -InstallId $installId -Completed @($done) }
$resumeCmd = "Install-PimManager -ConfigPath '$ConfigPath' -LicencePath '$LicencePath' -StatePath '$StatePath' -Resume"

# the licence: a Pro licence for THIS tenant, verifiable offline. Anything else is a bad bundle (exit 3).
$lic = $null; $licText = ''
try { $licText = Get-Content -Raw -LiteralPath $LicencePath -ErrorAction Stop; $lic = if ($TestLicenceCertB64) { Get-PimLicense -LicenseText $licText -PublicCertB64 $TestLicenceCertB64 } else { Get-PimLicense -LicenseText $licText } } catch { $lic = $null }
$licWhy = if (-not $lic) { "the licence file '$LicencePath' could not be read" }
          elseif ("$($lic.Status)" -notin 'Valid', 'Grace') { "the licence is $($lic.Status): $($lic.Reason)" }
          elseif ("$($lic.Sku)" -notmatch '^(?i)pro(-.+)?$') { "the licence is a '$($lic.Sku)' licence, not Pro" }
          elseif (-not ($licBind = Test-PimLicenseTenantBinding -License $lic -TenantId $cfg.tenantId).ok) { $licBind.reason }   # LIC anti-copy: bound, and to THIS tenant
          else { '' }
if ($licWhy) { Emit 'config' 'failed' $licWhy 'Download the installation bundle again from invardia.com, or contact support.'; Finish 3 }
Emit 'config' 'ok' ("installing into resource group '$($cfg.resourceGroup)' in $($cfg.location); licence: $($lic.Customer), valid until $($lic.ValidTo)") -Detail @{ resourceGroup = $cfg.resourceGroup; location = $cfg.location; edition = $cfg.edition }
$names = Get-PimInstallNames -Config $cfg

# ================================================================== 2. preflight
$who = $null
$preflightFailed = $false
function Pre([string]$Id, [scriptblock]$Body) {
    if ($done.Contains($Id) -and $Id -ne 'preflight-signin') { Emit $Id 'skipped' 'already checked (resume)'; return }
    Emit $Id 'started'
    try { $r = & $Body } catch { $r = @{ state = 'failed'; message = "the check could not run: $($_.Exception.Message)" } }
    Emit $Id $r.state "$($r.message)" "$($r.actionText)" "$($r.actionCommand)"
    if ($r.state -eq 'failed') { $script:preflightFailed = $true } else { Mark $Id }
}

Pre 'preflight-signin' {
    $script:who = Get-PimSignedInIdentity -TenantId $cfg.tenantId -SubscriptionId $cfg.subscriptionId -Az $Az
    if (-not $script:who.ok) { return @{ state = 'failed'; message = $script:who.reason; actionText = 'Sign in as yourself in this shell:'; actionCommand = "az login --tenant $($cfg.tenantId)" } }
    @{ state = 'ok'; message = "signed in as $($script:who.userName)" }
}
if ($preflightFailed) { Finish 2 }

Pre 'preflight-target' {
    $acc = Az-Json @('account', 'show', '--subscription', $cfg.subscriptionId)
    if (-not $acc) { return @{ state = 'failed'; message = "subscription $($cfg.subscriptionId) is not visible to $($who.userName)" } }
    if ("$($acc.tenantId)" -ine $cfg.tenantId) { return @{ state = 'failed'; message = "subscription $($cfg.subscriptionId) belongs to tenant $($acc.tenantId), not $($cfg.tenantId)" } }
    if ("$($acc.state)" -and "$($acc.state)" -ne 'Enabled') { return @{ state = 'failed'; message = "subscription '$($acc.name)' is $($acc.state)" } }
    @{ state = 'ok'; message = "subscription '$($acc.name)' in tenant $($cfg.tenantId)" }
}

$script:rights = $null
Pre 'preflight-rights' {
    $roles = @((Az-Text @('role', 'assignment', 'list', '--assignee', $who.objectId, '--scope', "/subscriptions/$($cfg.subscriptionId)", '--include-inherited', '--include-groups', '--subscription', $cfg.subscriptionId, '--query', '[].roleDefinitionName', '-o', 'tsv')) -split "`r?`n" | Where-Object { "$_".Trim() })
    $dir = Get-InstallRest 'https://graph.microsoft.com/v1.0/me/transitiveMemberOf/microsoft.graph.directoryRole?$select=roleTemplateId' 'https://graph.microsoft.com'
    $tpl = @(@($dir.value) | ForEach-Object { "$($_.roleTemplateId)" })
    $v = Get-PimInstallRightsVerdict -AzureRoles $roles -DirectoryRoleTemplateIds $tpl
    $script:rights = $v
    if (-not $v.azureOk) { return @{ state = 'failed'; message = $v.message; actionText = 'Ask a subscription Owner to grant you Owner (or Contributor + User Access Administrator):'; actionCommand = "az role assignment create --assignee $($who.userName) --role Owner --scope /subscriptions/$($cfg.subscriptionId)" } }
    if (-not $v.entraOk) { return @{ state = 'warning'; message = $v.message } }
    @{ state = 'ok'; message = 'Owner-level rights on the subscription and an active directory admin role' }
}

Pre 'preflight-providers' {
    $need = 'Microsoft.App', 'Microsoft.ContainerRegistry', 'Microsoft.Sql', 'Microsoft.OperationalInsights', 'Microsoft.ManagedIdentity', 'Microsoft.Network'
    $missing = @($need | Where-Object { (Az-Text @('provider', 'show', '-n', $_, '--subscription', $cfg.subscriptionId, '--query', 'registrationState', '-o', 'tsv')) -ne 'Registered' })
    if (-not $missing.Count) { return @{ state = 'ok'; message = 'all required resource providers are registered' } }
    if ($script:rights -and $script:rights.azureOk) { return @{ state = 'ok'; message = "will be registered by the installation: $($missing -join ', ')" } }
    @{ state = 'failed'; message = "not registered: $($missing -join ', ')"; actionText = 'Ask a subscription Owner to register them:'; actionCommand = (($missing | ForEach-Object { "az provider register -n $_ --subscription $($cfg.subscriptionId)" }) -join '; ') }
}

Pre 'preflight-names' {
    $msgs = @()
    $grp = Az-Json @('group', 'show', '-n', $names.resourceGroup, '--subscription', $cfg.subscriptionId)
    if ($grp) { $msgs += "resource group '$($names.resourceGroup)' exists and is used" ; if ("$($grp.location)" -and "$($grp.location)" -ne $cfg.location) { $msgs += "(it is in $($grp.location); the new resources go to $($cfg.location))" } }
    $ours = if ($grp) { Az-Json @('sql', 'server', 'show', '-g', $names.resourceGroup, '-n', $names.sqlServer, '--subscription', $cfg.subscriptionId) } else { $null }
    if (-not $ours -and (& $ResolveHost $names.sqlFqdn)) { return @{ state = 'failed'; message = "the database server name '$($names.sqlServer)' is already taken in Azure -- start a new installation from the wizard (a new installation id gives new names)" } }
    $acrFree = Az-Text @('acr', 'check-name', '-n', $names.acr, '--subscription', $cfg.subscriptionId, '--query', 'nameAvailable', '-o', 'tsv')
    if ($acrFree -eq 'false') {
        $acrOurs = if ($grp) { Az-Json @('acr', 'show', '-g', $names.resourceGroup, '-n', $names.acr, '--subscription', $cfg.subscriptionId) } else { $null }
        if (-not $acrOurs) { return @{ state = 'failed'; message = "the registry name '$($names.acr)' is already taken in Azure -- start a new installation from the wizard" } }
    }
    $msgs += "names: $($names.sqlServer), $($names.acr), $($names.environment)"
    @{ state = 'ok'; message = ($msgs -join ' ') }
}

Pre 'preflight-sql-region' {
    $cap = Get-InstallRest "https://management.azure.com/subscriptions/$($cfg.subscriptionId)/providers/Microsoft.Sql/locations/$($cfg.location)/capabilities?api-version=2021-11-01" 'https://management.azure.com/'
    if (-not $cap) { return @{ state = 'warning'; message = "could not read Azure SQL's capabilities in $($cfg.location) -- the database step will tell" } }
    if ("$($cap.status)" -eq 'Disabled') { return @{ state = 'failed'; message = "Azure SQL is not available for this subscription in $($cfg.location) -- choose another region in the wizard (Sweden Central is a good default)" } }
    @{ state = 'ok'; message = "Azure SQL is offered in $($cfg.location) ($($cap.status))" }
}
if ($preflightFailed) { Finish 2 }
if ($PreflightOnly) { Write-Host 'preflight passed -- nothing was changed (-PreflightOnly)' -ForegroundColor Green; Finish 0 }

# ================================================================== 3. deploy
$deployArgs = ConvertTo-PimInstallDeployArgs -Config $cfg -SignedInUpn $who.userName
$onStep = { param($ev) $e = ConvertTo-PimInstallStepEvent -DeployEvent $ev -InstallId $installId -ResumeCommand $resumeCmd; if ($e) { Send-Event $e; if ("$($e.state)" -in 'ok', 'warning', 'skipped') { Mark "$($e.step.id)" } } }
if (-not $Deploy) { $Deploy = { param([hashtable]$DeployArgs, [scriptblock]$OnStep) & (Join-Path $here 'Invoke-PimDeployAll.ps1') @DeployArgs -OnStep $OnStep } }
$summary = $null
try { $summary = @(& $Deploy $deployArgs $onStep) | Where-Object { $_ -and $_.PSObject.Properties['status'] } | Select-Object -Last 1 }
catch { Emit 'verify' 'failed' "the deployment stopped: $($_.Exception.Message)" 'Fix the cause above, then resume the installation:' $resumeCmd; Finish 1 }
if (-not $summary -or "$($summary.status)" -notin 'success', 'unverified') {
    $failed = @($summary.failedSteps | Where-Object { $_ }) -join ', '
    if (-not @($events | Where-Object { $_.state -eq 'failed' }).Count) { Emit 'verify' 'failed' "the deployment did not complete$(if ($failed) { " (failed: $failed)" })" 'Fix the cause above, then resume the installation:' $resumeCmd }
    Finish 1
}

# ================================================================== 4. licence, support access, health, outputs
if ($done.Contains('licence')) { Emit 'licence' 'skipped' 'already registered (resume)' }
else {
    Emit 'licence' 'started'
    if (-not $InstallLicence) { $InstallLicence = { param($Path, $SqlFqdn, $TenantId) & (Join-Path $here 'Set-PimLicense.ps1') -LicensePath $Path -SqlServer $SqlFqdn -TenantId $TenantId -UseSignedInAccount | Out-Host; @{ ok = (-not $LASTEXITCODE) } } }
    $lr = & $InstallLicence $LicencePath $names.sqlFqdn $cfg.tenantId
    if ($lr -and $lr.ok) { Emit 'licence' 'ok' "the $($cfg.edition) licence is registered -- the Pro features are on"; Mark 'licence' }
    else { Emit 'licence' 'failed' 'the licence could not be stored in the PIM database' 'Fix the cause above, then resume the installation:' $resumeCmd; Finish 1 }
}

if (-not "$($cfg.supportAppId)".Trim()) { Emit 'support-app-access' 'skipped' 'no Invardia Support app was named' }
elseif ($done.Contains('support-app-access')) { Emit 'support-app-access' 'skipped' 'already granted (resume)' }
else {
    Emit 'support-app-access' 'started'
    $grantCmd = "Grant-PimSupportAccess -AppId $($cfg.supportAppId) -Level $($cfg.supportAccess) -TenantId $($cfg.tenantId) -SubscriptionId $($cfg.subscriptionId) -ResourceGroup $($names.resourceGroup) -SqlServer $($names.sqlFqdn)"
    if (-not $GrantSupport) { $GrantSupport = { param([hashtable]$A) & (Join-Path $here 'Grant-PimSupportAccess.ps1') @A | Out-Host; @{ ok = (-not $LASTEXITCODE) } } }
    $gr = $null
    try { $gr = & $GrantSupport @{ AppId = $cfg.supportAppId; Level = $cfg.supportAccess; TenantId = $cfg.tenantId; SubscriptionId = $cfg.subscriptionId; ResourceGroup = $names.resourceGroup; SqlServer = $names.sqlFqdn } } catch { $gr = $null }
    if ($gr -and $gr.ok) { Emit 'support-app-access' 'ok' "the Invardia Support app has '$($cfg.supportAccess)' access"; Mark 'support-app-access' }
    else { Emit 'support-app-access' 'warning' 'the Invardia Support app could not be given its access with your rights' 'Ask a Privileged Role Administrator to run:' $grantCmd }
}

Emit 'health-check' 'started'
$healthy = ("$($summary.status)" -eq 'success') -and [bool]$summary.healthy
$warnings = @($events | Where-Object { $_.state -eq 'warning' } | ForEach-Object { $_.step.id } | Select-Object -Unique)
if ($healthy -and -not $warnings.Count) { Emit 'health-check' 'ok' 'the PIM Manager is deployed and healthy' }
elseif ($healthy) { Emit 'health-check' 'warning' "deployed and healthy; still waiting for: $($warnings -join ', ')" }
else { Emit 'health-check' 'warning' 'deployed, but the health check could not verify every part -- open the PIM Manager and check the status page' }

$tickPid = Az-Text @('containerapp', 'job', 'show', '-g', $names.resourceGroup, '-n', 'ca-pim-tick', '--subscription', $cfg.subscriptionId, '--query', 'identity.principalId', '-o', 'tsv')
$fqdn = Az-Text @('containerapp', 'show', '-g', $names.resourceGroup, '-n', $names.managerApp, '--subscription', $cfg.subscriptionId, '--query', 'properties.configuration.ingress.fqdn', '-o', 'tsv')
$verFile = Join-Path $sol 'VERSION'
$outputs = [ordered]@{
    subscriptionId          = $cfg.subscriptionId
    resourceGroup           = $names.resourceGroup
    sqlServerId             = (Az-Text @('sql', 'server', 'show', '-g', $names.resourceGroup, '-n', $names.sqlServer, '--subscription', $cfg.subscriptionId, '--query', 'id', '-o', 'tsv'))
    logAnalyticsWorkspaceId = (Az-Text @('monitor', 'log-analytics', 'workspace', 'show', '-g', $names.resourceGroup, '-n', $names.logAnalytics, '--subscription', $cfg.subscriptionId, '--query', 'id', '-o', 'tsv'))
    keyVaultId              = ''
    runtimeIdentity         = 'mi-container'
    runtimeIdentityClientId = $(if ($tickPid) { "$((Get-InstallRest "https://graph.microsoft.com/v1.0/servicePrincipals/$tickPid`?`$select=appId" 'https://graph.microsoft.com').appId)" } else { '' })   # never `az ad`: it follows the default account's tenant
    version                 = $(if (Test-Path -LiteralPath $verFile) { "$(Get-Content -Raw -LiteralPath $verFile)".Trim() } else { '' })
    portalUrl               = $(if ($fqdn) { "https://$fqdn" } else { '' })
}
Mark 'completed'
Emit 'completed' 'completed' $(if ($outputs.portalUrl) { "open the PIM Manager: $($outputs.portalUrl)" } else { 'installation complete' }) -Outputs $outputs
Finish 0
