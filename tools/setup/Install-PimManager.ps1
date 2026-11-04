#Requires -Version 5.1

<#
.SYNOPSIS
  Install PIM Manager into your own Azure subscription in one guided run: check the answers, check your sign-in, rights and subscription, deploy PIM Manager, give the Invardia Support app its access when you named one, and verify the installation.
  §95.2 -- the GUIDED INSTALL of the PIM Manager. ONE-LINE-INSTALL (owner 2026-11-02): one line, every value a parameter.

.DESCRIPTION
  -WhatIf: runs the checks (sign-in, subscription, rights, resource providers, names, every service PIM Manager needs in the chosen region -- reads only),
  then prints what the installation WOULD do -- the deploy's own plan included -- and stops before the first change
  (no Azure / Entra / SQL change, no state file outside the temp folder).

  Install-PimManager -TenantId <tenant id> -SubscriptionId <subscription id> [-Location <region>] [-ResourceGroup <name>]
      [-SuperAdmins <upn,...>] [-AlertRecipients <mail,...>] [-MailSender <mail>] [-PortalUsers <upn,...>] [-AllowAllMembers]
      [-VnetAddressPrefix <cidr>] [-VnetName <name>] [-AppsSubnetName <name>] [-AppsSubnetPrefix <cidr>]
      [-PrivateNetwork [-VnetId <id>] [-EndpointsSubnetName <name>] [-EndpointsSubnetPrefix <cidr>]
       [-PrivateDnsZonesResourceGroupId <id>] [-HubVnetId <id> [-PeerToHub] [-LinkZonesToHub]] [-WebAppAccess internal]]
      [-Edition Community|Trial|Pro] [-UpdateRing 2|3] [-KeyVaultName <name>] [-EngineAzureRootUserAccessAdmin] [-InstallId <id>]
      [-SupportAppId <client id> [-SupportAccess troubleshoot|setup|asbuilt]] [-Reporter <scriptblock>] [-StatePath <dir>]
      [-Resume] [-PreflightOnly] [-ViaSupportApp] [-WhatIf]

  INVARDIA SUPPORT ACCESS (INSTALL-1 ALIGN). The Invardia Support app gets 'troubleshoot' access (or the -SupportAccess
  level) only when -SupportAppId names it: the Support app is named by its id, never found by name. Without -SupportAppId
  nothing is granted. -ViaSupportApp: the installation runs as the Invardia Support app and needs a Connect-InvardiaSupport
  session for -TenantId in this PowerShell window (refused otherwise).

  EVERY ANSWER IS A PARAMETER, WITH ITS REAL VALUE (owner 2026-11-02). There is no answers file, no key and no licence in the
  command. Only -TenantId and -SubscriptionId are needed; everything else has a default (install-parameters.json:
  swedencentral, resource group rg-pim, 10.220.0.0/22 + /23, you as the administrator, the administrators' mailboxes for
  alerts) or is derived (the installation id, and from it every resource name and the state folder -- the same tenant,
  subscription and resource group give the same ones, so -Resume finds them). -Reporter is optional: without it every step
  is printed as one readable line.

  EDITION. No -Edition = PIM Manager COMMUNITY (free): one line says so, the Core features are installed, no multi-tenant
  (MSP) gate is switched on (that is Pro), and the updater follows the Community channel of the public release.
  -Edition Pro (or Trial) deploys exactly the same way, with the Pro updater: the environment is installed WITHOUT a
  licence, and the end of the installation says what to do next -- sign in to PIM Manager and add your licence in
  Settings > Licence. The Pro features switch on with the licence, and PIM Manager then registers itself with Invardia
  for its updates. Several tenants (MSP) are set up with the managing-tenant build, not this command.

  NETWORK. Public by default: the PIM Manager is reachable on the internet behind Microsoft Entra sign-in, in its own
  virtual network vnet-pim (-VnetAddressPrefix, default 10.220.0.0/22; the Container Apps subnet -AppsSubnetName /
  -AppsSubnetPrefix, default snet-pim-aca 10.220.0.0/23). -PrivateNetwork installs the PRIVATE shape with the same
  command: the Container Apps environment is internal (no public address; -WebAppAccess is then internal), the database and
  the registry are reached only over private endpoints in -EndpointsSubnetName / -EndpointsSubnetPrefix (default
  pim-endpoints, the /26 right after the apps subnet): SQL is created with public network access disabled and no firewall
  rule, the registry is Premium with public access disabled and builds its images on its agent pool (pimpool) inside the
  network. -VnetId uses a network you already have instead of making one (any resource group of the installation's
  subscription). -PrivateDnsZonesResourceGroupId names your central privatelink zones: they are used, never created or
  written. -HubVnetId names your hub; -PeerToHub peers it (your rights on both networks are checked first, and a peering is
  never left half made) and -LinkZonesToHub links all of PIM Manager's own private zones to it (both off). The same command
  with -PrivateNetwork on an existing PUBLIC installation converts it (Convert-PimToPrivate.ps1 runs underneath, data kept).
  Before anything is created the step 'preflight-network' reads the network, the hub's range and the central zones; at the
  end the network hand-off (peering, DNS for the PIM Manager, the database and the registry) is printed and written to
  network-hand-off.txt in the state folder. A private install runs from a machine inside that network or one peered to
  it (its SQL steps reach the database over the private endpoint), and so do its later setup scripts and a -Resume.

  Start it from the launcher (Start-PimManagerInstall.ps1, a release file of the public release: it downloads that
  release and runs this script from it with the same parameters), or from a copy of the release.

  Runs in PowerShell 7 on the administrator's own machine, signed in in the browser as that administrator -- never a
  secret, no Azure CLI, no PowerShell modules (2.4.554+). It:
    1. checks the answers (the parameters)                                                              -> exit 3 when bad
    2. preflight: sign-in, tenant + subscription, rights, providers, names, services in the region     -> exit 2 when failed
       (-PreflightOnly stops here, exit 0)
    3. deploys with Invoke-PimDeployAll (the signed-in Container Apps shape, public or -PrivateNetwork; the public
       release), reporting every step                                                                    -> exit 1 when failed
    4. grants the Invardia Support app its access when -SupportAppId names one, runs the END-OF-INSTALL CHECK
       ('verify-install', Confirm-PimInstall.ps1: SuperAdmins, updater + ring, licence (Pro: a reminder until it is added),
       mail sender + both sending identities in scope, alert recipients, the engine's Graph rights + Reader at the tenant
       root, sign-in, the SQL window; repairs what it can; a failed required line = exit 1 with that line's fix), checks
       health, and reports 'completed' with the outputs Invardia's support needs                       -> exit 0
  A step that needs a higher role than the installer holds ends as a WARNING with the command for the right person; the
  install continues. -Resume re-runs from where it stopped with the SAME parameters: completed preflight / support steps
  are skipped, and the deploy itself is idempotent (each of its steps checks what exists first). The installation keeps
  its own state (state.json in -StatePath; no key or token is ever written there), including that THIS install opened
  the SQL firewall rule 'AllowSetupHost': the install closes that rule on every way out (the end, a failed step, the next
  run), and never removes a rule it did not open itself. The preflight also checks the PIM Manager administrators: a
  sign-in name that is not in the tenant, or administrators without a mailbox and no alert recipients, stops the install
  there (exit 2), before anything is created.

  Reporter events: @{ installId; step = @{ id; title }; state = started|ok|warning|failed|skipped|completed; message;
  action = @{ text; command }; detail; outputs }. This script never calls invardia.com.

.EXAMPLE
  ./tools/setup/Install-PimManager.ps1 -TenantId '<tenant id>' -SubscriptionId '<subscription id>'
  The most common: PIM Manager Community in your own subscription, signed in in the browser, every other answer a default.
.EXAMPLE
  ./tools/setup/Install-PimManager.ps1 -TenantId '<tenant id>' -SubscriptionId '<subscription id>' -WhatIf
  To see the plan first: the checks run, then every step the installation would take is printed, and nothing is changed.
.EXAMPLE
  ./tools/setup/Install-PimManager.ps1 -TenantId '<tenant id>' -SubscriptionId '<subscription id>' -Location westeurope -ResourceGroup rg-pim-manager -SuperAdmins 'admin1@contoso.com','admin2@contoso.com' -AlertRecipients 'pim-alerts@contoso.com'
  When you choose the region and the resource group yourself, and name the PIM Manager administrators and who gets the alerts.
.EXAMPLE
  ./tools/setup/Install-PimManager.ps1 -TenantId '<tenant id>' -SubscriptionId '<subscription id>' -Edition Pro
  Pro or a trial: the same installation with the Pro updater; afterwards sign in to PIM Manager and add your licence in Settings > Licence.
.EXAMPLE
  ./tools/setup/Install-PimManager.ps1 -TenantId '<tenant id>' -SubscriptionId '<subscription id>' -Resume
  After a stop: run the same command with -Resume; finished steps are skipped and the installation goes on where it stopped.

.NOTES
  Requirements:
    PowerShell: 7.0 or later (pwsh; Azure Cloud Shell has it). Windows PowerShell 5.1 is not supported.
    Role: Owner on the target subscription (Azure); Privileged Role Administrator and Application Administrator
          (Microsoft Entra); Exchange Administrator only for the mail sender (optional). A -PrivateNetwork install with
          -PeerToHub / -LinkZonesToHub also needs the right to write the peering / the zone link on the hub network.
    Hosts: login.microsoftonline.com, management.azure.com, graph.microsoft.com, *.database.windows.net (port 1433),
           *.azurecr.io, outlook.office365.com (mail sender)

  PERMISSIONS (the full list, with scope, reason and undo, is on the documentation page and in Install-PimManager.doc.json):
  The person running it needs: Owner (or Contributor + User Access Administrator) on the subscription; in Entra ID
  Privileged Role Administrator (Graph app roles for the managed identities, the role-assignable SQL admin group) and
  Application Administrator (the Manager's sign-in app). Exchange Administrator only for the mail sender step.
  It creates: a resource group with a virtual network, a container registry, a Log Analytics workspace, Azure SQL server +
  database, managed identities, the Container Apps environment, the Manager app and its jobs (tick, updater), the Entra
  sign-in app and its members group, the SQL admin group grp-pim-sql-admins. It grants: Microsoft Graph application
  permissions to the engine job identity (the engine set) and the Manager identity (a read-only set); AcrPull, Reader,
  Contributor (updater, on the resource group) and Reader at the tenant root to the engine; the least-privilege SQL
  model (one database role per component: pim_web, pim_engine, pim_updater + db_ddladmin; a signed access procedure),
  the installer leaving the SQL admin group again at the end; the Invardia Support app's access when named -- at
  every level that includes its standing access to the PIM database (member of the SQL admin group, its own database
  user with db_owner), which stays until you switch the Support app off.
  Logs: a transcript of the run in the temp folder (pim-manager-logs); its path is printed.

.LINK
  https://invardia.com/docs/pim/scripts/Install-PimManager/
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    # ONE-LINE-INSTALL (owner 2026-11-02): every answer is a PARAMETER with its real value -- no answers file, no key, no
    # licence. -TenantId and -SubscriptionId are required; everything else has a default.
    [string]$TenantId = '',
    [string]$SubscriptionId = '',
    [string]$Location = '',
    [string]$ResourceGroup = '',
    [string[]]$SuperAdmins = @(),
    [string[]]$AlertRecipients = @(),
    [string]$MailSender = '',
    # who may sign in to the PIM Manager (default: the SuperAdmins); -AllowAllMembers = every member account of the tenant
    [string[]]$PortalUsers = @(),
    [switch]$AllowAllMembers,
    [string]$VnetAddressPrefix = '',
    # the old names of -AppsSubnetPrefix / -PrivateNetwork, kept one release for a printed -Resume command of an earlier run
    [Parameter(DontShow)][string]$SubnetAddressPrefix = '',
    [Parameter(DontShow)][string]$Exposure = '',
    # --- PRIVATE NETWORK (framework INSTALL-1 item 5): SI's names, name for name; public when -PrivateNetwork is not given ---
    [switch]$PrivateNetwork,
    [string]$VnetId = '',
    [string]$VnetName = '',
    [string]$AppsSubnetName = '',
    [string]$AppsSubnetPrefix = '',
    [string]$EndpointsSubnetName = '',
    [string]$EndpointsSubnetPrefix = '',
    [string]$PrivateDnsZonesResourceGroupId = '',
    [string]$HubVnetId = '',
    [switch]$LinkZonesToHub,
    [switch]$PeerToHub,
    [ValidateSet('', 'external', 'internal')][string]$WebAppAccess = '',
    # Community = the free edition, the Core features (the default when no edition is given). Trial / Pro install the same
    # way with the Pro updater and NO licence: the licence is added afterwards in PIM Manager > Settings > Licence.
    [ValidateSet('', 'Community', 'Trial', 'Pro')][string]$Edition = '',
    # Pro / trial: the update ring (2 = design partners, 3 = broad, the default)
    [ValidateSet('', '2', '3')][string]$UpdateRing = '',
    # the install's own Key Vault name (the sign-in front's keys); default kv-pim-<token>
    [string]$KeyVaultName = '',
    # §97: also give the engine User Access Administrator at the tenant root (off by default; Reader there is always given)
    [switch]$EngineAzureRootUserAccessAdmin,
    # the installation id (resource names + the state folder); default: derived from tenant, subscription and resource group
    [string]$InstallId = '',
    # the Invardia Support app's client id -- only when you want Invardia support to have access (nothing is granted otherwise)
    [string]$SupportAppId = '',
    [ValidateSet('', 'troubleshoot', 'setup', 'asbuilt')][string]$SupportAccess = '',
    [scriptblock]$Reporter,
    [string]$StatePath = '',
    [switch]$Resume,
    [switch]$PreflightOnly,
    # INSTALL-1 ALIGN (6): run as the Invardia Support app -- requires a Connect-InvardiaSupport session for -TenantId
    [switch]$ViaSupportApp,
    # --- test seams (offline tests/Test-PimGuidedInstall.ps1); omit them for a real install ---
    [scriptblock]$Az,
    [scriptblock]$Deploy,
    [scriptblock]$GrantSupport,
    [scriptblock]$ResolveHost,
    [scriptblock]$Http,
    # REGION-ACCEPTS-NEW test seam: param([string]$Url, [string]$Body) -> @{ StatusCode; Content } (the ARM deployment VALIDATE
    # POST). A real install (no -Http seam) posts over REST; a test that passes -Http without this one runs no validate.
    [scriptblock]$HttpPost,
    # INSTALL-HARDEN-1: param([hashtable]$VerifyArgs) -> @{ done; failed[]; warnings[]; sentence; rows[] } (Confirm-PimInstall.ps1)
    [scriptblock]$VerifyInstall,
    # test seam (REQ 98.4 b): param([string]$Op, $Target) -- 'get' answers the address of the SQL firewall rule 'AllowSetupHost'
    # ('' = not there; throws = not readable), 'remove' deletes it. A real install uses ARM REST (below).
    [scriptblock]$SetupHostRule,
    # test seam (PIM 100.156 B, framework 12.23 P5): param([string]$ObjectId, [string]$SqlServer, [string]$ResourceGroup) ->
    # @{ ok; released; reason } -- the signed-in installer leaves the SQL admin group at the end of the install. A real
    # install: Invoke-PimSqlAdminGroupSetupRelease (_PimSqlAdminGroup.ps1). Not run for an Invardia Support-app session
    # (the Support app is the group's standing member) or a managed-tenant install.
    [scriptblock]$ReleaseSqlAdmin,
    # test seam (INSTALL-1 GAP): param([string]$Sql) -> one scalar from the PIM database, as the installer -- records the trial /
    # Pro install edition (Set-PimInstallEditionSetting). A real install: the sign-in front step's database I/O.
    [scriptblock]$StoreSql,
    # --- test seam (GUIDED-INSTALL-FRONT, offline tests/Test-PimGuidedInstall.ps1): param([hashtable]$A, [scriptblock]$OnStep)
    # -> @{ ok; failedStep; reason; completed[]; keyVaultId } in place of Invoke-PimInstallSigninFront -- omit it for a real install ---
    [scriptblock]$SigninFront,
    # --- test seam (INSTALL-1 item 5, public -> private): param([hashtable]$A) -> the exit code of Convert-PimToPrivate.ps1 ---
    [scriptblock]$ConvertToPrivate
)
$ErrorActionPreference = 'Stop'
# INSTALL-SAMPLES: the command-line answers, captured FIRST -- PowerShell variables are case-insensitive, and this script's own
# $installId (assigned below) IS the -InstallId parameter; read the answers only from this copy.
$pimCli = @{}
foreach ($pk in @($PSBoundParameters.Keys)) { $pimCli[$pk] = $PSBoundParameters[$pk] }
$here = $PSScriptRoot
$sol = Split-Path -Parent (Split-Path -Parent $here)
. (Join-Path $here '_PimGuidedInstall.ps1')
. (Join-Path $here '_PimSignedIn.ps1')
. (Join-Path $sol 'engine\_shared\PIM-License.ps1')
. (Join-Path $PSScriptRoot '_PimScriptDoc.ps1')     # framework 12.7: the Documentation line + the transcript
# §100.41 (NO-AZ, framework 12.17): the installer's reads go over ARM / Graph REST with PIM-Rest's ONE token client (the
# Invardia Support-app session, else the person's browser sign-in -- Get-PimSignedInIdentity). Loaded at FILE scope (71.32).
. (Join-Path $sol 'engine\_shared\PIM-Rest.ps1')
. (Join-Path $sol 'engine\_shared\PIM-ArmSetup.ps1')
# GUIDED-INSTALL-FRONT (2026-10-21): the install ends on the sign-in front (vault + key, state, scope, image, the move)
. (Join-Path $sol 'engine\_shared\PIM-SigninFrontImage.ps1')
. (Join-Path $here '_PimInstallSigninFront.ps1')
# the step's real I/O builds the front image (PIM-AcrBuild) and writes the front's database state (PIM-SqlStore): loaded HERE,
# at file scope -- a library dot-sourced inside a function is gone when that function returns
if (-not (Get-Command Invoke-PimAcrRestBuild -ErrorAction SilentlyContinue)) { . (Join-Path $sol 'engine\_shared\PIM-AcrBuild.ps1') }
if (-not (Get-Command Resolve-PimSqlClientType -ErrorAction SilentlyContinue)) { . (Join-Path $sol 'engine\_shared\PIM-SqlStore.ps1') }
$null = Start-PimScriptRun -Script 'Install-PimManager'
# framework 8.13 INSTALL-HANDOFF (REQ 100.66): Invardia's bootstrap may have signed the person in already and handed this
# process ACCESS tokens in PIM_HANDOFF_TOKENS. Take them out of the environment at once -- from here they live in memory
# only (checked after the answers are read, below). Child processes never inherit this variable: the managed-tenant build
# hands each step process its own short-lived tokens. A previous run's handoff in this session is never reused.
$script:PimHandoffRaw = "$env:PIM_HANDOFF_TOKENS"
if ($script:PimHandoffRaw.Trim()) { $env:PIM_HANDOFF_TOKENS = $null }
$global:PimHandoffTokens = $null
$script:PimInstallVersion = $(try { "$((Get-Content -LiteralPath (Join-Path $sol 'VERSION') -Raw -ErrorAction Stop))".Trim() } catch { 'unknown' })   # in every config-OK event (2026-10-10)
try {

# -Az is the LEGACY az-shaped TEST seam (tests/Test-PimGuidedInstall.ps1 scripts az's answers). Without it -- every real
# install -- the same az-shaped reads are answered over REST by Invoke-PimInstallRestRead: no az CLI is needed or invoked.
$azSeam = [bool]$Az
function Invoke-PimInstallRestRead {
    <#
      The installer's az-shaped reads, answered over ARM / Graph REST (PIM-ArmSetup.ps1). ONLY the shapes this script uses
      are known; anything else THROWS (fails closed -- never a silent empty answer that would read as "absent").
      Output = what az printed: JSON text (-o json / no --query) or the --query value as text (-o tsv); '' when absent.
    #>
    param([string[]]$AzArgs)
    $words = @(); $opt = @{}; $i = 0
    while ($i -lt $AzArgs.Count -and "$($AzArgs[$i])" -notmatch '^-') { $words += "$($AzArgs[$i])"; $i++ }
    while ($i -lt $AzArgs.Count) {
        $k = "$($AzArgs[$i])"; $v = $true
        if ($i + 1 -lt $AzArgs.Count -and "$($AzArgs[$i + 1])" -notmatch '^--?[a-z]') { $v = "$($AzArgs[$i + 1])"; $i++ }
        $opt[$k] = $v; $i++
    }
    $o = { param($names) foreach ($n in $names) { if ($opt.ContainsKey($n)) { return "$($opt[$n])" } }; '' }
    $sub = & $o @('--subscription'); $rg = & $o @('-g', '--resource-group'); $name = & $o @('-n', '--name')
    $cmd = $words -join ' '
    $val = switch ($cmd) {
        'account show' {
            $s = Get-PimArmSubscription -SubscriptionId $sub
            if ($s) { [pscustomobject]@{ id = "$($s.subscriptionId)"; tenantId = "$($s.tenantId)"; name = "$($s.displayName)"; state = "$($s.state)" } }
        }
        'account get-access-token' { [pscustomobject]@{ accessToken = "$(Get-PimRestToken -Resource (& $o @('--resource')) -TenantId $cfg.tenantId)" } }
        'role assignment list' {
            # --include-groups: assignedTo() returns the principal's own AND its groups' assignments; --include-inherited
            # keeps the ones AT the scope or above it (az --scope never lists the ones below).
            $scope = (& $o @('--scope')).TrimEnd('/'); $oid = & $o @('--assignee')
            $f = [uri]::EscapeDataString("assignedTo('$oid')")
            @(Invoke-PimSetupArm -Path "$scope/providers/Microsoft.Authorization/roleAssignments?`$filter=$f" -ApiVersion (Get-PimSetupApiVersion authorization) -All |
                Where-Object { $_ -and (Test-PimInstallScopeAtOrAbove -Scope $scope -AssignmentScope "$($_.properties.scope)") } |
                ForEach-Object { [pscustomobject]@{ roleDefinitionName = (Get-PimArmRoleName -RoleDefinitionId "$($_.properties.roleDefinitionId)") } })
        }
        'provider show' { [pscustomobject]@{ registrationState = (Get-PimArmProviderState -SubscriptionId $sub -Namespace $name) } }
        'group show' { Get-PimArmResourceGroup -SubscriptionId $sub -Name $name }
        'sql server show' { Get-PimArmSqlServer -SubscriptionId $sub -ResourceGroup $rg -Name $name }
        'acr check-name' {
            Invoke-PimSetupArm -Method POST -Path "/subscriptions/$sub/providers/Microsoft.ContainerRegistry/checkNameAvailability" -ApiVersion (Get-PimSetupApiVersion acr) `
                -Body @{ name = $name; type = 'Microsoft.ContainerRegistry/registries' }
        }
        'acr show' { Get-PimArmAcr -SubscriptionId $sub -ResourceGroup $rg -Name $name }
        'containerapp job show' { Get-PimArmAcaJob -SubscriptionId $sub -ResourceGroup $rg -Name $name }
        'containerapp show' { Get-PimArmAcaApp -SubscriptionId $sub -ResourceGroup $rg -Name $name }
        'monitor log-analytics workspace show' { Get-PimArmLogAnalytics -SubscriptionId $sub -ResourceGroup $rg -Name $name }
        default { throw "Invoke-PimInstallRestRead: no REST form for 'az $cmd'" }
    }
    $q = & $o @('--query')
    if ($q) {
        # the --query forms this script uses: a dotted path, or '[].<field>' over a list
        if ($q -match '^\[\]\.(\w+)$') { $f = $Matches[1]; return (@(@($val) | ForEach-Object { "$($_.$f)" } | Where-Object { $_ }) -join "`n") }
        $cur = $val; foreach ($p in ($q -split '\.')) { if ($null -eq $cur) { break }; $cur = $cur.$p }
        if ($cur -is [bool]) { return "$cur".ToLowerInvariant() }
        return "$cur"
    }
    if ($null -eq $val) { return '' }
    return ($val | ConvertTo-Json -Depth 20)
}
# A failed READ answers '' exactly as the az wrapper did (2>$null); a shape with no REST form is a code defect and throws.
if (-not $Az) { $Az = { param([string[]]$AzArgs) try { Invoke-PimInstallRestRead -AzArgs $AzArgs } catch { if ("$($_.Exception.Message)" -like 'Invoke-PimInstallRestRead: no REST form*') { throw }; Write-Verbose "$($_.Exception.Message)"; '' } } }
if (-not $ResolveHost) { $ResolveHost = { param([string]$HostName) try { @([System.Net.Dns]::GetHostAddresses($HostName)).Count -gt 0 } catch { $false } } }
# REQ 98.4 (b): the SQL firewall rule this install opens, read and removed over ARM REST (PIM-ArmSetup.ps1). A failed read
# THROWS (the caller then treats the rule as "not readable" and removes nothing); a rule or server that is not there = ''.
# Under the offline -Az seam there is no ARM: the rule is then tracked only when a test hands in -SetupHostRule.
if (-not $SetupHostRule -and -not $azSeam) {
    $SetupHostRule = { param([string]$Op, $Target)
        switch ($Op) {
            'get'    { return "$((Get-PimArmSqlFirewallRule -SubscriptionId $Target['subscriptionId'] -ResourceGroup $Target['resourceGroup'] -Server $Target['server'] -Name $Target['name']).properties.startIpAddress)".Trim() }
            'remove' { [void](Remove-PimArmSqlFirewallRule -SubscriptionId $Target['subscriptionId'] -ResourceGroup $Target['resourceGroup'] -Server $Target['server'] -Name $Target['name']) }
        }
    }
}

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
# 2026-10-10 (a customer's install looked frozen while a browser sign-in waited in a hidden window): every browser sign-in
# announces itself in the progress feed first, so Invardia and the person see WHAT is waiting.
$global:PIM_SignInNotify = { param($Audience, $Tenant)
    try { Emit 'preflight-signin' 'waiting' "sign-in required for $Audience in tenant $Tenant -- complete it in the private (InPrivate) browser window, or open the address printed in this PowerShell window" } catch { } }
function Az-Text([string[]]$AzArgs) { "$(@(& $Az $AzArgs) -join "`n")".Trim() }
function Az-Json([string[]]$AzArgs) { $t = Az-Text ($AzArgs + @('-o', 'json')); if ($t) { try { return ($t | ConvertFrom-Json) } catch { } }; return $null }
# A REST read with a token taken FOR THE TARGET SUBSCRIPTION (its tenant). Never `az rest`: it has no --subscription and
# uses the default account's tenant -- on a machine holding several logins that is another directory.
$pimHttpSeamGiven = [bool]$Http   # REGION-ACCEPTS-NEW: a test that hands -Http (and no -HttpPost) runs no live validate
if (-not $Http) { $Http = { param([string]$Url, [string]$Token) Invoke-RestMethod -Method GET -Uri $Url -Headers @{ Authorization = "Bearer $Token" } -TimeoutSec 60 } }
function Get-InstallRest([string]$Url, [string]$Resource) {
    $t = Az-Json @('account', 'get-access-token', '--subscription', $cfg.subscriptionId, '--resource', $Resource)
    if (-not "$($t.accessToken)") { return $null }
    try { return (& $Http $Url "$($t.accessToken)") } catch { return $null }
}
# REQ 98.4 (b): what this install remembers for its next run, written to the state file with the completed steps: the SQL
# firewall rule this install opened. Read as a plain variable (never $script:): the state is also saved from the deploy's
# -OnStep, a CHILD script, where $script: is the deploy's own.
$pimInstallMem = @{ hostRule = $null; signedIn = $false }
function Save-InstallState {
    # -WhatIf: the state file lives outside the temp folder (clouddrive / home), so a preview never writes it.
    if (-not $WhatIfPreference) { Save-PimInstallState -StatePath $StatePath -InstallId $installId -Completed @($done) -SetupHostRule $pimInstallMem.hostRule }
}
function Close-InstallHostRule {
    # REQ 98.4 (b): close the SQL firewall rule THIS install opened -- on every way out (the normal end, a failed step, a
    # resume), read back; the record leaves the state file only when the rule is gone, so a run that could not close it
    # hands it to the next one. A rule this install did not open has no record and is never touched. Not before the
    # sign-in passed (no browser sign-in just to close), and never under -WhatIf / -PreflightOnly (they change nothing).
    if ($WhatIfPreference -or $PreflightOnly -or -not $SetupHostRule -or -not $pimInstallMem.hostRule -or -not $pimInstallMem.signedIn) { return }
    $t = $pimInstallMem.hostRule
    try {
        if ("$(& $SetupHostRule 'get' $t)".Trim()) { & $SetupHostRule 'remove' $t | Out-Null }
        if ("$(& $SetupHostRule 'get' $t)".Trim()) { Write-Host "    the database firewall rule '$($t['name'])' on $($t['server']) is still there -- the next run of this installation closes it" -ForegroundColor Yellow; return }
        $pimInstallMem.hostRule = $null
        Save-InstallState
        Write-Host "    the database firewall rule '$($t['name'])' this installation opened on $($t['server']) is closed" -ForegroundColor DarkGray
    } catch { Write-Host "    the database firewall rule '$($t['name'])' on $($t['server']) could not be closed now ($((("$($_.Exception.Message)") -split "`n")[0])) -- the next run of this installation closes it" -ForegroundColor Yellow }
}
function Finish([int]$Code) {
    try { Close-InstallHostRule } catch { Write-Verbose "setup-host rule close failed: $($_.Exception.Message)" }
    Remove-Item Env:\PIM_GUIDED_INSTALL_RUN -ErrorAction SilentlyContinue
    $global:LASTEXITCODE = $Code; exit $Code
}

# ================================================================== 1. the answers (the parameters)
Emit 'config' 'started'
# ONE-LINE-INSTALL (owner 2026-11-02): the answers = the parameters, nothing else (ConvertTo-PimInstallAnswers builds the
# answers object Test-PimInstallConfig validates; every check, name and step below runs on it).
$cliAnswers = @{ tenantId = $TenantId; subscriptionId = $SubscriptionId; location = $Location; resourceGroup = $ResourceGroup
                 superAdmins = @($SuperAdmins); alertRecipients = @($AlertRecipients); mailSender = $MailSender; portalUsers = @($PortalUsers)
                 vnetAddressPrefix = $VnetAddressPrefix; subnetAddressPrefix = $SubnetAddressPrefix; exposure = $Exposure
                 edition = $Edition; updateRing = $UpdateRing; keyVaultName = $KeyVaultName
                 installId = "$($pimCli['InstallId'])"; supportAppId = $SupportAppId; supportAccess = $SupportAccess }
# a switch is an answer only when it is GIVEN (a "False" text would read as true)
if ($AllowAllMembers) { $cliAnswers['allowAllMembers'] = $true }
if ($EngineAzureRootUserAccessAdmin) { $cliAnswers['engineAzureRootUserAccessAdmin'] = $true }
# PRIVATE NETWORK (INSTALL-1 item 5): SI's names, only what was GIVEN (Test-PimInstallNetworkAnswers checks them)
foreach ($nk in 'VnetId', 'VnetName', 'AppsSubnetName', 'AppsSubnetPrefix', 'EndpointsSubnetName', 'EndpointsSubnetPrefix', 'PrivateDnsZonesResourceGroupId', 'HubVnetId', 'WebAppAccess') {
    if ($pimCli.ContainsKey($nk)) { $cliAnswers[$nk.Substring(0, 1).ToLowerInvariant() + $nk.Substring(1)] = "$($pimCli[$nk])" }
}
foreach ($nk in 'PrivateNetwork', 'LinkZonesToHub', 'PeerToHub') { if ($pimCli.ContainsKey($nk) -and [bool]$pimCli[$nk]) { $cliAnswers[$nk.Substring(0, 1).ToLowerInvariant() + $nk.Substring(1)] = $true } }
$ans = ConvertTo-PimInstallAnswers -Parameters $cliAnswers
if (@($ans.missing).Count) {
    Emit 'config' 'failed' ("missing: " + (@($ans.missing | ForEach-Object { '-' + $_.Substring(0, 1).ToUpperInvariant() + $_.Substring(1) }) -join ' and ') + " -- the Microsoft Entra tenant and the Azure subscription to install PIM Manager into") 'Run the command again with them:' "-TenantId '<tenant id>' -SubscriptionId '<subscription id>'"
    Finish 3
}
$chk = Test-PimInstallConfig -Config $ans.answers
if (-not $chk.ok) { Emit 'config' 'failed' ("the answers cannot be used: " + (@($chk.errors) -join '; ')) 'Correct the parameters, then run the command again.'; Finish 3 }
$cfg = $chk.config
$installId = $cfg.installId
# No edition given = the free COMMUNITY edition, said in one calm line. Trial / Pro install the same way with the Pro updater
# and no licence: the licence is added in PIM Manager > Settings > Licence after the installation (ConvertTo-PimInstallDeployArgs).
$autoCommunity = $false
if (-not $ans.editionGiven) { $cfg.edition = 'community'; $autoCommunity = $true }
$community = ("$($cfg.edition)" -eq 'community')
$licenceLater = -not $community
$licenceHint = 'sign in to PIM Manager and add your licence in Settings > Licence -- the Pro features switch on with it'
if ($autoCommunity) { Write-Host '    This installs PIM Manager Community (free). For Pro, run the same command with -Edition Pro; you can also add a licence later in PIM Manager > Settings > Licence.' -ForegroundColor Cyan }
$defaultStatePath = Get-PimInstallDefaultStatePath -InstallId $installId
if (-not "$StatePath".Trim()) { $StatePath = $defaultStatePath }
$state = Read-PimInstallState -StatePath $StatePath
$done = New-Object System.Collections.Generic.List[string]
if ($Resume -and $state.installId -eq $installId) { foreach ($c in $state.completed) { $done.Add("$c") | Out-Null } }
function Mark([string]$Id) { if (-not $done.Contains($Id)) { $done.Add($Id) | Out-Null }; Save-InstallState }
$fullPath = { param([string]$p) if (-not "$p".Trim()) { return '' }; try { $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath("$p".Trim()) } catch { "$p".Trim() } }
# The printed resume command: the installer by its full path (a new PowerShell window needs no function defined), the SAME
# choices this run was given, -Resume. Parameters only -- never a file to write. INSTALL-LINE-MINIMAL (owner 2026-11-03):
# the line carries only the tenant, the subscription, the region and the choices that differ from the default --
# Get-PimInstallLineArgs leaves out a default restated (the launcher passes -Edition Community / -UpdateRing 3), an empty
# value, a parameter of an option not chosen, and the state folder when it is the one the installation derives by itself.
$stateFull = & $fullPath $StatePath
$cliResume = Get-PimInstallLineArgs -Given $pimCli -StatePath $stateFull -DefaultStatePath (& $fullPath $defaultStatePath)
$resumeCmd = "& '$PSCommandPath'$cliResume -Resume"
$editionText = if ($community) { 'Community (no licence needed)' } else { "$((Get-Culture).TextInfo.ToTitleCase("$($cfg.edition)")) -- installed without a licence; afterwards $licenceHint" }
Emit 'config' 'ok' ("PIM Manager $($script:PimInstallVersion): installing into resource group '$($cfg.resourceGroup)' in $($cfg.location); edition: $editionText") -Detail @{ resourceGroup = $cfg.resourceGroup; location = $cfg.location; edition = $cfg.edition }
$names = Get-PimInstallNames -Config $cfg
# REQ 98.4 (b): the SQL firewall rule of THIS install (a single-tenant install; a managed tenant's build owns its own window
# and closes it in its last step). A record in the state file counts only when it names exactly this install's rule.
$hostRuleTarget = [ordered]@{ name = 'AllowSetupHost'; server = "$($names.sqlServer)"; resourceGroup = "$($names.resourceGroup)"; subscriptionId = "$($cfg.subscriptionId)" }
if ($state.installId -eq $installId -and (Test-PimInstallSetupHostRuleRecord -Record $state.setupHostRule -Target $hostRuleTarget)) { $pimInstallMem.hostRule = $state.setupHostRule }

# ================================================================== 1b. framework 8.13: the handed-over sign-in
# Each audience is checked on its own claims (Import-PimHandoffTokens, PIM-Rest.ps1): this installation's tenant, a signed-in
# USER (not an application), more than 5 minutes left. A token for ANOTHER tenant refuses the whole handoff and stops here
# (the bootstrap and the answers disagree about the tenant -- nothing is used and no browser opens). Any other refusal, or an
# audience that was not handed over, falls back to PIM's own browser sign-in for that audience only, when it is first needed.
# Only the reasons are ever printed or reported -- never token text.
# APP-IDENTITY INSTALL (owner via Invardia 2026-10-21, Install-Invardia -ViaSupportApp): inside a Connect-InvardiaSupport
# session the handoff carries the Invardia Support APP's tokens -- accepted for exactly that app of THIS tenant, never another.
$script:handoffAppId = ''
$isa = $global:InvardiaSupportState
# INSTALL-1 ALIGN (6): -ViaSupportApp makes the Support-app install explicit -- without a Connect-InvardiaSupport session for
# THIS tenant it stops here, before any sign-in or change. Without the switch nothing changes.
if ($ViaSupportApp -and -not ($isa -is [hashtable] -and "$($isa.TenantId)".Trim() -ieq "$($cfg.tenantId)".Trim())) {
    Emit 'preflight-signin' 'failed' "-ViaSupportApp: this PowerShell window has no Invardia Support session for tenant $($cfg.tenantId) -- nothing was changed" 'Connect the Invardia Support app for this tenant first, then run the command again:' 'Connect-InvardiaSupport.ps1 -Environment <handle>'
    Finish 2
}
if ($isa -is [hashtable] -and "$($isa.TenantId)".Trim() -ieq "$($cfg.tenantId)".Trim() -and "$($isa.AppId)" -match '^[0-9a-fA-F-]{36}$') { $script:handoffAppId = "$($isa.AppId)".Trim().ToLowerInvariant() }
$script:handoff = Import-PimHandoffTokens -Json $script:PimHandoffRaw -TenantId $cfg.tenantId -AllowedAppId $script:handoffAppId
$script:PimHandoffRaw = $null
$script:handoffBrowserFor = @()
if ($script:handoff.present) {
    if ($script:handoff.refused) {
        Emit 'signin' 'failed' "$($script:handoff.reason)" 'Start the installation again and sign in with an account of the tenant -TenantId names (or correct -TenantId):' ''
        Finish 2
    }
    foreach ($f in @($script:handoff.fallback)) {
        $script:handoffBrowserFor += "$($f.audience)"
        Write-Host "    the sign-in handed over for $($f.audience) is not used: $($f.reason) -- you sign in in the browser for it when it is needed" -ForegroundColor Yellow
    }
    foreach ($need in 'https://management.azure.com', 'https://graph.microsoft.com', 'https://database.windows.net') {
        if (-not $script:handoff.accepted.ContainsKey((Get-PimHandoffAudienceKey $need)) -and -not @($script:handoff.fallback | Where-Object { (Get-PimHandoffAudienceKey $_.audience) -eq (Get-PimHandoffAudienceKey $need) }).Count) {
            $script:handoffBrowserFor += $need
            Write-Host "    no sign-in was handed over for $need -- you sign in in the browser for it when it is needed" -ForegroundColor DarkGray
        }
    }
    if ($script:handoff.accepted.Count) { $global:PimHandoffTokens = @{ tenantId = "$($cfg.tenantId)".Trim().ToLowerInvariant(); tokens = $script:handoff.accepted } }
}

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
    # §100.41: a real install signs in over REST (Get-PimSignedInIdentity: the Support-app session, else the browser);
    # the az-shaped -Az seam (Get-PimInstallSignedInIdentity, _PimGuidedInstall.ps1) is for the offline tests only.
    $script:who = if ($azSeam) { Get-PimInstallSignedInIdentity -TenantId $cfg.tenantId -SubscriptionId $cfg.subscriptionId -Az $Az } else { Get-PimSignedInIdentity -TenantId $cfg.tenantId -SubscriptionId $cfg.subscriptionId }
    if (-not $script:who.ok) { return @{ state = 'failed'; message = $script:who.reason; actionText = 'Run the installation in a PowerShell window (a browser sign-in opens), or connect the Invardia Support app first:'; actionCommand = 'Connect-InvardiaSupport.ps1 -Environment <handle>' } }
    # 2026-10-06 (SI finding K): with no superAdmins named, the PERSON who installs becomes the Manager's first SuperAdmin.
    # The Invardia Support app is an application -- it must never be that admin. Refused before anything is written.
    # APP-IDENTITY INSTALL (owner via Invardia 2026-10-21): superAdmins / portalUsers come ONLY from the answers -- an
    # application is never "the signed-in admin". A bad ANSWER, so exit 3 (nothing was touched), with the line to add.
    if ("$($script:who.supportAppId)".Trim() -and -not @($cfg.superAdmins | Where-Object { "$_".Trim() }).Count) {
        $script:appNoAdmins = $true
        return @{ state = 'failed'; message = 'the installation runs as an application (the Invardia Support app), so it cannot make the installer the PIM Manager administrator -- name at least one person in superAdmins'; actionText = 'Name the administrator with -SuperAdmins, then start the installation again:'; actionCommand = '-SuperAdmins admin@contoso.com' }
    }
    @{ state = 'ok'; message = "signed in as $($script:who.userName)" }
}
if ($preflightFailed) { Finish $(if ($script:appNoAdmins) { 3 } else { 2 }) }
$pimInstallMem.signedIn = $true   # REQ 98.4 (b): from here a way out may close this install's own SQL firewall rule (Close-InstallHostRule)
# framework 8.13: ONE event says HOW the person signed in, so Invardia's tracked install can show it. Audience names and
# the source only -- never token content. "Through Invardia" = the Azure (ARM) sign-in the checks above used was handed over.
$hoAccepted = @(if ($script:handoff -and $script:handoff.accepted) { @($script:handoff.accepted.Keys) | Sort-Object })
if ($hoAccepted -contains (Get-PimHandoffAudienceKey 'https://management.azure.com')) {
    Emit 'signin' 'ok' $(if ("$($script:handoff.kind)" -eq 'app') { 'signed in once through Invardia (handoff) as the Invardia Support app' } else { 'signed in once through Invardia (handoff)' }) -Detail ([ordered]@{ source = 'handoff'; principal = $(if ("$($script:handoff.kind)" -eq 'app') { 'application' } else { 'user' }); handedOver = @($hoAccepted); browserFor = @($script:handoffBrowserFor) })
} elseif ("$($who.supportAppId)".Trim()) {
    Emit 'signin' 'ok' 'signed in as the Invardia Support app' -Detail ([ordered]@{ source = 'support-app'; handedOver = @($hoAccepted) })
} else {
    Emit 'signin' 'ok' 'signed in in the browser' -Detail ([ordered]@{ source = 'browser'; handedOver = @($hoAccepted) })
}

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
    # 2026-10-06 (install rehearsal): the Invardia Support app is an application -- there is no /me. Read ITS directory roles
    # and its Graph app permissions (the 'roles' claim of its own Graph token); the warning was false for it.
    $appRoles = @()
    if ("$($who.supportAppId)".Trim()) {
        $dir = Get-InstallRest "https://graph.microsoft.com/v1.0/servicePrincipals/$($who.objectId)/transitiveMemberOf/microsoft.graph.directoryRole?`$select=roleTemplateId" 'https://graph.microsoft.com'
        $gt = Az-Json @('account', 'get-access-token', '--subscription', $cfg.subscriptionId, '--resource', 'https://graph.microsoft.com')
        try {
            $seg = "$($gt.accessToken)".Split('.')[1].Replace('-', '+').Replace('_', '/'); $seg += '=' * ((4 - $seg.Length % 4) % 4)
            $appRoles = @((([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($seg))) | ConvertFrom-Json).roles)
        } catch { $appRoles = @() }
    } else {
        $dir = Get-InstallRest 'https://graph.microsoft.com/v1.0/me/transitiveMemberOf/microsoft.graph.directoryRole?$select=roleTemplateId' 'https://graph.microsoft.com'
    }
    $tpl = @(@($dir.value) | ForEach-Object { "$($_.roleTemplateId)" })
    $isApp = [bool]"$($who.supportAppId)".Trim()
    $v = Get-PimInstallRightsVerdict -AzureRoles $roles -DirectoryRoleTemplateIds $tpl -AppRoles $appRoles -IsApp:$isApp
    $script:rights = $v
    if (-not $v.azureOk) { return @{ state = 'failed'; message = $v.message; actionText = 'Ask a subscription Owner to grant you Owner (or Contributor + User Access Administrator) on this subscription -- Azure portal > Subscriptions > the subscription > Access control (IAM) > Add role assignment:'; actionCommand = "$($who.userName) -> Owner on /subscriptions/$($cfg.subscriptionId)" } }
    if (-not $v.entraOk) { return @{ state = 'warning'; message = $v.message } }
    @{ state = 'ok'; message = $(if ($isApp) { 'Owner-level rights on the subscription and every Microsoft Graph application permission the installation uses' } else { 'Owner-level rights on the subscription and an active directory admin role' }) }
}

Pre 'preflight-providers' {
    $need = 'Microsoft.App', 'Microsoft.ContainerRegistry', 'Microsoft.Sql', 'Microsoft.OperationalInsights', 'Microsoft.ManagedIdentity', 'Microsoft.Network'
    $missing = @($need | Where-Object { (Az-Text @('provider', 'show', '-n', $_, '--subscription', $cfg.subscriptionId, '--query', 'registrationState', '-o', 'tsv')) -ne 'Registered' })
    if (-not $missing.Count) { return @{ state = 'ok'; message = 'all required resource providers are registered' } }
    if ($script:rights -and $script:rights.azureOk) { return @{ state = 'ok'; message = "will be registered by the installation: $($missing -join ', ')" } }
    @{ state = 'failed'; message = "not registered: $($missing -join ', ')"; actionText = 'Ask a subscription Owner to register them -- Azure portal > Subscriptions > the subscription > Resource providers > select each > Register:'; actionCommand = ($missing -join ', ') }
}

Pre 'preflight-names' {
    $msgs = @()
    $grp = Az-Json @('group', 'show', '-n', $names.resourceGroup, '--subscription', $cfg.subscriptionId)
    if ($grp) { $msgs += "resource group '$($names.resourceGroup)' exists and is used" ; if ("$($grp.location)" -and "$($grp.location)" -ne $cfg.location) { $msgs += "(it is in $($grp.location); the new resources go to $($cfg.location))" } }
    $ours = if ($grp) { Az-Json @('sql', 'server', 'show', '-g', $names.resourceGroup, '-n', $names.sqlServer, '--subscription', $cfg.subscriptionId) } else { $null }
    if (-not $ours -and (& $ResolveHost $names.sqlFqdn)) { return @{ state = 'failed'; message = "the database server name '$($names.sqlServer)' is already taken in Azure -- run the command again with another -InstallId (a new installation id gives new names)" } }
    $acrFree = Az-Text @('acr', 'check-name', '-n', $names.acr, '--subscription', $cfg.subscriptionId, '--query', 'nameAvailable', '-o', 'tsv')
    if ($acrFree -eq 'false') {
        $acrOurs = if ($grp) { Az-Json @('acr', 'show', '-g', $names.resourceGroup, '-n', $names.acr, '--subscription', $cfg.subscriptionId) } else { $null }
        if (-not $acrOurs) { return @{ state = 'failed'; message = "the registry name '$($names.acr)' is already taken in Azure -- run the command again with another -InstallId" } }
    }
    $msgs += "names: $($names.sqlServer), $($names.acr), $($names.environment)"
    @{ state = 'ok'; message = ($msgs -join ' ') }
}

# PRIVATE NETWORK (INSTALL-1 item 5): a -PrivateNetwork install reads, before anything is created, the network it is given
# (-VnetId: there, same region, subnets usable / free), the hub's range (no overlap) and the central zones (there -- they are
# never created). Reads only; the verdict is Get-PimInstallNetworkVerdict (pure, _PimGuidedInstall.ps1). A public install
# has no such step.
if ($cfg.privateNetwork) {
    Write-Host "    network: PRIVATE -- PIM Manager has no public address (Container Apps environment internal, database over a private endpoint)" -ForegroundColor Cyan
    Pre 'preflight-network' {
        $armGet = { param([string]$Id, [string]$Api) if (-not "$Id".Trim()) { return $null }; Get-InstallRest "https://management.azure.com$("$Id".Trim())?api-version=$Api" 'https://management.azure.com/' }
        $vn = if ("$($cfg.vnetId)".Trim()) { & $armGet $cfg.vnetId '2023-09-01' } else { $null }
        $hb = if ("$($cfg.hubVnetId)".Trim()) { & $armGet $cfg.hubVnetId '2023-09-01' } else { $null }
        $zs = @{}
        if ("$($cfg.privateDnsZonesResourceGroupId)".Trim()) { foreach ($z in @(Get-PimInstallPrivateZoneNames)) { $zs[$z] = [bool](& $armGet "$($cfg.privateDnsZonesResourceGroupId)/providers/Microsoft.Network/privateDnsZones/$z" '2020-06-01') } }
        Get-PimInstallNetworkVerdict -Config $cfg -Vnet $vn -Hub $hb -Zones $zs
    }
}

# 100.62 THE CUSTOMER DECIDES THE REGION: no region list -- this step reads, for THIS subscription, whether every service PIM
# Manager creates is offered in the chosen region (ARM provider locations + Azure SQL's capabilities: region open, Standard S0),
# names exactly what is missing and suggests the nearest region that has all of it. Reads only; the step id is kept (the
# progress feed and Invardia's wizard know it).
Pre 'preflight-sql-region' {
    # REGION-ACCEPTS-NEW (framework installer rule 9): also an ARM deployment VALIDATE of the install's own resources (creates
    # nothing) -- a region can offer every service and still refuse NEW resources for this subscription. A policy refusal or a
    # 403 is a warning ("could not be checked"), never a stop.
    $rgPost = $HttpPost
    if (-not $rgPost -and -not $pimHttpSeamGiven -and -not $azSeam) {
        $rgPost = {
            param([string]$Url, [string]$Body)
            $t = Az-Json @('account', 'get-access-token', '--subscription', $cfg.subscriptionId, '--resource', 'https://management.azure.com/')
            if (-not "$($t.accessToken)") { return @{ StatusCode = 0; Content = 'no ARM token' } }
            # 5.1 and 7: a 4xx answer throws -- its status from the response, its body from ErrorDetails
            try {
                $r = Invoke-WebRequest -Method POST -Uri $Url -Headers @{ Authorization = "Bearer $($t.accessToken)" } -ContentType 'application/json' -Body $Body -TimeoutSec 120 -UseBasicParsing
                @{ StatusCode = [int]$r.StatusCode; Content = "$($r.Content)" }
            } catch {
                $resp = $_.Exception.Response
                @{ StatusCode = $(if ($resp) { [int]$resp.StatusCode } else { 0 }); Content = $(if ("$($_.ErrorDetails.Message)") { "$($_.ErrorDetails.Message)" } else { "$($_.Exception.Message)" }) }
            }
        }
    }
    $rgArgs = @{}
    if ($rgPost) {
        $rgNames = Get-PimInstallNames -Config $cfg
        $rgUrlPost = { param([string]$Path, [string]$Body) & $rgPost ("https://management.azure.com$Path") $Body }.GetNewClosure()
        $rgExists = $null -ne (Get-InstallRest "https://management.azure.com/subscriptions/$($cfg.subscriptionId)/resourcegroups/$($rgNames.resourceGroup)?api-version=2021-04-01" 'https://management.azure.com/')
        $rgIsApp = [bool]"$($who.supportAppId)".Trim()
        $rgArgs = @{ Post = $rgUrlPost; ProbeNames = $rgNames; ResourceGroup = "$($rgNames.resourceGroup)"; ResourceGroupExists = $rgExists; TenantId = "$($cfg.tenantId)"
                     AdminObjectId = $(if ($rgIsApp) { "$($who.supportAppId)" } else { "$($who.objectId)" }); AdminType = $(if ($rgIsApp) { 'Application' } else { 'User' }); PrivateNetwork = [bool]$cfg.privateNetwork }
    }
    $rv = Invoke-PimRegionPreflight -SubscriptionId $cfg.subscriptionId -Location $cfg.location -Get { param($u) Get-InstallRest $u 'https://management.azure.com/' } @rgArgs
    if (-not $rv.ok) {
        return @{ state = 'failed'; message = $rv.message; actionText = 'Choose another region with -Location, then start the installation again:'
                  actionCommand = $(if (-not $rv.suggestion) { '' } else { "-Location $($rv.suggestion)" }) }
    }
    if (@($rv.unknown).Count) { return @{ state = 'warning'; message = "$($rv.message) -- the deploy steps will tell" } }
    @{ state = 'ok'; message = $rv.message }
}

# REQ 98.4 (c) + (d) (install findings 2026-10-11): the PIM Manager administrators are checked HERE, before anything is
# created. (d) a sign-in name that is not in the tenant used to stop the sign-in step about an hour into the install;
# (c) administrators without a mailbox and no alert recipients used to fail the end-of-install check after everything was
# built. One Graph read per administrator (a $filter, so "not there" is an empty answer and never a guessed error); the
# person installing is looked up by object id (a guest's sign-in name differs from the name in the token). A read that
# fails is a WARNING, never a stop. The verdict is Get-PimInstallAdminVerdict (pure, _PimGuidedInstall.ps1).
Pre 'preflight-admins' {
    # An object id is looked up by id. A value that is neither an address nor an object id (the sign-in step also accepts a
    # GROUP name) is not a user this check can judge: it gets no filter and ends as "could not be checked", never a stop.
    $ask = @($cfg.superAdmins | ForEach-Object { "$_".Trim() } | Where-Object { $_ } | ForEach-Object {
        if ($_ -match '^[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}$') { @{ upn = $_; filter = "id eq '$_'"; byId = $true } }
        elseif ($_ -match '^[^\s@]+@[^\s@]+$') { @{ upn = $_; filter = "userPrincipalName eq '$($_.Replace("'", "''"))'" } }
        else { @{ upn = $_; filter = '' } } })
    if (-not $ask.Count -and "$($who.userName)".Trim() -and "$($who.objectId)".Trim() -and -not "$($who.supportAppId)".Trim()) { $ask = @(@{ upn = "$($who.userName)".Trim(); filter = "id eq '$("$($who.objectId)".Trim())'" }) }
    $admins = @(foreach ($a in $ask) {
        if (-not $a.filter) { @{ upn = $a.upn; found = $null; mail = '' }; continue }
        $r = Get-InstallRest('https://graph.microsoft.com/v1.0/users?$filter=' + [uri]::EscapeDataString($a.filter) + '&$select=id,userPrincipalName,mail') 'https://graph.microsoft.com'
        if ($null -eq $r -or -not $r.PSObject.Properties['value']) { @{ upn = $a.upn; found = $null; mail = '' } }
        else {
            $hit = @($r.value | Where-Object { $_ }) | Select-Object -First 1
            # an object id that is no USER may be a group or an app the sign-in step accepts by id: not judged here
            if (-not $hit -and $a.byId) { @{ upn = $a.upn; found = $null; mail = '' } }
            else { @{ upn = $a.upn; found = [bool]$hit; mail = "$($hit.mail)".Trim() } }
        }
    })
    $av = Get-PimInstallAdminVerdict -Admins $admins -AlertRecipients @($cfg.alertRecipients)
    # An installation that COMPLETED before (a re-run): its alert recipients may have been set in the PIM Manager since, and
    # the preflight cannot read the store -- then the missing mailbox is a reminder, and the end-of-install check decides.
    if ("$($av.kind)" -eq 'no-mailbox' -and $state.installId -eq $installId -and @($state.completed) -contains 'completed') {
        return @{ state = 'warning'; message = "$("$($av.message)" -replace '; nothing was created$', '') -- this installation completed before: check PIM Manager > Settings > Alerting > Recipients" }
    }
    $av
}
if ($preflightFailed) { Finish 2 }
if ($PreflightOnly) { Write-Host 'preflight passed -- nothing was changed (-PreflightOnly)' -ForegroundColor Green; Finish 0 }

# ================================================================== framework 12.7: -WhatIf = the checks above + this preview
# Everything after this point writes (Azure, Entra ID, SQL, the state file), so a preview stops HERE and only describes
# it. The deploy's own plan is read with Invoke-PimDeployAll in its plan-only mode (reads only).
if ($WhatIfPreference) {
    Write-Host ''
    Write-Host 'WHAT IF -- the checks passed. The installation WOULD now do this (nothing below is done under -WhatIf):' -ForegroundColor Cyan
    $wiArgs = @{}
    $wiDeploy = ConvertTo-PimInstallDeployArgs -Config $cfg -SignedInUpn $who.userName
    foreach ($k in @($wiDeploy.Keys)) { if ("$k" -ne 'Apply') { $wiArgs[$k] = $wiDeploy[$k] } }
    $wiArgs['WhatIf'] = $true
    Write-Host "  What if: deploy PIM Manager into resource group '$($names.resourceGroup)' ($($cfg.location)) -- the deploy's plan, read now:" -ForegroundColor Yellow
    try { $null = @(& $Deploy $wiArgs { param($ev) }) }
    catch { Write-Host "    the deploy plan could not be read: $($_.Exception.Message)" -ForegroundColor Yellow }
    if ($community) { Write-Host '  What if: no licence step -- the Community edition (the Core features, updates from the Community channel); a licence can be added later in PIM Manager > Settings > Licence' -ForegroundColor Yellow }
    else { Write-Host "  What if: no licence step -- the $($cfg.edition) installation is deployed without a licence (the Pro updater included); afterwards $licenceHint" -ForegroundColor Yellow }
    if ("$($cfg.supportAppId)".Trim()) {
        Write-Host "  What if: give the Invardia Support app $($cfg.supportAppId) '$($cfg.supportAccess)' access (Grant-PimSupportAccess.ps1: at 'asbuilt' ONLY start the as-built job + read its PDF container; at 'troubleshoot' also a contained SQL user with db_datareader + VIEW DEFINITION; at 'setup' also ownership of PIM's own app registrations and groups; at EVERY level its standing access to the PIM database: membership of the SQL admin group and its own database user with the database owner role, which stays after the installation until you switch the Support app off)" -ForegroundColor Yellow
    }
    if ($cfg.privateNetwork) { Write-Host '  What if: private network -- when this resource group already holds a PUBLIC PIM Manager, it is first converted to the private network (Convert-PimToPrivate.ps1 underneath, data kept); SQL and the registry get NO public access and no firewall rule; the network hand-off is printed at the end' -ForegroundColor Yellow }
    Write-Host '  What if: run the end-of-install check (Confirm-PimInstall.ps1). It REPAIRS what it can, so it is not run under -WhatIf -- run without -WhatIf to apply.' -ForegroundColor Yellow
    Write-Host 'WHAT IF -- nothing was changed.' -ForegroundColor Green
    Finish 0
}

# 2026-10-11: this run IS the install (or its resume) -- the ring gate lets the install deploy the release it fetched even
# when a previous attempt already created the updater. Step processes inherit it; Finish removes it.
$env:PIM_GUIDED_INSTALL_RUN = '1'

# ================================================================== 3. deploy
# APP-IDENTITY INSTALL (2026-10-21): an application is never the default SuperAdmin / portal user -- only the answers name them.
$deployArgs = ConvertTo-PimInstallDeployArgs -Config $cfg -SignedInUpn $(if ("$($who.supportAppId)".Trim()) { '' } else { $who.userName })
# ================================================================== 3a. PUBLIC -> PRIVATE (INSTALL-1 item 5, Invardia 2026-11-02)
# "the SAME two lines + -PrivateNetwork on an existing PUBLIC PIM install converts it": the install reads its own Container
# Apps environment; when it is EXTERNAL, Convert-PimToPrivate.ps1 runs underneath with the mapped values (the customer never
# runs it by hand), then the deploy below continues on the private shape (idempotent). A stop where the network team must
# act (its exit 10) ends this run with the -Resume command; the conversion then continues where it stopped.
if ($cfg.privateNetwork -and -not $done.Contains('convert-private')) {
    $cvEnv = Get-InstallRest "https://management.azure.com/subscriptions/$($cfg.subscriptionId)/resourceGroups/$($names.resourceGroup)/providers/Microsoft.App/managedEnvironments/$($names.environment)?api-version=2024-03-01" 'https://management.azure.com/'
    $cvd = Get-PimInstallConvertDecision -Config $cfg -Environment $cvEnv
    if ($cvd.refuse) { Emit 'prereq' 'failed' "$($cvd.reason) -- nothing was changed" 'Run the same command without -VnetId.'; Finish 2 }
    if ($cvd.convert -or $done.Contains('convert-started')) {
        Emit 'prereq' 'started' "$(if ($cvd.reason) { $cvd.reason } else { 'continuing the conversion to the private network' })"
        $cvArgs = ConvertTo-PimInstallConvertArgs -Config $cfg -Names $names -PortalUsers @($deployArgs['EasyAuthAllowedPrincipals']) -AllMembers:([bool]$cfg.allowAllMembers) -Resume:($done.Contains('convert-started'))
        if (-not $ConvertToPrivate) { $ConvertToPrivate = { param([hashtable]$A) $global:LASTEXITCODE = 0; & (Join-Path $here 'Convert-PimToPrivate.ps1') @A | Out-Host; [int]$LASTEXITCODE } }
        Mark 'convert-started'
        $cvCode = 1
        try { $cvCode = [int](@(& $ConvertToPrivate ([hashtable]$cvArgs)) | Select-Object -Last 1) } catch { Write-Host "    the conversion stopped: $($_.Exception.Message)" -ForegroundColor Red; $cvCode = 1 }
        if ($cvCode -eq 10) { Emit 'prereq' 'failed' 'the conversion to the private network stopped where your network team must act (printed above: the hub side of the peering, or the check from inside the network)' 'When that is done, run the same command again with -Resume:' $resumeCmd; Finish 1 }
        if ($cvCode -ne 0) { Emit 'prereq' 'failed' "the conversion to the private network did not complete (exit $cvCode) -- its rollback is printed above; the data is kept" 'Fix the cause above, then resume the installation:' $resumeCmd; Finish 1 }
        Mark 'convert-private'
        Write-Host '    converted to the private network (Convert-PimToPrivate.ps1) -- the installation continues on the private shape' -ForegroundColor Cyan
    }
}
# REQ 98.4 (b) (install finding 2026-10-11): a run that DIED left 'AllowSetupHost' on the SQL server, the next run took it
# for somebody else's and the end-of-install check failed with a fix only possible in the portal. Now THIS install owns its
# window: before the deploy starts it reads the rule and -- when it is not there -- writes into the state file that the rule
# opened from here on is its own (before anything is created, so a run that dies still leaves the record). The deploy is
# told the caller owns the window (-KeepSetupHostRule: it opens / moves the rule and leaves it open for the licence step
# and the check), and the install closes it: the end-of-install check removes it and reads it back, and every way out
# (Finish, the finally below) closes what is left. A rule that was there BEFORE this install has no record: never removed.
# PRIVATE STAYS PRIVATE (INSTALL-1 item 5): a private install opens NO firewall window -- its SQL has no public endpoint and
# its SQL steps run from inside the network.
if ($SetupHostRule -and -not $cfg.privateNetwork) {
    $ruleNow = $null
    try { $ruleNow = "$(& $SetupHostRule 'get' $hostRuleTarget)".Trim() } catch { $ruleNow = $null; Write-Verbose "setup-host rule read failed: $($_.Exception.Message)" }
    $hostPlan = Get-PimInstallSetupHostRulePlan -Recorded $pimInstallMem.hostRule -Target $hostRuleTarget -RuleIp $ruleNow
    if ($hostPlan.record) {
        $pimInstallMem.hostRule = [ordered]@{ name = $hostRuleTarget.name; server = $hostRuleTarget.server; resourceGroup = $hostRuleTarget.resourceGroup; subscriptionId = $hostRuleTarget.subscriptionId; openedUtc = [datetime]::UtcNow.ToString('o') }
        Save-InstallState
    }
    Write-Host "    database firewall rule 'AllowSetupHost': $($hostPlan.reason)" -ForegroundColor DarkGray
    if ($hostPlan.owned) { $deployArgs['KeepSetupHostRule'] = $true }
}
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
# ONE-LINE-INSTALL (owner 2026-11-02: "license will come automatically when env is deployed. then i login and add"): the
# install never registers a licence. Community needs none; a trial / Pro environment is deployed WITHOUT one, and the
# administrator adds it in PIM Manager > Settings > Licence -- then the Pro features switch on and the engine claims the
# install key itself (the Manager queues that claim when the licence is stored). A warning, never a failed install.
# INSTALL-1 GAP (2026-11-02, owner: "make sure anyone can make a trial without me having to approve it"): a trial / Pro
# install records the edition it was installed as (pim.Settings 'InstallEdition'), so the engine's licence-request job knows
# it is meant to be Pro and asks Invardia for its licence on its first tick (Invardia auto-approves a tenant on the 60-day
# trial). Community records nothing and never asks. Every run, -Resume too (idempotent, read back); never a failed install.
$editionNote = ''
if (-not $community) {
    if (-not $StoreSql -and -not $azSeam) {
        $StoreSql = { param([string]$Sql)
            $Io = New-PimInstallSigninFrontIo -SubscriptionId $cfg.subscriptionId -ResourceGroup $names.resourceGroup -TenantId $cfg.tenantId -AcrName $names.acr `
                    -SqlServerFqdn $names.sqlFqdn -SqlDatabase $names.sqlDatabase -SetupDir $here
            & $Io.Sql $Sql }
    }
    if ($StoreSql) {
        $edR = Set-PimInstallEditionSetting -Edition "$($cfg.edition)" -Sql $StoreSql
        Write-Host "    install edition: $($edR.reason)" -ForegroundColor $(if ($edR.ok) { 'DarkGray' } else { 'Yellow' })
        if (-not $edR.ok) { $editionNote = " (the install edition was not recorded, so the licence is not requested by itself: $($edR.reason) -- run the installation again with -Resume)" }
    }
}
if ($community) { Emit 'licence' 'skipped' 'the Community edition has no licence -- a licence can be added later in PIM Manager > Settings > Licence' }
else { Emit 'licence' 'warning' "no licence yet: $licenceHint$editionNote" 'After the installation:' 'PIM Manager > Settings > Licence' }

# PIM REQUIREMENTS 100.116 (framework 4.1b): a named Support app also gets its STANDING database access here -- member of
# the SQL admin group + its own database user (from its client id) in db_owner -- while this install can still reach the
# database (the setup firewall rule is closed by the check below). Grant-PimSupportAccess does it at every level; the
# check's line 'support-sql' then proves it. No Support app named: nothing is created, and this one line says so.
if (-not "$($cfg.supportAppId)".Trim()) { Emit 'support-app-access' 'skipped' 'no Invardia Support app was named -- no support access and no database user for Invardia support were created' }
elseif ($done.Contains('support-app-access')) { Emit 'support-app-access' 'skipped' 'already granted (resume)' }
else {
    Emit 'support-app-access' 'started'
    # INSTALL-LINE-MINIMAL: -Level only when it is not Grant-PimSupportAccess's own default (troubleshoot)
    $grantCmd = "Grant-PimSupportAccess -AppId $($cfg.supportAppId)$(if ("$($cfg.supportAccess)" -ne 'troubleshoot') { " -Level $($cfg.supportAccess)" }) -TenantId $($cfg.tenantId) -SubscriptionId $($cfg.subscriptionId) -ResourceGroup $($names.resourceGroup) -SqlServer $($names.sqlFqdn)"
    if (-not $GrantSupport) { $GrantSupport = { param([hashtable]$A) & (Join-Path $here 'Grant-PimSupportAccess.ps1') @A | Out-Host; @{ ok = (-not $LASTEXITCODE) } } }
    $gr = $null
    try { $gr = & $GrantSupport @{ AppId = $cfg.supportAppId; Level = $cfg.supportAccess; TenantId = $cfg.tenantId; SubscriptionId = $cfg.subscriptionId; ResourceGroup = $names.resourceGroup; SqlServer = $names.sqlFqdn } } catch { $gr = $null }
    if ($gr -and $gr.ok) { Emit 'support-app-access' 'ok' "the Invardia Support app has '$($cfg.supportAccess)' access, and standing access to the PIM database: it is a member of the SQL admin group and has its own database user with the database owner role. This stays after the installation; you end it by switching the Invardia Support app off in Microsoft Entra ID"; Mark 'support-app-access' }
    else { Emit 'support-app-access' 'warning' 'the Invardia Support app could not be given its access with your rights' 'Ask a Privileged Role Administrator to run:' $grantCmd }
}

# ================================================================== 4a. GUIDED-INSTALL-FRONT: the sign-in front
# Owner 2026-10-21 (trial end-to-end: "no quick dirty" / "biz depends on it works"): a NEW install ends on the shared sign-in
# front -- the install's own Key Vault wraps its keys, its state is in the PIM database, it passes an access token to the
# PIM Manager, no client secret is used -- never on Easy Auth. Five steps (signin-front-vault / -state / -app / -image /
# signin-front), each its own event; a resume skips the ones done. Here, BEFORE the end-of-install check: the database is
# still reachable from this machine (the check closes the setup window). A failed move rolls itself back to Easy Auth
# (the PIM Manager is never without a sign-in) and the install stops with the resume command.
# Under the LEGACY offline -Az seam with no -SigninFront seam there is no Azure to talk to: nothing is run (tests only).
if ($SigninFront -or -not $azSeam) {
    $sfIds = @(Get-PimInstallSigninFrontStepIds)
    $sfDone = @($sfIds | Where-Object { $done.Contains($_) })
    $sfOnStep = { param($Id, $State, $Message) Emit $Id $State $Message; if ("$State" -in 'ok', 'skipped') { Mark $Id } }
    $sfArgs = @{ SubscriptionId = $cfg.subscriptionId; ResourceGroup = $names.resourceGroup; TenantId = $cfg.tenantId; Location = $cfg.location
                 ManagerApp = $names.managerApp; AcrName = $names.acr; SqlDatabase = $names.sqlDatabase; KeyVaultName = $names.keyVault
                 RepoRoot = (Split-Path -Parent (Split-Path -Parent $sol)); SolutionRoot = $sol; UpdateJob = $names.updateJob; Done = @($sfDone)
                 StateFile = (Join-Path $StatePath 'signin-front-rollback.json')
                 PrivateNetwork = [bool]$cfg.privateNetwork }   # rule 11: a private install's vault is private (made / recovered / found)
    if (-not $SigninFront) {
        $SigninFront = { param([hashtable]$A, [scriptblock]$OnStep)
            $io = New-PimInstallSigninFrontIo -SubscriptionId $A.SubscriptionId -ResourceGroup $A.ResourceGroup -TenantId $A.TenantId -AcrName $A.AcrName `
                    -SqlServerFqdn $names.sqlFqdn -SqlDatabase $A.SqlDatabase -SetupDir $here -AgentPoolName "$($deployArgs['AcrAgentPoolName'])"   # INSTALL-1 item 5: '' on a public install
            Invoke-PimInstallSigninFront @A -OnStep $OnStep -Io $io }
    }
    $sfR = $null
    try { $sfR = & $SigninFront $sfArgs $sfOnStep } catch { $sfR = @{ ok = $false; failedStep = 'signin-front'; reason = "$($_.Exception.Message)" } }
    if (-not $sfR -or -not [bool]$sfR.ok) {
        $sfStep = if ($sfR -and "$($sfR.failedStep)".Trim()) { "$($sfR.failedStep)" } else { 'signin-front' }
        if (-not @($events | Where-Object { "$($_.step.id)" -eq $sfStep -and $_.state -eq 'failed' }).Count) { Emit $sfStep 'failed' "$(if ($sfR) { $sfR.reason } else { 'the sign-in front step did not answer' })" }
        Emit 'verify-install' 'failed' "the PIM Manager is not on the sign-in front yet ($sfStep): $(if ($sfR) { $sfR.reason })" 'The PIM Manager still requires a sign-in (Easy Auth stays on until the front works). Fix the cause above, then resume the installation:' $resumeCmd
        Finish 1
    }
    if ("$($sfR.keyVaultId)".Trim()) { $pimInstallMem['keyVaultId'] = "$($sfR.keyVaultId)".Trim() }
}

# ================================================================== 4b. INSTALL-HARDEN-1: the END-OF-INSTALL VERIFY
# Owner 2026-10-08: "make sure that customers requesting a trial version will not have these issues". Every result the
# install must leave is read back -- SuperAdmins, updater + ring, licence + install key, mail sender + both sending
# identities in scope, alert recipients, the engine's Graph rights and its Reader at the tenant root, sign-in, the SQL
# window -- what is missing is repaired where it can be, and the install is NOT 'completed' while a required line fails.
# Always run (also on -Resume): it is a check, and re-running it is how a repaired line turns green.
Emit 'verify-install' 'started'
$mailEv = @($events | Where-Object { "$($_.step.id)" -eq 'mailsender' -and "$($_.state)" -eq 'warning' }) | Select-Object -Last 1
$vArgs = @{ Role = 'Single'; TenantId = $cfg.tenantId; SubscriptionId = $cfg.subscriptionId; ResourceGroup = $names.resourceGroup; SqlServerFqdn = $names.sqlFqdn
            SqlDatabase = $names.sqlDatabase; ManagerApp = $names.managerApp; EnvName = $names.environment; AcrName = $names.acr
            TickJobName = $names.tickJob; UpdateJobName = $names.updateJob   # CR5: the names this install was made with
            SuperAdmins = @("$($deployArgs['ManagerSuperAdmins'])" -split '[,;]' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
            AlertRecipients = @($cfg.alertRecipients); LicenceExpected = $false; LicenceLater = $licenceLater; SetupHostRuleOwner = 'this'; UseSignedInAccount = $true; ResumeCommand = $resumeCmd
            OutFile = (Join-Path $StatePath 'verify-install.json') }
if ($deployArgs.Contains('UpdateRing')) { $vArgs['UpdateRing'] = [int]$deployArgs['UpdateRing'] }
if ($deployArgs.Contains('UpdateSource')) { $vArgs['UpdateSource'] = "$($deployArgs['UpdateSource'])" }
if ($cfg.engineAzureRootUserAccessAdmin) { $vArgs['EngineAzureRootUserAccessAdmin'] = $true }
if ($mailEv) { $vArgs['MailDeferredReason'] = "$($mailEv.message)" }
if ("$($cfg.supportAppId)".Trim()) { $vArgs['SupportAppId'] = "$($cfg.supportAppId)".Trim() }   # 100.116: the 'support-sql' line
# REQ 98.4 (b): the rule this install opened is closed BY the check (after its store reads; removed and read back), so its
# 'SQL setup host rule' line is a fact and never fails for this install's own window. Without a record the check only reads.
if ($pimInstallMem.hostRule) { $vArgs['CloseSetupHostRule'] = $true }
if (-not $VerifyInstall) { $VerifyInstall = { param([hashtable]$A) @(& (Join-Path $here 'Confirm-PimInstall.ps1') @A) | Where-Object { $_ -and $_.PSObject.Properties['done'] } | Select-Object -Last 1 } }
$vr = $null
try { $vr = & $VerifyInstall $vArgs } catch { $vr = $null; Write-Verbose "verify-install threw: $($_.Exception.Message)" }
# REQ 100.77 (b): each line's fix = its command lines only; the script's doc page rides in its own docUrl (the event's action
# takes the same split in New-PimInstallEvent).
$vRows = @(@($vr.rows) | Where-Object { $_ } | ForEach-Object {
    $sp = Split-PimInstallDocLines -Text "$($_.fix)"
    $row = [ordered]@{ id = "$($_.id)"; title = "$($_.title)"; state = "$($_.state)"; detail = "$($_.detail)"; fix = "$($sp.text)" }
    if ($sp.docUrl) { $row['docUrl'] = $sp.docUrl }
    $row })
if (-not $vr) { Emit 'verify-install' 'failed' 'the end-of-install check could not run' 'Fix the cause above, then resume the installation:' $resumeCmd; Finish 1 }
if (-not [bool]$vr.done) {
    $bad = @($vRows | Where-Object { $_.state -eq 'failed' })
    $first = @($bad | Select-Object -First 1)
    Emit 'verify-install' 'failed' "$($vr.sentence)" "Fix: $(if ($first) { "$($first[0].title) -- " })the command below, then resume the installation:" $(if ($first -and "$($first[0].fix)".Trim()) { "$($first[0].fix)" + $(if ($first[0].Contains('docUrl')) { "`nWhat does this script do: $($first[0]['docUrl'])" } else { '' }) } else { $resumeCmd }) -Detail ([ordered]@{ lines = $vRows })
    Finish 1
}
if (@($vr.warnings).Count) { Emit 'verify-install' 'warning' "$($vr.sentence)" -Detail ([ordered]@{ lines = $vRows }) }
else { Emit 'verify-install' 'ok' "$($vr.sentence)" -Detail ([ordered]@{ lines = $vRows }) }

# PIM 100.156 B (framework 12.23 P5): the installer was a member of the SQL admin group only for the length of the install
# (the deploy keeps it -- -SkipInstallVerify -- because the licence, support and verify steps above still needed SQL). Now
# it leaves the group again, read back; the standing member is the Invardia Support app. Never fatal, never an event of its
# own (the install is complete either way); not for a Support-app session, which IS that standing member.
if ("$($script:who.objectId)".Trim() -and -not "$($script:who.supportAppId)".Trim()) {
    $relR = $null
    try {
        if ($ReleaseSqlAdmin) { $relR = & $ReleaseSqlAdmin "$($script:who.objectId)" "$($names.sqlServer)" "$($names.resourceGroup)" }
        elseif (-not $azSeam) {
            if (-not (Get-Command Invoke-PimSqlAdminGroupSetupRelease -ErrorAction SilentlyContinue)) { . (Join-Path $here '_PimSqlAdminGroup.ps1') }
            $invR = New-PimSqlAdminGroupInvokers -SubscriptionId $cfg.subscriptionId -TenantId $cfg.tenantId
            $relR = Invoke-PimSqlAdminGroupSetupRelease -Graph $invR.Graph -Arm $invR.Arm -SubscriptionId $cfg.subscriptionId -SqlResourceGroup $names.resourceGroup `
                        -SqlServerName $names.sqlServer -MemberObjectId "$($script:who.objectId)" -Label 'the signed-in administrator'
        }
    } catch { $relR = @{ ok = $false; reason = "$($_.Exception.Message)" } }
    if ($relR) { Write-Host "    SQL admin group: $($relR.reason)" -ForegroundColor $(if ($relR.ok) { 'DarkGray' } else { 'Yellow' }) }
}

Emit 'health-check' 'started'
$healthy = ("$($summary.status)" -eq 'success') -and [bool]$summary.healthy
$warnings = @($events | Where-Object { $_.state -eq 'warning' } | ForEach-Object { $_.step.id } | Select-Object -Unique)
if ($healthy -and -not $warnings.Count) { Emit 'health-check' 'ok' 'the PIM Manager is deployed and healthy' }
elseif ($healthy) { Emit 'health-check' 'warning' "deployed and healthy; still waiting for: $($warnings -join ', ')" }
else { Emit 'health-check' 'warning' 'deployed, but the health check could not verify every part -- open the PIM Manager and check the status page' }

$tickPid = Az-Text @('containerapp', 'job', 'show', '-g', $names.resourceGroup, '-n', $names.tickJob, '--subscription', $cfg.subscriptionId, '--query', 'identity.principalId', '-o', 'tsv')
$fqdn = Az-Text @('containerapp', 'show', '-g', $names.resourceGroup, '-n', $names.managerApp, '--subscription', $cfg.subscriptionId, '--query', 'properties.configuration.ingress.fqdn', '-o', 'tsv')
$verFile = Join-Path $sol 'VERSION'
$outputs = [ordered]@{
    subscriptionId          = $cfg.subscriptionId
    resourceGroup           = $names.resourceGroup
    sqlServerId             = (Az-Text @('sql', 'server', 'show', '-g', $names.resourceGroup, '-n', $names.sqlServer, '--subscription', $cfg.subscriptionId, '--query', 'id', '-o', 'tsv'))
    logAnalyticsWorkspaceId = (Az-Text @('monitor', 'log-analytics', 'workspace', 'show', '-g', $names.resourceGroup, '-n', $names.logAnalytics, '--subscription', $cfg.subscriptionId, '--query', 'id', '-o', 'tsv'))
    keyVaultId              = $(if ($pimInstallMem -and $pimInstallMem.Contains('keyVaultId')) { "$($pimInstallMem['keyVaultId'])" } else { '' })   # GUIDED-INSTALL-FRONT: the install's own vault
    runtimeIdentity         = 'mi-container'
    runtimeIdentityClientId = $(if ($tickPid) { "$((Get-InstallRest "https://graph.microsoft.com/v1.0/servicePrincipals/$tickPid`?`$select=appId" 'https://graph.microsoft.com').appId)" } else { '' })   # never `az ad`: it follows the default account's tenant
    version                 = $(if (Test-Path -LiteralPath $verFile) { "$(Get-Content -Raw -LiteralPath $verFile)".Trim() } else { '' })
    portalUrl               = $(if ($fqdn) { "https://$fqdn" } else { '' })
}
Mark 'completed'
# the end-of-install summary: a Pro / trial environment says what to do next, in the completed line and on the screen
$doneMsg = $(if ($outputs.portalUrl) { "open the PIM Manager: $($outputs.portalUrl)" } else { 'installation complete' })
if ($licenceLater) { $doneMsg += " -- next: $licenceHint" }
# PRIVATE NETWORK (INSTALL-1 item 5, EPS DESIGN §2b): the network hand-off -- peering, DNS for the PIM Manager and the
# database, where later scripts run -- on the screen, in the completed event and in network-hand-off.txt in the state folder
# (named "network notes" in code: the word handoff is reserved for the sign-in tokens, which are never written -- Test-PimInstallHandoff D2)
$netNotes = @(Get-PimInstallNetworkHandoff -Config $cfg -Names $names -PortalFqdn $fqdn)
$doneDetail = $null
if ($netNotes.Count) {
    $doneMsg += ' -- next: your network team makes it reachable (network hand-off below)'
    $doneDetail = [ordered]@{}
    $doneDetail['networkHandoff'] = @($netNotes)
    try { Set-Content -LiteralPath (Join-Path $StatePath 'network-hand-off.txt') -Value $netNotes -Encoding utf8 } catch { Write-Verbose "network notes file: $($_.Exception.Message)" }
}
Emit 'completed' 'completed' $doneMsg -Outputs $outputs -Detail $doneDetail
if ($netNotes.Count) {
    Write-Host '    Network hand-off (also in network-hand-off.txt in the state folder):' -ForegroundColor Cyan
    foreach ($hl in $netNotes) { Write-Host "      - $hl" -ForegroundColor Cyan }
}
if ($licenceLater) { Write-Host "    Next: $licenceHint. PIM Manager then registers itself with Invardia for its updates." -ForegroundColor Cyan }
Finish 0
} finally {
    # REQ 98.4 (b): a way out that did not pass Finish (a throw, an interrupted run) still closes this install's own SQL
    # firewall rule -- while the handed-over sign-in below is still in memory. Nothing to do when Finish already closed it.
    if ($pimInstallMem -and $pimInstallMem.hostRule -and (Get-Command Close-InstallHostRule -ErrorAction SilentlyContinue)) { try { Close-InstallHostRule } catch { Write-Verbose "setup-host rule close failed: $($_.Exception.Message)" } }
    # framework 8.13: the handed-over tokens never outlive this run -- the bootstrap runs this script in ITS session, so a
    # global left behind would sit in the caller's memory after the install returns.
    $global:PimHandoffTokens = $null; $script:handoff = $null; $script:PimHandoffRaw = $null
    Stop-PimScriptRun -Script 'Install-PimManager'   # framework 12.7: "Log written: <path>" on every exit
}
