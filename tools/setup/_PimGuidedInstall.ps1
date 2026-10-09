#Requires -Version 5.1
<#
.SYNOPSIS
  §95.2 -- the PURE parts of the guided install (Install-PimManager.ps1), offline-tested in tests/Test-PimGuidedInstall.ps1.

.DESCRIPTION
  The contract is Invardia's GUIDED-INSTALL §4.2-4.4 (the bootstrap calls ONE command, Install-PimManager):
    config.json  = the wizard's answers, keyed as in tools/setup/install-parameters.json, plus installId
    events       = @{ installId; step = @{ id; title }; state; message; action = @{ text; command }; detail; outputs }
                   state: started | ok | warning | failed | skipped | completed
    exit codes   = 0 succeeded (warnings allowed) | 1 a step failed | 2 preflight failed | 3 bad config
  A step that needs a higher role than the installer holds ends as 'warning' with action.command for the right person;
  the install continues. Only what nothing can work around is 'failed'.
#>

$script:PimInstallGuid = '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$'

# The stable step ids (the status page and support tickets refer to them) and their titles in customer language.
# Order = run order. DeployAll's 'appreg' step is never shown: a guided install runs on managed identities only.
# 🔴 INSTALL-FIX-EVIDA (REQUIREMENTS 100.25 item 3, 2026-10-09): the functions below read the catalog through
# Get-PimInstallStepCatalog, NEVER as $script:PimInstallSteps. Install-PimManager hands its -OnStep scriptblock to
# Invoke-PimDeployAll.ps1 -- a CHILD script, where $script: is the deploy's own script scope and this catalog does not
# exist: ConvertTo-PimInstallStepEvent threw on $null.Contains(), the deploy's Send-PimDeployStepEvent swallowed it
# (Write-Verbose), and not one deploy step reached the Reporter (a production install sat on 'preflight' at Invardia for
# an hour while it deployed). A function is found through the caller chain wherever the scriptblock runs.
function Get-PimInstallStepCatalog { return [ordered]@{
    'config'               = 'Check your answers'
    'preflight-signin'     = 'Your sign-in'
    'preflight-target'     = 'Tenant and subscription'
    'preflight-rights'     = 'Your Azure and Entra rights'
    'preflight-providers'  = 'Azure resource providers'
    'preflight-names'      = 'Resource names'
    'preflight-sql-region' = 'Azure SQL in the chosen region'
    'enroll'               = 'Link to your Invardia account'
    'prereq'             = 'Network, registry, identity and database'
    'image'                = 'Container image'
    'infra'                = 'Container Apps environment and apps'
    'sqlaccess'            = 'Database access'
    'schema'               = 'Database schema'
    'mailsender'           = 'Notification mailbox'
    'features'             = 'Feature settings'
    'easyauth'             = 'Sign-in for the PIM Manager'
    'code'                 = 'Roll out the application'
    'updater'              = 'Updates'
    'access'               = 'PIM Manager access'
    'alerting'             = 'Alert recipients'
    'verify'               = 'Deployment health check'
    'licence'              = 'Your licence'
    'support-app-access'   = 'Invardia support access'
    'verify-install'       = 'End-of-install check'
    'health-check'         = 'Final health check'
    'completed'            = 'Installation complete'
} }
# kept for readers that enumerate the ids in the scope that loaded this file (tests, Get-PimInstallParameters callers)
$script:PimInstallSteps = Get-PimInstallStepCatalog

function Get-PimInstallStepTitle([string]$Id) {
    $cat = Get-PimInstallStepCatalog
    if ($cat.Contains($Id)) { return $cat[$Id] }
    return $Id
}

function New-PimInstallEvent {
    <# PURE. One reporter event in the contract shape. Never carries a secret (callers pass customer-language text). #>
    param([Parameter(Mandatory)][string]$StepId, [Parameter(Mandatory)][ValidateSet('started', 'ok', 'warning', 'failed', 'skipped', 'waiting', 'completed')][string]$State,
          [string]$Message = '', [string]$ActionText = '', [string]$ActionCommand = '', [System.Collections.IDictionary]$Detail, [System.Collections.IDictionary]$Outputs, [string]$InstallId = '',
          # a managed-tenant install reports the managed-tenant build's own steps, with that build's titles
          [string]$Title = '')
    $e = [ordered]@{ installId = $InstallId; step = [ordered]@{ id = $StepId; title = $(if ("$Title".Trim()) { "$Title".Trim() } else { (Get-PimInstallStepTitle $StepId) }) }; state = $State; message = $Message }
    if ("$ActionText".Trim() -or "$ActionCommand".Trim()) { $e['action'] = [ordered]@{ text = $ActionText; command = $ActionCommand } }
    if ($Detail) { $e['detail'] = $Detail }
    if ($Outputs) { $e['outputs'] = $Outputs }
    return $e
}

function Get-PimInstallToken {
    <# PURE. A short, stable, lower-case name token from the install id (6 hex chars of its SHA-256). #>
    param([Parameter(Mandatory)][string]$InstallId)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { $h = $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes("$InstallId".Trim().ToLowerInvariant())) } finally { $sha.Dispose() }
    return (-join ($h[0..2] | ForEach-Object { $_.ToString('x2') }))
}

function Test-PimInstallConfig {
    <#
      PURE. Validate the wizard's answers (an object from config.json). Returns @{ ok; errors[]; config (normalised) }.
      Refuses: a missing / malformed required value, an unknown enum value, internal exposure (the guided install is
      external only -- Invardia refuses it too), an MSP role (managing / managed tenants are not a guided install yet),
      a bad CIDR / UPN / e-mail.
    #>
    # -HasEnrollmentKey: the key came on the command line (Install-PimManager -EnrollmentKey), not in the answers.
    param([AllowNull()][object]$Config, [switch]$HasEnrollmentKey)
    $err = New-Object System.Collections.Generic.List[string]
    if ($null -eq $Config) { return @{ ok = $false; errors = @('config.json could not be read as JSON'); config = $null } }
    $get = { param($k) $p = $Config.PSObject.Properties[$k]; if ($p) { $p.Value } else { $null } }
    $c = [ordered]@{}
    foreach ($k in 'installId', 'tenantId', 'subscriptionId') {
        $v = "$(& $get $k)".Trim(); $c[$k] = $v
        if (-not $v) { $err.Add("$k is required") }
    }
    foreach ($k in 'tenantId', 'subscriptionId') { if ($c[$k] -and $c[$k] -notmatch $script:PimInstallGuid) { $err.Add("$k must be a GUID") } }
    if ($c.installId -and $c.installId -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{2,63}$') { $err.Add('installId must be 3-64 letters, digits, dot, dash or underscore') }
    $loc = "$(& $get 'location')".Trim(); if (-not $loc) { $loc = 'swedencentral' }
    if ($loc -notmatch '^[a-z0-9]{3,30}$') { $err.Add("location '$loc' is not an Azure region name") }
    $c.location = $loc
    $rg = "$(& $get 'resourceGroup')".Trim(); if (-not $rg) { $rg = 'rg-pim' }
    if ($rg -notmatch '^[A-Za-z0-9._()-]{1,89}[A-Za-z0-9_()-]$') { $err.Add("resourceGroup '$rg' is not a valid resource group name") }
    $c.resourceGroup = $rg
    $ed = "$(& $get 'edition')".Trim().ToLowerInvariant(); if (-not $ed) { $ed = 'trial' }
    if ($ed -notin 'trial', 'pro') { $err.Add("edition must be trial or pro (got '$ed')") }
    $c.edition = $ed
    $ex = "$(& $get 'exposure')".Trim().ToLowerInvariant(); if (-not $ex) { $ex = 'external' }
    if ($ex -ne 'external') { $err.Add("exposure '$ex' is not supported by the guided install -- it installs the external (public, signed-in) shape; an internal install is a consultant-led setup") }
    $c.exposure = $ex
    $cidr = '^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})/(\d{1,2})$'
    $vn = "$(& $get 'vnetAddressPrefix')".Trim(); if (-not $vn) { $vn = '10.220.0.0/22' }
    $sn = "$(& $get 'subnetAddressPrefix')".Trim(); if (-not $sn) { $sn = '10.220.0.0/23' }
    foreach ($pair in @(@('vnetAddressPrefix', $vn), @('subnetAddressPrefix', $sn))) {
        $m = [regex]::Match($pair[1], $cidr)
        if (-not $m.Success -or @(1..4 | Where-Object { [int]$m.Groups[$_].Value -gt 255 }).Count -or [int]$m.Groups[5].Value -gt 32) { $err.Add("$($pair[0]) '$($pair[1])' is not an IPv4 CIDR") }
    }
    $snm = [regex]::Match($sn, $cidr)
    if ($snm.Success -and [int]$snm.Groups[5].Value -gt 23) { $err.Add("subnetAddressPrefix '$sn' is smaller than /23 -- Container Apps needs a /23 or larger") }
    $vnm = [regex]::Match($vn, $cidr)
    if ($snm.Success -and $vnm.Success -and [int]$snm.Groups[5].Value -lt [int]$vnm.Groups[5].Value) { $err.Add("subnetAddressPrefix '$sn' is larger than the VNet '$vn'") }
    $c.vnetAddressPrefix = $vn; $c.subnetAddressPrefix = $sn
    $role = "$(& $get 'mspRole')".Trim().ToLowerInvariant(); if (-not $role) { $role = 'single' }
    if ($role -notin 'single', 'managing', 'managed') { $err.Add("mspRole must be single, managing or managed (got '$role')") }
    elseif ($role -eq 'managing') { $err.Add("mspRole 'managing': a managing tenant is not a guided install yet -- install as single and contact support for the multi-tenant setup") }
    # framework 8.6 (owner 2026-10-08): a MANAGED tenant installs itself with the enrollment key its managing company got from
    # Invardia (checked below: 'managed' needs 'enrollmentKey'). It then runs the managed-tenant build (Invoke-PimMspBuild).
    $c.mspRole = $role
    if ($role -eq 'managed') {
        $ap = @(@(& $get 'adminPrefixes') | ForEach-Object { "$_" -split '[,;]' } | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
        if (-not $ap.Count) { $err.Add('adminPrefixes is required for a managed tenant (the prefix of the admin accounts your managing company manages here, e.g. Admin-)') }
        foreach ($p in $ap) { if ($p -notmatch '^[A-Za-z0-9._-]{1,20}$') { $err.Add("adminPrefixes entry '$p' is not a name prefix") } }
        $c.adminPrefixes = @($ap)
        $sr = "$(& $get 'slaveRing')".Trim(); if (-not $sr) { $sr = '2' }
        if ($sr -notin '0', '1', '2') { $err.Add("slaveRing must be 0, 1 or 2 (got '$sr')") }
        $c.slaveRing = $sr
    }
    $upn = '^[^@\s,;]+@[^@\s,;]+\.[^@\s,;]+$'
    foreach ($k in 'portalUsers', 'superAdmins') {
        $list = @(@(& $get $k) | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
        foreach ($u in $list) { if ($u -notmatch $upn) { $err.Add("$k entry '$u' is not a user principal name") } }
        $c[$k] = @($list)
    }
    $c.allowAllMembers = [bool](& $get 'allowAllMembers')
    # §97 (owner 2026-10-08): opt-in only -- Reader at the tenant root is always granted, User Access Administrator only on request.
    $c.engineAzureRootUserAccessAdmin = [bool](& $get 'engineAzureRootUserAccessAdmin')
    $ms = "$(& $get 'mailSender')".Trim()
    if ($ms -and $ms -notmatch $upn) { $err.Add("mailSender '$ms' is not an e-mail address") }
    $c.mailSender = $ms
    # INSTALL-HARDEN-1 item 5 (owner 2026-10-08): who gets the alerts. Invardia's wizard pre-fills it (and superAdmins) with
    # the requester's address; empty = the SuperAdmins' mailboxes. A stored list is never overwritten by an install.
    $ar = @(@(& $get 'alertRecipients') | ForEach-Object { "$_" -split '[,;]' } | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
    foreach ($a in $ar) { if ($a -notmatch $upn) { $err.Add("alertRecipients entry '$a' is not an e-mail address") } }
    $c.alertRecipients = @($ar)
    $sa = "$(& $get 'supportAppId')".Trim()
    if ($sa -and $sa -notmatch $script:PimInstallGuid) { $err.Add('supportAppId must be a GUID (the Invardia Support app''s client id)') }
    $c.supportAppId = $sa
    $lvl = "$(& $get 'supportAccess')".Trim().ToLowerInvariant(); if (-not $lvl) { $lvl = 'troubleshoot' }
    if ($lvl -notin 'troubleshoot', 'setup') { $err.Add("supportAccess must be troubleshoot or setup (got '$lvl')") }
    $c.supportAccess = $lvl
    # §95.4 (2026-10-06): the update ring a PRO install follows -- 2 = design partners, 3 = broad (default). Ring 0/1 are
    # Invardia's own and never a customer's. Not on the wizard page: an operator-run production install sets it in config.
    $ur = "$(& $get 'updateRing')".Trim(); if (-not $ur) { $ur = '3' }
    if ($ur -notin '2', '3') { $err.Add("updateRing must be 2 (design partners) or 3 (broad) (got '$ur')") }
    $c.updateRing = $ur
    # Invardia's bootstrap writes the install key it issued (2026-10-06): stored with the licence, so the engine never claims (409).
    $ik = "$(& $get 'installKey')".Trim()
    if ($ik -and $ik -notmatch '^inv-[A-Za-z0-9_-]{20,100}$') { $err.Add('installKey is not an Invardia install key (inv-...)') }
    $c.installKey = $ik
    # framework 8.6 "SINGLE-TENANT enrollment too" (owner 2026-10-08): an Invardia ENROLLMENT KEY (ek-...) instead of a
    # licence file -- the install claims this tenant at Invardia and gets the licence + install key from it. A bearer secret:
    # it is returned BESIDE the normalised config (never inside it, so nothing that shows or saves the config can carry it),
    # and no error text ever contains it.
    $ek = "$(& $get 'enrollmentKey')".Trim()
    if ($ek -and $ek -cnotmatch '^ek-[A-Za-z0-9_-]{43}$') { $err.Add('enrollmentKey is not an Invardia enrollment key (ek- followed by 43 letters, digits, - or _)') }
    # ONE CLAIMANT PER INSTALL (Invardia 2026-10-08): every claim issues a new install key and kills the previous one. When the
    # answers already carry installKey, Invardia's bootstrap (Install-Invardia -EnrollmentKey) has claimed: the enrollment key
    # is then informational only -- never sent, never returned (enrollmentKeyIgnored says so).
    $ekIgnored = $false
    if ($ek -and $ik) { $ek = ''; $ekIgnored = $true }
    # A MANAGED tenant: the claim's managing block. Either this install claims (enrollmentKey, the claim returns it) or the
    # bootstrap claimed and hands it over as 'managing': { bundleStorage, container, signingKeyIds[], tenantId? }.
    $mg = & $get 'managing'
    if ($mg) {
        $ms = "$($mg.bundleStorage)".Trim().ToLowerInvariant()
        $mc = "$($mg.container)".Trim().ToLowerInvariant(); if (-not $mc) { $mc = 'baselines' }
        $mp = @(@($mg.signingKeyIds) | Where-Object { $null -ne $_ -and "$_".Trim() } | ForEach-Object { "$_".Trim() })
        $mt = "$($mg.tenantId)".Trim()
        if ($ms -notmatch '^[a-z0-9]{3,24}$') { $err.Add('managing.bundleStorage is not a storage account name') }
        if ($mc -notmatch '^[a-z0-9](?!.*--)[a-z0-9-]{1,61}[a-z0-9]$') { $err.Add('managing.container is not a container name') }
        if (-not $mp.Count -or @($mp | Where-Object { $_ -cnotmatch '^[A-Za-z0-9_-]{43}$' }).Count) { $err.Add('managing.signingKeyIds must name the managing tenant''s signing key id(s) (43 characters each)') }
        if ($mt -and $mt -notmatch $script:PimInstallGuid) { $err.Add('managing.tenantId must be a GUID') }
        $mo = [ordered]@{ bundleStorage = $ms; container = $mc; signingKeyIds = @($mp) }; if ($mt) { $mo['tenantId'] = $mt.ToLowerInvariant() }
        $c.managing = [pscustomobject]$mo
    }
    if ($role -eq 'managed' -and -not $ek -and -not $ik -and -not $HasEnrollmentKey) { $err.Add("mspRole 'managed' needs enrollmentKey (or, from Invardia's installer, installKey + managing): a managed tenant is linked to its managing company by the enrollment key that company got from Invardia") }
    if ($role -eq 'managed' -and $ik -and -not $mg) { $err.Add("mspRole 'managed' with installKey needs 'managing' (the claim's managing block: bundleStorage, container, signingKeyIds) -- Invardia's installer claimed, so it hands it over") }
    if ($mg -and $role -ne 'managed') { $err.Add("'managing' belongs to a managed tenant (mspRole managed)") }
    return @{ ok = ($err.Count -eq 0); errors = @($err); config = [pscustomobject]$c; enrollmentKey = $ek; enrollmentKeyIgnored = $ekIgnored }
}

function Remove-PimInstallConfigEnrollmentKey {
    <#
      framework 8.6: once the enrolled licence is registered, the enrollment key is taken OUT of config.json (the wizard's
      answers on disk), so no copy of the bearer secret is left behind -- a resume no longer needs it (the licence step is
      done). Every other answer is kept as it was. Returns $true when a key was removed.
    #>
    param([Parameter(Mandatory)][string]$ConfigPath)
    if (-not (Test-Path -LiteralPath $ConfigPath)) { return $false }
    $o = $null; try { $o = Get-Content -Raw -LiteralPath $ConfigPath | ConvertFrom-Json } catch { return $false }
    if (-not $o -or -not $o.PSObject.Properties['enrollmentKey']) { return $false }
    $o.PSObject.Properties.Remove('enrollmentKey')
    [IO.File]::WriteAllText($ConfigPath, ($o | ConvertTo-Json -Depth 8), (New-Object Text.UTF8Encoding($false)))
    return $true
}

function Get-PimInstallNames {
    <# PURE. The resource names of a guided install (framework §5.5: purpose words; globally unique names carry the token). #>
    param([Parameter(Mandatory)][object]$Config)
    $t = Get-PimInstallToken -InstallId $Config.installId
    return [pscustomobject]@{
        token = $t; resourceGroup = $Config.resourceGroup; vnet = 'vnet-pim'; environment = 'cae-pim'; logAnalytics = 'log-pim'
        acr = "acrpim$t"; sqlServer = "sql-pim-$t"; sqlFqdn = "sql-pim-$t.database.windows.net"; sqlDatabase = 'PimPlatform'; managerApp = 'ca-pim-manager'
    }
}

function ConvertTo-PimInstallDeployArgs {
    <#
      PURE. The Invoke-PimDeployAll parameters for one guided install. Fixed by design: the signed-in account (Cloud Shell
      -- never a secret), no deploy application (-SkipAppReg: the runtime is managed identity only), scenario S2 (the
      public release, updated with Update-PimCommunity.ps1; the licence switches the Pro features on), -Apply.
    #>
    # -LicencePath / -InstallKeyPath: Invardia's bootstrap claimed -- its licence file and the install key in a FILE (a path,
    # never the key) go to the build's licence step, and nothing claims again.
    param([Parameter(Mandatory)][object]$Config, [string]$SignedInUpn = '', [string]$LicencePath = '', [string]$InstallKeyPath = '')
    $n = Get-PimInstallNames -Config $Config
    $admins = @($Config.superAdmins); if (-not $admins.Count -and "$SignedInUpn".Trim()) { $admins = @("$SignedInUpn".Trim()) }
    $portal = @($Config.portalUsers); if (-not $portal.Count -and -not $Config.allowAllMembers) { $portal = @($admins) }
    $a = [ordered]@{
        Scenario = 'S2'; TenantId = $Config.tenantId; SubscriptionId = $Config.subscriptionId; Location = $Config.location
        Exposure = 'external'; ResourceGroup = $n.resourceGroup; VnetName = $n.vnet; VnetResourceGroup = $n.resourceGroup
        EnvName = $n.environment; AcrName = $n.acr; LogAnalyticsWorkspaceName = $n.logAnalytics; LogAnalyticsResourceGroup = $n.resourceGroup
        SqlServerFqdn = $n.sqlFqdn; SqlDatabase = $n.sqlDatabase
        SqlConnectionString = "Server=tcp:$($n.sqlFqdn),1433;Database=$($n.sqlDatabase);Encrypt=True;TrustServerCertificate=False;Connection Timeout=30"
        PrereqToken = $n.token; PrereqVnetAddressPrefix = $Config.vnetAddressPrefix; PrereqSubnetAddressPrefix = $Config.subnetAddressPrefix
        ManagerSuperAdmins = (@($admins) -join ','); UseSignedInAccount = $true; SkipAppReg = $true; Apply = $true
    }
    if (@($portal).Count) { $a['EasyAuthAllowedPrincipals'] = @($portal) }
    if ($Config.allowAllMembers) { $a['EasyAuthAllowAllTenantUsers'] = $true }
    if ($Config.engineAzureRootUserAccessAdmin) { $a['EngineAzureRootUserAccessAdmin'] = $true }   # §97 opt-in
    if ("$($Config.mailSender)".Trim()) { $a['MailSender'] = "$($Config.mailSender)".Trim() }
    # INSTALL-HARDEN-1: the alert recipients (else the SuperAdmins' mailboxes); the deploy's own end-of-install verify is
    # skipped -- Install-PimManager runs it after the licence and the support access; and the deploy never posts to Invardia
    # itself (the bootstrap's -Reporter does), so its tracking token is explicitly empty.
    $ar = @($Config.alertRecipients | Where-Object { "$_".Trim() })
    if ($ar.Count) { $a['AlertRecipients'] = @($ar) }
    $a['SkipInstallVerify'] = $true
    $a['InvardiaInstallToken'] = ''
    # 2026-10-06 (install rehearsal): a PRO install deployed as S2 with no feed got NO updater. Pro updates arrive signed,
    # through Invardia, on this install's ring; the engine claims the install key once the licence is registered.
    # Trials too (Invardia 2026-10-06: a trial licence claims an install key and pulls updates like Pro until it expires; a
    # customer who buys keeps the same install).
    if ("$($Config.edition)" -in 'pro', 'trial') {
        $a['UpdateSource'] = 'Invardia'
        $a['UpdateRing'] = [int]$(if ("$($Config.updateRing)".Trim()) { "$($Config.updateRing)".Trim() } else { '3' })
    }
    return $a
}

function ConvertTo-PimInstallMspSlaveConfig {
    <#
      PURE. framework 8.6 -- a MANAGED tenant's guided install = the managed-tenant build (Invoke-PimMspBuild -Role Slave,
      signed-in, with the enrollment key): this is its config, made from the wizard's answers and the guided install's
      names. master{} only from a handed-over 'managing' block (else the claim returns it), NO deployIdentity (signed-in), NO secret (the key goes to the build
      as -EnrollmentKey, never into this file). Pro updates from Invardia on updateRing; the pull job on slaveRing.
    #>
    # -LicencePath / -InstallKeyPath: Invardia's bootstrap claimed -- its licence file and the install key in a FILE (a path,
    # never the key) go to the build's licence step, and nothing claims again.
    param([Parameter(Mandatory)][object]$Config, [string]$SignedInUpn = '', [string]$LicencePath = '', [string]$InstallKeyPath = '')
    $n = Get-PimInstallNames -Config $Config
    $admins = @($Config.superAdmins); if (-not $admins.Count -and "$SignedInUpn".Trim()) { $admins = @("$SignedInUpn".Trim()) }
    $portal = @($Config.portalUsers); if (-not $portal.Count -and -not $Config.allowAllMembers) { $portal = @($admins) }
    $c = [ordered]@{
        role = 'Slave'; tenantId = $Config.tenantId; subscriptionId = $Config.subscriptionId; resourceGroup = $n.resourceGroup; location = $Config.location
        token = $n.token; sqlServerName = $n.sqlServer; sqlDatabase = $n.sqlDatabase; acrName = $n.acr; envName = $n.environment; logAnalyticsName = $n.logAnalytics
        managerApp = $n.managerApp; exposure = 'external'; managerSuperAdmins = (@($admins) -join ',')
        updater = [ordered]@{ ring = [int]$(if ("$($Config.updateRing)".Trim()) { "$($Config.updateRing)".Trim() } else { '3' }); source = 'invardia' }
        network = [ordered]@{ vnetName = $n.vnet; vnetAddressPrefix = $Config.vnetAddressPrefix; subnetAddressPrefix = $Config.subnetAddressPrefix }
        adminPrefixes = @($Config.adminPrefixes); slaveRing = [int]$(if ("$($Config.slaveRing)".Trim()) { "$($Config.slaveRing)".Trim() } else { '2' })
        easyAuth = [ordered]@{ allowedPrincipals = @($portal); allowAllTenantUsers = [bool]$Config.allowAllMembers }
    }
    if (@($Config.alertRecipients).Count) { $c['alertRecipients'] = @($Config.alertRecipients) }
    if ($Config.engineAzureRootUserAccessAdmin) { $c['engineAzure'] = [ordered]@{ rootUserAccessAdmin = $true } }
    if ("$($Config.supportAppId)".Trim()) { $c['support'] = [ordered]@{ appId = "$($Config.supportAppId)".Trim(); access = "$($Config.supportAccess)" } }
    if ($Config.PSObject.Properties['managing'] -and $Config.managing) {
        $m = [ordered]@{ storageAccount = "$($Config.managing.bundleStorage)"; container = "$($Config.managing.container)"; signingKeyIds = @($Config.managing.signingKeyIds) }
        if ("$($Config.managing.tenantId)".Trim()) { $m['tenantId'] = "$($Config.managing.tenantId)".Trim() }
        $c['master'] = [pscustomobject]$m
    }
    if ("$LicencePath".Trim()) { $l = [ordered]@{ path = "$LicencePath".Trim() }; if ("$InstallKeyPath".Trim()) { $l['installKeyPath'] = "$InstallKeyPath".Trim() }; $c['licence'] = [pscustomobject]$l }
    return [pscustomobject]$c
}

function ConvertTo-PimInstallStepEvent {
    <#
      PURE. One Invoke-PimDeployAll -OnStep event -> the guided-install event, or $null when it is not shown (appreg).
      A failed step carries the deploy's own detail as the message; the customer action is to fix that and -Resume.
    #>
    param([Parameter(Mandatory)][object]$DeployEvent, [string]$InstallId = '', [string]$ResumeCommand = '')
    $key = "$($DeployEvent.key)"
    # INSTALL-HARDEN-1: the deploy's own 'verify-install' is skipped here -- the guided install runs ITS verify after the
    # licence and the support access (its own 'verify-install' event); a 'skipped' one from the deploy would only confuse.
    if (($key -in @('appreg', 'verify-install')) -or -not (Get-PimInstallStepCatalog).Contains($key)) { return $null }
    $state = "$($DeployEvent.state)"; $detail = "$($DeployEvent.detail)".Trim()
    if ($detail.Length -gt 400) { $detail = $detail.Substring(0, 400) + ' ...' }
    switch ($state) {
        'failed'  { return (New-PimInstallEvent -StepId $key -State failed -Message $(if ($detail) { $detail } else { 'the step failed' }) -ActionText 'Fix the cause above, then resume the installation:' -ActionCommand $ResumeCommand -InstallId $InstallId) }
        'warning' { return (New-PimInstallEvent -StepId $key -State warning -Message $detail -InstallId $InstallId) }
        default   { return (New-PimInstallEvent -StepId $key -State $state -Message $detail -InstallId $InstallId) }
    }
}

function Get-PimInstallRightsVerdict {
    <#
      PURE. Azure role names the signed-in user holds on the subscription (or above) + Entra directory role template ids.
      Returns @{ azureOk; entraOk; message; action }. Azure: Owner, or Contributor + (User Access Administrator | Role
      Based Access Control Administrator) -- without it nothing can be built (failed). Entra: Privileged Role
      Administrator or Global Administrator -- without it the install still completes; the directory steps end as
      warnings with the command for that person.
    #>
    param([string[]]$AzureRoles = @(), [string[]]$DirectoryRoleTemplateIds = @(),
          # 2026-10-06 (install rehearsal): the Invardia Support app is an APPLICATION -- its Graph app permissions (the
          # token's 'roles') do what a person's directory role does. Empty for a person.
          [string[]]$AppRoles = @())
    $r = @($AzureRoles | ForEach-Object { "$_".Trim().ToLowerInvariant() })
    $azureOk = ($r -contains 'owner') -or (($r -contains 'contributor') -and (($r -contains 'user access administrator') -or ($r -contains 'role based access control administrator')))
    $pra = 'e8611ab8-c189-46e8-94e1-60213ab1f814'; $ga = '62e90394-69f5-4237-9190-012177145e10'
    $ids = @($DirectoryRoleTemplateIds | ForEach-Object { "$_".Trim().ToLowerInvariant() })
    $entraOk = ($ids -contains $pra) -or ($ids -contains $ga)
    # The app permissions that carry the three directory steps: add the SQL admin group's members (a role-assignable
    # group) and grant the identities their Graph app roles, and consent the Manager's sign-in.
    $ar = @($AppRoles | ForEach-Object { "$_".Trim() })
    if (-not $entraOk -and $ar.Count) {
        $entraOk = (@('RoleManagement.ReadWrite.Directory', 'AppRoleAssignment.ReadWrite.All', 'DelegatedPermissionGrant.ReadWrite.All' | Where-Object { $ar -notcontains $_ }).Count -eq 0)
        if (-not $entraOk) { return @{ azureOk = $azureOk; entraOk = $false; message = ((@($(if (-not $azureOk) { 'the Invardia Support app needs Owner (or Contributor + User Access Administrator) on the subscription' })) + @("the Invardia Support app lacks the Graph application permission(s) $((@('RoleManagement.ReadWrite.Directory', 'AppRoleAssignment.ReadWrite.All', 'DelegatedPermissionGrant.ReadWrite.All' | Where-Object { $ar -notcontains $_ })) -join ', ') -- the SQL admin group, the Graph permissions and the sign-in consent will end as hand-off actions")) | Where-Object { $_ }) -join '; ' } }
    }
    $msg = @()
    if (-not $azureOk) { $msg += 'you need Owner (or Contributor + User Access Administrator) on the subscription' }
    if (-not $entraOk) { $msg += 'you are not an ACTIVE Privileged Role Administrator or Global Administrator -- the SQL admin group, the Graph permissions and the sign-in consent will end as hand-off actions (activate the role in PIM first if you have it)' }
    return @{ azureOk = $azureOk; entraOk = $entraOk; message = ($msg -join '; ') }
}

function Read-PimInstallState {
    <# The state file (state.json in -StatePath): @{ installId; completed[]; updatedUtc }. Missing or unreadable = empty. #>
    param([Parameter(Mandatory)][string]$StatePath)
    $f = Join-Path $StatePath 'state.json'
    if (Test-Path -LiteralPath $f) { try { $s = Get-Content -Raw -LiteralPath $f | ConvertFrom-Json; return [pscustomobject]@{ installId = "$($s.installId)"; completed = @($s.completed | Where-Object { $_ }); updatedUtc = "$($s.updatedUtc)" } } catch { } }
    return [pscustomobject]@{ installId = ''; completed = @(); updatedUtc = '' }
}

function Save-PimInstallState {
    param([Parameter(Mandatory)][string]$StatePath, [Parameter(Mandatory)][string]$InstallId, [string[]]$Completed = @())
    if (-not (Test-Path -LiteralPath $StatePath)) { New-Item -ItemType Directory -Force -Path $StatePath | Out-Null }
    $doc = [ordered]@{ schema = 1; installId = $InstallId; completed = @($Completed | Select-Object -Unique); updatedUtc = [datetime]::UtcNow.ToString('o') }
    Set-Content -LiteralPath (Join-Path $StatePath 'state.json') -Value ($doc | ConvertTo-Json -Depth 4) -Encoding utf8
}
