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
# 100.62: the customer decides the region -- the config step checks only that it is a plausible region name (Test-PimSetupRegion);
# Install-PimManager's preflight checks every service is offered there (Invoke-PimRegionPreflight) before anything is created.
. (Join-Path $PSScriptRoot '_PimRegions.ps1')
# CR5 step 2 (PIM 100.149): the name sets (today's / new) and the setup switch -- pure, no side effects.
. (Join-Path $PSScriptRoot '..\..\engine\_shared\PIM-InstallNames.ps1')

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
    'signin'               = 'How you signed in'
    'preflight-target'     = 'Tenant and subscription'
    'preflight-rights'     = 'Your Azure and Entra rights'
    'preflight-providers'  = 'Azure resource providers'
    'preflight-names'      = 'Resource names'
    'preflight-sql-region' = 'Azure services in the chosen region'
    'preflight-admins'     = 'PIM Manager administrators'
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
    # GUIDED-INSTALL-FRONT (2026-10-21): the PIM Manager ends on the sign-in front, never on Easy Auth
    'signin-front-vault'   = 'Key Vault for the sign-in'
    'signin-front-state'   = 'Sign-in state in the database'
    'signin-front-app'     = 'Sign-in application scope'
    'signin-front-image'   = 'Sign-in front image'
    'signin-front'         = 'Sign-in front for the PIM Manager'
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

function Split-PimInstallDocLines {
    <#
      PURE. REQ 100.77 (b): a fix text from the install check (Confirm-PimInstall adds "What does this script do: <url>" under
      each command block for the CONSOLE) -> @{ text = the same text WITHOUT those lines; docUrl = the first of their urls
      that is an https://invardia.com/docs/ page, else '' }. Invardia accepts only that origin, so anything else is dropped.
    #>
    param([AllowNull()][AllowEmptyString()][string]$Text)
    $t = "$Text"; $url = ''
    if (-not $t) { return @{ text = $t; docUrl = '' } }
    $nl = if ($t.Contains("`r`n")) { "`r`n" } else { "`n" }
    $keep = foreach ($l in ($t -split "\r?\n")) {
        $m = [regex]::Match($l, '^\s*What does this script do:\s*(?<u>\S+)\s*$')
        if ($m.Success) { if (-not $url -and $m.Groups['u'].Value -match '^https://invardia\.com/docs/') { $url = $m.Groups['u'].Value }; continue }
        $l
    }
    return @{ text = (@($keep) -join $nl); docUrl = $url }
}

function New-PimInstallEvent {
    <# PURE. One reporter event in the contract shape. Never carries a secret (callers pass customer-language text). #>
    param([Parameter(Mandatory)][string]$StepId, [Parameter(Mandatory)][ValidateSet('started', 'ok', 'warning', 'failed', 'skipped', 'waiting', 'completed')][string]$State,
          [string]$Message = '', [string]$ActionText = '', [string]$ActionCommand = '', [System.Collections.IDictionary]$Detail, [System.Collections.IDictionary]$Outputs, [string]$InstallId = '',
          # a managed-tenant install reports the managed-tenant build's own steps, with that build's titles
          [string]$Title = '')
    $e = [ordered]@{ installId = $InstallId; step = [ordered]@{ id = $StepId; title = $(if ("$Title".Trim()) { "$Title".Trim() } else { (Get-PimInstallStepTitle $StepId) }) }; state = $State; message = $Message }
    if ("$ActionText".Trim() -or "$ActionCommand".Trim()) {
        # REQ 100.77 (b), agreed with Invardia 2026-10-11: action.command = the command lines ONLY; the script's doc page is
        # its own optional field action.docUrl (Invardia renders it as a link under the copy box and refuses a doc line
        # inside a shown block).
        $sp = Split-PimInstallDocLines -Text $ActionCommand
        $e['action'] = [ordered]@{ text = $ActionText; command = $sp.text }
        if ($sp.docUrl) { $e['action']['docUrl'] = $sp.docUrl }
    }
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
    # 100.62: ANY Azure region (the customer decides). "Sweden Central" is accepted as swedencentral; only an empty or
    # malformed name is refused here (exit 3). Whether every service is offered there is the preflight's live check.
    $why = Test-PimSetupRegion -Location $loc
    if ($why) { $err.Add("location: $why") } else { $loc = ConvertTo-PimRegionKey $loc }
    $c.location = $loc
    $rg = "$(& $get 'resourceGroup')".Trim(); if (-not $rg) { $rg = 'rg-pim' }
    if ($rg -notmatch '^[A-Za-z0-9._()-]{1,89}[A-Za-z0-9_()-]$') { $err.Add("resourceGroup '$rg' is not a valid resource group name") }
    $c.resourceGroup = $rg
    # INSTALL-SAMPLES (owner 2026-10-29): 'community' = the free edition, installed without a licence or an enrollment key
    # (Install-PimManager -Edition Community, or chosen by it when neither is given). Empty stays 'trial' (the wizard's files).
    $ed = "$(& $get 'edition')".Trim().ToLowerInvariant(); if (-not $ed) { $ed = 'trial' }
    if ($ed -notin 'community', 'trial', 'pro') { $err.Add("edition must be community, trial or pro (got '$ed')") }
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
    # owner 2026-10-28: "community does not have msp support, only pro" -- a managed tenant is a Pro install.
    if ($role -eq 'managed' -and $ed -eq 'community') { $err.Add("a managed tenant (mspRole managed) is PIM Manager Pro, not Community -- install it with the enrollment key its managing company got from Invardia") }
    if ($role -eq 'managed') {
        $ap = @(@(& $get 'adminPrefixes') | ForEach-Object { "$_" -split '[,;]' } | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
        # OPTIONAL since the owner 2026-10-10 ("remove the admin pattern question"): the prefixes are REPORT-ONLY since 2.4.412
        # and the pull job prefers the tenant's own AdminAccountPatterns setting. Absent = accepted; a given entry is still checked.
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
    if ($lvl -notin 'troubleshoot', 'setup', 'asbuilt') { $err.Add("supportAccess must be troubleshoot, setup or asbuilt (got '$lvl')") }   # 100.61: asbuilt = only the as-built job + its container
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
    # CR5 step 2 (PIM 100.149): optional, NOT a wizard question (Invardia's contract is unchanged) -- an operator / Invardia
    # may set it in config.json; carried only when given, so an install without it is exactly as before.
    $nn = & $get 'newInstallNames'
    if ($null -ne $nn -and "$nn".Trim()) {
        if ("$nn".Trim() -notmatch '^(?i)(true|false|1|0|yes|no|on|off)$') { $err.Add('newInstallNames must be true or false') }
        else { $c.newInstallNames = [bool]("$nn".Trim() -match '^(?i)(true|1|yes|on)$') }
    }
    # GUIDED-INSTALL-FRONT (2026-10-21): the install's own Key Vault (the sign-in front's key). Optional, not a wizard question --
    # the customer's own naming when given (hybrid naming rule: every name settable); else 'kv-pim-<token>'. Carried only when given.
    $kvn = "$(& $get 'keyVaultName')".Trim()
    if ($kvn) {
        if ($kvn -notmatch '^[A-Za-z][A-Za-z0-9-]{1,22}[A-Za-z0-9]$' -or $kvn -match '--') { $err.Add("keyVaultName '$kvn' is not a valid Key Vault name (3-24 letters, digits and dashes; starts with a letter; no '--')") }
        else { $c.keyVaultName = $kvn.ToLowerInvariant() }
    }
    return @{ ok = ($err.Count -eq 0); errors = @($err); config = [pscustomobject]$c; enrollmentKey = $ek; enrollmentKeyIgnored = $ekIgnored }
}

function Get-PimInstallDerivedId {
    <#
      PURE. INSTALL-SAMPLES (owner 2026-10-29): the installation id of an install started with PARAMETERS only (no wizard
      answers file): 'pim-' + 12 hex characters of the SHA-256 of tenant | subscription | resource group (lower case). The
      same three answers give the same id -- so the same resource names and the same state folder, which is what -Resume
      needs -- and another resource group in the same subscription gives another id (other globally unique names).
    #>
    param([Parameter(Mandatory)][string]$TenantId, [Parameter(Mandatory)][string]$SubscriptionId, [string]$ResourceGroup = 'rg-pim')
    $rg = if ("$ResourceGroup".Trim()) { "$ResourceGroup".Trim() } else { 'rg-pim' }
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { $h = $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes(("{0}|{1}|{2}" -f "$TenantId".Trim(), "$SubscriptionId".Trim(), $rg).ToLowerInvariant())) } finally { $sha.Dispose() }
    return ('pim-' + (-join ($h[0..5] | ForEach-Object { $_.ToString('x2') })))
}

function ConvertTo-PimInstallAnswers {
    <#
      PURE. INSTALL-SAMPLES (owner 2026-10-29: "install commands take PARAMETERS, a config file is optional only"). Builds the
      answers object Test-PimInstallConfig validates -- the SAME object config.json gives -- from:
        -FileAnswers  the object read from -ConfigPath ($null when no file was given, or the file could not be read)
        -FileGiven    a -ConfigPath was given (an unreadable file then stays $null: "config.json could not be read as JSON")
        -Parameters   the command-line answers, keyed as in install-parameters.json (tenantId, subscriptionId, location,
                      resourceGroup, superAdmins, alertRecipients, mailSender, vnetAddressPrefix, subnetAddressPrefix,
                      exposure, edition, installId, supportAppId, supportAccess). Empty values are "not given".
      A parameter WINS over the same answer in the file. No file: tenantId and subscriptionId are required (missing[] names
      the ones not given), and the installation id is derived (Get-PimInstallDerivedId) unless one is given.
      Returns @{ answers; missing[]; overridden[]; editionGiven; fromFile }.
    #>
    param([AllowNull()][object]$FileAnswers, [switch]$FileGiven, [hashtable]$Parameters = @{})
    $given = [ordered]@{}
    foreach ($k in @($Parameters.Keys | Sort-Object)) {
        $v = $Parameters[$k]
        if ($null -eq $v) { continue }
        if ($v -is [array] -or $v -is [System.Collections.IList]) { $list = @(@($v) | ForEach-Object { "$_".Trim() } | Where-Object { $_ }); if ($list.Count) { $given[$k] = @($list) }; continue }
        if ("$v".Trim()) { $given[$k] = "$v".Trim() }
    }
    if ($given.Contains('edition')) { $given['edition'] = "$($given['edition'])".ToLowerInvariant() }
    if ($FileGiven -and $null -eq $FileAnswers) { return @{ answers = $null; missing = @(); overridden = @(); editionGiven = $given.Contains('edition'); fromFile = $true } }
    $o = [ordered]@{}
    if ($null -ne $FileAnswers) { foreach ($p in $FileAnswers.PSObject.Properties) { $o[$p.Name] = $p.Value } }
    $over = New-Object System.Collections.Generic.List[string]
    foreach ($k in $given.Keys) {
        if ($o.Contains($k) -and "$(@($o[$k]) -join ',')".Trim() -and "$(@($o[$k]) -join ',')" -ne "$(@($given[$k]) -join ',')") { $over.Add($k) }
        $o[$k] = $given[$k]
    }
    $missing = @()
    if (-not $FileGiven) { $missing = @(@('tenantId', 'subscriptionId') | Where-Object { -not "$($o[$_])".Trim() }) }
    if (-not "$($o['installId'])".Trim() -and "$($o['tenantId'])".Trim() -and "$($o['subscriptionId'])".Trim() -and -not $FileGiven) {
        $o['installId'] = Get-PimInstallDerivedId -TenantId "$($o['tenantId'])" -SubscriptionId "$($o['subscriptionId'])" -ResourceGroup "$($o['resourceGroup'])"
    }
    $edGiven = $given.Contains('edition') -or ($o.Contains('edition') -and "$($o['edition'])".Trim())
    return @{ answers = [pscustomobject]$o; missing = @($missing); overridden = @($over); editionGiven = [bool]$edGiven; fromFile = [bool]$FileGiven }
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
    $n = [pscustomobject]@{
        token = $t; resourceGroup = $Config.resourceGroup; vnet = 'vnet-pim'; environment = 'cae-pim'; logAnalytics = 'log-pim'
        acr = "acrpim$t"; sqlServer = "sql-pim-$t"; sqlFqdn = "sql-pim-$t.database.windows.net"; sqlDatabase = 'PimPlatform'; managerApp = 'ca-pim-manager'
        # CR5 step 1 (PIM 100.149): the engine + updater jobs named HERE, once (today's names) -- the install never repeats a literal
        tickJob = 'ca-pim-tick'; updateJob = 'ca-pim-update'; newNames = $false
        # GUIDED-INSTALL-FRONT: the install's own Key Vault -- the answers' keyVaultName, else kv-pim-<token> (globally unique)
        keyVault = $(if ($Config.PSObject.Properties['keyVaultName'] -and "$($Config.keyVaultName)".Trim()) { "$($Config.keyVaultName)".Trim().ToLowerInvariant() } else { "kv-pim-$t" })
    }
    # CR5 step 2: config 'newInstallNames' (else $env:PIM_Setup_NewInstallNames) -> the new names (OFF by default). The
    # deploy still checks the resource group first (Azure cannot rename) and keeps what is there. A MANAGED tenant's install
    # (Invoke-PimMspBuild) keeps today's names: the managed-tenant build is not part of CR5 step 2 yet.
    $explicit = if ($Config.PSObject.Properties['newInstallNames']) { $Config.newInstallNames } else { $null }
    $managed = ($Config.PSObject.Properties['mspRole'] -and "$($Config.mspRole)".Trim() -ieq 'managed')
    if (-not $managed -and (Test-PimNewInstallNamesSwitch -Explicit $explicit)) {
        $ns = Get-PimInstallNameNewDefaults
        $n.managerApp = $ns.web; $n.tickJob = $ns.engine; $n.updateJob = $ns.updater; $n.newNames = $true
    }
    return $n
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
    # CR5 step 2: the new names -- the deploy decides them from the resource group (a new one: the new names)
    if ($n.newNames) { $a['NewInstallNames'] = $true }
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
    } elseif ("$($Config.edition)" -eq 'community') {
        # INSTALL-SAMPLES (owner 2026-10-29): the COMMUNITY edition. Scenario S2 = the Core feature set (the scenario's
        # activeEdition, PIM-ScenarioProfile.ps1); the updater is the deploy's own Community path (COMMUNITY-INCLOUD-UPDATER:
        # Invardia's Community channel, ring 3 when no ring is given -- named here so the choice is explicit, the deploy would
        # take it for S2 anyway); and the feature gates WITHOUT any msp.* gate ("community does not have msp support, only
        # pro" -- the deploy also strips msp.* for S2 and switches msp.downlink off).
        $a['UpdateSource'] = 'InvardiaCommunity'
        $a['FeatureGates'] = @('scheduler.jobs', 'alerting.email')
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

function Test-PimInstallScopeAtOrAbove {
    <#
      PURE. Does a role assignment at -AssignmentScope apply AT -Scope (equal or above it)? A management group ('/providers/
      Microsoft.Management/managementGroups/<id>') or the root ('/') is above every subscription -- ARM's assignedTo() list at
      a subscription only returns the ones in its own hierarchy. 2026-10-11 (invardiademo): the old test was a string prefix
      ("/subscriptions/x".StartsWith(<mg scope>)), so Contributor inherited from the tenant root management group was DROPPED
      and the installer said "you need Owner" to an app that had Contributor + User Access Administrator. Below (a resource
      group of -Scope) does not count; '/subscriptions/ab' is not above '/subscriptions/abc'.
    #>
    param([Parameter(Mandatory)][string]$Scope, [string]$AssignmentScope)
    $s = "$Scope".Trim().TrimEnd('/').ToLowerInvariant(); $a = "$AssignmentScope".Trim().TrimEnd('/').ToLowerInvariant()
    if (-not $a) { return $true }                                                            # '/' = the root scope
    if ($a -eq $s) { return $true }
    if ($a -match '^/providers/microsoft\.management/managementgroups/[^/]+$') { return $true }
    return $s.StartsWith("$a/")
}

function Get-PimInstallAppRoleGaps {
    <#
      PURE. APP-IDENTITY INSTALL (owner via Invardia 2026-10-21): the Microsoft Graph APPLICATION permissions an application
      that installs PIM Manager needs, minus what -AppRoles (its Graph token's 'roles') holds -- in this order. A broader
      permission covers a narrower one: Group.ReadWrite.All -> Group.Create, GroupMember.ReadWrite.All;
      Directory.ReadWrite.All -> Directory.Read.All.
    #>
    param([string[]]$AppRoles = @())
    $have = @($AppRoles | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
    $need = [ordered]@{
        'RoleManagement.ReadWrite.Directory'     = @('RoleManagement.ReadWrite.Directory')
        'AppRoleAssignment.ReadWrite.All'        = @('AppRoleAssignment.ReadWrite.All')
        'Application.ReadWrite.All'              = @('Application.ReadWrite.All')
        'DelegatedPermissionGrant.ReadWrite.All' = @('DelegatedPermissionGrant.ReadWrite.All')
        'Group.Create'                           = @('Group.Create', 'Group.ReadWrite.All', 'Directory.ReadWrite.All')
        'GroupMember.ReadWrite.All'              = @('GroupMember.ReadWrite.All', 'Group.ReadWrite.All', 'Directory.ReadWrite.All')
        'Directory.Read.All'                     = @('Directory.Read.All', 'Directory.ReadWrite.All')
    }
    return @($need.Keys | Where-Object { $k = $_; -not @($need[$k] | Where-Object { $have -contains $_ }).Count })
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
          [string[]]$AppRoles = @(),
          # the signed-in principal is an APPLICATION (app-identity install): check -AppRoles, never a directory role
          [switch]$IsApp)
    $r = @($AzureRoles | ForEach-Object { "$_".Trim().ToLowerInvariant() })
    $azureOk = ($r -contains 'owner') -or (($r -contains 'contributor') -and (($r -contains 'user access administrator') -or ($r -contains 'role based access control administrator')))
    $pra = 'e8611ab8-c189-46e8-94e1-60213ab1f814'; $ga = '62e90394-69f5-4237-9190-012177145e10'
    $ids = @($DirectoryRoleTemplateIds | ForEach-Object { "$_".Trim().ToLowerInvariant() })
    $entraOk = ($ids -contains $pra) -or ($ids -contains $ga)
    # The app permissions that carry the three directory steps: add the SQL admin group's members (a role-assignable
    # group) and grant the identities their Graph app roles, and consent the Manager's sign-in.
    $ar = @($AppRoles | ForEach-Object { "$_".Trim() })
    # APP-IDENTITY INSTALL (owner via Invardia 2026-10-21, Install-Invardia -ViaSupportApp): an application has no directory
    # role to activate -- its Graph APPLICATION permissions are the check, and each missing one is named. Equivalents count
    # (Group.ReadWrite.All covers Group.Create + GroupMember.ReadWrite.All; Directory.ReadWrite.All covers Directory.Read.All).
    if ($IsApp -or ($ar.Count -and -not $entraOk)) {
        $missing = @(Get-PimInstallAppRoleGaps -AppRoles $ar)
        $entraOk = ($missing.Count -eq 0)
        if (-not $entraOk -or -not $azureOk) {
            return @{ azureOk = $azureOk; entraOk = $entraOk; missingAppRoles = @($missing); message = ((@($(if (-not $azureOk) { 'the Invardia Support app needs Owner (or Contributor + User Access Administrator) on the subscription' })) + @($(if ($missing.Count) { "the Invardia Support app lacks the Microsoft Graph application permission(s) $($missing -join ', ') -- the SQL admin group, the Graph permissions and the sign-in consent need them (they end as hand-off actions)" })) | Where-Object { $_ }) -join '; ') }
        }
        return @{ azureOk = $true; entraOk = $true; missingAppRoles = @(); message = '' }
    }
    $msg = @()
    if (-not $azureOk) { $msg += 'you need Owner (or Contributor + User Access Administrator) on the subscription' }
    if (-not $entraOk) { $msg += 'you are not an ACTIVE Privileged Role Administrator or Global Administrator -- the SQL admin group, the Graph permissions and the sign-in consent will end as hand-off actions (activate the role in PIM first if you have it)' }
    return @{ azureOk = $azureOk; entraOk = $entraOk; message = ($msg -join '; ') }
}

function Read-PimInstallState {
    <#
      The state file (state.json in -StatePath): @{ installId; completed[]; updatedUtc; licencePath; setupHostRule }.
      Missing or unreadable = empty. REQ 98.4 (a) + (b): licencePath (the PATH of the licence file the install was given --
      never its content) and setupHostRule (@{ name; server; resourceGroup; subscriptionId; openedUtc }: the SQL firewall
      rule THIS install opened) are optional -- a state file written before them reads as '' / $null and still resumes.
    #>
    param([Parameter(Mandatory)][string]$StatePath)
    $f = Join-Path $StatePath 'state.json'
    if (Test-Path -LiteralPath $f) {
        try {
            $s = Get-Content -Raw -LiteralPath $f | ConvertFrom-Json
            $hr = $null
            if ($s.PSObject.Properties['setupHostRule'] -and $s.setupHostRule) {
                # PowerShell 7 reads an ISO time as a DateTime: written back as the same round-trip text
                $at = $s.setupHostRule.openedUtc; $at = if ($at -is [datetime]) { $at.ToUniversalTime().ToString('o') } else { "$at" }
                $hr = [ordered]@{ name = "$($s.setupHostRule.name)"; server = "$($s.setupHostRule.server)"; resourceGroup = "$($s.setupHostRule.resourceGroup)"
                                  subscriptionId = "$($s.setupHostRule.subscriptionId)"; openedUtc = $at }
            }
            return [pscustomobject]@{ installId = "$($s.installId)"; completed = @($s.completed | Where-Object { $_ }); updatedUtc = "$($s.updatedUtc)"
                                      licencePath = "$($s.licencePath)".Trim(); setupHostRule = $hr }
        } catch { }
    }
    return [pscustomobject]@{ installId = ''; completed = @(); updatedUtc = ''; licencePath = ''; setupHostRule = $null }
}

function Save-PimInstallState {
    # -LicencePath: a PATH only. Never the licence text, a key or a token -- nothing secret is written to this file.
    param([Parameter(Mandatory)][string]$StatePath, [Parameter(Mandatory)][string]$InstallId, [string[]]$Completed = @(),
          [string]$LicencePath = '', [System.Collections.IDictionary]$SetupHostRule)
    if (-not (Test-Path -LiteralPath $StatePath)) { New-Item -ItemType Directory -Force -Path $StatePath | Out-Null }
    $doc = [ordered]@{ schema = 1; installId = $InstallId; completed = @($Completed | Select-Object -Unique); updatedUtc = [datetime]::UtcNow.ToString('o') }
    if ("$LicencePath".Trim()) { $doc['licencePath'] = "$LicencePath".Trim() }
    if ($SetupHostRule) {
        $doc['setupHostRule'] = [ordered]@{ name = "$($SetupHostRule['name'])"; server = "$($SetupHostRule['server'])"; resourceGroup = "$($SetupHostRule['resourceGroup'])"
                                            subscriptionId = "$($SetupHostRule['subscriptionId'])"; openedUtc = "$($SetupHostRule['openedUtc'])" }
    }
    Set-Content -LiteralPath (Join-Path $StatePath 'state.json') -Value ($doc | ConvertTo-Json -Depth 4) -Encoding utf8
}

function Test-PimInstallSetupHostRuleRecord {
    <#
      PURE. REQ 98.4 (b): is -Record (the state file's setupHostRule) the record of THIS install's own rule? Only when it names
      exactly 'AllowSetupHost' on this install's SQL server, resource group and subscription (-Target). Anything else -- a
      missing record, another rule name, another server -- is NOT this install's, so nothing is ever removed on its word.
    #>
    param([AllowNull()][object]$Record, [Parameter(Mandatory)][System.Collections.IDictionary]$Target)
    if (-not $Record) { return $false }
    $get = { param($o, $k) if ($o -is [System.Collections.IDictionary]) { "$($o[$k])".Trim() } else { "$($o.$k)".Trim() } }
    if ((& $get $Record 'name') -cne 'AllowSetupHost' -or (& $get $Target 'name') -cne 'AllowSetupHost') { return $false }
    foreach ($k in 'server', 'resourceGroup', 'subscriptionId') {
        $v = & $get $Record $k
        if (-not $v -or $v -ine (& $get $Target $k)) { return $false }
    }
    return $true
}

function Get-PimInstallSetupHostRulePlan {
    <#
      PURE. REQ 98.4 (b): whose is 'AllowSetupHost', decided BEFORE the deploy starts. Returns @{ owned; record; reason }.
        -Recorded  the state file's setupHostRule (an earlier run of this install opened it)   -> owned
        -RuleIp    the rule on the server now: '' = not there (or no server yet); $null = could not be read
          not there      -> owned + record: whatever opens it from here on is this install (written to the state file
                            BEFORE anything is created, so a run that dies still leaves the record)
          there, no record -> NOT owned: it was there before this install -- left exactly as found, never removed
          unreadable     -> NOT owned (nothing is removed on a guess)
    #>
    param([AllowNull()][object]$Recorded, [Parameter(Mandatory)][System.Collections.IDictionary]$Target, [AllowNull()][object]$RuleIp)
    if (Test-PimInstallSetupHostRuleRecord -Record $Recorded -Target $Target) { return @{ owned = $true; record = $false; reason = 'an earlier run of this installation opened it -- this run closes it when it ends' } }
    if ($null -eq $RuleIp) { return @{ owned = $false; record = $false; reason = 'it could not be read -- left as it is' } }
    if (-not "$RuleIp".Trim()) { return @{ owned = $true; record = $true; reason = 'not on the database server yet -- this installation opens it and closes it when it ends' } }
    return @{ owned = $false; record = $false; reason = 'it was on the database server before this installation started -- it is not this installation''s, so it is left as found' }
}

function Get-PimInstallAdminVerdict {
    <#
      PURE. REQ 98.4 (c) + (d): the preflight verdict on the PIM Manager administrators, before anything is created.
      -Admins: @{ upn; found = $true | $false | $null (could not be checked); mail } per administrator (the answers'
      superAdmins, else the person installing). Returns @{ state; message; actionText; actionCommand }.
        a name that is NOT in the tenant                      -> failed, naming every such address (it used to stop the
                                                                 sign-in step, about an hour into the install)
        every name found, none has a mailbox, no recipients   -> failed (the end-of-install check used to fail on
                                                                 "no alert reaches anyone", after everything was built)
        a name that could not be checked                      -> warning (never a stop on a read that failed)
    #>
    param([object[]]$Admins = @(), [string[]]$AlertRecipients = @())
    $list = @($Admins | Where-Object { $_ -and "$($_.upn)".Trim() })
    $rec = @($AlertRecipients | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
    $missing = @($list | Where-Object { $_.found -eq $false } | ForEach-Object { "$($_.upn)".Trim() })
    if ($missing.Count) {
        return @{ state = 'failed'; message = "$(if ($missing.Count -eq 1) { 'this sign-in name does' } else { 'these sign-in names do' }) not exist in the tenant: $($missing -join ', ') -- a PIM Manager administrator must be an account of this tenant; nothing was created"
                  actionText = 'Correct the administrator''s sign-in name in the answers (superAdmins in config.json), then run the installation again:'; actionCommand = '"superAdmins": ["admin@contoso.com"]' }
    }
    $unknown = @($list | Where-Object { $null -eq $_.found } | ForEach-Object { "$($_.upn)".Trim() })
    if ($unknown.Count) { return @{ state = 'warning'; message = "could not be checked in the tenant: $($unknown -join ', ') -- the sign-in step will tell" } }
    if (-not $list.Count) { return @{ state = 'ok'; message = 'no administrator to check' } }
    $withMail = @($list | Where-Object { "$($_.mail)".Trim() } | ForEach-Object { "$($_.mail)".Trim() })
    if (-not $rec.Count -and -not $withMail.Count) {
        # kind 'no-mailbox': the caller makes this a reminder (not a stop) for an installation that completed before -- its
        # recipients may have been set in the PIM Manager since, which a preflight cannot read
        return @{ state = 'failed'; kind = 'no-mailbox'; message = "no PIM Manager administrator has a mailbox ($(@($list | ForEach-Object { "$($_.upn)".Trim() }) -join ', ')) and no alert recipients were given -- the alerts would reach nobody; nothing was created"
                  actionText = 'Add the address that receives the alerts to the answers (alertRecipients in config.json), then run the installation again:'; actionCommand = '"alertRecipients": ["alerts@contoso.com"]' }
    }
    return @{ state = 'ok'; message = "found in the tenant: $(@($list | ForEach-Object { "$($_.upn)".Trim() }) -join ', '); the alerts go to $(if ($rec.Count) { $rec -join ', ' } else { $withMail -join ', ' })" }
}

# ---- the guided install's sign-in check (moved here from _PimSignedIn.ps1, 2026-10-10) -----------------------------------
# Framework 12.17 / REQ 100.42: _PimSignedIn.ps1 is inlined into the PUBLISHED support scripts (Initialize-PimMailSender),
# and those carry no second connect path. Install-PimManager.ps1 still reads its sign-in through its -Az seam (it is on the
# PIM 100.41 port list, tests\_shared\no-az-allowlist.json), so the CLI-shaped account check lives with the guided install
# and leaves when Install-PimManager is ported. Needs _PimSignedIn.ps1 loaded (the token + environment checks).
function Test-PimSignedInAccount {
    <#
      PURE. Judge an account object ({ id; tenantId; user = { name; type } }) for the signed-in install. Returns
      @{ ok; reason; userName; supportAppId }. Refused: no account, a service principal / managed identity, another
      tenant, another subscription. ONE exception (operator 2026-10-06: "we have only one agreed method"): the Invardia
      Support app, announced by Invardia's connect script for exactly this tenant and an allowed subscription
      (Get-PimSupportAppSession).
    #>
    param([object]$Account, [string]$TenantId, [string]$SubscriptionId, [hashtable]$Environment)
    $guid = '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
    $want = "$TenantId".Trim().ToLowerInvariant(); $sub = "$SubscriptionId".Trim().ToLowerInvariant()
    if ($want -notmatch $guid -or $sub -notmatch $guid) {
        return @{ ok = $false; reason = 'the tenant id and the subscription id must both be given explicitly (GUIDs) -- a signed-in install never relies on a default context' }
    }
    if ($null -eq $Account -or -not "$($Account.id)".Trim()) {
        return @{ ok = $false; reason = "no sign-in in this shell covers subscription $sub (tenant $want) -- sign in first" }
    }
    $type = "$($Account.user.type)".Trim().ToLowerInvariant()
    $name = "$($Account.user.name)".Trim()
    $supportAppId = ''
    if ($type -eq 'serviceprincipal') {
        $sess = Get-PimSupportAppSession -Environment $Environment
        if ($sess -and $sess.tenantId -eq $want -and ($sess.subscriptions -contains $sub) -and $name -match $guid) {
            $supportAppId = $name.ToLowerInvariant()
            if ("$($Account.tenantId)".Trim().ToLowerInvariant() -ne $want) { return @{ ok = $false; reason = "the support app session is in tenant '$($Account.tenantId)', not '$want' -- REFUSING" } }
            if ("$($Account.id)".Trim().ToLowerInvariant() -ne $sub) { return @{ ok = $false; reason = "the sign-in answered for subscription '$($Account.id)', not the requested '$sub' -- REFUSING" } }
            return @{ ok = $true; reason = "signed in as the Invardia Support app $supportAppId (support environment '$($sess.environment)', tenant $want, subscription $sub)"; userName = "Invardia Support app ($supportAppId)"; supportAppId = $supportAppId }
        }
        if ($sess -and $sess.tenantId -ne $want) { return @{ ok = $false; reason = "the Invardia Support session in this shell is for tenant '$($sess.tenantId)', but the build config names '$want' -- REFUSING" } }
        if ($sess -and -not ($sess.subscriptions -contains $sub)) { return @{ ok = $false; reason = "subscription $sub is not one the support environment allows ($($sess.subscriptions -join ', ')) -- REFUSING" } }
    }
    if ($type -ne 'user') {
        return @{ ok = $false; reason = ("the shell is signed in as a $(if ($type) { $type } else { 'non-user account' }) ('$name'), not a person. " +
                 'The signed-in build runs as the administrator at the keyboard; an application identity belongs in deployIdentity (certificate mode).') }
    }
    if ("$($Account.tenantId)".Trim().ToLowerInvariant() -ne $want) {
        return @{ ok = $false; reason = "the sign-in for subscription $sub is in tenant '$($Account.tenantId)', but the build config names tenant '$want' -- REFUSING (a wrong default context acts in somebody else's directory)" }
    }
    if ("$($Account.id)".Trim().ToLowerInvariant() -ne $sub) {
        return @{ ok = $false; reason = "the sign-in answered for subscription '$($Account.id)', not the requested '$sub' -- REFUSING" }
    }
    return @{ ok = $true; reason = "signed in as $name (tenant $want, subscription $sub)"; userName = $name }
}

function Get-PimInstallSignedInIdentity {
    <#
      Install-PimManager's preflight sign-in, through its -Az seam (a scriptblock param([string[]]$AzArgs) returning the
      tool's stdout; mocked offline in tests\Test-PimGuidedInstall.ps1 / Test-PimMspBuild.ps1). Every call pins
      --subscription. Returns the same shape as Get-PimSignedInIdentity (_PimSignedIn.ps1).
    #>
    param([Parameter(Mandatory)][string]$TenantId, [Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][scriptblock]$Az)
    [void](Clear-PimSignedInMachineIdentity); $conf = @(Get-PimSignedInEnvironmentConflicts)
    if ($conf.Count) {
        return @{ ok = $false; reason = ("REFUSED: $($conf -join ', ') $(if ($conf.Count -eq 1) { 'is' } else { 'are' }) set in this session -- a token call would authenticate as " +
                 'that identity instead of the signed-in user. ' + (Get-PimSignedInConflictHint -Names $conf)) }
    }
    $acct = $null
    try { $acct = ((& $Az @('account', 'show', '--subscription', "$SubscriptionId", '-o', 'json')) | Out-String | ConvertFrom-Json) } catch { $acct = $null }
    $a = Test-PimSignedInAccount -Account $acct -TenantId $TenantId -SubscriptionId $SubscriptionId
    if (-not $a.ok) { return $a }
    $tok = $null
    try { $tok = "$(((& $Az @('account', 'get-access-token', '--subscription', "$SubscriptionId", '--resource', 'https://management.azure.com/', '-o', 'json')) | Out-String | ConvertFrom-Json).accessToken)" } catch { $tok = $null }
    if (-not "$tok".Trim()) { return @{ ok = $false; reason = "no token could be issued for subscription $SubscriptionId (tenant $TenantId) -- sign in again" } }
    $t = Test-PimSignedInToken -Token $tok -TenantId $TenantId -AllowedAppId "$($a.supportAppId)"
    $tok = $null
    if (-not $t.ok) { return $t }
    return @{ ok = $true; reason = $a.reason; userName = $(if ($t.userName) { $t.userName } else { $a.userName }); objectId = $t.objectId
              tenantId = "$TenantId".Trim().ToLowerInvariant(); subscriptionId = "$SubscriptionId".Trim().ToLowerInvariant(); supportAppId = "$($a.supportAppId)" }
}
