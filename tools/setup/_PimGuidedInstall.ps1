#Requires -Version 5.1
<#
.SYNOPSIS
  §95.2 -- the PURE parts of the guided install (Install-PimManager.ps1), offline-tested in tests/Test-PimGuidedInstall.ps1.

.DESCRIPTION
  The contract (ONE-LINE-INSTALL, owner 2026-11-02): ONE command, Install-PimManager, every answer a parameter:
    answers      = the parameters, keyed as in tools/setup/install-parameters.json, plus installId (derived when not given)
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
# 🔴 INSTALL-FIX (REQUIREMENTS 100.25 item 3, 2026-10-09): the functions below read the catalog through
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
    'preflight-network'    = 'Your private network'   # a -PrivateNetwork install only
    'preflight-sql-region' = 'Azure services in the chosen region'
    'preflight-admins'     = 'PIM Manager administrators'
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
      PURE. Validate the answers (the object ConvertTo-PimInstallAnswers builds from the parameters). Returns
      @{ ok; errors[]; config (normalised) }. Refuses: a missing / malformed required value, an unknown enum value, a network
      answer that does not fit (Test-PimInstallNetworkAnswers), an MSP role (managing / managed tenants are set up with the
      managing-tenant build, not this install), a bad CIDR / UPN / e-mail.
    #>
    param([AllowNull()][object]$Config)
    $err = New-Object System.Collections.Generic.List[string]
    if ($null -eq $Config) { return @{ ok = $false; errors = @('no answers were given'); config = $null } }
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
    # 'community' = the free edition (Install-PimManager chooses it when no -Edition is given). trial / pro = the same install
    # with the Pro updater and no licence (the licence is added in PIM Manager > Settings > Licence). Empty stays 'trial'.
    $ed = "$(& $get 'edition')".Trim().ToLowerInvariant(); if (-not $ed) { $ed = 'trial' }
    if ($ed -notin 'community', 'trial', 'pro') { $err.Add("edition must be community, trial or pro (got '$ed')") }
    $c.edition = $ed
    # PRIVATE NETWORK (framework INSTALL-1 item 5): public by default, -PrivateNetwork = the private shape. The network answers
    # (SI's names; the old -Exposure / -SubnetAddressPrefix mapped for one release) are checked in ONE place below.
    $net = Test-PimInstallNetworkAnswers -Get $get -SubscriptionId $c.subscriptionId -ResourceGroup $rg
    foreach ($e in @($net.errors)) { $err.Add($e) }
    foreach ($k in @($net.values.Keys)) { $c[$k] = $net.values[$k] }
    $role = "$(& $get 'mspRole')".Trim().ToLowerInvariant(); if (-not $role) { $role = 'single' }
    # ONE-LINE-INSTALL (owner 2026-11-02): this install is a single tenant. A managing or managed tenant (MSP) is set up with the
    # managing-tenant build (Invoke-PimMspBuild), never with an answers file or an enrollment key here.
    if ($role -ne 'single') { $err.Add("mspRole '$role': a managing or managed tenant is set up with the managing-tenant build, not this install -- install as a single tenant") }
    $c.mspRole = $role
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
    # MAIL-SKIP (owner 2026-10-31, Pingala): the install leaves the mail sender to the tenant's own Exchange admin
    # (Initialize-PimMailSender, browser sign-in) -- the installing identity is given no Exchange role at all.
    # DEFAULT ON (owner 2026-10-31, both products: "mail is skipped in setup"): not given = skipped, unless a mailSender is
    # named (the explicit ask for the install to create it).
    $skRaw = & $get 'skipMailSender'
    $c.skipMailSender = if ($null -eq $skRaw -or "$skRaw".Trim() -eq '') { -not $ms } else { "$skRaw".Trim() -notin 'false', '0', 'no' }
    if ($c.skipMailSender -and $ms) { $err.Add("mailSender '$ms' and skipMailSender exclude each other -- the install either creates the sender or leaves it to the Exchange admin") }
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
    # Invardia's own and never a customer's. Install-PimManager -UpdateRing.
    $ur = "$(& $get 'updateRing')".Trim(); if (-not $ur) { $ur = '3' }
    if ($ur -notin '2', '3') { $err.Add("updateRing must be 2 (design partners) or 3 (broad) (got '$ur')") }
    $c.updateRing = $ur
    # CR5 step 2 (PIM 100.149): optional, NOT an install parameter -- an operator sets $env:PIM_Setup_NewInstallNames instead;
    # carried only when given, so an install without it is exactly as before.
    $nn = & $get 'newInstallNames'
    if ($null -ne $nn -and "$nn".Trim()) {
        if ("$nn".Trim() -notmatch '^(?i)(true|false|1|0|yes|no|on|off)$') { $err.Add('newInstallNames must be true or false') }
        else { $c.newInstallNames = [bool]("$nn".Trim() -match '^(?i)(true|1|yes|on)$') }
    }
    # GUIDED-INSTALL-FRONT (2026-10-21): the install's own Key Vault (the sign-in front's key). Optional (-KeyVaultName) --
    # the customer's own naming when given (-KeyVaultName; hybrid naming rule: every name settable); else 'kv-pim-<token>'.
    $kvn = "$(& $get 'keyVaultName')".Trim()
    if ($kvn) {
        if ($kvn -notmatch '^[A-Za-z][A-Za-z0-9-]{1,22}[A-Za-z0-9]$' -or $kvn -match '--') { $err.Add("keyVaultName '$kvn' is not a valid Key Vault name (3-24 letters, digits and dashes; starts with a letter; no '--')") }
        else { $c.keyVaultName = $kvn.ToLowerInvariant() }
    }
    return @{ ok = ($err.Count -eq 0); errors = @($err); config = [pscustomobject]$c }
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
      PURE. ONE-LINE-INSTALL (owner 2026-11-02: "i only support one method where i get cmdlets with all parameters"). Builds
      the answers object Test-PimInstallConfig validates from -Parameters: the command-line answers, keyed as in
      install-parameters.json (tenantId, subscriptionId, location, resourceGroup, superAdmins, alertRecipients, mailSender,
      portalUsers, allowAllMembers, vnetAddressPrefix, subnetAddressPrefix, exposure, edition, updateRing, keyVaultName,
      engineAzureRootUserAccessAdmin, installId, supportAppId, supportAccess). Empty values are "not given". tenantId and
      subscriptionId are required (missing[] names the ones not given), and the installation id is derived
      (Get-PimInstallDerivedId) unless one is given. There is no answers file. Returns @{ answers; missing[]; editionGiven }.
    #>
    param([hashtable]$Parameters = @{})
    $o = [ordered]@{}
    foreach ($k in @($Parameters.Keys | Sort-Object)) {
        $v = $Parameters[$k]
        if ($null -eq $v) { continue }
        if ($v -is [array] -or $v -is [System.Collections.IList]) { $list = @(@($v) | ForEach-Object { "$_".Trim() } | Where-Object { $_ }); if ($list.Count) { $o[$k] = @($list) }; continue }
        if ("$v".Trim()) { $o[$k] = "$v".Trim() }
    }
    if ($o.Contains('edition')) { $o['edition'] = "$($o['edition'])".ToLowerInvariant() }
    $missing = @(@('tenantId', 'subscriptionId') | Where-Object { -not "$($o[$_])".Trim() })
    if (-not "$($o['installId'])".Trim() -and "$($o['tenantId'])".Trim() -and "$($o['subscriptionId'])".Trim()) {
        $o['installId'] = Get-PimInstallDerivedId -TenantId "$($o['tenantId'])" -SubscriptionId "$($o['subscriptionId'])" -ResourceGroup "$($o['resourceGroup'])"
    }
    return @{ answers = [pscustomobject]$o; missing = @($missing); editionGiven = [bool]$o.Contains('edition') }
}

# ==== INSTALL-LINE-MINIMAL (owner 2026-11-03, all products; Invardia DESIGN ch 8 "Install lines carry only what the install
# uses"): "why mention cmdlet that are not used during setup ... simplify the cmdlet and strip out what is not used during
# initial setup" / "if it is a shared mailbox in m365, why tell fx port". Every install line PIM generates carries ONLY the
# tenant, the subscription, the region, the choices that differ from the default and the values of the chosen options --
# never an empty value, never a parameter of an option not chosen, never a default restated. The PARAMETERS stay on the
# scripts (existing callers keep working); only what is shown / generated changes. =======================================
function Get-PimInstallLineDefaults {
    <# PURE. The defaults an install line never restates (the same values as install-parameters.json -- Test-PimGuidedInstall ILM keeps them in step). #>
    return [ordered]@{
        ResourceGroup = 'rg-pim'; Edition = 'Community'; UpdateRing = '3'; SupportAccess = 'troubleshoot'
        VnetAddressPrefix = '10.220.0.0/22'; VnetName = 'vnet-pim'; AppsSubnetName = 'snet-pim-aca'; AppsSubnetPrefix = '10.220.0.0/23'
        EndpointsSubnetName = 'pim-endpoints'; WebAppAccess = 'external'; Exposure = 'external'
    }
}

function Get-PimInstallLineArgs {
    <#
      PURE. INSTALL-LINE-MINIMAL: the parameter text of an install line (Install-PimManager / Start-PimManagerInstall) from
      -Given (the parameters as given, keyed by parameter name: a hashtable of PSBoundParameters). Returns ' -Name ''value'' ...'
      (each part with a leading space; '' when nothing is carried). Rules:
        always (when given)      -TenantId, -SubscriptionId, -Location (the region)
        a default                left out (Get-PimInstallLineDefaults; -InstallId = the derived id; -KeyVaultName =
                                 kv-pim-<token>; -EndpointsSubnetPrefix = the /26 after the apps subnet; -PortalUsers = the
                                 -SuperAdmins; -StatePath = -DefaultStatePath)
        an option not chosen     its parameters left out: the network values of a private install without -PrivateNetwork,
                                 -VnetAddressPrefix / -VnetName with -VnetId, -PeerToHub / -LinkZonesToHub without
                                 -HubVnetId, -UpdateRing outside Pro / Trial, -SupportAccess without -SupportAppId
        empty / false            left out (an empty value, an empty list, a switch that is off)
        never                    -WebAppAccess (external is the default; internal is what -PrivateNetwork already means);
                                 any parameter the installer does not take (an SMTP host or port, -SqlAdminGroupId, ...):
                                 only the parameters named here are ever written
      -Edition: give -Edition '' for the launcher (its copy decides the edition) -- UpdateRing is then judged by -Channel.
    #>
    param([System.Collections.IDictionary]$Given = @{}, [string]$StatePath = '', [string]$DefaultStatePath = '',
          # the launcher's channel (its copy decides the edition): 'pro' = the Pro copy; '' = judge by -Edition
          [ValidateSet('', 'community', 'pro')][string]$Channel = '')
    $d = Get-PimInstallLineDefaults
    $has = { param($k) $Given.Contains($k) -and $null -ne $Given[$k] }
    $str = { param($k) if (& $has $k) { "$(@($Given[$k]) -join ',')".Trim() } else { '' } }
    $list = { param($k) if (& $has $k) { @(@($Given[$k]) | ForEach-Object { "$_" -split '[,;]' } | ForEach-Object { "$_".Trim() } | Where-Object { $_ }) } else { @() } }
    $on = { param($k) (& $has $k) -and ("$($Given[$k])".Trim() -match '^(?i)(true|1|yes|on)$') }
    $q = { param($v) "'" + ("$v" -replace "'", "''") + "'" }
    $isDef = { param($k, $v) $d.Contains($k) -and "$v".Trim() -ieq "$($d[$k])" }
    $out = New-Object System.Collections.Generic.List[string]
    $one = { param($n, $v) if ("$v".Trim()) { $out.Add(" -$n " + (& $q "$v".Trim())) } }
    $sw = { param($n) $out.Add(" -$n") }

    $tid = & $str 'TenantId'; $sub = & $str 'SubscriptionId'; $rg = & $str 'ResourceGroup'
    $ed = (& $str 'Edition').ToLowerInvariant()
    $paid = if ($ed) { $ed -in 'pro', 'trial' } else { $Channel -eq 'pro' }
    $exp = (& $str 'Exposure').ToLowerInvariant()
    $private = (& $on 'PrivateNetwork') -or $exp -eq 'internal'
    $vnetId = if ($private) { & $str 'VnetId' } else { '' }
    $hub = if ($private) { & $str 'HubVnetId' } else { '' }
    $supportApp = & $str 'SupportAppId'

    # the target: tenant, subscription, the region -- always; the resource group when it is not rg-pim
    & $one 'TenantId' $tid; & $one 'SubscriptionId' $sub; & $one 'Location' (& $str 'Location')
    if ($rg -and -not (& $isDef 'ResourceGroup' $rg)) { & $one 'ResourceGroup' $rg }
    # the people (lists: each value quoted, comma-joined); -PortalUsers equal to -SuperAdmins is the default
    $admins = @(& $list 'SuperAdmins')
    foreach ($n in 'SuperAdmins', 'AlertRecipients') { $l = @(& $list $n); if ($l.Count) { $out.Add(" -$n " + (@($l | ForEach-Object { & $q $_ }) -join ',')) } }
    & $one 'MailSender' (& $str 'MailSender')
    $pu = @(& $list 'PortalUsers')
    # (with -AllowAllMembers a named list is NOT the default: the list then still decides the sign-in app's assignments)
    $puIsAdmins = -not (& $on 'AllowAllMembers') -and $admins.Count -and $pu.Count -eq $admins.Count -and -not @($pu | Where-Object { $p = $_; -not @($admins | Where-Object { $_ -ieq $p }).Count }).Count
    if ($pu.Count -and -not $puIsAdmins) { $out.Add(' -PortalUsers ' + (@($pu | ForEach-Object { & $q $_ }) -join ',')) }
    # the network the installation makes (not with -VnetId): range + the old subnet name (one release)
    $appsPfx = & $str 'AppsSubnetPrefix'; $oldPfx = & $str 'SubnetAddressPrefix'
    if (-not $vnetId) { $v = & $str 'VnetAddressPrefix'; if ($v -and -not (& $isDef 'VnetAddressPrefix' $v)) { & $one 'VnetAddressPrefix' $v } }
    if ($oldPfx -and -not $appsPfx -and -not (& $isDef 'AppsSubnetPrefix' $oldPfx)) { & $one 'SubnetAddressPrefix' $oldPfx }
    # the old -Exposure (one release) is never written: internal = -PrivateNetwork (written below), external = the default
    # the edition and its ring (the ring only for Pro / Trial; 3 is the default)
    if ($ed -and -not (& $isDef 'Edition' $ed)) { & $one 'Edition' (& $str 'Edition') }
    $ur = & $str 'UpdateRing'; if ($paid -and $ur -and -not (& $isDef 'UpdateRing' $ur)) { & $one 'UpdateRing' $ur }
    # the derived names: the installation id and the Key Vault name are left out when they are what the install derives
    $derivedId = if ($tid -and $sub) { Get-PimInstallDerivedId -TenantId $tid -SubscriptionId $sub -ResourceGroup $rg } else { '' }
    $iid = & $str 'InstallId'
    $kv = & $str 'KeyVaultName'
    $tokenOf = if ($iid) { $iid } else { $derivedId }
    if ($kv -and -not ($tokenOf -and $kv -ieq ('kv-pim-' + (Get-PimInstallToken -InstallId $tokenOf)))) { & $one 'KeyVaultName' $kv }
    if ($iid -and $iid -ine $derivedId) { & $one 'InstallId' $iid }
    # the Invardia Support app: its level only with the app, and only when it is not troubleshoot
    & $one 'SupportAppId' $supportApp
    $lvl = & $str 'SupportAccess'; if ($supportApp -and $lvl -and -not (& $isDef 'SupportAccess' $lvl)) { & $one 'SupportAccess' $lvl }
    foreach ($n in 'AllowAllMembers', 'EngineAzureRootUserAccessAdmin', 'ViaSupportApp') { if (& $on $n) { & $sw $n } }
    # PRIVATE NETWORK: only the values of a private install that differ from their defaults
    if ($private) { & $one 'VnetId' $vnetId }
    if (-not $vnetId) { $v = & $str 'VnetName'; if ($v -and -not (& $isDef 'VnetName' $v)) { & $one 'VnetName' $v } }
    $v = & $str 'AppsSubnetName'; if ($v -and -not (& $isDef 'AppsSubnetName' $v)) { & $one 'AppsSubnetName' $v }
    if ($appsPfx -and -not (& $isDef 'AppsSubnetPrefix' $appsPfx)) { & $one 'AppsSubnetPrefix' $appsPfx }
    if ($private) {
        $v = & $str 'EndpointsSubnetName'; if ($v -and -not (& $isDef 'EndpointsSubnetName' $v)) { & $one 'EndpointsSubnetName' $v }
        $ep = & $str 'EndpointsSubnetPrefix'
        if ($ep) {
            $epDefault = ''
            $as = ConvertFrom-PimInstallCidr $(if ($appsPfx) { $appsPfx } elseif ($oldPfx) { $oldPfx } else { $d.AppsSubnetPrefix })
            if ($as) { $epDefault = ConvertTo-PimInstallCidrText ($as.End + 1) 26 }
            if ($ep -ne $epDefault) { & $one 'EndpointsSubnetPrefix' $ep }
        }
        & $one 'PrivateDnsZonesResourceGroupId' (& $str 'PrivateDnsZonesResourceGroupId')
        & $one 'HubVnetId' $hub
        & $sw 'PrivateNetwork'
        if ($hub) { foreach ($n in 'LinkZonesToHub', 'PeerToHub') { if (& $on $n) { & $sw $n } } }
    }
    # the state folder: only when it is not the one the installation derives by itself
    if ("$StatePath".Trim() -and "$StatePath".Trim().TrimEnd('\', '/') -ine "$DefaultStatePath".Trim().TrimEnd('\', '/')) { & $one 'StatePath' "$StatePath".Trim() }
    return (-join $out)
}

function Get-PimInstallDefaultStatePath {
    <# PURE. The state folder an installation uses when -StatePath is not given: <clouddrive or home>/invardia/<install id>. #>
    param([Parameter(Mandatory)][string]$InstallId, [string]$HomeDir = '')
    $h = if ("$HomeDir".Trim()) { "$HomeDir".Trim() } elseif ($env:HOME) { $env:HOME } else { $env:USERPROFILE }
    $base = if (Test-Path -LiteralPath (Join-Path $h 'clouddrive')) { Join-Path $h 'clouddrive' } else { $h }
    return (Join-Path (Join-Path $base 'invardia') $InstallId)
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
    param([Parameter(Mandatory)][object]$Config, [string]$SignedInUpn = '')
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
    # PRIVATE NETWORK (INSTALL-1 item 5): SI's names onto the engine's own parameters (public: the values above, unchanged)
    Add-PimInstallNetworkDeployArgs -DeployArgs $a -Config $Config -ResourceGroup $n.resourceGroup
    # CR5 step 2: the new names -- the deploy decides them from the resource group (a new one: the new names)
    if ($n.newNames) { $a['NewInstallNames'] = $true }
    if (@($portal).Count) { $a['EasyAuthAllowedPrincipals'] = @($portal) }
    if ($Config.allowAllMembers) { $a['EasyAuthAllowAllTenantUsers'] = $true }
    if ($Config.engineAzureRootUserAccessAdmin) { $a['EngineAzureRootUserAccessAdmin'] = $true }   # §97 opt-in
    if ("$($Config.mailSender)".Trim()) { $a['MailSender'] = "$($Config.mailSender)".Trim() }
    if ($Config.skipMailSender) { $a['SkipMailSender'] = $true }   # MAIL-SKIP: no Exchange role for the installing identity
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
    # customer who buys keeps the same install). ONE-LINE-INSTALL (owner 2026-11-02): deployed WITHOUT a licence -- the
    # administrator adds it in PIM Manager > Settings > Licence; until then the updater waits (never a failed run).
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

# ==== PRIVATE NETWORK ON THE TWO LINES (framework INSTALL-1 item 5; owner 2026-11-02: "must support public + private network.
# simple 2 line cmdlets" / "dont overcomplicate it") ====================================================================
# NOT a new capability: SI's parameter names, name for name (their meaning: EntraPolicySuite DESIGN §2b), mapped onto the
# private shape Invoke-PimDeployAll ALREADY builds with -Exposure internal (own VNet, SQL private endpoint, Premium registry,
# private DNS, optional hub). Public stays the default and is unchanged. The address helpers are EPS's, copied (isolation
# over sharing). Everything here is PURE; the one Azure read is Install-PimManager's 'preflight-network' step.
function ConvertFrom-PimInstallCidr {
    # 'a.b.c.d/n' -> @{ Start; End; Length; Text } (IPv4, the network address itself -- host bits set is refused); $null when not
    param([string]$Cidr)
    if ("$Cidr" -notmatch '^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})/(\d{1,2})$') { return $null }
    $m = $Matches; $o = @([int]$m[1], [int]$m[2], [int]$m[3], [int]$m[4]); $len = [int]$m[5]
    if (@($o | Where-Object { $_ -gt 255 }).Count -or $len -lt 8 -or $len -gt 29) { return $null }
    [uint64]$ip = ([uint64]$o[0] * 16777216) + ([uint64]$o[1] * 65536) + ([uint64]$o[2] * 256) + [uint64]$o[3]
    [uint64]$size = [uint64][math]::Pow(2, 32 - $len)
    if ($ip % $size) { return $null }
    return @{ Start = $ip; End = $ip + $size - 1; Length = $len; Text = "$Cidr" }
}
function ConvertTo-PimInstallCidrText([uint64]$Start, [int]$Length) {
    '{0}.{1}.{2}.{3}/{4}' -f ([math]::Floor($Start / 16777216) % 256), ([math]::Floor($Start / 65536) % 256), ([math]::Floor($Start / 256) % 256), ($Start % 256), $Length
}
function Test-PimInstallCidrOverlap($A, $B) { [bool]($A -and $B -and $A.Start -le $B.End -and $B.Start -le $A.End) }
function Test-PimInstallCidrInside($Inner, $Outer) { [bool]($Inner -and $Outer -and $Inner.Start -ge $Outer.Start -and $Inner.End -le $Outer.End) }
# EVERY privatelink zone a private install AND its updater need (framework installer rule 8, 2026-11-03: the preflight
# checks them all, names every missing one at once, and stops before the first resource): the SQL private endpoint's and the
# registry's (public access off, Invardia 2026-11-02: "private stays private"), and the blob zone of the as-built store,
# which the updater makes private with a blob private endpoint after the install (PIM-AsBuilt.ps1
# Invoke-PimAsBuiltBlobEndpointConverge: with central zones it READS privatelink.blob.core.windows.net in the same group as
# the SQL zone and never creates it there). No other private endpoint is made on a private install (checked 2026-11-03:
# the sign-in front's Key Vault keeps its network; the hybrid worker and the MSP baseline are separate deploys).
function Get-PimInstallPrivateZoneNames { @('privatelink.database.windows.net', 'privatelink.azurecr.io', 'privatelink.blob.core.windows.net') }
# the registry's agent pool of a private install: the image builds run on it, inside the network (billed while it exists)
function Get-PimInstallAgentPoolName { 'pimpool' }

function Test-PimInstallNetworkAnswers {
    <#
      PURE. The network answers of the install -> @{ errors[]; values } (values = the normalised config keys). -Get reads an
      answer by its key (Test-PimInstallConfig's reader). Public (the default): exposure external, the VNet range + the apps
      subnet as before. -PrivateNetwork: exposure internal (= the engine's private shape). Refused with one plain line each:
      a private-only answer without -PrivateNetwork, -WebAppAccess that contradicts the shape, a bad id / name / range, two
      ranges that overlap or a subnet outside its network, a -VnetId in another subscription (another resource group of
      the same subscription is fine: carried as VnetResourceGroup, Invardia 2026-11-02), -PeerToHub /
      -LinkZonesToHub without -HubVnetId. Old names, one release: -Exposure internal = -PrivateNetwork, -SubnetAddressPrefix =
      -AppsSubnetPrefix (an earlier run's printed -Resume command may carry them).
    #>
    param([Parameter(Mandatory)][scriptblock]$Get, [string]$SubscriptionId = '', [string]$ResourceGroup = '')
    $vnetRx = '(?i)^/subscriptions/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})/resourceGroups/([^/]+)/providers/Microsoft\.Network/virtualNetworks/([^/]+)$'
    $rgRx = '(?i)^/subscriptions/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})/resourceGroups/([^/]+?)/?$'
    $snRx = '^[A-Za-z0-9][A-Za-z0-9_.-]{0,78}[A-Za-z0-9_]$'
    $err = New-Object System.Collections.Generic.List[string]
    $s = { param($k) "$(& $Get $k)".Trim() }
    $on = { param($k) "$(& $Get $k)".Trim() -match '^(?i)(true|1|yes|on)$' }
    $pn = { param($k) '-' + $k.Substring(0, 1).ToUpperInvariant() + $k.Substring(1) }
    $v = [ordered]@{}
    $ex = (& $s 'exposure').ToLowerInvariant()
    if ($ex -and $ex -notin 'external', 'internal') { $err.Add("exposure must be external or internal (got '$ex') -- -PrivateNetwork is the private network install") }
    $private = [bool]((& $on 'privateNetwork') -or $ex -eq 'internal')
    if ($ex -eq 'external' -and (& $on 'privateNetwork')) { $err.Add('-Exposure external and -PrivateNetwork contradict each other -- leave -Exposure out') }
    $v.privateNetwork = $private
    $v.exposure = $(if ($private) { 'internal' } else { 'external' })
    $wa = (& $s 'webAppAccess').ToLowerInvariant()
    if ($wa -and $wa -notin 'external', 'internal') { $err.Add("webAppAccess must be external or internal (got '$wa')") }
    elseif ($wa -eq 'internal' -and -not $private) { $err.Add('-WebAppAccess internal needs -PrivateNetwork (the PIM Manager is then reachable from your network only)') }
    elseif ($wa -eq 'external' -and $private) { $err.Add('-PrivateNetwork means -WebAppAccess internal: the Container Apps environment has no public address -- leave -WebAppAccess out or say internal') }
    $v.webAppAccess = $v.exposure
    $privOnly = @(@(@('vnetId', 'endpointsSubnetName', 'endpointsSubnetPrefix', 'privateDnsZonesResourceGroupId', 'hubVnetId') | Where-Object { & $s $_ }) + @(@('linkZonesToHub', 'peerToHub') | Where-Object { & $on $_ }))
    if (-not $private -and $privOnly.Count) { $err.Add("$(@($privOnly | ForEach-Object { & $pn $_ }) -join ', ') belong to a private network install: add -PrivateNetwork (or leave them out for the public install)") }
    # the network: an existing one (-VnetId) or one the install makes (-VnetName + -VnetAddressPrefix)
    $vid = & $s 'vnetId'; $vnetName = & $s 'vnetName'; $vnetPfx = & $s 'vnetAddressPrefix'
    $v.vnetId = ''; $v.vnetResourceGroup = "$ResourceGroup".Trim()
    if ($vid -and $private) {
        $m = [regex]::Match($vid, $vnetRx)
        if (-not $m.Success) { $err.Add("-VnetId '$vid' is not a virtual network resource id (/subscriptions/<id>/resourceGroups/<rg>/providers/Microsoft.Network/virtualNetworks/<name>)") }
        else {
            $v.vnetId = $vid.TrimEnd('/')
            # Invardia 2026-11-02: a network in ANOTHER RESOURCE GROUP of the same subscription is fine (the customer's network
            # resource group; the deploy carries it as VnetResourceGroup). Another SUBSCRIPTION stays refused.
            if ($SubscriptionId -and $m.Groups[1].Value -ine "$SubscriptionId".Trim()) { $err.Add("-VnetId is in subscription $($m.Groups[1].Value): PIM Manager uses a network in the subscription it is installed in ($("$SubscriptionId".Trim())) -- give a network of that subscription, or leave -VnetId out and the installation makes its own") }
            $v.vnetResourceGroup = $m.Groups[2].Value
            if ($vnetPfx) { $err.Add('-VnetAddressPrefix is only for a network the installation makes -- not with -VnetId (your network keeps its own range)') }
            if ($vnetName -and $vnetName -ine $m.Groups[3].Value) { $err.Add('-VnetName is only for a network the installation makes -- with -VnetId the name is in the id') }
            $vnetName = $m.Groups[3].Value
        }
    }
    if (-not $vnetName) { $vnetName = 'vnet-pim' }
    if ($vnetName -notmatch '^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}[A-Za-z0-9_]$') { $err.Add("-VnetName '$vnetName' is not a virtual network name") }
    if (-not $vnetPfx) { $vnetPfx = '10.220.0.0/22' }
    $v.vnetName = $vnetName; $v.vnetAddressPrefix = $vnetPfx
    $vn = ConvertFrom-PimInstallCidr $vnetPfx
    if (-not $vn) { $err.Add("vnetAddressPrefix '$vnetPfx' is not an IPv4 CIDR (a.b.c.d/n, the network address itself)") }
    # the Container Apps subnet: -AppsSubnetName / -AppsSubnetPrefix (old name -SubnetAddressPrefix)
    $an = & $s 'appsSubnetName'; $ap = & $s 'appsSubnetPrefix'; $old = & $s 'subnetAddressPrefix'
    if ($ap -and $old -and $ap -ne $old) { $err.Add('-SubnetAddressPrefix is the old name of -AppsSubnetPrefix -- give one of them') }
    if (-not $ap) { $ap = $old }; if (-not $ap) { $ap = '10.220.0.0/23' }
    if ($an -and $an -notmatch $snRx) { $err.Add("-AppsSubnetName '$an' is not a subnet name") }
    $v.appsSubnetName = $an; $v.appsSubnetPrefix = $ap; $v.subnetAddressPrefix = $ap
    $as = ConvertFrom-PimInstallCidr $ap
    if (-not $as) { $err.Add("appsSubnetPrefix '$ap' is not an IPv4 CIDR (a.b.c.d/n, the network address itself)") }
    elseif ($as.Length -gt 23) { $err.Add("appsSubnetPrefix '$ap' is smaller than /23 -- Container Apps needs a /23 or larger") }
    elseif ($vn -and -not $v.vnetId -and -not (Test-PimInstallCidrInside $as $vn)) { $err.Add("appsSubnetPrefix '$ap' is not inside the VNet '$vnetPfx'") }
    # the private endpoints subnet (private only): default = the /26 right after the apps subnet
    $en = & $s 'endpointsSubnetName'; $ep = & $s 'endpointsSubnetPrefix'
    $v.endpointsSubnetName = ''; $v.endpointsSubnetPrefix = ''
    if ($private) {
        if ($en -and $en -notmatch $snRx) { $err.Add("-EndpointsSubnetName '$en' is not a subnet name") }
        if ($en -and $en -ieq $(if ($an) { $an } else { 'snet-pim-aca' })) { $err.Add('-AppsSubnetName and -EndpointsSubnetName must be two different subnets') }
        if (-not $ep -and $as) {
            $next = ConvertFrom-PimInstallCidr (ConvertTo-PimInstallCidrText ($as.End + 1) 26)
            if ($next -and ($v.vnetId -or (Test-PimInstallCidrInside $next $vn))) { $ep = $next.Text }
            elseif (-not $v.vnetId -and $vn) { $err.Add("there is no room for the private endpoints subnet after '$ap' in the VNet '$vnetPfx' -- give -EndpointsSubnetPrefix (a /28 or larger inside the VNet)") }
        }
        if ($ep) {
            $es = ConvertFrom-PimInstallCidr $ep
            if (-not $es) { $err.Add("endpointsSubnetPrefix '$ep' is not an IPv4 CIDR (a.b.c.d/n, the network address itself)") }
            elseif ($es.Length -gt 28) { $err.Add("endpointsSubnetPrefix '$ep' is too small: at least a /28") }
            elseif (Test-PimInstallCidrOverlap $es $as) { $err.Add("-AppsSubnetPrefix $ap and -EndpointsSubnetPrefix $ep overlap") }
            elseif ($vn -and -not $v.vnetId -and -not (Test-PimInstallCidrInside $es $vn)) { $err.Add("endpointsSubnetPrefix '$ep' is not inside the VNet '$vnetPfx'") }
        }
        $v.endpointsSubnetName = $en; $v.endpointsSubnetPrefix = $ep
    }
    # the customer's central privatelink zones: used, never created or written
    $zr = & $s 'privateDnsZonesResourceGroupId'
    $v.privateDnsZonesResourceGroupId = ''
    if ($zr -and $private) {
        if ($zr -notmatch $rgRx) { $err.Add("-PrivateDnsZonesResourceGroupId '$zr' is not a resource group id (/subscriptions/<id>/resourceGroups/<name>)") }
        else { $v.privateDnsZonesResourceGroupId = $zr.TrimEnd('/') }
    }
    # the hub: peering and zone links are both OFF unless asked
    $hid = & $s 'hubVnetId'
    $v.hubVnetId = ''; $v.linkZonesToHub = [bool]($private -and (& $on 'linkZonesToHub')); $v.peerToHub = [bool]($private -and (& $on 'peerToHub'))
    if ($hid -and $private) {
        $hm = [regex]::Match($hid, $vnetRx)
        if (-not $hm.Success) { $err.Add("-HubVnetId '$hid' is not a virtual network resource id") }
        else {
            $v.hubVnetId = $hid.TrimEnd('/')
            $spokeId = if ($v.vnetId) { $v.vnetId } else { "/subscriptions/$("$SubscriptionId".Trim())/resourceGroups/$("$ResourceGroup".Trim())/providers/Microsoft.Network/virtualNetworks/$vnetName" }
            if ($v.hubVnetId -ieq $spokeId) { $err.Add('-HubVnetId is the same network as the PIM network -- the hub is the network your clients reach Azure through; PIM Manager runs in its own (spoke) network') }
        }
    } elseif ($v.linkZonesToHub -or $v.peerToHub) { $err.Add('-PeerToHub and -LinkZonesToHub need -HubVnetId') }
    return @{ errors = @($err); values = $v }
}

function Add-PimInstallNetworkDeployArgs {
    <#
      PURE. The network answers onto Invoke-PimDeployAll's EXISTING parameters (-DeployArgs is changed in place). Public: only a
      given -VnetName / -AppsSubnetName / -AppsSubnetPrefix replaces the default, so a public install's arguments are exactly
      what they were. -PrivateNetwork:
        Exposure internal (the engine then turns on the SQL private endpoint and a Premium registry by itself)
        VnetName / VnetResourceGroup             <- -VnetId (parsed; its own resource group) or -VnetName (the install's)
        SqlPublicAccessDisabled, AcrPublicAccess false, AcrAgentPoolName pimpool   <- private stays private (INSTALL-1 item 5)
        PeeringAllOrNothing / LinkZonesToHub     <- -PeerToHub / -LinkZonesToHub given
        PrereqVnetAddressPrefix                  <- -VnetAddressPrefix
        PrereqSubnetName / PrereqSubnetAddressPrefix <- -AppsSubnetName / -AppsSubnetPrefix (the Container Apps subnet)
        PrivateEndpointSubnetName / ...AddressPrefix <- -EndpointsSubnetName / -EndpointsSubnetPrefix
        PrivateDnsResourceGroup                  <- the install's resource group (PIM's own zones, never the hub's)
        PrivateDnsZonesResourceGroupId           <- -PrivateDnsZonesResourceGroupId (central zones: used, never created or written)
        HubVnetName / -ResourceGroup / -SubscriptionId <- -HubVnetId (parsed)
        SkipPeering                              <- NOT -PeerToHub      SkipZoneLinkToHub <- NOT -LinkZonesToHub
    #>
    param([Parameter(Mandatory)][System.Collections.IDictionary]$DeployArgs, [Parameter(Mandatory)][object]$Config, [string]$ResourceGroup = '')
    $p = { param($k) if ($Config.PSObject.Properties[$k]) { $Config.$k } else { $null } }
    if ("$(& $p 'vnetName')".Trim()) { $DeployArgs['VnetName'] = "$(& $p 'vnetName')".Trim() }
    if ("$(& $p 'appsSubnetPrefix')".Trim()) { $DeployArgs['PrereqSubnetAddressPrefix'] = "$(& $p 'appsSubnetPrefix')".Trim() }
    if ("$(& $p 'appsSubnetName')".Trim()) { $DeployArgs['PrereqSubnetName'] = "$(& $p 'appsSubnetName')".Trim() }
    if (-not [bool](& $p 'privateNetwork')) { return }
    $DeployArgs['Exposure'] = 'internal'
    if ("$ResourceGroup".Trim()) { $DeployArgs['VnetResourceGroup'] = "$ResourceGroup".Trim(); $DeployArgs['PrivateDnsResourceGroup'] = "$ResourceGroup".Trim() }
    # Invardia 2026-11-02: a -VnetId in another resource group of the subscription -- the VNet's own resource group
    if ("$(& $p 'vnetResourceGroup')".Trim()) { $DeployArgs['VnetResourceGroup'] = "$(& $p 'vnetResourceGroup')".Trim() }
    # PRIVATE STAYS PRIVATE (INSTALL-1 item 5 / Invardia DESIGN ch 12): SQL with no public endpoint and no firewall rule;
    # the registry Premium (the engine's internal default) with public access off, its images built on its agent pool
    # inside the network (the engine's private-registry path, as the managing-tenant build uses: acr.agentPoolName)
    $DeployArgs['SqlPublicAccessDisabled'] = $true
    $DeployArgs['AcrPublicAccess'] = 'false'
    $DeployArgs['AcrAgentPoolName'] = (Get-PimInstallAgentPoolName)
    if ("$(& $p 'endpointsSubnetName')".Trim()) { $DeployArgs['PrivateEndpointSubnetName'] = "$(& $p 'endpointsSubnetName')".Trim() }
    if ("$(& $p 'endpointsSubnetPrefix')".Trim()) { $DeployArgs['PrivateEndpointSubnetAddressPrefix'] = "$(& $p 'endpointsSubnetPrefix')".Trim() }
    if ("$(& $p 'privateDnsZonesResourceGroupId')".Trim()) { $DeployArgs['PrivateDnsZonesResourceGroupId'] = "$(& $p 'privateDnsZonesResourceGroupId')".Trim() }
    $hub = "$(& $p 'hubVnetId')".Trim()
    if ($hub -match '(?i)^/subscriptions/([^/]+)/resourceGroups/([^/]+)/providers/Microsoft\.Network/virtualNetworks/([^/]+)$') {
        $DeployArgs['HubVnetSubscriptionId'] = $Matches[1]; $DeployArgs['HubVnetResourceGroup'] = $Matches[2]; $DeployArgs['HubVnetName'] = $Matches[3]
        if (-not [bool](& $p 'peerToHub')) { $DeployArgs['SkipPeering'] = $true } else { $DeployArgs['PeeringAllOrNothing'] = $true }
        if (-not [bool](& $p 'linkZonesToHub')) { $DeployArgs['SkipZoneLinkToHub'] = $true } else { $DeployArgs['LinkZonesToHub'] = $true }
    }
}

function Get-PimInstallNetworkVerdict {
    <#
      PURE. The 'preflight-network' verdict of a -PrivateNetwork install, from what Azure answered (reads only, nothing is
      created yet). Returns @{ state; message; actionText; actionCommand }.
        -Vnet   the -VnetId network ($null = not there or not readable); not used when the installation makes its own
        -Hub    the -HubVnetId network ($null = not readable: a warning, the overlap is then not checked)
        -Zones  zone name -> $true / $false: is it in -PrivateDnsZonesResourceGroupId (central zones are never created)
      Failed: the network missing, in another region, a named subnet delegated to something else, a new subnet outside the
      network or overlapping one of its subnets, the PIM range overlapping the hub's, a central zone that is not there.
    #>
    param([Parameter(Mandatory)][object]$Config, [AllowNull()][object]$Vnet, [AllowNull()][object]$Hub, [hashtable]$Zones = @{})
    $fail = { param($m, $t = '', $c = '') @{ state = 'failed'; message = "$m -- nothing was created"; actionText = $t; actionCommand = $c } }
    $vid = "$($Config.vnetId)".Trim()
    $appsName = if ("$($Config.appsSubnetName)".Trim()) { "$($Config.appsSubnetName)".Trim() } else { 'snet-pim-aca' }
    $endName = if ("$($Config.endpointsSubnetName)".Trim()) { "$($Config.endpointsSubnetName)".Trim() } else { 'pim-endpoints' }
    $ranges = @()
    $notes = New-Object System.Collections.Generic.List[string]
    if ($vid) {
        if (-not $Vnet) { return (& $fail "the network $vid does not exist, or you cannot read it" 'Correct -VnetId (or leave it out: the installation then makes its own network):' '-VnetId /subscriptions/<id>/resourceGroups/<rg>/providers/Microsoft.Network/virtualNetworks/<name>') }
        $loc = "$($Vnet.location)".Replace(' ', '').ToLowerInvariant()
        if ($loc -and $loc -ne "$($Config.location)".ToLowerInvariant()) { return (& $fail "the network $($Vnet.name) is in '$($Vnet.location)' and PIM Manager is installed in '$($Config.location)' -- a private install needs its network in the same region" 'Install in the network''s region:' "-Location $loc") }
        $ranges = @(@($Vnet.properties.addressSpace.addressPrefixes) | ForEach-Object { ConvertFrom-PimInstallCidr "$_" } | Where-Object { $_ })
        $subs = @(@($Vnet.properties.subnets) | Where-Object { $_ })
        foreach ($role in @(@{ n = $appsName; p = "$($Config.appsSubnetPrefix)"; apps = $true; arg = 'AppsSubnetPrefix' }, @{ n = $endName; p = "$($Config.endpointsSubnetPrefix)"; apps = $false; arg = 'EndpointsSubnetPrefix' })) {
            $sub = @($subs | Where-Object { "$($_.name)" -ieq $role.n }) | Select-Object -First 1
            $dl = @(@($sub.properties.delegations) | ForEach-Object { "$($_.properties.serviceName)" } | Where-Object { $_ })
            if ($sub) {
                if ($role.apps -and $dl.Count -and $dl -notcontains 'Microsoft.App/environments') { return (& $fail "the subnet $($role.n) is delegated to $($dl -join ', ') -- the Container Apps environment needs a subnet delegated to Microsoft.App/environments, or an empty one") }
                if (-not $role.apps -and $dl.Count) { return (& $fail "the subnet $($role.n) is delegated to $($dl -join ', ') -- private endpoints need a subnet without a delegation") }
                $notes.Add("subnet $($role.n) is used as it is"); continue
            }
            $c = ConvertFrom-PimInstallCidr $role.p
            if (-not $c) { return (& $fail "the subnet $($role.n) is not in $($Vnet.name) and has no range to create it" "Give the range for it (a free range inside the network):" "-$($role.arg) <a.b.c.d/n>") }
            if (-not @($ranges | Where-Object { Test-PimInstallCidrInside $c $_ }).Count) { return (& $fail "-$($role.arg) $($role.p) is not inside the range of $($Vnet.name) ($(@($Vnet.properties.addressSpace.addressPrefixes) -join ', '))" "Give a free range inside the network:" "-$($role.arg) <a.b.c.d/n>") }
            foreach ($o in $subs) {
                foreach ($op in @(@($o.properties.addressPrefix) + @($o.properties.addressPrefixes) | Where-Object { $_ })) {
                    if (Test-PimInstallCidrOverlap $c (ConvertFrom-PimInstallCidr "$op")) { return (& $fail "-$($role.arg) $($role.p) overlaps the subnet $($o.name) ($op)" "Give a free range inside the network:" "-$($role.arg) <a.b.c.d/n>") }
                }
            }
            $notes.Add("subnet $($role.n) $($role.p) is created")
        }
    } else {
        $ranges = @(ConvertFrom-PimInstallCidr "$($Config.vnetAddressPrefix)" | Where-Object { $_ })
        $notes.Add("network $($Config.vnetName) $($Config.vnetAddressPrefix) is created")
    }
    $warn = ''
    if ("$($Config.hubVnetId)".Trim()) {
        if (-not $Hub) { $warn = "the hub $("$($Config.hubVnetId)" -replace '^.*/', '') could not be read, so its range was not compared with PIM's -- the peering is on the hand-off list" }
        else {
            foreach ($h in @($Hub.properties.addressSpace.addressPrefixes)) {
                foreach ($r in $ranges) { if (Test-PimInstallCidrOverlap (ConvertFrom-PimInstallCidr "$h") $r) { return (& $fail "the PIM network range $($r.Text) overlaps the hub's $h -- the two cannot be peered" 'Choose a range that is free in your network plan:' '-VnetAddressPrefix <a.b.c.d/n>') } }
            }
            $notes.Add("hub $($Hub.name): no overlap")
        }
    }
    if ("$($Config.privateDnsZonesResourceGroupId)".Trim()) {
        $missing = @(Get-PimInstallPrivateZoneNames | Where-Object { -not $Zones[$_] })
        # ALL missing zones in ONE message (framework installer rule 8): never one at a time across reruns
        if ($missing.Count) {
            $zg = "$($Config.privateDnsZonesResourceGroupId)".Trim()
            return (& $fail ("$(if ($missing.Count -eq 1) { 'the zone' } else { "$($missing.Count) zones" }) $($missing -join ', ') $(if ($missing.Count -eq 1) { 'is' } else { 'are' }) not in $zg -- the installation and its updater use your central zones and never create them") `
                ("Create these zones in $zg, or leave -PrivateDnsZonesResourceGroupId out and PIM makes its own:") "privatelink zone(s): $($missing -join ', ')")
        }
        $notes.Add("central zone(s) $(@(Get-PimInstallPrivateZoneNames) -join ', ') found (used, never changed)")
    }
    if ($warn) { return @{ state = 'warning'; message = "$warn; $($notes -join '; ')"; actionText = ''; actionCommand = '' } }
    return @{ state = 'ok'; message = "private network: $($notes -join '; ')"; actionText = ''; actionCommand = '' }
}

function Get-PimInstallConvertDecision {
    <#
      PURE. Public -> private (Invardia 2026-11-02: "the SAME two lines + -PrivateNetwork on an existing PUBLIC PIM install
      converts it"). -Environment = this install's Container Apps environment as ARM answered ($null = not there).
      Returns @{ convert; refuse; reason }:
        public run, or no environment yet, or already internal  -> nothing to convert (the deploy builds / keeps it)
        -PrivateNetwork + an EXTERNAL environment                -> convert (Convert-PimToPrivate.ps1 underneath)
        ...with -VnetId                                          -> refused: an existing install keeps its own network
    #>
    param([Parameter(Mandatory)][object]$Config, [AllowNull()][object]$Environment)
    if (-not [bool]$Config.privateNetwork -or -not $Environment) { return @{ convert = $false; refuse = $false; reason = '' } }
    $internal = "$($Environment.properties.vnetConfiguration.internal)" -eq 'True'
    if ($internal) { return @{ convert = $false; refuse = $false; reason = 'the Container Apps environment is already internal' } }
    if ("$($Config.vnetId)".Trim()) { return @{ convert = $true; refuse = $true; reason = "this installation is PUBLIC today in its own network; converting it keeps that network -- leave -VnetId out (the conversion cannot move it to $(("$($Config.vnetId)" -split '/')[-1]))" } }
    return @{ convert = $true; refuse = $false; reason = 'this installation is PUBLIC today: it is converted to the private network first (Convert-PimToPrivate.ps1, run by the installation), data kept' }
}

function ConvertTo-PimInstallConvertArgs {
    <#
      PURE. The Convert-PimToPrivate.ps1 parameters for a public -> private conversion, from the same answers and names the
      install uses (the customer never runs it by hand). Route Redeploy, the registry private on its agent pool, the SQL
      private endpoint with its public access off at the end (-SqlPrivate), the hub as given. -Resume continues a
      conversion that stopped (and says the hub side is done -- the customer re-runs after the network team acted).
    #>
    param([Parameter(Mandatory)][object]$Config, [Parameter(Mandatory)][object]$Names, [string[]]$PortalUsers = @(), [switch]$AllMembers, [switch]$Resume)
    $a = @{ TenantId = $Config.tenantId; SubscriptionId = $Config.subscriptionId; ResourceGroup = $Names.resourceGroup; Route = 'Redeploy'
                     Tag = $Names.token; Location = $Config.location; VnetName = $Config.vnetName; VnetResourceGroup = $Names.resourceGroup
                     VnetAddressPrefix = $Config.vnetAddressPrefix; SubnetAddressPrefix = $Config.appsSubnetPrefix; AcrName = $Names.acr
                     LogAnalyticsName = $Names.logAnalytics; SqlServerFqdn = $Names.sqlFqdn; SqlDatabase = $Names.sqlDatabase
                     EnvName = $Names.environment; ManagerApp = $Names.managerApp; AcrAgentPoolName = (Get-PimInstallAgentPoolName)
                     PrivateDnsResourceGroup = $Names.resourceGroup; SqlPrivate = $true; Apply = $true }
    if ("$($Config.appsSubnetName)".Trim()) { $a['SubnetName'] = "$($Config.appsSubnetName)".Trim() }
    if ("$($Config.endpointsSubnetName)".Trim()) { $a['PrivateEndpointSubnetName'] = "$($Config.endpointsSubnetName)".Trim() }
    if ("$($Config.endpointsSubnetPrefix)".Trim()) { $a['PrivateEndpointSubnetAddressPrefix'] = "$($Config.endpointsSubnetPrefix)".Trim() }
    if ("$($Config.hubVnetId)".Trim()) {
        $a['HubVnetId'] = @("$($Config.hubVnetId)".Trim())
        if (-not [bool]$Config.peerToHub) { $a['SkipPeering'] = $true }
    }
    if ($AllMembers) { $a['EasyAuthAllowAllTenantUsers'] = $true } elseif (@($PortalUsers).Count) { $a['EasyAuthAllowedPrincipals'] = @($PortalUsers) }
    if ($Resume) { $a['Resume'] = $true; if ($a.Contains('SkipPeering')) { $a['HubSideDone'] = $true } }
    return $a
}

function Get-PimInstallNetworkHandoff {
    <#
      PURE. The network hand-off of a -PrivateNetwork install (EPS DESIGN §2b: "the network hand-off list is printed"): what
      the customer's network team does so people reach the PIM Manager -- peering, DNS for the PIM Manager's name, DNS for
      the database's private endpoint, and where later setup scripts must run. @() for a public install.
    #>
    param([Parameter(Mandatory)][object]$Config, [Parameter(Mandatory)][object]$Names, [string]$PortalFqdn = '')
    if (-not [bool]$Config.privateNetwork) { return @() }
    $rg = "$($Names.resourceGroup)"
    $spoke = if ("$($Config.vnetId)".Trim()) { "$($Config.vnetId)".Trim() } else { "/subscriptions/$($Config.subscriptionId)/resourceGroups/$rg/providers/Microsoft.Network/virtualNetworks/$($Config.vnetName)" }
    $hub = "$($Config.hubVnetId)".Trim(); $hubName = $hub -replace '^.*/', ''
    $who = if ("$PortalFqdn".Trim()) { "$PortalFqdn".Trim() } else { 'the PIM Manager' }
    $l = New-Object System.Collections.Generic.List[string]
    $l.Add("PIM Manager runs in a private network ($spoke): $who has no public address -- it answers only inside that network and the networks peered to it.")
    if ($hub -and $Config.peerToHub) { $l.Add("Peering: made with the hub $hubName by the installation (both sides) -- check that it shows Connected.") }
    elseif ($hub) { $l.Add("Peering: peer $spoke with the hub $hub, both directions (allow virtual network access). New-PimHubPrepareScript.ps1 writes the script the hub owner runs for the hub side.") }
    else { $l.Add("Peering: peer $spoke with the network your users reach Azure from, both directions -- no -HubVnetId was given, so nothing was peered.") }
    $central = "$($Config.privateDnsZonesResourceGroupId)".Trim()
    $own = if ($central) { "the Container Apps environment's default domain" } else { "the Container Apps environment's default domain, privatelink.database.windows.net and privatelink.azurecr.io" }
    if ($hub -and $Config.linkZonesToHub) { $l.Add("DNS for $($who): PIM Manager's own private zones ($own; resource group $rg) are linked to the hub $hubName by the installation.") }
    else { $l.Add("DNS for $($who): link PIM Manager's own private zones ($own; resource group $rg) to the network your clients resolve names in, or forward those names from your DNS servers to 168.63.129.16 inside a linked network.") }
    if ($central) { $l.Add("DNS for the database and the registry: $($Names.sqlFqdn) and $($Names.acr).azurecr.io are registered by their private endpoints in your zones privatelink.database.windows.net and privatelink.azurecr.io ($central); those zones must answer inside $($Config.vnetName) (a link to it, or your DNS servers). The installation created and changed nothing in that resource group. The as-built report's storage is made private by the updater later, with its private endpoint registered in your zone privatelink.blob.core.windows.net there too (used, never created).") }
    else { $l.Add("DNS for the database and the registry: the zones privatelink.database.windows.net and privatelink.azurecr.io in resource group $rg answer inside $($Config.vnetName); outside it $($Names.sqlFqdn) resolves to the private address only through your DNS. Both have NO public access -- the database and the registry are reached only through their private endpoints.") }
    $l.Add('Run later PIM Manager setup scripts that reach the database (and a -Resume of this installation) from a machine inside that network or one peered to it.')
    return @($l)
}

function Set-PimInstallEditionSetting {
    <#
      INSTALL-1 GAP (2026-11-02): record the edition this environment was INSTALLED as in pim.Settings 'InstallEdition'
      ("trial" | "pro", a JSON string) so the licence-request job knows a fresh, still unlicensed trial / Pro install is meant
      to be Pro and knocks at Invardia on its first tick (Invoke-PimLicenceRequestCycle). Community writes NOTHING -- a
      Community install never knocks (owner 2026-10-16). Idempotent (one MERGE; a -Resume writes the same value again),
      read back. -Sql = param([string]$Sql) -> one scalar, as the installer (New-PimInstallSigninFrontIo's Sql).
      Returns @{ ok; written; value; reason }. Never throws.
    #>
    param([AllowNull()][string]$Edition, [Parameter(Mandatory)][scriptblock]$Sql)
    $e = "$Edition".Trim().ToLowerInvariant()
    if ($e -notin 'trial', 'pro') { return @{ ok = $true; written = $false; value = ''; reason = 'the Community edition records no install edition (it never requests a licence)' } }
    $json = '"' + $e + '"'   # a fixed literal from the two names above -- never caller text in the statement
    try {
        [void](& $Sql ("MERGE pim.Settings WITH (HOLDLOCK) AS t USING (SELECT N'InstallEdition' AS Name, N'$json' AS V) AS s ON t.Name = s.Name " +
                       "WHEN MATCHED AND (t.ValueJson IS NULL OR t.ValueJson <> s.V) THEN UPDATE SET ValueJson = s.V, UpdatedUtc = SYSUTCDATETIME() " +
                       "WHEN NOT MATCHED THEN INSERT (Name, ValueJson, UpdatedUtc) VALUES (s.Name, s.V, SYSUTCDATETIME());"))
        $back = "$(& $Sql "SELECT ValueJson FROM pim.Settings WHERE Name = N'InstallEdition'")".Trim()
    } catch { return @{ ok = $false; written = $false; value = $e; reason = "the install edition could not be recorded: $((("$($_.Exception.Message)") -split "`n")[0])" } }
    if ($back -ne $json) { return @{ ok = $false; written = $false; value = $e; reason = "the install edition was not read back (found '$back')" } }
    return @{ ok = $true; written = $true; value = $e; reason = "recorded as a $e installation -- it asks Invardia for its licence by itself" }
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
      a subscription only returns the ones in its own hierarchy. 2026-10-11 (a demo environment): the old test was a string prefix
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
      The installation's OWN state file (state.json in -StatePath): @{ installId; completed[]; updatedUtc; setupHostRule }.
      Missing or unreadable = empty. REQ 98.4 (b): setupHostRule (@{ name; server; resourceGroup; subscriptionId; openedUtc }:
      the SQL firewall rule THIS install opened) is optional -- a state file written before it reads as $null and still resumes.
      An older file's licencePath is ignored (ONE-LINE-INSTALL: the install never takes a licence).
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
                                      setupHostRule = $hr }
        } catch { }
    }
    return [pscustomobject]@{ installId = ''; completed = @(); updatedUtc = ''; setupHostRule = $null }
}

function Save-PimInstallState {
    # Never a licence, a key or a token -- nothing secret is written to this file.
    param([Parameter(Mandatory)][string]$StatePath, [Parameter(Mandatory)][string]$InstallId, [string[]]$Completed = @(),
          [System.Collections.IDictionary]$SetupHostRule)
    if (-not (Test-Path -LiteralPath $StatePath)) { New-Item -ItemType Directory -Force -Path $StatePath | Out-Null }
    $doc = [ordered]@{ schema = 1; installId = $InstallId; completed = @($Completed | Select-Object -Unique); updatedUtc = [datetime]::UtcNow.ToString('o') }
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
                  actionText = 'Correct the administrator''s sign-in name (-SuperAdmins), then run the installation again:'; actionCommand = '-SuperAdmins admin@contoso.com' }
    }
    $unknown = @($list | Where-Object { $null -eq $_.found } | ForEach-Object { "$($_.upn)".Trim() })
    if ($unknown.Count) { return @{ state = 'warning'; message = "could not be checked in the tenant: $($unknown -join ', ') -- the sign-in step will tell" } }
    if (-not $list.Count) { return @{ state = 'ok'; message = 'no administrator to check' } }
    $withMail = @($list | Where-Object { "$($_.mail)".Trim() } | ForEach-Object { "$($_.mail)".Trim() })
    if (-not $rec.Count -and -not $withMail.Count) {
        # kind 'no-mailbox': the caller makes this a reminder (not a stop) for an installation that completed before -- its
        # recipients may have been set in the PIM Manager since, which a preflight cannot read
        return @{ state = 'failed'; kind = 'no-mailbox'; message = "no PIM Manager administrator has a mailbox ($(@($list | ForEach-Object { "$($_.upn)".Trim() }) -join ', ')) and no alert recipients were given -- the alerts would reach nobody; nothing was created"
                  actionText = 'Add the address that receives the alerts (-AlertRecipients), then run the installation again:'; actionCommand = '-AlertRecipients alerts@contoso.com' }
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
