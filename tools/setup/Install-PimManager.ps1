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
       config.json names one, runs the END-OF-INSTALL CHECK ('verify-install', Confirm-PimInstall.ps1: SuperAdmins, updater +
       ring, licence + install key, mail sender + both sending identities in scope, alert recipients, the engine's Graph
       rights + Reader at the tenant root, sign-in, the SQL window; repairs what it can; a failed required line = exit 1
       with that line's fix), checks health, and reports 'completed' with the outputs Invardia's support needs -> exit 0
  A step that needs a higher role than the installer holds ends as a WARNING with the command for the right person; the
  install continues. -Resume re-runs from where it stopped: completed preflight / licence / support steps are skipped,
  and the deploy itself is idempotent (each of its steps checks what exists first).

  ENROLLMENT KEY instead of a licence file (framework 8.6 "SINGLE-TENANT enrollment too", owner 2026-10-08): with
  'enrollmentKey' in config.json (or -EnrollmentKey) -LicencePath is not needed. After the preflight, step 'enroll' claims
  this tenant at Invardia FIRST (the environment is created under the customer, the licence signed -- asked again until
  ready -- and an install key issued); step 'licence' registers that licence and stores the install key (from files in a
  restricted per-run folder). A managed-tenant key, a refused key, or Invardia not issuing single-tenant enrollment yet =
  exit 3 with one plain sentence, nothing deployed. The key is never printed (masked) and is removed from config.json once
  the licence is registered.

  Reporter events: @{ installId; step = @{ id; title }; state = started|ok|warning|failed|skipped|completed; message;
  action = @{ text; command }; detail; outputs }. The bootstrap adds seq and at. This script never calls invardia.com.

.EXAMPLE
  ./Install-PimManager.ps1 -ConfigPath ~/clouddrive/invardia/ab12/config.json -LicencePath ~/clouddrive/invardia/ab12/Contoso.pimlicense `
      -Reporter { param($e) "$($e.step.id) $($e.state) $($e.message)" | Write-Host }
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$ConfigPath,
    # The licence file -- required unless the answers carry an Invardia enrollment key (config 'enrollmentKey', or
    # -EnrollmentKey): then the licence comes from the enrollment (framework 8.6 "SINGLE-TENANT enrollment too").
    [string]$LicencePath = '',
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
    [scriptblock]$Http,
    # INSTALL-HARDEN-1: param([hashtable]$VerifyArgs) -> @{ done; failed[]; warnings[]; sentence; rows[] } (Confirm-PimInstall.ps1)
    [scriptblock]$VerifyInstall,
    # framework 8.6: the enrollment key on the command line (else config.json 'enrollmentKey'). Never printed (masked).
    [string]$EnrollmentKey = '',
    [string]$InvardiaBaseUrl = "$($env:PIM_INVARDIA_BASE_URL)",
    # --- test seams: Invardia (param($method, $url, $body, $headers) -> @{ status; body }) and the licence-poll wait ---
    [scriptblock]$EnrollmentHttp,
    [scriptblock]$EnrollmentSleep,
    [int]$EnrollmentTimeoutSeconds = 900,
    # test seam: param([hashtable]$MspArgs, [scriptblock]$OnStep) -> exit code, in place of Invoke-PimMspBuild (mspRole managed)
    [scriptblock]$MspBuild
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
$script:enrolDir = ''
function Finish([int]$Code) {
    # framework 8.6: the per-run directory with the claimed licence + install key never outlives the run.
    if ($script:enrolDir) { Remove-PimEnrollmentRunDirectory -Path $script:enrolDir; $script:enrolDir = '' }
    $global:LASTEXITCODE = $Code; exit $Code
}

# ================================================================== 1. config + licence
Emit 'config' 'started'
$raw = $null
try { $raw = Get-Content -Raw -LiteralPath $ConfigPath -ErrorAction Stop | ConvertFrom-Json } catch { $raw = $null }
$chk = Test-PimInstallConfig -Config $raw -HasEnrollmentKey:([bool]"$EnrollmentKey".Trim())
if (-not $chk.ok) { Emit 'config' 'failed' ("the answers cannot be used: " + (@($chk.errors) -join '; ')) 'Correct the answers in the wizard and download the command again.'; Finish 3 }
$cfg = $chk.config
$installId = $cfg.installId
# framework 8.6 "SINGLE-TENANT enrollment too": the enrollment key lives in THIS variable only (never in $cfg).
$enrolKey = if ("$EnrollmentKey".Trim()) { "$EnrollmentKey".Trim() } else { "$($chk.enrollmentKey)" }
$enrolKeyInConfig = [bool]"$($chk.enrollmentKey)"
$EnrollmentKey = ''; $chk.enrollmentKey = ''
# ONE CLAIMANT PER INSTALL (Invardia 2026-10-08): every claim kills the previous install key. Answers that already carry
# installKey were claimed by Invardia's bootstrap (Install-Invardia -EnrollmentKey) -- this install then NEVER claims; an
# enrollment key beside it is informational only and is never sent.
if ($enrolKey -and "$($cfg.installKey)".Trim()) { $enrolKey = ''; $enrolKeyInConfig = $false }
if ($chk.enrollmentKeyIgnored -or (-not $enrolKey -and "$($cfg.installKey)".Trim() -and "$($raw.enrollmentKey)".Trim())) { Write-Host '    the enrollment key is not used: Invardia''s installer already claimed this installation (installKey is in the answers) -- nothing is claimed again' -ForegroundColor DarkGray }
$enrolling = [bool]$enrolKey
if ($enrolling -or "$($cfg.mspRole)" -eq 'managed') { $enrolLib = Join-Path $sol 'engine\msp\PIM-InvardiaEnrollment.ps1'; if (Test-Path -LiteralPath $enrolLib) { . $enrolLib } else { Emit 'config' 'failed' 'enrollment keys and managed tenants come with PIM Manager Pro; this copy is the Community edition' 'Install with the licence file, or download PIM Manager Pro from invardia.com.'; Finish 3 } }
if ($enrolling -and -not (Test-PimEnrollmentKeyFormat -Key $enrolKey)) { Emit 'config' 'failed' 'the enrollment key is not an Invardia enrollment key (ek- followed by 43 letters, digits, - or _)' 'Copy the key again from invardia.com and download the command again.'; Finish 3 }
if (-not "$StatePath".Trim()) {
    $homeDir = if ($env:HOME) { $env:HOME } else { $env:USERPROFILE }
    $base = if (Test-Path -LiteralPath (Join-Path $homeDir 'clouddrive')) { Join-Path $homeDir 'clouddrive' } else { $homeDir }
    $StatePath = Join-Path (Join-Path $base 'invardia') $installId
}
$state = Read-PimInstallState -StatePath $StatePath
$done = New-Object System.Collections.Generic.List[string]
if ($Resume -and $state.installId -eq $installId) { foreach ($c in $state.completed) { $done.Add("$c") | Out-Null } }
function Mark([string]$Id) { if (-not $done.Contains($Id)) { $done.Add($Id) | Out-Null }; Save-PimInstallState -StatePath $StatePath -InstallId $installId -Completed @($done) }
$resumeCmd = if ($enrolling -and -not "$LicencePath".Trim()) { "Install-PimManager -ConfigPath '$ConfigPath' -StatePath '$StatePath' -Resume" } else { "Install-PimManager -ConfigPath '$ConfigPath' -LicencePath '$LicencePath' -StatePath '$StatePath' -Resume" }

# the licence: a Pro licence for THIS tenant, verifiable offline. Anything else is a bad bundle (exit 3).
function Get-InstallLicenceProblem([string]$Text, [string]$What) {
    $l = $null
    try { if ("$Text".Trim()) { $l = if ($TestLicenceCertB64) { Get-PimLicense -LicenseText $Text -PublicCertB64 $TestLicenceCertB64 } else { Get-PimLicense -LicenseText $Text } } } catch { $l = $null }
    $why = if (-not $l) { "$What could not be read" }
           elseif ("$($l.Status)" -notin 'Valid', 'Grace') { "the licence is $($l.Status): $($l.Reason)" }
           elseif ("$($l.Sku)" -notmatch '^(?i)pro(-.+)?$') { "the licence is a '$($l.Sku)' licence, not Pro" }
           elseif (-not ($b = Test-PimLicenseTenantBinding -License $l -TenantId $cfg.tenantId).ok) { $b.reason }   # LIC anti-copy: bound, and to THIS tenant
           else { '' }
    return @{ lic = $l; why = $why }
}
$lic = $null; $licText = ''
$licenceDone = $done.Contains('licence')
if ($enrolling) {
    # framework 8.6: the licence comes from the enrollment (claimed after the preflight, step 'enroll'); a licence file is not used.
    if ("$LicencePath".Trim()) { Write-Host "    the licence file '$LicencePath' is not used: the enrollment returns this tenant's licence" -ForegroundColor Yellow }
    Write-Host ("    enrollment key: {0} -- sent only in the claim to Invardia, never written to a log, the state file or the support outputs" -f (Get-PimEnrollmentKeyMask -Key $enrolKey)) -ForegroundColor DarkGray
    Emit 'config' 'ok' ("installing into resource group '$($cfg.resourceGroup)' in $($cfg.location); licence: from your Invardia enrollment (after the checks)") -Detail @{ resourceGroup = $cfg.resourceGroup; location = $cfg.location; edition = $cfg.edition }
} elseif (-not "$LicencePath".Trim() -and $licenceDone) {
    Emit 'config' 'ok' ("installing into resource group '$($cfg.resourceGroup)' in $($cfg.location); licence: already registered (resume)") -Detail @{ resourceGroup = $cfg.resourceGroup; location = $cfg.location; edition = $cfg.edition }
} else {
    if (-not "$LicencePath".Trim()) { Emit 'config' 'failed' 'no licence: give the licence file (-LicencePath) or an Invardia enrollment key (enrollmentKey in the answers)' 'Download the installation bundle again from invardia.com, or contact support.'; Finish 3 }
    try { $licText = Get-Content -Raw -LiteralPath $LicencePath -ErrorAction Stop } catch { $licText = '' }
    $lp = Get-InstallLicenceProblem -Text $licText -What "the licence file '$LicencePath'"
    $lic = $lp.lic
    if ($lp.why) { Emit 'config' 'failed' $lp.why 'Download the installation bundle again from invardia.com, or contact support.'; Finish 3 }
    Emit 'config' 'ok' ("installing into resource group '$($cfg.resourceGroup)' in $($cfg.location); licence: $($lic.Customer), valid until $($lic.ValidTo)") -Detail @{ resourceGroup = $cfg.resourceGroup; location = $cfg.location; edition = $cfg.edition }
}
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
    # 2026-10-06 (SI finding K): with no superAdmins named, the PERSON who installs becomes the Manager's first SuperAdmin.
    # The Invardia Support app is an application -- it must never be that admin. Refused before anything is written.
    if ("$($script:who.supportAppId)".Trim() -and -not @($cfg.superAdmins | Where-Object { "$_".Trim() }).Count) {
        return @{ state = 'failed'; message = 'the installation runs as the Invardia Support app, so it cannot make the installer the PIM Manager administrator -- name at least one person in superAdmins'; actionText = 'Add the administrator''s sign-in name to config.json, then resume:'; actionCommand = '"superAdmins": ["admin@contoso.com"]' }
    }
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
    $v = Get-PimInstallRightsVerdict -AzureRoles $roles -DirectoryRoleTemplateIds $tpl -AppRoles $appRoles
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

# ================================================================== 2b. framework 8.6: the ENROLLMENT (single tenant)
# Claimed FIRST -- before anything is deployed: Invardia creates this environment under the customer, signs its licence
# (asynchronously; asked again until ready) and issues the install key. A managed-tenant key (the answer carries a managing
# block), a refused key, or Invardia not issuing single-tenant enrollment yet = exit 3 with one plain sentence; nothing is
# deployed. Every claim issues a NEW install key, so once the licence step has stored one a resume does not claim again.
$enrolLicPath = ''; $enrolKeyPath = ''; $alreadyInstalled = $false
$managedInstall = ("$($cfg.mspRole)" -eq 'managed')
if ($enrolling -and -not $managedInstall) {
    if ($licenceDone) { Emit 'enroll' 'skipped' 'already linked and licensed (resume) -- not claimed again, so the stored install key stays valid' }
    else {
        Emit 'enroll' 'started'
        $script:enrolDir = New-PimEnrollmentRunDirectory
        $eh = if ($EnrollmentHttp) { $EnrollmentHttp } else { { param($m, $u, $b, $h) Invoke-PimEnrollmentHttp -Method $m -Url $u -Body $b -Headers $h } }
        $es = if ($EnrollmentSleep) { $EnrollmentSleep } else { { param($sec) Start-Sleep -Seconds $sec } }
        $eb = ''; try { $eb = Resolve-PimEnrollmentBaseUrl -BaseUrl $InvardiaBaseUrl } catch { Emit 'enroll' 'failed' "$($_.Exception.Message)"; Finish 3 }
        $sc = Invoke-PimEnrollmentSingleClaim -Http $eh -BaseUrl $eb -EnrollmentKey $enrolKey -TenantId $cfg.tenantId -SubscriptionId $cfg.subscriptionId -Directory $script:enrolDir `
                -TimeoutSeconds $EnrollmentTimeoutSeconds -Sleep $es -Progress { param($msg) Emit 'enroll' 'waiting' "$msg" }
        $enrolKey = ''   # used once
        if (-not $sc.ok -and $sc.alreadyInstalled) {
            # Owner 2026-10-08: the install already succeeded with this key -- no new key; the stored licence + key are kept and
            # the install goes on as a re-run of the existing one (the deploy is idempotent; the licence step is skipped).
            $alreadyInstalled = $true
            Emit 'enroll' 'warning' "$($sc.reason)"
        } elseif (-not $sc.ok) {
            Emit 'enroll' 'failed' "$($sc.reason)" $(if ($sc.refused) { 'Nothing was installed. Check the key, or install with the licence file:' } else { 'Nothing was installed yet. Resume when Invardia answers:' }) $(if ($sc.refused) { "Install-PimManager -ConfigPath '$ConfigPath' -LicencePath <licence file>" } else { $resumeCmd })
            Finish $(if ($sc.refused) { 3 } else { 1 })
        }
        if (-not $alreadyInstalled) {
        $lp = Get-InstallLicenceProblem -Text $sc.licenceText -What 'the licence Invardia returned'
        if ($lp.why) { Emit 'enroll' 'failed' "the enrollment's licence cannot be used: $($lp.why)" 'Contact Invardia support (support@invardia.com); nothing was installed.'; Finish 3 }
        $lic = $lp.lic
        $enrolLicPath = $sc.licencePath; $enrolKeyPath = $sc.installKeyPath
        Emit 'enroll' 'ok' "linked to your Invardia account as environment '$($sc.environmentHandle)'; licence: $($lic.Customer), valid until $($lic.ValidTo)"
        }
    }
}

# ================================================================== 2c. framework 8.6: a MANAGED tenant of an MSP
# Owner 2026-10-08: the customer receives ONE command when the managing company issues an enrollment key. With mspRole
# 'managed' this install IS the managed-tenant build (Invoke-PimMspBuild -Role Slave, signed-in, -EnrollmentKey): claim ->
# licence + install key -> link to the managing tenant from the claim's managing block -> pull subnet reported -> pull job.
# Nothing is re-implemented here; every step of that build reaches -Reporter with its own id and title.
$mspCode = $null
if ($managedInstall) {
    $script:enrolDir = New-PimEnrollmentRunDirectory
    $bootLic = ''; $bootKey = ''
    if (-not $enrolling) {
        # Invardia's bootstrap claimed: its licence file + the install key (written to a FILE here; the build reads the file)
        # go to the build's licence step, the handed-over managing block is the master{} block, and NOTHING claims again.
        $bootLic = Join-Path $script:enrolDir 'bootstrap.pimlicense'; [IO.File]::WriteAllText($bootLic, "$licText", (New-Object Text.UTF8Encoding($false)))
        $bootKey = Join-Path $script:enrolDir 'bootstrap.installkey'; [IO.File]::WriteAllText($bootKey, "$($cfg.installKey)", (New-Object Text.UTF8Encoding($false)))
    }
    $mspCfg = ConvertTo-PimInstallMspSlaveConfig -Config $cfg -SignedInUpn $who.userName -LicencePath $bootLic -InstallKeyPath $bootKey
    $mspCfgPath = Join-Path $script:enrolDir 'managed-tenant.json'   # ids, names and file PATHS only -- never a key
    [IO.File]::WriteAllText($mspCfgPath, ($mspCfg | ConvertTo-Json -Depth 8), (New-Object Text.UTF8Encoding($false)))
    $mspArgs = @{ Role = 'Slave'; ConfigPath = $mspCfgPath; Apply = $true; InvardiaInstallToken = ''; EnrollmentTimeoutSeconds = $EnrollmentTimeoutSeconds }
    if ($enrolling) { $mspArgs['EnrollmentKey'] = $enrolKey }
    if ("$InvardiaBaseUrl".Trim()) { $mspArgs['InvardiaBaseUrl'] = "$InvardiaBaseUrl".Trim() }
    if ($EnrollmentHttp) { $mspArgs['EnrollmentHttp'] = $EnrollmentHttp }
    if ($EnrollmentSleep) { $mspArgs['EnrollmentSleep'] = $EnrollmentSleep }
    $enrolKey = ''
    $mspOnStep = { param($ev)
        $st = "$($ev.state)"; if ($st -notin 'started', 'ok', 'warning', 'failed', 'skipped', 'waiting') { return }
        $a = @{ StepId = "$($ev.key)"; State = $st; Message = "$($ev.detail)"; Title = "$($ev.name)"; InstallId = $installId }
        if ($st -eq 'failed') { $a['ActionText'] = 'Fix the cause above, then resume the installation:'; $a['ActionCommand'] = $resumeCmd }
        Send-Event (New-PimInstallEvent @a)
    }
    if (-not $MspBuild) { $MspBuild = { param([hashtable]$A, [scriptblock]$OnStep) $global:LASTEXITCODE = 0; & (Join-Path $here 'Invoke-PimMspBuild.ps1') @A -OnStep $OnStep | Out-Host; [int]$LASTEXITCODE } }
    try { $mspCode = @(& $MspBuild $mspArgs $mspOnStep) | Select-Object -Last 1 } catch { Emit 'verify' 'failed' "the managed-tenant build stopped: $($_.Exception.Message)" 'Fix the cause above, then resume the installation:' $resumeCmd; Finish 1 }
    $mspArgs = $null
    if ([int]$mspCode -notin 0, 2) {
        if (-not @($events | Where-Object { $_.state -eq 'failed' }).Count) { Emit 'verify' 'failed' "the managed-tenant build did not complete (exit $mspCode)" 'Fix the cause above, then resume the installation:' $resumeCmd }
        Finish $(if (@($events | Where-Object { $_.state -eq 'failed' -and "$($_.step.id)" -eq 'enroll' }).Count) { 3 } else { 1 })
    }
    Mark 'licence'
    if ("$($raw.enrollmentKey)".Trim()) { try { if (Remove-PimInstallConfigEnrollmentKey -ConfigPath $ConfigPath) { Write-Host '    the enrollment key was removed from config.json (it is no longer needed)' -ForegroundColor DarkGray } } catch { Write-Host '    could not remove the enrollment key from config.json -- delete that line yourself' -ForegroundColor Yellow } }
}

if (-not $managedInstall) {# ================================================================== 3. deploy
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
elseif ($alreadyInstalled) { Emit 'licence' 'skipped' 'already installed with this enrollment key: the stored licence and install key are kept'; Mark 'licence' }
else {
    Emit 'licence' 'started'
    # framework 8.6: an enrolled install hands the install key over as a FILE (-InstallKeyPath), never as an argument.
    if (-not $InstallLicence) { $InstallLicence = { param($Path, $SqlFqdn, $TenantId, $Key, $KeyPath)
        if ("$KeyPath".Trim()) { & (Join-Path $here 'Set-PimLicense.ps1') -LicensePath $Path -SqlServer $SqlFqdn -TenantId $TenantId -UseSignedInAccount -InstallKeyPath "$KeyPath" | Out-Host }
        else { & (Join-Path $here 'Set-PimLicense.ps1') -LicensePath $Path -SqlServer $SqlFqdn -TenantId $TenantId -UseSignedInAccount -InstallKey "$Key" -QueueInstallKeyClaim:(-not "$Key".Trim()) | Out-Host }
        @{ ok = (-not $LASTEXITCODE) } } }
    $lr = if ($enrolling) { & $InstallLicence $enrolLicPath $names.sqlFqdn $cfg.tenantId '' $enrolKeyPath } else { & $InstallLicence $LicencePath $names.sqlFqdn $cfg.tenantId "$($cfg.installKey)" }
    if ($lr -and $lr.ok) {
        Emit 'licence' 'ok' "the $($cfg.edition) licence is registered -- the Pro features are on"; Mark 'licence'
        # framework 8.6: the key has done its job -- no copy of it stays in the answers on disk (a resume no longer needs it).
        if ("$($raw.enrollmentKey)".Trim()) { try { if (Remove-PimInstallConfigEnrollmentKey -ConfigPath $ConfigPath) { Write-Host '    the enrollment key was removed from config.json (it is no longer needed)' -ForegroundColor DarkGray } } catch { Write-Host "    could not remove the enrollment key from config.json -- delete that line yourself" -ForegroundColor Yellow } }
    }
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
            SuperAdmins = @("$($deployArgs['ManagerSuperAdmins'])" -split '[,;]' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
            AlertRecipients = @($cfg.alertRecipients); LicenceExpected = $true; SetupHostRuleOwner = 'this'; UseSignedInAccount = $true; ResumeCommand = $resumeCmd
            OutFile = (Join-Path $StatePath 'verify-install.json') }
if ($deployArgs.Contains('UpdateRing')) { $vArgs['UpdateRing'] = [int]$deployArgs['UpdateRing'] }
if ($deployArgs.Contains('UpdateSource')) { $vArgs['UpdateSource'] = "$($deployArgs['UpdateSource'])" }
if ($cfg.engineAzureRootUserAccessAdmin) { $vArgs['EngineAzureRootUserAccessAdmin'] = $true }
if ($mailEv) { $vArgs['MailDeferredReason'] = "$($mailEv.message)" }
if (-not $VerifyInstall) { $VerifyInstall = { param([hashtable]$A) @(& (Join-Path $here 'Confirm-PimInstall.ps1') @A) | Where-Object { $_ -and $_.PSObject.Properties['done'] } | Select-Object -Last 1 } }
$vr = $null
try { $vr = & $VerifyInstall $vArgs } catch { $vr = $null; Write-Verbose "verify-install threw: $($_.Exception.Message)" }
$vRows = @(@($vr.rows) | Where-Object { $_ } | ForEach-Object { [ordered]@{ id = "$($_.id)"; title = "$($_.title)"; state = "$($_.state)"; detail = "$($_.detail)"; fix = "$($_.fix)" } })
if (-not $vr) { Emit 'verify-install' 'failed' 'the end-of-install check could not run' 'Fix the cause above, then resume the installation:' $resumeCmd; Finish 1 }
if (-not [bool]$vr.done) {
    $bad = @($vRows | Where-Object { $_.state -eq 'failed' })
    $first = @($bad | Select-Object -First 1)
    Emit 'verify-install' 'failed' "$($vr.sentence)" "Fix: $(if ($first) { "$($first[0].title) -- " })the command below, then resume the installation:" $(if ($first -and "$($first[0].fix)".Trim()) { "$($first[0].fix)" } else { $resumeCmd }) -Detail ([ordered]@{ lines = $vRows })
    Finish 1
}
if (@($vr.warnings).Count) { Emit 'verify-install' 'warning' "$($vr.sentence)" -Detail ([ordered]@{ lines = $vRows }) }
else { Emit 'verify-install' 'ok' "$($vr.sentence)" -Detail ([ordered]@{ lines = $vRows }) }

}   # end: not a managed-tenant install (2c ran the managed-tenant build instead of 3 - 4b)

Emit 'health-check' 'started'
$healthy = if ($managedInstall) { [int]$mspCode -eq 0 } else { ("$($summary.status)" -eq 'success') -and [bool]$summary.healthy }
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
