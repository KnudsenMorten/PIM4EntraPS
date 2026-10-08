#Requires -Version 5.1
<#
.SYNOPSIS
    INSTALL-HARDEN-1 (PIM REQUIREMENTS §99, owner 2026-10-08) -- the END-OF-INSTALL VERIFY: read every result an install
    must leave behind, repair what can be repaired, print ONE table, and refuse "done" when a required line fails.

.DESCRIPTION
    The last step of every install path: Invoke-PimDeployAll ('verify-install'), the MSP build Master + Slave
    ('verify-install'), and the guided / trial install (Install-PimManager 'verify-install').

    Lines (Get-PimInstallVerifyRows, _PimInstallVerify.ps1, decides each one):
      superadmins         every SuperAdmin of the install is a SuperAdmin in pim.Settings['ManagerAccess']   REPAIRS (Set-PimManagerAccess)
      updater             the updater job exists, its PIM_UPDATE_RING reads back (+ the update-state record) REPAIRS (Deploy-PimUpdateJob)
      licence             the licence is registered (+ the install key stored / its claim queued) -- Pro, trial and MSP
      mailsender          a mail sender is set AND every sending identity (engine job + Manager) is InScope
                          (Exchange Test-ServicePrincipalAuthorization; WARNING only when Exchange is not reachable)
      alerting            the alert recipients are not empty                                               REPAIRS (Set-PimAlertRecipients)
      engine-graph        the engine job holds every required Microsoft Graph app role
      engine-root-reader  the engine job holds Reader at the tenant root management group                    REPAIRS (one grant attempt)
      easyauth            Easy Auth is on and every SuperAdmin may sign in
      sql-host-rule       no 'AllowSetupHost' SQL firewall rule is left                                      REPAIRS when this run owns it
      managed tenant only: registered on the managing tenant, its pull subnet allowed, the first pull OK
                          (WARNING with the exact step when the managing tenant cannot be read from here)
    A failed line carries its fix: the published scripts (browser sign-in), the PIM Manager page, or the resume command of
    the install that ran -- never a certificate.

    Exit codes: 0 done (warnings allowed); 1 a required line failed (the table says which, and how to fix it).

.NOTES
    TEST seams: -Probe param($lineId, $ctx) -> the fact for that line (replaces every live read); -Repair param($lineId, $ctx)
    -> $true when the repair ran (replaces every live repair). tests/Test-PimInstallVerify.ps1.
#>
[CmdletBinding()]
param(
    [ValidateSet('Single', 'Master', 'Slave')][string]$Role = 'Single',
    [Parameter(Mandatory)][string]$TenantId,
    [Parameter(Mandatory)][string]$SubscriptionId,
    [Parameter(Mandatory)][string]$ResourceGroup,
    [Parameter(Mandatory)][string]$SqlServerFqdn,
    [string]$SqlDatabase = 'PimPlatform',
    [string]$SqlResourceGroup,
    [string]$ManagerApp = 'ca-pim-manager',
    [string]$TickJobName = 'ca-pim-tick',
    [string]$UpdateJobName = 'ca-pim-update',
    [string]$DownlinkJobName = 'ca-pim-downlink-s6',
    [string]$EnvName,
    [string]$AcrName,
    [string]$ImageRepo = 'pim-manager',
    [string]$AcrAgentPoolName,
    [string[]]$SuperAdmins = @(),
    [string[]]$AlertRecipients = @(),
    [int]$UpdateRing = -1,
    [string]$UpdateSource,
    # community install without a feed: there is no in-cloud updater by design (Update-PimCommunity.ps1 is the updater)
    [switch]$NoUpdater,
    [switch]$LicenceExpected,
    # why the install could not set the mail sender itself (a signed-in PERSON without an Exchange role): the line is then a
    # WARNING with the Get Started follow-up instead of a failure
    [string]$MailDeferredReason,
    # 'this' = this run opened 'AllowSetupHost' (with -CloseSetupHostRule the verify removes it and reads it back);
    # 'caller' = the MSP build owns the window and its last step (-ClosingStep) closes it; 'none' = not applicable
    [ValidateSet('this', 'caller', 'none')][string]$SetupHostRuleOwner = 'this',
    [string]$ClosingStep = 'sqlhostclose',
    [switch]$CloseSetupHostRule,
    [switch]$EngineAzureRootUserAccessAdmin,
    # managed tenant: where the managing tenant is, for the lines it can read from here
    [string]$MasterSubscriptionId,
    [string]$MasterStorageAccount,
    [string]$ManagingTenantStep,
    # the command that re-runs this install's verify (and with it every repair): shown as the fix of a repairable line
    [string]$ResumeCommand,
    [string]$ClientId,
    [string]$CertThumbprint,
    [switch]$UseSignedInAccount,
    [switch]$NoRepair,
    [string]$OutFile,
    [scriptblock]$Probe,
    [scriptblock]$Repair
)
$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
. (Join-Path $here '_PimInstallVerify.ps1')
# the tenant-root helpers (Get-PimTenantRootScope / Get-PimRootAzureHoldings / Get-PimRootAzureFixCommand), pure
. (Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'engine\_shared\PIM-PermissionHealth.ps1')
$norm = { param($l) @(@($l) | ForEach-Object { "$_" -split '[,;]' } | ForEach-Object { "$_".Trim() } | Where-Object { $_ }) }
$SuperAdmins = @(& $norm $SuperAdmins); $AlertRecipients = @(& $norm $AlertRecipients)
$sqlServer = ("$SqlServerFqdn".Trim() -split '\.')[0]
$sqlRg = if ("$SqlResourceGroup".Trim()) { "$SqlResourceGroup".Trim() } else { $ResourceGroup }
$ctx = [ordered]@{ role = $Role; tenantId = $TenantId; subscriptionId = $SubscriptionId; resourceGroup = $ResourceGroup; sqlServerFqdn = $SqlServerFqdn
                   superAdmins = $SuperAdmins; alertRecipients = $AlertRecipients; updateRing = $UpdateRing; noUpdater = [bool]$NoUpdater
                   setupHostRuleOwner = $SetupHostRuleOwner; closeSetupHostRule = [bool]$CloseSetupHostRule; mailDeferredReason = "$MailDeferredReason" }
$idArgs = if ($UseSignedInAccount) { @{ UseSignedInAccount = $true } } else { @{ ClientId = $ClientId; CertThumbprint = $CertThumbprint } }

# ============================================================================ live reads (replaced by -Probe in tests)
$script:cv = @{}
function Invoke-CvAz([string[]]$A) {
    $eap = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    try { $o = & az @A --subscription $SubscriptionId --only-show-errors 2>$null; $code = $LASTEXITCODE } finally { $ErrorActionPreference = $eap }
    $global:LASTEXITCODE = 0
    if ($code) { throw "az $($A[0..([Math]::Min(2, $A.Count - 1))] -join ' ') failed (exit $code)" }
    return ("$(@($o) -join "`n")".Trim())
}
function Invoke-CvAzJson([string[]]$A) { $t = Invoke-CvAz ($A + @('-o', 'json')); if (-not $t) { return $null }; return ($t | ConvertFrom-Json) }
function Get-CvToken([string]$Resource) {
    $eap = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    try { $t = "$(& az account get-access-token --subscription $SubscriptionId --resource $Resource --query accessToken -o tsv 2>$null)".Trim() } finally { $ErrorActionPreference = $eap }
    $global:LASTEXITCODE = 0
    return $t
}
function Invoke-CvGraph([string]$Path, [switch]$All) {
    $tok = Get-CvToken 'https://graph.microsoft.com'
    if (-not $tok) { throw 'no Microsoft Graph token from the signed-in az context' }
    $u = if ($Path -match '^https://') { $Path } else { "https://graph.microsoft.com/v1.0/$Path" }
    if (-not $All) { return (Invoke-RestMethod -Uri $u -Headers @{ Authorization = "Bearer $tok" } -TimeoutSec 60) }
    $items = @()
    while ($u) { $r = Invoke-RestMethod -Uri $u -Headers @{ Authorization = "Bearer $tok" } -TimeoutSec 60; $items += @($r.value); $u = "$($r.'@odata.nextLink')" }
    return $items
}
function Get-CvStore {
    if ($script:cv.ContainsKey('cs')) { return $script:cv['cs'] }
    . (Join-Path $here '_PimSetupSql.ps1')
    $script:cv['cs'] = Connect-PimSetupStore -SqlServerFqdn $SqlServerFqdn -SqlDatabase $SqlDatabase -TenantId $TenantId @idArgs
    return $script:cv['cs']
}
function Get-CvSetting([string]$Name) { $cs = Get-CvStore; $v = Get-PimSqlSetting -ConnectionString $cs -Name $Name; if ($v -is [string]) { try { $v = $v | ConvertFrom-Json } catch { } }; return $v }
function Get-CvMiOid([string]$Kind, [string]$Name) {
    $k = "mi:${Kind}:${Name}"; if ($script:cv.ContainsKey($k)) { return $script:cv[$k] }
    $a = if ($Kind -eq 'job') { @('containerapp', 'job', 'show') } else { @('containerapp', 'show') }
    $o = Invoke-CvAz ($a + @('-g', $ResourceGroup, '-n', $Name, '--query', 'identity.principalId', '-o', 'tsv'))
    $script:cv[$k] = "$o".Trim(); return $script:cv[$k]
}

function Get-CvFact([string]$Id) {
    if ($Probe) { return (& $Probe $Id $ctx) }
    try {
        switch ($Id) {
            'superadmins' {
                $cur = Get-CvSetting 'ManagerAccess'
                $stored = @(if ($cur -and $cur.PSObject.Properties['managerAccess']) { $cur.managerAccess } elseif ($cur) { $cur })
                return @{ readable = $true; stored = $stored; want = $SuperAdmins }
            }
            'updater' {
                if ($NoUpdater) { return @{ readable = $true; notApplicable = $true; reason = 'community edition without a release feed: no in-cloud updater by design -- keep it current with tools\setup\Update-PimCommunity.ps1 -Apply' } }
                $jobEnv = $null
                try { $jobEnv = Invoke-CvAzJson @('containerapp', 'job', 'show', '-g', $ResourceGroup, '-n', $UpdateJobName, '--query', 'properties.template.containers[0].env') } catch { $jobEnv = $null }
                if ($null -eq $jobEnv) {
                    $exists = $false
                    try { $exists = [bool](Invoke-CvAz @('containerapp', 'job', 'list', '-g', $ResourceGroup, '--query', "[?name=='$UpdateJobName'].name", '-o', 'tsv')) } catch { throw }
                    if (-not $exists) { return @{ readable = $true; jobExists = $false } }
                }
                $ring = "$(@(@($jobEnv) | Where-Object { "$($_.name)" -eq 'PIM_UPDATE_RING' }) | Select-Object -First 1 | ForEach-Object { $_.value })".Trim()
                $us = Get-CvSetting 'UpdateState'
                $seed = [bool](Select-String -LiteralPath (Join-Path $here '_PimUpdateRing.ps1') -Pattern 'function Get-PimUpdateStateSeedPlan' -Quiet)
                return @{ readable = $true; jobExists = $true; ringEnv = $ring; wantRing = $(if ($UpdateRing -ge 0) { "$UpdateRing" } else { '' }); seedSupported = $seed; stateRing = "$(Get-PimFactValue $us 'ring')".Trim() }
            }
            'licence' {
                $cs = Get-CvStore
                $sol = Split-Path -Parent (Split-Path -Parent $here)
                if (-not (Get-Command Get-PimLicense -ErrorAction SilentlyContinue)) { . (Join-Path $sol 'engine\_shared\PIM-License.ps1') }
                $raw = Invoke-PimSqlScalar -ConnectionString $cs -Sql "SELECT ValueJson FROM pim.Settings WHERE Name = N'License'"
                $txt = ConvertFrom-PimLicenseSettingRaw $raw
                $st = ''; if ($txt) { try { $st = "$((Get-PimLicense -LicenseText $txt).Status)" } catch { $st = 'Unreadable' } }
                $key = "$(Get-PimSqlSetting -ConnectionString $cs -Name 'InvardiaInstallKey')".Trim()
                $trig = @(@(Get-PimSqlSetting -ConnectionString $cs -Name 'SchedulerTriggers') | Where-Object { $_ -and "$($_.type)" -eq 'install-key' })
                $claim = Get-CvSetting 'InstallKeyClaimState'
                return @{ readable = $true; present = [bool]$txt; status = $st; installKey = ([bool]$key -or "$(Get-PimFactValue $claim 'action')" -eq 'claimed'); claimQueued = [bool]$trig.Count }
            }
            'mailsender' {
                $sender = "$(Get-CvSetting 'MailSender')".Trim().Trim('"')
                $f = @{ readable = $true; sender = $sender; deferredReason = "$MailDeferredReason".Trim(); exoReachable = $false; identities = @(); exoError = '' }
                if (-not $sender) { return $f }
                $ids = @()
                foreach ($res in @(@{ kind = 'job'; name = $TickJobName; label = "engine job $TickJobName" }, @{ kind = 'app'; name = $ManagerApp; label = "Manager $ManagerApp" })) {
                    $oid = ''; try { $oid = Get-CvMiOid $res.kind $res.name } catch { $oid = '' }
                    if (-not $oid) { continue }
                    $app = ''; try { $app = "$((Invoke-CvGraph "servicePrincipals/$oid`?`$select=appId").appId)".Trim() } catch { $app = '' }
                    $ids += @{ label = $res.label; objectId = $oid; appId = $app; inScope = $null }
                }
                $f.identities = $ids
                $tok = Get-CvToken 'https://outlook.office365.com'
                if (-not $tok) { $f.exoError = 'no Exchange Online token for the installer'; return $f }
                $exo = "https://outlook.office365.com/adminapi/beta/$TenantId/InvokeCommand"
                $h = @{ Authorization = "Bearer $tok"; 'Content-Type' = 'application/json'; 'X-ResponseFormat' = 'json'; 'X-AnchorMailbox' = "UPN:$sender" }
                foreach ($i in $ids) {
                    if (-not $i.appId) { $i.inScope = $false; continue }
                    $body = @{ CmdletInput = @{ CmdletName = 'Test-ServicePrincipalAuthorization'; Parameters = @{ Identity = $i.appId; Resource = $sender } } } | ConvertTo-Json -Depth 6
                    try { $r = Invoke-RestMethod -Method POST -Uri $exo -Headers $h -Body $body -TimeoutSec 90 }
                    catch {
                        $m = "$($_.Exception.Message)"
                        if ($m -match '\b(401|403)\b|Unauthorized|Forbidden') { $f.exoReachable = $false; $f.exoError = 'Exchange refused the installer (no Exchange role)'; return $f }
                        $i.inScope = $false; continue
                    }
                    $f.exoReachable = $true
                    $i.inScope = [bool](@(@($r.value) | Where-Object { "$($_.RoleName)" -eq 'Application Mail.Send' -and "$($_.InScope)" -eq 'True' }).Count)
                }
                if ($ids.Count -and -not @($ids | Where-Object { $_.appId }).Count) { $f.exoReachable = $true }
                return $f
            }
            'alerting' {
                $a = Get-CvSetting 'Alerting'
                return @{ readable = $true; recipients = @(& $norm (Get-PimFactValue $a 'recipients')) }
            }
            'engine-graph' {
                if (-not (Get-Command Get-PimGraphAppRoleMap -ErrorAction SilentlyContinue)) { . (Join-Path $here '_PimSetupShared.ps1') }
                $oid = Get-CvMiOid 'job' $TickJobName
                if (-not $oid) { return @{ readable = $false; error = "the engine job '$TickJobName' has no managed identity" } }
                $map = Get-PimGraphAppRoleMap -RoleSet Engine
                $have = @(Invoke-CvGraph "servicePrincipals/$oid/appRoleAssignments" -All | ForEach-Object { "$($_.appRoleId)".ToLowerInvariant() })
                $miss = @($map.Keys | Where-Object { "$($map[$_])".ToLowerInvariant() -notin $have } | Sort-Object)
                return @{ readable = $true; missing = $miss; required = $map.Count; objectId = $oid }
            }
            'engine-root-reader' {
                # (Get-PimRootAzureHoldings is loaded at the top: PIM-PermissionHealth.ps1)
                $oid = Get-CvMiOid 'job' $TickJobName
                if (-not $oid) { return @{ readable = $false; error = "the engine job '$TickJobName' has no managed identity" } }
                $scope = Get-PimTenantRootScope -TenantId $TenantId
                $asg = @(Invoke-CvAzJson @('role', 'assignment', 'list', '--assignee', $oid, '--scope', $scope, '--include-inherited'))
                $hold = Get-PimRootAzureHoldings -Assignments $asg -TenantId $TenantId
                return @{ readable = $true; reader = [bool]$hold.reader; scope = $scope; objectId = $oid }
            }
            'engine-first-run' {
                $ex = @(Invoke-CvAzJson @('containerapp', 'job', 'execution', 'list', '-g', $ResourceGroup, '-n', $TickJobName))
                $last = @($ex | Sort-Object { "$($_.properties.startTime)" } -Descending) | Select-Object -First 1
                return @{ readable = $true; status = "$($last.properties.status)"; at = "$($last.properties.startTime)" }
            }
            'easyauth' {
                $auth = Invoke-CvAzJson @('containerapp', 'auth', 'show', '-g', $ResourceGroup, '-n', $ManagerApp)
                $enabled = [bool]$auth.platform.enabled
                $appId = "$($auth.identityProviders.azureActiveDirectory.registration.clientId)".Trim()
                if (-not $enabled -or -not $appId) { return @{ readable = $true; ok = $false; reason = $(if (-not $enabled) { 'Easy Auth is NOT enabled on the PIM Manager' } else { 'Easy Auth has no Microsoft Entra registration' }) } }
                $sp = @(Invoke-CvGraph "servicePrincipals?`$filter=appId eq '$appId'&`$select=id,appRoleAssignmentRequired,displayName" -All) | Select-Object -First 1
                if (-not $sp) { return @{ readable = $true; ok = $false; reason = "the Easy Auth application $appId has no service principal in this tenant" } }
                $assigned = @(Invoke-CvGraph "servicePrincipals/$($sp.id)/appRoleAssignedTo?`$select=principalId" -All | ForEach-Object { "$($_.principalId)" })
                $sa = @()
                foreach ($u in $SuperAdmins) {
                    $id = ''; $groups = @()
                    try { $id = "$((Invoke-CvGraph "users/$([uri]::EscapeDataString($u))?`$select=id").id)" } catch { $id = '' }
                    if ($id -and [bool]$sp.appRoleAssignmentRequired) { try { $groups = @(Invoke-CvGraph "users/$id/transitiveMemberOf/microsoft.graph.group?`$select=id" -All | ForEach-Object { "$($_.id)" }) } catch { $groups = @() } }
                    $sa += @{ upn = $u; id = $id; groupIds = $groups }
                }
                $v = Test-PimEasyAuthSignInAllowed -Enabled $true -AssignmentRequired ([bool]$sp.appRoleAssignmentRequired) -AssignedPrincipalIds $assigned -SuperAdmins $sa
                return @{ readable = $true; ok = $v.ok; reason = $v.reason; appName = "$($sp.displayName)" }
            }
            'sql-host-rule' {
                if ($SetupHostRuleOwner -eq 'none') { return @{ readable = $true; notApplicable = $true; reason = 'no setup-host window in this install (private store or no host-side SQL)' } }
                $n = Invoke-CvAz @('sql', 'server', 'firewall-rule', 'list', '-g', $sqlRg, '-s', $sqlServer, '--query', "[?name=='AllowSetupHost'].name", '-o', 'tsv')
                return @{ readable = $true; present = [bool]"$n".Trim(); owner = $SetupHostRuleOwner; closingStep = $ClosingStep }
            }
            'msp-registered' {
                return @{ readable = $false; value = $null; step = $(if ("$ManagingTenantStep".Trim()) { "$ManagingTenantStep" } else { 'the managing tenant registers this tenant in its build (Invoke-PimMspBuild -Role Master -From register-<n>), or by itself with an enrollment key' }) }
            }
            'msp-subnet' {
                $step = if ("$ManagingTenantStep".Trim()) { "$ManagingTenantStep" } else { 'the managing tenant allows this subnet (Invoke-PimMspBuild -Role Master -From network-<n>), or by itself with an enrollment key' }
                if (-not "$MasterSubscriptionId".Trim() -or -not "$MasterStorageAccount".Trim() -or -not "$EnvName".Trim()) { return @{ readable = $false; value = $null; step = $step } }
                $subnet = Invoke-CvAz @('containerapp', 'env', 'show', '-g', $ResourceGroup, '-n', $EnvName, '--query', 'properties.vnetConfiguration.infrastructureSubnetId', '-o', 'tsv')
                $eap = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
                $rules = "$(& az storage account show -n $MasterStorageAccount --subscription $MasterSubscriptionId --query 'networkRuleSet.virtualNetworkRules[].virtualNetworkResourceId' -o tsv --only-show-errors 2>$null)"
                $code = $LASTEXITCODE; $ErrorActionPreference = $eap; $global:LASTEXITCODE = 0
                if ($code) { return @{ readable = $false; value = $null; step = $step } }
                $hit = @("$rules" -split "`r?`n" | Where-Object { "$_".Trim() -and "$_".Trim() -ieq "$subnet".Trim() }).Count -gt 0
                return @{ readable = $true; value = $hit; detail = $(if ($hit) { "this subnet is allowed on $MasterStorageAccount" } else { "this subnet is NOT allowed on $MasterStorageAccount -- $step" }); step = $step }
            }
            'msp-first-pull' {
                $ex = @(Invoke-CvAzJson @('containerapp', 'job', 'execution', 'list', '-g', $ResourceGroup, '-n', $DownlinkJobName))
                $last = @($ex | Sort-Object { "$($_.properties.startTime)" } -Descending) | Select-Object -First 1
                return @{ readable = $true; status = "$($last.properties.status)"; at = "$($last.properties.startTime)" }
            }
        }
    } catch { return @{ readable = $false; error = (("$($_.Exception.Message)" -split "`n")[0]) } }
    return $null
}

# ============================================================================ repairs (replaced by -Repair in tests)
function Invoke-CvRepair([string]$Id, $Fact) {
    if ($NoRepair) { return $false }
    if ($Repair) { return [bool](& $Repair $Id $ctx) }
    $global:LASTEXITCODE = 0
    try {
        switch ($Id) {
            'superadmins' {
                $want = @($SuperAdmins); if (-not $want.Count) { return $false }
                $json = '{"managerAccess":[' + (($want | ForEach-Object { '{"identity":"' + $_ + '","role":"SuperAdmin"}' }) -join ',') + ']}'
                $a = @{ TenantId = $TenantId; SqlServerFqdn = $SqlServerFqdn; SqlDatabase = $SqlDatabase; AccessJson = $json }
                if ($UseSignedInAccount) { $a['UseSignedInAccount'] = $true } else { $a['AdminAppId'] = $ClientId; $a['AdminCertThumbprint'] = $CertThumbprint }
                Write-Host "    repair: SuperAdmin $($want -join ', ') -> pim.Settings['ManagerAccess'] (Set-PimManagerAccess)" -ForegroundColor Yellow
                & (Join-Path $here 'Set-PimManagerAccess.ps1') @a | Out-Host
                return (-not $LASTEXITCODE)
            }
            'updater' {
                if ($NoUpdater -or -not "$AcrName".Trim() -or -not "$EnvName".Trim()) { return $false }
                $img = Invoke-CvAz @('containerapp', 'show', '-g', $ResourceGroup, '-n', $ManagerApp, '--query', 'properties.template.containers[0].image', '-o', 'tsv')
                $tag = if ("$img" -match ':([^:/@]+)$') { $Matches[1] } else { '' }
                if (-not $tag) { return $false }
                $a = @{ SubscriptionId = $SubscriptionId; ResourceGroup = $ResourceGroup; EnvName = $EnvName; AcrName = $AcrName; ImageRepo = $ImageRepo; ImageTag = $tag
                        TargetImage = "$img".Trim(); TargetVersion = $tag; LastBuiltVersion = $tag; JobName = $UpdateJobName; ManagerApp = $ManagerApp; TickJobName = $TickJobName; TenantId = $TenantId }
                if ($UpdateRing -ge 0) { $a['UpdateRing'] = $UpdateRing }
                if ("$UpdateSource".Trim()) { $a['UpdateSource'] = "$UpdateSource".Trim() }
                if ("$AcrAgentPoolName".Trim()) { $a['AcrAgentPoolName'] = "$AcrAgentPoolName".Trim() }
                if ($UseSignedInAccount) { $a['UseSignedInAccount'] = $true } else { $a['SqlAdminClientId'] = $ClientId; $a['SqlAdminCertThumbprint'] = $CertThumbprint }
                Write-Host "    repair: re-install the updater '$UpdateJobName' on the running image $tag (Deploy-PimUpdateJob)" -ForegroundColor Yellow
                & (Join-Path $here 'Deploy-PimUpdateJob.ps1') @a | Out-Host
                return (-not $LASTEXITCODE)
            }
            'alerting' {
                $a = @{ SqlServerFqdn = $SqlServerFqdn; SqlDatabase = $SqlDatabase; TenantId = $TenantId; SubscriptionId = $SubscriptionId; AlertRecipients = $AlertRecipients; SuperAdmins = $SuperAdmins } + $idArgs
                Write-Host '    repair: set the alert recipients (Set-PimAlertRecipients)' -ForegroundColor Yellow
                & (Join-Path $here 'Set-PimAlertRecipients.ps1') @a | Out-Host
                return ($LASTEXITCODE -eq 0)
            }
            'engine-root-reader' {
                $oid = "$(Get-PimFactValue $Fact 'objectId')"; if (-not $oid) { try { $oid = Get-CvMiOid 'job' $TickJobName } catch { $oid = '' } }
                if (-not $oid) { return $false }
                if (-not (Get-Command Grant-PimEngineRootAzureAccess -ErrorAction SilentlyContinue)) { . (Join-Path $here '_PimSetupShared.ps1') }
                Write-Host '    repair: grant the engine Reader at the tenant root (one attempt)' -ForegroundColor Yellow
                $r = Grant-PimEngineRootAzureAccess -MiObjectId $oid -Name $TickJobName -TenantId $TenantId -SubscriptionId $SubscriptionId -IncludeUserAccessAdministrator:$EngineAzureRootUserAccessAdmin
                return [bool]$r.ok
            }
            'sql-host-rule' {
                if ($SetupHostRuleOwner -ne 'this' -or -not $CloseSetupHostRule) { return $false }
                Write-Host "    repair: remove this run's 'AllowSetupHost' from $sqlServer" -ForegroundColor Yellow
                [void](Invoke-CvAz @('sql', 'server', 'firewall-rule', 'delete', '-g', $sqlRg, '-s', $sqlServer, '-n', 'AllowSetupHost'))
                return $true
            }
        }
    } catch { Write-Host "    repair of '$Id' failed: $((("$($_.Exception.Message)") -split "`n")[0])" -ForegroundColor Yellow; return $false }
    return $false
}

# ============================================================================ fix commands (never a certificate)
. (Join-Path $here '_PimMailSenderPlan.ps1')
$resume = "$ResumeCommand".Trim()
$fix = @{}
$viaResume = { param($what) if ($resume) { "re-run the install's verify (it repairs $what): $resume" } else { '' } }
$fix['superadmins'] = (@((& $viaResume 'this'), ".\tools\setup\Set-PimManagerAccess.ps1 -TenantId $TenantId -SqlServerFqdn $SqlServerFqdn -UseSignedInAccount -AccessJson '{`"managerAccess`":[{`"identity`":`"<upn>`",`"role`":`"SuperAdmin`"}]}'") | Where-Object { $_ }) -join "`n"
$fix['updater'] = (@((& $viaResume 'this'), ".\tools\setup\Deploy-PimUpdateJob.ps1 -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -EnvName $(if ($EnvName) { $EnvName } else { '<env>' }) -AcrName $(if ($AcrName) { $AcrName } else { '<acr>' }) -UseSignedInAccount$(if ($UpdateRing -ge 0) { " -UpdateRing $UpdateRing" })$(if ($UpdateSource) { " -UpdateSource $UpdateSource" })") | Where-Object { $_ }) -join "`n"
$fix['licence'] = (@('PIM Manager > Settings > Licence: upload the .pimlicense file (the install key is claimed by the engine within minutes)', (& $viaResume 'the check')) | Where-Object { $_ }) -join "`n"
$mailCmd = New-PimMailSenderCommand -TenantId $TenantId -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -TickJobName $TickJobName -ManagerAppName $ManagerApp -SqlServerFqdn $SqlServerFqdn
$fix['mailsender'] = (@('PIM Manager > Get Started > Mail sender (shared mailbox: an Exchange or Global Administrator runs this in a browser sign-in; it also gives BOTH identities the scoped send right):') + @($mailCmd)) -join "`n"
$fix['alerting'] = (@('PIM Manager > Settings > Alerting > Recipients', (& $viaResume 'this')) | Where-Object { $_ }) -join "`n"
$fix['engine-graph'] = "Invoke-WebRequest https://invardia.com/support/pim/Grant-PimEnginePermissions.ps1 -OutFile Grant-PimEnginePermissions.ps1`n.\Grant-PimEnginePermissions.ps1 -TenantId '$TenantId' -EngineObjectId '<engine job object id>' -GraphPermissions <the missing ones above>   (a Privileged Role Administrator, browser sign-in)"
$fix['engine-root-reader'] = ''
$fix['easyauth'] = (@("Microsoft Entra admin center > Enterprise applications > the PIM Manager's sign-in application > Users and groups: assign the SuperAdmins (or a group that holds them)", (& $viaResume 'the check')) | Where-Object { $_ }) -join "`n"
$fix['sql-host-rule'] = "az sql server firewall-rule delete --subscription $SubscriptionId -g $sqlRg -s $sqlServer -n AllowSetupHost   (or Azure portal > SQL server > Networking: remove 'AllowSetupHost')"
$fix['msp-registered'] = 'on the managing tenant: Invoke-PimMspBuild.ps1 -Role Master -ConfigPath <its config> -Apply -From register-<n> (with an enrollment key this happens by itself)'
$fix['msp-subnet'] = "on the managing tenant: add this tenant's pull subnet id as slaves[<n>].subnetResourceId, then Invoke-PimMspBuild.ps1 -Role Master -ConfigPath <its config> -Apply -From network-<n> (with an enrollment key this happens by itself)"
$fix['msp-first-pull'] = "az containerapp job start -n $DownlinkJobName -g $ResourceGroup --subscription $SubscriptionId   (after the managing tenant allows the subnet)"
$fix['engine-first-run'] = 'PIM Manager > Home (the engine status and its last run), or Settings > Job schedule > Run now'

# ============================================================================ run
Write-Host "`n==> END-OF-INSTALL VERIFY ($Role) -- $ResourceGroup / $SqlServerFqdn" -ForegroundColor Cyan
$facts = @{}
$lineIds = Get-PimInstallVerifyLineIds -Role $Role
foreach ($id in $lineIds) { $facts[$id] = Get-CvFact $id }
# The engine identity's object id for the root fix command (the fact carries it when it was read).
$eoid = "$(Get-PimFactValue $facts['engine-root-reader'] 'objectId')"
$fix['engine-root-reader'] = (Get-PimRootAzureFixCommand -TenantId $TenantId -EngineObjectId $eoid -Roles @('Reader')) + "`n(a Global Administrator, browser sign-in; first turn on Microsoft Entra ID > Properties > Access management for Azure resources)"
if ($eoid) { $fix['engine-graph'] = $fix['engine-graph'].Replace('<engine job object id>', $eoid) }

# Repair pass: a line that FAILS and has a repair is repaired once, then read again.
$rows0 = Get-PimInstallVerifyRows -Role $Role -Facts $facts -Fix $fix -LicenceExpected ([bool]$LicenceExpected)
foreach ($r in @($rows0 | Where-Object { ($_.state -eq 'failed' -and $_.id -in 'superadmins', 'updater', 'alerting', 'engine-root-reader', 'sql-host-rule') -or ($_.state -eq 'warning' -and $_.id -eq 'engine-root-reader') })) {
    if ($r.id -eq 'sql-host-rule' -and -not [bool](Get-PimFactValue $facts[$r.id] 'readable')) { continue }
    if (Invoke-CvRepair $r.id $facts[$r.id]) {
        $again = Get-CvFact $r.id
        if ($again -is [System.Collections.IDictionary]) { $again['repaired'] = $true } elseif ($again) { $again | Add-Member -NotePropertyName repaired -NotePropertyValue $true -Force }
        $facts[$r.id] = $again
    } elseif ($r.id -eq 'engine-root-reader' -and -not $NoRepair) {
        # §97: the one grant attempt was refused (the installer holds no right at the tenant root) -- a warning, not a stop
        $f0 = $facts[$r.id]
        if ($f0 -is [System.Collections.IDictionary]) { $f0['refused'] = $true } elseif ($f0) { $f0 | Add-Member -NotePropertyName refused -NotePropertyValue $true -Force }
    }
}
$rows = Get-PimInstallVerifyRows -Role $Role -Facts $facts -Fix $fix -LicenceExpected ([bool]$LicenceExpected)
$verdict = Get-PimInstallVerifyVerdict -Rows $rows
Write-Host ''
foreach ($l in (Format-PimInstallVerifyTable -Rows $rows)) {
    $c = if ($l -match '^\s+FAILED') { 'Red' } elseif ($l -match '^\s+WARNING') { 'Yellow' } elseif ($l -match '^\s+(OK|REPAIRED)') { 'Green' } elseif ($l -match '^\s+fix:|^\s{14}') { 'Yellow' } else { 'Gray' }
    Write-Host $l -ForegroundColor $c
}
Write-Host ''
Write-Host "    $($verdict.sentence)" -ForegroundColor $(if ($verdict.done) { 'Green' } else { 'Red' })
if ("$OutFile".Trim()) { try { [ordered]@{ done = $verdict.done; failed = $verdict.failed; warnings = $verdict.warnings; sentence = $verdict.sentence; rows = $rows } | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $OutFile -Encoding UTF8 } catch { } }
[pscustomobject]@{ done = $verdict.done; failed = $verdict.failed; warnings = $verdict.warnings; sentence = $verdict.sentence; rows = $rows }
if (-not $verdict.done) { exit 1 }
exit 0
