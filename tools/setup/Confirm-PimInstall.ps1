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
      manager-rg-reader   the Manager holds Reader on the PIM resource group only (the Environment report)   REPAIRS (one grant attempt; a WARNING, never a stop)
      engine-size         the engine job is at least the size its tenant count needs (framework 12.15; WARNING with the az
                          command for that tier -- 2.0 CPU / 4Gi / 7200 s from 5,000 objects, 4.0 / 8Gi / 14400 s from 15,000)
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
    [scriptblock]$Repair,
    # TEST seams (INSTALL-FIX-EVIDA 100.25): -StoreRead param($kind, $name) -> the store's value for that setting, in place of
    # the SQL read ($kind 'raw' = the ValueJson column as stored; 'setting' = as Get-PimSqlSetting returns it). A -Probe that
    # answers '<live>' for a line lets that line run its real code against -StoreRead. -TestLicenceCertB64: an ephemeral
    # licensing certificate for the licence line (never the real key).
    [scriptblock]$StoreRead,
    [string]$TestLicenceCertB64
)
$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
. (Join-Path $here '_PimInstallVerify.ps1')
# the tenant-root helpers (Get-PimTenantRootScope / Get-PimRootAzureHoldings / Get-PimRootAzureFixCommand), pure
. (Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'engine\_shared\PIM-PermissionHealth.ps1')
# 100.31: the engine job's size for the tenant (Test-PimJobUndersized / ConvertFrom-PimTenantSizingTags), pure
. (Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'engine\_shared\PIM-TenantSizing.ps1')
# SCRIPT-DOC-1 (framework 12.7): every fix command this check prints carries the script's doc page + the checksum check
. (Join-Path $here '_PimScriptDoc.ps1')
# 🔴 The store: Connect-PimSetupStore + its token provider (PIM-Rest: Get-PimRestToken) + the reads (PIM-SqlStore:
# Get-PimSqlSetting / Invoke-PimSqlScalar) -- loaded HERE, AT FILE SCOPE. The live proof on a managing tenant
# (2026-10-08, the check run ON ITS OWN through the Invardia Support app) failed every store line twice over, and both
# were the one 71.32 scoping trap: _PimSetupSql.ps1 was dot-sourced INSIDE Get-CvStore, so everything it loads was
# discarded when that function returned --
#   1. "The term 'Get-PimSqlSetting' is not recognized" (inside an install the caller had happened to load the store);
#   2. with the store loaded, "Login failed for user ''": New-PimSqlConnection found NO Get-PimRestToken, so the
#      connection carried no token at all -- in -UseSignedInAccount mode the signed-in az session's SQL token
#      (https://database.windows.net/, minted and checked by Connect-PimSignedInSql) never reached it. The SPN path
#      had the same hole. Loaded at file scope, both identities reach every store read.
# Always loaded (never "only if a caller has not"): what a caller happened to load is exactly what hid cause 1 inside an install.
. (Join-Path $here '_PimSetupSql.ps1')
# §100.41: the ARM / Graph REST layer for the live reads (no az) -- file scope, always (same 71.32 rule).
. (Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'engine\_shared\PIM-ArmSetup.ps1')
# 🔴 INSTALL-FIX-EVIDA (100.25 item 1, 2026-10-09): the licence functions -- loaded HERE, AT FILE SCOPE, ALWAYS. The licence
# line loaded PIM-License.ps1 only "if Get-PimLicense is not loaded yet", INSIDE Get-CvFact. Install-PimManager (the caller)
# has it loaded, so nothing was loaded here, and the caller's Get-PimLicense ran in THIS script, where its $script: trusted
# signing certificates do not exist -- every licence read "Invalid", and a production install refused "done" while its licence
# step had just stored and read back a Valid licence. Loaded here, the certificates live in this script's own scope.
. (Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'engine\_shared\PIM-License.ps1')
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
# §100.41 (NO-AZ, framework 12.17): every live read goes over ARM / Graph REST (engine\_shared\PIM-ArmSetup.ps1) with a
# token from PIM-Rest's ONE client -- the signed-in session (Invardia Support app / browser) or the certificate identity.
# Connected lazily (the first live read), so a -Probe run never signs in.
function Connect-CvRest {
    if ($script:cv.ContainsKey('rest')) { return }
    # (PIM-Rest via _PimSetupSql.ps1 and PIM-ArmSetup.ps1 are loaded at FILE scope above -- 71.32: never inside a function)
    if ($UseSignedInAccount) {
        # the build's step launcher / the guided install already pointed PIM-Rest at the signed-in session: keep it
        if (-not $global:PIM_SetupRestMode -and -not $global:PIM_SignedInAccount) { [void](Connect-PimSetupRest -TenantId $TenantId -SubscriptionId $SubscriptionId) }
    } elseif ("$ClientId".Trim() -and "$CertThumbprint".Trim()) {
        [void](Connect-PimSetupRest -TenantId $TenantId @idArgs)   # the certificate identity ($idArgs: ClientId + CertThumbprint)
    }
    $script:cv['rest'] = $true
}
function Get-CvToken([string]$Resource) {
    Connect-CvRest
    $t = ''; try { $t = "$(Get-PimRestToken -Resource $Resource -TenantId $TenantId)".Trim() } catch { $t = '' }
    return $t
}
function Get-CvArm([string]$Path, [string]$Api = 'aca', [switch]$All) {
    # a failed read THROWS (the line is "not checked: <reason>"); a missing resource answers $null
    Connect-CvRest
    Invoke-PimSetupArm -Path $Path -ApiVersion (Get-PimSetupApiVersion $Api) -NotFoundOk -All:$All
}
function Get-CvResId([string]$Type, [string]$Name, [string]$Child = '', [string]$Rg = $ResourceGroup) { Connect-CvRest; Get-PimArmResourceId $SubscriptionId $Rg $Type $Name $Child }
function Invoke-CvGraph([string]$Path, [switch]$All) {
    $tok = Get-CvToken 'https://graph.microsoft.com'
    if (-not $tok) { throw 'no Microsoft Graph token for the signed-in identity' }
    $u = if ($Path -match '^https://') { $Path } else { "https://graph.microsoft.com/v1.0/$Path" }
    if (-not $All) { return (Invoke-RestMethod -Uri $u -Headers @{ Authorization = "Bearer $tok" } -TimeoutSec 60) }
    $items = @()
    while ($u) { $r = Invoke-RestMethod -Uri $u -Headers @{ Authorization = "Bearer $tok" } -TimeoutSec 60; $items += @($r.value); $u = "$($r.'@odata.nextLink')" }
    return $items
}
function New-CvStoreError([string]$Message) {
    # A store read that failed is "not checked (could not read the store: <reason>)", never "<the thing> is missing":
    # the exception carries a marker the fact keeps (store = $true) so the row can say so.
    $m = (("$Message" -split "`n")[0]) -replace '^Exception calling "[^"]+" with "\d+" argument\(s\): ', ''
    $e = [System.InvalidOperationException]::new("$m".Trim().Trim('"')); $e.Data['pimStore'] = $true
    return $e
}
function Get-CvStore {
    if ($script:cv.ContainsKey('cs')) { return $script:cv['cs'] }
    # a connect that failed once fails every store line with the same reason (no second sign-in attempt per line)
    if ($script:cv.ContainsKey('csErr')) { throw (New-CvStoreError $script:cv['csErr']) }
    try { $script:cv['cs'] = Connect-PimSetupStore -SqlServerFqdn $SqlServerFqdn -SqlDatabase $SqlDatabase -TenantId $TenantId @idArgs }
    catch { $script:cv['csErr'] = "$($_.Exception.Message)"; throw (New-CvStoreError $script:cv['csErr']) }
    return $script:cv['cs']
}
function Invoke-CvStoreRead([scriptblock]$Read) {
    # Every store read runs through here: connect (signed-in az token, or the SPN), then the read; any failure is a STORE failure.
    $cs = Get-CvStore
    try { return (& $Read $cs) } catch { throw (New-CvStoreError "$($_.Exception.Message)") }
}
function Get-CvSettingRaw([string]$Name) {
    # the ValueJson column exactly as stored (a licence is a JSON string literal holding the licence document)
    if ($StoreRead) { return (& $StoreRead 'raw' $Name) }
    return (Invoke-CvStoreRead { param($cs) Invoke-PimSqlScalar -ConnectionString $cs -Sql 'SELECT ValueJson FROM pim.Settings WHERE Name = @n' -Parameters @{ n = $Name } })
}
function Get-CvSetting([string]$Name) {
    $v = if ($StoreRead) { & $StoreRead 'setting' $Name } else { Invoke-CvStoreRead { param($cs) Get-PimSqlSetting -ConnectionString $cs -Name $Name } }
    if ($v -is [string]) { try { $v = $v | ConvertFrom-Json } catch { } }
    return $v
}
function Get-CvMiOid([string]$Kind, [string]$Name) {
    $k = "mi:${Kind}:${Name}"; if ($script:cv.ContainsKey($k)) { return $script:cv[$k] }
    $res = Get-CvArm (Get-CvResId $(if ($Kind -eq 'job') { 'Microsoft.App/jobs' } else { 'Microsoft.App/containerApps' }) $Name)
    $script:cv[$k] = "$($res.identity.principalId)".Trim(); return $script:cv[$k]
}

function Get-CvFact([string]$Id) {
    if ($Probe) { $pf = & $Probe $Id $ctx; if (-not ($pf -is [string] -and $pf -eq '<live>')) { return $pf } }
    try {
        switch ($Id) {
            'superadmins' {
                $cur = Get-CvSetting 'ManagerAccess'
                $stored = @(if ($cur -and $cur.PSObject.Properties['managerAccess']) { $cur.managerAccess } elseif ($cur) { $cur })
                return @{ readable = $true; stored = $stored; want = $SuperAdmins }
            }
            'updater' {
                if ($NoUpdater) { return @{ readable = $true; notApplicable = $true; reason = 'community edition without a release feed: no in-cloud updater by design -- keep it current with tools\setup\Update-PimCommunity.ps1 -Apply' } }
                $updJob = Get-CvArm (Get-CvResId 'Microsoft.App/jobs' $UpdateJobName)
                if (-not $updJob) { return @{ readable = $true; jobExists = $false } }
                $jobEnv = @($updJob.properties.template.containers)[0].env
                $ring = "$(@(@($jobEnv) | Where-Object { "$($_.name)" -eq 'PIM_UPDATE_RING' }) | Select-Object -First 1 | ForEach-Object { $_.value })".Trim()
                $us = Get-CvSetting 'UpdateState'
                $seed = [bool](Select-String -LiteralPath (Join-Path $here '_PimUpdateRing.ps1') -Pattern 'function Get-PimUpdateStateSeedPlan' -Quiet)
                return @{ readable = $true; jobExists = $true; ringEnv = $ring; wantRing = $(if ($UpdateRing -ge 0) { "$UpdateRing" } else { '' }); seedSupported = $seed; stateRing = "$(Get-PimFactValue $us 'ring')".Trim() }
            }
            'licence' {
                # pim.Settings stores the licence as a JSON STRING LITERAL holding the document: always unwrap it
                # (ConvertFrom-PimLicenseSettingRaw, loaded at file scope above) -- the raw string itself never reaches Get-PimLicense.
                $txt = ConvertFrom-PimLicenseSettingRaw (Get-CvSettingRaw 'License')
                $st = ''; $why = ''
                if ($txt) {
                    try { $lic = if ($TestLicenceCertB64) { Get-PimLicense -LicenseText $txt -PublicCertB64 $TestLicenceCertB64 } else { Get-PimLicense -LicenseText $txt }; $st = "$($lic.Status)"; $why = "$($lic.Reason)" }
                    catch { $st = 'Unreadable'; $why = "$($_.Exception.Message)" }
                }
                $key = "$(Get-CvSetting 'InvardiaInstallKey')".Trim()
                $trig = @(@(Get-CvSetting 'SchedulerTriggers') | Where-Object { $_ -and "$($_.type)" -eq 'install-key' })
                $claim = Get-CvSetting 'InstallKeyClaimState'
                return @{ readable = $true; present = [bool]$txt; status = $st; reason = $(if ($st -notin 'Valid', 'Grace') { $why } else { '' }); installKey = ([bool]$key -or "$(Get-PimFactValue $claim 'action')" -eq 'claimed'); claimQueued = [bool]$trig.Count }
            }
            'mailsender' {
                $sender = "$(Get-CvSetting 'MailSender')".Trim().Trim('"')
                $f = @{ readable = $true; sender = $sender; deferredReason = "$MailDeferredReason".Trim(); exoReachable = $false; identities = @(); exoError = '' }
                if (-not $sender) { return $f }
                # INSTALL-FIX-EVIDA (100.25 item 4): the PRIMARY SMTP address the customer chose. MailSender is the mailbox's UPN
                # (BUG-296); the address is the record the mail-sender setup stored (pim.Settings 'MailSenderAddress', only while
                # it belongs to THIS sender), else the directory's own 'mail' of that UPN (Microsoft Graph, no Exchange needed).
                $rec = $null; try { $rec = Get-CvSetting 'MailSenderAddress' } catch { $rec = $null }
                $f.address = if ($rec -and "$(Get-PimFactValue $rec 'sender')".Trim() -ieq $sender) { "$(Get-PimFactValue $rec 'address')".Trim() } else { '' }
                if (-not $f.address -and -not $StoreRead) { try { $f.address = "$((Invoke-CvGraph "users/$([uri]::EscapeDataString($sender))?`$select=mail").mail)".Trim() } catch { $f.address = '' } }
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
                $asg = @(Get-PimArmRoleAssignments -Scope $scope -PrincipalId $oid -IncludeInherited -SubscriptionId $SubscriptionId)
                $hold = Get-PimRootAzureHoldings -Assignments $asg -TenantId $TenantId
                return @{ readable = $true; reader = [bool]$hold.reader; scope = $scope; objectId = $oid }
            }
            'manager-rg-reader' {
                # PIM 100.22 (b): Reader assigned AT the resource group itself (never read as "covered" by something wider).
                if (-not (Get-Command Get-PimManagerRgReaderScope -ErrorAction SilentlyContinue)) { . (Join-Path $here '_PimSetupShared.ps1') }
                $oid = Get-CvMiOid 'app' $ManagerApp
                if (-not $oid) { return @{ readable = $false; error = "the Manager '$ManagerApp' has no managed identity" } }
                $scope = Get-PimManagerRgReaderScope -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup
                $asg = @(Get-PimArmRoleAssignments -Scope $scope -PrincipalId $oid -Role 'Reader' -SubscriptionId $SubscriptionId)
                $held = @($asg | Where-Object { $_ -and "$($_.scope)".TrimEnd('/') -ieq $scope })
                return @{ readable = $true; reader = [bool]$held.Count; scope = $scope; objectId = $oid }
            }
            'engine-first-run' {
                $ex = @(Get-CvArm (Get-CvResId 'Microsoft.App/jobs' $TickJobName 'executions') -All | Where-Object { $_ })
                $last = @($ex | Sort-Object { "$($_.properties.startTime)" } -Descending) | Select-Object -First 1
                return @{ readable = $true; status = "$($last.properties.status)"; at = "$($last.properties.startTime)" }
            }
            'engine-size' {
                # 100.31 / framework 12.15: the job's size vs the tier for the tenant count RECORDED on it at install (its
                # pim-sizing-* tags); no recorded count -> counted now (Graph $count as the installer). Never a stop.
                $jo = Get-CvArm (Get-CvResId 'Microsoft.App/jobs' $TickJobName)
                if (-not $jo) { return @{ readable = $false; error = "the engine job '$TickJobName' was not found" } }
                $res = @($jo.properties.template.containers)[0].resources
                $rec = ConvertFrom-PimTenantSizingTags -Tags $jo.tags -Job $TickJobName
                $counts = $rec.counts; $from = "recorded $($rec.sizedUtc)"
                if (-not $rec.recorded) {
                    $tok = Get-CvToken 'https://graph.microsoft.com'
                    if (-not $tok) { return @{ readable = $false; error = 'no tenant size is recorded on the job, and no Microsoft Graph token to count it' } }
                    $cnt = Get-PimTenantObjectCounts -GraphGet { param($p) Invoke-RestMethod -Uri ('https://graph.microsoft.com/v1.0' + $p) -Headers @{ Authorization = "Bearer $tok"; ConsistencyLevel = 'eventual' } -TimeoutSec 60 }
                    if (-not $cnt.ok) { return @{ readable = $false; error = "no tenant size is recorded on the job, and counting failed: $($cnt.error)" } }
                    $counts = @{ Users = $cnt.Users; Groups = $cnt.Groups; ServicePrincipals = $cnt.ServicePrincipals }; $from = 'counted now'
                }
                $u = Test-PimJobUndersized -Counts $counts -Cpu "$($res.cpu)" -Memory "$($res.memory)" -ReplicaTimeout ([int]"0$($jo.properties.configuration.replicaTimeout)") `
                        -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -JobName $TickJobName
                return @{ readable = $true; undersized = [bool]$u.undersized; reason = "$($u.reason) ($from)"; command = "$($u.command)" }
            }
            'easyauth' {
                # ARM's authConfigs/current carries platform / identityProviders under .properties (az flattened them)
                $auth = (Get-CvArm (Get-CvResId 'Microsoft.App/containerApps' $ManagerApp 'authConfigs/current')).properties
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
                $n = Get-CvArm (Get-CvResId 'Microsoft.Sql/servers' $sqlServer 'firewallRules/AllowSetupHost' $sqlRg) 'sql'
                return @{ readable = $true; present = [bool]$n; owner = $SetupHostRuleOwner; closingStep = $ClosingStep }
            }
            'msp-registered' {
                return @{ readable = $false; value = $null; step = $(if ("$ManagingTenantStep".Trim()) { "$ManagingTenantStep" } else { 'the managing tenant registers this tenant in its build (Invoke-PimMspBuild -Role Master -From register-<n>), or by itself with an enrollment key' }) }
            }
            'msp-subnet' {
                $step = if ("$ManagingTenantStep".Trim()) { "$ManagingTenantStep" } else { 'the managing tenant allows this subnet (Invoke-PimMspBuild -Role Master -From network-<n>), or by itself with an enrollment key' }
                if (-not "$MasterSubscriptionId".Trim() -or -not "$MasterStorageAccount".Trim() -or -not "$EnvName".Trim()) { return @{ readable = $false; value = $null; step = $step } }
                $subnet = "$((Get-CvArm (Get-CvResId 'Microsoft.App/managedEnvironments' $EnvName)).properties.vnetConfiguration.infrastructureSubnetId)"
                # the managing tenant's account, found by name in ITS subscription (az storage account show -n, no -g)
                $acct = $null
                try { $acct = @(Get-CvArm "/subscriptions/$MasterSubscriptionId/providers/Microsoft.Storage/storageAccounts" 'storage' -All | Where-Object { $_ -and "$($_.name)" -ieq $MasterStorageAccount }) | Select-Object -First 1 } catch { $acct = $null }
                if (-not $acct) { return @{ readable = $false; value = $null; step = $step } }
                $rules = @(@($acct.properties.networkAcls.virtualNetworkRules) | ForEach-Object { "$($_.id)" })
                $hit = @($rules | Where-Object { "$_".Trim() -and "$_".Trim() -ieq "$subnet".Trim() }).Count -gt 0
                return @{ readable = $true; value = $hit; detail = $(if ($hit) { "this subnet is allowed on $MasterStorageAccount" } else { "this subnet is NOT allowed on $MasterStorageAccount -- $step" }); step = $step }
            }
            'msp-first-pull' {
                $ex = @(Get-CvArm (Get-CvResId 'Microsoft.App/jobs' $DownlinkJobName 'executions') -All | Where-Object { $_ })
                $last = @($ex | Sort-Object { "$($_.properties.startTime)" } -Descending) | Select-Object -First 1
                return @{ readable = $true; status = "$($last.properties.status)"; at = "$($last.properties.startTime)" }
            }
        }
    } catch {
        $ex = $_.Exception
        return @{ readable = $false; error = (("$($ex.Message)" -split "`n")[0]); store = [bool]($ex.Data -and $ex.Data.Contains('pimStore')) }
    }
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
                $img = "$(@((Get-CvArm (Get-CvResId 'Microsoft.App/containerApps' $ManagerApp)).properties.template.containers)[0].image)".Trim()
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
            'manager-rg-reader' {
                $oid = "$(Get-PimFactValue $Fact 'objectId')"; if (-not $oid) { try { $oid = Get-CvMiOid 'app' $ManagerApp } catch { $oid = '' } }
                if (-not $oid) { return $false }
                if (-not (Get-Command Grant-PimManagerRgReader -ErrorAction SilentlyContinue)) { . (Join-Path $here '_PimSetupShared.ps1') }
                Write-Host '    repair: grant the Manager Reader on the PIM resource group only (one attempt)' -ForegroundColor Yellow
                $r = Grant-PimManagerRgReader -MiObjectId $oid -Name $ManagerApp -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup
                return [bool]$r.ok
            }
            'sql-host-rule' {
                if ($SetupHostRuleOwner -ne 'this' -or -not $CloseSetupHostRule) { return $false }
                Write-Host "    repair: remove this run's 'AllowSetupHost' from $sqlServer" -ForegroundColor Yellow
                Connect-CvRest
                [void](Remove-PimArmSqlFirewallRule -SubscriptionId $SubscriptionId -ResourceGroup $sqlRg -Server $sqlServer -Name 'AllowSetupHost')
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
$fix['engine-graph'] = (Get-PimSupportScriptCommand -Script 'Grant-PimEnginePermissions' -Run @(".\Grant-PimEnginePermissions.ps1 -TenantId '$TenantId' -EngineObjectId '<engine job object id>' -GraphPermissions <the missing ones above>   (a Privileged Role Administrator, browser sign-in)")) -join "`n"
$fix['engine-root-reader'] = ''
# PIM 100.22 (b): the Manager's Reader on the resource group -- the exact command (the object id is filled in below once read)
$fix['manager-rg-reader'] = "az role assignment create --subscription $SubscriptionId --assignee-object-id <Manager managed identity object id> --assignee-principal-type ServicePrincipal --role Reader --scope /subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup`n(an Owner or User Access Administrator of the resource group; or Azure portal > the resource group > Access control (IAM) > Add role assignment > Reader > the managed identity $ManagerApp)"
$fix['easyauth'] = (@("Microsoft Entra admin center > Enterprise applications > the PIM Manager's sign-in application > Users and groups: assign the SuperAdmins (or a group that holds them)", (& $viaResume 'the check')) | Where-Object { $_ }) -join "`n"
$fix['sql-host-rule'] = "az sql server firewall-rule delete --subscription $SubscriptionId -g $sqlRg -s $sqlServer -n AllowSetupHost   (or Azure portal > SQL server > Networking: remove 'AllowSetupHost')"
$fix['msp-registered'] = 'on the managing tenant: Invoke-PimMspBuild.ps1 -Role Master -ConfigPath <its config> -Apply -From register-<n> (with an enrollment key this happens by itself)'
$fix['msp-subnet'] = "on the managing tenant: add this tenant's pull subnet id as slaves[<n>].subnetResourceId, then Invoke-PimMspBuild.ps1 -Role Master -ConfigPath <its config> -Apply -From network-<n> (with an enrollment key this happens by itself)"
$fix['msp-first-pull'] = "az containerapp job start -n $DownlinkJobName -g $ResourceGroup --subscription $SubscriptionId   (after the managing tenant allows the subnet)"
$fix['engine-size'] = (Get-PimJobSizeCommand -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -JobName $TickJobName -Cpu '2.0' -Memory '4.0Gi' -ReplicaTimeout 7200) + '   (4.0 CPU / 8Gi / 14400 from 15,000 objects)'
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
$moid = "$(Get-PimFactValue $facts['manager-rg-reader'] 'objectId')"
if ($moid) { $fix['manager-rg-reader'] = $fix['manager-rg-reader'].Replace('<Manager managed identity object id>', $moid) }

# Repair pass: a line that FAILS and has a repair is repaired once, then read again.
$rows0 = Get-PimInstallVerifyRows -Role $Role -Facts $facts -Fix $fix -LicenceExpected ([bool]$LicenceExpected)
foreach ($r in @($rows0 | Where-Object { ($_.state -eq 'failed' -and $_.id -in 'superadmins', 'updater', 'alerting', 'engine-root-reader', 'sql-host-rule') -or ($_.state -eq 'warning' -and $_.id -eq 'engine-root-reader') -or
                                    ($_.state -eq 'warning' -and $_.id -eq 'manager-rg-reader' -and [bool](Get-PimFactValue $facts[$_.id] 'readable')) })) {
    if ($r.id -eq 'sql-host-rule' -and -not [bool](Get-PimFactValue $facts[$r.id] 'readable')) { continue }
    # a line the STORE could not be read for is never "repaired": what is there is unknown, and a write (Set-PimManagerAccess,
    # Set-PimAlertRecipients) over an unread value could replace what an administrator chose. It stays not-done (fail closed).
    if ((Get-PimFactValue $facts[$r.id] 'readable') -eq $false -and [bool](Get-PimFactValue $facts[$r.id] 'store')) { continue }
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
