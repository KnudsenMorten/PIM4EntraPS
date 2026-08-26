#Requires -Version 5.1
<#
.SYNOPSIS
  IMP-06 -- make an environment able to send its own notification mail, UNATTENDED.

.DESCRIPTION
  Operator directive 2026-08-12: *"the onboarding scripts must handle this prep unattended"*. Doing
  these steps by hand in a portal is the DEFECT, not the workaround: every future tenant would
  otherwise land in the state EFIF was in -- engine provisions fine, mail never sends, and nothing
  reports an error.

  Why "nothing reports an error" is the whole point. With no sender configured the notify path
  RENDERS the mail and returns without sending (PIM-Notify.ps1 L201, a warning only), while account
  creation and TAP minting still report success. A mail-mute environment therefore looks completely
  healthy, and the first symptom is a TAP that never arrives -- days later, blamed on the TAP
  provider. That is why the precondition below FAILS LOUDLY rather than warning.

  Four steps, each idempotent and each VERIFIED BY READING BACK rather than by trusting its own
  create call:

    0. PRECONDITION -- the tenant must have a real Exchange Online plan.
       🪤 `assignedPlans` reporting `exchange = Enabled` is NOT the signal. EXCHANGE_S_FOUNDATION
       rides along with Entra P2 and reports exactly that while mailbox creation is impossible --
       it provisions directory objects only. The signal is an Exchange service plan in
       `subscribedSkus` BEYOND Foundation (e.g. EXCHANGE_S_STANDARD). Measured on EFIF: the org
       looked mail-capable and `New-Mailbox -Shared` would still have failed, for a reason the
       status does not hint at.
    1. CREATE THE SHARED SENDER MAILBOX (default `PIM-Engine@<initial domain>`). A shared mailbox
       is the designed sender and is FREE once an EXO plan exists -- admin accounts themselves need
       no mailbox and no licence, because the engine mails *about* them, not *as* them.
    2. GRANT SEND ACCESS *SCOPED TO THAT ONE MAILBOX*, via Exchange RBAC for Applications.
    3. ENSURE NO TENANT-WIDE Graph `Mail.Send` CONSENT EXISTS -- revoking it if it does.

  ⚠️ STEPS 2 AND 3 ARE INVERTED FROM IMP-06 AS WRITTEN, and the inversion is load-bearing.
  The finding said "grant Mail.Send, then scope it with an Application Access Policy". Measured in
  EFIF, doing exactly that leaves the app UNSCOPED: Exchange RBAC does not RESTRICT a tenant-wide
  Graph consent, it GRANTS scoped access in its own right, and a tenant-wide consent alongside it
  keeps winning. Proven both directions, ~60 minutes apart so propagation is not the explanation:
    * WITH the Graph consent    -- in-scope send ACCEPTED, out-of-scope send ACCEPTED  (unscoped)
    * WITHOUT the Graph consent -- in-scope send ACCEPTED, out-of-scope send DENIED    (scoped)
  So the right configuration grants NO tenant-wide permission at all. That is strictly better than
  the finding asked for: there is never a tenant-wide send right to claw back.

  🔒 WHICH IDENTITY DOES THE WORK, and why it is not the obvious one.
  Exchange administration is done by the ONBOARDING SPN (-AdminAppId/-AdminSecret), never by the
  engine SPN. The obvious-looking alternative -- grant the engine SPN `Exchange.ManageAsApp` + the
  Exchange Administrator directory role -- hands the LONG-LIVED RUNTIME identity tenant-wide
  Exchange administration in order to create a single mailbox. That is a strictly BIGGER grant than
  the Application Access Policy in step 3 exists to claw back, so it would defeat the finding it is
  meant to implement. The onboarding SPN is a provisioning-time credential that already elevates
  itself to Global Administrator + Owner, so it is the correct holder of a transient Exchange grant.
  Net result: the engine SPN ends up with `Mail.Send` SCOPED TO ONE MAILBOX and nothing else.

  Measured on EFIF before this script existed: the engine SPN held ~100 Graph app-roles but NOT
  Mail.Send, NOT Exchange.ManageAsApp, and no directory role at all -- its EXO token came back with
  an empty `roles` claim and the admin endpoint answered 401.

  REST-only: no ExchangeOnlineManagement module, no Graph SDK, no `az`. Exchange is driven through
  the `/adminapi/beta/<tenant>/InvokeCommand` endpoint that the EXO V3 module itself uses.

.PARAMETER OutFile
  Where to write the result JSON ({ ok, sender, ... }). This is how the orchestrator gets the sender
  UPN back: each onboarding step runs in its OWN process with stdout redirected to a log, so a
  return value cannot travel any other way. Initialize-PlatformEnvironment reads it and passes the
  UPN to Setup-PimContainers as -MailSender.

.NOTES
  🪤 An Application Access Policy can take up to ~30 minutes to take effect tenant-wide. A send
  attempted immediately after this script may still fail; that is Microsoft-side propagation, not a
  misconfiguration. The policy is verified as EXISTING here, which is what this script can honestly
  assert.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$TenantId,
    # The ONBOARDING SPN -- privileged, provisioning-time. See the identity note above.
    [Parameter(Mandatory)][string]$AdminAppId,
    [Parameter(Mandatory)][string]$AdminSecret,
    # The engine SPN that will receive scoped Mail.Send. Read from the environment's own Key Vault
    # ('Modern-AppId') when not supplied.
    [string]$EngineAppId,
    [string]$KeyVaultName,
    [string]$BootstrapAppId,
    [string]$BootstrapThumbprint,
    # Local part of the sender mailbox. The domain is the tenant's initial (onmicrosoft.com) domain
    # unless -MailDomain says otherwise -- a freshly-onboarded tenant has no custom domain, and
    # guessing one produces a mailbox nobody can receive from.
    [string]$MailboxName  = 'PIM-Engine',
    [string]$MailDomain,
    [string]$DisplayName  = 'PIM4EntraPS Engine (notifications)',
    # Where the sender is PERSISTED (IMP-06a runtime half). Writing it to pim.Settings is what lets
    # this script run AFTER the containers are already deployed: the store overrides the deploy-time
    # env var and a cold-booted tick Job hydrates it on its next run, so no redeploy is needed.
    # Optional -- without it the sender still travels via -OutFile / -MailSender at deploy time.
    [string]$SqlServerFqdn,
    [string]$SqlDatabase  = 'PimPlatform',
    [string]$OutFile,
    # Exchange provisioning after a licence lands is not instant, and neither is app-role
    # propagation. Bounded, and it reports what it waited for rather than hanging silently.
    [int]$TimeoutSeconds  = 600
)

$ErrorActionPreference = 'Stop'
$here = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
$solRoot = Split-Path -Parent (Split-Path -Parent $here)   # ...\SOLUTIONS\PIM4EntraPS
. (Join-Path $solRoot 'engine\_shared\PIM-Rest.ps1')

$graphResourceAppId = '00000003-0000-0000-c000-000000000000'   # Microsoft Graph
$exoResourceAppId   = '00000002-0000-0ff1-ce00-000000000000'   # Office 365 Exchange Online

$result = [ordered]@{
    ok = $false; sender = ''; tenantId = $TenantId; engineAppId = ''
    exchangePlan = ''; mailboxCreated = $false; mailSendGranted = $false
    accessPolicyCreated = $false; steps = @(); reason = ''
}
function Note($m, $c = 'Gray') { Write-Host "    $m" -ForegroundColor $c }
function Step($m) { Write-Host "`n--- $m ---" -ForegroundColor Cyan }
function Add-Result($name, $state, $detail) { $result.steps += [ordered]@{ step = $name; state = $state; detail = $detail } }

function Write-ResultFile {
    if (-not "$OutFile".Trim()) { return }
    try {
        $dir = Split-Path -Parent $OutFile
        if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
        # -WhatIf:$false deliberately. This file is a LOCAL REPORT of what happened (or would
        # happen), not a change to the environment -- and under -WhatIf the write was suppressed
        # while the script still logged "result written", which is a log that lies.
        ($result | ConvertTo-Json -Depth 8) | Set-Content -LiteralPath $OutFile -Encoding utf8 -WhatIf:$false
        Note "result written: $OutFile" 'DarkGray'
    } catch { Write-Warning "could not write -OutFile '$OutFile': $($_.Exception.Message)" }
}
# A failure must still leave a readable result behind -- the orchestrator reads the file, and an
# absent file is indistinguishable from a step that never ran.
function Fail($reason) {
    $result.reason = $reason
    Write-ResultFile
    Write-Host "`nRESULT: FAILED -- $reason" -ForegroundColor Red
    exit 1
}

Write-Host ("=" * 78) -ForegroundColor Cyan
Write-Host " PIM MAIL SENDER (IMP-06)  tenant $TenantId" -ForegroundColor Cyan
Write-Host ("=" * 78) -ForegroundColor Cyan

# --- tokens -------------------------------------------------------------------
# The onboarding SPN authenticates with a SECRET here because that is the credential the estate
# onboarding path already carries for it (workbook / kv-automatit-dev). The ENGINE never uses a
# secret -- it is cert-only -- and this script never gives it one.
Step 'authenticate (onboarding SPN)'
try {
    $graphTok = Get-PimRestToken -Resource 'graph' -TenantId $TenantId -ClientId $AdminAppId -ClientSecret $AdminSecret -Force
} catch { Fail "could not acquire a Graph token as the onboarding SPN ($AdminAppId): $($_.Exception.Message)" }
$GH = @{ Authorization = "Bearer $graphTok"; 'Content-Type' = 'application/json' }
function Gr {
    param([string]$Method = 'GET', [Parameter(Mandatory)][string]$Path, [object]$Body)
    $u = if ($Path -like 'http*') { $Path } else { "https://graph.microsoft.com/v1.0/$Path" }
    $a = @{ Method = $Method; Uri = $u; Headers = $GH }
    if ($null -ne $Body) { $a.Body = ($Body | ConvertTo-Json -Depth 20) }
    Invoke-RestMethod @a
}
Note "onboarding SPN: $AdminAppId" 'DarkGray'

function Confirm-Eventually {
    <#
      Verify by READING BACK, but tolerate Graph's eventual consistency.
      🪤 MEASURED, not theoretical: the first live run of this script granted Mail.Send, got a 2xx,
      and then failed its own verification because the assignment was not yet queryable. A single
      read-back after a write is therefore a FLAKY GATE -- it reports a successful grant as a
      failure, and the natural "fix" (drop the verification) would be the wrong one, since the
      whole point is not to trust the POST. Poll instead: still a real gate, just one that gives
      the directory time to converge. Same class as the deleted-users-still-listed lag in the
      session-22 handoff.
    #>
    param([Parameter(Mandatory)][scriptblock]$Test, [int]$Seconds = 90, [string]$What = 'change')
    $stop = (Get-Date).AddSeconds($Seconds); $n = 0
    while ($true) {
        $n++
        try { if (& $Test) { if ($n -gt 1) { Note "$What visible after $n read(s)" 'DarkGray' }; return $true } } catch { }
        if ((Get-Date) -ge $stop) { return $false }
        Start-Sleep -Seconds 5
    }
}

# --- 0. PRECONDITION: a real Exchange plan ------------------------------------
Step '[0] precondition -- Exchange Online plan present'
try { $skus = @((Gr -Path 'subscribedSkus').value) }
catch { Fail "could not read subscribedSkus: $($_.Exception.Message)" }

# BEYOND Foundation is the test. Foundation alone = directory objects only, no mailboxes, while
# assignedPlans still says "exchange = Enabled".
$exchangePlans = @($skus.servicePlans |
    Where-Object { $_.servicePlanName -like '*EXCHANGE*' -and $_.servicePlanName -ne 'EXCHANGE_S_FOUNDATION' } |
    ForEach-Object { $_.servicePlanName } | Sort-Object -Unique)
foreach ($s in $skus) { Note ("sku {0,-28} enabled={1}" -f $s.skuPartNumber, $s.prepaidUnits.enabled) 'DarkGray' }

if (-not $exchangePlans.Count) {
    Add-Result 'precondition' 'FAILED' 'no Exchange service plan beyond EXCHANGE_S_FOUNDATION'
    Fail @"
no Exchange Online plan in this tenant -- a shared sender mailbox CANNOT be created.
  Found SKUs: $(($skus.skuPartNumber) -join ', ')
  🪤 If you are about to object that 'exchange' shows Enabled: that is EXCHANGE_S_FOUNDATION riding
     along with Entra P2. It provisions DIRECTORY OBJECTS ONLY -- New-Mailbox -Shared still fails.
     The signal is an Exchange-bearing SKU (e.g. EXCHANGESTANDARD -> EXCHANGE_S_STANDARD).
  FIX: assign an Exchange Online plan to the tenant (a trial suffices), then re-run.
       The licence is a human/commercial step by design; everything after it is automated here.
  This is FATAL, not a warning, because continuing would leave a MAIL-MUTE environment that reports
  success everywhere: the engine would render notification mail and never send it, and the first
  symptom would be a TAP that never arrives.
"@
}
$result.exchangePlan = ($exchangePlans -join ', ')
Note "Exchange plan(s) beyond Foundation: $($exchangePlans -join ', ')" 'Green'
Add-Result 'precondition' 'ok' ($exchangePlans -join ', ')

# --- resolve the sender address ------------------------------------------------
Step 'resolve sender address'
try { $org = (Gr -Path 'organization').value[0] } catch { Fail "could not read organization: $($_.Exception.Message)" }
$initialDomain = ($org.verifiedDomains | Where-Object { $_.isInitial } | Select-Object -First 1).name
$domain = if ("$MailDomain".Trim()) { $MailDomain.Trim() } else { $initialDomain }
if (-not $domain) { Fail 'could not resolve a mail domain (no initial verified domain on the organization)' }
$sender = "$MailboxName@$domain"
$result.sender = $sender
Note "sender: $sender" 'Green'

# --- resolve the engine SPN ----------------------------------------------------
Step 'resolve the engine SPN (receives the SCOPED Mail.Send)'
if (-not "$EngineAppId".Trim()) {
    if (-not ("$KeyVaultName".Trim() -and "$BootstrapAppId".Trim() -and "$BootstrapThumbprint".Trim())) {
        Fail 'no -EngineAppId, and no -KeyVaultName/-BootstrapAppId/-BootstrapThumbprint to read Modern-AppId from'
    }
    try {
        $kvTok = Get-PimRestToken -Resource 'https://vault.azure.net' -TenantId $TenantId -ClientId $BootstrapAppId -CertThumbprint $BootstrapThumbprint -Force
        $EngineAppId = (Invoke-RestMethod -Headers @{ Authorization = "Bearer $kvTok" } `
            -Uri "https://$KeyVaultName.vault.azure.net/secrets/Modern-AppId`?api-version=7.4").value
    } catch { Fail "could not read Modern-AppId from $KeyVaultName : $($_.Exception.Message)" }
}
$EngineAppId = "$EngineAppId".Trim()
$result.engineAppId = $EngineAppId
$engineSp = (Gr -Path "servicePrincipals?`$filter=appId eq '$EngineAppId'").value | Select-Object -First 1
if (-not $engineSp) { Fail "engine service principal not found for appId $EngineAppId" }
Note "engine SPN: $EngineAppId (objectId $($engineSp.id))" 'DarkGray'

# Resolve the Graph Mail.Send role now, but DO NOT GRANT IT YET -- see the ordering note at the
# grant step near the end of this script. Resolving early keeps the failure "this tenant has no
# Mail.Send role" separate from anything Exchange does.
$graphSp = (Gr -Path "servicePrincipals?`$filter=appId eq '$graphResourceAppId'").value | Select-Object -First 1
if (-not $graphSp) { Fail 'Microsoft Graph service principal not found in tenant' }
$mailSendRole = $graphSp.appRoles | Where-Object { $_.value -eq 'Mail.Send' -and $_.allowedMemberTypes -contains 'Application' } | Select-Object -First 1
if (-not $mailSendRole) { Fail 'Mail.Send app-role not found on the Graph service principal' }

# --- enable the ONBOARDING SPN to drive Exchange -------------------------------
# Transient, and on the provisioning identity by design (see the header). Two things are needed:
# the Exchange.ManageAsApp app-role, and the Exchange Administrator DIRECTORY role -- the app-role
# alone yields a token whose `roles` claim is empty and an admin endpoint that answers 401.
Step 'enable Exchange administration for the onboarding SPN (transient, provisioning-time)'
$adminSp = (Gr -Path "servicePrincipals?`$filter=appId eq '$AdminAppId'").value | Select-Object -First 1
if (-not $adminSp) { Fail "onboarding service principal not found for appId $AdminAppId" }

$exoSp = (Gr -Path "servicePrincipals?`$filter=appId eq '$exoResourceAppId'").value | Select-Object -First 1
if (-not $exoSp) { Fail 'Office 365 Exchange Online service principal not found in tenant (no EXO plan provisioned yet?)' }
$manageAsApp = $exoSp.appRoles | Where-Object { $_.value -eq 'Exchange.ManageAsApp' -and $_.allowedMemberTypes -contains 'Application' } | Select-Object -First 1
if (-not $manageAsApp) { Fail 'Exchange.ManageAsApp app-role not found on the Exchange Online service principal' }

$hasManage = @((Gr -Path "servicePrincipals/$($adminSp.id)/appRoleAssignments").value |
    Where-Object { $_.resourceId -eq $exoSp.id -and $_.appRoleId -eq $manageAsApp.id })
if ($hasManage.Count) { Note 'Exchange.ManageAsApp already held' 'DarkGray' }
elseif ($PSCmdlet.ShouldProcess($AdminAppId, 'grant Exchange.ManageAsApp')) {
    try {
        Gr -Method POST -Path "servicePrincipals/$($adminSp.id)/appRoleAssignments" `
            -Body @{ principalId = $adminSp.id; resourceId = $exoSp.id; appRoleId = $manageAsApp.id } | Out-Null
        Note 'Exchange.ManageAsApp granted' 'Green'
    } catch { Fail "could not grant Exchange.ManageAsApp to the onboarding SPN: $($_.Exception.Message)" }
}

$exchAdminRole = (Gr -Path "roleManagement/directory/roleDefinitions?`$filter=displayName eq 'Exchange Administrator'").value | Select-Object -First 1
if (-not $exchAdminRole) { Fail "'Exchange Administrator' role definition not found" }
$hasExchAdmin = @((Gr -Path "roleManagement/directory/roleAssignments?`$filter=principalId eq '$($adminSp.id)'").value |
    Where-Object { $_.roleDefinitionId -eq $exchAdminRole.id })
if ($hasExchAdmin.Count) { Note 'Exchange Administrator already assigned' 'DarkGray' }
elseif ($PSCmdlet.ShouldProcess($AdminAppId, 'assign Exchange Administrator')) {
    try {
        Gr -Method POST -Path 'roleManagement/directory/roleAssignments' `
            -Body @{ principalId = $adminSp.id; roleDefinitionId = $exchAdminRole.id; directoryScopeId = '/' } | Out-Null
        Note 'Exchange Administrator assigned' 'Green'
    } catch { Fail "could not assign Exchange Administrator to the onboarding SPN: $($_.Exception.Message)" }
}

if ($WhatIfPreference) {
    Note 'WhatIf: stopping before any Exchange call' 'DarkYellow'
    Add-Result 'exchange' 'whatif' 'would create mailbox + access policy'
    $result.ok = $true; Write-ResultFile; exit 0
}

# --- Exchange Online admin REST ------------------------------------------------
# The transport the EXO V3 module uses internally. Token audience is outlook.office365.com; a token
# minted BEFORE the grants above will carry an empty `roles` claim, so it is always minted fresh
# (-Force) and retried while the grant propagates.
$exoUri = "https://outlook.office365.com/adminapi/beta/$TenantId/InvokeCommand"
$anchor = "UPN:SystemMailbox{bb558c35-97f1-4cb9-8ff7-d53741dc928c}@$initialDomain"
function Invoke-Exo {
    param([Parameter(Mandatory)][string]$Cmdlet, [hashtable]$Parameters = @{})
    $tok = Get-PimRestToken -Resource 'https://outlook.office365.com' -TenantId $TenantId -ClientId $AdminAppId -ClientSecret $AdminSecret -Force
    $h = @{ Authorization = "Bearer $tok"; 'Content-Type' = 'application/json'
            'X-ResponseFormat' = 'json'; 'X-AnchorMailbox' = $anchor }
    $body = @{ CmdletInput = @{ CmdletName = $Cmdlet; Parameters = $Parameters } } | ConvertTo-Json -Depth 10
    Invoke-RestMethod -Method POST -Uri $exoUri -Headers $h -Body $body
}

Step 'wait for Exchange administration to become usable'
# Two independent delays are being absorbed here, and they look identical from outside: app-role
# propagation (seconds to minutes) and EXO org provisioning after a licence lands (can be longer).
# Reporting the elapsed wait is what makes them distinguishable in a log afterwards.
$deadline = (Get-Date).AddSeconds($TimeoutSeconds)
$ready = $false; $lastErr = ''
$attempt = 0
while ((Get-Date) -lt $deadline) {
    $attempt++
    try { [void](Invoke-Exo -Cmdlet 'Get-OrganizationConfig'); $ready = $true; break }
    catch {
        $lastErr = ($_.Exception.Message -split "`n")[0]
        Note "attempt $attempt : not ready yet ($lastErr)" 'DarkGray'
        Start-Sleep -Seconds 20
    }
}
if (-not $ready) {
    Add-Result 'exchange-ready' 'FAILED' $lastErr
    Fail "Exchange admin endpoint never became usable within ${TimeoutSeconds}s (last error: $lastErr). Both app-role propagation and EXO org provisioning can cause this; re-running is safe and idempotent."
}
Note "Exchange administration usable after $attempt attempt(s)" 'Green'
Add-Result 'exchange-ready' 'ok' "$attempt attempt(s)"

# --- 1. CREATE THE SHARED SENDER MAILBOX ---------------------------------------
Step "[1] shared sender mailbox  $sender"
$existingMbx = $null
try {
    $r = Invoke-Exo -Cmdlet 'Get-Mailbox' -Parameters @{ Identity = $sender }
    $existingMbx = @($r.value) | Select-Object -First 1
} catch { $existingMbx = $null }   # not-found is the normal first-run path, not an error

if ($existingMbx) {
    Note "mailbox already exists (RecipientTypeDetails=$($existingMbx.RecipientTypeDetails))" 'DarkGray'
    Add-Result 'mailbox' 'already' "$($existingMbx.PrimarySmtpAddress)"
} else {
    try {
        [void](Invoke-Exo -Cmdlet 'New-Mailbox' -Parameters @{
            Shared = $true; Name = $MailboxName; DisplayName = $DisplayName; PrimarySmtpAddress = $sender })
    } catch {
        $m = ($_.Exception.Message -split "`n")[0]
        $detail = if ($_.ErrorDetails.Message) { $_.ErrorDetails.Message.Substring(0, [Math]::Min(400, $_.ErrorDetails.Message.Length)) } else { '' }
        Add-Result 'mailbox' 'FAILED' "$m $detail"
        Fail "could not create the shared mailbox '$sender': $m $detail"
    }
    # Read back. A shared mailbox can take a moment to become queryable, so this is a bounded poll
    # rather than a single read -- and a create that never becomes visible is a FAILURE, not a pass.
    $mbxDeadline = (Get-Date).AddSeconds(180); $seen = $null
    while ((Get-Date) -lt $mbxDeadline) {
        try { $seen = @((Invoke-Exo -Cmdlet 'Get-Mailbox' -Parameters @{ Identity = $sender }).value) | Select-Object -First 1 } catch { $seen = $null }
        if ($seen) { break }
        Start-Sleep -Seconds 10
    }
    if (-not $seen) { Add-Result 'mailbox' 'FAILED' 'created but never became queryable'; Fail "mailbox '$sender' was created but never became queryable within 180s" }
    Note "mailbox created (verified by read-back): $($seen.PrimarySmtpAddress)" 'Green'
    $result.mailboxCreated = $true
    Add-Result 'mailbox' 'created' "$($seen.PrimarySmtpAddress)"
}

# --- 3. SCOPE THE SEND RIGHT TO THAT ONE MAILBOX -------------------------------
# Exchange Online RBAC FOR APPLICATIONS, not an Application Access Policy. Both express "this app
# may only touch this mailbox"; the RBAC one is chosen because it is the one that WORKS AND CAN BE
# READ BACK. Measured in EFIF: Get-ApplicationAccessPolicy answers 404 and New-ApplicationAccessPolicy
# answers 400/500, so an AAP could be neither verified nor made idempotent -- and an unverifiable
# security control is not a security control. Get-ManagementRoleAssignment / Get-ManagementScope
# both read cleanly, so every step below is gated on a real read-back.
#
# Three objects:
#   New-ServicePrincipal          register the engine app inside Exchange
#   New-ManagementScope           a recipient scope matching EXACTLY the sender mailbox
#   New-ManagementRoleAssignment  'Application Mail.Send' bound to the app AND that scope
Step "[3] scope the send right to $sender (Exchange RBAC for applications)"

# 3a. hydrate the organization. A fresh EXO tenant is "dehydrated" and REFUSES every custom RBAC
#     create with InvalidOperationInDehydratedContextException -- a 400 that reads like a bad
#     request and actually means "not yet".
# 🪤 MEASURED, and this is the trap: Enable-OrganizationCustomization returns success immediately,
#    and Get-OrganizationConfig then reports IsDehydrated=FALSE while the creates STILL fail as
#    dehydrated. So the flag is NOT a readiness signal -- same shape as `exchange = Enabled` being
#    no proof of a mailbox. The only honest readiness test is to attempt the real operation and
#    retry, which is what Wait-Hydrated does. Do not "optimise" this into a flag check.
$dehydratedMarker = 'InvalidOperationInDehydratedContextException'
try {
    $oc = (Invoke-Exo -Cmdlet 'Get-OrganizationConfig').value[0]
    if ("$($oc.IsDehydrated)" -eq 'True') {
        Note 'organization is dehydrated -- enabling customization' 'DarkYellow'
        try { [void](Invoke-Exo -Cmdlet 'Enable-OrganizationCustomization') } catch {
            # Already-enabled is reported as an error by this cmdlet; not fatal.
            Note "Enable-OrganizationCustomization: $((($_.Exception.Message) -split "`n")[0])" 'DarkGray'
        }
    } else { Note 'organization reports hydrated' 'DarkGray' }
} catch { Note "could not read organization config: $((($_.Exception.Message) -split "`n")[0])" 'DarkYellow' }

function Invoke-ExoWhenHydrated {
    # Run an EXO create, retrying for as long as the org still answers "dehydrated". Any OTHER
    # error is returned immediately -- a real failure must not be hidden behind a long wait.
    param([Parameter(Mandatory)][string]$Cmdlet, [hashtable]$Parameters = @{}, [int]$Seconds = 3600, [string]$What = 'object')
    $stop = (Get-Date).AddSeconds($Seconds); $n = 0
    while ($true) {
        $n++
        try { return @{ ok = $true; value = (Invoke-Exo -Cmdlet $Cmdlet -Parameters $Parameters) } }
        catch {
            $e = $_
            $raw = "$($e.ErrorDetails.Message)"
            $isDehydrated = $raw -like "*$dehydratedMarker*"
            if (-not $isDehydrated) { return @{ ok = $false; error = ($e.Exception.Message -split "`n")[0]; detail = $raw } }
            if ((Get-Date) -ge $stop) { return @{ ok = $false; error = 'organization still dehydrated'; detail = $raw } }
            if ($n -eq 1 -or ($n % 5) -eq 0) { Note "waiting for organization customization to take effect ($What, attempt $n)" 'DarkGray' }
            Start-Sleep -Seconds 60
        }
    }
}

# 3b. register the engine app inside Exchange
$exoSpList = $null
try { $exoSpList = @((Invoke-Exo -Cmdlet 'Get-ServicePrincipal').value) } catch { $exoSpList = @() }
if (@($exoSpList | Where-Object { "$($_.AppId)" -eq $EngineAppId }).Count) {
    Note 'engine app already registered in Exchange' 'DarkGray'
} else {
    $r = Invoke-ExoWhenHydrated -Cmdlet 'New-ServicePrincipal' -What 'service principal' -Parameters @{
        AppId = $EngineAppId; ObjectId = $engineSp.id; DisplayName = 'PIM4EntraPS Engine' }
    if (-not $r.ok) { Add-Result 'exo-sp' 'FAILED' "$($r.error) $($r.detail)"; Fail "could not register the engine app in Exchange: $($r.error)" }
    Note 'engine app registered in Exchange' 'Green'
}

# 3c. a recipient scope containing exactly the sender mailbox
$scopeName = "PIM4EntraPS-Sender"
$scopes = $null
try { $scopes = @((Invoke-Exo -Cmdlet 'Get-ManagementScope').value) } catch { $scopes = @() }
if (@($scopes | Where-Object { "$($_.Name)" -eq $scopeName }).Count) {
    Note "management scope '$scopeName' already present" 'DarkGray'
} else {
    $r = Invoke-ExoWhenHydrated -Cmdlet 'New-ManagementScope' -What 'management scope' -Parameters @{
        Name = $scopeName; RecipientRestrictionFilter = "PrimarySmtpAddress -eq '$sender'" }
    if (-not $r.ok) { Add-Result 'exo-scope' 'FAILED' "$($r.error) $($r.detail)"; Fail "could not create the management scope: $($r.error)" }
    Note "management scope '$scopeName' created (-> $sender only)" 'Green'
}

# 3d. the scoped role assignment. THIS is the control: 'Application Mail.Send' bound to the app and
#     restricted by the scope above. Its absence is why the Graph grant is withheld until now.
$assignName = 'PIM4EntraPS-Engine-MailSend'
$assigns = $null
try { $assigns = @((Invoke-Exo -Cmdlet 'Get-ManagementRoleAssignment' -Parameters @{ RoleAssigneeType = 'ServicePrincipal' }).value) } catch { $assigns = @() }
$haveAssign = @($assigns | Where-Object { "$($_.Role)" -eq 'Application Mail.Send' -and "$($_.CustomResourceScope)" -eq $scopeName })
if ($haveAssign.Count) {
    Note 'scoped Application Mail.Send assignment already present' 'DarkGray'
    $result.accessPolicyCreated = $true; Add-Result 'exo-scoped-send' 'already' "$scopeName"
} else {
    $r = Invoke-ExoWhenHydrated -Cmdlet 'New-ManagementRoleAssignment' -What 'role assignment' -Parameters @{
        App = $EngineAppId; Role = 'Application Mail.Send'; CustomResourceScope = $scopeName; Name = $assignName }
    if (-not $r.ok) { Add-Result 'exo-scoped-send' 'FAILED' "$($r.error) $($r.detail)"; Fail "could not create the scoped Application Mail.Send assignment: $($r.error)" }
    # Read back -- the whole reason RBAC was chosen over an Application Access Policy.
    $confirmedScope = Confirm-Eventually -What 'scoped Mail.Send assignment' -Seconds 120 -Test {
        @((Invoke-Exo -Cmdlet 'Get-ManagementRoleAssignment' -Parameters @{ RoleAssigneeType = 'ServicePrincipal' }).value |
            Where-Object { "$($_.Role)" -eq 'Application Mail.Send' -and "$($_.CustomResourceScope)" -eq $scopeName }).Count -gt 0
    }
    if (-not $confirmedScope) { Add-Result 'exo-scoped-send' 'FAILED' 'not present on read-back'; Fail 'the scoped Mail.Send assignment was created but is not present on read-back' }
    Note "scoped Application Mail.Send assignment created (verified): $assignName -> $scopeName" 'Green'
    $result.accessPolicyCreated = $true; Add-Result 'exo-scoped-send' 'created' "$assignName -> $scopeName"
}

# --- 2. ENSURE THE ENGINE SPN DOES *NOT* HOLD TENANT-WIDE Mail.Send -------------
# 🔒 THIS IS INVERTED FROM IMP-06 AS WRITTEN, AND THE INVERSION IS THE WHOLE POINT.
# IMP-06 step 3 said "grant the engine SPN Mail.Send" and step 4 said "scope it". Measured in EFIF:
# doing both leaves the app UNSCOPED. Exchange RBAC for Applications does not RESTRICT a tenant-wide
# Graph consent -- it GRANTS scoped access in its own right, and a tenant-wide consent sitting
# alongside it simply keeps winning.
#
# Proven, both directions, ~60 minutes apart so propagation is not the explanation:
#   * WITH the Graph consent    -- send as the scoped mailbox: ACCEPTED.
#                                  send as a second out-of-scope mailbox: ACCEPTED.  <- unscoped
#   * WITHOUT the Graph consent -- Mail.Send verified GONE from the minted token, then
#                                  send as the scoped mailbox: ACCEPTED.   <- RBAC grants it
#                                  send as a second out-of-scope mailbox: ErrorAccessDenied. <- scoped
#
# So the correct configuration grants NO tenant-wide permission at all: the RBAC assignment created
# above is the entire grant, and it is scoped by construction. That is strictly better than what the
# finding asked for -- there is never a tenant-wide send right to claw back.
#
# An EXISTING grant must therefore be REVOKED, not left alone: its mere presence silently defeats the
# scope, and it is exactly what an earlier run of this very script (and any hand-done IMP-06) would
# have left behind.
Step '[2] ensure NO tenant-wide Graph Mail.Send on the engine SPN (it would defeat the scope)'
$existingGrant = @((Gr -Path "servicePrincipals/$($engineSp.id)/appRoleAssignments").value |
    Where-Object { $_.resourceId -eq $graphSp.id -and $_.appRoleId -eq $mailSendRole.id })
if (-not $existingGrant.Count) {
    Note 'no tenant-wide Mail.Send present -- correct; the scoped RBAC assignment is the grant' 'Green'
    $result.mailSendGranted = $false; Add-Result 'mail-send-tenantwide' 'absent' 'correct (RBAC grants, scoped)'
} elseif ($PSCmdlet.ShouldProcess($EngineAppId, 'REVOKE tenant-wide Graph Mail.Send')) {
    Note "found $($existingGrant.Count) tenant-wide Mail.Send assignment(s) -- REVOKING (they defeat the scope)" 'DarkYellow'
    foreach ($a in $existingGrant) {
        try { Gr -Method DELETE -Path "servicePrincipals/$($engineSp.id)/appRoleAssignments/$($a.id)" | Out-Null }
        catch { Fail "could not revoke tenant-wide Mail.Send ($($a.id)): $($_.Exception.Message)" }
    }
    $revoked = Confirm-Eventually -What 'Mail.Send revocation' -Test {
        @((Gr -Path "servicePrincipals/$($engineSp.id)/appRoleAssignments").value |
            Where-Object { $_.resourceId -eq $graphSp.id -and $_.appRoleId -eq $mailSendRole.id }).Count -eq 0
    }
    if (-not $revoked) { Fail 'tenant-wide Mail.Send was deleted but is still present on read-back -- the send right is NOT scoped' }
    Note 'tenant-wide Mail.Send revoked (verified by read-back)' 'Green'
    $result.mailSendGranted = $false; Add-Result 'mail-send-tenantwide' 'revoked' 'removed so the RBAC scope governs'
} else { Add-Result 'mail-send-tenantwide' 'whatif' 'would revoke' }

# --- 4. PERSIST THE SENDER (IMP-06a runtime half) --------------------------------
# This is the step that actually makes the environment send. Everything above only made it
# POSSIBLE: without a configured sender the notify path still renders and returns quietly.
Step '[4] persist the sender to pim.Settings'
if (-not "$SqlServerFqdn".Trim()) {
    Note 'no -SqlServerFqdn given -- NOT persisted. The sender must reach the engine some other way' 'DarkYellow'
    Note "(pass -MailSender '$sender' to Setup-PimContainers, or set 'MailSender' in pim.Settings by hand)" 'DarkYellow'
    Add-Result 'persist' 'skipped' 'no -SqlServerFqdn'
} else {
    . (Join-Path $solRoot 'engine\_shared\PIM-SqlStore.ps1')
    # An EXPLICIT credential beats ambient managed identity in New-PimSqlConnection, which matters
    # here: mgmt1 has an MI of its own, and an MI can only mint tokens for ITS OWN tenant, so an
    # ambient token would authenticate successfully against the WRONG directory (BUG-34). The
    # onboarding SPN is the SQL server's Entra admin, so it is the identity that can write.
    $global:PIM_TenantId     = $TenantId
    $global:PIM_ClientId     = $AdminAppId
    $global:PIM_ClientSecret = $AdminSecret
    $global:PIM_SqlServer    = $SqlServerFqdn
    $global:PIM_SqlDatabase  = $SqlDatabase
    try {
        $cs = Get-PimSqlConnectionString -Server $SqlServerFqdn -Database $SqlDatabase
        Set-PimSqlSetting -ConnectionString $cs -Name 'MailSender' -Value $sender
        # Read back through the same reader the ENGINE uses, not through a raw SELECT -- the point
        # is to prove what the engine will see, not that a row exists.
        $all = Get-PimAllSqlSettings -ConnectionString $cs
        $stored = "$($all['MailSender'])".Trim()
        if ($stored -ne $sender) { throw "read-back mismatch: store holds '$stored', expected '$sender'" }
        Note "persisted to pim.Settings and verified: MailSender = $stored" 'Green'
        Add-Result 'persist' 'ok' $stored
    } catch {
        $m = ($_.Exception.Message -split "`n")[0]
        Add-Result 'persist' 'FAILED' $m
        Fail "mailbox + grants are in place, but the sender could NOT be persisted to pim.Settings ($SqlServerFqdn/$SqlDatabase): $m  -- the environment is still MAIL-MUTE. Re-run, or pass -MailSender '$sender' to Setup-PimContainers."
    }
}

# --- summary --------------------------------------------------------------------
$result.ok = $true
Write-Host ""
Write-Host ("=" * 78) -ForegroundColor Cyan
Write-Host " MAIL SENDER READY" -ForegroundColor Green
Write-Host ("=" * 78) -ForegroundColor Cyan
Write-Host "  sender        : $sender"
Write-Host "  send right    : Exchange RBAC '$assignName' -> scope '$scopeName' -> $sender ONLY"
Write-Host "  engine SPN    : $EngineAppId  (NO tenant-wide Graph Mail.Send -- by design)"
Write-Host "  exchange plan : $($result.exchangePlan)"
Write-Host ""
Write-Host "  NEXT: pass -MailSender '$sender' to Setup-PimContainers (Initialize-PlatformEnvironment"
Write-Host "        does this automatically), or set a 'MailSender' value in pim.Settings."
Write-Host ""
# Say only what was verified BY READ-BACK. An earlier summary asserted "Mail.Send, RESTRICTED to
# that mailbox" while the app was in fact unscoped -- an unverified security claim is worse than
# none, because it stops anyone from checking.
Write-Host "  VERIFIED BY READ-BACK: mailbox exists; scoped RBAC assignment exists; no tenant-wide" -ForegroundColor Green
Write-Host "  Graph Mail.Send is present on the engine SPN." -ForegroundColor Green
Write-Host "  🪤 The restriction was proven in EFIF with a second out-of-scope mailbox (in-scope send" -ForegroundColor DarkGray
Write-Host "     accepted, out-of-scope send ErrorAccessDenied). This script does NOT re-prove it per" -ForegroundColor DarkGray
Write-Host "     tenant -- that would mean creating a decoy mailbox in a customer tenant. If you need" -ForegroundColor DarkGray
Write-Host "     that assurance here, do it deliberately and delete the decoy afterwards. (IMP-06e)" -ForegroundColor DarkGray
Write-ResultFile
exit 0
