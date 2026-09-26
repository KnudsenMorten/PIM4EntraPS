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
  Exchange administration is done by the ONBOARDING SPN (-AdminAppId plus -AdminSecret OR
  -AdminCertThumbprint; a certificate is the preferred form), never by the
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

.EXAMPLE
  # From another process (a deploy step, a scheduled task): `pwsh -File` passes every argument as a
  # STRING, so a PowerShell array literal ('a','b') arrives as ONE value. Pass several managed
  # identities comma-separated with no quotes or spaces -- the script splits and validates them.
  pwsh -NoProfile -File tools\setup\Initialize-PimMailSender.ps1 -TenantId <tid> -AdminAppId <appId> `
       -AdminCertThumbprint <thumbprint> -ManagedIdentityObjectId <tickMiObjectId>,<managerMiObjectId> `
       -SqlServerFqdn <server>.database.windows.net

.NOTES
  RE-RUNNING IS SAFE. Every step reads first and treats "already there" as success; a read that
  FAILS (as opposed to finding nothing) stops the run instead of guessing that the object is absent.
  A re-run on a fully configured tenant changes nothing in Exchange -- it only re-activates the
  short-lived Exchange Administrator role (through PIM) it needs in order to read.

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
    # ONE of these. 🔴 The secret used to be Mandatory, which made a CLIENT SECRET structurally
    # required to provision the sender mailbox -- against the repo-root rule ("authenticate as its
    # SPN using a CERTIFICATE, never a client secret") and unsatisfiable where the onboarding SPN
    # is cert-only. Grant-PimMiSql was fixed for exactly this on 2026-08-09; this script was not,
    # and neither were Initialize-PimTenantStore.ps1 or Setup-PimMsp.ps1 -- three instances of one
    # defect, which is why the offline gate now audits the whole family instead of naming them.
    [string]$AdminSecret,
    [string]$AdminCertThumbprint,
    # The engine SPN. It receives the scoped Mail.Send ONLY when no managed identity is named below
    # (a non-hosted engine sends as the SPN). With a managed identity it is still checked for a
    # tenant-wide Graph Mail.Send. Read from the environment's own Key Vault ('Modern-AppId') when
    # not supplied and no managed identity is given.
    [string]$EngineAppId,
    # 🔒 THE HOSTED SENDER (REQUIREMENTS 65.11, operator decision 2026-09-13): the container sends as
    # its MANAGED IDENTITY, so the scoped assignment must name that identity -- the tick job's, and
    # the Manager's when it sends alerts. Service-principal OBJECT ids (the resource's
    # identity.principalId). A non-managed-identity object is refused.
    [string[]]$ManagedIdentityObjectId = @(),
    # Or resolve the tick job's managed identity by ARM REST (read only), by the same rule the
    # engine's token call uses (PIM_ManagedIdentityClientId -> that user-assigned identity, else
    # system-assigned).
    [string]$SubscriptionId,
    [string]$ResourceGroup,
    [string]$TickJobName,
    # EXPLICIT, off by default: also remove the older scoped assignment that names the engine SPN.
    # Left in place by default -- it is scoped to the same single mailbox, so it widens nothing,
    # and removing a working send right is the operator's call, not a side effect.
    [switch]$RemoveEngineSpnAssignment,
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
    [int]$TimeoutSeconds  = 600,
    # IMP-31 (2026-09-18): how long the onboarding SPN's Exchange Administrator role stays ACTIVE. The
    # role is now granted THROUGH PIM as a time-bound assignment that expires on its own -- it used to be
    # a permanent assignment outside PIM, which the SPN could not remove again (Graph refuses a self-
    # removal) and which the tenant's alerting flagged. ISO 8601, PT15M..PT24H.
    [string]$ExchangeAdminDuration = 'PT4H'
)

$ErrorActionPreference = 'Stop'

# EITHER a secret OR a certificate, never both and never neither. Checked before anything is
# provisioned: this script creates a mailbox and grants Exchange rights, and finding out the
# credential was unusable halfway through leaves a half-configured tenant nobody asked for.
if ($AdminSecret -and $AdminCertThumbprint) { throw 'Initialize-PimMailSender: pass EITHER -AdminSecret OR -AdminCertThumbprint, not both.' }
if (-not $AdminSecret -and -not $AdminCertThumbprint) { throw 'Initialize-PimMailSender: one of -AdminSecret / -AdminCertThumbprint is required.' }

$here = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
$solRoot = Split-Path -Parent (Split-Path -Parent $here)   # ...\SOLUTIONS\PIM4EntraPS
. (Join-Path $solRoot 'engine\_shared\PIM-Rest.ps1')
. (Join-Path $here '_PimMailSenderPlan.ps1')          # pure planners (tested offline)

# Both refusals happen BEFORE anything is touched: a malformed argument found halfway through leaves
# a half-configured tenant.
# BUG-167: `pwsh -File` delivers an array as one literal string -- normalise it, and name the
# marshalling cause when a value is not an object id (it used to surface as a directory 400).
$miParse = ConvertTo-PimObjectIdList -Value $ManagedIdentityObjectId
if ($miParse.reason) { throw "Initialize-PimMailSender: -ManagedIdentityObjectId: $($miParse.reason)" }
$ManagedIdentityObjectId = @($miParse.ids)
$durCheck = Test-PimAssignmentDuration -Duration $ExchangeAdminDuration
if (-not $durCheck.ok) { throw "Initialize-PimMailSender: -ExchangeAdminDuration: $($durCheck.reason)" }

$graphResourceAppId = '00000003-0000-0000-c000-000000000000'   # Microsoft Graph
$exoResourceAppId   = '00000002-0000-0ff1-ce00-000000000000'   # Office 365 Exchange Online

$result = [ordered]@{
    ok = $false; sender = ''; tenantId = $TenantId; engineAppId = ''; sendIdentities = @()
    exchangePlan = ''; mailboxCreated = $false; mailSendGranted = $false
    accessPolicyCreated = $false; privilegedGrants = $null; steps = @(); reason = ''
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

# =============================================================================================
# PURE DECISION CORES. Extracted from the step bodies below so they can be TESTED without a
# tenant -- they were inline, and inline logic in a provisioning script is logic that only ever
# gets exercised against live infrastructure, one tenant at a time, by somebody watching.
# These two carry the two traps this whole script exists for, so they are exactly the parts that
# must not be verified by eye. No network, no state, no Write-Host: data in, decision out.
# =============================================================================================

function Select-PimExchangeMailboxPlans {
    <#
      🪤 THE TRAP THIS ENCODES: `assignedPlans` reporting `exchange = Enabled` is NOT evidence that
      a mailbox can be created. EXCHANGE_S_FOUNDATION rides along with Entra P2 and reports exactly
      that while provisioning DIRECTORY OBJECTS ONLY -- `New-Mailbox -Shared` still fails. Measured
      on a real tenant: the org looked mail-capable and was not, for a reason the status does not
      hint at.
      So the signal is an Exchange service plan BEYOND Foundation. Returns the qualifying plan
      names (sorted, unique); an EMPTY result means "cannot host a mailbox" and is the fatal case.
      PURE: takes the already-fetched subscribedSkus collection.
    #>
    [CmdletBinding()] param([AllowEmptyCollection()][object[]]$SubscribedSkus = @())
    return @(@($SubscribedSkus).servicePlans |
        Where-Object { $_.servicePlanName -like '*EXCHANGE*' -and $_.servicePlanName -ne 'EXCHANGE_S_FOUNDATION' } |
        ForEach-Object { $_.servicePlanName } | Sort-Object -Unique)
}

function Resolve-PimMailSenderAddress {
    <#
      Where the notification mail comes FROM. The domain is the tenant's INITIAL
      (`onmicrosoft.com`) domain unless -MailDomain overrides it: a freshly-onboarded tenant has no
      custom domain, and guessing one produces a mailbox nobody can receive from.
      Returns @{ sender; domain; reason }. `reason` non-empty means it could not be resolved --
      REPORTED rather than thrown, so the caller decides what is fatal and the decision stays
      testable.
      PURE: takes the already-fetched organization object.
    #>
    [CmdletBinding()] param($Organization, [string]$MailboxName, [string]$MailDomain)
    $initial = @(@($Organization.verifiedDomains) | Where-Object { $_.isInitial } | Select-Object -First 1)
    $initialName = if ($initial.Count) { "$($initial[0].name)".Trim() } else { '' }
    $domain = if ("$MailDomain".Trim()) { "$MailDomain".Trim() } else { $initialName }
    $box = "$MailboxName".Trim()
    if (-not $box)    { return [ordered]@{ sender = ''; domain = $domain; reason = 'no mailbox name was given' } }
    # 🔒 An unresolved domain is a REFUSAL, not a guess. Inventing one yields a mailbox address
    # that provisions cleanly and can never receive anything -- the mail-mute failure this script
    # exists to prevent, arrived at from the other direction.
    if (-not $domain) { return [ordered]@{ sender = ''; domain = ''; reason = 'could not resolve a mail domain (no initial verified domain on the organization)' } }
    return [ordered]@{ sender = "$box@$domain"; domain = $domain; reason = '' }
}

Write-Host ("=" * 78) -ForegroundColor Cyan
Write-Host " PIM MAIL SENDER  tenant $TenantId" -ForegroundColor Cyan
Write-Host ("=" * 78) -ForegroundColor Cyan

# --- tokens -------------------------------------------------------------------
# The onboarding SPN authenticates with a SECRET here because that is the credential the estate
# onboarding path already carries for it (workbook / kv-automatit-dev). The ENGINE never uses a
# secret -- it is cert-only -- and this script never gives it one.
Step 'authenticate (onboarding SPN)'
try {
    $graphTok = Get-PimRestToken -Resource 'graph' -TenantId $TenantId -ClientId $AdminAppId -ClientSecret $AdminSecret -CertThumbprint $AdminCertThumbprint -Force
} catch { Fail "could not acquire a Graph token as the onboarding SPN ($AdminAppId): $($_.Exception.Message)" }
$GH = @{ Authorization = "Bearer $graphTok"; 'Content-Type' = 'application/json' }
function Gr {
    param([string]$Method = 'GET', [Parameter(Mandatory)][string]$Path, [object]$Body)
    $u = if ($Path -like 'http*') { $Path } else { "https://graph.microsoft.com/v1.0/$Path" }
    $a = @{ Method = $Method; Uri = $u; Headers = $GH }
    if ($null -ne $Body) { $a.Body = ($Body | ConvertTo-Json -Depth 20) }
    Invoke-RestMethod @a
}
# 🔴 A COLLECTION READ MUST FOLLOW THE PAGES. Graph returns at most 100 items per page, and the
# onboarding SPN this runs as holds ~100 Graph app roles on its own (measured on EFIF/RIDE 2026-09-18),
# so a first-page-only read of its appRoleAssignments could miss Exchange.ManageAsApp, plan a grant,
# and hit 400 "already exists" -- the fatal re-run of BUG-166 (a).
function GrAll {
    param([Parameter(Mandatory)][string]$Path)
    $r = Gr -Path $Path
    $items = @($r.value)
    $pages = 1
    while ($r.PSObject.Properties['@odata.nextLink'] -and "$($r.'@odata.nextLink')".Trim()) {
        if (++$pages -gt 50) { throw "more than 50 pages reading $Path -- refusing to guess the rest" }
        $r = Gr -Path "$($r.'@odata.nextLink')"
        $items += @($r.value)
    }
    return $items
}
Note "onboarding SPN: $AdminAppId" 'DarkGray'

# 🔴 THE ONBOARDING SPN CANNOT GRANT ITSELF. The header says this script's identity "already
# elevates itself to Global Administrator + Owner" -- true of the estate's onboarding SPN, and NOT
# true of a customer deploy SPN created with `az ad sp create-for-rbac --role Owner`, which holds
# Azure RBAC and nothing in Graph. Every Graph call here uses that SPN's own token, so the two
# grants below -- Exchange.ManageAsApp and the Exchange Administrator role -- ask the SPN to assign
# roles TO ITSELF, needing AppRoleAssignment.ReadWrite.All and RoleManagement.ReadWrite.Directory.
# A create-for-rbac SPN has neither, so the script failed at its own first grant. Measured while
# preparing a live customer's mail sender, 2026-09-08.
#
# The directive this script opens with is "the onboarding scripts must handle this prep unattended",
# so refusing with an instruction to go and grant it by hand is the wrong answer. Instead: fall back
# to the AMBIENT az context for the grant only. The operator running onboarding is signed in as a
# Global Administrator (the identity phase requires it for exactly the same reason), which is the
# same borrowed-token pattern Install-PimEngineAppRegistration.ps1 already uses.
#
# 🔒 Scope of the fallback is deliberately narrow: READS stay on the SPN token, and only these two
# POSTs may elevate. Anything that is not an authorization failure is rethrown untouched -- a
# fallback that swallowed a real error would hide the thing it was meant to surface.
function Invoke-PimGrant {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][object]$Body, [string]$What = 'grant')
    try { Gr -Method POST -Path $Path -Body $Body | Out-Null; return 'onboarding SPN' }
    catch {
        # BUG-131's lesson: the Graph error body is in ErrorDetails, NOT in Exception.Message.
        $m = "$($_.Exception.Message) $($_.ErrorDetails.Message)"
        # BUG-166 (a): a grant that is ALREADY THERE is the goal reached, not a failure. It was fatal,
        # so a second run died before the step that actually still needed doing.
        if (Test-PimAlreadyExistsError -Text $m) { return 'already held (nothing granted)' }
        if ($m -notmatch 'Authorization_RequestDenied|Insufficient privileges|\b403\b|Forbidden') { throw }
        Note "$What refused for the onboarding SPN (it cannot grant itself) -- retrying with the signed-in az context" 'DarkYellow'
        $azTok = az account get-access-token --tenant $TenantId --resource https://graph.microsoft.com --query accessToken -o tsv 2>$null
        if (-not "$azTok".Trim()) {
            throw ("$What was denied to the onboarding SPN, and no az context is available to fall back to. " +
                   "Sign in as a Global Administrator (az login) and re-run, or grant $AdminAppId " +
                   "AppRoleAssignment.ReadWrite.All + RoleManagement.ReadWrite.Directory.")
        }
        try {
            Invoke-RestMethod -Method POST -Uri "https://graph.microsoft.com/v1.0/$Path" `
                -Headers @{ Authorization = "Bearer $azTok"; 'Content-Type' = 'application/json' } `
                -Body ($Body | ConvertTo-Json -Depth 20) | Out-Null
        } catch {
            if (Test-PimAlreadyExistsError -Text "$($_.Exception.Message) $($_.ErrorDetails.Message)") { return 'already held (nothing granted)' }
            throw
        }
        return 'signed-in az context'
    }
}

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
# assignedPlans still says "exchange = Enabled". The decision itself is Select-PimExchangeMailboxPlans
# (pure, tested offline) -- it used to be inline here, where nothing could exercise it.
$exchangePlans = @(Select-PimExchangeMailboxPlans -SubscribedSkus $skus)
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
$senderPlan = Resolve-PimMailSenderAddress -Organization $org -MailboxName $MailboxName -MailDomain $MailDomain
if ($senderPlan.reason) { Fail $senderPlan.reason }
$domain = $senderPlan.domain
$sender = $senderPlan.sender
$result.sender = $sender
Note "sender: $sender" 'Green'

# --- resolve the SENDING identity (hosted: the tick job's managed identity) -------------
Step 'resolve the sending identity (managed identity when hosted)'
$miOids = @($ManagedIdentityObjectId | Where-Object { "$_".Trim() } | ForEach-Object { "$_".Trim() })
if (-not $miOids.Count -and "$SubscriptionId".Trim() -and "$ResourceGroup".Trim() -and "$TickJobName".Trim()) {
    try {
        $armTok = Get-PimRestToken -Resource 'arm' -TenantId $TenantId -ClientId $AdminAppId -ClientSecret $AdminSecret -CertThumbprint $AdminCertThumbprint -Force
        $job = Invoke-RestMethod -Headers @{ Authorization = "Bearer $armTok" } `
            -Uri "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.App/jobs/$TickJobName`?api-version=2024-03-01"
    } catch { Fail "could not read tick job '$TickJobName' to resolve its managed identity: $($_.Exception.Message)" }
    $pick = Get-PimJobManagedIdentityPrincipalId -Job $job
    if ($pick.reason) { Fail "tick job '$TickJobName': $($pick.reason)" }
    $miOids = @($pick.principalId)
    Note "tick job '$TickJobName' sends as its $($pick.kind)-assigned managed identity $($pick.principalId)" 'DarkGray'
}
$miSps = @()
foreach ($oid in $miOids) {
    try { $miSps += Gr -Path "servicePrincipals/$oid`?`$select=id,appId,displayName,servicePrincipalType" }
    catch { Fail "managed identity service principal '$oid' not found: $($_.Exception.Message)" }
}

# --- resolve the engine SPN ----------------------------------------------------
Step 'resolve the engine SPN (receives the SCOPED Mail.Send when no managed identity sends)'
if (-not "$EngineAppId".Trim() -and -not $miSps.Count) {
    if (-not ("$KeyVaultName".Trim() -and "$BootstrapAppId".Trim() -and "$BootstrapThumbprint".Trim())) {
        Fail 'no -EngineAppId or -ManagedIdentityObjectId, and no -KeyVaultName/-BootstrapAppId/-BootstrapThumbprint to read Modern-AppId from'
    }
    try {
        $kvTok = Get-PimRestToken -Resource 'https://vault.azure.net' -TenantId $TenantId -ClientId $BootstrapAppId -CertThumbprint $BootstrapThumbprint -Force
        $EngineAppId = (Invoke-RestMethod -Headers @{ Authorization = "Bearer $kvTok" } `
            -Uri "https://$KeyVaultName.vault.azure.net/secrets/Modern-AppId`?api-version=7.4").value
    } catch { Fail "could not read Modern-AppId from $KeyVaultName : $($_.Exception.Message)" }
}
$EngineAppId = "$EngineAppId".Trim()
$result.engineAppId = $EngineAppId
$engineSp = $null
if ($EngineAppId) {
    $engineSp = (Gr -Path "servicePrincipals?`$filter=appId eq '$EngineAppId'").value | Select-Object -First 1
    if (-not $engineSp -and -not $miSps.Count) { Fail "engine service principal not found for appId $EngineAppId" }
    if ($engineSp) { Note "engine SPN: $EngineAppId (objectId $($engineSp.id))" 'DarkGray' }
}
$sendPlan = Resolve-PimMailSendPrincipals -ManagedIdentitySps $miSps -EngineSp $engineSp
if ($sendPlan.reason) { Fail $sendPlan.reason }
$sendPrincipals = @($sendPlan.principals)
$result.sendIdentities = @($sendPrincipals | ForEach-Object { [ordered]@{ kind = $_.kind; appId = $_.appId; objectId = $_.objectId } })
foreach ($p in $sendPrincipals) { Note "sends as: $($p.kind) appId $($p.appId) (objectId $($p.objectId))" 'Green' }

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

# Every page, not the first 100 (see GrAll) -- a missed page planned a duplicate grant.
try {
    $hasManage = @(GrAll -Path "servicePrincipals/$($adminSp.id)/appRoleAssignments" |
        Where-Object { $_.resourceId -eq $exoSp.id -and $_.appRoleId -eq $manageAsApp.id })
} catch { Fail "could not read the onboarding SPN's app-role assignments, so cannot tell whether Exchange.ManageAsApp is already held -- refusing to guess: $($_.Exception.Message)" }
$manageAsAppState = if ($hasManage.Count) { 'held (already)' } else { '' }
if ($hasManage.Count) { Note 'Exchange.ManageAsApp already held' 'DarkGray' }
elseif ($PSCmdlet.ShouldProcess($AdminAppId, 'grant Exchange.ManageAsApp')) {
    try {
        $by = Invoke-PimGrant -Path "servicePrincipals/$($adminSp.id)/appRoleAssignments" `
                -Body @{ principalId = $adminSp.id; resourceId = $exoSp.id; appRoleId = $manageAsApp.id } `
                -What 'Exchange.ManageAsApp'
        Note "Exchange.ManageAsApp: $by" 'Green'
        $manageAsAppState = "held ($by)"
    } catch { Fail "could not grant Exchange.ManageAsApp to the onboarding SPN: $($_.Exception.Message)" }
}

# 🔒 THE EXCHANGE ADMINISTRATOR ROLE IS TIME-BOUND, AND GRANTED THROUGH PIM.
# It used to be POSTed to roleManagement/directory/roleAssignments: a PERMANENT active assignment made
# outside PIM. Measured 2026-09-18 on EFIF and RIDE: the tenants' own alerting flagged it ("assigned
# outside of PIM"), and the SPN holding it could NOT remove it -- Graph refuses a self-removal
# ("Removing self from ... built-in role is not allowed"). A privileged-access product must not leave
# exactly the standing privilege it exists to prevent. Now: an active assignment through
# roleAssignmentScheduleRequests that EXPIRES by itself after -ExchangeAdminDuration.
$exchAdminTemplate = '29232cdf-9323-42fd-ade2-1d097af3e4de'   # built-in; definition id == template id
$exchAdminRole = (Gr -Path "roleManagement/directory/roleDefinitions?`$filter=displayName eq 'Exchange Administrator'").value | Select-Object -First 1
$exchAdminRoleId = if ($exchAdminRole) { "$($exchAdminRole.id)" } else { $exchAdminTemplate }
function Read-ExchAdminGrant {
    # Active instances cover BOTH a permanent assignment and a PIM-activated/time-bound one.
    $inst = @(GrAll -Path "roleManagement/directory/roleAssignmentScheduleInstances?`$filter=principalId eq '$($adminSp.id)'")
    Select-PimActiveRoleGrant -Instances $inst -PrincipalId "$($adminSp.id)" -RoleDefinitionId $exchAdminRoleId
}
# 🔴 SELF-HEAL -- RoleManagement.ReadWrite.Directory (2026-09-26, the 13th "MAIL SENDER NOT PROVISIONED").
# Both the read above and the activation below need it. A deploy identity created by
# New-PimDeployIdentity -GrantGraph before 2026-09-26 does not hold it, and every one of those installs
# ended here with 403 and a mail-mute environment. That identity DOES hold AppRoleAssignment.ReadWrite.All,
# which is exactly the right to grant an app role -- including to itself -- so the step grants the missing
# role, mints a FRESH token (roles are baked into the token at issue) and waits for the claim to carry it.
$roleMgmtRole = $graphSp.appRoles | Where-Object { $_.value -eq 'RoleManagement.ReadWrite.Directory' -and $_.allowedMemberTypes -contains 'Application' } | Select-Object -First 1
if (-not $roleMgmtRole) { Fail 'RoleManagement.ReadWrite.Directory app-role not found on the Graph service principal' }
try {
    $hasRoleMgmt = @(GrAll -Path "servicePrincipals/$($adminSp.id)/appRoleAssignments" |
        Where-Object { $_.resourceId -eq $graphSp.id -and $_.appRoleId -eq $roleMgmtRole.id })
} catch { Fail "could not read the onboarding SPN's app-role assignments, so cannot tell whether RoleManagement.ReadWrite.Directory is held -- refusing to guess: $($_.Exception.Message)" }
if ($hasRoleMgmt.Count) { Note 'RoleManagement.ReadWrite.Directory already held' 'DarkGray' }
elseif ($PSCmdlet.ShouldProcess($AdminAppId, 'grant RoleManagement.ReadWrite.Directory (self-heal)')) {
    try {
        $by = Invoke-PimGrant -Path "servicePrincipals/$($adminSp.id)/appRoleAssignments" `
                -Body @{ principalId = $adminSp.id; resourceId = $graphSp.id; appRoleId = $roleMgmtRole.id } `
                -What 'RoleManagement.ReadWrite.Directory'
        Note "RoleManagement.ReadWrite.Directory: $by (self-heal -- the deploy identity predates it)" 'Green'
    } catch { Fail "could not grant RoleManagement.ReadWrite.Directory to the onboarding SPN: $($_.Exception.Message)" }
    # A token minted before the grant carries the OLD roles claim; re-mint until the claim shows the new role.
    $claimSeen = Confirm-Eventually -What 'RoleManagement.ReadWrite.Directory in the token' -Seconds 600 -Test {
        $t = Get-PimRestToken -Resource 'graph' -TenantId $TenantId -ClientId $AdminAppId -ClientSecret $AdminSecret -CertThumbprint $AdminCertThumbprint -Force
        $p = "$t".Split('.')[1].Replace('-', '+').Replace('_', '/'); while ($p.Length % 4) { $p += '=' }
        $roles = @(([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($p)) | ConvertFrom-Json).roles)
        if ($roles -contains 'RoleManagement.ReadWrite.Directory') { $script:GH = @{ Authorization = "Bearer $t"; 'Content-Type' = 'application/json' }; $true } else { $false }
    }
    if (-not $claimSeen) { Fail 'RoleManagement.ReadWrite.Directory was granted but no fresh token carried it within 10 minutes -- re-run this step; the grant itself is in place' }
}
# 🪤 A 403 HERE IS NOT FINAL (measured 2026-09-26, Community): RoleManagement.ReadWrite.Directory was held and IN the
# token, and this read still answered 403 once -- then 200 on every later try. Entra makes a new app permission effective
# on the role-management read path some time after the token already carries it. Retry a 403 with a FRESH token for up
# to 5 minutes before calling the environment mail-mute; anything that is not a 403 still fails at once.
$exchAdminState = $null; $exchReadErr = $null
$exchReadUntil = (Get-Date).AddMinutes(5)
while ($true) {
    try { $exchAdminState = Read-ExchAdminGrant; $exchReadErr = $null; break }
    catch {
        $exchReadErr = $_
        $m = "$($_.Exception.Message) $($_.ErrorDetails.Message)"
        if ($m -notmatch '\b403\b|Forbidden|Authorization_RequestDenied' -or (Get-Date) -ge $exchReadUntil) { break }
        Note 'role read answered 403 -- retrying with a fresh token (a new permission takes effect on this path after the token carries it)' 'DarkYellow'
        Start-Sleep -Seconds 20
        $t = Get-PimRestToken -Resource 'graph' -TenantId $TenantId -ClientId $AdminAppId -ClientSecret $AdminSecret -CertThumbprint $AdminCertThumbprint -Force
        $script:GH = @{ Authorization = "Bearer $t"; 'Content-Type' = 'application/json' }
    }
}
try { if ($exchReadErr) { throw $exchReadErr } }
catch { Fail "could not read the onboarding SPN's active directory roles, so cannot tell whether Exchange Administrator is already active -- refusing to guess: $($_.Exception.Message)" }
if ($exchAdminState.active) {
    if ($exchAdminState.kind -eq 'permanent') {
        Note 'Exchange Administrator already active -- as a PERMANENT assignment (standing privilege; see the summary)' 'Yellow'
    } else { Note "Exchange Administrator already active until $($exchAdminState.endDateTime.ToString('u')) (time-bound, reused)" 'DarkGray' }
}
elseif ($PSCmdlet.ShouldProcess($AdminAppId, "activate Exchange Administrator through PIM for $ExchangeAdminDuration")) {
    try {
        $body = New-PimRoleScheduleRequestBody -PrincipalId "$($adminSp.id)" -RoleDefinitionId $exchAdminRoleId -Duration $ExchangeAdminDuration
        $by = Invoke-PimGrant -Path 'roleManagement/directory/roleAssignmentScheduleRequests' -Body $body -What 'Exchange Administrator (time-bound)'
        Note "Exchange Administrator requested for $ExchangeAdminDuration through PIM (via the $by)" 'Green'
    } catch { Fail "could not activate Exchange Administrator for the onboarding SPN through PIM: $($_.Exception.Message)" }
    # READ BACK -- a request that was accepted is not yet an active role.
    $seen = Confirm-Eventually -What 'time-bound Exchange Administrator' -Seconds 120 -Test { (Read-ExchAdminGrant).active }
    if (-not $seen) { Fail 'the time-bound Exchange Administrator request was accepted but the role is not active on read-back' }
    $exchAdminState = Read-ExchAdminGrant
    Note "Exchange Administrator active until $(if ($exchAdminState.endDateTime) { $exchAdminState.endDateTime.ToString('u') } else { '(no end)' }) (verified by read-back)" 'Green'
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
# The tenant's INITIAL (*.onmicrosoft.com) domain. `$initialDomain` used to be read here and assigned nowhere, so the
# anchor ended in "@" -- harmless only because EXO falls back when the anchor mailbox does not resolve.
$initialDomain = "$(@(@($org.verifiedDomains) | Where-Object { $_.isInitial } | Select-Object -First 1).name)".Trim()
$anchor = "UPN:SystemMailbox{bb558c35-97f1-4cb9-8ff7-d53741dc928c}@$initialDomain"
function Invoke-Exo {
    param([Parameter(Mandatory)][string]$Cmdlet, [hashtable]$Parameters = @{})
    $tok = Get-PimRestToken -Resource 'https://outlook.office365.com' -TenantId $TenantId -ClientId $AdminAppId -ClientSecret $AdminSecret -CertThumbprint $AdminCertThumbprint -Force
    $h = @{ Authorization = "Bearer $tok"; 'Content-Type' = 'application/json'
            'X-ResponseFormat' = 'json'; 'X-AnchorMailbox' = $anchor }
    $body = @{ CmdletInput = @{ CmdletName = $Cmdlet; Parameters = $Parameters } } | ConvertTo-Json -Depth 10
    Invoke-RestMethod -Method POST -Uri $exoUri -Headers $h -Body $body
}

function Read-ExoWithRetry {
    <#
      A READ that distinguishes the three answers the old code collapsed into one:
        found / absent (a single-object -Lookup that Exchange says does not exist) / unreadable.
      Transient failures (401/403 while the role propagates -- measured, 429, 5xx) are retried a
      bounded number of times; what is still failing after that is 'unreadable', and the CALLER
      refuses. Returns @{ outcome; value; error }.
    #>
    param([Parameter(Mandatory)][string]$Cmdlet, [hashtable]$Parameters = @{}, [switch]$Lookup, [int]$Attempts = 6, [int]$DelaySeconds = 15)
    $err = ''
    for ($i = 1; $i -le $Attempts; $i++) {
        try { return @{ outcome = 'found'; value = (Invoke-Exo -Cmdlet $Cmdlet -Parameters $Parameters); error = '' } }
        catch {
            $err = ("$($_.Exception.Message) $($_.ErrorDetails.Message)" -replace '\s+', ' ').Trim()
            if ($Lookup -and (Resolve-PimExoLookupOutcome -ErrorText $err) -eq 'absent') { return @{ outcome = 'absent'; value = $null; error = '' } }
            if (-not (Test-PimTransientReadError -Text $err) -or $i -eq $Attempts) { break }
            Note "$Cmdlet not readable yet (attempt $i/$Attempts): $(($err -split '\. ')[0])" 'DarkGray'
            Start-Sleep -Seconds $DelaySeconds
        }
    }
    return @{ outcome = 'unreadable'; value = $null; error = $err.Substring(0, [Math]::Min(300, $err.Length)) }
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
# Not-found is the normal first-run path. ANY OTHER failure is "could not look", and it used to be
# read as "absent" too -- which planned a create against a mailbox that existed. Refuse instead.
$mbxRead = Read-ExoWithRetry -Cmdlet 'Get-Mailbox' -Parameters @{ Identity = $sender } -Lookup
if ($mbxRead.outcome -eq 'unreadable') {
    Add-Result 'mailbox' 'FAILED' "could not read: $($mbxRead.error)"
    Fail "could not check whether the mailbox '$sender' exists ($($mbxRead.error)) -- refusing to create it on a guess. Re-run when Exchange answers."
}
if ($mbxRead.outcome -eq 'found') { $existingMbx = @($mbxRead.value.value) | Select-Object -First 1 }

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
    # Run an EXO create. The outcome of a failure is decided by Resolve-PimExoCreateOutcome (pure,
    # tested offline):
    #   exists     -> SUCCESS (idempotent re-run; BUG-166 -- it used to be fatal)
    #   dehydrated -> wait for organization customization (up to -Seconds)
    #   retry      -> Exchange has not materialised a service principal created moments ago
    #                 (New-ManagementRoleAssignment answers 404; measured on EFIF/RIDE) -- bounded wait
    #   fail       -> returned at once: a real failure must not be hidden behind a long wait
    param([Parameter(Mandatory)][string]$Cmdlet, [hashtable]$Parameters = @{}, [int]$Seconds = 3600, [string]$What = 'object',
          [int]$MaterialiseSeconds = 600)
    $stop = (Get-Date).AddSeconds($Seconds); $matStop = (Get-Date).AddSeconds($MaterialiseSeconds); $n = 0
    while ($true) {
        $n++
        try { return @{ ok = $true; existed = $false; value = (Invoke-Exo -Cmdlet $Cmdlet -Parameters $Parameters) } }
        catch {
            $e = $_
            $raw = "$($e.ErrorDetails.Message)"
            $txt = "$($e.Exception.Message) $raw"
            switch (Resolve-PimExoCreateOutcome -Cmdlet $Cmdlet -ErrorText $txt) {
                'exists' { return @{ ok = $true; existed = $true; value = $null } }
                'dehydrated' {
                    if ((Get-Date) -ge $stop) { return @{ ok = $false; error = 'organization still dehydrated'; detail = $raw } }
                    if ($n -eq 1 -or ($n % 5) -eq 0) { Note "waiting for organization customization to take effect ($What, attempt $n)" 'DarkGray' }
                    Start-Sleep -Seconds 60
                }
                'retry' {
                    if ((Get-Date) -ge $matStop) { return @{ ok = $false; error = "Exchange never made the new service principal usable within ${MaterialiseSeconds}s"; detail = $raw } }
                    Note "Exchange has not made the new service principal usable yet ($What, attempt $n) -- waiting" 'DarkGray'
                    Start-Sleep -Seconds 30
                }
                default { return @{ ok = $false; error = ($e.Exception.Message -split "`n")[0]; detail = $raw } }
            }
        }
    }
}

# 3b-3d. PLAN, then execute. What is missing is decided by New-PimMailSenderExoPlan
#     (_PimMailSenderPlan.ps1, tested offline): New-ServicePrincipal for each SENDING identity,
#     New-ManagementScope for the sender mailbox, New-ManagementRoleAssignment 'Application Mail.Send'
#     per identity. An empty plan = already in place; a second run writes nothing.
# 🔴 THE OLD CHECK MATCHED ROLE + SCOPE ONLY. Once the engine SPN held the assignment, the managed
#     identity's was reported "already present" and never created -- and the hosted engine, which
#     sends as that managed identity, was refused with nothing in this log to say why. The plan
#     matches assignments by ASSIGNEE.
$scopeName = "PIM4EntraPS-Sender"
# 🔴 BUG-166 (b) -- these three used to end in `catch { @() }`, so "I could not read the scopes" became
# "there are no scopes": measured on EFIF/RIDE, Get-ManagementScope answered 401 during the Exchange
# Administrator propagation, the plan said "create", and New-ManagementScope then failed with
# ADObjectAlreadyExistsException. A plan is only as good as the reads under it: an unreadable one
# STOPS the run (re-running is safe), it never plans a create.
$exoSpList = $null; $scopes = $null; $assigns = $null
$pre = [ordered]@{
    'Get-ServicePrincipal'         = @{ }
    'Get-ManagementScope'          = @{ }
    'Get-ManagementRoleAssignment' = @{ RoleAssigneeType = 'ServicePrincipal' }
}
$preRead = @{}
foreach ($c in $pre.Keys) {
    $rr = Read-ExoWithRetry -Cmdlet $c -Parameters $pre[$c]
    if ($rr.outcome -ne 'found') {
        Add-Result "exo-read:$c" 'FAILED' $rr.error
        Fail "could not read the existing Exchange configuration ($($c): $($rr.error)) -- refusing to plan changes on a partial picture. Nothing was changed; re-run when Exchange answers."
    }
    $preRead[$c] = @($rr.value.value)
}
$exoSpList = $preRead['Get-ServicePrincipal']; $scopes = $preRead['Get-ManagementScope']; $assigns = $preRead['Get-ManagementRoleAssignment']
$engineOid = if ($engineSp) { "$($engineSp.id)" } else { '' }
$exoPlan = @(New-PimMailSenderExoPlan -ExoServicePrincipals $exoSpList -Scopes $scopes -Assignments $assigns `
    -Principals $sendPrincipals -Sender $sender -ScopeName $scopeName -EngineAppId $EngineAppId -EngineObjectId $engineOid `
    -RemoveEngineSpnAssignment:$RemoveEngineSpnAssignment)
if (-not $exoPlan.Count) {
    Note 'Exchange registration, scope and scoped Application Mail.Send assignment(s) already present' 'DarkGray'
    $result.accessPolicyCreated = $true; Add-Result 'exo-scoped-send' 'already' "$scopeName"
}
foreach ($item in $exoPlan) {
    $r = Invoke-ExoWhenHydrated -Cmdlet $item.cmdlet -What $item.what -Parameters $item.parameters
    if (-not $r.ok) { Add-Result "exo:$($item.cmdlet)" 'FAILED' "$($r.error) $($r.detail)"; Fail "could not $($item.what): $($r.error)" }
    if ($r.existed) { Note "$($item.cmdlet): $($item.what) -- already present, nothing changed" 'DarkGray' }
    else { Note "$($item.cmdlet): $($item.what)" 'Green' }
}
if ($exoPlan.Count) {
    # Read back -- the whole reason RBAC was chosen over an Application Access Policy. EVERY sending
    # identity must hold its own assignment, not merely "some" assignment in the scope.
    $confirmedScope = Confirm-Eventually -What 'scoped Mail.Send assignment' -Seconds 120 -Test {
        $now = @((Invoke-Exo -Cmdlet 'Get-ManagementRoleAssignment' -Parameters @{ RoleAssigneeType = 'ServicePrincipal' }).value)
        $spNow = @((Invoke-Exo -Cmdlet 'Get-ServicePrincipal').value)
        @($sendPrincipals | Where-Object {
            $ids = Get-PimExoAssigneeIds -ExoServicePrincipals $spNow -AppId $_.appId -ObjectId $_.objectId
            -not @(Select-PimExoMailSendAssignment -Assignments $now -ScopeName $scopeName -AssigneeIds $ids -AssignmentName $_.assignmentName).Count
        }).Count -eq 0
    }
    if (-not $confirmedScope) { Add-Result 'exo-scoped-send' 'FAILED' 'not present on read-back'; Fail 'the scoped Mail.Send assignment was created but is not present on read-back for every sending identity' }
    Note "scoped Application Mail.Send assignment(s) verified for: $((@($sendPrincipals | ForEach-Object { $_.appId })) -join ', ') -> $scopeName" 'Green'
    $result.accessPolicyCreated = $true; Add-Result 'exo-scoped-send' 'created' "$($exoPlan.Count) change(s) -> $scopeName"
}
if ($EngineAppId -and -not $RemoveEngineSpnAssignment -and @($sendPrincipals | Where-Object { $_.kind -eq 'managed-identity' }).Count) {
    Note "the engine SPN's older scoped assignment (if any) is LEFT in place -- pass -RemoveEngineSpnAssignment to remove it" 'DarkGray'
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
Step '[2] ensure NO tenant-wide Graph Mail.Send on any sending identity or the engine SPN (it would defeat the scope)'
# Every identity that can send is checked: the managed identities that now carry the scoped grant,
# AND the engine SPN -- a tenant-wide consent on either defeats the per-mailbox scope.
$tenantWideTargets = @()
foreach ($p in $sendPrincipals) { $tenantWideTargets += [pscustomobject]@{ label = "$($p.kind) $($p.appId)"; spId = $p.objectId } }
if ($engineSp -and -not @($tenantWideTargets | Where-Object { $_.spId -eq "$($engineSp.id)" }).Count) {
    $tenantWideTargets += [pscustomobject]@{ label = "engine SPN $EngineAppId"; spId = "$($engineSp.id)" }
}
$anyRevoked = $false
foreach ($tgt in $tenantWideTargets) {
    # Every page (GrAll): the engine SPN holds ~100 app roles, so a first-page read could miss the very
    # consent this step exists to find -- and report the send right as scoped when it is not.
    try { $existingGrant = @(Select-PimTenantWideMailSend -Assignments @(GrAll -Path "servicePrincipals/$($tgt.spId)/appRoleAssignments") -GraphSpId $graphSp.id -MailSendRoleId $mailSendRole.id) }
    catch { Fail "could not read the app-role assignments of $($tgt.label), so cannot tell whether it holds a tenant-wide Mail.Send -- refusing to report the send right as scoped: $($_.Exception.Message)" }
    if (-not $existingGrant.Count) { Note "no tenant-wide Mail.Send on $($tgt.label) -- correct" 'Green'; continue }
    if (-not $PSCmdlet.ShouldProcess($tgt.label, 'REVOKE tenant-wide Graph Mail.Send')) { Add-Result 'mail-send-tenantwide' 'whatif' "would revoke on $($tgt.label)"; continue }
    Note "found $($existingGrant.Count) tenant-wide Mail.Send assignment(s) on $($tgt.label) -- REVOKING (they defeat the scope)" 'DarkYellow'
    foreach ($a in $existingGrant) {
        try { Gr -Method DELETE -Path "servicePrincipals/$($tgt.spId)/appRoleAssignments/$($a.id)" | Out-Null }
        catch { Fail "could not revoke tenant-wide Mail.Send ($($a.id)) on $($tgt.label): $($_.Exception.Message)" }
    }
    $revoked = Confirm-Eventually -What 'Mail.Send revocation' -Test {
        @(Select-PimTenantWideMailSend -Assignments @(GrAll -Path "servicePrincipals/$($tgt.spId)/appRoleAssignments") -GraphSpId $graphSp.id -MailSendRoleId $mailSendRole.id).Count -eq 0
    }
    if (-not $revoked) { Fail "tenant-wide Mail.Send was deleted on $($tgt.label) but is still present on read-back -- the send right is NOT scoped" }
    Note "tenant-wide Mail.Send revoked on $($tgt.label) (verified by read-back)" 'Green'
    $anyRevoked = $true
}
$result.mailSendGranted = $false
if ($anyRevoked) { Add-Result 'mail-send-tenantwide' 'revoked' 'removed so the RBAC scope governs' }
else { Add-Result 'mail-send-tenantwide' 'absent' 'correct (RBAC grants, scoped)' }

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
    # Set only the credential that was actually supplied, and CLEAR the other -- a stale
    # global of the opposite kind would otherwise win inside Get-PimRestToken's chain and
    # authenticate as something other than what this call asked for. Same reasoning, and the
    # same two lines, as Grant-PimMiSql.
    $global:PIM_ClientSecret   = $AdminSecret
    $global:PIM_CertThumbprint = $AdminCertThumbprint
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
Write-Host "  send right    : Exchange RBAC 'Application Mail.Send' -> scope '$scopeName' -> $sender ONLY"
foreach ($p in $sendPrincipals) { Write-Host "  sends as      : $($p.kind) $($p.appId)  (assignment $($p.assignmentName))" }
Write-Host "  tenant-wide   : NO Graph Mail.Send on any sending identity or the engine SPN -- by design"
Write-Host "  exchange plan : $($result.exchangePlan)"
Write-Host ""
# IMP-31 -- SAY WHAT PRIVILEGE IS LEFT BEHIND, AND UNTIL WHEN. The old run granted the provisioning
# identity tenant-wide Exchange administration and never mentioned it again; the tenant's own alerting
# was how anyone found out.
try { $exchAdminNow = Read-ExchAdminGrant } catch { $exchAdminNow = $exchAdminState }
$exAdminLine = if (-not $exchAdminNow.active) { 'not active (expired or never granted)' }
               elseif ($exchAdminNow.kind -eq 'permanent') { 'ACTIVE, PERMANENT (standing privilege outside PIM -- remove it with a DIFFERENT administrator: an identity cannot remove its own directory role)' }
               else { "active until $($exchAdminNow.endDateTime.ToString('u')), then expires on its own (granted through PIM)" }
$result.privilegedGrants = [ordered]@{
    identity = $AdminAppId
    exchangeAdministrator = [ordered]@{ active = [bool]$exchAdminNow.active; kind = "$($exchAdminNow.kind)"; endUtc = $(if ($exchAdminNow.endDateTime) { $exchAdminNow.endDateTime.ToString('o') } else { '' }) }
    exchangeManageAsApp = "$manageAsAppState"
}
$pc = if ($exchAdminNow.active -and $exchAdminNow.kind -eq 'permanent') { 'Red' } else { 'Yellow' }
Write-Host "  PRIVILEGED GRANTS STILL HELD by the setup identity $AdminAppId :" -ForegroundColor $pc
Write-Host "    Exchange Administrator (directory role) : $exAdminLine" -ForegroundColor $pc
Write-Host "    Exchange.ManageAsApp (app role)         : $(if ($manageAsAppState) { $manageAsAppState } else { 'not held' }) -- no expiry; inert without the directory role" -ForegroundColor $pc
Write-Host ""
Write-Host "  NEXT: pass -MailSender '$sender' to Setup-PimContainers (Initialize-PlatformEnvironment"
Write-Host "        does this automatically), or set a 'MailSender' value in pim.Settings."
Write-Host ""
# Say only what was verified BY READ-BACK. An earlier summary asserted "Mail.Send, RESTRICTED to
# that mailbox" while the app was in fact unscoped -- an unverified security claim is worse than
# none, because it stops anyone from checking.
Write-Host "  VERIFIED BY READ-BACK: mailbox exists; scoped RBAC assignment exists; no tenant-wide" -ForegroundColor Green
Write-Host "  Graph Mail.Send is present on any sending identity." -ForegroundColor Green
Write-Host "  🪤 The restriction was proven in EFIF with a second out-of-scope mailbox (in-scope send" -ForegroundColor DarkGray
Write-Host "     accepted, out-of-scope send ErrorAccessDenied). This script does NOT re-prove it per" -ForegroundColor DarkGray
Write-Host "     tenant -- that would mean creating a decoy mailbox in a customer tenant. If you need" -ForegroundColor DarkGray
Write-Host "     that assurance here, do it deliberately and delete the decoy afterwards." -ForegroundColor DarkGray
Write-ResultFile
exit 0
