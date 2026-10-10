#Requires -Version 5.1

<#
.SYNOPSIS
  Set up the shared mailbox PIM Manager sends its notification mail from: create the mailbox, give each sending identity a send right scoped to that one mailbox (Exchange RBAC for applications), remove any tenant-wide Microsoft Graph Mail.Send from those identities, and store the sender in the PIM store.

.DESCRIPTION
  IMP-06 / MAIL-1 -- make an environment able to send its own notification mail, UNATTENDED.
  Run it with -WhatIf first: it signs in, reads, and prints every change it would make (mailbox, Exchange
  registration, scope, scoped send right, revoked tenant-wide Mail.Send, the stored setting) without making any.

  Operator directive 2026-08-12: *"the onboarding scripts must handle this prep unattended"*. Doing
  these steps by hand in a portal is the DEFECT, not the workaround: every future tenant would
  otherwise land in the state a test tenant was in -- engine provisions fine, mail never sends, and nothing
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
       `subscribedSkus` BEYOND Foundation (e.g. EXCHANGE_S_STANDARD). Measured on a test tenant: the org
       looked mail-capable and `New-Mailbox -Shared` would still have failed, for a reason the
       status does not hint at.
    1. CREATE THE SHARED SENDER MAILBOX (default `PIM-Engine@<initial domain>`). A shared mailbox
       is the designed sender and is FREE once an EXO plan exists -- admin accounts themselves need
       no mailbox and no licence, because the engine mails *about* them, not *as* them.
    2. GRANT SEND ACCESS *SCOPED TO THAT ONE MAILBOX*, via Exchange RBAC for Applications.
    3. ENSURE NO TENANT-WIDE Graph `Mail.Send` CONSENT EXISTS -- revoking it if it does.

  ⚠️ STEPS 2 AND 3 ARE INVERTED FROM IMP-06 AS WRITTEN, and the inversion is load-bearing.
  The finding said "grant Mail.Send, then scope it with an Application Access Policy". Measured in
  a test tenant, doing exactly that leaves the app UNSCOPED: Exchange RBAC does not RESTRICT a tenant-wide
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

  Measured on a test tenant before this script existed: the engine SPN held ~100 Graph app-roles but NOT
  Mail.Send, NOT Exchange.ManageAsApp, and no directory role at all -- its EXO token came back with
  an empty `roles` claim and the admin endpoint answered 401.

  REST-only: no ExchangeOnlineManagement module, no Graph SDK, no command-line tools. Exchange is driven through
  the `/adminapi/beta/<tenant>/InvokeCommand` endpoint that the EXO V3 module itself uses.

  🔒 HOW IT SIGNS IN (MAIL-1, framework 12.3, owner 2026-10-08: "we dont use certificates here, either interactive
  login or secret. not certificates"). Four ways, decided before anything is touched (Resolve-PimMailSetupAuthMode):
    * nothing passed           -> BROWSER sign-in (the default for a person): an Exchange or Global Administrator signs
                                  in in Edge (auth code + PKCE on localhost, no device code, no module). The person acts
                                  with their OWN Exchange role -- no app is granted Exchange.ManageAsApp or a directory
                                  role, so that whole step is skipped. -AdminAppId is not needed.
    * -AdminAppId -AdminSecret -> the Invardia Support app (the setup / support identity; its secret is the one
                                  allowed exception, framework 4.1a). It activates its own time-boxed Exchange
                                  Administrator through PIM.
    * -UseSignedInAccount      -> the signed-in session of this window: the Invardia Support session when one is
                                  open for this tenant, otherwise the person's own browser sign-in.
    * -AdminCertThumbprint     -> still accepted for old callers; never what a page or a document prints.
  Published standalone at https://invardia.com/support/pim/Initialize-PimMailSender.ps1 (Build-PimSupportScripts.ps1).

.PARAMETER OutFile
  Where to write the result JSON ({ ok, sender, ... }). This is how a calling deploy gets the sender
  UPN back: each setup step runs in its OWN process with stdout redirected to a log, so a
  return value cannot travel any other way.

.PARAMETER MailboxName
  The mailbox name (the part before the @) -- your company's naming. Default PIM-Engine.

.PARAMETER MailDomain
  The mailbox domain, one of the tenant's verified domains. Default: the tenant's initial (onmicrosoft.com) domain.

.PARAMETER DisplayName
  The mailbox display name (what recipients see as the sender). Default 'PIM Manager (notifications)'.

.PARAMETER ScopeName
  The Exchange management scope name. Default '<MailboxName>-SendScope'; an existing scope for this mailbox is kept.

.PARAMETER AssignmentNamePrefix
  The prefix of the Exchange role-assignment names ('<prefix>-<short id>-MailSend'). Default: the mailbox name.

.PARAMETER AllowThisIpTemporarily
  Opt-in: if the PIM database refuses this computer (SQL firewall), add a temporary rule for this IP, save the sender,
  and always remove the rule again. Without it, no firewall rule is changed and PIM Manager finishes the step.

.EXAMPLE
  # A person (Exchange or Global Administrator), browser sign-in -- what PIM Manager's Get Started prints:
  .\Initialize-PimMailSender.ps1 -TenantId <tid> -MailboxName pim-notify -MailDomain contoso.com -DisplayName 'PIM notifications' `
       -ManagedIdentityObjectId <managerMiObjectId>,<tickMiObjectId> -SqlServerFqdn <server>.database.windows.net

.EXAMPLE
  # From another process (a deploy step, a scheduled task): `pwsh -File` passes every argument as a
  # STRING, so a PowerShell array literal ('a','b') arrives as ONE value. Pass several managed
  # identities comma-separated with no quotes or spaces -- the script splits and validates them.
  pwsh -NoProfile -File tools\setup\Initialize-PimMailSender.ps1 -TenantId <tid> -AdminAppId <supportAppId> `
       -AdminSecret <secret> -ManagedIdentityObjectId <tickMiObjectId>,<managerMiObjectId> `
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

  PERMISSIONS (full list with scope, reason and undo: Initialize-PimMailSender.doc.json / the documentation page)
    The person running it: Exchange Administrator or Global Administrator (browser sign-in); to store the sender,
    membership of the SQL server's admin group. With -AdminAppId + -AdminSecret the Invardia Support app needs
    AppRoleAssignment.ReadWrite.All + RoleManagement.ReadWrite.Directory to give itself the transient grants below.
    It creates / grants: the shared mailbox (New-Mailbox -Shared); per sending identity New-ServicePrincipal (Exchange
    registration) and New-ManagementRoleAssignment 'Application Mail.Send' on a New-ManagementScope that matches ONLY
    the sender mailbox; it REMOVES a tenant-wide Graph Mail.Send (application) from the sending identities and the
    engine identity; it writes MailSender + MailMode to pim.Settings. App sign-in only: Exchange.ManageAsApp (app role)
    and a time-bound Exchange Administrator (through PIM) on the setup app itself, and RoleManagement.ReadWrite.Directory
    (self-heal) when the setup app lacks it.
    Transcript: <temp>\pim-manager-logs\Initialize-PimMailSender-<utc>.log (path printed at the start and the end).

.LINK
  https://invardia.com/docs/pim/scripts/Initialize-PimMailSender/
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$TenantId,
    # The ONBOARDING SPN -- privileged, provisioning-time. See the identity note above. Not needed (and refused alone)
    # for the browser sign-in: the person who signs in acts with their own Exchange role.
    [string]$AdminAppId,
    # ONE of these. 🔴 The secret used to be Mandatory, which made a CLIENT SECRET structurally
    # required to provision the sender mailbox -- against the repo-root rule ("authenticate as its
    # SPN using a CERTIFICATE, never a client secret") and unsatisfiable where the onboarding SPN
    # is cert-only. Grant-PimMiSql was fixed for exactly this on 2026-08-09; this script was not,
    # and neither were Initialize-PimTenantStore.ps1 or Setup-PimMsp.ps1 -- three instances of one
    # defect, which is why the offline gate now audits the whole family instead of naming them.
    [string]$AdminSecret,
    [string]$AdminCertThumbprint,
    # 2026-10-07 (operator, at a customer: "you are welcome to fix this at <customer>"): run as the SIGNED-IN session
    # instead -- the Invardia Support session open in this window (Connect-InvardiaSupport), else the person's browser
    # sign-in (framework 12.17: one sign-in rule, _PimSignedIn.ps1) -- with no secret or certificate passed. -AdminAppId is then the signed-in app (it activates its own short-lived Exchange Administrator role).
    [switch]$UseSignedInAccount,
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
    # MAIL-1: and the Manager container app's (it sends the alert notices) -- same ARM read, same rule.
    [string]$ManagerAppName,
    # EXPLICIT, off by default: also remove the older scoped assignment that names the engine SPN.
    # Left in place by default -- it is scoped to the same single mailbox, so it widens nothing,
    # and removing a working send right is the operator's call, not a side effect.
    [switch]$RemoveEngineSpnAssignment,
    [string]$KeyVaultName,
    [string]$BootstrapAppId,
    [string]$BootstrapThumbprint,
    # MAIL-NAMING (100.14, owner 2026-10-09: "companies have their own naming"): the company names the mailbox.
    # Local part of the sender mailbox. The domain is the tenant's initial (onmicrosoft.com) domain
    # unless -MailDomain says otherwise -- a freshly-onboarded tenant has no custom domain, and
    # guessing one produces a mailbox nobody can receive from. A mailbox that already exists under that address is
    # used as it is (not created again). PIM Manager's Get Started > Mail sender prints the command with these filled in.
    [string]$MailboxName  = 'PIM-Engine',
    [string]$MailDomain,
    [string]$DisplayName  = 'PIM Manager (notifications)',
    # The Exchange names this script creates, also the company's: the management scope (default '<MailboxName>-SendScope')
    # and the role-assignment name prefix (default <MailboxName> -> '<prefix>-<short id>-MailSend'). A scope that already
    # restricts to this mailbox, and assignments already held by the sending identities, are KEPT under their existing
    # names (an install from before 2.4.538: 'PIM4EntraPS-Sender', 'PIM4EntraPS-MI-<id>-MailSend') -- never duplicated.
    [string]$ScopeName,
    [string]$AssignmentNamePrefix,
    # Opt-in, off by default: when the store refuses this computer's IP (the Azure SQL firewall), add a TEMPORARY firewall
    # rule for exactly that IP, write the sender, and ALWAYS remove the rule again (finally). Needs the signed-in person's
    # (or app's) Azure rights on the SQL server; honours -WhatIf / -Confirm. Without it no firewall is changed.
    [switch]$AllowThisIpTemporarily,
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
    [string]$ExchangeAdminDuration = 'PT4H',
    # INSTALL-HARDEN-1 item 4: how long to wait for a just-hydrated Exchange organization that still refuses RBAC creates
    # ("you must be assigned a delegating role assignment"; measured ~40-60 min), and how often to try again.
    [ValidateRange(1, 240)][int]$ExchangeReadyMinutes = 75,
    [ValidateRange(10, 900)][int]$ExchangeReadyIntervalSeconds = 150,
    # one plain progress line per wait (the deploy forwards it to the install's reporter as a 'waiting' event)
    [scriptblock]$OnProgress
)

$ErrorActionPreference = 'Stop'

$here = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
# Every helper is dot-sourced by a literal path relative to this script's folder, so Build-PimSupportScripts.ps1 can
# inline it: the published file at https://invardia.com/support/pim/Initialize-PimMailSender.ps1 is ONE standalone script.
. (Join-Path $PSScriptRoot '_PimScriptDoc.ps1')               # 12.7: the Documentation line + the run transcript
. (Join-Path $PSScriptRoot '..\..\engine\_shared\PIM-Rest.ps1')
. (Join-Path $PSScriptRoot '_PimMailSenderPlan.ps1')          # pure planners (tested offline)
. (Join-Path $PSScriptRoot '_PimMailSetup.ps1')               # how it signs in + the browser sign-in
. (Join-Path $PSScriptRoot '_PimSignedIn.ps1')                # -UseSignedInAccount: the Support session, else the browser
$null = Start-PimScriptRun -Script 'Initialize-PimMailSender'
try {

# EITHER a secret OR a certificate (or the signed-in session, or the browser), never two at once. Checked before
# anything is provisioned: this script creates a mailbox and grants Exchange rights, and finding out the credential was
# unusable halfway through leaves a half-configured tenant nobody asked for. ("pass EITHER" / "-AdminAppId is required"
# are the refusals; the decision is Resolve-PimMailSetupAuthMode in _PimMailSetup.ps1, tested offline.)
$authPlan = Resolve-PimMailSetupAuthMode -AdminAppId $AdminAppId -AdminSecret $AdminSecret -AdminCertThumbprint $AdminCertThumbprint -UseSignedInAccount:$UseSignedInAccount
if ($authPlan.reason) { throw "Initialize-PimMailSender: $($authPlan.reason)" }
$script:PimMailAuthMode = $authPlan.mode
$browserMode = ($script:PimMailAuthMode -eq 'browser')
# INSTALL-HARDEN-1 (owner 2026-10-08; the trial runs in the customer's Cloud Shell as a PERSON): -UseSignedInAccount with no
# -AdminAppId is the signed-in PERSON's delegated token -- like the browser sign-in, that person's own Exchange
# Administrator / Global Administrator role does the work and no app is granted anything.
$personSignedIn = ($script:PimMailAuthMode -eq 'signedIn' -and -not "$AdminAppId".Trim())
$delegatedMode = ($browserMode -or $personSignedIn)
# Framework 12.17 (ONE sign-in rule): a signed-in run takes every token from the source _PimSignedIn.ps1 registers in
# PIM-Rest ($global:PIM_TokenProvider) -- the Invardia Support session open in this window (Get-InvardiaSupportToken),
# otherwise the person's own browser sign-in (auth code + PKCE, never device code). PIM-Rest checks each token's tenant.
if ($script:PimMailAuthMode -eq 'signedIn') { Set-PimSignedInGlobals -TenantId $TenantId }
function Get-PimMailSignedInUpn {
    if ($browserMode) { return (Get-PimMsSignedInUpn) }
    if ($personSignedIn) {
        try {
            $c = ConvertFrom-PimJwtClaims -Token (Get-PimMailAdminToken -Resource 'graph')
            return "$(if ($c.upn) { $c.upn } elseif ($c.unique_name) { $c.unique_name } else { $c.preferred_username })".Trim()
        } catch { return '' }
    }
    return ''
}
if ($browserMode -and -not (Test-PimMsInteractiveHost)) {
    throw 'Initialize-PimMailSender: no credential was passed, so this run signs in in the BROWSER -- and this session is not interactive. Run it in a PowerShell window, or pass -AdminAppId + -AdminSecret (the Invardia Support app).'
}

function Get-PimMailAdminToken {
    # The admin (onboarding) identity's token for 'graph' | 'arm' | a resource URL: the browser sign-in (the person),
    # the signed-in session with -UseSignedInAccount (PIM-Rest's registered token source: the Invardia Support session,
    # else the person's browser sign-in), else the app's own secret / certificate. Never cached across identities (-Force).
    param([Parameter(Mandatory)][string]$Resource)
    if ($script:PimMailAuthMode -eq 'browser') { return (Get-PimMsBrowserToken -Resource $Resource -TenantId $TenantId) }
    if ($UseSignedInAccount) {
        if (-not ($global:PIM_TokenProvider -is [scriptblock])) { Set-PimSignedInGlobals -TenantId $TenantId }
        $tok = "$(Get-PimRestToken -Resource $Resource -TenantId $TenantId)".Trim()
        if (-not $tok) { throw "Initialize-PimMailSender: the signed-in session gave no token for $Resource in tenant $TenantId -- connect with the Invardia Support app (Connect-InvardiaSupport.ps1 -Environment <handle>), or run it in a PowerShell window and sign in in the browser." }
        return $tok
    }
    return (Get-PimRestToken -Resource $Resource -TenantId $TenantId -ClientId $AdminAppId -ClientSecret $AdminSecret -CertThumbprint $AdminCertThumbprint -Force)
}

# Both refusals happen BEFORE anything is touched: a malformed argument found halfway through leaves
# a half-configured tenant.
# BUG-167: `pwsh -File` delivers an array as one literal string -- normalise it, and name the
# marshalling cause when a value is not an object id (it used to surface as a directory 400).
$miParse = ConvertTo-PimObjectIdList -Value $ManagedIdentityObjectId
if ($miParse.reason) { throw "Initialize-PimMailSender: -ManagedIdentityObjectId: $($miParse.reason)" }
$ManagedIdentityObjectId = @($miParse.ids)
$durCheck = Test-PimAssignmentDuration -Duration $ExchangeAdminDuration
if (-not $durCheck.ok) { throw "Initialize-PimMailSender: -ExchangeAdminDuration: $($durCheck.reason)" }
# MAIL-NAMING (100.14): the company's names, checked before anything is touched.
$nameErr = Test-PimMailboxLocalPart -Value $MailboxName
if ($nameErr) { throw "Initialize-PimMailSender: -MailboxName: $nameErr" }
foreach ($nv in @(@{ n = 'ScopeName'; v = $ScopeName }, @{ n = 'AssignmentNamePrefix'; v = $AssignmentNamePrefix })) {
    $e = Test-PimExoObjectName -Value $nv.v -What "-$($nv.n)"
    if ($e) { throw "Initialize-PimMailSender: $e" }
}
if ("$MailDomain".Trim() -and "$MailDomain".Trim() -notmatch '^[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$') { throw "Initialize-PimMailSender: -MailDomain '$MailDomain' is not a domain name" }
if (-not "$AssignmentNamePrefix".Trim()) { $AssignmentNamePrefix = ConvertTo-PimExoNamePart -Value $MailboxName }

$graphResourceAppId = '00000003-0000-0000-c000-000000000000'   # Microsoft Graph
$exoResourceAppId   = '00000002-0000-0ff1-ce00-000000000000'   # Office 365 Exchange Online

$result = [ordered]@{
    ok = $false; sender = ''; tenantId = $TenantId; engineAppId = ''; sendIdentities = @()
    exchangePlan = ''; mailboxCreated = $false; mailSendGranted = $false
    accessPolicyCreated = $false; privilegedGrants = $null; steps = @(); reason = ''; authMode = "$($authPlan.mode)"; persisted = $false
}
function Note($m, $c = 'Gray') { Write-Host "    $m" -ForegroundColor $c }
function Step($m) { Write-Host "`n--- $m ---" -ForegroundColor Cyan }
function Add-Result($name, $state, $detail) { $result.steps += [ordered]@{ step = $name; state = $state; detail = $detail } }

function Write-ResultFile {
    if (-not "$OutFile".Trim()) { return }
    # 12.7: under -WhatIf nothing is written outside the temp folder -- the result file then only goes to a path in it.
    $tmpRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
    $outFull = try { [IO.Path]::GetFullPath($OutFile) } catch { "$OutFile" }
    if ($WhatIfPreference -and -not $outFull.StartsWith($tmpRoot, [StringComparison]::OrdinalIgnoreCase)) {
        Note "WhatIf: the result file $OutFile is NOT written (it is outside the temp folder)" 'DarkYellow'
        return
    }
    try {
        $dir = Split-Path -Parent $OutFile
        if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Force -Path $dir -WhatIf:$false | Out-Null }
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

function Resolve-PimMailSenderGraphKey {
    <#
      BUG-296 (found live at a customer 2026-10-07): what the ENGINE must store as MailSender is the key Microsoft Graph
      addresses the mailbox by -- /users/<id | userPrincipalName>/sendMail -- NOT its mail address. Exchange gives a new
      shared mailbox a UPN on the tenant's DEFAULT domain while -PrimarySmtpAddress put its mail on the initial
      (onmicrosoft) domain; Graph then answers 404 for /users/<mail address> and the environment is mail-mute although
      the mailbox, the scope and the send right are all correct.
      PURE. -GraphUsers: the Graph users whose mail or proxyAddresses carry -Sender ($filter=mail eq ... OR
      proxyAddresses/any). Returns @{ key; reason }: the UPN of the ONE matching user; -Sender itself when it already is
      that UPN; '' + a reason when nobody or more than one user matches (refuse rather than pick).
    #>
    [CmdletBinding()] param([Parameter(Mandatory)][string]$Sender, [object[]]$GraphUsers = @())
    $s = "$Sender".Trim()
    $hits = @(@($GraphUsers) | Where-Object { $_ } | Where-Object {
        $u = $_; ("$($u.userPrincipalName)" -ieq $s) -or ("$($u.mail)" -ieq $s) -or (@($u.proxyAddresses) | Where-Object { ("$_" -replace '^(?i)smtp:', '') -ieq $s }) })
    $ids = @($hits | ForEach-Object { "$($_.id)$($_.userPrincipalName)" } | Select-Object -Unique)
    if ($ids.Count -eq 0) { return [ordered]@{ key = ''; reason = "no directory user carries $s (the mailbox is not visible in Microsoft Graph yet)" } }
    if ($ids.Count -gt 1) { return [ordered]@{ key = ''; reason = "more than one directory user carries $s -- refusing to pick one" } }
    return [ordered]@{ key = "$($hits[0].userPrincipalName)".Trim(); reason = '' }
}

Write-Host ("=" * 78) -ForegroundColor Cyan
Write-Host " PIM MAIL SENDER  tenant $TenantId" -ForegroundColor Cyan
Write-Host ("=" * 78) -ForegroundColor Cyan

# --- tokens -------------------------------------------------------------------
# The onboarding SPN authenticates with a SECRET here because that is the credential the estate
# onboarding path already carries for it (workbook / the build key vault). The ENGINE never uses a
# secret -- it is cert-only -- and this script never gives it one.
$adminLabel = if ($browserMode) { 'the administrator signing in in the browser' } else { "the onboarding SPN ($AdminAppId)" }
Step $(if ($browserMode) { 'authenticate (browser sign-in: an Exchange or Global Administrator)' } else { 'authenticate (onboarding SPN)' })
try {
    $graphTok = Get-PimMailAdminToken -Resource 'graph'
} catch { Fail "could not acquire a Graph token as $adminLabel : $($_.Exception.Message)" }
$GH = @{ Authorization = "Bearer $graphTok"; 'Content-Type' = 'application/json' }
function Gr {
    param([string]$Method = 'GET', [Parameter(Mandatory)][string]$Path, [object]$Body)
    $u = if ($Path -like 'http*') { $Path } else { "https://graph.microsoft.com/v1.0/$Path" }
    $a = @{ Method = $Method; Uri = $u; Headers = $GH }
    if ($null -ne $Body) { $a.Body = ($Body | ConvertTo-Json -Depth 20) }
    Invoke-RestMethod @a
}
# 🔴 A COLLECTION READ MUST FOLLOW THE PAGES. Graph returns at most 100 items per page, and the
# onboarding SPN this runs as holds ~100 Graph app roles on its own (measured on two test tenants 2026-09-18),
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
if ($browserMode) { Note "signed in as $(Get-PimMsSignedInUpn) (browser sign-in; no app identity is used or granted anything)" 'DarkGray' }
elseif ($personSignedIn) { Note "signed in as $(Get-PimMailSignedInUpn) (a person's own sign-in; no app identity is used or granted anything)" 'DarkGray' }
else { Note "onboarding SPN: $AdminAppId" 'DarkGray' }

# 🔴 THE ONBOARDING SPN CANNOT GRANT ITSELF. The header says this script's identity "already
# elevates itself to Global Administrator + Owner" -- true of the estate's onboarding SPN, and NOT
# true of a customer deploy SPN that was only given the Azure Owner role (create-for-rbac), which holds
# Azure RBAC and nothing in Graph. Every Graph call here uses that SPN's own token, so the two
# grants below -- Exchange.ManageAsApp and the Exchange Administrator role -- ask the SPN to assign
# roles TO ITSELF, needing AppRoleAssignment.ReadWrite.All and RoleManagement.ReadWrite.Directory.
# A create-for-rbac SPN has neither, so the script failed at its own first grant. Measured while
# preparing a live customer's mail sender, 2026-09-08.
#
# The directive this script opens with is "the onboarding scripts must handle this prep unattended",
# so refusing with an instruction to go and grant it by hand is the wrong answer. Instead: fall back
# to a Global Administrator's BROWSER sign-in for the grant only (framework 12.17: no command-line tool session is
# borrowed any more). Only where a person is at the console -- an unattended run gets the refusal, naming the grant.
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
        $deny = ("$What was denied to the onboarding SPN. Re-run in a PowerShell window and sign in in the browser as a " +
                 "Global Administrator when asked, or grant $AdminAppId AppRoleAssignment.ReadWrite.All + RoleManagement.ReadWrite.Directory.")
        if (-not (Test-PimMsInteractiveHost)) { throw $deny }
        Note "$What refused for the onboarding SPN (it cannot grant itself) -- sign in in the browser as a Global Administrator for this grant" 'DarkYellow'
        $gaTok = ''
        try { $gaTok = "$(Get-PimMsBrowserToken -Resource 'graph' -TenantId $TenantId)".Trim() } catch { throw "$deny ($($_.Exception.Message))" }
        if (-not $gaTok) { throw $deny }
        try {
            Invoke-RestMethod -Method POST -Uri "https://graph.microsoft.com/v1.0/$Path" `
                -Headers @{ Authorization = "Bearer $gaTok"; 'Content-Type' = 'application/json' } `
                -Body ($Body | ConvertTo-Json -Depth 20) | Out-Null
        } catch {
            if (Test-PimAlreadyExistsError -Text "$($_.Exception.Message) $($_.ErrorDetails.Message)") { return 'already held (nothing granted)' }
            throw
        }
        return 'Global Administrator browser sign-in'
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
# MAIL-NAMING 100.14 item 4 (owner 2026-10-09, noise): every SKU of the tenant only with -Verbose -- the line that matters
# is the Exchange verdict below (plan found / not found).
foreach ($s in $skus) { Write-Verbose ("sku {0,-28} enabled={1}" -f $s.skuPartNumber, $s.prepaidUnits.enabled) }

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
Note "Exchange Online plan: found ($($exchangePlans -join ', '))" 'Green'
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
# MAIL-1 (2026-10-08): ADDED to the identities passed, not only used when none are -- PIM Manager's Get Started passes
# its own managed identity by object id and names the tick job, whose identity it may not be able to read itself.
if ("$SubscriptionId".Trim() -and "$ResourceGroup".Trim() -and "$TickJobName".Trim()) {
    try {
        $armTok = Get-PimMailAdminToken -Resource 'arm'
        $job = Invoke-RestMethod -Headers @{ Authorization = "Bearer $armTok" } `
            -Uri "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.App/jobs/$TickJobName`?api-version=2024-03-01"
    } catch { Fail "could not read tick job '$TickJobName' to resolve its managed identity: $($_.Exception.Message)" }
    $pick = Get-PimJobManagedIdentityPrincipalId -Job $job
    if ($pick.reason) { Fail "tick job '$TickJobName': $($pick.reason)" }
    if ($miOids -notcontains "$($pick.principalId)") { $miOids += "$($pick.principalId)" }
    Note "tick job '$TickJobName' sends as its $($pick.kind)-assigned managed identity $($pick.principalId)" 'DarkGray'
}
if ("$SubscriptionId".Trim() -and "$ResourceGroup".Trim() -and "$ManagerAppName".Trim()) {
    try {
        $armTok = Get-PimMailAdminToken -Resource 'arm'
        $app = Invoke-RestMethod -Headers @{ Authorization = "Bearer $armTok" } `
            -Uri "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.App/containerApps/$ManagerAppName`?api-version=2024-03-01"
    } catch { Fail "could not read the Manager app '$ManagerAppName' to resolve its managed identity: $($_.Exception.Message)" }
    $pick = Get-PimJobManagedIdentityPrincipalId -Job $app
    if ($pick.reason) { Fail "Manager app '$ManagerAppName': $($pick.reason)" }
    if ($miOids -notcontains "$($pick.principalId)") { $miOids += "$($pick.principalId)" }
    Note "Manager app '$ManagerAppName' sends as its $($pick.kind)-assigned managed identity $($pick.principalId)" 'DarkGray'
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
$sendPlan = Resolve-PimMailSendPrincipals -ManagedIdentitySps $miSps -EngineSp $engineSp -AssignmentNamePrefix $AssignmentNamePrefix
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
$manageAsAppState = ''; $exchAdminState = $null
# 🔒 BROWSER SIGN-IN: NOTHING IS GRANTED TO ANY APP. The person who signed in acts with their OWN Exchange Administrator /
# Global Administrator role (a delegated token), so the transient app grants below -- Exchange.ManageAsApp, the
# time-boxed Exchange Administrator through PIM -- have no subject and are skipped as a whole. An admin without an
# Exchange role is refused by Exchange itself at the readiness wait below, with Exchange's own message.
if ($delegatedMode) {
    Step 'Exchange administration: the signed-in administrator''s own role (nothing is granted)'
    Note "Exchange is administered as $(Get-PimMailSignedInUpn) -- an Exchange Administrator or Global Administrator role is needed" 'DarkGray'
} else {
Step 'enable Exchange administration for the onboarding SPN (transient, provisioning-time)'
$adminSp =(Gr -Path "servicePrincipals?`$filter=appId eq '$AdminAppId'").value | Select-Object -First 1
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
# outside PIM. Measured 2026-09-18 on two test tenants: the tenants' own alerting flagged it ("assigned
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
        $t = Get-PimMailAdminToken -Resource 'graph'
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
        if ($m -notmatch '\b403\b|Forbidden|Authorization_RequestDenied' -or (Get-Date) -ge $exchReadUntil -or $WhatIfPreference) { break }
        Note 'role read answered 403 -- retrying with a fresh token (a new permission takes effect on this path after the token carries it)' 'DarkYellow'
        Start-Sleep -Seconds 20
        $t = Get-PimMailAdminToken -Resource 'graph'
        $script:GH = @{ Authorization = "Bearer $t"; 'Content-Type' = 'application/json' }
    }
}
if ($exchReadErr -and $WhatIfPreference) {
    # 12.7: the read needs RoleManagement.ReadWrite.Directory, which -WhatIf did not grant above -- say so, preview the activation.
    Note "WhatIf: the Exchange Administrator state of the setup app cannot be read yet ($((("$($exchReadErr.Exception.Message)") -split "`n")[0])) -- this step cannot be previewed exactly; run without -WhatIf to apply" 'DarkYellow'
    $exchAdminState = [pscustomobject]@{ active = $false; kind = ''; endDateTime = $null }
    $exchReadErr = $null
}
try { if ($exchReadErr) { throw $exchReadErr } }
catch { Fail "could not read the onboarding SPN's active directory roles, so cannot tell whether Exchange Administrator is already active -- refusing to guess: $($_.Exception.Message)" }
if ($exchAdminState.active) {
    if ($exchAdminState.kind -eq 'permanent') {
        Note 'Exchange Administrator already active -- as a PERMANENT assignment (standing privilege; see the summary)' 'Yellow'
    } else {
        $ol = Test-PimGrantOverlong -Grant $exchAdminState -Duration $ExchangeAdminDuration
        if ($ol.overlong) { Note "Exchange Administrator already active, but it $($ol.reason) -- that is STANDING privilege until then (a portal assignment defaults to one year); shorten it to $ExchangeAdminDuration or remove it after this run" 'Yellow' }
        else { Note "Exchange Administrator already active until $($exchAdminState.endDateTime.ToString('u')) (time-bound, reused)" 'DarkGray' }
    }
}
elseif ($PSCmdlet.ShouldProcess($AdminAppId, "activate Exchange Administrator through PIM for $ExchangeAdminDuration")) {
    try {
        $body = New-PimRoleScheduleRequestBody -PrincipalId "$($adminSp.id)" -RoleDefinitionId $exchAdminRoleId -Duration $ExchangeAdminDuration
        $by = Invoke-PimGrant -Path 'roleManagement/directory/roleAssignmentScheduleRequests' -Body $body -What 'Exchange Administrator (time-bound)'
        Note "Exchange Administrator requested for $ExchangeAdminDuration through PIM (via the $by)" 'Green'
    } catch {
        # BUG-248: both identities can be refused (seen at a customer: 403 as the SPN and as the signed-in Global Administrator --
        # the Azure CLI's token carries no delegated role-management scope). Say what the manual way must look like.
        Fail ("could not activate Exchange Administrator for the onboarding SPN through PIM: $($_.Exception.Message)" +
              " -- MANUAL WAY: in Entra > Roles > Exchange Administrator > Add assignments, assign app $AdminAppId as ACTIVE and TIME-BOUND," +
              " ending within $ExchangeAdminDuration (the portal defaults to ONE YEAR -- change it), then re-run this script; it reuses the assignment.")
    }
    # READ BACK -- a request that was accepted is not yet an active role.
    $seen = Confirm-Eventually -What 'time-bound Exchange Administrator' -Seconds 120 -Test { (Read-ExchAdminGrant).active }
    if (-not $seen) { Fail 'the time-bound Exchange Administrator request was accepted but the role is not active on read-back' }
    $exchAdminState = Read-ExchAdminGrant
    Note "Exchange Administrator active until $(if ($exchAdminState.endDateTime) { $exchAdminState.endDateTime.ToString('u') } else { '(no end)' }) (verified by read-back)" 'Green'
}
}   # end: app identity (not the browser sign-in)

# 12.7 (-WhatIf): from here on Exchange is READ (Get-* cmdlets) and every create / remove / store write is announced
# through ShouldProcess instead of made. An app identity whose Exchange grants were skipped above may not be able to read
# Exchange yet -- then steps [1]-[3] say they cannot be previewed, and only what can be read is shown.
$whatIfRun = [bool]$WhatIfPreference
$exoPreviewable = $true

# --- Exchange Online admin REST ------------------------------------------------
# The transport the EXO V3 module uses internally. Token audience is outlook.office365.com; a token
# minted BEFORE the grants above will carry an empty `roles` claim, so it is always minted fresh
# (-Force) and retried while the grant propagates.
$exoUri = "https://outlook.office365.com/adminapi/beta/$TenantId/InvokeCommand"
# The tenant's INITIAL (*.onmicrosoft.com) domain. `$initialDomain` used to be read here and assigned nowhere, so the
# anchor ended in "@" -- harmless only because EXO falls back when the anchor mailbox does not resolve.
$initialDomain = "$(@(@($org.verifiedDomains) | Where-Object { $_.isInitial } | Select-Object -First 1).name)".Trim()
# A delegated (browser) token anchors on the signed-in person, an app-only one on the system mailbox -- as the EXO V3
# module does (Get-PimMsExoAnchor). The Exchange token is minted first so the person's UPN is known.
if ($browserMode) { try { [void](Get-PimMailAdminToken -Resource 'https://outlook.office365.com') } catch { Fail "could not sign in to Exchange Online: $($_.Exception.Message)" } }
$anchor = if ($personSignedIn) { Get-PimMsExoAnchor -Mode 'browser' -Upn (Get-PimMailSignedInUpn) -InitialDomain $initialDomain }
          else { Get-PimMsExoAnchor -Mode $script:PimMailAuthMode -Upn (Get-PimMsSignedInUpn) -InitialDomain $initialDomain }
function Invoke-Exo {
    param([Parameter(Mandatory)][string]$Cmdlet, [hashtable]$Parameters = @{})
    $tok = Get-PimMailAdminToken -Resource 'https://outlook.office365.com'
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
        if ($whatIfRun) { break }   # a preview does not wait for grants it did not make
        Start-Sleep -Seconds 20
    }
}
if (-not $ready -and $whatIfRun) {
    $exoPreviewable = $false
    Note "WhatIf: Exchange administration is not usable for this sign-in yet ($lastErr) -- steps [1]-[3] cannot be previewed; run without -WhatIf to apply. Without -WhatIf they would: create the shared mailbox $sender, register each sending identity in Exchange, create the scope for $sender only and give each identity 'Application Mail.Send' on it." 'DarkYellow'
    Add-Result 'exchange-ready' 'whatif' 'not previewable (Exchange not usable for this sign-in yet)'
}
elseif (-not $ready) {
    Add-Result 'exchange-ready' 'FAILED' $lastErr
    Fail "Exchange admin endpoint never became usable within ${TimeoutSeconds}s (last error: $lastErr). Both app-role propagation and EXO org provisioning can cause this; re-running is safe and idempotent."
}
if ($ready) {
    Note "Exchange administration usable after $attempt attempt(s)" 'Green'
    Add-Result 'exchange-ready' 'ok' "$attempt attempt(s)"
}

# --- 1. CREATE THE SHARED SENDER MAILBOX ---------------------------------------
$mbxPlanned = $false   # -WhatIf: the mailbox does not exist and would be created
if ($exoPreviewable) {
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
} elseif (-not $PSCmdlet.ShouldProcess("Exchange Online mailbox $sender", "create the shared sender mailbox (New-Mailbox -Shared, display name '$DisplayName')")) {
    if (-not $whatIfRun) { Fail "the shared mailbox $sender was not created (declined) -- nothing further is changed" }
    $mbxPlanned = $true
    Add-Result 'mailbox' 'whatif' "would create $sender"
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
}   # end: $exoPreviewable (step [1])

# --- 1b. THE KEY GRAPH SENDS AS (BUG-296) -----------------------------------------
# The engine calls /users/<MailSender>/sendMail. Graph resolves an id or a userPrincipalName, never a bare mail address,
# so the value persisted below is the mailbox's UPN (mail still goes out FROM the primary address $sender).
Step "[1b] how Microsoft Graph addresses $sender"
$graphKey = [ordered]@{ key = ''; reason = '' }; $gkReadError = ''
$gkDeadline = (Get-Date).AddSeconds(180)
if ($mbxPlanned -or -not $exoPreviewable) {
    # -WhatIf: the mailbox does not exist yet, so the key Graph will address it by is known only once it is created.
    Note "WhatIf: the mailbox's directory UPN is known only after it is created -- the preview uses $sender" 'DarkYellow'
    $graphKey = [ordered]@{ key = $sender; reason = '' }
} else {
do {
    try {
        $f = [uri]::EscapeDataString("mail eq '$sender' or userPrincipalName eq '$sender' or proxyAddresses/any(p:p eq 'smtp:$sender')")
        $gu = @(GrAll -Path "users?`$filter=$f&`$select=id,userPrincipalName,mail,proxyAddresses"); $gkReadError = ''
    } catch { $gu = @(); $gkReadError = ($_.Exception.Message -split "`n")[0] }
    $graphKey = Resolve-PimMailSenderGraphKey -Sender $sender -GraphUsers $gu
    if ($graphKey.key -or $gkReadError) { break }
    Start-Sleep -Seconds 15
} while ((Get-Date) -lt $gkDeadline)
if ($gkReadError) {
    # Could not LOOK (e.g. no User.Read.All on the onboarding identity): keep the old behaviour, but say what it risks.
    Note "could not read the directory to find the mailbox's UPN ($gkReadError) -- storing $sender as it is; if Graph cannot resolve it, mail fails with 404: set MailSender to the mailbox's UPN." 'Yellow'
    $graphKey = [ordered]@{ key = $sender; reason = '' }
}
}   # end: the mailbox exists (step [1b] read)
if (-not $graphKey.key) { Add-Result 'graph-key' 'FAILED' $graphKey.reason; Fail "the mailbox $sender exists, but $($graphKey.reason). Re-run in a few minutes." }
$storeSender = $graphKey.key
if ($storeSender -ine $sender) { Note "Graph addresses this mailbox as $storeSender (its UPN); that is what the engine stores. Mail still goes out from $sender." 'Yellow' }
else { Note "Graph addresses it by $storeSender" 'DarkGray' }
Add-Result 'graph-key' 'ok' $storeSender
$result.storeSender = $storeSender

# --- 3. SCOPE THE SEND RIGHT TO THAT ONE MAILBOX -------------------------------
# Exchange Online RBAC FOR APPLICATIONS, not an Application Access Policy. Both express "this app
# may only touch this mailbox"; the RBAC one is chosen because it is the one that WORKS AND CAN BE
# READ BACK. Measured in a test tenant: Get-ApplicationAccessPolicy answers 404 and New-ApplicationAccessPolicy
# answers 400/500, so an AAP could be neither verified nor made idempotent -- and an unverifiable
# security control is not a security control. Get-ManagementRoleAssignment / Get-ManagementScope
# both read cleanly, so every step below is gated on a real read-back.
#
# Three objects:
#   New-ServicePrincipal          register the engine app inside Exchange
#   New-ManagementScope           a recipient scope matching EXACTLY the sender mailbox
#   New-ManagementRoleAssignment  'Application Mail.Send' bound to the app AND that scope
# A first name for the -WhatIf preview (before Exchange is read): -ScopeName, else '<mailbox>-SendScope'. Once the scopes are
# read, Resolve-PimMailSenderScope decides it for real (an existing scope for this mailbox is adopted under its own name).
$scopeName = if ("$ScopeName".Trim()) { "$ScopeName".Trim() } else { Get-PimMailSenderScopeName -Sender $sender }
if ($exoPreviewable) {
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
        if ($PSCmdlet.ShouldProcess('Exchange Online organization', 'enable organization customization (Enable-OrganizationCustomization; needed before any custom RBAC object)')) {
            Note 'organization is dehydrated -- enabling customization' 'DarkYellow'
            try { [void](Invoke-Exo -Cmdlet 'Enable-OrganizationCustomization') } catch {
                # Already-enabled is reported as an error by this cmdlet; not fatal.
                Note "Enable-OrganizationCustomization: $((($_.Exception.Message) -split "`n")[0])" 'DarkGray'
            }
        }
    } else { Note 'organization reports hydrated' 'DarkGray' }
} catch { Note "could not read organization config: $((($_.Exception.Message) -split "`n")[0])" 'DarkYellow' }

function Invoke-ExoWhenHydrated {
    # Run an EXO create. The outcome of a failure is decided by Resolve-PimExoCreateOutcome (pure,
    # tested offline):
    #   exists     -> SUCCESS (idempotent re-run; BUG-166 -- it used to be fatal)
    #   dehydrated -> wait for organization customization (up to -Seconds)
    #   retry      -> Exchange has not materialised a service principal created moments ago
    #                 (New-ManagementRoleAssignment answers 404; measured on two test tenants) -- bounded wait
    #   fail       -> returned at once: a real failure must not be hidden behind a long wait
    param([Parameter(Mandatory)][string]$Cmdlet, [hashtable]$Parameters = @{}, [int]$Seconds = 3600, [string]$What = 'object',
          [int]$MaterialiseSeconds = 600)
    $stop = (Get-Date).AddSeconds($Seconds); $matStop = (Get-Date).AddSeconds($MaterialiseSeconds); $n = 0
    $notReadyStart = $null; $notReadyN = 0
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
                'notready' {
                    # INSTALL-HARDEN-1 item 4: a just-hydrated organization refuses RBAC creates ("delegating role
                    # assignment") for ~40-60 min. Bounded (-ExchangeReadyMinutes, default 75), a plain line every attempt.
                    if (-not $notReadyStart) { $notReadyStart = Get-Date }
                    $notReadyN++
                    $w = Get-PimExoNotReadyWait -Attempt $notReadyN -ElapsedSeconds ((Get-Date) - $notReadyStart).TotalSeconds -BoundSeconds ($ExchangeReadyMinutes * 60) -IntervalSeconds $ExchangeReadyIntervalSeconds -What $What
                    if (-not $w.wait) { return @{ ok = $false; error = $w.message; detail = $raw } }
                    Note $w.message 'DarkYellow'
                    if ($OnProgress) { try { & $OnProgress $w.message | Out-Null } catch { } }
                    Start-Sleep -Seconds $w.sleepSeconds
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
# The scope name is decided AFTER the reads below (Resolve-PimMailSenderScope): a scope that already restricts to this
# sender is adopted under its existing name; else -ScopeName; else '<mailbox>-SendScope' (§94: one scope per mailbox).
# 🔴 BUG-166 (b) -- these three used to end in `catch { @() }`, so "I could not read the scopes" became
# "there are no scopes": measured on two test tenants, Get-ManagementScope answered 401 during the Exchange
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
$scopePick = Resolve-PimMailSenderScope -Sender $sender -ScopeName $ScopeName -Scopes $scopes
$scopeName = $scopePick.name
if ($scopePick.note) { Note $scopePick.note 'DarkGray' }
$result.scopeName = $scopeName
$engineOid = if ($engineSp) { "$($engineSp.id)" } else { '' }
$exoPlan = @(New-PimMailSenderExoPlan -ExoServicePrincipals $exoSpList -Scopes $scopes -Assignments $assigns `
    -Principals $sendPrincipals -Sender $sender -ScopeName $scopeName -EngineAppId $EngineAppId -EngineObjectId $engineOid `
    -RemoveEngineSpnAssignment:$RemoveEngineSpnAssignment)
if (-not $exoPlan.Count) {
    Note 'Exchange registration, scope and scoped Application Mail.Send assignment(s) already present' 'DarkGray'
    $result.accessPolicyCreated = $true; Add-Result 'exo-scoped-send' 'already' "$scopeName"
    $script:PimScopedSendConfirmed = $true   # MAIL-STEP-PROOF: read cleanly above, every sending identity holds its assignment
}
$exoDone = 0
foreach ($item in $exoPlan) {
    if (-not $PSCmdlet.ShouldProcess("Exchange Online ($sender)", "$($item.cmdlet): $($item.what)")) {
        if (-not $whatIfRun) { Fail "Exchange change declined ($($item.cmdlet): $($item.what)) -- the scoped send right is incomplete; re-run to finish" }
        Add-Result "exo:$($item.cmdlet)" 'whatif' "would $($item.what)"
        continue
    }
    $r = Invoke-ExoWhenHydrated -Cmdlet $item.cmdlet -What $item.what -Parameters $item.parameters
    if (-not $r.ok) { Add-Result "exo:$($item.cmdlet)" 'FAILED' "$($r.error) $($r.detail)"; Fail "could not $($item.what): $($r.error)" }
    if ($r.existed) { Note "$($item.cmdlet): $($item.what) -- already present, nothing changed" 'DarkGray' }
    else { Note "$($item.cmdlet): $($item.what)" 'Green' }
    $exoDone++
}
if ($exoDone) {
    # Read back -- the whole reason RBAC was chosen over an Application Access Policy. EVERY sending
    # identity must hold its own assignment, not merely "some" assignment in the scope.
    $confirmedScope = Confirm-Eventually -What 'scoped Mail.Send assignment' -Seconds 120 -Test {
        $now = @((Invoke-Exo -Cmdlet 'Get-ManagementRoleAssignment' -Parameters @{ RoleAssigneeType = 'ServicePrincipal' }).value)
        $spNow = @((Invoke-Exo -Cmdlet 'Get-ServicePrincipal').value)
        @($sendPrincipals | Where-Object {
            $ids = Get-PimExoAssigneeIds -ExoServicePrincipals $spNow -AppId $_.appId -ObjectId $_.objectId
            -not @(Select-PimExoMailSendAssignment -Assignments $now -ScopeName $scopeName -AssigneeIds $ids -AssignmentName $_.assignmentName -AlternateNames @($_.legacyAssignmentNames)).Count
        }).Count -eq 0
    }
    if (-not $confirmedScope) { Add-Result 'exo-scoped-send' 'FAILED' 'not present on read-back'; Fail 'the scoped Mail.Send assignment was created but is not present on read-back for every sending identity' }
    Note "scoped Application Mail.Send assignment(s) verified for: $((@($sendPrincipals | ForEach-Object { $_.appId })) -join ', ') -> $scopeName" 'Green'
    $result.accessPolicyCreated = $true; Add-Result 'exo-scoped-send' 'created' "$($exoPlan.Count) change(s) -> $scopeName"
    $script:PimScopedSendConfirmed = $true   # MAIL-STEP-PROOF: verified on read-back for EVERY sending identity
}
if ($EngineAppId -and -not $RemoveEngineSpnAssignment -and @($sendPrincipals | Where-Object { $_.kind -eq 'managed-identity' }).Count) {
    Note "the engine SPN's older scoped assignment (if any) is LEFT in place -- pass -RemoveEngineSpnAssignment to remove it" 'DarkGray'
}
}   # end: $exoPreviewable (step [3])

# --- 2. ENSURE THE ENGINE SPN DOES *NOT* HOLD TENANT-WIDE Mail.Send -------------
# 🔒 THIS IS INVERTED FROM IMP-06 AS WRITTEN, AND THE INVERSION IS THE WHOLE POINT.
# IMP-06 step 3 said "grant the engine SPN Mail.Send" and step 4 said "scope it". Measured in a test tenant:
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
    Note "Saved: no -- no -SqlServerFqdn was given. Finish in PIM Manager: Get Started > Mail sender > Check and send a test mail (mailbox $storeSender)" 'DarkYellow'
    Add-Result 'persist' 'skipped' 'no -SqlServerFqdn'
} elseif (-not $PSCmdlet.ShouldProcess("$SqlServerFqdn / $SqlDatabase (pim.Settings)", "store MailSender = $storeSender and MailMode = sharedMailbox")) {
    # -WhatIf (or declined): no SQL connection is opened at all.
    Add-Result 'persist' 'whatif' "would store MailSender = $storeSender"
} else {
    . (Join-Path $PSScriptRoot '..\..\engine\_shared\PIM-SqlStore.ps1')
    # An EXPLICIT credential beats ambient managed identity in New-PimSqlConnection, which matters
    # here: a build machine has an MI of its own, and an MI can only mint tokens for ITS OWN tenant, so an
    # ambient token would authenticate successfully against the WRONG directory (BUG-34). The
    # onboarding SPN is the SQL server's Entra admin, so it is the identity that can write.
    $global:PIM_TenantId     = $TenantId
    $persistErr = ''
    if ($browserMode) {
        # The person's own SQL token (Azure PowerShell public client, from the browser sign-in). No app credential is set,
        # managed identity is switched off (a VM's own would otherwise win), and the token is placed in the store's
        # per-identity token cache under the "no app credential" key -- the cache is read before any other source, so
        # the connection presents exactly this person and nothing ambient (never a tool's default account).
        foreach ($n in 'PIM_ClientId', 'PIM_ClientSecret', 'PIM_CertThumbprint', 'PIM_SqlClientId', 'PIM_SqlClientSecret', 'PIM_SqlCertThumbprint', 'PIM_SqlAccessToken') { Set-Variable -Scope Global -Name $n -Value $null }
        $global:PIM_NoManagedIdentity = $true
        try {
            $sqlTok = Get-PimMailAdminToken -Resource 'https://database.windows.net'
            $script:PimSqlTokenCache = @{ key = 'sql|||False'; token = $sqlTok; expires = (Get-Date).ToUniversalTime().AddMinutes(45) }
            $global:PIM_SetupActor = Get-PimMsSignedInUpn
        } catch { $persistErr = "could not sign in to Azure SQL: $($_.Exception.Message)" }
    }
    elseif ($UseSignedInAccount) {
        # the signed-in session (a member of the SQL admin group) writes the store -- as Set-PimLicense -UseSignedInAccount
        . (Join-Path $PSScriptRoot '_PimSignedIn.ps1')
        $null = Connect-PimSignedInSql -TenantId $TenantId
    } else {
    $global:PIM_ClientId     = $AdminAppId
    # Set only the credential that was actually supplied, and CLEAR the other -- a stale
    # global of the opposite kind would otherwise win inside Get-PimRestToken's chain and
    # authenticate as something other than what this call asked for. Same reasoning, and the
    # same two lines, as Grant-PimMiSql.
    $global:PIM_ClientSecret   = $AdminSecret
    $global:PIM_CertThumbprint = $AdminCertThumbprint
    }
    $global:PIM_SqlServer    = $SqlServerFqdn
    $global:PIM_SqlDatabase  = $SqlDatabase
    $script:PimMailStoredAll = $null
    $writeSender = {
        if ($persistErr) { throw $persistErr }
        $cs = Get-PimSqlConnectionString -Server $SqlServerFqdn -Database $SqlDatabase
        Set-PimSqlSetting -ConnectionString $cs -Name 'MailSender' -Value $storeSender
        # MAIL-1: this script sets up the SHARED MAILBOX mode, so it also says so (an environment switched to the SMTP
        # relay goes back to the mailbox it was just given).
        Set-PimSqlSetting -ConnectionString $cs -Name 'MailMode' -Value 'sharedMailbox'
        # Read back through the same reader the ENGINE uses, not through a raw SELECT -- the point
        # is to prove what the engine will see, not that a row exists.
        $all = Get-PimAllSqlSettings -ConnectionString $cs
        $st = "$($all['MailSender'])".Trim()
        if ($st -ne $storeSender) { throw "read-back mismatch: store holds '$st', expected '$storeSender'" }
        $script:PimMailStoredAll = $all
        # INSTALL-FIX-EVIDA (100.25 item 4): MailSender is the UPN (above); the PRIMARY SMTP address the customer chose ($sender)
        # is stored beside it, so PIM Manager and the end-of-install check show that address (with the UPN as detail).
        $addrRec = New-PimMailSenderAddressRecord -Sender $storeSender -Address $sender
        if ($addrRec) {
            try { Set-PimSqlSetting -ConnectionString $cs -Name 'MailSenderAddress' -Value $addrRec }
            catch { Note "the mailbox's address could not be stored ($(($_.Exception.Message -split "`n")[0])) -- PIM Manager shows the UPN $storeSender instead" 'Yellow' }
        }
        # MAIL-STEP-PROOF (owner 2026-10-09: "why dont you trigger somehing or accept that we just did a test mail"): store
        # what step [3]'s read-back CONFIRMED -- the scoped Application Mail.Send assignment for every sending identity, in
        # ONE scope on THIS mailbox -- so PIM Manager can show the engine job's send right as granted (with the Manager's
        # own test mail) without waiting for an engine send. Only a confirmed read-back is stored; never a guess. Written
        # here, inside the write, so a temporary firewall rule (-AllowThisIpTemporarily) covers it too.
        $chk = New-PimMailSenderSetupCheck -Confirmed ([bool]$script:PimScopedSendConfirmed) -Sender $storeSender -ScopeName "$scopeName" -Principals $sendPrincipals -By "$($global:PIM_SetupActor)"
        if ($chk) {
            try { Set-PimSqlSetting -ConnectionString $cs -Name 'MailSenderSetupCheck' -Value $chk; Note "stored the setup check for PIM Manager: scoped Mail.Send confirmed for $(@($chk.identities).Count) sending identit$(if (@($chk.identities).Count -eq 1) { 'y' } else { 'ies' }) in $scopeName" 'Green' }
            catch { Note "the setup check could not be stored ($(($_.Exception.Message -split "`n")[0])) -- PIM Manager proves the engine at its first send instead" 'Yellow' }
        }
    }
    # MAIL-NAMING 100.14 item 5: -AllowThisIpTemporarily -- the temporary SQL firewall rule (ARM, as the identity that signed
    # in here). The server is found by its name in -SubscriptionId, else in every subscription that identity can see.
    $sqlServerName = ("$SqlServerFqdn".Trim() -split '\.')[0]
    $script:PimSqlServerId = ''
    $armApi = '2021-11-01'
    $findSqlServer = {
        if ($script:PimSqlServerId) { return $script:PimSqlServerId }
        $h = @{ Authorization = "Bearer $(Get-PimMailAdminToken -Resource 'arm')" }
        $subs = if ("$SubscriptionId".Trim()) { @("$SubscriptionId".Trim()) } else {
            @((Invoke-RestMethod -Headers $h -Uri 'https://management.azure.com/subscriptions?api-version=2020-01-01').value | ForEach-Object { "$($_.subscriptionId)" } | Select-Object -First 50) }
        foreach ($s in $subs) {
            try { $hit = @((Invoke-RestMethod -Headers $h -Uri "https://management.azure.com/subscriptions/$s/providers/Microsoft.Sql/servers?api-version=$armApi").value | Where-Object { "$($_.name)" -ieq $sqlServerName }) | Select-Object -First 1 } catch { $hit = $null }
            if ($hit) { $script:PimSqlServerId = "$($hit.id)"; return $script:PimSqlServerId }
        }
        throw "the SQL server '$sqlServerName' was not found in the subscription(s) this sign-in can see$(if (-not "$SubscriptionId".Trim()) { ' (pass -SubscriptionId)' })"
    }
    $addRule = {
        param($ip)
        $sid = & $findSqlServer
        $rn = New-PimSqlTempFirewallRuleName -Ip $ip
        $u = "https://management.azure.com$sid/firewallRules/$rn`?api-version=$armApi"
        [void](Invoke-RestMethod -Method PUT -Uri $u -Headers @{ Authorization = "Bearer $(Get-PimMailAdminToken -Resource 'arm')"; 'Content-Type' = 'application/json' } `
                   -Body (@{ properties = @{ startIpAddress = $ip; endIpAddress = $ip } } | ConvertTo-Json -Depth 4))
        Note "temporary SQL firewall rule '$rn' added for $ip (it is removed again right after the write)" 'DarkYellow'
        return $u
    }
    $removeRule = {
        param($u)
        [void](Invoke-RestMethod -Method DELETE -Uri $u -Headers @{ Authorization = "Bearer $(Get-PimMailAdminToken -Resource 'arm')" })
    }
    $scriptCmdlet = $PSCmdlet   # THIS script's ShouldProcess (-WhatIf / -Confirm), not the helper function's
    $mayAddRule = { param($ip) $scriptCmdlet.ShouldProcess("SQL server $SqlServerFqdn", "add a TEMPORARY firewall rule for $ip, write the sender, remove the rule") }
    $wr = Invoke-PimSqlWriteWithTemporaryFirewall -Write $writeSender -AllowThisIpTemporarily:$AllowThisIpTemporarily -AddRule $addRule -RemoveRule $removeRule -ShouldProcess $mayAddRule
    if ($wr.ruleAdded) {
        if ($wr.ruleRemoved) { Note 'temporary SQL firewall rule removed again' 'DarkGray' }
        else { Write-Host "    WARNING: the temporary SQL firewall rule could NOT be removed ($($wr.removeError)). Remove it now: SQL server $sqlServerName > Networking > rule $(("$($wr.rule)" -split '/firewallRules/')[-1] -replace '\?.*$', '')" -ForegroundColor Red }
    }
    $finish = "Finish in PIM Manager: Get Started > Mail sender > Check and send a test mail (mailbox $storeSender)"
    if ($wr.ok) {
        $all = $script:PimMailStoredAll
        $stored = "$($all['MailSender'])".Trim()
        Note "Saved: yes -- pim.Settings MailSender = $stored, MailMode = $("$($all['MailMode'])".Trim()) (verified by read-back)" 'Green'
        Add-Result 'persist' 'ok' $stored
        $result.persisted = $true
    } else {
        $m = ("$($wr.error)" -split "`n")[0]
        $short = if ($wr.whatIf) { "Saved: no -- the temporary firewall rule was not added (-WhatIf / declined). $finish" }
                 elseif ($wr.firewall) { "Saved: no -- this PC cannot reach the PIM database (firewall). $finish$(if (-not $AllowThisIpTemporarily) { ', or re-run with -AllowThisIpTemporarily' })." }
                 else { "Saved: no -- $m. $finish." }
        if ($browserMode) {
            # From a person's own PC the store is often out of reach (a private endpoint, a firewall) -- and the hard part,
            # the mailbox and its scoped send right, IS done. So this is NOT a failure here: PIM Manager stores the sender.
            Add-Result 'persist' 'manual' $m
            $result.persisted = $false
            Note $short 'Yellow'
        } else {
            Add-Result 'persist' 'FAILED' $m
            Fail "mailbox + grants are in place, but the sender is not saved. $short"
        }
    }
}

# --- summary --------------------------------------------------------------------
if ($whatIfRun) {
    # 12.7: the preview ends here -- say what WOULD change, and that nothing did.
    $result.ok = $true
    Write-Host ""
    Write-Host ("=" * 78) -ForegroundColor Cyan
    Write-Host " WHATIF / PREVIEW -- nothing was changed" -ForegroundColor Yellow
    Write-Host ("=" * 78) -ForegroundColor Cyan
    foreach ($s in @($result.steps | Where-Object { "$($_.state)" -eq 'whatif' })) { Write-Host "  would: $($s.step) -- $($s.detail)" }
    if (-not @($result.steps | Where-Object { "$($_.state)" -eq 'whatif' }).Count) { Write-Host '  nothing to change: the mailbox, its scoped send right and the stored sender are already in place (as far as could be read).' }
    Write-Host "  Run the same command without -WhatIf to apply."
    Write-ResultFile
    exit 0
}
$result.ok = $true
Write-Host ""
Write-Host ("=" * 78) -ForegroundColor Cyan
Write-Host " MAIL SENDER READY" -ForegroundColor Green
Write-Host ("=" * 78) -ForegroundColor Cyan
Write-Host "  sender        : $sender"
Write-Host "  send right    : Exchange RBAC 'Application Mail.Send' -> scope '$scopeName' -> $sender ONLY"
foreach ($p in $sendPrincipals) {
    # the name the assignment really has: an existing (adopted) one keeps its name, a new one got the planned name
    $held = @(Select-PimExoMailSendAssignment -Assignments $assigns -ScopeName $scopeName -AssigneeIds (Get-PimExoAssigneeIds -ExoServicePrincipals $exoSpList -AppId $p.appId -ObjectId $p.objectId) -AssignmentName $p.assignmentName -AlternateNames @($p.legacyAssignmentNames)) | Select-Object -First 1
    $an = if ($held -and "$($held.Name)".Trim()) { "$($held.Name)".Trim() } else { $p.assignmentName }
    Write-Host "  sends as      : $($p.kind) $($p.appId)  (assignment $an)"
}
Write-Host "  tenant-wide   : NO Graph Mail.Send on any sending identity or the engine SPN -- by design"
Write-Host "  exchange plan : $($result.exchangePlan)"
Write-Host ""
# IMP-31 -- SAY WHAT PRIVILEGE IS LEFT BEHIND, AND UNTIL WHEN. The old run granted the provisioning
# identity tenant-wide Exchange administration and never mentioned it again; the tenant's own alerting
# was how anyone found out.
if ($delegatedMode) {
    # Nothing was granted to any identity in a browser / signed-in person run -- the administrator used their own role, which they keep.
    $result.privilegedGrants = [ordered]@{ identity = (Get-PimMailSignedInUpn); exchangeAdministrator = $null; exchangeManageAsApp = 'not used (delegated sign-in)' }
    Write-Host "  PRIVILEGED GRANTS: none -- the administrator $(Get-PimMailSignedInUpn) used their own role; no app was granted anything." -ForegroundColor Green
    Write-Host ""
} else {
try { $exchAdminNow = Read-ExchAdminGrant } catch { $exchAdminNow = $exchAdminState }
$exAdminLine = if (-not $exchAdminNow.active) { 'not active (expired or never granted)' }
               elseif ($exchAdminNow.kind -eq 'permanent') { 'ACTIVE, PERMANENT (standing privilege outside PIM -- remove it with a DIFFERENT administrator: an identity cannot remove its own directory role)' }
               elseif ((Test-PimGrantOverlong -Grant $exchAdminNow -Duration $ExchangeAdminDuration).overlong) { "ACTIVE until $($exchAdminNow.endDateTime.ToString('u')) -- LONGER than the requested ${ExchangeAdminDuration}: standing privilege until then (shorten or remove it with a different administrator)" }
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
}
if ($result.persisted) {
    Write-Host "  NEXT: PIM Manager > Get Started > Mail sender > Send a test mail."
} else {
    Write-Host "  NEXT: PIM Manager > Get Started > Mail sender > Check and send a test mail (mailbox $storeSender)."
}
Write-Host ""
# Say only what was verified BY READ-BACK. An earlier summary asserted "Mail.Send, RESTRICTED to
# that mailbox" while the app was in fact unscoped -- an unverified security claim is worse than
# none, because it stops anyone from checking.
Write-Host "  VERIFIED BY READ-BACK: mailbox exists; scoped RBAC assignment exists; no tenant-wide" -ForegroundColor Green
Write-Host "  Graph Mail.Send is present on any sending identity." -ForegroundColor Green
Write-Host "  The restriction was proven in a test tenant with a second out-of-scope mailbox (in-scope send" -ForegroundColor DarkGray
Write-Host "  accepted, out-of-scope send ErrorAccessDenied). This script does NOT re-prove it in your" -ForegroundColor DarkGray
Write-Host "  tenant -- that would mean creating a decoy mailbox. If you need that assurance here, do it" -ForegroundColor DarkGray
Write-Host "  deliberately and delete the decoy afterwards." -ForegroundColor DarkGray
Write-ResultFile
exit 0
} finally { Stop-PimScriptRun -Script 'Initialize-PimMailSender' }
