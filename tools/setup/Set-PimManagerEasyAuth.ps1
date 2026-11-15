#Requires -Version 5.1
<#
.SYNOPSIS
  §44.5 / §47.3 -- put Easy Auth in front of the hosted Manager, as a DEPLOY STEP.

.DESCRIPTION
  Until this existed, nothing in the setup configured authentication for the Manager.
  `Setup-PimContainers` printed advice ("put Easy Auth in front before anyone opens it") and the
  deploy finished. With `-Exposure external` -- the shape a first customer install uses, because an
  internal-only environment cannot be reached from the operator's laptop -- that leaves a
  privileged-access control plane **publicly reachable with no authentication** between the deploy
  completing and somebody doing this by hand.

  It also made a green deploy impossible: the post-deploy release gate mints a token through Easy
  Auth to probe the served page, and with no auth configured there is no audience to mint for. The
  gate correctly refuses to score a skip as a pass (§7a), so the deploy failed on a healthy
  environment. An externally-exposed Manager with nothing in front of it SHOULD fail a release gate.

  WHAT IT DOES (idempotent, and safe to re-run on a configured environment):
    1. resolves the app's ingress FQDN,
    2. finds or creates an app registration -- display name is a PRODUCT name, never a customer
       name (§39), because this object lives in the customer's own tenant where it is unique,
    3. sets the reply URL, the `api://<appId>` identifier URI and ID-token issuance,
    4. ensures the app registration has a service principal in the tenant,
    5. BUILT-IN-AUTH-1 (owner 2026-11-14) -- NO CLIENT SECRET: the web identity id-pim-web (made and
       attached when the Manager has none), a federated credential on the registration that trusts it,
       the container-app setting 'override-use-mi-fic-assertion-client-id' (its CLIENT id), and the
       token store (blob container 'pim-auth-tokens' in the install's own storage account with
       shared-key access off; Storage Blob Data Contributor for id-pim-web on THAT container only),
    6. puts Microsoft's built-in authentication on with the standard (engine/_shared/PIM-BuiltinAuth.ps1:
       RedirectToLoginPage, the v2 issuer, both audiences, the account picker, the token store, an
       8-hour session),
    7. READS IT BACK and fails if anything differs -- only THEN the Manager container is set to verify
       the signed token itself (PIM_HOSTED_AUTH_LAYER=easyauth, PIM_HOSTED_REQUIRE_SIGNED_TOKEN=true,
       PIM_HOSTED_EASYAUTH_AUD, PIM_HOSTED_AUTH_TENANT, PORT), an opt-in sign-in front still in the
       template is removed in the same write, and the old Easy Auth client secrets ('easyauth*') are
       removed (read back),
    8. restricts who may sign in (an EXPLICIT choice: -AllowedPrincipals, or -AllowAllTenantUsers =
       every member account and never a guest), and only then
    9. OPENS the Manager: a new Manager is created closed (Setup-PimContainers) and stays closed until
       every step above has succeeded. -CloseIngressOnly (re)closes it and does nothing else.

  🔒 Step 7 is not ceremony. Every other "configure it and report success" step in this solution
  that skipped a read-back eventually turned out to be configuring nothing (BUG-37, the Graph
  grants, the workspace move). A setting that flips instantly and takes effect later is exactly the
  shape that fools a writer-only check.

.PARAMETER ClientId
  Use an EXISTING app registration instead of creating one. When set, nothing is created -- the
  script only wires the app to it. Its reply URL still has to be right, so it is checked and, if
  the deployment's callback URL is missing, added.

.EXAMPLE
  pwsh -File Set-PimManagerEasyAuth.ps1 -ResourceGroup rg-x -SubscriptionId <sub> -TenantId <tid>
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$App            = 'ca-pim-manager',
    [Parameter(Mandatory)][string]$ResourceGroup,
    [string]$SubscriptionId,
    [Parameter(Mandatory)][string]$TenantId,
    # A PRODUCT name, not a customer one. This object is created inside the customer's own tenant,
    # so it does not need to be told apart from another customer's -- and naming customers in
    # identifiers is what stops a setup routine being usable for the next thousand of them (§39).
    # 🔑 CONSISTENT WITH ITS SIBLINGS (operator, 2026-09-10: "i prefer consistence with
    # displayname, either no - (dash) or dash"). 'PIM4EntraPS Deploy' and 'PIM4EntraPS Engine' use
    # a space; only this one used a dash. Spaces win on a 2-to-1 vote and because renaming the
    # other two would disturb identities that are working.
    [string]$AppDisplayName = 'PIM4EntraPS Manager',
    # 🔴 EVERY NAME THIS APP HAS EVER SHIPPED UNDER, newest first.
    # Renaming is only safe because adoption searches ALL of them. Without this list, the release
    # that changes the name is the release that forks every existing tenant: the stable-uri lookup
    # misses (nothing has been stamped yet), the new-name lookup misses (the app still has the old
    # name), and a THIRD registration is created. Sequencing the rename a release later would also
    # work, but a list is honest about the history and cannot be forgotten.
    [string[]]$LegacyDisplayNames = @('PIM4EntraPS-Manager', 'PIM-Manager-Hosted'),
    # 🔑 THE STABLE KEY. An identifier uri is unique within the tenant and survives a rename, which
    # a display name does not. It must NOT be derived from the appId (api://<appId> cannot be used
    # to FIND the app -- you need the app to know its appId), so it is built from the TENANT id,
    # which the caller already supplies.
    # 🪤 A BARE 'api://pim4entraps-manager' IS REFUSED BY ENTRA:
    #     "All newly added URIs must contain a tenant verified domain, tenant id or app id"
    # -- measured on a live deploy 2026-09-10, six times in the retry loop. The tenant id is the
    # only one of those three that is both known before the app exists and stable across renames.
    [string]$StableIdentifierUri,
    [string]$ClientId,                      # reuse an existing registration instead of creating one
    # §48.1 -- WHO may sign in. Easy Auth alone answers "is this a real account in this tenant?",
    # which on a privileged-access console is not the question. Give UPNs, group display names or
    # object ids: the enterprise application is then switched to assignment-required and each one
    # is assigned. It never switches assignment on with nobody assigned, because that locks out the
    # operator, the customer and the release gate in one call.
    # 🔴 SEC-44 (2026-09-18) -- LEAVING IT EMPTY IS NO LONGER A CHOICE THIS SCRIPT MAKES FOR YOU. The old
    # "empty = every account in the tenant, guests included, only warned" put every guest on a tier-0
    # console as a Reader by default. Now one of these is REQUIRED (refused before anything changes):
    #   -AllowedPrincipals <upn|group|objectId>[,...]  -- exactly these (plus the deploy identity), or
    #   -AllowAllTenantUsers                           -- every MEMBER account, NEVER guests (see below).
    # The only exception is an app that is ALREADY assignment-required: its restriction was chosen
    # before, and is kept as it is (a re-run, a -RotateSecret).
    [string[]]$AllowedPrincipals = @(),
    # "Everyone in the tenant" -- but never guests. Implemented as a DYNAMIC security group whose rule
    # is (user.userType -eq "Member") and (user.accountEnabled -eq true), assigned to the enterprise
    # application with assignment required. A guest is not a member of it, so a guest cannot sign in.
    # (Dynamic groups need Entra ID P1; a tenant running PIM has P2.) Membership is evaluated by Entra
    # asynchronously, so a NEW group admits people after a few minutes -- it fails closed until then.
    [switch]$AllowAllTenantUsers,
    [string]$MembersGroupName        = 'PIM4EntraPS Manager users (members, no guests)',
    [string]$MembersGroupMailNickname = 'pim4entraps-manager-members',
    # 🔴 SEC-31 -- THE MANAGER IS CLOSED UNTIL EASY AUTH IS PROVEN. Setup-PimContainers creates a new
    # Manager behind an ingress access restriction that admits nobody (the 'pim-closed-until-easyauth'
    # rule); this script removes it ONLY after Easy Auth is configured, read back, consented and the
    # sign-in restriction is in place. -CloseIngressOnly does nothing else: it (re)applies that rule and
    # reads it back -- what Setup-PimContainers calls at create, and what Invoke-PimDeployAll calls when
    # the Easy Auth step fails on a Manager that has no Easy Auth in front of it.
    [switch]$CloseIngressOnly,
    # BUILT-IN-AUTH-1: the NAME of the old Easy Auth client secret on the container app. Nothing is minted any more (the sign-in
    # is secretless); a container-app secret of this name left by an earlier version is REMOVED once the standard reads back.
    [string]$SecretName     = 'easyauth-client-secret',
    [int]$SecretYears       = 2,            # IGNORED since BUILT-IN-AUTH-1 (no client secret): kept so existing command lines bind
    # IGNORED since BUILT-IN-AUTH-1: there is no client secret to rotate (a federated credential has nothing that expires).
    [switch]$RotateSecret,
    # the install's storage account for the token store ('' = the one with shared-key access off in the resource group, else
    # the install's own stpimab<hash> account is created)
    [string]$TokenStoreAccount = '',
    [string]$OutFile
)
$ErrorActionPreference = 'Stop'
# Built here rather than defaulted in the param block: a parameter default cannot reference another
# parameter, and deriving it from -TenantId is the whole point (Entra refuses a uri that contains
# neither a verified domain, the tenant id, nor the app id).
if (-not "$StableIdentifierUri".Trim()) { $StableIdentifierUri = "api://$TenantId/pim4entraps-manager" }
# One comma-separated string (what crosses `pwsh -File`) or an array -- either way, one entry per principal.
$AllowedPrincipals = @(@($AllowedPrincipals) | ForEach-Object { "$_" -split '[,;]' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })
$here = Split-Path -Parent $PSCommandPath
# REQUIREMENTS 100.41 / framework 12.17 NO-AZ: every Azure + Graph call below is REST through PIM-Rest's ONE token client
# (PIM-ArmSetup.ps1 wrappers). No az CLI, no module.
$sharedDir = Join-Path (Split-Path -Parent (Split-Path -Parent $here)) 'engine\_shared'
if (-not (Get-Command Invoke-PimRest -ErrorAction SilentlyContinue)) { . (Join-Path $sharedDir 'PIM-Rest.ps1') }
. (Join-Path $sharedDir 'PIM-ArmSetup.ps1')
. (Join-Path $sharedDir 'PIM-InstallNames.ps1')   # CR5 item 5: the display name's earlier / current form (never renamed back)
# BUG-169: the sign-in consent scopes + the pure consent plan.
. (Join-Path $here '_PimDeployGraph.ps1')
# BUILT-IN-AUTH-1: the ONE definition of the built-in sign-in standard (also what the updater reports against)
. (Join-Path $sharedDir 'PIM-BuiltinAuth.ps1')
$script:PimBa = Get-PimBuiltinAuthStandard

function Step($m) { Write-Host "==> $m" -ForegroundColor Cyan }
function Note($m) { Write-Host "    $m" -ForegroundColor DarkGray }
function Warn($m) { Write-Host "    $m" -ForegroundColor Yellow }

$result = [ordered]@{ ok = $false; reason = ''; clientId = ''; fqdn = ''; created = $false; whatIf = [bool]$WhatIfPreference; ingress = '' }
function Write-ResultFile { if ("$OutFile".Trim()) { try { $result | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $OutFile -Encoding UTF8 } catch {} } }

# =================================================================================================
# 🔴 SEC-31 -- THE INGRESS GATE. A new Manager is created CLOSED and is opened here, last, once Easy
# Auth is proven. "Closed" = an ingress access restriction whose only Allow rule is an address no
# client can have (192.0.2.1 is RFC 5737 TEST-NET-1, never routed): ACA then refuses every other
# caller, whether the ingress is public or VNet-only. The FQDN does not change, so Easy Auth's reply
# URL is the one people will actually use once it opens.
# 🪤 ONLY OUR RULE IS EVER TOUCHED, BY NAME. An operator's own allow-list (office IPs) is left alone,
# and opening the gate on an app that carries one leaves exactly that allow-list in force.
# =================================================================================================
function Get-PimManagerGateRuleSpec {
    # PURE. One definition, used to close (Setup-PimContainers, the deploy's failure path) and to open.
    return @{ name = 'pim-closed-until-easyauth'; ipAddress = '192.0.2.1/32'; action = 'Allow'
              description = 'PIM4EntraPS closed until Easy Auth is configured and verified' }
}
function Get-PimManagerGateState {
    # PURE. Judge the app's ingress ipSecurityRestrictions (as JSON). 'unknown' (unreadable) is NEVER 'open'.
    param([string]$ListJson)
    $spec = Get-PimManagerGateRuleSpec
    if (-not "$ListJson".Trim()) { return @{ state = 'unknown'; rules = @(); reason = 'the access-restriction list could not be read' } }
    $rules = $null
    # PS 5.1: ConvertFrom-Json emits a JSON array as ONE object, so @(ConvertFrom-Json ...) is an array
    # holding an array -- assign first, then enumerate (the note PIM-Scheduler.ps1 carries).
    try { $parsed = ConvertFrom-Json -InputObject "$ListJson"; $rules = @($parsed) } catch { return @{ state = 'unknown'; rules = @(); reason = 'the access-restriction list is not JSON' } }
    $names = @($rules | Where-Object { $_ } | ForEach-Object { "$($_.name)" })
    return @{ state = $(if ($names -contains $spec.name) { 'closed' } else { 'open' }); rules = $names; reason = '' }
}
function Set-PimManagerIngressGate {
    <#
      Close or open the gate on one app, and READ IT BACK. Returns @{ ok; changed; state; rules; reason }.
      The rules are the app's properties.configuration.ingress.ipSecurityRestrictions, over ARM REST (read-modify-write
      of the configuration: every other rule, the ingress and the secrets stay as they are).
      -Io is the test seam: a scriptblock param([string]$Op, [object]$Arg, [string]$SubscriptionId) where Op is
      'list' (return the rules as JSON, '' when unreadable), 'add' (Arg = the rule spec) or 'remove' (Arg = the rule name).
      Fail closed: a Close that cannot be read back is ok=$false; an Open that cannot be read back is ok=$false.
    #>
    param([Parameter(Mandatory)][ValidateSet('Close', 'Open')][string]$Mode,
          [Parameter(Mandatory)][string]$App, [Parameter(Mandatory)][string]$ResourceGroup,
          [Parameter(Mandatory)][string]$SubscriptionId, [scriptblock]$Io)
    if (-not $Io) {
        $Io = {
            param([string]$Op, [object]$Arg, [string]$Sub)
            if ($Op -eq 'list') {
                $a = Get-PimArmAcaApp -SubscriptionId $Sub -ResourceGroup $ResourceGroup -Name $App -ErrorAsNull
                if (-not $a) { return '' }
                $rules = @(@($a.properties.configuration.ingress.ipSecurityRestrictions) | Where-Object { $_ })
                return (ConvertTo-Json -InputObject @($rules) -Depth 6 -Compress)
            }
            # A refused write is not reported here: the READ-BACK below decides (as the az path did).
            $gateApp = "$App"; $gateRg = "$ResourceGroup"
            # 2026-10-10 (a customer's fresh install): the write came seconds after the app was created and ARM refused it as
            # busy (409 OperationInProgress); the refusal was swallowed and only the empty read-back surfaced. Now: wait out a
            # busy app (Invoke-PimArmBusyRetry, bounded) and keep the write's own error for the reason.
            $global:PimGateWriteError = ''
            $gateWrite = {
                # 🪤 .GetNewClosure() captures ONLY the variables LOCAL to the scope it is called in -- here, this scriptblock's
                # scope, not $Io's. So copy what the mutate needs into locals HERE first; without this the mutate saw an empty
                # $Op/$Arg, added no rule, and the PATCH went out unchanged (the read-back then waited 60 s and failed).
                $mOp = "$Op"; $mApp = "$gateApp"
                $mRule = [pscustomobject]@{ name = $(if ($Op -eq 'add') { "$($Arg.name)" } else { "$Arg" })
                                            description = "$($Arg.description)"; ipAddressRange = "$($Arg.ipAddress)"; action = "$($Arg.action)" }
                Set-PimArmAcaAppConfiguration -SubscriptionId $Sub -ResourceGroup $gateRg -Name $gateApp -Mutate {
                    param($cfg)
                    $ing = $cfg.ingress
                    if (-not $ing) { throw "'$mApp' has no ingress -- there is nothing to restrict." }
                    $keep = @(@($ing.ipSecurityRestrictions) | Where-Object { $_ -and "$($_.name)" -ne "$($mRule.name)" })
                    if ($mOp -eq 'add') { $keep += [pscustomobject]@{ name = "$($mRule.name)"; description = "$($mRule.description)"; ipAddressRange = "$($mRule.ipAddressRange)"; action = "$($mRule.action)" } }
                    $ing | Add-Member -NotePropertyName ipSecurityRestrictions -NotePropertyValue @($keep) -Force
                }.GetNewClosure() | Out-Null   # the MUTATE may be a closure: it calls only cmdlets, never a dot-sourced function
            }   # $gateWrite itself is NOT .GetNewClosure(): a closure cannot see the PIM-ArmSetup functions this script dot-sourced
            try {
                [void](Invoke-PimEaBusyRetry -Write $gateWrite)
            } catch { $global:PimGateWriteError = "$($_.Exception.Message)"; Write-Verbose "ingress access-restriction $Op on $gateApp refused: $($global:PimGateWriteError)" }
        }
    }
    $spec = Get-PimManagerGateRuleSpec
    $read = { Get-PimManagerGateState -ListJson ("$(& $Io 'list' $null $SubscriptionId)") }
    $before = & $read
    if ($before.state -eq 'unknown') { return @{ ok = $false; changed = $false; state = 'unknown'; rules = @(); reason = $before.reason } }
    $want = $(if ($Mode -eq 'Close') { 'closed' } else { 'open' })
    if ($before.state -eq $want) { return @{ ok = $true; changed = $false; state = $want; rules = $before.rules; reason = "already $want" } }
    if ($Mode -eq 'Close') { [void](& $Io 'add' $spec $SubscriptionId) }
    else { [void](& $Io 'remove' $spec.name $SubscriptionId) }
    $after = & $read
    # the change lands with a new revision: read back for up to ~60 s before calling it failed
    for ($w = 0; $w -lt 6 -and $after.state -ne $want -and -not "$($global:PimGateWriteError)".Trim(); $w++) { Start-Sleep -Seconds 10; $after = & $read }
    if ($after.state -ne $want) {
        $why = $(if ($after.state -eq 'unknown') { $after.reason } else { "the rule list reads [$(@($after.rules) -join ', ')] after the $($Mode.ToLowerInvariant())" })
        if ("$($global:PimGateWriteError)".Trim()) { $why += " -- the write was refused: $($global:PimGateWriteError)" }
        return @{ ok = $false; changed = $false; state = $after.state; rules = $after.rules; reason = $why }
    }
    return @{ ok = $true; changed = $true; state = $want; rules = $after.rules; reason = '' }
}

# =================================================================================================
# 🔴 SEC-44 -- WHO MAY SIGN IN IS AN EXPLICIT CHOICE. PURE.
# =================================================================================================
function Get-PimEasyAuthAccessDecision {
    param([string[]]$AllowedPrincipals = @(), [switch]$AllowAllTenantUsers, [switch]$AlreadyRestricted)
    $named = @($AllowedPrincipals | Where-Object { "$_".Trim() })
    if ($named.Count -and $AllowAllTenantUsers) { return @{ ok = $true; mode = 'principals+members'; reason = 'the named principals AND every member account (no guests)' } }
    if ($named.Count)                           { return @{ ok = $true; mode = 'principals';         reason = "only the $($named.Count) named principal(s) and the deploy identity" } }
    if ($AllowAllTenantUsers)                   { return @{ ok = $true; mode = 'members';            reason = 'every member account in the tenant -- guests are NOT included' } }
    if ($AlreadyRestricted)                     { return @{ ok = $true; mode = 'keep-existing';      reason = 'the application is already assignment-required; its existing assignments are kept as they are' } }
    return @{ ok = $false; mode = 'refused'
              reason = ('no sign-in choice was made. Pass -AllowedPrincipals <upn-or-group>[,...] (deploy-all: -EasyAuthAllowedPrincipals) ' +
                        'to admit exactly those, or -AllowAllTenantUsers (deploy-all: -EasyAuthAllowAllTenantUsers) to admit every member ' +
                        'account -- guests are never admitted by that. Refusing to leave a privileged-access console open to every ' +
                        'account in the tenant, guests included.') }
}
function Get-PimRevisionRestartVerdict {
    # PURE (BUG-183). Did a revision restart actually replace what was running? The new secret is read
    # when a replica STARTS, so the proof is that none of the replicas seen before the restart remain.
    param([int]$RestartExitCode = 0, [string[]]$ReplicasBefore = @(), [string[]]$ReplicasAfter = @())
    $b = @($ReplicasBefore | Where-Object { "$_".Trim() } | ForEach-Object { "$_".Trim() })
    $a = @($ReplicasAfter  | Where-Object { "$_".Trim() } | ForEach-Object { "$_".Trim() })
    if ($RestartExitCode -ne 0) { return @{ ok = $false; done = $true; reason = "the revision restart was refused (code $RestartExitCode)" } }
    if (-not $b.Count) { return @{ ok = $true; done = $true; reason = 'no replica was running, so the next one to start reads the new secret' } }
    $still = @($b | Where-Object { $a -contains $_ })
    if (-not $still.Count) { return @{ ok = $true; done = $true; reason = "replica(s) replaced ($($b.Count) before, $($a.Count) now)" } }
    return @{ ok = $false; done = $false; reason = "the replica(s) running before the restart are still running: $($still -join ', ')" }
}
function Get-PimManagerMembersGroupSpec {
    # PURE. The dynamic "every member, no guests" group -- the body POSTed to /groups, and the rule it must still carry.
    param([string]$DisplayName = 'PIM4EntraPS Manager users (members, no guests)', [string]$MailNickname = 'pim4entraps-manager-members')
    $rule = '(user.userType -eq "Member") and (user.accountEnabled -eq true)'
    return @{
        rule = $rule
        body = [ordered]@{ displayName = $DisplayName; mailNickname = $MailNickname; mailEnabled = $false; securityEnabled = $true
                           groupTypes = @('DynamicMembership'); membershipRule = $rule; membershipRuleProcessingState = 'On'
                           description = 'Every enabled MEMBER account (never a guest) -- the sign-in allow-list of the PIM4EntraPS Manager.' }
    }
}
function Test-PimManagerMembersGroup {
    # PURE. Is this group (a Graph group object) still the "members, no guests" group? Whitespace/case-insensitive.
    param($Group, [string]$Rule)
    if (-not $Group) { return @{ ok = $false; reason = 'no group' } }
    $norm = { param($s) (("$s" -replace '\s+', ' ').Trim()).ToLowerInvariant() }
    if (@($Group.groupTypes) -notcontains 'DynamicMembership') { return @{ ok = $false; reason = "group $($Group.id) is not a dynamic group" } }
    if ((& $norm $Group.membershipRule) -ne (& $norm $Rule)) { return @{ ok = $false; reason = "group $($Group.id) carries the rule '$($Group.membershipRule)', not '$Rule' -- it may admit guests" } }
    if ("$($Group.membershipRuleProcessingState)" -and "$($Group.membershipRuleProcessingState)" -ne 'On') { return @{ ok = $false; reason = "group $($Group.id) has rule processing '$($Group.membershipRuleProcessingState)'" } }
    return @{ ok = $true; reason = '' }
}

# ---- who the REST calls run as -----------------------------------------------------------------
# This script is run IN-PROCESS by Invoke-PimDeployAll / Setup-PimContainers / Rebuild-PimEnvExternal, so it uses the
# identity their PIM-Rest session already carries (certificate, Support-app secret, or the signed-in person). Run on its
# own, it connects PIM-Rest as the person at the keyboard for -TenantId. Either way: no az, no default context.
$SubscriptionId = "$SubscriptionId".Trim()
if (-not $SubscriptionId) {
    $result.reason = '-SubscriptionId is required (the container app is addressed over ARM REST -- there is no az default context to fall back to)'
    Write-ResultFile; throw "Set-PimManagerEasyAuth: $($result.reason)"
}
if (-not "$($global:PIM_SetupRestMode)".Trim() -and -not "$($global:PIM_ClientId)".Trim()) {
    [void](Connect-PimSetupRest -SubscriptionId $SubscriptionId -TenantId $TenantId)
} elseif (-not "$($global:PIM_TenantId)".Trim()) { $global:PIM_TenantId = "$TenantId".Trim() }

function Invoke-PimEaBusyRetry {
    # A Container App that was just created / changed answers its next write with 409 "OperationInProgress" until the revision
    # settles (2026-10-10, a customer's fresh install). Wait that out, bounded (6 x 20 s); any other error is thrown at once.
    param([Parameter(Mandatory)][scriptblock]$Write, [int[]]$Waits = @(20, 20, 20, 20, 20, 20))
    $n = 0
    while ($true) {
        try { return (& $Write) }
        catch {
            if ("$($_.Exception.Message)" -notmatch '(?i)OperationInProgress|active provisioning operation|another operation is in progress' -or $n -ge $Waits.Count) { throw }
            Write-Host "    the container app is still busy with a previous change -- waiting $($Waits[$n]) s" -ForegroundColor DarkGray
            Start-Sleep -Seconds $Waits[$n]; $n++
        }
    }
}
function Test-PimEaGraphRefusal([string]$Text) {
    # Graph refusing the CALLER: say what the token actually carries (a token minted before a grant has none of it).
    if ("$Text" -match 'Insufficient privileges|Authorization_RequestDenied|HTTP 403') { Write-PimGraphTokenRolesHint }
}
function Get-PimEaAssignedPrincipalIds {
    # The principals assigned to the Manager's enterprise application ($spOid), @() when unreadable.
    $r = Invoke-PimSetupGraph -Path "https://graph.microsoft.com/v1.0/servicePrincipals/$spOid/appRoleAssignedTo" -All -ErrorAsNull
    return @(@($r) | Where-Object { $_ } | ForEach-Object { "$($_.principalId)".Trim() } | Where-Object { $_ })
}
function Get-PimEaDeployAppId {
    # The appid of the DEPLOY identity when the calls run as an application (idtyp=app, or no user claims) -- '' for a
    # person (whose token's appid is only the sign-in client, not an identity to assign). Never prints the token.
    try {
        $t = Get-PimRestToken -Resource 'graph'
        $seg = "$t".Split('.')[1].Replace('-', '+').Replace('_', '/'); while ($seg.Length % 4) { $seg += '=' }
        $c = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($seg)) | ConvertFrom-Json
        $isApp = ("$($c.idtyp)" -ieq 'app') -or (-not "$($c.upn)$($c.unique_name)$($c.preferred_username)$($c.scp)".Trim())
        if ($isApp) { return "$($c.appid)".Trim() }
    } catch { Write-Verbose "deploy identity not read from the token: $($_.Exception.Message)" }
    return ''
}

if ($CloseIngressOnly) {
    Write-Host "`n=== PIM Manager ingress: CLOSE until Easy Auth is verified ($App) ===" -ForegroundColor Cyan
    if ($WhatIfPreference) { Note "WhatIf: would apply the access restriction '$((Get-PimManagerGateRuleSpec).name)' and read it back"; $result.ok = $true; Write-ResultFile; return }
    $g = Set-PimManagerIngressGate -Mode Close -App $App -ResourceGroup $ResourceGroup -SubscriptionId $SubscriptionId
    $result.ingress = $g.state
    if (-not $g.ok) {
        $result.reason = "could not close the Manager's ingress: $($g.reason)"
        Write-ResultFile
        throw ("Set-PimManagerEasyAuth: $($result.reason). An app that cannot be closed must not be exposed -- " +
               "resume the installation (it closes the ingress first), or run Set-PimManagerEasyAuth.ps1 -CloseIngressOnly -App $App -ResourceGroup $ResourceGroup -SubscriptionId $SubscriptionId -TenantId <tenant>.")
    }
    Note ("ingress CLOSED: access restriction '$((Get-PimManagerGateRuleSpec).name)' " + $(if ($g.changed) { 'applied and read back' } else { 'already in place' }) +
          " -- nobody can reach the Manager until this script has put Easy Auth in front of it and opened it.")
    $result.ok = $true; Write-ResultFile
    return
}

Write-Host "`n=== PIM Manager Easy Auth ($App) ===" -ForegroundColor Cyan

# ---- 1. the app's public address -------------------------------------------------------------
Step 'resolve the ingress FQDN'
$caApp = Get-PimArmAcaApp -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $App -ErrorAsNull
$fqdn = "$($caApp.properties.configuration.ingress.fqdn)".Trim()
if (-not "$fqdn".Trim()) {
    $result.reason = "no ingress FQDN on $App -- is ingress enabled?"
    Write-ResultFile; throw "Set-PimManagerEasyAuth: $($result.reason)"
}
$fqdn = "$fqdn".Trim(); $result.fqdn = $fqdn
$reply = "https://$fqdn/.auth/login/aad/callback"
# 🪤 AN APP ON INTERNAL INGRESS HAS AN '.internal.' FQDN, and the address people use once it is
# exposed is the SAME name without that label (Rebuild-PimEnvExternal attaches Easy Auth BEFORE it
# flips the ingress to external). Register both, or the first sign-in after the flip dies on a
# redirect-URI mismatch that names the app, not the setting.
$wantReplies = @($reply)
if ($fqdn -match '\.internal\.') { $wantReplies += "https://$($fqdn -replace '\.internal\.', '.')/.auth/login/aad/callback" }
Note "fqdn:   $fqdn"
Note "reply:  $reply"

# ---- 2. the app registration -----------------------------------------------------------------
# Microsoft Graph (v1.0), through PIM-Rest's token -- the tenant is the one PIM-Rest was pointed at above.
$appId = "$ClientId".Trim()
# Graph reads that the az path made with `2>$null` (any failure = "not there"): the first appId of a lookup, or ''.
function Get-PimEaFirstAppId([string]$IdentifierUri, [string]$DisplayName) {
    try {
        $hits = if ("$IdentifierUri".Trim()) { @(Find-PimGraphApplications -IdentifierUri $IdentifierUri) } else { @(Find-PimGraphApplications -DisplayName $DisplayName) }
        return "$(@($hits | ForEach-Object { "$($_.appId)".Trim() } | Where-Object { $_ }) | Select-Object -First 1)".Trim()
    } catch { return '' }
}
# A Graph application PATCH whose failure the read-back below judges (the az path ran these with `2>$null`).
function Update-PimEaApp([hashtable]$Properties) {
    try { Update-PimGraphApplication -Id $appId -Properties $Properties; return $true }
    catch { Write-Verbose "application update refused: $($_.Exception.Message)"; return $false }
}
# SEC-44: decided BEFORE anything is created or changed. An existing application that is already
# assignment-required keeps its restriction; anything else needs the caller's explicit choice.
$script:PimEaAccess = $null
function Assert-PimEaAccessChoice([string]$ExistingAppId) {
    $already = $false
    if ("$ExistingAppId".Trim()) {
        $sp0 = Get-PimGraphServicePrincipal -Id $ExistingAppId -ErrorAsNull
        $req = "$($sp0.appRoleAssignmentRequired)".Trim()
        $already = ($req -match '(?i)^true$')
    }
    $script:PimEaAccess = Get-PimEasyAuthAccessDecision -AllowedPrincipals $AllowedPrincipals -AllowAllTenantUsers:$AllowAllTenantUsers -AlreadyRestricted:$already
    if (-not $script:PimEaAccess.ok) {
        $result.reason = $script:PimEaAccess.reason
        Write-ResultFile
        throw "Set-PimManagerEasyAuth: REFUSED (nothing was changed) -- $($script:PimEaAccess.reason)"
    }
    Note "who may sign in: $($script:PimEaAccess.reason)"
}
if ($appId) { Assert-PimEaAccessChoice -ExistingAppId $appId }
if (-not $appId) {
    # 🔴 IDENTITY MUST NOT BE KEYED ON A DISPLAY NAME.
    # This looked the app up by `--display-name` alone. A display name is MUTABLE and not unique:
    # rename it -- in the portal, or by us between versions -- and the lookup finds nothing, so the
    # next deploy CREATES A SECOND registration and orphans the first, with its reply URLs and any
    # consented permissions still attached.
    # 🪤 PROVEN IN TWO TENANTS, 2026-09-10. A customer carried both 'PIM4EntraPS Manager' (orphan,
    # no credential) and 'PIM4EntraPS-Manager' (live); and rebuilding our own environment orphaned
    # 'PIM-Manager-Hosted' (June) by creating 'PIM4EntraPS-Manager'. At a thousand customers that is
    # a thousand stale registrations nobody will ever clean up.
    # 🔑 So key on a STABLE IDENTIFIER URI, which is unique per tenant and survives any rename. The
    # display-name lookup is kept as a FALLBACK purely to ADOPT installs that predate this -- and
    # adoption then stamps the stable uri on, so each environment migrates itself exactly once.
    Step "find or create the app registration (stable id: $StableIdentifierUri)"
    $appId = Get-PimEaFirstAppId -IdentifierUri $StableIdentifierUri
    if ("$appId".Trim()) {
        $appId = "$appId".Trim()
        Note "reusing registration $appId (matched on the stable identifier uri)"
    } else {
        # Current name first, then every name this app has ever shipped under. A tenant deployed
        # last month carries the old one; without searching for it, the rename creates a duplicate
        # instead of adopting -- the exact defect this whole block exists to end.
        # CR5 item 5: each name in BOTH forms ('PIM4EntraPS Manager' / 'PIM Manager') -- the update may have renamed it
        $eaNames = New-Object System.Collections.Generic.List[string]
        foreach ($nm0 in @(@($AppDisplayName) + @($LegacyDisplayNames))) { foreach ($f in @(Get-PimDisplayNameForms "$nm0")) { if (-not $eaNames.Contains($f)) { [void]$eaNames.Add($f) } } }
        foreach ($nm in @($eaNames.ToArray())) {
            if (-not "$nm".Trim()) { continue }
            $appId = Get-PimEaFirstAppId -DisplayName "$nm"
            if ("$appId".Trim()) {
                $appId = "$appId".Trim()
                Note "adopting existing registration $appId (found as '$nm') -- stamping the stable identifier uri so this cannot recur"
                break
            }
        }
    }
    Assert-PimEaAccessChoice -ExistingAppId $appId
    if ("$appId".Trim()) {
        # no-op: resolved above
    } elseif ($PSCmdlet.ShouldProcess($AppDisplayName, 'create the Easy Auth app registration')) {
        $appId = ''
        try {
            $newApp = New-PimGraphApplication -Body @{ displayName = $AppDisplayName
                                                       web = @{ redirectUris = @($reply); implicitGrantSettings = @{ enableIdTokenIssuance = $true; enableAccessTokenIssuance = $false } } }
            $appId = "$($newApp.appId)".Trim()
        } catch { Write-Host "    Graph refused the create: $($_.Exception.Message)" -ForegroundColor DarkYellow; Test-PimEaGraphRefusal "$($_.Exception.Message)" }
        if (-not "$appId".Trim()) {
            $result.reason = 'could not create the app registration (does the signed-in identity hold Application.ReadWrite or Application Administrator?)'
            Write-ResultFile; throw "Set-PimManagerEasyAuth: $($result.reason)"
        }
        $appId = "$appId".Trim(); $result.created = $true
        Note "created registration $appId"
        # 🔴 A JUST-CREATED APP REGISTRATION IS NOT IMMEDIATELY READABLE. Graph is eventually
        # consistent: `az ad app create` returns the appId and the very next `az ad app show/update`
        # answers
        #     Resource '<appId>' does not exist or one of its queried reference-property objects
        #     are not present.
        # Measured at a live customer 2026-09-08 -- the create succeeded and the three calls after
        # it all failed, so the registration existed with no reply URL, no identifier URI and no
        # service principal. Exactly the BUG-44 shape (a new managed identity's SP is not visible
        # either), and this script shipped without the lesson that file already learned.
        # Capped backoff, and NOT fatal on its own: the caller decides what a still-invisible
        # registration means, and the steps below report their own failures.
        foreach ($wait in @(2, 4, 8, 16, 30, 30)) {
            $seen = "$((Get-PimGraphApplication -Id $appId -ErrorAsNull).appId)".Trim()
            if ("$seen".Trim()) { Note "registration is readable after the create"; break }
            Note "  waiting ${wait}s for the registration to replicate..."
            Start-Sleep -Seconds $wait
        }
    } else { Note 'WhatIf: would create the app registration'; $result.ok = $true; Write-ResultFile; return }
} else {
    Step "using the supplied app registration $appId"
}
$result.clientId = $appId

# ---- 3. reply URL + identifier URI + id tokens -------------------------------------------------
# Re-applied every run rather than checked-then-set: the FQDN changes if the environment is rebuilt,
# and a stale reply URL fails at sign-in with an error that names the app, not the setting.
if ($PSCmdlet.ShouldProcess($appId, 'ensure reply URL, identifier URI and ID-token issuance')) {
    Step 'ensure the reply URL, api:// identifier and ID-token issuance'
    # Retried and READ BACK, for the replication reason above: on the first live run these three
    # calls all failed seconds after a successful create, leaving a registration with no reply URL,
    # no identifier and no service principal -- and the step carried on to the next thing.
    $replyOk = $false
    foreach ($wait in @(0, 3, 6, 12, 20, 30)) {
        if ($wait) { Start-Sleep -Seconds $wait }
        $existingReplies = @(@((Get-PimGraphApplication -Id $appId -ErrorAsNull).web.redirectUris) | Where-Object { "$_".Trim() })
        $replies = @(@($existingReplies) + @($wantReplies) | Sort-Object -Unique)
        [void](Update-PimEaApp @{ web = @{ redirectUris = @($replies); implicitGrantSettings = @{ enableIdTokenIssuance = $true; enableAccessTokenIssuance = $false } } })
        $nowReplies = @(@((Get-PimGraphApplication -Id $appId -ErrorAsNull).web.redirectUris) | Where-Object { "$_".Trim() })
        if (-not @($wantReplies | Where-Object { $nowReplies -notcontains $_ }).Count) { $replyOk = $true; break }
    }
    if ($replyOk) { Note 'reply URL present' }
    else { Warn 'could not confirm the reply URL -- sign-in will fail with a redirect-URI mismatch.' }
    # The gate mints `az account get-access-token --resource api://<appId>`, which requires the app
    # to actually claim that identifier. Without it the token request fails and the live-HTTP layer
    # self-skips -- which a release gate scores as a failure.
    # 🔑 BOTH URIS, ALWAYS. api://<appId> is what the release gate mints a token against; the
    # STABLE one is what the next deploy finds this app by. Setting both is what makes the
    # duplicate-registration defect a one-time migration rather than a permanent condition: an
    # install adopted by name today is found by uri forever after.
    # 🪤 --identifier-uris REPLACES the list, so pass them together. Setting one then the other
    # leaves only the second, and the app silently loses the identity the other half depends on.
    # Bring an adopted app onto the current name, so a tenant does not keep whatever it was called
    # when it was first deployed. Safe now, and only now: identity is the stable uri, so the name
    # is a label rather than a key. Best-effort -- a failed rename is cosmetic, not functional.
    $curName = "$((Get-PimGraphApplication -Id $appId -ErrorAsNull).displayName)".Trim()
    # CR5 item 5: an app the update already renamed to "PIM Manager" is never renamed BACK by a run that still asks for the
    # earlier name -- the newer form is kept.
    if ($curName -and (Test-PimDisplayNameIsNewerForm -Current $curName -Wanted $AppDisplayName)) { Note "display name '$curName' kept (the current form of '$AppDisplayName')" }
    elseif ($curName -and $curName -ne $AppDisplayName) {
        [void](Update-PimEaApp @{ displayName = $AppDisplayName })
        $nowName = "$((Get-PimGraphApplication -Id $appId -ErrorAsNull).displayName)".Trim()
        if ($nowName -eq $AppDisplayName) { Note "renamed '$curName' -> '$AppDisplayName' (consistent with the sibling registrations)" }
        else { Warn "could not rename '$curName' to '$AppDisplayName' -- cosmetic only; identity is the stable uri." }
    }

    $wantIds = @("api://$appId", $StableIdentifierUri) | Sort-Object -Unique
    $idOk = $false
    foreach ($wait in @(0, 3, 6, 12, 20, 30)) {
        if ($wait) { Start-Sleep -Seconds $wait }
        $ids = @(@((Get-PimGraphApplication -Id $appId -ErrorAsNull).identifierUris) | Where-Object { "$_".Trim() })
        if ((@($ids) -contains "api://$appId") -and (@($ids) -contains $StableIdentifierUri)) { $idOk = $true; break }
        # Keep anything the tenant already had -- another product may have added one, and replacing
        # the list would take it away.
        $merged = @(@($ids) + @($wantIds) | Where-Object { "$_".Trim() } | Sort-Object -Unique)
        [void](Update-PimEaApp @{ identifierUris = @($merged) })   # identifierUris REPLACES the list: pass the merged set
    }
    if ($idOk) { Note "identifiers present: api://$appId + $StableIdentifierUri" }
    else { Warn "could not set both identifier URIs -- the gate may not mint a token, and the next deploy may not FIND this app and could create a duplicate." }
    # AUTH-MODERN-1 (owner 2026-11-15 "use only modern and secure method"): the registration EXPOSES the delegated scope
    # api://<id>/user_impersonation that the sign-in asks for (the Manager verifies the ACCESS token: scp, aud, tenant, expiry),
    # and the Azure CLI is pre-authorised for it so a script can use `az account get-access-token --resource api://<id>` / MSAL.
    # Idempotent (existing URIs, scopes and pre-authorisations are kept), READ BACK. No secret, no password credential.
    $scPlan = Get-PimBuiltinAuthApiScopePlan -AppReg (Get-PimGraphApplication -Id $appId -ErrorAsNull) -NewScopeId ([guid]::NewGuid().ToString())
    if (@($scPlan.steps).Count) {
        if ($scPlan.patchScopes) { [void](Update-PimEaApp ([hashtable]$scPlan.patchScopes)) }
        $scOk = $false
        foreach ($wait in @(0, 3, 6, 12, 20, 30)) {
            if ($wait) { Start-Sleep -Seconds $wait }
            $regNow = Get-PimGraphApplication -Id $appId -ErrorAsNull
            if (-not (Test-PimBuiltinAuthApiScopeExposed -AppReg $regNow)) { continue }
            # a scope must exist before it is pre-authorised (Graph refuses the pre-authorisation of an unknown scope id)
            $pp = Get-PimBuiltinAuthApiScopePlan -AppReg $regNow -NewScopeId $scPlan.scopeId
            if ($pp.patchPreAuth) { [void](Update-PimEaApp ([hashtable]$pp.patchPreAuth)); continue }
            $scOk = $true; break
        }
        if ($scOk) { Note "API scope api://$appId/$($script:PimBa.apiScope) exposed; the Azure CLI is pre-authorised for it (read back)" }
        else { Warn "could not confirm the API scope api://$appId/$($script:PimBa.apiScope) (or the Azure CLI pre-authorisation) -- the sign-in then falls back to the ID token until this step is run again." }
    } else { Note "API scope api://$appId/$($script:PimBa.apiScope) already exposed (Azure CLI pre-authorised)" }
    # A registration with no service principal in this tenant cannot be signed in to at all.
    # Same replication story as the create above: a service principal is not visible the instant it
    # is made, and `az ad sp create` on a registration Graph has not caught up with fails outright.
    # Retried, then VERIFIED -- "the command exited 0" is not the same as "the object is there".
    $spOid = "$((Get-PimGraphServicePrincipal -Id $appId -ErrorAsNull).id)".Trim()
    if (-not "$spOid".Trim()) {
        Note 'creating the service principal for the registration'
        foreach ($wait in @(0, 3, 6, 12, 20, 30)) {
            if ($wait) { Start-Sleep -Seconds $wait }
            try { [void](New-PimGraphServicePrincipal -AppId $appId) } catch { Write-Verbose "service principal create refused: $($_.Exception.Message)" }
            $spOid = "$((Get-PimGraphServicePrincipal -Id $appId -ErrorAsNull).id)".Trim()
            if ("$spOid".Trim()) { break }
        }
        if ("$spOid".Trim()) { Note "service principal $spOid" }
        else { Warn 'could not create the service principal -- sign-in will fail until it exists.' }
    }
}

# ---- 4. NO CLIENT SECRET: web identity + federated credential + token store (BUILT-IN-AUTH-1) ----------------
# Owner 2026-11-14 (proven on every install that night): the sign-in app registration trusts the Manager's web identity
# id-pim-web by a FEDERATED CREDENTIAL, and the platform signs in with it -- there is no client secret to mint, store, rotate
# or leak. The platform finds the identity through ONE container-app setting, 'override-use-mi-fic-assertion-client-id', which
# holds the identity's CLIENT id (an identifier, not a secret). The token store (the signed ID token the Manager verifies) is a
# blob container in the install's own storage account, reached as id-pim-web, with shared-key access off. Each part is
# idempotent and READ BACK; setup may grant the one role this needs (the updater never does).
$script:PimEaWeb = $null; $script:PimEaBlobUri = ''
if ($RotateSecret -or $PSBoundParameters.ContainsKey('SecretYears')) { Note "-RotateSecret / -SecretYears $SecretYears ignored: there is no client secret any more (the sign-in uses a federated credential) -- nothing to mint or rotate" }
if ($PSCmdlet.ShouldProcess($App, 'secretless sign-in: web identity, federated credential, token store')) {
    $rgPath = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup"
    $appPath = "$rgPath/providers/Microsoft.App/containerApps/$App"
    # ---- 4a. the web identity id-pim-web on the Manager (made + attached only when it has none)
    Step "the web identity $($script:PimBa.webIdentityName) on the Manager (the federated credential's subject)"
    $caNow = Get-PimArmAcaApp -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $App
    $wi = Get-PimBuiltinAuthWebIdentity -App $caNow -Name $script:PimBa.webIdentityName
    if (-not $wi.ok) {
        $uamiId = "$rgPath/providers/Microsoft.ManagedIdentity/userAssignedIdentities/$($script:PimBa.webIdentityName)"
        $u = Invoke-PimSetupArm -Path $uamiId -ApiVersion (Get-PimSetupApiVersion msi) -NotFoundOk -ErrorAsNull
        if (-not $u) {
            try { $u = Invoke-PimSetupArm -Method PUT -Path $uamiId -ApiVersion (Get-PimSetupApiVersion msi) -Body @{ location = "$($caNow.location)"; tags = @{ 'pim-component' = 'web' } } }
            catch { $result.reason = "could not create the web identity $($script:PimBa.webIdentityName): $($_.Exception.Message)"; Write-ResultFile; throw "Set-PimManagerEasyAuth: $($result.reason)" }
            Note "created $($script:PimBa.webIdentityName)"
        }
        $idBody = New-PimBuiltinAuthIdentityBody -App $caNow -AddId "$($u.id)"
        if ($idBody) {
            try { [void](Invoke-PimEaBusyRetry -Write { Invoke-PimSetupArm -Method PATCH -Path $appPath -ApiVersion (Get-PimSetupApiVersion aca) -Body @{ identity = $idBody } }) }
            catch { $result.reason = "could not attach $($script:PimBa.webIdentityName) to ${App}: $($_.Exception.Message)"; Write-ResultFile; throw "Set-PimManagerEasyAuth: $($result.reason)" }
            [void](Wait-PimArmProvisioned -Path $appPath -ApiVersion (Get-PimSetupApiVersion aca) -TimeoutSeconds 600)
        }
        $caNow = Get-PimArmAcaApp -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $App
        $wi = Get-PimBuiltinAuthWebIdentity -App $caNow -Name $script:PimBa.webIdentityName
        if (-not $wi.ok -or -not "$($wi.principalId)".Trim() -or -not "$($wi.clientId)".Trim()) {
            $result.reason = "read-back: $($script:PimBa.webIdentityName) is not attached to $App ($($wi.reason))"; Write-ResultFile; throw "Set-PimManagerEasyAuth: $($result.reason)"
        }
        Note "attached $($script:PimBa.webIdentityName) to $App (read back) -- it is ONLY the sign-in identity here; what the Manager itself signs in as is unchanged"
    } else { Note "$($script:PimBa.webIdentityName) is attached ($($wi.clientId))" }
    $script:PimEaWeb = $wi

    # ---- 4b. the federated credential: the registration trusts id-pim-web (issuer = this tenant, v2)
    Step 'federated credential on the app registration (no client secret)'
    $regObj = Get-PimGraphApplication -Id $appId -ErrorAsNull
    $regOid = "$($regObj.id)".Trim()
    if (-not $regOid) { $result.reason = "the app registration $appId could not be read"; Write-ResultFile; throw "Set-PimManagerEasyAuth: $($result.reason)" }
    $readFics = { @(@((Invoke-PimSetupGraph -Path "https://graph.microsoft.com/v1.0/applications/$regOid/federatedIdentityCredentials" -ErrorAsNull).value) | Where-Object { $_ }) }
    $ficOk = Test-PimBuiltinAuthFicPresent -Fics @(& $readFics) -PrincipalId $wi.principalId -TenantId $TenantId
    if (-not $ficOk) {
        $ficBody = Get-PimBuiltinAuthFicBody -TenantId $TenantId -PrincipalId $wi.principalId -Name $script:PimBa.ficName
        try { [void](Invoke-PimSetupGraph -Method POST -Path "https://graph.microsoft.com/v1.0/applications/$regOid/federatedIdentityCredentials" -Body $ficBody) }
        catch { Write-Host "    Graph refused the federated credential: $($_.Exception.Message)" -ForegroundColor DarkYellow; Test-PimEaGraphRefusal "$($_.Exception.Message)" }
        foreach ($wait in @(0, 3, 6, 12, 20, 30)) {
            if ($wait) { Start-Sleep -Seconds $wait }
            if (Test-PimBuiltinAuthFicPresent -Fics @(& $readFics) -PrincipalId $wi.principalId -TenantId $TenantId) { $ficOk = $true; break }
        }
        if (-not $ficOk) { $result.reason = 'the federated credential for the web identity did not read back on the app registration'; Write-ResultFile; throw "Set-PimManagerEasyAuth: $($result.reason)" }
        Note "federated credential '$($script:PimBa.ficName)' added (subject $($wi.principalId), read back)"
    } else { Note 'the app registration already trusts the web identity (federated credential present)' }

    # ---- 4c. the token store: the blob container + the ONE role, on that container only
    Step "token store: blob container '$($script:PimBa.tokenContainer)' (managed identity; shared-key access off)"
    $saList = @(Invoke-PimSetupArm -Path "$rgPath/providers/Microsoft.Storage/storageAccounts" -ApiVersion (Get-PimSetupApiVersion storage) -All -ErrorAsNull | Where-Object { $_ })
    if ("$TokenStoreAccount".Trim()) { $saList = @($saList | Where-Object { "$($_.name)" -ieq "$TokenStoreAccount".Trim() }) }
    $saDefault = $(if ("$TokenStoreAccount".Trim()) { "$TokenStoreAccount".Trim().ToLowerInvariant() } else { Get-PimBuiltinAuthDefaultStorageName -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup })
    $saPick = Select-PimBuiltinAuthStorageAccount -Accounts $saList -DefaultName $saDefault
    if (-not $saPick.ok) { $result.reason = $saPick.reason; Write-ResultFile; throw "Set-PimManagerEasyAuth: $($result.reason)" }
    if ($saPick.create) {
        Note $saPick.reason
        try {
            [void](New-PimArmStorageAccount -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $saPick.name -Location "$($caNow.location)" -Sku Standard_LRS -Kind StorageV2 -AllowBlobPublicAccess $false)
            [void](Update-PimArmStorageAccount -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $saPick.name -Properties @{ allowSharedKeyAccess = $false })
        } catch { $result.reason = "could not create the storage account $($saPick.name): $($_.Exception.Message)"; Write-ResultFile; throw "Set-PimManagerEasyAuth: $($result.reason)" }
    }
    $sa = Get-PimArmStorageAccount -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $saPick.name -ErrorAsNull
    if (-not $sa -or "$($sa.properties.allowSharedKeyAccess)" -notmatch '^(?i)false$') { $result.reason = "read-back: the storage account $($saPick.name) does not have shared-key access OFF"; Write-ResultFile; throw "Set-PimManagerEasyAuth: $($result.reason)" }
    $cScope = "$($sa.id)/blobServices/default/containers/$($script:PimBa.tokenContainer)"
    try { [void](Invoke-PimSetupArm -Method PUT -Path $cScope -ApiVersion (Get-PimSetupApiVersion storage) -Body @{ properties = @{ publicAccess = 'None' } }) }
    catch { if (-not (Invoke-PimSetupArm -Path $cScope -ApiVersion (Get-PimSetupApiVersion storage) -NotFoundOk -ErrorAsNull)) { $result.reason = "could not create the blob container $($script:PimBa.tokenContainer): $($_.Exception.Message)"; Write-ResultFile; throw "Set-PimManagerEasyAuth: $($result.reason)" } }
    $rdId = "/subscriptions/$SubscriptionId/providers/Microsoft.Authorization/roleDefinitions/$($script:PimBa.blobDataContributor)"
    $readRa = { @(@((Invoke-PimSetupArm -Path "$cScope/providers/Microsoft.Authorization/roleAssignments?`$filter=atScope()" -ApiVersion (Get-PimSetupApiVersion authorization) -ErrorAsNull).value) |
                  Where-Object { $_ -and "$($_.properties.principalId)" -eq "$($wi.principalId)" -and "$($_.properties.roleDefinitionId)" -like "*$($script:PimBa.blobDataContributor)" -and "$($_.properties.scope)" -ieq $cScope }) }
    if (-not @(& $readRa).Count) {
        $raName = Get-PimBuiltinAuthRoleAssignmentName -Scope $cScope -PrincipalId $wi.principalId -RoleDefinitionId $script:PimBa.blobDataContributor
        $raBody = @{ properties = @{ roleDefinitionId = $rdId; principalId = "$($wi.principalId)"; principalType = 'ServicePrincipal' } }
        $raOk = $false
        foreach ($wait in @(0, 10, 20, 30, 60)) {
            if ($wait) { Start-Sleep -Seconds $wait }
            try { [void](Invoke-PimSetupArm -Method PUT -Path "$cScope/providers/Microsoft.Authorization/roleAssignments/$raName" -ApiVersion (Get-PimSetupApiVersion authorization) -Body $raBody) } catch { Write-Verbose "role assignment: $($_.Exception.Message)" }
            if (@(& $readRa).Count) { $raOk = $true; break }
        }
        if (-not $raOk) { $result.reason = "Storage Blob Data Contributor for $($script:PimBa.webIdentityName) on the container $($script:PimBa.tokenContainer) did not read back (setup needs Owner or User Access Administrator there)"; Write-ResultFile; throw "Set-PimManagerEasyAuth: $($result.reason)" }
        Note "Storage Blob Data Contributor for $($script:PimBa.webIdentityName) on the container $($script:PimBa.tokenContainer) ONLY (read back)"
    } else { Note "$($script:PimBa.webIdentityName) already holds Storage Blob Data Contributor on the container $($script:PimBa.tokenContainer)" }
    $script:PimEaBlobUri = "$($sa.properties.primaryEndpoints.blob)".TrimEnd('/') + "/$($script:PimBa.tokenContainer)"

    # ---- 4d. the ONE container-app setting the platform reads: the web identity's CLIENT id (an identifier, not a secret)
    Step "container-app setting '$($script:PimBa.secretName)' = the web identity's client id"
    $haveSet = @(@($caNow.properties.configuration.secrets) | Where-Object { $_ -and "$($_.name)" -eq $script:PimBa.secretName })
    $setOk = $false
    if ($haveSet.Count) {
        $cur = @(@(Get-PimArmAcaAppSecrets -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $App) | Where-Object { "$($_.name)" -eq $script:PimBa.secretName })[0]
        $setOk = ("$($cur.value)".Trim() -eq "$($wi.clientId)".Trim())
    }
    if (-not $setOk) {
        $webClient = "$($wi.clientId)".Trim()
        try { [void](Invoke-PimEaBusyRetry -Write { Set-PimArmAcaAppSecret -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $App -SecretName $script:PimBa.secretName -Value $webClient }) }
        catch { $result.reason = "could not set '$($script:PimBa.secretName)' on ${App}: $($_.Exception.Message)"; Write-ResultFile; throw "Set-PimManagerEasyAuth: $($result.reason)" }
        [void](Wait-PimArmProvisioned -Path $appPath -ApiVersion (Get-PimSetupApiVersion aca) -TimeoutSeconds 600)
        $cur = @(@(Get-PimArmAcaAppSecrets -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $App) | Where-Object { "$($_.name)" -eq $script:PimBa.secretName })[0]
        if ("$($cur.value)".Trim() -ne $webClient) { $result.reason = "read-back: '$($script:PimBa.secretName)' does not hold the web identity's client id"; Write-ResultFile; throw "Set-PimManagerEasyAuth: $($result.reason)" }
        Note 'set and read back'
    } else { Note 'already set to the web identity''s client id' }
}

# ---- 4b. THE DELEGATED PERMISSION THE LOGIN FLOW NEEDS ------------------------------------------
# 🔴 §52.17. Easy Auth was configured, verified, and reported success -- and no human could sign
# in. Every browser login died at /.auth/login/aad/callback with HTTP 401, while the release gate
# stayed green. The middleware log named it:
#
#   AADSTS650056: Misconfigured application ... the client has not listed any permissions for
#   'AAD Graph' in the requested permissions in the client's application registration.
#
# TWO causes, and the first one is ours:
#  1. This script configured the V1 issuer (https://sts.windows.net/<tid>/). On a v1 issuer Easy
#     Auth's login flow asks for a token against the LEGACY AZURE AD GRAPH resource -- which is
#     RETIRED. A registration in a new tenant cannot hold permissions to it, so the flow can never
#     succeed. It survived this long because the environments built earlier had registrations from
#     before that retirement. Now the v2 issuer, which uses openid/profile/email and never touches
#     AAD Graph.
#  2. The registration carried NO delegated permission at all. A registration with an empty
#     requiredResourceAccess is exactly what 650056 describes, so ensure Microsoft Graph
#     User.Read (delegated) and consent to it -- on the REUSE path as well as on create, because
#     a reused registration is the case that actually failed.
# 🪤 And the reason nobody caught it: the release gate mints an EDGE TOKEN with
# `az account get-access-token`, which performs no interactive login. The gate and the human use
# DIFFERENT PATHS, so 11/0 was true and unusable at the same time -- the same shape as the content
# hash being read from a place nothing writes.
# 🔴 BUG-169 (2026-09-18) -- AND THEN NOBODY COULD SIGN IN ANYWAY: "Need admin approval".
# Measured on both test tenants: the Manager registration had NO consent grant at all, and those tenants
# do not let users consent for themselves. Three defects, all in this block:
#  1. it consented User.Read ONLY, while the v2 sign-in requests openid/profile/email too;
#  2. the deploy identity was never given DelegatedPermissionGrant.ReadWrite.All, the one role the
#     Graph grant needs (now in _PimDeployGraph.ps1), so the grant was refused;
#  3. the refusal was a yellow WARNING followed by `exit 0` -- the build reported success over a
#     Manager no human could open, and nothing read the grant back.
# Now: list every scope, create-or-PATCH the tenant-wide grant to the union, READ IT BACK, and if it
# is still missing, finish configuring Easy Auth (the console stays protected) and then FAIL the run.
$consentOk = $true; $consentWhy = ''
if (-not $WhatIfPreference -and "$appId".Trim()) {
    $scopeIds = Get-PimEasyAuthConsentScopes
    Step "ensure the sign-in permissions (Microsoft Graph, delegated: $(@($scopeIds.Keys) -join ' '))"
    $graphAppId = '00000003-0000-0000-c000-000000000000'
    # LIST them on the registration too: the portal's "Grant admin consent" consents what is listed,
    # so a human fallback then covers every scope instead of User.Read alone.
    $listed = @()
    # The registration's requiredResourceAccess (what `permission list` printed).
    $rraNow = @(@((Get-PimGraphApplication -Id $appId -ErrorAsNull).requiredResourceAccess) | Where-Object { $_ })
    $listed = @($rraNow | Where-Object { "$($_.resourceAppId)" -eq $graphAppId } |
                ForEach-Object { @($_.resourceAccess) } | Where-Object { $_ } | ForEach-Object { "$($_.id)".ToLowerInvariant() })
    $toList = @($scopeIds.Keys | Where-Object { $listed -notcontains $scopeIds[$_].ToLowerInvariant() })
    if ($toList.Count) {
        $apiPerms = @($toList | ForEach-Object { "$($scopeIds[$_])=Scope" })
        # `permission add` = the whole requiredResourceAccess written back with the Graph entry widened: every other API's
        # entry and every permission already listed stay (requiredResourceAccess REPLACES the list on a PATCH).
        $graphAccess = @(@($rraNow | Where-Object { "$($_.resourceAppId)" -eq $graphAppId } | ForEach-Object { @($_.resourceAccess) }) | Where-Object { $_ } |
                         ForEach-Object { @{ id = "$($_.id)"; type = "$($_.type)" } })
        $graphAccess += @($apiPerms | ForEach-Object { $pp = "$_" -split '='; @{ id = $pp[0]; type = $pp[1] } })
        $newRra = @($rraNow | Where-Object { "$($_.resourceAppId)" -ne $graphAppId } | ForEach-Object {
                        @{ resourceAppId = "$($_.resourceAppId)"; resourceAccess = @(@($_.resourceAccess) | Where-Object { $_ } | ForEach-Object { @{ id = "$($_.id)"; type = "$($_.type)" } }) } })
        $newRra += @{ resourceAppId = $graphAppId; resourceAccess = @($graphAccess) }
        [void](Update-PimEaApp @{ requiredResourceAccess = @($newRra) })
        Note "listed on the registration: $($toList -join ', ')"
    } else { Note 'every sign-in scope is already listed on the registration' }

    # CONSENT, as a tenant-wide oauth2PermissionGrant through Microsoft Graph.
    # 🔴 BUG-161 -- `az ad app permission admin-consent` only works with a USER token; under a
    # certificate SPN (every scripted deploy) it is refused with S2S17001 'UnsupportedAccessTokenType'.
    # The Graph grant works for both, so it goes FIRST and admin-consent is only the user-token fallback.
    $clientSp = "$((Get-PimGraphServicePrincipal -Id $appId -ErrorAsNull).id)".Trim()
    $graphSp  = "$((Get-PimGraphServicePrincipal -Id $graphAppId -ErrorAsNull).id)".Trim()
    function Read-PimEaConsentGrant {
        # Every grant this client holds, filtered here (no $filter in the URL -- one call shape, nothing to encode).
        # 🪤 "could NOT read" is not "absent" (BUG-166's lesson): an unreadable answer returns ok=$false and is never
        # planned as a create.
        $r = Invoke-PimSetupGraph -Path "https://graph.microsoft.com/v1.0/servicePrincipals/$clientSp/oauth2PermissionGrants" -ErrorAsNull
        if ($null -eq $r) { return @{ ok = $false; grant = $null } }
        $v = @(@($r.value) | Where-Object { $_ })
        return @{ ok = $true; grant = (@($v | Where-Object { $_.consentType -eq 'AllPrincipals' -and $_.resourceId -eq $graphSp }) | Select-Object -First 1) }
    }
    function Wait-PimEaConsent {
        # READ BACK with backoff -- measured 2026-09-18: a grant POSTed a moment earlier read back
        # EMPTY, and complete a few seconds later. Eventually consistent, like every Graph write here.
        $delay = 2
        for ($attempt = 1; $attempt -le 6; $attempt++) {
            $rb = Read-PimEaConsentGrant
            if ($rb.ok -and (Get-PimEasyAuthConsentPlan -ExistingScope "$($rb.grant.scope)" -GrantExists:([bool]$rb.grant)).Action -eq 'none') {
                return "$($rb.grant.scope)"
            }
            if ($attempt -lt 6) { Start-Sleep -Seconds $delay; $delay = [Math]::Min($delay * 2, 15) }
        }
        return $null
    }
    if (-not $clientSp -or -not $graphSp) {
        $consentWhy = "could not resolve the service principals (Manager '$clientSp', Microsoft Graph '$graphSp')"
    } else {
        $rd = Read-PimEaConsentGrant
        if (-not $rd.ok) {
            $consentWhy = "could not READ the existing consent grants, so refusing to guess: $("$($global:PimSetupRestLastError)".Trim())"
        } else {
            $plan = Get-PimEasyAuthConsentPlan -ExistingScope "$($rd.grant.scope)" -GrantExists:([bool]$rd.grant)
            if ($plan.Action -eq 'none') {
                Note "consent already in place (tenant-wide): $($rd.grant.scope)"
            } else {
                if ($plan.Action -eq 'create') {
                    $method = 'POST'; $uri = 'https://graph.microsoft.com/v1.0/oauth2PermissionGrants'
                    $body = @{ clientId = $clientSp; consentType = 'AllPrincipals'; resourceId = $graphSp; scope = $plan.Scope }
                } else {
                    # PATCH to the UNION -- never narrow a grant someone else widened.
                    $method = 'PATCH'; $uri = "https://graph.microsoft.com/v1.0/oauth2PermissionGrants/$($rd.grant.id)"
                    $body = @{ scope = $plan.Scope }
                }
                # The JSON body goes straight to Graph (REST) -- no temp file, no shell quoting in between.
                try { [void](Invoke-PimSetupGraph -Method $method -Path $uri -Body $body) }
                catch { $consentWhy = "Microsoft Graph refused the consent $method`: $("$($_.Exception.Message)".Trim())"; Test-PimEaGraphRefusal "$($_.Exception.Message)" }
                if (-not $consentWhy) {
                    $got = Wait-PimEaConsent
                    if ($got) { Note "consented (tenant-wide, $($plan.Action)): $got" }
                    else { $consentWhy = "the consent grant was written but never read back with every scope ($($plan.Scope))" }
                }
            }
        }
        # The fallback: admin-consent of everything LISTED on the registration (Grant-PimGraphAdminConsent -- the REST
        # form of `az ad app permission admin-consent`, which works for a user token and an application token alike).
        if ($consentWhy) {
            $acOk = $true
            try { [void](Grant-PimGraphAdminConsent -AppId $appId) } catch { $acOk = $false; Write-Verbose "admin-consent refused: $($_.Exception.Message)" }
            if ($acOk) {
                $got = Wait-PimEaConsent
                if ($got) { Note "consented via admin-consent: $got"; $consentWhy = '' }
            }
        }
    }
    if ($consentWhy) {
        $consentOk = $false
        $result.consent = 'MISSING'
        Write-Warning ("NO HUMAN CAN SIGN IN TO THE MANAGER YET: admin consent for '$AppDisplayName' ($appId) is missing -- $consentWhy. " +
                       "Easy Auth is still configured below so the console stays protected, and this run will FAIL at the end.")
    } else { $result.consent = 'ok' }
    # ID-token issuance, on the REUSE path too -- the create call sets it, and a reused
    # registration never got it (the same create-path-only defect as the permission above).
    # 🪤 The reply URLs travel in the same web object, so they are re-sent as they read now: the ID-token switch must
    # never be the call that takes a reply URL away.
    $webNow = (Get-PimGraphApplication -Id $appId -ErrorAsNull).web
    $webBody = @{ implicitGrantSettings = @{ enableIdTokenIssuance = $true; enableAccessTokenIssuance = $false } }
    if ($webNow -and @($webNow.redirectUris).Count) { $webBody.redirectUris = @($webNow.redirectUris) }
    [void](Update-PimEaApp @{ web = $webBody })
}

# ---- 5. built-in authentication ON, the standard (BUILT-IN-AUTH-1) ------------------------------------------------
# ONE PUT of authConfigs/current with the standard (engine/_shared/PIM-BuiltinAuth.ps1 New-PimBuiltinAuthConfig), api
# 2024-10-02-preview: the token store's managed identity exists only from that version -- an older read-modify-write drops it.
# excludedPaths = EXACTLY the protected-resource metadata documents (Get-PimBuiltinAuthExcludedPaths); anything else is removed.
$authPath = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.App/containerApps/$App/authConfigs/current"
if ($PSCmdlet.ShouldProcess($App, 'put Microsoft built-in authentication on (the standard)')) {
    Step 'built-in authentication ON: RedirectToLoginPage, no client secret, token store, account picker, 8-hour session'
    $authBefore = Invoke-PimSetupArm -Path $authPath -ApiVersion $script:PimBa.authApi -NotFoundOk -ErrorAsNull
    $before = @(@($authBefore.properties.globalValidation.excludedPaths) | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
    # AUTH-MODERN-1 (group ruling 2026-11-15): the ONLY paths the platform lets through unauthenticated are the RFC 9728
    # protected-resource metadata documents (public by definition: they name the sign-in, nothing else). /mcp stays behind
    # the platform (layer 1) AND is validated by the Manager (layer 2) -- an older /mcp exclusion is removed here.
    $keepEx = @(Get-PimBuiltinAuthExcludedPaths)
    $dropped = @($before | Where-Object { $keepEx -notcontains $_ })
    if ($dropped.Count) { Note "excluded paths removed (only the protected-resource metadata stays outside the sign-in): $($dropped -join ', ')" }
    try {
        $authProps = New-PimBuiltinAuthConfig -TenantId $TenantId -ClientId $appId -SecretSettingName $script:PimBa.secretName `
                         -BlobContainerUri $script:PimEaBlobUri -WebIdentityResourceId "$($script:PimEaWeb.resourceId)" -ExcludedPaths $keepEx
        [void](Invoke-PimEaBusyRetry -Write { Invoke-PimSetupArm -Method PUT -Path $authPath -ApiVersion $script:PimBa.authApi -Body @{ properties = $authProps } })
    } catch {
        $result.reason = "turning built-in authentication on failed: $($_.Exception.Message)"
        Write-ResultFile; throw "Set-PimManagerEasyAuth: $($result.reason)"
    }
    Note "excluded paths: $($keepEx -join ', ') (nothing else)"
}

# ---- 6. READ IT BACK ---------------------------------------------------------------------------
# 🔒 A configure step that reports success without reading back is how BUG-37 shipped a workspace
# move that moved nothing, and how the Graph grant loop printed "granted" three times while
# granting nothing. Auth config flips instantly and takes effect a moment later -- precisely the
# shape that fools a writer-only check.
if (-not $WhatIfPreference) {
    Step 'read the configuration back'
    $authNow = (Invoke-PimSetupArm -Path $authPath -ApiVersion $script:PimBa.authApi -NotFoundOk -ErrorAsNull).properties
    $aad = $authNow.identityProviders.azureActiveDirectory
    $aud = @(@($aad.validation.allowedAudiences) | Where-Object { "$_".Trim() })
    $enabled = "$($authNow.platform.enabled)".Trim()
    $iss = "$($aad.registration.openIdIssuer)".Trim()
    $bad = New-Object System.Collections.Generic.List[string]
    if ("$enabled".ToLowerInvariant() -ne 'true') { $bad.Add("platform.enabled reads '$enabled'") }
    if (-not $aud.Count) { $bad.Add('NO allowed audience') }
    elseif ($aud -notcontains "api://$appId" -or $aud -notcontains $appId) { $bad.Add("audiences read '$($aud -join ',')'") }
    # 🔴 §52.17 -- a v1 issuer makes the sign-in flow request the RETIRED Azure AD Graph resource (AADSTS650056)
    if ("$iss" -notmatch '(?i)/v2\.0/?$') { $bad.Add("issuer reads '$iss', which is not the v2 endpoint https://login.microsoftonline.com/$TenantId/v2.0") }
    if ("$($aad.registration.clientSecretSettingName)" -ne $script:PimBa.secretName) { $bad.Add("the credential setting reads '$($aad.registration.clientSecretSettingName)'") }
    if ("$($authNow.login.tokenStore.enabled)" -notmatch '^(?i)true$' -or "$($authNow.login.tokenStore.azureBlobStorage.managedIdentityResourceId)" -notmatch '(?i)/id-pim-web$') { $bad.Add('the token store is not on with id-pim-web') }
    if (@($aad.login.loginParameters) -notcontains 'prompt=select_account') { $bad.Add('the account picker (prompt=select_account) is missing') }
    # AUTH-MODERN-1: the access token for this app's API scope + offline_access (silent renewal), on the PROVIDER's login block
    $lpRb = Test-PimBuiltinAuthLoginParametersStandard -LoginParameters @($aad.login.loginParameters) -ClientId $appId
    foreach ($m in @($lpRb.missing | Where-Object { $_ -ne 'account picker missing' })) { $bad.Add($m) }
    if ("$($authNow.globalValidation.unauthenticatedClientAction)" -ne 'RedirectToLoginPage') { $bad.Add("unauthenticated callers are '$($authNow.globalValidation.unauthenticatedClientAction)'") }
    if ($bad.Count) {
        $result.reason = "built-in authentication did not read back as the standard: $($bad -join '; ')"
        Write-ResultFile; throw "Set-PimManagerEasyAuth: $($result.reason). The Manager was NOT changed further (an opt-in sign-in front, if any, is still in place)."
    }
    Note "verified: enabled=$enabled audiences=$($aud -join ',') issuer=$iss credential=$($script:PimBa.secretName) token store=id-pim-web picker=on"

    # ---- 6b. ONLY NOW the Manager container: verify the signed token itself; the opt-in front out of the template ----------
    # Order (Invardia review 2026-11-14, must-fix): the platform sign-in is ON and read back FIRST; only then is a sign-in
    # front still in the template removed -- never a window where nothing but the Manager's own check stands in front of it.
    Step 'the Manager verifies the signed token itself (PIM_HOSTED_AUTH_LAYER=easyauth, signed token required)'
    $caM = Get-PimArmAcaApp -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $App
    $ctrs = @(@($caM.properties.template.containers) | Where-Object { $_ })
    $mgrC = @($ctrs | Where-Object { "$($_.name)" -eq $App }) | Select-Object -First 1
    if (-not $mgrC) { $mgrC = @($ctrs | Where-Object { "$($_.name)" -ne 'signin-front' }) | Select-Object -First 1 }
    if (-not $mgrC) { $result.reason = "the Manager container of $App could not be found"; Write-ResultFile; throw "Set-PimManagerEasyAuth: $($result.reason)" }
    $port = [int]$caM.properties.configuration.ingress.targetPort
    $want = Get-PimBuiltinAuthManagerEnv -ClientId $appId -TenantId $TenantId -Port $port
    $envNow = @{}; foreach ($e in @($mgrC.env)) { if ($e) { $envNow["$($e.name)"] = $e } }
    $front = @($ctrs | Where-Object { "$($_.name)" -eq 'signin-front' }).Count -gt 0
    $leftover = @($envNow.Keys | Where-Object { $_ -match '^(PIM_SIGNIN_FRONT_|SIGNIN_)' })
    $envDiff = @($want.Keys | Where-Object { -not $envNow.ContainsKey($_) -or "$($envNow[$_].value)" -ne "$($want[$_])" -or "$($envNow[$_].secretRef)".Trim() })
    if ($front -or $envDiff.Count -or $leftover.Count) {
        $env2 = @(@($mgrC.env) | Where-Object { $_ -and "$($_.name)" -notin @($want.Keys) -and "$($_.name)" -notmatch '^(PIM_SIGNIN_FRONT_|SIGNIN_)' })
        foreach ($k in $want.Keys) { $env2 += [pscustomobject]@{ name = $k; value = "$($want[$k])" } }
        $mgrC | Add-Member -NotePropertyName env -NotePropertyValue @($env2) -Force
        if ($mgrC.probes) { foreach ($pr in @($mgrC.probes)) { foreach ($pk in 'httpGet', 'tcpSocket') { if ($pr.$pk -and $pr.$pk.port) { $pr.$pk.port = $port } } } }
        $tpl = $caM.properties.template; $tpl.containers = @($mgrC)
        try { [void](Invoke-PimEaBusyRetry -Write { Invoke-PimSetupArm -Method PATCH -Path "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.App/containerApps/$App" -ApiVersion (Get-PimSetupApiVersion aca) -Body @{ properties = @{ template = $tpl } } }) }
        catch { $result.reason = "could not set the Manager's sign-in settings: $($_.Exception.Message)"; Write-ResultFile; throw "Set-PimManagerEasyAuth: $($result.reason). Built-in authentication IS on and protects the Manager." }
        $st = Wait-PimArmProvisioned -Path "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.App/containerApps/$App" -ApiVersion (Get-PimSetupApiVersion aca) -TimeoutSeconds 600
        $caB = Get-PimArmAcaApp -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $App
        $mB = @(@($caB.properties.template.containers) | Where-Object { $_ -and "$($_.name)" -ne 'signin-front' }) | Select-Object -First 1
        $evB = @{}; foreach ($e in @($mB.env)) { if ($e) { $evB["$($e.name)"] = "$($e.value)" } }
        $missB = @($want.Keys | Where-Object { "$($evB[$_])" -ne "$($want[$_])" })
        if (@($caB.properties.template.containers).Count -ne 1 -or $missB.Count -or "$st" -notmatch '(?i)^Succeeded') {
            $result.reason = "read-back of the Manager after the sign-in settings ($st): $(if ($missB.Count) { "not set: $($missB -join ', ')" } else { "containers $(@($caB.properties.template.containers | ForEach-Object { $_.name }) -join '+')" })"
            Write-ResultFile; throw "Set-PimManagerEasyAuth: $($result.reason). Built-in authentication IS on and protects the Manager."
        }
        Note "set and read back$(if ($front) { '; the opt-in sign-in front container was removed (built-in sign-in is in front now)' })$(if ($leftover.Count) { "; leftover settings removed: $($leftover -join ', ')" })"
    } else { Note 'already set' }

    # ---- 6c. the old Easy Auth client secrets: nothing uses them now -- removed and read back ------------------------
    Step 'remove the old Easy Auth client secrets (nothing uses them any more)'
    $caS = Get-PimArmAcaApp -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $App
    if (@(@($caS.properties.configuration.secrets) | Where-Object { $_ -and "$($_.name)" -eq $SecretName }).Count) {
        try {
            $keep = @(@(Get-PimArmAcaAppSecrets -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $App) | Where-Object { $_ -and "$($_.name)" -ne $SecretName } | ForEach-Object {
                if ("$($_.keyVaultUrl)".Trim()) { @{ name = "$($_.name)"; keyVaultUrl = "$($_.keyVaultUrl)"; identity = "$($_.identity)" } } else { @{ name = "$($_.name)"; value = "$($_.value)" } } })
            if ($keep.Count -lt (@($caS.properties.configuration.secrets).Count - 1)) { throw 'the secret values could not all be read -- refusing a write that would drop secrets' }
            [void](Invoke-PimEaBusyRetry -Write { Invoke-PimSetupArm -Method PATCH -Path "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.App/containerApps/$App" -ApiVersion (Get-PimSetupApiVersion aca) -Body @{ properties = @{ configuration = @{ secrets = @($keep) } } } })
            [void](Wait-PimArmProvisioned -Path "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.App/containerApps/$App" -ApiVersion (Get-PimSetupApiVersion aca) -TimeoutSeconds 600)
            $still = @(@((Get-PimArmAcaApp -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $App).properties.configuration.secrets) | Where-Object { $_ -and "$($_.name)" -eq $SecretName }).Count
            if ($still) { Warn "the container-app secret '$SecretName' still reads back -- a re-run removes it (sign-in is not affected)" } else { Note "container-app secret '$SecretName' removed (read back)" }
        } catch { Warn "the container-app secret '$SecretName' was not removed yet ($($_.Exception.Message)) -- sign-in is not affected; a re-run removes it" }
    }
    $regP = Get-PimGraphApplication -Id $appId -ErrorAsNull
    $cp = Get-PimBuiltinAuthSecretCleanupPlan -PasswordCredentials @($regP.passwordCredentials)
    foreach ($r in @($cp.remove)) {
        try { [void](Invoke-PimSetupGraph -Method POST -Path "https://graph.microsoft.com/v1.0/applications/$($regP.id)/removePassword" -Body @{ keyId = "$($r.keyId)" }) }
        catch { Warn "the client secret '$($r.name)' was not removed yet ($($_.Exception.Message)) -- sign-in is not affected; a re-run removes it" }
    }
    if (@($cp.remove).Count) {
        $left = @()
        foreach ($wait in @(0, 3, 6, 12)) { if ($wait) { Start-Sleep -Seconds $wait }; $left = @((Get-PimBuiltinAuthSecretCleanupPlan -PasswordCredentials @((Get-PimGraphApplication -Id $appId -ErrorAsNull).passwordCredentials)).remove); if (-not $left.Count) { break } }
        if ($left.Count) { Warn "$($left.Count) old Easy Auth client secret(s) still read back on the registration -- a re-run removes them" } else { Note "$(@($cp.remove).Count) old Easy Auth client secret(s) removed from the registration (read back)" }
    } else { Note 'no Easy Auth client secret on the registration' }
    if (@($cp.keep).Count) { Note "other credentials on the registration are not this script's and are kept: $(@($cp.keep | ForEach-Object { $_.name }) -join ', ')" }
}

# ---- 7. RESTRICT WHO MAY SIGN IN (§48.1) --------------------------------------------------------
# 🔴 EASY AUTH ANSWERS THE WRONG QUESTION ON ITS OWN. RedirectToLoginPage proves the caller holds a
# valid account IN THIS TENANT -- every employee, every guest, every service account. For a console
# that mints TAPs and grants tier-0 roles, "authenticated" is not "authorised". Until this block
# existed the script printed a sentence asking the operator to go and fix that by hand, which is the
# same shape as the advice `Setup-PimContainers` used to print about Easy Auth itself (§44.5): a
# step that names the gap instead of closing it leaves the gap.
function Resolve-PimManagerMembersGroup {
    # SEC-44: the "every member, never a guest" group. Found by its mailNickname (stable), created when
    # absent, and VERIFIED to still carry the members-only rule before it is trusted with sign-in.
    $spec = Get-PimManagerMembersGroupSpec -DisplayName $MembersGroupName -MailNickname $MembersGroupMailNickname
    try { $ids = @(Find-PimGraphGroups -Filter "mailNickname eq '$MembersGroupMailNickname'" | ForEach-Object { "$($_.id)".Trim() } | Where-Object { $_ }) }
    catch { throw "could not search for the members group '$MembersGroupMailNickname': $("$($_.Exception.Message)".Trim())" }
    if (@($ids).Count -gt 1) { throw "more than one group has the mailNickname '$MembersGroupMailNickname' ($(@($ids) -join ', ')) -- refusing to guess which one admits people." }
    $gid = "$(@($ids) | Select-Object -First 1)".Trim()
    if (-not $gid) {
        Step "create the dynamic group '$MembersGroupName' -- every enabled MEMBER account, never a guest"
        $grpWhy = ''
        try { $gid = "$((Invoke-PimSetupGraph -Method POST -Path 'https://graph.microsoft.com/v1.0/groups' -Body $spec.body).id)".Trim() }
        catch { $gid = ''; $grpWhy = "$($_.Exception.Message)".Trim(); Test-PimEaGraphRefusal $grpWhy }
        if (-not $gid) {
            throw ("could not create the dynamic group '$MembersGroupName': $grpWhy. The deploy identity needs " +
                   'Group.Create (or Group.ReadWrite.All), and dynamic groups need Entra ID P1/P2. Or name who may sign in with -AllowedPrincipals.')
        }
        Note "created group $gid (Entra evaluates its membership in the background -- people are admitted once it has)"
    }
    $g = $null
    foreach ($wait in @(0, 3, 6, 12, 20, 30)) {
        if ($wait) { Start-Sleep -Seconds $wait }
        $g = Invoke-PimSetupGraph -Path "https://graph.microsoft.com/v1.0/groups/$gid" -ErrorAsNull
        if ($g) { break }
    }
    $v = Test-PimManagerMembersGroup -Group $g -Rule $spec.rule
    if (-not $v.ok) { throw "the members group is not safe to admit sign-in with: $($v.reason)" }
    return $gid
}

$needRestrict = [bool]($script:PimEaAccess -and "$($script:PimEaAccess.mode)" -ne 'keep-existing')
if (-not $WhatIfPreference -and $needRestrict -and -not "$spOid".Trim()) {
    $result.reason = "the Manager's enterprise application (service principal) does not exist, so sign-in cannot be restricted"
    Write-ResultFile
    throw "Set-PimManagerEasyAuth: $($result.reason). Nothing was opened; re-run once 'az ad sp create --id $appId' succeeds."
}
if (-not $WhatIfPreference -and "$spOid".Trim()) {
    if ($needRestrict) {
        Step "restrict sign-in: $($script:PimEaAccess.reason)"
        # Resolve first, ALL of them, before changing anything: switching the app to
        # assignment-required and then failing to resolve principal #3 leaves a Manager nobody can
        # open. Resolve -> assign -> only then require.
        $resolved = New-Object System.Collections.Generic.List[object]
        $unresolved = New-Object System.Collections.Generic.List[string]
        foreach ($p in @($AllowedPrincipals | Where-Object { "$_".Trim() })) {
            $pv = "$p".Trim(); $oid = ''; $kind = ''
            $oid = "$((Get-PimGraphUser -Id $pv -ErrorAsNull).id)".Trim()
            if ($oid) { $kind = 'user' }
            if (-not $oid) {
                $oid = "$((Get-PimGraphGroup -Id $pv -ErrorAsNull).id)".Trim()
                if ($oid) { $kind = 'group' }
            }
            if (-not $oid -and $pv -match '^[0-9a-fA-F-]{36}$') {
                # An object id for something we cannot name-resolve (a service principal, or a
                # directory object the deploy identity may only read by id).
                $oid = $pv; $kind = 'objectId'
            }
            if ($oid) { [void]$resolved.Add([pscustomobject]@{ input = $pv; id = $oid; kind = $kind }) }
            else      { [void]$unresolved.Add($pv) }
        }
        if ($unresolved.Count) {
            $result.reason = "could not resolve these principals in the tenant: $($unresolved -join ', ')"
            Write-ResultFile
            throw ("Set-PimManagerEasyAuth: $($result.reason). Nothing was changed -- resolving them AFTER " +
                   "switching the app to assignment-required is how a Manager ends up with no one able to open it.")
        }
        if ("$($script:PimEaAccess.mode)" -match 'members') {
            try { $mgid = Resolve-PimManagerMembersGroup }
            catch {
                $result.reason = "$($_.Exception.Message)"
                Write-ResultFile
                throw "Set-PimManagerEasyAuth: $($result.reason). Sign-in was NOT restricted and the Manager was NOT opened."
            }
            [void]$resolved.Add([pscustomobject]@{ input = "$MembersGroupName (every member, no guests)"; id = $mgid; kind = 'group' })
        }
        # 🪤 The deploying identity needs an assignment too, or the post-deploy release gate can no
        # longer mint its token for api://<appId> and the deploy fails on its own security fix.
        # WHO the calls run as, from PIM-Rest's own Graph token: an APPLICATION token (certificate / Support-app secret)
        # names the deploy identity's appid; a person's token does not (az printed a UPN there and this was skipped).
        $meAppId = Get-PimEaDeployAppId
        if ($meAppId -match '^[0-9a-fA-F-]{36}$') {
            $meOid = "$((Get-PimGraphServicePrincipal -Id $meAppId -ErrorAsNull).id)".Trim()
            if ($meOid -and -not (@($resolved | Where-Object { $_.id -eq $meOid }).Count)) {
                [void]$resolved.Add([pscustomobject]@{ input = "$meAppId (the deploy identity)"; id = $meOid; kind = 'servicePrincipal' })
                Note 'including the deploy identity, so the post-deploy release gate can still mint its token'
            }
        }
        # Assign each to the application's DEFAULT access role. appRoleId all-zeros is the
        # documented "no app role, just access" assignment, which is what the GUI's "Assign
        # users and groups" does when the app declares no roles of its own.
        $assignedNow = 0
        # Why each assignment was refused, if it was. Empty means "nothing was rejected", which is
        # what separates a slow directory from a denied one below.
        $script:PimEaAssignErrors = @{}
        $existing = @(Get-PimEaAssignedPrincipalIds)
        foreach ($r in $resolved) {
            if ($existing -contains $r.id) { Note "already assigned: $($r.input)"; continue }
            # 🪤 DO NOT SWALLOW THE POST'S OWN ERROR. A rejected assignment that produced no reason left the
            # read-back failing afterwards as the only evidence -- which reads as "the grant did not stick"
            # and says nothing about why. Keep whatever Graph answered and report it alongside the missing principal.
            try {
                [void](Invoke-PimSetupGraph -Method POST -Path "https://graph.microsoft.com/v1.0/servicePrincipals/$spOid/appRoleAssignedTo" `
                           -Body ([ordered]@{ principalId = $r.id; resourceId = $spOid; appRoleId = '00000000-0000-0000-0000-000000000000' }))
            } catch {
                $script:PimEaAssignErrors["$($r.input)"] = "$($_.Exception.Message)".Trim()
                Test-PimEaGraphRefusal "$($_.Exception.Message)"
            }
            $assignedNow++
        }
        # READ BACK -- the whole file's standard, and this is the assertion that matters most: an
        # assignment that did not land, on an app that IS assignment-required, is a locked door.
        #
        # 🔴 BUT A JUST-CREATED ENTERPRISE APP IS EVENTUALLY CONSISTENT, and this read used to happen
        # the instant after the POST. Measured at a customer 2026-09-11: every USER assignment landed
        # and the SERVICE PRINCIPAL added moments earlier came back missing, so the deploy failed --
        # on an assignment that was in fact fine a few seconds later. Same Graph-replication shape as
        # BUG-44, and the same bounded backoff answers it.
        # 🪤 A refusal is NOT a delay: if the POST itself was rejected, waiting cannot help, so that
        # case skips the wait entirely and reports what Graph said.
        $missing = @()
        $delay = 2; $waited = 0
        for ($attempt = 1; $attempt -le 6; $attempt++) {
            $after = @(Get-PimEaAssignedPrincipalIds)
            $missing = @($resolved | Where-Object { $after -notcontains $_.id })
            if (-not $missing.Count) {
                if ($attempt -gt 1) { Note "directory caught up after ${waited}s ($attempt attempts)" }
                break
            }
            if ($script:PimEaAssignErrors.Count) { break }   # rejected, not late
            if ($attempt -eq 6) { break }
            Note "  assignment not visible yet -- retry in ${delay}s ($attempt/6)"
            Start-Sleep -Seconds $delay
            $waited += $delay
            $delay = [Math]::Min($delay * 2, 15)
        }
        if ($missing.Count) {
            $detail = @($missing | ForEach-Object {
                $e = $script:PimEaAssignErrors["$($_.input)"]
                if ("$e".Trim()) { "$($_.input) -- Graph said: $e" } else { "$($_.input) -- the POST reported no error; it simply never appeared" }
            })
            $result.reason = "these principals are NOT assigned after the grant: $(($missing | ForEach-Object { $_.input }) -join ', ')"
            Write-ResultFile
            throw ("Set-PimManagerEasyAuth: $($result.reason). Sign-in was NOT restricted (the app is left open " +
                   "rather than locked against everyone).`n  " + ($detail -join "`n  ") +
                   "`n  The deploy identity needs Application.ReadWrite.All or Cloud Application Administrator to " +
                   "assign users to an enterprise application.")
        }
        # Only NOW require assignment. Every principal that must get in already can.
        # 🪤 KEEP THE UPDATE'S ERROR, AND RE-READ WITH BACKOFF -- the same two lessons as the
        # assignment loop above, which this line sat right next to and did neither. `az ad sp update`
        # ended in `-o none 2>$null`, so a refusal produced no reason; and the read-back was
        # immediate, on a service principal created by this same run. Measured at a customer
        # 2026-09-11, one step after the identical defect in the loop above: every assignment landed
        # and THIS read came back 'false'.
        $updErr = ''
        try { [void](Update-PimGraphServicePrincipal -ObjectId $spOid -Properties @{ appRoleAssignmentRequired = $true }) }
        catch { $updErr = "$($_.Exception.Message)".Trim(); Test-PimEaGraphRefusal $updErr }
        $req = ''
        $delay = 2; $waited = 0
        for ($attempt = 1; $attempt -le 6; $attempt++) {
            $req = "$((Get-PimGraphServicePrincipal -Id $spOid -ErrorAsNull).appRoleAssignmentRequired)".Trim()
            if ($req -match '(?i)^true$') {
                if ($attempt -gt 1) { Note "directory caught up after ${waited}s ($attempt attempts)" }
                break
            }
            if ($updErr) { break }          # refused, not late -- waiting cannot help
            if ($attempt -eq 6) { break }
            Note "  appRoleAssignmentRequired still reads '$req' -- retry in ${delay}s ($attempt/6)"
            Start-Sleep -Seconds $delay
            $waited += $delay
            $delay = [Math]::Min($delay * 2, 15)
        }
        if ($req -notmatch '(?i)^true$') {
            $result.reason = "appRoleAssignmentRequired reads '$req' after being switched on"
            Write-ResultFile
            throw ("Set-PimManagerEasyAuth: $($result.reason) -- so ANY account in the tenant can still sign in " +
                   "to the Manager. Refusing to report the access restriction as applied." +
                   $(if ($updErr) { "`n  Graph said: $updErr" } else { "`n  The update reported no error; the value simply did not change." }))
        }
        Note "assignment required = true; $($resolved.Count) principal(s) assigned ($assignedNow new)"
        $result.allowedPrincipals = @($resolved | ForEach-Object { $_.input })
    } else {
        # SEC-44: the only way to get here without a choice is an application that was ALREADY
        # assignment-required -- and that is re-read now, not trusted from the earlier look.
        $reqNow = "$((Get-PimGraphServicePrincipal -Id $spOid -ErrorAsNull).appRoleAssignmentRequired)".Trim()
        if ($reqNow -notmatch '(?i)^true$') {
            $result.reason = "sign-in is not restricted (appRoleAssignmentRequired reads '$reqNow') and no choice was given"
            Write-ResultFile
            throw ("Set-PimManagerEasyAuth: $($result.reason). Pass -AllowedPrincipals or -AllowAllTenantUsers. " +
                   'The Manager was NOT opened.')
        }
        Note 'sign-in restriction kept: the application is assignment-required and its existing assignments are unchanged'
        $result.allowedPrincipals = @('(existing assignments kept)')
    }
}

# 🔴 BUG-169 -- a Manager nobody can sign in to is a FAILED deploy, not a warning. Everything above
# still ran (Easy Auth is on, sign-in is restricted), so failing here leaves the console protected.
if (-not $consentOk) {
    $result.reason = "admin consent for the Manager's sign-in scopes is missing: $consentWhy"
    Write-ResultFile
    throw ("Set-PimManagerEasyAuth: $($result.reason)`n" +
           "  Easy Auth IS configured and the Manager is protected -- but every human sign-in stops at 'Need admin approval'.`n" +
           "  Fix, then re-run this script (idempotent):`n" +
           "    * give the deploy identity DelegatedPermissionGrant.ReadWrite.All: New-PimDeployIdentity.ps1 -GrantGraph -Apply, or`n" +
           "    * as a Global/Privileged Role Administrator: Entra admin center > Enterprise applications > '$AppDisplayName' >`n" +
           "      Permissions > Grant admin consent (every scope it needs is listed on the registration).")
}

# ---- 8. OPEN THE GATE -- last, and only now (SEC-31) ----------------------------------------------
# Everything that makes the console safe has been done AND read back above: Easy Auth enabled with the
# v2 issuer and an audience, consent in place, sign-in restricted. Only then is the closing access
# restriction that Setup-PimContainers put on a NEW Manager removed. Any throw above leaves it closed.
if (-not $WhatIfPreference) {
    Step 'open the Manager (remove the closed-until-Easy-Auth access restriction)'
    $gate = Set-PimManagerIngressGate -Mode Open -App $App -ResourceGroup $ResourceGroup -SubscriptionId $SubscriptionId
    $result.ingress = $gate.state
    if (-not $gate.ok) {
        $result.reason = "Easy Auth is configured, but the Manager could not be opened: $($gate.reason)"
        Write-ResultFile
        throw ("Set-PimManagerEasyAuth: $($result.reason). It stays CLOSED (safe). Re-run this script, or remove the rule " +
               "by hand once you have checked Easy Auth: Azure portal > Container Apps > $App > Ingress > IP restrictions, delete the rule $((Get-PimManagerGateRuleSpec).name)")
    }
    Note $(if ($gate.changed) { 'OPENED: the closing access restriction was removed and read back' } else { 'nothing to open (the closing access restriction is not on this app)' })
    if (@($gate.rules).Count) { Note "access restrictions still in force (yours, untouched): $(@($gate.rules) -join ', ')" }
    # 2026-10-10 (a customer's resume): the infra step creates the Manager on INTERNAL ingress, closes it, then switches it to
    # external. When the close failed on the first run the switch never happened, and every resume skipped infra as current --
    # so the Manager stayed internal (unreachable) with Easy Auth working. Easy Auth is verified here, so on an EXTERNAL
    # environment put the app on external ingress now (read back). An internal-only environment is left alone.
    try {
        $mApp = Get-PimArmAcaApp -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $App -ErrorAsNull
        $envId = "$($mApp.properties.managedEnvironmentId)$($mApp.properties.environmentId)".Trim()
        $envObj = $(if ($envId) { Invoke-PimSetupArm -Path $envId -ApiVersion (Get-PimSetupApiVersion aca) -ErrorAsNull } else { $null })
        $envInternal = "$($envObj.properties.vnetConfiguration.internal)".Trim()
        $isExt = "$($mApp.properties.configuration.ingress.external)".Trim()
        if ($mApp -and $isExt -notmatch '(?i)^true$' -and $envInternal -notmatch '(?i)^true$') {
            Step "put '$App' on external ingress (Easy Auth is in front of it)"
            [void](Invoke-PimEaBusyRetry -Write {
                Set-PimArmAcaAppConfiguration -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $App -Mutate { param($cfg) if ($cfg.ingress) { $cfg.ingress.external = $true } }
            })
            $back = "$((Get-PimArmAcaApp -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $App -ErrorAsNull).properties.configuration.ingress.external)".Trim()
            if ($back -match '(?i)^true$') { Note "EXPOSED behind Easy Auth: '$App' is on external ingress (read back)" }
            else { Write-Host "    '$App' ingress.external still reads '$back' -- it stays internal (closed); re-run to retry" -ForegroundColor Yellow }
        }
    } catch { Write-Host "    could not put '$App' on external ingress: $($_.Exception.Message) -- it stays internal (closed); re-run to retry" -ForegroundColor Yellow }
}

$result.ok = $true
Write-ResultFile
Write-Host "==> Microsoft built-in sign-in is in front of $App (client $appId; no client secret -- a federated credential with $($script:PimBa.webIdentityName))." -ForegroundColor Green
Write-Host "    Sign-in is required AND restricted: $($script:PimEaAccess.reason)." -ForegroundColor Green
exit 0
