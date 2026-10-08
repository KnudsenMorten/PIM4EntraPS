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
    5. mints a client secret ONLY when the app has none this deployment can use, and stores it as
       an ACA secret so it never appears in the container spec,
    6. configures the Microsoft identity provider + turns Easy Auth on with RedirectToLoginPage,
    7. READS IT BACK and fails if the audience is not there,
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
    [string]$SecretName     = 'easyauth-client-secret',
    [int]$SecretYears       = 2,
    # 🔑 ROTATE THE SIGN-IN SECRET. Without this the script deliberately never re-mints: a secret
    # that already exists may be in use, and `credential reset` without --append revokes the lot.
    # With it, a NEW secret is minted (--append, so the old one keeps working), written to the ACA
    # secret, and the app is re-verified. The OLD credential is left in place on purpose -- see the
    # note at the rotation block. Deleting it is a separate, deliberate act once the new one is
    # proven, because revoking the live credential before the new one is confirmed is how a
    # rotation becomes an outage.
    [switch]$RotateSecret,
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
. (Join-Path $here '_PimAz.ps1')            # the guarded az shadow
# BUG-169: the sign-in consent scopes + the pure consent plan.
. (Join-Path $here '_PimDeployGraph.ps1')

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
    # PURE. Judge an `access-restriction list -o json` answer. 'unknown' (unreadable) is NEVER 'open'.
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
      -Az is the test seam: a scriptblock param([string[]]$AzArgs) returning az's stdout (default: real az).
      Fail closed: a Close that cannot be read back is ok=$false; an Open that cannot be read back is ok=$false.
    #>
    param([Parameter(Mandatory)][ValidateSet('Close', 'Open')][string]$Mode,
          [Parameter(Mandatory)][string]$App, [Parameter(Mandatory)][string]$ResourceGroup,
          [string[]]$SubArgs = @(), [scriptblock]$Az)
    if (-not $Az) { $Az = { param([string[]]$AzArgs) $ErrorActionPreference = 'Continue'; & az @AzArgs 2>$null } }
    $spec = Get-PimManagerGateRuleSpec
    $base = @('containerapp', 'ingress', 'access-restriction')
    $tgt  = @($SubArgs) + @('-g', $ResourceGroup, '-n', $App)
    $read = { Get-PimManagerGateState -ListJson ((@(& $Az (@($base) + @('list') + $tgt + @('-o', 'json'))) -join "`n")) }
    $before = & $read
    if ($before.state -eq 'unknown') { return @{ ok = $false; changed = $false; state = 'unknown'; rules = @(); reason = $before.reason } }
    $want = $(if ($Mode -eq 'Close') { 'closed' } else { 'open' })
    if ($before.state -eq $want) { return @{ ok = $true; changed = $false; state = $want; rules = $before.rules; reason = "already $want" } }
    if ($Mode -eq 'Close') {
        [void](& $Az (@($base) + @('set') + $tgt + @('--rule-name', $spec.name, '--ip-address', $spec.ipAddress,
                                                     '--action', $spec.action, '--description', $spec.description, '-o', 'none')))
    } else {
        [void](& $Az (@($base) + @('remove') + $tgt + @('--rule-name', $spec.name, '-o', 'none')))
    }
    $after = & $read
    if ($after.state -ne $want) {
        $why = $(if ($after.state -eq 'unknown') { $after.reason } else { "the rule list reads [$(@($after.rules) -join ', ')] after the $($Mode.ToLowerInvariant())" })
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
    if ($RestartExitCode -ne 0) { return @{ ok = $false; done = $true; reason = "az refused the restart (exit $RestartExitCode)" } }
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

# 🪤 Every --query below is free of ( ) & | < > ^ -- see §46.1. az on Windows is az.cmd, PowerShell
# does not quote an argument with no spaces, and cmd.exe then eats those characters.
$subArgs = @(); if ("$SubscriptionId".Trim()) { $subArgs = @('--subscription', "$SubscriptionId".Trim()) }

if ($CloseIngressOnly) {
    Write-Host "`n=== PIM Manager ingress: CLOSE until Easy Auth is verified ($App) ===" -ForegroundColor Cyan
    if ($WhatIfPreference) { Note "WhatIf: would apply the access restriction '$((Get-PimManagerGateRuleSpec).name)' and read it back"; $result.ok = $true; Write-ResultFile; return }
    $g = Set-PimManagerIngressGate -Mode Close -App $App -ResourceGroup $ResourceGroup -SubArgs $subArgs
    $result.ingress = $g.state
    if (-not $g.ok) {
        $result.reason = "could not close the Manager's ingress: $($g.reason)"
        Write-ResultFile
        throw ("Set-PimManagerEasyAuth: $($result.reason). An app that cannot be closed must not be exposed -- " +
               "keep its ingress internal (az containerapp ingress update --type internal) until this succeeds.")
    }
    Note ("ingress CLOSED: access restriction '$((Get-PimManagerGateRuleSpec).name)' " + $(if ($g.changed) { 'applied and read back' } else { 'already in place' }) +
          " -- nobody can reach the Manager until this script has put Easy Auth in front of it and opened it.")
    $result.ok = $true; Write-ResultFile
    return
}

Write-Host "`n=== PIM Manager Easy Auth ($App) ===" -ForegroundColor Cyan

# ---- 1. the app's public address -------------------------------------------------------------
Step 'resolve the ingress FQDN'
$fqdn = @(az containerapp show @subArgs -g $ResourceGroup -n $App --query "properties.configuration.ingress.fqdn" -o tsv 2>$null) |
        Where-Object { "$_".Trim() } | Select-Object -First 1
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
# `az ad ...` addresses the GRAPH plane and REJECTS --subscription (§46 / the hygiene gate exempts
# it for exactly this reason), so no $subArgs on any of these calls.
$appId = "$ClientId".Trim()
# SEC-44: decided BEFORE anything is created or changed. An existing application that is already
# assignment-required keeps its restriction; anything else needs the caller's explicit choice.
$script:PimEaAccess = $null
function Assert-PimEaAccessChoice([string]$ExistingAppId) {
    $already = $false
    if ("$ExistingAppId".Trim()) {
        $req = "$(az ad sp show --id $ExistingAppId --query appRoleAssignmentRequired -o tsv 2>$null)".Trim()
        $global:LASTEXITCODE = 0
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
    $appId = @(az ad app list --identifier-uri $StableIdentifierUri --query "[].appId" -o tsv 2>$null) |
             Where-Object { "$_".Trim() } | Select-Object -First 1
    if ("$appId".Trim()) {
        $appId = "$appId".Trim()
        Note "reusing registration $appId (matched on the stable identifier uri)"
    } else {
        # Current name first, then every name this app has ever shipped under. A tenant deployed
        # last month carries the old one; without searching for it, the rename creates a duplicate
        # instead of adopting -- the exact defect this whole block exists to end.
        foreach ($nm in @(@($AppDisplayName) + @($LegacyDisplayNames))) {
            if (-not "$nm".Trim()) { continue }
            $appId = @(az ad app list --display-name "$nm" --query "[].appId" -o tsv 2>$null) |
                     Where-Object { "$_".Trim() } | Select-Object -First 1
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
        $appId = @(az ad app create --display-name $AppDisplayName `
                        --web-redirect-uris $reply --enable-id-token-issuance true `
                        --query appId -o tsv 2>$null) | Where-Object { "$_".Trim() } | Select-Object -First 1
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
            $seen = @(az ad app show --id $appId --query appId -o tsv 2>$null) |
                    Where-Object { "$_".Trim() } | Select-Object -First 1
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
        $existingReplies = @(az ad app show --id $appId --query "web.redirectUris" -o tsv 2>$null) | Where-Object { "$_".Trim() }
        $replies = @(@($existingReplies) + @($wantReplies) | Sort-Object -Unique)
        az ad app update --id $appId --web-redirect-uris @replies --enable-id-token-issuance true -o none 2>$null
        $nowReplies = @(az ad app show --id $appId --query "web.redirectUris" -o tsv 2>$null) | Where-Object { "$_".Trim() }
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
    $curName = "$(az ad app show --id $appId --query displayName -o tsv 2>$null)".Trim()
    if ($curName -and $curName -ne $AppDisplayName) {
        az ad app update --id $appId --display-name $AppDisplayName -o none 2>$null
        $nowName = "$(az ad app show --id $appId --query displayName -o tsv 2>$null)".Trim()
        if ($nowName -eq $AppDisplayName) { Note "renamed '$curName' -> '$AppDisplayName' (consistent with the sibling registrations)" }
        else { Warn "could not rename '$curName' to '$AppDisplayName' -- cosmetic only; identity is the stable uri." }
    }

    $wantIds = @("api://$appId", $StableIdentifierUri) | Sort-Object -Unique
    $idOk = $false
    foreach ($wait in @(0, 3, 6, 12, 20, 30)) {
        if ($wait) { Start-Sleep -Seconds $wait }
        $ids = @(az ad app show --id $appId --query "identifierUris" -o tsv 2>$null) | Where-Object { "$_".Trim() }
        if ((@($ids) -contains "api://$appId") -and (@($ids) -contains $StableIdentifierUri)) { $idOk = $true; break }
        # Keep anything the tenant already had -- another product may have added one, and replacing
        # the list would take it away.
        $merged = @(@($ids) + @($wantIds) | Where-Object { "$_".Trim() } | Sort-Object -Unique)
        az ad app update --id $appId --identifier-uris @merged -o none 2>$null
    }
    if ($idOk) { Note "identifiers present: api://$appId + $StableIdentifierUri" }
    else { Warn "could not set both identifier URIs -- the gate may not mint a token, and the next deploy may not FIND this app and could create a duplicate." }
    # A registration with no service principal in this tenant cannot be signed in to at all.
    # Same replication story as the create above: a service principal is not visible the instant it
    # is made, and `az ad sp create` on a registration Graph has not caught up with fails outright.
    # Retried, then VERIFIED -- "the command exited 0" is not the same as "the object is there".
    $spOid = @(az ad sp show --id $appId --query id -o tsv 2>$null) | Where-Object { "$_".Trim() } | Select-Object -First 1
    if (-not "$spOid".Trim()) {
        Note 'creating the service principal for the registration'
        foreach ($wait in @(0, 3, 6, 12, 20, 30)) {
            if ($wait) { Start-Sleep -Seconds $wait }
            az ad sp create --id $appId -o none 2>$null
            $spOid = @(az ad sp show --id $appId --query id -o tsv 2>$null) | Where-Object { "$_".Trim() } | Select-Object -First 1
            if ("$spOid".Trim()) { break }
        }
        if ("$spOid".Trim()) { Note "service principal $spOid" }
        else { Warn 'could not create the service principal -- sign-in will fail until it exists.' }
    }
}

# ---- 4. client secret -> ACA secret ------------------------------------------------------------
# Minted only when the app does not already carry one this deployment can use, because
# `az ad app credential reset` without --append REVOKES every existing secret -- and on a reused
# registration those may belong to something else that is working.
if ($PSCmdlet.ShouldProcess($App, 'ensure the Easy Auth client secret')) {
    $haveSecret = @(az containerapp secret list @subArgs -g $ResourceGroup -n $App --query "[].name" -o tsv 2>$null) |
                  Where-Object { "$_".Trim() -eq $SecretName }
    if ($haveSecret -and $RotateSecret) {
        # 🔑 ROTATION, IN THE ONLY SAFE ORDER: mint the new credential, put it in place, verify --
        # and leave the OLD one valid. Both work simultaneously (Entra allows multiple secrets), so
        # there is no window in which sign-in is broken, and no reliance on this script's own
        # verification being perfect. Revoking the old one is a separate decision, taken once real
        # users have signed in on the new one.
        Step "ROTATE the client secret on $appId (the old one stays valid until you revoke it)"
        $new = @(az ad app credential reset --id $appId --append --years $SecretYears `
                    --display-name "easyauth-$(Get-Date -Format yyyyMMdd)" --query password -o tsv 2>$null) |
               Where-Object { "$_".Trim() } | Select-Object -First 1
        if (-not "$new".Trim()) {
            $result.reason = 'could not mint a replacement client secret'
            Write-ResultFile; throw "Set-PimManagerEasyAuth: $($result.reason)"
        }
        az containerapp secret set @subArgs -g $ResourceGroup -n $App --secrets "$SecretName=$("$new".Trim())" -o none
        if ($LASTEXITCODE -ne 0) {
            $result.reason = 'minted a new secret but could not store it on the container app -- the OLD secret is still in place, so sign-in still works'
            Write-ResultFile; throw "Set-PimManagerEasyAuth: $($result.reason)"
        }
        Note "rotated: ACA secret '$SecretName' now holds a credential valid for $SecretYears year(s)"
        Warn "the PREVIOUS credential is still valid. Once people have signed in on the new one, revoke it:"
        Warn "  az ad app credential list --id $appId --query `"[].{name:displayName,id:keyId,expires:endDateTime}`" -o table"
        Warn "  az ad app credential delete --id $appId --key-id <the OLD keyId>"
        # 🪤 An ACA secret change does NOT restart the app or create a revision. The auth sidecar
        # picks the new value up on the next revision, so a rotation that is never rolled looks
        # applied and is not. Say so, and do it.
        Step 'restart the active revision so the auth sidecar picks up the new secret'
        # 🔴 BUG-183 -- THIS QUERY WAS '[?properties.active].name | [0]', AND az IS az.cmd: cmd.exe
        # read the '|' as a PIPE, the call died, $rev came back EMPTY and the new secret was never
        # used -- while the rotation above reported success. No pipe in the JMESPath: list the
        # active names and pick the first in PowerShell (the same fix Invoke-PimDeployAll carries).
        # And a restart is READ BACK: the replica set must change (or there must be none to change).
        $rev = @(az containerapp revision list @subArgs -g $ResourceGroup -n $App --query '[?properties.active].name' -o tsv 2>$null) |
               Where-Object { "$_".Trim() } | Select-Object -First 1
        $rev = "$rev".Trim()
        if (-not $rev) {
            $result.reason = 'the secret was rotated but the active revision could not be found, so nothing was restarted -- the Manager still signs in with the OLD secret (which is still valid)'
            Write-ResultFile; throw "Set-PimManagerEasyAuth: $($result.reason). Restart it: az containerapp revision restart -g $ResourceGroup -n $App --revision <active revision>"
        }
        $replicasBefore = @(az containerapp replica list @subArgs -g $ResourceGroup -n $App --revision $rev --query '[].name' -o tsv 2>$null) | Where-Object { "$_".Trim() }
        az containerapp revision restart @subArgs -g $ResourceGroup -n $App --revision $rev -o none 2>$null | Out-Null
        $restartExit = $LASTEXITCODE
        $rs = $null
        for ($attempt = 1; $attempt -le 8; $attempt++) {
            $replicasAfter = @(az containerapp replica list @subArgs -g $ResourceGroup -n $App --revision $rev --query '[].name' -o tsv 2>$null) | Where-Object { "$_".Trim() }
            $rs = Get-PimRevisionRestartVerdict -RestartExitCode $restartExit -ReplicasBefore $replicasBefore -ReplicasAfter $replicasAfter
            if ($rs.done) { break }
            Start-Sleep -Seconds 10
        }
        $global:LASTEXITCODE = 0
        if (-not $rs.ok) {
            $result.reason = "the secret was rotated but the restart of $rev could not be confirmed: $($rs.reason)"
            Write-ResultFile; throw "Set-PimManagerEasyAuth: $($result.reason). The OLD secret is still valid, so sign-in keeps working; restart the revision and re-check."
        }
        Note "restarted $rev -- $($rs.reason)"
    }
    elseif ($haveSecret) {
        Note "ACA secret '$SecretName' already present -- not minting a new credential. Pass -RotateSecret to replace it."
    } else {
        Step 'mint a client secret and store it as an ACA secret'
        # 🪤 `--append` is a FLAG, not a boolean-valued option. `--append true` is rejected with
        #     ERROR: unrecognized arguments: true
        # which reads like the command is unsupported rather than mis-spelled. It still matters
        # that it is present: without it, `credential reset` REVOKES every existing secret on the
        # registration -- so the wrong fix (dropping the argument) would quietly break whatever
        # else was using a reused app.
        $pwd = @(az ad app credential reset --id $appId --append --years $SecretYears `
                    --display-name 'easyauth' --query password -o tsv 2>$null) |
               Where-Object { "$_".Trim() } | Select-Object -First 1
        if (-not "$pwd".Trim()) {
            $result.reason = 'could not mint a client secret for the app registration'
            Write-ResultFile; throw "Set-PimManagerEasyAuth: $($result.reason)"
        }
        # As an ACA secret, referenced by NAME -- so the value never appears in the container spec
        # or in `az containerapp show`, the same rule the engine secret follows.
        az containerapp secret set @subArgs -g $ResourceGroup -n $App --secrets "$SecretName=$("$pwd".Trim())" -o none
        if ($LASTEXITCODE -ne 0) {
            $result.reason = 'could not store the client secret on the container app'
            Write-ResultFile; throw "Set-PimManagerEasyAuth: $($result.reason)"
        }
        Note "stored as ACA secret '$SecretName' (never printed, never in the container spec)"
    }
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
# Measured on EFIF and RIDE: the Manager registration had NO consent grant at all, and those tenants
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
    $permJson = (@(az ad app permission list --id $appId -o json 2>$null) -join "`n")
    # PS 5.1: assign ConvertFrom-Json first -- a JSON array arrives as ONE object and @(...) would nest it.
    try { $permParsed = ConvertFrom-Json $permJson
          $listed = @(@($permParsed) | Where-Object { $_.resourceAppId -eq $graphAppId } |
                      ForEach-Object { @($_.resourceAccess) } | ForEach-Object { "$($_.id)".ToLowerInvariant() }) } catch { $listed = @() }
    $toList = @($scopeIds.Keys | Where-Object { $listed -notcontains $scopeIds[$_].ToLowerInvariant() })
    if ($toList.Count) {
        $apiPerms = @($toList | ForEach-Object { "$($scopeIds[$_])=Scope" })
        az ad app permission add --id $appId --api $graphAppId --api-permissions @apiPerms -o none 2>$null
        Note "listed on the registration: $($toList -join ', ')"
    } else { Note 'every sign-in scope is already listed on the registration' }

    # CONSENT, as a tenant-wide oauth2PermissionGrant through Microsoft Graph.
    # 🔴 BUG-161 -- `az ad app permission admin-consent` only works with a USER token; under a
    # certificate SPN (every scripted deploy) it is refused with S2S17001 'UnsupportedAccessTokenType'.
    # The Graph grant works for both, so it goes FIRST and admin-consent is only the user-token fallback.
    $clientSp = "$(az ad sp show --id $appId --query id -o tsv 2>$null)".Trim()
    $graphSp  = "$(az ad sp show --id $graphAppId --query id -o tsv 2>$null)".Trim()
    function Read-PimEaConsentGrant {
        # Every grant this client holds, filtered here: no $filter, so the URL carries no quote or space
        # for az.cmd to mangle (§46.1). 🪤 "could NOT read" is not "absent" (BUG-166's lesson): an
        # unreadable answer returns ok=$false and is never planned as a create.
        $j = (@(az rest --method GET --uri "https://graph.microsoft.com/v1.0/servicePrincipals/$clientSp/oauth2PermissionGrants" -o json 2>$null) -join "`n")
        if ($LASTEXITCODE -ne 0 -or -not "$j".Trim()) { return @{ ok = $false; grant = $null } }
        try { $v = @((ConvertFrom-Json $j).value) } catch { return @{ ok = $false; grant = $null } }
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
            $consentWhy = "could not READ the existing consent grants, so refusing to guess: $("$($global:PimAzLastError)".Trim())"
        } else {
            $plan = Get-PimEasyAuthConsentPlan -ExistingScope "$($rd.grant.scope)" -GrantExists:([bool]$rd.grant)
            if ($plan.Action -eq 'none') {
                Note "consent already in place (tenant-wide): $($rd.grant.scope)"
            } else {
                $bodyFile = Join-Path ([IO.Path]::GetTempPath()) ("pim-consent-" + [guid]::NewGuid().ToString('N') + '.json')
                try {
                    if ($plan.Action -eq 'create') {
                        $method = 'POST'; $uri = 'https://graph.microsoft.com/v1.0/oauth2PermissionGrants'
                        $body = @{ clientId = $clientSp; consentType = 'AllPrincipals'; resourceId = $graphSp; scope = $plan.Scope }
                    } else {
                        # PATCH to the UNION -- never narrow a grant someone else widened.
                        $method = 'PATCH'; $uri = "https://graph.microsoft.com/v1.0/oauth2PermissionGrants/$($rd.grant.id)"
                        $body = @{ scope = $plan.Scope }
                    }
                    Set-Content -LiteralPath $bodyFile -Encoding ascii -NoNewline -Value ($body | ConvertTo-Json -Compress)
                    az rest --method $method --uri $uri --headers Content-Type=application/json --body "@$bodyFile" -o none 2>$null
                    if ($LASTEXITCODE -ne 0) { $consentWhy = "Microsoft Graph refused the consent $method`: $("$($global:PimAzLastError)".Trim())" }
                } finally { Remove-Item -LiteralPath $bodyFile -Force -ErrorAction SilentlyContinue }
                if (-not $consentWhy) {
                    $got = Wait-PimEaConsent
                    if ($got) { Note "consented (tenant-wide, $($plan.Action)): $got" }
                    else { $consentWhy = "the consent grant was written but never read back with every scope ($($plan.Scope))" }
                }
            }
        }
        # The user-token fallback (a human running this interactively): consents what is LISTED above.
        if ($consentWhy) {
            az ad app permission admin-consent --id $appId -o none 2>$null
            if ($LASTEXITCODE -eq 0) {
                $got = Wait-PimEaConsent
                if ($got) { Note "consented via admin-consent (user token): $got"; $consentWhy = '' }
            }
        }
    }
    $global:LASTEXITCODE = 0
    if ($consentWhy) {
        $consentOk = $false
        $result.consent = 'MISSING'
        Write-Warning ("NO HUMAN CAN SIGN IN TO THE MANAGER YET: admin consent for '$AppDisplayName' ($appId) is missing -- $consentWhy. " +
                       "Easy Auth is still configured below so the console stays protected, and this run will FAIL at the end.")
    } else { $result.consent = 'ok' }
    # ID-token issuance, on the REUSE path too -- the create call sets it, and a reused
    # registration never got it (the same create-path-only defect as the permission above).
    az ad app update --id $appId --enable-id-token-issuance true -o none 2>$null
    $global:LASTEXITCODE = 0
}

# ---- 5. configure + enable ---------------------------------------------------------------------
if ($PSCmdlet.ShouldProcess($App, 'configure the Microsoft identity provider and enable Easy Auth')) {
    Step 'configure the Microsoft identity provider'
    az containerapp auth microsoft update @subArgs -g $ResourceGroup -n $App `
        --client-id $appId --client-secret-name $SecretName `
        --issuer "https://login.microsoftonline.com/$TenantId/v2.0" `
        --allowed-audiences "api://$appId" --yes -o none
    if ($LASTEXITCODE -ne 0) {
        $result.reason = 'az containerapp auth microsoft update failed'
        Write-ResultFile; throw "Set-PimManagerEasyAuth: $($result.reason)"
    }
    Step 'enable Easy Auth (unauthenticated requests -> login page)'
    az containerapp auth update @subArgs -g $ResourceGroup -n $App `
        --enabled true --action RedirectToLoginPage --redirect-provider azureactivedirectory -o none
    if ($LASTEXITCODE -ne 0) {
        $result.reason = 'az containerapp auth update failed'
        Write-ResultFile; throw "Set-PimManagerEasyAuth: $($result.reason)"
    }
}

# ---- 6. READ IT BACK ---------------------------------------------------------------------------
# 🔒 A configure step that reports success without reading back is how BUG-37 shipped a workspace
# move that moved nothing, and how the Graph grant loop printed "granted" three times while
# granting nothing. Auth config flips instantly and takes effect a moment later -- precisely the
# shape that fools a writer-only check.
if (-not $WhatIfPreference) {
    Step 'read the configuration back'
    $aud = @(az containerapp auth show @subArgs -g $ResourceGroup -n $App `
                --query "identityProviders.azureActiveDirectory.validation.allowedAudiences" -o tsv 2>$null) |
           Where-Object { "$_".Trim() } | Select-Object -First 1
    $enabled = @(az containerapp auth show @subArgs -g $ResourceGroup -n $App --query "platform.enabled" -o tsv 2>$null) |
               Where-Object { "$_".Trim() } | Select-Object -First 1
    if (-not "$aud".Trim()) {
        $result.reason = 'Easy Auth reports NO allowed audience after configuration -- the release gate will still not be able to mint a token'
        Write-ResultFile; throw "Set-PimManagerEasyAuth: $($result.reason)"
    }
    if ("$enabled".Trim().ToLowerInvariant() -ne 'true') {
        $result.reason = "Easy Auth platform.enabled reads '$enabled' after being turned on"
        Write-ResultFile; throw "Set-PimManagerEasyAuth: $($result.reason)"
    }
    # 🔴 §52.17 -- READ THE ISSUER BACK TOO. A v1 issuer here means the login flow will ask for the
    # RETIRED Azure AD Graph resource and every human sign-in dies with AADSTS650056, while the
    # audience and platform.enabled checks above both pass. Two green assertions over a Manager
    # nobody can open is precisely what happened.
    $iss = @(az containerapp auth show @subArgs -g $ResourceGroup -n $App `
                --query "identityProviders.azureActiveDirectory.registration.openIdIssuer" -o tsv 2>$null) |
           Where-Object { "$_".Trim() } | Select-Object -First 1
    if ("$iss".Trim() -notmatch '(?i)/v2\.0/?$') {
        $result.reason = "Easy Auth issuer reads '$iss', which is not the v2 endpoint"
        Write-ResultFile
        throw ("Set-PimManagerEasyAuth: $($result.reason). A v1 issuer makes the sign-in flow request the " +
               "RETIRED Azure AD Graph resource, and every browser login then fails with AADSTS650056 while " +
               "this script's other checks pass. Expected https://login.microsoftonline.com/$TenantId/v2.0")
    }
    Note "verified: enabled=$enabled audience=$aud issuer=$iss"
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
    $ids = @(az ad group list --filter "mailNickname eq '$MembersGroupMailNickname'" --query "[].id" -o tsv 2>$null) | Where-Object { "$_".Trim() }
    if ($LASTEXITCODE -ne 0) { throw "could not search for the members group '$MembersGroupMailNickname': $("$($global:PimAzLastError)".Trim())" }
    if (@($ids).Count -gt 1) { throw "more than one group has the mailNickname '$MembersGroupMailNickname' ($(@($ids) -join ', ')) -- refusing to guess which one admits people." }
    $gid = "$(@($ids) | Select-Object -First 1)".Trim()
    if (-not $gid) {
        Step "create the dynamic group '$MembersGroupName' -- every enabled MEMBER account, never a guest"
        $bodyFile = Join-Path ([IO.Path]::GetTempPath()) ("pim-ea-grp-" + [guid]::NewGuid().ToString('N') + '.json')
        try {
            Set-Content -LiteralPath $bodyFile -Encoding ascii -NoNewline -Value ($spec.body | ConvertTo-Json -Compress -Depth 5)
            $gid = "$(@(az rest --method POST --uri 'https://graph.microsoft.com/v1.0/groups' --headers Content-Type=application/json --body "@$bodyFile" --query id -o tsv 2>$null) | Select-Object -First 1)".Trim()
        } finally { Remove-Item -LiteralPath $bodyFile -Force -ErrorAction SilentlyContinue }
        if (-not $gid) {
            throw ("could not create the dynamic group '$MembersGroupName': $("$($global:PimAzLastError)".Trim()). The deploy identity needs " +
                   'Group.Create (or Group.ReadWrite.All), and dynamic groups need Entra ID P1/P2. Or name who may sign in with -AllowedPrincipals.')
        }
        Note "created group $gid (Entra evaluates its membership in the background -- people are admitted once it has)"
    }
    $g = $null
    foreach ($wait in @(0, 3, 6, 12, 20, 30)) {
        if ($wait) { Start-Sleep -Seconds $wait }
        $j = (@(az rest --method GET --uri "https://graph.microsoft.com/v1.0/groups/$gid" -o json 2>$null) -join "`n")
        if ("$j".Trim()) { try { $g = ConvertFrom-Json -InputObject $j } catch { $g = $null } }
        if ($g) { break }
    }
    $global:LASTEXITCODE = 0
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
            $oid = "$(az ad user show --id $pv --query id -o tsv 2>$null)".Trim()
            if ($oid) { $kind = 'user' }
            if (-not $oid) {
                $oid = "$(az ad group show --group $pv --query id -o tsv 2>$null)".Trim()
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
        $meAppId = "$(az account show --query user.name -o tsv 2>$null)".Trim()
        if ($meAppId -match '^[0-9a-fA-F-]{36}$') {
            $meOid = "$(az ad sp show --id $meAppId --query id -o tsv 2>$null)".Trim()
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
        $existing = @(az rest --method GET --uri "https://graph.microsoft.com/v1.0/servicePrincipals/$spOid/appRoleAssignedTo" `
                        --query "value[].principalId" -o tsv 2>$null) | Where-Object { "$_".Trim() }
        foreach ($r in $resolved) {
            if ($existing -contains $r.id) { Note "already assigned: $($r.input)"; continue }
            # 🪤 --body @file, not an inline JSON string: an inline body is a single argument full
            # of double quotes, and how those survive to the CLI depends on the host and on whether
            # az is a batch file (§46.1). A file has no quoting problem to get wrong.
            $bodyFile = Join-Path ([IO.Path]::GetTempPath()) ("pim-ea-{0}.json" -f ([guid]::NewGuid().ToString('N').Substring(0,8)))
            ([ordered]@{ principalId = $r.id; resourceId = $spOid; appRoleId = '00000000-0000-0000-0000-000000000000' } |
                ConvertTo-Json -Compress) | Set-Content -LiteralPath $bodyFile -Encoding ascii
            # 🪤 DO NOT SWALLOW THE POST'S OWN ERROR. This used to end in `-o none 2>$null`, so a
            # rejected assignment produced no reason at all and the only evidence was the read-back
            # failing afterwards -- which reads as "the grant did not stick" and says nothing about
            # why. Keep whatever Graph answered and report it alongside the missing principal.
            $post = az rest --method POST --uri "https://graph.microsoft.com/v1.0/servicePrincipals/$spOid/appRoleAssignedTo" `
                        --headers Content-Type=application/json --body "@$bodyFile" -o none 2>&1
            if ($LASTEXITCODE -ne 0) {
                $why = "$(@($post) -join ' ')".Trim()
                if (-not $why) { $why = "$($global:PimAzLastError)".Trim() }
                $script:PimEaAssignErrors["$($r.input)"] = $why
            }
            Remove-Item -LiteralPath $bodyFile -Force -ErrorAction SilentlyContinue
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
            $after = @(az rest --method GET --uri "https://graph.microsoft.com/v1.0/servicePrincipals/$spOid/appRoleAssignedTo" `
                         --query "value[].principalId" -o tsv 2>$null) | Where-Object { "$_".Trim() }
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
        $upd = az ad sp update --id $spOid --set appRoleAssignmentRequired=true -o none 2>&1
        $updErr = ''
        if ($LASTEXITCODE -ne 0) {
            $updErr = "$(@($upd) -join ' ')".Trim()
            if (-not $updErr) { $updErr = "$($global:PimAzLastError)".Trim() }
        }
        $req = ''
        $delay = 2; $waited = 0
        for ($attempt = 1; $attempt -le 6; $attempt++) {
            $req = "$(az ad sp show --id $spOid --query appRoleAssignmentRequired -o tsv 2>$null)".Trim()
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
        $reqNow = "$(az ad sp show --id $spOid --query appRoleAssignmentRequired -o tsv 2>$null)".Trim()
        $global:LASTEXITCODE = 0
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
    $gate = Set-PimManagerIngressGate -Mode Open -App $App -ResourceGroup $ResourceGroup -SubArgs $subArgs
    $result.ingress = $gate.state
    if (-not $gate.ok) {
        $result.reason = "Easy Auth is configured, but the Manager could not be opened: $($gate.reason)"
        Write-ResultFile
        throw ("Set-PimManagerEasyAuth: $($result.reason). It stays CLOSED (safe). Re-run this script, or remove the rule " +
               "by hand once you have checked Easy Auth: az containerapp ingress access-restriction remove -g $ResourceGroup -n $App --rule-name $((Get-PimManagerGateRuleSpec).name)")
    }
    Note $(if ($gate.changed) { 'OPENED: the closing access restriction was removed and read back' } else { 'nothing to open (the closing access restriction is not on this app)' })
    if (@($gate.rules).Count) { Note "access restrictions still in force (yours, untouched): $(@($gate.rules) -join ', ')" }
}

$result.ok = $true
Write-ResultFile
Write-Host "==> Easy Auth is in front of $App (client $appId)." -ForegroundColor Green
Write-Host "    Sign-in is required AND restricted: $($script:PimEaAccess.reason)." -ForegroundColor Green
exit 0
