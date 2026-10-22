#Requires -Version 5.1
<#
.SYNOPSIS
    CR7 / framework §12.11g item 4 -- move the PIM Manager's web sign-in from Easy Auth + a client SECRET to the shared
    sign-in front (FRAMEWORK/signin-front, no secret). PLANS by default; changes nothing without -Apply.

.DESCRIPTION
    One environment at a time, coordinated with the customer, through the Invardia Support app (or the person signed in
    in the browser). On the Manager container app and its existing Easy Auth application (found from the app -- never
    created here):

      0. front image           (PIM 100.168) with no -FrontImage: <the Manager's registry>/signin-front:<pinned version>.
                               Not there yet -> PIM_BUILD_SIGNIN_FRONT=1 on the updater job, ONE updater run started
                               (-NoUpdaterRun: you start it), and the script waits (-FrontImageWaitMinutes) until the image
                               is in the registry. Nothing below happens before it is there.
      1. federated credential  the web identity (the user-assigned managed identity on the Manager) is trusted by the SAME
                               app registration: issuer https://login.microsoftonline.com/<tenant>/v2.0, subject = the
                               identity's principal id, audience api://AzureADTokenExchange.        (merged, never removed)
      2. redirect URIs         https://<host>/signin-oidc for the app's FQDN and every custom domain; logout URL
                               https://<host>/signout-callback-oidc.                           (merged -- existing kept)
      3. refresh scope         delegated Microsoft Graph User.Read on the registration, admin-consented (the front
                               refreshes the 1-hour ID token silently inside the 8-hour session).        (merged)
      4. two-container revision  'signin-front' (the pinned front image, ingress target port 8080, probes on /healthz)
                               + the Manager on 127.0.0.1:<UpstreamPort> (PIM_HOSTED_AUTH_LAYER=signin-front, its own
                               probes removed). Replicas pinned min = max = 1 (the front's keys and token cache are in
                               memory -- FRAMEWORK/signin-front/README.md "Known limits").
      5. switch                Easy Auth OFF -- only AFTER the new revision is up, so the Manager is never reachable
                               without a sign-in in front of it.
      6. read back             /healthz 200; a navigation to / is sent to THIS tenant's authorize endpoint with
                               response_type=code + PKCE (S256) + this client id; a script call to /api gets 401.
                               Any failure here ROLLS BACK at once (Easy Auth on, the saved revision template back).

    Before anything changes, the container app and its auth config are saved to -StateFile: the rollback.
      -Rollback -StateFile <file>   Easy Auth ON first, then the saved template + ingress back (auth is never off).
      -DeleteSecret                 a LATER run, once people have signed in through the front: removes the Easy Auth
                                    client secret(s) ('easyauth-*') from the registration. The point of no return for
                                    a rollback to Easy Auth -- refused unless the front is live. Other secrets on the
                                    registration are listed, never removed.

    Nothing here changes an install that is not run with -Apply: the Manager keeps Easy Auth + its secret until then.
    100.41 (framework 12.17 NO-AZ): every call is ARM / Graph REST through PIM-Rest (PIM-ArmSetup.ps1) -- a calling
    deploy's REST session, else the Invardia Support app's session, else the person signs in in the browser. No modules.

.EXAMPLE
    .\Set-PimManagerSigninFront.ps1 -SubscriptionId <sub> -ResourceGroup <rg> -TenantId <tenant>
    Plan: names the front image the install's own updater builds (<registry>/signin-front:<pinned version>) and whether it is there.
.EXAMPLE
    .\Set-PimManagerSigninFront.ps1 -SubscriptionId <sub> -ResourceGroup <rg> -TenantId <tenant> -FrontImage <registry>/signin-front:1.1.0
.EXAMPLE
    .\Set-PimManagerSigninFront.ps1 -SubscriptionId <sub> -ResourceGroup <rg> -TenantId <tenant> -FrontImage <registry>/signin-front:1.1.0 -Apply
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$SubscriptionId,
    [Parameter(Mandatory)][string]$ResourceGroup,
    [Parameter(Mandatory)][string]$TenantId,
    [string]$ManagerApp = 'ca-pim-manager',
    # the signin-front image at the version PIM pins (tools/pim-manager/signin-front.version), e.g. <acr>/signin-front:1.1.0
    [string]$FrontImage = '',
    # the web identity (user-assigned managed identity) -- needed only when the Manager carries more than one
    [string]$WebIdentityResourceId = '',
    # front 1.3.0+: the Key Vault key id that wraps the front's Data Protection keys (Set-PimSigninFrontState prints it)
    [string]$KeyVaultKeyId = '',
    # front 1.4.0+ access-token mode (framework 12.11g item 10): 'api://<this app's client id>/user_impersonation' -- the
    # scope must already be on the registration with its self-grant (the guided install's 'signin-front-app' step does it).
    # Carried in the SAME revision write; '' = ID-token mode, as before.
    [string]$UpstreamScope = '',
    # a PRIVATE install: this machine cannot reach the Manager -- skip the HTTP read-back; a person signs in from inside
    [switch]$PrivateReadBackByPerson,
    [ValidateRange(1024, 65535)][int]$UpstreamPort = 8081,
    [ValidateRange(1, 24)][int]$SessionHours = 8,
    [string]$StateFile = '',
    # PIM 100.168 (the image step): with no -FrontImage, the front image is <the Manager's registry>/signin-front:<pinned version>,
    # built by the install's OWN updater. -Apply sets PIM_BUILD_SIGNIN_FRONT=1 on -UpdateJob, starts one updater run (not with
    # -NoUpdaterRun: then the operator starts it) and waits up to -FrontImageWaitMinutes for the image before anything else.
    [string]$UpdateJob = 'ca-pim-update',
    [ValidateRange(5, 240)][int]$FrontImageWaitMinutes = 60,
    [switch]$NoUpdaterRun,
    [switch]$Apply,
    [switch]$Rollback,
    [switch]$DeleteSecret
)
$ErrorActionPreference = 'Stop'
$solRootSf = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
if (-not (Get-Command Get-PimRestToken -ErrorAction SilentlyContinue)) { . (Join-Path $solRootSf 'engine\_shared\PIM-Rest.ps1') }
if (-not (Get-Command Invoke-PimSetupArm -ErrorAction SilentlyContinue)) { . (Join-Path $solRootSf 'engine\_shared\PIM-ArmSetup.ps1') }
$script:SfGraphAppId = '00000003-0000-0000-c000-000000000000'   # Microsoft Graph (first-party, the same in every tenant)
$script:SfFrontName = 'signin-front'
$script:SfFrontPort = 8080

# ---- PURE: the decisions (tests/Test-PimSigninFrontSetup.ps1) -------------------------------------------------------

function Get-PimSigninFrontWebIdentity {
    <#
      PURE. Which user-assigned managed identity on the Manager is the web identity (the front's federated credential)?
      -App = the container app resource. Exactly one attached = that one; more than one = -ResourceId must name it;
      none = refused (§12.11g item 5: the web identity must exist first -- §12.11f step 1). @{ ok; resourceId;
      clientId; principalId; reason }.
    #>
    param([Parameter(Mandatory)][object]$App, [string]$ResourceId = '')
    $ua = $null
    if ($App.identity -and $App.identity.PSObject.Properties['userAssignedIdentities']) { $ua = $App.identity.userAssignedIdentities }
    $ids = @(if ($ua) { @($ua.PSObject.Properties | ForEach-Object { [pscustomobject]@{ id = "$($_.Name)"; clientId = "$($_.Value.clientId)"; principalId = "$($_.Value.principalId)" } }) })
    if ($ids.Count -eq 0) { return @{ ok = $false; resourceId = ''; clientId = ''; principalId = ''; reason = 'the Manager has no user-assigned managed identity -- its web identity must exist before the sign-in front' } }
    $pick = $null
    if ("$ResourceId".Trim()) {
        $pick = @($ids | Where-Object { "$($_.id)".ToLowerInvariant() -eq "$ResourceId".Trim().ToLowerInvariant() }) | Select-Object -First 1
        if (-not $pick) { return @{ ok = $false; resourceId = ''; clientId = ''; principalId = ''; reason = "-WebIdentityResourceId '$ResourceId' is not attached to the Manager (attached: $(($ids | ForEach-Object { $_.id }) -join ', '))" } }
    } elseif ($ids.Count -eq 1) { $pick = $ids[0] }
    else { return @{ ok = $false; resourceId = ''; clientId = ''; principalId = ''; reason = "the Manager carries $($ids.Count) user-assigned identities -- name the web identity with -WebIdentityResourceId ($(($ids | ForEach-Object { $_.id }) -join ', '))" } }
    if (-not "$($pick.clientId)".Trim() -or -not "$($pick.principalId)".Trim()) { return @{ ok = $false; resourceId = "$($pick.id)"; clientId = ''; principalId = ''; reason = 'the web identity carries no clientId / principalId on the app -- read it again after the identity is fully attached' } }
    return @{ ok = $true; resourceId = "$($pick.id)"; clientId = "$($pick.clientId)"; principalId = "$($pick.principalId)"; reason = 'web identity found' }
}

function Get-PimSigninFrontHosts {
    <# PURE. Every public host name the Manager answers on: the ingress FQDN + each custom domain (lower case, unique). #>
    param([Parameter(Mandatory)][object]$App)
    $ing = $null
    if ($App.properties -and $App.properties.configuration) { $ing = $App.properties.configuration.ingress }
    $h = New-Object System.Collections.Generic.List[string]
    if ($ing) {
        if ("$($ing.fqdn)".Trim()) { $h.Add("$($ing.fqdn)".Trim().ToLowerInvariant()) }
        foreach ($d in @($ing.customDomains)) { if ($d -and "$($d.name)".Trim()) { $h.Add("$($d.name)".Trim().ToLowerInvariant()) } }
    }
    return @($h | Select-Object -Unique)
}

function Get-PimSigninFrontFicSpec {
    <# PURE. The federated identity credential the front's client assertion needs (README "Setup" step 2). #>
    param([Parameter(Mandatory)][string]$TenantId, [Parameter(Mandatory)][string]$PrincipalId)
    return [ordered]@{
        name        = 'signin-front-web-identity'
        issuer      = "https://login.microsoftonline.com/$TenantId/v2.0"
        subject     = "$PrincipalId"
        audiences   = @('api://AzureADTokenExchange')
        description = 'PIM Manager sign-in front (CR7): the web identity is the client credential -- no secret.'
    }
}

function Test-PimSigninFrontFicPresent {
    <# PURE. Is a credential with this issuer + subject + audience already on the registration? #>
    param([object[]]$Existing = @(), [Parameter(Mandatory)][object]$Spec)
    foreach ($f in @($Existing)) {
        if (-not $f) { continue }
        if ("$($f.issuer)" -eq "$($Spec.issuer)" -and "$($f.subject)" -eq "$($Spec.subject)" -and (@($f.audiences) -contains 'api://AzureADTokenExchange')) { return $true }
    }
    return $false
}

function New-PimSigninFrontTemplate {
    <#
      PURE. The two-container revision template from the Manager's CURRENT template (deep copy; the input is not touched):
        * 'signin-front': -FrontImage, the SIGNIN_* settings, 0.25 CPU / 0.5Gi, liveness + readiness GET /healthz :8080.
        * the Manager container (the one that is not the front): PIM_HOSTED_AUTH_LAYER=signin-front,
          PIM_SIGNIN_FRONT_CLIENT_ID=<client id>, PORT=<UpstreamPort> (WEBSITES_PORT dropped: it would win over PORT and
          collide with the front), its own probes REMOVED (it listens on 127.0.0.1, a probe from outside cannot reach it).
          Every other env var, secret ref, image, volume mount and size is kept as read.
        * scale: minReplicas = maxReplicas = 1 (the front keeps its keys + token cache in memory -- README "Known limits");
          any other scale rule is kept.
    #>
    param([Parameter(Mandatory)][object]$Template, [Parameter(Mandatory)][string]$FrontImage, [Parameter(Mandatory)][string]$TenantId,
          [Parameter(Mandatory)][string]$ClientId, [Parameter(Mandatory)][string]$MiClientId, [int]$UpstreamPort = 8081, [int]$SessionHours = 8,
          # front 1.3.0+ (framework 12.11g item 9): the Key Vault key that wraps the front's keys; the SQL server + database are
          # the Manager's own (PIM_SqlServer / PIM_SqlDatabase). 1.3.0+ refuses to start without them -- so does this template.
          [string]$KeyVaultKeyId = '',
          # 1.4.0+ access-token mode: SIGNIN_UPSTREAM_SCOPE = api://<ClientId>/<scope> (the front refuses any other client id)
          [string]$UpstreamScope = '')
    $us = "$UpstreamScope".Trim()
    if ($us -and $us -notmatch ('^(?i)api://' + [regex]::Escape("$ClientId".Trim()) + '/[A-Za-z0-9_.-]+$')) { throw "-UpstreamScope '$us' must be api://$ClientId/<scope> (this app's own scope)" }
    $t = ($Template | ConvertTo-Json -Depth 30 | ConvertFrom-Json)
    $cs = @(@($t.containers) | Where-Object { $_ })
    $mgr = @($cs | Where-Object { "$($_.name)" -ne $script:SfFrontName })
    if ($mgr.Count -ne 1) { throw "the Manager's template has $($mgr.Count) non-front containers -- expected exactly one (the Manager)" }
    $m = $mgr[0]
    $stateEnv = @()
    $mEnvOf = { param($n) "$(@(@($m.env) | Where-Object { $_ -and "$($_.name)" -eq $n } | ForEach-Object { $_.value }) | Select-Object -First 1)".Trim() }
    if ("$KeyVaultKeyId".Trim()) {
        $stateEnv = @(
            [pscustomobject]@{ name = 'SIGNIN_SQL_SERVER'; value = (& $mEnvOf 'PIM_SqlServer') }
            [pscustomobject]@{ name = 'SIGNIN_SQL_DATABASE'; value = (& $mEnvOf 'PIM_SqlDatabase') }
            [pscustomobject]@{ name = 'SIGNIN_KEYVAULT_KEY_ID'; value = "$KeyVaultKeyId".Trim() })
        if (@($stateEnv | Where-Object { -not "$($_.value)" }).Count) { throw "the Manager carries no PIM_SqlServer / PIM_SqlDatabase -- the front's state cannot be placed" }
    }
    $fv = if ("$FrontImage" -match ':(\d+\.\d+\.\d+)$') { [version]$Matches[1] } else { $null }
    if ($fv -and $fv -ge [version]'1.3.0' -and -not $stateEnv.Count) { throw "front $fv needs its state settings: pass -KeyVaultKeyId (run Set-PimSigninFrontState first)" }
    $set = [ordered]@{ PIM_HOSTED_AUTH_LAYER = 'signin-front'; PIM_SIGNIN_FRONT_CLIENT_ID = "$ClientId"; PORT = "$UpstreamPort" }
    $env = New-Object System.Collections.Generic.List[object]
    foreach ($e in @($m.env)) { if ($e -and -not $set.Contains("$($e.name)") -and "$($e.name)" -ne 'WEBSITES_PORT') { $env.Add($e) } }
    foreach ($k in $set.Keys) { $env.Add([pscustomobject]@{ name = $k; value = "$($set[$k])" }) }
    $m | Add-Member -NotePropertyName env -NotePropertyValue @($env.ToArray()) -Force
    $m | Add-Member -NotePropertyName probes -NotePropertyValue @() -Force
    # Live 2026-10-18 (ring-1 test install: HTTP 400 ContainerAppInvalidResourceTotal): an app's containers share the
    # Consumption maximum, 4.0 CPU / 8.0Gi. The front takes 0.25 / 0.5Gi, so the Manager keeps at most 3.75 / 7.5Gi -- a
    # smaller Manager is kept as it is. The updater's sizing step applies the same cap (Get-PimManagerAppResize).
    $mCpu = 0.0; $mMem = 0.0
    if ($m.resources) { try { $mCpu = [double]("$($m.resources.cpu)" -replace '[^0-9.]', '') } catch { $mCpu = 0.0 }; try { $mMem = [double]("$($m.resources.memory)" -replace '[^0-9.]', '') } catch { $mMem = 0.0 } }
    if ($mCpu -gt 3.75 -or $mMem -gt 7.5 -or $mCpu -le 0 -or $mMem -le 0) {
        if ($null -eq $m.resources) { $m | Add-Member -NotePropertyName resources -NotePropertyValue ([pscustomobject]@{}) -Force }
        $m.resources | Add-Member -NotePropertyName cpu -NotePropertyValue $(if ($mCpu -gt 0) { [Math]::Min($mCpu, 3.75) } else { 3.75 }) -Force
        $m.resources | Add-Member -NotePropertyName memory -NotePropertyValue ('{0}Gi' -f ($(if ($mMem -gt 0) { [Math]::Min($mMem, 7.5) } else { 7.5 })).ToString('0.0#', [Globalization.CultureInfo]::InvariantCulture)) -Force
    }
    $probe = { param($type) [pscustomobject][ordered]@{ type = $type; httpGet = [pscustomobject][ordered]@{ path = '/healthz'; port = $script:SfFrontPort; scheme = 'HTTP' }; initialDelaySeconds = 3; periodSeconds = 10; failureThreshold = 3; timeoutSeconds = 3 } }
    $front = [pscustomobject][ordered]@{
        name      = $script:SfFrontName
        image     = "$FrontImage"
        resources = [pscustomobject][ordered]@{ cpu = 0.25; memory = '0.5Gi' }
        env       = @(
            [pscustomobject]@{ name = 'SIGNIN_TENANT_ID'; value = "$TenantId" }
            [pscustomobject]@{ name = 'SIGNIN_CLIENT_ID'; value = "$ClientId" }
            [pscustomobject]@{ name = 'SIGNIN_FIC_MI_CLIENT_ID'; value = "$MiClientId" }
            [pscustomobject]@{ name = 'SIGNIN_UPSTREAM_PORT'; value = "$UpstreamPort" }
            [pscustomobject]@{ name = 'SIGNIN_SESSION_HOURS'; value = "$SessionHours" }
            [pscustomobject]@{ name = 'SIGNIN_BEARER_PATHS'; value = '/mcp,/.well-known' }
            [pscustomobject]@{ name = 'ASPNETCORE_HTTP_PORTS'; value = "$($script:SfFrontPort)" }
        ) + $stateEnv + @(if ($us) { [pscustomobject]@{ name = 'SIGNIN_UPSTREAM_SCOPE'; value = $us } })
        probes    = @((& $probe 'Liveness'), (& $probe 'Readiness'))
    }
    $t | Add-Member -NotePropertyName containers -NotePropertyValue @($front, $m) -Force
    if ($null -eq $t.scale) { $t | Add-Member -NotePropertyName scale -NotePropertyValue ([pscustomobject]@{}) -Force }
    $t.scale | Add-Member -NotePropertyName minReplicas -NotePropertyValue 1 -Force
    $t.scale | Add-Member -NotePropertyName maxReplicas -NotePropertyValue 1 -Force
    return $t
}

function Test-PimSigninFrontLive {
    <# PURE. Is the front live on this app: a 'signin-front' container in the template AND Easy Auth off? #>
    param([Parameter(Mandatory)][object]$App, [AllowNull()][object]$Auth)
    $hasFront = [bool](@(@($App.properties.template.containers) | Where-Object { $_ -and "$($_.name)" -eq $script:SfFrontName }).Count)
    $eaOn = $false
    if ($Auth -and $Auth.PSObject.Properties['platform'] -and $Auth.platform -and $Auth.platform.PSObject.Properties['enabled']) { $eaOn = [bool]$Auth.platform.enabled }
    return ($hasFront -and -not $eaOn)
}

function Get-PimSigninFrontSecretPlan {
    <#
      PURE. Which password credentials -DeleteSecret removes: the Easy Auth ones only ('easyauth*' display names, which
      Set-PimManagerEasyAuth mints). Anything else on the registration may belong to something that works -- listed,
      never removed. @{ remove = @(keyId, name); keep = @(...) }.
    #>
    param([object[]]$PasswordCredentials = @())
    $rm = @(); $keep = @()
    foreach ($p in @($PasswordCredentials)) {
        if (-not $p) { continue }
        $o = [pscustomobject]@{ keyId = "$($p.keyId)"; name = "$($p.displayName)"; ends = "$($p.endDateTime)" }
        if ("$($p.displayName)" -match '^(?i)easyauth') { $rm += $o } else { $keep += $o }
    }
    return @{ remove = @($rm); keep = @($keep) }
}

function Test-PimSigninFrontRevisionReady {
    <#
      PURE. Does the app serve the two-container revision NOW: the latest revision is the latest READY one, and its template
      carries the front. Live 2026-10-18 (ring-1 test install): the front revision became Healthy, but the read-back 20 s after
      the write still reached the OLD Manager-only revision (/healthz 404) -- so the switch waits on this, with Easy Auth ON.
    #>
    param([AllowNull()][object]$App)
    if (-not $App -or -not $App.properties) { return $false }
    $latest = "$($App.properties.latestRevisionName)"; $ready = "$($App.properties.latestReadyRevisionName)"
    if (-not $latest.Trim() -or $latest -ne $ready) { return $false }
    return [bool](@(@($App.properties.template.containers) | Where-Object { $_ -and "$($_.name)" -eq $script:SfFrontName }).Count)
}

function Test-PimSfBusy {
    <#
      PURE. Must the move wait before it changes the Manager? Yes while the updater run it started is still going (Running /
      Processing) or the container app is provisioning (InProgress, or not read = unknown = wait). A finished run (Succeeded /
      Failed / Stopped / Degraded) or none, on an app that is Succeeded / Failed / Canceled, is not busy.
    #>
    param([string]$ExecutionStatus = '', [string]$ProvisioningState = 'Succeeded')
    if ("$ExecutionStatus".Trim() -in @('Running', 'Processing')) { return $true }
    $p = "$ProvisioningState".Trim()
    return (-not $p -or $p -in @('InProgress', 'Updating', 'Provisioning', 'Deleting'))
}

function Test-PimSfOperationInProgress {
    <# PURE. Is this ARM error the transient "another operation on the app is running" (409 ContainerAppOperationInProgress)? #>
    param([string]$Message = '')
    return ("$Message" -match 'HTTP 409' -and "$Message" -match 'ContainerAppOperationInProgress')
}

function Get-PimSigninFrontProbeVerdict {
    <#
      PURE. The read-back after the switch, from three answers of the live Manager:
        /healthz -> 200; a NAVIGATION to / -> 302 to https://login.microsoftonline.com/<tenant>/oauth2/v2.0/authorize with
        client_id=<this app>, response_type=code, code_challenge_method=S256; a SCRIPT call to /api -> 401.
      Anything else = not proven (the caller rolls back). @{ ok; reason }.
    #>
    param([int]$HealthStatus, [int]$RootStatus, [string]$RootLocation = '', [int]$ApiStatus, [Parameter(Mandatory)][string]$TenantId, [Parameter(Mandatory)][string]$ClientId)
    if ($HealthStatus -ne 200) { return @{ ok = $false; reason = "/healthz answered $HealthStatus, not 200 -- the front is not serving" } }
    if ($RootStatus -ne 302) { return @{ ok = $false; reason = "/ answered $RootStatus, not 302 to the sign-in -- a page without a sign-in in front of it is never accepted" } }
    $loc = "$RootLocation"
    if ($loc -notlike "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/authorize*") { return @{ ok = $false; reason = "/ redirects to '$loc', not to this tenant's authorize endpoint" } }
    foreach ($need in @("client_id=$ClientId", 'response_type=code', 'code_challenge=', 'code_challenge_method=S256')) {
        if ($loc -notlike "*$need*") { return @{ ok = $false; reason = "the sign-in redirect lacks '$need' (code flow + PKCE for this app is required)" } }
    }
    if ($loc -like '*response_type=code%20id_token*' -or $loc -like '*client_secret*') { return @{ ok = $false; reason = 'the sign-in redirect is not the pure code flow' } }
    if ($ApiStatus -ne 401) { return @{ ok = $false; reason = "/api answered $ApiStatus to a script call without a session, not 401" } }
    return @{ ok = $true; reason = 'front serving; navigation -> this tenant, code + PKCE, this client; /api -> 401' }
}

function Get-PimSigninFrontPlan {
    <#
      PURE. What -Apply would do, from what is read: the container app (-App), its auth config (-Auth), the registration
      (-AppReg), its federated credentials (-Fics), whether User.Read is already consented (-UserReadGranted) and on the
      registration (-UserReadRequired), the web identity (-Identity, Get-PimSigninFrontWebIdentity) and -FrontImage.
      @{ ok; steps; reason; live }.
    #>
    param([Parameter(Mandatory)][object]$App, [AllowNull()][object]$Auth, [AllowNull()][object]$AppReg, [object[]]$Fics = @(),
          [bool]$UserReadRequired = $false, [bool]$UserReadGranted = $false, [Parameter(Mandatory)][hashtable]$Identity,
          [string]$FrontImage = '', [Parameter(Mandatory)][string]$TenantId,
          # PIM 100.168: $false = the front image is not in the registry yet -> 'front-image' comes FIRST (the updater builds it)
          [bool]$FrontImageReady = $true)
    $live = Test-PimSigninFrontLive -App $App -Auth $Auth
    if ($live) { return @{ ok = $true; steps = @(); live = $true; reason = 'the sign-in front is already live (front container in the revision, Easy Auth off)' } }
    if (-not $AppReg) { return @{ ok = $false; steps = @(); live = $false; reason = 'the Manager has no Easy Auth application -- there is nothing to move (install the Manager first)' } }
    if (-not $Identity.ok) { return @{ ok = $false; steps = @(); live = $false; reason = "$($Identity.reason)" } }
    if (-not "$FrontImage".Trim()) { return @{ ok = $false; steps = @(); live = $false; reason = '-FrontImage is required: the signin-front image at the version PIM pins (tools/pim-manager/signin-front.version)' } }
    if ("$FrontImage" -notmatch '(?i)signin-front(:[0-9]+\.[0-9]+\.[0-9]+|@sha256:[0-9a-f]{64})$') { return @{ ok = $false; steps = @(); live = $false; reason = "-FrontImage '$FrontImage' must be a signin-front image pinned to a version tag or a digest -- never 'latest'" } }
    $hosts = @(Get-PimSigninFrontHosts -App $App)
    if (-not $hosts.Count) { return @{ ok = $false; steps = @(); live = $false; reason = 'the Manager has no ingress FQDN -- the sign-in needs a public (or private) host name for its redirect URI' } }
    $steps = New-Object System.Collections.Generic.List[string]
    if (-not $FrontImageReady) { $steps.Add('front-image') | Out-Null }
    $spec = Get-PimSigninFrontFicSpec -TenantId $TenantId -PrincipalId "$($Identity.principalId)"
    if (-not (Test-PimSigninFrontFicPresent -Existing @($Fics) -Spec $spec)) { $steps.Add('federated-credential') | Out-Null }
    $haveUris = @(if ($AppReg.web -and $AppReg.web.redirectUris) { @($AppReg.web.redirectUris) })
    if (@($hosts | Where-Object { $haveUris -notcontains "https://$_/signin-oidc" }).Count) { $steps.Add('redirect-uris') | Out-Null }
    if (-not $UserReadRequired) { $steps.Add('user-read-permission') | Out-Null }
    if (-not $UserReadGranted) { $steps.Add('user-read-consent') | Out-Null }
    $steps.Add('revision') | Out-Null
    $steps.Add('easy-auth-off') | Out-Null
    $steps.Add('read-back') | Out-Null
    return @{ ok = $true; steps = @($steps); live = $false; hosts = $hosts; fic = $spec; reason = "to do: $($steps -join ', ')" }
}

function Get-PimSigninFrontDefaultImage {
    <#
      PURE. PIM 100.168: the front image this install's OWN updater builds -- <the Manager's registry>/signin-front:<pin>,
      the registry read from the Manager container's image (the container that is not 'signin-front'). @{ ok; image;
      loginServer; registry; reason }. Never 'latest': -Pinned must be a version.
    #>
    param([Parameter(Mandatory)][object]$App, [AllowEmptyString()][string]$Pinned = '')
    $no = @{ ok = $false; image = ''; loginServer = ''; registry = '' }
    if ("$Pinned".Trim() -notmatch '^[0-9]+\.[0-9]+\.[0-9]+$') { $no.reason = 'this script''s tree pins no sign-in front version (tools/pim-manager/signin-front.version) -- pass -FrontImage'; return $no }
    $cs = @(@($App.properties.template.containers) | Where-Object { $_ -and "$($_.name)" -ne $script:SfFrontName })
    if ($cs.Count -ne 1) { $no.reason = "the Manager's template has $($cs.Count) non-front containers -- pass -FrontImage"; return $no }
    $img = "$($cs[0].image)".Trim()
    $slash = $img.IndexOf('/')
    if ($slash -lt 1) { $no.reason = "the Manager's image '$img' names no registry -- pass -FrontImage"; return $no }
    $ls = $img.Substring(0, $slash).ToLowerInvariant()
    if ($ls -notmatch '\.azurecr\.io$') { $no.reason = "the Manager's registry '$ls' is not an Azure container registry the updater builds in -- pass -FrontImage"; return $no }
    return @{ ok = $true; image = "$ls/$($script:SfFrontName):$("$Pinned".Trim())"; loginServer = $ls; registry = ($ls -replace '\.azurecr\.io$', ''); reason = 'built by this install''s updater' }
}

function Get-PimSigninFrontImageProbeVerdict {
    <#
      PURE. Is the front image there yet? From one probe: -Digest (the registry's digest for the tag, '' = not seen), -Recorded
      (the updater's PIM_SIGNIN_FRONT_BUILT), -Pinned, -RunStatus (the started updater execution's status, '' = unknown).
      @{ ready; done; reason }: ready = the image exists; done = stop waiting (ready, or the run ended without it).
    #>
    param([AllowEmptyString()][string]$Digest = '', [AllowEmptyString()][string]$Recorded = '', [Parameter(Mandatory)][string]$Pinned, [AllowEmptyString()][string]$RunStatus = '')
    if ("$Digest".Trim()) { return @{ ready = $true; done = $true; reason = "signin-front:$Pinned is in the registry ($("$Digest".Trim()))" } }
    if ("$Recorded".Trim() -eq "$Pinned".Trim()) { return @{ ready = $true; done = $true; reason = "the updater recorded signin-front:$Pinned as built (PIM_SIGNIN_FRONT_BUILT)" } }
    if ("$RunStatus".Trim() -match '^(?i)(Succeeded|Failed|Stopped|Degraded|Canceled)$') {
        return @{ ready = $false; done = $true; reason = "the updater run ended '$RunStatus' and signin-front:$Pinned is not there -- read that run's log ('sign-in front image: ...' says why)" }
    }
    return @{ ready = $false; done = $false; reason = "waiting for signin-front:$Pinned (updater run: $(if ("$RunStatus".Trim()) { $RunStatus } else { 'not started / unknown' }))" }
}

function Wait-PimSigninFrontImage {
    <#
      Wait for the front image: -Probe { } -> @{ Digest; Recorded; RunStatus } each -PollSeconds, up to -TimeoutSeconds.
      -Sleep is a test seam. @{ ready; reason; polls }. Never throws.
    #>
    param([Parameter(Mandatory)][scriptblock]$Probe, [Parameter(Mandatory)][string]$Pinned, [int]$TimeoutSeconds = 3600, [int]$PollSeconds = 30, [scriptblock]$Sleep)
    if (-not $Sleep) { $Sleep = { param($s) Start-Sleep -Seconds $s } }
    $waited = 0; $polls = 0; $last = $null
    while ($true) {
        $p = $null; try { $p = & $Probe } catch { $p = $null }
        $polls++
        $last = Get-PimSigninFrontImageProbeVerdict -Digest "$($p.Digest)" -Recorded "$($p.Recorded)" -Pinned $Pinned -RunStatus "$($p.RunStatus)"
        if ($last.done) { return @{ ready = $last.ready; reason = $last.reason; polls = $polls } }
        if ($waited -ge $TimeoutSeconds) { return @{ ready = $false; reason = "signin-front:$Pinned was not there after $([int]($TimeoutSeconds / 60)) minutes ($($last.reason))"; polls = $polls } }
        & $Sleep $PollSeconds
        $waited += $PollSeconds
    }
}

if ($MyInvocation.InvocationName -eq '.') { return }

# ---- LIVE --------------------------------------------------------------------------------------------------------------
function Step($m) { Write-Host "==> $m" -ForegroundColor Cyan }
function Note($m) { Write-Host "    $m" -ForegroundColor DarkGray }
function Warn($m) { Write-Host "    $m" -ForegroundColor Yellow }

if (@($Apply, $Rollback, $DeleteSecret | Where-Object { $_ }).Count -gt 1) { throw 'choose ONE of -Apply, -Rollback, -DeleteSecret' }
if (-not "$($global:PIM_SetupRestMode)".Trim()) { [void](Connect-PimSetupRest -SubscriptionId $SubscriptionId -TenantId $TenantId) }
elseif ("$($global:PIM_TenantId)".Trim() -and "$($global:PIM_TenantId)".Trim().ToLowerInvariant() -ne "$TenantId".Trim().ToLowerInvariant()) {
    throw "the REST session in this shell is for tenant '$($global:PIM_TenantId)', not '$TenantId' -- refusing."
}

function Get-PimSfAuth {
    $r = Get-PimArmAcaAuthConfig -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $ManagerApp
    if ($r -and $r.properties) { return $r.properties }
    return $null
}
function Set-PimSfEasyAuth([bool]$Enabled) {
    [void](Set-PimArmAcaAuthConfig -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $ManagerApp -Mutate {
        param($p)
        if ($null -eq $p.platform) { $p | Add-Member -NotePropertyName platform -NotePropertyValue ([pscustomobject]@{}) -Force }
        $p.platform | Add-Member -NotePropertyName enabled -NotePropertyValue $Enabled -Force
    }.GetNewClosure())
}
function Invoke-PimSfProbe([string]$Url, [hashtable]$Headers = @{}) {
    # One request, NO redirect following (HttpClient: the same on PS 5.1 and 7). @{ status; location }.
    try { Add-Type -AssemblyName System.Net.Http -ErrorAction SilentlyContinue } catch { }
    $h = New-Object System.Net.Http.HttpClientHandler
    $h.AllowAutoRedirect = $false
    $c = New-Object System.Net.Http.HttpClient($h)
    $c.Timeout = [TimeSpan]::FromSeconds(30)
    try {
        $req = New-Object System.Net.Http.HttpRequestMessage([System.Net.Http.HttpMethod]::Get, $Url)
        foreach ($k in $Headers.Keys) { [void]$req.Headers.TryAddWithoutValidation($k, "$($Headers[$k])") }
        $r = $c.SendAsync($req).GetAwaiter().GetResult()
        $loc = ''; if ($r.Headers.Location) { $loc = "$($r.Headers.Location)" }
        return @{ status = [int]$r.StatusCode; location = $loc }
    } catch { return @{ status = 0; location = "$($_.Exception.Message)" } }
    finally { $c.Dispose() }
}
function Invoke-PimSfRollback([object]$Saved) {
    Step 'ROLLBACK: Easy Auth ON first (the Manager is never without a sign-in), then the saved revision template back'
    Set-PimSfEasyAuth -Enabled $true
    [void](Set-PimArmAcaApp -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $ManagerApp -Resource @{ properties = @{ template = $Saved.app.properties.template } })
    $tp = $Saved.app.properties.configuration.ingress.targetPort
    if ($tp) { [void](Set-PimArmAcaAppConfiguration -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $ManagerApp -Mutate { param($cfg) $cfg.ingress.targetPort = $tp }.GetNewClosure()) }
    Note "rolled back to the template saved at $($Saved.savedUtc). Old revision kept by Container Apps: $($Saved.app.properties.latestRevisionName)"
}

$ca = Get-PimArmAcaApp -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $ManagerApp
if (-not $ca) { throw "container app $ManagerApp not found in $ResourceGroup" }
$auth = Get-PimSfAuth

if ($Rollback) {
    if (-not "$StateFile".Trim() -or -not (Test-Path -LiteralPath $StateFile)) { throw '-Rollback needs -StateFile <the file -Apply wrote>' }
    $saved = Get-Content -LiteralPath $StateFile -Raw | ConvertFrom-Json
    $appIdRb = "$($saved.auth.identityProviders.azureActiveDirectory.registration.clientId)".Trim()
    if ($appIdRb) {
        $regRb = Get-PimGraphApplication -Id $appIdRb
        if ($regRb -and -not @(@($regRb.passwordCredentials) | Where-Object { $_ }).Count) { throw "the registration $appIdRb has no client secret any more (-DeleteSecret ran) -- Easy Auth could not sign anyone in; a rollback would lock the Manager. Fix forward, or mint a secret with Set-PimManagerEasyAuth.ps1 -RotateSecret first." }
    }
    Invoke-PimSfRollback -Saved $saved
    return
}

$appId = "$($auth.identityProviders.azureActiveDirectory.registration.clientId)".Trim()
$reg = $(if ($appId) { Get-PimGraphApplication -Id $appId } else { $null })

if ($DeleteSecret) {
    if (-not (Test-PimSigninFrontLive -App $ca -Auth $auth)) { throw 'the sign-in front is not live on this Manager (front container + Easy Auth off) -- -DeleteSecret is refused: Easy Auth still needs its secret' }
    if (-not $reg) { throw 'the Manager names no application registration -- nothing to clean' }
    $sp = Get-PimSigninFrontSecretPlan -PasswordCredentials @($reg.passwordCredentials)
    foreach ($k in $sp.keep) { Warn "kept (not an Easy Auth secret -- review it yourself): '$($k.name)' $($k.keyId) ends $($k.ends)" }
    if (-not $sp.remove.Count) { Step 'no Easy Auth client secret left on the registration'; return $sp }
    foreach ($r in $sp.remove) {
        Step "remove the Easy Auth client secret '$($r.name)' ($($r.keyId)) from $appId"
        [void](Invoke-PimSetupGraph -Method POST -Path "/applications/$($reg.id)/removePassword" -Body @{ keyId = "$($r.keyId)" })
    }
    $reg2 = Get-PimGraphApplication -Id $appId
    $left = @((Get-PimSigninFrontSecretPlan -PasswordCredentials @($reg2.passwordCredentials)).remove)
    if ($left.Count) { throw "read-back: $($left.Count) Easy Auth secret(s) still on the registration" }
    Step 'done: no Easy Auth client secret on the registration. The Container App secret that held it is now a dead value.'
    return $sp
}

$identity = Get-PimSigninFrontWebIdentity -App $ca -ResourceId $WebIdentityResourceId
$fics = @(); $userReadRequired = $false; $userReadGranted = $false; $graphSp = $null; $appSp = $null; $userReadId = ''
if ($reg) {
    $fics = @(Invoke-PimSetupGraph -Path "/applications/$($reg.id)/federatedIdentityCredentials" -All -ErrorAsNull)
    $graphSp = Invoke-PimSetupGraph -Path "/servicePrincipals(appId='$($script:SfGraphAppId)')?`$select=id,oauth2PermissionScopes"
    $userReadId = "$(@(@($graphSp.oauth2PermissionScopes) | Where-Object { "$($_.value)" -eq 'User.Read' })[0].id)"
    $gr = @(@($reg.requiredResourceAccess) | Where-Object { "$($_.resourceAppId)" -eq $script:SfGraphAppId })
    $userReadRequired = [bool](@($gr | ForEach-Object { @($_.resourceAccess) } | Where-Object { "$($_.id)" -eq $userReadId -and "$($_.type)" -eq 'Scope' }).Count)
    $appSp = Invoke-PimSetupGraph -Path "/servicePrincipals(appId='$appId')" -NotFoundOk
    if ($appSp) {
        $grants = @(Invoke-PimSetupGraph -Path "/oauth2PermissionGrants?`$filter=$([uri]::EscapeDataString("clientId eq '$($appSp.id)' and resourceId eq '$($graphSp.id)'"))" -All -ErrorAsNull)
        $userReadGranted = [bool](@($grants | Where-Object { $_ -and "$($_.consentType)" -eq 'AllPrincipals' -and (@("$($_.scope)" -split '\s+') -contains 'User.Read') }).Count)
    }
}
# ---- PIM 100.168: THE FRONT IMAGE -- built by this install's own updater, in its own registry, at the pinned version -------
$sfPinned = "$(Get-Content -LiteralPath (Join-Path $solRootSf 'tools\pim-manager\signin-front.version') -Raw -ErrorAction SilentlyContinue)".Trim()
$sfDefault = $null; $frontReady = $true; $sfExec = ''
$sfProbe = { param($execName) @{ Digest = ''; Recorded = ''; RunStatus = '' } }
if (-not "$FrontImage".Trim() -and -not (Test-PimSigninFrontLive -App $ca -Auth $auth)) {
    $sfDefault = Get-PimSigninFrontDefaultImage -App $ca -Pinned $sfPinned
    if (-not $sfDefault.ok) { throw "Set-PimManagerSigninFront: $($sfDefault.reason)" }
    $FrontImage = $sfDefault.image
    $sfProbe = {
        param($execName)
        $dg = Get-PimAcrImageDigest -Registry $sfDefault.registry -Repository $script:SfFrontName -Tag $sfPinned -LoginServer $sfDefault.loginServer
        $rec = ''
        $uj = Get-PimArmAcaJob -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $UpdateJob -ErrorAsNull
        if ($uj) { foreach ($c in @($uj.properties.template.containers)) { foreach ($e in @($c.env)) { if ($e -and "$($e.name)" -eq 'PIM_SIGNIN_FRONT_BUILT') { $rec = "$($e.value)" } } } }
        $st = ''
        if ("$execName".Trim()) { $ex = Get-PimArmAcaJobExecution -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $UpdateJob -Execution "$execName"; if ($ex) { $st = "$($ex.properties.status)" } }
        @{ Digest = "$dg"; Recorded = $rec; RunStatus = $st }
    }
    $p0 = & $sfProbe ''
    $first = Get-PimSigninFrontImageProbeVerdict -Digest "$($p0.Digest)" -Recorded "$($p0.Recorded)" -Pinned $sfPinned
    $frontReady = [bool]$first.ready
    Write-Host "==> front image $FrontImage : $(if ($frontReady) { $first.reason } else { "not in the registry yet -- $UpdateJob builds it (PIM_BUILD_SIGNIN_FRONT=1, one updater run)" })" -ForegroundColor Cyan
}
$plan = Get-PimSigninFrontPlan -App $ca -Auth $auth -AppReg $reg -Fics $fics -UserReadRequired $userReadRequired -UserReadGranted $userReadGranted -Identity $identity -FrontImage $FrontImage -TenantId $TenantId -FrontImageReady $frontReady
Write-Host "==> $ManagerApp / application $appId : $($plan.reason)" -ForegroundColor Cyan
if ($plan.ok -and @($plan.steps) -contains 'front-image') {
    Write-Host ("    front-image: set PIM_BUILD_SIGNIN_FRONT=1 on $UpdateJob, " + $(if ($NoUpdaterRun) { 'YOU start one updater run' } else { 'start one updater run' }) +
                ", wait up to $FrontImageWaitMinutes min for $FrontImage -- nothing on the Manager changes before it is there") -ForegroundColor DarkGray
}
if (-not $plan.ok) { throw $plan.reason }
if (-not $plan.steps.Count) { return $plan }
if (-not $Apply) { Write-Host '    PLAN ONLY -- re-run with -Apply (coordinated with the customer; the Manager signs everyone in again after the switch).' -ForegroundColor Yellow; return $plan }

# ---- APPLY -------------------------------------------------------------------------------------------------------------
if ($plan.steps -contains 'front-image') {
    # PIM 100.168: the image FIRST, and nothing on the Manager changes until it is there. The flag only makes the updater
    # build the front image (engine/_shared/PIM-SigninFrontImage.ps1); its Manager update is otherwise its normal run.
    Step "front image: PIM_BUILD_SIGNIN_FRONT=1 on $UpdateJob (its updater builds $FrontImage in this install's registry)"
    [void](Set-PimArmAcaJobEnvVars -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $UpdateJob -Env @{ PIM_BUILD_SIGNIN_FRONT = '1' })
    $sfExec = ''
    if ($NoUpdaterRun) {
        Warn "start ONE run of $UpdateJob now (portal: Container Apps job $UpdateJob > Run now) -- this script waits for the image"
    } else {
        $sfExec = Start-PimArmAcaJob -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $UpdateJob
        if (-not $sfExec) { throw "Set-PimManagerSigninFront: $UpdateJob could not be started ($($global:PimSetupRestLastError)) -- start it yourself and re-run with -NoUpdaterRun. Nothing on the Manager changed." }
        Note "updater run $sfExec started"
    }
    $sfWait = Wait-PimSigninFrontImage -Probe { & $sfProbe $sfExec } -Pinned $sfPinned -TimeoutSeconds ($FrontImageWaitMinutes * 60) -PollSeconds 30
    if (-not $sfWait.ready) { throw "Set-PimManagerSigninFront: the front image is not there -- $($sfWait.reason). Nothing on the Manager changed; re-run when it is." }
    Step "front image ready: $($sfWait.reason)"
}
# 🔴 2026-10-20 fleet run (invardiademo, efif-rideakademiet-test): the updater run that builds the front image ALSO rolls the
# Manager when a newer version is released -- the image was ready while that roll was still provisioning, the revision PATCH
# got 409 ContainerAppOperationInProgress and the move rolled back. Worse, $ca was read BEFORE that run: the two-container
# template and the rollback record would have carried the OLD Manager image and silently undone the roll. So: wait until the
# updater run has ended and the app is not provisioning, THEN read the app again -- everything below works on that read.
if ($plan.steps -contains 'front-image' -or (Test-PimSfBusy -ProvisioningState "$($ca.properties.provisioningState)")) {
    $busyBy = [datetime]::UtcNow.AddMinutes($FrontImageWaitMinutes); $waited = $false
    while ($true) {
        $exSt = ''
        if ($sfExec) { $ex = Get-PimArmAcaJobExecution -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $UpdateJob -Execution "$sfExec"; if ($ex) { $exSt = "$($ex.properties.status)" } }
        $cur = $null; try { $cur = Get-PimArmAcaApp -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $ManagerApp } catch { }
        $pv = if ($cur) { "$($cur.properties.provisioningState)" } else { 'InProgress' }
        if (-not (Test-PimSfBusy -ExecutionStatus $exSt -ProvisioningState $pv)) { break }
        if ([datetime]::UtcNow -ge $busyBy) { throw "Set-PimManagerSigninFront: the updater run '$sfExec' ($exSt) / the Manager ($pv) is still busy after $FrontImageWaitMinutes min. Nothing on the Manager changed; re-run when it is done." }
        if (-not $waited) { Note "waiting for the updater run ($exSt) and the Manager ($pv) to finish before the Manager is changed"; $waited = $true }
        Start-Sleep -Seconds 20
    }
    $ca = Get-PimArmAcaApp -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $ManagerApp
    $auth = Get-PimSfAuth
    Note "Manager read again after the updater run: $((@($ca.properties.template.containers) | ForEach-Object { ("$($_.image)" -split '/')[-1] }) -join ' + ')"
}
if (-not "$StateFile".Trim()) { $StateFile = Join-Path ([IO.Path]::GetTempPath()) ("pim-signin-front-$ManagerApp-" + (Get-Date).ToUniversalTime().ToString('yyyyMMddHHmmss') + '.json') }
$saved = [ordered]@{ savedUtc = (Get-Date).ToUniversalTime().ToString('o'); app = $ca; auth = $auth }
$saved | ConvertTo-Json -Depth 40 | Set-Content -LiteralPath $StateFile -Encoding UTF8
Step "rollback state saved: $StateFile  (undo: -Rollback -StateFile `"$StateFile`")"

if ($plan.steps -contains 'federated-credential') {
    Step "federated credential: the web identity $($identity.principalId) on application $appId"
    [void](Invoke-PimSetupGraph -Method POST -Path "/applications/$($reg.id)/federatedIdentityCredentials" -Body $plan.fic)
}
if ($plan.steps -contains 'redirect-uris') {
    $uris = @(@(@($reg.web.redirectUris) + @($plan.hosts | ForEach-Object { "https://$_/signin-oidc" })) | Where-Object { "$_".Trim() } | Select-Object -Unique)
    Step "redirect URIs: $(@($plan.hosts | ForEach-Object { "https://$_/signin-oidc" }) -join ', ') (existing kept)"
    [void](Invoke-PimSetupGraph -Method PATCH -Path "/applications/$($reg.id)" -Body ([ordered]@{ web = [ordered]@{ redirectUris = @($uris); logoutUrl = "https://$(@($plan.hosts)[0])/signout-callback-oidc" } }))
}
if ($plan.steps -contains 'user-read-permission') {
    Step 'delegated Microsoft Graph User.Read on the registration (the silent ID token refresh)'
    $rra = New-Object System.Collections.Generic.List[object]
    $done = $false
    foreach ($r in @($reg.requiredResourceAccess)) {
        if (-not $r) { continue }
        if ("$($r.resourceAppId)" -eq $script:SfGraphAppId) {
            $acc = @(@($r.resourceAccess) + [pscustomobject]@{ id = $userReadId; type = 'Scope' } | Group-Object { "$($_.id)|$($_.type)" } | ForEach-Object { $_.Group[0] })
            $rra.Add([pscustomobject]@{ resourceAppId = $script:SfGraphAppId; resourceAccess = @($acc) }); $done = $true
        } else { $rra.Add($r) }
    }
    if (-not $done) { $rra.Add([pscustomobject]@{ resourceAppId = $script:SfGraphAppId; resourceAccess = @([pscustomobject]@{ id = $userReadId; type = 'Scope' }) }) }
    [void](Invoke-PimSetupGraph -Method PATCH -Path "/applications/$($reg.id)" -Body @{ requiredResourceAccess = @($rra.ToArray()) })
}
if ($plan.steps -contains 'user-read-consent') {
    if (-not $appSp) { throw "application $appId has no service principal -- run Set-PimManagerEasyAuth.ps1 first" }
    Step 'admin consent: openid profile offline_access User.Read for every user (AllPrincipals)'
    $g = @(Invoke-PimSetupGraph -Path "/oauth2PermissionGrants?`$filter=$([uri]::EscapeDataString("clientId eq '$($appSp.id)' and resourceId eq '$($graphSp.id)'"))" -All -ErrorAsNull) | Where-Object { $_ -and "$($_.consentType)" -eq 'AllPrincipals' } | Select-Object -First 1
    $want = @('openid', 'profile', 'offline_access', 'User.Read')
    if ($g) {
        $sc = @(@("$($g.scope)" -split '\s+' | Where-Object { $_ }) + $want | Select-Object -Unique) -join ' '
        [void](Invoke-PimSetupGraph -Method PATCH -Path "/oauth2PermissionGrants/$($g.id)" -Body @{ scope = $sc })
    } else {
        [void](Invoke-PimSetupGraph -Method POST -Path '/oauth2PermissionGrants' -Body @{ clientId = "$($appSp.id)"; consentType = 'AllPrincipals'; resourceId = "$($graphSp.id)"; scope = ($want -join ' ') })
    }
}

# The revision FIRST, with Easy Auth still on in front of it: there is no moment in which the Manager answers without a
# sign-in in front. Then the ingress to the front's port, then Easy Auth off, then the proof -- or the rollback.
Step "two-container revision: $script:SfFrontName ($FrontImage) + the Manager on 127.0.0.1:$UpstreamPort; replicas 1..1"
$tpl = New-PimSigninFrontTemplate -Template $ca.properties.template -FrontImage $FrontImage -TenantId $TenantId -ClientId $appId -MiClientId "$($identity.clientId)" -UpstreamPort $UpstreamPort -SessionHours $SessionHours -KeyVaultKeyId $KeyVaultKeyId -UpstreamScope $UpstreamScope
try {
    # A 409 "operation in progress" is transient (a roll or a job update on the app): retried for up to 10 minutes, never
    # treated as a failed switch -- the 2026-10-20 fleet run rolled two installs back on exactly this.
    $opBy = [datetime]::UtcNow.AddMinutes(10)
    while ($true) {
        try { [void](Set-PimArmAcaApp -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $ManagerApp -Resource @{ properties = @{ template = $tpl } }); break }
        catch {
            if (-not (Test-PimSfOperationInProgress -Message "$($_.Exception.Message)") -or [datetime]::UtcNow -ge $opBy) { throw }
            Note 'the Manager is busy with another operation (409) -- retrying in 30 s'
            Start-Sleep -Seconds 30
        }
    }
    if ([int]$ca.properties.configuration.ingress.targetPort -ne $script:SfFrontPort) {
        $fp = $script:SfFrontPort
        [void](Set-PimArmAcaAppConfiguration -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $ManagerApp -Mutate { param($cfg) $cfg.ingress.targetPort = $fp }.GetNewClosure())
    }
    # Wait (Easy Auth still ON) until the front revision is the one that serves -- up to 10 minutes.
    $rdyBy = [datetime]::UtcNow.AddMinutes(10); $rdy = $false
    while (-not $rdy -and [datetime]::UtcNow -lt $rdyBy) {
        $cur = $null; try { $cur = Get-PimArmAcaApp -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $ManagerApp } catch { }
        $rdy = Test-PimSigninFrontRevisionReady -App $cur
        if (-not $rdy) { Start-Sleep -Seconds 15 }
    }
    if (-not $rdy) { throw 'the two-container revision did not become the ready revision within 10 minutes' }
    Step 'front revision ready -- switch: Easy Auth OFF (the front signs people in from now on)'
    Set-PimSfEasyAuth -Enabled $false
    $hostP = "$(@($plan.hosts)[0])"
    if ($PrivateReadBackByPerson) {
        # a PRIVATE install (no route from here): the read-back is a person signing in from inside the network; until then
        # the rollback record stays (-Rollback -StateFile). Nothing here can prove it, so nothing here claims it.
        Step "read-back: NOT from here (private install) -- a person signs in at https://$hostP/ from inside the network; undo: -Rollback -StateFile `"$StateFile`""
        $plan.live = $true
        return $plan
    }
    # Easy Auth off takes a moment to reach the edge: /healthz is asked every 10 s for up to 3 minutes before it counts.
    $hzBy = [datetime]::UtcNow.AddMinutes(3)
    do { Start-Sleep -Seconds 10; $hz = Invoke-PimSfProbe -Url "https://$hostP/healthz" } while ($hz.status -ne 200 -and [datetime]::UtcNow -lt $hzBy)
    $root = Invoke-PimSfProbe -Url "https://$hostP/" -Headers @{ 'Sec-Fetch-Mode' = 'navigate'; 'Accept' = 'text/html' }
    $api = Invoke-PimSfProbe -Url "https://$hostP/api/whoami" -Headers @{ 'Sec-Fetch-Mode' = 'cors' }
    $v = Get-PimSigninFrontProbeVerdict -HealthStatus $hz.status -RootStatus $root.status -RootLocation $root.location -ApiStatus $api.status -TenantId $TenantId -ClientId $appId
    if (-not $v.ok) { throw "read-back: $($v.reason)" }
    Step "read back: $($v.reason)"
} catch {
    Warn "the switch did not prove itself: $($_.Exception.Message)"
    Invoke-PimSfRollback -Saved ([pscustomobject]$saved)
    throw "Set-PimManagerSigninFront: rolled back -- $($_.Exception.Message)"
}
Write-Host "==> done. Sign in at https://$(@($plan.hosts)[0])/ . The Easy Auth secret is still on the registration (rollback stays possible);" -ForegroundColor Green
Write-Host "    once people have signed in through the front: re-run with -DeleteSecret. Rollback until then: -Rollback -StateFile `"$StateFile`"" -ForegroundColor Green
return $plan
