#Requires -Version 5.1
<#
.SYNOPSIS
    71.33 -- the SIGNED-IN (interactive) identity for the one-shot MSP build and the setup steps it runs.

.DESCRIPTION
    Operator 2026-09-17: "I thought I could just do interactive login to deploy." A customer deploys by signing in
    with `az login` as a human administrator; certificates are the MSP management host's automation pattern only. So
    every step the build runs inside ONE tenant accepts -UseSignedInAccount (or, where the script already had that
    convention, simply no credential) and then authenticates as the account signed in to az -- no certificate, no
    secret, nothing written to disk by this code, and no token ever printed or logged.

    WHAT IS ASSERTED BEFORE ANYTHING IS USED (a wrong default az context on a multi-tenant machine is a real trap):
      * the az account for the named subscription is a USER (a service principal is refused -- that is the certificate
        mode's job, and a signed-in SPN would silently change who the audit trail names);
      * its tenant equals the build config's tenantId, and the subscription is the one named explicitly;
      * every token minted from it (ARM, SQL) is decoded and its tenant and user-ness checked;
      * no environment variable is set that would make a token call quietly authenticate as somebody else
        (AZURE_CLIENT_SECRET, PIM_CERT_THUMBPRINT, a managed identity endpoint ...).

    SQL: Azure SQL here is Entra-only, so the signed-in user needs database rights -- by being a MEMBER of the SQL admin
    group (grp-pim-sql-admins) that is the server's Entra admin. Invoke-PimSignedInSqlAdminMembership adds the user as a
    member (members-only: it never creates the group and never moves the admin).
    TRAP: an Entra token carries group membership as of when it was issued, and az caches tokens for up to about an
    hour. A user added to the group in THIS run may be refused by SQL until their token refreshes -- the helper says so.

    Pure parts are offline-tested in tests/Test-PimMspBuild.ps1 (section S).
#>

$script:PimSignedInGuid = '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
# Environment variables that make a token call authenticate as SOMEBODY ELSE than the signed-in user.
$script:PimSignedInConflictVars = @('AZURE_CLIENT_ID', 'AZURE_CLIENT_SECRET', 'AZURE_CLIENT_CERTIFICATE_PATH', 'AZURE_FEDERATED_TOKEN_FILE',
                                    'PIM_CERT_THUMBPRINT', 'IDENTITY_ENDPOINT', 'MSI_ENDPOINT')

function ConvertFrom-PimJwtClaims {
    # PURE. The claims of a JWT (never validates the signature -- this is only used to ASSERT who a token is for).
    param([string]$Token)
    try {
        $seg = "$Token".Split('.')[1].Replace('-', '+').Replace('_', '/')
        while ($seg.Length % 4) { $seg += '=' }
        return ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($seg)) | ConvertFrom-Json)
    } catch { return $null }
}

function Get-PimSupportAppSession {
    <#
      PURE given -Environment (name -> value; default: this process). The Invardia Support app session that Invardia's
      Connect-InvardiaSupport.ps1 -AzCli opened in THIS shell (framework 4.1a: the one agreed access method), or $null.
      It is recognised only when the connect script's private az profile IS the active one (INVARDIA_SUPPORT_AZCONFIG ==
      AZURE_CONFIG_DIR) -- a service principal signed in any other way is never treated as the support app.
      Returns @{ tenantId; subscriptions[]; environment } or $null.
    #>
    param([hashtable]$Environment)
    $get = { param($n) if ($Environment) { "$($Environment[$n])" } else { "$([Environment]::GetEnvironmentVariable($n))" } }
    $dir = "$(& $get 'INVARDIA_SUPPORT_AZCONFIG')".Trim(); $cur = "$(& $get 'AZURE_CONFIG_DIR')".Trim()
    if (-not $dir -or -not $cur -or $dir.TrimEnd('\', '/') -ne $cur.TrimEnd('\', '/')) { return $null }
    $tid = "$(& $get 'INVARDIA_SUPPORT_TENANT')".Trim().ToLowerInvariant()
    if ($tid -notmatch $script:PimSignedInGuid) { return $null }
    $subs = @("$(& $get 'INVARDIA_SUPPORT_SUBSCRIPTIONS')" -split '[,;\s]+' | ForEach-Object { "$_".Trim().ToLowerInvariant() } | Where-Object { $_ -match $script:PimSignedInGuid })
    return @{ tenantId = $tid; subscriptions = $subs; environment = "$(& $get 'INVARDIA_SUPPORT_ENVIRONMENT')".Trim() }
}

function Test-PimSignedInAccount {
    <#
      PURE. Judge an `az account show` object for the signed-in build. Returns @{ ok; reason; userName; supportAppId }.
      Refused: no account, a service principal / managed identity, another tenant, another subscription.
      ONE exception (operator 2026-10-06: "we have only one agreed method"): the Invardia Support app, signed in by
      Invardia's connect script for exactly this tenant and an allowed subscription (Get-PimSupportAppSession).
    #>
    param([object]$Account, [string]$TenantId, [string]$SubscriptionId, [hashtable]$Environment)
    $want = "$TenantId".Trim().ToLowerInvariant(); $sub = "$SubscriptionId".Trim().ToLowerInvariant()
    if ($want -notmatch $script:PimSignedInGuid -or $sub -notmatch $script:PimSignedInGuid) {
        return @{ ok = $false; reason = 'the tenant id and the subscription id must both be given explicitly (GUIDs) -- a signed-in build never relies on the default az context' }
    }
    if ($null -eq $Account -or -not "$($Account.id)".Trim()) {
        return @{ ok = $false; reason = "no az sign-in covers subscription $sub. Sign in first: az login --tenant $want" }
    }
    $type = "$($Account.user.type)".Trim().ToLowerInvariant()
    $name = "$($Account.user.name)".Trim()
    $supportAppId = ''
    if ($type -eq 'serviceprincipal') {
        $sess = Get-PimSupportAppSession -Environment $Environment
        if ($sess -and $sess.tenantId -eq $want -and ($sess.subscriptions -contains $sub) -and $name -match $script:PimSignedInGuid) {
            $supportAppId = $name.ToLowerInvariant()
            if ("$($Account.tenantId)".Trim().ToLowerInvariant() -ne $want) { return @{ ok = $false; reason = "the support app session is in tenant '$($Account.tenantId)', not '$want' -- REFUSING" } }
            if ("$($Account.id)".Trim().ToLowerInvariant() -ne $sub) { return @{ ok = $false; reason = "az answered for subscription '$($Account.id)', not the requested '$sub' -- REFUSING" } }
            return @{ ok = $true; reason = "signed in as the Invardia Support app $supportAppId (support environment '$($sess.environment)', tenant $want, subscription $sub)"; userName = "Invardia Support app ($supportAppId)"; supportAppId = $supportAppId }
        }
        if ($sess -and $sess.tenantId -ne $want) { return @{ ok = $false; reason = "the Invardia Support session in this shell is for tenant '$($sess.tenantId)', but the build config names '$want' -- REFUSING" } }
        if ($sess -and -not ($sess.subscriptions -contains $sub)) { return @{ ok = $false; reason = "subscription $sub is not one the support environment allows ($($sess.subscriptions -join ', ')) -- REFUSING" } }
    }
    if ($type -ne 'user') {
        return @{ ok = $false; reason = ("az is signed in as a $(if ($type) { $type } else { 'non-user account' }) ('$name'), not a person. " +
                 'The signed-in build runs as the administrator at the keyboard; an application identity belongs in deployIdentity (certificate mode).') }
    }
    if ("$($Account.tenantId)".Trim().ToLowerInvariant() -ne $want) {
        return @{ ok = $false; reason = "the az sign-in for subscription $sub is in tenant '$($Account.tenantId)', but the build config names tenant '$want' -- REFUSING (a wrong default context acts in somebody else's directory)" }
    }
    if ("$($Account.id)".Trim().ToLowerInvariant() -ne $sub) {
        return @{ ok = $false; reason = "az answered for subscription '$($Account.id)', not the requested '$sub' -- REFUSING" }
    }
    return @{ ok = $true; reason = "signed in as $name (tenant $want, subscription $sub)"; userName = $name }
}

function Test-PimSignedInToken {
    <#
      PURE. Assert a token belongs to a signed-in USER of -TenantId. Returns @{ ok; reason; objectId; userName; tenantId }.
      An application token (idtyp=app, or no user claims) is refused: that is a different principal wearing the same call.
    #>
    # -AllowedAppId: the Invardia Support app's appId (from Test-PimSignedInAccount); an application token is accepted
    # ONLY when its appid is exactly that app.
    param([string]$Token, [string]$TenantId, [string]$AllowedAppId = '')
    $c = ConvertFrom-PimJwtClaims -Token $Token
    if (-not $c) { return @{ ok = $false; reason = 'the token could not be decoded' } }
    $tid = "$($c.tid)".Trim().ToLowerInvariant()
    if ($tid -ne "$TenantId".Trim().ToLowerInvariant()) { return @{ ok = $false; reason = "the token is for tenant '$tid', not '$TenantId' -- REFUSING" } }
    $upn = "$(if ($c.upn) { $c.upn } elseif ($c.unique_name) { $c.unique_name } elseif ($c.preferred_username) { $c.preferred_username } else { '' })".Trim()
    $idtyp = "$($c.idtyp)".Trim().ToLowerInvariant()
    $appid = "$(if ($c.appid) { $c.appid } else { $c.azp })".Trim().ToLowerInvariant()
    if ("$AllowedAppId".Trim() -and $appid -eq "$AllowedAppId".Trim().ToLowerInvariant() -and -not $upn) {
        if ("$($c.oid)".Trim() -notmatch $script:PimSignedInGuid) { return @{ ok = $false; reason = 'the support app token carries no object id' } }
        return @{ ok = $true; reason = ''; objectId = "$($c.oid)".Trim().ToLowerInvariant(); userName = "Invardia Support app ($appid)"; tenantId = $tid; supportApp = $true }
    }
    if ($idtyp -eq 'app' -or (-not $upn -and $idtyp -ne 'user')) {
        return @{ ok = $false; reason = "the token is an APPLICATION token (appid '$($c.appid)'), not the signed-in user's -- REFUSING" }
    }
    if ("$($c.oid)".Trim() -notmatch $script:PimSignedInGuid) { return @{ ok = $false; reason = 'the token carries no user object id' } }
    return @{ ok = $true; reason = ''; objectId = "$($c.oid)".Trim().ToLowerInvariant(); userName = $upn; tenantId = $tid }
}

function Test-PimCloudShell {
    # PURE given -Environment. Azure Cloud Shell sets AZUREPS_HOST_ENVIRONMENT=cloud-shell/<ver> and ACC_CLOUD; there the
    # MSI_ENDPOINT / IDENTITY_ENDPOINT serve the SIGNED-IN USER's token (Cloud Shell's own token broker), not a machine
    # identity -- so they are no conflict there (§95.2 Cloud Shell blocker 2, guided install 2026-10-03).
    param([hashtable]$Environment)
    $get = { param($n) if ($Environment) { "$($Environment[$n])" } else { "$([Environment]::GetEnvironmentVariable($n))" } }
    return ((& $get 'AZUREPS_HOST_ENVIRONMENT') -match '^(?i)cloud-shell') -or [bool]"$(& $get 'ACC_CLOUD')".Trim()
}

function Get-PimSignedInEnvironmentConflicts {
    # PURE given -Environment (a hashtable name -> value); by default reads this process. The names that are set.
    # In Azure Cloud Shell MSI_ENDPOINT / IDENTITY_ENDPOINT are the user's own token broker and are not counted.
    param([hashtable]$Environment)
    $cloudShell = Test-PimCloudShell -Environment $Environment
    $out = @()
    foreach ($n in $script:PimSignedInConflictVars) {
        if ($cloudShell -and $n -in 'MSI_ENDPOINT', 'IDENTITY_ENDPOINT') { continue }
        $v = if ($Environment) { $Environment[$n] } else { [Environment]::GetEnvironmentVariable($n) }
        if ("$v".Trim()) { $out += $n }
    }
    return @($out)
}

function Get-PimSignedInConflictHint {
    # PURE. How to clear the named variables for THIS session only (§73.9: on an Azure Arc / Azure VM host
    # IDENTITY_ENDPOINT is set machine-wide, and an operator had to be told how to clear it).
    param([string[]]$Names)
    $n = @($Names | Where-Object { "$_".Trim() })
    if (-not $n.Count) { return '' }
    $cmd = ($n | ForEach-Object { "`$env:$_ = `$null" }) -join '; '
    $arc = if ($n -contains 'IDENTITY_ENDPOINT' -or $n -contains 'MSI_ENDPOINT') {
        ' IDENTITY_ENDPOINT / MSI_ENDPOINT are set machine-wide by Azure Arc or an Azure VM agent: clearing them in this window affects this window only, never the machine or the agent.'
    } else { '' }
    return "Clear them for this session only, then re-run in the same window: $cmd.$arc Or use the certificate mode."
}

function Use-PimSupportAppRestSession {
    <#
      100.41 / framework 4.1a -- the Invardia Support app's REST session ($global:InvardiaSupportState, set by
      Connect-InvardiaSupport.ps1 WITHOUT -AzCli) for -TenantId (+ an allowed -SubscriptionId): point PIM-Rest's ONE token
      client at it (client credentials with the app's secret -- the one agreed support method). Returns the app id
      (lowercase) or '' when no such session covers this tenant + subscription. Nothing is printed; the secret only moves
      into PIM-Rest's process-local global. -State is the test seam (default: the session in this shell).
    #>
    param([Parameter(Mandatory)][string]$TenantId, [string]$SubscriptionId, [object]$State)
    $s = if ($PSBoundParameters.ContainsKey('State')) { $State } else { $global:InvardiaSupportState }
    if (-not ($s -is [hashtable]) -or -not $s.Secret -or "$($s.AppId)" -notmatch $script:PimSignedInGuid) { return '' }
    if ("$($s.TenantId)".Trim().ToLowerInvariant() -ne "$TenantId".Trim().ToLowerInvariant()) { return '' }
    $subs = @(@($s.Subscriptions) | ForEach-Object { "$_".Trim().ToLowerInvariant() } | Where-Object { $_ })
    if ("$SubscriptionId".Trim() -and -not ($subs -contains "$SubscriptionId".Trim().ToLowerInvariant())) { return '' }
    # Owner token rule (2026-10-09): tools get TOKENS from Get-InvardiaSupportToken -- the Support app's secret NEVER leaves
    # the support session. So PIM-Rest is pointed at the session's token function (Set-PimSignedInGlobals registers
    # Get-PimSignedInToken as $global:PIM_TokenProvider), never at a copy of the secret.
    if (-not $PSBoundParameters.ContainsKey('State') -and -not (Get-Command Get-InvardiaSupportToken -ErrorAction SilentlyContinue)) { return '' }
    Set-PimSignedInGlobals -TenantId "$TenantId".Trim().ToLowerInvariant()
    foreach ($n in 'PIM_ClientSecret', 'PIM_CertThumbprint', 'PIM_UseManagedIdentity', 'PIM_Interactive', 'PIM_InteractiveFallback') { Set-Variable -Scope Global -Name $n -Value $null -WhatIf:$false }
    $global:PIM_NoManagedIdentity = $true
    return "$($s.AppId)".Trim().ToLowerInvariant()
}

function Get-PimSignedInIdentity {
    <#
      Read and ASSERT the signed-in identity for one tenant + subscription. Returns @{ ok; reason; userName; objectId;
      tenantId; subscriptionId }. The ARM token is minted only to read the user's object id and is then discarded.
      100.41 (NO-AZ): over REST by default -- the token comes from PIM-Rest's ONE client (the Invardia Support app's REST
      session when one covers this tenant, else the person's own sign-in), its claims are asserted, and the subscription
      is read over ARM to prove it is visible and in -TenantId.
      -Az is the LEGACY test seam (a scriptblock param([string[]]$AzArgs) returning az's stdout): only when a caller
      passes one is the az-shaped path below used. Nothing in this file invokes az itself.
      -Token / -Arm are the REST test seams: { param($Resource, $TenantId) <jwt> } and { param($Path) <ARM object> }.
    #>
    param([Parameter(Mandatory)][string]$TenantId, [Parameter(Mandatory)][string]$SubscriptionId, [scriptblock]$Az, [scriptblock]$Token, [scriptblock]$Arm)
    $conf = @(Get-PimSignedInEnvironmentConflicts)
    if ($conf.Count) {
        return @{ ok = $false; reason = ("REFUSED: $($conf -join ', ') $(if ($conf.Count -eq 1) { 'is' } else { 'are' }) set in this session -- a token call would authenticate as " +
                 'that identity instead of the signed-in user. ' + (Get-PimSignedInConflictHint -Names $conf)) }
    }
    if (-not $Az) { return (Get-PimSignedInIdentityRest -TenantId $TenantId -SubscriptionId $SubscriptionId -Token $Token -Arm $Arm) }
    $acct = $null
    try { $acct = ((& $Az @('account', 'show', '--subscription', "$SubscriptionId", '-o', 'json')) | Out-String | ConvertFrom-Json) } catch { $acct = $null }
    $a = Test-PimSignedInAccount -Account $acct -TenantId $TenantId -SubscriptionId $SubscriptionId
    if (-not $a.ok) { return $a }
    $tok = $null
    try { $tok = "$(((& $Az @('account', 'get-access-token', '--subscription', "$SubscriptionId", '--resource', 'https://management.azure.com/', '-o', 'json')) | Out-String | ConvertFrom-Json).accessToken)" } catch { $tok = $null }
    if (-not "$tok".Trim()) { return @{ ok = $false; reason = "az could not issue a token for subscription $SubscriptionId (sign in again: az login --tenant $TenantId)" } }
    $t = Test-PimSignedInToken -Token $tok -TenantId $TenantId -AllowedAppId "$($a.supportAppId)"
    $tok = $null
    if (-not $t.ok) { return $t }
    return @{ ok = $true; reason = $a.reason; userName = $(if ($t.userName) { $t.userName } else { $a.userName }); objectId = $t.objectId
              tenantId = "$TenantId".Trim().ToLowerInvariant(); subscriptionId = "$SubscriptionId".Trim().ToLowerInvariant(); supportAppId = "$($a.supportAppId)" }
}

function Get-PimSignedInToken {
    <#
      REQ 100.42 / framework 12.17 (owner 2026-10-09: "modern single connect only"; owner token rule: tools get TOKENS from
      Get-InvardiaSupportToken). THE token source of a signed-in setup run, registered into PIM-Rest by
      Set-PimSignedInGlobals ($global:PIM_TokenProvider). No az CLI, no module:
        * the Invardia Support-app session is open in this shell (Get-InvardiaSupportToken exists) -> its token;
        * otherwise the signed-in person -> Get-PimInteractiveToken (browser, auth-code + PKCE; never device code).
      Returns the token string (Support app) or PIM-Rest's @{ token; expiresUtc } (interactive). PIM-Rest verifies the tid.
    #>
    param([Parameter(Mandatory)][string]$Audience, [string]$TenantId)
    if (Get-Command Get-InvardiaSupportToken -ErrorAction SilentlyContinue) {
        return (Get-InvardiaSupportToken -Resource ("$Audience".TrimEnd('/')))
    }
    if (-not (Get-Command Get-PimInteractiveToken -ErrorAction SilentlyContinue)) { throw 'Get-PimSignedInToken: engine\_shared\PIM-Rest.ps1 is not loaded.' }
    return (Get-PimInteractiveToken -Audience $Audience -TenantId $TenantId)
}

function Get-PimSignedInIdentityRest {
    <#
      100.41 -- Get-PimSignedInIdentity over REST (no az). The identity is the Invardia Support app's REST session when one
      covers -TenantId + -SubscriptionId (Use-PimSupportAppRestSession), else the person at the keyboard: PIM-Rest's own
      sign-in (the browser, auth code + PKCE). The token's claims are asserted (Test-PimSignedInToken: this tenant, a USER --
      or exactly the support app), then the subscription is read over ARM: it must be visible and belong to -TenantId.
      -Token { param($Resource, $TenantId) <jwt> } and -Arm { param($Path) <object> } are the test seams.
    #>
    param([Parameter(Mandatory)][string]$TenantId, [Parameter(Mandatory)][string]$SubscriptionId, [scriptblock]$Token, [scriptblock]$Arm)
    $want = "$TenantId".Trim().ToLowerInvariant(); $sub = "$SubscriptionId".Trim().ToLowerInvariant()
    if ($want -notmatch $script:PimSignedInGuid -or $sub -notmatch $script:PimSignedInGuid) {
        return @{ ok = $false; reason = 'the tenant id and the subscription id must both be given explicitly (GUIDs) -- a signed-in build never relies on a default context' }
    }
    $supportApp = ''
    if (-not $Token) {
        if (-not (Get-Command Get-PimRestToken -ErrorAction SilentlyContinue)) {
            $rest = Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'engine\_shared\PIM-Rest.ps1'
            if (Test-Path -LiteralPath $rest) { . $rest } else { return @{ ok = $false; reason = 'engine\_shared\PIM-Rest.ps1 is not loaded -- the signed-in identity cannot be read' } }
        }
        $supportApp = Use-PimSupportAppRestSession -TenantId $want -SubscriptionId $sub
        if (-not $supportApp) {
            Set-PimSignedInGlobals -TenantId $want
            # the person signs in in the browser (PIM-Rest: auth code + PKCE) -- only where a person can
            $interactive = $true
            try { if (-not [Environment]::UserInteractive -or [Console]::IsInputRedirected) { $interactive = $false } } catch { }
            $global:PIM_InteractiveFallback = $interactive
        }
        $Token = { param($r, $t) Get-PimRestToken -Resource $r -TenantId $t }
    }
    $tok = ''; $why = ''
    try { $tok = "$(& $Token 'arm' $want)".Trim() } catch { $why = "$($_.Exception.Message)"; $tok = '' }
    if (-not $tok) {
        return @{ ok = $false; reason = ("could not sign in to tenant $want$(if ($why) { " ($why)" }). Run it in a PowerShell window (a browser sign-in opens), " +
                 'or in a shell connected with the Invardia Support app (Connect-InvardiaSupport.ps1 -Environment <handle>).') }
    }
    $allow = $supportApp
    if (-not $allow) {
        # the az-profile support session (Connect-InvardiaSupport -AzCli), recognised by its environment: the token's own app id
        $sess = Get-PimSupportAppSession
        if ($sess -and $sess.tenantId -eq $want -and ($sess.subscriptions -contains $sub)) {
            $c = ConvertFrom-PimJwtClaims -Token $tok
            $allow = "$(if ($c.appid) { $c.appid } else { $c.azp })".Trim().ToLowerInvariant()
        }
    }
    $t = Test-PimSignedInToken -Token $tok -TenantId $want -AllowedAppId $allow
    $tok = $null
    if (-not $t.ok) { return $t }
    if (-not $Arm) { $Arm = { param($p) Invoke-PimArm -Method GET -Path $p -ApiVersion '2022-12-01' } }
    $s = $null; $why = ''
    try { $s = & $Arm "/subscriptions/$sub" } catch { $why = "$($_.Exception.Message)"; $s = $null }
    if (-not $s -or "$($s.subscriptionId)".Trim().ToLowerInvariant() -ne $sub) {
        return @{ ok = $false; reason = "subscription $sub is not visible to $($t.userName)$(if ($why) { " ($why)" }) -- REFUSING" }
    }
    if ("$($s.tenantId)".Trim() -and "$($s.tenantId)".Trim().ToLowerInvariant() -ne $want) {
        return @{ ok = $false; reason = "subscription $sub belongs to tenant '$($s.tenantId)', not '$want' -- REFUSING (a wrong default acts in somebody else's directory)" }
    }
    $label = if ($t.supportApp) { "signed in as the Invardia Support app $allow (tenant $want, subscription $sub)" } else { "signed in as $($t.userName) (tenant $want, subscription $sub)" }
    return @{ ok = $true; reason = $label; userName = $t.userName; objectId = $t.objectId; tenantId = $want; subscriptionId = $sub; supportAppId = "$allow" }
}

function Set-PimSignedInGlobals {
    <#
      Make the engine's token helpers (Get-PimRestToken, New-PimSqlConnection) take the signed-in token source in THIS
      process: clear every application-identity global, pin the tenant, and switch the managed-identity probe off (a
      deploy host that is an Azure VM has a managed identity of its own, and it would otherwise win).
    #>
    param([Parameter(Mandatory)][string]$TenantId)
    foreach ($n in 'PIM_ClientId', 'PIM_ClientSecret', 'PIM_CertThumbprint', 'PIM_SqlClientId', 'PIM_SqlClientSecret', 'PIM_SqlCertThumbprint', 'PIM_SqlAccessToken', 'PIM_UseManagedIdentity') {
        Set-Variable -Scope Global -Name $n -Value $null -WhatIf:$false
    }
    $global:PIM_TenantId = "$TenantId".Trim()
    $global:PIM_NoManagedIdentity = $true
    $global:PIM_UseGraphSdk = $false
    $global:PIM_SignedInAccount = $true
    # REQ 100.42: register the signed-in token source (Support app / browser) -- PIM-Rest no longer falls back to az.
    $global:PIM_TokenProvider = ${function:Get-PimSignedInToken}
}

function Connect-PimSignedInSql {
    <#
      Prepare THIS process to reach Azure SQL as the signed-in user, and prove the token is right before any statement
      runs. PIM-Rest.ps1 must be loaded. Returns @{ userName; objectId }. The token itself stays in the engine's
      in-memory cache and is never returned, printed or written.
    #>
    param([Parameter(Mandatory)][string]$TenantId)
    $conf = @(Get-PimSignedInEnvironmentConflicts)
    if ($conf.Count) { throw "REFUSED: $($conf -join ', ') set in this session -- the SQL token would be minted for that identity, not the signed-in user. $(Get-PimSignedInConflictHint -Names $conf)" }
    if (-not (Get-Command Get-PimRestToken -ErrorAction SilentlyContinue)) { throw 'Connect-PimSignedInSql: engine\_shared\PIM-Rest.ps1 is not loaded.' }
    Set-PimSignedInGlobals -TenantId $TenantId
    # 100.41 (no az): the Invardia Support app's REST session for this tenant is the identity when there is one (PIM-Rest
    # client credentials with its secret); else the person's own sign-in.
    $allowApp = Use-PimSupportAppRestSession -TenantId $TenantId
    if (-not $allowApp) {
        $interactive = $true
        try { if (-not [Environment]::UserInteractive -or [Console]::IsInputRedirected) { $interactive = $false } } catch { }
        if (-not $global:PIM_InteractiveFallback) { $global:PIM_InteractiveFallback = $interactive }
    }
    $tok = Get-PimRestToken -Resource 'https://database.windows.net' -TenantId $TenantId
    if (-not $allowApp) {
        # the az-profile support session (Connect-InvardiaSupport -AzCli): accept exactly the app its token names
        $sess = Get-PimSupportAppSession
        if ($sess -and $sess.tenantId -eq "$TenantId".Trim().ToLowerInvariant()) {
            $c = ConvertFrom-PimJwtClaims -Token "$tok"
            if (-not "$(if ($c.upn) { $c.upn } else { $c.unique_name })".Trim()) { $allowApp = "$(if ($c.appid) { $c.appid } else { $c.azp })".Trim() }
        }
    }
    $t = Test-PimSignedInToken -Token "$tok" -TenantId $TenantId -AllowedAppId $allowApp
    $tok = $null
    if (-not $t.ok) { throw "SQL as the signed-in user: $($t.reason)" }
    $global:PIM_SetupActor = $(if ($t.userName) { $t.userName } else { $t.objectId })
    return @{ userName = $t.userName; objectId = $t.objectId }
}

function Invoke-PimSignedInSqlAdminMembership {
    <#
      Make the signed-in user a MEMBER of the SQL admin group of -SqlServerName (members-only: never creates the group,
      never moves the Entra admin). Returns @{ ok; blocked; added; reason }. Blocked = the server's admin is not the
      group, so membership would grant nothing -- the caller must refuse with that reason.
    #>
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$TenantId, [Parameter(Mandatory)][string]$ResourceGroup,
          [Parameter(Mandatory)][string]$SqlServerName, [Parameter(Mandatory)][string]$UserObjectId, [string]$GroupName = 'grp-pim-sql-admins',
          # test seam: @{ Graph; Arm; TenantId } instead of the signed-in az context
          [object]$Invokers)
    # Loaded on demand through a variable path: Build-PimSupportScripts.ps1 inlines the literal dot-source-of-a-Join-Path
    # lines, and a standalone script that inlines THIS file (Initialize-PimMailSender.ps1) never calls this function.
    if (-not (Get-Command Invoke-PimSqlAdminGroupStep -ErrorAction SilentlyContinue)) { $__sag = Join-Path $PSScriptRoot '_PimSqlAdminGroup.ps1'; . $__sag }
    $inv = if ($Invokers) { $Invokers } else { New-PimSqlAdminGroupInvokers -SubscriptionId $SubscriptionId -TenantId $TenantId }
    $srv = ("$SqlServerName".Trim() -split '\.')[0]
    $sqlRg = $ResourceGroup
    if (Get-Command Resolve-PimSqlServerFromFqdn -ErrorAction SilentlyContinue) {
        try { $res = Resolve-PimSqlServerFromFqdn -Arm $inv.Arm -SubscriptionId $SubscriptionId -Server $srv; if ($res) { $sqlRg = $res.resourceGroup; $srv = $res.name } } catch { }
    }
    # §95.2 Cloud Shell blocker 5 (guided install): an installer WITHOUT Privileged Role Administrator cannot create the
    # role-assignable SQL admin group, so the prerequisites leave the server's Entra admin = the signed-in user. That user
    # already holds every SQL right; the members-only step would only fail on "group does not exist". Say so, hand the
    # group to a Privileged Role Administrator, and let the deploy continue.
    try {
        $list = & $inv.Arm -Method GET -Path "/subscriptions/$SubscriptionId/resourceGroups/$sqlRg/providers/Microsoft.Sql/servers/$srv/administrators?api-version=$($script:PimSqlApi)"
        $cur = @(@($list.value) | Where-Object { $_ }) | Select-Object -First 1
        if ($cur -and "$($cur.properties.sid)".Trim() -ieq "$UserObjectId".Trim()) {
            $action = ".\Initialize-PimSqlAdminGroup.ps1 -SubscriptionId $SubscriptionId -TenantId $TenantId -ResourceGroup $sqlRg -SqlServerName $srv -GroupName $GroupName"
            Write-Host "    the signed-in user IS the Entra admin of $srv -- SQL is reachable. The SQL admin group '$GroupName' is not the admin yet; a Privileged Role Administrator converges it with: $action" -ForegroundColor Yellow
            return @{ ok = $true; blocked = $false; added = $false; direct = $true; reason = ''; action = $action }
        }
    } catch { Write-Verbose "reading the Entra admin of $srv failed: $($_.Exception.Message) -- falling back to the group membership" }
    $r = Invoke-PimSqlAdminGroupStep -Graph $inv.Graph -Arm $inv.Arm -TenantId $inv.TenantId -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup `
            -SqlResourceGroup $sqlRg -SqlServerName $srv -GroupName $GroupName -UpdateJobName '' -NoDiscovery -Mode membersOnly `
            -ExtraMembers @([pscustomobject]@{ objectId = "$UserObjectId".Trim(); label = 'the signed-in administrator' })
    Write-PimSqlAdminGroupReport -Result $r
    $added = @(@($r.added) | Where-Object { "$($_.objectId)" -ieq "$UserObjectId".Trim() }).Count -gt 0
    if (-not $r.ok) { return @{ ok = $false; blocked = $false; added = $added; reason = "could not make the signed-in user a member of '$GroupName': $(@($r.problems) -join '; ')" } }
    if ($r.blocked) { return @{ ok = $true; blocked = $true; added = $false; reason = "the Entra admin of $srv is not '$GroupName' ($($r.blocked)) -- membership grants nothing there. Converge the server onto the group first (Initialize-PimSqlAdminGroup.ps1), or make the signed-in user the Entra admin." } }
    if ($added) {
        Write-Host ("    NOTE: you were ADDED to '$GroupName' just now. An Entra token carries group membership as of when it was issued, " +
                    'and az caches tokens for up to about an hour -- if SQL refuses the next step, sign in again (az logout; az login --tenant <tenant>) and resume.') -ForegroundColor Yellow
    }
    return @{ ok = $true; blocked = $false; added = $added; reason = '' }
}
