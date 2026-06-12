#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Applications, Microsoft.Graph.Identity.SignIns, Microsoft.Graph.Authentication
<#
.SYNOPSIS
    Create the Entra app registration that the PIM Activator Edge extension
    needs: SPA redirect URI + delegated PIM/Group/User permissions, optionally
    pre-consented for the tenant.

.DESCRIPTION
    The PIM Activator extension uses chrome.identity.launchWebAuthFlow + PKCE
    (vanilla JS, no MSAL.js) to:
      - Read the signed-in user's eligible PIM-for-Groups assignments
      - POST assignmentScheduleRequests to bulk-activate selected groups

    The redirect URI is registered as a Public Client / native URI rather than
    SPA. This is required because the token endpoint is called from the
    extension's fetch context (no Origin: https://*.chromiumapp.org header),
    and Entra rejects SPA-registered redirect URIs in that case with
    AADSTS9002326 ("Cross-origin token redemption is permitted only for the
    'Single-Page Application' client-type").

    Required delegated permissions (resolved by displayName -> id at runtime):
      Microsoft Graph (00000003-0000-0000-c000-000000000000):
        - PrivilegedAccess.ReadWrite.AzureADGroup (POST/DELETE activation -- ReadWrite REQUIRED, Read-only breaks Activate)
        - Group.Read.All
        - User.Read
        - RoleManagement.Read.Directory
        - RoleManagement.ReadWrite.Directory (activate direct Entra role assignments)
        - AdministrativeUnit.Read.All
        - Application.Read.All (first-run onboarding wizard -- discovers the per-tenant app reg by displayName)
      Azure Service Management (797f4846-ba00-4fd7-ba43-dac1f8f63013):
        - user_impersonation (mint ARM token for Azure RBAC eligibility + activation)
      - User.Read
      - RoleManagement.Read.Directory   (powers the "My Access" tab -- lists
        Entra role assignments attached to the user's active PIM-for-Groups
        memberships. Admin-consentable. Without it, the My Access tab still
        renders memberships but each row shows a 403 for the role lookup.)
      - AdministrativeUnit.Read.All     (resolves AU displayNames in the My
        Access tab. RoleManagement.Read.Directory exposes the AU id on each
        role assignment but reading the AU object requires this scope; without
        it, the popup renders "scoped to N Administrative Units" without
        names.)

    Caller (you) must have:
      - Graph scopes: Application.ReadWrite.All, AppRoleAssignment.ReadWrite.All,
                      DelegatedPermissionGrant.ReadWrite.All
      - Entra roles, ACTIVE in the session (PIM-eligible does NOT count until
        activated -- activate in PIM FIRST, then Connect-MgGraph; a session
        established before the activation will not carry the role):
          * Application Administrator OR Cloud Application Administrator OR
            Global Administrator -- app registration + service principals
          * Privileged Role Administrator OR Global Administrator -- only when
            -GrantConsent is used (tenant-wide admin consent incl. the
            protected RoleManagement.ReadWrite.Directory scope)
        The script pre-flights these and stops with actionable guidance when
        a required role is missing or not yet activated.

.PARAMETER ExtensionId
    The Edge extension id assigned when you load the unpacked extension at
    edge://extensions (Developer Mode -> Load unpacked). Used to build the
    SPA redirect URI: https://<ExtensionId>.chromiumapp.org/

.PARAMETER DisplayName
    Display name of the app registration. Default: "PIM Activator".

.PARAMETER GrantConsent
    Also grant tenant-wide admin consent for the delegated permissions so
    individual users don't get the consent prompt on first sign-in. Requires
    the caller to be Privileged Role Administrator or higher.

.PARAMETER TenantId
    Optional. If omitted, uses whatever Connect-MgGraph defaulted to (the
    -TenantId you passed, or the home tenant of the signed-in account).

.EXAMPLE
    # Zero-arg -- script auto-runs Connect-MgGraph interactively if no
    # context exists, with the right scopes:
    .\Deploy-PimActivatorBackend.ps1

.EXAMPLE
    # Skip auto-connect by pre-connecting yourself (useful when scripting
    # against a specific tenant):
    Connect-MgGraph -TenantId <tenant-id> -Scopes 'Application.ReadWrite.All','AppRoleAssignment.ReadWrite.All','DelegatedPermissionGrant.ReadWrite.All'
    .\Deploy-PimActivatorBackend.ps1 -ExtensionId 'abcd...wxyz' -GrantConsent

.NOTES
    Re-runnable: if an app with the same DisplayName already exists in the
    tenant, the script updates its redirect URI + required permissions in
    place rather than creating a duplicate.
#>
[CmdletBinding()]
param(
    # Extension id is derived from the manifest.json "key" field, which is
    # identical across every install of this distribution -- so default it
    # rather than make every operator look it up. Override only if you fork
    # the extension under a different key.
    [ValidatePattern('^[a-p]{32}$')]   # Chromium extension id format
    [string]$ExtensionId = 'eheocihmlppcophaeakmdenhgcookkab',

    [string]$DisplayName = 'PIM Activator',

    [string]$TenantId,

    # Default ON: a fresh app reg without admin consent makes every user hit
    # the per-user consent dialog on first sign-in, which most operators don't
    # want. Pass -GrantConsent:$false to skip the tenant-wide consent step
    # (rare -- e.g. when the caller doesn't hold Privileged Role Administrator
    # and a delegated approver will consent later via the Enterprise apps blade).
    [switch]$GrantConsent = $true,

    # Default ON: run the interactive sign-in through Microsoft Edge
    # explicitly instead of the system default browser. MSAL's interactive
    # flow launches whatever the OS default handler is -- on servers that is
    # often legacy Internet Explorer, which mangles the auth redirect and
    # kills the flow with MSAL's 'state mismatch' error, re-prompting on
    # every Graph call. Uses the same first-party 'Microsoft Graph Command
    # Line Tools' app as Connect-MgGraph (auth-code + PKCE on a loopback
    # listener), so no extra app registration or consent. Pass
    # -UseEdge:$false to fall back to MSAL's default-browser flow.
    [switch]$UseEdge = $true
)

$ErrorActionPreference = 'Stop'

# Version banner -- VERSION lives at the PIM4EntraPS solution root, two
# levels up from tools/pim-activator/.
$_versionFile = Join-Path $PSScriptRoot '..\..\VERSION'
$_scriptVer   = if (Test-Path $_versionFile) { 'v' + (Get-Content $_versionFile -TotalCount 1).Trim() } else { '(VERSION file not found)' }
Write-Host "Deploy-PimActivatorBackend -- PIM4EntraPS $_scriptVer" -ForegroundColor Cyan

# Mixed Microsoft.Graph submodule versions (a stale install loaded alongside a
# newer one) cause exactly the failures this script has hit in the field:
# cmdlets returning silent `$null instead of erroring, and token requests that
# bypass the cache and re-prompt interactively on every call. Verify the
# loaded trio agree before doing anything.
$_graphMods = 'Microsoft.Graph.Authentication', 'Microsoft.Graph.Applications', 'Microsoft.Graph.Identity.SignIns' |
    ForEach-Object { Import-Module $_ -PassThru -ErrorAction Stop }
$_graphVers = @($_graphMods | ForEach-Object { $_.Version.ToString() } | Sort-Object -Unique)
if ($_graphVers.Count -gt 1) {
    $detail = ($_graphMods | ForEach-Object { "$($_.Name) $($_.Version)" }) -join ', '
    throw "Mixed Microsoft.Graph module versions loaded in this session: $detail. All Microsoft.Graph.* submodules must be the SAME version -- this mismatch causes silent cmdlet failures and broken token caching. Fix: close ALL PowerShell sessions, remove the stale versions (Get-InstalledModule Microsoft.Graph* -AllVersions to inspect, Uninstall-Module <name> -RequiredVersion <old>), or Update-Module Microsoft.Graph -Force, then retry in a fresh session."
}
Write-Host "Graph SDK  : v$($_graphVers[0])" -ForegroundColor Cyan

# ---------------------------------------------------------------------------
# Connect (or verify) Microsoft Graph
# ---------------------------------------------------------------------------

$_requiredScopes = @(
    'Application.ReadWrite.All'
    'AppRoleAssignment.ReadWrite.All'
    'DelegatedPermissionGrant.ReadWrite.All'
)

$_connectArgs = @{ Scopes = $_requiredScopes; NoWelcome = $true; ErrorAction = 'Stop' }
if ($TenantId) { $_connectArgs['TenantId'] = $TenantId }

# Interactive sign-in forced through Microsoft Edge (-UseEdge). MSAL offers
# no way to pick the browser, so this runs the auth-code + PKCE flow itself:
# loopback TcpListener (no HttpListener URL-ACL requirement, works
# non-elevated), Edge launched explicitly on the authorize URL, token
# exchanged and handed to Connect-MgGraph -AccessToken.
function Connect-MgGraphViaEdge {
    param([string[]]$Scopes, [string]$Tenant)

    $clientId = '14d82eec-204b-4c2f-b7e8-296a70dab67e'   # Microsoft Graph Command Line Tools (same app Connect-MgGraph uses)
    $edge = @(
        (Join-Path ${env:ProgramFiles(x86)} 'Microsoft\Edge\Application\msedge.exe'),
        (Join-Path $env:ProgramFiles 'Microsoft\Edge\Application\msedge.exe')
    ) | Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1
    if (-not $edge) { throw 'msedge.exe not found under Program Files -- cannot use -UseEdge on this host.' }

    # PKCE verifier + S256 challenge
    $bytes = New-Object byte[] 32
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    $verifier  = [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
    $sha       = [System.Security.Cryptography.SHA256]::Create()
    $challenge = [Convert]::ToBase64String($sha.ComputeHash([System.Text.Encoding]::ASCII.GetBytes($verifier))).TrimEnd('=').Replace('+', '-').Replace('/', '_')
    $state     = [guid]::NewGuid().ToString('N')

    # Loopback listener on an OS-assigned free port. First-party public
    # clients accept any localhost port on the redirect URI.
    $tcp = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, 0)
    $tcp.Start()
    $port     = ([System.Net.IPEndPoint]$tcp.LocalEndpoint).Port
    $redirect = "http://localhost:$port/"

    $scopeStr = [uri]::EscapeDataString(((@($Scopes) + 'openid', 'profile', 'offline_access') -join ' '))
    $authUrl  = "https://login.microsoftonline.com/$Tenant/oauth2/v2.0/authorize" +
                "?client_id=$clientId&response_type=code&response_mode=query" +
                "&redirect_uri=$([uri]::EscapeDataString($redirect))" +
                "&scope=$scopeStr&state=$state" +
                "&code_challenge=$challenge&code_challenge_method=S256&prompt=select_account"

    Write-Host "Launching Edge for sign-in (loopback listener on $redirect)..." -ForegroundColor Yellow
    Start-Process -FilePath $edge -ArgumentList @('--new-window', $authUrl)

    $query = $null
    try {
        $deadline = (Get-Date).AddMinutes(5)
        while (-not $query) {
            if ((Get-Date) -gt $deadline) { throw 'Timed out (5 min) waiting for the sign-in redirect from Edge.' }
            if (-not $tcp.Pending()) { Start-Sleep -Milliseconds 200; continue }
            $client = $tcp.AcceptTcpClient()
            try {
                $stream      = $client.GetStream()
                $reader      = New-Object System.IO.StreamReader($stream)
                $requestLine = $reader.ReadLine()
                $html   = '<html><body style="font-family:sans-serif"><h3>Sign-in complete.</h3>You can close this tab and return to PowerShell.</body></html>'
                $writer = New-Object System.IO.StreamWriter($stream)
                $writer.Write("HTTP/1.1 200 OK`r`nContent-Type: text/html`r`nContent-Length: $($html.Length)`r`nConnection: close`r`n`r`n$html")
                $writer.Flush()
                if ($requestLine -match '^GET /\?(\S+) HTTP') { $query = $Matches[1] }
            } finally { $client.Close() }
        }
    } finally { $tcp.Stop() }

    $kv = @{}
    foreach ($pair in ($query -split '&')) {
        $k, $v = $pair -split '=', 2
        $kv[$k] = if ($null -ne $v) { [uri]::UnescapeDataString(($v -replace '\+', ' ')) } else { '' }
    }
    if ($kv['error'])             { throw "Sign-in failed: $($kv['error']) -- $($kv['error_description'])" }
    if ($kv['state'] -ne $state)  { throw 'State mismatch on the loopback redirect -- the response did not come from this sign-in attempt. Close ALL browser windows and retry.' }
    if (-not $kv['code'])         { throw 'Sign-in redirect carried no authorization code.' }

    $tok = Invoke-RestMethod -Method POST -Uri "https://login.microsoftonline.com/$Tenant/oauth2/v2.0/token" -ContentType 'application/x-www-form-urlencoded' -Body @{
        client_id     = $clientId
        grant_type    = 'authorization_code'
        code          = $kv['code']
        redirect_uri  = $redirect
        code_verifier = $verifier
        scope         = (@($Scopes) -join ' ')
    }
    Connect-MgGraph -AccessToken (ConvertTo-SecureString $tok.access_token -AsPlainText -Force) -NoWelcome -ErrorAction Stop | Out-Null
    Write-Host 'Connected via Edge sign-in (token valid ~1 hour).' -ForegroundColor Green
}

function Invoke-PaGraphConnect {
    if ($UseEdge) {
        Connect-MgGraphViaEdge -Scopes $_requiredScopes -Tenant $(if ($TenantId) { $TenantId } else { 'organizations' })
    } else {
        Connect-MgGraph @_connectArgs | Out-Null
    }
}

$ctx = Get-MgContext -ErrorAction SilentlyContinue

if ($UseEdge -and $ctx -and $ctx.TokenCredentialType -ne 'UserProvidedAccessToken') {
    # A cached MSAL context re-auths through the SYSTEM DEFAULT browser the
    # moment any call needs a fresh token -- the exact behavior -UseEdge
    # exists to avoid (field case: IE and Edge both opened, the IE attempt
    # died on state-mismatch). Discard it and sign in through Edge instead.
    Write-Host "Discarding cached MSAL Graph session (it would re-auth via the system default browser)..." -ForegroundColor Yellow
    Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
    $ctx = $null
}

if (-not $ctx) {
    Write-Host "Not connected to Microsoft Graph. Launching sign-in (scopes: $($_requiredScopes -join ', '))..." -ForegroundColor Yellow
    Invoke-PaGraphConnect
    $ctx = Get-MgContext -ErrorAction Stop
}

$missingScopes = $_requiredScopes | Where-Object { $_ -notin $ctx.Scopes }
if ($missingScopes -and $ctx.TokenCredentialType -eq 'UserProvidedAccessToken') {
    # Edge-flow and operator-provided tokens both land here: scope
    # introspection is unreliable for provided tokens and re-connecting
    # would discard the token -- trust it and let the actual Graph calls be
    # the judge. (The Edge flow requested exactly $_requiredScopes itself.)
    if (-not $UseEdge) {
        Write-Host "Session uses a user-provided access token -- skipping scope verification (required: $($_requiredScopes -join ', '))." -ForegroundColor DarkYellow
    }
    $missingScopes = $null
}
if ($missingScopes) {
    Write-Host "Current Graph session is missing required scopes: $($missingScopes -join ', '). Re-connecting..." -ForegroundColor Yellow
    Invoke-PaGraphConnect
    $ctx = Get-MgContext -ErrorAction Stop
    $stillMissing = $_requiredScopes | Where-Object { $_ -notin $ctx.Scopes }
    if ($stillMissing -and $ctx.TokenCredentialType -ne 'UserProvidedAccessToken') {
        throw "After re-connect, Graph session is STILL missing: $($stillMissing -join ', '). Admin consent may be required."
    }
}

if ($TenantId -and $TenantId -ne $ctx.TenantId) {
    throw "Connected to tenant $($ctx.TenantId) but -TenantId says $TenantId. Reconnect with the correct -TenantId."
}
$TenantId = $ctx.TenantId

# A cached context can outlive its ability to mint tokens (refresh token
# expired/evicted, Conditional Access reauth policy). Without this probe, the
# FIRST real Graph call mid-script triggers a surprise interactive sign-in --
# which on managed servers often dies with MSAL's state-mismatch error (a
# proxy / security product truncating the redirect URL). Validate up front
# and reconnect cleanly instead.
# The guidance shown whenever this host cannot complete browser auth.
$_brokenAuthHelp = @"
This host cannot complete the sign-in. Known causes + fixes, in order of likelihood:
  1. Mixed Microsoft.Graph module versions (confirmed field cause of silent failures + MSAL 'state mismatch' loops): Get-InstalledModule Microsoft.Graph* -AllVersions -- remove old versions, start a FRESH PowerShell session, retry.
  2. The system default browser is legacy Internet Explorer, which mangles the auth redirect. This script defaults to -UseEdge (launches Edge explicitly) to avoid that; if you passed -UseEdge:`$false, drop it. To fix the host itself: Settings > Default apps > set Microsoft Edge as default for HTTP/HTTPS.
  3. Stale pending sign-in tabs answering the listener with an old state: close ALL browser windows, retry once.
  4. Run this script from another machine where sign-in works (it only talks to Graph -- nothing tenant-side requires this host).
  5. Pre-connect with an access token minted via Az PowerShell's WAM broker (native account picker, no browser involved):
       Connect-AzAccount -TenantId <tenant-id>     # if it opens a browser instead of a native window: Update-AzConfig -EnableLoginByWam `$true
       `$t = Get-AzAccessToken -ResourceUrl 'https://graph.microsoft.com'
       `$sec = if (`$t.Token -is [securestring]) { `$t.Token } else { ConvertTo-SecureString `$t.Token -AsPlainText -Force }
       Connect-MgGraph -AccessToken `$sec
     then re-run this script in the same session.
"@

try {
    Invoke-MgGraphRequest -Method GET -Uri 'v1.0/me?$select=id' | Out-Null
} catch {
    if ($ctx.TokenCredentialType -eq 'UserProvidedAccessToken' -and -not $UseEdge) {
        throw ("The pre-connected access token was rejected: $($_.Exception.Message)`nProvided tokens expire after ~1 hour -- mint a fresh one and Connect-MgGraph -AccessToken again.")
    }
    Write-Host "Cached Graph session can no longer mint tokens -- reconnecting fresh..." -ForegroundColor Yellow
    Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
    try {
        Invoke-PaGraphConnect
        $ctx = Get-MgContext -ErrorAction Stop
        $TenantId = $ctx.TenantId
        Invoke-MgGraphRequest -Method GET -Uri 'v1.0/me?$select=id' | Out-Null
    } catch {
        throw ("Re-connect failed: $($_.Exception.Message)`n$_brokenAuthHelp")
    }
}

Write-Host "Tenant   : $TenantId"  -ForegroundColor Cyan
Write-Host "Signed-in: $($ctx.Account)" -ForegroundColor Cyan
Write-Host ""

# ---------------------------------------------------------------------------
# Pre-flight: verify the signed-in admin's ACTIVE directory roles
# ---------------------------------------------------------------------------

# PIM-eligible roles do NOT count until activated, and a Graph session
# established BEFORE the activation may not reflect it. Check up front so the
# operator gets one clear message instead of a confusing mid-run 403 (or the
# SDK's silent-empty-result variant of one).
function Assert-ActiveEntraRoles {
    param([bool]$NeedsConsentRole)

    $tpl = @{   # well-known directory role template ids
        GlobalAdmin   = '62e90394-69f5-4237-9190-012177145e10'
        AppAdmin      = '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3'
        CloudAppAdmin = '158c047a-c907-4556-b7ef-446551a6b5f7'
        PrivRoleAdmin = 'e8611ab8-c189-46e8-94e1-60213ab1f814'
    }
    try {
        $resp = Invoke-MgGraphRequest -Method GET -Uri 'v1.0/me/memberOf/microsoft.graph.directoryRole?$select=displayName,roleTemplateId'
    } catch {
        # Auth failures are NOT a skippable pre-flight problem -- every later
        # Graph call will hit the same wall. Stop with reconnect guidance.
        if ("$_" -match 'authentication failed|msal-statemismatcherror|invalid_grant|AADSTS') {
            throw ("Graph authentication failed: $($_.Exception.Message)`n$_brokenAuthHelp")
        }
        # Best-effort otherwise: reading own role memberships can be blocked by
        # scope/tenant policy -- don't fail the deploy over the pre-flight.
        Write-Host "Pre-flight: could not read your active directory roles -- continuing without the check. ($($_.Exception.Message))" -ForegroundColor DarkYellow
        return
    }
    $active = @($resp.value)
    if (-not $active) {
        # Empty is INCONCLUSIVE, not proof of no active roles: listing
        # directory-role memberships needs a directory-read scope
        # (Directory.Read.All / RoleManagement.Read.Directory) that this
        # script's lean token set does not include -- without it Graph
        # silently filters the roles out of memberOf instead of returning
        # 403. Field case: operator HAD activated the roles in PIM and the
        # check still showed '(none)'. Warn and continue; the real calls
        # will 403 with clear errors if roles are genuinely missing.
        Write-Host "Pre-flight: cannot see your directory-role memberships with this token (or no roles are active) -- continuing. If later calls fail with 403: activate 'Application Administrator' or 'Cloud Application Administrator' in PIM (+ 'Privileged Role Administrator' for -GrantConsent)." -ForegroundColor DarkYellow
        Write-Host ""
        return
    }
    $names     = @($active | ForEach-Object { $_.displayName }) -join ', '
    $activeIds = @($active | ForEach-Object { $_.roleTemplateId })
    Write-Host "Active directory roles: $names" -ForegroundColor Cyan
    Write-Host ""

    $problems = @()
    if (-not ($activeIds | Where-Object { $_ -in @($tpl.GlobalAdmin, $tpl.AppAdmin, $tpl.CloudAppAdmin) })) {
        $problems += "App registration + service-principal steps need an ACTIVE 'Application Administrator', 'Cloud Application Administrator' or 'Global Administrator' role."
    }
    if ($NeedsConsentRole -and -not ($activeIds | Where-Object { $_ -in @($tpl.GlobalAdmin, $tpl.PrivRoleAdmin) })) {
        $problems += "-GrantConsent (tenant-wide admin consent incl. the protected RoleManagement.ReadWrite.Directory scope) needs an ACTIVE 'Privileged Role Administrator' or 'Global Administrator' role. Alternative: re-run with -GrantConsent:`$false and have an authorized admin consent later via the Enterprise applications blade."
    }
    if ($problems) {
        throw ("Missing ACTIVE Entra roles:`n  - " + ($problems -join "`n  - ") + "`nIf these roles are PIM-eligible, activate them in PIM first, then run Disconnect-MgGraph and re-run this script so the new Graph session is established AFTER the activation.")
    }
}

Assert-ActiveEntraRoles -NeedsConsentRole:([bool]$GrantConsent)

# ---------------------------------------------------------------------------
# Resolve Microsoft Graph delegated permission ids
# ---------------------------------------------------------------------------

# First-party Microsoft service principals (Graph, ARM) are NOT guaranteed to
# exist in every tenant -- fresh / lightly-used tenants only get them
# instantiated on first use, so resolve-or-create instead of assuming
# presence. Raw Invoke-MgGraphRequest throughout: the SDK's
# New-MgServicePrincipal has been observed returning $null (no error, no Id)
# on permission failures, masking the real API response entirely.
function Resolve-FirstPartySp {
    param([string]$AppId, [string]$Name)

    function Get-RawSpByAppId([string]$Id) {
        try {
            Invoke-MgGraphRequest -Method GET -Uri "v1.0/servicePrincipals(appId='$Id')"
        } catch {
            if ("$_" -match 'Request_ResourceNotFound|ResourceNotFound|does not exist|404') { return $null }
            throw
        }
    }

    $raw = Get-RawSpByAppId $AppId
    if (-not $raw) {
        Write-Host "  $Name service principal not present in tenant -- instantiating it (appId $AppId)..." -ForegroundColor Yellow
        try {
            Invoke-MgGraphRequest -Method POST -Uri 'v1.0/servicePrincipals' -Body @{ appId = $AppId } | Out-Null
        } catch {
            throw "$Name service principal (appId $AppId) could not be instantiated in tenant ${TenantId}: $($_.Exception.Message)"
        }
        # New SPs can take a few seconds to become queryable.
        for ($i = 0; $i -lt 6 -and -not $raw; $i++) {
            $raw = Get-RawSpByAppId $AppId
            if (-not $raw) { Start-Sleep -Seconds 2 }
        }
        if (-not $raw) {
            throw "$Name service principal (appId $AppId) was created but is not yet queryable in tenant $TenantId -- Entra replication delay. Re-run this script in a minute."
        }
    }
    # Project the raw hashtable onto the object shape downstream code consumes.
    [pscustomobject]@{
        Id                     = $raw.id
        DisplayName            = $raw.displayName
        Oauth2PermissionScopes = @($raw.oauth2PermissionScopes | ForEach-Object { [pscustomobject]@{ Id = $_.id; Value = $_.value } })
    }
}

$graphAppId = '00000003-0000-0000-c000-000000000000'
$graphSp    = Resolve-FirstPartySp -AppId $graphAppId -Name 'Microsoft Graph'

$needed = @(
    # Activation / deactivation -- POST + DELETE on
    # /privilegedAccess/aadGroups/.../assignmentScheduleRequests.
    # ReadWrite is the ONLY variant that grants the write half; Read-only
    # breaks every Activate / Deactivate click with HTTP 403. Do NOT
    # downgrade to PrivilegedAccess.Read.AzureADGroup.
    'PrivilegedAccess.ReadWrite.AzureADGroup',
    # Listing eligible groups + hydrating displayNames.
    'Group.Read.All',
    # id_token claims (account name shown in the popup header).
    'User.Read',
    # My Access tab -- resolves Entra role assignments attached to the active
    # PIM-for-Groups memberships via roleManagement/directory/roleAssignments.
    # NOTE: ReadWrite covers Read so this entry is technically redundant when
    # ReadWrite is below, but it is kept for documentation purposes / tenants
    # that prefer the smaller scope when read-only is sufficient.
    'RoleManagement.Read.Directory',
    # v1.3.0 -- activate direct Entra role assignments (role granted directly
    # to the user, no PIM group in between). Lists eligibilities AND POSTs
    # roleAssignmentScheduleRequests with action=selfActivate. Without
    # ReadWrite the Activate tab can only surface PIM-for-Groups rows;
    # activation of direct role assignments returns 403.
    'RoleManagement.ReadWrite.Directory',
    # My Access tab -- resolves Administrative Unit displayNames so the
    # scope column shows the AU name instead of "N Administrative Units".
    'AdministrativeUnit.Read.All',
    # First-run onboarding wizard (popup v1.1.2+) -- after interactive
    # sign-in the wizard queries /applications?$filter=startswith(displayName,
    # 'PIM Activator') so the admin can pick the per-tenant app reg without
    # typing the GUID. Read-only is correct here -- we never write app regs.
    'Application.Read.All'
)
$scopeMap = @{}
foreach ($name in $needed) {
    $scope = $graphSp.Oauth2PermissionScopes | Where-Object { $_.Value -eq $name }
    if (-not $scope) { throw "Delegated scope '$name' not found on Microsoft Graph SP." }
    $scopeMap[$name] = $scope.Id
    Write-Host ("  resolved {0,-45} -> {1}" -f $name, $scope.Id) -ForegroundColor DarkGray
}

# Azure Service Management API (well-known appId 797f4846-...) +
# user_impersonation. Required so the popup can mint an ARM token (separate
# audience: management.azure.com) and list Azure RBAC eligibilities + active
# assignments. Without it, the My Access tab shows a "Azure RBAC roles not
# visible yet" banner and the Azure-direct rows on Activate never load.
$asmAppId = '797f4846-ba00-4fd7-ba43-dac1f8f63013'
$asmSp    = Resolve-FirstPartySp -AppId $asmAppId -Name 'Azure Service Management'
$asmScope = $asmSp.Oauth2PermissionScopes | Where-Object { $_.Value -eq 'user_impersonation' }
if (-not $asmScope) { throw "user_impersonation scope not found on Azure Service Management SP." }
Write-Host ("  resolved {0,-45} -> {1}" -f 'user_impersonation (ASM)', $asmScope.Id) -ForegroundColor DarkGray

$requiredResourceAccess = @(
    @{
        ResourceAppId  = $graphAppId
        ResourceAccess = $needed | ForEach-Object { @{ Id = $scopeMap[$_]; Type = 'Scope' } }
    },
    @{
        ResourceAppId  = $asmAppId
        ResourceAccess = @( @{ Id = $asmScope.Id; Type = 'Scope' } )
    }
)

$redirectUri = "https://$ExtensionId.chromiumapp.org/"

# ---------------------------------------------------------------------------
# Create or update the app registration
# ---------------------------------------------------------------------------

$existing = Get-MgApplication -Filter "displayName eq '$DisplayName'" -ConsistencyLevel eventual -CountVariable c -ErrorAction SilentlyContinue
if ($existing.Count -gt 1) {
    throw "Multiple app registrations named '$DisplayName' already exist. Disambiguate (rename or specify a different -DisplayName) and re-run."
}

if ($existing) {
    Write-Host "Updating existing app registration '$DisplayName' (appId $($existing.AppId))..." -ForegroundColor Yellow
    # Modern Edge / Chrome MV3 extension auth needs BOTH SPA URIs registered:
    #   1. https://<id>.chromiumapp.org/  -- the redirect that
    #      chrome.identity.launchWebAuthFlow listens for + intercepts to extract
    #      the auth code.
    #   2. chrome-extension://<id>/  -- because the popup.js fetch() to the
    #      /oauth2/v2.0/token endpoint sends Origin: chrome-extension://<id>,
    #      and Entra's SPA flow validates the Origin header against registered
    #      redirect URIs. Without this, token redemption fails with
    #      AADSTS9002326 ("Cross-origin token redemption is permitted only for
    #      the 'Single-Page Application' client-type. Request origin:
    #      'chrome-extension://<id>'").
    # Both must be SPA type (Public Client type bounces with the same error).
    # Wipe any stale Public Client URI a previous install may have left behind.
    $extensionOrigin = "chrome-extension://$ExtensionId/"
    Update-MgApplication -ApplicationId $existing.Id `
        -Spa @{ RedirectUris = @($redirectUri, $extensionOrigin) } `
        -PublicClient @{ RedirectUris = @() } `
        -IsFallbackPublicClient:$false `
        -RequiredResourceAccess $requiredResourceAccess
    $app = Get-MgApplication -ApplicationId $existing.Id
} else {
    Write-Host "Creating app registration '$DisplayName'..." -ForegroundColor Green
    $extensionOrigin = "chrome-extension://$ExtensionId/"
    $app = New-MgApplication `
        -DisplayName $DisplayName `
        -SignInAudience 'AzureADMyOrg' `
        -Spa @{ RedirectUris = @($redirectUri, $extensionOrigin) } `
        -IsFallbackPublicClient:$false `
        -RequiredResourceAccess $requiredResourceAccess
}

# Ensure the service principal exists in the tenant (creates the enterprise
# app). Raw requests for the same silent-null reason as Resolve-FirstPartySp.
$sp = $null
try { $sp = Invoke-MgGraphRequest -Method GET -Uri "v1.0/servicePrincipals(appId='$($app.AppId)')" }
catch { if ("$_" -notmatch 'Request_ResourceNotFound|ResourceNotFound|does not exist|404') { throw } }
if (-not $sp) {
    $sp = Invoke-MgGraphRequest -Method POST -Uri 'v1.0/servicePrincipals' -Body @{ appId = $app.AppId }
    Write-Host "Created service principal (objectId $($sp.Id))." -ForegroundColor Green
} else {
    Write-Host "Service principal already present (objectId $($sp.Id))." -ForegroundColor DarkGray
}

# ---------------------------------------------------------------------------
# Optional: tenant-wide admin consent for the delegated scopes
# ---------------------------------------------------------------------------

if ($GrantConsent) {
    Write-Host ""
    Write-Host "Granting tenant-wide admin consent for delegated scopes..." -ForegroundColor Cyan
    # Include the OpenID Connect basics + offline_access alongside the Graph
    # delegated scopes. They are NOT in $needed (which lists named API
    # permissions for RequiredResourceAccess), but tenants with restrictive
    # user-consent settings route sign-ins through the "Approval required"
    # workflow whenever the requested scope set isn't fully covered by an
    # existing grant -- and the extension always asks for openid/profile/
    # offline_access. Bake them in so first-run users sign in silently.
    $scopeString = (($needed + @('openid','profile','offline_access')) -join ' ')
    $existingGrant = Get-MgOauth2PermissionGrant -Filter "clientId eq '$($sp.Id)' and consentType eq 'AllPrincipals' and resourceId eq '$($graphSp.Id)'" -ErrorAction SilentlyContinue
    if ($existingGrant) {
        Update-MgOauth2PermissionGrant -OAuth2PermissionGrantId $existingGrant.Id -Scope $scopeString
        Write-Host "  updated existing Graph consent grant" -ForegroundColor DarkGray
    } else {
        New-MgOauth2PermissionGrant -ClientId $sp.Id -ConsentType 'AllPrincipals' -ResourceId $graphSp.Id -Scope $scopeString | Out-Null
        Write-Host "  created new Graph consent grant" -ForegroundColor DarkGray
    }

    # Azure Service Management user_impersonation -- mirrors the Graph block
    # above but against the ARM SP. Without admin-consent here, the popup
    # surfaces a yellow "Azure RBAC roles not visible yet" banner until the
    # admin runs through this script with -GrantConsent.
    $existingAsmGrant = Get-MgOauth2PermissionGrant -Filter "clientId eq '$($sp.Id)' and consentType eq 'AllPrincipals' and resourceId eq '$($asmSp.Id)'" -ErrorAction SilentlyContinue
    if ($existingAsmGrant) {
        Update-MgOauth2PermissionGrant -OAuth2PermissionGrantId $existingAsmGrant.Id -Scope 'user_impersonation'
        Write-Host "  updated existing ARM consent grant" -ForegroundColor DarkGray
    } else {
        New-MgOauth2PermissionGrant -ClientId $sp.Id -ConsentType 'AllPrincipals' -ResourceId $asmSp.Id -Scope 'user_impersonation' | Out-Null
        Write-Host "  created new ARM consent grant" -ForegroundColor DarkGray
    }
}

# ---------------------------------------------------------------------------
# Emit the config the extension needs
# ---------------------------------------------------------------------------

Write-Host ""
Write-Host "==========================================================================" -ForegroundColor Green
Write-Host " PIM Activator app registration ready" -ForegroundColor Green
Write-Host "==========================================================================" -ForegroundColor Green
Write-Host ""
Write-Host "  tenantId    : $TenantId"
Write-Host "  clientId    : $($app.AppId)"
Write-Host "  redirectUri : $redirectUri"
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Yellow
Write-Host "  1. Install the CRX in Edge / Chrome (Deploy-PimActivatorClient.ps1 or sideload)."
Write-Host "  2. Open the extension popup. The first-run wizard will ask for your work email,"
Write-Host "     auto-discover this tenant + the PIM Activator app reg, and save the values"
Write-Host "     into the browser profile -- no config.js / Group Policy / Intune push needed."
if (-not $GrantConsent) {
    Write-Host ""
    Write-Host "Tip: re-run with -GrantConsent to grant tenant-wide admin consent (avoids" -ForegroundColor DarkYellow
    Write-Host "     per-user consent prompts on first sign-in)." -ForegroundColor DarkYellow
}
Write-Host ""

[pscustomobject]@{
    TenantId    = $TenantId
    ClientId    = $app.AppId
    AppObjectId = $app.Id
    SpObjectId  = $sp.Id
    RedirectUri = $redirectUri
    Scopes      = $needed
}
