# _PimActivatorAuth.ps1 -- shared Graph auth machinery for the pim-activator
# deploy scripts. Dot-source from a sibling script; defines functions only
# (no side effects on load). Extracted from Deploy-PimActivatorBackend.ps1
# v2.4.148 after a field-debugging session proved every piece necessary:
# servers whose default browser is legacy IE, stale Graph module versions
# causing silent cmdlet failures, and cached MSAL contexts re-prompting on
# every call.

# VERSION lives at the PIM4EntraPS solution root, two levels up from
# tools/pim-activator/.
function Get-PimActivatorSolutionVersion {
    $f = Join-Path $PSScriptRoot '..\..\VERSION'
    if (Test-Path $f) { 'v' + (Get-Content $f -TotalCount 1).Trim() } else { '(VERSION file not found)' }
}

# Mixed Microsoft.Graph submodule versions (a stale install loaded alongside
# a newer one) cause cmdlets returning silent $null instead of erroring, and
# token requests that bypass the cache and re-prompt interactively on every
# call. Verify the loaded set agrees before doing anything; returns the
# common version string.
function Assert-GraphModuleVersions {
    param([string[]]$Modules = @('Microsoft.Graph.Authentication'))
    $loaded = @($Modules | ForEach-Object { Import-Module $_ -PassThru -ErrorAction Stop })
    $vers   = @($loaded | ForEach-Object { $_.Version.ToString() } | Sort-Object -Unique)
    if ($vers.Count -gt 1) {
        $detail = ($loaded | ForEach-Object { "$($_.Name) $($_.Version)" }) -join ', '
        throw "Mixed Microsoft.Graph module versions loaded in this session: $detail. All Microsoft.Graph.* submodules must be the SAME version -- this mismatch causes silent cmdlet failures and broken token caching. Fix: close ALL PowerShell sessions, remove the stale versions (Get-InstalledModule Microsoft.Graph* -AllVersions to inspect, Uninstall-Module <name> -RequiredVersion <old>), or Update-Module Microsoft.Graph -Force, then retry in a fresh session."
    }
    $vers[0]
}

# The guidance shown whenever a host cannot complete the sign-in.
function Get-PaBrokenAuthHelp {
    @"
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
     then re-run the deploy script in the same session.
"@
}

# Interactive sign-in forced through Microsoft Edge. MSAL offers no way to
# pick the browser, so this runs the auth-code + PKCE flow itself: loopback
# TcpListener (no HttpListener URL-ACL requirement, works non-elevated),
# Edge launched explicitly on the authorize URL, token exchanged and handed
# to Connect-MgGraph -AccessToken.
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

# One-stop connect: discard cached MSAL contexts in Edge mode (they re-auth
# through the SYSTEM DEFAULT browser -- field case: IE and Edge opened side
# by side, the IE attempt died on state-mismatch), connect via Edge or MSAL,
# verify scopes (skipped for provided tokens -- introspection is unreliable
# and reconnecting would discard the token), enforce -TenantId, then probe
# with a cheap /me call so a context that can no longer mint tokens is
# reconnected cleanly instead of exploding mid-run. Returns the context.
function Connect-PimActivatorGraph {
    param(
        [Parameter(Mandatory)][string[]]$RequiredScopes,
        [string]$TenantId,
        [bool]$UseEdge = $true
    )

    $connectArgs = @{ Scopes = $RequiredScopes; NoWelcome = $true; ErrorAction = 'Stop' }
    if ($TenantId) { $connectArgs['TenantId'] = $TenantId }

    function Connect-Once {
        if ($UseEdge) {
            Connect-MgGraphViaEdge -Scopes $RequiredScopes -Tenant $(if ($TenantId) { $TenantId } else { 'organizations' })
        } else {
            Connect-MgGraph @connectArgs | Out-Null
        }
    }

    $ctx = Get-MgContext -ErrorAction SilentlyContinue
    if ($UseEdge -and $ctx -and $ctx.TokenCredentialType -ne 'UserProvidedAccessToken') {
        Write-Host 'Discarding cached MSAL Graph session (it would re-auth via the system default browser)...' -ForegroundColor Yellow
        Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
        $ctx = $null
    }
    if (-not $ctx) {
        Write-Host "Not connected to Microsoft Graph. Launching sign-in (scopes: $($RequiredScopes -join ', '))..." -ForegroundColor Yellow
        Connect-Once
        $ctx = Get-MgContext -ErrorAction Stop
    }

    $missingScopes = $RequiredScopes | Where-Object { $_ -notin $ctx.Scopes }
    if ($missingScopes -and $ctx.TokenCredentialType -eq 'UserProvidedAccessToken') {
        if (-not $UseEdge) {
            Write-Host "Session uses a user-provided access token -- skipping scope verification (required: $($RequiredScopes -join ', '))." -ForegroundColor DarkYellow
        }
        $missingScopes = $null
    }
    if ($missingScopes) {
        Write-Host "Current Graph session is missing required scopes: $($missingScopes -join ', '). Re-connecting..." -ForegroundColor Yellow
        Connect-Once
        $ctx = Get-MgContext -ErrorAction Stop
        $stillMissing = $RequiredScopes | Where-Object { $_ -notin $ctx.Scopes }
        if ($stillMissing -and $ctx.TokenCredentialType -ne 'UserProvidedAccessToken') {
            throw "After re-connect, Graph session is STILL missing: $($stillMissing -join ', '). Admin consent may be required."
        }
    }

    if ($TenantId -and $TenantId -ne $ctx.TenantId) {
        throw "Connected to tenant $($ctx.TenantId) but -TenantId says $TenantId. Reconnect with the correct -TenantId."
    }

    try {
        Invoke-MgGraphRequest -Method GET -Uri 'v1.0/me?$select=id' | Out-Null
    } catch {
        if ($ctx.TokenCredentialType -eq 'UserProvidedAccessToken' -and -not $UseEdge) {
            throw ("The pre-connected access token was rejected: $($_.Exception.Message)`nProvided tokens expire after ~1 hour -- mint a fresh one and Connect-MgGraph -AccessToken again.")
        }
        Write-Host 'Cached Graph session can no longer mint tokens -- reconnecting fresh...' -ForegroundColor Yellow
        Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
        try {
            Connect-Once
            $ctx = Get-MgContext -ErrorAction Stop
            Invoke-MgGraphRequest -Method GET -Uri 'v1.0/me?$select=id' | Out-Null
        } catch {
            throw ("Re-connect failed: $($_.Exception.Message)`n$(Get-PaBrokenAuthHelp)")
        }
    }
    $ctx
}
