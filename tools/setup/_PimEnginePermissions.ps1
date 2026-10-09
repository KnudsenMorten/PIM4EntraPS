# _PimEnginePermissions.ps1 -- the pieces behind Grant-PimEnginePermissions.ps1: browser sign-in, one REST seam for
# Microsoft Graph and Azure Resource Manager, the pure request builders, and the grant itself. Dot-source it; it defines
# functions only (no side effects on load).
#
# NO MODULES (owner 2026-10-07: "neither pim, si or invardia must have dependencies"): plain Invoke-RestMethod + .NET.
# Sign-in is auth code + PKCE on a localhost loopback in the browser (Edge launched explicitly, the default browser when
# Edge is missing) -- the pattern proven by the PIM Activator deploy scripts:
#   * Microsoft Graph: the first-party "Microsoft Graph Command Line Tools" public client.
#   * Azure Resource Manager (only when Azure role assignments are asked for): the first-party "Microsoft Azure
#     PowerShell" public client, which is pre-authorized for Azure Resource Manager in every tenant.
# Nothing from the engine tree is loaded: the script is published as ONE standalone file at
# https://invardia.com/support/pim/Grant-PimEnginePermissions.ps1 (tools/setup/Build-PimSupportScripts.ps1 inlines this).

# ---- constants --------------------------------------------------------------------------------------------------------
function Get-PimEpGraphCliClientId { '14d82eec-204b-4c2f-b7e8-296a70dab67e' }      # Microsoft Graph Command Line Tools
function Get-PimEpAzurePowerShellClientId { '1950a258-227b-4e31-a9cf-717495945fc2' } # Microsoft Azure PowerShell
function Get-PimEpGraphAppId { '00000003-0000-0000-c000-000000000000' }             # Microsoft Graph (the resource)
function Get-PimEpGraphScopes { @('AppRoleAssignment.ReadWrite.All', 'Application.Read.All') }
function Get-PimEpArmScope { 'https://management.azure.com/user_impersonation' }
function Get-PimEpArmApiVersion { '2022-04-01' }

# Built-in Azure roles by name (the ids are the same in every tenant); any other name is looked up at the scope.
function Get-PimEpBuiltInAzureRoles {
    @{
        'owner'                                   = '8e3af657-a8ff-443c-a75c-2fe8c4bcb635'
        'contributor'                             = 'b24988ac-6180-42a0-ab88-20f7382dd24c'
        'reader'                                  = 'acdd72a7-3385-48ef-bd42-f606fba81ae7'
        'user access administrator'               = '18d7d88d-d35e-4fb5-a5c3-7773c20a72d9'
        'role based access control administrator' = 'f58310d9-a9f6-439a-9e8d-f62e7b41a168'
    }
}

function Test-PimEpGuid {
    param([AllowEmptyString()][string]$Text)
    "$Text" -match '^[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}$'
}

# VERSION at the solution root (two levels up from tools/setup); a standalone copy reads the header the build writes.
function Get-PimEpSolutionVersion {
    $f = Join-Path $PSScriptRoot '..\..\VERSION'
    if (Test-Path -LiteralPath $f) { return 'v' + (Get-Content -LiteralPath $f -TotalCount 1).Trim() }
    foreach ($self in @($PSCommandPath, $MyInvocation.ScriptName) | Where-Object { $_ }) {
        try {
            foreach ($l in @(Get-Content -LiteralPath $self -TotalCount 5 -ErrorAction Stop)) { if ($l -match '^# PIM Manager (\S+) --') { return 'v' + $Matches[1] + ' (standalone)' } }
        } catch { }
    }
    '(version not known)'
}

# ---- list + spec parsing (pure) ---------------------------------------------------------------------------------------
# A list parameter as clean items: "a,b" (one string, as `pwsh -File` passes it) and 'a','b' both become a, b.
function ConvertTo-PimEpList {
    param([object[]]$Items)
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($i in @($Items)) {
        if ($null -eq $i) { continue }
        foreach ($p in ("$i" -split ',')) { $t = $p.Trim().Trim("'").Trim('"').Trim(); if ($t -and -not $out.Contains($t)) { $out.Add($t) } }
    }
    $out.ToArray()
}

# An application permission: 'Group.ReadWrite.All' (Microsoft Graph) or '<Role>@<resource appId>' (another API, e.g.
# 'Exchange.ManageAsApp@00000002-0000-0ff1-ce00-000000000000'). Returns @{ value; resourceAppId; spec }.
function ConvertTo-PimEpAppRoleSpec {
    param([Parameter(Mandatory)][string]$Spec, [string]$DefaultResourceAppId = (Get-PimEpGraphAppId))
    $s = $Spec.Trim()
    $value = $s; $res = $DefaultResourceAppId
    if ($s -match '^(?<v>[^@]+)@(?<r>[^@]+)$') { $value = $Matches['v'].Trim(); $res = $Matches['r'].Trim() }
    if (-not $value -or $value -match '\s') { throw "Not an application permission name: '$Spec'." }
    if (-not (Test-PimEpGuid $res)) { throw "The API in '$Spec' must be its application (client) id, a GUID." }
    [pscustomobject]@{ value = $value; resourceAppId = $res.ToLowerInvariant(); spec = $s }
}

# An Azure role assignment: '<role name or role definition id>@<scope>', e.g.
# 'User Access Administrator@/providers/Microsoft.Management/managementGroups/<tenant id>'. Returns
# @{ role; roleDefinitionGuid (or $null = look the name up); scope; spec }.
function ConvertTo-PimEpAzureRoleSpec {
    param([Parameter(Mandatory)][string]$Spec)
    $s = $Spec.Trim()
    $i = $s.LastIndexOf('@')
    if ($i -lt 1) { throw "An Azure role assignment is '<role>@<scope>' (e.g. 'User Access Administrator@/subscriptions/<id>'): '$Spec'." }
    $role = $s.Substring(0, $i).Trim(); $scope = $s.Substring($i + 1).Trim()
    if (-not $scope.StartsWith('/')) { throw "The scope in '$Spec' must start with '/' (e.g. /subscriptions/<id> or /providers/Microsoft.Management/managementGroups/<id>)." }
    if ($scope.Length -gt 1) { $scope = $scope.TrimEnd('/') }
    $guid = $null
    if (Test-PimEpGuid $role) { $guid = $role.ToLowerInvariant() }
    else {
        $known = Get-PimEpBuiltInAzureRoles
        $k = $role.ToLowerInvariant()
        if ($known.ContainsKey($k)) { $guid = $known[$k] }
    }
    [pscustomobject]@{ role = $role; roleDefinitionGuid = $guid; scope = $scope; spec = $s }
}

# ---- request builders (pure) ------------------------------------------------------------------------------------------
# POST /servicePrincipals/{resource}/appRoleAssignedTo -- the body that gives the engine one application permission.
function New-PimEpAppRoleAssignmentRequest {
    param([Parameter(Mandatory)][string]$PrincipalId, [Parameter(Mandatory)][string]$ResourceId, [Parameter(Mandatory)][string]$AppRoleId)
    [pscustomobject]@{
        Method = 'POST'
        Path   = "/servicePrincipals/$ResourceId/appRoleAssignedTo"
        Body   = [ordered]@{ principalId = $PrincipalId; resourceId = $ResourceId; appRoleId = $AppRoleId }
    }
}

# The full role definition id at a scope ('/' = tenant root: no prefix).
function Get-PimEpRoleDefinitionId {
    param([Parameter(Mandatory)][string]$Scope, [Parameter(Mandatory)][string]$RoleDefinitionGuid)
    $prefix = if ($Scope -eq '/') { '' } else { $Scope.TrimEnd('/') }
    "$prefix/providers/Microsoft.Authorization/roleDefinitions/$RoleDefinitionGuid"
}

# PUT {scope}/providers/Microsoft.Authorization/roleAssignments/{new GUID} -- one Azure role for the engine.
# principalType ServicePrincipal: ARM then does not wait for directory replication of a freshly made identity.
function New-PimEpArmRoleAssignmentRequest {
    param(
        [Parameter(Mandatory)][string]$Scope,
        [Parameter(Mandatory)][string]$RoleDefinitionGuid,
        [Parameter(Mandatory)][string]$PrincipalId,
        [string]$AssignmentId = ([guid]::NewGuid().ToString())
    )
    $prefix = if ($Scope -eq '/') { '' } else { $Scope.TrimEnd('/') }
    [pscustomobject]@{
        Method       = 'PUT'
        Path         = "$prefix/providers/Microsoft.Authorization/roleAssignments/$($AssignmentId)?api-version=$(Get-PimEpArmApiVersion)"
        AssignmentId = $AssignmentId
        Body         = [ordered]@{ properties = [ordered]@{
            roleDefinitionId = (Get-PimEpRoleDefinitionId -Scope $Scope -RoleDefinitionGuid $RoleDefinitionGuid)
            principalId      = $PrincipalId
            principalType    = 'ServicePrincipal'
        } }
    }
}

# Which application permissions are still to grant. -ResourceSps maps resource appId -> its service principal
# (id, displayName, appRoles) or $null when the API has no service principal in the tenant. -Existing = the engine's
# appRoleAssignments (resourceId, appRoleId). Each item: action grant | present | unknown-role | no-resource.
function Get-PimEpAppRolePlan {
    param([object[]]$Wanted, [hashtable]$ResourceSps, [object[]]$Existing)
    $have = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($a in @($Existing)) { if ($a) { [void]$have.Add("$($a.resourceId)|$($a.appRoleId)") } }
    foreach ($w in @($Wanted)) {
        if (-not $w) { continue }
        $sp = $null; if ($ResourceSps -and $ResourceSps.ContainsKey($w.resourceAppId)) { $sp = $ResourceSps[$w.resourceAppId] }
        $item = [ordered]@{ value = $w.value; resourceAppId = $w.resourceAppId; resourceName = ''; resourceId = ''; appRoleId = ''; action = '' }
        if (-not $sp) { $item.action = 'no-resource'; [pscustomobject]$item; continue }
        $item.resourceName = "$($sp.displayName)"; $item.resourceId = "$($sp.id)"
        $role = @(@($sp.appRoles) | Where-Object { $_ -and "$($_.value)" -eq $w.value -and @($_.allowedMemberTypes) -contains 'Application' }) | Select-Object -First 1
        if (-not $role) { $item.action = 'unknown-role'; [pscustomobject]$item; continue }
        $item.appRoleId = "$($role.id)"
        $item.action = if ($have.Contains("$($sp.id)|$($role.id)")) { 'present' } else { 'grant' }
        [pscustomobject]$item
    }
}

# Does the engine already hold the role at (or above) the scope? -Assignments = ARM roleAssignments (properties.scope,
# properties.roleDefinitionId). Exact scope, the tenant root '/', or a parent path (a subscription above a resource
# group) count; a management-group parent is not visible from the path and is simply granted again (harmless).
function Find-PimEpArmAssignment {
    param([object[]]$Assignments, [Parameter(Mandatory)][string]$Scope, [Parameter(Mandatory)][string]$RoleDefinitionGuid)
    $target = $Scope.TrimEnd('/').ToLowerInvariant(); if (-not $target) { $target = '/' }
    foreach ($a in @($Assignments)) {
        if (-not $a -or -not $a.properties) { continue }
        $rd = "$($a.properties.roleDefinitionId)".ToLowerInvariant()
        if (-not $rd.EndsWith('/' + $RoleDefinitionGuid.ToLowerInvariant())) { continue }
        $s = "$($a.properties.scope)".TrimEnd('/').ToLowerInvariant(); if (-not $s) { $s = '/' }
        if ($s -eq $target) { return [pscustomobject]@{ how = 'exact'; scope = "$($a.properties.scope)"; id = "$($a.id)" } }
        if ($s -eq '/' -or $target.StartsWith($s + '/')) { return [pscustomobject]@{ how = 'inherited'; scope = "$($a.properties.scope)"; id = "$($a.id)" } }
    }
    $null
}

# ---- browser sign-in --------------------------------------------------------------------------------------------------
function ConvertTo-PimEpB64Url {
    param([Parameter(Mandatory)][byte[]]$Bytes)
    [Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

# The claims of a JWT (no signature check; only tid / upn / exp are read). $null when not a readable JWT.
function ConvertFrom-PimEpJwtClaims {
    param([AllowEmptyString()][string]$Token)
    if (-not $Token) { return $null }
    $parts = $Token -split '\.'
    if ($parts.Count -lt 2) { return $null }
    $s = $parts[1].Replace('-', '+').Replace('_', '/')
    switch ($s.Length % 4) { 2 { $s += '==' } 3 { $s += '=' } }
    try { [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($s)) | ConvertFrom-Json } catch { $null }
}

function New-PimEpPkcePair {
    $bytes = New-Object byte[] 32
    [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    $verifier = ConvertTo-PimEpB64Url $bytes
    $challenge = ConvertTo-PimEpB64Url ([Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::ASCII.GetBytes($verifier)))
    [pscustomobject]@{ Verifier = $verifier; Challenge = $challenge }
}

# The delegated scope string: bare Graph names are qualified, OIDC basics appended once.
function Get-PimEpScopeString {
    param([Parameter(Mandatory)][string[]]$Scopes)
    $q = @($Scopes | Where-Object { $_ } | ForEach-Object { if ($_ -match '^(https?://|openid$|profile$|offline_access$)') { $_ } else { "https://graph.microsoft.com/$_" } })
    (@($q) + @('openid', 'profile', 'offline_access') | Select-Object -Unique) -join ' '
}

function New-PimEpAuthorizeUrl {
    param(
        [Parameter(Mandatory)][string]$Tenant, [Parameter(Mandatory)][string]$ClientId, [Parameter(Mandatory)][string]$RedirectUri,
        [Parameter(Mandatory)][string]$Scope, [Parameter(Mandatory)][string]$State, [Parameter(Mandatory)][string]$CodeChallenge,
        [string]$LoginHint
    )
    $u = "https://login.microsoftonline.com/$Tenant/oauth2/v2.0/authorize" +
        "?client_id=$ClientId&response_type=code&response_mode=query" +
        "&redirect_uri=$([uri]::EscapeDataString($RedirectUri))" +
        "&scope=$([uri]::EscapeDataString($Scope))&state=$State" +
        "&code_challenge=$CodeChallenge&code_challenge_method=S256"
    if ($LoginHint) { $u += "&login_hint=$([uri]::EscapeDataString($LoginHint))" } else { $u += '&prompt=select_account' }
    $u
}

function Get-PimEpEdgePath {
    @(
        $(if (${env:ProgramFiles(x86)}) { Join-Path ${env:ProgramFiles(x86)} 'Microsoft\Edge\Application\msedge.exe' }),
        $(if ($env:ProgramFiles) { Join-Path $env:ProgramFiles 'Microsoft\Edge\Application\msedge.exe' }),
        $(if ($env:LOCALAPPDATA) { Join-Path $env:LOCALAPPDATA 'Microsoft\Edge\Application\msedge.exe' })
    ) | Where-Object { $_ -and (Test-Path -LiteralPath $_) } | Select-Object -First 1
}

function Get-PimEpBrokenAuthHelp {
    @"
This computer could not complete the sign-in. Known causes, in order of likelihood:
  1. The default browser is legacy Internet Explorer: this script opens Microsoft Edge (-UseEdge `$true, the default). If you passed -UseEdge `$false, drop it.
  2. An old sign-in tab answered: close ALL browser windows and run the script again.
  3. Something blocks the local listener the browser answers to (a firewall or proxy rule for 127.0.0.1): allow it, or run the script on another computer.
  4. Bring tokens: -GraphAccessToken (scopes AppRoleAssignment.ReadWrite.All + Application.Read.All) and, for Azure roles, -ArmAccessToken.
"@
}

# Interactive sign-in: auth code + PKCE on a loopback TcpListener (works without elevation), Edge launched explicitly,
# the default browser when Edge is missing or -UseEdge is $false. Returns the token response.
function Get-PimEpInteractiveToken {
    param(
        [Parameter(Mandatory)][string]$ClientId,
        [Parameter(Mandatory)][string[]]$Scopes,
        [string]$Tenant = 'organizations',
        [bool]$UseEdge = $true,
        [string]$LoginHint
    )
    $pkce  = New-PimEpPkcePair
    $state = [guid]::NewGuid().ToString('N')
    $scope = Get-PimEpScopeString -Scopes $Scopes
    $tcp = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, 0)
    $tcp.Start()
    $redirect = "http://localhost:$(([System.Net.IPEndPoint]$tcp.LocalEndpoint).Port)/"
    $authUrl  = New-PimEpAuthorizeUrl -Tenant $Tenant -ClientId $ClientId -RedirectUri $redirect -Scope $scope -State $state -CodeChallenge $pkce.Challenge -LoginHint $LoginHint
    $query = $null
    try {
        $edge = if ($UseEdge) { Get-PimEpEdgePath } else { $null }
        # -WhatIf:$false -- the sign-in is a READ the preview needs: an inherited -WhatIf would stop Start-Process from
        # opening the browser and the run would wait 5 minutes for an answer that never comes.
        if ($edge) {
            Write-Host "Opening Microsoft Edge for sign-in (answer comes back to $redirect)..." -ForegroundColor Yellow
            Start-Process -FilePath $edge -ArgumentList @('--new-window', $authUrl) -WhatIf:$false
        } else {
            if ($UseEdge) { Write-Host 'Microsoft Edge not found -- using the default browser.' -ForegroundColor DarkYellow }
            Write-Host "Opening the default browser for sign-in (answer comes back to $redirect)..." -ForegroundColor Yellow
            Start-Process $authUrl -WhatIf:$false
        }
        Write-Host "If no browser opened, open this address yourself:`n  $authUrl" -ForegroundColor DarkGray
        $deadline = (Get-Date).AddMinutes(5)
        while (-not $query) {
            if ((Get-Date) -gt $deadline) { throw 'Timed out (5 minutes) waiting for the browser to finish the sign-in.' }
            if (-not $tcp.Pending()) { Start-Sleep -Milliseconds 200; continue }
            $client = $tcp.AcceptTcpClient()
            try {
                $stream      = $client.GetStream()
                $requestLine = (New-Object System.IO.StreamReader($stream)).ReadLine()
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
    if ($kv['error'])            { throw "Sign-in failed: $($kv['error']) -- $($kv['error_description'])" }
    if ($kv['state'] -ne $state) { throw 'The browser answer did not come from this sign-in attempt. Close ALL browser windows and run the script again.' }
    if (-not $kv['code'])        { throw 'The browser answer carried no authorization code.' }
    Invoke-RestMethod -Method POST -Uri "https://login.microsoftonline.com/$Tenant/oauth2/v2.0/token" -ContentType 'application/x-www-form-urlencoded' -Body @{
        client_id     = $ClientId
        grant_type    = 'authorization_code'
        code          = $kv['code']
        redirect_uri  = $redirect
        code_verifier = $pkce.Verifier
        scope         = $scope
    }
}

# ---- tokens + the REST seam -------------------------------------------------------------------------------------------
# $script:PimEpTokens = @{ graph = '<token>'; arm = '<token>' } -- set by the sign-in (or -GraphAccessToken / -ArmAccessToken).
function Set-PimEpToken {
    param([Parameter(Mandatory)][ValidateSet('graph', 'arm')][string]$Api, [Parameter(Mandatory)][string]$AccessToken)
    if (-not $script:PimEpTokens) { $script:PimEpTokens = @{} }
    $script:PimEpTokens[$Api] = $AccessToken
}

function Resolve-PimEpUri {
    param([ValidateSet('graph', 'arm')][string]$Api = 'graph', [Parameter(Mandatory)][string]$Path)
    if ($Path -match '^https?://') { return $Path }
    if ($Api -eq 'arm') { return 'https://management.azure.com/' + $Path.TrimStart('/') }
    $rel = $Path.TrimStart('/')
    if ($rel -match '^(v1\.0|beta)/') { return "https://graph.microsoft.com/$rel" }
    "https://graph.microsoft.com/v1.0/$rel"
}

# HTTP status of a failed Invoke-RestMethod (5.1 WebException / 7 HttpResponseException), message as fallback. 0 = unknown.
function Get-PimEpHttpStatus {
    param($ErrorRecord)
    $ex = if ($ErrorRecord -is [System.Management.Automation.ErrorRecord]) { $ErrorRecord.Exception } else { $ErrorRecord }
    try { if ($ex.Response -and $ex.Response.StatusCode) { return [int]$ex.Response.StatusCode } } catch { }
    $m = "$($ex.Message)"
    if ($m -match '\((\d{3})\)') { return [int]$Matches[1] }
    if ($m -match 'status code[^0-9]{0,40}(\d{3})') { return [int]$Matches[1] }
    0
}

# "<code>: <message>" from the JSON error body (Graph and ARM use the same { error: { code, message } } shape).
function Get-PimEpErrorText {
    param($ErrorRecord)
    $raw = $null
    if ($ErrorRecord -is [System.Management.Automation.ErrorRecord] -and $ErrorRecord.ErrorDetails -and $ErrorRecord.ErrorDetails.Message) { $raw = $ErrorRecord.ErrorDetails.Message }
    if (-not $raw) {
        try {
            $resp = $ErrorRecord.Exception.Response
            if ($resp -and ($resp | Get-Member -Name GetResponseStream -MemberType Method)) { $raw = (New-Object System.IO.StreamReader($resp.GetResponseStream())).ReadToEnd() }
        } catch { }
    }
    if (-not $raw) { return "$($ErrorRecord.Exception.Message)" }
    try { $j = $raw | ConvertFrom-Json; if ($j.error) { return "$($j.error.code): $($j.error.message)" } } catch { }
    "$raw"
}

# One call to Graph or ARM. JSON bodies go as UTF-8. Collections come back as their `value` items (-All follows
# @odata.nextLink / nextLink). 429/503/504 are retried. A failure throws "HTTP <n> <code>: <message>".
function Invoke-PimEpRest {
    param(
        [ValidateSet('graph', 'arm')][string]$Api = 'graph',
        [string]$Method = 'GET',
        [Parameter(Mandatory)][string]$Path,
        [object]$Body,
        [switch]$All,
        [int]$MaxRetries = 4
    )
    $tok = $null; if ($script:PimEpTokens) { $tok = $script:PimEpTokens[$Api] }
    if (-not $tok) { throw "Not signed in to $(if ($Api -eq 'arm') { 'Azure' } else { 'Microsoft Graph' })." }
    $uri = Resolve-PimEpUri -Api $Api -Path $Path
    $bytes = $null
    if ($null -ne $Body) { $bytes = [Text.Encoding]::UTF8.GetBytes($(if ($Body -is [string]) { $Body } else { ConvertTo-Json -InputObject $Body -Depth 10 -Compress })) }
    $send = {
        param([string]$M, [string]$U, [byte[]]$B)
        for ($try = 0; ; $try++) {
            $p = @{ Method = $M; Uri = $U; Headers = @{ Authorization = "Bearer $tok" }; ErrorAction = 'Stop' }
            if ($null -ne $B) { $p.Body = $B; $p.ContentType = 'application/json; charset=utf-8' }
            try { return Invoke-RestMethod @p }
            catch {
                $code = Get-PimEpHttpStatus $_
                if (($code -in @(429, 503, 504)) -and ($try -lt $MaxRetries)) { Start-Sleep -Seconds ([int][Math]::Min(30, [Math]::Pow(2, $try + 1))); continue }
                $ct = if ($code) { "HTTP $code " } else { '' }
                throw "$ct$(Get-PimEpErrorText $_)"
            }
        }
    }
    $resp = & $send $Method $uri $bytes
    $vp = $null; if ($null -ne $resp -and $resp.PSObject) { $vp = $resp.PSObject.Properties['value'] }
    if (-not ($vp -and ($null -eq $vp.Value -or $vp.Value -is [array]))) { return $resp }
    $items = New-Object System.Collections.Generic.List[object]
    $page = $resp
    while ($true) {
        foreach ($i in @($page.value)) { if ($null -ne $i) { $items.Add($i) } }
        if (-not $All) { break }
        $next = $null
        foreach ($n in '@odata.nextLink', 'nextLink') { if ($page.PSObject.Properties[$n] -and $page.$n) { $next = "$($page.$n)"; break } }
        if (-not $next) { break }
        $page = & $send 'GET' $next $null
    }
    $items.ToArray()
}

# The status number in an error text thrown by Invoke-PimEpRest (0 = none).
function Get-PimEpErrorStatus {
    param([AllowEmptyString()][string]$Text)
    if ("$Text" -match '^HTTP (\d{3})') { return [int]$Matches[1] }
    0
}

# ---- the grant ----------------------------------------------------------------------------------------------------------
function New-PimEpResult {
    param([string]$Kind, [string]$What, [string]$Where, [string]$Status, [string]$Detail = '')
    [pscustomobject]@{ kind = $Kind; what = $What; where = $Where; status = $Status; detail = $Detail }
}

# Application permissions (Graph and others) for the engine identity. Needs the Graph token. Idempotent: what is
# already held is reported and left alone; every grant is read back.
function Invoke-PimEpAppRoleGrant {
    param([Parameter(Mandatory)][string]$EngineObjectId, [object[]]$Specs, [switch]$PlanOnly)
    $results = New-Object System.Collections.Generic.List[object]
    if (-not @($Specs).Count) { return $results.ToArray() }
    $sps = @{}
    foreach ($appId in @($Specs | ForEach-Object { $_.resourceAppId } | Select-Object -Unique)) {
        $r = @(Invoke-PimEpRest -Api graph -Path ("/servicePrincipals?`$filter=appId eq '{0}'&`$select=id,appId,displayName,appRoles" -f $appId))
        $sps[$appId] = $(if ($r.Count) { $r[0] } else { $null })
    }
    $existing = @(Invoke-PimEpRest -Api graph -Path "/servicePrincipals/$EngineObjectId/appRoleAssignments" -All)
    $plan = @(Get-PimEpAppRolePlan -Wanted $Specs -ResourceSps $sps -Existing $existing)
    $toCheck = New-Object System.Collections.Generic.List[object]
    foreach ($p in $plan) {
        $where = if ($p.resourceName) { $p.resourceName } else { $p.resourceAppId }
        switch ($p.action) {
            'present'      { $results.Add((New-PimEpResult 'app permission' $p.value $where 'already there')) }
            'no-resource'  { $results.Add((New-PimEpResult 'app permission' $p.value $where 'refused' "the API $($p.resourceAppId) has no service principal in this tenant")) }
            'unknown-role' { $results.Add((New-PimEpResult 'app permission' $p.value $where 'refused' "$where has no application permission named '$($p.value)'")) }
            'grant' {
                if ($PlanOnly) { $results.Add((New-PimEpResult 'app permission' $p.value $where 'would grant')); continue }
                $req = New-PimEpAppRoleAssignmentRequest -PrincipalId $EngineObjectId -ResourceId $p.resourceId -AppRoleId $p.appRoleId
                try {
                    [void](Invoke-PimEpRest -Api graph -Method $req.Method -Path $req.Path -Body $req.Body)
                    $toCheck.Add($p)
                } catch {
                    $msg = "$_"; $st = Get-PimEpErrorStatus $msg
                    if ($st -eq 400 -and $msg -match '(?i)already exists') { $results.Add((New-PimEpResult 'app permission' $p.value $where 'already there')) }
                    elseif ($st -eq 403 -or $st -eq 401) { $results.Add((New-PimEpResult 'app permission' $p.value $where 'refused' "$msg -- sign in as a Global Administrator or Privileged Role Administrator")) }
                    else { $results.Add((New-PimEpResult 'app permission' $p.value $where 'refused' $msg)) }
                }
            }
        }
    }
    if ($toCheck.Count) {
        # read back: every grant must now be on the engine identity
        $after = @(Invoke-PimEpRest -Api graph -Path "/servicePrincipals/$EngineObjectId/appRoleAssignments" -All)
        $held = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
        foreach ($a in $after) { if ($a) { [void]$held.Add("$($a.resourceId)|$($a.appRoleId)") } }
        foreach ($p in $toCheck) {
            $where = if ($p.resourceName) { $p.resourceName } else { $p.resourceAppId }
            if ($held.Contains("$($p.resourceId)|$($p.appRoleId)")) { $results.Add((New-PimEpResult 'app permission' $p.value $where 'granted')) }
            else { $results.Add((New-PimEpResult 'app permission' $p.value $where 'granted' 'accepted, not visible on the read-back yet -- check again in a minute')) }
        }
    }
    $results.ToArray()
}

# Azure role assignments for the engine identity. Needs the ARM token. Idempotent: an assignment at (or above) the
# scope is reported and left alone; a new one gets a new GUID and is read back.
function Invoke-PimEpAzureRoleGrant {
    param([Parameter(Mandatory)][string]$EngineObjectId, [object[]]$Specs, [switch]$PlanOnly)
    $results = New-Object System.Collections.Generic.List[object]
    $api = Get-PimEpArmApiVersion
    foreach ($s in @($Specs)) {
        if (-not $s) { continue }
        $prefix = if ($s.scope -eq '/') { '' } else { $s.scope }
        $guid = $s.roleDefinitionGuid
        try {
            if (-not $guid) {
                $f = [uri]::EscapeDataString("roleName eq '$($s.role.Replace("'", "''"))'")
                $defs = @(Invoke-PimEpRest -Api arm -Path "$prefix/providers/Microsoft.Authorization/roleDefinitions?`$filter=$f&api-version=$api")
                if (-not $defs.Count) { $results.Add((New-PimEpResult 'Azure role' $s.role $s.scope 'refused' "no Azure role named '$($s.role)' at this scope")); continue }
                $guid = "$($defs[0].name)".ToLowerInvariant()
            }
            $cur = @(Invoke-PimEpRest -Api arm -Path "$prefix/providers/Microsoft.Authorization/roleAssignments?`$filter=assignedTo('$EngineObjectId')&api-version=$api" -All)
            $hit = Find-PimEpArmAssignment -Assignments $cur -Scope $s.scope -RoleDefinitionGuid $guid
            if ($hit) {
                $d = if ($hit.how -eq 'inherited') { "inherited from $($hit.scope)" } else { '' }
                $results.Add((New-PimEpResult 'Azure role' $s.role $s.scope 'already there' $d)); continue
            }
            if ($PlanOnly) { $results.Add((New-PimEpResult 'Azure role' $s.role $s.scope 'would grant')); continue }
            $req = New-PimEpArmRoleAssignmentRequest -Scope $s.scope -RoleDefinitionGuid $guid -PrincipalId $EngineObjectId
            try { [void](Invoke-PimEpRest -Api arm -Method $req.Method -Path $req.Path -Body $req.Body) }
            catch {
                $msg = "$_"; $st = Get-PimEpErrorStatus $msg
                if ($st -eq 409 -and $msg -match '(?i)RoleAssignmentExists') { $results.Add((New-PimEpResult 'Azure role' $s.role $s.scope 'already there')); continue }
                if ($st -eq 403 -or $st -eq 401) {
                    $hint = 'you need Owner or User Access Administrator at this scope'
                    if ($s.scope -match '(?i)managementGroups') { $hint += "; at the tenant root a Global Administrator first turns on 'Access management for Azure resources' (Microsoft Entra ID > Properties), then runs this script again" }
                    $results.Add((New-PimEpResult 'Azure role' $s.role $s.scope 'refused' "$msg -- $hint")); continue
                }
                $results.Add((New-PimEpResult 'Azure role' $s.role $s.scope 'refused' $msg)); continue
            }
            $back = $null
            try { $back = Invoke-PimEpRest -Api arm -Path ($req.Path) } catch { $back = $null }
            if ($back -and "$($back.properties.principalId)" -eq $EngineObjectId) { $results.Add((New-PimEpResult 'Azure role' $s.role $s.scope 'granted')) }
            else { $results.Add((New-PimEpResult 'Azure role' $s.role $s.scope 'granted' 'accepted, not readable yet -- check again in a minute')) }
        } catch {
            $results.Add((New-PimEpResult 'Azure role' $s.role $s.scope 'refused' "$_"))
        }
    }
    $results.ToArray()
}

# The result table for the console (pure: returns the lines).
function Format-PimEpResults {
    param([object[]]$Results)
    $lines = New-Object System.Collections.Generic.List[string]
    foreach ($r in @($Results)) {
        if (-not $r) { continue }
        $l = '  {0,-14} {1,-15} {2} ({3})' -f $r.status, $r.kind, $r.what, $r.where
        if ($r.detail) { $l += " -- $($r.detail)" }
        $lines.Add($l)
    }
    $lines.ToArray()
}
