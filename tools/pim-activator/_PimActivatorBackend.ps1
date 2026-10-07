# _PimActivatorBackend.ps1 -- Graph REST seam + write helpers for the PIM Activator backend deploy (app registration +
# service principal + delegated admin-consent grants). Dot-source from Deploy-PimActivatorBackend.ps1; defines
# functions only (no side effects on load).
#
# NO MODULES (owner 2026-10-07: "neither pim, si or invardia must have dependencies"): every Graph call goes through
# Invoke-PaGraph -- plain Invoke-RestMethod with the session token that _PimActivatorAuth.ps1 establishes
# (Set-PaGraphSession). Nothing from the engine tree is loaded either: the deploy is published as ONE standalone file
# (tools/setup/Build-PimSupportScripts.ps1), which cannot carry the engine. Pure builders (body shapes, scope strings,
# scope-id resolution) are unit-tested offline.

# The session token, renewed through Update-PaGraphSession (_PimActivatorAuth.ps1) when it is within 5 minutes of
# expiry and a renewal recipe exists. Throws when no one has signed in.
function Get-PaGraphAccessToken {
    if (-not $script:PaGraphToken) { throw 'Not signed in to Microsoft Graph (no session token) -- sign in first (Connect-PimActivatorGraph).' }
    if ($script:PaGraphTokenRefresh -and $script:PaGraphTokenExpiresUtc -and
        [datetime]::UtcNow -gt ([datetime]$script:PaGraphTokenExpiresUtc).AddMinutes(-5) -and
        (Get-Command Update-PaGraphSession -ErrorAction SilentlyContinue)) {
        Update-PaGraphSession
    }
    $script:PaGraphToken
}

# "https://graph.microsoft.com/v1.0/<path>" (or beta) from a v1.0/beta-relative path; absolute URLs (an
# @odata.nextLink) pass through, "v1.0/..." / "beta/..." prefixes are honoured.
function Resolve-PaGraphUri {
    param([Parameter(Mandatory)][string]$Path, [switch]$Beta)
    if ($Path -match '^https?://') { return $Path }
    $rel = $Path.TrimStart('/')
    if ($rel -match '^(v1\.0|beta)/') { return "https://graph.microsoft.com/$rel" }
    $ver = if ($Beta) { 'beta' } else { 'v1.0' }
    "https://graph.microsoft.com/$ver/$rel"
}

# HTTP status of a failed Invoke-RestMethod (5.1: WebException.Response; 7: HttpResponseException.Response), with the
# message as the fallback ("(429)" in 5.1, "status code ... 429" in 7). 0 = unknown.
function Get-PaHttpStatus {
    param($ErrorRecord)
    $ex = if ($ErrorRecord -is [System.Management.Automation.ErrorRecord]) { $ErrorRecord.Exception } else { $ErrorRecord }
    try { if ($ex.Response -and $ex.Response.StatusCode) { return [int]$ex.Response.StatusCode } } catch { }
    $m = "$($ex.Message)"
    if ($m -match '\((\d{3})\)') { return [int]$Matches[1] }
    if ($m -match 'status code[^0-9]{0,40}(\d{3})') { return [int]$Matches[1] }
    0
}

# Seconds from a Retry-After header on a failed request, or $null.
function Get-PaRetryAfterSeconds {
    param($ErrorRecord)
    $ex = if ($ErrorRecord -is [System.Management.Automation.ErrorRecord]) { $ErrorRecord.Exception } else { $ErrorRecord }
    try {
        $h = $ex.Response.Headers
        if ($null -eq $h) { return $null }
        if ($h.PSObject.Properties['RetryAfter'] -and $h.RetryAfter) {          # 7: HttpResponseHeaders
            if ($h.RetryAfter.Delta) { return [int][Math]::Ceiling($h.RetryAfter.Delta.TotalSeconds) }
            if ($h.RetryAfter.Date)  { return [int][Math]::Max(1, [Math]::Ceiling(($h.RetryAfter.Date.UtcDateTime - [datetime]::UtcNow).TotalSeconds)) }
        }
        $v = $null
        try { $v = $h['Retry-After'] } catch { }                                # 5.1: WebHeaderCollection
        if ($v -and "$v" -match '^\d+$') { return [int]"$v" }
    } catch { }
    $null
}

# The Graph error body (JSON) of a failed request, best effort: "<code>: <message>".
function Get-PaGraphErrorText {
    param($ErrorRecord)
    $raw = $null
    if ($ErrorRecord -is [System.Management.Automation.ErrorRecord] -and $ErrorRecord.ErrorDetails -and $ErrorRecord.ErrorDetails.Message) { $raw = $ErrorRecord.ErrorDetails.Message }
    if (-not $raw) {
        try {
            $resp = $ErrorRecord.Exception.Response
            if ($resp -and ($resp | Get-Member -Name GetResponseStream -MemberType Method)) {
                $raw = (New-Object System.IO.StreamReader($resp.GetResponseStream())).ReadToEnd()
            }
        } catch { }
    }
    if (-not $raw) { return "$($ErrorRecord.Exception.Message)" }
    try {
        $j = $raw | ConvertFrom-Json
        if ($j.error) { return "$($j.error.code): $($j.error.message)" }
    } catch { }
    "$raw"
}

# The single Graph seam used by every backend call. -Path is a v1.0/beta-relative Graph path (e.g.
# "/applications?`$filter=...") or an absolute URL. JSON bodies are sent as UTF-8 bytes. Collections come back as the
# `value` items (all pages with -All, following @odata.nextLink); single resources as the object. 429/503/504 are
# retried (Retry-After honoured, max -MaxRetries). Any other failure throws "Graph <METHOD> <uri> failed: HTTP <n>
# <code>: <message>" -- so a 404 carries both "404" and "Request_ResourceNotFound" for the callers' not-found checks.
function Invoke-PaGraph {
    param(
        [string]$Method = 'GET',
        [Parameter(Mandatory)][string]$Path,
        [object]$Body,
        [switch]$Beta,
        [switch]$All,
        [int]$MaxRetries = 5
    )
    $uri = Resolve-PaGraphUri -Path $Path -Beta:$Beta
    $bytes = $null
    if ($null -ne $Body) {
        $json = if ($Body -is [string]) { $Body } else { ConvertTo-Json -InputObject $Body -Depth 12 }
        $bytes = [Text.Encoding]::UTF8.GetBytes($json)
    }

    $send = {
        param([string]$M, [string]$U, [byte[]]$B)
        for ($try = 0; ; $try++) {
            $p = @{ Method = $M; Uri = $U; Headers = @{ Authorization = "Bearer $(Get-PaGraphAccessToken)" }; ErrorAction = 'Stop' }
            if ($null -ne $B) { $p.Body = $B; $p.ContentType = 'application/json; charset=utf-8' }
            try { return Invoke-RestMethod @p }
            catch {
                $code = Get-PaHttpStatus $_
                if (($code -in @(429, 503, 504)) -and ($try -lt $MaxRetries)) {
                    $wait = Get-PaRetryAfterSeconds $_
                    if (-not $wait -or $wait -lt 1) { $wait = [int][Math]::Min(60, [Math]::Pow(2, $try + 1)) }
                    Write-Host "  Graph answered HTTP $code -- retry $($try + 1)/$MaxRetries in $wait s" -ForegroundColor DarkGray
                    Start-Sleep -Seconds $wait
                    continue
                }
                $codeText = if ($code) { "HTTP $code " } else { '' }
                throw "Graph $M $U failed: $codeText$(Get-PaGraphErrorText $_)"
            }
        }
    }

    $resp = & $send $Method $uri $bytes
    $isCollection = {
        param($r)
        if ($null -eq $r) { return $false }
        if ($r -is [System.Collections.IDictionary]) { return $r.Contains('value') -and ($null -eq $r['value'] -or $r['value'] -is [array]) }
        $vp = $r.PSObject.Properties['value']
        [bool]($vp -and ($null -eq $vp.Value -or $vp.Value -is [array]))
    }
    if (-not (& $isCollection $resp)) { return $resp }

    $items = New-Object System.Collections.Generic.List[object]
    $page = $resp
    while ($true) {
        foreach ($i in @(Get-PaProp $page 'value')) { if ($null -ne $i) { $items.Add($i) } }
        if (-not $All) { break }
        $next = Get-PaProp $page '@odata.nextLink'
        if (-not $next) { break }
        $page = & $send 'GET' "$next" $null
    }
    $items.ToArray()
}

# Read a property off a Graph object case-insensitively (REST returns camelCase 'appId'/'id'; hashtables and older
# objects may carry PascalCase). Returns $null when absent. -Name is the canonical camelCase key (e.g. 'appId', 'id').
function Get-PaProp {
    param([AllowNull()]$Object, [Parameter(Mandatory)][string]$Name)
    if ($null -eq $Object) { return $null }
    $pascal = $Name.Substring(0,1).ToUpperInvariant() + $Name.Substring(1)
    if ($Object -is [System.Collections.IDictionary]) {
        foreach ($k in @($Name, $pascal)) { if ($Object.Contains($k)) { return $Object[$k] } }
        return $null
    }
    foreach ($k in @($Name, $pascal)) {
        $p = $Object.PSObject.Properties[$k]
        if ($p) { return $p.Value }
    }
    $null
}

# Idempotently create-or-update an AllPrincipals oauth2PermissionGrant (tenant-
# wide admin consent) from one client SP to one resource SP, over Graph REST via
# Invoke-PaGraph (GET by filter, then PATCH or POST). -ClientSpId/-ResourceSpId are SP object ids; -Scope a space-delimited
# scope string. Returns nothing; writes a status line.
function Set-PaOauth2Grant {
    param(
        [Parameter(Mandatory)][string]$ClientSpId,
        [Parameter(Mandatory)][string]$ResourceSpId,
        [Parameter(Mandatory)][string]$Scope,
        [string]$Label = 'consent'
    )
    $filter = "clientId eq '$ClientSpId' and consentType eq 'AllPrincipals' and resourceId eq '$ResourceSpId'"
    $existing = @(Invoke-PaGraph -Method GET -Path "/oauth2PermissionGrants?`$filter=$([uri]::EscapeDataString($filter))" -All)
    if ($existing.Count -gt 0) {
        $gid = Get-PaProp $existing[0] 'id'
        Invoke-PaGraph -Method PATCH -Path "/oauth2PermissionGrants/$gid" -Body @{ scope = $Scope } | Out-Null
        Write-Host "  updated existing $Label consent grant" -ForegroundColor DarkGray
    } else {
        Invoke-PaGraph -Method POST -Path '/oauth2PermissionGrants' -Body @{
            clientId = $ClientSpId; consentType = 'AllPrincipals'; resourceId = $ResourceSpId; scope = $Scope
        } | Out-Null
        Write-Host "  created new $Label consent grant" -ForegroundColor DarkGray
    }
}

# ---------------------------------------------------------------------------
# Pure builders (no network) -- unit-tested in PIM.Activator.Tests.ps1
# ---------------------------------------------------------------------------

# Resolve a set of delegated permission VALUES to their scope ids from a Graph
# servicePrincipal's oauth2PermissionScopes collection. Returns an ordered map
# value -> id; throws on any value not exposed by the SP (so a typo / removed
# scope fails loud instead of silently dropping a permission).
function Resolve-PaGraphScopeIds {
    param(
        [Parameter(Mandatory)]$Oauth2PermissionScopes,   # array of objects with .value/.Value + .id/.Id
        [Parameter(Mandatory)][string[]]$Names
    )
    $byVal = @{}
    foreach ($s in @($Oauth2PermissionScopes)) {
        $v = if ($null -ne $s.value) { $s.value } else { $s.Value }
        $i = if ($null -ne $s.id)    { $s.id }    else { $s.Id }
        if ($v) { $byVal["$v"] = "$i" }
    }
    $out = [ordered]@{}
    foreach ($n in $Names) {
        if (-not $byVal.ContainsKey($n)) { throw "Delegated scope '$n' not found on the service principal." }
        $out[$n] = $byVal[$n]
    }
    $out
}

# Build the requiredResourceAccess block (Graph delegated scopes + ASM
# user_impersonation) as the plain REST shape Graph expects on
# applications create/PATCH. -GraphScopeIds is the ordered map from
# Resolve-PaGraphScopeIds; -AsmScopeId the ASM user_impersonation scope id.
function New-PaRequiredResourceAccess {
    param(
        [Parameter(Mandatory)][string]$GraphAppId,
        [Parameter(Mandatory)]$GraphScopeIds,        # ordered map name->id (or hashtable)
        [Parameter(Mandatory)][string]$AsmAppId,
        [Parameter(Mandatory)][string]$AsmScopeId
    )
    $graphAccess = @()
    foreach ($k in $GraphScopeIds.Keys) { $graphAccess += @{ id = "$($GraphScopeIds[$k])"; type = 'Scope' } }
    @(
        @{ resourceAppId = $GraphAppId; resourceAccess = $graphAccess },
        @{ resourceAppId = $AsmAppId;   resourceAccess = @(@{ id = "$AsmScopeId"; type = 'Scope' }) }
    )
}

# Build the application create/update body for the activator SPA app. Modern
# Edge/Chrome MV3 auth needs BOTH SPA redirect URIs: the chromiumapp.org
# redirect and the chrome-extension origin (Entra validates Origin on token
# redemption). Public-client URIs are explicitly cleared.
function New-PaAppRegistrationBody {
    param(
        [Parameter(Mandatory)][string]$DisplayName,
        [Parameter(Mandatory)][string]$ExtensionId,
        [Parameter(Mandatory)]$RequiredResourceAccess,
        # Extra extension ids to ALSO register redirect URIs for (e.g. the TEST
        # channel id alongside the RELEASED id) so one app reg serves multiple
        # PIM Activator builds side-by-side.
        [string[]]$AdditionalExtensionIds = @(),
        # Pre-existing SPA redirect URIs to PRESERVE (union), so updating an app to
        # "accept this as well" never drops URIs already configured in the tenant.
        [string[]]$ExistingSpaRedirectUris = @(),
        [switch]$IncludeDisplayName
    )
    # Both forms per id: https://<id>.chromiumapp.org/ (launchWebAuthFlow redirect)
    # + chrome-extension://<id>/ (Origin for SPA token redemption).
    $ids = @(@($ExtensionId) + @($AdditionalExtensionIds)) | Where-Object { $_ } | Select-Object -Unique
    $uris = @($ExistingSpaRedirectUris)
    foreach ($id in $ids) { $uris += "https://$id.chromiumapp.org/"; $uris += "chrome-extension://$id/" }
    $body = @{
        signInAudience          = 'AzureADMyOrg'
        spa                     = @{ redirectUris = @($uris | Where-Object { $_ } | Select-Object -Unique) }
        publicClient            = @{ redirectUris = @() }
        isFallbackPublicClient  = $false
        requiredResourceAccess  = $RequiredResourceAccess
    }
    if ($IncludeDisplayName) { $body.displayName = $DisplayName }
    $body
}

# The space-delimited scope string written into an oauth2PermissionGrant. Always
# appends the OIDC basics + offline_access so tenants with restrictive user-
# consent settings sign users in silently (matches the previous behaviour).
function New-PaConsentScopeString {
    param([Parameter(Mandatory)][string[]]$Scopes)
    (@($Scopes) + @('openid','profile','offline_access') | Select-Object -Unique) -join ' '
}
