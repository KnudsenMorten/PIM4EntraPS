# _PimActivatorBackend.ps1 -- REST-first write helpers for the PIM Activator
# backend deploy (app registration + service principal + delegated admin-consent
# grants). Dot-source from Deploy-PimActivatorBackend.ps1; defines functions only
# (no side effects on load).
#
# REST migration (REQUIREMENTS §19 -- "Write/activator/setup/EXO path"): the
# backend's WRITE operations no longer require the Microsoft.Graph PowerShell SDK.
# Every Graph call routes through Invoke-PaGraph, which talks pure Graph REST via
# the module-free PIM-Rest data plane (Invoke-PimGraph) by default, and only falls
# back to the SDK's Invoke-MgGraphRequest when $global:PIM_UseGraphSdk is set (the
# documented opt-in fallback used elsewhere in the solution). Pure builders here
# (body shapes, scope strings, scope-id resolution) are unit-tested offline with
# no network and no modules; they are identical under both auth modes.
#
# Auth modes:
#   * App-only (cert): -AppId + -CertificateThumbprint -> PIM-Rest mints a
#     certificate-signed app-only token (no Graph SDK, no MSAL, PS 5.1-safe). This
#     is the headless / automation path and is now FULLY module-free.
#   * Interactive (break-glass human sign-in): the existing Edge loopback + PKCE
#     flow in _PimActivatorAuth.ps1 establishes a Connect-MgGraph session; in that
#     mode Invoke-PaGraph still issues raw REST through the SDK request pipeline
#     unless $global:PIM_UseGraphSdk forces the legacy cmdlet path. No interactive
#     fallback flow is introduced here (the package validator enforces NODEVCODE).

# Load the module-free PIM-Rest data plane at dot-source time, into the CALLER's
# scope. Dot-sourcing a script INSIDE a function would scope its functions to
# that function (they vanish on return), so PIM-Rest must be sourced here at the
# helper's top level -- this file is itself dot-sourced, so Invoke-PimGraph then
# lands in the deploy script's scope. Idempotent + best-effort.
$PaBackendDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
if (-not (Get-Command Invoke-PimGraph -ErrorAction SilentlyContinue)) {
    $PaRestPlane = Join-Path $PaBackendDir '..\..\engine\_shared\PIM-Rest.ps1'
    if (Test-Path -LiteralPath $PaRestPlane) { . $PaRestPlane }
}

# Back-compat shim: callers may still invoke Import-PaRestPlane explicitly. The
# real load happens at dot-source above; this only covers the rare case where
# PIM-Rest wasn't present then but is needed now (e.g. the helper was loaded
# before the engine tree existed). No-op when Invoke-PimGraph is already defined.
function Import-PaRestPlane {
    if (Get-Command Invoke-PimGraph -ErrorAction SilentlyContinue) { return }
    $rest = Join-Path $PaBackendDir '..\..\engine\_shared\PIM-Rest.ps1'
    if (Test-Path -LiteralPath $rest) { . $rest }   # note: caller should dot-source this file, not call this fn, for scope reasons
}

# True when the caller asked for the legacy Graph SDK path. Default is REST.
function Test-PaUseGraphSdk { [bool]$global:PIM_UseGraphSdk }

# The single Graph seam used by every backend write. By default it calls the
# module-free PIM-Rest data plane (Invoke-PimGraph); under $global:PIM_UseGraphSdk
# it routes to the SDK's Invoke-MgGraphRequest so an operator who prefers the
# legacy session pipeline keeps working. -Path is a v1.0/beta-relative Graph
# path (e.g. "/applications?\$filter=..."); -Method/-Body as usual.
function Invoke-PaGraph {
    param(
        [string]$Method = 'GET',
        [Parameter(Mandatory)][string]$Path,
        [object]$Body,
        [switch]$Beta,
        [switch]$All
    )
    if (Test-PaUseGraphSdk) {
        # Legacy SDK pipeline. Normalise the path to the SDK's expected form
        # ("v1.0/..." / "beta/...") without a leading slash.
        $rel = $Path.TrimStart('/')
        $ver = if ($Beta) { 'beta' } else { 'v1.0' }
        $uri = if ($rel -match '^https?://' -or $rel -match '^(v1\.0|beta)/') { $rel } else { "$ver/$rel" }
        $sdkArgs = @{ Method = $Method; Uri = $uri }
        if ($null -ne $Body) { $sdkArgs.Body = $Body }
        return Invoke-MgGraphRequest @sdkArgs
    }
    Import-PaRestPlane
    Invoke-PimGraph -Method $Method -Path $Path -Body $Body -Beta:$Beta -All:$All
}

# Read a property off a Graph object case-insensitively (REST returns camelCase
# 'appId'/'id'; the SDK's Invoke-MgGraphRequest returns a hashtable with the same
# camelCase JSON keys; older SDK objects expose PascalCase). Returns $null when
# absent. -Name is the canonical camelCase key (e.g. 'appId', 'id').
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
# Invoke-PaGraph. Mirrors the previous Get/New/Update-MgOauth2PermissionGrant
# block. -ClientSpId/-ResourceSpId are SP object ids; -Scope a space-delimited
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
        [switch]$IncludeDisplayName
    )
    $redirectUri = "https://$ExtensionId.chromiumapp.org/"
    $extOrigin   = "chrome-extension://$ExtensionId/"
    $body = @{
        signInAudience          = 'AzureADMyOrg'
        spa                     = @{ redirectUris = @($redirectUri, $extOrigin) }
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
