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

    Required delegated Graph permissions (resolved by displayName -> id at runtime):
      - PrivilegedAccess.ReadWrite.AzureADGroup
      - Group.Read.All
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
      - Entra role: Application Administrator (or Cloud App Admin / Global Admin)

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
    Connect-MgGraph -TenantId f0fa27a0-... -Scopes 'Application.ReadWrite.All','AppRoleAssignment.ReadWrite.All','DelegatedPermissionGrant.ReadWrite.All'
    .\Deploy-PimActivatorBackend.ps1 -ExtensionId 'abcd...wxyz' -GrantConsent

.NOTES
    Re-runnable: if an app with the same DisplayName already exists in the
    tenant, the script updates its redirect URI + required permissions in
    place rather than creating a duplicate.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^[a-p]{32}$')]   # Chromium extension id format
    [string]$ExtensionId,

    [string]$DisplayName = 'PIM Activator',

    [string]$TenantId,

    [switch]$GrantConsent
)

$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Connect (or verify) Microsoft Graph
# ---------------------------------------------------------------------------

$ctx = Get-MgContext
if (-not $ctx) {
    Write-Host "Not connected to Microsoft Graph. Run Connect-MgGraph first:" -ForegroundColor Yellow
    Write-Host "  Connect-MgGraph -Scopes 'Application.ReadWrite.All','AppRoleAssignment.ReadWrite.All','DelegatedPermissionGrant.ReadWrite.All'" -ForegroundColor Yellow
    throw "Connect-MgGraph required."
}

$missingScopes = @('Application.ReadWrite.All') | Where-Object { $_ -notin $ctx.Scopes }
if ($missingScopes) {
    throw "Current Graph session is missing required scopes: $($missingScopes -join ', '). Re-run Connect-MgGraph with those scopes."
}

if ($TenantId -and $TenantId -ne $ctx.TenantId) {
    throw "Connected to tenant $($ctx.TenantId) but -TenantId says $TenantId. Reconnect with the correct -TenantId."
}
$TenantId = $ctx.TenantId

Write-Host "Tenant   : $TenantId"  -ForegroundColor Cyan
Write-Host "Signed-in: $($ctx.Account)" -ForegroundColor Cyan
Write-Host ""

# ---------------------------------------------------------------------------
# Resolve Microsoft Graph delegated permission ids
# ---------------------------------------------------------------------------

$graphAppId = '00000003-0000-0000-c000-000000000000'
$graphSp    = Get-MgServicePrincipal -Filter "appId eq '$graphAppId'"
if (-not $graphSp) { throw "Microsoft Graph service principal not found in tenant -- this should never happen." }

$needed = @('PrivilegedAccess.ReadWrite.AzureADGroup', 'Group.Read.All', 'User.Read', 'RoleManagement.Read.Directory', 'AdministrativeUnit.Read.All')
$scopeMap = @{}
foreach ($name in $needed) {
    $scope = $graphSp.Oauth2PermissionScopes | Where-Object { $_.Value -eq $name }
    if (-not $scope) { throw "Delegated scope '$name' not found on Microsoft Graph SP." }
    $scopeMap[$name] = $scope.Id
    Write-Host ("  resolved {0,-45} -> {1}" -f $name, $scope.Id) -ForegroundColor DarkGray
}

$requiredResourceAccess = @(@{
    ResourceAppId  = $graphAppId
    ResourceAccess = $needed | ForEach-Object { @{ Id = $scopeMap[$_]; Type = 'Scope' } }
})

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

# Ensure the service principal exists in the tenant (creates the enterprise app).
$sp = Get-MgServicePrincipal -Filter "appId eq '$($app.AppId)'" -ErrorAction SilentlyContinue
if (-not $sp) {
    $sp = New-MgServicePrincipal -AppId $app.AppId
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
    $scopeString = ($needed -join ' ')
    $existingGrant = Get-MgOauth2PermissionGrant -Filter "clientId eq '$($sp.Id)' and consentType eq 'AllPrincipals' and resourceId eq '$($graphSp.Id)'" -ErrorAction SilentlyContinue
    if ($existingGrant) {
        Update-MgOauth2PermissionGrant -OAuth2PermissionGrantId $existingGrant.Id -Scope $scopeString
        Write-Host "  updated existing consent grant" -ForegroundColor DarkGray
    } else {
        New-MgOauth2PermissionGrant -ClientId $sp.Id -ConsentType 'AllPrincipals' -ResourceId $graphSp.Id -Scope $scopeString | Out-Null
        Write-Host "  created new consent grant" -ForegroundColor DarkGray
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
Write-Host "  1. Copy config.template.js to config.js in the extension folder."
Write-Host "  2. Replace the placeholder tenantId + clientId with the values above."
Write-Host "  3. Reload the extension at edge://extensions."
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
