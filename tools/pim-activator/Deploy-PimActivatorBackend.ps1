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
    [switch]$GrantConsent = $true
)

$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Connect (or verify) Microsoft Graph
# ---------------------------------------------------------------------------

$_requiredScopes = @(
    'Application.ReadWrite.All'
    'AppRoleAssignment.ReadWrite.All'
    'DelegatedPermissionGrant.ReadWrite.All'
)

$ctx = Get-MgContext -ErrorAction SilentlyContinue
if (-not $ctx) {
    Write-Host "Not connected to Microsoft Graph. Launching interactive sign-in (scopes: $($_requiredScopes -join ', '))..." -ForegroundColor Yellow
    Connect-MgGraph -Scopes $_requiredScopes -NoWelcome -ErrorAction Stop | Out-Null
    $ctx = Get-MgContext -ErrorAction Stop
}

$missingScopes = $_requiredScopes | Where-Object { $_ -notin $ctx.Scopes }
if ($missingScopes) {
    Write-Host "Current Graph session is missing required scopes: $($missingScopes -join ', '). Re-connecting interactively..." -ForegroundColor Yellow
    Connect-MgGraph -Scopes $_requiredScopes -NoWelcome -ErrorAction Stop | Out-Null
    $ctx = Get-MgContext -ErrorAction Stop
    $stillMissing = $_requiredScopes | Where-Object { $_ -notin $ctx.Scopes }
    if ($stillMissing) {
        throw "After re-connect, Graph session is STILL missing: $($stillMissing -join ', '). Admin consent may be required."
    }
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

# First-party Microsoft service principals (Graph, ARM) are NOT guaranteed to
# exist in every tenant -- fresh / lightly-used tenants only get them
# instantiated on first use. Application.ReadWrite.All (already held by the
# caller) is enough to instantiate the well-known appId on the spot, so
# resolve-or-create instead of assuming presence.
function Resolve-FirstPartySp {
    param([string]$AppId, [string]$Name)
    $sp = Get-MgServicePrincipal -Filter "appId eq '$AppId'"
    if (-not $sp) {
        Write-Host "  $Name service principal not present in tenant -- instantiating it (appId $AppId)..." -ForegroundColor Yellow
        try {
            $created = New-MgServicePrincipal -AppId $AppId
            # Re-fetch so downstream consumers see fully-populated properties
            # (Oauth2PermissionScopes in particular).
            $sp = Get-MgServicePrincipal -ServicePrincipalId $created.Id
        } catch {
            throw "$Name service principal (appId $AppId) is missing from tenant $TenantId and could not be instantiated: $($_.Exception.Message)"
        }
    }
    $sp
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
