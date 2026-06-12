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

# Shared auth machinery: version banner, Graph SDK version-conflict check,
# Edge-forced PKCE sign-in, session probe/heal. One implementation for all
# pim-activator deploy scripts.
. (Join-Path $PSScriptRoot '_PimActivatorAuth.ps1')

Write-Host "Deploy-PimActivatorBackend -- PIM4EntraPS $(Get-PimActivatorSolutionVersion)" -ForegroundColor Cyan
Write-Host "Graph SDK  : v$(Assert-GraphModuleVersions -Modules 'Microsoft.Graph.Authentication','Microsoft.Graph.Applications','Microsoft.Graph.Identity.SignIns')" -ForegroundColor Cyan

# ---------------------------------------------------------------------------
# Connect (or verify) Microsoft Graph
# ---------------------------------------------------------------------------

$_requiredScopes = @(
    'Application.ReadWrite.All'
    'AppRoleAssignment.ReadWrite.All'
    'DelegatedPermissionGrant.ReadWrite.All'
)

$ctx = Connect-PimActivatorGraph -RequiredScopes $_requiredScopes -TenantId $TenantId -UseEdge:([bool]$UseEdge)
$TenantId = $ctx.TenantId

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
            throw ("Graph authentication failed: $($_.Exception.Message)`n$(Get-PaBrokenAuthHelp)")
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
