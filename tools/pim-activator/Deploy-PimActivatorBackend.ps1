#Requires -Version 5.1

<#
.SYNOPSIS
    Creates or updates the PIM Activator app registration in your tenant (the sign-in app of the PIM Activator browser extension): its SPA redirect URIs, its delegated Microsoft Graph and Azure permissions, tenant-wide admin consent for them, and "Assignment required" so only the group you name can sign in.

.DESCRIPTION
    Documentation (purpose, who may run it, every change and permission, -WhatIf, undo):
    https://invardia.com/docs/pim/scripts/Deploy-PimActivatorBackend/
    -WhatIf signs in, reads the tenant and prints every change it would make; it changes nothing.

    The PIM Activator extension uses chrome.identity.launchWebAuthFlow + PKCE
    (vanilla JS, no MSAL.js) to:
      - Read the signed-in user's eligible PIM-for-Groups assignments
      - POST assignmentScheduleRequests to bulk-activate selected groups

    The redirect URIs are registered as SPA (Single-Page Application) URIs --
    both https://<id>.chromiumapp.org/ (what launchWebAuthFlow intercepts) and
    chrome-extension://<id>/ (the Origin the popup's token-endpoint fetch
    sends). Entra validates that Origin against SPA-registered URIs; a Public
    Client / native registration fails redemption with AADSTS9002326
    ("Cross-origin token redemption is permitted only for the 'Single-Page
    Application' client-type"). Any stale Public Client URI a previous install
    left behind is cleared.

    By default ONLY the released extension id is registered (-Channel
    Released). The TEST build's id is added only when you ask for it
    (-Channel Both / Test) -- never on a customer tenant: the app carries
    tenant-wide consent for RoleManagement.ReadWrite.Directory, so every
    registered redirect is a build that can hold those tokens.

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

    Sign-in: no PowerShell modules are needed. By default the script opens
    Microsoft Edge (the default browser when Edge is not installed) for an
    interactive sign-in -- auth code + PKCE on a localhost loopback, using the
    first-party "Microsoft Graph Command Line Tools" client, so no extra app
    registration. Alternatives: -AccessToken <token> (a Microsoft Graph token
    you already have) or app-only -AppId + -CertificateThumbprint + -TenantId.

    Caller (you) must have:
      - Graph scopes: Application.ReadWrite.All, AppRoleAssignment.ReadWrite.All,
                      DelegatedPermissionGrant.ReadWrite.All
      - Entra roles, ACTIVE in the session (PIM-eligible does NOT count until
        activated -- activate in PIM FIRST, then run this script; a sign-in
        made before the activation does not carry the role, and the script
        signs you in once more when it sees that):
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

.PARAMETER AssignToGroupId
    The object id of the group whose members may use the PIM Activator. The app is
    always set to "Assignment required", so only assigned people can sign in; this
    group is assigned to it and read back. Direct, permanent members only (Entra does
    not pass app access through nested groups; a PIM-eligible membership would lock
    the person out of the tool that activates it). Not given: nobody can sign in until
    a group is assigned. An existing app that is open to everyone today is not closed
    without a group (that would lock every current user out).

.PARAMETER DisplayName
    Display name of the app registration. Default: "PIM Activator".

.PARAMETER GrantConsent
    Also grant tenant-wide admin consent for the delegated permissions so
    individual users don't get the consent prompt on first sign-in. Requires
    the caller to be Privileged Role Administrator or higher.

.PARAMETER TenantId
    Optional for the browser sign-in (omitted = the home tenant of the account
    you sign in with). Required for app-only sign-in.

.PARAMETER AccessToken
    A Microsoft Graph access token you already have (automation), with the
    delegated scopes above (or the equivalent application permissions). Skips
    the browser sign-in. Not renewed -- valid ~1 hour from when it was minted.

.PARAMETER AppId
    App-only sign-in: the client id of an app registration that holds
    Application.ReadWrite.All (and DelegatedPermissionGrant.ReadWrite.All for
    -GrantConsent) as APPLICATION permissions. Use with -CertificateThumbprint
    and -TenantId.

.PARAMETER CertificateThumbprint
    App-only sign-in: thumbprint of that app's certificate, with its private
    key, in Cert:\CurrentUser\My or Cert:\LocalMachine\My.

.EXAMPLE
    # The command the PIM Manager page shows: this tenant, PROD, for the group of admins who use it:
    .\Deploy-PimActivatorBackend.ps1 -TenantId <tenant-id> -Channel Released -DisplayName 'PIM Activator' -AssignToGroupId <group-id>

.EXAMPLE
    # Zero-arg -- opens Edge for the sign-in, with the right scopes (nobody assigned yet):
    .\Deploy-PimActivatorBackend.ps1

.EXAMPLE
    # A specific tenant:
    .\Deploy-PimActivatorBackend.ps1 -TenantId <tenant-id> -ExtensionId 'abcd...wxyz' -GrantConsent

.EXAMPLE
    # Automation with a token you already have:
    .\Deploy-PimActivatorBackend.ps1 -TenantId <tenant-id> -AccessToken $token

.EXAMPLE
    # Headless, app-only with a certificate:
    .\Deploy-PimActivatorBackend.ps1 -TenantId <tenant-id> -AppId <app-id> -CertificateThumbprint <thumbprint>

.EXAMPLE
    # Preview: signs in, reads, prints every change it would make -- changes nothing:
    .\Deploy-PimActivatorBackend.ps1 -TenantId <tenant-id> -AssignToGroupId <group-id> -WhatIf

.NOTES
    Re-runnable: if an app with the same DisplayName already exists in the
    tenant, the script updates its redirect URI + required permissions in
    place rather than creating a duplicate.
    A transcript of the run is written to <temp>\pim-manager-logs\ (its path is printed).
    NO MODULES (owner 2026-10-07: "neither pim, si or invardia must have dependencies"): plain Microsoft Graph REST
    (Invoke-RestMethod + .NET) in every mode -- browser sign-in, app-only certificate, or a token you pass. Windows
    PowerShell 5.1 and PowerShell 7. Published standalone as https://invardia.com/support/pim/Deploy-PimActivatorBackend.ps1
    (one file: tools/setup/Build-PimSupportScripts.ps1 inlines the helpers).

.LINK
    https://invardia.com/docs/pim/scripts/Deploy-PimActivatorBackend/
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    # Extension id is derived from the manifest.json "key" field, which is
    # identical across every install of this distribution -- so default it
    # rather than make every operator look it up. Override only if you fork
    # the extension under a different key.
    [ValidatePattern('^[a-p]{32}$')]   # Chromium extension id format
    [string]$ExtensionId = 'eheocihmlppcophaeakmdenhgcookkab',

    # Which extension ids get redirect URIs registered (always merged, never replacing):
    #   'Released' (DEFAULT) registers ONLY the released id -- the customer-tenant deploy.
    #     (SEC-37: the default used to be 'Both', which put the TEST build's redirect on
    #     every customer app that holds tenant-wide RoleManagement.ReadWrite.Directory.)
    #   'Both' registers the released id AND the TEST id, so prod + test builds both sign
    #     in -- for the internal/dev tenant only; ask for it explicitly.
    #   'Test' is kept as an alias of 'Both' for back-compat.
    [ValidateSet('Both','Released','Test')]
    [string]$Channel = 'Released',

    [string]$DisplayName = 'PIM Activator',

    [string]$TenantId,

    # Default ON: a fresh app reg without admin consent makes every user hit
    # the per-user consent dialog on first sign-in, which most operators don't
    # want. Pass -GrantConsent:$false to skip the tenant-wide consent step
    # (rare -- e.g. when the caller doesn't hold Privileged Role Administrator
    # and a delegated approver will consent later via the Enterprise apps blade).
    [switch]$GrantConsent = $true,

    # Default ON: open the browser sign-in in Microsoft Edge explicitly
    # instead of the system default browser -- on servers that is often legacy
    # Internet Explorer, which mangles the auth redirect. Falls back to the
    # default browser when Edge is not installed. Pass -UseEdge:$false to use
    # the default browser always.
    [switch]$UseEdge = $true,

    # App-only (certificate) sign-in for headless deployment. Supply both with
    # -TenantId; the app must hold Application.ReadWrite.All (app-reg CRUD) and,
    # for -GrantConsent, DelegatedPermissionGrant.ReadWrite.All. When used, the
    # browser sign-in + delegated role pre-flight are skipped.
    [string]$AppId,
    [string]$CertificateThumbprint,

    # A Microsoft Graph access token you already have (automation). Skips the
    # browser sign-in; not renewed (valid ~1 hour from when it was minted).
    [string]$AccessToken,

    # 97.2 (owner 2026-10-08: "customer must define who (group) to deploy to - not
    # everyone"): the app is ALWAYS set to "Assignment required" (appRoleAssignmentRequired),
    # so only people you assign can sign in to the PIM Activator. -AssignToGroupId assigns
    # that group (direct members; read back). Not given = nobody can sign in until you
    # assign a group (Enterprise applications > the app > Users and groups, or re-run with it).
    [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
    [string]$AssignToGroupId
)

$ErrorActionPreference = 'Stop'
$script:PimActivatorAppOnly = [bool]($AppId -and $CertificateThumbprint -and -not $AccessToken)
# Windows PowerShell 5.1 may default to TLS 1.0/1.1; Entra + Graph need 1.2.
try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 } catch { }

# Shared sign-in (browser PKCE / app-only certificate / provided token) + the version banner.
. (Join-Path $PSScriptRoot '_PimActivatorAuth.ps1')
# Graph REST seam (Invoke-PaGraph) + the app reg / SP / consent-grant body builders.
. (Join-Path $PSScriptRoot '_PimActivatorBackend.ps1')
# 12.7 run frame: "Documentation: <page>" as the first line + a transcript in the temp folder (its path printed at the end).
. (Join-Path $PSScriptRoot '..\setup\_PimScriptDoc.ps1')
$null = Start-PimScriptRun -Script 'Deploy-PimActivatorBackend'
try {
$_preview = [bool]$WhatIfPreference
if ($_preview) { Write-Host 'PREVIEW (-WhatIf): signs in and reads; every change is listed as "What if:" and none is made.' -ForegroundColor Yellow }

$_mode =if ($AccessToken) { 'provided token' } elseif ($script:PimActivatorAppOnly) { 'app-only certificate' } else { 'browser sign-in' }
Show-PimActivatorBanner -ScriptName "Deploy-PimActivatorBackend (REST, no modules; $_mode)"

# ---------------------------------------------------------------------------
# Sign in to Microsoft Graph
# ---------------------------------------------------------------------------

$_requiredScopes = @(
    'Application.ReadWrite.All'
    'AppRoleAssignment.ReadWrite.All'
    'DelegatedPermissionGrant.ReadWrite.All'
)

if ($script:PimActivatorAppOnly -and -not $TenantId) { throw "App-only sign-in requires -TenantId." }
$ctx = Connect-PimActivatorGraph -RequiredScopes $_requiredScopes -TenantId $TenantId -UseEdge:([bool]$UseEdge) -AppId $AppId -CertificateThumbprint $CertificateThumbprint -AccessToken $AccessToken
if ($ctx.TenantId) { $TenantId = $ctx.TenantId }
Write-Host "Tenant   : $TenantId"  -ForegroundColor Cyan
Write-Host "Signed-in: $(if ($ctx.Account) { $ctx.Account } else { $ctx.ClientId })" -ForegroundColor Cyan
Write-Host ""

# ---------------------------------------------------------------------------
# Pre-flight: verify the signed-in admin's ACTIVE directory roles
# ---------------------------------------------------------------------------

# PIM-eligible roles do NOT count until activated, and a Graph session
# established BEFORE the activation may not reflect it. Check up front so the
# operator gets one clear message instead of a confusing mid-run 403 (or the
# silent-empty-result variant of one).
function Assert-ActiveEntraRoles {
    param([bool]$NeedsConsentRole)

    $tpl = @{   # well-known directory role template ids
        GlobalAdmin   = '62e90394-69f5-4237-9190-012177145e10'
        AppAdmin      = '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3'
        CloudAppAdmin = '158c047a-c907-4556-b7ef-446551a6b5f7'
        PrivRoleAdmin = 'e8611ab8-c189-46e8-94e1-60213ab1f814'
    }
    try {
        $active = @(Invoke-PaGraph -Method GET -Path '/me/memberOf/microsoft.graph.directoryRole?$select=displayName,roleTemplateId' -All)
    } catch {
        # Auth failures are NOT a skippable pre-flight problem -- every later
        # Graph call will hit the same wall. Stop with reconnect guidance.
        if ("$_" -match 'authentication failed|InvalidAuthenticationToken|HTTP 401|invalid_grant|AADSTS') {
            throw ("Graph authentication failed: $($_.Exception.Message)`n$(Get-PaBrokenAuthHelp)")
        }
        # Best-effort otherwise: reading own role memberships can be blocked by
        # scope/tenant policy -- don't fail the deploy over the pre-flight.
        Write-Host "Pre-flight: could not read your active directory roles -- continuing without the check. ($($_.Exception.Message))" -ForegroundColor DarkYellow
        return
    }
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
        throw ("Missing ACTIVE Entra roles:`n  - " + ($problems -join "`n  - ") + "`nIf these roles are PIM-eligible, activate them in PIM first, then re-run this script so the sign-in happens AFTER the activation.")
    }
}

# Preferred check: the session token's wids claim (works with the lean token,
# where /me/memberOf hides roles without a directory-read scope). A browser
# sign-in is repeated ONCE when the PIM activation postdates the token; a token
# passed with -AccessToken cannot be renewed here, so that case stops with the
# fix. Falls back to the memberOf-based check when the token has no wids claim.
# Delegated sessions only -- an app-only token's wids are the APP's roles.
$_delegated = $ctx.AuthType -eq 'Interactive' -or ($ctx.AuthType -eq 'ProvidedToken' -and @($ctx.Scopes).Count -gt 0)
if ($_delegated -and $null -ne (Get-PaTokenRoleIds)) {
    $_reconnect = if ($ctx.AuthType -eq 'Interactive') { { $script:ctx = Connect-PimActivatorGraph -RequiredScopes $_requiredScopes -TenantId $TenantId -UseEdge:([bool]$UseEdge) } } else { $null }
    Assert-PaSessionRole -Reconnect $_reconnect `
        -AnyOfRoleIds @(
            '62e90394-69f5-4237-9190-012177145e10'   # Global Administrator
            '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3'   # Application Administrator
            '158c047a-c907-4556-b7ef-446551a6b5f7'   # Cloud Application Administrator
        ) `
        -RoleDescription "an ACTIVE 'Application Administrator' / 'Cloud Application Administrator' / 'Global Administrator' role (needed for the app registration + service principals)"
    if ($GrantConsent) {
        Assert-PaSessionRole -Reconnect $_reconnect `
            -AnyOfRoleIds @(
                '62e90394-69f5-4237-9190-012177145e10'   # Global Administrator
                'e8611ab8-c189-46e8-94e1-60213ab1f814'   # Privileged Role Administrator
            ) `
            -RoleDescription "an ACTIVE 'Privileged Role Administrator' or 'Global Administrator' role (needed for -GrantConsent; alternatively re-run with -GrantConsent:`$false)"
    }
} elseif ($_delegated) {
    Assert-ActiveEntraRoles -NeedsConsentRole:([bool]$GrantConsent)
} else {
    Write-Host "App-only mode: skipping delegated role pre-flight (app permissions govern; calls will error clearly if insufficient)." -ForegroundColor DarkYellow
}

# ---------------------------------------------------------------------------
# Resolve Microsoft Graph delegated permission ids
# ---------------------------------------------------------------------------

# First-party Microsoft service principals (Graph, ARM) are NOT guaranteed to
# exist in every tenant -- fresh / lightly-used tenants only get them
# instantiated on first use, so resolve-or-create instead of assuming
# presence. Raw REST throughout, so a permission failure surfaces as the real
# Graph error instead of a silent empty result.
function Resolve-FirstPartySp {
    param([string]$AppId, [string]$Name)

    function Get-RawSpByAppId([string]$Id) {
        try {
            Invoke-PaGraph -Method GET -Path "/servicePrincipals(appId='$Id')"
        } catch {
            if ("$_" -match 'Request_ResourceNotFound|ResourceNotFound|does not exist|404') { return $null }
            throw
        }
    }

    $raw = Get-RawSpByAppId $AppId
    if (-not $raw) {
        if (-not $PSCmdlet.ShouldProcess("$Name service principal (appId $AppId) in tenant $TenantId", 'Create (instantiate the Microsoft first-party service principal; POST /servicePrincipals)')) {
            # preview: the permission ids are resolved from this service principal at apply time
            return [pscustomobject]@{ Id = $null; DisplayName = $Name; Oauth2PermissionScopes = @() }
        }
        Write-Host "  $Name service principal not present in tenant -- instantiating it (appId $AppId)..." -ForegroundColor Yellow
        try {
            Invoke-PaGraph -Method POST -Path '/servicePrincipals' -Body @{ appId = $AppId } | Out-Null
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
    # Project the raw REST object onto the object shape downstream code consumes.
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
if ($graphSp.Id) {
    $scopeMap = Resolve-PaGraphScopeIds -Oauth2PermissionScopes $graphSp.Oauth2PermissionScopes -Names $needed
} else {
    $scopeMap = [ordered]@{}; foreach ($name in $needed) { $scopeMap[$name] = '(resolved when applied)' }
}
foreach ($name in $needed) {
    Write-Host ("  resolved {0,-45} -> {1}" -f $name, $scopeMap[$name]) -ForegroundColor DarkGray
}

# Azure Service Management API (well-known appId 797f4846-...) +
# user_impersonation. Required so the popup can mint an ARM token (separate
# audience: management.azure.com) and list Azure RBAC eligibilities + active
# assignments. Without it, the My Access tab shows a "Azure RBAC roles not
# visible yet" banner and the Azure-direct rows on Activate never load.
$asmAppId = '797f4846-ba00-4fd7-ba43-dac1f8f63013'
$asmSp    = Resolve-FirstPartySp -AppId $asmAppId -Name 'Azure Service Management'
$asmScope = $asmSp.Oauth2PermissionScopes | Where-Object { $_.Value -eq 'user_impersonation' }
if (-not $asmScope -and -not $asmSp.Id) { $asmScope = [pscustomobject]@{ Id = '(resolved when applied)'; Value = 'user_impersonation' } }
if (-not $asmScope) { throw "user_impersonation scope not found on Azure Service Management SP." }
Write-Host ("  resolved {0,-45} -> {1}" -f 'user_impersonation (ASM)', $asmScope.Id) -ForegroundColor DarkGray

# REST shape (lowercase keys) Graph expects on applications create/PATCH.
# Built by the unit-tested pure helper.
$requiredResourceAccess = New-PaRequiredResourceAccess `
    -GraphAppId $graphAppId -GraphScopeIds $scopeMap `
    -AsmAppId $asmAppId -AsmScopeId $asmScope.Id

$redirectUri = "https://$ExtensionId.chromiumapp.org/"

# Channel controls which extension ids get their redirect URIs registered on the app
# (always MERGED with whatever is there — never replaces existing URIs):
#   Released (DEFAULT) -> ONLY $ExtensionId (a clean customer-tenant deploy, no dev/test id).
#   Both               -> released $ExtensionId AND the TEST id, so prod + test builds both
#                         sign in (internal/dev tenant; must be asked for -- SEC-37).
#   Test               -> same as Both (kept for back-compat).
$TEST_EXT_ID = 'glldnbmjpdkjemcnficagdhgienfdpoo'
$additionalExtIds = if ($Channel -ne 'Released' -and $ExtensionId -ne $TEST_EXT_ID) { @($TEST_EXT_ID) } else { @() }
if ($additionalExtIds.Count -gt 0) { Write-Host "Channel = $Channel -> also registering redirect URIs for test id $TEST_EXT_ID" -ForegroundColor Yellow }

# ---------------------------------------------------------------------------
# Create or update the app registration
# ---------------------------------------------------------------------------

# Modern Edge / Chrome MV3 extension auth needs BOTH SPA URIs registered:
#   1. https://<id>.chromiumapp.org/  -- the redirect that
#      chrome.identity.launchWebAuthFlow listens for + intercepts to extract
#      the auth code.
#   2. chrome-extension://<id>/  -- because the popup.js fetch() to the
#      /oauth2/v2.0/token endpoint sends Origin: chrome-extension://<id>,
#      and Entra's SPA flow validates the Origin header against registered
#      redirect URIs. Without this, token redemption fails with AADSTS9002326
#      ("Cross-origin token redemption is permitted only for the
#      'Single-Page Application' client-type"). Both must be SPA type (Public
#      Client type bounces with the same error). The body builder also wipes
#      any stale Public Client URI a previous install left behind.
$existingResp = Invoke-PaGraph -Method GET -Path "/applications?`$filter=displayName eq '$DisplayName'&`$select=id,appId,spa" -All
$existing = @($existingResp)
if ($existing.Count -gt 1) {
    throw "Multiple app registrations named '$DisplayName' already exist. Disambiguate (rename or specify a different -DisplayName) and re-run."
}

if ($existing.Count -eq 1) {
    $existingApp = $existing[0]
    Write-Host "Updating existing app registration '$DisplayName' (appId $($existingApp.appId))..." -ForegroundColor Yellow
    # Preserve whatever SPA redirect URIs are already on the app (union), so this
    # run ADDS the channel's URIs rather than replacing the tenant's existing set.
    $existingSpa = @()
    $spaObj = Get-PaProp $existingApp 'spa'
    if ($spaObj) { $existingSpa = @(Get-PaProp $spaObj 'redirectUris') | Where-Object { $_ } }
    $updateBody = New-PaAppRegistrationBody -DisplayName $DisplayName -ExtensionId $ExtensionId -RequiredResourceAccess $requiredResourceAccess -AdditionalExtensionIds $additionalExtIds -ExistingSpaRedirectUris $existingSpa
    if ($PSCmdlet.ShouldProcess("app registration '$DisplayName' (appId $($existingApp.appId))", "Update (PATCH /applications): SPA redirect URIs $(@($updateBody.spa.redirectUris) -join ', '); delegated permissions Microsoft Graph $($needed -join ', ') + Azure Service Management user_impersonation; public-client URIs cleared")) {
        Invoke-PaGraph -Method PATCH -Path "/applications/$($existingApp.id)" -Body $updateBody | Out-Null
    }
    $app = Invoke-PaGraph -Method GET -Path "/applications/$($existingApp.id)?`$select=id,appId,displayName"
} else {
    $createBody = New-PaAppRegistrationBody -DisplayName $DisplayName -ExtensionId $ExtensionId -RequiredResourceAccess $requiredResourceAccess -AdditionalExtensionIds $additionalExtIds -IncludeDisplayName
    $app = $null
    if ($PSCmdlet.ShouldProcess("app registration '$DisplayName' (single tenant)", "Create (POST /applications): SPA redirect URIs $(@($createBody.spa.redirectUris) -join ', '); delegated permissions Microsoft Graph $($needed -join ', ') + Azure Service Management user_impersonation")) {
        Write-Host "Creating app registration '$DisplayName'..." -ForegroundColor Green
        $app = Invoke-PaGraph -Method POST -Path '/applications' -Body $createBody
    }
}

# Normalise an id off a Graph object (REST camelCase; Get-PaProp also
# accepts PascalCase and hashtables).
$appId    = Get-PaProp $app 'appId'
$appObjId = Get-PaProp $app 'id'

# Ensure the service principal exists in the tenant (creates the enterprise
# app). Raw requests for the same silent-null reason as Resolve-FirstPartySp.
$sp = $null
if ($appId) {
    try { $sp = Invoke-PaGraph -Method GET -Path "/servicePrincipals(appId='$appId')" }
    catch { if ("$_" -notmatch 'Request_ResourceNotFound|ResourceNotFound|does not exist|404') { throw } }
}
if (-not $sp -and -not $PSCmdlet.ShouldProcess("service principal (enterprise application) of '$DisplayName'", 'Create (POST /servicePrincipals)')) {
    # preview: nothing more to read for an app that does not exist yet
} elseif (-not $sp) {
    # A freshly-created application object can take a few seconds to replicate;
    # POSTing the SP immediately then 400s with NoBackingApplicationObject.
    # Retry with backoff instead of failing the deploy.
    $sp = $null
    for ($spTry = 1; $spTry -le 6; $spTry++) {
        try { $sp = Invoke-PaGraph -Method POST -Path '/servicePrincipals' -Body @{ appId = $appId }; break }
        catch {
            if ("$_" -match 'NoBackingApplicationObject|does not reference a valid application' -and $spTry -lt 6) {
                Write-Host "  app object not replicated yet -- retry $spTry/6 in $($spTry * 5)s" -ForegroundColor DarkGray
                Start-Sleep -Seconds ($spTry * 5)
            } else { throw }
        }
    }
    Write-Host "Created service principal (objectId $(Get-PaProp $sp 'id'))." -ForegroundColor Green
} else {
    Write-Host "Service principal already present (objectId $(Get-PaProp $sp 'id'))." -ForegroundColor DarkGray
}
$spId = Get-PaProp $sp 'id'

# ---------------------------------------------------------------------------
# WHO may sign in (97.2, owner 2026-10-08): "Assignment required" + the group
# ---------------------------------------------------------------------------
# Without appRoleAssignmentRequired every user in the tenant can sign in to the
# app (and, with the tenant-wide consent below, get its tokens). With it, only
# the people assigned to the enterprise app can. A group assignment covers the
# group's DIRECT members (Entra does not pass app access through nested groups),
# and the membership must be permanent: a PIM-eligible membership would lock the
# person out of the very tool that activates it.
$_assignedNow = @(); $_spNow = $null
if ($spId) {
    $_assignedNow = @(Invoke-PaGraph -Method GET -Path "/servicePrincipals/$spId/appRoleAssignedTo?`$select=id,principalId,principalDisplayName,principalType" -All)
    $_spNow = Invoke-PaGraph -Method GET -Path "/servicePrincipals/$spId`?`$select=id,appRoleAssignmentRequired"
}
if (-not [bool](Get-PaProp $_spNow 'appRoleAssignmentRequired')) {
    if ($spId -and $existing.Count -eq 1 -and -not $AssignToGroupId -and -not $_assignedNow.Count) {
        # An app that is in use and open to everyone: switching it to "assignment required" with nobody assigned would
        # lock every current user out at once. Refuse, and say what to run.
        throw ("'$DisplayName' (appId $appId) is open to EVERY user today and nobody is assigned to it. Setting 'Assignment required' now would lock " +
               "every current user out. Re-run with -AssignToGroupId <group object id> (the admins who use the PIM Activator) -- the group is " +
               "assigned first, then the app is closed to everyone else.")
    }
}
if ($AssignToGroupId) {
    $_hit = @($_assignedNow | Where-Object { "$(Get-PaProp $_ 'principalId')" -ieq $AssignToGroupId })
    if ($_hit.Count) {
        Write-Host "Group $AssignToGroupId ($(Get-PaProp $_hit[0] 'principalDisplayName')) is already assigned to the app." -ForegroundColor DarkGray
    } elseif ($PSCmdlet.ShouldProcess("group $AssignToGroupId", "Assign to the enterprise application '$DisplayName' (app role assignment, default access; POST appRoleAssignedTo) -- its direct members may sign in to the PIM Activator")) {
        Write-Host "Assigning group $AssignToGroupId to '$DisplayName' (default access)..." -ForegroundColor Cyan
        $_new = Invoke-PaGraph -Method POST -Path "/servicePrincipals/$spId/appRoleAssignedTo" -Body @{
            principalId = $AssignToGroupId; resourceId = $spId; appRoleId = '00000000-0000-0000-0000-000000000000' }
        if ("$(Get-PaProp $_new 'principalType')" -and "$(Get-PaProp $_new 'principalType')" -ne 'Group') {
            # Not a group (a user or a service principal id was passed): take back what was just added.
            try { Invoke-PaGraph -Method DELETE -Path "/servicePrincipals/$spId/appRoleAssignedTo/$(Get-PaProp $_new 'id')" | Out-Null } catch { }
            throw "$AssignToGroupId is a $(Get-PaProp $_new 'principalType'), not a group -- the assignment was removed again. Pass the object id of a GROUP."
        }
    }
}
if (-not [bool](Get-PaProp $_spNow 'appRoleAssignmentRequired')) {
    if ($PSCmdlet.ShouldProcess("enterprise application '$DisplayName'", "Set 'Assignment required' (appRoleAssignmentRequired = true; PATCH /servicePrincipals) -- only assigned users and groups can sign in")) {
        Invoke-PaGraph -Method PATCH -Path "/servicePrincipals/$spId" -Body @{ appRoleAssignmentRequired = $true } | Out-Null
    }
}
if ($_preview) {
    # nothing was written, so there is nothing to read back
    if ($GrantConsent) {
        $scopeString = New-PaConsentScopeString -Scopes $needed
        [void]$PSCmdlet.ShouldProcess("Microsoft Graph (all users of '$DisplayName')", "Grant tenant-wide admin consent for the delegated permissions (oauth2PermissionGrant AllPrincipals): $scopeString")
        [void]$PSCmdlet.ShouldProcess("Azure Service Management (all users of '$DisplayName')", 'Grant tenant-wide admin consent for the delegated permission (oauth2PermissionGrant AllPrincipals): user_impersonation')
    }
    Write-Host ''
    Write-Host 'PREVIEW (-WhatIf) complete: nothing was changed. Run the same command without -WhatIf to apply.' -ForegroundColor Yellow
    return
}
# read back: assignment required, and the group is there
$_spBack =Invoke-PaGraph -Method GET -Path "/servicePrincipals/$spId`?`$select=id,appRoleAssignmentRequired"
if (-not [bool](Get-PaProp $_spBack 'appRoleAssignmentRequired')) { throw "'$DisplayName': 'Assignment required' did not read back as set -- check Enterprise applications > $DisplayName > Properties." }
$_assignedBack = @(Invoke-PaGraph -Method GET -Path "/servicePrincipals/$spId/appRoleAssignedTo?`$select=id,principalId,principalDisplayName,principalType" -All)
$_groupName = ''
if ($AssignToGroupId) {
    $_g = @($_assignedBack | Where-Object { "$(Get-PaProp $_ 'principalId')" -ieq $AssignToGroupId -and "$(Get-PaProp $_ 'principalType')" -eq 'Group' })
    if (-not $_g.Count) { throw "'$DisplayName': group $AssignToGroupId did not read back as assigned -- check Enterprise applications > $DisplayName > Users and groups." }
    $_groupName = "$(Get-PaProp $_g[0] 'principalDisplayName')"
}
Write-Host "Assignment required: ON (read back) -- only assigned users and groups can sign in." -ForegroundColor Green
if ($_assignedBack.Count) {
    Write-Host ("Deploys to: " + (@($_assignedBack | ForEach-Object { "$(Get-PaProp $_ 'principalDisplayName') ($(Get-PaProp $_ 'principalType'))" }) -join ', ')) -ForegroundColor Green
} else {
    Write-Host "Deploys to: NOBODY yet -- nobody can sign in until you assign a group: re-run with -AssignToGroupId <group object id>, or Enterprise applications > $DisplayName > Users and groups > Add." -ForegroundColor Yellow
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
    $scopeString = New-PaConsentScopeString -Scopes $needed
    Set-PaOauth2Grant -ClientSpId $spId -ResourceSpId $graphSp.Id -Scope $scopeString -Label 'Graph'

    # Azure Service Management user_impersonation -- mirrors the Graph block
    # above but against the ARM SP. Without admin-consent here, the popup
    # surfaces a yellow "Azure RBAC roles not visible yet" banner until the
    # admin runs through this script with -GrantConsent.
    Set-PaOauth2Grant -ClientSpId $spId -ResourceSpId $asmSp.Id -Scope 'user_impersonation' -Label 'ARM'
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
Write-Host "  clientId    : $appId"
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
    ClientId    = $appId
    AppObjectId = $appObjId
    SpObjectId  = $spId
    AssignmentRequired = $true
    AssignedGroupId    = $(if ($AssignToGroupId) { $AssignToGroupId.ToLowerInvariant() } else { '' })
    AssignedGroupName  = $_groupName
    AssignedTo         = @($_assignedBack | ForEach-Object { "$(Get-PaProp $_ 'principalDisplayName')" })
    RedirectUri = $redirectUri
    Scopes      = $needed
}
} finally { Stop-PimScriptRun -Script 'Deploy-PimActivatorBackend' }
