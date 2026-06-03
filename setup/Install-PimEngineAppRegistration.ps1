#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Applications, Microsoft.Graph.Identity.SignIns, Microsoft.Graph.Authentication, Microsoft.Graph.Identity.DirectoryManagement
<#
.SYNOPSIS
    Create the Entra app registration (SPN + certificate + permissions + admin
    consent) that the PIM4EntraPS *engine* uses to apply changes to the tenant.

.DESCRIPTION
    Companion to Deploy-PimActivatorBackend.ps1, but for the OTHER
    direction:

      - Activator (browser extension)    = delegated perms, signed-in admin
                                           activates their own assignments.
      - Engine   (this script's target)  = application perms, runs unattended
                                           from a VM / Azure Function / Logic
                                           App to create + maintain the model.

    What this script does, in order:

      1. Connect-MgGraph sanity check.
      2. Resolve the application-role (NOT delegated scope) ids on the
         Microsoft Graph + Office 365 Exchange Online service principals.
      3. Create or update the engine app registration with the right
         RequiredResourceAccess block.
      4. Issue or reuse a certificate (self-signed by default; -ExistingThumbprint
         opts in to a pre-issued one), upload its public key to the app reg.
      5. Create / find the service principal.
      6. (Optional, -GrantConsent) Tenant-wide admin consent: write
         appRoleAssignedTo entries for every requested app permission.
      7. (Optional, -AzureRbac) Assign User Access Administrator on the root
         management group so the engine can manage Azure RBAC PIM. Requires
         Az.Accounts + Az.Resources and is called via Az cmdlets, not Graph.

    Re-runnable: every step is idempotent. Same -DisplayName -> update in place.

.PARAMETER DisplayName
    Display name of the engine app registration. Default: 'PIM4EntraPS Engine'.

.PARAMETER TenantId
    Optional. If omitted, uses whatever Connect-MgGraph defaulted to.

.PARAMETER ExistingThumbprint
    Use a pre-issued cert (must already be in Cert:\CurrentUser\My with the
    private key present). When omitted, the script generates a fresh
    self-signed cert.

.PARAMETER CertSubject
    Subject DN for the auto-generated cert. Default 'CN=PIM4EntraPS-Engine'.
    Ignored when -ExistingThumbprint is supplied.

.PARAMETER CertValidityYears
    Validity window for the auto-generated cert. Default 2.

.PARAMETER ExportPfxPath
    If set, export the cert (including private key) to this .pfx path so you
    can install it on the engine host. Prompts for a PFX password.

.PARAMETER GrantConsent
    Write the tenant-wide admin-consent appRoleAssignments for every requested
    permission. Without this you'll have to click 'Grant admin consent for
    <tenant>' in the Entra portal afterwards. Requires the caller to have
    Privileged Role Administrator (or Global Administrator).

.PARAMETER AzureRbac
    Also assign User Access Administrator at the root management group scope
    so the engine can configure Azure RBAC PIM. Requires Az.Accounts +
    Az.Resources to be installed AND the caller to be signed in via
    Connect-AzAccount with sufficient rights.

.PARAMETER IncludeExchange
    Also request the Exchange.ManageAsApp app permission + assign the Exchange
    Administrator directory role to the SP. Required if the engine creates /
    updates admin mailboxes (CreateUpdate-Accounts-From-file-CSV with
    Exchange.Online.Management calls).

.EXAMPLE
    # First time, in the target tenant. Connect with the right scopes first.
    Connect-MgGraph -TenantId '<tid>' -Scopes `
        'Application.ReadWrite.All',
        'AppRoleAssignment.ReadWrite.All',
        'DelegatedPermissionGrant.ReadWrite.All',
        'RoleManagement.ReadWrite.Directory'

    .\Install-PimEngineAppRegistration.ps1 -GrantConsent -IncludeExchange -ExportPfxPath C:\TMP\pim-engine.pfx

.EXAMPLE
    # Reuse an existing cert (already in Cert:\CurrentUser\My):
    .\Install-PimEngineAppRegistration.ps1 -ExistingThumbprint '0123ABCD...' -GrantConsent

.NOTES
    Permissions requested (all APPLICATION, NOT delegated):

      Microsoft Graph:
        RoleManagement.ReadWrite.Directory     -- PIM Entra ID role schedules + policies
        Group.ReadWrite.All                    -- create PIM-* groups, manage memberships
        User.ReadWrite.All                     -- create admin accounts
        Directory.Read.All                     -- enumerate tenant
        AdministrativeUnit.ReadWrite.All       -- create + manage AUs and AU role assignments
        PrivilegedAccess.ReadWrite.AzureADGroup -- PIM-for-Groups configuration
        UserAuthenticationMethod.ReadWrite.All -- TAP creation for new admins

      Office 365 Exchange Online (-IncludeExchange only):
        Exchange.ManageAsApp                   -- Connect-ExchangeOnline app-only

    The SP gets a self-signed cert (default). Export the PFX, install on the
    engine host (LocalMachine\My for service-account use), and feed the
    thumbprint to the launcher LauncherConfig.custom.ps1 via the existing
    $global:HighPriv_Modern_CertificateThumbprint_Azure variable.
#>
[CmdletBinding()]
param(
    [string]$DisplayName = 'PIM4EntraPS Engine',

    [string]$TenantId,

    [string]$ExistingThumbprint,

    [string]$CertSubject = 'CN=PIM4EntraPS-Engine',

    [ValidateRange(1, 5)]
    [int]$CertValidityYears = 2,

    [string]$ExportPfxPath,

    [switch]$GrantConsent,

    [switch]$AzureRbac,

    [switch]$IncludeExchange
)

$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Pre-flight: Graph connection + caller scopes
# ---------------------------------------------------------------------------

$ctx = Get-MgContext
if (-not $ctx) {
    Write-Host "Not connected to Microsoft Graph. Run Connect-MgGraph first:" -ForegroundColor Yellow
    Write-Host "  Connect-MgGraph -Scopes 'Application.ReadWrite.All','AppRoleAssignment.ReadWrite.All','DelegatedPermissionGrant.ReadWrite.All','RoleManagement.ReadWrite.Directory'" -ForegroundColor Yellow
    throw "Connect-MgGraph required."
}

$requiredCallerScopes = @('Application.ReadWrite.All')
if ($GrantConsent) { $requiredCallerScopes += 'AppRoleAssignment.ReadWrite.All' }
if ($IncludeExchange -and $GrantConsent) { $requiredCallerScopes += 'RoleManagement.ReadWrite.Directory' }

$missing = $requiredCallerScopes | Where-Object { $_ -notin $ctx.Scopes }
if ($missing) {
    throw "Current Graph session is missing required scopes: $($missing -join ', '). Reconnect with those scopes."
}

if ($TenantId -and $TenantId -ne $ctx.TenantId) {
    throw "Connected to tenant $($ctx.TenantId) but -TenantId says $TenantId. Reconnect with the correct -TenantId."
}
$TenantId = $ctx.TenantId

Write-Host ""
Write-Host "==========================================================================" -ForegroundColor Cyan
Write-Host " PIM4EntraPS Engine app registration installer" -ForegroundColor Cyan
Write-Host "==========================================================================" -ForegroundColor Cyan
Write-Host "  Tenant      : $TenantId"
Write-Host "  Signed-in   : $($ctx.Account)"
Write-Host "  Display name: $DisplayName"
Write-Host "  GrantConsent: $GrantConsent"
Write-Host "  AzureRbac   : $AzureRbac"
Write-Host "  Exchange    : $IncludeExchange"
Write-Host ""

# ---------------------------------------------------------------------------
# Resolve Microsoft Graph app-role ids (NOT delegated scopes)
# ---------------------------------------------------------------------------

$graphAppId = '00000003-0000-0000-c000-000000000000'
$graphSp    = Get-MgServicePrincipal -Filter "appId eq '$graphAppId'"
if (-not $graphSp) { throw "Microsoft Graph service principal not found in tenant." }

$graphRolesWanted = @(
    'RoleManagement.ReadWrite.Directory',
    'Group.ReadWrite.All',
    'User.ReadWrite.All',
    'Directory.Read.All',
    'AdministrativeUnit.ReadWrite.All',
    'PrivilegedAccess.ReadWrite.AzureADGroup',
    'UserAuthenticationMethod.ReadWrite.All'
)

Write-Host "Resolving Microsoft Graph application roles..." -ForegroundColor Cyan
$graphRoleMap = @{}
foreach ($name in $graphRolesWanted) {
    $role = $graphSp.AppRoles | Where-Object { $_.Value -eq $name -and $_.AllowedMemberTypes -contains 'Application' }
    if (-not $role) { throw "Graph app role '$name' not found (or not application-assignable)." }
    $graphRoleMap[$name] = $role.Id
    Write-Host ("  resolved {0,-42} -> {1}" -f $name, $role.Id) -ForegroundColor DarkGray
}

# ---------------------------------------------------------------------------
# Resolve Office 365 Exchange Online app-role (optional)
# ---------------------------------------------------------------------------

$exoAppId = '00000002-0000-0ff1-ce00-000000000000'   # Office 365 Exchange Online
$exoSp = $null
$exoRoleMap = @{}
if ($IncludeExchange) {
    Write-Host "Resolving Office 365 Exchange Online application roles..." -ForegroundColor Cyan
    $exoSp = Get-MgServicePrincipal -Filter "appId eq '$exoAppId'"
    if (-not $exoSp) {
        throw "Office 365 Exchange Online SP not found. Tenant may not have Exchange Online provisioned, or run 'New-MgServicePrincipal -AppId $exoAppId' first."
    }
    $role = $exoSp.AppRoles | Where-Object { $_.Value -eq 'Exchange.ManageAsApp' -and $_.AllowedMemberTypes -contains 'Application' }
    if (-not $role) { throw "Exchange.ManageAsApp role not found on Exchange Online SP." }
    $exoRoleMap['Exchange.ManageAsApp'] = $role.Id
    Write-Host ("  resolved {0,-42} -> {1}" -f 'Exchange.ManageAsApp', $role.Id) -ForegroundColor DarkGray
}

# Build the RequiredResourceAccess block (one element per resource SP).
$requiredResourceAccess = @(
    @{
        ResourceAppId  = $graphAppId
        ResourceAccess = $graphRolesWanted | ForEach-Object { @{ Id = $graphRoleMap[$_]; Type = 'Role' } }
    }
)
if ($IncludeExchange) {
    $requiredResourceAccess += @{
        ResourceAppId  = $exoAppId
        ResourceAccess = @(@{ Id = $exoRoleMap['Exchange.ManageAsApp']; Type = 'Role' })
    }
}

# ---------------------------------------------------------------------------
# Certificate: reuse existing OR generate self-signed
# ---------------------------------------------------------------------------

Write-Host ""
Write-Host "Preparing certificate..." -ForegroundColor Cyan

if ($ExistingThumbprint) {
    $cert = Get-Item -Path "Cert:\CurrentUser\My\$ExistingThumbprint" -ErrorAction SilentlyContinue
    if (-not $cert) { throw "Cert with thumbprint $ExistingThumbprint not found in Cert:\CurrentUser\My." }
    Write-Host "  using existing cert: $($cert.Subject) (thumbprint $($cert.Thumbprint))" -ForegroundColor DarkGray
} else {
    $notAfter = (Get-Date).AddYears($CertValidityYears)
    $cert = New-SelfSignedCertificate `
        -Subject $CertSubject `
        -CertStoreLocation 'Cert:\CurrentUser\My' `
        -KeyExportPolicy Exportable `
        -KeySpec Signature `
        -KeyLength 2048 `
        -KeyAlgorithm RSA `
        -HashAlgorithm SHA256 `
        -NotAfter $notAfter
    Write-Host "  created self-signed cert: $($cert.Subject) (thumbprint $($cert.Thumbprint), expires $($cert.NotAfter.ToString('yyyy-MM-dd')))" -ForegroundColor Green
}

$certBytes  = $cert.GetRawCertData()
$certBase64 = [Convert]::ToBase64String($certBytes)

# ---------------------------------------------------------------------------
# Create or update the app registration
# ---------------------------------------------------------------------------

Write-Host ""
Write-Host "Creating / updating app registration..." -ForegroundColor Cyan

$existing = Get-MgApplication -Filter "displayName eq '$DisplayName'" -ConsistencyLevel eventual -CountVariable c -ErrorAction SilentlyContinue
if ($existing.Count -gt 1) {
    throw "Multiple app registrations named '$DisplayName' already exist. Disambiguate (rename or specify a different -DisplayName) and re-run."
}

$keyCredentials = @(@{
    Type           = 'AsymmetricX509Cert'
    Usage          = 'Verify'
    Key            = $certBytes
    DisplayName    = "PIM4EntraPS Engine cert ($($cert.NotBefore.ToString('yyyy-MM-dd')) -> $($cert.NotAfter.ToString('yyyy-MM-dd')))"
    StartDateTime  = $cert.NotBefore
    EndDateTime    = $cert.NotAfter
})

if ($existing) {
    Write-Host "  updating existing app (appId $($existing.AppId))" -ForegroundColor Yellow
    # Preserve any other key credentials already on the app (e.g. older certs
    # the customer rotated in). We add ours alongside; rotation drops the old
    # ones manually.
    $allKeys = @($existing.KeyCredentials) + $keyCredentials
    # Dedupe by thumbprint (use first 20 bytes of the Key as a key-id surrogate).
    $allKeys = $allKeys | Group-Object { ($_.Key[0..19] | ForEach-Object { $_.ToString('x2') }) -join '' } | ForEach-Object { $_.Group[0] }

    Update-MgApplication -ApplicationId $existing.Id `
        -RequiredResourceAccess $requiredResourceAccess `
        -KeyCredentials $allKeys
    $app = Get-MgApplication -ApplicationId $existing.Id
} else {
    Write-Host "  creating new app" -ForegroundColor Green
    $app = New-MgApplication `
        -DisplayName $DisplayName `
        -SignInAudience 'AzureADMyOrg' `
        -RequiredResourceAccess $requiredResourceAccess `
        -KeyCredentials $keyCredentials
}

# Service principal (the enterprise app object)
$sp = Get-MgServicePrincipal -Filter "appId eq '$($app.AppId)'" -ErrorAction SilentlyContinue
if (-not $sp) {
    $sp = New-MgServicePrincipal -AppId $app.AppId
    Write-Host "  created service principal (objectId $($sp.Id))" -ForegroundColor Green
} else {
    Write-Host "  service principal already present (objectId $($sp.Id))" -ForegroundColor DarkGray
}

# ---------------------------------------------------------------------------
# Tenant-wide admin consent (per app permission)
# ---------------------------------------------------------------------------

if ($GrantConsent) {
    Write-Host ""
    Write-Host "Granting tenant-wide admin consent (app role assignments)..." -ForegroundColor Cyan

    function Grant-AppRole {
        param([string]$ResourceSpId, [string]$AppRoleId, [string]$Label)
        # Idempotent: skip if already assigned.
        $existingAssign = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id `
            | Where-Object { $_.ResourceId -eq $ResourceSpId -and $_.AppRoleId -eq $AppRoleId }
        if ($existingAssign) {
            Write-Host ("  [skip]  {0} -- already granted" -f $Label) -ForegroundColor DarkGray
            return
        }
        try {
            New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id `
                -PrincipalId $sp.Id `
                -ResourceId $ResourceSpId `
                -AppRoleId $AppRoleId | Out-Null
            Write-Host ("  [ok]    {0}" -f $Label) -ForegroundColor Green
        } catch {
            Write-Host ("  [fail]  {0}: {1}" -f $Label, $_.Exception.Message) -ForegroundColor Red
        }
    }

    foreach ($name in $graphRolesWanted) {
        Grant-AppRole -ResourceSpId $graphSp.Id -AppRoleId $graphRoleMap[$name] -Label "Graph/$name"
    }
    if ($IncludeExchange) {
        Grant-AppRole -ResourceSpId $exoSp.Id -AppRoleId $exoRoleMap['Exchange.ManageAsApp'] -Label "EXO/Exchange.ManageAsApp"
    }
}

# ---------------------------------------------------------------------------
# Exchange Administrator directory role (only useful when -IncludeExchange)
# ---------------------------------------------------------------------------

if ($IncludeExchange -and $GrantConsent) {
    Write-Host ""
    Write-Host "Assigning 'Exchange Administrator' directory role to the SP..." -ForegroundColor Cyan
    # Find role definition (template).
    $roleDefs = Get-MgRoleManagementDirectoryRoleDefinition -All
    $exoAdminRole = $roleDefs | Where-Object { $_.DisplayName -eq 'Exchange Administrator' }
    if (-not $exoAdminRole) {
        Write-Host "  [skip] 'Exchange Administrator' role definition not found." -ForegroundColor Yellow
    } else {
        $existingAssign = Get-MgRoleManagementDirectoryRoleAssignment -All `
            | Where-Object { $_.PrincipalId -eq $sp.Id -and $_.RoleDefinitionId -eq $exoAdminRole.Id }
        if ($existingAssign) {
            Write-Host "  [skip] already assigned" -ForegroundColor DarkGray
        } else {
            try {
                New-MgRoleManagementDirectoryRoleAssignment -PrincipalId $sp.Id `
                    -RoleDefinitionId $exoAdminRole.Id `
                    -DirectoryScopeId '/' | Out-Null
                Write-Host "  [ok] Exchange Administrator assigned" -ForegroundColor Green
            } catch {
                Write-Host "  [fail] $($_.Exception.Message)" -ForegroundColor Red
            }
        }
    }
}

# ---------------------------------------------------------------------------
# Azure RBAC: User Access Administrator at root (optional)
# ---------------------------------------------------------------------------

if ($AzureRbac) {
    Write-Host ""
    Write-Host "Assigning 'User Access Administrator' at root management group scope..." -ForegroundColor Cyan
    $azReady = (Get-Module -ListAvailable -Name Az.Accounts) -and (Get-Module -ListAvailable -Name Az.Resources)
    if (-not $azReady) {
        Write-Host "  [skip] Az.Accounts + Az.Resources not installed. Run:" -ForegroundColor Yellow
        Write-Host "    Install-Module Az.Accounts, Az.Resources -Scope CurrentUser" -ForegroundColor Yellow
    } else {
        try {
            $azCtx = Get-AzContext -ErrorAction SilentlyContinue
            if (-not $azCtx) {
                Write-Host "  Connecting to Azure (browser)..." -ForegroundColor Cyan
                Connect-AzAccount -Tenant $TenantId | Out-Null
            }
            $rootScope = "/providers/Microsoft.Management/managementGroups/$TenantId"
            $existingRa = Get-AzRoleAssignment -ObjectId $sp.Id -Scope $rootScope -RoleDefinitionName 'User Access Administrator' -ErrorAction SilentlyContinue
            if ($existingRa) {
                Write-Host "  [skip] already assigned at root MG" -ForegroundColor DarkGray
            } else {
                New-AzRoleAssignment -ObjectId $sp.Id -RoleDefinitionName 'User Access Administrator' -Scope $rootScope | Out-Null
                Write-Host "  [ok] User Access Administrator at $rootScope" -ForegroundColor Green
            }
        } catch {
            Write-Host "  [fail] $($_.Exception.Message)" -ForegroundColor Red
            Write-Host "  Manual fallback: in the Azure portal, root management group -> Access control (IAM) ->" -ForegroundColor Yellow
            Write-Host "    Add role assignment -> 'User Access Administrator' -> assign to '$DisplayName'." -ForegroundColor Yellow
        }
    }
}

# ---------------------------------------------------------------------------
# Cert PFX export (optional)
# ---------------------------------------------------------------------------

if ($ExportPfxPath) {
    Write-Host ""
    Write-Host "Exporting cert to PFX..." -ForegroundColor Cyan
    $pfxPwd = Read-Host -Prompt "PFX password (the engine host will need this to import)" -AsSecureString
    Export-PfxCertificate -Cert $cert -FilePath $ExportPfxPath -Password $pfxPwd | Out-Null
    Write-Host "  wrote $ExportPfxPath" -ForegroundColor Green
}

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

Write-Host ""
Write-Host "==========================================================================" -ForegroundColor Green
Write-Host " PIM4EntraPS Engine app registration ready" -ForegroundColor Green
Write-Host "==========================================================================" -ForegroundColor Green
Write-Host ""
Write-Host "  tenantId    : $TenantId"
Write-Host "  clientId    : $($app.AppId)"
Write-Host "  spObjectId  : $($sp.Id)"
Write-Host "  thumbprint  : $($cert.Thumbprint)"
Write-Host "  cert valid  : $($cert.NotBefore.ToString('yyyy-MM-dd')) -> $($cert.NotAfter.ToString('yyyy-MM-dd'))"
if ($ExportPfxPath) {
    Write-Host "  pfx export  : $ExportPfxPath"
}
Write-Host ""
Write-Host "Wire these into the engine launcher's LauncherConfig.custom.ps1:" -ForegroundColor Yellow
Write-Host ""
Write-Host "  `$global:AzureTenantID                                = '$TenantId'"
Write-Host "  `$global:HighPriv_Modern_ApplicationID_Azure         = '$($app.AppId)'"
Write-Host "  `$global:HighPriv_Modern_CertificateThumbprint_Azure = '$($cert.Thumbprint)'"
if ($IncludeExchange) {
    Write-Host "  `$global:HighPriv_Modern_ApplicationID_O365          = '$($app.AppId)'"
    Write-Host "  `$global:HighPriv_Modern_CertificateThumbprint_O365 = '$($cert.Thumbprint)'"
}
Write-Host ""

if (-not $GrantConsent) {
    Write-Host "Note: -GrantConsent was NOT supplied. Visit the Entra portal and click" -ForegroundColor DarkYellow
    Write-Host "      'Grant admin consent for <tenant>' on the app's API permissions page" -ForegroundColor DarkYellow
    Write-Host "      before the engine will run." -ForegroundColor DarkYellow
    Write-Host ""
}
if (-not $AzureRbac) {
    Write-Host "Note: -AzureRbac was NOT supplied. Azure RBAC PIM management will fail" -ForegroundColor DarkYellow
    Write-Host "      until the SP gets 'User Access Administrator' (or equivalent) at" -ForegroundColor DarkYellow
    Write-Host "      the management group scope you want to manage." -ForegroundColor DarkYellow
    Write-Host ""
}

[pscustomobject]@{
    TenantId        = $TenantId
    ClientId        = $app.AppId
    AppObjectId     = $app.Id
    SpObjectId      = $sp.Id
    CertThumbprint  = $cert.Thumbprint
    CertSubject     = $cert.Subject
    CertNotAfter    = $cert.NotAfter
    ExportedPfxPath = $ExportPfxPath
    GraphRolesGranted = if ($GrantConsent) { $graphRolesWanted } else { @() }
    ExchangeRoleGranted = if ($GrantConsent -and $IncludeExchange) { 'Exchange.ManageAsApp + Exchange Administrator' } else { '' }
    AzureRbacGranted = if ($AzureRbac) { 'User Access Administrator @ root MG (attempted)' } else { '' }
}
