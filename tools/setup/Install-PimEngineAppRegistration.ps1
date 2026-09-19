#requires -Version 5.1
<#
.SYNOPSIS
    Create / maintain the Entra app registration (SPN + certificate + Graph app-roles
    + Exchange ManageAsApp + Azure User Access Administrator) that the PIM4EntraPS
    *engine* uses to apply changes -- REST + certificate, NO PowerShell Graph/Az
    modules. PS 5.1-safe.

.DESCRIPTION
    The pure-REST companion to the engine. The legacy setup/Install-PimEngineAppRegistration.ps1
    drives the Microsoft.Graph PowerShell SDK; this one talks to Graph + ARM over REST
    (matching the module-free engine), so it runs on a bare PS 5.1 box with only az CLI.

    The caller authenticates ONCE as a role-assigner (Global Administrator or
    Privileged Role Administrator) via `az login`; this script borrows that az token for
    Graph + ARM. It then, idempotently:

      1. Creates (or reuses) a self-signed certificate in LocalMachine\My (default;
         -MachineStore:$false for CurrentUser\My). Reuses the newest valid
         CN=PIM4EntraPS-Engine cert (>30d, has private key) instead of minting a new
         one every run (the orphaned-cert / desync bug).
      2. Creates / updates the engine app registration with the right application
         (NOT delegated) RequiredResourceAccess + uploads the cert public key.
      3. Ensures the service principal exists.
      4. (-GrantConsent) Writes tenant-wide admin-consent appRoleAssignments for every
         requested Graph (+ Exchange) permission. The Graph list IS the engine map in
         _PimSetupShared.ps1 (Get-PimEngineSpnGraphRoles, BUG-181) -- one source, no drift.
      5. (-IncludeExchange + -GrantConsent) Activates the Exchange Administrator directory
         role for the SP THROUGH PIM, TIME-BOUND (-ExchangeAdminDuration, default PT4H), and
         reads it back (SEC-34). It is never a permanent assignment made outside PIM.
      6. (-GrantRootUserAccessAdministrator, OPT-IN) Assigns User Access Administrator at the
         ROOT management group so the engine can manage Azure RBAC PIM tenant-wide. Standing
         tier-0 in Azure, so it is no longer done by default (SEC-34); grant it at the
         narrowest scope the engine manages instead when you can.
      7. Writes the resolved tenantId / clientId / cert thumbprint into the engine
         launcher's LauncherConfig.custom.ps1 ($global:HighPriv_Modern_* contract),
         unless -NoWriteLauncherConfig. The block is REPLACED on every run, never appended
         (IMP-49 p).

.PARAMETER DisplayName
    App registration display name. Default 'PIM4EntraPS Engine'.

.PARAMETER TenantId
    Tenant to operate in. Defaults to the az-logged-in tenant.

.PARAMETER ExistingThumbprint
    Reuse a pre-issued cert (must be in the chosen store with its private key).

.PARAMETER CertSubject
    Subject DN for the generated cert. Default 'CN=PIM4EntraPS-Engine'.

.PARAMETER CertValidityYears
    Generated-cert validity window. Default 2.

.PARAMETER MachineStore
    Default ON: create/reuse the cert in Cert:\LocalMachine\My (service-account
    readable). -MachineStore:$false uses Cert:\CurrentUser\My (ad-hoc testing).

.PARAMETER GrantConsent
    Write the tenant-wide admin-consent app-role assignments. Without it you must click
    'Grant admin consent' in the portal afterwards.

.PARAMETER IncludeExchange
    Also request Exchange.ManageAsApp + (with -GrantConsent) activate the Exchange
    Administrator directory role THROUGH PIM for -ExchangeAdminDuration. It EXPIRES on its
    own: whatever the engine does in Exchange as this SPN stops working when it does, and
    re-running this script re-activates it.

.PARAMETER ExchangeAdminDuration
    ISO 8601 duration of the time-bound Exchange Administrator activation, PT15M..PT24H.
    Default PT4H (the same bound Initialize-PimMailSender.ps1 uses, IMP-31).

.PARAMETER GrantRootUserAccessAdministrator
    OPT-IN (SEC-34). Assign User Access Administrator at the ROOT management group to the
    engine SPN (or -RuntimeMiObjectId). Without it nothing is assigned in Azure, and the
    script says what the engine's Azure RBAC PIM needs.

.PARAMETER SkipAzureRbac
    Accepted for existing callers; the root-MG assignment is now opt-in
    (-GrantRootUserAccessAdministrator), so this only wins over that switch.

.PARAMETER LauncherConfigPath
    Path to the engine launcher's LauncherConfig.custom.ps1. Defaults to
    launcher/PIM-Baseline-Management-CSV/LauncherConfig.custom.ps1 under the solution.

.PARAMETER NoWriteLauncherConfig
    Do not write the resolved identity into LauncherConfig.custom.ps1.

.PARAMETER WhatIf
    Plan only -- create nothing, write nothing.

.EXAMPLE
    az login --tenant <tenant>          # as Global Admin / Privileged Role Admin
    .\Install-PimEngineAppRegistration.ps1 -GrantConsent -IncludeExchange

.NOTES
    Application permissions requested (all APPLICATION, not delegated):
      Graph: exactly the engine map in tools/setup/_PimSetupShared.ps1 ($script:PimGraphAppRoles,
             via Get-PimEngineSpnGraphRoles) -- the same set the hosted engine's managed identity
             holds. Never Mail.Send (IMP-06e).
      Exchange (-IncludeExchange): Office 365 Exchange Online Exchange.ManageAsApp
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$DisplayName = 'PIM4EntraPS Engine',
    [string]$TenantId,
    [string]$ExistingThumbprint,
    [string]$CertSubject = 'CN=PIM4EntraPS-Engine',
    [ValidateRange(1,5)][int]$CertValidityYears = 2,
    [switch]$MachineStore = $true,
    [switch]$GrantConsent,
    [switch]$IncludeExchange,
    # SEC-34: the Exchange Administrator role is activated THROUGH PIM for this long, then expires on its own.
    [string]$ExchangeAdminDuration = 'PT4H',
    # SEC-34: User Access Administrator at the ROOT management group is standing tier-0 in Azure -- OPT-IN only.
    [switch]$GrantRootUserAccessAdministrator,
    [switch]$SkipAzureRbac,
    # 🔴 §64.5 #3 -- WHICH PRINCIPAL GETS User Access Administrator AT THE ROOT MG.
    # This script creates the engine APP REGISTRATION, so it naturally assigned root-MG UAA to the
    # SPN. But in the HOSTED topology the engine runs as the container MANAGED IDENTITY, and the
    # SPN is not the runtime identity at all (§64.7 trap 1, §63.2) -- which is why internal ended up
    # with UAA on no principal that needed it. Pass the tick job's MI objectId here and it is
    # assigned to that instead. Omitted = the SPN (correct for a non-hosted/VM engine), and the
    # script then says plainly that a hosted deployment still needs the MI granted.
    [string]$RuntimeMiObjectId,
    [string]$LauncherConfigPath,
    [switch]$NoWriteLauncherConfig
)

$ErrorActionPreference = 'Stop'
$here = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
$solRoot = Split-Path -Parent (Split-Path -Parent $here)   # ...\PIM4EntraPS
. (Join-Path $here '_PimSetupShared.ps1')
. (Join-Path $here '_PimMailSenderPlan.ps1')   # IMP-31 pure cores reused for SEC-34: time-bound PIM role request + active-grant read

$graphAppId = '00000003-0000-0000-c000-000000000000'
$exoAppId   = '00000002-0000-0ff1-ce00-000000000000'   # Office 365 Exchange Online

# SEC-34: refuse a malformed or over-long Exchange Administrator window BEFORE anything is created.
if ($IncludeExchange) {
    $durCheck = Test-PimAssignmentDuration -Duration $ExchangeAdminDuration
    if (-not $durCheck.ok) { throw "Install-PimEngineAppRegistration: -ExchangeAdminDuration $($durCheck.reason)" }
}

# Graph application app-role ids (stable, public; from the shared map + the EXO role).
$graphRoleMap = Get-PimGraphAppRoleMap
# 🔴 BUG-181 -- THE LIST IS THE ENGINE MAP, NOT A COPY OF IT. This used to be a hand-kept literal that had drifted behind
# the map the managed identity is granted from: it lacked RoleManagement.ReadWrite.Directory (70.16: creating a
# role-assignable ROLE-* group needs it), plus AppRoleAssignment / Application.Read / Defender / DeviceManagementRBAC /
# the .Remove.* schedule roles -- so an engine running AS THIS SPN (the VM path, a master acting cross-tenant) was
# 403-blind where the managed identity was not, and nothing reported it. tests/Test-PimGraphRoleMap.ps1 pins this.
$graphRolesWanted = @(Get-PimEngineSpnGraphRoles)
$exoRoleValue = 'Exchange.ManageAsApp'

Show-PimSetupBanner -ScriptName 'Install-PimEngineAppRegistration' -SolutionRoot $solRoot

# --- az-borrowed Graph token (caller is GA / Privileged Role Admin via az login) ---
function Get-AzGraphToken { az account get-access-token --resource https://graph.microsoft.com --query accessToken -o tsv 2>$null }
$gtok = Get-AzGraphToken
if (-not $gtok) {
    Write-Host "Not logged in to az. Run as a role-assigner first:" -ForegroundColor Yellow
    Write-Host "  az login --tenant <tenant>     # Global Admin or Privileged Role Admin" -ForegroundColor Yellow
    throw "az login required (the script borrows the az token for Graph + ARM REST)."
}
if (-not $TenantId) { $TenantId = az account show --query tenantId -o tsv 2>$null }
$GH = @{ Authorization = "Bearer $gtok"; 'Content-Type' = 'application/json' }
function Gr { param([string]$Method='GET',[string]$Path,[object]$Body)
    $u = if ($Path -like 'http*') { $Path } else { "https://graph.microsoft.com/v1.0/$Path" }
    $a = @{ Method=$Method; Uri=$u; Headers=$GH }
    if ($null -ne $Body) { $a.Body = ($Body | ConvertTo-Json -Depth 20) }
    Invoke-RestMethod @a
}

Write-Host "  Tenant      : $TenantId"
Write-Host "  Display name: $DisplayName"
$doRootUaa = ([bool]$GrantRootUserAccessAdministrator -and -not $SkipAzureRbac)
$script:rootUaaError = ''
Write-Host "  GrantConsent: $GrantConsent   Exchange: $IncludeExchange$(if ($IncludeExchange) { " (through PIM, $ExchangeAdminDuration)" })   Root-MG UAA: $doRootUaa (opt-in)"
Write-Host ''

# --- Resolve resource SPs + app-role ids over REST -------------------------------
$graphSp = (Gr -Path "servicePrincipals?`$filter=appId eq '$graphAppId'").value | Select-Object -First 1
if (-not $graphSp) { throw "Microsoft Graph service principal not found in tenant." }
foreach ($n in $graphRolesWanted) {
    $r = $graphSp.appRoles | Where-Object { $_.value -eq $n -and ($_.allowedMemberTypes -contains 'Application') } | Select-Object -First 1
    if (-not $r) { throw "Graph app role '$n' not found / not application-assignable." }
    # SEC-18's lesson, enforced here too: a hardcoded id is NEVER trusted over the live catalog. A map id that resolves
    # to a DIFFERENT role would grant something nobody asked for (the PSTN call-records incident) -- refuse instead.
    if ($graphRoleMap.ContainsKey($n) -and "$($graphRoleMap[$n])" -ne "$($r.id)") {
        throw "Graph app role '$n': the engine map says id $($graphRoleMap[$n]) but the live catalog says $($r.id) -- REFUSING to grant a mismatched id (fix _PimSetupShared.ps1)."
    }
    $graphRoleMap[$n] = $r.id
}
$exoSp = $null; $exoRoleId = $null
if ($IncludeExchange) {
    $exoSp = (Gr -Path "servicePrincipals?`$filter=appId eq '$exoAppId'").value | Select-Object -First 1
    if (-not $exoSp) { throw "Office 365 Exchange Online SP not found (tenant may lack EXO; create the SP first)." }
    $er = $exoSp.appRoles | Where-Object { $_.value -eq $exoRoleValue -and ($_.allowedMemberTypes -contains 'Application') } | Select-Object -First 1
    if (-not $er) { throw "$exoRoleValue role not found on Exchange Online SP." }
    $exoRoleId = $er.id
}

# --- Certificate: reuse newest valid or mint self-signed -------------------------
Write-Host "Preparing certificate..." -ForegroundColor Cyan
$certStore = if ($MachineStore) { 'Cert:\LocalMachine\My' } else { 'Cert:\CurrentUser\My' }
$cert = $null
if ($ExistingThumbprint) {
    $tp = ($ExistingThumbprint -replace '\s','').ToUpperInvariant()
    $cert = Get-ChildItem $certStore -ErrorAction SilentlyContinue | Where-Object { $_.Thumbprint -eq $tp } | Select-Object -First 1
    if (-not $cert) { throw "Cert with thumbprint $ExistingThumbprint not found in $certStore." }
    Write-Host "  using existing cert: $($cert.Subject) (thumbprint $($cert.Thumbprint))" -ForegroundColor DarkGray
} else {
    $cert = Get-ChildItem $certStore -ErrorAction SilentlyContinue |
        Where-Object { $_.Subject -eq $CertSubject -and $_.NotAfter -gt (Get-Date).AddDays(30) -and $_.HasPrivateKey } |
        Sort-Object NotAfter -Descending | Select-Object -First 1
    if ($cert) {
        Write-Host "  reusing cert: $($cert.Subject) (thumbprint $($cert.Thumbprint), expires $($cert.NotAfter.ToString('yyyy-MM-dd')))" -ForegroundColor DarkGray
    } elseif ($PSCmdlet.ShouldProcess($CertSubject, "create self-signed cert in $certStore")) {
        $cert = New-SelfSignedCertificate -Subject $CertSubject -CertStoreLocation $certStore `
            -KeyExportPolicy Exportable -KeySpec Signature -KeyLength 2048 -KeyAlgorithm RSA `
            -HashAlgorithm SHA256 -NotAfter (Get-Date).AddYears($CertValidityYears)
        Write-Host "  created cert: $($cert.Subject) (thumbprint $($cert.Thumbprint), expires $($cert.NotAfter.ToString('yyyy-MM-dd')))" -ForegroundColor Green
    } else {
        Write-Host "  [WhatIf] would create a self-signed cert in $certStore ($CertSubject)" -ForegroundColor DarkYellow
    }
}
$certB64 = if ($cert) { [Convert]::ToBase64String($cert.GetRawCertData()) } else { '' }
$certThumb = if ($cert) { $cert.Thumbprint } else { '<thumbprint-pending>' }

# --- RequiredResourceAccess block ------------------------------------------------
$rra = @(
    @{ resourceAppId = $graphAppId
       resourceAccess = @($graphRolesWanted | ForEach-Object { @{ id = $graphRoleMap[$_]; type = 'Role' } }) }
)
if ($IncludeExchange) {
    $rra += @{ resourceAppId = $exoAppId; resourceAccess = @(@{ id = $exoRoleId; type = 'Role' }) }
}

# --- Create / update the app registration ----------------------------------------
Write-Host ""
Write-Host "Creating / updating app registration..." -ForegroundColor Cyan
# 🔴 FIND BY A STABLE IDENTIFIER FIRST, NOT BY DISPLAY NAME.
# A display name is MUTABLE and not unique. Renaming the app -- in the portal, or by us between
# versions -- makes this filter return nothing, so the block below CREATES A SECOND registration
# and orphans the first, credentials and consented permissions intact. Proven in two tenants on
# 2026-09-10 for the Manager registration, which had exactly this lookup.
# 🔑 identifierUris are unique per tenant and survive renames, so they are the key. The name filter
# remains only to ADOPT installs that predate this; adoption stamps the stable uri on, so each
# environment migrates itself once and can never fork again.
# 🪤 MUST CONTAIN THE TENANT ID. Entra refuses a bare 'api://pim4entraps-engine':
#     "All newly added URIs must contain a tenant verified domain, tenant id or app id"
# The tenant id is the only one of those three known before the app exists AND stable across
# renames, so it is the key. Measured on a live deploy 2026-09-10.
$tid = "$TenantId".Trim()
if (-not $tid) { $tid = "$((Gr -Path 'organization').value[0].id)".Trim() }
$stableEngineUri = "api://$tid/pim4entraps-engine"
$existing = @()
try { $existing = @((Gr -Path "applications?`$filter=identifierUris/any(u:u eq '$stableEngineUri')").value) } catch { $existing = @() }
if (@($existing).Count) {
    Write-Host "  matched on the stable identifier uri ($stableEngineUri)" -ForegroundColor DarkGray
} else {
    $existing = @((Gr -Path "applications?`$filter=displayName eq '$DisplayName'").value)
    # 🪤 Keep this refusal. More than one app of this name means a fork has ALREADY happened, and
    # picking one at random would bind the engine to whichever Graph listed first -- silently, and
    # differently on the next run.
    if (@($existing).Count -gt 1) { throw "Multiple app regs named '$DisplayName' exist. Disambiguate and re-run." }
    if (@($existing).Count) { Write-Host "  adopting by name -- stamping $stableEngineUri so this cannot recur" -ForegroundColor Yellow }
}
$app = @($existing) | Select-Object -First 1

$keyCred = $null
if ($cert) {
    $keyCred = @{
        type = 'AsymmetricX509Cert'; usage = 'Verify'; key = $certB64
        displayName = "PIM4EntraPS Engine cert ($($cert.NotBefore.ToString('yyyy-MM-dd')) -> $($cert.NotAfter.ToString('yyyy-MM-dd')))"
        startDateTime = $cert.NotBefore.ToUniversalTime().ToString('o')
        endDateTime   = $cert.NotAfter.ToUniversalTime().ToString('o')
    }
}

if ($app) {
    if ($PSCmdlet.ShouldProcess($DisplayName, "update app (appId $($app.appId))")) {
        # Stamp the stable uri on adoption -- this is the migration, and it must happen on the
        # UPDATE path or an existing install never gains it and stays forkable forever.
        # 🪤 identifierUris REPLACES the list, so merge rather than assign: another product may
        # have added one, and overwriting would take it away.
        $curIds = @($app.identifierUris) | Where-Object { "$_".Trim() }
        if (@($curIds) -notcontains $stableEngineUri) {
            $mergedIds = @(@($curIds) + @($stableEngineUri) | Sort-Object -Unique)
            try { Gr -Method PATCH -Path "applications/$($app.id)" -Body @{ identifierUris = $mergedIds } | Out-Null }
            catch { Write-Host "  could not stamp $stableEngineUri (a later deploy may not find this app by id): $($_.Exception.Message)" -ForegroundColor Yellow }
        }
        Gr -Method PATCH -Path "applications/$($app.id)" -Body @{ requiredResourceAccess = $rra } | Out-Null
        if ($keyCred) { Gr -Method PATCH -Path "applications/$($app.id)" -Body @{ keyCredentials = @($keyCred) } | Out-Null }
        $app = Gr -Path "applications/$($app.id)"
    }
    Write-Host "  updated existing app (appId $($app.appId))" -ForegroundColor Yellow
} else {
    if ($PSCmdlet.ShouldProcess($DisplayName, 'create app registration')) {
        $body = @{ displayName = $DisplayName; signInAudience = 'AzureADMyOrg'; requiredResourceAccess = $rra
                   identifierUris = @($stableEngineUri) }
        if ($keyCred) { $body.keyCredentials = @($keyCred) }
        $app = Gr -Method POST -Path 'applications' -Body $body
        Write-Host "  created app (appId $($app.appId))" -ForegroundColor Green
    } else {
        Write-Host "  [WhatIf] would create app '$DisplayName'" -ForegroundColor DarkYellow
    }
}

# Service principal
# 🪤 ENTRA READ-AFTER-WRITE, MEASURED ON A FRESH TENANT 2026-09-07. An app object created
# seconds ago is NOT yet visible to the endpoints that consume it, and this script hit that
# twice in a row on a first run:
#   1. POST servicePrincipals -> Request_BadRequest / NoBackingApplicationObject
#      "The appId '...' of the service principal does not reference a valid application object"
#   2. then every appRoleAssignment -> 404, because the SP was itself seconds old
# Each cleared by simply re-running, so the script needed THREE passes to onboard one tenant
# while exiting non-zero on the first two -- which stops any caller that treats exit codes as
# truth. This is the same class the repo already records for AUs and for a seconds-old user
# ("a bounded retry fixed it"); it was just never applied here.
function Wait-Graph {
    param([scriptblock]$Do, [string]$What, [int]$Attempts = 6, [int]$DelaySeconds = 5)
    for ($i = 1; $i -le $Attempts; $i++) {
        try { return & $Do }
        catch {
            # 🔴 THE BODY IS NOT IN Exception.Message. Invoke-RestMethod throws
            # HttpResponseException, whose Message is ONLY the status line --
            # "Response status code does not indicate success: 400 (Bad Request)." The Graph
            # error body, and therefore the string 'NoBackingApplicationObject', lands in
            # $_.ErrorDetails.Message. Reading just the exception message made the FIRST of the
            # three shapes below dead code: a 400 never matched, so the propagation failure this
            # retry exists for was never retried at all. Measured on a fresh tenant 2026-09-08.
            # 🪤 The 404 half worked by accident -- "404 (Not Found)" IS in the status line -- and
            # that is exactly why this survived its own verification: the fix was proven by
            # DELETING THE SP, which reproduces the 404 path, not the 400 path. The half that was
            # broken was the half the test could not reach. Match on both, always.
            $m = "$($_.Exception.Message) $($_.ErrorDetails.Message)"
            # Only retry the propagation shapes. A real 403/400 must fail fast and loudly --
            # retrying a permissions problem just turns a clear error into a slow one.
            $transient = ($m -match 'NoBackingApplicationObject' -or $m -match '\b404\b' -or $m -match 'Not Found' -or $m -match 'ResourceNotFound')
            if (-not $transient -or $i -eq $Attempts) { throw }
            Write-Host ("  ...{0} not visible yet ({1}/{2}) -- Entra propagation, retrying in {3}s" -f $What, $i, $Attempts, $DelaySeconds) -ForegroundColor DarkYellow
            Start-Sleep -Seconds $DelaySeconds
        }
    }
}

$sp = $null
if ($app -and $app.appId) {
    $sp = (Gr -Path "servicePrincipals?`$filter=appId eq '$($app.appId)'").value | Select-Object -First 1
    if (-not $sp -and $PSCmdlet.ShouldProcess($app.appId, 'create service principal')) {
        $sp = Wait-Graph -What "app $($app.appId)" -Do { Gr -Method POST -Path 'servicePrincipals' -Body @{ appId = $app.appId } }
        Write-Host "  created service principal (objectId $($sp.id))" -ForegroundColor Green
        # And the SP itself is now seconds old. Block until it is readable, so the consent
        # loop below does not fire ten POSTs at an object the directory cannot see yet.
        Wait-Graph -What "service principal $($sp.id)" -Do { Gr -Path "servicePrincipals/$($sp.id)" } | Out-Null
    } elseif ($sp) {
        Write-Host "  service principal present (objectId $($sp.id))" -ForegroundColor DarkGray
    }
}

# --- Admin consent (app-role assignments) ----------------------------------------
$script:grantOk   = [System.Collections.Generic.List[string]]::new()
$script:grantFail = [System.Collections.Generic.List[string]]::new()
function Grant-AppRole { param($ResourceSpId,$AppRoleId,$Label)
    try {
        # 🔴 THIS READ IS THE ONE THAT WAS NOT RETRIED, and it cost the first two grants of
        # every fresh-tenant run. On a seconds-old SP this GET is itself a 404, so the catch
        # below fired before the retried POST was ever reached: the grant was abandoned with a
        # [fail] line and NO retry, while grants 3..n succeeded because by then the SP had
        # propagated. Measured on a fresh tenant 2026-09-08 -- RoleManagement.ReadWrite.Directory
        # and Group.ReadWrite.All were the two lost, and they are exactly the two a PIM product
        # cannot run without. Retrying the POST but not the pre-check read is half a fix.
        $cur = (Wait-Graph -What "appRoleAssignments read for $Label" -Do {
                    Gr -Path "servicePrincipals/$($sp.id)/appRoleAssignments"
                }).value |
            Where-Object { $_.resourceId -eq $ResourceSpId -and $_.appRoleId -eq $AppRoleId }
        if ($cur) { Write-Host "  [skip]  $Label -- already granted" -ForegroundColor DarkGray; $script:grantOk.Add($Label); return }
        # Retried for the same propagation reason as the SP above: on a fresh tenant every one
        # of these returned 404 purely because the principal was seconds old.
        Wait-Graph -What "appRoleAssignment $Label" -Do {
            Gr -Method POST -Path "servicePrincipals/$($sp.id)/appRoleAssignments" `
                -Body @{ principalId = $sp.id; resourceId = $ResourceSpId; appRoleId = $AppRoleId }
        } | Out-Null
        Write-Host "  [ok]    $Label" -ForegroundColor Green
        $script:grantOk.Add($Label)
    } catch {
        # 🔴 RECORDED, not just printed. This [fail] used to be swallowed entirely: the script
        # still exited 0 and its summary reported GraphRolesGranted = the list it WANTED, so two
        # missing core permissions were reported as granted. The onboarding driver treats the
        # exit code as truth, so it walked straight on to the deploy phase with a
        # half-permissioned engine. Same family as BUG-130 -- a check that cannot fail is not a
        # check, and a summary that reports intent instead of outcome is worse than no summary.
        $script:grantFail.Add($Label)
        Write-Host "  [fail]  $Label : $($_.Exception.Message)" -ForegroundColor Red
    }
}
if ($GrantConsent -and $sp) {
    Write-Host ""
    Write-Host "Granting tenant-wide admin consent (app-role assignments)..." -ForegroundColor Cyan
    foreach ($n in $graphRolesWanted) { if ($PSCmdlet.ShouldProcess($n,'grant')) { Grant-AppRole -ResourceSpId $graphSp.id -AppRoleId $graphRoleMap[$n] -Label "Graph/$n" } }
    if ($IncludeExchange) { if ($PSCmdlet.ShouldProcess($exoRoleValue,'grant')) { Grant-AppRole -ResourceSpId $exoSp.id -AppRoleId $exoRoleId -Label "EXO/$exoRoleValue" } }
}

# --- Exchange Administrator directory role (with -IncludeExchange) ----------------
# 🔒 SEC-34 -- TIME-BOUND, THROUGH PIM, READ BACK. This POSTed roleManagement/directory/roleAssignments: a PERMANENT active
# assignment made OUTSIDE PIM -- exactly the pattern IMP-31 removed from Initialize-PimMailSender.ps1 after EFIF and RIDE's
# own alerting flagged it ("assigned outside of PIM") and the SPN holding it could not remove it again (Graph refuses a
# self-removal). A privileged-access product must not leave the standing privilege it exists to prevent. Now: an ACTIVE
# assignment through roleAssignmentScheduleRequests that EXPIRES by itself after -ExchangeAdminDuration, reusing IMP-31's
# pure cores (New-PimRoleScheduleRequestBody / Select-PimActiveRoleGrant), and the summary says what is held until when.
$script:exchAdmin = [ordered]@{ wanted = [bool]($IncludeExchange -and $GrantConsent); active = $false; kind = ''; endUtc = ''; error = '' }
if ($IncludeExchange -and $GrantConsent -and $sp) {
    Write-Host ""
    Write-Host "Activating 'Exchange Administrator' for the SP THROUGH PIM, time-bound ($ExchangeAdminDuration)..." -ForegroundColor Cyan
    $exchTemplate = '29232cdf-9323-42fd-ade2-1d097af3e4de'   # built-in; definition id == template id
    try {
        $roleDef = (Gr -Path "roleManagement/directory/roleDefinitions?`$filter=displayName eq 'Exchange Administrator'").value | Select-Object -First 1
        $exchRoleId = if ($roleDef) { "$($roleDef.id)" } else { $exchTemplate }
        $readGrant = {
            $inst = @((Gr -Path "roleManagement/directory/roleAssignmentScheduleInstances?`$filter=principalId eq '$($sp.id)'").value)
            Select-PimActiveRoleGrant -Instances $inst -PrincipalId "$($sp.id)" -RoleDefinitionId $exchRoleId
        }
        $st = & $readGrant
        if ($st.active -and $st.kind -eq 'permanent') {
            Write-Host "  [warn] Exchange Administrator is ALREADY active as a PERMANENT assignment (standing privilege, made outside this run)." -ForegroundColor Red
            Write-Host "         Remove it with a DIFFERENT administrator (an identity cannot remove its own directory role); re-run this to get the time-bound one." -ForegroundColor Red
        } elseif ($st.active) {
            Write-Host "  [skip] already active until $($st.endDateTime.ToString('u')) (time-bound, reused)" -ForegroundColor DarkGray
        } elseif ($PSCmdlet.ShouldProcess('Exchange Administrator', "activate through PIM for $ExchangeAdminDuration")) {
            $body = New-PimRoleScheduleRequestBody -PrincipalId "$($sp.id)" -RoleDefinitionId $exchRoleId -Duration $ExchangeAdminDuration `
                        -Justification 'PIM4EntraPS engine app registration (Install-PimEngineAppRegistration.ps1): time-bound Exchange administration'
            Wait-Graph -What 'Exchange Administrator schedule request' -Do { Gr -Method POST -Path 'roleManagement/directory/roleAssignmentScheduleRequests' -Body $body } | Out-Null
            # READ BACK -- an accepted request is not yet an active role.
            $seen = $false
            for ($i = 0; $i -lt 24 -and -not $seen; $i++) { $st = & $readGrant; if ($st.active) { $seen = $true } else { Start-Sleep -Seconds 5 } }
            if (-not $seen) { throw 'the time-bound Exchange Administrator request was accepted but the role is not active on read-back (120s)' }
            Write-Host "  [ok] Exchange Administrator active until $($st.endDateTime.ToString('u')) through PIM (read back); it then EXPIRES on its own" -ForegroundColor Green
        }
        $script:exchAdmin.active = [bool]$st.active; $script:exchAdmin.kind = "$($st.kind)"
        $script:exchAdmin.endUtc = $(if ($st.endDateTime) { $st.endDateTime.ToString('o') } else { '' })
    } catch {
        $script:exchAdmin.error = "$($_.Exception.Message) $($_.ErrorDetails.Message)".Trim()
        Write-Host "  [fail] Exchange Administrator through PIM: $($script:exchAdmin.error)" -ForegroundColor Red
    }
}

# --- Azure RBAC: User Access Administrator at root MG (OPT-IN, SEC-34) -------------
if (-not $doRootUaa) {
    Write-Host ""
    Write-Host "Azure RBAC: User Access Administrator at the ROOT management group was NOT assigned (opt-in: -GrantRootUserAccessAdministrator)." -ForegroundColor DarkYellow
    Write-Host "      It is standing tier-0 over every subscription. The engine's Azure RBAC PIM needs User Access Administrator (or" -ForegroundColor DarkYellow
    Write-Host "      Owner) on the scopes it manages -- grant it at the NARROWEST such scope to the principal that runs the engine" -ForegroundColor DarkYellow
    Write-Host "      (hosted: the tick job's managed identity, via Setup-PimContainers -AzureRbacRoles). Until then Azure RBAC PIM 403s." -ForegroundColor DarkYellow
}
if ($doRootUaa -and $sp) {
    Write-Host ""
    # 🔴 §64.5 #3 -- ASSIGN IT TO THE PRINCIPAL THAT ACTUALLY RUNS, not to whichever one this
    # script happens to have created. Hosted = the container MANAGED IDENTITY; non-hosted = the SPN.
    # Getting this wrong does not fail: the assignment lands on a principal that never calls ARM,
    # and the engine's Azure half is silently blind (BUG-51, measured as azure-scopes=0).
    $targetOid  = if ("$RuntimeMiObjectId".Trim()) { "$RuntimeMiObjectId".Trim() } else { $sp.id }
    $targetWhat = if ("$RuntimeMiObjectId".Trim()) { "the runtime managed identity ($targetOid)" } else { "the engine SPN ($($sp.id))" }
    Write-Host "Assigning 'User Access Administrator' at root management group scope to $targetWhat..." -ForegroundColor Cyan
    $rootScope = "/providers/Microsoft.Management/managementGroups/$TenantId"
    $uaaRoleId = '18d7d88d-d35e-4fb5-a5c3-7773c20a72d9'   # User Access Administrator (built-in)
    try {
        $armTok = az account get-access-token --tenant $TenantId --resource https://management.azure.com --query accessToken -o tsv 2>$null
        if (-not $armTok) { throw "no ARM token" }
        $aH = @{ Authorization = "Bearer $armTok"; 'Content-Type' = 'application/json' }
        $raId = [guid]::NewGuid().ToString()
        $uri = "https://management.azure.com$rootScope/providers/Microsoft.Authorization/roleAssignments/$raId`?api-version=2022-04-01"
        $b = @{ properties = @{ roleDefinitionId = "$rootScope/providers/Microsoft.Authorization/roleDefinitions/$uaaRoleId"; principalId = $targetOid; principalType = 'ServicePrincipal' } }
        if ($PSCmdlet.ShouldProcess($rootScope,'assign User Access Administrator')) {
            try {
                Invoke-RestMethod -Method PUT -Uri $uri -Headers $aH -Body ($b | ConvertTo-Json -Depth 10) | Out-Null
                Write-Host "  [ok] User Access Administrator at root MG -> $targetWhat" -ForegroundColor Green
                if (-not "$RuntimeMiObjectId".Trim()) {
                    # 🪤 SAY IT WHERE IT WILL BE READ. A hosted deployment's runtime identity is the
                    # container MI, and it does NOT inherit anything from the SPN -- internal ran
                    # with UAA on the SPN and an Azure-blind tick until this was found by hand.
                    Write-Host "  [note] This granted the ENGINE SPN. In a HOSTED deployment the engine runs as the" -ForegroundColor DarkYellow
                    Write-Host "         container managed identity, which needs this too and inherits NOTHING from the SPN." -ForegroundColor DarkYellow
                    Write-Host "         Setup-PimContainers.ps1 grants it (-AzureRbacRoles), or re-run this with" -ForegroundColor DarkYellow
                    Write-Host "         -RuntimeMiObjectId <tick MI objectId>." -ForegroundColor DarkYellow
                }
            } catch {
                if ("$($_.Exception.Message)" -match 'RoleAssignmentExists|already exists') { Write-Host "  [skip] already assigned" -ForegroundColor DarkGray }
                else { throw }
            }
        }
    } catch {
        $script:rootUaaError = "$($_.Exception.Message)"
        Write-Host "  [fail] $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "  Manual fallback (GA-not-owner): Azure portal -> root management group ->" -ForegroundColor Yellow
        Write-Host "    Access control (IAM) -> Add role assignment -> 'User Access Administrator' -> '$DisplayName'." -ForegroundColor Yellow
    }
}

# --- Write the identity into the engine launcher config ---------------------------
if (-not $NoWriteLauncherConfig -and $app -and $app.appId) {
    if (-not $LauncherConfigPath) {
        $LauncherConfigPath = Join-Path $solRoot 'launcher\PIM-Baseline-Management-CSV\LauncherConfig.custom.ps1'
    }
    if ($PSCmdlet.ShouldProcess($LauncherConfigPath, 'write engine identity ($global:HighPriv_Modern_*)')) {
        # (the begin/end markers are added by Update-PimLauncherIdentityBlock)
        $lines = @(
            "`$global:AzureTenantID                                = '$TenantId'",
            "`$global:HighPriv_Modern_ApplicationID_Azure         = '$($app.appId)'",
            "`$global:HighPriv_Modern_CertificateThumbprint_Azure = '$certThumb'"
        )
        if ($IncludeExchange) {
            $lines += "`$global:HighPriv_Modern_ApplicationID_O365          = '$($app.appId)'"
            $lines += "`$global:HighPriv_Modern_CertificateThumbprint_O365 = '$certThumb'"
        }
        $dir = Split-Path -Parent $LauncherConfigPath
        if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        # 🔴 IMP-49 p -- REPLACE, never append. AppendAllText added one more identity block per run (nine were found in one
        # tree) and the LAST one silently won. Every earlier block -- marked or legacy unmarked -- is removed and exactly one
        # written; everything else in the file is kept verbatim. UTF8 without BOM via .NET (PS 5.1-safe).
        $prevText = if (Test-Path -LiteralPath $LauncherConfigPath) { [System.IO.File]::ReadAllText($LauncherConfigPath) } else { '' }
        $newText = Update-PimLauncherIdentityBlock -Existing $prevText -Lines $lines
        [System.IO.File]::WriteAllText($LauncherConfigPath, $newText, (New-Object System.Text.UTF8Encoding($false)))
        Write-Host ""
        Write-Host "  wrote engine identity into $LauncherConfigPath (one block, replaced)" -ForegroundColor Green
    }
}

# --- Summary ---------------------------------------------------------------------
# 🔒 The banner reports the OUTCOME, not the intent. It used to say "ready" unconditionally,
# over a run in which app-role grants had failed. Say plainly which ones did not land -- the
# operator reads this banner, and a green word here is what stopped anyone looking further.
Write-Host ""
$privFail = @()
if ($script:exchAdmin.wanted -and $sp -and -not $WhatIfPreference -and -not $script:exchAdmin.active) { $privFail += "Exchange Administrator through PIM: $(if ($script:exchAdmin.error) { $script:exchAdmin.error } else { 'not active' })" }
if ($doRootUaa -and "$($script:rootUaaError)") { $privFail += "User Access Administrator @ root MG: $($script:rootUaaError)" }
if (($GrantConsent -and $script:grantFail.Count) -or $privFail.Count) {
    Write-Host "==========================================================================" -ForegroundColor Red
    Write-Host " PIM4EntraPS Engine app registration INCOMPLETE" -ForegroundColor Red
    Write-Host "==========================================================================" -ForegroundColor Red
    if ($GrantConsent -and $script:grantFail.Count) {
        Write-Host ("  {0} app-role grant(s) FAILED and are NOT in place:" -f $script:grantFail.Count) -ForegroundColor Red
        foreach ($f in $script:grantFail) { Write-Host "    - $f" -ForegroundColor Red }
    }
    foreach ($f in $privFail) { Write-Host "    - $f" -ForegroundColor Red }
    Write-Host "  Re-run this script: the grants are idempotent and a second pass repairs them." -ForegroundColor Yellow
} else {
    Write-Host "==========================================================================" -ForegroundColor Green
    Write-Host " PIM4EntraPS Engine app registration ready" -ForegroundColor Green
    Write-Host "==========================================================================" -ForegroundColor Green
}
Write-Host "  tenantId   : $TenantId"
Write-Host "  clientId   : $(if ($app) { $app.appId } else { '<pending (WhatIf)>' })"
Write-Host "  spObjectId : $(if ($sp) { $sp.id } else { '<pending (WhatIf)>' })"
Write-Host "  thumbprint : $certThumb"
# SEC-34 / IMP-31 -- SAY WHAT PRIVILEGE IS LEFT BEHIND, AND UNTIL WHEN.
if ($script:exchAdmin.wanted) {
    $exLine = if (-not $script:exchAdmin.active) { 'NOT active' }
              elseif ($script:exchAdmin.kind -eq 'permanent') { 'ACTIVE, PERMANENT (standing privilege outside PIM -- remove it with a DIFFERENT administrator)' }
              else { "active until $($script:exchAdmin.endUtc), then EXPIRES on its own (through PIM); re-run to renew" }
    Write-Host "  Exchange Administrator (directory role) : $exLine" -ForegroundColor $(if ($script:exchAdmin.kind -eq 'permanent') { 'Red' } else { 'Yellow' })
}
Write-Host "  User Access Administrator @ root MG     : $(if ($doRootUaa) { if ("$($script:rootUaaError)") { 'FAILED' } else { 'assigned (opt-in)' } } else { 'not assigned (opt-in, -GrantRootUserAccessAdministrator)' })"
if (-not $GrantConsent) {
    Write-Host ""
    Write-Host "Note: -GrantConsent not supplied. Grant admin consent in the Entra portal before the engine runs." -ForegroundColor DarkYellow
}
Write-Host ""

[pscustomobject]@{
    TenantId       = $TenantId
    ClientId       = if ($app) { $app.appId } else { $null }
    AppObjectId    = if ($app) { $app.id } else { $null }
    SpObjectId     = if ($sp) { $sp.id } else { $null }
    CertThumbprint = $certThumb
    CertSubject    = $CertSubject
    # OUTCOME, not intent. This was $graphRolesWanted -- the list the script MEANT to grant --
    # so a caller inspecting the returned object saw two permissions listed as granted that had
    # failed with a 404 minutes earlier. GraphRolesFailed is empty on a clean run.
    GraphRolesGranted   = if ($GrantConsent) { @($script:grantOk   | Where-Object { $_ -like 'Graph/*' } | ForEach-Object { $_ -replace '^Graph/','' }) } else { @() }
    GraphRolesFailed    = if ($GrantConsent) { @($script:grantFail | Where-Object { $_ -like 'Graph/*' } | ForEach-Object { $_ -replace '^Graph/','' }) } else { @() }
    # OUTCOME again (SEC-34): the Exchange Administrator activation's kind + end, not the words "Exchange Administrator".
    ExchangeRoleGranted = if ($script:exchAdmin.wanted -and $script:exchAdmin.active) { "Exchange.ManageAsApp + Exchange Administrator ($($script:exchAdmin.kind) until $($script:exchAdmin.endUtc))" } else { '' }
    ExchangeAdminEndUtc = "$($script:exchAdmin.endUtc)"
    AzureRbacGranted    = if ($doRootUaa -and -not "$($script:rootUaaError)") { 'User Access Administrator @ root MG (opt-in)' } else { '' }
}
