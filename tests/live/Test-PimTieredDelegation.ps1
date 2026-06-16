<#
.SYNOPSIS
  Rerunnable LIVE tiered delegation / VISIBILITY test for PIM4EntraPS.

  Provisions a small set of test-/pimlab-prefixed personas + resources in the
  internal tenant (myfamilynetwork) using the TEST subscriptions, then for each
  persona asserts that the persona's COMPUTED VISIBLE SET (produced by the REAL
  delegation-scoping engine -- the same Select-PimPortalVisibleRows /
  Test-PimPortalCanSeeGroup the Manager's /api/portal-access uses) matches the
  expectation. "L0 sees all" is proven via the SuperAdmin visibility computation,
  NOT a human login.

  Scenarios:
    1. L0 / SuperAdmin       -> visible set = ALL.
    2. L1 Intune admin       -> visible set = only the Intune (L1 workload) group.
    3. L2 Helpdesk (AU)      -> visible set = only the AU-scoped L2 Entra group.
    4. L5 single-resource    -> a test Azure resource "Integration-Uni-X" in an RG
                                in a test sub; a consultant is Contributor on it,
                                delegated to a business owner. Biz owner sees ONLY
                                that resource (+ the consultant); consultant sees
                                only that resource.
    5. Guest invite (wizard) -> invite a test account from another test tenant as
                                an external-guest admin, assert it provisions, then
                                DELETE it.
    6. Power BI              -> delegate a Power BI workspace to the biz owner.
                                BLOCKED (not failed) if no Power BI API/license.

  Auth: CERTIFICATE ONLY (engine SPN for Graph, mgmt SPN for ARM), values from
  kv-automatit-dev / internal/ENGINE-IDENTITY.md. No interactive / device-code /
  secret. Real prod admins/resources are NEVER touched. -Cleanup tears down all
  test-/pimlab- objects this script creates (and -Cleanup runs automatically at
  the end of a normal run unless -KeepObjects is passed).

.PARAMETER Domain
  KV domain key. Default 'myfamilynetwork' (the only tenant where PIM runs + this
  lab is allowed).
.PARAMETER Subs
  TEST subscription ids for Azure resources. Default = the two myfamilynetwork PIM
  lab/test subs. NEVER the primary/prod sub.
.PARAMETER GuestFromDomain
  The other test tenant a guest is invited FROM. Default 2linkit.onmicrosoft.com.
.PARAMETER Cleanup
  Remove everything and exit (idempotent; safe to run repeatedly).
.PARAMETER KeepObjects
  Do NOT auto-cleanup at the end of a run (for manual inspection).

.NOTES
  PS 5.1 compatible (engine runtime). Run in a real PowerShell process.
#>
[CmdletBinding()]
param(
    [string]$Domain = 'myfamilynetwork',
    [string[]]$Subs = @('ad2ea027-413e-4edc-bc92-cf8b9b5c9aa6', '9c220810-0cb4-486d-af7d-f2e28c19aafe'),
    [string]$GuestFromDomain = '2linkit.onmicrosoft.com',
    [string]$Prefix = 'pimlabtd',   # 'td' = tiered-delegation; distinct from the sibling 'pimlab' lab so the two never collide
    [string]$StatePath,
    [switch]$Cleanup,
    [switch]$KeepObjects
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Off
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $here) { $here = 'C:\SCRIPTS\AutomateIT\SOLUTIONS\PIM4EntraPS\tests\live' }
if (-not $StatePath) { $StatePath = Join-Path $here 'pimlab-tiered-state.json' }

. (Join-Path $here 'PimLab-CertAuth.ps1')
$shared = (Resolve-Path (Join-Path $here '..\..\engine\_shared')).Path
. (Join-Path $shared 'PIM-PortalAccess.ps1')      # the visible-set engine (Select-PimPortalVisibleRows etc.)
. (Join-Path $shared 'PIM-PermissionWizard.ps1')  # the wizard derivation (level/tier/plane)
. (Join-Path $shared 'PIM-Onboarding.ps1')        # guest-invite mode resolution + body builder

# ------------------------------------------------------------------ connection
$conn = Resolve-PimLabTenantConnection -Domain $Domain
$UpnDomain = "$Domain.onmicrosoft.com"
Write-Host "=== PIM4EntraPS tiered delegation/visibility LIVE test ===" -ForegroundColor Cyan
Write-Host ("tenant {0} | domain {1} | engine SPN {2} (cert {3})" -f $conn.TenantId, $UpnDomain, $conn.EngineClientId, $conn.EngineThumb.Substring(0,8)) -ForegroundColor DarkGray

$script:GraphTok = Get-PimLabSpnToken -TenantId $conn.TenantId -ClientId $conn.EngineClientId -CertificateThumbprint $conn.EngineThumb -Resource 'https://graph.microsoft.com'
$script:ArmTok = $null
$script:MgmtGraphTok = $null   # GA-equivalent Graph token (mgmt SPN) for deleting role-protected users
if ($conn.MgmtClientId -and $conn.MgmtThumb) {
    try { $script:ArmTok = Get-PimLabSpnToken -TenantId $conn.TenantId -ClientId $conn.MgmtClientId -CertificateThumbprint $conn.MgmtThumb -Resource 'https://management.azure.com' }
    catch { Write-Host "  ! ARM token (mgmt SPN) unavailable: $($_.Exception.Message)" -ForegroundColor DarkYellow }
    try { $script:MgmtGraphTok = Get-PimLabSpnToken -TenantId $conn.TenantId -ClientId $conn.MgmtClientId -CertificateThumbprint $conn.MgmtThumb -Resource 'https://graph.microsoft.com' }
    catch { Write-Host "  ! Mgmt Graph token unavailable: $($_.Exception.Message)" -ForegroundColor DarkYellow }
}

# ------------------------------------------------------------------ REST helpers
function Invoke-LabGraph {
    param([string]$Method, [string]$Path, $Body, [switch]$Beta)
    $base = if ($Beta) { 'https://graph.microsoft.com/beta' } else { 'https://graph.microsoft.com/v1.0' }
    $url = if ($Path -match '^https?://') { $Path } else { "$base$Path" }
    $h = @{ Authorization = "Bearer $script:GraphTok"; 'Content-Type' = 'application/json' }
    $p = @{ Method = $Method; Uri = $url; Headers = $h }
    if ($PSBoundParameters.ContainsKey('Body') -and $null -ne $Body) { $p.Body = ($Body | ConvertTo-Json -Depth 12) }
    try { Invoke-RestMethod @p }
    catch {
        $txt = $null
        if ($_.ErrorDetails -and $_.ErrorDetails.Message) { $txt = "$($_.ErrorDetails.Message)" }
        if ($txt) { throw "Graph $Method $url failed: $txt" }
        throw
    }
}
function Invoke-LabArm {
    param([string]$Method, [string]$Url, $Body)
    if (-not $script:ArmTok) { throw "ARM token unavailable (mgmt SPN cert not resolved)." }
    $h = @{ Authorization = "Bearer $script:ArmTok"; 'Content-Type' = 'application/json' }
    $p = @{ Method = $Method; Uri = $Url; Headers = $h }
    if ($PSBoundParameters.ContainsKey('Body') -and $null -ne $Body) { $p.Body = ($Body | ConvertTo-Json -Depth 12) }
    try { Invoke-RestMethod @p }
    catch {
        $txt = $null
        if ($_.ErrorDetails -and $_.ErrorDetails.Message) { $txt = "$($_.ErrorDetails.Message)" }
        if ($txt) { throw "ARM $Method $Url failed: $txt" }
        throw
    }
}
function Invoke-LabGraphRetry {
    # Graph call that tolerates directory-replication lag on freshly-created objects
    # (404 "ResourceNotFound" / 400 referencing a not-yet-replicated id). Retries a
    # few times; rethrows on the last attempt. Treats "already exists" as success.
    param([string]$Method, [string]$Path, $Body, [int]$Tries = 8)
    for ($i = 0; $i -lt $Tries; $i++) {
        try {
            if ($PSBoundParameters.ContainsKey('Body')) { return Invoke-LabGraph -Method $Method -Path $Path -Body $Body }
            return Invoke-LabGraph -Method $Method -Path $Path
        } catch {
            $m = "$_"
            if ($m -match 'already exist|references already') { return $null }
            $transient = $m -match '\(404\)|\(400\)|ResourceNotFound|does not exist|Request_ResourceNotFound'
            if ($i -eq $Tries - 1 -or -not $transient) { throw }
            Start-Sleep -Seconds 5
        }
    }
}
function Wait-LabUserReplicated {
    param([string]$Id, [int]$Tries = 8)
    for ($i = 0; $i -lt $Tries; $i++) {
        try { Invoke-LabGraph GET "/users/$Id`?`$select=id" | Out-Null; return $true } catch { Start-Sleep -Seconds 4 }
    }
    return $false
}
function Remove-LabUserWithRetry {
    # Delete a test user. A user that was ever assigned a privileged (incl. AU-scoped)
    # directory role becomes role-protected: the engine SPN's User.ReadWrite.All gets
    # 403, only a GA-equivalent can delete it. So prefer the MGMT SPN Graph token when
    # available, falling back to the engine token.
    param([string]$Id, [int]$Tries = 6)
    $tokens = @()
    if ($script:MgmtGraphTok) { $tokens += $script:MgmtGraphTok }
    $tokens += $script:GraphTok
    for ($i = 0; $i -lt $Tries; $i++) {
        foreach ($t in $tokens) {
            try {
                Invoke-RestMethod -Method DELETE -Uri "https://graph.microsoft.com/v1.0/users/$Id" -Headers @{ Authorization = "Bearer $t"; 'Content-Type' = 'application/json' } | Out-Null
                return $true
            } catch { }
        }
        if ($i -lt $Tries - 1) { Start-Sleep -Seconds 3 }
    }
    return $false
}

# ------------------------------------------------------------------ find-or-create
function Get-OrNewLabUser {
    param([string]$Upn, [string]$Display)
    $nick = ($Upn -split '@')[0]
    $found = Invoke-LabGraph GET "/users?`$filter=userPrincipalName eq '$Upn'&`$select=id,userPrincipalName"
    if ($found.value -and $found.value.Count -gt 0) { Write-Host "  = user $Upn" -ForegroundColor DarkGray; return $found.value[0] }
    $pwd = ([guid]::NewGuid().ToString('N').Substring(0, 12)) + '!Aa9'
    $u = Invoke-LabGraph POST "/users" @{
        accountEnabled = $true; displayName = $Display; mailNickname = $nick; userPrincipalName = $Upn
        passwordProfile = @{ forceChangePasswordNextSignIn = $true; password = $pwd }
    }
    Write-Host "  + user $Upn" -ForegroundColor Green
    $u
}
function Get-OrNewLabGroup {
    param([string]$Name, [string]$Desc)
    $nick = ($Name -replace '[^a-zA-Z0-9]', '')
    if ($nick.Length -gt 60) { $nick = $nick.Substring(0, 60) }   # Graph mailNickname max 64
    $found = Invoke-LabGraph GET "/groups?`$filter=displayName eq '$Name'&`$select=id,displayName"
    if ($found.value -and $found.value.Count -gt 0) { Write-Host "  = group $Name" -ForegroundColor DarkGray; return $found.value[0] }
    $g = Invoke-LabGraph POST "/groups" @{ displayName = $Name; description = $Desc; mailEnabled = $false; mailNickname = $nick; securityEnabled = $true; isAssignableToRole = $false }
    Write-Host "  + group $Name" -ForegroundColor Green
    $g
}

# ===========================================================================
# CLEANUP (also called automatically at the end of a normal run)
# ===========================================================================
function Get-LabIdValues {
    # Extract GUID-shaped id values from a state sub-collection that may be either an
    # in-memory [ordered] hashtable (end-of-run auto-cleanup) or a PSCustomObject
    # (JSON round-trip via -Cleanup). Only returns real ids, never container members.
    param($Container)
    if (-not $Container) { return @() }
    $vals = @()
    if ($Container -is [System.Collections.IDictionary]) { $vals = @($Container.Values) }
    else { $vals = @($Container.PSObject.Properties | Where-Object { $_.MemberType -eq 'NoteProperty' } | ForEach-Object { $_.Value }) }
    return @($vals | ForEach-Object { "$_" } | Where-Object { $_ -match '^[0-9a-fA-F-]{36}$' })
}
function Invoke-LabCleanup {
    param($St)
    Write-Host "`n--- CLEANUP: removing $Prefix tiered-lab objects ---" -ForegroundColor Yellow
    if (-not $St -and (Test-Path $StatePath)) { $St = Get-Content $StatePath -Raw | ConvertFrom-Json }
    # ARM: delete the lab resource group(s) (removes the Integration-Uni-X resource +
    # the Contributor role assignment on it).
    if ($script:ArmTok -and $St -and $St.arm) {
        foreach ($p in $St.arm.PSObject.Properties) {
            $rgScope = "$($p.Value.scope)".Trim()
            if (-not ($rgScope -match '^/subscriptions/')) { continue }   # skip non-scope props (empty arm after JSON round-trip)
            try { Invoke-LabArm DELETE "https://management.azure.com$rgScope`?api-version=2021-04-01" | Out-Null; Write-Host "  - RG $rgScope (delete requested)" -ForegroundColor Yellow }
            catch { Write-Host "  . RG ${rgScope}: $($_.Exception.Message.Split([char]10)[0])" -ForegroundColor DarkGray }
        }
    }
    if ($St) {
        foreach ($g in (Get-LabIdValues $St.groups)) { try { Invoke-LabGraph DELETE "/groups/$g" | Out-Null; Write-Host "  - group $g" } catch {} }
        foreach ($u in (Get-LabIdValues $St.users))  { if (Remove-LabUserWithRetry -Id $u) { Write-Host "  - user $u" } else { Write-Host "  . user $u not removed (role-protected? need GA / mgmt SPN)" -ForegroundColor DarkYellow } }
        if ($St.guestId) { if (Remove-LabUserWithRetry -Id $St.guestId) { Write-Host "  - guest $($St.guestId)" } else { Write-Host "  . guest $($St.guestId) not yet removable (replication lag)" -ForegroundColor DarkYellow } }
        if ($St.auId)   { try { Invoke-LabGraph DELETE "/directory/administrativeUnits/$($St.auId)" | Out-Null; Write-Host "  - AU $($St.auId)" } catch {} }
    }
    if (Test-Path $StatePath) { Remove-Item $StatePath -Force }
    Write-Host "Cleanup done." -ForegroundColor Yellow
}

if ($Cleanup) { Invoke-LabCleanup; return }

# ===========================================================================
# PROVISION
# ===========================================================================
$state = [ordered]@{
    createdUtc = (Get-Date).ToUniversalTime().ToString('o')
    domain = $Domain; upnDomain = $UpnDomain; subs = $Subs
    users = [ordered]@{}; groups = [ordered]@{}; arm = [ordered]@{}
}

Write-Host "`n[provision] Administrative Unit (L2 helpdesk scope)" -ForegroundColor Cyan
$auName = "$Prefix-AU-Helpdesk"
$au = (Invoke-LabGraph GET "/directory/administrativeUnits?`$filter=displayName eq '$auName'").value | Select-Object -First 1
if (-not $au) { $au = Invoke-LabGraph POST "/directory/administrativeUnits" @{ displayName = $auName; description = 'PIM tiered-lab L2 helpdesk scope'; visibility = 'HiddenMembership' }; Write-Host "  + AU $auName" -ForegroundColor Green }
else { Write-Host "  = AU $auName" -ForegroundColor DarkGray }
$state.auId = $au.id

Write-Host "`n[provision] personas" -ForegroundColor Cyan
$personas = [ordered]@{
    intuneAdmin   = @{ upn = "$Prefix-admin-intune@$UpnDomain";    name = 'PIMLAB Admin - Intune (L1)' }
    helpdeskL2    = @{ upn = "$Prefix-admin-helpdesk@$UpnDomain";   name = 'PIMLAB Helpdesk Manager (L2, AU-scoped)' }
    bizOwner      = @{ upn = "$Prefix-owner-integration@$UpnDomain"; name = 'PIMLAB Business Owner - Integration' }
    consultant    = @{ upn = "$Prefix-consultant-uni@$UpnDomain";   name = 'PIMLAB Consultant - Integration-Uni-X' }
}
foreach ($k in $personas.Keys) { $u = Get-OrNewLabUser -Upn $personas[$k].upn -Display $personas[$k].name; $state.users[$k] = $u.id }

Write-Host "`n[provision] PIM delegation groups (engine naming grammar)" -ForegroundColor Cyan
# Group names carry the $Prefix as the {Name} segment so they are unique to THIS
# test and can never collide with real PIM-* groups in the tenant.
$tag = ($Prefix -replace '[^a-zA-Z0-9]', '')
# L1 Intune workload group (Intune = 'workload' service axis; wizard default tier1/L1-ish).
$gIntune = Get-OrNewLabGroup -Name "PIM-Intune-$tag-IntuneAdministrator-L1-T1-WDP-ID" -Desc 'Intune administrator (L1 workload) - tiered-delegation test'
# L2 AU-scoped Entra helpdesk/user-admin group.
$gHelp   = Get-OrNewLabGroup -Name "PIM-Entra-$tag-UserAdministrator-AU-$($au.id)-L2-T2-CP-ID" -Desc 'User Administrator, AU-scoped (L2) - tiered-delegation test'
# L5 single-resource Azure group: Contributor on the Integration-Uni-X resource (resource scope -> level 3).
$gAzRes  = Get-OrNewLabGroup -Name "PIM-Azure-$tag-IntegrationUniX-Contributor-L3-T1-WDP-RES" -Desc 'Contributor on Integration-Uni-X resource (single-resource delegation) - tiered-delegation test'
$state.groups.intune   = $gIntune.id
$state.groups.helpdesk = $gHelp.id
$state.groups.azres    = $gAzRes.id

Write-Host "`n[provision] AU membership + AU-scoped User Administrator" -ForegroundColor Cyan
# The L2 delegation is the user's AU-scoped role (below); the helpdesk user is the
# AU member so the scope is non-empty. (Groups can also be AU members in some
# tenants but are not required for the scoped-role grant.)
[void](Wait-LabUserReplicated -Id $state.users.helpdeskL2)
foreach ($mid in @($state.users.helpdeskL2)) {
    try { Invoke-LabGraphRetry POST "/directory/administrativeUnits/$($au.id)/members/`$ref" @{ '@odata.id' = "https://graph.microsoft.com/v1.0/directoryObjects/$mid" } | Out-Null }
    catch { Write-Host "    (au member: $($_.Exception.Message.Split([char]10)[0]))" -ForegroundColor DarkYellow }
}
# User Administrator roleTemplateId
$userAdminTemplate = 'fe930be7-5e62-47db-91af-98c3a49a38b1'
$role = (Invoke-LabGraph GET "/directoryRoles?`$filter=roleTemplateId eq '$userAdminTemplate'").value | Select-Object -First 1
if (-not $role) { $role = Invoke-LabGraph POST "/directoryRoles" @{ roleTemplateId = $userAdminTemplate }; Write-Host "  + activated User Administrator role" -ForegroundColor Green }
$scoped = (Invoke-LabGraph GET "/directory/administrativeUnits/$($au.id)/scopedRoleMembers").value
$already = $scoped | Where-Object { $_.roleId -eq $role.id -and $_.roleMemberInfo.id -eq $state.users.helpdeskL2 }
if (-not $already) {
    try { Invoke-LabGraphRetry POST "/directory/administrativeUnits/$($au.id)/scopedRoleMembers" @{ roleId = $role.id; roleMemberInfo = @{ id = $state.users.helpdeskL2 } } | Out-Null; Write-Host "  + helpdesk scoped as User Administrator over AU" -ForegroundColor Green }
    catch { Write-Host "    (scoped role: $($_.Exception.Message.Split([char]10)[0]))" -ForegroundColor DarkYellow }
} else { Write-Host "  = scoped role present" -ForegroundColor DarkGray }

# ---- Azure: Integration-Uni-X resource + Contributor delegation -----------
Write-Host "`n[provision] Azure resource 'Integration-Uni-X' + Contributor delegation" -ForegroundColor Cyan
$azSub = $Subs[0]
$rgName = "rg-$Prefix-integration"
$resName = "Integration-Uni-X"
$resScope = $null
if ($script:ArmTok) {
    try {
        # Ensure the Microsoft.Network RP is registered on the lab sub (registration is
        # free; only needed once). Wait briefly for it to flip to Registered.
        try {
            $rp = Invoke-LabArm GET "https://management.azure.com/subscriptions/$azSub/providers/Microsoft.Network?api-version=2021-04-01"
            if ("$($rp.registrationState)" -ne 'Registered') {
                Invoke-LabArm POST "https://management.azure.com/subscriptions/$azSub/providers/Microsoft.Network/register?api-version=2021-04-01" | Out-Null
                for ($w = 0; $w -lt 20; $w++) {
                    Start-Sleep -Seconds 6
                    $rp = Invoke-LabArm GET "https://management.azure.com/subscriptions/$azSub/providers/Microsoft.Network?api-version=2021-04-01"
                    if ("$($rp.registrationState)" -eq 'Registered') { break }
                }
                Write-Host "  . Microsoft.Network registrationState=$($rp.registrationState)" -ForegroundColor DarkGray
            }
        } catch { Write-Host "  . RP register check: $($_.Exception.Message.Split([char]10)[0])" -ForegroundColor DarkGray }

        $rgScope = "/subscriptions/$azSub/resourceGroups/$rgName"
        Invoke-LabArm PUT "https://management.azure.com$rgScope`?api-version=2021-04-01" @{ location = 'westeurope' } | Out-Null
        # A real, license-free resource to represent the single "service": a Network
        # Security Group (no compute cost, role-assignable at resource scope).
        $candidateScope = "$rgScope/providers/Microsoft.Network/networkSecurityGroups/$resName"
        Invoke-LabArm PUT "https://management.azure.com$candidateScope`?api-version=2023-09-01" @{ location = 'westeurope'; properties = @{} } | Out-Null
        $resScope = $candidateScope
        Write-Host "  + resource $resName in $rgName (sub $azSub)" -ForegroundColor Green
        # Contributor role definition id (built-in, well-known GUID).
        $contributorRoleId = "/subscriptions/$azSub/providers/Microsoft.Authorization/roleDefinitions/b24988ac-6180-42a0-ab88-20f7382dd24c"
        # Delegate Contributor on the RESOURCE to the AzRes PIM group (group-centric delegation).
        $raId = [guid]::NewGuid().ToString()
        $raDone = $false
        for ($ra = 0; $ra -lt 6 -and -not $raDone; $ra++) {
            try {
                Invoke-LabArm PUT "https://management.azure.com$resScope/providers/Microsoft.Authorization/roleAssignments/$raId`?api-version=2022-04-01" @{
                    properties = @{ roleDefinitionId = $contributorRoleId; principalId = $state.groups.azres; principalType = 'Group' }
                } | Out-Null
                Write-Host "  + Contributor on $resName -> AzRes PIM group" -ForegroundColor Green; $raDone = $true
            } catch {
                if ("$_" -match 'RoleAssignmentExists') { Write-Host "  = role assignment present" -ForegroundColor DarkGray; $raDone = $true }
                elseif ("$_" -match 'PrincipalNotFound|does not exist in the directory') { Start-Sleep -Seconds 8 }
                else { Write-Host "  ! role assignment: $($_.Exception.Message.Split([char]10)[0])" -ForegroundColor DarkYellow; break }
            }
        }
        $state.arm[$azSub] = @{ rg = $rgName; scope = $rgScope; resourceScope = $resScope; resource = $resName; delegatedGroup = $state.groups.azres; role = 'Contributor' }
    } catch {
        Write-Host "  ! Azure provisioning failed: $($_.Exception.Message.Split([char]10)[0])" -ForegroundColor Red
    }
} else {
    Write-Host "  ! ARM token unavailable -> Azure resource scenario will be BLOCKED" -ForegroundColor DarkYellow
}

# ---- Guest invite from another test tenant (scenario 5) -------------------
Write-Host "`n[provision] Guest invite (external admin from $GuestFromDomain)" -ForegroundColor Cyan
$guestEmail = "$Prefix.extguest@$GuestFromDomain"
$mode = Resolve-PimOnboardingMode -External $true -Cloud $true   # engine decides: external+cloud -> guest-invite
Write-Host ("  wizard mode: {0} ({1})" -f $mode.mode, $mode.reason) -ForegroundColor DarkGray
$guestProvisioned = $false
if ($mode.mode -eq 'guest-invite') {
    $body = New-PimGuestInvitationBody -Email $guestEmail -DisplayName 'PIMLAB External Guest Admin' -RedirectUrl 'https://myapps.microsoft.com'
    $body.sendInvitationMessage = $false
    try {
        $inv = Invoke-LabGraph POST "/invitations" $body
        $state.guestId = $inv.invitedUser.id
        $guestProvisioned = $true
        Write-Host "  + guest invited $guestEmail (id $($inv.invitedUser.id))" -ForegroundColor Green
    } catch { Write-Host "  ! guest invite failed: $($_.Exception.Message.Split([char]10)[0])" -ForegroundColor Red }
}

# save state early so a crash still leaves a cleanup-able record
$state | ConvertTo-Json -Depth 12 | Set-Content -Path $StatePath -Encoding UTF8

# ===========================================================================
# COMPUTE VISIBLE SETS via the REAL engine + ASSERT
# ===========================================================================
$script:pass = 0; $script:fail = 0; $script:blocked = 0
$script:results = [ordered]@{}
function Assert([string]$name, [bool]$cond, [string]$detail) {
    if ($cond) { $script:pass++; Write-Host ("  PASS  {0}" -f $name) -ForegroundColor Green }
    else { $script:fail++; Write-Host ("  FAIL  {0}  {1}" -f $name, $detail) -ForegroundColor Red }
}
function Mark([string]$scenario, [string]$status, [string]$evidence) {
    $script:results[$scenario] = @{ status = $status; evidence = $evidence }
    if ($status -eq 'BLOCKED') { $script:blocked++ }
}

# Definition ROWS the engine sees (mirror the live groups). Each row's facets are
# parsed by the SAME Get-PimGroupFacets the Manager uses.
$rowIntune = [pscustomobject]@{ GroupName = $gIntune.displayName; GroupTag = 'intune-l1';   Workload = 'Intune' }
$rowHelp   = [pscustomobject]@{ GroupName = $gHelp.displayName;   GroupTag = 'helpdesk-l2'; Workload = 'Entra-ID'; AdministrativeUnitTag = $au.id }
$rowAz     = [pscustomobject]@{ GroupName = $gAzRes.displayName;  GroupTag = 'azres-l3';    Workload = 'Azure'; PermissionScope = $resScope }
# A handful of OTHER groups that must stay INVISIBLE to scoped personas.
$rowGA     = [pscustomobject]@{ GroupName = 'PIM-Entra-GlobalAdmin-L0-T0-CP-ID'; GroupTag = 'ga-l0'; Workload = 'Entra-ID' }
$rowAzOther= [pscustomobject]@{ GroupName = 'PIM-Azure-Other-Owner-L1-T1-WDP-RES'; GroupTag = 'azother'; Workload = 'Azure'; PermissionScope = "/subscriptions/$($Subs[1])/resourceGroups/rg-unrelated" }
$allRows = @($rowIntune, $rowHelp, $rowAz, $rowGA, $rowAzOther)

# Persona portal profiles (delegated GUI managers) -- what each persona is entitled to.
$profIntune = [pscustomobject]@{ identity = $personas.intuneAdmin.upn; services = @('workload'); tierMax = 1; levelMax = 1; capabilities = @('manage-indirect') }
$profHelp   = [pscustomobject]@{ identity = $personas.helpdeskL2.upn;  services = @('entra');    tierMax = 2; levelMax = 2; capabilities = @('manage-indirect') }
$profBiz    = [pscustomobject]@{ identity = $personas.bizOwner.upn;    services = @('azure');    tierMax = 1; levelMax = 3; scopes = @($resScope); capabilities = @('manage-indirect','assign-admin','enable-consultants','approve-assignment'); managedAdmins = @($personas.consultant.upn) }
$profConsult= [pscustomobject]@{ identity = $personas.consultant.upn;  services = @('azure');    tierMax = 1; levelMax = 3; scopes = @($resScope); capabilities = @('manage-indirect') }

function Get-VisibleNames {
    param($Profile, [switch]$Super)
    @(Select-PimPortalVisibleRows -Profile $Profile -Rows $allRows -IsSuperAdmin:$Super | ForEach-Object { $_.GroupName })
}

# ----- Scenario 1: L0 / SuperAdmin sees ALL --------------------------------
Write-Host "`n[1] L0 / SuperAdmin -> visible set = ALL" -ForegroundColor Cyan
$visSuper = Get-VisibleNames -Profile $null -Super
$expSuper = @($allRows | ForEach-Object { $_.GroupName })
$ok1 = ($visSuper.Count -eq $expSuper.Count) -and (@($expSuper | Where-Object { $visSuper -notcontains $_ }).Count -eq 0)
Assert "L0/SuperAdmin visible set = ALL ($($visSuper.Count)/$($expSuper.Count))" $ok1 "got: $($visSuper -join ', ')"
Mark 'L0/SuperAdmin' ($(if ($ok1) { 'PASS' } else { 'FAIL' })) ("visible={$($visSuper -join ', ')} expected=ALL($($expSuper.Count))")

# ----- Scenario 2: L1 Intune admin -> only the Intune group ----------------
Write-Host "`n[2] L1 Intune admin -> visible set = only Intune (L1) resources" -ForegroundColor Cyan
$visIntune = Get-VisibleNames -Profile $profIntune
$ok2 = ($visIntune.Count -eq 1) -and ($visIntune -contains $gIntune.displayName)
Assert "Intune admin sees ONLY the Intune L1 group" $ok2 "got: $($visIntune -join ', ')"
Assert "Intune admin does NOT see Entra/Azure/GA groups" (($visIntune -notcontains $gHelp.displayName) -and ($visIntune -notcontains $gAzRes.displayName) -and ($visIntune -notcontains 'PIM-Entra-GlobalAdmin-L0-T0-CP-ID')) ""
Mark 'L1 Intune admin' ($(if ($ok2) { 'PASS' } else { 'FAIL' })) ("visible={$($visIntune -join ', ')} expected={$($gIntune.displayName)}")

# ----- Scenario 3: L2 Helpdesk (AU-scoped) -> only the L2 AU group ----------
Write-Host "`n[3] L2 Helpdesk (AU-scoped) -> visible set = only that AU's L2 resources" -ForegroundColor Cyan
$visHelp = Get-VisibleNames -Profile $profHelp
$ok3 = ($visHelp.Count -eq 1) -and ($visHelp -contains $gHelp.displayName)
Assert "Helpdesk L2 sees ONLY the AU-scoped L2 Entra group" $ok3 "got: $($visHelp -join ', ')"
Assert "Helpdesk L2 does NOT see T0/L0 Global Admin" ($visHelp -notcontains 'PIM-Entra-GlobalAdmin-L0-T0-CP-ID') ""
Assert "Helpdesk L2 does NOT see Intune/Azure (service gate)" (($visHelp -notcontains $gIntune.displayName) -and ($visHelp -notcontains $gAzRes.displayName)) ""
# AU binding is real: the group's facet carries the live AU id.
$fHelp = Get-PimGroupFacets -Row $rowHelp
Assert "Helpdesk L2 group facet carries the live AU id" ("$($fHelp.au)" -eq "$($au.id)") "au facet=$($fHelp.au)"
Mark 'L2 Helpdesk (AU)' ($(if ($ok3) { 'PASS' } else { 'FAIL' })) ("visible={$($visHelp -join ', ')} expected={$($gHelp.displayName)} au=$($fHelp.au)")

# ----- Scenario 4: L5 single-resource (biz owner + consultant) -------------
Write-Host "`n[4] L5 single-resource: biz owner + consultant see ONLY Integration-Uni-X" -ForegroundColor Cyan
if (-not $resScope) {
    Assert "L5 single-resource provisioned" $false "ARM unavailable -> resource not created"
    Mark 'L5 single-resource' 'BLOCKED' 'ARM token unavailable; Integration-Uni-X resource not provisioned'
} else {
    $visBiz = Get-VisibleNames -Profile $profBiz
    $visCon = Get-VisibleNames -Profile $profConsult
    $ok4a = ($visBiz.Count -eq 1) -and ($visBiz -contains $gAzRes.displayName)
    $ok4b = ($visCon.Count -eq 1) -and ($visCon -contains $gAzRes.displayName)
    Assert "biz owner sees ONLY Integration-Uni-X resource group" $ok4a "got: $($visBiz -join ', ')"
    Assert "biz owner does NOT see the unrelated Azure RG (scope gate)" ($visBiz -notcontains 'PIM-Azure-Other-Owner-L1-T1-WDP-RES') ""
    # biz owner manages the consultant (and ONLY that consultant)
    $ok4c = (Test-PimPortalCanEnableConsultant -Profile $profBiz -AdminName $personas.consultant.upn) -and (Test-PimPortalCanAssignAdmin -Profile $profBiz -AdminName $personas.consultant.upn)
    $ok4d = -not (Test-PimPortalCanAssignAdmin -Profile $profBiz -AdminName 'someone-else@contoso.example')
    Assert "biz owner can manage the consultant (enable + assign)" $ok4c ""
    Assert "biz owner canNOT manage a NON-managed admin" $ok4d ""
    Assert "consultant sees ONLY Integration-Uni-X resource" $ok4b "got: $($visCon -join ', ')"
    Assert "consultant does NOT see the unrelated Azure RG" ($visCon -notcontains 'PIM-Azure-Other-Owner-L1-T1-WDP-RES') ""
    $st4 = if ($ok4a -and $ok4b -and $ok4c -and $ok4d) { 'PASS' } else { 'FAIL' }
    Mark 'L5 single-resource' $st4 ("biz_visible={$($visBiz -join ', ')} consultant_visible={$($visCon -join ', ')} resource=$resName managesConsultant=$ok4c")
}

# ----- Scenario 5: Guest invite via the admin wizard -----------------------
Write-Host "`n[5] Guest invite via the wizard -> provisions, then DELETE" -ForegroundColor Cyan
if ($guestProvisioned -and $state.guestId) {
    $g = $null
    try { $g = Invoke-LabGraph GET "/users/$($state.guestId)?`$select=id,userType,userPrincipalName,externalUserState" } catch {}
    $ok5 = ($g -and "$($g.userType)" -eq 'Guest')
    Assert "guest provisioned as userType=Guest" $ok5 "userType=$($g.userType)"
    # Now DELETE it (cleanup of this scenario specifically) + verify gone.
    $deleted = Remove-LabUserWithRetry -Id $state.guestId
    Assert "guest deleted (cleanup)" $deleted ""
    if ($deleted) { $state.Remove('guestId') | Out-Null; $state | ConvertTo-Json -Depth 12 | Set-Content -Path $StatePath -Encoding UTF8 }
    Mark 'Guest invite (wizard)' ($(if ($ok5 -and $deleted) { 'PASS' } else { 'FAIL' })) ("userType=$($g.userType); deleted=$deleted")
} else {
    Assert "guest invite provisioned" $false "invitation did not return an invited user"
    Mark 'Guest invite (wizard)' 'FAIL' 'invitation not provisioned'
}

# ----- Scenario 6: Power BI workspace delegation ---------------------------
Write-Host "`n[6] Power BI workspace delegation to the biz owner" -ForegroundColor Cyan
# Attempt the REAL delegation: create a workspace, add the biz owner as Member, then
# clean it up. PASS only if the delegation actually applied; BLOCKED (never FAIL) if
# the engine SPN lacks a Power BI tenant role / Power BI Pro license in the lab.
$pbiTok = $null
try { $pbiTok = Get-PimLabSpnToken -TenantId $conn.TenantId -ClientId $conn.EngineClientId -CertificateThumbprint $conn.EngineThumb -Resource 'https://analysis.windows.net/powerbi/api' } catch {}
$pbiBlockReason = $null
$pbiApplied = $false
if (-not $pbiTok) {
    $pbiBlockReason = 'no Power BI token for the engine SPN (no Power BI service principal access enabled)'
} else {
    $PH = @{ Authorization = "Bearer $pbiTok"; 'Content-Type' = 'application/json' }
    $wsName = "$Prefix-Workspace-Integration"
    $wsId = $null
    try {
        $created = Invoke-RestMethod -Method POST -Uri 'https://api.powerbi.com/v1.0/myorg/groups?workspaceV2=true' -Headers $PH -Body (@{ name = $wsName } | ConvertTo-Json)
        $wsId = $created.id
    } catch {
        $em = "$_"; if ($_.ErrorDetails.Message) { $em = "$($_.ErrorDetails.Message)" }
        $pbiBlockReason = "workspace create refused: " + ($em -replace '\s+', ' ').Trim()
    }
    if ($wsId) {
        try {
            # Delegate: add the business owner as a workspace Member (the "delegation applies" proof).
            Invoke-RestMethod -Method POST -Uri "https://api.powerbi.com/v1.0/myorg/groups/$wsId/users" -Headers $PH -Body (@{ identifier = $personas.bizOwner.upn; principalType = 'User'; groupUserAccessRight = 'Member' } | ConvertTo-Json) | Out-Null
            $users = Invoke-RestMethod -Method GET -Uri "https://api.powerbi.com/v1.0/myorg/groups/$wsId/users" -Headers $PH
            $pbiApplied = [bool](@($users.value | Where-Object { "$($_.identifier)".ToLowerInvariant() -eq $personas.bizOwner.upn.ToLowerInvariant() }).Count -ge 1)
        } catch {
            $em = "$_"; if ($_.ErrorDetails.Message) { $em = "$($_.ErrorDetails.Message)" }
            $pbiBlockReason = "user delegation refused: " + ($em -replace '\s+', ' ').Trim()
        }
        # cleanup the workspace regardless
        try { Invoke-RestMethod -Method DELETE -Uri "https://api.powerbi.com/v1.0/myorg/groups/$wsId" -Headers $PH | Out-Null } catch {}
    }
}
if ($pbiApplied) {
    Mark 'Power BI' 'PASS' "workspace created + biz owner delegated as Member, then cleaned up"
    Assert "Power BI workspace delegation applied to the biz owner" $true ""
} else {
    Write-Host "  BLOCKED: $pbiBlockReason" -ForegroundColor DarkYellow
    Mark 'Power BI' 'BLOCKED' ("Power BI delegation could not be exercised in this lab -- " + $pbiBlockReason)
}

# ===========================================================================
# RESULT + auto-cleanup
# ===========================================================================
Write-Host "`n=== SCENARIO SUMMARY ===" -ForegroundColor Cyan
foreach ($k in $script:results.Keys) {
    $r = $script:results[$k]
    $c = switch ($r.status) { 'PASS' { 'Green' } 'BLOCKED' { 'DarkYellow' } default { 'Red' } }
    Write-Host ("  [{0,-7}] {1}" -f $r.status, $k) -ForegroundColor $c
    Write-Host ("           {0}" -f $r.evidence) -ForegroundColor DarkGray
}
Write-Host ("`n=== RESULT: {0} passed, {1} failed, {2} scenario(s) blocked ===" -f $script:pass, $script:fail, $script:blocked) -ForegroundColor ($(if ($script:fail) { 'Red' } else { 'Green' }))

if (-not $KeepObjects) { Invoke-LabCleanup -St $state }
else { Write-Host "`n(-KeepObjects: objects left in place; run with -Cleanup to remove)" -ForegroundColor DarkYellow }

if ($script:fail) { exit 1 }
