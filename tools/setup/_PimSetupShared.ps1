#requires -Version 5.1
<#
.SYNOPSIS
    Shared helpers for the PIM4EntraPS setup/deploy family (container / VM / MSP /
    engine app-registration).

.DESCRIPTION
    Dot-source this from any Setup-Pim*.ps1 / Install-Pim*.ps1 script. It provides:

      * Show-PimSetupBanner       -- SI-parity deploy banner (PowerShell + .NET +
                                     az CLI + Graph SDK versions printed up front).
      * Get-PimSetupSolutionVersion -- the VERSION file value.
      * Assert-PimSetupRegion     -- region guard: West Europe / Denmark East /
                                     Sweden Central only; France is explicitly
                                     refused (data-residency).
      * Grant-PimMiSql            -- create/refresh a contained SQL DB user for a
                                     managed-identity/app appId (SID-from-appId,
                                     TYPE=E). MI-only, no SQL login.
      * Grant-PimMiGraph          -- assign the directory app-roles the engine needs
                                     to an MI/SPN object (idempotent).
      * Set-PimSqlNoAutoPause     -- assert/disable Azure SQL serverless auto-pause
                                     (persistent compute, REQUIREMENTS S5).
      * Get-PimGsaPrivateLinkGuidance / Show-PimGsaPrivateLinkGuidance --
                                     the GSA / Private Access + private-link/DNS
                                     advice (which zones to add) printed at the end
                                     of a deploy.
      * Write-PimDnsRecord        -- register the Manager FQDN -> env static IP on an
                                     AD DNS server (extracted from Setup-PimContainers).
      * Set-PimVnetPeering        -- BUG-49: peer the PIM spoke VNet to the hub, BOTH
                                     directions, and verify both read Connected.
      * Set-PimPrivateDnsZone     -- BUG-49: publish the ACA env default domain to the
                                     env static IP in an Azure Private DNS zone and link
                                     it to the VNets that must resolve it.
      * Grant-PimMiAzureRbac      -- BUG-51: grant a workload identity its ARM role
                                     (Reader by default) so PIM's Azure half is not blind.
      * Resolve-PimAcrImageDigest -- BUG-40: resolve a mutable tag to the immutable
                                     digest it points at, so a deploy writes content,
                                     not a pointer. Pairs with the pure reference
                                     helpers in engine/_shared/PIM-ImageRef.ps1.

    Everything is REST / az-CLI based and PS 5.1-safe (no ?./??, no
    RSA.ImportFromPem, no PS7-only members). No real tenant/subscription/customer
    values are baked in -- callers pass them.
#>

# The PURE image-reference helpers (Test-PimImageDigest / New-PimImageReference /
# Test-PimImageDeployed). Kept in engine/_shared because the deploy scripts, the update
# scripts and the offline tests all need the same definition of "is the running image the
# one we deployed" -- and that question must have exactly one answer.
. (Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'engine\_shared\PIM-ImageRef.ps1')

# The PURE reachability planners (peering pairs / private-DNS record set / ARM role
# assignments). Same reason as above: the deploy scripts and the offline tests must share
# one definition of "what makes a deployed environment reachable and Azure-sighted".
. (Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'engine\_shared\PIM-Reachability.ps1')

# The guarded `az` shadow. Every script that dot-sources this file is az-driven, so the guard
# belongs here rather than in each of them: az writes ordinary WARNINGS to stderr, and under
# $ErrorActionPreference='Stop' PowerShell 5.1 makes any such write terminating. See _PimAz.ps1.
# 🪤 A script that calls az BEFORE dot-sourcing this file is not covered -- Update-PimContainers,
# Invoke-PimUpdate and Build-PimManagerImage therefore load _PimAz.ps1 themselves, at the top.
. (Join-Path $PSScriptRoot '_PimAz.ps1')

# Region allow-list. EU-only hosting. France is REFUSED (data-residency).
# swedencentral added 2026-08-09 (operator decision): the 28-tenant test estate is provisioned
# there because a FRESH subscription refuses new resources in westeurope/northeurope -- see
# New-PimHostingPrerequisites.ps1's -Location default. Until that was allowed here, step 3 built
# the estate in a region Setup-PimContainers then threw on, so the container steps could never
# run against what the estate actually is. Sweden Central is EU; the explicit denial is France.
$script:PimAllowedRegions = @('westeurope','denmarkeast','swedencentral')
$script:PimDeniedRegions  = @('francecentral','francesouth')

function Get-PimSetupSolutionVersion {
    [CmdletBinding()] param([string]$SolutionRoot)
    if (-not $SolutionRoot) {
        $here = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
        $SolutionRoot = Split-Path -Parent (Split-Path -Parent $here)   # ...\PIM4EntraPS
    }
    $vf = Join-Path $SolutionRoot 'VERSION'
    if (Test-Path -LiteralPath $vf) { return ((Get-Content -LiteralPath $vf -Raw).Trim()) }
    return 'unknown'
}

function Show-PimSetupBanner {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ScriptName,
        [string]$SolutionRoot,
        [string[]]$GraphModules,
        [string[]]$AzModules
    )
    $ver = Get-PimSetupSolutionVersion -SolutionRoot $SolutionRoot
    Write-Host ''
    Write-Host "==========================================================================" -ForegroundColor Cyan
    Write-Host " $ScriptName -- PIM4EntraPS $ver" -ForegroundColor Cyan
    Write-Host "==========================================================================" -ForegroundColor Cyan
    Write-Host ("  PowerShell : {0} ({1})" -f $PSVersionTable.PSVersion, $PSVersionTable.PSEdition) -ForegroundColor Cyan
    $dotnet = try { [System.Runtime.InteropServices.RuntimeInformation]::FrameworkDescription } catch { [System.Environment]::Version.ToString() }
    Write-Host ("  .NET       : {0}" -f $dotnet) -ForegroundColor Cyan
    $azv = $null
    try {
        $azJson = az version -o json 2>$null | ConvertFrom-Json
        if ($azJson) { $azv = $azJson.'azure-cli' }
    } catch {}
    Write-Host ("  az CLI     : {0}" -f $(if ($azv) { "v$azv" } else { 'not found (install Azure CLI)' })) -ForegroundColor Cyan
    foreach ($m in @($GraphModules | Where-Object { $_ })) {
        $mod = Get-Module -ListAvailable -Name $m -ErrorAction SilentlyContinue | Sort-Object Version -Descending | Select-Object -First 1
        Write-Host ("  {0,-10}: {1}" -f $m, $(if ($mod) { "v$($mod.Version)" } else { 'not installed' })) -ForegroundColor Cyan
    }
    foreach ($m in @($AzModules | Where-Object { $_ })) {
        $mod = Get-Module -ListAvailable -Name $m -ErrorAction SilentlyContinue | Sort-Object Version -Descending | Select-Object -First 1
        Write-Host ("  {0,-10}: {1}" -f $m, $(if ($mod) { "v$($mod.Version)" } else { 'not installed' })) -ForegroundColor Cyan
    }
    Write-Host ''
}

function Assert-PimSetupRegion {
    [CmdletBinding()] param([Parameter(Mandatory)][string]$Location)
    $norm = ($Location -replace '\s','').ToLowerInvariant()
    if ($norm -in $script:PimDeniedRegions) {
        throw "Region '$Location' is not allowed for PIM hosting (data residency). Use West Europe ('westeurope'), Denmark East ('denmarkeast') or Sweden Central ('swedencentral') -- never France."
    }
    if ($norm -notin $script:PimAllowedRegions) {
        throw "Region '$Location' is not an approved PIM hosting region. Approved: $($script:PimAllowedRegions -join ', '). (France is explicitly disallowed.)"
    }
    return $norm
}

function ConvertTo-PimSqlSidFromAppId {
    [CmdletBinding()] param([Parameter(Mandatory)][string]$AppId)
    $g = [guid]$AppId
    return '0x' + (($g.ToByteArray() | ForEach-Object { $_.ToString('X2') }) -join '')
}

function Grant-PimMiSql {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$DbUserName,
        [Parameter(Mandatory)][string]$MiAppId,
        [Parameter(Mandatory)][string]$SqlServerFqdn,
        [Parameter(Mandatory)][string]$SqlDatabase,
        [Parameter(Mandatory)][string]$TenantId,
        [string]$SqlAdminClientId,
        # ONE of these. Secret was Mandatory, which made a CLIENT SECRET structurally required to
        # deploy -- against the repo-root rule ("authenticate as its SPN using a CERTIFICATE, never
        # a client secret") and impossible to satisfy in a tenant whose admin SPN is cert-only.
        # Get-PimRestToken has supported -CertThumbprint all along; only this signature forced the
        # secret. Added 2026-08-09 while deploying PIM §34.
        [string]$SqlAdminClientSecret,
        [string]$SqlAdminCertThumbprint,
        # 71.33: connect as the SIGNED-IN az user (a member of the SQL admin group) instead of an admin application.
        [switch]$UseSignedInAccount
    )
    if ($UseSignedInAccount) {
        if ("$SqlAdminClientId".Trim() -or $SqlAdminClientSecret -or $SqlAdminCertThumbprint) { throw 'Grant-PimMiSql: -UseSignedInAccount cannot be combined with -SqlAdminClientId/-SqlAdminClientSecret/-SqlAdminCertThumbprint.' }
        if (-not (Get-Command Connect-PimSignedInSql -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot '_PimSignedIn.ps1') }
        [void](Connect-PimSignedInSql -TenantId $TenantId)   # clears every application identity, asserts a user token for -TenantId
    } else {
    if (-not "$SqlAdminClientId".Trim()) { throw 'Grant-PimMiSql: -SqlAdminClientId (with -SqlAdminCertThumbprint) or -UseSignedInAccount is required.' }
    if ($SqlAdminClientSecret -and $SqlAdminCertThumbprint) { throw 'Grant-PimMiSql: pass EITHER -SqlAdminClientSecret OR -SqlAdminCertThumbprint, not both.' }
    if (-not $SqlAdminClientSecret -and -not $SqlAdminCertThumbprint) { throw 'Grant-PimMiSql: one of -SqlAdminClientSecret / -SqlAdminCertThumbprint is required.' }
    $global:PIM_TenantId = $TenantId
    $global:PIM_ClientId = $SqlAdminClientId
    if ($SqlAdminCertThumbprint) {
        # Clear any inherited secret so a stale $global:PIM_ClientSecret cannot silently win inside
        # Get-PimRestToken's fallback chain -- that would authenticate as something other than what
        # this call asked for, and the log would not show it.
        $global:PIM_ClientSecret   = $null
        $global:PIM_CertThumbprint = $SqlAdminCertThumbprint
        $global:PIM_SqlAccessToken = Get-PimRestToken -Resource 'https://database.windows.net' -ClientId $SqlAdminClientId -CertThumbprint $SqlAdminCertThumbprint -Force
    } else {
        $global:PIM_ClientSecret   = $SqlAdminClientSecret
        $global:PIM_SqlAccessToken = Get-PimRestToken -Resource 'https://database.windows.net' -ClientId $SqlAdminClientId -ClientSecret $SqlAdminClientSecret -Force
    }
    }
    $sid = ConvertTo-PimSqlSidFromAppId -AppId $MiAppId
    $cs  = "Server=tcp:$SqlServerFqdn,1433;Database=$SqlDatabase;Encrypt=True;TrustServerCertificate=False;Connection Timeout=30"
    $c = New-PimSqlConnection -ConnectionString $cs
    $c.Open()
    try {
        # BUG-47 -- this used to be an unconditional DROP USER + CREATE USER, which is NOT
        # idempotent and fails on the FIRST re-run of a working environment:
        #
        #   "The database principal owns a schema in the database, and cannot be dropped.
        #    User, group, or role 'ca-pim-manager' already exists in the current database."
        #
        # The user holds db_ddladmin (it has to -- it applies the schema), so as soon as it
        # creates a schema it OWNS that schema, and an owner cannot be dropped. Measured on the
        # mfnpr production deploy: the very re-run that was fixing an unrelated defect died here,
        # and it would fail identically on every customer whose environment has ever been used.
        #
        # The drop was never the point -- the point is that the contained user maps to the RIGHT
        # SID. So: only recreate when the SID actually differs, and when it does, hand the owned
        # schemas to dbo first so the drop can proceed. Role membership is applied unconditionally
        # but guarded, because ALTER ROLE on an existing member is a no-op we should not depend on.
        $b = @"
IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name='$DbUserName' AND sid = $sid)
BEGIN
    IF EXISTS (SELECT 1 FROM sys.database_principals WHERE name='$DbUserName')
    BEGIN
        -- Same NAME, different SID: the identity was rebuilt, so the user genuinely must be
        -- replaced. Transfer anything it owns to dbo first, or the DROP cannot succeed.
        DECLARE @reassign NVARCHAR(MAX);
        SELECT @reassign = STRING_AGG('ALTER AUTHORIZATION ON SCHEMA::' + QUOTENAME(s.name) + ' TO [dbo];', ' ')
        FROM sys.schemas s
        JOIN sys.database_principals p ON s.principal_id = p.principal_id
        WHERE p.name = '$DbUserName';
        IF @reassign IS NOT NULL EXEC sp_executesql @reassign;
        DROP USER [$DbUserName];
    END
    CREATE USER [$DbUserName] WITH SID = $sid, TYPE = E;
END
IF IS_ROLEMEMBER('db_datareader','$DbUserName') = 0 ALTER ROLE db_datareader ADD MEMBER [$DbUserName];
IF IS_ROLEMEMBER('db_datawriter','$DbUserName') = 0 ALTER ROLE db_datawriter ADD MEMBER [$DbUserName];
IF IS_ROLEMEMBER('db_ddladmin','$DbUserName')   = 0 ALTER ROLE db_ddladmin   ADD MEMBER [$DbUserName];
"@
        $cmd = $c.CreateCommand(); $cmd.CommandText = $b; [void]$cmd.ExecuteNonQuery()
    } finally { $c.Close() }
}

$script:PimGraphAppRoles = @{
    'Directory.Read.All'                       = '7ab1d382-f21e-4acd-a863-ba3e13f7da61'
    'User.ReadWrite.All'                       = '741f803b-c850-494e-b5df-cde7c675a1ca'
    'Group.ReadWrite.All'                      = '62a82d76-70ea-41e2-9197-370581804d09'
    # 🔴 BUG-151 -- THE BROAD ROLE WAS REPLACED BY THE NARROW SET THE RUNNING ENGINE ACTUALLY USES.
    # `RoleManagement.ReadWrite.Directory` (9e3f62cf-…) is the documented HIGHER-PRIVILEGED
    # ALTERNATIVE to the schedule roles below (MS Learn); v1 used the narrow set, and §64.2 switched
    # internal to it after verifying an EntraRoles run completed with NO 403. Leaving the broad role
    # here meant the next deploy silently re-granted it to all four remaining tenants, undoing that.
    # 🔑 DERIVED FROM THE RUNNING SYSTEM, NOT FROM A LIST: read live from ca-pim-tick 2026-09-12
    # ($top=999) -- the identity that actually executes the engine (§64.7 trap 1) and is proven
    # 403-free. Encoding what a PROVEN environment holds is the only safe direction here, because
    # under-granting does not fail loudly: it 403s inside a provider and reads as an engine bug.
    # 🪤 The `.Remove.*` roles are NOT redundant with `.ReadWrite.*`. Graph app-roles do not imply
    # one another, and adminRemove (revoke/prune) is a separate permission -- dropping them would
    # have made revoke a silent no-op while assignment kept working, which is the hardest
    # half-broken state to notice.
    'RoleEligibilitySchedule.ReadWrite.Directory'  = 'fee28b28-e1f3-4841-818e-2704dc62245f'
    'RoleEligibilitySchedule.Remove.Directory'     = '79c7e69c-0d9f-4eff-97a8-49170a5a08ba'
    'RoleAssignmentSchedule.ReadWrite.Directory'   = 'dd199f4a-f148-40a4-a2ec-f0069cc799ec'
    'RoleAssignmentSchedule.Remove.Directory'      = 'd3495511-98b7-4df3-b317-4e35c19f6129'
    'RoleManagement.Read.All'                      = 'c7fbd983-d9aa-4fa7-84b8-17382c103bc4'
    'RoleManagementPolicy.Read.Directory'          = 'fdc4c997-9942-4479-bfcb-75a36d1138df'
    'RoleManagementPolicy.Read.AzureADGroup'       = '69e67828-780e-47fd-b28c-7b27d14864e6'
    'PrivilegedEligibilitySchedule.Remove.AzureADGroup' = '55745561-7572-4314-a737-a2c2a1b0dd2e'
    'PrivilegedAssignmentSchedule.Remove.AzureADGroup'  = '55d1104b-3821-413d-b3ca-e2393d333cd3'
    # 🔴 BUG-148 -- THIS ENTRY WAS MISLABELLED: id 618b6020-… is
    # PrivilegedEligibilitySchedule.ReadWrite.AzureADGroup, NOT PrivilegedAccess.ReadWrite.AzureADGroup
    # (2f6817f8-…). Third wrong id in this one map, found by the live name-vs-id check in
    # tests/Test-PimGraphRoleMap.ps1. The GRANT was harmless -- eligibility-schedule is what
    # PIM-for-Groups eligible assignment actually needs, which is why nesting works -- but the map
    # said one thing and did another, so nobody could tell what an environment really held.
    # Relabelled to the truth; the id is unchanged, so this alters no existing grant.
    'PrivilegedEligibilitySchedule.ReadWrite.AzureADGroup' = '618b6020-bca8-4de6-99f6-ef445fa4d857'
    # 🔑 BUG-149 -- THE MAP DID NOT COVER WHAT THE CODE CALLS. Derived 2026-09-12 by enumerating
    # every `Invoke-PimGraph -Path` in engine/ + tools/ and mapping endpoint -> permission, rather
    # than trusting either existing list. Each id resolved from the LIVE Graph service principal.
    # Operator: *"in my opininn you are lacking many pemissions ... i have 20+ permissions in pim v1"*
    # -- correct: the runtime identity held 9 and the code needs ~16. Without these the provider
    # named against each one is a permanent, swallowed 403:
    'PrivilegedAccess.ReadWrite.AzureADGroup'  = '2f6817f8-7b12-4f0f-bc18-eeaf60705a9e'   # group PIM (v1 parity; the SPN list already requires it)
    'PrivilegedAssignmentSchedule.ReadWrite.AzureADGroup' = '41202f2c-f7ab-45be-b001-85c9728b9d69' # ACTIVE group assignments (/assignmentScheduleRequests)
    'AppRoleAssignment.ReadWrite.All'          = '06b708a9-e830-4db3-a914-8e69da51d44f'   # EntraAppRole provider -> /servicePrincipals/{id}/appRoleAssignedTo
    'Application.Read.All'                     = '9a5d68dd-52b0-4cc2-bd40-abcf44ac3a30'   # ...and reading the target servicePrincipal first
    'RoleManagement.ReadWrite.Defender'        = '8b7e8c0a-7e9d-4049-97ec-04b5e1bcaf05'   # DefenderXdrRoles provider -> /roleManagement/defender/*
    'DeviceManagementRBAC.ReadWrite.All'       = 'e330c4f0-4170-414e-a55a-2f022ec2b57b'   # IntuneRoles provider -> /deviceManagement/role*
    # ⚠️ This WIDENS what every deploy grants the container identity. It is deliberate: each role
    # above is required by a provider that is otherwise inert, and the scheduler now runs those
    # providers (the workload jobs). AccessReview.ReadWrite.All is still deliberately NOT here --
    # docs hold it back until live decision recording is wanted (read is enough for the provider).
    # 🔴 SEC-18 -- THIS ID WAS WRONG, AND IT WAS THE WRONG ROLE ENTIRELY. It read
    # 'a2611786-80b3-417e-adaa-707d4261a5f0', which is **CallRecord-PstnCalls.Read.All** -- so every
    # environment granted a privacy-sensitive PSTN call-records permission nobody asked for, and never
    # got the role-management-policy permission this line is named after. Resolved against the live
    # Microsoft Graph service principal 2026-09-08; wrong since e29856d5 (2026-06-15).
    # 🪤 A hardcoded id here is NEVER validated: Install-PimEngineAppRegistration only looks a name up
    # in the live catalog when this map does NOT contain it, so a wrong entry is authoritative forever
    # -- the lookup that would have caught this is skipped precisely because the map "already knows".
    # This table also feeds Grant-PimMiGraph, which grants the CONTAINER MANAGED IDENTITY on every
    # deploy, so the blast radius was existing environments too, not just new onboardings.
    # ⚠️ Correcting this does NOT revoke the stray grant where it already landed -- these scripts only
    # add. Removing CallRecord-PstnCalls.Read.All from principals that already hold it is a separate,
    # live-tenant change.
    #
    # 🔴 BUG-146 -- SEC-18's CORRECTION DELETED THE ENTRY INSTEAD OF FIXING ITS ID, so the role this
    # whole comment is about was absent from the map entirely: nine entries, and no
    # RoleManagementPolicy.ReadWrite.AzureADGroup anywhere. The comment survived and reads like a
    # header for a line that no longer exists, which is why it looked corrected.
    # 🪤 THE CONSEQUENCE IS THE OPPOSITE OF WHAT SEC-18's NOTE PROMISES. Grant-PimMiGraph grants the
    # container MANAGED IDENTITY -- the principal that actually calls Graph in the hosted topology --
    # so with the entry gone, re-running the deploy could never grant it. Measured on internal
    # 2026-09-12: ca-pim-tick and ca-pim-manager each hold 9 Graph roles and are missing exactly
    # this one, and every run logs `GroupsPolicies: no member policy for '<group>'` -- a swallowed
    # 403 -- on every policy-managed group. The documented remedy ("re-run the deploy") was inert.
    # 🔑 Id resolved from the LIVE Microsoft Graph service principal 2026-09-12, not from memory --
    # which also re-confirmed SEC-18's story: a2611786-80b3-417e-adaa-707d4261a5f0 really is
    # CallRecord-PstnCalls.Read.All. Guarded now by tests/Test-PimGraphRoleMap.ps1.
    'RoleManagementPolicy.ReadWrite.AzureADGroup' = 'b38dcc4d-a239-4ed6-aa84-6c65b284f97c'
    # 🔴 BUG-147 -- TWO LISTS, ONE CONCEPT. setup/Grant-PimGraphAppRoles.ps1 lists
    # AccessReview.Read.All as required; this map (the one that grants the RUNTIME identity) omitted
    # it, so the AccessReviews provider 403s and is a permanent no-op in every hosted environment --
    # while the doc that calls it required points at the SPN list, which is not what executes.
    'AccessReview.Read.All'                    = 'd07a8cc0-3d51-4b77-b3b0-32704d1f69fa'
    'RoleManagementPolicy.ReadWrite.Directory' = '31e08e0a-d3f7-4ca2-ac39-7343fb83e8ad'
    'AdministrativeUnit.ReadWrite.All'         = '5eb59dd3-1da2-4329-8733-9dabdc435916'
    'UserAuthenticationMethod.ReadWrite.All'   = '50483e42-d915-4231-9639-7fdb7fd190e5'
    # BUG-82: reading the tenant's default verified domain (/domains) needs its own role -- none of
    # the eight above covers it, not even Directory.Read.All. The managed-tenant downlink resolves
    # that domain to build synced admins' UPNs (IMP-12), and without it the engine SPN gets
    #   GET /v1.0/domains -> 403 Authorization_RequestDenied
    # so the downlink refuses to stage admins rather than guess a domain -- correct, and fatal to
    # the whole S6 apply. Id read from the live Graph service principal, not from memory.
    'Domain.Read.All'                          = 'dbb9058a-0e50-45d7-ae91-66909b5d4664'
    # 2026-09-12: the tenant's Temporary Access Pass policy (one-time use, lifetime range) is read so a
    # TAP request conforms to it (PIM-TapPolicy.ps1). Without this the first TAP of every run takes a
    # 400 "Tenant Policy does not allow multiple use temporary access pass" plus a retry (measured on
    # internal). Id from the Microsoft Graph permissions reference -- NOT yet read back from the live
    # Graph service principal the way the ids above were; confirm on the next deploy's grant step.
    'Policy.Read.All'                          = '246dd0d5-5bd0-4def-940b-0421030a5b68'
    # 🔴 §70.16 (2026-09-13) -- BUG-151's least-privilege switch REMOVED THE ONE ROLE THAT CREATES ROLE-ASSIGNABLE
    # GROUPS. It was verified only against an EntraRoles run ("no 403"), and no group was created that day. The
    # schedule pair covers role ASSIGNMENT; creating a group with isAssignableToRole=true (and managing the members
    # and owners of one) additionally needs RoleManagement.ReadWrite.Directory -- Group.ReadWrite.All is NOT enough.
    # Measured on internal: the operator's new PIM-ROLE-test1 (all 26 ROLE-* definitions are role-assignable) ->
    # POST /v1.0/groups -> 403 Authorization_RequestDenied from ca-pim-tick, and every delegation on it failed after.
    # Granted to ca-pim-tick 2026-09-13 14:55Z on the operator's order ("ok, add it"); id read from the LIVE Graph SP.
    'RoleManagement.ReadWrite.Directory'       = '9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8'
}

# ---------------------------------------------------------------------------
# 🔒 §65.4 -- THE MANAGER'S SET. READ-ONLY, DELIBERATELY, AND SEPARATE FROM THE ENGINE'S.
#
# Operator, 2026-09-12: *"remember to reduce the pim manager permissions to read only"* /
# *"as the engine/queue must do the actual change"*.
#
# 🪤 WHY A SECOND SET AND NOT A FLAG. Grant-PimMiGraph used to apply ONE map to every identity it
# was handed -- Setup-PimContainers calls it for the Manager app AND for the tick job. So the
# 26 -> 13 least-privilege narrowing applied by hand to ca-pim-manager on 2026-09-12 would have
# SILENTLY REVERTED on the next deploy. Least privilege that the tooling undoes is not least
# privilege; it is a manual step nobody will repeat on 30 customers.
#
# 🔑 THIS IS ONLY SAFE BECAUSE THE MANAGER NO LONGER WRITES (§65.1-§65.3). Its five write paths --
# three revokes, TAP reset, session revoke -- now enqueue, and the ENGINE applies them. Narrowing
# these roles BEFORE that landed would have turned five working features into silent 403s, which is
# the failure class §61-§63 exist to end. Order matters; see §65.0.
#
# ⚠️ DO NOT ADD A `*.ReadWrite.*` OR `*.Remove.*` ROLE HERE. If the Manager appears to need one,
# the correct fix is a queued action in PIM-QueueActions.ps1, not a wider grant.
# tests/Test-PimSetupHosting.ps1 asserts this negatively, because a widening here is invisible:
# nothing fails, the GUI just quietly regains the ability to write to the directory.
#
# Every id resolved from the LIVE Microsoft Graph service principal 2026-09-12 (SEC-18: a
# hardcoded id is never validated, so a wrong one is authoritative forever).
# ---------------------------------------------------------------------------
$script:PimGraphAppRolesManager = @{
    'Directory.Read.All'                              = '7ab1d382-f21e-4acd-a863-ba3e13f7da61'
    'Domain.Read.All'                                 = 'dbb9058a-0e50-45d7-ae91-66909b5d4664'
    'User.Read.All'                                   = 'df021288-bdef-4463-88db-98f22de89214'
    'Group.Read.All'                                  = '5b567255-7703-4780-807c-7be8301ae99b'
    'AdministrativeUnit.Read.All'                     = '134fd756-38ce-4afd-ba33-e9623dbe66c2'
    'Application.Read.All'                            = '9a5d68dd-52b0-4cc2-bd40-abcf44ac3a30'
    'AccessReview.Read.All'                           = 'd07a8cc0-3d51-4b77-b3b0-32704d1f69fa'
    'RoleManagement.Read.All'                         = 'c7fbd983-d9aa-4fa7-84b8-17382c103bc4'
    'RoleManagementPolicy.Read.Directory'             = 'fdc4c997-9942-4479-bfcb-75a36d1138df'
    'RoleManagementPolicy.Read.AzureADGroup'          = '69e67828-780e-47fd-b28c-7b27d14864e6'
    'RoleEligibilitySchedule.Read.Directory'          = 'ff278e11-4a33-4d0c-83d2-d01dc58929a5'
    'RoleAssignmentSchedule.Read.Directory'           = 'd5fe8ce8-684c-4c83-a52c-46e882ce4be1'
    'PrivilegedAccess.Read.AzureADGroup'              = '01e37dc9-c035-40bd-b438-b2879c4870a6'
    'PrivilegedEligibilitySchedule.Read.AzureADGroup' = 'edb419d6-7edc-42a3-9345-509bfdf5d87c'
    'PrivilegedAssignmentSchedule.Read.AzureADGroup'  = 'cd4161cb-f098-48f8-a884-1eda9a42434c'
}

function Get-PimGraphAppRoleMap {
    # -RoleSet Engine (default) = the full set the tick job needs to reconcile the directory.
    #          Manager          = the read-only set (§65.4).
    # The default is Engine so every existing caller keeps its current behaviour untouched.
    [CmdletBinding()] param([ValidateSet('Engine','Manager')][string]$RoleSet = 'Engine')
    $src = if ($RoleSet -eq 'Manager') { $script:PimGraphAppRolesManager } else { $script:PimGraphAppRoles }
    $h = @{}; foreach ($k in $src.Keys) { $h[$k] = $src[$k] }
    return $h
}

function Get-PimEngineSpnGraphRoles {
    <#
      BUG-181 -- THE ENGINE SPN'S Graph app-role list, DERIVED from the engine map above, never kept by hand.
      setup/Grant-PimGraphAppRoles.ps1 and tools/setup/Install-PimEngineAppRegistration.ps1 each carried their
      own literal list, and both had drifted BEHIND the map: no RoleManagement.ReadWrite.Directory (creates
      role-assignable groups, 70.16), no UserAuthenticationMethod.ReadWrite.All (mints TAPs), no Domain.Read.All
      (the downlink's default domain), no AppRoleAssignment / Application.Read / Defender / DeviceManagementRBAC.
      An engine running AS THE SPN (the VM path, a master acting cross-tenant) therefore could not do what the
      managed identity could, and nothing said so. One source now: the SPN is granted exactly the engine map.
      Returns the sorted role NAMES. Mail.Send is REFUSED here, not merely absent (IMP-06e: a tenant-wide
      Mail.Send defeats the per-mailbox Exchange RBAC scope).
    #>
    [CmdletBinding()] param()
    $names = @((Get-PimGraphAppRoleMap -RoleSet Engine).Keys | Sort-Object)
    if ($names -contains 'Mail.Send') { throw 'Get-PimEngineSpnGraphRoles: the engine map carries Mail.Send -- REFUSED (the send right is the scoped Exchange RBAC assignment, never tenant-wide).' }
    return $names
}

function Get-PimSqlContainedUserSql {
    <#
      PURE. The T-SQL that converges ONE contained database user for an Entra application / managed identity,
      created from its APP ID as a SID (WITH SID = <appId bytes>, TYPE = E). `FROM EXTERNAL PROVIDER` is NOT used:
      it makes SQL resolve the name through Microsoft Graph AS THE SERVER's identity, which fails on these servers.
      The SID form needs no directory lookup at all.
        -Roles          fixed database roles the user must be a member of (added when missing)
        -RevokeRoles    fixed database roles the user must NOT be a member of (dropped when present) -- least
                        privilege is converged, not just granted, so an earlier broader grant is taken back
        -SelectObjects  'schema.table' names the user may SELECT (GRANT SELECT ON OBJECT); a name that does not
                        exist yet is skipped by OBJECT_ID, so a registry without an optional table still applies
        -WriteObjects   'schema.object' names the user may INSERT + UPDATE (never DELETE) -- the publish job's one
                        CHECK-OPTION view onto its own last-run row (PIM-JobCadence.ps1). Same OBJECT_ID skip.
      Same-name-different-SID (the identity was rebuilt): owned schemas go to dbo, then the user is recreated --
      the BUG-47 shape Grant-PimMiSql handles.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$DbUserName,
        [Parameter(Mandatory)][string]$AppId,
        [string[]]$Roles = @(),
        [string[]]$RevokeRoles = @(),
        [string[]]$SelectObjects = @(),
        [string[]]$WriteObjects = @()
    )
    if ("$DbUserName" -notmatch '^[A-Za-z0-9][A-Za-z0-9 ._@-]{0,127}$') { throw "Get-PimSqlContainedUserSql: '$DbUserName' is not a safe database user name." }
    foreach ($o in @($WriteObjects)) { if ("$o" -notmatch '^[A-Za-z_][A-Za-z0-9_]*\.[A-Za-z_][A-Za-z0-9_]*$') { throw "Get-PimSqlContainedUserSql: '$o' is not a schema.object name." } }
    $okRoles = @('db_datareader', 'db_datawriter', 'db_ddladmin', 'db_owner', 'db_securityadmin', 'db_accessadmin', 'db_backupoperator', 'db_denydatareader', 'db_denydatawriter')
    foreach ($r in @($Roles) + @($RevokeRoles)) { if ("$r" -and "$r" -notin $okRoles) { throw "Get-PimSqlContainedUserSql: '$r' is not a fixed database role this helper manages." } }
    foreach ($r in @($Roles)) { if (@($RevokeRoles) -contains $r) { throw "Get-PimSqlContainedUserSql: '$r' is both granted and revoked." } }
    foreach ($o in @($SelectObjects)) { if ("$o" -notmatch '^[A-Za-z_][A-Za-z0-9_]*\.[A-Za-z_][A-Za-z0-9_]*$') { throw "Get-PimSqlContainedUserSql: '$o' is not a schema.table name." } }
    $sid = ConvertTo-PimSqlSidFromAppId -AppId $AppId
    $n = "$DbUserName".Replace("'", "''")
    $q = "[$("$DbUserName".Replace(']', ']]'))]"
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine("IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name = N'$n' AND sid = $sid)")
    [void]$sb.AppendLine('BEGIN')
    [void]$sb.AppendLine("    IF EXISTS (SELECT 1 FROM sys.database_principals WHERE name = N'$n')")
    [void]$sb.AppendLine('    BEGIN')
    [void]$sb.AppendLine('        DECLARE @reassign NVARCHAR(MAX);')
    [void]$sb.AppendLine("        SELECT @reassign = STRING_AGG('ALTER AUTHORIZATION ON SCHEMA::' + QUOTENAME(s.name) + ' TO [dbo];', ' ')")
    [void]$sb.AppendLine('        FROM sys.schemas s JOIN sys.database_principals p ON s.principal_id = p.principal_id')
    [void]$sb.AppendLine("        WHERE p.name = N'$n';")
    [void]$sb.AppendLine('        IF @reassign IS NOT NULL EXEC sp_executesql @reassign;')
    [void]$sb.AppendLine("        DROP USER $q;")
    [void]$sb.AppendLine('    END')
    [void]$sb.AppendLine("    CREATE USER $q WITH SID = $sid, TYPE = E;")
    [void]$sb.AppendLine('END')
    foreach ($r in @($Roles | Where-Object { "$_" })) {
        [void]$sb.AppendLine("IF IS_ROLEMEMBER('$r', N'$n') = 0 ALTER ROLE [$r] ADD MEMBER $q;")
    }
    foreach ($r in @($RevokeRoles | Where-Object { "$_" })) {
        [void]$sb.AppendLine("IF IS_ROLEMEMBER('$r', N'$n') = 1 ALTER ROLE [$r] DROP MEMBER $q;")
    }
    foreach ($o in @($SelectObjects | Where-Object { "$_" })) {
        $parts = "$o".Split('.')
        [void]$sb.AppendLine("IF OBJECT_ID(N'$o') IS NOT NULL GRANT SELECT ON OBJECT::[$($parts[0])].[$($parts[1])] TO $q;")
    }
    foreach ($o in @($WriteObjects | Where-Object { "$_" })) {
        $parts = "$o".Split('.')
        [void]$sb.AppendLine("IF OBJECT_ID(N'$o') IS NOT NULL GRANT INSERT, UPDATE ON OBJECT::[$($parts[0])].[$($parts[1])] TO $q;")
    }
    return $sb.ToString()
}

function Get-PimSqlContainedUserReadBackSql {
    <#
      PURE. One-row read-back of what Get-PimSqlContainedUserSql converged, so the caller proves the outcome instead of
      trusting the batch: sidOk (the user exists WITH that SID), one column per role (1 = member), one per object
      (1 = SELECT granted, NULL = the object does not exist). Column names: role_<role>, sel_<schema>_<table>.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$DbUserName, [Parameter(Mandatory)][string]$AppId, [string[]]$Roles = @(), [string[]]$SelectObjects = @(), [string[]]$WriteObjects = @())
    $sid = ConvertTo-PimSqlSidFromAppId -AppId $AppId
    $n = "$DbUserName".Replace("'", "''")
    $cols = New-Object System.Collections.Generic.List[string]
    [void]$cols.Add("CASE WHEN EXISTS (SELECT 1 FROM sys.database_principals WHERE name = N'$n' AND sid = $sid) THEN 1 ELSE 0 END AS sidOk")
    foreach ($r in @($Roles | Where-Object { "$_" } | Select-Object -Unique)) {
        [void]$cols.Add(("CASE WHEN EXISTS (SELECT 1 FROM sys.database_role_members rm JOIN sys.database_principals rp ON rp.principal_id = rm.role_principal_id " +
                         "JOIN sys.database_principals mp ON mp.principal_id = rm.member_principal_id WHERE rp.name = N'$r' AND mp.name = N'$n') THEN 1 ELSE 0 END AS [role_$r]"))
    }
    foreach ($o in @($SelectObjects | Where-Object { "$_" } | Select-Object -Unique)) {
        $safe = "$o".Replace('.', '_')
        [void]$cols.Add(("CASE WHEN OBJECT_ID(N'$o') IS NULL THEN NULL WHEN EXISTS (SELECT 1 FROM sys.database_permissions dp JOIN sys.database_principals gp ON gp.principal_id = dp.grantee_principal_id " +
                         "WHERE gp.name = N'$n' AND dp.class = 1 AND dp.major_id = OBJECT_ID(N'$o') AND dp.permission_name = 'SELECT' AND dp.state IN ('G','W')) THEN 1 ELSE 0 END AS [sel_$safe]"))
    }
    foreach ($o in @($WriteObjects | Where-Object { "$_" } | Select-Object -Unique)) {
        $safe = "$o".Replace('.', '_')
        foreach ($perm in @('INSERT', 'UPDATE')) {
            [void]$cols.Add(("CASE WHEN OBJECT_ID(N'$o') IS NULL THEN NULL WHEN EXISTS (SELECT 1 FROM sys.database_permissions dp JOIN sys.database_principals gp ON gp.principal_id = dp.grantee_principal_id " +
                             "WHERE gp.name = N'$n' AND dp.class = 1 AND dp.major_id = OBJECT_ID(N'$o') AND dp.permission_name = '$perm' AND dp.state IN ('G','W')) THEN 1 ELSE 0 END AS [$($perm.Substring(0,3).ToLowerInvariant())_$safe]"))
        }
    }
    return ('SELECT ' + ($cols -join ",`n       ") + ';')
}

function Test-PimSqlContainedUserReadBack {
    <#
      PURE. Judge a Get-PimSqlContainedUserReadBackSql row: every -Roles member, no -RevokeRoles member, every EXISTING
      -SelectObjects object granted. Returns { ok; problems[] }. A missing row is a failure, never a pass.
    #>
    [CmdletBinding()]
    param([object]$Row, [string[]]$Roles = @(), [string[]]$RevokeRoles = @(), [string[]]$SelectObjects = @(), [string[]]$WriteObjects = @(), [string]$DbUserName = 'the user')
    $p = New-Object System.Collections.Generic.List[string]
    if ($null -eq $Row) { return [pscustomobject]@{ ok = $false; problems = @('the read-back returned no row -- nothing is proven') } }
    $get = { param($name) $pr = $Row.PSObject.Properties[$name]; if ($pr) { $pr.Value } else { $null } }
    if ("$(& $get 'sidOk')" -ne '1') { [void]$p.Add("$DbUserName does not exist with the expected SID") }
    foreach ($r in @($Roles | Where-Object { "$_" })) { if ("$(& $get "role_$r")" -ne '1') { [void]$p.Add("$DbUserName is NOT a member of $r") } }
    foreach ($r in @($RevokeRoles | Where-Object { "$_" })) { if ("$(& $get "role_$r")" -eq '1') { [void]$p.Add("$DbUserName is STILL a member of $r (least privilege not converged)") } }
    foreach ($o in @($SelectObjects | Where-Object { "$_" })) {
        $v = & $get ("sel_" + "$o".Replace('.', '_'))
        if ($null -eq $v -or $v -is [DBNull]) { continue }   # the object does not exist in this store: nothing to grant
        if ("$v" -ne '1') { [void]$p.Add("$DbUserName has no SELECT on $o") }
    }
    foreach ($o in @($WriteObjects | Where-Object { "$_" })) {
        foreach ($perm in @('ins', 'upd')) {
            $v = & $get ("$($perm)_" + "$o".Replace('.', '_'))
            if ($null -eq $v -or $v -is [DBNull]) { continue }
            if ("$v" -ne '1') { [void]$p.Add("$DbUserName has no $(if ($perm -eq 'ins') { 'INSERT' } else { 'UPDATE' }) on $o") }
        }
    }
    return [pscustomobject]@{ ok = ($p.Count -eq 0); problems = @($p.ToArray()) }
}

function Get-PimBaselinePublishSqlReads {
    <#
      SEC-39 -- the ONLY objects the signed-baseline publish job reads (engine/_shared/PIM-BaselinePublish.ps1,
      Get-PimBaselineBundlePayload). Its database user is granted SELECT on these and nothing else.
      tests/Test-PimBaselinePublishJob.ps1 parses every FROM in the producer and fails when it reads a table
      that is not listed here, so a new read cannot land as a runtime "permission denied".
    #>
    [CmdletBinding()] param()
    return @('pim.CentralAdmins', 'pim.Rows', 'pim.TenantRoleProjection', 'platform.Tenants')
}

function Update-PimLauncherIdentityBlock {
    <#
      PURE. IMP-49 p -- Install-PimEngineAppRegistration APPENDED its identity block to LauncherConfig.custom.ps1 on
      every run, so a file grew one duplicate block per run (nine were found in one tree) and the LAST one silently
      won. This returns -Existing with EVERY earlier block removed -- the marked form written now, and the legacy
      unmarked form (the header line plus the `$global:AzureTenantID / `$global:HighPriv_Modern_* assignments under
      it) -- and exactly ONE block of -Lines appended. Anything else in the file is kept verbatim.
    #>
    [CmdletBinding()]
    param([AllowEmptyString()][AllowNull()][string]$Existing, [Parameter(Mandatory)][string[]]$Lines)
    $begin = '# --- PIM4EntraPS engine identity (written by Install-PimEngineAppRegistration.ps1) ---'
    $end   = '# --- end PIM4EntraPS engine identity ---'
    $keep = New-Object System.Collections.Generic.List[string]
    $state = 'out'
    foreach ($ln in @("$Existing" -split "`r?`n")) {
        $t = "$ln".Trim()
        if ($state -eq 'in') {
            if ($t -eq $end) { $state = 'out'; continue }
            if ($t -match '^\$global:(AzureTenantID|HighPriv_Modern_[A-Za-z0-9_]+)\s*=') { continue }
            if (-not $t) { continue }
            $state = 'out'
        }
        if ($t -eq $begin) { $state = 'in'; continue }
        if ($t -eq $end) { continue }
        [void]$keep.Add($ln)
    }
    while ($keep.Count -and -not "$($keep[$keep.Count - 1])".Trim()) { $keep.RemoveAt($keep.Count - 1) }
    $nl = [Environment]::NewLine
    $out = if ($keep.Count) { (($keep.ToArray()) -join $nl) + $nl } else { '' }
    return $out + $begin + $nl + ((@($Lines)) -join $nl) + $nl + $end + $nl
}

function Grant-PimMiGraph {
    <#
      BUG-45 -- a DENIED app-role assignment is not a warning, it is a broken deployment.

      This used to swallow every POST failure into Write-Warning. An identity that silently
      failed to get Directory.Read.All still produced a "successful" deploy, and the breakage
      only surfaced later as 403s inside the container -- where it reads like an engine bug,
      not a grant that never happened. Measured on mfnpr's tick Job: zero app-role assignments,
      four green executions, no work done.

      'Already exists' remains the ONE tolerated outcome, because re-running the deploy is
      normal and must stay idempotent. Everything else now throws and names the role.
    #>
    [CmdletBinding()] param(
        [Parameter(Mandatory)][string]$MiObjectId,
        # BUG-150: pin the token's tenant. Both optional so existing callers are unchanged, but a
        # caller that knows the target SHOULD pass them -- see the refusal below.
        [string]$SubscriptionId,
        [string]$ExpectedTenantId,
        # §65.4 -- WHICH SET this identity gets. Engine (default) = the full reconciling set; Manager =
        # the read-only set. Defaulting to Engine keeps every pre-§65 caller behaving exactly as before.
        [ValidateSet('Engine','Manager')][string]$RoleSet = 'Engine'
    )
    # 🔴 BUG-150 -- THIS MINTED A GRAPH TOKEN WITH NO TENANT PINNING, AND THEN GRANTED WITH IT.
    # `az account get-access-token` with no --subscription uses the CLI's DEFAULT context. On a host
    # that holds logins for more than one tenant -- which the build host does -- that default is
    # frequently a DIFFERENT COMPANY's tenant (CLAUDE.md records it landing on ExpertsLiveDK, and
    # SEC-12 is the same failure in the engine's own token path). The best case is a confusing
    # failure; the worst is issuing app-role grants against the wrong directory.
    # 🔑 So: pin the subscription when the caller knows it, and ALWAYS decode the token and assert
    # the tenant before using it. Verification, not hope -- the same rule the engine already follows.
    $tokArgs = @('account','get-access-token','--resource','https://graph.microsoft.com','-o','json')
    if ("$SubscriptionId".Trim()) { $tokArgs += @('--subscription', "$SubscriptionId") }
    $gtokRaw = (& az @tokArgs 2>$null) | ConvertFrom-Json
    $gtok = "$($gtokRaw.accessToken)"
    if (-not $gtok) { throw "Grant-PimMiGraph: no Graph token (run 'az login' as a role-assigner)." }
    if ("$ExpectedTenantId".Trim()) {
        $seg = $gtok.Split('.')[1].Replace('-','+').Replace('_','/')
        switch ($seg.Length % 4) { 2 { $seg += '==' } 3 { $seg += '=' } }
        $claims = $null
        try { $claims = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($seg)) | ConvertFrom-Json } catch { }
        if (-not $claims -or "$($claims.tid)" -ne "$ExpectedTenantId") {
            throw ("Grant-PimMiGraph: REFUSING to grant -- the Graph token is for tenant '{0}', expected '{1}'. " -f "$($claims.tid)", "$ExpectedTenantId") +
                  "Pass -SubscriptionId for the target tenant, or 'az login' to it. (A grant issued against the wrong directory is not recoverable by re-running this.)"
        }
    }
    $gh = @{ Authorization = "Bearer $gtok"; 'Content-Type' = 'application/json' }
    $graphSp = (Invoke-RestMethod -Headers $gh -Uri "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId eq '00000003-0000-0000-c000-000000000000'").value[0]
    # 🪤 DO NOT go back to "POST everything and tolerate an 'already exists' error string". Graph
    # answers a duplicate assignment with **HTTP 400**, and the explanatory text ("Permission being
    # assigned already exists on the object") is in the response BODY -- `$_.Exception.Message` is
    # only "Response status code does not indicate success: 400 (Bad Request)." So a message match
    # on 'already' can never fire, which is why the old code needed to swallow every failure to
    # stay idempotent, and why swallowing them hid a genuinely un-granted identity. Reading the
    # current assignments first removes the guesswork: assign only what is missing, and then any
    # failure that remains is real.
    $assignUri = "https://graph.microsoft.com/v1.0/servicePrincipals/$MiObjectId/appRoleAssignments"
    function Get-PimAssignedRoleIds {
        param($Headers, $Uri)
        try { return @((Invoke-RestMethod -Headers $Headers -Uri $Uri).value | ForEach-Object { "$($_.appRoleId)" }) }
        catch { return $null }   # cannot read => treat every role as missing (fail-safe)
    }
    $have = Get-PimAssignedRoleIds -Headers $gh -Uri $assignUri
    if ($null -eq $have) { $have = @() }

    # §65.4 -- grant THIS identity's set, not "the" set. The Manager gets read-only roles; the
    # engine gets the full reconciling set. Resolved once here so every loop below agrees.
    $roles = Get-PimGraphAppRoleMap -RoleSet $RoleSet
    Write-Host "    role set: $RoleSet ($($roles.Count) app-role(s))" -ForegroundColor DarkGray

    $failed = [System.Collections.Generic.List[string]]::new()
    $granted = 0
    # 🔴 71.18 (found 2026-09-15 auditing the Friday build) -- THE LOOPS BELOW ITERATED $script:PimGraphAppRoles, THE ENGINE
    # MAP, WHATEVER -RoleSet SAID. $roles was resolved and printed ("role set: Manager (15)") and then never used, so a
    # deploy handed the read-only Manager identity every ReadWrite/Remove role in the engine set -- the widening §65.4
    # exists to prevent, invisible because nothing fails. Every loop now uses the requested set.
    foreach ($r in $roles.GetEnumerator()) {
        if ("$($r.Value)" -in $have) { continue }   # already assigned -- nothing to do
        try {
            Invoke-RestMethod -Method POST -Headers $gh -Uri $assignUri `
                -Body (@{ principalId = $MiObjectId; resourceId = $graphSp.id; appRoleId = $r.Value } | ConvertTo-Json) -ErrorAction Stop | Out-Null
            $granted++
        } catch {
            # The BODY carries the reason; the exception message carries only the status line.
            $body = ''
            try { $body = "$($_.ErrorDetails.Message)" } catch { }
            $failed.Add("$($r.Key): $($_.Exception.Message)$(if ("$body".Trim()) { " -- $body" })")
        }
    }
    if ($failed.Count) {
        # Re-read before condemning: a role can land and be reported as failed if the write raced a
        # read, and a directory that already has the assignment is a success no matter what the POST
        # said. Only a role that is STILL absent is a real failure.
        $now = Get-PimAssignedRoleIds -Headers $gh -Uri $assignUri
        if ($null -ne $now) {
            $stillMissing = @($roles.GetEnumerator() | Where-Object { "$($_.Value)" -notin $now })
            if (-not $stillMissing.Count) {
                Write-Host "    all $($roles.Count) Graph app-roles present (POST errors were duplicates)" -ForegroundColor DarkGray
                return
            }
            throw ("Grant-PimMiGraph: $($stillMissing.Count) of $($roles.Count) Graph app-roles are " +
                   "MISSING on identity $MiObjectId after the grant, so it cannot read/write the directory. " +
                   "Missing: " + (($stillMissing | ForEach-Object { $_.Key }) -join ', ') + ". " +
                   "The deploying identity needs AppRoleAssignment.ReadWrite.All. Errors: " + ($failed -join ' | '))
        }
        throw ("Grant-PimMiGraph: $($failed.Count) Graph app-role assignment(s) failed for identity $MiObjectId " +
               "and the current assignments could not be read back to confirm. Errors: " + ($failed -join ' | '))
    }
    if ($granted) { Write-Host "    granted $granted new Graph app-role(s)" -ForegroundColor DarkGray }
}

function Resolve-PimMiAppId {
    <#
      BUG-44 -- a managed identity's service principal is EVENTUALLY consistent in the directory.

      MEASURED on mfnpr 2026-08-09: `az containerapp job create` returned, the Job's
      system-assigned SP was stamped at 22:59:27, and `az ad sp show` seconds later returned
      NOTHING -- so the deploy threw "could not resolve an appId" and stopped before the SQL and
      Graph grants. The identical lookup on the identical objectId succeeds now. The manager app
      90 lines earlier survived the same call only because `containerapp create` blocks on
      provisioning and therefore gave the directory time; the Job create returns immediately.

      This was previously mis-recorded as a PERMISSIONS gap (§34.2b) and nearly bought an
      identity-model change plus a per-tenant admin-consent step for a problem that is a race.
      The evidence against that reading: the SAME deploying SPN granted the manager's identity
      eight Graph app-roles in the SAME run.

      Retries are therefore the fix, and they must be BOUNDED -- an identity that never appears
      is a real failure and has to stop the deploy rather than hang it.

      -Lookup / -Sleep are injectable so the retry policy is provable offline, with no az and no
      real waiting (tests/Test-PimMiAppIdRetry.ps1).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ObjectId,
        # What this identity belongs to, for the error message: "ca-pim-tick", "ca-pim-manager".
        [Parameter(Mandatory)][string]$What,
        [int]$MaxAttempts          = 8,
        [int]$InitialDelaySeconds  = 2,
        [int]$MaxDelaySeconds      = 30,
        # Default: the real directory read. Returns '' when the SP is not visible yet.
        # 🔴 IT ALSO RECORDS WHY IT FAILED. The old body ended in `2>$null`, which threw the reason
        # away and made "the identity has not replicated yet" and "you are not allowed to read the
        # directory" produce the identical empty string. Measured at a live customer 2026-09-08: a
        # deploy SPN with Owner but no Graph roles hit "Insufficient privileges to complete the
        # operation", and this function retried it EIGHT times over 120s before failing with
        # "a newly-created managed identity is eventually consistent" -- a confident, wrong
        # diagnosis of a permissions problem. BUG-131 states the rule this broke: retrying a
        # permissions error just turns a clear failure into a slow one.
        [scriptblock]$Lookup = {
            param($oid)
            $script:PimMiLookupErr = ''
            $out = & az ad sp show --id $oid --query appId -o tsv 2>&1
            if ($LASTEXITCODE -ne 0) {
                # 🪤 $out IS EMPTY UNDER THE az SHADOW, and the shadow is what every setup script
                # runs with. _PimAz's Invoke-PimAz splits stderr out of its return value (that is
                # how it stays quiet on success), so `2>&1` here captures nothing and this variable
                # stayed '' -- which made the refusal check below dead code for exactly the case it
                # was written for. $global:PimAzLastError is the shadow's published failure text;
                # $out remains the fallback for a real, unshadowed az.
                $script:PimMiLookupErr = (@($out) -join ' ').Trim()
                if (-not $script:PimMiLookupErr) { $script:PimMiLookupErr = "$($global:PimAzLastError)".Trim() }
                return ''
            }
            "$out".Trim()
        },
        [scriptblock]$Sleep  = { param($sec) Start-Sleep -Seconds $sec }
    )
    if ($MaxAttempts -lt 1) { throw 'Resolve-PimMiAppId: -MaxAttempts must be at least 1.' }
    $delay = $InitialDelaySeconds
    $waited = 0
    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        $appId = "$(& $Lookup $ObjectId)".Trim()
        if ($appId) {
            if ($attempt -gt 1) { Write-Host "    directory caught up after $waited s ($attempt attempts)" -ForegroundColor DarkGray }
            return $appId
        }
        # A REFUSAL IS NOT A DELAY. Waiting cannot grant a permission, so stop immediately and say
        # what is actually missing. ($script:PimMiLookupErr stays empty for an injected -Lookup, so
        # the offline tests are unaffected.)
        if ("$script:PimMiLookupErr" -match 'Insufficient privileges|Authorization_RequestDenied|Forbidden|\b403\b') {
            throw ("Cannot read the directory to resolve '$What' identity $ObjectId -- the DEPLOYING " +
                   "identity was REFUSED, not out of date: `"$script:PimMiLookupErr`". Waiting will not fix " +
                   "this. Grant the deploy identity Microsoft Graph Directory.Read.All (and " +
                   "AppRoleAssignment.ReadWrite.All, which the next step needs to grant this managed " +
                   "identity its own Graph roles). An SPN created with 'az ad sp create-for-rbac --role " +
                   "Owner' holds Azure RBAC and NOTHING in Graph.")
        }
        if ($attempt -eq $MaxAttempts) { break }
        Write-Host "    identity $ObjectId not in the directory yet -- retry in ${delay}s ($attempt/$MaxAttempts)" -ForegroundColor DarkGray
        & $Sleep $delay
        $waited += $delay
        $delay = [Math]::Min($delay * 2, $MaxDelaySeconds)
    }
    throw ("Could not resolve an appId for '$What' identity $ObjectId after $MaxAttempts attempts " +
           "over ${waited}s. A newly-created managed identity is eventually consistent, so a short " +
           "delay is normal -- this waited past that. Check that the identity exists and that the " +
           "deploying identity can read the directory (Directory.Read.All or equivalent).")
}

function Resolve-PimAcrImageDigest {
    <#
      BUG-40 -- resolve a MUTABLE tag to the IMMUTABLE digest it currently points at.

      This is the thin `az` half; every decision it feeds is made by the pure helpers in
      engine/_shared/PIM-ImageRef.ps1 (New-PimImageReference / Test-PimImageDeployed).

      Deploying by tag is what let a rebuilt image go un-pulled: ARM saw an unchanged image
      field, so no new revision was created and the platform kept the image it already had.
      Resolving here means the deploy writes content-addressed bytes, not a pointer.

      THROWS rather than falling back to the tag. Silent degradation is precisely what hid
      BUG-39/BUG-40, and the failure it would degrade into is not benign: if the tag cannot be
      resolved the image is not in the registry, so deploying it would ImagePullFailure anyway.
      Failing here names the real cause; failing there names the wrong one.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$AcrName,
        [Parameter(Mandatory)][string]$Repository,
        [Parameter(Mandatory)][string]$Tag,
        # 🔴 SCOPED, or this resolves against the ambient az context. Measured 2026-08-30: the image
        # built and pushed fine, then digest resolution looked in another company's subscription, az
        # prompted for a registry username, and the caller saw "got 'Username:'" -- which reads like
        # a broken build and is actually a wrong-tenant lookup. The BUG-40 guard below then correctly
        # refused to deploy by tag, so the failure was SAFE -- but it was diagnosed three layers away
        # from its cause, which is the cost this parameter removes.
        [string]$SubscriptionId = $(if ($env:PIM_SUBSCRIPTION_ID) { $env:PIM_SUBSCRIPTION_ID } else { '' })
    )
    $ref = "$Repository`:$Tag"
    # `az acr manifest show-metadata` is the current command; `az acr repository show` is the
    # older one that still ships. Try both before concluding the tag is absent -- an az version
    # difference must not read as "the image was never built".
    # 🔴 IMP-49 o -- $digest WAS NEVER INITIALISED, and the show-metadata half this comment promises was missing. PowerShell
    # scoping is DYNAMIC: an unset local reads the CALLER's variable of the same name, so a deploy script that already held
    # a `$digest` (say, the previous image's) had it tested here, found well-formed, and RETURNED -- the registry was never
    # asked, and the deploy wrote the wrong image's digest. Start empty; ask the registry, both commands.
    $digest = ''
    $acrSubArgs = @(); if ("$SubscriptionId".Trim()) { $acrSubArgs = @('--subscription', "$SubscriptionId".Trim()) }
    $digest = "$(az acr manifest show-metadata @acrSubArgs -r $AcrName -n $ref --query digest -o tsv --only-show-errors 2>$null)".Trim()
    if (-not (Test-PimImageDigest -Digest $digest)) {
        $digest = az acr repository show @acrSubArgs -n $AcrName --image $ref --query digest -o tsv --only-show-errors 2>$null
    }
    $digest = "$digest".Trim()
    if (-not (Test-PimImageDigest -Digest $digest)) {
        throw ("Could not resolve a digest for '$AcrName.azurecr.io/$ref' (got '$digest'). Either the tag " +
               "was never pushed, or this identity cannot read the registry. Refusing to deploy by tag as a " +
               "fallback -- a tag deploy can silently keep running the previous image (BUG-40).")
    }
    return $digest
}

function Set-PimSqlNoAutoPause {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$ResourceGroup,
        [Parameter(Mandatory)][string]$SqlServerName,
        [Parameter(Mandatory)][string]$SqlDatabase,
        # Same shape as Resolve-PimImageDigest above: explicit wins, else the deploy's own env var.
        # Both calls below were bare, and a bare read on a host with two contexts answers about
        # somebody else's subscription -- here that means "could not read autoPauseDelay", which the
        # function treats as "probably provisioned compute" and skips. A wrong context would have
        # silently left serverless auto-pause ON.
        [string]$SubscriptionId = $(if ($env:PIM_SUBSCRIPTION_ID) { $env:PIM_SUBSCRIPTION_ID } else { '' })
    )
    # Named "...sub..." on purpose: that is this codebase's scoping convention, and the hygiene gate
    # recognises a scoped call by it. A splat called $sa scopes the call correctly and still reads
    # as unscoped to the gate -- correct code that fails its own guard is a guard that gets muted.
    $subArgs = @(); if ("$SubscriptionId".Trim()) { $subArgs = @('--subscription', "$SubscriptionId".Trim()) }
    $delay = az sql db show @subArgs -g $ResourceGroup -s $SqlServerName -n $SqlDatabase --query autoPauseDelay -o tsv 2>$null
    if (-not $delay) { Write-Warning "  could not read autoPauseDelay for $SqlServerName/$SqlDatabase (skip; may be provisioned compute)."; return }
    if ([string]$delay -eq '-1') { Write-Host "  SQL persistent compute already enforced (autoPauseDelay = -1)." -ForegroundColor DarkGray; return }
    if ($PSCmdlet.ShouldProcess("$SqlServerName/$SqlDatabase", 'disable serverless auto-pause (set autoPauseDelay -1)')) {
        az sql db update @subArgs -g $ResourceGroup -s $SqlServerName -n $SqlDatabase --auto-pause-delay -1 -o none 2>$null
        Write-Host "  SQL auto-pause disabled (autoPauseDelay -1) -- persistent compute enforced." -ForegroundColor Green
    }
}

function Write-PimDnsRecord {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$DnsServer,
        [Parameter(Mandatory)][string]$Fqdn,
        [Parameter(Mandatory)][string]$EnvDomain,
        [Parameter(Mandatory)][string]$StaticIp
    )
    if (-not (Get-Command Add-DnsServerResourceRecordA -ErrorAction SilentlyContinue)) {
        Write-Warning "  DnsServer module not available -- skip AD DNS registration for $Fqdn (add manually: A '$Fqdn' -> $StaticIp)."
        return
    }
    if (-not $PSCmdlet.ShouldProcess($DnsServer, "A $Fqdn -> $StaticIp")) { return }
    $zone = $EnvDomain
    $name = $Fqdn.Substring(0, $Fqdn.Length - $zone.Length - 1)
    if (-not (Get-DnsServerZone -ComputerName $DnsServer -Name $zone -ErrorAction SilentlyContinue)) {
        Add-DnsServerPrimaryZone -ComputerName $DnsServer -Name $zone -ReplicationScope Forest
    }
    foreach ($n in @('*', $name)) {
        $old = Get-DnsServerResourceRecord -ComputerName $DnsServer -ZoneName $zone -Name $n -RRType A -ErrorAction SilentlyContinue
        if ($old) { Remove-DnsServerResourceRecord -ComputerName $DnsServer -ZoneName $zone -Name $n -RRType A -Force -ErrorAction SilentlyContinue }
        Add-DnsServerResourceRecordA -ComputerName $DnsServer -ZoneName $zone -Name $n -IPv4Address $StaticIp -ErrorAction SilentlyContinue
    }
}

function Set-PimVnetPeering {
    <#
      BUG-49 -- THE DEPLOY BUILT AN ISLAND.

      `New-PimHostingPrerequisites` creates an isolated spoke VNet and nothing ever peered it,
      so the production Manager had NO ROUTE FROM ANYWHERE while every resource-level check
      passed: app Succeeded, ingress reporting an FQDN, image verified. Reachability is the one
      property the resource graph cannot show.

      BOTH directions, always. A one-sided peering reads `Initiated` on the side you created and
      carries no traffic -- and whichever blade you happen to open shows a peering that exists.
      So this verifies the STATE of both, and a peering that is not `Connected` is a failure, not
      a warning: the whole point of the step is that the environment is reachable when it ends.

      Idempotent: an existing peering with the right remote is left alone.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$SpokeVnetName,
        [Parameter(Mandatory)][string]$SpokeResourceGroup,
        [Parameter(Mandatory)][string]$SpokeSubscriptionId,
        [Parameter(Mandatory)][string]$HubVnetName,
        [Parameter(Mandatory)][string]$HubResourceGroup,
        [string]$HubSubscriptionId
    )
    # Read the address spaces so the PURE planner can refuse an overlap by name rather than
    # letting az refuse it with a message that names neither range. Unreadable => $null =>
    # the planner treats overlap as UNKNOWN and proceeds (Azure remains the backstop).
    $spokeCidr = az network vnet show -g $SpokeResourceGroup -n $SpokeVnetName --subscription $SpokeSubscriptionId `
                    --query "addressSpace.addressPrefixes[0]" -o tsv --only-show-errors 2>$null
    $hubSub    = $(if ("$HubSubscriptionId".Trim()) { $HubSubscriptionId } else { $SpokeSubscriptionId })
    $hubCidr   = az network vnet show -g $HubResourceGroup -n $HubVnetName --subscription $hubSub `
                    --query "addressSpace.addressPrefixes[0]" -o tsv --only-show-errors 2>$null

    $plan = Get-PimPeeringPlan -SpokeVnetName $SpokeVnetName -SpokeResourceGroup $SpokeResourceGroup `
                -SpokeSubscriptionId $SpokeSubscriptionId -HubVnetName $HubVnetName `
                -HubResourceGroup $HubResourceGroup -HubSubscriptionId $HubSubscriptionId `
                -SpokeAddressSpace "$spokeCidr".Trim() -HubAddressSpace "$hubCidr".Trim()
    if (-not $plan.ok) { throw "VNet peering refused: $($plan.reason)" }
    Write-Host "    $($plan.reason)" -ForegroundColor DarkGray

    foreach ($p in $plan.pairs) {
        $existing = az network vnet peering show -g $p.resourceGroup --vnet-name $p.vnetName -n $p.name `
                        --subscription $p.subscriptionId --query "remoteVirtualNetwork.id" -o tsv --only-show-errors 2>$null
        if ("$existing".Trim() -and "$existing".Trim().ToLowerInvariant() -eq $p.remoteVnetId.ToLowerInvariant()) {
            Write-Host "    peering $($p.name): exists" -ForegroundColor DarkGray
        } elseif ($PSCmdlet.ShouldProcess("$($p.vnetName)/$($p.name)", "peer -> $($p.remoteVnetId)")) {
            if ("$existing".Trim()) {
                # A peering of the right NAME pointing at the WRONG VNet is worse than none: it
                # occupies the name, so every later "create" is a no-op and the environment stays
                # unreachable while a peering visibly exists.
                throw ("peering '$($p.name)' on $($p.vnetName) already points at $existing, not $($p.remoteVnetId). " +
                       "Refusing to leave a peering whose name says one thing and whose target says another -- " +
                       "delete it (az network vnet peering delete -g $($p.resourceGroup) --vnet-name $($p.vnetName) -n $($p.name)) and re-run.")
            }
            az network vnet peering create -g $p.resourceGroup --vnet-name $p.vnetName -n $p.name `
                --remote-vnet $p.remoteVnetId --allow-vnet-access --subscription $p.subscriptionId -o none --only-show-errors
            if ($LASTEXITCODE -and $LASTEXITCODE -ne 0) {
                throw "az network vnet peering create failed for '$($p.name)' on $($p.vnetName) (exit $LASTEXITCODE). Cross-subscription peering needs Network Contributor on BOTH sides."
            }
            Write-Host "    peering $($p.name): created" -ForegroundColor Green
        }
    }

    if ($WhatIfPreference) { return }
    # VERIFY THE STATE, not the create calls. `Initiated` is the exact shape of a half-built
    # peering, and it is indistinguishable from a working one unless you read peeringState.
    $bad = New-Object System.Collections.Generic.List[string]
    foreach ($p in $plan.pairs) {
        $state = az network vnet peering show -g $p.resourceGroup --vnet-name $p.vnetName -n $p.name `
                    --subscription $p.subscriptionId --query peeringState -o tsv --only-show-errors 2>$null
        Write-Host ("    {0,-40} {1}" -f $p.name, $(if ("$state".Trim()) { "$state".Trim() } else { 'UNREADABLE' })) -ForegroundColor DarkGray
        if ("$state".Trim() -ne 'Connected') { $bad.Add("$($p.name)=$(if ("$state".Trim()) { "$state".Trim() } else { 'unreadable' })") | Out-Null }
    }
    if ($bad.Count) {
        throw ("VNet peering is NOT Connected in both directions ($($bad -join ', ')). The Manager will have no " +
               "route from the hub, which every resource-level check will still report as a healthy deploy (BUG-49).")
    }
}

function Set-PimPrivateDnsZone {
    <#
      BUG-49, the other half -- A ROUTE WITHOUT A NAME IS STILL UNREACHABLE.

      An `--internal-only` ACA environment publishes its apps on the environment's default domain
      at ONE static private IP, and nothing off the ACA subnet resolves that name. Peering alone
      therefore produces a client that can route to the Manager and cannot find it.

      This mirrors what the tenant already had for the predecessor environment: a Private DNS zone
      named for the default domain, apex + wildcard + `*.internal` A records at the env static IP,
      linked to every VNet that must resolve it.

      Idempotent: find-or-create the zone, upsert each record set, find-or-create each link.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$EnvDomain,
        [Parameter(Mandatory)][string]$StaticIp,
        [Parameter(Mandatory)][string]$ResourceGroup,
        [Parameter(Mandatory)][string]$SubscriptionId,
        [string[]]$LinkVnetIds = @(),
        [string]$ManagerFqdn = ''
    )
    $plan = Get-PimPrivateDnsPlan -EnvDomain $EnvDomain -StaticIp $StaticIp -ResourceGroup $ResourceGroup `
                -LinkVnetIds $LinkVnetIds -ManagerFqdn $ManagerFqdn
    if (-not $plan.ok) { throw "private DNS refused: $($plan.reason)" }
    Write-Host "    $($plan.reason)" -ForegroundColor DarkGray
    foreach ($w in @($plan.warnings)) { Write-Warning "  $w" }

    if (-not $PSCmdlet.ShouldProcess($plan.zoneName, "private DNS zone -> $($plan.staticIp)")) { return }

    az network private-dns zone create -g $ResourceGroup -n $plan.zoneName --subscription $SubscriptionId `
        -o none --only-show-errors 2>$null | Out-Null
    $zoneOk = az network private-dns zone show -g $ResourceGroup -n $plan.zoneName --subscription $SubscriptionId `
                  --query name -o tsv --only-show-errors 2>$null
    if (-not "$zoneOk".Trim()) {
        throw "could not create or read private DNS zone '$($plan.zoneName)' in $ResourceGroup. Without it the Manager FQDN does not resolve for any client."
    }

    foreach ($r in $plan.records) {
        # 🔴 READ BEFORE WRITING, and do NOTHING when it already matches.
        # The write below is delete-then-add, because `add-record` is create-or-append: a re-run
        # would STACK a second A record rather than replace one whose IP has moved, and only
        # delete-then-add converges when an ACA environment is recreated with a new static IP.
        # But on an environment that is ALREADY CORRECT -- which is every idempotent re-deploy,
        # and the common case -- that same delete would briefly remove the record the Manager is
        # reached through. A deploy that re-runs cleanly must not blink the name it just published.
        $have = @(az network private-dns record-set a show -g $ResourceGroup -z $plan.zoneName -n $r.name `
                      --subscription $SubscriptionId --query "aRecords[].ipv4Address" -o tsv --only-show-errors 2>$null)
        $have = @($have | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
        if ($have.Count -eq 1 -and $have[0] -eq $r.ipv4Address) {
            Write-Host ("    A {0,-12} -> {1}   (already correct)" -f $r.name, $r.ipv4Address) -ForegroundColor DarkGray
            continue
        }
        if ($have.Count) { Write-Host ("    A {0,-12} currently {1} -> replacing with {2}" -f $r.name, ($have -join ','), $r.ipv4Address) -ForegroundColor Yellow }
        az network private-dns record-set a delete -g $ResourceGroup -z $plan.zoneName -n $r.name `
            --subscription $SubscriptionId --yes -o none --only-show-errors 2>$null | Out-Null
        az network private-dns record-set a add-record -g $ResourceGroup -z $plan.zoneName -n $r.name `
            -a $r.ipv4Address --subscription $SubscriptionId -o none --only-show-errors
        if ($LASTEXITCODE -and $LASTEXITCODE -ne 0) { throw "could not write A record '$($r.name)' in zone '$($plan.zoneName)' (exit $LASTEXITCODE)." }
        Write-Host ("    A {0,-12} -> {1}   ({2})" -f $r.name, $r.ipv4Address, $r.purpose) -ForegroundColor DarkGray
    }

    # 🔴 MATCH ON THE VNET, NOT ON THE LINK NAME. MEASURED against the live production zone
    # 2026-08-10: the existing link is named `cae-pim-mfnpr-dnslink`, this looked for
    # `link-vnet-platform`, concluded "missing", tried to create it, and Azure refused with
    # `Conflict: Private zone ... is already linked to the virtual network ...` -- failing the
    # whole deploy over a desired state that was ALREADY SATISFIED. Any environment whose link
    # was created by hand or under an older naming convention would have hit this on every run.
    # The link NAME is arbitrary metadata; the only thing that decides whether clients on a VNet
    # can resolve the zone is whether SOME link points at that VNet. Probe the capability being
    # used, not the artefact this script happens to name (the BUG-46 lesson).
    $linkedVnetIds = @(az network private-dns link vnet list -g $ResourceGroup -z $plan.zoneName `
                          --subscription $SubscriptionId --query "[].virtualNetwork.id" -o tsv --only-show-errors 2>$null)
    $linkedVnetIds = @($linkedVnetIds | ForEach-Object { "$_".Trim().ToLowerInvariant() } | Where-Object { $_ })
    foreach ($l in $plan.links) {
        $want = "$($l.vnetId)".Trim().ToLowerInvariant()
        if ($linkedVnetIds -contains $want) {
            Write-Host "    link -> $(($l.vnetId -split '/')[-1]): already linked" -ForegroundColor DarkGray
            continue
        }
        az network private-dns link vnet create -g $ResourceGroup -z $plan.zoneName -n $l.name `
            -v $l.vnetId -e $(if ($l.registrationEnabled) { 'true' } else { 'false' }) `
            --subscription $SubscriptionId -o none --only-show-errors
        if ($LASTEXITCODE -and $LASTEXITCODE -ne 0) {
            throw "could not link VNet '$($l.vnetId)' to zone '$($plan.zoneName)' (exit $LASTEXITCODE). Without the link, clients on that VNet cannot resolve the Manager."
        }
        Write-Host "    link $($l.name): created" -ForegroundColor Green
    }

    # Read back the record that actually matters. A zone with no A records looks like a
    # configured zone right up until the first client resolves NXDOMAIN.
    $apex = az network private-dns record-set a show -g $ResourceGroup -z $plan.zoneName -n '@' `
                --subscription $SubscriptionId --query "aRecords[0].ipv4Address" -o tsv --only-show-errors 2>$null
    if ("$apex".Trim() -ne $plan.staticIp) {
        throw "private DNS zone '$($plan.zoneName)' apex resolves to '$apex', not $($plan.staticIp). Do NOT assume the records landed."
    }
    Write-Host "    zone verified: $($plan.zoneName) apex -> $apex" -ForegroundColor DarkGray
}

function Grant-PimMiAzureRbac {
    <#
      BUG-51 -- THE DIRECTORY HALF WORKED PERFECTLY AND THE AZURE HALF SAW NOTHING.

      The deploy granted these identities their GRAPH app-roles and no ARM rights whatsoever, so
      the tenant-cache job returned `entra-roles=146 aus=36 pim-groups=332 azure-scopes=0
      azure-rbac-roles=0` next to `ARM managementGroups list failed ... 403 AuthorizationFailed`.
      Nothing failed. There was simply nothing to see.

      This is the exact mirror of framework DOCS/REQUIREMENTS.md §10.0b -- "Global Administrator
      is a directory role and grants nothing in Azure" -- read in the other direction.

      Non-fatal BY DESIGN, unlike the Graph grant: the deploying identity frequently has enough
      rights to create resources and NOT enough to assign roles (role assignment needs User Access
      Administrator or Owner). Failing the whole deploy there would block environments that are
      otherwise correct -- so this WARNS, loudly and specifically, naming the az command to run.
      Pass -Required to make it fatal where the deploying identity is known to be able to do it.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$MiObjectId,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$SubscriptionId,
        [string[]]$Roles = @('Reader'),
        [string]$ManagementGroupId = '',
        [switch]$Required
    )
    $plan = Get-PimAzureRbacPlan -Principals @(@{ name = $Name; objectId = $MiObjectId }) `
                -SubscriptionId $SubscriptionId -Roles $Roles -ManagementGroupId $ManagementGroupId
    if (-not $plan.ok) { throw "Azure RBAC refused: $($plan.reason)" }
    foreach ($w in @($plan.warnings)) { Write-Verbose "  Azure RBAC: $w" }

    $failed = New-Object System.Collections.Generic.List[string]
    $granted = 0
    foreach ($a in $plan.assignments) {
        $have = az role assignment list --subscription $SubscriptionId --assignee $a.principalId --scope $a.scope --role $a.role `
                    --query "[0].roleDefinitionName" -o tsv --only-show-errors 2>$null
        if ("$have".Trim() -eq $a.role) { continue }
        if (-not $PSCmdlet.ShouldProcess("$($a.principalName) @ $($a.scope)", "grant $($a.role)")) { continue }
        az role assignment create --subscription $SubscriptionId --assignee-object-id $a.principalId --assignee-principal-type ServicePrincipal `
            --role $a.role --scope $a.scope -o none --only-show-errors 2>$null
        # Read back rather than trust the exit code: a duplicate assignment exits non-zero
        # (RoleAssignmentExists) and IS success, and a silent no-op exits zero and is not.
        $now = az role assignment list --subscription $SubscriptionId --assignee $a.principalId --scope $a.scope --role $a.role `
                   --query "[0].roleDefinitionName" -o tsv --only-show-errors 2>$null
        if ("$now".Trim() -eq $a.role) { $granted++ }
        else { $failed.Add("$($a.role) @ $($a.scopeKind) $($a.scope)") | Out-Null }
    }

    if ($failed.Count) {
        $msg = ("Azure RBAC NOT granted to '$Name' ($MiObjectId): " + ($failed -join '; ') + ". " +
                "PIM's Azure half will be BLIND -- the tenant cache will report azure-scopes=0 " +
                "azure-rbac-roles=0 while the directory half looks perfect (BUG-51). Grant it with: " +
                "az role assignment create --assignee-object-id $MiObjectId --assignee-principal-type " +
                "ServicePrincipal --role Reader --scope /subscriptions/$SubscriptionId")
        if ($Required) { throw $msg }
        Write-Warning "  $msg"
        return
    }
    if ($granted) { Write-Host "    granted $granted Azure role assignment(s) to $Name" -ForegroundColor DarkGray }
    else { Write-Host "    Azure RBAC already present for $Name" -ForegroundColor DarkGray }
}

function Get-PimGsaPrivateLinkGuidance {
    [CmdletBinding()] param([string]$ManagerFqdn)
    $mgr = if ($ManagerFqdn) { $ManagerFqdn } else { '<manager-fqdn>' }
    @"
GSA / Private Access + private-link / DNS checklist
---------------------------------------------------
Goal: cloud-only users reach the INTERNAL Manager (no public IP) without a VPN,
and on-prem/peered clients resolve the private names. The Manager stays private
(internal ACA env with --ingress external = a static private IP, no public exposure).

1. Entra Global Secure Access -- Private Access (not suffix-based):
   * Define the Manager as a Private Access application targeting its private FQDN/IP:
       host = $mgr   (or the ACA env static IP)   port = 443 (or 80 internal HTTP)
   * Assign the access policy to the cloud-only user/group that must reach it.
   * Install/enable the GSA client on those endpoints; it tunnels to the private app
     over the Microsoft backbone -- no VPN, no public ingress.
   * Verify the connector/forwarding profile covers the Manager FQDN and the SQL/KV
     private names below.

2. Private-link DNS zones to add (link each to the spoke VNet, and forward from any
   custom/on-prem DNS so the VNet resolves them):
   * privatelink.database.windows.net   -- Azure SQL  (PRESENT in this env; keep it)
   * privatelink.blob.core.windows.net  -- run-staging storage / MSP signed-baseline pulls
   * privatelink.vaultcore.azure.net    -- Key Vault (app-only cert/secret over PE)
   NOTE: an ACA *internal* environment with --ingress external publishes the env's
   default domain to a STATIC private IP -- register that name on AD DNS (this script
   does that via -DnsServer); it does not need a privatelink.* zone of its own.

3. Custom-DNS VNets (on-prem domain controllers as the VNet DNS):
   custom-DNS VNets do NOT resolve Azure privatelink.* zones automatically. Production
   fix = a conditional forwarder (or Azure DNS Private Resolver) on the DCs sending
   database.windows.net / blob.core.windows.net / vaultcore.azure.net
   to 168.63.129.16. Hosts-file entries are a bootstrap stopgap ONLY.
"@
}

function Show-PimGsaPrivateLinkGuidance {
    [CmdletBinding()] param([string]$ManagerFqdn)
    Write-Host (Get-PimGsaPrivateLinkGuidance -ManagerFqdn $ManagerFqdn) -ForegroundColor Yellow
}
