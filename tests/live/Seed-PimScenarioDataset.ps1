#Requires -Version 5.1
<#
.SYNOPSIS
  Seed the SYNTHETIC demo estate for the §31 hosting/edition scenario matrix
  (S1-S6) and tear it down. Companion seeder for
  tests/live/Test-PimScenarioMatrix.ps1.

.DESCRIPTION
  This is the dataset half of the LIVE §31 scenario harness. It seeds, into the
  MASTER tenant's central platform registry + the local desired store, the
  synthetic MSP demo estate the matrix verifier asserts against, and signs the
  master baseline bundle so the managed (S5/S6) ring-gated downlink + admin sync
  can be exercised end-to-end:

    MASTER (myfamilynetwork) demo:
      * MSP operator admin accounts in pim.CentralAdmins (Owner='MSP'), each
        ring-stamped (ring 0 broad, ring 1 pilot, ring 2 test) with naming
        markers (L0/T0 / L1/T1) -- these are the admins that must MATERIALIZE in
        each managed/slave tenant by its ring.
      * a small template catalog (admin templates) on the central admins.
      * the per-tenant registry rows (platform.Tenants + platform.TenantApps)
        for the two managed/slave tenants, ring-stamped, so the ring fan-out view
        (pim.vw_AdminTenantTargets) resolves the correct admin->tenant reach.
      * a small T0/T1 x L0-L3 delegation group + role-group + Entra-role
        assignment set in the local desired store (pim.Rows) -- so the engine has
        a desired estate to deploy/validate in the master and managed tenants.
      * GA/PRA people-based approval (approval-required policy template) on the
        high-priv groups.
      * one OFFBOARDING row + one DISCOVERY row (synthetic).
      * the SIGNED baseline bundle (New-PimBaselineBundle) is produced so the
        managed downlink (S5/S6) can pull+verify it.

    PER-SLAVE subset:
      * the seeder computes, from the registry + the slave's ring, the EXACT set
        of MSP admin UPNs that SHOULD exist in that slave tenant after sync, and
        writes it to the state file so the matrix verifier can assert the live
        Graph /users set against it (NOT a guess).

  SYNTHETIC ONLY. Every created object name carries a marker (default
  'PIMSCEN-' for desired-store rows, 'pimscen-' lower-case for UPN locals, and
  the MSP admin UserName naming markers carry L0/T0 etc). No real customer names.
  Cleanup (-Cleanup) removes ONLY marked rows + marked tenant objects -- prod
  rows (no marker) are never touched.

  SAFETY:
    * Idempotent (find-or-create / upsert).
    * -Cleanup performs a full teardown of everything this seeder created
      (registry rows, desired rows, and -- with -RemoveTenantObjects -- the
      marked tenant objects created by an engine deploy of this dataset).
    * Connect ONLY via SPN + certificate (client id / thumbprint / tenant id
      read from kv-automatit-dev or passed in). Never interactive, never a
      secret, never device-code.

.PARAMETER MasterTenantId
  The MSP MASTER tenant id (myfamilynetwork). Holds the central registry, the
  desired store, and the signing key for the baseline bundle.

.PARAMETER MasterClientId / MasterCertThumbprint
  The MASTER engine SPN appId + cert thumbprint (cert on mgmt1 LocalMachine\My).

.PARAMETER SlaveCentralTenantId  (S5 -- managedoperation)
  The CENTRAL-hosted managed/slave tenant id. Reached by the master's
  multi-tenant SPN (S5) -- registered ring 1 (pilot) by default.

.PARAMETER SlaveLocalTenantId    (S6 -- 2linkit)
  The LOCAL-hosted managed/slave tenant id. Has its OWN local SPN (S6) --
  registered ring 2 (test) by default.

.PARAMETER SlaveCentralClientId / SlaveCentralCertThumbprint
.PARAMETER SlaveLocalClientId   / SlaveLocalCertThumbprint
  The managed/slave tenants' engine SPN appId + cert thumbprint (used by the
  matrix verifier to authenticate INTO each slave to assert the synced admins
  exist; registered into platform.TenantApps so the fan-out can reach them).

.PARAMETER MasterSubscriptionId / SlaveCentralSubscriptionId / SlaveLocalSubscriptionId
  Optional Azure subscription ids -- when supplied, an Azure-RBAC delegation
  group + eligibility is added to the desired set at that subscription scope.

.PARAMETER Ring
  Restrict the seed/cleanup to one ring (0/1/2). Default: seed all rings.

.PARAMETER StorageAccount / Container
  Optional: where New-PimBaselineBundle publishes the signed bundle (the S5/S6
  downlink pull source). When omitted, the bundle step is reported as a SKIP in
  the seed summary (the verifier then reports the downlink as not-verifiable).

.PARAMETER Cleanup
  Full teardown of everything this seeder created.

.PARAMETER RemoveTenantObjects
  With -Cleanup, also delete the MARKED tenant objects an engine deploy created
  from this dataset (groups/AUs/admin accounts whose displayName/UPN carries the
  marker). Without it, -Cleanup only removes the SQL rows.

.EXAMPLE
  # seed (values pulled from kv-automatit-dev by the caller / main session)
  $env:PIM_SqlServer='.\SQLEXPRESS'; $env:PIM_SqlDatabase='PimPlatform'
  .\Seed-PimScenarioDataset.ps1 `
     -MasterTenantId f0fa27a0-... -MasterClientId 7c0f9a79-... -MasterCertThumbprint 642E1F8F... `
     -SlaveCentralTenantId 9927fa1f-... -SlaveCentralClientId 7fe46852-... -SlaveCentralCertThumbprint 1B134245... `
     -SlaveLocalTenantId 4ff34194-...  -SlaveLocalClientId 4e1e628c-...  -SlaveLocalCertThumbprint F71AB429...

.EXAMPLE
  .\Seed-PimScenarioDataset.ps1 -Cleanup                      # remove all marked rows
  .\Seed-PimScenarioDataset.ps1 -Cleanup -RemoveTenantObjects # + delete marked tenant objects
#>
[CmdletBinding(DefaultParameterSetName = 'Seed')]
param(
    [Parameter(ParameterSetName = 'Seed', Mandatory)][string]$MasterTenantId,
    [Parameter(ParameterSetName = 'Seed', Mandatory)][string]$MasterClientId,
    [Parameter(ParameterSetName = 'Seed', Mandatory)][string]$MasterCertThumbprint,

    [Parameter(ParameterSetName = 'Seed')][string]$SlaveCentralTenantId,
    [Parameter(ParameterSetName = 'Seed')][string]$SlaveCentralClientId,
    [Parameter(ParameterSetName = 'Seed')][string]$SlaveCentralCertThumbprint,

    [Parameter(ParameterSetName = 'Seed')][string]$SlaveLocalTenantId,
    [Parameter(ParameterSetName = 'Seed')][string]$SlaveLocalClientId,
    [Parameter(ParameterSetName = 'Seed')][string]$SlaveLocalCertThumbprint,

    [Parameter(ParameterSetName = 'Seed')][string]$MasterSubscriptionId,
    [Parameter(ParameterSetName = 'Seed')][string]$SlaveCentralSubscriptionId,
    [Parameter(ParameterSetName = 'Seed')][string]$SlaveLocalSubscriptionId,

    # ring of the CENTRAL (S5) slave and LOCAL (S6) slave in the registry.
    [Parameter(ParameterSetName = 'Seed')][ValidateRange(0, 2)][int]$SlaveCentralRing = 1,
    [Parameter(ParameterSetName = 'Seed')][ValidateRange(0, 2)][int]$SlaveLocalRing = 2,

    [Parameter(ParameterSetName = 'Seed')][ValidateRange(0, 2)][int]$Ring = -1,

    [Parameter(ParameterSetName = 'Seed')][string]$StorageAccount,
    [Parameter(ParameterSetName = 'Seed')][string]$Container = 'baselines',

    [Parameter(ParameterSetName = 'Cleanup', Mandatory)][switch]$Cleanup,
    [Parameter(ParameterSetName = 'Cleanup')][switch]$RemoveTenantObjects,

    [string]$Marker      = 'PIMSCEN-',
    [string]$SqlServer   = $env:PIM_SqlServer,
    [string]$SqlDatabase = $env:PIM_SqlDatabase,
    [string]$StatePath
)

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $here) { $here = 'C:\SCRIPTS\AutomateIT\SOLUTIONS\PIM4EntraPS\tests\live' }
$shared = Resolve-Path (Join-Path $here '..\..\engine\_shared')
if (-not $SqlServer)   { $SqlServer = '.\SQLEXPRESS' }
if (-not $SqlDatabase -and -not $Cleanup) { $SqlDatabase = 'PimPlatform' }
if (-not $SqlDatabase) { $SqlDatabase = 'PimPlatform' }
if (-not $StatePath)   { $StatePath = Join-Path $here 'pimscenario-state.json' }

$global:PIM_UseGraphSdk = $false
$global:PIM_SqlServer   = $SqlServer
$global:PIM_SqlDatabase = $SqlDatabase
. (Join-Path $shared 'PIM-ChangeQueue.ps1')
. (Join-Path $shared 'PIM-SqlStore.ps1')

# ---------------------------------------------------------------------------
# Synthetic estate definition (shared by seed + cleanup + state export).
# All names carry $Marker / the MSP UserName naming markers (L0/T0 etc).
# ---------------------------------------------------------------------------
$m = $Marker

# The MSP operator admin accounts (Owner='MSP', ring-stamped). These are the
# admins that must MATERIALIZE in each managed/slave tenant by its ring.
#   ring 0 = broad  (reaches every slave, incl. ring 1 + ring 2)
#   ring 1 = pilot  (reaches ring >= 1 slaves: the CENTRAL slave + the LOCAL slave)
#   ring 2 = test   (reaches ONLY ring 2 slaves: the LOCAL slave)
# UserName carries the naming markers (L0/T0, L1/T1) the routing reads.
$mspAdmins = @(
    @{ UserName = "${m}Admin-MSPGlobal-L0-T0-ID"; FirstName = 'MSP'; LastName = 'Global Operator'; Initials = 'MG'; DisplayName = "${m}Admin MSP Global Operator (L0/T0)"; Ring = 0; Template = 'msp-operator'; Purpose = 'HighPriv'; UsageLocation = 'DK' }
    @{ UserName = "${m}Admin-MSPCloud-L1-T1-ID";  FirstName = 'MSP'; LastName = 'Cloud Engineer'; Initials = 'MC'; DisplayName = "${m}Admin MSP Cloud Engineer (L1/T1)"; Ring = 1; Template = 'consultant';   Purpose = 'Day2Day'; UsageLocation = 'DK' }
    @{ UserName = "${m}Admin-MSPHelp-L2-T2-ID";   FirstName = 'MSP'; LastName = 'Helpdesk Tech';  Initials = 'MH'; DisplayName = "${m}Admin MSP Helpdesk Tech (L2/T2)";   Ring = 2; Template = 'consultant';   Purpose = 'Day2Day'; UsageLocation = 'DK' }
)

# Managed/slave tenant registry rows (platform.Tenants + platform.TenantApps).
# Built at runtime from the params so the ring fan-out resolves correctly.
function Get-SlaveRegistryRows {
    $rows = @()
    if ($SlaveCentralTenantId) {
        $rows += @{ Role = 'central'; TenantId = $SlaveCentralTenantId; DisplayName = "${m}Slave-Central (S5)"; Ring = $SlaveCentralRing; AppId = $SlaveCentralClientId; Thumb = $SlaveCentralCertThumbprint }
    }
    if ($SlaveLocalTenantId) {
        $rows += @{ Role = 'local'; TenantId = $SlaveLocalTenantId; DisplayName = "${m}Slave-Local (S6)"; Ring = $SlaveLocalRing; AppId = $SlaveLocalClientId; Thumb = $SlaveLocalCertThumbprint }
    }
    return $rows
}

# Admin templates (small catalog) carried on the central admins.
$adminTemplates = @(
    @{ Id = 'msp-operator'; Description = 'MSP global operator (high-priv, ring 0)' }
    @{ Id = 'consultant';   Description = 'Day-to-day consultant (ring 1/2)' }
)

# T0/T1 x L0-L3 delegation groups (desired store, marker-fenced). Mirrors the
# baseline seed grammar so the engine + DeployValidation assertions recognise them.
$desiredAUs = @(
    @{ AdministrativeUnitTag = 'AU-L0'; AUDisplayName = "${m}AU-HighPrivGlobalRoles"; AUDescription = 'High-priv global roles (scenario seed)'; Workload = 'PIM'; Level = 'L0'; Visibility = 'Public' }
    @{ AdministrativeUnitTag = 'AU-L2'; AUDisplayName = "${m}AU-ScopedHelpdesk";       AUDescription = 'AU-scoped helpdesk (scenario seed)';   Workload = 'PIM'; Level = 'L2'; Visibility = 'Public' }
)
$desiredDepartments = @(
    @{ Department = "${m}IT";       OwnersToken = 'MASTER_OWNER'; Mode = 'Serial' }
    @{ Department = "${m}Security"; OwnersToken = 'MASTER_OWNER'; Mode = 'Serial' }
)
# Role groups (Tier-1 job functions, L1).
$desiredRoles = @(
    @{ GroupName = "${m}PIM-ROLE-CloudEngineer-L1-T1"; GroupTag = "${m}ROLE-CloudEngineer"; GroupDescription = 'Cloud engineer role group (scenario seed)'; IsRoleAssignable = 'TRUE'; Department = "${m}IT"; SponsorToken = 'MASTER_OWNER'; PolicyTemplate = '' }
)
# Permission (service) groups across T0/T1 x L0-L3 with GA/PRA approval on high-priv.
$desiredServices = @(
    @{ GroupName = "${m}PIM-Entra-ID-GlobalAdministrator-L0-T0-CP-ID";         GroupTag = "${m}Entra-ID-GlobalAdministrator-L0";        GroupDescription = 'Global Administrator (scenario seed)';          IsRoleAssignable = 'TRUE'; Workload = 'Entra-ID'; Level = 'L0'; Plane = 'CP'; CPPlatform = 'ID'; Department = "${m}Security"; PolicyTemplate = 'approval-required' }
    @{ GroupName = "${m}PIM-Entra-ID-PrivilegedRoleAdministrator-L1-T0-CP-ID"; GroupTag = "${m}Entra-ID-PrivilegedRoleAdministrator-L1"; GroupDescription = 'Privileged Role Administrator (scenario seed)'; IsRoleAssignable = 'TRUE'; Workload = 'Entra-ID'; Level = 'L1'; Plane = 'CP'; CPPlatform = 'ID'; Department = "${m}Security"; PolicyTemplate = 'approval-required' }
    @{ GroupName = "${m}PIM-Entra-ID-UserAdministrator-L1-T1-CP-ID";           GroupTag = "${m}Entra-ID-UserAdministrator-L1";          GroupDescription = 'User Administrator (scenario seed)';            IsRoleAssignable = 'TRUE'; Workload = 'Entra-ID'; Level = 'L1'; Plane = 'CP'; CPPlatform = 'ID'; Department = "${m}IT";       PolicyTemplate = '' }
    @{ GroupName = "${m}PIM-Entra-Helpdesk-L3-T1-CP-ID";                       GroupTag = "${m}Entra-Helpdesk-L3";                      GroupDescription = 'Helpdesk Administrator (scenario seed)';        IsRoleAssignable = 'TRUE'; Workload = 'Entra-ID'; Level = 'L3'; Plane = 'CP'; CPPlatform = 'ID'; AdministrativeUnitTag = 'AU-L2'; Department = "${m}IT"; PolicyTemplate = '' }
)
$desiredRoleGroupAssignments = @(
    @{ GroupTag = "${m}Entra-ID-GlobalAdministrator-L0";         RoleDefinitionName = 'Global Administrator';          AssignmentType = 'Eligible'; Action = 'Assign'; AutoExtend = 'TRUE'; NumOfDaysWhenExpire = '365'; Permanent = 'FALSE'; Plane = 'CP'; PermissionScope = 'Global' }
    @{ GroupTag = "${m}Entra-ID-PrivilegedRoleAdministrator-L1"; RoleDefinitionName = 'Privileged Role Administrator'; AssignmentType = 'Eligible'; Action = 'Assign'; AutoExtend = 'TRUE'; NumOfDaysWhenExpire = '365'; Permanent = 'FALSE'; Plane = 'CP'; PermissionScope = 'Global' }
    @{ GroupTag = "${m}Entra-ID-UserAdministrator-L1";           RoleDefinitionName = 'User Administrator';            AssignmentType = 'Eligible'; Action = 'Assign'; AutoExtend = 'TRUE'; NumOfDaysWhenExpire = '365'; Permanent = 'FALSE'; Plane = 'CP'; PermissionScope = 'Global' }
    @{ GroupTag = "${m}Entra-Helpdesk-L3";                       RoleDefinitionName = 'Helpdesk Administrator';        AssignmentType = 'Eligible'; Action = 'Assign'; AutoExtend = 'TRUE'; NumOfDaysWhenExpire = '90';  Permanent = 'FALSE'; Plane = 'CP'; PermissionScope = 'AU' }
)
# admin -> role-group delegation (the MSP cloud engineer is eligible on the role group)
$desiredAdminAssignments = @(
    @{ Username = "${m}Admin-MSPCloud-L1-T1-ID"; GroupTag = "${m}ROLE-CloudEngineer"; AssignmentType = 'Eligible'; Action = 'Assign'; AutoExtend = 'TRUE'; NumOfDaysWhenExpire = '365'; Permanent = 'FALSE' }
)
$desiredGroupAssignments = @(
    @{ TargetGroupTag = "${m}Entra-ID-UserAdministrator-L1"; SourceGroupTag = "${m}ROLE-CloudEngineer"; AssignmentType = 'Eligible'; Action = 'Assign'; AutoExtend = 'TRUE'; NumOfDaysWhenExpire = '365'; Permanent = 'FALSE' }
)
# one OFFBOARDING row + one DISCOVERY row (synthetic).
$desiredOffboard = @(
    @{ Username = "${m}Admin-Offboard-L2-T2-ID"; OffboardDate = (Get-Date).AddDays(-1).ToString('yyyy-MM-dd'); DeleteAfterDays = '30'; AccountStatus = 'Disabled'; Reason = 'scenario-seed offboarding' }
)
$desiredDiscovery = @(
    @{ DiscoveryTag = "${m}Discovery-Entra"; Plane = 'Entra'; Scope = 'directory'; Notes = 'scenario-seed discovery row' }
)

# Entities owned by this seeder in the DESIRED store (a -Clear removes only marked rows here).
$desiredEntities = @(
    'PIM-Definitions-AU', 'PIM-Definitions-Roles', 'PIM-Definitions-Services',
    'PIM-Definitions-Departments', 'PIM-Assignments-Admins', 'PIM-Assignments-Groups',
    'PIM-Assignments-Roles-Groups', 'PIM-Assignments-Azure-Resources',
    'PIM-Offboarding', 'PIM-Discovery'
)

# ===========================================================================
# CLEANUP
# ===========================================================================
if ($Cleanup) {
    $cs = Get-PimSqlConnectionString
    Write-Host "CLEANUP: removing scenario-seed rows (marker '$Marker')" -ForegroundColor Yellow
    $removed = 0
    foreach ($e in $desiredEntities) {
        try {
            $n = Invoke-PimSqlNonQuery -ConnectionString $cs -Sql "DELETE FROM pim.Rows WHERE Entity=@e AND ([Key] LIKE @m OR DataJson LIKE @md)" -Parameters @{ e = $e; m = "$Marker%"; md = "%$Marker%" }
            $removed += [int]$n
        } catch { Write-Host "  (skip entity $e -- $($_.Exception.Message))" -ForegroundColor DarkGray }
    }
    Write-Host "  removed $removed marked desired rows from pim.Rows" -ForegroundColor Yellow
    # central registry: remove marked admins + marked tenant/app rows
    try {
        $n1 = Invoke-PimSqlNonQuery -ConnectionString $cs -Sql "DELETE FROM pim.CentralAdmins WHERE UserName LIKE @m" -Parameters @{ m = "$Marker%" }
        Write-Host "  removed $([int]$n1) marked central admins" -ForegroundColor Yellow
    } catch { Write-Host "  (no pim.CentralAdmins / $($_.Exception.Message))" -ForegroundColor DarkGray }
    try {
        $n2 = Invoke-PimSqlNonQuery -ConnectionString $cs -Sql "DELETE FROM platform.TenantApps WHERE TenantId IN (SELECT TenantId FROM platform.Tenants WHERE DisplayName LIKE @m)" -Parameters @{ m = "$Marker%" }
        $n3 = Invoke-PimSqlNonQuery -ConnectionString $cs -Sql "DELETE FROM platform.Tenants WHERE DisplayName LIKE @m" -Parameters @{ m = "$Marker%" }
        Write-Host "  removed $([int]$n2) tenant-app + $([int]$n3) tenant registry rows" -ForegroundColor Yellow
    } catch { Write-Host "  (no platform.Tenants / $($_.Exception.Message))" -ForegroundColor DarkGray }

    if ($RemoveTenantObjects) {
        Write-Host "  -RemoveTenantObjects: deleting marked tenant objects via the engine cleanup harness is" -ForegroundColor Yellow
        Write-Host "  delegated to Manage-PimCoreEngineTest.ps1 -Cleanup with this marker (run per tenant)." -ForegroundColor Yellow
        Write-Host "  (This seeder does not authenticate to tenants on -Cleanup; the matrix verifier / the" -ForegroundColor DarkGray
        Write-Host "   per-tenant marker harness deletes the live objects so cleanup stays auth-explicit.)" -ForegroundColor DarkGray
    }
    if (Test-Path $StatePath) { Remove-Item $StatePath -Force -ErrorAction SilentlyContinue; Write-Host "  removed state file $StatePath" -ForegroundColor Yellow }
    Write-Host "Cleanup done." -ForegroundColor Green
    return
}

# ===========================================================================
# SEED
# ===========================================================================
Write-Host "==========================================================================" -ForegroundColor Cyan
Write-Host " Seeding SYNTHETIC §31 scenario estate (marker '$Marker')" -ForegroundColor Cyan
Write-Host "==========================================================================" -ForegroundColor Cyan
Write-Host "  master tenant: $MasterTenantId"
Write-Host "  SQL          : $SqlServer / $SqlDatabase"
if ($Ring -ge 0) { Write-Host "  ring filter  : $Ring" -ForegroundColor Yellow }

# ensure DB + the local desired store schema exist
Initialize-PimSqlDatabase -Server $SqlServer -Database $SqlDatabase
$cs = Get-PimSqlConnectionString
Initialize-PimSqlStore -ConnectionString $cs

# ensure the platform/central registry schema exists (Tenants/TenantApps/CentralAdmins/view)
$platformSchema = Resolve-Path (Join-Path $here '..\..\sql\platform-schema.sql')
function Invoke-PimSqlScriptBatches {
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][string]$Path)
    $text = Get-Content -LiteralPath $Path -Raw
    # split on GO batch separators (SqlClient cannot run GO directly)
    $batches = [regex]::Split($text, "(?im)^\s*GO\s*$")
    foreach ($b in $batches) {
        $sql = $b.Trim()
        if (-not $sql) { continue }
        Invoke-PimSqlNonQuery -ConnectionString $ConnectionString -Sql $sql | Out-Null
    }
}
try {
    Invoke-PimSqlScriptBatches -ConnectionString $cs -Path $platformSchema
    Write-Host "  platform registry schema ensured" -ForegroundColor DarkGray
} catch { Write-Warning "  platform schema apply: $($_.Exception.Message)" }

# ---- 1) central registry: MSP admins (Owner='MSP') -----------------------
Write-Host "[1] central MSP admins (pim.CentralAdmins, Owner='MSP')" -ForegroundColor Cyan
$seedAdmins = if ($Ring -ge 0) { @($mspAdmins | Where-Object { [int]$_.Ring -eq $Ring }) } else { $mspAdmins }
foreach ($a in $seedAdmins) {
    # the actual UPN is per-tenant (UserName@<slave default domain>) -- the central
    # row carries a master-tenant placeholder UPN; the fan-out rewrites it per slave.
    $upn = "$($a.UserName.ToLower())@scenario.invalid"
    Invoke-PimSqlNonQuery -ConnectionString $cs -Sql @"
MERGE pim.CentralAdmins AS t
USING (SELECT @u AS UserName) AS s ON t.UserName = s.UserName
WHEN MATCHED THEN UPDATE SET DisplayName=@dn, Upn=@upn, Ring=@ring, Template=@tpl, Enabled=1, FirstName=@fn, LastName=@ln, Initials=@ini, UsageLocation=@ul, Purpose=@purpose, Owner='MSP', UpdatedAtUtc=SYSUTCDATETIME()
WHEN NOT MATCHED THEN INSERT (UserName, DisplayName, Upn, Ring, Template, Enabled, FirstName, LastName, Initials, UsageLocation, Purpose, Owner)
     VALUES (@u, @dn, @upn, @ring, @tpl, 1, @fn, @ln, @ini, @ul, @purpose, 'MSP');
"@ -Parameters @{ u = $a.UserName; dn = $a.DisplayName; upn = $upn; ring = [int]$a.Ring; tpl = $a.Template; fn = $a.FirstName; ln = $a.LastName; ini = $a.Initials; ul = $a.UsageLocation; purpose = $a.Purpose } | Out-Null
    Write-Host ("  + admin {0,-30} ring {1} template {2}" -f $a.UserName, $a.Ring, $a.Template) -ForegroundColor Green
}
Write-Host ("  template catalog: {0}" -f (($adminTemplates | ForEach-Object { $_.Id }) -join ', ')) -ForegroundColor DarkGray

# ---- 2) managed/slave tenant registry rows + apps ------------------------
Write-Host "[2] managed/slave tenant registry (platform.Tenants + platform.TenantApps)" -ForegroundColor Cyan
$slaveRows = Get-SlaveRegistryRows
foreach ($s in $slaveRows) {
    if (-not $s.TenantId) { continue }
    Invoke-PimSqlNonQuery -ConnectionString $cs -Sql @"
MERGE platform.Tenants AS t
USING (SELECT CAST(@tid AS UNIQUEIDENTIFIER) AS TenantId) AS x ON t.TenantId = x.TenantId
WHEN MATCHED THEN UPDATE SET DisplayName=@dn, Ring=@ring, Enabled=1, UpdatedAtUtc=SYSUTCDATETIME()
WHEN NOT MATCHED THEN INSERT (TenantId, DisplayName, Ring, Enabled) VALUES (@tid, @dn, @ring, 1);
"@ -Parameters @{ tid = $s.TenantId; dn = $s.DisplayName; ring = [int]$s.Ring } | Out-Null
    if ($s.AppId) {
        Invoke-PimSqlNonQuery -ConnectionString $cs -Sql @"
MERGE platform.TenantApps AS t
USING (SELECT CAST(@tid AS UNIQUEIDENTIFIER) AS TenantId, 'PIM' AS Product) AS x ON t.TenantId = x.TenantId AND t.Product = x.Product
WHEN MATCHED THEN UPDATE SET AppId=@app, CertificateThumbprint=@th, AuthMode='Certificate', UpdatedAtUtc=SYSUTCDATETIME()
WHEN NOT MATCHED THEN INSERT (TenantId, Product, AppId, CertificateThumbprint, AuthMode) VALUES (@tid, 'PIM', @app, @th, 'Certificate');
"@ -Parameters @{ tid = $s.TenantId; app = $s.AppId; th = $s.Thumb } | Out-Null
    }
    Write-Host ("  + tenant {0,-26} ring {1} app {2}" -f $s.DisplayName, $s.Ring, $s.AppId) -ForegroundColor Green
}
if (-not $slaveRows.Count) { Write-Host "  (no slave tenant params supplied -- registry left empty; S5/S6 sync not verifiable)" -ForegroundColor Yellow }

# ---- 3) desired estate (local store, marker-fenced) ----------------------
Write-Host "[3] desired estate in pim.Rows (T0/T1 x L0-L3, GA/PRA approval, offboard + discovery)" -ForegroundColor Cyan
function Seed-Rows([string]$Entity, [object[]]$Rows, [string]$Base) {
    $b = if ($Base) { $Base } else { $Entity }
    $count = 0
    foreach ($r in $Rows) {
        $obj = [pscustomobject]$r
        $key = Get-PimStoreRowKey -Base $b -Row $obj
        if (-not $key) { Write-Warning "  no key derived for a $Entity row -- skipped"; continue }
        Set-PimSqlRow -ConnectionString $cs -Entity $Entity -Key $key -Data $obj
        $count++
    }
    Write-Host ("  seeded {0,-34} {1} rows" -f $Entity, $count) -ForegroundColor Green
}
# Azure-RBAC surface (optional): add a group + eligibility at the master sub scope.
$azGroups = @(); $azAssignments = @()
if ($MasterSubscriptionId) {
    $azGroups += @{ GroupName = "${m}PIM-AzRes-Subscription-Reader-L5-T1-MP-RES"; GroupTag = "${m}AzRes-Subscription-Reader-L5"; GroupDescription = 'Azure Reader at subscription (scenario seed)'; IsRoleAssignable = 'FALSE'; Workload = 'Azure'; Level = 'L5'; Plane = 'MP'; CPPlatform = 'RES'; Department = "${m}IT"; PolicyTemplate = '' }
    $azAssignments += @{ GroupTag = "${m}AzRes-Subscription-Reader-L5"; AzScope = "/subscriptions/$MasterSubscriptionId"; AzScopePermission = 'Reader'; AssignmentType = 'Eligible'; Action = 'Assign'; Permanent = 'FALSE'; NumOfDaysWhenExpire = '365' }
}

Seed-Rows 'PIM-Definitions-AU'            $desiredAUs           'PIM-Definitions-AU'
foreach ($d in $desiredDepartments) {
    $dept = [pscustomobject]@{ Department = $d.Department; Owners = ''; Mode = $d.Mode }   # Owners resolved live (see note)
    Set-PimSqlRow -ConnectionString $cs -Entity 'PIM-Definitions-Departments' -Key $d.Department -Data $dept
}
Write-Host ("  seeded {0,-34} {1} rows" -f 'PIM-Definitions-Departments', $desiredDepartments.Count) -ForegroundColor Green
Seed-Rows 'PIM-Definitions-Roles'        $desiredRoles                       'PIM-Definitions-Roles'
Seed-Rows 'PIM-Definitions-Services'     ($desiredServices + $azGroups)      'PIM-Definitions-Services'
Seed-Rows 'PIM-Assignments-Admins'       $desiredAdminAssignments            'PIM-Assignments-Admins'
Seed-Rows 'PIM-Assignments-Groups'       $desiredGroupAssignments            'PIM-Assignments-Groups'
Seed-Rows 'PIM-Assignments-Roles-Groups' $desiredRoleGroupAssignments        'PIM-Assignments-Roles-Groups'
if ($azAssignments.Count) { Seed-Rows 'PIM-Assignments-Azure-Resources' $azAssignments 'PIM-Assignments-Azure-Resources' }
Seed-Rows 'PIM-Offboarding'              $desiredOffboard                    'PIM-Offboarding'
Seed-Rows 'PIM-Discovery'                $desiredDiscovery                   'PIM-Discovery'
Write-Host "  NOTE: department Owners + role SponsorUpn are left blank -- the deploy run must set them to a" -ForegroundColor DarkYellow
Write-Host "        REAL resolvable owner UPN per target tenant (you cannot own a group with a non-existent" -ForegroundColor DarkYellow
Write-Host "        user). Pass the owner UPN to the engine via the scenario deploy step." -ForegroundColor DarkYellow

# ---- 4) sign + publish the master baseline bundle ------------------------
Write-Host "[4] signed master baseline bundle (the S5/S6 ring-gated downlink source)" -ForegroundColor Cyan
$baselineStatus = 'skipped (no -StorageAccount)'
if ($StorageAccount) {
    try {
        $producer = Resolve-Path (Join-Path $here '..\..\setup\New-PimBaselineBundle.ps1')
        # New-PimBaselineBundle reads pim.CentralAdmins WHERE Owner='MSP' -> our seeded admins.
        & $producer -CentralServer $SqlServer -Database $SqlDatabase -StorageAccount $StorageAccount -Container $Container -Scope 'fleet'
        $baselineStatus = 'published'
    } catch {
        $baselineStatus = "FAILED: $($_.Exception.Message)"
        Write-Warning "  baseline bundle publish failed: $($_.Exception.Message)"
    }
} else {
    Write-Host "  (no -StorageAccount -- baseline bundle NOT published; S5/S6 downlink pull will report not-verifiable)" -ForegroundColor Yellow
}

# ---- 5) compute the per-slave EXPECTED admin set + write the state file ---
Write-Host "[5] per-slave expected admin set -> state file" -ForegroundColor Cyan
# An admin reaches a slave when admin.Ring <= slave.Ring (engine ring semantics:
# ring 0 = broad reaches everyone; a ring-2 admin reaches only ring-2 slaves).
function Get-ExpectedAdminsForSlave {
    param([int]$SlaveRing)
    @($mspAdmins | Where-Object { [int]$_.Ring -le $SlaveRing } | ForEach-Object {
            [pscustomobject]@{ UserName = $_.UserName; Ring = $_.Ring; Template = $_.Template; DisplayName = $_.DisplayName }
        })
}
$expected = [ordered]@{}
foreach ($s in $slaveRows) {
    $exp = Get-ExpectedAdminsForSlave -SlaveRing ([int]$s.Ring)
    $expected[$s.Role] = [ordered]@{
        tenantId    = $s.TenantId
        ring        = [int]$s.Ring
        clientId    = $s.AppId
        thumbprint  = $s.Thumb
        # UPN is UserName@<slave default domain>; the verifier resolves the default
        # domain live and matches on UserName (the stable part of the UPN).
        expectedAdminUserNames = @($exp | ForEach-Object { $_.UserName })
    }
    Write-Host ("  slave '{0}' (ring {1}) expects {2} admin(s): {3}" -f $s.Role, $s.Ring, $exp.Count, (($exp | ForEach-Object { $_.UserName }) -join ', ')) -ForegroundColor Green
}

$state = [ordered]@{
    createdUtc      = (Get-Date).ToUniversalTime().ToString('o')
    marker          = $Marker
    sqlServer       = $SqlServer
    sqlDatabase     = $SqlDatabase
    master          = [ordered]@{ tenantId = $MasterTenantId; clientId = $MasterClientId; thumbprint = $MasterCertThumbprint; subscriptionId = $MasterSubscriptionId }
    mspAdminUserNames   = @($mspAdmins | ForEach-Object { $_.UserName })
    desiredGroupNames   = @(($desiredRoles + $desiredServices + $azGroups) | ForEach-Object { $_.GroupName })
    desiredAUNames      = @($desiredAUs | ForEach-Object { $_.AUDisplayName })
    approvalGroupNames  = @($desiredServices | Where-Object { "$($_.PolicyTemplate)" -match '(?i)approval' } | ForEach-Object { $_.GroupName })
    baseline        = [ordered]@{ status = $baselineStatus; storageAccount = $StorageAccount; container = $Container }
    slaves          = $expected
}
$state | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $StatePath -Encoding UTF8
Write-Host "`nState written: $StatePath" -ForegroundColor Cyan

$marked = Invoke-PimSqlScalar -ConnectionString $cs -Sql "SELECT COUNT(*) FROM pim.Rows WHERE DataJson LIKE @md" -Parameters @{ md = "%$Marker%" }
Write-Host ("Seed complete: {0} marked desired rows, {1} central admin(s), {2} slave tenant(s), baseline={3}." -f $marked, $seedAdmins.Count, $slaveRows.Count, $baselineStatus) -ForegroundColor Green
Write-Host "Next: deploy with the scenario matrix verifier (Test-PimScenarioMatrix.ps1 -SeedFirst:`$false)." -ForegroundColor Green
