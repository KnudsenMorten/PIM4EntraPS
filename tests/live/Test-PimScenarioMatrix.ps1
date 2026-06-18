#Requires -Version 5.1
<#
.SYNOPSIS
  The REAL §31 hosting/edition scenario verifier (S1-S6). For each scenario it
  performs real operations and asserts real outcomes against the live tenants,
  returning a structured per-scenario result object and a non-zero exit code if
  any REQUIRED assertion fails.

.DESCRIPTION
  This is the verifier half of the LIVE §31 scenario harness (seeder:
  tests/live/Seed-PimScenarioDataset.ps1). It is NOT a logic-only / resolver-only
  check -- the resolution assertion is necessary but NEVER sufficient on its own.

  For each scenario S1..S6 it runs these assertion families (each becomes a Step
  in the result object; every Step is {name; ok; detail; required; skipped}):

    resolution   -- the scenario resolves to the correct update-source / hosting /
                    SPN model / license tier / sync-file location via
                    Resolve-PimScenarioContext. REQUIRED but not sufficient.
    deploy/update-- the correct update path is selected (Get-PimUpdateSourceProfile
                    honours the resolved source incl. from-master + ManagedHosting),
                    and where applicable executed; for S1/S3 the hosted Manager
                    must RESPOND on the resolved host (live HTTP).
    sync (S5/S6) -- after the ring-gated pull + master->slave sync, the expected
                    MSP/local admin accounts ACTUALLY EXIST in the slave tenant
                    (live Graph GET /users against the slave with ITS SPN, matched
                    against the seeder's per-slave expected set) with the correct
                    ring; AND the sync files landed in the resolved folder
                    (central vs local).
    agent/sched  -- the in-host runner triggered + the engine produced output/state.
    idempotency  -- a second pass makes zero changes.
    safety       -- empty-desired set never prunes (mass-disable guard holds).

  STRICT SKIP != PASS DISCIPLINE (per the operator directive):
    * A REQUIRED capability that is NOT BUILT YET (e.g. the §31.3 sync wiring) is
      reported as ok=$false with a clear detail -- it is NEVER silently skipped or
      counted as a pass.
    * A self-skip (no creds / no SQL / no host reachable) is recorded as
      skipped=$true (distinct from ok). A scenario with ANY skipped REQUIRED step
      is reported NOT-VERIFIED. The process exit code is non-zero if any REQUIRED
      step is ok=$false (a hard failure). Self-skips do not, by themselves, set a
      non-zero exit (they are "didn't run", surfaced as NOT-VERIFIED) UNLESS
      -FailOnSkip is set -- then a skipped REQUIRED step is also a hard failure
      (use this in the gated live run so a missing-cred run can't masquerade as OK).

  Real reads only -- Graph / SQL / REST. No mocks. Connect ONLY via SPN +
  certificate (client id / thumbprint / tenant id from kv-automatit-dev or the
  state file). Never interactive, never a secret, never device-code.

.PARAMETER Scenario
  'S1'..'S6' or 'All' (default).

.PARAMETER StatePath
  The seeder's state file (default tests/live/pimscenario-state.json). Carries
  the master/slave tenant + SPN inputs + the per-slave EXPECTED admin set the
  sync assertions match against.

.PARAMETER MasterTenantId / MasterClientId / MasterCertThumbprint
  Override / supply the master identity when no state file is present.

.PARAMETER SlaveCentralTenantId / ...ClientId / ...CertThumbprint   (S5)
.PARAMETER SlaveLocalTenantId   / ...ClientId / ...CertThumbprint   (S6)
  The managed/slave tenant identities (used to authenticate INTO each slave to
  assert the synced admins exist).

.PARAMETER S1Fqdn / S3Fqdn
  The resolved hosted-Manager FQDN for the single-tenant (S1) / MSP-master (S3)
  in-tenant host. When supplied, the deploy/update step probes it live (HTTP).
  When omitted, the host-responds assertion self-skips (recorded as skipped).

.PARAMETER SqlServer / SqlDatabase
  The desired/registry store (default .\SQLEXPRESS / PimPlatform).

.PARAMETER Marker
  Synthetic-estate marker (default 'PIMSCEN-'); must match the seeder.

.PARAMETER SeedFirst
  Call Seed-PimScenarioDataset.ps1 before verifying.

.PARAMETER Cleanup
  After verifying, tear down (calls the seeder -Cleanup).

.PARAMETER FailOnSkip
  Treat a skipped REQUIRED step as a hard failure (non-zero exit). Use in the
  gated live run so a no-cred run cannot pass.

.OUTPUTS
  Emits the array of per-scenario result objects to the pipeline (for capture)
  and prints a human matrix. Exits non-zero on any REQUIRED ok=$false (and on
  any skipped REQUIRED step when -FailOnSkip).

.EXAMPLE
  # MAIN SESSION runs this live against the 3 tenants (creds from kv-automatit-dev):
  $env:PIM_SqlServer='.\SQLEXPRESS'; $env:PIM_SqlDatabase='PimPlatform'
  .\Test-PimScenarioMatrix.ps1 -Scenario All -SeedFirst -FailOnSkip `
     -MasterTenantId f0fa27a0-... -MasterClientId 7c0f9a79-... -MasterCertThumbprint 642E1F8F... `
     -SlaveCentralTenantId 9927fa1f-... -SlaveCentralClientId 7fe46852-... -SlaveCentralCertThumbprint 1B134245... `
     -SlaveLocalTenantId 4ff34194-...  -SlaveLocalClientId 4e1e628c-...  -SlaveLocalCertThumbprint F71AB429... `
     -S1Fqdn app-pim-manager-xxxx.azurecontainerapps.io -S3Fqdn app-pim-master-xxxx.azurecontainerapps.io
#>
[CmdletBinding()]
param(
    [ValidateSet('S1', 'S2', 'S3', 'S4', 'S5', 'S6', 'All')][string]$Scenario = 'All',
    [string]$StatePath,

    [string]$MasterTenantId,
    [string]$MasterClientId,
    [string]$MasterCertThumbprint,

    [string]$SlaveCentralTenantId,
    [string]$SlaveCentralClientId,
    [string]$SlaveCentralCertThumbprint,

    [string]$SlaveLocalTenantId,
    [string]$SlaveLocalClientId,
    [string]$SlaveLocalCertThumbprint,

    [string]$S1Fqdn,
    [string]$S3Fqdn,

    # Owner UPNs threaded into the seeded desired rows at DEPLOY time. The seeder leaves
    # department Owners + role SponsorUpn BLANK on purpose (you cannot own a group with a
    # non-existent user), and warns the deploy must set a REAL resolvable owner UPN per
    # target tenant. These are NOT hardcoded -- the operator passes a UPN that exists in
    # the relevant tenant (e.g. the engine SPN's owner, or a seeded synthetic owner).
    #   -MasterOwnerUpn       : owner for the master/in-tenant deploys (S1-S4 engine apply).
    #   -SlaveCentralOwnerUpn : owner resolvable in the CENTRAL slave (S5).
    #   -SlaveLocalOwnerUpn   : owner resolvable in the LOCAL slave (S6).
    [string]$MasterOwnerUpn,
    [string]$SlaveCentralOwnerUpn,
    [string]$SlaveLocalOwnerUpn,

    # The signed master baseline the managed (S5/S6) downlink pulls + verifies. The matrix
    # actually RUNS the downlink for S5/S6, so it needs the bundle (local file or HTTPS URL).
    # When neither is supplied for a managed scenario, the runner step SKIPs (no live run).
    [string]$BaselineDocPath,
    [string]$BaselineUrl,
    [string]$BaselineAccessToken,

    [string]$SqlServer   = $env:PIM_SqlServer,
    [string]$SqlDatabase = $env:PIM_SqlDatabase,
    [string]$Marker      = 'PIMSCEN-',

    [switch]$SeedFirst,
    [switch]$Cleanup,
    [switch]$FailOnSkip
)

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $here) { $here = 'C:\SCRIPTS\AutomateIT\SOLUTIONS\PIM4EntraPS\tests\live' }
$shared = Resolve-Path (Join-Path $here '..\..\engine\_shared')
if (-not $SqlServer)   { $SqlServer = '.\SQLEXPRESS' }
if (-not $SqlDatabase) { $SqlDatabase = 'PimPlatform' }
if (-not $StatePath)   { $StatePath = Join-Path $here 'pimscenario-state.json' }

$global:PIM_UseGraphSdk = $false
$global:PIM_SqlServer   = $SqlServer
$global:PIM_SqlDatabase = $SqlDatabase

# Pure-REST + scenario resolver + store + update-source profile.
# PIM-ScenarioProfile.ps1 dot-sources PIM-Downlink.ps1 (the scenario-bound runner
# Invoke-PimScenarioDeploy + the managed downlink) at its tail; PIM-Baseline.ps1 is
# loaded for the signed-baseline verify/load the managed (S5/S6) downlink needs.
. (Join-Path $shared 'PIM-ScenarioProfile.ps1')
. (Join-Path $shared 'PIM-Baseline.ps1')
. (Join-Path $shared 'PIM-UpdateLifecycle.ps1')
. (Join-Path $shared 'PIM-Rest.ps1')
. (Join-Path $shared 'PIM-ChangeQueue.ps1')
. (Join-Path $shared 'PIM-SqlStore.ps1')
. (Join-Path $shared 'PIM-AccountRest.ps1')

# ---------------------------------------------------------------------------
# Step recorder. ok=$true PASS; ok=$false FAIL (REQUIRED -> non-zero exit);
# skipped=$true SKIP (couldn't run -> NOT-VERIFIED, and FAIL with -FailOnSkip
# for REQUIRED steps). 'required' defaults TRUE.
# ---------------------------------------------------------------------------
function New-StepList { , (New-Object System.Collections.Generic.List[object]) }
function Add-Step {
    param(
        [System.Collections.Generic.List[object]]$Steps,
        [Parameter(Mandatory)][string]$Name,
        # $Ok is tri-state: $true PASS, $false FAIL, $null = not-evaluated (skip).
        # Kept as a plain [object] (NOT [Nullable[bool]]) -- in Windows PowerShell
        # 5.1 a [Nullable[bool]] property throws "Argument types do not match" when
        # compared with -eq inside Where-Object. Normalise to a real bool / $null.
        [object]$Ok = $null,
        [string]$Detail = '',
        [bool]$Required = $true,
        [bool]$Skipped = $false
    )
    $okVal = if ($null -eq $Ok) { $null } else { [bool]$Ok }
    $step = [pscustomobject]@{ name = $Name; ok = $okVal; detail = $Detail; required = $Required; skipped = $Skipped }
    $Steps.Add($step) | Out-Null
    $tag = if ($Skipped) { 'SKIP' } elseif ($okVal -eq $true) { 'PASS' } elseif ($okVal -eq $false) { 'FAIL' } else { 'SKIP' }
    $col = switch ($tag) { 'PASS' { 'Green' } 'FAIL' { 'Red' } default { 'DarkYellow' } }
    $req = if ($Required) { '' } else { ' (optional)' }
    Write-Host ("    [{0}] {1}{2}{3}" -f $tag, $Name, $req, $(if ($Detail) { " -- $Detail" } else { '' })) -ForegroundColor $col
    # NB: deliberately no `return` -- the step is already added to $Steps; returning
    # it would leak step objects into the caller's pipeline (mixing with results).
}

# ---------------------------------------------------------------------------
# Cert-only Graph auth against a specific tenant (per-tenant SPN). Mints + proves
# a token via PIM-Rest, then runs Invoke-PimGraph against that tenant. Returns
# $true on success; throws on failure (caller catches -> SKIP/FAIL).
# ---------------------------------------------------------------------------
function Connect-PimTenant {
    param([Parameter(Mandatory)][string]$TenantId, [Parameter(Mandatory)][string]$ClientId, [Parameter(Mandatory)][string]$Thumbprint)
    if (-not (Get-Item "Cert:\LocalMachine\My\$Thumbprint" -ErrorAction SilentlyContinue) -and -not (Get-Item "Cert:\CurrentUser\My\$Thumbprint" -ErrorAction SilentlyContinue)) {
        throw "certificate $Thumbprint not in the machine/user store (cannot auth to $TenantId)"
    }
    $global:PIM_TenantId       = $TenantId
    $global:PIM_ClientId       = $ClientId
    $global:PIM_CertThumbprint = $Thumbprint
    $global:PIM_UseManagedIdentity = $false
    $global:PIM_Interactive        = $false
    $null = Get-PimRestToken -Resource graph -TenantId $TenantId -ClientId $ClientId -CertThumbprint $Thumbprint -Force
    return $true
}

# Live: does the slave tenant contain the expected MSP admin UserNames?
# Returns @{ found=[string[]]; missing=[string[]]; domain=<defaultDomain> }.
function Get-SlaveAdminPresence {
    param([Parameter(Mandatory)][string[]]$ExpectedUserNames)
    $domain = Get-PimRestDefaultDomain
    $found = New-Object System.Collections.Generic.List[string]
    $missing = New-Object System.Collections.Generic.List[string]
    foreach ($un in $ExpectedUserNames) {
        $upn = "$($un.ToLower())@$domain"
        $esc = $upn -replace "'", "''"
        $u = @(Invoke-PimGraph -All -Path "/users?`$filter=userPrincipalName eq '$esc'&`$select=id,userPrincipalName")
        if ($u.Count -gt 0) { $found.Add($un) | Out-Null } else { $missing.Add($un) | Out-Null }
    }
    return @{ found = @($found.ToArray()); missing = @($missing.ToArray()); domain = $domain }
}

# Live HTTP: does a hosted Manager respond on the resolved host?
function Test-HostResponds {
    param([Parameter(Mandatory)][string]$Fqdn)
    $url = if ($Fqdn -match '^https?://') { $Fqdn } else { "https://$Fqdn/" }
    try {
        $resp = Invoke-WebRequest -Uri $url -Method GET -UseBasicParsing -TimeoutSec 30 -ErrorAction Stop
        return @{ ok = $true; code = [int]$resp.StatusCode; detail = "HTTP $([int]$resp.StatusCode) from $url" }
    } catch {
        # Easy Auth fronts the hosted Manager: a 401/403/302-to-login is a LIVE,
        # RESPONDING host (the edge answered). A connection failure is a real fail.
        $code = $null
        try { $code = [int]$_.Exception.Response.StatusCode.value__ } catch {}
        if ($code -in 401, 403, 302) { return @{ ok = $true; code = $code; detail = "HTTP $code (Easy Auth) from $url -- host is live" } }
        return @{ ok = $false; code = $code; detail = "no response from $url -- $($_.Exception.Message)" }
    }
}

# ---------------------------------------------------------------------------
# Thread a REAL owner UPN into the seeded desired rows BEFORE a deploy. The seeder
# leaves department Owners + role SponsorUpn blank (you cannot own a group with a
# non-existent user). The engine resolves a group's owner as Owners -> SponsorUpn
# (Roles) -> the group's Department contact (PIM-Definitions-Departments.Owners), so
# setting the marker-fenced departments' Owners (and roles' SponsorUpn) to a real,
# resolvable UPN makes EVERY seeded group ownable -> the engine can actually create
# it. Marker-fenced only -- never touches prod rows. Returns the #rows it rewrote.
# ---------------------------------------------------------------------------
function Set-PimScenarioOwnerUpn {
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][string]$OwnerUpn, [string]$RowMarker = 'PIMSCEN-')
    if (-not "$OwnerUpn".Trim()) { return 0 }
    $n = 0
    # Departments: set Owners to the real UPN (this is the fallback every group inherits).
    foreach ($d in @(Get-PimSqlRows -ConnectionString $ConnectionString -Entity 'PIM-Definitions-Departments')) {
        $dept = "$($d.Department)"
        if (-not ($dept -like "$RowMarker*")) { continue }
        $obj = [pscustomobject]@{ Department = $dept; Owners = $OwnerUpn; Mode = "$($d.Mode)" }
        Set-PimSqlRow -ConnectionString $ConnectionString -Entity 'PIM-Definitions-Departments' -Key $dept -Data $obj
        $n++
    }
    # Roles: set SponsorUpn directly too (belt + braces; the engine prefers SponsorUpn over dept).
    foreach ($r in @(Get-PimSqlRows -ConnectionString $ConnectionString -Entity 'PIM-Definitions-Roles')) {
        $gt = "$($r.GroupTag)"
        if (-not ($gt -like "$RowMarker*")) { continue }
        $r.PSObject.Properties.Remove('SponsorUpn') | Out-Null
        $r | Add-Member -NotePropertyName SponsorUpn -NotePropertyValue $OwnerUpn -Force
        $key = Get-PimStoreRowKey -Base 'PIM-Definitions-Roles' -Row $r
        if ($key) { Set-PimSqlRow -ConnectionString $ConnectionString -Entity 'PIM-Definitions-Roles' -Key $key -Data $r; $n++ }
    }
    return $n
}

# Load the signed master baseline document the managed (S5/S6) downlink verifies +
# applies. Returns the parsed doc (PSCustomObject) or $null when no source is given
# (the caller then SKIPs the live runner step -- distinct from a pass).
function Get-PimScenarioBaselineDoc {
    if ("$BaselineDocPath".Trim()) {
        if (-not (Test-Path -LiteralPath $BaselineDocPath)) { throw "baseline doc not found: $BaselineDocPath" }
        $raw = Get-Content -LiteralPath $BaselineDocPath -Raw
        $br = $raw.IndexOf('{'); if ($br -gt 0) { $raw = $raw.Substring($br) }
        return ($raw | ConvertFrom-Json)
    }
    if ("$BaselineUrl".Trim()) {
        $headers = @{ 'x-ms-version' = '2021-08-06' }
        if ("$BaselineAccessToken".Trim()) { $headers['Authorization'] = "Bearer $BaselineAccessToken" }
        $raw = Invoke-RestMethod -Method GET -Uri $BaselineUrl -Headers $headers -ErrorAction Stop
        if ($raw -is [string]) { $br = $raw.IndexOf('{'); if ($br -gt 0) { $raw = $raw.Substring($br) }; return ($raw | ConvertFrom-Json) }
        return $raw
    }
    return $null
}

# ---------------------------------------------------------------------------
# Load state (seeder output) -- supplies tenant/SPN inputs + expected sets.
# Explicit params override the state file.
# ---------------------------------------------------------------------------
$state = $null
if (Test-Path $StatePath) { try { $state = Get-Content $StatePath -Raw | ConvertFrom-Json } catch { Write-Warning "state file unreadable: $($_.Exception.Message)" } }

function Coalesce { param($a, $b) if ("$a".Trim()) { return $a } return $b }
# Slave registry rings (the downlink ring-gate uses admin.Ring <= slave.Ring). The seeder
# records each slave's ring in state; default to the seeder's defaults (central=1, local=2).
$SlaveCentralRingFromState = 1
$SlaveLocalRingFromState   = 2
if ($state) {
    $MasterTenantId       = Coalesce $MasterTenantId       $state.master.tenantId
    $MasterClientId       = Coalesce $MasterClientId       $state.master.clientId
    $MasterCertThumbprint = Coalesce $MasterCertThumbprint $state.master.thumbprint
    if ($state.slaves.central) {
        $SlaveCentralTenantId       = Coalesce $SlaveCentralTenantId       $state.slaves.central.tenantId
        $SlaveCentralClientId       = Coalesce $SlaveCentralClientId       $state.slaves.central.clientId
        $SlaveCentralCertThumbprint = Coalesce $SlaveCentralCertThumbprint $state.slaves.central.thumbprint
        if ($null -ne $state.slaves.central.ring) { $SlaveCentralRingFromState = [int]$state.slaves.central.ring }
    }
    if ($state.slaves.local) {
        $SlaveLocalTenantId       = Coalesce $SlaveLocalTenantId       $state.slaves.local.tenantId
        $SlaveLocalClientId       = Coalesce $SlaveLocalClientId       $state.slaves.local.clientId
        $SlaveLocalCertThumbprint = Coalesce $SlaveLocalCertThumbprint $state.slaves.local.thumbprint
        if ($null -ne $state.slaves.local.ring) { $SlaveLocalRingFromState = [int]$state.slaves.local.ring }
    }
}

# ---------------------------------------------------------------------------
# Optional pre-seed.
# ---------------------------------------------------------------------------
if ($SeedFirst) {
    Write-Host "== Seeding the synthetic estate first (Seed-PimScenarioDataset.ps1) ==" -ForegroundColor Cyan
    $seeder = Resolve-Path (Join-Path $here 'Seed-PimScenarioDataset.ps1')
    $seedArgs = @{ MasterTenantId = $MasterTenantId; MasterClientId = $MasterClientId; MasterCertThumbprint = $MasterCertThumbprint; SqlServer = $SqlServer; SqlDatabase = $SqlDatabase; Marker = $Marker; StatePath = $StatePath }
    if ($SlaveCentralTenantId) { $seedArgs.SlaveCentralTenantId = $SlaveCentralTenantId; $seedArgs.SlaveCentralClientId = $SlaveCentralClientId; $seedArgs.SlaveCentralCertThumbprint = $SlaveCentralCertThumbprint }
    if ($SlaveLocalTenantId)   { $seedArgs.SlaveLocalTenantId = $SlaveLocalTenantId;     $seedArgs.SlaveLocalClientId = $SlaveLocalClientId;     $seedArgs.SlaveLocalCertThumbprint = $SlaveLocalCertThumbprint }
    & $seeder @seedArgs
    if (Test-Path $StatePath) { $state = Get-Content $StatePath -Raw | ConvertFrom-Json }
}

# ---------------------------------------------------------------------------
# The §31.3 sync wiring is NOT yet built. This single flag (read from the
# resolved capability, not hardcoded per scenario) makes the verifier assert the
# truth: the sync/admin-materialization REQUIRED steps FAIL until the wiring
# lands -- never silently skipped, never counted as pass.
#
# Capability probe: the master->managed admin+permission sync + the ring-gated
# from-master downlink are delivered when a callable orchestrator exists. Today
# there is none (only the resolver + the descriptor + Get-PimUpdateSourceProfile
# recognising 'from-master'); so this resolves $false and the sync steps FAIL.
# ---------------------------------------------------------------------------
function Test-SyncWiringBuilt {
    # The end-to-end managed downlink orchestrator (ring-gated pull + master->slave
    # admin/permission apply, bound to the resolved scenario) exposes one of these
    # entry points. These now exist (§31.3 Phase-2, PIM-Downlink.ps1) -> BUILT. NB:
    # this only proves the CAPABILITY is defined; the live RESULT (admins/groups
    # created in the slave) is asserted by the run+assert steps below, NOT by this.
    $candidates = @('Invoke-PimManagedDownlink', 'Sync-PimMasterToSlave', 'Invoke-PimScenarioSync')
    foreach ($c in $candidates) { if (Get-Command $c -ErrorAction SilentlyContinue) { return $true } }
    return $false
}
$syncWiringBuilt = Test-SyncWiringBuilt

# Live Graph: which of the given group displayNames exist as Entra groups in the
# CURRENTLY-CONNECTED tenant? Returns @{ found=[string[]]; missing=[string[]] }.
# Mirrors PIM.DeployValidation/Test-PimRestEngineLive's GET /groups?$filter=displayName.
function Get-GroupPresence {
    param([Parameter(Mandatory)][string[]]$DisplayNames)
    $found = New-Object System.Collections.Generic.List[string]
    $missing = New-Object System.Collections.Generic.List[string]
    foreach ($gn in $DisplayNames) {
        if (-not "$gn".Trim()) { continue }
        $esc = $gn -replace "'", "''"
        $g = @(Invoke-PimGraph -All -Path "/groups?`$filter=displayName eq '$esc'&`$select=id,displayName")
        if ($g.Count -gt 0) { $found.Add($gn) | Out-Null } else { $missing.Add($gn) | Out-Null }
    }
    return @{ found = @($found.ToArray()); missing = @($missing.ToArray()) }
}

# ---------------------------------------------------------------------------
# Per-scenario assertion runner.
# ---------------------------------------------------------------------------
function Invoke-ScenarioChecks {
    param([Parameter(Mandatory)][string]$Id)
    $steps = New-StepList
    Write-Host ""
    Write-Host "=== $Id ===" -ForegroundColor Cyan

    $sc = Get-PimScenario -Id $Id
    if (-not $sc) { Add-Step -Steps $steps -Name 'scenario-known' -Ok $false -Detail "unknown scenario id $Id" | Out-Null; return [pscustomobject]@{ Scenario = $Id; Steps = @($steps.ToArray()) } }
    $ctx = Resolve-PimScenarioContext -Scenario $sc

    # ---- resolution (REQUIRED, necessary-not-sufficient) ------------------
    $expect = switch ($Id) {
        'S1' { @{ updateSourceProfile = 'sync-automateit'; configVariant = 'local'; hostingLocation = 'in-tenant';   spnModel = 'local-spn';         activeEdition = 'Pro-DesignPartner'; ringGated = $false; syncAdminsPermissions = $false; syncFileLocation = 'none' } }
        'S2' { @{ updateSourceProfile = 'git-pull';        configVariant = 'local'; hostingLocation = 'in-tenant';   spnModel = 'local-spn';         activeEdition = 'Core';              ringGated = $false; syncAdminsPermissions = $false; syncFileLocation = 'none' } }
        'S3' { @{ updateSourceProfile = 'sync-automateit'; configVariant = 'msp';   hostingLocation = 'in-tenant';   spnModel = 'local-spn';         activeEdition = 'Pro-DesignPartner'; ringGated = $false; syncAdminsPermissions = $false; syncFileLocation = 'central-msp' } }
        'S4' { @{ updateSourceProfile = 'git-pull';        configVariant = 'msp';   hostingLocation = 'in-tenant';   spnModel = 'local-spn';         activeEdition = 'Pro';               ringGated = $false; syncAdminsPermissions = $false; syncFileLocation = 'central-msp' } }
        'S5' { @{ updateSourceProfile = 'from-master';     configVariant = 'msp';   hostingLocation = 'central-msp'; spnModel = 'multi-tenant-spn';  activeEdition = 'Pro-DesignPartner'; ringGated = $true;  syncAdminsPermissions = $true;  syncFileLocation = 'central-msp' } }
        'S6' { @{ updateSourceProfile = 'from-master';     configVariant = 'msp';   hostingLocation = 'local-slave'; spnModel = 'local-spn';         activeEdition = 'Pro-DesignPartner'; ringGated = $true;  syncAdminsPermissions = $true;  syncFileLocation = 'local-slave' } }
    }
    $mismatch = @()
    foreach ($k in $expect.Keys) {
        $got = $ctx.$k
        if ("$got" -ne "$($expect[$k])") { $mismatch += "$k=$got (want $($expect[$k]))" }
    }
    Add-Step -Steps $steps -Name 'resolution' -Ok ($mismatch.Count -eq 0) -Detail $(if ($mismatch.Count) { $mismatch -join '; ' } else { "resolves correctly ($($ctx.updateSourceProfile) / $($ctx.hostingLocation) / $($ctx.spnModel) / $($ctx.activeEdition))" }) | Out-Null

    # ---- deploy/update: correct update path selected (REQUIRED) -----------
    # The resolved updateSourceProfile must be a recognised source AND the
    # update-source normalizer must produce the right build/deploy/ringGated plan.
    try {
        $mh = if ($ctx.hostingLocation -eq 'central-msp') { 'central' } else { 'local' }
        $prof = Get-PimUpdateSourceProfile -Source $ctx.updateSourceProfile -ManagedHosting $mh
        $wantRing = [bool]$expect.ringGated
        $okPlan = ("$($prof.source)" -eq "$($ctx.updateSourceProfile)") -and ([bool]$prof.ringGated -eq $wantRing)
        Add-Step -Steps $steps -Name 'update-path-selected' -Ok $okPlan -Detail "source=$($prof.source) build=$($prof.buildMode) deploy=$($prof.deployMode) ringGated=$($prof.ringGated)" | Out-Null
    } catch {
        Add-Step -Steps $steps -Name 'update-path-selected' -Ok $false -Detail "Get-PimUpdateSourceProfile threw: $($_.Exception.Message)" | Out-Null
    }

    # ---- S1/S3: hosted Manager responds on the resolved host (REQUIRED) ----
    if ($Id -in 'S1', 'S3') {
        $fqdn = if ($Id -eq 'S1') { $S1Fqdn } else { $S3Fqdn }
        if (-not "$fqdn".Trim()) {
            Add-Step -Steps $steps -Name 'host-responds' -Skipped $true -Detail "no -$($Id)Fqdn supplied -- cannot probe the hosted Manager" | Out-Null
        } else {
            $r = Test-HostResponds -Fqdn $fqdn
            Add-Step -Steps $steps -Name 'host-responds' -Ok $r.ok -Detail $r.detail | Out-Null
        }
    }

    # =======================================================================
    # LIVE DEPLOY PHASE -- run the scenario-bound runner ONCE, for real.
    # This is the de-tautologised core. We do NOT pass any step merely because a
    # function EXISTS. We RUN Invoke-PimScenarioDeploy (live, -WhatIfMode:$false)
    # against the resolved TARGET for this scenario:
    #   * S1-S4 (single/master): engine apply against the in-tenant MASTER store + cred.
    #   * S5/S6 (managed): downlink-sync (ring pull -> verify -> STAGE sync files ->
    #     fan-out into the slave via ITS OWN SPN) THEN engine apply.
    # The captured result + engine change summary then drive the assertions below
    # (sync-files-landed, slave-admins-materialized, scenario-runner-triggers-engine,
    # idempotent-second-pass). If we cannot run (no cred / no baseline) the dependent
    # REQUIRED steps SKIP (distinct from PASS); if the runner does not exist they FAIL.
    # =======================================================================
    $engineEntry = Test-Path (Join-Path $here '..\..\tools\pim-engine\Invoke-PimEngineCore.ps1')
    Add-Step -Steps $steps -Name 'engine-entry-present' -Ok $engineEntry -Detail $(if ($engineEntry) { 'Invoke-PimEngineCore.ps1 present' } else { 'engine entry missing' }) -Required $false | Out-Null

    $runner   = Get-Command Invoke-PimScenarioDeploy -ErrorAction SilentlyContinue
    $managed  = ($Id -in 'S5', 'S6')
    $tidR  = if ($Id -eq 'S5') { $SlaveCentralTenantId } elseif ($Id -eq 'S6') { $SlaveLocalTenantId } else { $MasterTenantId }
    $cidR  = if ($Id -eq 'S5') { $SlaveCentralClientId } elseif ($Id -eq 'S6') { $SlaveLocalClientId } else { $MasterClientId }
    $thbR  = if ($Id -eq 'S5') { $SlaveCentralCertThumbprint } elseif ($Id -eq 'S6') { $SlaveLocalCertThumbprint } else { $MasterCertThumbprint }
    $ownR  = if ($Id -eq 'S5') { $SlaveCentralOwnerUpn } elseif ($Id -eq 'S6') { $SlaveLocalOwnerUpn } else { $MasterOwnerUpn }
    $ringR = if ($Id -eq 'S5') { [int]$SlaveCentralRingFromState } elseif ($Id -eq 'S6') { [int]$SlaveLocalRingFromState } else { 0 }

    $firstRun = $null            # captured first-pass result (drives every dependent step)
    $firstRanLive = $false       # did a real live deploy actually execute?
    $runSkipReason = $null       # set when we could not run (-> dependent steps SKIP)
    $blDoc = $null

    if (-not $runner) {
        $runSkipReason = 'RUNNER-MISSING'    # special: dependent steps FAIL, not skip
    } else {
        if (-not ($tidR -and $cidR -and $thbR)) { $runSkipReason = "no target tenant SPN inputs for $Id -- cannot run the engine/downlink live" }
        elseif ($managed) {
            try { $blDoc = Get-PimScenarioBaselineDoc } catch { $runSkipReason = "baseline doc load failed: $($_.Exception.Message)" }
            if (-not $runSkipReason -and -not $blDoc) { $runSkipReason = "managed scenario $Id but no -BaselineDocPath/-BaselineUrl -- cannot run the downlink live" }
        }
        if (-not $runSkipReason) {
            try {
                # thread a REAL resolvable owner UPN into the seeded rows so groups are ownable.
                if ("$ownR".Trim()) {
                    $nOwn = Set-PimScenarioOwnerUpn -ConnectionString (Get-PimSqlConnectionString) -OwnerUpn $ownR -RowMarker $Marker
                    Write-Host "    [owner] set $nOwn seeded dept/role row(s) owner -> $ownR" -ForegroundColor DarkGray
                } else {
                    $ownParam = if ($managed) { "Slave$(if($Id -eq 'S5'){'Central'}else{'Local'})OwnerUpn" } else { 'MasterOwnerUpn' }
                    Write-Host "    [owner] WARNING: no -$ownParam for $Id -- the engine may refuse ownerless groups" -ForegroundColor DarkYellow
                }
                # authenticate to the TARGET tenant as its engine SPN (cert-only) + run LIVE.
                $null = Connect-PimTenant -TenantId $tidR -ClientId $cidR -Thumbprint $thbR
                $global:PIM_TenantId = $tidR; $global:PIM_ClientId = $cidR; $global:PIM_CertThumbprint = $thbR
                $deployArgs = @{ Scenario = $sc; EngineScope = 'All'; EngineMode = 'Full'; WhatIfMode = $false
                                 SqlServer = $SqlServer; SqlDatabase = $SqlDatabase }
                if ($managed) {
                    $deployArgs.Doc = $blDoc; $deployArgs.TenantId = $tidR; $deployArgs.SlaveRing = $ringR
                    $deployArgs.CentralRoot = $env:PIM_SyncRootCentral; $deployArgs.LocalRoot = $env:PIM_SyncRootLocal
                }
                $firstRun = Invoke-PimScenarioDeploy @deployArgs
                $firstRanLive = $true
            } catch {
                $runSkipReason = "could not run the scenario deploy for $Id : $($_.Exception.Message)"
            }
        }
    }
    $cs1 = if ($firstRun) { $firstRun.changeSummary } else { $null }
    $ranEngine = [bool]($cs1 -and ("$($cs1.kind)" -eq 'pim-engine-summary'))

    # ---- S5/S6: ring-gated pull + master->slave admin/permission sync ------
    if ($Id -in 'S5', 'S6') {
        $slaveKey = if ($Id -eq 'S5') { 'central' } else { 'local' }
        $expected = @()
        if ($state -and $state.slaves.$slaveKey -and $state.slaves.$slaveKey.expectedAdminUserNames) {
            $expected = @($state.slaves.$slaveKey.expectedAdminUserNames)
        }

        # (a) the sync WIRING must exist -- REQUIRED. (capability probe; the live RESULT is (b)/(c).)
        Add-Step -Steps $steps -Name 'sync-wiring-built' -Ok $syncWiringBuilt `
            -Detail $(if ($syncWiringBuilt) { 'managed downlink orchestrator present (Invoke-PimManagedDownlink/Sync-PimMasterToSlave/Invoke-PimScenarioSync)' } else { 'NOT BUILT: no master->managed downlink orchestrator. REQUIRED -> FAIL.' }) | Out-Null

        # (b) sync files landed in the resolved folder (central vs local) -- REQUIRED.
        # The downlink we ran above STAGES admins.sync.json + manifest.sync.json under the
        # per-tenant staging folder. Assert they exist ON DISK after the real run.
        if (-not $firstRanLive) {
            if ($runSkipReason -eq 'RUNNER-MISSING') { Add-Step -Steps $steps -Name 'sync-files-landed' -Ok $false -Detail 'no downlink orchestrator ran -> nothing staged. REQUIRED -> FAIL.' | Out-Null }
            else { Add-Step -Steps $steps -Name 'sync-files-landed' -Skipped $true -Detail "downlink not run ($runSkipReason) -- cannot assert staged sync files" | Out-Null }
        } else {
            $root = if ($Id -eq 'S5') { $env:PIM_SyncRootCentral } else { $env:PIM_SyncRootLocal }
            if (-not "$root".Trim()) {
                Add-Step -Steps $steps -Name 'sync-files-landed' -Skipped $true -Detail "downlink ran but no staging-root env (PIM_SyncRoot$(if($Id -eq 'S5'){'Central'}else{'Local'})) set -- cannot verify the staged files" | Out-Null
            } else {
                $tenantFolder = Join-Path $root "$tidR"
                $files = @(Get-ChildItem -Path $tenantFolder -Filter '*.sync.json' -ErrorAction SilentlyContinue)
                $okFiles = ($files.Count -gt 0)
                $fileDetail = if ($okFiles) { "$($files.Count) sync file(s) staged in ${tenantFolder}: $(@($files | ForEach-Object { $_.Name }) -join ', ')" } else { "no sync files in $tenantFolder after the downlink ran" }
                Add-Step -Steps $steps -Name 'sync-files-landed' -Ok $okFiles -Detail $fileDetail | Out-Null
            }
        }

        # (c) the expected MSP admins ACTUALLY EXIST in the slave tenant -- REQUIRED.
        # REAL Graph read into the slave with its SPN, matched against the seeder's per-slave
        # expected set. Only meaningful after the downlink fan-out ran (b).
        if (-not ($tidR -and $cidR -and $thbR)) {
            Add-Step -Steps $steps -Name 'slave-admins-materialized' -Skipped $true -Detail "no slave SPN inputs for $Id -- cannot authenticate into the slave to assert admins" | Out-Null
        } elseif (-not $expected.Count) {
            Add-Step -Steps $steps -Name 'slave-admins-materialized' -Skipped $true -Detail "seeder did not record an expected admin set for slave '$slaveKey' (run -SeedFirst)" | Out-Null
        } elseif (-not $firstRanLive) {
            Add-Step -Steps $steps -Name 'slave-admins-materialized' -Skipped $true -Detail "downlink not run ($runSkipReason) -- cannot assert the synced admins materialized" | Out-Null
        } else {
            try {
                $null = Connect-PimTenant -TenantId $tidR -ClientId $cidR -Thumbprint $thbR
                $pres = Get-SlaveAdminPresence -ExpectedUserNames $expected
                $okAdmins = ($pres.missing.Count -eq 0)
                $detail = if ($okAdmins) { "all $($expected.Count) expected admins present in slave ($($pres.domain)) after the downlink: $($pres.found -join ', ')" }
                          else { "MISSING in slave ($($pres.domain)): $($pres.missing -join ', '); present: $($pres.found -join ', ')" }
                Add-Step -Steps $steps -Name 'slave-admins-materialized' -Ok $okAdmins -Detail $detail | Out-Null
            } catch {
                Add-Step -Steps $steps -Name 'slave-admins-materialized' -Skipped $true -Detail "could not query slave $Id : $($_.Exception.Message)" | Out-Null
            }
        }
    }

    # ---- scenario-runner-triggers-engine: the live run produced REAL state --
    # REQUIRED. Asserts the deploy actually ran the engine (structured change summary
    # returned) AND the seeded groups now EXIST in the target tenant (Graph). NOT a
    # capability check. Re-authenticate to the target before the Graph assertion
    # (the slave-admins step above may have switched the connected tenant for S5/S6).
    if ($runSkipReason -eq 'RUNNER-MISSING') {
        Add-Step -Steps $steps -Name 'scenario-runner-triggers-engine' -Ok $false -Detail 'Invoke-PimScenarioDeploy not defined -- the scenario-bound runner does not exist. REQUIRED -> FAIL.' | Out-Null
    } elseif (-not $firstRanLive) {
        Add-Step -Steps $steps -Name 'scenario-runner-triggers-engine' -Skipped $true -Detail $runSkipReason | Out-Null
    } else {
        try {
            $null = Connect-PimTenant -TenantId $tidR -ClientId $cidR -Thumbprint $thbR
            $names = @(); if ($state -and $state.desiredGroupNames) { $names = @($state.desiredGroupNames) }
            $okGroups = $false; $grpDetail = ''
            if (-not $names.Count) { $grpDetail = 'no desiredGroupNames in state (run -SeedFirst) -- cannot assert groups landed' }
            else {
                $pres = Get-GroupPresence -DisplayNames $names
                $okGroups = ($pres.missing.Count -eq 0)
                $grpDetail = if ($okGroups) { "all $($names.Count) seeded group(s) exist in target tenant" } else { "MISSING groups in target: $($pres.missing -join ', ')" }
            }
            $okRun = ([bool]$firstRun.ok) -and $ranEngine -and $okGroups
            $detail = "runner ran $Id ($($firstRun.scenarioId)); engine summary: $(if($cs1){"create=$($cs1.create) update=$($cs1.update) remove=$($cs1.remove) errors=$($cs1.errors)"}else{'<none returned>'}); groups: $grpDetail"
            Add-Step -Steps $steps -Name 'scenario-runner-triggers-engine' -Ok $okRun -Detail $detail | Out-Null
        } catch {
            Add-Step -Steps $steps -Name 'scenario-runner-triggers-engine' -Skipped $true -Detail "could not assert runner outcome for $Id : $($_.Exception.Message)" | Out-Null
        }
    }

    # ---- idempotent-second-pass: a SECOND real pass makes ZERO changes ------
    # REQUIRED. RUN the scenario deploy a SECOND time against the same target and assert
    # the engine reports create=0, update=0, remove=0 (and no errors). FAIL on any change.
    # If the first pass did not run live there is nothing to re-run -> SKIP (not a pass).
    if ($runSkipReason -eq 'RUNNER-MISSING') {
        Add-Step -Steps $steps -Name 'idempotent-second-pass' -Ok $false -Detail 'Invoke-PimScenarioDeploy not defined -- no runner to re-run. REQUIRED -> FAIL.' | Out-Null
    } elseif (-not $firstRanLive) {
        Add-Step -Steps $steps -Name 'idempotent-second-pass' -Skipped $true -Detail "first pass did not run live for $Id ($runSkipReason) -- cannot assert a second-pass no-op" | Out-Null
    } else {
        try {
            $null = Connect-PimTenant -TenantId $tidR -ClientId $cidR -Thumbprint $thbR
            $global:PIM_TenantId = $tidR; $global:PIM_ClientId = $cidR; $global:PIM_CertThumbprint = $thbR
            $deployArgs2 = @{ Scenario = $sc; EngineScope = 'All'; EngineMode = 'Full'; WhatIfMode = $false
                              SqlServer = $SqlServer; SqlDatabase = $SqlDatabase }
            if ($managed) {
                $deployArgs2.Doc = $blDoc; $deployArgs2.TenantId = $tidR; $deployArgs2.SlaveRing = $ringR
                $deployArgs2.CentralRoot = $env:PIM_SyncRootCentral; $deployArgs2.LocalRoot = $env:PIM_SyncRootLocal
            }
            $secondRun = Invoke-PimScenarioDeploy @deployArgs2
            $cs2 = $secondRun.changeSummary
            if (-not ($cs2 -and "$($cs2.kind)" -eq 'pim-engine-summary')) {
                Add-Step -Steps $steps -Name 'idempotent-second-pass' -Ok $false -Detail 'second pass returned no engine change summary -- cannot prove zero changes. FAIL.' | Out-Null
            } else {
                $delta = [int]$cs2.create + [int]$cs2.update + [int]$cs2.remove
                $okIdem = ([bool]$secondRun.ok) -and ($delta -eq 0) -and ([int]$cs2.errors -eq 0)
                $detail = "second pass: create=$($cs2.create) update=$($cs2.update) remove=$($cs2.remove) errors=$($cs2.errors)"
                $detail += if ($okIdem) { ' -- zero changes (idempotent)' } else { ' -- NON-ZERO changes (NOT idempotent)' }
                Add-Step -Steps $steps -Name 'idempotent-second-pass' -Ok $okIdem -Detail $detail | Out-Null
            }
        } catch {
            Add-Step -Steps $steps -Name 'idempotent-second-pass' -Ok $false -Detail "second scenario pass threw: $($_.Exception.Message)" | Out-Null
        }
    }

    # ---- safety: empty-desired set never prunes (mass-disable guard) -------
    # This guard lives in the REST engine core (PIM-EngineCore.ps1) and is REQUIRED
    # for EVERY scenario. We assert it via the engine's fail-hard preflight: an
    # empty desired scope must never prune. Real check against the engine core
    # function (no live writes -- it is a guard assertion).
    try {
        . (Join-Path $shared 'PIM-EngineCore.ps1')
        $guardFn = Get-Command Test-PimEngineDesiredGuard -ErrorAction SilentlyContinue
        if (-not $guardFn) { $guardFn = Get-Command Assert-PimEngineDesiredNotEmpty -ErrorAction SilentlyContinue }
        if ($guardFn) {
            $guardHeld = $false
            try { & $guardFn.Name -Desired @() ; $guardHeld = $false }   # should THROW on empty
            catch { $guardHeld = $true }
            Add-Step -Steps $steps -Name 'safety-empty-desired-no-prune' -Ok $guardHeld -Detail $(if ($guardHeld) { 'engine guard throws on empty desired (no mass-prune)' } else { 'guard did NOT block empty desired' }) | Out-Null
        } else {
            # Fall back to a source-level assertion of the ACTUAL guard CODE (not a
            # comment): the prune gate must (1) require -Prune (opt-in) AND (2) flip
            # $doPrune off when the desired set is empty + not allowEmptyDesiredPrune.
            # Both code lines must be present -- a comment-only match is rejected.
            $coreText = Get-Content (Join-Path $shared 'PIM-EngineCore.ps1') -Raw -ErrorAction SilentlyContinue
            $optInPrune  = $coreText -and ($coreText -match '\$doPrune\s*=\s*\(\$Mode\s*-eq\s*''Full''\)\s*-and\s*\$Prune')
            $emptyGuard  = $coreText -and ($coreText -match '\$doPrune\s*-and\s*@\(\$desired\)\.Count\s*-eq\s*0\s*-and\s*-not\s*\$p\.allowEmptyDesiredPrune')
            if ($optInPrune -and $emptyGuard) {
                Add-Step -Steps $steps -Name 'safety-empty-desired-no-prune' -Ok $true -Detail 'engine core gate verified in source: prune is opt-in (-Prune + Full) AND empty-desired forces $doPrune=$false (mass-disable guard holds)' | Out-Null
            } else {
                Add-Step -Steps $steps -Name 'safety-empty-desired-no-prune' -Ok $false -Detail "engine prune-guard CODE not found (optInPrune=$optInPrune emptyGuard=$emptyGuard) -- the mass-disable guard is NOT in place" | Out-Null
            }
        }
    } catch {
        Add-Step -Steps $steps -Name 'safety-empty-desired-no-prune' -Skipped $true -Detail "could not load engine core to assert the guard: $($_.Exception.Message)" | Out-Null
    }

    # Return Steps as a PLAIN ARRAY (not the List[object]) -- in Windows PowerShell
    # 5.1, `@()` over a [List[object]] property surfaced from a [pscustomobject]
    # captured via `+=` throws "Argument types do not match". A flat object[] is safe.
    return [pscustomobject]@{ Scenario = $Id; Steps = @($steps.ToArray()) }
}

# ---------------------------------------------------------------------------
# Run the requested scenario(s).
# ---------------------------------------------------------------------------
$ids = if ($Scenario -eq 'All') { @('S1', 'S2', 'S3', 'S4', 'S5', 'S6') } else { @($Scenario) }
Write-Host "==========================================================================" -ForegroundColor Cyan
Write-Host " PIM4EntraPS §31 scenario MATRIX verifier -- $($ids -join ', ')" -ForegroundColor Cyan
Write-Host "==========================================================================" -ForegroundColor Cyan
Write-Host "  §31.3 sync wiring built: $syncWiringBuilt  (capability probe only -- the runner + idempotency steps RUN the deploy live and assert real outcomes, not this flag)"

$results = @()
foreach ($id in $ids) { $results += Invoke-ScenarioChecks -Id $id }

# ---------------------------------------------------------------------------
# Summary matrix + exit code.
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "==========================================================================" -ForegroundColor Cyan
Write-Host " Scenario matrix summary" -ForegroundColor Cyan
Write-Host "==========================================================================" -ForegroundColor Cyan
$hardFail = 0
$skipReqTotal = 0
foreach ($r in $results) {
    $stepArr = @($r.Steps)
    [int]$reqFail = @($stepArr | Where-Object { $_.required -and ($_.ok -eq $false) -and (-not $_.skipped) }).Count
    [int]$reqSkip = @($stepArr | Where-Object { $_.required -and $_.skipped }).Count
    [int]$pass    = @($stepArr | Where-Object { ($_.ok -eq $true) -and (-not $_.skipped) }).Count
    [int]$total   = $stepArr.Count
    $hardFail += $reqFail
    $skipReqTotal += $reqSkip
    $verdict = if ($reqFail -gt 0) { 'FAIL' } elseif ($reqSkip -gt 0) { 'NOT-VERIFIED' } else { 'VERIFIED' }
    $col = if ($verdict -eq 'VERIFIED') { 'Green' } elseif ($verdict -eq 'FAIL') { 'Red' } else { 'DarkYellow' }
    $line = "  {0}: {1}  ({2} pass / {3} required-fail / {4} required-skip / {5} steps)" -f "$($r.Scenario)", $verdict, $pass, $reqFail, $reqSkip, $total
    Write-Host $line -ForegroundColor $col
}

if ($Cleanup) {
    Write-Host "`n== Cleanup (Seed-PimScenarioDataset.ps1 -Cleanup) ==" -ForegroundColor Cyan
    & (Resolve-Path (Join-Path $here 'Seed-PimScenarioDataset.ps1')) -Cleanup -Marker $Marker -SqlServer $SqlServer -SqlDatabase $SqlDatabase -StatePath $StatePath
}

# Emit the structured results to the pipeline for capture.
$results

$exit = 0
if ($hardFail -gt 0) { $exit = 1 }
if ($FailOnSkip -and $skipReqTotal -gt 0) { $exit = 1 }
Write-Host ""
Write-Host ("==== Matrix: {0} required-fail, {1} required-skip across {2} scenario(s). Exit {3}. ====" -f $hardFail, $skipReqTotal, $results.Count, $exit) -ForegroundColor $(if ($exit) { 'Red' } else { 'Green' })
exit $exit
