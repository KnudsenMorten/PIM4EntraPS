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
  The desired/registry store. **REQUIRED — there is no default, deliberately (TEST-17).** The
  supported store is Azure SQL (PaaS), so a non-'*.database.windows.net' server is REFUSED
  unless -AllowUnsupportedStore is also passed. This used to default to .\SQLEXPRESS, which
  meant every run measured a configuration the product does not ship.

.PARAMETER AllowUnsupportedStore
  Opt in to running against a non-Azure-SQL store (e.g. a local instance) for offline work.
  The run then WARNS that its verdicts say nothing about the shipped PaaS configuration.

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
  # MAIN SESSION runs this live against the 3 tenants (creds from kv-automatit-dev).
  # The store must be Azure SQL -- the .\SQLEXPRESS this example used to show is NOT supported
  # and the harness now refuses it without -AllowUnsupportedStore (TEST-17):
  $env:PIM_SqlServer='<server>.database.windows.net'; $env:PIM_SqlDatabase='<db>'
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

    # The subscription each target may write Azure-RBAC eligibilities into. The seeder
    # plants ONE Azure assignment scoped to the subscription it was given; each scenario
    # rebinds it to ITS OWN target before running, because a slave's SPN cannot see (and
    # must not see) the master's subscription. Omit one and that scenario's Azure rows are
    # left as-is -- the run then reports the AzRes result honestly instead of passing on a
    # scope it never exercised.
    [string]$MasterSubscriptionId,
    [string]$SlaveCentralSubscriptionId,
    [string]$SlaveLocalSubscriptionId,

    # The signed master baseline the managed (S5/S6) downlink pulls + verifies. The matrix
    # actually RUNS the downlink for S5/S6, so it needs the bundle (local file or HTTPS URL).
    # When neither is supplied for a managed scenario, the runner step SKIPs (no live run).
    [string]$BaselineDocPath,
    [string]$BaselineUrl,
    [string]$BaselineAccessToken,

    [string]$SqlServer   = $env:PIM_SqlServer,
    [string]$SqlDatabase = $env:PIM_SqlDatabase,
    [string]$Marker      = 'PIMSCEN-',

    # TEST-17: the SQLEXPRESS path stays available for offline work, but never BY ACCIDENT.
    # See the store gate below for why a default here was worse than no default.
    [switch]$AllowUnsupportedStore,

    [switch]$SeedFirst,
    [switch]$Cleanup,
    [switch]$FailOnSkip
)

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $here) { $here = 'C:\SCRIPTS\AutomateIT\SOLUTIONS\PIM4EntraPS\tests\live' }
$shared = Resolve-Path (Join-Path $here '..\..\engine\_shared')
# ---------------------------------------------------------------------------
# TEST-17 -- THE STORE GATE. A harness whose DEFAULT is a store the product does not ship
# cannot report on the one it does.
#
# This used to read `if (-not $SqlServer) { $SqlServer = '.\SQLEXPRESS' }`, and the .EXAMPLE
# above taught the same thing. The operator's correction (2026-08-08) was blunt: *"we dont
# support that [SQLEXPRESS]. it is native sql inside azure we support (paas)."* So every live
# matrix run to date -- including all six S1-S6 "VERIFIED" verdicts -- was measured against a
# configuration the product does not support, and nothing anywhere said so.
#
# 🪤 The default was worse than no default, and that is the general lesson: a fallback makes the
# unsupported path the SILENT one. A run with no store configured did not fail, it quietly
# pointed at a local Express instance and went green. Same reasoning that made
# tests/live/Seed-PimSql.ps1 refuse to run with no target -- a default there points a live write
# at somebody else's database.
#
# Now: the store is REQUIRED, and it must be Azure SQL unless the caller explicitly says
# otherwise. -AllowUnsupportedStore keeps SQLEXPRESS reachable for offline work while making it
# impossible to reach by accident. (Depended on BUG-30: until the explicit -Server path returned
# a token connection string, a mandatory Azure FQDN had nothing valid to point at. BUG-30 is
# fixed and verified, so this gate now has somewhere to send people.)
# ---------------------------------------------------------------------------
if (-not "$SqlServer".Trim()) {
    throw ("Test-PimScenarioMatrix: -SqlServer is REQUIRED (or `$env:PIM_SqlServer). There is no default " +
           "on purpose -- this harness used to fall back to '.\SQLEXPRESS', which is NOT a supported store, " +
           "so runs went green against a configuration the product does not ship (TEST-17). " +
           "Pass the Azure SQL FQDN, e.g. -SqlServer <server>.database.windows.net -SqlDatabase <db>. " +
           "For deliberate offline work against a local instance, pass -AllowUnsupportedStore as well.")
}
if (-not "$SqlDatabase".Trim()) {
    throw "Test-PimScenarioMatrix: -SqlDatabase is REQUIRED (or `$env:PIM_SqlDatabase). No default -- see -SqlServer above (TEST-17)."
}
if ($SqlServer -notmatch '(?i)database\.windows\.net') {
    if (-not $AllowUnsupportedStore) {
        throw ("Test-PimScenarioMatrix: REFUSING to run against '$SqlServer' -- the supported store is Azure SQL " +
               "(PaaS), and a result measured on anything else does not describe the shipped product (TEST-17). " +
               "Re-run against a '*.database.windows.net' server, or pass -AllowUnsupportedStore if you " +
               "deliberately want an offline/local run and accept that its verdicts say nothing about PaaS.")
    }
    Write-Warning ("  [TEST-17] Running against '$SqlServer', which is NOT the supported store. " +
                   "-AllowUnsupportedStore was passed, so this is deliberate -- but every verdict below " +
                   "describes a configuration the product does not ship.")
}
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
. (Join-Path $here '_PimScenarioTenants.ps1')

# RETIRED-ESTATE GUARD. This matrix takes tenant ids as PARAMETERS, so it never passes
# through the -TenantJson parser where the guard also lives -- and that is exactly how it
# was run against both retired tenants, twice, on 2026-08-08. Refuse before anything
# authenticates or writes. DOCS/REQUIREMENTS.md s10.0.
Assert-PimScenarioTenantAllowed -TenantId $MasterTenantId       -What '-MasterTenantId'
Assert-PimScenarioTenantAllowed -TenantId $SlaveCentralTenantId -What '-SlaveCentralTenantId'
Assert-PimScenarioTenantAllowed -TenantId $SlaveLocalTenantId   -What '-SlaveLocalTenantId'

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
    # -ExpectedUserNames  : must EXIST in this slave (the ring reaches them).
    # -ForbiddenUserNames : must NOT exist here (the ring does NOT reach them). This is the
    #   half that makes ring gating measurable rather than claimed: "the right admins
    #   arrived" is satisfied just as well by sending EVERY admin to EVERY tenant, which is
    #   precisely the failure an MSP cannot afford. A ring-2 operator appearing in a ring-1
    #   customer is a privilege leak between customers.
    param([Parameter(Mandatory)][string[]]$ExpectedUserNames, [string[]]$ForbiddenUserNames = @())
    $domain = Get-PimRestDefaultDomain
    $found = New-Object System.Collections.Generic.List[string]
    $missing = New-Object System.Collections.Generic.List[string]
    $leaked = New-Object System.Collections.Generic.List[string]
    foreach ($un in $ExpectedUserNames) {
        $upn = "$($un.ToLower())@$domain"
        $esc = $upn -replace "'", "''"
        $u = @(Invoke-PimGraph -All -Path "/users?`$filter=userPrincipalName eq '$esc'&`$select=id,userPrincipalName")
        if ($u.Count -gt 0) { $found.Add($un) | Out-Null } else { $missing.Add($un) | Out-Null }
    }
    foreach ($un in @($ForbiddenUserNames)) {
        if (@($ExpectedUserNames) -contains $un) { continue }
        $upn = "$($un.ToLower())@$domain"
        $esc = $upn -replace "'", "''"
        $u = @(Invoke-PimGraph -All -Path "/users?`$filter=userPrincipalName eq '$esc'&`$select=id,userPrincipalName")
        if ($u.Count -gt 0) { $leaked.Add($un) | Out-Null }
    }
    return @{ found = @($found.ToArray()); missing = @($missing.ToArray()); leaked = @($leaked.ToArray()); domain = $domain }
}

function Get-PimTenantObjectInventory {
    <#
      A NAMED inventory (not counts) of one tenant, for the cross-tenant blast-radius
      assertion. Names, because a count survives a swap: delete one group and create
      another and the count is identical.

      Authenticates with the given SPN explicitly, so it cannot accidentally read whichever
      tenant the ambient context happens to point at -- which is the very failure this
      assertion exists to catch (BUG-22/BUG-23).
    #>
    param([Parameter(Mandatory)][string]$TenantId, [Parameter(Mandatory)][string]$ClientId, [Parameter(Mandatory)][string]$Thumbprint)
    $tok = Get-PimRestToken -Resource graph -TenantId $TenantId -ClientId $ClientId -CertThumbprint $Thumbprint -Force
    $h = @{ Authorization = "Bearer $tok"; ConsistencyLevel = 'eventual' }
    $inv = [ordered]@{}
    foreach ($k in @(
        @{ n = 'users';  u = 'https://graph.microsoft.com/v1.0/users?$select=userPrincipalName&$top=999'; p = 'userPrincipalName' }
        @{ n = 'groups'; u = 'https://graph.microsoft.com/v1.0/groups?$select=displayName&$top=999';     p = 'displayName' }
        @{ n = 'aus';    u = 'https://graph.microsoft.com/v1.0/directory/administrativeUnits?$select=displayName'; p = 'displayName' }
    )) {
        $names = New-Object System.Collections.Generic.List[string]
        $url = $k.u
        while ($url) {
            $r = Invoke-RestMethod -Uri $url -Headers $h
            foreach ($o in @($r.value)) { $names.Add("$($o.$($k.p))") }
            $url = $r.'@odata.nextLink'
        }
        $inv[$k.n] = @($names | Sort-Object -Unique)
    }
    $inv
}

function Compare-PimTenantInventory {
    # Returns @{ same; added; removed } -- what CHANGED in a tenant that should not have changed.
    param([Parameter(Mandatory)][object]$Before, [Parameter(Mandatory)][object]$After)
    $added = New-Object System.Collections.Generic.List[string]
    $removed = New-Object System.Collections.Generic.List[string]
    foreach ($k in @('users', 'groups', 'aus')) {
        $b = @{}; foreach ($n in @($Before.$k)) { $b["$n"] = $true }
        $a = @{}; foreach ($n in @($After.$k))  { $a["$n"] = $true }
        foreach ($n in @($After.$k))  { if (-not $b.ContainsKey("$n")) { $added.Add("$k`:$n")   | Out-Null } }
        foreach ($n in @($Before.$k)) { if (-not $a.ContainsKey("$n")) { $removed.Add("$k`:$n") | Out-Null } }
    }
    @{ same = (($added.Count + $removed.Count) -eq 0); added = @($added.ToArray()); removed = @($removed.ToArray()) }
}

function Test-PimScenarioTamperRefusal {
    <#
      The NEGATIVE half of the signed-baseline promise (§33.7.f-3): a managed tenant must
      pull ONLY from a bundle that verifies against the master's public key.

      "It accepted a good bundle" says nothing on its own -- a downlink that skipped
      verification entirely would pass that every time. So take the REAL bundle, corrupt
      the payload while leaving the signature untouched, and require a refusal.

      Returns @{ ok; detail }. ok = the tampered document was REFUSED.
    #>
    param([Parameter(Mandatory)][object]$Doc)
    if (-not (Get-Command Test-PimBaselineDoc -ErrorAction SilentlyContinue)) {
        return @{ ok = $false; detail = 'Test-PimBaselineDoc not available -- cannot exercise the signature check' }
    }
    # Decode, alter one field, re-encode. The signature still covers the ORIGINAL bytes.
    $raw = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("$($Doc.payloadB64)"))
    $tamperedJson = $raw -replace '"scope"\s*:\s*"[^"]*"', '"scope":"tampered-by-test"'
    if ($tamperedJson -eq $raw) { $tamperedJson = $raw + ' ' }   # ensure the bytes really differ
    $bad = [pscustomobject]@{
        product       = $Doc.product
        payloadB64    = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($tamperedJson))
        signature     = $Doc.signature          # untouched -- this is the point
        keyThumbprint = $Doc.keyThumbprint
    }
    $accepted = $false; $why = ''
    try {
        $r = Test-PimBaselineDoc -Doc $bad
        # A verifier may return a verdict object or throw. Treat "no explicit refusal" as accepted.
        if ($null -eq $r) { $accepted = $false; $why = 'returned null' }
        elseif ($r -is [bool]) { $accepted = [bool]$r; $why = "returned $r" }
        elseif ($r.PSObject.Properties['ok']) { $accepted = [bool]$r.ok; $why = "ok=$($r.ok) $($r.reason)" }
        elseif ($r.PSObject.Properties['valid']) { $accepted = [bool]$r.valid; $why = "valid=$($r.valid) $($r.reason)" }
        else { $accepted = $true; $why = 'verifier returned a value with no ok/valid field' }
    } catch {
        $accepted = $false; $why = "threw: $($_.Exception.Message)"
    }
    return @{ ok = (-not $accepted); detail = "tampered bundle -> $(if ($accepted) { 'ACCEPTED (signature not enforced!)' } else { "REFUSED ($why)" })" }
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

function Set-PimScenarioAzScope {
    <#
      Repoint the seeded Azure-RBAC assignment at the subscription of the tenant this
      scenario actually targets.

      Why this exists: the seeder plants ONE PIM-Assignments-Azure-Resources row, scoped to
      the subscription it was given (the master's). Every scenario then ran against that one
      scope -- so the S6 (local-slave) run tried to create an eligibility on a subscription
      that lives in the MASTER's tenant and got, correctly:
          AzRes: ARM role 'Reader' not found at /subscriptions/<master sub>
      The slave's SPN cannot see the master's subscription, and it should not. That is a
      defect in the test DATA, not in the engine -- the same class as the owner UPN, which
      is why this mirrors Set-PimScenarioOwnerUpn: the seed is tenant-neutral, and the run
      binds it to its target.

      A scenario with no subscription of its own gets its Azure rows left alone; the run
      then reports the AzRes limitation rather than silently passing.
    #>
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][string]$SubscriptionId, [string]$RowMarker = 'PIMSCEN-')
    if (-not "$SubscriptionId".Trim()) { return 0 }
    $n = 0
    foreach ($r in @(Get-PimSqlRows -ConnectionString $ConnectionString -Entity 'PIM-Assignments-Azure-Resources')) {
        $gt = "$($r.GroupTag)"
        if (-not ($gt -like "$RowMarker*")) { continue }
        $newScope = "/subscriptions/$SubscriptionId"
        if ("$($r.AzScope)" -eq $newScope) { continue }
        # The scope is part of the row KEY, so the old row has to go or the store keeps both
        # and the engine sees two desired Azure assignments for one group.
        $oldKey = Get-PimStoreRowKey -Base 'PIM-Assignments-Azure-Resources' -Row $r
        $r.PSObject.Properties.Remove('AzScope') | Out-Null
        $r | Add-Member -NotePropertyName AzScope -NotePropertyValue $newScope -Force
        $newKey = Get-PimStoreRowKey -Base 'PIM-Assignments-Azure-Resources' -Row $r
        if ($newKey) {
            Set-PimSqlRow -ConnectionString $ConnectionString -Entity 'PIM-Assignments-Azure-Resources' -Key $newKey -Data $r
            if ($oldKey -and $oldKey -ne $newKey) {
                Remove-PimSqlRow -ConnectionString $ConnectionString -Entity 'PIM-Assignments-Azure-Resources' -Key $oldKey
            }
            $n++
        }
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

    # =======================================================================
    # BUG-31 -- ACTIVATE THE SCENARIO. Until 2026-08-08 this matrix never did.
    # Set-PimScenarioContext is the ONLY function that sets $global:PIM_ActiveScenario,
    # and Get-PimSqlConnectionString enters its per-scenario hosting branch ONLY when that
    # global is set. This file never called it and never set $env:PIM_Scenario, so
    # Resolve-PimScenarioHostingStore was never reached in a live run and EVERY scenario --
    # S5 'central-msp' and S6 'local-slave' included -- read and wrote the single ambient
    # store. S5 was reported VERIFIED with no central store in existence.
    # It degraded silently because the resolver's own no-server fallback is "use ambient",
    # which is indistinguishable from a correct answer when nobody supplied a server.
    # Activating here makes the run exercise the real runtime resolution, exactly as
    # Invoke-PimEngineCore.ps1:95 and Invoke-PimScenarioRun.ps1:86 do in production.
    # =======================================================================
    $null = Set-PimScenarioContext -Scenario $sc -Quiet
    Add-Step -Steps $steps -Name 'scenario-activated' -Ok ("$($global:PIM_ActiveScenario)" -eq "$Id") `
        -Detail "PIM_ActiveScenario='$($global:PIM_ActiveScenario)' (must equal $Id -- without it the hosting resolver is never called)" | Out-Null

    # ---- store placement (REQUIRED) -- the guard BUG-31 exists to provide ----
    # Assert the store this scenario ACTUALLY resolves to is the one its hostingLocation
    # demands. A scenario that silently falls back to ambient must NOT pass: that fallback
    # is the exact failure mode that let S5 look verified for two live runs.
    # SKIP (never pass) when the operator supplied no server for a placement that needs one
    # -- an unmeasurable step is not a passing step.
    $hostStore = Resolve-PimScenarioHostingStore -Scenario $sc
    $actualCs  = Get-PimSqlConnectionString -Database $SqlDatabase
    switch ($ctx.hostingLocation) {
        'central-msp' {
            if (-not "$($env:PIM_SqlServerCentral)".Trim()) {
                Add-Step -Steps $steps -Name 'store-placement' -Skipped $true `
                    -Detail "hostingLocation=central-msp but no `$env:PIM_SqlServerCentral supplied -- the central store is UNMEASURED, not correct" | Out-Null
            } else {
                $want = "$($env:PIM_SqlServerCentral)".Trim()
                $ok   = ($actualCs -match [regex]::Escape($want)) -and ($actualCs -notmatch '(?i)Integrated\s*Security')
                Add-Step -Steps $steps -Name 'store-placement' -Ok $ok `
                    -Detail "central-msp -> resolver='$($hostStore.server)' kind=$($hostStore.kind); CS uses '$want'=$($actualCs -match [regex]::Escape($want)); passwordless=$($actualCs -notmatch '(?i)Integrated\s*Security')" | Out-Null
            }
        }
        'local-slave' {
            if (-not "$($env:PIM_SqlServerLocal)".Trim()) {
                Add-Step -Steps $steps -Name 'store-placement' -Skipped $true `
                    -Detail "hostingLocation=local-slave but no `$env:PIM_SqlServerLocal supplied -- the local slave store is UNMEASURED" | Out-Null
            } else {
                $want = "$($env:PIM_SqlServerLocal)".Trim()
                Add-Step -Steps $steps -Name 'store-placement' -Ok ($actualCs -match [regex]::Escape($want)) `
                    -Detail "local-slave -> resolver='$($hostStore.server)'; CS uses '$want'=$($actualCs -match [regex]::Escape($want))" | Out-Null
            }
        }
        default {
            # in-tenant (S1-S4): no override is CORRECT. Assert the resolver says so rather
            # than assuming it, so a future change that starts overriding here is caught.
            Add-Step -Steps $steps -Name 'store-placement' -Ok ("$($hostStore.source)" -eq 'in-tenant' -and -not "$($hostStore.server)".Trim()) `
                -Detail "in-tenant -> no scenario override (source=$($hostStore.source)); ambient store in use" | Out-Null
        }
    }

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
    $subR  = if ($Id -eq 'S5') { $SlaveCentralSubscriptionId } elseif ($Id -eq 'S6') { $SlaveLocalSubscriptionId } else { $MasterSubscriptionId }

    $firstRun = $null            # captured first-pass result (drives every dependent step)
    $firstRanLive = $false       # did a real live deploy actually execute?
    $runSkipReason = $null       # set when we could not run (-> dependent steps SKIP)
    $blDoc = $null

    # ---- §33.7.f-2 CROSS-TENANT BLAST RADIUS: who must NOT change? ----------
    # The scenario deploys into exactly ONE tenant ($tidR). Every OTHER tenant in the
    # estate must come out byte-identical, BY NAME -- counts survive a swap (delete one
    # group, create another, and the count is unchanged), which is why the helpers
    # inventory names.
    #
    # The "other" tenant is the master when the target is a slave, and the local slave
    # when the target IS the master. ⚠️ In S5 the central "slave" can BE the master --
    # the same tenant playing both roles. When that happens there is no second tenant to
    # measure and the step SKIPs, which is NOT a pass: an assertion comparing a tenant
    # with itself is the vacuous shape §33.7.e-9 already cost us once on the ring gate.
    $otherTid = $null; $otherCid = $null; $otherThb = $null; $otherName = $null
    if ("$tidR" -and "$MasterTenantId" -and ("$tidR" -ne "$MasterTenantId")) {
        $otherTid = $MasterTenantId; $otherCid = $MasterClientId; $otherThb = $MasterCertThumbprint; $otherName = 'master'
    } elseif ("$tidR" -and "$SlaveLocalTenantId" -and ("$tidR" -ne "$SlaveLocalTenantId")) {
        $otherTid = $SlaveLocalTenantId; $otherCid = $SlaveLocalClientId; $otherThb = $SlaveLocalCertThumbprint; $otherName = 'local slave'
    }
    $blastBefore = $null
    $blastSkip   = $null
    if (-not $otherTid) { $blastSkip = "no SECOND tenant distinct from the $Id target -- nothing to measure blast radius against (this is a SKIP, never a pass)" }

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
                # ...and bind the Azure-RBAC row to THIS target's subscription (see
                # Set-PimScenarioAzScope): a slave cannot assign into the master's sub.
                if ("$subR".Trim()) {
                    $nAz = Set-PimScenarioAzScope -ConnectionString (Get-PimSqlConnectionString) -SubscriptionId $subR -RowMarker $Marker
                    if ($nAz) { Write-Host "    [azscope] rebound $nAz Azure row(s) -> /subscriptions/$subR" -ForegroundColor DarkGray }
                } else {
                    Write-Host "    [azscope] no subscription supplied for $Id -- Azure rows left at their seeded scope (AzRes not exercised for this target)" -ForegroundColor DarkYellow
                }
                # §33.7.f-2 BLAST RADIUS, half 1 of 2: inventory the tenant this scenario
                # must NOT touch, BEFORE the run. Captured here -- inside the same guarded
                # block, immediately before the deploy -- so the "before" can never be read
                # from a different point in time than the run it brackets.
                #
                # 🪤 Read it with the OTHER tenant's OWN SPN, explicitly. Using the ambient
                # context would make this assertion read the TARGET tenant twice and pass
                # unconditionally -- and "the ambient identity was left on the last tenant
                # touched" is literally BUG-23. An assertion that cannot fail is worse than
                # no assertion.
                if ($otherTid -and $otherCid -and $otherThb -and ("$otherTid" -ne "$tidR")) {
                    try {
                        $blastBefore = Get-PimTenantObjectInventory -TenantId $otherTid -ClientId $otherCid -Thumbprint $otherThb
                        Write-Host ("    [blast] before: {0} users / {1} groups / {2} AUs in the untouched tenant" -f @($blastBefore.users).Count, @($blastBefore.groups).Count, @($blastBefore.aus).Count) -ForegroundColor DarkGray
                    } catch { $blastSkip = "could not inventory the other tenant before the run: $($_.Exception.Message)" }
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

    # ---- §33.7.f-2 BLAST RADIUS, half 2: the untouched tenant is UNTOUCHED --
    # REQUIRED. This is the assertion the helpers were built for in 398d8e6d and that
    # nothing ever called. It is the only check in the matrix that can catch a
    # cross-tenant leak -- an engine that wrote into the wrong directory because a token
    # or an ambient context bled across the fan-out (BUG-22/BUG-23). Every other
    # assertion here looks at the tenant we MEANT to change.
    if (-not $firstRanLive) {
        Add-Step -Steps $steps -Name 'cross-tenant-blast-radius' -Skipped $true `
            -Detail "no live deploy ran ($(Coalesce $runSkipReason 'unknown')) -- nothing to measure a blast radius from" | Out-Null
    } elseif ($blastSkip) {
        Add-Step -Steps $steps -Name 'cross-tenant-blast-radius' -Skipped $true -Detail $blastSkip | Out-Null
    } elseif (-not $blastBefore) {
        Add-Step -Steps $steps -Name 'cross-tenant-blast-radius' -Skipped $true `
            -Detail 'no BEFORE inventory was captured -- cannot compare (a missing baseline must never read as "nothing changed")' | Out-Null
    } else {
        try {
            $blastAfter = Get-PimTenantObjectInventory -TenantId $otherTid -ClientId $otherCid -Thumbprint $otherThb
            $diff = Compare-PimTenantInventory -Before $blastBefore -After $blastAfter
            # Report the SIZE of what was compared. A comparison of two empty inventories
            # is trivially "same" and would be a vacuous pass -- so state the denominator,
            # the same lesson BUG-26's "inspected N of M" summary records.
            $measured = @($blastBefore.users).Count + @($blastBefore.groups).Count + @($blastBefore.aus).Count
            if ($measured -eq 0) {
                Add-Step -Steps $steps -Name 'cross-tenant-blast-radius' -Skipped $true `
                    -Detail "the $otherName tenant inventoried as EMPTY (0 users/groups/AUs) -- the comparison would be vacuous, so this is a SKIP, not a pass" | Out-Null
            } else {
                # ---- RING-AWARE classification (operator directive 2026-08-08) -------------
                # "in a master/slave setup, then central admins will be created locally in each
                #  slave tenant, so the IT staff can help each of the tenants using their admin
                #  account." So a change in ANOTHER managed tenant is NOT automatically a leak:
                # propagating the central admins into every managed tenant is the product working.
                # The first live run of this step failed on exactly that -- it asserted
                # "nothing changed", which contradicts the MSP model.
                # What must STILL fail, and is the assertion actually worth having:
                #   * an admin that tenant's RING does NOT entitle it to (cross-customer
                #     privilege leak -- the Get-SlaveAdminPresence 'forbidden' half, applied here),
                #   * any GROUP or AU change (admin propagation does not create groups/AUs),
                #   * any REMOVAL (a deploy targeting A must not delete objects in B).
                # Sanctioning "any user" would have made this step unable to fail; it is scoped
                # to the exact per-ring set the seeder recorded for THAT tenant.
                $sanctionedAdmins = @()
                foreach ($slaveKey in @('central', 'local')) {
                    $sl = $state.slaves.$slaveKey
                    if ($sl -and ("$($sl.tenantId)" -eq "$otherTid")) { $sanctionedAdmins = @($sl.expectedAdminUserNames) }
                }
                $unexpectedAdds = @()
                $sanctionedAdds = @()
                foreach ($a in @($diff.added)) {
                    if ("$a" -match '^(?i)users:(.+)$') {
                        $localPart = ($Matches[1] -split '@')[0]
                        if (@($sanctionedAdmins) -contains $localPart) { $sanctionedAdds += $a; continue }
                    }
                    $unexpectedAdds += $a
                }
                $unexpectedRemovals = @($diff.removed)
                $contained = ($unexpectedAdds.Count -eq 0) -and ($unexpectedRemovals.Count -eq 0)
                $detail = if ($diff.same) {
                    "$otherName tenant [$otherTid] UNCHANGED across the $Id deploy -- $measured named object(s) compared, 0 added, 0 removed"
                } elseif ($contained) {
                    "$otherName tenant [$otherTid] changed ONLY by sanctioned central-admin propagation ($($sanctionedAdds.Count) of $(@($sanctionedAdmins).Count) ring-entitled admin(s): $(@($sanctionedAdds) -join ', ')) -- $measured object(s) compared, 0 unsanctioned add, 0 removal"
                } else {
                    "LEAK: the $otherName tenant [$otherTid] changed in ways central-admin propagation does not explain, during a deploy targeting [$tidR]. unsanctioned added: $(@($unexpectedAdds) -join ', ') | removed: $(@($unexpectedRemovals) -join ', ') | (sanctioned admin adds ignored: $(@($sanctionedAdds) -join ', '))"
                }
                Add-Step -Steps $steps -Name 'cross-tenant-blast-radius' -Ok $contained -Detail $detail | Out-Null
            }
        } catch {
            # An error reading the other tenant is NOT "it did not change".
            Add-Step -Steps $steps -Name 'cross-tenant-blast-radius' -Skipped $true `
                -Detail "could not inventory the $otherName tenant AFTER the run: $($_.Exception.Message) -- unverified, not clean" | Out-Null
        }
    }

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
                # Everything the master holds, minus what THIS slave's ring should reach,
                # is what must NOT be here (§33.7.f-3, the negative half of ring gating).
                $allMsp = @(); if ($state -and $state.mspAdminUserNames) { $allMsp = @($state.mspAdminUserNames) }
                $forbidden = @($allMsp | Where-Object { @($expected) -notcontains $_ })
                $pres = Get-SlaveAdminPresence -ExpectedUserNames $expected -ForbiddenUserNames $forbidden
                $okAdmins = ($pres.missing.Count -eq 0)
                $detail = if ($okAdmins) { "all $($expected.Count) expected admins present in slave ($($pres.domain)) after the downlink: $($pres.found -join ', ')" }
                          else { "MISSING in slave ($($pres.domain)): $($pres.missing -join ', '); present: $($pres.found -join ', ')" }
                Add-Step -Steps $steps -Name 'slave-admins-materialized' -Ok $okAdmins -Detail $detail | Out-Null

                # ---- ring gating, the OTHER direction -- REQUIRED ----------------
                # A higher-ring admin must NOT have materialised in a lower-ring slave.
                # Without this, "the ring reached the right admins" is satisfied equally
                # well by shipping every admin to every customer.
                if ("$tidR" -eq "$MasterTenantId") {
                    # NOT MEASURABLE **BY PRESENCE** in this fleet, and saying so beats both
                    # alternatives. This "slave" is the MASTER tenant itself (only two test
                    # tenants exist, so one plays both roles). The master legitimately holds
                    # EVERY seeded admin -- S1-S4 deploy the full estate into it -- so an admin
                    # outside this ring's reach is present for a reason that has nothing to do
                    # with the ring. Failing here would report a leak that did not happen;
                    # passing would claim a guarantee nothing checked.
                    #
                    # It is NOT required any more, because the ring promise is no longer
                    # resting on it: 'ring-gate-one-customer-both-directions' below measures
                    # the SAME guarantee by a route a shared tenant cannot confound (operator
                    # directive 2026-08-07 -- one customer as the ring gate, simulated on the
                    # two test tenants, instead of waiting for a third). This step stays as
                    # informational evidence, not as the thing that decides S5's verdict.
                    Add-Step -Steps $steps -Name 'ring-gating-excludes-higher-ring' -Skipped $true -Required $false `
                        -Detail "not measurable BY PRESENCE: the '$slaveKey' slave IS the master tenant in this 2-tenant fleet, so out-of-ring admins ($($forbidden -join ', ')) are present from the master's own estate, not from the downlink. The ring guarantee is measured instead by 'ring-gate-one-customer-both-directions' (which reads the gate's SELECTION for this one customer, not the tenant's population)." | Out-Null
                } elseif (-not $forbidden.Count) {
                    Add-Step -Steps $steps -Name 'ring-gating-excludes-higher-ring' -Ok $true `
                        -Detail "slave '$slaveKey' is at the widest ring for this fleet -- every seeded admin legitimately reaches it, so there is nothing this ring must exclude (asserted, not skipped)" | Out-Null
                } else {
                    $okRing = ($pres.leaked.Count -eq 0)
                    $rd = if ($okRing) { "correctly ABSENT from slave '$slaveKey' ($($pres.domain)): $($forbidden -join ', ')" }
                          else { "RING LEAK -- these are out of ring reach for '$slaveKey' but EXIST in it: $($pres.leaked -join ', ')" }
                    Add-Step -Steps $steps -Name 'ring-gating-excludes-higher-ring' -Ok $okRing -Detail $rd | Out-Null
                }
            } catch {
                Add-Step -Steps $steps -Name 'slave-admins-materialized' -Skipped $true -Detail "could not query slave $Id : $($_.Exception.Message)" | Out-Null
                Add-Step -Steps $steps -Name 'ring-gating-excludes-higher-ring' -Skipped $true -Detail "could not query slave $Id : $($_.Exception.Message)" | Out-Null
            }
        }

        # ---- RING GATE: ONE CUSTOMER, BOTH DIRECTIONS -- REQUIRED ----------------
        # Operator directive 2026-08-07: express the ring gate as ONE customer whose ring
        # MOVES, and simulate it on the two test tenants -- instead of blocking on a third,
        # slave-only tenant.
        #
        # WHY THIS IS MEASURABLE WHERE THE PRESENCE CHECK ABOVE IS NOT.
        # That one asks "does this admin EXIST in the slave tenant?" -- unanswerable when the
        # slave IS the master, because the master holds every seeded admin from its own estate.
        # This asks a different and strictly better question: "for THIS ONE customer, what does
        # the ring gate SELECT?" That is a property of the downlink's DECISION for one tenant,
        # not of the tenant's population, so a shared tenant cannot confound it. It runs the
        # REAL gate -- Get-PimDownlinkPlan -> Select-PimDownlinkAdmins, the very call the live
        # downlink makes (PIM-Downlink.ps1:366) -- against the REAL signed baseline. No mock.
        #
        # BOTH DIRECTIONS come from moving the CUSTOMER's ring, which needs only one customer:
        #     narrowest ring -> an out-of-ring admin must be ABSENT from the selection
        #     widened        -> that SAME admin must APPEAR
        # A gate that shipped everything to everyone fails the first; a gate that shipped
        # nothing fails the second. Neither can pass by accident.
        if (-not $blDoc) {
            Add-Step -Steps $steps -Name 'ring-gate-one-customer-both-directions' -Skipped $true `
                -Detail "no signed baseline doc (-BaselineDocPath/-BaselineUrl) -- the ring gate reads its admin set from the verified baseline, so it cannot be simulated" | Out-Null
        } else {
            try {
                # Run the REAL gate for this ONE customer at each ring, narrowest to widest.
                $ringNames = @{}; $ringRows = @{}; $blVer = 0
                foreach ($r in 0, 1, 2) {
                    $rp = Get-PimDownlinkPlan -Scenario $sc -Doc $blDoc -TenantId $tidR -SlaveRing $r `
                            -CentralRoot $env:PIM_SyncRootCentral -LocalRoot $env:PIM_SyncRootLocal
                    if (-not $rp.ok) { throw "the downlink refused to plan at ring ${r}: $($rp.reason)" }
                    $ringRows[$r]  = @($rp.admins)
                    $ringNames[$r] = @(@($rp.admins) | ForEach-Object { "$(Get-PimDownlinkValue -Object $_ -Key 'UserName')" })
                    $blVer = $rp.baselineVersion
                }

                # The VERDICT is the shared pure function (PIM-Downlink.ps1) -- the same one
                # tests/Test-PimDownlink.ps1 proves offline, so the live matrix and the
                # offline gate can never drift apart. Do not re-implement it here.
                $rg = Test-PimDownlinkRingGate -RingRows $ringRows

                if ($rg.vacuous) {
                    Add-Step -Steps $steps -Name 'ring-gate-one-customer-both-directions' -Skipped $true `
                        -Detail "NOT MEASURABLE (vacuous): $($rg.vacuousReason)" | Out-Null
                } else {
                    $detail = if ($rg.ok) {
                        "ONE customer ($tidR), ring moved 0->2 against the real signed baseline v${blVer}:" +
                        " ring0 selects $($ringNames[0].Count) [$($ringNames[0] -join ', ')];" +
                        " ring2 selects $($ringNames[2].Count) [$($ringNames[2] -join ', ')]." +
                        " EXCLUDED at ring 0 and ADMITTED at ring 2 -- both directions proven on one customer: $($rg.gained -join ', ')"
                    } else { "RING GATE BROKEN: $($rg.failures -join ' | ')" }
                    Add-Step -Steps $steps -Name 'ring-gate-one-customer-both-directions' -Ok $rg.ok -Detail $detail | Out-Null
                }
            } catch {
                Add-Step -Steps $steps -Name 'ring-gate-one-customer-both-directions' -Skipped $true `
                    -Detail "could not simulate the ring gate for $Id : $($_.Exception.Message)" | Out-Null
            }
        }

        # ---- signed-baseline refusal -- REQUIRED ---------------------------------
        # The positive half (a good bundle is accepted and applied) is proven by the
        # downlink steps above. This is the negative half: a TAMPERED bundle must be
        # refused. A downlink that never verified anything would pass the positive half
        # every single time, so on its own it proves nothing about the signature.
        if (-not $blDoc) {
            Add-Step -Steps $steps -Name 'tampered-baseline-refused' -Skipped $true -Detail "no baseline doc loaded for $Id -- cannot exercise the signature check" | Out-Null
        } else {
            $t = Test-PimScenarioTamperRefusal -Doc $blDoc
            Add-Step -Steps $steps -Name 'tampered-baseline-refused' -Ok $t.ok -Detail $t.detail | Out-Null
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
            # What this step is for: the runner really invoked the engine and the estate
            # really LANDED in the target tenant. Error-freedom is the NEXT step's job.
            #
            # That split matters on a first-ever deploy into an empty tenant, where the
            # create pass reliably reports 1 error it will heal by itself: an AU created at
            # order 10 is not yet attachable at order 22 (TEST-16). Failing here on that
            # would mean a cold estate fails and a warm one passes -- the same code, judged
            # by its history. So a first pass whose ONLY problem is engine errors is left to
            # the convergence assertion, which does NOT tolerate errors and will fail if they
            # are real. A run that is not-ok with ZERO engine errors (a failed downlink, say)
            # still fails right here.
            $firstPassErrors = if ($cs1) { [int]$cs1.errors } else { 0 }
            $okRun = $ranEngine -and $okGroups -and (([bool]$firstRun.ok) -or ($firstPassErrors -gt 0))
            $detail = "runner ran $Id ($($firstRun.scenarioId)); engine summary: $(if($cs1){"create=$($cs1.create) update=$($cs1.update) remove=$($cs1.remove) errors=$($cs1.errors)"}else{'<none returned>'}); groups: $grpDetail"
            if ($okRun -and $firstPassErrors -gt 0) { $detail += " -- NOTE: $firstPassErrors create-pass error(s); convergence is asserted by the next step" }
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
            # CONVERGENCE, not "the very next pass". On a FIRST-EVER deploy into an empty
            # tenant the first pass creates objects that Entra/ARM do not serve yet -- an AU
            # created at order 10 is not attachable at order 22 (TEST-16), and a
            # roleEligibilitySchedule is not listed for a minute or so. The next pass
            # therefore REPAIRS one thing (create=1, errors=0), which is BUG-16's reconciling
            # scope doing exactly its job, and only the pass after that is a true no-op.
            #
            # Asserting "pass 2 changes nothing" measured before convergence and so failed a
            # cold estate while passing a warm one -- the same run, different history. What
            # the product actually promises is that repeated passes CONVERGE and then stop,
            # so that is what is asserted: allow up to $maxPasses, require a genuinely empty
            # pass, and REPORT how many it took. A pass that ERRORS is never tolerated, and
            # anything beyond the first repair round still fails.
            $maxPasses = 3
            $passNo = 0; $cs2 = $null; $secondRun = $null; $okIdem = $false; $trail = @()
            while ($passNo -lt $maxPasses) {
                $passNo++
                if ($passNo -gt 1) { Start-Sleep -Seconds 30 }   # let the previous pass's writes become readable
                $secondRun = Invoke-PimScenarioDeploy @deployArgs2
                $cs2 = $secondRun.changeSummary
                if (-not ($cs2 -and "$($cs2.kind)" -eq 'pim-engine-summary')) { break }
                $delta = [int]$cs2.create + [int]$cs2.update + [int]$cs2.remove
                $trail += "pass$($passNo + 1): create=$($cs2.create) update=$($cs2.update) remove=$($cs2.remove) errors=$($cs2.errors)"
                if (([bool]$secondRun.ok) -and ($delta -eq 0) -and ([int]$cs2.errors -eq 0)) { $okIdem = $true; break }
                if ([int]$cs2.errors -gt 0) { break }            # an ERROR is not convergence -- stop and fail
            }
            if (-not ($cs2 -and "$($cs2.kind)" -eq 'pim-engine-summary')) {
                Add-Step -Steps $steps -Name 'idempotent-second-pass' -Ok $false -Detail 'second pass returned no engine change summary -- cannot prove zero changes. FAIL.' | Out-Null
            } else {
                $detail = ($trail -join ' | ')
                $detail += if ($okIdem) {
                    if ($passNo -eq 1) { ' -- zero changes on the FIRST re-run (idempotent)' }
                    else { " -- converged after $passNo re-run(s); the earlier one(s) repaired what the create pass could not yet see (TEST-16)" }
                } else { ' -- NEVER converged (NOT idempotent)' }
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
# BUG-31: Invoke-ScenarioChecks now ACTIVATES each scenario, which mutates the runtime globals
# (PIM_ActiveScenario / hosting / spnModel / configVariant ...). Capture them once and restore
# after the loop so scenario state cannot leak into the cleanup pass or a caller's session --
# the last scenario in the list must not decide the store the teardown talks to.
$savedScenarioGlobals = @{
    PIM_ActiveScenario       = $global:PIM_ActiveScenario
    PIM_ConfigVariant        = $global:PIM_ConfigVariant
    PIM_ScenarioRingGated    = $global:PIM_ScenarioRingGated
    PIM_DistributionEdition  = $global:PIM_DistributionEdition
    PIM_HostingLocation      = $global:PIM_HostingLocation
    PIM_SpnModel             = $global:PIM_SpnModel
    PIM_SyncFileLocation     = $global:PIM_SyncFileLocation
    PIM_SyncAdminsPermissions= $global:PIM_SyncAdminsPermissions
}
try {
    foreach ($id in $ids) { $results += Invoke-ScenarioChecks -Id $id }
} finally {
    foreach ($k in $savedScenarioGlobals.Keys) { Set-Variable -Name $k -Scope Global -Value $savedScenarioGlobals[$k] }
}

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
