#Requires -Version 5.1
<#
.SYNOPSIS
  END-TO-END SIMULATION OF AN MSP PAIR -- a synthetic MASTER estate and TWO synthetic
  MANAGED estates, with no live tenant anywhere. Framework MSP-2 (control #2),
  MSP-3 (pull, not push) and MSP-4 (targeting + class gating).

  WHY THIS EXISTS. Until now the downlink could only be proven against the REAL
  estate: the decision was run against a bundle built from a live master and planned
  against two live managed tenants. That is backwards for a feature whose whole job
  is to write privilege into a customer's tenant -- the dangerous cases (a denied
  role that still creates a Global-Administrator-bound group, a sync that prunes the
  customer's own delegation) are exactly the ones you cannot afford to discover in
  production. This runs the SAME code paths against throwaway SQL stores and a
  stateful fake tenant.

  WHAT IS REAL HERE, AND WHAT IS SIMULATED:
    REAL  -- the shipped producer (setup/New-PimBaselineBundle.ps1) reading a real SQL
             store and signing with the real CN=PIM4EntraPS-Baseline key; the real
             signature verification; the real plan (Get-PimDownlinkPlan); the real
             applies; the real engine and its real providers.
    FAKE  -- the tenants (PIM-FakeTenant.ps1, stateful) and the stores (throwaway
             local SQLEXPRESS databases, dropped at the end).

  THE THREE ESTATES:
    MASTER    the rich delegation model from PIM-ScenarioSeedSpec.ps1 plus a platform
              registry (pim.CentralAdmins / platform.Tenants / pim.TenantRoleProjection).
    MANAGED A ring 2, EMPTY on day one. Its relationship DENIES the SecurityLead role
              group, which nests Global Administrator.
    MANAGED B ring 1, already owns a group carrying one of the master's tags and has a
              local admin of its own. Its relationship is an allow-LIST of one tag.
  See PIM-MspScenarioSpec.ps1 for why each difference is there.

  SELF-SKIPS (exit 0) when SQLEXPRESS is unreachable or the baseline signing key is
  not installed on this host -- a bundle can only be produced where the key lives.

.EXAMPLE
  powershell -NoProfile -File tests\scenario\Test-PimScenarioMspPair.ps1
#>
[CmdletBinding()]
param(
    [string]$SqlServer,
    [string]$MasterDomain = 'msp-master.invalid',
    [string]$SlaveADomain = 'managed-a.invalid',
    [string]$SlaveBDomain = 'managed-b.invalid',
    # Keep the stores + the produced bundle after the run (debugging aid).
    [switch]$KeepStores
)
$ErrorActionPreference = 'Stop'
if (-not $SqlServer) { $SqlServer = if ($env:PIM_SqlServer) { $env:PIM_SqlServer } else { '.\SQLEXPRESS' } }

. (Join-Path $PSScriptRoot 'PIM-ScenarioHarness.ps1')

# ---- self-skips ------------------------------------------------------------
$pre = Test-PimScenarioPrereq -SqlServer $SqlServer
if (-not $pre.ok) { Write-Host "  SKIP (msp pair sim): $($pre.reason)" -ForegroundColor Yellow; exit 0 }
$signer = @(Get-ChildItem Cert:\LocalMachine\My -ErrorAction SilentlyContinue |
            Where-Object { $_.Subject -eq 'CN=PIM4EntraPS-Baseline' -and $_.HasPrivateKey }) |
          Sort-Object NotAfter -Descending | Select-Object -First 1
if (-not $signer) {
    Write-Host "  SKIP (msp pair sim): CN=PIM4EntraPS-Baseline signing key is not installed on this host -- a bundle can only be produced where the key lives." -ForegroundColor Yellow
    exit 0
}

$Ctx  = New-PimScenarioContext
$suffix = [guid]::NewGuid().ToString('N').Substring(0,8)
$mdb  = "PimMspM_$suffix"; $adb = "PimMspA_$suffix"; $bdb = "PimMspB_$suffix"
$work = Join-Path $env:TEMP "pim-msp-pair-$suffix"
$null = New-Item -ItemType Directory -Force -Path $work

$global:PIM_UseGraphSdk = $false
$global:PIM_SqlServer   = $SqlServer
$global:PIM_SqlDatabase = $mdb
$env:PIM_SkipPreflight  = '1'   # the fake tenant replaces the live preflight

# Engine at THIS top-level scope (so the providers' script-scoped caches are reachable
# by the harness reset), plus the downlink cores and this sim's own spec.
foreach ($f in (Get-PimScenarioEngineFiles)) { . $f }
$root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
. (Join-Path $root 'engine\_shared\PIM-ScenarioProfile.ps1')   # also dot-sources PIM-Downlink.ps1
. (Join-Path $root 'engine\_shared\PIM-Baseline.ps1')
. (Join-Path $PSScriptRoot 'PIM-MspScenarioSpec.ps1')
Register-PimDefaultEngineProviders

$Marker    = 'PIMSCENARIO-'
# The MANAGED tenant must recognise the MSP's admin naming prefix as an admin prefix, or its
# own Admins provider cannot see the accounts the sync just made: the live set is limited by
# AdminAccountPatterns, so the synced admins fall outside it and every tick tries to create
# them again. Real MSP logins start with 'Admin-', which the shipped locked config already
# matches; the scenario marker does not, so it is declared here exactly as a customer would
# declare it. 📌 Onboarding consequence, not a workaround: a managed tenant whose MSP uses a
# house prefix must carry that prefix in its own naming conventions.
Set-PimScenarioNamingConventions -Marker $Marker
$TenantAId = '11111111-aaaa-4aaa-8aaa-1111111111a1'
$TenantBId = '22222222-bbbb-4bbb-8bbb-2222222222b2'
$reg       = Get-PimMspRegistrySpec -TenantAId $TenantAId -TenantBId $TenantBId -Marker $Marker -MasterDomain $MasterDomain
$pubKey    = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($signer)

function Invoke-PimSqlScriptBatches {
    # SqlClient cannot run GO; split the schema script into batches (same helper the
    # live seeder uses -- duplicated deliberately rather than widening a shared tool).
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][string]$Path)
    foreach ($b in [regex]::Split((Get-Content -LiteralPath $Path -Raw), "(?im)^\s*GO\s*$")) {
        $sql = $b.Trim(); if (-not $sql) { continue }
        Invoke-PimSqlNonQuery -ConnectionString $ConnectionString -Sql $sql | Out-Null
    }
}
function New-PimMspStore {
    # A throwaway store: database + pim.Rows/pim.ChangeQueue. Returns its CS.
    param([Parameter(Mandatory)][string]$Database)
    Initialize-PimSqlDatabase -Server $SqlServer -Database $Database
    $cs = Get-PimSqlConnectionString -Server $SqlServer -Database $Database
    Initialize-PimSqlStore -ConnectionString $cs
    Invoke-PimSqlNonQuery -ConnectionString $cs -Sql "DELETE FROM pim.Rows" | Out-Null
    return $cs
}
function Set-PimMspRows {
    # Write an entity -> rows map into a store, keyed exactly as the engine keys it.
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][object]$Spec)
    $n = 0
    foreach ($entity in $Spec.Keys) {
        foreach ($r in @($Spec[$entity])) {
            $key = if ($entity -eq 'PIM-Definitions-Departments') { "$($r.Department)" } else { Get-PimStoreRowKey -Base $entity -Row $r }
            if (-not $key) { throw "Set-PimMspRows: a '$entity' row derived NO key -- it would have been dropped silently." }
            Set-PimSqlRow -ConnectionString $ConnectionString -Entity $entity -Key $key -Data $r
            $n++
        }
    }
    return $n
}
function Get-PimMspSlaveGroupTags {
    # The group tags a managed tenant ALREADY has, read from its own store exactly as
    # the S6 downlink would before planning.
    param([Parameter(Mandatory)][string]$ConnectionString)
    $tags = New-Object System.Collections.Generic.List[string]
    foreach ($e in @('PIM-Definitions-Roles','PIM-Definitions-Services','PIM-Definitions-Organization','PIM-Definitions-Tasks','PIM-Definitions')) {
        foreach ($r in @(Get-PimSqlRows -ConnectionString $ConnectionString -Entity $e)) {
            $t = "$($r.GroupTag)".Trim(); if ($t) { $tags.Add($t) | Out-Null }
        }
    }
    return @($tags.ToArray() | Select-Object -Unique)
}

$masterCs = $null; $slaveCs = @{}
try {
    # =====================================================================
    # 1. THE MASTER ESTATE -- delegation model + platform registry
    # =====================================================================
    Set-PimScenarioName $Ctx 'master estate (the MSP''s own store + central registry)'
    $masterCs = New-PimMspStore -Database $mdb
    $modelRows = Set-PimMspRows -ConnectionString $masterCs -Spec (Get-PimScenarioSeedSpec -OwnerUpn "owner@$MasterDomain" -DefaultDomain $MasterDomain -Marker $Marker)
    Assert-PimScenario $Ctx 'SYSTEM: the master holds a full delegation model' ($modelRows -ge 25) "rows=$modelRows"

    Invoke-PimSqlScriptBatches -ConnectionString $masterCs -Path (Join-Path $root 'sql\platform-schema.sql')
    foreach ($a in @($reg.admins)) {
        Invoke-PimSqlNonQuery -ConnectionString $masterCs -Sql @"
INSERT INTO pim.CentralAdmins (UserName, DisplayName, Upn, Ring, Template, Enabled, FirstName, LastName, Initials, UsageLocation, Purpose, Owner, Target)
VALUES (@u, @dn, @upn, @ring, @tpl, 1, @fn, @ln, @ini, @ul, @purpose, 'MSP', @target);
"@ -Parameters @{ u=$a.UserName; dn=$a.DisplayName; upn=$a.Upn; ring=[int]$a.Ring; tpl=$a.Template; fn=$a.FirstName; ln=$a.LastName; ini=$a.Initials; ul=$a.UsageLocation; purpose=$a.Purpose; target=$a.Target } | Out-Null
    }
    foreach ($t in @($reg.tenants)) {
        Invoke-PimSqlNonQuery -ConnectionString $masterCs -Sql "INSERT INTO platform.Tenants (TenantId, DisplayName, Ring, Enabled, Tags) VALUES (@tid, @dn, @ring, 1, @tags);" `
            -Parameters @{ tid=$t.TenantId; dn=$t.DisplayName; ring=[int]$t.Ring; tags=(@($t.Tags) -join ';') } | Out-Null
    }
    foreach ($p in @($reg.projection)) {
        Invoke-PimSqlNonQuery -ConnectionString $masterCs -Sql "INSERT INTO pim.TenantRoleProjection (TenantId, Mode, GroupTag, Notes) VALUES (@tid, @mode, @tag, @n);" `
            -Parameters @{ tid=$p.TenantId; mode=$p.Mode; tag=$p.GroupTag; n=$p.Notes } | Out-Null
    }
    # The ring fan-out view is the master's own answer to "who reaches whom" -- RING ONLY, which
    # is why it is fewer than every admin times every tenant. (Targeting narrows later, in the
    # plan; the registry view predates it and does not know about tags.)
    $expectedPairs = 0
    foreach ($t in @($reg.tenants)) { $expectedPairs += @(@($reg.admins) | Where-Object { [int]$_.Ring -le [int]$t.Ring }).Count }
    $allPairs = @($reg.admins).Count * @($reg.tenants).Count
    $targets = @(Invoke-PimSqlQuery -ConnectionString $masterCs -Sql "SELECT UserName, TenantId FROM pim.vw_AdminTenantTargets")
    Assert-PimScenario $Ctx "USE-CASE: the ring fan-out narrows PER TENANT ($expectedPairs admin/tenant pairs, not $allPairs)" ($targets.Count -eq $expectedPairs) "pairs=$($targets.Count)"
    $csTargets = @($targets | Where-Object { "$($_.UserName)" -eq "${Marker}Admin-CS-L2-T1-ID" })
    Assert-PimScenario $Ctx 'USE-CASE: the ring-2 consultant reaches ONLY the ring-2 tenant' ($csTargets.Count -eq 1 -and "$($csTargets[0].TenantId)" -eq $TenantAId)

    # =====================================================================
    # 2. THE SIGNED BUNDLE -- produced by the SHIPPED producer, real signature
    # =====================================================================
    Set-PimScenarioName $Ctx 'signed baseline bundle (the real producer, against the simulated master)'
    $bundlePath = Join-Path $work 'baseline.json'
    $savedSrv = $global:PIM_SqlServer; $savedDb = $global:PIM_SqlDatabase
    try {
        & (Join-Path $root 'setup\New-PimBaselineBundle.ps1') -CentralServer $SqlServer -Database $mdb -LocalSql -OutFile $bundlePath | Out-Null
    } finally {
        # the producer sets these globals for its own SQL read; restore ours or the
        # engine would later read desired from the MASTER store.
        $global:PIM_SqlServer = $savedSrv; $global:PIM_SqlDatabase = $savedDb
    }
    Assert-PimScenario $Ctx 'SYSTEM: the producer emitted a bundle' (Test-Path -LiteralPath $bundlePath)
    $doc = Get-Content -LiteralPath $bundlePath -Raw | ConvertFrom-Json
    $verify = Test-PimDownlinkBaseline -Doc $doc -PublicKey $pubKey -AllowedKind @('baseline')
    Assert-PimScenario $Ctx 'SYSTEM: the bundle verifies against the REAL baseline signing key' ([bool]$verify.ok) "$($verify.reason)"
    $payload = $verify.payload
    Assert-PimScenario $Ctx "USE-CASE: it carries exactly the $(@($reg.admins).Count) MSP-owned admins" (@($payload.rows).Count -eq @($reg.admins).Count) "rows=$(@($payload.rows).Count)"
    $obPublished = @(@($payload.assignments) | Where-Object { "$($_.UserName)" -match '(?i)Admin-OB-' })
    Assert-PimScenario $Ctx 'USE-CASE: a master-LOCAL admin''s rows are NOT published to customers' ($obPublished.Count -eq 0)
    Assert-PimScenario $Ctx 'USE-CASE: it carries the 4 MSP role memberships' (@($payload.assignments).Count -eq 4) "assignments=$(@($payload.assignments).Count)"
    $polA = @($payload.projectionPolicy.$TenantAId)
    Assert-PimScenario $Ctx 'USE-CASE: the per-relationship policy rides IN the signed bundle' ($polA.Count -eq 1 -and "$($polA[0].Mode)" -eq 'deny')
    # BUG-59's half: the memberships mean nothing without the groups they name.
    $bundledGroups = @($payload.definitions.groups)
    Assert-PimScenario $Ctx 'USE-CASE: it carries the GROUP DEFINITIONS the memberships depend on' ($bundledGroups.Count -ge 5) "groups=$($bundledGroups.Count)"
    Assert-PimScenario $Ctx 'USE-CASE: ...and their Entra role bindings' (@($payload.definitions.roleBindings).Count -ge 3) "bindings=$(@($payload.definitions.roleBindings).Count)"
    # MSP-4: which tenants an artifact reaches is decided from the tenant's TAGS, and
    # a downlink running inside the slave can only learn them from the signed bundle.
    $tagMap = $payload.tenantTags
    Assert-PimScenario $Ctx 'USE-CASE (MSP-4): the bundle carries the per-tenant TAG map' ($null -ne $tagMap -and @($tagMap.$TenantAId) -contains 'retail') "tenantTags=$(if ($tagMap) { ($tagMap | ConvertTo-Json -Compress -Depth 4) } else { '(absent)' })"

    # =====================================================================
    # 3. MANAGED TENANT A -- empty on day one, SecurityLead denied
    # =====================================================================
    Set-PimScenarioName $Ctx 'managed A: day-one empty tenant, GA-nesting role DENIED by the relationship'
    $slaveCs[$TenantAId] = New-PimMspStore -Database $adb
    $expA = Get-PimMspExpectedForTenant -Registry $reg -TenantId $TenantAId
    $planA = Get-PimDownlinkPlan -Scenario 'S6' -Doc $doc -PublicKey $pubKey -TenantId $TenantAId -SlaveRing $expA.ring `
        -LocalRoot $work -SlaveGroupTags (Get-PimMspSlaveGroupTags -ConnectionString $slaveCs[$TenantAId])
    Assert-PimScenario $Ctx 'SYSTEM: the plan is accepted (signature, expiry, anti-rollback)' ([bool]$planA.ok) "$($planA.reason)"
    Assert-PimScenario $Ctx "USE-CASE: $($expA.adminCount) admins reach ring $($expA.ring)" (@($planA.admins).Count -eq $expA.adminCount) "admins=$(@($planA.admins).Count)"
    # MSP-4 targeting, on real bundle data: a ring-0 admin the RING lets through everywhere is
    # still held back from the tenant that lacks their tag -- and the plan reports it as
    # NOT TARGETED, separately from a ring or policy exclusion.
    $offTargetA = @(@($planA.notTargeted) | Where-Object { "$($_.name)" -eq "${Marker}Admin-VIP-L0-T1-ID" })
    Assert-PimScenario $Ctx 'USE-CASE (MSP-4): a ring-0 admin targeted at a tag this tenant lacks does NOT arrive' `
        ($offTargetA.Count -eq 1 -and "$($offTargetA[0].reason)" -match 'none of the target selectors') "notTargeted=$(@($planA.notTargeted).Count)"
    Assert-PimScenario $Ctx 'USE-CASE (MSP-4): the tenant''s own tags came from the SIGNED bundle, not a registry read' (@($planA.tenantTags) -contains 'retail') "tags=$(@($planA.tenantTags) -join ', ')"
    $denied = @(@($planA.projection.excluded) | Where-Object { "$($_.GroupTag)" -eq "${Marker}ROLE-SecurityLead" })
    Assert-PimScenario $Ctx 'USE-CASE: the SecurityLead membership is excluded, WITH a reason' ($denied.Count -eq 1 -and "$($denied[0].reason)" -match 'denied by relationship policy')
    Assert-PimScenario $Ctx 'USE-CASE: 3 memberships project, 0 unresolved' (@($planA.projection.projected).Count -eq 3 -and @($planA.projection.unresolved).Count -eq 0) `
        "projected=$(@($planA.projection.projected).Count) unresolved=$(@($planA.projection.unresolved).Count)"
    # THE PROPERTY WORTH KEEPING: denying the MEMBERSHIP must remove the whole path --
    # the GA group and its Entra role binding, not just the row.
    $createTags = @(@($planA.definitions.create) | ForEach-Object { "$($_.GroupTag)" })
    $bindNames  = @(@($planA.definitions.roleBindings) | ForEach-Object { "$($_.RoleDefinitionName)" })
    Assert-PimScenario $Ctx 'USE-CASE: no Global-Administrator group is created (the deny governs the whole path)' (-not (@($createTags) -match '(?i)GlobalAdministrator')) "create=$($createTags -join ', ')"
    Assert-PimScenario $Ctx 'USE-CASE: no Global Administrator role binding survives the deny' (-not (@($bindNames) -contains 'Global Administrator')) "bindings=$($bindNames -join ', ')"
    Assert-PimScenario $Ctx 'USE-CASE: the groups the projection DOES need are staged for creation' (@($planA.definitions.create).Count -ge 3) "create=$(@($planA.definitions.create).Count)"

    # MSP-4 class gate, against the same real bundle: the customer blocks msp-roles in
    # their OWN manifest and the roles are HELD -- reported separately from a policy deny.
    $planHeld = Get-PimDownlinkPlan -Scenario 'S6' -Doc $doc -PublicKey $pubKey -TenantId $TenantAId -SlaveRing $expA.ring `
        -LocalRoot $work -BlockedCapabilities @('msp-roles')
    Assert-PimScenario $Ctx 'USE-CASE (MSP-4): a customer who blocks msp-roles gets NO memberships, and it says HELD' `
        (@($planHeld.assignments).Count -eq 0 -and @($planHeld.classHeld).Count -ge 1 -and "$(@($planHeld.classHeld)[0].reason)" -match 'blocked')

    # ---- apply into A's own store, through the REAL S6 ORCHESTRATOR -----------------
    # Deliberately NOT the three applies called by hand: that is what hid IMP-12 (the admin
    # apply existed and no production path called it). If the orchestrator ever stops staging
    # one of the three, this fails instead of quietly proving a code path nothing uses.
    $syncA = Invoke-PimManagedDownlink -Scenario 'S6' -Doc $doc -PublicKey $pubKey `
        -TenantId $TenantAId -SlaveRing $expA.ring -LocalRoot $work `
        -SlaveGroupTags (Get-PimMspSlaveGroupTags -ConnectionString $slaveCs[$TenantAId]) `
        -SlaveStoreConnectionString $slaveCs[$TenantAId] -SlaveDefaultDomain $SlaveADomain -WhatIfMode:$false
    Assert-PimScenario $Ctx 'SYSTEM: the S6 orchestrator ran the whole pull (verify -> stage -> apply)' ([bool]$syncA.ok) "$($syncA.reason)"
    Assert-PimScenario $Ctx 'SYSTEM: it never ran the S5 fan-out -- the master does not push into a customer' ($null -eq $syncA.fanout)
    Assert-PimScenario $Ctx "SYSTEM: the $($expA.adminCount) MSP admins are staged as desired rows in the slave's own store" `
        ($null -ne $syncA.admins -and $syncA.admins.created -eq $expA.adminCount) "$($syncA.admins.detail)"
    Assert-PimScenario $Ctx 'SYSTEM: the group model is staged in the slave''s own store' ([bool]$syncA.definitions.ok -and $syncA.definitions.created -ge 3) "$($syncA.definitions.detail)"
    Assert-PimScenario $Ctx 'SYSTEM: the projected memberships are staged in the slave''s own store' ($syncA.assignments.created -eq 3) "$($syncA.assignments.detail)"

    # 🔴 BUG-65: RE-PLAN against the store this sync just wrote. The tag list that decides
    # "does the customer already own this?" must EXCLUDE the rows we own, or the second run
    # disowns its own output -- create drops to 0, every group reads as customer-owned, the
    # nestings and bindings are withheld, and the apply offers to prune what it just planted.
    # Measured live before this was asserted: HOGYM's second sync, minutes after its first.
    $tagsA2 = @(Get-PimSqlRows -ConnectionString $slaveCs[$TenantAId] -Entity 'PIM-Definitions-Roles' |
                Where-Object { "$($_.Owner)" -ne 'MSP' } | ForEach-Object { "$($_.GroupTag)" })
    $planA2 = Get-PimDownlinkPlan -Scenario 'S6' -Doc $doc -PublicKey $pubKey -TenantId $TenantAId -SlaveRing $expA.ring `
        -LocalRoot $work -SlaveGroupTags $tagsA2
    Assert-PimScenario $Ctx 'USE-CASE: a re-sync does NOT mistake its own groups for the customer''s' `
        (@($planA2.definitions.defer).Count -eq 0) "deferred=$((@($planA2.definitions.defer) | ForEach-Object { $_.GroupTag }) -join ', ')"
    Assert-PimScenario $Ctx '  ...so the group model still stands, and nothing is offered up for pruning' `
        (@($planA2.definitions.create).Count -eq @($planA.definitions.create).Count -and @($planA2.definitions.nestings).Count -eq @($planA.definitions.nestings).Count) `
        "create=$(@($planA2.definitions.create).Count) nestings=$(@($planA2.definitions.nestings).Count)"

    # ---- and now the part that has never been proven: the slave's ENGINE runs -------
    Set-PimScenarioName $Ctx 'managed A: the slave''s OWN engine grants what was synced'
    $tenantA = New-PimFakeTenant -OwnerUpn "owner@$SlaveADomain" -OrgName 'Managed A' -DefaultDomain $SlaveADomain
    Enable-PimFakeTenant -Tenant $tenantA
    $global:PIM_EngineSqlCs = $slaveCs[$TenantAId]
    Reset-PimEngineRunCaches
    $runA = Invoke-PimScenarioEngine -Scope All -Mode Full -FreshProcess
    Assert-PimScenario $Ctx 'SYSTEM: the slave engine ran with zero errors' ($runA.errors -eq 0) "errors=$($runA.errors)"
    $mspUsers = @($tenantA.Users.Values | Where-Object { "$($_.userPrincipalName)" -match "(?i)@$([regex]::Escape($SlaveADomain))$" -and "$($_.userPrincipalName)" -match '(?i)pimscenario-admin' })
    Assert-PimScenario $Ctx "USE-CASE: the $($expA.adminCount) MSP admins now EXIST in the managed tenant, at ITS domain" ($mspUsers.Count -eq $expA.adminCount) "users=$($mspUsers.Count)"
    $ceGid = $tenantA.GroupsByName[("${Marker}PIM-ROLE-CloudEngineer").ToLower()]
    Assert-PimScenario $Ctx 'USE-CASE: the MSP role group was CREATED in the empty managed tenant' ($null -ne $ceGid) "groups=$($tenantA.Groups.Count)"
    $ceUpn = "$($Marker.ToLower())admin-ce-l1-t1-id@$SlaveADomain"
    $ceId  = $tenantA.UsersByUpn[$ceUpn.ToLower()]
    $ceMem = @($tenantA.GrpElig | Where-Object { $_.groupId -eq $ceGid -and $_.principalId -eq $ceId })
    Assert-PimScenario $Ctx 'USE-CASE: the synced admin HOLDS the projected membership (bare-name resolution worked)' ($ceMem.Count -ge 1)
    # the empirical form of the deny: no group in this tenant is eligible for GA.
    $gaLive = @($tenantA.DirElig | Where-Object { "$($_.roleDefinition.displayName)" -eq 'Global Administrator' })
    Assert-PimScenario $Ctx 'USE-CASE: NOTHING in the managed tenant became eligible for Global Administrator' ($gaLive.Count -eq 0) "gaSchedules=$($gaLive.Count)"
    $beforeGroups = $tenantA.Groups.Count; $beforeGrp = $tenantA.GrpElig.Count
    $reRunA = Invoke-PimScenarioEngine -Scope All -Mode Delta -FreshProcess
    # name the scopes that re-applied: "applied=3" with no scope is a failure you cannot act on.
    $reApplied = @(@($reRunA.scopes) | Where-Object { [int]$_.applied -gt 0 } | ForEach-Object { "$($_.scope)=$($_.applied)" })
    Assert-PimScenario $Ctx 'USE-CASE: a second engine pass creates nothing new (the sync is idempotent end to end)' `
        ($reRunA.applied -eq 0 -and $tenantA.Groups.Count -eq $beforeGroups -and $tenantA.GrpElig.Count -eq $beforeGrp) `
        "applied=$($reRunA.applied) in $($reApplied -join ', ')"

    # =====================================================================
    # 4. MANAGED TENANT B -- ring 1, owns its own model, has local rows
    # =====================================================================
    Set-PimScenarioName $Ctx 'managed B: the customer owns a group with our tag, and their own admin'
    Disable-PimFakeTenant
    $slaveCs[$TenantBId] = New-PimMspStore -Database $bdb
    $ownRows = Set-PimMspRows -ConnectionString $slaveCs[$TenantBId] -Spec (Get-PimMspSlaveOwnEstate -DefaultDomain $SlaveBDomain -Marker $Marker)
    Assert-PimScenario $Ctx 'SYSTEM: the customer''s own estate is in place before the first sync' ($ownRows -eq 3) "rows=$ownRows"

    $expB  = Get-PimMspExpectedForTenant -Registry $reg -TenantId $TenantBId
    $tagsB = Get-PimMspSlaveGroupTags -ConnectionString $slaveCs[$TenantBId]
    $planB = Get-PimDownlinkPlan -Scenario 'S6' -Doc $doc -PublicKey $pubKey -TenantId $TenantBId -SlaveRing $expB.ring -LocalRoot $work -SlaveGroupTags $tagsB
    Assert-PimScenario $Ctx "USE-CASE: only $($expB.adminCount) admins reach the tighter ring $($expB.ring)" (@($planB.admins).Count -eq $expB.adminCount) "admins=$(@($planB.admins).Count)"
    $bNames = @(@($planB.admins) | ForEach-Object { "$($_.UserName)" })
    Assert-PimScenario $Ctx 'USE-CASE: the ring-2 consultant does NOT reach this tenant' (-not ($bNames -contains "${Marker}Admin-CS-L2-T1-ID"))
    Assert-PimScenario $Ctx 'USE-CASE (MSP-4): the vip-targeted admin DOES reach this one -- the same target, the opposite answer' `
        ($bNames -contains "${Marker}Admin-VIP-L0-T1-ID") "admins=$($bNames -join ', ')"
    Assert-PimScenario $Ctx 'USE-CASE: the allow-LIST projects exactly the one bought delegation' (@($planB.projection.projected).Count -eq 1) "projected=$(@($planB.projection.projected).Count)"
    $notInList = @(@($planB.projection.excluded) | Where-Object { "$($_.reason)" -match 'allow-list' })
    Assert-PimScenario $Ctx 'USE-CASE: everything else is excluded as NOT IN the allow-list (not silently)' ($notInList.Count -ge 1)
    $deferred = @(@($planB.definitions.defer) | Where-Object { "$($_.GroupTag)" -eq "${Marker}ROLE-CloudEngineer" })
    Assert-PimScenario $Ctx 'USE-CASE: the customer''s own group is DEFERRED to, never re-created' ($deferred.Count -eq 1) "defer=$(@($planB.definitions.defer).Count)"
    $skipNest = @(@($planB.definitions.skipped) | Where-Object { "$($_.reason)" -match 'customer-owned' })
    Assert-PimScenario $Ctx 'USE-CASE: no nesting or role binding is written INTO the customer''s group' ($skipNest.Count -ge 1) "skipped=$(@($planB.definitions.skipped).Count)"

    # ---- the prune-safety property: the customer's own rows must survive -----------
    $syncB = Invoke-PimManagedDownlink -Scenario 'S6' -Doc $doc -PublicKey $pubKey `
        -TenantId $TenantBId -SlaveRing $expB.ring -LocalRoot $work -SlaveGroupTags $tagsB `
        -SlaveStoreConnectionString $slaveCs[$TenantBId] -SlaveDefaultDomain $SlaveBDomain -WhatIfMode:$false
    Assert-PimScenario $Ctx 'SYSTEM: the sync applied into B without touching what it does not own' `
        ($syncB.admins.skippedForeign -eq 1 -and $syncB.assignments.skippedForeign -eq 1) "adminForeign=$($syncB.admins.skippedForeign) assignForeign=$($syncB.assignments.skippedForeign)"
    $bLocalAdmin = @(Get-PimSqlRows -ConnectionString $slaveCs[$TenantBId] -Entity 'Account-Definitions-Admins' | Where-Object { "$($_.UserName)" -eq 'CUSTB-Admin-LOCAL-ID' })
    Assert-PimScenario $Ctx 'USE-CASE: the customer''s LOCAL admin row still exists after the sync' ($bLocalAdmin.Count -eq 1)
    $bLocalAsg = @(Get-PimSqlRows -ConnectionString $slaveCs[$TenantBId] -Entity 'PIM-Assignments-Admins' | Where-Object { "$($_.Username)" -match '(?i)custb-admin-local' })
    Assert-PimScenario $Ctx 'USE-CASE: the customer''s LOCAL delegation survived the first sync (no full-set replace)' ($bLocalAsg.Count -eq 1)
    $bOwnGroup = @(Get-PimSqlRows -ConnectionString $slaveCs[$TenantBId] -Entity 'PIM-Definitions-Roles' | Where-Object { "$($_.GroupName)" -eq 'CUSTB-PIM-ROLE-CloudEngineer' })
    Assert-PimScenario $Ctx 'USE-CASE: the customer''s own group definition is untouched' ($bOwnGroup.Count -eq 1 -and -not "$($bOwnGroup[0].Owner)")

    # a second sync must be a no-op, not a churn of deletes and re-creates
    $syncB2 = Invoke-PimManagedDownlink -Scenario 'S6' -Doc $doc -PublicKey $pubKey `
        -TenantId $TenantBId -SlaveRing $expB.ring -LocalRoot $work `
        -SlaveGroupTags (Get-PimMspSlaveGroupTags -ConnectionString $slaveCs[$TenantBId]) `
        -SlaveStoreConnectionString $slaveCs[$TenantBId] -SlaveDefaultDomain $SlaveBDomain -WhatIfMode:$false
    Assert-PimScenario $Ctx 'USE-CASE: re-syncing changes nothing (updates, never re-creates or prunes)' `
        ($syncB2.assignments.created -eq 0 -and $syncB2.assignments.removed -eq 0 -and $syncB2.assignments.updated -eq @($planB.assignments).Count) "$($syncB2.assignments.detail)"
    Assert-PimScenario $Ctx '  ...including the admin accounts and the group model' `
        ($syncB2.admins.created -eq 0 -and $syncB2.admins.removed -eq 0 -and $syncB2.definitions.created -eq 0 -and $syncB2.definitions.removed -eq 0) `
        "admins=$($syncB2.admins.detail) defs=$($syncB2.definitions.detail)"

} finally {
    Disable-PimFakeTenant
    if (-not $KeepStores) {
        foreach ($d in @($mdb, $adb, $bdb)) { Remove-PimScenarioStore -SqlServer $SqlServer -SqlDatabase $d }
        Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
    } else {
        Write-Host "  (kept: $mdb / $adb / $bdb and $work)" -ForegroundColor DarkGray
    }
}

Write-Host ("`n==== MSP PAIR SIM RESULT: {0} pass, {1} fail ====" -f $Ctx.pass, $Ctx.fail) -ForegroundColor $(if ($Ctx.fail) { 'Red' } else { 'Green' })
if ($Ctx.fail) { exit 1 }
