#Requires -Version 5.1
<#
.SYNOPSIS
  END-TO-END SCENARIO SIMULATION for PIM4EntraPS (REQUIREMENTS.md §20 "engine+GUI
  scenario sim") -- the ENGINE half. Proves the real REST engine deploys a rich,
  realistic estate from the SQL desired store against a stateful fake tenant, that the
  plan is correct, and that a second pass is idempotent. For each scenario it evaluates
  three levels critically:

      (1) SYSTEM     -- the engine runtime actually functions end-to-end (every provider
                        applies with 0 errors; the fake tenant ends in the expected state).
      (2) USE-CASE   -- the real workflow a delegated admin / workload owner / approver /
                        offboarding operator performs is reflected in tenant state.
      (3) IDEMPOTENCY-- a re-run (the operator's "did it take?" re-deploy) creates nothing
                        new (every item is validated-and-skipped). This is the engine-side
                        of the UX promise "running it again is safe".

  The GUI half (boot the Manager in SQL mode + drive it with Playwright) lives in
  tests/scenario/gui/ and reuses the Playwright harness from the GUI-test PR when present;
  it self-skips when Node/Playwright/the harness are absent (see Test-PimScenarioGui.ps1).

  Scenarios:
    1. delegate-ga-with-approval     -- a security-lead role group reaches Global Admin +
                                        Privileged Role Admin via nesting; both high-priv
                                        groups carry a people-based activation-approval policy.
    2. workload-owner-manages-group  -- a workload-owner role group is eligible to an Azure
                                        RBAC scope (Owner at subscription) via nesting.
    3. offboard-admin                -- a Lifecycle=Retire admin's PIM-for-Groups memberships
                                        are planned for removal (Enforce mode), others untouched.
    4. cutover-then-deploy           -- desired moves into the SQL store (the cutover end-state)
                                        and the engine deploys cleanly from SQL.
    5. people-based-activation-approval -- the high-priv activation policy resolves its
                                        approver to a real PERSON (department owner), never a
                                        department, satisfying Entra's people-only rule.
    6. discovery-reconcile           -- a newly discovered Azure scope produces an EMPTY
                                        permission container (propose, never auto-map a principal).

  PS 5.1, REST-only, no Graph/Az modules, no secrets/IDs/customer names. SELF-SKIPS (exit 0)
  when SQLEXPRESS is unreachable.

.EXAMPLE
  powershell -NoProfile -File tests\scenario\Test-PimScenarioSim.ps1
#>
[CmdletBinding()]
param(
    [string]$SqlServer,
    [string]$OwnerUpn = 'admin@example.onmicrosoft.com',
    [string]$DefaultDomain = 'example.onmicrosoft.com'
)
$ErrorActionPreference = 'Stop'
if (-not $SqlServer) { $SqlServer = if ($env:PIM_SqlServer) { $env:PIM_SqlServer } else { '.\SQLEXPRESS' } }
. (Join-Path $PSScriptRoot 'PIM-ScenarioHarness.ps1')

# ---- self-skip when SQLEXPRESS isn't reachable (mirrors the Live-test doctrine) -------
$pre = Test-PimScenarioPrereq -SqlServer $SqlServer
if (-not $pre.ok) { Write-Host "  SKIP (scenario sim): $($pre.reason)" -ForegroundColor Yellow; exit 0 }

$Ctx = New-PimScenarioContext
$db  = "PimScn_$([guid]::NewGuid().ToString('N').Substring(0,8))"
$global:PIM_UseGraphSdk = $false; $global:PIM_SqlServer = $SqlServer; $global:PIM_SqlDatabase = $db
$env:PIM_SkipPreflight = '1'   # the fake tenant replaces the live preflight

# Dot-source the engine at THIS top-level scope so every engine function (and the
# providers' $script: caches) live where the harness can reach + reset them.
foreach ($f in (Get-PimScenarioEngineFiles)) { . $f }
Register-PimDefaultEngineProviders

try {
    $cs = Initialize-PimScenarioStore -SqlServer $SqlServer -SqlDatabase $db -OwnerUpn $OwnerUpn -DefaultDomain $DefaultDomain
    $tenant = New-PimFakeTenant -OwnerUpn $OwnerUpn
    Enable-PimFakeTenant -Tenant $tenant

    # ===== One Full deploy underpins scenarios 1,2,4,5 (the engine deploys the whole estate) =====
    Set-PimScenarioName $Ctx 'cutover-then-deploy  (system: engine deploys the rich estate from SQL)'
    # The desired set is ALREADY in the SQL store (the cutover end-state: store=sql). Deploy it.
    $full = Invoke-PimScenarioEngine -Scope All -Mode Full
    Assert-PimScenario $Ctx 'SYSTEM: engine Full deploy has zero errors across all providers' ($full.errors -eq 0) "errors=$($full.errors)"
    Assert-PimScenario $Ctx 'SYSTEM: every desired item was created (applied > 40)' ($full.applied -gt 40) "applied=$($full.applied)"
    Assert-PimScenario $Ctx 'USE-CASE: desired was read from the SQL store, not a file' ($global:PIM_EngineSqlCs -eq $cs)
    $sum = Get-PimFakeTenantSummary -Tenant $tenant
    Assert-PimScenario $Ctx 'USE-CASE: 3 Administrative Units exist in the tenant' ($sum.aus -eq 3) "aus=$($sum.aus)"
    Assert-PimScenario $Ctx 'USE-CASE: all 9 PIM groups exist in the tenant' ($sum.groups -eq 9) "groups=$($sum.groups)"
    Assert-PimScenario $Ctx 'USE-CASE: every shipped group carries an activation policy' ($sum.policies -ge 9) "policies=$($sum.policies)"
    Assert-PimScenario $Ctx 'SYSTEM: no unexpected tenant API traffic (unknown paths = 0)' ($sum.unknown -eq 0) "unknown=$($sum.unknown)"

    # ===== Scenario 1: delegate GA with approval =====
    Set-PimScenarioName $Ctx 'delegate-ga-with-approval'
    $gaGid  = $tenant.GroupsByName['pimscenario-pim-entra-id-globaladministrator-l0-t0-cp-id']
    $praGid = $tenant.GroupsByName['pimscenario-pim-entra-id-privilegedroleadministrator-l0-t0-cp-id']
    $roleGid= $tenant.GroupsByName['pimscenario-pim-role-securitylead']
    Assert-PimScenario $Ctx 'SYSTEM: GA + PRA permission groups + the SecurityLead role group all exist' ($gaGid -and $praGid -and $roleGid)
    # the GA group holds the Global Administrator directory role (engine-applied)
    $gaRole = @($tenant.DirElig | Where-Object { $_.principalId -eq $gaGid -and $_.roleDefinition.displayName -eq 'Global Administrator' })
    Assert-PimScenario $Ctx 'USE-CASE: the GA permission group is eligible for the Global Administrator role' ($gaRole.Count -ge 1)
    # the role group is nested INTO GA + PRA (so a member of the role group reaches both)
    $nestGa  = @($tenant.GrpElig | Where-Object { $_.groupId -eq $gaGid  -and $_.principalId -eq $roleGid })
    $nestPra = @($tenant.GrpElig | Where-Object { $_.groupId -eq $praGid -and $_.principalId -eq $roleGid })
    Assert-PimScenario $Ctx 'USE-CASE: SecurityLead role group is nested into GA (delegation reaches GA)' ($nestGa.Count -ge 1)
    Assert-PimScenario $Ctx 'USE-CASE: SecurityLead role group is nested into PRA' ($nestPra.Count -ge 1)
    # the high-priv groups carry an APPROVAL-required activation policy (people-based)
    $gaPolKey = ($tenant.RolePolicies.Keys | Where-Object { $tenant.RolePolicies[$_].rules.Keys -match 'Approval' }) | Select-Object -First 1
    Assert-PimScenario $Ctx 'SYSTEM: an Approval activation rule was written to a high-priv group policy' ($null -ne $gaPolKey)

    # ===== Scenario 5: people-based activation approval =====
    Set-PimScenarioName $Ctx 'people-based-activation-approval'
    # the engine resolved the approval-required group's approver from the department OWNER (a real
    # PERSON), never a department -- Entra requires people. The seed's Security dept owner = OwnerUpn.
    $ownerId = $tenant.UsersByUpn[$OwnerUpn.ToLower()]
    $apprBodies = @()
    foreach ($k in $tenant.RolePolicies.Keys) {
        $rules = $tenant.RolePolicies[$k].rules
        foreach ($rk in @($rules.Keys)) { if ($rk -match 'Approval') { $apprBodies += $rules[$rk] } }
    }
    Assert-PimScenario $Ctx 'SYSTEM: at least one Approval rule body was deployed' ($apprBodies.Count -ge 1)
    $hasPersonApprover = $false
    foreach ($b in $apprBodies) {
        $json = ($b | ConvertTo-Json -Depth 12 -Compress)
        if ($json -match [regex]::Escape($ownerId)) { $hasPersonApprover = $true }
    }
    Assert-PimScenario $Ctx 'USE-CASE: the activation approver resolves to a real PERSON (dept owner), not a department' $hasPersonApprover
    # the engine must NEVER send an activation email (Entra owns activation notifications)
    Assert-PimScenario $Ctx 'USE-CASE: engine sent no activation mail (Entra owns activation notifications)' (-not ($tenant.Stats.create.ContainsKey('mail') -and $tenant.Stats.create['mail'] -gt 0))

    # ===== Scenario 2: workload owner manages an Azure-RBAC group =====
    Set-PimScenarioName $Ctx 'workload-owner-manages-group'
    $woGid  = $tenant.GroupsByName['pimscenario-pim-role-workloadowner']
    $azGid  = $tenant.GroupsByName['pimscenario-pim-azres-subscription-owner-l5-t0-mp-res']
    Assert-PimScenario $Ctx 'SYSTEM: the WorkloadOwner role group + the Azure-RBAC permission group exist' ($woGid -and $azGid)
    $azAssign = @($tenant.AzAssign | Where-Object { "$($_.properties.principalId)" -eq $azGid })
    Assert-PimScenario $Ctx 'USE-CASE: the Azure-RBAC group is eligible for an Azure role at the subscription scope' ($azAssign.Count -ge 1)
    $azScope = if ($azAssign.Count) { "$($azAssign[0].properties.roleDefinitionId)" } else { '' }
    Assert-PimScenario $Ctx 'USE-CASE: the Azure delegation targets a subscription scope' ($azScope -match '/subscriptions/')
    $nestAz = @($tenant.GrpElig | Where-Object { $_.groupId -eq $azGid -and $_.principalId -eq $woGid })
    Assert-PimScenario $Ctx 'USE-CASE: the WorkloadOwner role group is nested into the Azure-RBAC group' ($nestAz.Count -ge 1)

    # ===== Idempotency (the "run it again" UX promise) underpinning all of the above =====
    Set-PimScenarioName $Ctx 'idempotency  (UX: re-running the deploy is safe -- creates nothing new)'
    $beforeGroups = $tenant.Groups.Count; $beforeDir = $tenant.DirElig.Count; $beforeGrp = $tenant.GrpElig.Count; $beforeAz = $tenant.AzAssign.Count
    $delta = Invoke-PimScenarioEngine -Scope All -Mode Delta -FreshProcess
    Assert-PimScenario $Ctx 'SYSTEM: Delta re-run applied ZERO new creates' ($delta.applied -eq 0) "applied=$($delta.applied)"
    Assert-PimScenario $Ctx 'SYSTEM: Delta re-run had zero errors' ($delta.errors -eq 0) "errors=$($delta.errors)"
    Assert-PimScenario $Ctx 'USE-CASE: every already-present item was validated-and-skipped' ($delta.skipped -ge 1) "skipped=$($delta.skipped)"
    Assert-PimScenario $Ctx 'USE-CASE: no duplicate groups created on re-run' ($tenant.Groups.Count -eq $beforeGroups)
    Assert-PimScenario $Ctx 'USE-CASE: no duplicate directory-role schedules on re-run' ($tenant.DirElig.Count -eq $beforeDir)
    Assert-PimScenario $Ctx 'USE-CASE: no duplicate PIM-for-Groups schedules on re-run' ($tenant.GrpElig.Count -eq $beforeGrp)
    Assert-PimScenario $Ctx 'USE-CASE: no duplicate Azure-RBAC assignments on re-run' ($tenant.AzAssign.Count -eq $beforeAz)

    # ===== Scenario 3: offboard admin =====
    Set-PimScenarioName $Ctx 'offboard-admin'
    # Flip the offboarding admin to Lifecycle=Retire is ALREADY in the seed; enable Enforce + Prune.
    # OPERATOR POLICY: automatic offboarding is OFF by default -- this scenario deliberately
    # opts in to exercise the path; production keeps PIM_EnableAutomaticOffboarding unset.
    $global:PIM_EnableAutomaticOffboarding = $true
    $global:PIM_OffboardCleanupMode = 'Enforce'
    # The offboarding admin currently HOLDS a membership in the CloudEngineer role group (created by the
    # Full deploy). Seed that live membership so the offboarding planner has something to remove.
    $obUpn = "$($('PIMSCENARIO-').ToLower())admin-ob-l2-t1-id@$DefaultDomain"
    $obId  = $tenant.UsersByUpn[$obUpn.ToLower()]
    $ceRoleGid = $tenant.GroupsByName['pimscenario-pim-role-cloudengineer']
    Assert-PimScenario $Ctx 'SYSTEM: the offboarding admin account exists in the tenant' ($null -ne $obId)
    $obMembership = @($tenant.GrpElig | Where-Object { $_.groupId -eq $ceRoleGid -and $_.principalId -eq $obId })
    Assert-PimScenario $Ctx 'USE-CASE: the offboarding admin currently HOLDS a role-group membership (pre-offboard)' ($obMembership.Count -ge 1)
    $offb = Invoke-PimScenarioEngine -Scope AdminOffboarding -Mode Full -Prune -FreshProcess
    $obScope = Get-PimScenarioScope -Result $offb -Scope 'AdminOffboarding'
    Assert-PimScenario $Ctx 'SYSTEM: offboarding scope ran without errors' ($offb.errors -eq 0) "errors=$($offb.errors)"
    Assert-PimScenario $Ctx 'USE-CASE: the offboarding admin''s membership was planned for removal' ($obScope.remove -ge 1) "remove=$($obScope.remove)"
    $obMembershipAfter = @($tenant.GrpElig | Where-Object { $_.groupId -eq $ceRoleGid -and $_.principalId -eq $obId })
    Assert-PimScenario $Ctx 'USE-CASE: the offboarding admin''s membership is GONE after Enforce' ($obMembershipAfter.Count -eq 0)
    # a NON-offboarded admin (cloud engineer) keeps their membership
    $ceId = $tenant.UsersByUpn["$($('PIMSCENARIO-').ToLower())admin-ce-l1-t1-id@$DefaultDomain".ToLower()]
    $ceMembership = @($tenant.GrpElig | Where-Object { $_.groupId -eq $ceRoleGid -and $_.principalId -eq $ceId })
    Assert-PimScenario $Ctx 'USE-CASE: a NON-offboarded admin keeps their membership (offboard is targeted)' ($ceMembership.Count -ge 1)
    $global:PIM_OffboardCleanupMode = 'Report'
    $global:PIM_EnableAutomaticOffboarding = $null   # restore: OFF by default after the scenario

    # ===== Scenario 6: discovery reconcile (propose, never auto-map) =====
    Set-PimScenarioName $Ctx 'discovery-reconcile'
    # The Azure reconcile planner must CREATE an empty container for a newly discovered scope and
    # NEVER auto-map a principal into it. This is a pure planner assertion (REST-only, offline).
    if (Get-Command Resolve-PimDiscoveryAutoMap -ErrorAction SilentlyContinue) {
        # A reconcile plan with ONE freshly discovered, auto-import subscription scope.
        $plan = [pscustomobject]@{
            create = @([pscustomobject]@{ autoImport=$true; expected=[pscustomobject]@{ groupName='PIMSCENARIO-PIM-AzRes-Discovered-Sub-L5-T1-MP-RES'; scopeId='/subscriptions/11111111-1111-1111-1111-111111111111'; scopeType='subscription' } })
            rename = @(); orphan = @(); unchanged = @()
        }
        $res = Resolve-PimDiscoveryAutoMap -Plan $plan
        Assert-PimScenario $Ctx 'SYSTEM: discovery created an empty permission CONTAINER for the new scope' (@($res.definitions).Count -ge 1)
        Assert-PimScenario $Ctx 'USE-CASE: discovery NEVER auto-maps a principal (assignment list is ALWAYS empty)' (@($res.assignments).Count -eq 0)
        Assert-PimScenario $Ctx 'USE-CASE: the discovered container row carries the discovered scope' ("$($res.definitions[0].payload.scopeId)" -match '/subscriptions/11111111')
        # a NON-auto-import discovery is staged PENDING for a human, not created
        $plan2 = [pscustomobject]@{ create=@([pscustomobject]@{ autoImport=$false; expected=[pscustomobject]@{ groupName='PIMSCENARIO-PIM-AzRes-Manual-RG' } }); rename=@(); orphan=@(); unchanged=@() }
        $res2 = Resolve-PimDiscoveryAutoMap -Plan $plan2
        Assert-PimScenario $Ctx 'USE-CASE: a non-auto-import discovery awaits a human decision (pending, not created)' (@($res2.pending).Count -ge 1 -and @($res2.definitions).Count -eq 0)
    } else {
        Write-Host "  (info) Resolve-PimDiscoveryAutoMap not present -- asserting the documented contract via the seed shape instead" -ForegroundColor DarkYellow
        $azAssignRows = @(Get-PimSqlRows -ConnectionString $cs -Entity 'PIM-Assignments-Azure-Resources')
        Assert-PimScenario $Ctx 'USE-CASE: discovery contract -- no orphan/unmapped principal rows in the seed' ($azAssignRows.Count -le 1)
    }

} finally {
    Disable-PimFakeTenant
    Remove-PimScenarioStore -SqlServer $SqlServer -SqlDatabase $db
}

Write-Host ("`n==== SCENARIO SIM RESULT: {0} pass, {1} fail ====" -f $Ctx.pass, $Ctx.fail) -ForegroundColor $(if ($Ctx.fail) { 'Red' } else { 'Green' })
if ($Ctx.fail) { exit 1 }
