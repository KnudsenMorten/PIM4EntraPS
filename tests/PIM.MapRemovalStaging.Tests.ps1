#Requires -Version 5.1
<#
.SYNOPSIS
    [M8] residual -- STAGE A REMOVAL (revoke a grant) directly from the Delegation
    Map. Offline, in-proc Pester. No SQL, no Graph, no HTTP, no server boot.

    The Delegation Map could already STAGE ADDS; the residual was staging a
    REMOVAL from the visual. This proves the PURE core (Resolve-PimMapRemovalPlan
    in engine/_shared/PIM-MapRisk.ps1) maps a flagged node / a grant edge to the
    correct row-level revocation plan, and that the plan flows through the SAME
    Review & Save staged-change + keyed-diff + sensitive maker/checker path the
    rest of the Manager uses -- never a one-click destructive bypass.

    Cases proven:
      (1) EDGE selection -> the matching grant row is removed; the after-set is
          the current set minus that row (a replace set).
      (2) NODE selection (a flagged target) -> every grant row referencing the
          node is removed across its owning base(s).
      (3) The removal shows up in the keyed Review & Save diff (Compare-PimRowSets,
          the REAL extracted function) as a REMOVE (and nothing else).
      (4) The same keyed shape via Get-PimAuthoringPreview (the [M3] preview the
          Manager confirms) is destructive=$true with the right removeCount.
      (5) A privileged removal trips the [M4] sensitivity gate (maker/checker):
          sensitive=$true, allowed=$false with NO approval; allowed=$true when a
          DIFFERENT admin's Approved request exists -- and self-approval is refused.
      (6) DESTRUCTIVE GUARD: a selection that resolves to ZERO rows returns
          ok=$false (never an empty/over-broad plan); a blank match never matches
          everything; destructive is ALWAYS $true for a removal.
      (7) NO DIRECT WRITE: the core/preview never mutate the input row sets and
          never call any write/connect cmdlet (they only compute).

    Run:  Invoke-Pester -Path tests\PIM.MapRemovalStaging.Tests.ps1
    Or:   tests\Run-AllPimTests.ps1
#>
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingInvokeExpression', '')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
param()

BeforeAll {
    $script:Root      = Split-Path -Parent $PSScriptRoot
    $script:MapRisk   = Join-Path $Root 'engine\_shared\PIM-MapRisk.ps1'
    $script:Authoring = Join-Path $Root 'engine\_shared\PIM-Authoring.ps1'
    $script:SensAuth  = Join-Path $Root 'engine\_shared\PIM-SensitiveAuthoring.ps1'
    $script:Approval  = Join-Path $Root 'engine\_shared\PIM-ApprovalGate.ps1'
    $script:SqlPath   = Join-Path $Root 'engine\_shared\PIM-SqlStore.ps1'
    $script:SrvPath   = Join-Path $Root 'tools\pim-manager\Open-PimManager.ps1'

    # Pure libs are safe to dot-source whole (no boot, no I/O at load).
    . $script:MapRisk
    . $script:Authoring
    . $script:SensAuth
    . $script:Approval

    # The keyed Review & Save diff lives inside the boot-laden server file; extract
    # it by name (same technique the KeyedReviewDiff suite uses -- no boot).
    function Get-FunctionTextFrom([string]$file, [string]$name) {
        $src = [System.IO.File]::ReadAllText($file)
        $m = [regex]::Match($src, ("(?m)^function {0}\b[\s\S]*?^\}}" -f [regex]::Escape($name)))
        if (-not $m.Success) { throw "Could not extract function '$name' from $file" }
        return $m.Value
    }
    Invoke-Expression (Get-FunctionTextFrom $script:SqlPath 'Get-PimStoreRowKey')
    Invoke-Expression (Get-FunctionTextFrom $script:SrvPath 'Compare-PimRowSets')

    function New-Row([hashtable]$h) {
        $o = [ordered]@{}
        foreach ($k in $h.Keys) { $o[$k] = $h[$k] }
        return $o
    }

    # --- Seeded graph model (the SHAPE Build-PimGraphData emits) ----------------
    # adm-ga  -> ROLE-GA  -> Entra-GA  -> Global Administrator (T0, privileged)
    # adm-help-> ROLE-Help-> Tasks-Help-> Helpdesk @ AU-Users (T2, ordinary)
    # Each edge carries source_csv + match (the key fields of its source row),
    # exactly as the real builder emits.
    function New-SeedGraph {
        $nodes = @(
            (New-Row @{ id = 'adm-ga@seed.test';   label = 'GA Admin';  kind = 'admin' }),
            (New-Row @{ id = 'adm-help@seed.test'; label = 'Helpdesk';  kind = 'admin' }),
            (New-Row @{ id = 'group:ROLE-GA';    label = 'GA role';        kind = 'role-group';       tier = 'T0'; groupTag = 'ROLE-GA' }),
            (New-Row @{ id = 'group:ROLE-Help';  label = 'Helpdesk role';  kind = 'role-group';       tier = 'T2'; groupTag = 'ROLE-Help' }),
            (New-Row @{ id = 'group:Entra-GA';   label = 'GA bundle';      kind = 'permission-group'; tier = 'T0'; groupTag = 'Entra-GA' }),
            (New-Row @{ id = 'group:Tasks-Help'; label = 'Helpdesk tasks'; kind = 'permission-group'; tier = 'T2'; groupTag = 'Tasks-Help' }),
            (New-Row @{ id = 'entra-role:Global Administrator'; label = 'Global Administrator'; kind = 'entra-role'; tier = 'T0'; roleName = 'Global Administrator' }),
            (New-Row @{ id = 'au-role:AU-Users:Helpdesk Administrator'; label = 'Helpdesk Administrator @ AU:AU-Users'; kind = 'au-role'; tier = 'T2'; roleName = 'Helpdesk Administrator'; auTag = 'AU-Users' })
        )
        $edges = @(
            (New-Row @{ source = 'adm-ga@seed.test'; target = 'group:ROLE-GA'; kind = 'admin-to-group'; source_csv = 'PIM-Assignments-Admins';
                        match = (New-Row @{ Username = 'adm-ga@seed.test'; GroupTag = 'ROLE-GA'; AssignmentType = 'Eligible' }) }),
            (New-Row @{ source = 'adm-help@seed.test'; target = 'group:ROLE-Help'; kind = 'admin-to-group'; source_csv = 'PIM-Assignments-Admins';
                        match = (New-Row @{ Username = 'adm-help@seed.test'; GroupTag = 'ROLE-Help'; AssignmentType = 'Eligible' }) }),
            (New-Row @{ source = 'group:Entra-GA'; target = 'group:ROLE-GA'; kind = 'group-to-group'; source_csv = 'PIM-Assignments-Groups';
                        match = (New-Row @{ TargetGroupTag = 'ROLE-GA'; SourceGroupTag = 'Entra-GA'; AssignmentType = 'Eligible' }) }),
            (New-Row @{ source = 'group:Tasks-Help'; target = 'group:ROLE-Help'; kind = 'group-to-group'; source_csv = 'PIM-Assignments-Groups';
                        match = (New-Row @{ TargetGroupTag = 'ROLE-Help'; SourceGroupTag = 'Tasks-Help'; AssignmentType = 'Eligible' }) }),
            (New-Row @{ source = 'group:Entra-GA'; target = 'entra-role:Global Administrator'; kind = 'group-to-entra-role'; source_csv = 'PIM-Assignments-Roles-Groups';
                        match = (New-Row @{ GroupTag = 'Entra-GA'; RoleDefinitionName = 'Global Administrator'; AssignmentType = 'Eligible' }) }),
            (New-Row @{ source = 'group:Tasks-Help'; target = 'au-role:AU-Users:Helpdesk Administrator'; kind = 'group-to-au-role'; source_csv = 'PIM-Assignments-Roles-AUs';
                        match = (New-Row @{ GroupTag = 'Tasks-Help'; AdministrativeUnitTag = 'AU-Users'; RoleDefinitionName = 'Helpdesk Administrator'; AssignmentType = 'Eligible' }) }),
            # cosmetic AU->au-role mirror edge: owns no removable row
            (New-Row @{ source = 'au:AU-Users'; target = 'au-role:AU-Users:Helpdesk Administrator'; kind = 'au-to-au-role'; cosmetic = $true; source_csv = 'PIM-Assignments-Roles-AUs';
                        match = (New-Row @{ GroupTag = 'Tasks-Help'; AdministrativeUnitTag = 'AU-Users'; RoleDefinitionName = 'Helpdesk Administrator' }) })
        )
        return @{ nodes = $nodes; edges = $edges }
    }

    # The CURRENT store rows per assignment base (what Read-PimRows would return).
    function New-SeedStore {
        return @{
            'PIM-Assignments-Admins' = @(
                (New-Row @{ Username = 'adm-ga@seed.test';   GroupTag = 'ROLE-GA';   AssignmentType = 'Eligible'; NumOfDaysWhenExpire = '365' }),
                (New-Row @{ Username = 'adm-help@seed.test'; GroupTag = 'ROLE-Help'; AssignmentType = 'Eligible'; NumOfDaysWhenExpire = '365' })
            )
            'PIM-Assignments-Groups' = @(
                (New-Row @{ TargetGroupTag = 'ROLE-GA';   SourceGroupTag = 'Entra-GA';   AssignmentType = 'Eligible' }),
                (New-Row @{ TargetGroupTag = 'ROLE-Help'; SourceGroupTag = 'Tasks-Help'; AssignmentType = 'Eligible' })
            )
            'PIM-Assignments-Roles-Groups' = @(
                (New-Row @{ GroupTag = 'Entra-GA'; RoleDefinitionName = 'Global Administrator'; AssignmentType = 'Eligible' })
            )
            'PIM-Assignments-Roles-AUs' = @(
                (New-Row @{ GroupTag = 'Tasks-Help'; AdministrativeUnitTag = 'AU-Users'; RoleDefinitionName = 'Helpdesk Administrator'; AssignmentType = 'Eligible' })
            )
            'PIM-Assignments-Azure-Resources' = @()
        }
    }
}

Describe '[M8] Resolve-PimMapRemovalPlan -- EDGE selection (one grant)' {

    It '(1) removes the exactly-matching grant row; after = current minus that row' {
        $g = New-SeedGraph; $store = New-SeedStore
        $edge = @($g.edges) | Where-Object { $_.kind -eq 'group-to-entra-role' } | Select-Object -First 1
        $plan = Resolve-PimMapRemovalPlan -Data $g -CurrentRows $store -EdgeMatch $edge.match -EdgeKind $edge.kind
        $plan.ok          | Should -BeTrue
        $plan.mode        | Should -Be 'edge'
        $plan.destructive | Should -BeTrue
        $plan.removedCount | Should -Be 1
        @($plan.plans).Count | Should -Be 1
        $pl = @($plan.plans)[0]
        $pl.base | Should -Be 'PIM-Assignments-Roles-Groups'
        @($pl.afterRows).Count | Should -Be 0       # the only row was the revoked grant
        @($pl.removedRows).Count | Should -Be 1
        "$(Get-PimAuthoringCell $pl.removedRows[0] 'RoleDefinitionName')" | Should -Be 'Global Administrator'
    }

    It 'ignores AssignmentType / expiry differences (revokes the grant by KEY)' {
        $g = New-SeedGraph; $store = New-SeedStore
        # edge match has AssignmentType=Eligible; the store row keys on Username|GroupTag only.
        $edge = @($g.edges) | Where-Object { $_.kind -eq 'admin-to-group' -and $_.match.GroupTag -eq 'ROLE-Help' } | Select-Object -First 1
        $plan = Resolve-PimMapRemovalPlan -Data $g -CurrentRows $store -EdgeMatch $edge.match -EdgeKind $edge.kind
        $plan.removedCount | Should -Be 1
        @(@($plan.plans)[0].afterRows).Count | Should -Be 1   # the OTHER admin row survives
    }
}

Describe '[M8] Resolve-PimMapRemovalPlan -- NODE selection (flagged node)' {

    It '(2) removing a flagged TARGET drops the grant row that attaches it' {
        $g = New-SeedGraph; $store = New-SeedStore
        $plan = Resolve-PimMapRemovalPlan -Data $g -CurrentRows $store -NodeId 'entra-role:Global Administrator'
        $plan.ok   | Should -BeTrue
        $plan.mode | Should -Be 'node'
        $plan.removedCount | Should -Be 1
        @($plan.plans)[0].base | Should -Be 'PIM-Assignments-Roles-Groups'
    }

    It 'removing a flagged GROUP drops every grant referencing it (admin-in + target-out)' {
        $g = New-SeedGraph; $store = New-SeedStore
        # ROLE-GA is referenced by: admin-to-group (adm-ga) + group-to-group (Entra-GA nested in)
        $plan = Resolve-PimMapRemovalPlan -Data $g -CurrentRows $store -NodeId 'group:ROLE-GA'
        $plan.ok | Should -BeTrue
        $bases = @($plan.plans | ForEach-Object { $_.base }) | Sort-Object
        $bases | Should -Contain 'PIM-Assignments-Admins'
        $bases | Should -Contain 'PIM-Assignments-Groups'
        # the OTHER admin / nest rows (ROLE-Help) are untouched
        $admPlan = @($plan.plans | Where-Object { $_.base -eq 'PIM-Assignments-Admins' })[0]
        @($admPlan.afterRows).Count | Should -Be 1
        "$(Get-PimAuthoringCell $admPlan.afterRows[0] 'GroupTag')" | Should -Be 'ROLE-Help'
    }

    It 'a cosmetic au-to-au-role edge owns no removable row (not double-counted)' {
        $g = New-SeedGraph; $store = New-SeedStore
        $plan = Resolve-PimMapRemovalPlan -Data $g -CurrentRows $store -NodeId 'au-role:AU-Users:Helpdesk Administrator'
        # touched by the real group-to-au-role edge AND the cosmetic au-to-au-role
        # edge, but the grant row is removed ONCE.
        $plan.removedCount | Should -Be 1
        @($plan.plans)[0].base | Should -Be 'PIM-Assignments-Roles-AUs'
    }
}

Describe '[M8] removal flows through the SAME Review & Save keyed diff' {

    It '(3) the after-set vs current shows the revoked grant as a keyed REMOVE only' {
        $g = New-SeedGraph; $store = New-SeedStore
        $edge = @($g.edges) | Where-Object { $_.kind -eq 'group-to-entra-role' } | Select-Object -First 1
        $plan = Resolve-PimMapRemovalPlan -Data $g -CurrentRows $store -EdgeMatch $edge.match -EdgeKind $edge.kind
        $pl = @($plan.plans)[0]
        $d = Compare-PimRowSets -Before @($store[$pl.base]) -After @($pl.afterRows) -Base $pl.base
        @($d.adds).Count     | Should -Be 0
        @($d.modifies).Count | Should -Be 0
        @($d.removes).Count  | Should -Be 1
        "$(Get-PimAuthoringCell $d.removes[0] 'RoleDefinitionName')" | Should -Be 'Global Administrator'
    }

    It '(4) the [M3] authoring preview reports it destructive with removeCount=1' {
        $g = New-SeedGraph; $store = New-SeedStore
        $edge = @($g.edges) | Where-Object { $_.kind -eq 'group-to-au-role' } | Select-Object -First 1
        $plan = Resolve-PimMapRemovalPlan -Data $g -CurrentRows $store -EdgeMatch $edge.match -EdgeKind $edge.kind
        $pl = @($plan.plans)[0]
        $pv = Get-PimAuthoringPreview -Base $pl.base -Before @($store[$pl.base]) -After @($pl.afterRows) -Mode 'replace' -Action 'delete-rows'
        $pv.destructive | Should -BeTrue
        $pv.removeCount | Should -Be 1
        $pv.addCount    | Should -Be 0
        $pv.modifyCount | Should -Be 0
    }
}

Describe '[M8] removal honours the [M4] maker/checker sensitivity gate' {

    It '(5a) revoking a PRIVILEGED grant is sensitive and BLOCKED with no approval' {
        $g = New-SeedGraph; $store = New-SeedStore
        $plan = Resolve-PimMapRemovalPlan -Data $g -CurrentRows $store -NodeId 'entra-role:Global Administrator'
        $removed = @(); foreach ($pl in @($plan.plans)) { $removed += @($pl.removedRows) }
        $gate = Test-PimAuthoringCommitAllowed -Action 'delete-rows' -Base 'PIM-Assignments-Roles-Groups' -Rows $removed -Requests @()
        $gate.sensitive | Should -BeTrue
        $gate.allowed   | Should -BeFalse
        $gate.gate      | Should -Be 'needs-approval'
    }

    It '(5b) ALLOWED once a DIFFERENT admin has an Approved request for the same target' {
        $g = New-SeedGraph; $store = New-SeedStore
        $plan = Resolve-PimMapRemovalPlan -Data $g -CurrentRows $store -NodeId 'entra-role:Global Administrator'
        $removed = @(); foreach ($pl in @($plan.plans)) { $removed += @($pl.removedRows) }
        $target = Get-PimSensitiveAuthoringTarget -Action 'delete-rows' -Base 'PIM-Assignments-Roles-Groups'
        $req = [ordered]@{
            id = 'r1'; action = 'authoring'; target = $target; status = 'Approved'
            requestedBy = 'maker@seed.test'; approver = 'checker@seed.test'   # maker != checker (enforced at decision time)
            requestedUtc = (Get-Date).ToUniversalTime().ToString('o')
            decidedUtc   = (Get-Date).ToUniversalTime().ToString('o')
            executed = $false
        }
        $gate = Test-PimAuthoringCommitAllowed -Action 'delete-rows' -Base 'PIM-Assignments-Roles-Groups' -Rows $removed -Requests @($req)
        $gate.sensitive | Should -BeTrue
        $gate.allowed   | Should -BeTrue
    }

    It '(5c) revoking an ORDINARY (non-privileged) grant is NOT sensitive (commits as before)' {
        $g = New-SeedGraph; $store = New-SeedStore
        $plan = Resolve-PimMapRemovalPlan -Data $g -CurrentRows $store -NodeId 'au-role:AU-Users:Helpdesk Administrator'
        $removed = @(); foreach ($pl in @($plan.plans)) { $removed += @($pl.removedRows) }
        $gate = Test-PimAuthoringCommitAllowed -Action 'delete-rows' -Base 'PIM-Assignments-Roles-AUs' -Rows $removed -Requests @()
        $gate.allowed | Should -BeTrue
    }
}

Describe '[M8] destructive guard + no direct write' {

    It '(6a) a selection that matches NOTHING returns ok=$false (no empty/over-broad plan)' {
        $g = New-SeedGraph; $store = New-SeedStore
        $bogus = New-Row @{ GroupTag = 'NOPE'; RoleDefinitionName = 'Nonexistent Role' }
        $plan = Resolve-PimMapRemovalPlan -Data $g -CurrentRows $store -EdgeMatch $bogus -EdgeKind 'group-to-entra-role'
        $plan.ok | Should -BeFalse
        $plan.removedCount | Should -Be 0
        @($plan.reasons).Count | Should -BeGreaterThan 0
    }

    It '(6b) a BLANK match value never matches everything' {
        $g = New-SeedGraph; $store = New-SeedStore
        $blank = New-Row @{ GroupTag = ''; RoleDefinitionName = '' }
        $plan = Resolve-PimMapRemovalPlan -Data $g -CurrentRows $store -EdgeMatch $blank -EdgeKind 'group-to-entra-role'
        $plan.ok | Should -BeFalse
        $plan.removedCount | Should -Be 0
    }

    It '(6c) destructive is ALWAYS true for a removal, even when nothing matched' {
        $g = New-SeedGraph; $store = New-SeedStore
        $plan = Resolve-PimMapRemovalPlan -Data $g -CurrentRows $store -NodeId 'nonexistent-node'
        $plan.ok | Should -BeFalse
        $plan.destructive | Should -BeTrue
    }

    It '(7) the core does NOT mutate the input store rows (computes a new set)' {
        $g = New-SeedGraph; $store = New-SeedStore
        $beforeCount = @($store['PIM-Assignments-Roles-Groups']).Count
        $edge = @($g.edges) | Where-Object { $_.kind -eq 'group-to-entra-role' } | Select-Object -First 1
        $null = Resolve-PimMapRemovalPlan -Data $g -CurrentRows $store -EdgeMatch $edge.match -EdgeKind $edge.kind
        @($store['PIM-Assignments-Roles-Groups']).Count | Should -Be $beforeCount   # untouched
    }
}
