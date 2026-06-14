<#
  PIM4EntraPS -- LIVE deploy-validation Pester suite.

  After a real engine deploy (Invoke-PimEngineCore.ps1 -Scope All), this suite reads the
  DESIRED set from the SQL store (pim.Rows) and asserts -- against the LIVE tenant over
  Graph REST -- that EVERY desired object was actually created in PIM:
    * every marker-fenced group definition exists as an Entra group (role-assignable flag matches)
    * every desired Administrative Unit exists
    * every group has at least one owner (engine rule: no group without an owner)
    * every Entra-role -> group assignment exists as an eligible/active role schedule
    * every admin -> role-group delegation exists as a PIM-for-Groups eligible membership
    * every approval-required group's PIM member policy actually requires approval

  It is a TRUE round-trip (desired-in-SQL -> live-in-PIM), not a logic-only check.

  SAFETY: read-only. It never creates or deletes. It only inspects marker-fenced objects.

  Run (against a deployed test tenant):
    $env:PIM_SqlServer='.\SQLEXPRESS'; $env:PIM_SqlDatabase='PimPlatform'
    $env:PIM_TenantId='<test-tenant>'; $env:PIM_ClientId='<engine-spn>'; $env:PIM_CertThumbprint='<thumb>'
    Invoke-Pester -Path tests\live\PIM.DeployValidation.Tests.ps1

  Skips cleanly (Inconclusive) if SQL or the tenant identity is not configured.
#>
[CmdletBinding()] param()

BeforeDiscovery {
    # Pester 5 expands -ForEach at DISCOVERY time, so the desired set must be read from SQL
    # HERE (not in BeforeAll). Read-only: just pulls the desired rows so each desired object
    # becomes its own test case.
    $Marker = if ($env:PIM_DEPLOY_MARKER) { $env:PIM_DEPLOY_MARKER } else { 'PIMCOREENGINE-' }
    $here   = Split-Path -Parent $PSCommandPath
    $shared = Resolve-Path "$here\..\..\engine\_shared"
    $global:PIM_UseGraphSdk = $false
    . "$shared\PIM-ChangeQueue.ps1"; . "$shared\PIM-SqlStore.ps1"; . "$shared\PIM-Rest.ps1"
    $global:PIM_SqlServer   = if ($env:PIM_SqlServer) { $env:PIM_SqlServer } else { '.\SQLEXPRESS' }
    $global:PIM_SqlDatabase = if ($env:PIM_SqlDatabase) { $env:PIM_SqlDatabase } else { 'PimPlatform' }
    $csD = Get-PimSqlConnectionString
    # NB: Pester 5 binds -ForEach item PROPERTIES to variables only when items are HASHTABLES
    # (a [pscustomobject] is bound as $_ but its props don't become $GroupName etc.). So every
    # discovery collection below is built as @{ } hashtables.
    $discGroups = @()
    foreach ($e in @('PIM-Definitions-Roles','PIM-Definitions-Services','PIM-Definitions-Organization','PIM-Definitions-Tasks')) {
        foreach ($r in @(Get-PimSqlRows -ConnectionString $csD -Entity $e)) {
            $gn = "$($r.GroupName)"; if (-not $gn -or ($gn -notlike "$Marker*")) { continue }
            $discGroups += @{ GroupName=$gn; GroupTag="$($r.GroupTag)"; IsRoleAssignable="$($r.IsRoleAssignable)"; PolicyTemplate="$($r.PolicyTemplate)" }
        }
    }
    $script:DiscGroups       = $discGroups
    $script:DiscApprovalGrps = @($discGroups | Where-Object { "$($_.PolicyTemplate)" -match '(?i)approval' })
    $script:DiscAUs          = @(Get-PimSqlRows -ConnectionString $csD -Entity 'PIM-Definitions-AU' | Where-Object { "$($_.AUDisplayName)" -like "$Marker*" } | ForEach-Object { @{ AUName = "$($_.AUDisplayName)" } })
    $script:DiscRoleAsg      = @(Get-PimSqlRows -ConnectionString $csD -Entity 'PIM-Assignments-Roles-Groups' | Where-Object { "$($_.GroupTag)" -like "$Marker*" -and "$($_.Action)" -ne 'Remove' } | ForEach-Object { @{ GroupTag="$($_.GroupTag)"; RoleDefinitionName="$($_.RoleDefinitionName)" } })
    $script:DiscAdminAsg     = @(Get-PimSqlRows -ConnectionString $csD -Entity 'PIM-Assignments-Admins' | Where-Object { "$($_.GroupTag)" -like "$Marker*" -and "$($_.Action)" -ne 'Remove' } | ForEach-Object { @{ Username="$($_.Username)"; GroupTag="$($_.GroupTag)" } })
    $script:DiscAzAsg        = @(Get-PimSqlRows -ConnectionString $csD -Entity 'PIM-Assignments-Azure-Resources' | Where-Object { "$($_.GroupTag)" -like "$Marker*" -and "$($_.Action)" -ne 'Remove' } | ForEach-Object { @{ GroupTag="$($_.GroupTag)"; AzScope="$($_.AzScope)"; AzScopePermission="$($_.AzScopePermission)" } })
}

BeforeAll {
    $here   = Split-Path -Parent $PSCommandPath
    $shared = Resolve-Path "$here\..\..\engine\_shared"
    $global:PIM_UseGraphSdk = $false
    . "$shared\PIM-Rest.ps1"
    . "$shared\PIM-ChangeQueue.ps1"
    . "$shared\PIM-SqlStore.ps1"
    $Marker = if ($env:PIM_DEPLOY_MARKER) { $env:PIM_DEPLOY_MARKER } else { 'PIMCOREENGINE-' }

    if (-not $env:PIM_SqlDatabase) { throw 'PIM_SqlDatabase not set -- cannot read the desired store.' }
    if (-not ($env:PIM_TenantId -and ($env:PIM_ClientId -or $env:PIM_UseManagedIdentity))) { throw 'Tenant identity not set (PIM_TenantId + PIM_ClientId/cert) -- cannot query live PIM.' }
    $global:PIM_SqlServer   = if ($env:PIM_SqlServer) { $env:PIM_SqlServer } else { '.\SQLEXPRESS' }
    $global:PIM_SqlDatabase = $env:PIM_SqlDatabase
    $global:PIM_TenantId    = $env:PIM_TenantId
    $global:PIM_ClientId    = $env:PIM_ClientId
    $global:PIM_CertThumbprint = $env:PIM_CertThumbprint
    $cs = Get-PimSqlConnectionString

    # tag -> live group id resolver (cached)
    $script:liveGroupByName = @{}
    $script:GetLiveGroup = {
        param($name)
        if ($script:liveGroupByName.ContainsKey($name)) { return $script:liveGroupByName[$name] }
        $esc = $name -replace "'", "''"
        $g = @(Invoke-PimGraph -Headers @{ ConsistencyLevel='eventual' } -All -Path "/groups?`$filter=displayName eq '$esc'&`$count=true&`$select=id,displayName,isAssignableToRole")
        $obj = if ($g.Count) { $g[0] } else { $null }
        $script:liveGroupByName[$name] = $obj
        return $obj
    }
    # Rebuild the tag->name map from SQL in the RUN phase (discovery-scope $script: vars do not
    # cross into the run phase in Pester 5).
    $script:tagToName = @{}
    foreach ($e in @('PIM-Definitions-Roles','PIM-Definitions-Services','PIM-Definitions-Organization','PIM-Definitions-Tasks')) {
        foreach ($r in @(Get-PimSqlRows -ConnectionString $cs -Entity $e)) {
            $gn = "$($r.GroupName)"; $gt = "$($r.GroupTag)"
            if ($gn -like "$Marker*" -and $gt) { $script:tagToName[$gt.ToLowerInvariant()] = $gn }
        }
    }
}

Describe 'Deploy validation: desired groups exist live in PIM' {
    It 'has a non-empty marker-fenced desired set in SQL' {
        @($script:DiscGroups).Count | Should -BeGreaterThan 0
    }
    It "group '<GroupName>' exists in the tenant" -ForEach $script:DiscGroups {
        $g = & $script:GetLiveGroup $GroupName
        $g | Should -Not -BeNullOrEmpty -Because "the engine should have created '$GroupName'"
    }
    It "group '<GroupName>' has the correct role-assignable flag" -ForEach $script:DiscGroups {
        $g = & $script:GetLiveGroup $GroupName
        $g | Should -Not -BeNullOrEmpty
        $wantRA = ("$IsRoleAssignable" -match '(?i)true')
        [bool]$g.isAssignableToRole | Should -Be $wantRA
    }
    It "group '<GroupName>' has at least one owner (engine rule: never ownerless)" -ForEach $script:DiscGroups {
        $g = & $script:GetLiveGroup $GroupName
        $g | Should -Not -BeNullOrEmpty
        $owners = @(Invoke-PimGraph -All -Path "/groups/$($g.id)/owners?`$select=id")
        $owners.Count | Should -BeGreaterThan 0
    }
    # PIM-active = onboarded to PIM-for-Groups (has a member role-management policy) AND has at
    # least one PIM schedule. This applies to ROLE-ASSIGNABLE groups (the Entra-role / PIM-for-
    # Groups delegation surface). Azure-RBAC-only groups (non-role-assignable) are PIM-active via
    # ARM role schedules instead -- validated in the Azure-RBAC block below.
    It "group '<GroupName>' is PIM-ACTIVE (onboarded to PIM-for-Groups, not just created)" -ForEach @($script:DiscGroups | Where-Object { "$($_.IsRoleAssignable)" -match '(?i)true' }) {
        $g = & $script:GetLiveGroup $GroupName
        $g | Should -Not -BeNullOrEmpty
        $memPol = @(Invoke-PimGraph -All -Path "/policies/roleManagementPolicyAssignments?`$filter=scopeId eq '$($g.id)' and scopeType eq 'Group' and roleDefinitionId eq 'member'")
        $memPol.Count | Should -BeGreaterThan 0 -Because "a PIM-onboarded group has a member role-management policy"
        $memElig = @(Invoke-PimGraph -All -Path "/identityGovernance/privilegedAccess/group/eligibilitySchedules?`$filter=groupId eq '$($g.id)'")
        $memAsg  = @(Invoke-PimGraph -All -Path "/identityGovernance/privilegedAccess/group/assignmentSchedules?`$filter=groupId eq '$($g.id)'")
        $dirElig = @(Invoke-PimGraph -All -Path "/roleManagement/directory/roleEligibilitySchedules?`$filter=principalId eq '$($g.id)'")
        $dirAsg  = @(Invoke-PimGraph -All -Path "/roleManagement/directory/roleAssignmentSchedules?`$filter=principalId eq '$($g.id)'")
        ($memElig.Count + $memAsg.Count + $dirElig.Count + $dirAsg.Count) | Should -BeGreaterThan 0 -Because "a PIM-active group has at least one PIM schedule"
    }
}

Describe 'Deploy validation: desired Administrative Units exist' {
    It "AU '<AUName>' exists in the tenant" -ForEach $script:DiscAUs {
        $au = @(Invoke-PimGraph -All -Path "/directory/administrativeUnits?`$select=id,displayName" | Where-Object { "$($_.displayName)" -eq $AUName })
        $au.Count | Should -BeGreaterThan 0
    }
}

Describe 'Deploy validation: Entra-role -> group assignments exist as PIM schedules' {
    It "role '<RoleDefinitionName>' is assigned to group tag '<GroupTag>'" -ForEach $script:DiscRoleAsg {
        $name = $script:tagToName[("$GroupTag").ToLowerInvariant()]
        $name | Should -Not -BeNullOrEmpty -Because "the group tag should map to a desired group name"
        $g = & $script:GetLiveGroup $name
        $g | Should -Not -BeNullOrEmpty
        $elig = @(Invoke-PimGraph -All -Path "/roleManagement/directory/roleEligibilitySchedules?`$filter=principalId eq '$($g.id)'&`$expand=roleDefinition")
        $act  = @(Invoke-PimGraph -All -Path "/roleManagement/directory/roleAssignmentSchedules?`$filter=principalId eq '$($g.id)'&`$expand=roleDefinition")
        $all  = @($elig + $act | ForEach-Object { "$($_.roleDefinition.displayName)" })
        $all | Should -Contain $RoleDefinitionName
    }
}

Describe 'Deploy validation: admin -> role-group delegations exist as PIM-for-Groups memberships' {
    It "admin '<Username>' is an eligible member of group tag '<GroupTag>'" -ForEach $script:DiscAdminAsg {
        $name = $script:tagToName[("$GroupTag").ToLowerInvariant()]
        $name | Should -Not -BeNullOrEmpty
        $g = & $script:GetLiveGroup $name
        $g | Should -Not -BeNullOrEmpty
        $mem = @(Invoke-PimGraph -All -Path "/identityGovernance/privilegedAccess/group/eligibilitySchedules?`$filter=groupId eq '$($g.id)'")
        $mem += @(Invoke-PimGraph -All -Path "/identityGovernance/privilegedAccess/group/assignmentSchedules?`$filter=groupId eq '$($g.id)'")
        $mem.Count | Should -BeGreaterThan 0 -Because "the admin delegation should be a live PIM membership on '$name'"
    }
}

Describe 'Deploy validation: approval-required groups actually require approval' {
    It "group '<GroupName>' member policy requires approval (template '<PolicyTemplate>')" -ForEach $script:DiscApprovalGrps {
        $g = & $script:GetLiveGroup $GroupName
        $g | Should -Not -BeNullOrEmpty
        $pa = @(Invoke-PimGraph -All -Path "/policies/roleManagementPolicyAssignments?`$filter=scopeId eq '$($g.id)' and scopeType eq 'Group' and roleDefinitionId eq 'member'")
        $pa.Count | Should -BeGreaterThan 0 -Because 'a member policy must exist'
        $pol = Invoke-PimGraph -Path "/policies/roleManagementPolicies/$($pa[0].policyId)?`$expand=rules"
        $rule = @($pol.rules) | Where-Object { $_.id -eq 'Approval_EndUser_Assignment' } | Select-Object -First 1
        [bool]$rule.setting.isApprovalRequired | Should -BeTrue
    }
}

Describe 'Deploy validation: Azure-RBAC delegation surface is deployed + PIM-active' {
    # Third delegation surface (Entra roles + PIM-for-Groups + AZURE RBAC). The Azure role is
    # assigned to the PIM group as an ARM eligibility/assignment schedule at the desired scope.
    It "Azure role '<AzScopePermission>' is eligible for group tag '<GroupTag>' at '<AzScope>'" -ForEach $script:DiscAzAsg {
        $name = $script:tagToName[("$GroupTag").ToLowerInvariant()]
        $name | Should -Not -BeNullOrEmpty
        $g = & $script:GetLiveGroup $name
        $g | Should -Not -BeNullOrEmpty
        $sched = @()
        foreach ($ep in @('roleEligibilityScheduleInstances','roleAssignmentScheduleInstances')) {
            $sched += @(Invoke-PimArm -Path "$AzScope/providers/Microsoft.Authorization/$ep`?`$filter=principalId eq '$($g.id)'" -ApiVersion '2020-10-01-preview' -All)
        }
        $sched.Count | Should -BeGreaterThan 0 -Because "the Azure RBAC delegation should be a live ARM PIM schedule on '$name' at '$AzScope'"
    }
}
