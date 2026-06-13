#Requires -Version 5.1
<#
    Pester job for PIM4EntraPS -- reruns every offline flow + framework checks.
    Run:  Invoke-Pester -Path tests\PIM.Tests.ps1
    Or:   tests\Run-AllPimTests.ps1   (also drives this)
    The three functional suites are executed as child processes (clean assembly
    state) and asserted green; the workload-connector framework is tested in-proc.
#>
BeforeAll {
    $script:Root = Split-Path -Parent $PSScriptRoot
    $script:Tests = $PSScriptRoot
    $global:PIM_ConfigVariant = 'test'
    Import-Module (Join-Path $Root 'engine\_shared\PIM-Functions.psm1') -Force -DisableNameChecking
    function Invoke-Suite([string]$name) {
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $script:Tests $name) | Out-Null
        $LASTEXITCODE
    }
}

Describe 'Functional suites (child-process, asserted green)' {
    It 'Test-PimFeatures.ps1 exits 0'          { Invoke-Suite 'Test-PimFeatures.ps1'         | Should -Be 0 }
    It 'Test-PimManagerEndpoints.ps1 exits 0'  { Invoke-Suite 'Test-PimManagerEndpoints.ps1' | Should -Be 0 }
    It 'Test-PimScenarios.ps1 exits 0'         { Invoke-Suite 'Test-PimScenarios.ps1'        | Should -Be 0 }
}

Describe 'Workload-connector framework' {
    It 'Get-PimNestedProp reads dotted paths' {
        Get-PimNestedProp ([pscustomobject]@{ a = [pscustomobject]@{ b = [pscustomobject]@{ c = 'v' } } }) 'a.b.c' | Should -Be 'v'
        Get-PimNestedProp ([pscustomobject]@{ a = $null }) 'a.b' | Should -Be $null
    }
    It 'Get-PimWorkloadToken prefers the launcher-supplied token' {
        $global:PIM_WorkloadTokens = @{ arm = 'token-123' }
        Get-PimWorkloadToken -Connector ([pscustomobject]@{ id='t'; auth='arm'; api=[pscustomobject]@{ baseUrl='https://x' } }) | Should -Be 'token-123'
        $global:PIM_WorkloadTokens = $null
    }
    It 'Get-PimWorkloadToken throws for an unknown adapter with no override' {
        { Get-PimWorkloadToken -Connector ([pscustomobject]@{ id='t'; auth='mystery'; api=[pscustomobject]@{ baseUrl='https://x' } }) } | Should -Throw
    }
    It 'every connector JSON is valid + has required ops + known auth' {
        $knownAuth = 'graph','arm','powerbi','devops','businesscentral','dataverse'
        $files = Get-ChildItem (Join-Path $Root 'workloads\connectors') -Filter '*.connector.json'
        $files.Count | Should -BeGreaterThan 0
        foreach ($f in $files) {
            $c = Get-Content $f.FullName -Raw | ConvertFrom-Json   # throws -> It fails, which is the JSON-validity assertion
            $c.id   | Should -Not -BeNullOrEmpty
            $c.auth | Should -BeIn $knownAuth -Because "$($f.Name) auth must be a known adapter"
            $c.api.assign | Should -Not -BeNullOrEmpty -Because "$($f.Name) needs an assign op"
            $c.api.remove | Should -Not -BeNullOrEmpty -Because "$($f.Name) needs a remove op"
            # a connector must list roles via API or carry a static roles array
            ($null -ne $c.api.listRoles -or $null -ne $c.roles) | Should -BeTrue -Because "$($f.Name) needs listRoles or a static roles array"
        }
    }
    It 'Get-PimWorkloadRoles returns the static roles for a no-listRoles connector (powerbi)' {
        $pbi = Get-Content (Join-Path $Root 'workloads\connectors\powerbi.connector.json') -Raw | ConvertFrom-Json
        $roles = @(Get-PimWorkloadRoles -Connector $pbi)
        $roles.Count | Should -Be 4
        ($roles | ForEach-Object { $_.name }) | Should -Contain 'Member'
    }
    It 'nested-membership connectors declare resolveContainer + listContainerRoles' {
        $files = Get-ChildItem (Join-Path $Root 'workloads\connectors') -Filter '*.connector.json'
        foreach ($f in $files) {
            $c = Get-Content $f.FullName -Raw | ConvertFrom-Json
            if ($c.membershipModel) {
                $c.api.resolveContainer   | Should -Not -BeNullOrEmpty -Because "$($f.Name) is membershipModel -> needs resolveContainer"
                $c.api.listContainerRoles | Should -Not -BeNullOrEmpty -Because "$($f.Name) is membershipModel -> needs listContainerRoles"
            }
        }
    }
    It 'Get-PimWorkloadContainerId returns null when the connector has no resolveContainer' {
        Get-PimWorkloadContainerId -Connector ([pscustomobject]@{ api = [pscustomobject]@{} }) -Tokens @{ groupId = 'g' } | Should -Be $null
    }
    It 'membership tokens expand into Dataverse container paths + odata body' {
        $dv = Get-Content (Join-Path $Root 'workloads\connectors\dataverse.connector.json') -Raw | ConvertFrom-Json
        $tok = @{ groupId = 'GID'; container = 'TEAM1'; roleId = 'ROLE9'; resource = 'org.crm4.dynamics.com' }
        (Expand-PimWorkloadTokens -Text $dv.api.resolveContainer.path -Tokens $tok) | Should -BeLike '*azureactivedirectoryobjectid eq GID*'
        (Expand-PimWorkloadTokens -Text $dv.api.listContainerRoles.path -Tokens $tok) | Should -BeLike '*/teams(TEAM1)/teamroles_association*'
        $body = Expand-PimWorkloadTokens -Text ($dv.api.assign.body | ConvertTo-Json) -Tokens $tok
        ($body -like '*roles(ROLE9)*' -and $body -like '*org.crm4.dynamics.com*') | Should -BeTrue
    }
}

Describe 'Offline feature spot-checks (in-proc)' {
    It 'date expression resolves'      { (Resolve-PimDateExpression -Expression 'FirstWorkdayNextMonth@08:00') | Should -Not -BeNullOrEmpty }
    It 'license status resolves'       { (Get-PimLicense -Refresh).Status | Should -Not -BeNullOrEmpty }
    It 'random password has 4 classes' { $p = New-PimRandomPassword; ($p -cmatch '[A-Z]' -and $p -cmatch '[a-z]' -and $p -match '\d') | Should -BeTrue }
    It 'HighPriv name matches marker'  { 'Admin-X-L0-T0-ID' -match '(?i)(^|[-_.])(L0|T0)([-_.]|$)' | Should -BeTrue }
    It 'Day2Day name does not match'   { 'Admin-X-ID' -match '(?i)(^|[-_.])(L0|T0)([-_.]|$)' | Should -BeFalse }
}

Describe 'PIM conformance engine (native template versioning + reconcile)' {
    BeforeAll {
        $script:Now = [datetime]::Parse('2026-06-13T12:00:00Z').ToUniversalTime()
        $script:Tpl = ConvertTo-PimTemplate -Json ([System.IO.File]::ReadAllText((Join-Path $Root 'workloads\templates\defender-xdr-roles.template.json'), [System.Text.UTF8Encoding]::new($false)))
        $script:Preview = 'role:Security Operator (preview)'
        $script:Ring0Keys = @('role:Security Reader','role:Security Operator','role:Security Administrator')
    }
    It 'shipped template validates + is approved' {
        (Test-PimTemplateDoc -Template $Tpl).valid | Should -BeTrue
        (Test-PimTemplateApproved -Template $Tpl) | Should -BeTrue
        (Test-PimTemplateApproved -Template ([pscustomobject]@{ status='draft' })) | Should -BeFalse
    }
    It 'ring scope: ring-0 tenant sees 3 roles, ring-2 sees all 4' {
        (Select-PimInScopeEntries -Template $Tpl -TenantRing 0).Count | Should -Be 3
        (Select-PimInScopeEntries -Template $Tpl -TenantRing 2).Count | Should -Be 4
    }
    It 'exemption: no-expiry Invalid, past Expired, future Active' {
        (Test-PimExemptionValid -Exemption ([pscustomobject]@{ reason='r' }) -NowUtc $Now).state | Should -Be 'Invalid'
        (Test-PimExemptionValid -Exemption ([pscustomobject]@{ reason='r'; expiresUtc='2026-01-01T00:00:00Z' }) -NowUtc $Now).state | Should -Be 'Expired'
        (Test-PimExemptionValid -Exemption ([pscustomobject]@{ reason='r'; expiresUtc='2026-12-01T00:00:00Z' }) -NowUtc $Now).active | Should -BeTrue
    }
    It 'reconcile: Gap / Exempt / OutOfRing / DriftExtra / Behind' {
        $g = Get-PimConformance -Template $Tpl -TenantRing 2 -TenantId 't2' -LiveKeys $Ring0Keys -AppliedVersion 7
        @($g.Rows | Where-Object { $_.Key -eq $Preview -and $_.Status -eq 'Gap' }).Count | Should -Be 1
        $g.Behind | Should -Be 1
        $e = Get-PimConformance -Template $Tpl -TenantRing 2 -TenantId 't2' -LiveKeys $Ring0Keys -ActiveExemptionKeys @($Preview) -AppliedVersion 8
        @($e.Rows | Where-Object { $_.Key -eq $Preview -and $_.Status -eq 'Exempt' }).Count | Should -Be 1
        $p = Get-PimConformance -Template $Tpl -TenantRing 0 -TenantId 'p0' -LiveKeys $Ring0Keys -AppliedVersion 8
        @($p.Rows | Where-Object { $_.Key -eq $Preview -and $_.Status -eq 'OutOfRing' }).Count | Should -Be 1
        $d = Get-PimConformance -Template $Tpl -TenantRing 0 -TenantId 'p0' -LiveKeys @($Ring0Keys + $Preview) -AppliedVersion 8
        @($d.Rows | Where-Object { $_.Key -eq $Preview -and $_.Status -eq 'DriftExtra' }).Count | Should -Be 1
    }
    It 'catalog-ahead flags an uncovered live capability' {
        $c = Get-PimConformance -Template $Tpl -TenantRing 2 -TenantId 't2' -LiveCatalog @('Security Reader','Custom Threat Hunter')
        @($c.CatalogAhead | Where-Object { $_.Capability -eq 'Custom Threat Hunter' }).Count | Should -Be 1
    }
    It 'draft + approve + promote are pure (clone, original untouched)' {
        $draft = New-PimTemplateDraft -Template $Tpl -Capabilities @('Custom Threat Hunter') -NowUtc $Now
        $draft.templateVersion | Should -Be 9
        "$($draft.status)" | Should -Be 'draft'
        $Tpl.templateVersion | Should -Be 8
        (Test-PimTemplateApproved -Template (Approve-PimTemplate -Template $draft -ApprovedBy 'mok' -NowUtc $Now)) | Should -BeTrue
        $promoted = Set-PimEntryRing -Template $Tpl -Key $Preview -Ring 0
        ((@($promoted.entries | Where-Object { "$($_.key)" -eq $Preview }) | ForEach-Object { Get-PimTemplateEntryRing -Entry $_ })) | Should -Be 0
        ((@($Tpl.entries | Where-Object { "$($_.key)" -eq $Preview }) | ForEach-Object { Get-PimTemplateEntryRing -Entry $_ })) | Should -Be 2
    }
    It 'roll-forward rows: approved, ring-gated, exemption-skipped; draft throws' {
        $ex = @([pscustomobject]@{ tenantId='t2'; templateId='defender-xdr-roles'; itemKey='role:Security Reader'; reason='held'; expiresUtc='2026-12-01T00:00:00Z' })
        $rows = @(Get-PimRollForwardRows -Template $Tpl -TenantRing 2 -TenantId 't2' -Exemptions $ex -NowUtc $Now)
        $rows.Count | Should -Be 3   # 4 in-scope minus 1 exempted
        ($rows | Where-Object { $_.RoleName -eq 'Security Reader' }).Count | Should -Be 0
        ($rows | Where-Object { $_.Workload -eq 'defender-xdr' }).Count | Should -Be 3
        $prod = @(Get-PimRollForwardRows -Template $Tpl -TenantRing 0 -TenantId 'p0' -NowUtc $Now)
        $prod.Count | Should -Be 3   # ring-2 preview excluded on a ring-0 tenant
        { Get-PimRollForwardRows -Template ([pscustomobject]@{ templateId='d'; workload='w'; status='draft'; entries=@() }) -TenantRing 2 -NowUtc $Now } | Should -Throw
    }
}

Describe 'Portal-admin scoping (delegated GUI managers)' {
    BeforeAll {
        $script:Profiles = @((Get-Content (Join-Path $Root 'config\portal-admins.sample.json') -Raw | ConvertFrom-Json).portalAdmins)
        $script:Helpdesk = Get-PimPortalProfile -Profiles $Profiles -Identity 'CONTOSO\helpdesk1'
        $script:AzDev    = Get-PimPortalProfile -Profiles $Profiles -Identity 'devlead@contoso.com'
        $script:Dept     = Get-PimPortalProfile -Profiles $Profiles -Identity 'deptowner@contoso.com'
    }
    It 'facets from a definition row (columns)' {
        $f = Get-PimGroupFacets -Row ([pscustomobject]@{ GroupName='PIM-Entra-ID-UserAdmin-L1-T0-CP-ID'; Workload='Entra-ID'; Level='L1'; TierLevel='T0'; Plane='CP'; GroupTag='Entra-ID-UserAdmin-L1' })
        $f.service | Should -Be 'entra'; $f.tier | Should -Be 0; $f.level | Should -Be 1; $f.kind | Should -Be 'indirect'
    }
    It 'facets fall back to parsing the group name' {
        $f = Get-PimGroupFacets -Row ([pscustomobject]@{ GroupName='PIM-Azure-Sub-Owner-L1-T1-WDP-RES'; GroupTag='Azure-Sub-Owner-L1' })
        $f.service | Should -Be 'azure'; $f.tier | Should -Be 1; $f.level | Should -Be 1; $f.plane | Should -Be 'WDP'
    }
    It 'helpdesk (entra, levelMax 2) sees L2+ entra but not L0/L1, not azure' {
        $see = { param($svc,$t,$l) Test-PimPortalCanSeeGroup -Profile $Helpdesk -Facets @{ service=$svc; tier=$t; level=$l; kind='indirect'; scope='' } }
        (& $see 'entra' 0 2) | Should -BeTrue
        (& $see 'entra' 0 1) | Should -BeFalse
        (& $see 'entra' 0 0) | Should -BeFalse
        (& $see 'azure' 1 3) | Should -BeFalse
    }
    It 'helpdesk can manage indirect (has cap) but not direct (no cap)' {
        (Test-PimPortalCanManageGroup -Profile $Helpdesk -Facets @{ service='entra'; tier=0; level=2; kind='indirect'; scope='' }) | Should -BeTrue
        (Test-PimPortalCanManageGroup -Profile $Helpdesk -Facets @{ service='entra'; tier=0; level=2; kind='direct'; scope='' }) | Should -BeFalse
    }
    It 'azure dev is scope-gated + tier-gated' {
        $base = @{ service='azure'; tier=1; level=1; kind='indirect' }
        (Test-PimPortalCanSeeGroup -Profile $AzDev -Facets ($base + @{ scope='/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/rg1' })) | Should -BeTrue
        (Test-PimPortalCanSeeGroup -Profile $AzDev -Facets ($base + @{ scope='/subscriptions/99999999-9999-9999-9999-999999999999' })) | Should -BeFalse
        (Test-PimPortalCanSeeGroup -Profile $AzDev -Facets @{ service='azure'; tier=0; level=0; kind='indirect'; scope='/subscriptions/11111111-1111-1111-1111-111111111111' }) | Should -BeFalse
        (Test-PimPortalCanSeeGroup -Profile $AzDev -Facets @{ service='entra'; tier=0; level=2; kind='indirect'; scope='' }) | Should -BeFalse
    }
    It 'dept owner: assign-only (no manage), assign-admin only for managed consultants, enable own consultants' {
        (Test-PimPortalCanManageGroup -Profile $Dept -Facets @{ service='entra'; tier=1; level=3; kind='indirect'; scope='' }) | Should -BeFalse
        (Test-PimPortalCanAssign -Profile $Dept) | Should -BeTrue
        (Test-PimPortalCanAssignAdmin -Profile $Dept -AdminName 'Admin-EXT1-ID') | Should -BeTrue
        (Test-PimPortalCanAssignAdmin -Profile $Dept -AdminName 'Admin-OTHER-ID') | Should -BeFalse
        (Test-PimPortalCanEnableConsultant -Profile $Dept -AdminName 'Admin-EXT2-ID') | Should -BeTrue
        (Test-PimPortalCanEnableConsultant -Profile $Helpdesk -AdminName 'Admin-EXT2-ID') | Should -BeFalse
    }
    It 'SuperAdmin bypasses all scoping' {
        (Test-PimPortalCanSeeGroup -Profile $null -Facets @{ service='entra'; tier=0; level=0; kind='indirect'; scope='' } -IsSuperAdmin) | Should -BeTrue
        (Test-PimPortalCanManageGroup -Profile $null -Facets @{ service='azure'; tier=0; level=0; kind='direct'; scope='' } -IsSuperAdmin) | Should -BeTrue
    }
    It 'Select-PimPortalVisibleRows filters a row set for the profile' {
        $rows = @(
            [pscustomobject]@{ GroupName='PIM-Entra-ID-GA-L0-T0-CP-ID'; Workload='Entra-ID'; Level='L0'; TierLevel='T0'; Plane='CP' }
            [pscustomobject]@{ GroupName='PIM-Entra-ID-UA-AU-Fin-L2-T0-CP-ID'; Workload='Entra-ID'; Level='L2'; TierLevel='T0'; Plane='CP' }
        )
        $vis = @(Select-PimPortalVisibleRows -Profile $Helpdesk -Rows $rows)
        $vis.Count | Should -Be 1
        "$($vis[0].GroupName)" | Should -BeLike '*-L2-*'
    }
}

Describe 'Permission-wizard auto-derivation (reversed create flow)' {
    It 'entra single privileged role -> service, L0/T0/CP/ID' {
        $d = Get-PimEntraDerivation -Roles @('Global Administrator')
        $d.kind | Should -Be 'permission-service'; $d.level | Should -Be 0; $d.tier | Should -Be 0; $d.plane | Should -Be 'CP'
        $d.groupName | Should -BeLike 'PIM-Entra-ID-*-L0-T0-CP-ID'
    }
    It 'entra single ordinary role -> L1; with AU scope -> L2 + AU segment' {
        (Get-PimEntraDerivation -Roles @('User Administrator')).level | Should -Be 1
        $au = Get-PimEntraDerivation -Roles @('User Administrator') -AuScope 'Finance'
        $au.level | Should -Be 2; $au.au | Should -Be 'Finance'; $au.groupName | Should -BeLike '*-AU-Finance-*'
    }
    It 'AU step only when ALL selected roles are AU-scopable' {
        (Test-PimRolesAuScopable -Roles @('User Administrator','Groups Administrator')) | Should -BeTrue
        (Test-PimRolesAuScopable -Roles @('User Administrator','Security Reader')) | Should -BeFalse
        # a non-AU-scopable role ignores AuScope -> stays L1
        (Get-PimEntraDerivation -Roles @('Security Reader') -AuScope 'Finance').level | Should -Be 1
    }
    It 'entra multiple roles -> bundle; any privileged -> L0' {
        $d = Get-PimEntraDerivation -Roles @('Global Administrator','User Administrator')
        $d.kind | Should -Be 'permission-bundle'; $d.level | Should -Be 0
    }
    It 'azure tenant root -> L0/T0/CP; sub LZ -> L1/T1/WDP' {
        $root = Get-PimAzureDerivation -ScopeType tenantRoot -Roles @('Owner') -ScopeName 'Tenant Root'
        $root.level | Should -Be 0; $root.tier | Should -Be 0; $root.plane | Should -Be 'CP'
        $lz = Get-PimAzureDerivation -ScopeType subscription -Roles @('Contributor') -ScopePath '/subscriptions/abc' -ScopeName 'lz-corp-prod'
        $lz.level | Should -Be 1; $lz.tier | Should -Be 1; $lz.plane | Should -Be 'WDP'
    }
    It 'azure plane heuristics + depth + data domain' {
        (Get-PimAzureDerivation -ScopeType managementGroup -Roles @('Reader') -ScopeName 'platform-management' -ManagementGroupDepth 1).plane | Should -Be 'MP'
        (Get-PimAzureDerivation -ScopeType resourceGroup -Roles @('Contributor') -ScopeName 'rg-app').level | Should -Be 2
        (Get-PimAzureDerivation -ScopeType resource -Roles @('Reader') -ScopeName 'sql-data-prod').domain | Should -Be 'DAT'
        $b = Get-PimAzureDerivation -ScopeType subscription -Roles @('Owner','Contributor') -ScopeName 'lz-x'
        $b.kind | Should -Be 'permission-bundle'
    }
    It 'workload derivation: defender single -> service, T1/WDP' {
        $d = Get-PimWorkloadDerivation -Workload 'Defender' -Roles @('Security Operator')
        $d.kind | Should -Be 'permission-service'; $d.tier | Should -Be 1; $d.plane | Should -Be 'WDP'
        $d.groupName | Should -BeLike 'PIM-Defender-*-T1-WDP-*'
    }
}

Describe 'Change queue + full/delta run modes' {
    It 'Create then Remove on the same key cancels out' {
        $q = @(
            New-PimChange -Entity 'PIM-Definitions-Tasks' -Key 'k1' -Op Create -Payload @{ v=1 } -EnqueuedUtc '2026-06-13T10:00:00Z'
            New-PimChange -Entity 'PIM-Definitions-Tasks' -Key 'k1' -Op Remove -EnqueuedUtc '2026-06-13T10:01:00Z'
        )
        @(Get-PimQueueNetChanges -Queue $q).Count | Should -Be 0
    }
    It 'Create then Update folds to Create with the latest payload' {
        $q = @(
            New-PimChange -Entity 'PIM-Definitions-Tasks' -Key 'k2' -Op Create -Payload @{ v=1 } -EnqueuedUtc '2026-06-13T10:00:00Z'
            New-PimChange -Entity 'PIM-Definitions-Tasks' -Key 'k2' -Op Update -Payload @{ v=2 } -EnqueuedUtc '2026-06-13T10:05:00Z'
        )
        $net = @(Get-PimQueueNetChanges -Queue $q)
        $net.Count | Should -Be 1; $net[0].op | Should -Be 'Create'; $net[0].payload.v | Should -Be 2
    }
    It 'Update then Remove folds to Remove' {
        $q = @(
            New-PimChange -Entity 'PIM-Assignments-Admins' -Key 'a1' -Op Update -EnqueuedUtc '2026-06-13T10:00:00Z'
            New-PimChange -Entity 'PIM-Assignments-Admins' -Key 'a1' -Op Remove -EnqueuedUtc '2026-06-13T10:09:00Z'
        )
        $net = @(Get-PimQueueNetChanges -Queue $q)
        $net.Count | Should -Be 1; $net[0].op | Should -Be 'Remove'
    }
    It 'apply plan: definitions before assignments; removes after creates' {
        $q = @(
            New-PimChange -Entity 'PIM-Assignments-Admins' -Key 'a' -Op Create -EnqueuedUtc '2026-06-13T10:00:00Z'
            New-PimChange -Entity 'PIM-Definitions-Tasks' -Key 'd' -Op Create -EnqueuedUtc '2026-06-13T10:00:00Z'
            New-PimChange -Entity 'PIM-Definitions-Tasks' -Key 'x' -Op Remove -EnqueuedUtc '2026-06-13T10:00:00Z'
        )
        $plan = @(Get-PimQueueApplyPlan -Queue $q)
        "$($plan[0].entity)" | Should -BeLike '*Definitions*'   # definition create first
        $plan[0].op | Should -Be 'Create'
        $plan[-1].op | Should -Be 'Remove'                       # removes last
    }
    It 'Delta run = queue net plan; Full run = upsert all desired' {
        $q = @( New-PimChange -Entity 'PIM-Definitions-Tasks' -Key 'k' -Op Create -EnqueuedUtc '2026-06-13T10:00:00Z' )
        @(Get-PimRunSet -Mode Delta -Queue $q).Count | Should -Be 1
        $desired = @(
            [pscustomobject]@{ entity='PIM-Definitions-Tasks'; key='a'; payload=@{} }
            [pscustomobject]@{ entity='PIM-Definitions-Tasks'; key='b'; payload=@{} }
        )
        $full = @(Get-PimRunSet -Mode Full -DesiredItems $desired)
        $full.Count | Should -Be 2; ($full | Where-Object op -ne 'Update').Count | Should -Be 0
    }
    It 'persistence: enqueue -> read -> clear round-trip' {
        $qf = Join-Path ([System.IO.Path]::GetTempPath()) ("pimq-" + [guid]::NewGuid().ToString('N').Substring(0,8) + '.json')
        try {
            $c1 = New-PimChange -Entity 'PIM-Definitions-Tasks' -Key 'k1' -Op Create
            Add-PimChangeToQueue -QueueFile $qf -Change $c1 | Should -Be 1
            Add-PimChangeToQueue -QueueFile $qf -Change (New-PimChange -Entity 'PIM-Definitions-Tasks' -Key 'k2' -Op Create) | Should -Be 2
            @(Read-PimChangeQueue -QueueFile $qf).Count | Should -Be 2
            Clear-PimChangeQueue -QueueFile $qf -KeepIds @("$($c1.id)") | Should -Be 1
            @(Read-PimChangeQueue -QueueFile $qf).Count | Should -Be 1
        } finally { Remove-Item -LiteralPath $qf -Force -ErrorAction SilentlyContinue }
    }
    It 'queue SQL DDL is emitted (Phase-6 readiness)' {
        (Get-PimChangeQueueDdl) | Should -BeLike '*CREATE TABLE pim.ChangeQueue*'
    }
}
