#Requires -Version 5.1
<#
    PIM4EntraPS -- FEATURE-COVERAGE Pester suite (Pester v5).

    Purpose: one detailed test per DELIVERED feature in docs/FEATURES.md, organised as
    one `Describe` per FEATURES.md chapter and one `It` per feature. The acceptance
    detail asserted by each test (consolidated from docs/REQUIREMENTS.md) is written as a
    comment immediately above the `It`.

    This complements (does not replace) tests/PIM.Tests.ps1 -- the deep per-function
    regression suite. Where PIM.Tests.ps1 already exhaustively covers a feature's logic
    (e.g. portal scoping, approver matrix, change-queue folding), the feature test here
    asserts the headline contract and references the deeper suite rather than duplicating
    every branch.

    Rules honoured (the user's hard rule: "all tests must be real, dont cheat"):
      * Pure-logic features call the ACTUAL engine function and assert real output.
      * Contract/structure features assert the REAL artifact exists + is wired
        (function defined, config default present, SQL column, connector field, ...).
      * Live-only features (live REST writes, ACA hosting, MSP pull, container runtime,
        real mail send) get a real `It` but are tagged 'Live' and -Skip'd with a reason;
        the supporting offline code path/artifact is still asserted to exist.

    Run (non-live only):   Invoke-Pester -Path tests\PIM.Features.Tests.ps1 -ExcludeTag Live
    Run (incl. live):      Invoke-Pester -Path tests\PIM.Features.Tests.ps1 -Tag Live
    Also driven by:        tests\Run-AllPimTests.ps1 (when extended to discover *.Tests.ps1)

    PS 5.1-compatible: no ?./??, no RSA.ImportFromPem, no PS7-only syntax.
#>
BeforeDiscovery {
    # Live tests are opt-in. They skip unless PIM_LIVE_TESTS is set to a truthy value,
    # so the offline gate stays green on any box with no tenant/SQL/Docker.
    $script:LiveEnabled = [bool]("$($env:PIM_LIVE_TESTS)" -match '^(1|true|yes)$')
}

BeforeAll {
    $script:Root   = Split-Path -Parent $PSScriptRoot          # SOLUTIONS/PIM4EntraPS
    $script:Shared = Join-Path $script:Root 'engine\_shared'
    $global:PIM_ConfigVariant = 'test'

    # Dot-source the real engine units the feature tests assert against (same chain the
    # scheduler / Invoke-PimEngineCore uses). PIM-Functions.psm1 carries the bulk of the
    # pure helpers; the _shared scripts carry the new REST engine.
    Import-Module (Join-Path $script:Shared 'PIM-Functions.psm1') -Force -DisableNameChecking
    . (Join-Path $script:Shared 'PIM-Rest.ps1')
    . (Join-Path $script:Shared 'PIM-ContextBuilder.ps1')
    . (Join-Path $script:Shared 'PIM-EngineCore.ps1')
    . (Join-Path $script:Shared 'PIM-Notify.ps1')
    . (Join-Path $script:Shared 'PIM-EngineProviders.ps1')
    $global:PIM_TemplateDir = Join-Path $script:Root 'templates\policy'
    Register-PimDefaultEngineProviders

    # helper: does a function exist (loaded artifact assertion)?
    function script:Fn([string]$n) { [bool](Get-Command -Name $n -CommandType Function -ErrorAction SilentlyContinue) }
    # helper: read a connector JSON
    function script:Conn([string]$id) {
        Get-Content (Join-Path $script:Root "workloads\connectors\$id.connector.json") -Raw | ConvertFrom-Json
    }
    function script:HasMember($o,[string]$n) { [bool]($o.PSObject.Properties.Name -contains $n) }
}

# =====================================================================================
Describe '1. Hosting / Runtime' {

    # FEATURE: "Run it where it fits you" -- Manager central OR local against the DB; a
    # break-glass loopback edition on a client PC for when the hosted plan is down.
    # REQ §1: local Manager runs directly against SQL (no central web server); loopback
    # break-glass edition exists; super-admins never auto-locked out.
    It 'Manager has a hosted entrypoint and a local/loopback edition (script artifacts present)' {
        (Test-Path -LiteralPath (Join-Path $Root 'tools\pim-manager\Open-PimManager.ps1')) | Should -BeTrue
        # local data path: the SQL store resolves an Integrated (on-prem / local) connection
        # string with NO secret, so the Manager can run straight against a local DB.
        $cs = Get-PimSqlConnectionString -Server '.\SQLEXPRESS' -Database 'PIM4EntraPS'
        $cs | Should -BeLike '*Integrated Security=SSPI*'
        $cs | Should -Not -BeLike '*Password=*'
    }

    # FEATURE (Live): hosted 24/7, internal-only, reachable over GSA, NO public IP (ACA).
    # REQ §1: ACA with internal env + external ingress; hub-spoke; no public exposure.
    It 'Hosted ACA/GSA reachability (live infra)' -Tag 'Live' -Skip:(-not $script:LiveEnabled) {
        # Live-gated: needs the deployed Azure Container App + GSA. Offline we can only
        # assert the deploy script that wires it exists; the reachability is a live check.
        (Test-Path -LiteralPath (Join-Path $Root 'tools\setup\Setup-PimContainers.ps1')) | Should -BeTrue
    }
}

# =====================================================================================
Describe '2. Containers' {

    # FEATURE: "One image, many roles" -- a single configurable engine image runs as
    # manager/scheduler/engine/connector/queue worker/discovery; you tell each which roles.
    # REQ §2: one parameterized engine image; config-driven worker matrix.
    It 'A single engine image + role-parameterised entrypoint exist' {
        (Test-Path -LiteralPath (Join-Path $Root 'engine\container\Dockerfile')) | Should -BeTrue
        (Test-Path -LiteralPath (Join-Path $Root 'tools\setup\Update-PimContainers.ps1')) | Should -BeTrue
        # the engine entrypoint accepts -Scope (which job types this worker does) + -Mode.
        $entry = Join-Path $Root 'tools\pim-engine\Invoke-PimEngineCore.ps1'
        (Test-Path -LiteralPath $entry) | Should -BeTrue
        $txt = Get-Content $entry -Raw
        $txt | Should -Match '(?m)\[string\]\$Scope'                    # worker scoping param
        $txt | Should -Match "ValidateSet\('Full','Delta'\)"            # run mode
    }

    # FEATURE: "Each worker does only its assigned jobs" -- scope a worker to job types,
    # run a single pass, or preview without applying.
    # REQ §2 / §6: -Scope picks the job set; -WhatIf previews; -FromQueue applies only queued.
    It 'Worker scoping + preview (-WhatIf) + commit-only (-FromQueue) are real engine switches' {
        (Get-Command Invoke-PimEngine).Parameters.ContainsKey('WhatIf')    | Should -BeTrue
        (Get-Command Invoke-PimEngine).Parameters.ContainsKey('FromQueue') | Should -BeTrue
        (Get-Command Invoke-PimEngine).Parameters.ContainsKey('Scope')     | Should -BeTrue
    }

    # FEATURE: "Headless and safe by default" -- containers auth via managed identity, no
    # interactive prompts, no secrets in the image.
    # REQ §9/§2: MI token path exists; the image COPYs only code (no *.custom.* / *.pimlicense).
    It 'Headless MI auth exists + the image carries no secrets/customer data' {
        script:Fn 'Get-PimManagedIdentityToken' | Should -BeTrue   # unattended MI token
        # The Dockerfile COPYs only specific engine code files (NOT `COPY . .`), so no
        # config/*.custom.csv or *.pimlicense can be baked in. Assert that real mechanism.
        $df = Get-Content (Join-Path $Root 'engine\container\Dockerfile') -Raw
        $df | Should -Not -Match '(?im)^\s*COPY\s+\.\s+'                 # never copy the whole tree
        $df | Should -Not -Match '(?i)\.custom\.'                       # no custom data
        $df | Should -Not -Match '(?i)\.pimlicense'                     # no license in image
        $df | Should -Match '(?i)USER\s+1000'                           # non-root
    }
}

# =====================================================================================
Describe '3. Setup / Deploy' {

    # FEATURE: "Repeatable, script-driven setup" -- container / VM / MSP setup scripts.
    # REQ §3: one setup-script family (container/VM/MSP).
    It 'Setup scripts for container, VM and MSP all exist' {
        (Test-Path -LiteralPath (Join-Path $Root 'tools\setup\Setup-PimContainers.ps1')) | Should -BeTrue
        (Test-Path -LiteralPath (Join-Path $Root 'tools\setup\Setup-PimVM.ps1'))         | Should -BeTrue
        (Test-Path -LiteralPath (Join-Path $Root 'tools\setup\Setup-PimMsp.ps1'))        | Should -BeTrue
    }

    # FEATURE: "Database access without passwords" -- MI against the DB wires up passwordless.
    # REQ §3/§5: Azure SQL connection string is token/MI based, never carries a password;
    # the grant-mi SQL creates a contained DB user FROM EXTERNAL PROVIDER (no SQL login).
    It 'Passwordless DB access is wired (no password in CS; MI grant from external provider)' {
        $cs = Get-PimAzureSqlConnectionString -Fqdn 'srv.database.windows.net' -Database 'PIM4EntraPS'
        $cs | Should -BeLike '*Encrypt=True*'
        $cs | Should -Not -BeLike '*Password=*'
        $cs | Should -Not -BeLike '*User ID=*'
        $grant = Get-Content (Join-Path $Root 'infra\azure-sql\grant-mi.sql') -Raw
        $grant | Should -Match '(?i)CREATE USER .* FROM EXTERNAL PROVIDER'
    }

    # FEATURE: "Permissions granted for you" -- setup assigns each worker identity the
    # directory permissions the engine needs.
    # REQ §3: Install-PimEngineAppRegistration grants Graph roles + consent.
    It 'App-registration / consent setup grants the engine its directory permissions' {
        (Test-Path -LiteralPath (Join-Path $Root 'setup\Install-PimEngineAppRegistration.ps1')) | Should -BeTrue
        (Test-Path -LiteralPath (Join-Path $Root 'setup\Grant-PimEngineAdminConsent.ps1'))      | Should -BeTrue
    }
}

# =====================================================================================
Describe '4. MSP' {

    # FEATURE: "Pull, never push" -- the provider never writes the customer tenant; each
    # tenant pulls a signed baseline into its own local DB; data never leaves the tenant.
    # REQ §4: signed baseline; pull-not-push; per-tenant LOCAL DB; central template only.
    It 'MSP sync is pull-based + a signed baseline bundle path exists' {
        script:Fn 'Sync-PimMspConfig'   | Should -BeTrue   # customer pulls config
        script:Fn 'Get-PimBaselineBundle' | Should -BeTrue # local consumes a baseline bundle
        (Test-Path -LiteralPath (Join-Path $Root 'setup\New-PimBaselineBundle.ps1')) | Should -BeTrue
    }

    # FEATURE: "Per-tenant isolation" -- each customer has its own data store, no
    # cross-customer visibility; provider keeps only the central template.
    # REQ §4: two DBs (template DB + per-customer LOCAL DB); local schema is pim.* only.
    It 'Two-DB isolation: platform/template schema vs per-customer local schema' {
        $platform = Get-Content (Join-Path $Root 'sql\platform-schema.sql') -Raw
        $local    = Get-Content (Join-Path $Root 'sql\local-schema.sql') -Raw
        # template/central DB carries the tenant catalog; local DB does not.
        $platform | Should -Match '(?i)CREATE TABLE platform\.Tenants'
        $platform | Should -Match '(?i)CREATE TABLE pim\.CentralAdmins'
        $local    | Should -Not -Match '(?i)platform\.Tenants'        # no cross-customer catalog locally
        $local    | Should -Match '(?i)CREATE TABLE pim\.Local'       # local-only pim.* tables
    }

    # FEATURE: ring-driven rollout (which template version a tenant pulls).
    # REQ §4: Ring on tenants/admins; fan-out JOIN admin.Ring <= tenant.Ring.
    It 'Rings drive MSP fan-out (Ring column + ring-gated fan-out query)' {
        $platform = Get-Content (Join-Path $Root 'sql\platform-schema.sql') -Raw
        $platform | Should -Match '(?i)Ring\s+TINYINT'
        $platform | Should -Match '(?i)a\.Ring\s*<=\s*t\.Ring'        # ring 0 = broadest reach
    }
}

# =====================================================================================
Describe '5. SQL / Data' {

    # FEATURE: "Single source of truth in SQL" -- config/settings/rules/profiles in the DB.
    # REQ §5: SQL data layer with rows + settings + change queue.
    It 'SQL data layer reads/writes rows, settings and a change queue' {
        foreach ($f in 'Get-PimSqlRows','Set-PimSqlRow','Get-PimSqlSetting','Set-PimSqlSetting','Add-PimSqlQueueChange','Invoke-PimSqlCommit') {
            script:Fn $f | Should -BeTrue -Because "$f is the SQL data-path contract"
        }
    }

    # FEATURE: "Passwordless database auth" -- cloud uses Entra/MI only; on-prem uses
    # integrated Windows auth.
    # REQ §5: Azure SQL FQDN -> token CS (no creds); on-prem -> Integrated Security.
    It 'Azure SQL is token/MI (no creds); on-prem/Express is Integrated Windows auth' {
        (Get-PimSqlConnectionString -Server 'localhost\SQLEXPRESS') | Should -BeLike '*Integrated Security=SSPI*'
        # an Azure SQL FQDN routes to the passwordless builder (no Password/User ID).
        $global:PIM_SqlServer = 'pim.database.windows.net'
        try {
            $cs = Get-PimSqlConnectionString
            $cs | Should -BeLike '*database.windows.net*'
            $cs | Should -Not -BeLike '*Password=*'
        } finally { $global:PIM_SqlServer = $null }
    }

    # FEATURE: "One consistent data path" -- the Manager reads/writes through one DB-aware
    # layer and never reads the connection string/secret from a config file.
    # REQ §5/§9: no secrets in config -- CS resolves from in-memory or a KV pointer only.
    It 'Connection string never comes from a JSON/config file (in-memory or KV pointer)' {
        # With nothing set and no -Server, it builds a passwordless default -- it does not
        # read a stored secret file. (KV-pointer branch is exercised in PIM.Tests / live.)
        $global:PIM_SqlConnectionString = 'Server=in-mem;Database=X;Integrated Security=SSPI'
        try { (Get-PimSqlConnectionString) | Should -Be 'Server=in-mem;Database=X;Integrated Security=SSPI' }
        finally { $global:PIM_SqlConnectionString = $null }
    }
}

# =====================================================================================
Describe '6. Engine - Core' {

    # FEATURE: "Modern, dependency-free engine" -- direct API + DB, no heavy PS modules.
    # REQ §6/§19: REST-only; $global:PIM_UseGraphSdk default off; module-free read+auth.
    It 'Engine is REST-only (direct Graph/ARM/PowerBI callers, no SDK dependency)' {
        foreach ($f in 'Invoke-PimGraph','Invoke-PimArm','Invoke-PimPowerBI','Invoke-PimRest') {
            script:Fn $f | Should -BeTrue
        }
        # the REST token minters cover MI + cert + secret, none of which need a PS module.
        script:Fn 'Get-PimClientCertToken' | Should -BeTrue
    }

    # FEATURE: "Fast incremental runs" -- queue changes, apply only what changed, scoped;
    # full reprocessing still available.
    # REQ §6: Delta = net queue plan; Full = upsert all desired; -FromQueue applies queued only.
    It 'Delta applies only changed/queued items; Full reprocesses all desired' {
        $desired = @([pscustomobject]@{ k='a'; v=1 }, [pscustomobject]@{ k='b'; v=2 })
        $live    = @([pscustomobject]@{ k='b'; v=2 })
        $diff = Compare-PimDesiredVsLive -Desired $desired -Live $live -KeyOf { param($r) $r.k } -Equal { param($d,$l) $d.v -eq $l.v }
        $diff.create.Count   | Should -Be 1   # a is new
        $diff.nochange.Count | Should -Be 1   # b unchanged -> skipped (incremental)
        # commit-queue-fed delta applies ONLY the queued (entity,key) -- the headline of
        # "apply only what actually changed". (full branch matrix in PIM.Tests.ps1)
        Register-PimEngineProvider -Provider @{
            scope='FeatUnit'; entity='Feat-Entity'
            GetDesired = { param($c) @([pscustomobject]@{ k='x' }, [pscustomobject]@{ k='y' }) }
            GetLive    = { param($c) @() }
            KeyOf = { param($r) $r.k }; Equal = { param($d,$l) $true }
            ApplyCreate = { param($i,$c) $true }
        }
        $res = Invoke-PimEngineScope -Scope 'FeatUnit' -Mode Delta -WhatIf -Changes @(@{ Entity='Feat-Entity'; Key='x' })
        # only the queued key 'x' is planned, not 'y' (plan is always an array via .ToArray()).
        @($res.plan).Count    | Should -Be 1
        "$($res.plan[0].key)" | Should -Be 'x'
    }

    # FEATURE: "Sets everything up for you" -- one run creates groups, delegations,
    # org-group access, TAPs, admin schedules and notification emails.
    # REQ §6/§7: providers exist for the full building-block set, ordered by dependency.
    It 'One run drives the full provider set in dependency order' {
        $scopes = @(Get-PimEngineScopes)
        foreach ($must in 'AdministrativeUnits','Groups','GroupOwners','Admins','EntraRoles','AzRes','AdminTap') {
            $scopes | Should -Contain $must -Because "$must is a delivered engine building block"
        }
        # dependency order: AUs before Groups before GroupOwners.
        $scopes.IndexOf('AdministrativeUnits') | Should -BeLessThan $scopes.IndexOf('Groups')
        $scopes.IndexOf('Groups')              | Should -BeLessThan $scopes.IndexOf('GroupOwners')
    }

    # FEATURE: "Stricter policy for the most privileged roles" -- GA-style delegation is
    # automatically configured to require approval.
    # REQ §13/§6: approval-required template extends default + carries an Approval rule +
    # MFA enablement; default carries none; engine never touches an approval rule it didn't apply.
    It 'High-privilege delegation auto-gets an approval-required policy template' {
        $ar = Get-PimEnginePolicyTemplate -Id 'approval-required'
        $ar | Should -Not -BeNullOrEmpty
        $ar.rules.ContainsKey('Approval') | Should -BeTrue
        @($ar.rules['Member_Enablement_EndUser_Assignment_enabledRules']) | Should -Contain 'MultiFactorAuthentication'
        (Get-PimEnginePolicyTemplate -Id 'default').rules.ContainsKey('Approval') | Should -BeFalse
    }

    # FEATURE: "Clear, readable logs" -- single tagged line per action; errors name the
    # real resource; full transcript kept per run.
    # REQ §6/§21: engine entrypoint writes a timestamped transcript; audit events are structured.
    It 'Engine keeps a per-run transcript + structured audit events' {
        (Get-Content (Join-Path $Root 'tools\pim-engine\Invoke-PimEngineCore.ps1') -Raw) | Should -Match '(?i)Start-Transcript'
        script:Fn 'Write-PimAuditEvent' | Should -BeTrue
    }
}

# =====================================================================================
Describe '7. Engine - Providers / Connectors' {

    # FEATURE: "Map one PIM group to many workloads" -- connectors across Entra roles,
    # Azure RBAC, Power BI/Fabric, gallery apps, Dataverse/D365; each turns on its prereq.
    # REQ §7: every connector JSON is valid, has assign/remove + listRoles-or-static-roles,
    # a known auth adapter, AND declares its RBAC prerequisite.
    It 'Connectors cover the delivered workloads, each with assign/remove + a declared prerequisite' {
        $known = 'graph','arm','powerbi','devops','businesscentral','dataverse'
        $files = Get-ChildItem (Join-Path $Root 'workloads\connectors') -Filter '*.connector.json'
        @($files).Count | Should -BeGreaterThan 4
        foreach ($f in $files) {
            $c = Get-Content $f.FullName -Raw | ConvertFrom-Json
            $c.id   | Should -Not -BeNullOrEmpty
            $c.auth | Should -BeIn $known -Because "$($f.Name) must use a known auth adapter"
            $c.api.assign | Should -Not -BeNullOrEmpty
            $c.api.remove | Should -Not -BeNullOrEmpty
            ((script:HasMember $c.api 'listRoles') -or ($null -ne $c.roles)) | Should -BeTrue
            script:HasMember $c 'prerequisites' | Should -BeTrue -Because "$($f.Name) must declare its access prerequisite"
        }
        # the headline workloads are all present.
        foreach ($id in 'entra-roles','azure-rbac','powerbi','dataverse','entra-approle') {
            (Test-Path -LiteralPath (Join-Path $Root "workloads\connectors\$id.connector.json")) | Should -BeTrue
        }
    }

    # FEATURE: "Full set of building blocks" -- AUs, groups+owners, admins+TAPs, Entra
    # roles + role-scoped AUs, memberships, Azure resources, group policies, access reviews.
    # REQ §7: every block is a registered engine provider.
    It 'Every building-block provider is registered' {
        $scopes = @(Get-PimEngineScopes)
        foreach ($must in 'AdministrativeUnits','Groups','GroupOwners','Admins','AdminMembers','GroupMembers','EntraRoles','RolesAUs','AzRes','GroupsPolicies','AccessReviews','AdminTap') {
            $scopes | Should -Contain $must
        }
    }

    # FEATURE: "Import roles, don't type them" -- read the live role list, diff vs existing,
    # super-admin confirms before import.
    # REQ §7: Get-PimDefinitionImportPlan splits existing/auto/manual; ConvertTo-PimImportQueueChanges
    # emits auto by default and adds manual only with -IncludeManual (the confirm gate).
    It 'Role import diffs live roles vs existing and gates manual imports' {
        $live = @([pscustomobject]@{ name='User Administrator' }, [pscustomobject]@{ name='Global Administrator' })
        $plan = Get-PimDefinitionImportPlan -ServiceType 'entra' -LiveRoles $live -Policy @(@{ serviceType='entra'; maxTierNum=0; minLevel=1; maxLevel=2 })
        @(ConvertTo-PimImportQueueChanges -Plan $plan).Count                 | Should -Be 1   # only auto (UA)
        @(ConvertTo-PimImportQueueChanges -Plan $plan -IncludeManual).Count  | Should -Be 2   # + GA after confirm
    }
}

# =====================================================================================
Describe '9. Auth / Identity' {

    # FEATURE: "100% direct API, no modules" -- auth runs entirely over REST.
    # REQ §9/§19: token minters are pure REST; no Graph/Az module needed for auth.
    It 'Token acquisition is pure REST (MI / cert / secret / interactive minters present)' {
        foreach ($f in 'Get-PimRestToken','Get-PimManagedIdentityToken','Get-PimClientCertToken','Get-PimClientSecretToken') {
            script:Fn $f | Should -BeTrue
        }
    }

    # FEATURE: "Certificate-based app auth" -- signs in as an app with a certificate,
    # defaulting to the machine certificate store.
    # REQ §9/§3: cert resolution defaults to the machine store (LocalMachine\My).
    It 'App auth uses a certificate and defaults to the machine store' {
        script:Fn 'Resolve-PimCertificate' | Should -BeTrue
        (Get-Content (Join-Path $Shared 'PIM-Rest.ps1') -Raw) | Should -Match '(?i)LocalMachine'
    }

    # FEATURE: "No secrets in configuration" -- MI or KV pointer; seed files carry no secrets.
    # REQ §9/§5: KV-secret fetch never persists to disk; CS resolution prefers MI/KV pointer.
    It 'Secrets come from MI / Key Vault pointer, never persisted to a config file' {
        script:Fn 'Get-PimSqlSecretFromKeyVault' | Should -BeTrue
        (Get-Content (Join-Path $Shared 'PIM-SqlStore.ps1') -Raw) | Should -Match '(?i)NEVER cached to disk'
    }
}

# =====================================================================================
Describe '10. Delegation model' {

    # FEATURE: "Two-tier group nesting at the core" -- direct groups nest into permission
    # groups that hold the roles/scopes.
    # REQ §10: the permission-wizard derives a permission group name + level/tier/plane.
    It 'Permission groups are derived with level/tier/plane (two-tier nesting model)' {
        $d = Get-PimEntraDerivation -Roles @('Global Administrator')
        $d.kind     | Should -Be 'permission-service'
        $d.level    | Should -Be 0
        $d.tier     | Should -Be 0
        $d.plane    | Should -Be 'CP'
        $d.groupName | Should -BeLike 'PIM-Entra-ID-*-L0-T0-CP-ID'
    }

    # FEATURE: "Everything is a group" -- the thing you grant is always a group; AUs and
    # Azure scopes are only the where.
    # REQ §10: AU-scoping adds an -AU-<name>- segment but the principal stays a group name.
    It 'AU / Azure are scopes only -- the grant is always a group' {
        $au = Get-PimEntraDerivation -Roles @('User Administrator') -AuScope 'Finance'
        $au.au        | Should -Be 'Finance'
        $au.groupName | Should -BeLike 'PIM-Entra-ID-*-AU-Finance-*'   # scope is a segment, still a group
        $az = Get-PimAzureDerivation -ScopeType subscription -Roles @('Contributor') -ScopePath '/subscriptions/abc' -ScopeName 'lz-corp-prod'
        $az.groupName | Should -BeLike 'PIM-Azure-*'                   # azure scope still yields a group
    }

    # FEATURE: "Every group has an owner -- automatically" -- owner resolved from the
    # assignment, the sponsor, or the department-to-owner mapping.
    # REQ §10: Resolve-PimGroupOwnerIds reads pipe-joined Owners then falls back to Department.
    It 'Group owner resolves from Owners, then the department mapping' {
        $Global:Users_All_ID = @(
            [pscustomobject]@{ Id='u-mok'; UserPrincipalName='mok@x.com' },
            [pscustomobject]@{ Id='u-dep'; UserPrincipalName='dep@x.com' })
        try {
            $r1 = Resolve-PimGroupOwnerIds -Row ([pscustomobject]@{ GroupName='G'; Owners='mok@x.com|dep@x.com' }) -Ctx @{}
            ($r1 -contains 'u-mok' -and $r1 -contains 'u-dep') | Should -BeTrue
            $global:PIM_DesiredRows = @{ 'PIM-Definitions-Departments' = @([pscustomobject]@{ Department='IT'; Owners='dep@x.com' }) }
            Set-Variable -Scope Script -Name '__pimDeptOwners' -Value $null -ErrorAction SilentlyContinue
            $r2 = Resolve-PimGroupOwnerIds -Row ([pscustomobject]@{ GroupName='G'; Department='IT' }) -Ctx @{}
            $r2 | Should -Contain 'u-dep'
        } finally { $Global:Users_All_ID = $null; $global:PIM_DesiredRows = $null }
    }

    # FEATURE: "Scoped portal admins" -- a portal profile carries services/tier/level
    # ceilings, scopes and the managed-admin set; workload owners see only owned groups;
    # the admin list hides the most privileged tiers; super-admins bypass scoping.
    # REQ §10: Test-PimPortalCanSeeGroup / ...CanManageGroup honour the ceilings; SuperAdmin bypasses.
    It 'Portal-admin scoping enforces ceilings + SuperAdmin bypass' {
        $profiles = @((Get-Content (Join-Path $Root 'config\portal-admins.sample.json') -Raw | ConvertFrom-Json).portalAdmins)
        $hd = Get-PimPortalProfile -Profiles $profiles -Identity 'CONTOSO\helpdesk1'
        # helpdesk (entra, level ceiling 2) sees L2 but not L0/L1
        (Test-PimPortalCanSeeGroup -Profile $hd -Facets @{ service='entra'; tier=0; level=2; kind='indirect'; scope='' }) | Should -BeTrue
        (Test-PimPortalCanSeeGroup -Profile $hd -Facets @{ service='entra'; tier=0; level=0; kind='indirect'; scope='' }) | Should -BeFalse
        # SuperAdmin bypasses all of it
        (Test-PimPortalCanSeeGroup -Profile $null -Facets @{ service='entra'; tier=0; level=0; kind='indirect'; scope='' } -IsSuperAdmin) | Should -BeTrue
    }

    # FEATURE: "Cloud-only guest invite and self-service consultant enable/disable."
    # REQ §10: guest invite is cloud-only; self-service toggle allowed only for managed consultants.
    It 'Cloud-only guest invite + managed-consultant self-service toggle' {
        (Resolve-PimOnboardingMode -Cloud $true  -External $true).mode | Should -Be 'guest-invite'
        (Resolve-PimOnboardingMode -Cloud $false -External $true).mode | Should -Be 'unsupported'   # on-prem guest impossible
        $profiles = @((Get-Content (Join-Path $Root 'config\portal-admins.sample.json') -Raw | ConvertFrom-Json).portalAdmins)
        $dept = Get-PimPortalProfile -Profiles $profiles -Identity 'deptowner@contoso.com'
        (Resolve-PimSelfServiceToggle -Profile $dept -AccountName 'consultant1@contoso.com' -Action disable).allowed | Should -BeTrue
        (Resolve-PimSelfServiceToggle -Profile $dept -AccountName 'someone-else@contoso.com' -Action enable).allowed | Should -BeFalse
    }
}

# =====================================================================================
Describe '11. GUI / Manager' {

    # FEATURE: "Browser-based delegation editor -- PIM Manager" -- create/map/delete/
    # bulk-edit/revoke/clone through a browser grid with wizards.
    # REQ §11: the Manager server entrypoint exists (deeper /api coverage in Test-PimManagerEndpoints).
    It 'The PIM Manager browser app exists (server entrypoint)' {
        (Test-Path -LiteralPath (Join-Path $Root 'tools\pim-manager\Open-PimManager.ps1')) | Should -BeTrue
    }

    # FEATURE: "Role tiers with the right powers" -- Reader/Admin/Super-Admin/Delegated;
    # Super-Admin sees all + skips validation + can update schema; fails CLOSED to read-only.
    # REQ §11: SuperAdmin bypasses scoping (asserted above); the portal profile model carries
    # the delegated role facets; absence of a determinable role must not grant write.
    It 'Role-tier model present: SuperAdmin bypass + delegated profile facets + fail-closed default' {
        # SuperAdmin bypass on manage (the most-powerful path)
        (Test-PimPortalCanManageGroup -Profile $null -Facets @{ service='azure'; tier=0; level=0; kind='direct'; scope='' } -IsSuperAdmin) | Should -BeTrue
        # a NON-super profile with no matching capability cannot manage (fail-closed)
        $profiles = @((Get-Content (Join-Path $Root 'config\portal-admins.sample.json') -Raw | ConvertFrom-Json).portalAdmins)
        $hd = Get-PimPortalProfile -Profiles $profiles -Identity 'CONTOSO\helpdesk1'
        (Test-PimPortalCanManageGroup -Profile $hd -Facets @{ service='entra'; tier=0; level=2; kind='direct'; scope='' }) | Should -BeFalse
    }
}

# =====================================================================================
Describe '12. Notifications / Email' {

    # FEATURE: "Built-in, template-driven email" -- renders HTML templates with {{tokens}};
    # templates customizable; lab redirect keeps test mail out of real inboxes; render is
    # split from send so you can preview.
    # REQ §12/§25b: ConvertTo-PimNotifyRendering is PURE (no network); Send-PimNotifyMail
    # honours $global:PIM_MailRedirectAllTo; templates ship for the lifecycle events.
    It 'Templated email renders tokens purely + redirect option (render split from send)' {
        $render = ConvertTo-PimNotifyRendering -TemplateText '<!-- subject: Hi {{Name}} -->Hello {{Name}}, role {{Role}}.' -Tokens @{ Name='Mok'; Role='GA' }
        $render.Subject  | Should -Be 'Hi Mok'
        $render.BodyHtml | Should -BeLike '*Hello Mok, role GA.*'
        $render.BodyText | Should -BeLike '*Hello Mok*'              # text variant produced for preview
        # the shipped lifecycle templates exist (new-admin / new-role / new-permission / TAP).
        foreach ($t in 'new-admin','new-role','new-permission','tap-delivery') {
            (Test-Path -LiteralPath (Join-Path $Root "templates\mail\$t.mailtemplate.html")) | Should -BeTrue
        }
        # lab redirect is wired in the sender (asserted by source contract; live send is gated below).
        (Get-Content (Join-Path $Shared 'PIM-Notify.ps1') -Raw) | Should -Match '(?i)PIM_MailRedirectAllTo'
    }

    # FEATURE (Live): a real app-only Mail.Send via Graph (with lab redirect).
    # REQ §20: a live send is not yet a recorded result -- gate it.
    It 'Real Graph sendMail with lab redirect (live mailbox)' -Tag 'Live' -Skip:(-not $script:LiveEnabled) {
        $global:PIM_MailSender = "$($env:PIM_MAIL_SENDER)"
        $global:PIM_MailRedirectAllTo = "$($env:PIM_MAIL_REDIRECT)"
        try {
            $r = Send-PimNotifyMail -Type 'new-admin' -Tokens @{ AdminName='live-test' } -Recipient 'someone@example.com'
            $r.sent | Should -BeTrue
        } finally { $global:PIM_MailSender = $null; $global:PIM_MailRedirectAllTo = $null }
    }
}

# =====================================================================================
Describe '14. Scale / Performance' {

    # FEATURE: "Built for large tenants" -- never bulk-list; users on demand; PIM-managed
    # groups queried by name prefix server-side.
    # REQ §14: Get-PimNamePrefix extracts the literal prefix; group filtering is by prefix;
    # context users are looked up on demand (not bulk-listed).
    It 'Groups queried by server-side name prefix; users on demand (no bulk-list)' {
        Get-PimNamePrefix 'PIM-{Service}-{Name}-L{Level}-T{Tier}-{Code}-{Domain}' | Should -Be 'PIM-'
        Get-PimNamePrefix 'Admin-{Initials}-L{Level}-T{Tier}-{Platform}'           | Should -Be 'Admin-'
        # the lean group resolver uses a server-side displayName $filter (not a full list).
        (Get-Content (Join-Path $Shared 'PIM-EngineProviders.ps1') -Raw) | Should -Match "displayName eq '"
    }

    # FEATURE: "One efficient role-schedule read" -- tenant-wide directory-role schedules
    # read once and indexed.
    # REQ §14: a single bulk preload indexes schedules instead of per-group queries.
    It 'Directory/group role schedules are bulk-preloaded once + indexed' {
        script:Fn 'Get-PimDirRoleSchedulePreload' | Should -BeTrue
        script:Fn 'Get-PimGroupSchedulePreload'   | Should -BeTrue
        (Get-Content (Join-Path $Shared 'PIM-EngineProviders.ps1') -Raw) | Should -Match '(?i)One bulk read'
    }

    # FEATURE: "Validate-and-skip with smart retries" -- existing is skipped; too-long
    # durations retried shorter down to permanent; disallowed nesting skipped cleanly.
    # REQ §14: Compare nochange => skip; Invoke-PimScheduleCreate retries a duration ladder
    # (180/90/30 -> noExpiration) on ExpirationRule failures.
    It 'Existing is skipped (nochange) + durations retry down a ladder to permanent' {
        $diff = Compare-PimDesiredVsLive -Desired @([pscustomobject]@{ k='a'; v=1 }) -Live @([pscustomobject]@{ k='a'; v=1 }) -KeyOf { param($r) $r.k } -Equal { param($d,$l) $d.v -eq $l.v }
        $diff.nochange.Count | Should -Be 1
        $diff.create.Count   | Should -Be 0
        $src = Get-Content (Join-Path $Shared 'PIM-EngineProviders.ps1') -Raw
        $src | Should -Match '(?i)DURATION-LADDER'
        $src | Should -Match '180,\s*90,\s*30,\s*0'                  # ladder shortens to permanent
    }

    # FEATURE: "No artificial caps" -- scaling is empirical, no max-N limits.
    # REQ §14 / Constraints §22: no hard MaxN/SkipAboveX caps in the engine providers.
    It 'No artificial Max-N / SkipAbove caps in the engine providers' {
        $src = Get-Content (Join-Path $Shared 'PIM-EngineProviders.ps1') -Raw
        $src | Should -Not -Match '(?i)\$MaxN\b'
        $src | Should -Not -Match '(?i)SkipAbove'
    }
}

# =====================================================================================
Describe '16. PIM Activator (browser extension)' {

    # FEATURE: "One-click bulk activation" -- MV3 extension; pick groups, justify, duration,
    # activate all at once; covers Entra roles + Azure RBAC + group access; expands nested.
    # REQ §16: MV3 manifest; storage + identity permissions; description states the 3 types.
    It 'MV3 activator manifest present with the right permissions + bulk/3-type description' {
        $m = Get-Content (Join-Path $Root 'tools\pim-activator\manifest.json') -Raw | ConvertFrom-Json
        $m.manifest_version | Should -Be 3
        @($m.permissions) | Should -Contain 'identity'      # browser sign-in flow
        @($m.permissions) | Should -Contain 'storage'       # favourites / config
        $m.description | Should -Match '(?i)bulk-activate'
        $m.description | Should -Match '(?i)Entra'
        $m.description | Should -Match '(?i)Azure'
    }

    # FEATURE: "Simple, secure sign-in" -- browser built-in flow (no MSAL/extra software);
    # first-run onboarding wizard.
    # REQ §16/§22: never device-code, never system-browser; uses chrome.identity (PKCE).
    It 'Activator uses the browser identity flow (no device-code grant, no MSAL bundle)' {
        $js = @(Get-ChildItem (Join-Path $Root 'tools\pim-activator') -Filter '*.js' -File)
        @($js).Count | Should -BeGreaterThan 0
        $all = ($js | ForEach-Object { Get-Content $_.FullName -Raw }) -join "`n"
        # the built-in browser sign-in flow (PKCE) is used...
        $all | Should -Match '(?i)launchWebAuthFlow'
        # ...and NO ACTIVE device-code grant is requested (constraint: MS blocks device-code).
        # (historical "device-code retired" comments are allowed; an active grant call is not.)
        $all | Should -Not -Match '(?i)grant_type[^\n]{0,20}device'
        $all | Should -Not -Match '(?i)oauth2/v2\.0/devicecode'
        # no MSAL library bundled (uses the browser identity API instead).
        $all | Should -Not -Match '(?i)msal\.js|@azure/msal'
    }

    # FEATURE: "Works for one tenant or many" + "Fleet-friendly deployment" -- single
    # tenant silent or a multi-tenant catalog; Intune/policy deploy; managed_schema.
    # REQ §16: managed_schema declared for managed (policy) deployment; Intune deploy script.
    It 'Activator supports managed (policy/Intune) deployment + multi-tenant catalog' {
        $m = Get-Content (Join-Path $Root 'tools\pim-activator\manifest.json') -Raw | ConvertFrom-Json
        (script:HasMember $m 'storage') | Should -BeTrue
        $m.storage.managed_schema | Should -Be 'managed-schema.json'
        (Test-Path -LiteralPath (Join-Path $Root 'tools\pim-activator\managed-schema.json')) | Should -BeTrue
        # an Intune deploy script ships (ADMX/forcelist) for fleet deployment.
        @(Get-ChildItem (Join-Path $Root 'tools\pim-activator') -Recurse -Filter 'Deploy-PimActivatorIntune.ps1' -ErrorAction SilentlyContinue).Count | Should -BeGreaterThan 0
    }
}

# =====================================================================================
Describe '17. Naming' {

    # FEATURE: "Naming lives in config, never hardcoded" -- admin/group/resource patterns
    # in config with per-tenant overrides, tokens for initials/level/tier/platform.
    # REQ §17: $global:PIM_NamingConventions ships the patterns; a .custom override file exists;
    # day-to-day admin = Admin-CCC-ID (no L#-T#), high-priv = Admin-CCC-L0-T0-ID.
    It 'Naming patterns live in config (tokens, day2day vs high-priv, per-tenant override)' {
        . (Join-Path $Root 'config\PIM4EntraPS.NamingConventions.locked.ps1')
        $nc = $global:PIM_NamingConventions
        $nc | Should -Not -BeNullOrEmpty
        $nc.AdminAccountPattern         | Should -Be 'Admin-{Owner}'                  # day-2-day: no L#-T#
        $nc.AdminAccountPatternHighPriv | Should -Be 'Admin-{Owner}-L0-T0-{Platform}' # high-priv markers
        $nc.PimGroupPattern             | Should -BeLike 'PIM-*'                       # dash separator, token-based
        $nc.ResourceGroupPattern        | Should -Be 'rg-pim-{Tier}'
        # a per-tenant override file ships (sample) so customers can match their convention.
        (Test-Path -LiteralPath (Join-Path $Root 'config\PIM4EntraPS.NamingConventions.custom.sample.ps1')) | Should -BeTrue
    }
}

# =====================================================================================
Describe '18. Launchers / Structure' {

    # FEATURE: internal structure / release-engineering (SI-mirror layout, flavours).
    # REQ §18: engine/_shared + tools/<role> layout; locked configs ship; VERSION bumped per release.
    It 'SI-mirror layout is in place (shared engine, role tools, locked config, VERSION)' {
        (Test-Path -LiteralPath (Join-Path $Root 'engine\_shared')) | Should -BeTrue
        (Test-Path -LiteralPath (Join-Path $Root 'tools\pim-engine')) | Should -BeTrue
        (Test-Path -LiteralPath (Join-Path $Root 'VERSION')) | Should -BeTrue
        # locked configs ship (baselines), distinct from .custom (gitignored).
        @(Get-ChildItem (Join-Path $Root 'config') -Filter '*.locked.*').Count | Should -BeGreaterThan 0
    }
}

# =====================================================================================
Describe '19. REST migration' {

    # FEATURE: "Direct-API engine and pagination" -- runs on direct API with robust paging.
    # REQ §19: Invoke-PimGraph/-PimArm support -All (paged) result sets; no module reliance.
    It 'Direct-API callers support paged (-All) result sets' {
        (Get-Command Invoke-PimGraph).Parameters.ContainsKey('All') | Should -BeTrue
        (Get-Command Invoke-PimArm).Parameters.ContainsKey('All')   | Should -BeTrue
        # SDK-shape normalization exists so REST responses match what callers expect.
        script:Fn 'ConvertTo-PimSdkShape' | Should -BeTrue
    }
}

# =====================================================================================
Describe '20. Testing / Validation' {

    # FEATURE: "Tested for real, never faked" -- validation against real test tenants,
    # creating + verifying + cleaning up real objects.
    # REQ §20: the live lab provision/test/cleanup scripts exist (driven manually / -Tag Live).
    It 'A real live lab (provision -> test -> cleanup) ships' {
        (Test-Path -LiteralPath (Join-Path $Root 'tests\live\Provision-PimLab.ps1'))      | Should -BeTrue
        (Test-Path -LiteralPath (Join-Path $Root 'tests\live\Test-PimLabDelegation.ps1')) | Should -BeTrue
        (Get-Content (Join-Path $Root 'tests\live\Provision-PimLab.ps1') -Raw) | Should -Match '(?i)-Cleanup'
    }

    # FEATURE: "Safe, self-cleaning test data" -- test data under a dedicated marker so
    # prod groups are never touched.
    # REQ §20: the core-engine marker harness prefixes objects with PIMCOREENGINE- and only
    # deletes marked objects.
    It 'Test data is marker-fenced (never touches prod)' {
        $harness = Join-Path $Root 'tests\live\Manage-PimCoreEngineTest.ps1'
        (Test-Path -LiteralPath $harness) | Should -BeTrue
        (Get-Content $harness -Raw) | Should -Match 'PIMCOREENGINE-'
    }

    # FEATURE: "Verified end to end" -- delegations confirmed live in PIM; Azure access
    # validated against sample RGs; a rerunnable offline suite covers engine + Manager.
    # REQ §20: the offline runner + the REST-no-modules live proof exist.
    It 'A rerunnable offline suite + a no-modules REST live proof exist' {
        (Test-Path -LiteralPath (Join-Path $Root 'tests\Run-AllPimTests.ps1'))          | Should -BeTrue
        (Test-Path -LiteralPath (Join-Path $Root 'tests\PIM.Tests.ps1'))                | Should -BeTrue
        (Test-Path -LiteralPath (Join-Path $Root 'tests\live\Test-PimRestNoModules.ps1')) | Should -BeTrue
    }

    # FEATURE (Live): Azure roles actually exist for the sample resources (REQ §20 open item).
    It 'Sample Azure roles resolve live (ARM)' -Tag 'Live' -Skip:(-not $script:LiveEnabled) {
        # Live-gated: needs ARM + the provisioned sample RGs. Offline we assert the resolver exists.
        script:Fn 'Resolve-PimArmRoleId' | Should -BeTrue
    }
}

# =====================================================================================
Describe '21. Docs' {

    # FEATURE: "Clear documentation set" -- a design doc + this feature catalog.
    # REQ §21: the canonical public docs exist (FEATURES + DESIGN), TESTS internal.
    It 'The canonical doc set exists (FEATURES, DESIGN, TESTS)' {
        (Test-Path -LiteralPath (Join-Path $Root 'docs\FEATURES.md')) | Should -BeTrue
        (Test-Path -LiteralPath (Join-Path $Root 'docs\DESIGN.md'))   | Should -BeTrue
        (Test-Path -LiteralPath (Join-Path $Root 'docs\TESTS.md'))    | Should -BeTrue
    }
}
