#Requires -Version 5.1
<#
.SYNOPSIS
    RIGHTS-LIVE-1 (framework, owner 2026-11-10) step 1 -- PIM Manager's APPROVED rights list in Invardia's normalised shape
    ("schema": "invardia-rights/1"), GENERATED FROM THE CODE'S OWN GRANT SETS so the list and the grants cannot drift.

.DESCRIPTION
    Invardia reads every product identity's live rights every day and judges them against the list the product hands over
    (handover\rights\pim-manager\<version>\: ONE .json + SHA256SUMS.txt). This file builds that list.

    WHERE EACH PART COMES FROM
      * Microsoft Graph application permissions -- READ FROM THE GRANT CODE, never copied:
          engine    tools\setup\_PimSetupShared.ps1  $script:PimGraphAppRoles         (Grant-PimMiGraph -RoleSet Engine)
          web       tools\setup\_PimSetupShared.ps1  $script:PimGraphAppRolesManager  (Grant-PimMiGraph -RoleSet Manager)
          updater   engine\_shared\PIM-UpdaterGraphRoles.ps1  Get-PimUpdaterGraphAppRoles (Grant-PimMiGraph -RoleSet Updater)
          downlink  the engine set (Deploy-PimDownlinkJob.ps1: Grant-PimMiGraph -RoleSet Engine)
        _PimSetupShared.ps1 is PARSED (its hashtable literals), never dot-sourced: it is a setup helper with load-time side
        effects (the same reason engine\_shared\PIM-WorkloadPrereqSelfCheck.ps1 parses it). PIM-UpdaterGraphRoles.ps1 is pure.
      * Azure role assignments + the one Entra directory role -- a table below, ONE row per grant the setup / updater code
        makes, each with its source. tests\Test-PimRightsList.ps1 holds the table against the identity move's code-read
        rights map (engine\_shared\PIM-IdentityMove.ps1 Get-PimIdentityMoveRoleNeeds): every Azure role that map gives a role
        is in the list for that identity, and nothing else.
      * Out of this file by the format: SQL, Exchange RBAC, group memberships, ownership, federated credentials.

    PURE: no network, no Azure, no Graph. ASCII only; PS 5.1 + 7; no modules. The JSON is written by its own serializer
    (fixed key order, 2-space indent, LF), so the same input gives byte-identical output on 5.1 and 7.

      Get-PimApprovedRightsList     -Version <v> [-Approval <text>]  -> the list (ordered dictionaries)
      ConvertTo-PimRightsListJson   -List <list>                    -> the JSON text (LF, trailing newline)
      Get-PimRightsCodeGraphSets                                    -> the code's Graph grant sets per identity role
      Get-PimRightsListAllowedValues                                -> the format's allowed kind / scope / when values
      Get-PimRightsListNotListedRoles                               -> identity roles of the standard that hold no right
      Get-PimRightsListExtraFeatureKeys                             -> featureKeys that are not catalog keys, with the reason
#>
Set-StrictMode -Off

$script:PimRightsListSolRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
if (-not (Get-Command Get-PimUpdaterGraphAppRoles -ErrorAction SilentlyContinue)) {
    $__pimRlUgr = Join-Path $PSScriptRoot 'PIM-UpdaterGraphRoles.ps1'
    if (Test-Path -LiteralPath $__pimRlUgr) { . $__pimRlUgr }
}

function Get-PimRightsListRoot {
    <# The solution root (engine\_shared -> ..\..). A function: a dot-sourced file's $PSScriptRoot is valid only at load. #>
    return $script:PimRightsListSolRoot
}

function Get-PimRightsListAllowedValues {
    <# PURE. The format's value sets (framework RIGHTS-LIVE-1 point 2). #>
    return [ordered]@{
        schema = 'invardia-rights/1'
        kinds  = @('azure-rbac', 'graph-app-role', 'defender-app-role', 'entra-directory-role')
        scopes = @('resource', 'install-rg', 'subscription', 'tenant-root', 'tenant')
        whens  = @('always', 'feature', 'kept')
    }
}

function Get-PimRightsListGraphResource {
    <# PURE. Microsoft Graph as the resource of a graph-app-role row (its well-known application id). #>
    return [ordered]@{ name = 'Microsoft Graph'; appId = '00000003-0000-0000-c000-000000000000' }
}

function Get-PimRightsSetupMapFromSource {
    <#
      PURE (reads a file). A role-name -> appRole-id hashtable literal assigned to -Variable in tools\setup\_PimSetupShared.ps1,
      READ BY PARSING the file (never dot-sourced). Throws when the map is missing, not a literal, or empty -- a list built from
      no grant set proves nothing.
    #>
    param([Parameter(Mandatory)][string]$Variable, [string]$Path = (Join-Path (Get-PimRightsListRoot) 'tools\setup\_PimSetupShared.ps1'))
    if (-not (Test-Path -LiteralPath $Path)) { throw "the Graph grant source is missing: $Path" }
    $errs = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$null, [ref]$errs)
    $asg = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and "$($n.Left.Extent.Text)" -ieq $Variable }, $true))
    if (-not $asg.Count) { throw "no $Variable map in $Path" }
    $ht = @($asg[0].Right.FindAll({ param($n) $n -is [System.Management.Automation.Language.HashtableAst] }, $true))[0]
    if (-not $ht) { throw "$Variable in $Path is not a hashtable literal" }
    $map = [ordered]@{}
    foreach ($kv in $ht.KeyValuePairs) {
        $k = if ($kv.Item1 -is [System.Management.Automation.Language.StringConstantExpressionAst]) { "$($kv.Item1.Value)" } else { "$($kv.Item1.Extent.Text)".Trim("'", '"') }
        $v = "$($kv.Item2.Extent.Text)".Trim().Trim("'", '"')
        if ($k) { $map[$k] = $v.ToLowerInvariant() }
    }
    if (-not $map.Count) { throw "$Variable in $Path is empty" }
    return $map
}

function Get-PimRightsCodeGraphSets {
    <#
      PURE (reads the grant files). The Graph application permissions the CODE grants, per identity role:
        @{ engine = <name -> id>; web = ...; updater = ...; downlink = ... }   (ordered name -> appRole id)
    #>
    param([string]$SetupSharedPath = (Join-Path (Get-PimRightsListRoot) 'tools\setup\_PimSetupShared.ps1'))
    $engine = Get-PimRightsSetupMapFromSource -Variable '$script:PimGraphAppRoles' -Path $SetupSharedPath
    $web = Get-PimRightsSetupMapFromSource -Variable '$script:PimGraphAppRolesManager' -Path $SetupSharedPath
    if (-not (Get-Command Get-PimUpdaterGraphAppRoles -ErrorAction SilentlyContinue)) { throw 'Get-PimUpdaterGraphAppRoles is not loaded (engine\_shared\PIM-UpdaterGraphRoles.ps1)' }
    $u = Get-PimUpdaterGraphAppRoles
    $updater = [ordered]@{}; foreach ($k in @($u.Keys)) { $updater["$k"] = "$($u[$k])".ToLowerInvariant() }
    $downlink = [ordered]@{}; foreach ($k in @($engine.Keys)) { $downlink["$k"] = $engine[$k] }
    return [ordered]@{ engine = $engine; web = $web; updater = $updater; downlink = $downlink }
}

function Get-PimRightsGraphPurpose {
    <#
      PURE. What a Graph application permission is for, in plain words (the 'feature' field). -Identity picks an identity's
      own wording first. '' = no text (tests\Test-PimRightsList.ps1 fails on a code-granted role without one).
    #>
    param([Parameter(Mandatory)][string]$Role, [string]$Identity = '')
    $own = @{
        'updater|PrivilegedAssignmentSchedule.ReadWrite.AzureADGroup' = 'Keeps the database job identity a time-limited member of the SQL admin group (PIM for Groups)'
        'updater|PrivilegedAssignmentSchedule.Read.AzureADGroup'      = 'Reads that membership back'
        'updater|RoleManagementPolicy.Read.AzureADGroup'              = 'Reads the SQL admin group''s PIM policy maximum, so the membership asks for exactly that length'
        'updater|GroupMember.Read.All'                                = 'Reads the SQL admin group and the database job identity''s memberships (read only)'
        'updater|Application.Read.All'                                = 'Reads the database job identity''s service principal memberships (read only)'
        'updater|Application.ReadWrite.OwnedBy'                       = 'Changes only the PIM app registrations it owns'
        'updater|User.ReadBasic.All'                                  = 'Reads the SuperAdmins'' mail addresses for the alert recipients (basic profile only)'
        'web|User.ReadBasic.All'                                      = 'The people picker and the user name to object id lookups an admin triggers (basic profile only)'
        'web|GroupMember.Read.All'                                    = 'The group picker and the group id to name lookups (basic group properties)'
    }
    $k = "$Identity|$Role"
    if ($own.ContainsKey($k)) { return $own[$k] }
    $all = @{
        'Directory.Read.All'                                   = 'Reads users, groups and roles to compare what is defined with what is live'
        'User.ReadWrite.All'                                   = 'Creates and manages the admin accounts PIM defines'
        'Group.ReadWrite.All'                                  = 'Creates and manages the PIM groups'
        'RoleManagement.ReadWrite.Directory'                   = 'Creates role-assignable groups and manages their members and owners'
        'RoleEligibilitySchedule.ReadWrite.Directory'          = 'Assigns Entra directory roles (eligible)'
        'RoleEligibilitySchedule.Remove.Directory'             = 'Removes eligible Entra role assignments PIM manages'
        'RoleAssignmentSchedule.ReadWrite.Directory'           = 'Assigns Entra directory roles (active)'
        'RoleAssignmentSchedule.Remove.Directory'              = 'Removes active Entra role assignments PIM manages'
        'RoleManagement.Read.All'                              = 'Reads role definitions and assignments'
        'RoleManagementPolicy.ReadWrite.Directory'             = 'Sets the Entra role activation policies (duration, MFA, approval)'
        'RoleManagementPolicy.ReadWrite.AzureADGroup'          = 'Sets the PIM for Groups activation policies (duration, MFA, approval)'
        'PrivilegedEligibilitySchedule.ReadWrite.AzureADGroup' = 'Eligible group assignments (PIM for Groups)'
        'PrivilegedEligibilitySchedule.Remove.AzureADGroup'    = 'Removes eligible group assignments PIM manages'
        'PrivilegedAssignmentSchedule.ReadWrite.AzureADGroup'  = 'Active group assignments (PIM for Groups)'
        'PrivilegedAssignmentSchedule.Remove.AzureADGroup'     = 'Removes active group assignments PIM manages'
        'AdministrativeUnit.ReadWrite.All'                     = 'Administrative units and their scoped roles'
        'UserAuthenticationMethod.ReadWrite.All'               = 'Issues and resets Temporary Access Passes for new admin accounts'
        'Domain.Read.All'                                      = 'Resolves the tenant default domain for admin account names'
        'Policy.Read.All'                                      = 'Reads the Temporary Access Pass policy (one-time use, lifetime)'
        'AccessReview.Read.All'                                = 'Reads access reviews (the engine records them for the pages)'
        'AccessReview.ReadWrite.All'                           = 'Creates the group access reviews'
        'AppRoleAssignment.ReadWrite.All'                      = 'Enterprise-application role delegations'
        'Application.Read.All'                                 = 'Reads the target application of an enterprise-application role'
        'RoleManagement.ReadWrite.Defender'                    = 'Defender XDR role delegations'
        'DeviceManagementRBAC.ReadWrite.All'                   = 'Intune role and scope-tag delegations'
    }
    if ($all.ContainsKey($Role)) { return $all[$Role] }
    return ''
}

function Get-PimRightsListNotListedRoles {
    <#
      PURE. Identity roles of the standard (engine\_shared\PIM-IdentitySplit.ps1 Get-PimIdentityRoleWords) that the list does
      not carry, with the reason. Nothing else may be missing (tests\Test-PimRightsList.ps1).
    #>
    return [ordered]@{
        mcp = 'no setup or updater code deploys an id-pim-mcp identity or grants it a right: the MCP server runs inside the web app (/mcp) as id-pim-web'
    }
}

function Get-PimRightsListExtraFeatureKeys {
    <#
      PURE. featureKeys this list uses that are not keys of engine\_shared\PIM-FeatureCatalog.ps1, with the reason. Every other
      featureKey must be a catalog key (tests\Test-PimRightsList.ps1).
    #>
    return [ordered]@{
        # Invardia 2026-11-10 (RIGHTS-LIVE-1): an install that pulls with a SHARED registry identity gives its workload
        # identities no AcrPull of their own -- 'always' made that a false MISSING. The heartbeat reports this key (RIGHTS-1.8,
        # optionalComponents): on = the identity pulls with its own AcrPull. Downlink / publish / requests keep their own feature.
        'own-registry-pull' = 'The identity pulls its image from the install''s registry with its OWN AcrPull (not a shared registry identity); reported on the heartbeat as an optional component (RIGHTS-1.8).'
        'azure-rbac' ='Azure resource role delegations (the workload connector id, engine\_shared\PIM-PermissionHealth.ps1 Get-PimWorkloadConnectorRequirements). Free and not a catalog gate: the engine needs User Access Administrator only where the store defines Azure scopes (engine\_shared\PIM-EngineAzureAccess.ps1, 95.2k)'
    }
}

function Get-PimRightsAzureTable {
    <#
      PURE. Every Azure role assignment (and the one Entra directory role) the setup / updater code grants a PIM identity --
      one row per grant, with the code that makes it. Role ids are Microsoft's built-in role definition ids (Learn:
      azure/role-based-access-control/built-in-roles; the Entra one: entra/identity/role-based-access-control/permissions-reference).
      Keys: identity, key (the id suffix), kind, role, roleId, scope, scopeNote, when, featureKey, feature, source.
    #>
    $reader = 'acdd72a7-3385-48ef-bd42-f606fba81ae7'; $uaa = '18d7d88d-d35e-4fb5-a5c3-7773c20a72d9'
    $acr = '7f951dda-4ed3-4680-a7ca-43fe172d538d'; $stdc = '0a9a7e1f-b9d0-4cc4-a60d-0319b160aaa3'
    $jobsOp = 'b9a307c4-5aa3-4b52-ba60-2b17c136cd7b'; $kvCseu = 'e147488a-f6f5-4113-8e2d-b22465e65bf6'
    $contrib = 'b24988ac-6180-42a0-ab88-20f7382dd24c'; $sbdc = 'ba92f5b4-2d11-453d-a403-e96b0029c9fe'; $kvcu = '12338af0-0e69-4776-bea7-57ae8d297424'
    $fabric = 'a9ea8996-122f-4c74-9520-8edcd192826c'
    $r = { param($identity, $key, $kind, $role, $roleId, $scope, $scopeNote, $when, $featureKey, $feature, $source)
        [ordered]@{ identity = $identity; key = $key; kind = $kind; role = $role; roleId = $roleId; scope = $scope; scopeNote = $scopeNote
                    when = $when; featureKey = $featureKey; feature = $feature; source = $source } }
    return @(
        # ---- engine (the engine job's identity)
        (& $r 'engine' 'reader@subscription' 'azure-rbac' 'Reader' $reader 'subscription' 'the hosting subscription' 'always' '' 'Reads Azure in the hosting subscription (Discovery, the Azure half of the tenant cache)' 'tools\setup\Setup-PimContainers.ps1 Grant-PimMiAzureRbac (-AzureRbacRoles default Reader; Get-PimAzureRbacPlan scope /subscriptions/<sub>)')
        (& $r 'engine' 'reader@tenant-root' 'azure-rbac' 'Reader' $reader 'tenant-root' 'the Tenant Root Group (its id is the tenant id)' 'always' '' 'Discovery lists management groups and subscriptions (read only)' 'tools\setup\_PimSetupShared.ps1 Get-PimEngineRootAzurePlan / Grant-PimEngineRootAzureAccess (PIM 97)')
        (& $r 'engine' 'reader@engine-job' 'azure-rbac' 'Reader' $reader 'resource' 'the engine job itself (caj-pim-engine / ca-pim-tick)' 'always' '' 'Reads its own job executions (one engine run at a time)' 'tools\setup\Initialize-PimHostingAccess.ps1 (Reader on the tick job)')
        (& $r 'engine' 'container-apps-jobs-operator@updater-job' 'azure-rbac' 'Container Apps Jobs Operator' $jobsOp 'resource' 'the updater job only' 'always' '' 'The engine starts the updater for "update now" (update-expedite) and reads its executions' 'tools\setup\_PimSetupShared.ps1 Grant-PimEngineUpdaterJobAccess (Deploy-PimUpdateJob.ps1, Initialize-PimHostingAccess.ps1); owner rights decision 2026-11-09 "approved with A"')
        (& $r 'engine' 'contributor@updater-job' 'azure-rbac' 'Contributor' $contrib 'resource' 'the updater job only' 'always' '' 'The watchdog restores the updater job to its last good image' 'tools\setup\_PimSetupShared.ps1 Grant-PimEngineUpdaterJobAccess (Deploy-PimUpdateJob.ps1, Initialize-PimHostingAccess.ps1); owner rights decision 2026-11-09 "approved with A"')
        (& $r 'engine' 'user-access-administrator@defined-scopes' 'azure-rbac' 'User Access Administrator' $uaa 'subscription' 'each top Azure scope the store defines (subscription, management group or resource group of PIM-Assignments-Azure-Resources / PIM-Definitions-Resources) -- never Owner' 'feature' 'azure-rbac' 'Assigns Azure resource roles (eligible / active) and sets their PIM policies where Azure delegations are defined' 'engine\_shared\PIM-EngineAzureAccess.ps1 (95.2k) + engine\_shared\PIM-EngineAzureScopeTrim.ps1 (4.3); tools\setup\_PimWorkloadPrereqRunner.ps1 Invoke-PimPrereqAzureRbac')
        (& $r 'engine' 'user-access-administrator@tenant-root' 'azure-rbac' 'User Access Administrator' $uaa 'tenant-root' 'only with the install opt-in -EngineAzureRootUserAccessAdmin; then it replaces the per-scope grants' 'feature' 'azure-rbac' 'Assigns Azure resource roles at every subscription (opt-in)' 'tools\setup\_PimSetupShared.ps1 Get-PimEngineRootAzurePlan -IncludeUserAccessAdministrator')
        (& $r 'engine' 'storage-table-data-contributor@rfa-store' 'azure-rbac' 'Storage Table Data Contributor' $stdc 'resource' 'the RFA broker''s storage account' 'feature' 'rfa.portal' 'Pulls the requests and answers of the RFA portal / access request API' 'tools\setup\_PimRfaBrokerPlan.ps1 (role-engine-<id>), tools\setup\Deploy-PimRfaBroker.ps1')
        (& $r 'engine' 'acrpull@registry' 'azure-rbac' 'AcrPull' $acr 'resource' 'the install''s container registry' 'feature' 'own-registry-pull' 'Pulls the engine image' 'tools\setup\Setup-PimContainers.ps1 (AcrPull per workload identity); engine\_shared\PIM-IdentityMove.ps1 Get-PimIdentityMoveRoleNeeds')
        (& $r 'engine' 'fabric-administrator@tenant' 'entra-directory-role' 'Fabric Administrator' $fabric 'tenant' 'directory scope / (active, permanent); older tenants show it as Power BI Administrator' 'feature' 'connectors.powerbi' 'Gives Power BI workspace roles through the Fabric admin API' 'tools\setup\_PimWorkloadPrereqRunner.ps1 (powerbi.fabricAdmin, Initialize-PimWorkloadPrereqs.ps1 -Workload PowerBI -GrantFabricAdministrator)')
        # ---- web (the web app's identity)
        (& $r 'web' 'reader@install-rg' 'azure-rbac' 'Reader' $reader 'install-rg' 'the PIM resource group only (never the subscription)' 'always' '' 'The Environment report reads the installation''s own architecture' 'tools\setup\_PimSetupShared.ps1 Get-PimManagerRgReaderScope / Grant-PimManagerRgReader (PIM 100.22 b, RIGHTS-1 B)')
        (& $r 'web' 'container-apps-jobs-operator@engine-job' 'azure-rbac' 'Container Apps Jobs Operator' $jobsOp 'resource' 'the engine job only' 'always' '' 'Commit and Run now start the engine job' 'tools\setup\Initialize-PimHostingAccess.ps1')
        (& $r 'web' 'key-vault-crypto-service-encryption-user@signin-front-key' 'azure-rbac' 'Key Vault Crypto Service Encryption User' $kvCseu 'resource' 'the key signin-front in the install''s own Key Vault' 'always' '' 'The sign-in front wraps and unwraps its session keys' 'tools\setup\_PimInstallSigninFront.ps1 (signin-front-vault)')
        (& $r 'web' 'acrpull@registry' 'azure-rbac' 'AcrPull' $acr 'resource' 'the install''s container registry' 'feature' 'own-registry-pull' 'Pulls the web app image' 'tools\setup\Setup-PimContainers.ps1 (AcrPull per workload identity)')
        # ---- updater (the update job's identity)
        (& $r 'updater' 'contributor@install-rg' 'azure-rbac' 'Contributor' $contrib 'install-rg' 'the PIM resource group only; also on the registry itself when it lives in another resource group' 'always' '' 'Rolls the web app and the jobs to the approved image and builds it in the registry' 'tools\setup\Deploy-PimUpdateJob.ps1 (step 2)')
        (& $r 'updater' 'acrpull@registry' 'azure-rbac' 'AcrPull' $acr 'resource' 'the install''s container registry' 'feature' 'own-registry-pull' 'Pulls its own image' 'tools\setup\Deploy-PimUpdateJob.ps1 (step 2)')
        # ---- downlink (the managed-tenant pull job's identity)
        (& $r 'downlink' 'reader@downlink-job' 'azure-rbac' 'Reader' $reader 'resource' 'the pull job itself' 'feature' 'msp.downlink' 'Reads the status of its own earlier runs (cadence gate)' 'tools\setup\Deploy-PimDownlinkJob.ps1 (framework 12.24 / PIM 100.166 a), engine\_shared\PIM-JobSelfId.ps1')
        (& $r 'downlink' 'acrpull@registry' 'azure-rbac' 'AcrPull' $acr 'resource' 'the install''s container registry' 'feature' 'msp.downlink' 'Pulls the engine image' 'tools\setup\Deploy-PimDownlinkJob.ps1 (post-create grant)')
        # ---- publish (the managing tenant's baseline publish job's identity)
        (& $r 'publish' 'storage-blob-data-contributor@bundle-container' 'azure-rbac' 'Storage Blob Data Contributor' $sbdc 'resource' 'the bundle container only (not the account)' 'feature' 'msp.downlink' 'Writes the signed baseline bundle' 'engine\msp\PIM-BaselinePublish.ps1 Get-PimBaselinePublishJobGrants')
        (& $r 'publish' 'key-vault-crypto-user@signing-key' 'azure-rbac' 'Key Vault Crypto User' $kvcu 'resource' 'the signing key only (not the vault)' 'feature' 'msp.downlink' 'Signs the bundle and reads the public half' 'engine\msp\PIM-BaselinePublish.ps1 Get-PimBaselinePublishJobGrants')
        (& $r 'publish' 'reader@publish-job' 'azure-rbac' 'Reader' $reader 'resource' 'the publish job itself' 'feature' 'msp.downlink' 'Reads the status of its own earlier runs (cadence gate)' 'tools\setup\Deploy-PimBaselinePublishJob.ps1, engine\_shared\PIM-JobSelfId.ps1')
        (& $r 'publish' 'acrpull@registry' 'azure-rbac' 'AcrPull' $acr 'resource' 'the install''s container registry' 'feature' 'msp.downlink' 'Pulls its own image' 'tools\setup\Deploy-PimBaselinePublishJob.ps1')
        # ---- requests (the RFA broker app's identity)
        (& $r 'requests' 'storage-table-data-contributor@rfa-store' 'azure-rbac' 'Storage Table Data Contributor' $stdc 'resource' 'the RFA broker''s storage account (its only Azure data right)' 'feature' 'rfa.portal' 'Keeps the requests, PINs and sessions of the RFA portal / access request API' 'tools\setup\_PimRfaBrokerPlan.ps1 (role-app), tools\setup\Deploy-PimRfaBroker.ps1')
        (& $r 'requests' 'acrpull@registry' 'azure-rbac' 'AcrPull' $acr 'resource' 'the install''s container registry' 'feature' 'rfa.portal' 'Pulls the broker image' 'engine\_shared\PIM-IdentityMove.ps1 Get-PimIdentityMoveRoleNeeds')
        # ---- dbinit (the database job's identity)
        (& $r 'dbinit' 'acrpull@registry' 'azure-rbac' 'AcrPull' $acr 'resource' 'the install''s container registry' 'feature' 'own-registry-pull' 'Pulls its own image' 'engine\_shared\PIM-IdentityMove.ps1 Get-PimIdentityMoveRoleNeeds')
        # ---- docs (the installation documentation job's identity; internal role key 'asbuilt')
        (& $r 'docs' 'storage-blob-data-contributor@asbuilt-container' 'azure-rbac' 'Storage Blob Data Contributor' $sbdc 'resource' 'the asbuilt container only' 'always' '' 'Writes the installation documentation PDF' 'tools\setup\Deploy-PimAsBuiltJob.ps1 (step 4), tools\setup\Initialize-PimHostingAccess.ps1')
        (& $r 'docs' 'acrpull@registry' 'azure-rbac' 'AcrPull' $acr 'resource' 'the install''s container registry' 'feature' 'own-registry-pull' 'Pulls its own image' 'tools\setup\Deploy-PimAsBuiltJob.ps1 (step 2)')
    )
}

function Get-PimRightsKeptGraphRows {
    <#
      PURE. Graph application permissions the code NO LONGER GRANTS but an install keeps until it runs the version that stops
      using them (when = 'kept': never MISSING, never EXTRA -- framework RIGHTS-LIVE-1 point 2). The only rows of the list that
      are not in a code grant set; tests\Test-PimRightsList.ps1 allows nothing else beyond the grant sets.
    #>
    return @(
        # AR-ENGINE-1 (3.0.71): access reviews are read by the engine and replayed by the web app; before 3.0.71 the web app read them itself
        [ordered]@{ identity = 'web'; role = 'AccessReview.Read.All'; roleId = 'd07a8cc0-3d51-4b77-b3b0-32704d1f69fa'
                    scopeNote = 'until the install runs 3.0.71 or later; then removed'; feature = 'Reads access reviews in the web app (versions before 3.0.71; from 3.0.71 the engine reads them)' }
    )
}

function Get-PimRightsIdentityCatalog {
    <#
      PURE. The identities of the list: role (the id-pim-<role> word), the code role key (engine\_shared\PIM-IdentitySplit.ps1),
      the old names (renamed identities), the Graph set it gets (a key of Get-PimRightsCodeGraphSets, '' = none) and when.
    #>
    return @(
        [ordered]@{ role = 'engine';   codeRole = 'engine';   oldNames = @();                  graph = 'engine';   when = 'always';  featureKey = '' }
        [ordered]@{ role = 'web';      codeRole = 'web';      oldNames = @();                  graph = 'web';      when = 'always';  featureKey = '' }
        [ordered]@{ role = 'updater';  codeRole = 'updater';  oldNames = @();                  graph = 'updater';  when = 'always';  featureKey = '' }
        [ordered]@{ role = 'downlink'; codeRole = 'downlink'; oldNames = @();                  graph = 'downlink'; when = 'feature'; featureKey = 'msp.downlink' }
        [ordered]@{ role = 'publish';  codeRole = 'publish';  oldNames = @();                  graph = '';         when = 'feature'; featureKey = 'msp.downlink' }
        [ordered]@{ role = 'requests'; codeRole = 'requests'; oldNames = @();                  graph = '';         when = 'feature'; featureKey = 'rfa.portal' }
        [ordered]@{ role = 'dbinit';   codeRole = 'dbinit';   oldNames = @();                  graph = '';         when = 'always';  featureKey = '' }
        [ordered]@{ role = 'docs';     codeRole = 'asbuilt';  oldNames = @('id-pim-asbuilt');  graph = '';         when = 'always';  featureKey = '' }
    )
}

function Get-PimRightsSortedOrdinal {
    <# PURE. Strings sorted ordinally (culture-independent: the same order on every machine). #>
    param([AllowEmptyCollection()][string[]]$Items = @())
    [string[]]$a = @($Items)
    [Array]::Sort($a, [StringComparer]::Ordinal)
    return , $a
}

function Get-PimApprovedRightsList {
    <#
      PURE. The approved rights list of THIS code, in the invardia-rights/1 shape. Identities sorted by role, rights by id
      (ordinal). Throws when a grant set cannot be read.
    #>
    param([Parameter(Mandatory)][string]$Version, [string]$Approval = '', [string]$SetupSharedPath = (Join-Path (Get-PimRightsListRoot) 'tools\setup\_PimSetupShared.ps1'))
    if ("$Version".Trim() -notmatch '^\d+\.\d+\.\d+([.-][0-9A-Za-z.-]+)?$') { throw "Get-PimApprovedRightsList: '$Version' is not a version" }
    $v = "$Version".Trim()
    if (-not "$Approval".Trim()) { $Approval = "released with PIM Manager $v (owner ring approval); generated from the code's grant sets (engine\_shared\PIM-RightsList.ps1), not kept by hand" }
    $sets = Get-PimRightsCodeGraphSets -SetupSharedPath $SetupSharedPath
    $gres = Get-PimRightsListGraphResource
    $azure = @(Get-PimRightsAzureTable)
    $byRole = @{}
    foreach ($id in @(Get-PimRightsIdentityCatalog)) {
        $rights = @{}
        if ($id.graph) {
            $set = $sets[$id.graph]
            foreach ($name in @($set.Keys)) {
                $rid = "$($id.role).graph.$name"
                $o = [ordered]@{ id = $rid; kind = 'graph-app-role'; role = "$name"; roleId = "$($set[$name])"; resource = $gres.name; resourceAppId = $gres.appId; scope = 'tenant' }
                $o['when'] = $id.when
                if ($id.when -eq 'feature') { $o['featureKey'] = $id.featureKey }
                $o['feature'] = (Get-PimRightsGraphPurpose -Role "$name" -Identity $id.role)
                $rights[$rid] = $o
            }
        }
        foreach ($k in @(Get-PimRightsKeptGraphRows | Where-Object { $_.identity -eq $id.role })) {
            $rid = "$($id.role).graph.$($k.role)"
            if ($rights.ContainsKey($rid)) { throw "Get-PimApprovedRightsList: kept row $rid is also in the code grant set -- it is then not 'kept'" }
            $rights[$rid] = [ordered]@{ id = $rid; kind = 'graph-app-role'; role = $k.role; roleId = $k.roleId; resource = $gres.name; resourceAppId = $gres.appId
                                        scope = 'tenant'; scopeNote = $k.scopeNote; when = 'kept'; feature = $k.feature }
        }
        foreach ($a in @($azure | Where-Object { $_.identity -eq $id.role })) {
            $tag = $(if ($a.kind -eq 'entra-directory-role') { 'directory' } else { 'azure' })
            $rid = "$($id.role).$tag.$($a.key)"
            if ($rights.ContainsKey($rid)) { throw "Get-PimApprovedRightsList: duplicate right id $rid" }
            $o = [ordered]@{ id = $rid; kind = $a.kind; role = $a.role; roleId = $a.roleId; scope = $a.scope }
            if ("$($a.scopeNote)".Trim()) { $o['scopeNote'] = $a.scopeNote }
            $o['when'] = $a.when
            if ($a.when -eq 'feature') { $o['featureKey'] = $a.featureKey }
            $o['feature'] = $a.feature
            $rights[$rid] = $o
        }
        $ids = Get-PimRightsSortedOrdinal -Items @($rights.Keys)
        $old = Get-PimRightsSortedOrdinal -Items @($id.oldNames)
        $byRole[$id.role] = [ordered]@{ role = $id.role; name = "id-pim-$($id.role)"; oldNames = $old; rights = @(foreach ($k in $ids) { $rights[$k] }) }
    }
    $roles = Get-PimRightsSortedOrdinal -Items @($byRole.Keys)
    return [ordered]@{
        schema     = (Get-PimRightsListAllowedValues).schema
        product    = 'pim-manager'
        version    = $v
        approval   = "$Approval"
        identities = @(foreach ($k in $roles) { $byRole[$k] })
    }
}

function ConvertTo-PimRightsJsonValue {
    <# PURE. One value as JSON text at -Indent (2 spaces per level). Dictionaries keep their key order. #>
    param([AllowNull()][object]$Value, [int]$Indent = 0)
    $pad = '  ' * $Indent; $pad1 = '  ' * ($Indent + 1)
    if ($null -eq $Value) { return 'null' }
    if ($Value -is [bool]) { return $(if ($Value) { 'true' } else { 'false' }) }
    if ($Value -is [int] -or $Value -is [long]) { return "$Value" }
    if ($Value -is [string]) {
        $sb = New-Object System.Text.StringBuilder
        [void]$sb.Append('"')
        foreach ($ch in $Value.ToCharArray()) {
            $c = [int]$ch
            if ($ch -eq '"') { [void]$sb.Append('\"') }
            elseif ($ch -eq '\') { [void]$sb.Append('\\') }
            elseif ($c -eq 10) { [void]$sb.Append('\n') }
            elseif ($c -eq 13) { [void]$sb.Append('\r') }
            elseif ($c -eq 9) { [void]$sb.Append('\t') }
            elseif ($c -lt 32 -or $c -gt 126) { [void]$sb.Append(('\u{0:x4}' -f $c)) }
            else { [void]$sb.Append($ch) }
        }
        [void]$sb.Append('"')
        return $sb.ToString()
    }
    if ($Value -is [System.Collections.IDictionary]) {
        $keys = @($Value.Keys)
        if (-not $keys.Count) { return '{}' }
        $parts = @(foreach ($k in $keys) { $pad1 + (ConvertTo-PimRightsJsonValue -Value "$k") + ': ' + (ConvertTo-PimRightsJsonValue -Value $Value[$k] -Indent ($Indent + 1)) })
        return "{`n" + ($parts -join ",`n") + "`n$pad}"
    }
    if ($Value -is [System.Collections.IEnumerable]) {
        $items = @($Value)
        if (-not $items.Count) { return '[]' }
        $parts = @(foreach ($i in $items) { $pad1 + (ConvertTo-PimRightsJsonValue -Value $i -Indent ($Indent + 1)) })
        return "[`n" + ($parts -join ",`n") + "`n$pad]"
    }
    return (ConvertTo-PimRightsJsonValue -Value "$Value" -Indent $Indent)
}

function ConvertTo-PimRightsListJson {
    <# PURE. The list as JSON: fixed key order, 2-space indent, LF line endings, one trailing newline, ASCII. #>
    param([Parameter(Mandatory)][System.Collections.IDictionary]$List)
    return ((ConvertTo-PimRightsJsonValue -Value $List -Indent 0) + "`n")
}
